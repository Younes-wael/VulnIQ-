"""
Migrate CVE embeddings from local ChromaDB to Qdrant Cloud.

Usage:
    python migrate_to_qdrant.py

Credentials are loaded from .env — never hardcoded.
"""

import os
import sys

from dotenv import load_dotenv

load_dotenv()

QDRANT_URL = os.environ.get("QDRANT_URL")
QDRANT_API_KEY = os.environ.get("QDRANT_API_KEY")

if not QDRANT_URL or not QDRANT_API_KEY:
    sys.exit("ERROR: QDRANT_URL and QDRANT_API_KEY must be set in .env")

import time
import chromadb
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from tqdm import tqdm

COLLECTION_NAME = "cve_vulnerabilities"
VECTOR_SIZE = 384
BATCH_SIZE = 64        # reduced to avoid write timeouts
CHROMA_PATH = "db/chroma"
MAX_RETRIES = 5


def get_chroma_collection():
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    return client.get_or_create_collection(COLLECTION_NAME)


def get_qdrant_client():
    return QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY, timeout=60)


def upsert_with_retry(qdrant: QdrantClient, points: list):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            qdrant.upsert(collection_name=COLLECTION_NAME, points=points)
            return
        except Exception as e:
            if attempt == MAX_RETRIES:
                raise
            wait = 2 ** attempt
            tqdm.write(f"  Retry {attempt}/{MAX_RETRIES} after error: {e!r} — waiting {wait}s")
            time.sleep(wait)


def ensure_qdrant_collection(qdrant: QdrantClient):
    existing = [c.name for c in qdrant.get_collections().collections]
    if COLLECTION_NAME not in existing:
        qdrant.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )
        print(f"Created Qdrant collection: {COLLECTION_NAME}")
    else:
        print(f"Qdrant collection already exists: {COLLECTION_NAME}")


def cve_id_to_int(cve_id: str) -> int:
    """Convert CVE string ID to a stable non-negative integer for Qdrant."""
    return abs(hash(cve_id)) % (2**63)


def migrate():
    chroma_col = get_chroma_collection()
    total = chroma_col.count()
    print(f"ChromaDB source: {total} vectors")

    qdrant = get_qdrant_client()
    ensure_qdrant_collection(qdrant)

    qdrant_existing = qdrant.count(collection_name=COLLECTION_NAME).count
    print(f"Qdrant currently has: {qdrant_existing} vectors")

    if qdrant_existing >= total:
        print("Qdrant already has all vectors. Skipping upload, running verification.")
    else:
        # Resume from where we left off — ChromaDB get() order is stable
        offset = qdrant_existing
        uploaded = 0

        with tqdm(total=total, desc="Migrating", unit="vec", initial=qdrant_existing) as pbar:
            while True:
                batch = chroma_col.get(
                    limit=BATCH_SIZE,
                    offset=offset,
                    include=["embeddings", "metadatas", "documents"],
                )

                ids = batch["ids"]
                if not ids:
                    break

                points = []
                for i, cve_id in enumerate(ids):
                    meta = batch["metadatas"][i]
                    points.append(
                        PointStruct(
                            id=cve_id_to_int(cve_id),
                            vector=batch["embeddings"][i],
                            payload={
                                "cve_id": cve_id,
                                "severity": meta.get("severity"),
                                "cvss_score": meta.get("cvss_score"),
                                "year": meta.get("year"),
                                "vendors": meta.get("vendors"),
                                "products": meta.get("products"),
                                "document": batch["documents"][i],
                            },
                        )
                    )

                upsert_with_retry(qdrant, points)
                uploaded += len(points)
                offset += len(ids)
                pbar.update(len(ids))

                if len(ids) < BATCH_SIZE:
                    break

        print(f"Upload complete. Upserted {uploaded} vectors.")

    # Verification
    print("\nVerifying migration...")
    chroma_count = chroma_col.count()
    qdrant_count = qdrant.count(collection_name=COLLECTION_NAME).count

    if qdrant_count == chroma_count:
        print(f"MIGRATION VERIFIED: {qdrant_count} vectors")
    else:
        raise RuntimeError(
            f"COUNT MISMATCH: ChromaDB={chroma_count}, Qdrant={qdrant_count}. "
            "Re-run the script to resume upload."
        )


if __name__ == "__main__":
    migrate()
