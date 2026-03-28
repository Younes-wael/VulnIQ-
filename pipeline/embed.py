"""Chunks CVE descriptions, generates embeddings using sentence-transformers, and stores them in ChromaDB."""

import json
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

from config import EMBEDDING_MODEL, CHROMA_PATH, PROCESSED_DATA_PATH, PIPELINE_START_YEAR, PIPELINE_END_YEAR


def get_chroma_collection() -> chromadb.Collection:
    """Initialize ChromaDB persistent client and get/create collection.
    
    Returns:
        ChromaDB collection for CVE vulnerabilities
    """
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_or_create_collection(
        name="cve_vulnerabilities",
        metadata={"hnsw:space": "cosine"},
    )
    return collection


def build_chunk(cve: dict) -> str:
    """Build enriched text chunk from CVE data for embedding.
    
    Args:
        cve: CVE dictionary
        
    Returns:
        Formatted text chunk string
    """
    cve_id = cve.get('cve_id', 'Unknown')
    severity = cve.get('severity', 'Unknown')
    cvss_score = str(cve.get('cvss_score', 'Unknown'))
    vendors = ', '.join(cve.get('vendors', [])) if cve.get('vendors') else 'Unknown'
    products = ', '.join(cve.get('products', [])) if cve.get('products') else 'Unknown'
    published_date = cve.get('published_date', 'Unknown')
    description = cve.get('description', 'Unknown')
    
    chunk = f"""CVE ID: {cve_id}
Severity: {severity}
CVSS Score: {cvss_score}
Vendors: {vendors}
Products: {products}
Published: {published_date}
Description: {description}"""
    
    return chunk


def embed_file(collection: chromadb.Collection, model: SentenceTransformer, year: int) -> tuple[int, int, int]:
    """Load and embed CVEs from one processed JSON file.

    Args:
        collection: ChromaDB collection
        model: Pre-loaded SentenceTransformer embedding model
        year: Year to process

    Returns:
        Tuple of (embedded, skipped, failed) counts
    """
    processed_file = Path(PROCESSED_DATA_PATH) / f"cves-{year}.json"
    if not processed_file.exists():
        print(f"Processed file for {year} not found: {processed_file}")
        return 0, 0, 0

    try:
        with open(processed_file, 'r', encoding='utf-8') as f:
            cves = json.load(f)
        
        embedded = 0
        skipped = 0
        failed = 0
        
        # Batch processing variables
        batch_size = 100
        ids_batch = []
        embeddings_batch = []
        documents_batch = []
        metadatas_batch = []
        
        def add_batch():
            """Add current batch to collection."""
            if ids_batch:
                collection.add(
                    ids=ids_batch,
                    embeddings=embeddings_batch,
                    documents=documents_batch,
                    metadatas=metadatas_batch
                )
        
        for cve in tqdm(cves, desc=f"Embedding {year}", unit="CVEs"):
            try:
                cve_id = cve['cve_id']
                
                # Check if already exists
                existing = collection.get(ids=[cve_id])
                if existing['ids']:
                    skipped += 1
                    continue
                
                # Build chunk and embed
                chunk = build_chunk(cve)
                embedding = model.encode([chunk])[0]
                
                # Prepare metadata (all strings)
                metadata = {
                    'cve_id': cve_id,
                    'severity': cve.get('severity') or '',
                    'cvss_score': str(cve.get('cvss_score') or ''),
                    'year': str(cve.get('year') or ''),
                    'vendors': ', '.join(cve.get('vendors', [])),
                    'products': ', '.join(cve.get('products', []))
                }
                
                # Add to batch
                ids_batch.append(cve_id)
                embeddings_batch.append(embedding.tolist())
                documents_batch.append(chunk)
                metadatas_batch.append(metadata)
                
                # Process batch if full
                if len(ids_batch) >= batch_size:
                    add_batch()
                    ids_batch = []
                    embeddings_batch = []
                    documents_batch = []
                    metadatas_batch = []
                
                embedded += 1
                
            except Exception as e:
                print(f"Failed to embed CVE {cve.get('cve_id', 'unknown')}: {e}")
                failed += 1
        
        # Add remaining batch
        add_batch()
        
        return embedded, skipped, failed
        
    except Exception as e:
        print(f"Error processing {year}: {e}")
        return 0, 0, 0


def embed_all(start_year: int = 2015, end_year: int = 2026) -> None:
    """Embed all processed CVE files into ChromaDB.
    
    Args:
        start_year: First year to embed
        end_year: Last year to embed (inclusive)
    """
    collection = get_chroma_collection()
    model = SentenceTransformer(EMBEDDING_MODEL)

    total_embedded = 0
    total_skipped = 0
    total_failed = 0

    print(f"Embedding CVE data from {start_year} to {end_year}...")

    for year in range(start_year, end_year + 1):
        embedded, skipped, failed = embed_file(collection, model, year)
        
        total_embedded += embedded
        total_skipped += skipped
        total_failed += failed
        
        if embedded + skipped + failed > 0:
            print(f"Year {year}: {embedded} embedded, {skipped} skipped, {failed} failed")
        else:
            print(f"Year {year}: No data to embed")
    
    print(f"\nTotal Summary:")
    print(f"  Embedded: {total_embedded}")
    print(f"  Skipped: {total_skipped}")
    print(f"  Failed: {total_failed}")


def main() -> None:
    """Entry point for the embed pipeline."""
    embed_all(start_year=PIPELINE_START_YEAR, end_year=PIPELINE_END_YEAR)


if __name__ == "__main__":
    main()
