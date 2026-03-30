"""Handles semantic search over Qdrant Cloud — embeds user queries and retrieves top-K most relevant CVE chunks."""

import os
import re
from functools import lru_cache

from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchAny, MatchText

from config import EMBEDDING_MODEL, TOP_K_RETRIEVAL
from core.db import get_db


CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_qdrant_client: QdrantClient | None = None
COLLECTION_NAME = "cve_vulnerabilities"


@lru_cache(maxsize=1)
def get_embedding_model() -> SentenceTransformer:
    """Return the shared embedding model, loading it on first call."""
    return SentenceTransformer(EMBEDDING_MODEL)


def get_qdrant_client() -> QdrantClient:
    """Return the shared Qdrant client, initializing it on first call."""
    global _qdrant_client
    if _qdrant_client is None:
        url = os.environ.get("QDRANT_URL")
        api_key = os.environ.get("QDRANT_API_KEY")
        if not url or not api_key:
            raise RuntimeError("QDRANT_URL and QDRANT_API_KEY must be set in environment")
        _qdrant_client = QdrantClient(url=url, api_key=api_key, timeout=30)
    return _qdrant_client


def _sqlite_result(row) -> dict:
    """Convert a SQLite row (from the cves table) to a retrieve()-compatible dict."""
    cve_id, description, published_date, last_modified, cvss_score, severity, year, vendors_str, products_str = row
    vendors = [v.strip() for v in vendors_str.split(',')] if vendors_str else []
    products = [p.strip() for p in products_str.split(',')] if products_str else []
    return {
        "cve_id": cve_id,
        "document": description or "",
        "severity": severity or "",
        "cvss_score": float(cvss_score) if cvss_score else None,
        "year": int(year) if year else None,
        "vendors": ", ".join(vendors),
        "products": ", ".join(products),
        "relevance_score": 1.0,  # exact match
    }


def _fetch_exact_cves(cve_ids: list[str]) -> list[dict]:
    """Look up specific CVE IDs directly from SQLite."""
    if not cve_ids:
        return []
    conn = get_db()
    placeholders = ",".join("?" * len(cve_ids))
    rows = conn.execute(
        f"SELECT cve_id, description, published_date, last_modified, "
        f"cvss_score, severity, year, vendors, products FROM cves "
        f"WHERE cve_id IN ({placeholders})",
        [c.upper() for c in cve_ids],
    ).fetchall()
    return [_sqlite_result(r) for r in rows]


def _build_qdrant_filter(filters: dict) -> Filter | None:
    """Translate retrieve() filter dict into a Qdrant Filter object."""
    conditions = []

    if filters.get("severities"):
        conditions.append(
            FieldCondition(key="severity", match=MatchAny(any=filters["severities"]))
        )

    if "severity" in filters and not filters.get("severities"):
        conditions.append(
            FieldCondition(key="severity", match=MatchAny(any=[filters["severity"]]))
        )

    # Year is stored as string ('2022') in the payload — enumerate the range
    year_from = filters.get("year_from")
    year_to = filters.get("year_to")
    if year_from or year_to:
        lo = int(year_from) if year_from else 2002
        hi = int(year_to) if year_to else 2024
        year_strings = [str(y) for y in range(lo, hi + 1)]
        conditions.append(
            FieldCondition(key="year", match=MatchAny(any=year_strings))
        )

    if filters.get("vendor"):
        conditions.append(
            FieldCondition(key="vendors", match=MatchText(text=filters["vendor"]))
        )

    if not conditions:
        return None
    if len(conditions) == 1:
        return Filter(must=[conditions[0]])
    return Filter(must=conditions)


def retrieve(query: str, top_k: int = None, filters: dict = None) -> list[dict]:
    """Retrieve top-K most relevant CVE chunks for a query.

    If the query contains explicit CVE IDs (e.g. CVE-2021-44228), those are
    fetched directly from SQLite so the LLM always receives the right record.
    Remaining slots are filled with semantic search results from Qdrant.

    Args:
        query: Search query string
        top_k: Number of results to return (default: TOP_K_RETRIEVAL)
        filters: Optional dict with filter criteria

    Returns:
        List of result dictionaries with keys:
        cve_id, document, severity, cvss_score, year, vendors, products, relevance_score
    """
    if top_k is None:
        top_k = TOP_K_RETRIEVAL

    # --- 1. Exact CVE ID lookup ---
    mentioned_ids = [m.upper() for m in CVE_ID_PATTERN.findall(query)]
    exact_results = _fetch_exact_cves(mentioned_ids) if mentioned_ids else []
    exact_ids = {r["cve_id"] for r in exact_results}

    # How many more slots do we need from semantic search?
    semantic_top_k = max(top_k - len(exact_results), 0)

    semantic_results = []
    if semantic_top_k > 0:
        model = get_embedding_model()
        embedding = model.encode([query])[0].tolist()

        qdrant_filter = _build_qdrant_filter(filters) if filters else None

        client = get_qdrant_client()
        response = client.query_points(
            collection_name=COLLECTION_NAME,
            query=embedding,
            limit=semantic_top_k,
            query_filter=qdrant_filter,
            with_payload=True,
        )

        for hit in response.points:
            payload = hit.payload
            cve_id = payload.get("cve_id", "")
            if cve_id in exact_ids:
                continue
            cvss_raw = payload.get("cvss_score")
            year_raw = payload.get("year")
            semantic_results.append({
                "cve_id": cve_id,
                "document": payload.get("document", ""),
                "severity": payload.get("severity", ""),
                "cvss_score": float(cvss_raw) if cvss_raw else None,
                "year": int(year_raw) if year_raw else None,
                "vendors": payload.get("vendors", ""),
                "products": payload.get("products", ""),
                "relevance_score": round(float(hit.score), 4),
            })

    # Exact matches first, then semantic results
    return exact_results + semantic_results


def get_cve_by_id(cve_id: str) -> dict | None:
    """Fetch a single CVE by exact ID from SQLite database.

    Args:
        cve_id: CVE ID to lookup

    Returns:
        CVE dict or None if not found
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cve_id, description, published_date, last_modified,
               cvss_score, severity, year, vendors, products
        FROM cves WHERE cve_id = ?
    """, (cve_id,))

    row = cursor.fetchone()
    if row:
        cve_id, description, published_date, last_modified, cvss_score, severity, year, vendors_str, products_str = row

        vendors = [v.strip() for v in vendors_str.split(',')] if vendors_str else []
        products = [p.strip() for p in products_str.split(',')] if products_str else []

        return {
            "cve_id": cve_id,
            "description": description,
            "published_date": published_date,
            "last_modified": last_modified,
            "cvss_score": cvss_score,
            "severity": severity,
            "year": year,
            "vendors": vendors,
            "products": products,
        }
    return None


def format_context(results: list[dict]) -> str:
    """Format retrieval results as context string for LLM prompts.

    Args:
        results: List of result dicts from retrieve()

    Returns:
        Formatted context string
    """
    if not results:
        return "No relevant CVEs found."

    context = ""
    for result in results:
        cve_id = result['cve_id']
        severity = result['severity']
        cvss_score = result['cvss_score'] if result['cvss_score'] is not None else 'N/A'
        vendors = result['vendors']
        products = result['products']

        description = result['document']

        context += f"[{cve_id}] Severity: {severity} | CVSS: {cvss_score}\n"
        context += f"Vendors: {vendors} | Products: {products}\n"
        context += f"Description: {description}\n"
        context += "---\n"

    return context
