"""Handles semantic search over ChromaDB — embeds user queries and retrieves top-K most relevant CVE chunks."""

import re
import sqlite3

import chromadb
import streamlit as st
from sentence_transformers import SentenceTransformer

from config import EMBEDDING_MODEL, CHROMA_PATH, TOP_K_RETRIEVAL, SQLITE_PATH


CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@st.cache_resource
def get_embedding_model() -> SentenceTransformer:
    """Load the embedding model once and cache it across all pages and sessions."""
    return SentenceTransformer(EMBEDDING_MODEL)


@st.cache_resource
def get_collection() -> chromadb.Collection:
    """Initialize ChromaDB once and cache it across all pages and sessions."""
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    return client.get_or_create_collection(name="cve_vulnerabilities")


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
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        placeholders = ",".join("?" * len(cve_ids))
        rows = conn.execute(
            f"SELECT cve_id, description, published_date, last_modified, "
            f"cvss_score, severity, year, vendors, products FROM cves "
            f"WHERE cve_id IN ({placeholders})",
            [c.upper() for c in cve_ids],
        ).fetchall()
        return [_sqlite_result(r) for r in rows]
    finally:
        conn.close()


def retrieve(query: str, top_k: int = None, filters: dict = None) -> list[dict]:
    """Retrieve top-K most relevant CVE chunks for a query.

    If the query contains explicit CVE IDs (e.g. CVE-2021-44228), those are
    fetched directly from SQLite so the LLM always receives the right record.
    Remaining slots are filled with semantic search results.

    Args:
        query: Search query string
        top_k: Number of results to return (default: TOP_K_RETRIEVAL)
        filters: Optional dict with filter criteria

    Returns:
        List of result dictionaries
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
        collection = get_collection()
        model = get_embedding_model()
        embedding = model.encode([query])[0]

        # Build where clause
        where = None
        if filters:
            conditions = []

            if 'severity' in filters:
                conditions.append({"severity": {"$eq": filters['severity']}})

            if 'year_from' in filters:
                conditions.append({"year": {"$gte": str(filters['year_from'])}})

            if 'year_to' in filters:
                conditions.append({"year": {"$lte": str(filters['year_to'])}})

            if 'vendor' in filters:
                conditions.append({"vendors": {"$contains": filters['vendor']}})

            if len(conditions) == 1:
                where = conditions[0]
            elif len(conditions) > 1:
                where = {"$and": conditions}

        # Query ChromaDB
        raw = collection.query(
            query_embeddings=[embedding.tolist()],
            n_results=semantic_top_k,
            where=where,
        )

        if raw['ids'] and raw['ids'][0]:
            for i in range(len(raw['ids'][0])):
                cve_id = raw['ids'][0][i]
                if cve_id in exact_ids:
                    continue  # already included from exact lookup
                metadata = raw['metadatas'][0][i]
                semantic_results.append({
                    "cve_id": cve_id,
                    "document": raw['documents'][0][i],
                    "severity": metadata.get('severity', ''),
                    "cvss_score": float(metadata.get('cvss_score', 0)) if metadata.get('cvss_score') else None,
                    "year": int(metadata.get('year', 0)) if metadata.get('year') else None,
                    "vendors": metadata.get('vendors', ''),
                    "products": metadata.get('products', ''),
                    "relevance_score": round(1 - raw['distances'][0][i], 4),
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
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, description, published_date, last_modified, 
                   cvss_score, severity, year, vendors, products 
            FROM cves WHERE cve_id = ?
        """, (cve_id,))
        
        row = cursor.fetchone()
        if row:
            cve_id, description, published_date, last_modified, cvss_score, severity, year, vendors_str, products_str = row
            
            # Parse comma-separated strings back to lists
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
                "products": products
            }
        return None
    finally:
        conn.close()


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
        
        # Truncate description to keep prompt small
        description = result['document']
        if len(description) > 200:
            description = description[:200] + "..."
        
        context += f"[{cve_id}] Severity: {severity} | CVSS: {cvss_score}\n"
        context += f"Vendors: {vendors} | Products: {products}\n"
        context += f"Description: {description}\n"
        context += "---\n"
    
    return context
