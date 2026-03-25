"""Handles semantic search over ChromaDB — embeds user queries and retrieves top-K most relevant CVE chunks."""

import sqlite3

import chromadb
import streamlit as st
from sentence_transformers import SentenceTransformer

from config import EMBEDDING_MODEL, CHROMA_PATH, TOP_K_RETRIEVAL, SQLITE_PATH


@st.cache_resource
def get_embedding_model() -> SentenceTransformer:
    """Load the embedding model once and cache it across all pages and sessions."""
    return SentenceTransformer(EMBEDDING_MODEL)


@st.cache_resource
def get_collection() -> chromadb.Collection:
    """Initialize ChromaDB once and cache it across all pages and sessions."""
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    return client.get_or_create_collection(name="cve_vulnerabilities")


def retrieve(query: str, top_k: int = None, filters: dict = None) -> list[dict]:
    """Retrieve top-K most relevant CVE chunks for a query.
    
    Args:
        query: Search query string
        top_k: Number of results to return (default: TOP_K_RETRIEVAL)
        filters: Optional dict with filter criteria
        
    Returns:
        List of result dictionaries
    """
    if top_k is None:
        top_k = TOP_K_RETRIEVAL
    
    collection = get_collection()
    model = get_embedding_model()

    # Embed query
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
    results = collection.query(
        query_embeddings=[embedding.tolist()],
        n_results=top_k,
        where=where
    )
    
    # Process results
    processed_results = []
    if results['ids'] and results['ids'][0]:
        ids = results['ids'][0]
        documents = results['documents'][0]
        metadatas = results['metadatas'][0]
        distances = results['distances'][0]
        
        for i in range(len(ids)):
            metadata = metadatas[i]
            relevance_score = round(1 - distances[i], 4)
            
            result = {
                "cve_id": ids[i],
                "document": documents[i],
                "severity": metadata.get('severity', ''),
                "cvss_score": float(metadata.get('cvss_score', 0)) if metadata.get('cvss_score') else None,
                "year": int(metadata.get('year', 0)) if metadata.get('year') else None,
                "vendors": metadata.get('vendors', ''),
                "products": metadata.get('products', ''),
                "relevance_score": relevance_score
            }
            processed_results.append(result)
    
    return processed_results


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
