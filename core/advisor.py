"""
Generates structured patch and mitigation recommendations by combining CVE data with LLM reasoning.
"""

import sqlite3
from datetime import date
from typing import List, Dict, Optional, Generator

from config import SQLITE_PATH
from core.retriever import get_cve_by_id
from core.llm import advise


def get_related_by_vendor(vendor: str, exclude_cve_id: str, limit: int = 5) -> List[Dict]:
    """Get CVEs from the same vendor, ordered by CVSS score.
    
    Args:
        vendor: Vendor name to search for
        exclude_cve_id: CVE ID to exclude from results
        limit: Maximum number of results
        
    Returns:
        List of CVE dicts with basic info
    """
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.cve_id, c.severity, c.cvss_score, c.published_date, c.description
            FROM cves c
            JOIN vendors v ON c.cve_id = v.cve_id
            WHERE v.vendor = ? AND c.cve_id != ?
            ORDER BY c.cvss_score DESC
            LIMIT ?
        """, (vendor, exclude_cve_id, limit))
        
        rows = cursor.fetchall()
        results = []
        for row in rows:
            results.append({
                'cve_id': row[0],
                'severity': row[1],
                'cvss_score': row[2],
                'published_date': row[3],
                'description': row[4]
            })
        return results
    finally:
        conn.close()


def get_related_by_product(product: str, exclude_cve_id: str, limit: int = 5) -> List[Dict]:
    """Get CVEs affecting the same product, ordered by CVSS score.
    
    Args:
        product: Product name to search for
        exclude_cve_id: CVE ID to exclude from results
        limit: Maximum number of results
        
    Returns:
        List of CVE dicts with basic info
    """
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.cve_id, c.severity, c.cvss_score, c.published_date, c.description
            FROM cves c
            JOIN products p ON c.cve_id = p.cve_id
            WHERE p.product = ? AND c.cve_id != ?
            ORDER BY c.cvss_score DESC
            LIMIT ?
        """, (product, exclude_cve_id, limit))
        
        rows = cursor.fetchall()
        results = []
        for row in rows:
            results.append({
                'cve_id': row[0],
                'severity': row[1],
                'cvss_score': row[2],
                'published_date': row[3],
                'description': row[4]
            })
        return results
    finally:
        conn.close()


def compute_risk_summary(cve: Dict) -> Dict:
    """Compute structured risk assessment from CVE data.
    
    Args:
        cve: Full CVE dict from database
        
    Returns:
        Risk summary dict with level, color, urgency, etc.
    """
    severity = cve.get('severity')
    cvss_score = cve.get('cvss_score')
    
    # Determine risk level
    if severity:
        if severity == 'CRITICAL':
            risk_level = 'CRITICAL'
        elif severity == 'HIGH':
            risk_level = 'HIGH'
        elif severity == 'MEDIUM':
            risk_level = 'MEDIUM'
        elif severity == 'LOW':
            risk_level = 'LOW'
        else:
            risk_level = 'UNKNOWN'
    else:
        # Fallback to CVSS score
        if cvss_score is not None:
            if cvss_score >= 9.0:
                risk_level = 'CRITICAL'
            elif cvss_score >= 7.0:
                risk_level = 'HIGH'
            elif cvss_score >= 4.0:
                risk_level = 'MEDIUM'
            elif cvss_score > 0:
                risk_level = 'LOW'
            else:
                risk_level = 'UNKNOWN'
        else:
            risk_level = 'UNKNOWN'
    
    # Risk colors and urgencies
    risk_colors = {
        'CRITICAL': '#FF4444',
        'HIGH': '#FF8800',
        'MEDIUM': '#FFCC00',
        'LOW': '#44AA44',
        'UNKNOWN': '#888888'
    }
    
    urgencies = {
        'CRITICAL': 'Patch immediately',
        'HIGH': 'Patch within 7 days',
        'MEDIUM': 'Patch within 30 days',
        'LOW': 'Monitor',
        'UNKNOWN': 'Assess manually'
    }
    
    # Age calculation
    published_date = cve.get('published_date')
    age_days = -1
    is_recent = False
    
    if published_date:
        try:
            pub_date = date.fromisoformat(published_date)
            today = date.today()
            age_days = (today - pub_date).days
            is_recent = age_days <= 365
        except ValueError:
            pass  # Invalid date format
    
    return {
        'risk_level': risk_level,
        'risk_color': risk_colors[risk_level],
        'urgency': urgencies[risk_level],
        'cvss_score': cvss_score,
        'age_days': age_days,
        'is_recent': is_recent
    }


def get_full_advisory(cve_id: str) -> Optional[Dict]:
    """Get complete advisory data for a CVE including risk assessment and related CVEs.
    
    Args:
        cve_id: CVE ID to analyze
        
    Returns:
        Full advisory dict or None if CVE not found
    """
    cve = get_cve_by_id(cve_id)
    if not cve:
        return None
    
    risk_summary = compute_risk_summary(cve)
    
    # Get related CVEs (use first vendor/product)
    vendors = cve.get('vendors', [])
    products = cve.get('products', [])
    
    related_by_vendor = []
    if vendors:
        related_by_vendor = get_related_by_vendor(vendors[0], cve_id)
    
    related_by_product = []
    if products:
        related_by_product = get_related_by_product(products[0], cve_id)
    
    return {
        'cve': cve,
        'risk_summary': risk_summary,
        'related_by_vendor': related_by_vendor,
        'related_by_product': related_by_product
    }


def stream_advice(cve_id: str) -> Generator[str, None, None]:
    """Stream LLM-generated advice for a CVE.
    
    Args:
        cve_id: CVE ID to get advice for
        
    Yields:
        Response tokens from LLM
    """
    for token in advise(cve_id):
        yield token


if __name__ == "__main__":
    # Test with Log4Shell CVE
    advisory = get_full_advisory("CVE-2021-44228")
    if advisory:
        print(f"CVE: {advisory['cve']['cve_id']}")
        print(f"Risk Level: {advisory['risk_summary']['risk_level']}")
        print(f"Urgency: {advisory['risk_summary']['urgency']}")
        print(f"Related by vendor: {len(advisory['related_by_vendor'])} CVEs")
        print(f"Related by product: {len(advisory['related_by_product'])} CVEs")
    else:
        print("CVE-2021-44228 not found in database")