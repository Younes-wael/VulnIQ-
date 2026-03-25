"""
Search & Filter page — browse and filter CVEs by severity, vendor, year, and keyword using SQLite queries.
"""

import sqlite3
import time
from typing import List, Dict, Tuple

import streamlit as st

from config import SQLITE_PATH


def build_query(filters: Dict) -> Tuple[str, List]:
    """Build parameterized SQL query from filters.
    
    Args:
        filters: Dict of filter criteria
        
    Returns:
        Tuple of (SQL string, parameters list)
    """
    base_query = """
        SELECT cve_id, description, published_date, cvss_score, 
               severity, year, vendors, products 
        FROM cves
    """
    
    where_clauses = []
    params = []
    
    # Severity filter
    if 'severities' in filters and filters['severities']:
        placeholders = ','.join(['?'] * len(filters['severities']))
        where_clauses.append(f"severity IN ({placeholders})")
        params.extend(filters['severities'])
    
    # Year range
    if 'year_from' in filters:
        where_clauses.append("year >= ?")
        params.append(filters['year_from'])
    
    if 'year_to' in filters:
        where_clauses.append("year <= ?")
        params.append(filters['year_to'])
    
    # Vendor filter (via vendors table)
    if 'vendor' in filters and filters['vendor'].strip():
        where_clauses.append("cve_id IN (SELECT cve_id FROM vendors WHERE vendor LIKE ?)")
        params.append(f"%{filters['vendor'].strip()}%")
    
    # CVSS score range
    if 'cvss_min' in filters:
        where_clauses.append("cvss_score >= ?")
        params.append(filters['cvss_min'])
    
    if 'cvss_max' in filters:
        where_clauses.append("cvss_score <= ?")
        params.append(filters['cvss_max'])
    
    # Keyword search in description
    if 'keyword' in filters and filters['keyword'].strip():
        where_clauses.append("description LIKE ?")
        params.append(f"%{filters['keyword'].strip()}%")
    
    # Build final query
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)
    
    base_query += " ORDER BY cvss_score DESC NULLS LAST LIMIT 500"
    
    return base_query, params


def run_query(filters: Dict) -> Tuple[List[Dict], float]:
    """Execute query and return results with timing.
    
    Args:
        filters: Filter criteria dict
        
    Returns:
        Tuple of (results list, elapsed time in ms)
    """
    sql, params = build_query(filters)
    
    start_time = time.time()
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
    finally:
        conn.close()
    
    elapsed_ms = (time.time() - start_time) * 1000
    
    # Convert rows to dicts
    results = []
    for row in rows:
        results.append({
            'cve_id': row[0],
            'description': row[1],
            'published_date': row[2],
            'cvss_score': row[3],
            'severity': row[4],
            'year': row[5],
            'vendors': row[6] or '',
            'products': row[7] or ''
        })
    
    return results, elapsed_ms


def render_severity_badge(severity: str) -> str:
    """Render HTML severity badge with color.
    
    Args:
        severity: Severity level string
        
    Returns:
        HTML string for badge
    """
    colors = {
        'CRITICAL': '#FF4444',
        'HIGH': '#FF8800',
        'MEDIUM': '#FFCC00',
        'LOW': '#44AA44'
    }
    color = colors.get(severity, '#888888')
    
    return f'<span style="background:{color};padding:2px 8px;border-radius:4px;color:white;font-weight:bold">{severity}</span>'


def render():
    """Main Streamlit render function."""
    st.set_page_config(page_title="CVE Search", page_icon="🔎", layout="wide")
    
    st.title("🔎 CVE Search & Filter")
    
    # Sidebar filters
    with st.sidebar:
        st.header("🔍 Filters")
        
        severities = st.multiselect(
            "Severity", 
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"], 
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
        
        year_range = st.slider("Year Range", 2015, 2026, (2015, 2026))
        
        vendor = st.text_input("Filter by vendor (e.g. microsoft)")
        
        cvss_range = st.slider("CVSS Score Range", 0.0, 10.0, (0.0, 10.0), 0.1)
        
        keyword = st.text_input("Search in description")
        
        col1, col2 = st.columns(2)
        with col1:
            search_clicked = st.button("Search", type="primary")
        with col2:
            clear_clicked = st.button("Clear Filters")
    
    # Handle search
    if search_clicked:
        filters = {
            'severities': severities,
            'year_from': year_range[0],
            'year_to': year_range[1],
            'vendor': vendor,
            'cvss_min': cvss_range[0],
            'cvss_max': cvss_range[1],
            'keyword': keyword
        }
        
        with st.spinner("Searching..."):
            results, elapsed = run_query(filters)
        
        st.session_state["search_results"] = results
        st.session_state["query_time"] = elapsed
        st.session_state["selected_cve"] = None
    
    # Handle clear
    if clear_clicked:
        st.session_state["search_results"] = []
        st.session_state["selected_cve"] = None
    
    # Display results
    if "search_results" in st.session_state:
        results = st.session_state["search_results"]
        elapsed = st.session_state.get("query_time", 0)
        
        st.write(f"Found {len(results)} results in {elapsed:.1f}ms")
        
        if results:
            # Prepare dataframe data
            df_data = []
            for r in results:
                df_data.append({
                    'CVE ID': r['cve_id'],
                    'Severity': r['severity'],
                    'CVSS Score': r['cvss_score'],
                    'Year': r['year'],
                    'Vendors': r['vendors'][:50] + '...' if len(r['vendors']) > 50 else r['vendors'],
                    'Published Date': r['published_date']
                })
            
            st.dataframe(df_data, use_container_width=True)
            
            # CVE detail selector
            cve_options = ["Select a CVE..."] + [r['cve_id'] for r in results]
            selected = st.selectbox("Select a CVE to view details", cve_options)
            
            if selected != "Select a CVE...":
                cve_data = next((r for r in results if r['cve_id'] == selected), None)
                if cve_data:
                    with st.expander(f"Details for {selected}", expanded=True):
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.markdown(render_severity_badge(cve_data['severity']), unsafe_allow_html=True)
                        
                        with col2:
                            st.write(f"**CVSS Score:** {cve_data['cvss_score'] or 'N/A'}")
                        
                        with col3:
                            st.write(f"**Published:** {cve_data['published_date']}")
                        
                        st.write(f"**Description:** {cve_data['description']}")
                        
                        st.write(f"**Vendors:** {', '.join(cve_data['vendors'].split(', ')) if cve_data['vendors'] else 'None'}")
                        
                        st.write(f"**Products:** {', '.join(cve_data['products'].split(', ')) if cve_data['products'] else 'None'}")
                        
                        st.markdown(f"[View on NVD](https://nvd.nist.gov/vuln/detail/{selected})")
                
                st.session_state["selected_cve"] = selected
        else:
            st.write("No results found. Try adjusting your filters.")


render()