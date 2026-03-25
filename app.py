"""
Streamlit entry point for the CVE Assistant application.
"""

import sqlite3

import streamlit as st
from dotenv import load_dotenv
load_dotenv()

from config import SQLITE_PATH

st.set_page_config(
    page_title="CVE Assistant",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🔐 CVE Security Assistant")
st.markdown("---")

# Main content in two columns
col1, col2 = st.columns([2, 1])

with col1:
    st.markdown("""
    A RAG-powered vulnerability intelligence platform built on the
    NVD (National Vulnerability Database). Ask natural language questions
    about CVEs, explore trends, and get AI-powered patch recommendations.
    """)
    
    # Feature cards
    features = [
        ("💬 Chat", "Ask natural language questions about CVEs"),
        ("🔎 Search", "Filter and browse 200k+ vulnerabilities"),
        ("📊 Dashboard", "Visualize CVE trends and severity distributions"),
        ("🛡️ Patch Advisor", "Get AI-powered remediation recommendations")
    ]
    
    for icon_text, desc in features:
        with st.container():
            st.markdown(f"### {icon_text}")
            st.markdown(desc)
            st.markdown("---")

with col2:
    # Quick stats
    try:
        conn = sqlite3.connect(SQLITE_PATH)
        total_cves = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        critical_count = conn.execute("SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL'").fetchone()[0]
        max_year = conn.execute("SELECT MAX(year) FROM cves").fetchone()[0]
        years_covered = max_year - 2015 + 1 if max_year else 0
        conn.close()
        
        st.metric("Total CVEs Indexed", f"{total_cves:,}")
        st.metric("Critical CVEs", f"{critical_count:,}")
        st.metric("Years of Data", years_covered)
        
    except Exception:
        st.info("Run the pipeline first to populate the database")

st.markdown("---")
st.subheader("🚀 Getting Started")
st.markdown("""
1. Run the data pipeline (see README)
2. Start Ollama with your model  
3. Use the sidebar to navigate between pages
""")