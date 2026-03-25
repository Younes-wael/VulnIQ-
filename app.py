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

# ─────────────────────────────────────────
# 1. HERO SECTION
# ─────────────────────────────────────────
st.title("🔐 CVE Security Assistant")
st.markdown("**Instant vulnerability intelligence, powered by RAG and grounded in real NVD data.**")
st.markdown(
    "This platform lets you query the National Vulnerability Database using natural language, "
    "explore CVE trends through interactive dashboards, and receive AI-generated patch recommendations. "
    "Every answer is grounded in real NVD records — no hallucinated CVE IDs, no made-up scores."
)

st.divider()

# ─────────────────────────────────────────
# 2. ABOUT THIS PROJECT
# ─────────────────────────────────────────
st.subheader("About This Project")
st.info(
    "This was built as a portfolio project to demonstrate end-to-end skills in RAG pipeline design, "
    "LLM integration, vector search, and security data engineering. "
    "The pipeline fetches CVE records from the NVD REST API 2.0, embeds them with **sentence-transformers** "
    "into a persistent **ChromaDB** vector store, and stores structured data in **SQLite** for fast filtering. "
    "At query time, the top matching CVEs are retrieved and passed as context to **Groq** "
    "(**llama-3.3-70b-versatile**), which streams a grounded answer back through a **Streamlit** interface."
)

st.divider()

# ─────────────────────────────────────────
# 3. HOW IT WORKS
# ─────────────────────────────────────────
st.subheader("⚙️ How It Works")
st.markdown(
    "`NVD REST API 2.0` → `Raw JSON` → `Parser` → "
    "`SQLite (structured)` + `ChromaDB (vectors)` → `Groq LLM` → `Answer`"
)
st.markdown("""
- **Download** — CVE feeds are fetched year by year from the NVD REST API 2.0 in 90-day chunks.
- **Parse & Ingest** — Records are cleaned, normalised, and loaded into SQLite with indexed vendor and product tables.
- **Embed** — Each CVE description is embedded with `all-MiniLM-L6-v2` and stored in ChromaDB for semantic search.
- **Query** — User questions are embedded, the top-K most relevant CVEs are retrieved, and Groq streams a cited answer.
""")

st.divider()

# ─────────────────────────────────────────
# 4. FEATURE CARDS (2×2 grid)
# ─────────────────────────────────────────
st.subheader("🗂️ Pages")

col1, col2 = st.columns(2)

with col1:
    with st.container(border=True):
        st.markdown("### 💬 Chat")
        st.markdown(
            "Ask natural language questions like *'What Log4j CVEs affect Apache?'* "
            "and get cited answers grounded in NVD data."
        )
    with st.container(border=True):
        st.markdown("### 📊 Dashboard")
        st.markdown(
            "Explore interactive Plotly charts showing CVE trends, severity distributions, "
            "and top affected vendors."
        )

with col2:
    with st.container(border=True):
        st.markdown("### 🔎 Search")
        st.markdown(
            "Filter 79,330+ CVEs by severity, vendor, year, and keyword "
            "with sub-second SQLite queries."
        )
    with st.container(border=True):
        st.markdown("### 🛡️ Patch Advisor")
        st.markdown(
            "Enter any CVE ID and receive a structured risk assessment plus "
            "AI-generated remediation steps."
        )
    with st.container(border=True):
        st.markdown("### 🧱 Stack Analysis")
        st.markdown(
            "Input your tech stack and get a personalized CVE exposure "
            "report — find which vulnerabilities may affect you specifically."
        )

st.divider()

# ─────────────────────────────────────────
# 5. RECENT CRITICAL CVEs
# ─────────────────────────────────────────
st.subheader("🚨 Recent Critical Vulnerabilities")

try:
    conn = sqlite3.connect(SQLITE_PATH)
    rows = conn.execute("""
        SELECT cve_id, published_date, cvss_score, description
        FROM cves
        WHERE severity = 'CRITICAL'
        ORDER BY published_date DESC
        LIMIT 3
    """).fetchall()
    conn.close()

    if not rows:
        st.info("No critical CVEs found. Run the data pipeline first to populate the database.")
    else:
        for cve_id, published_date, cvss_score, description in rows:
            with st.container(border=True):
                st.markdown(f"**{cve_id}**")
                col_a, col_b = st.columns(2)
                col_a.markdown(f"📅 Published: `{published_date}`")
                col_b.markdown(f"⚠️ CVSS Score: `{cvss_score}`")
                excerpt = (description[:200] + "...") if description and len(description) > 200 else description
                st.markdown(excerpt)
                st.markdown(f"[View on NVD](https://nvd.nist.gov/vuln/detail/{cve_id})")

except Exception:
    st.info("Run the data pipeline first to populate the database.")

st.divider()

# ─────────────────────────────────────────
# 6. FOOTER
# ─────────────────────────────────────────
st.caption(
    "© 2026 Younes-wael · Built as a portfolio project · "  # TODO: replace with your name
    "Data sourced from NVD (nvd.nist.gov) · Not affiliated with NIST"
)
