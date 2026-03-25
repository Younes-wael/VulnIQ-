# CVE Security Assistant

A RAG-powered vulnerability intelligence platform built on NVD data. Ask natural language questions about CVEs, explore security trends through interactive visualizations, and receive AI-driven patch recommendations — all grounded in real NVD data.

---

## Features

| Page | Description |
|------|-------------|
| **Chat** | Ask natural language questions about CVEs and receive answers grounded in NVD data via RAG |
| **Search** | Filter and browse vulnerabilities by severity, year, vendor, product, and keyword |
| **Visualizations** | Interactive charts for CVE trends, severity distributions, and vendor impact |
| **Patch Advisor** | Structured risk assessments with AI-generated remediation recommendations |
| **Stack Analysis** | Input your tech stack and get a personalised CVE exposure report — find which vulnerabilities may affect you specifically |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| UI | Streamlit |
| Vector DB | ChromaDB (persistent, local) |
| Structured DB | SQLite |
| Embeddings | sentence-transformers (`all-MiniLM-L6-v2`) |
| LLM | Groq (`llama-3.3-70b-versatile`) |
| Charts | Plotly (dark theme) |
| Data Source | NVD REST API 2.0 (nvd.nist.gov) |

---

## Prerequisites

- Python 3.10+
- A free [Groq API key](https://console.groq.com)
- 4 GB+ RAM recommended

---

## Installation

**1. Clone the repository**
```bash
git clone <your-repo-url>
cd cve-assistant
```

**2. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**3. Set your Groq API key**

Create a `.env` file in the project root:
```
GROQ_API_KEY=your_key_here
```

> Get a free API key at [console.groq.com](https://console.groq.com). Never commit your `.env` file — it is already excluded by `.gitignore`.

---

## Configuration

All settings are in [`config.py`](config.py). The most important ones:

```python
GROQ_MODEL          = "llama-3.3-70b-versatile"  # LLM used for chat and patch advice
PIPELINE_START_YEAR = 2023                         # First year to download/process
PIPELINE_END_YEAR   = 2023                         # Last year to download/process (inclusive)
```

> **Tip:** For quick testing, keep the year range to a single year (e.g. 2023 only).
> For the full dataset, set `PIPELINE_START_YEAR = 2015` and `PIPELINE_END_YEAR = 2026`.

---

## Running the Data Pipeline

Run the full pipeline with a single command:

```bash
python run_pipeline.py
```

This executes all four steps in order:

| Step | Script | Description |
|------|--------|-------------|
| 1 | `pipeline/download.py` | Fetches CVE data from the NVD REST API 2.0 for each configured year |
| 2 | `pipeline/parse.py` | Parses and cleans raw JSON into structured CVE records |
| 3 | `pipeline/ingest.py` | Populates SQLite with structured CVE data |
| 4 | `pipeline/embed.py` | Generates vector embeddings and stores them in ChromaDB |

> **Note:** Steps 1–3 are fast. Step 4 (embedding) is slower on first run but skips CVEs that are already embedded on subsequent runs.

You can also run individual steps:
```bash
python -m pipeline.download
python -m pipeline.parse
python -m pipeline.ingest
python -m pipeline.embed
```

---

## Running the App

```bash
streamlit run app.py
```

Open your browser at **http://localhost:8501**

> The Search and Visualizations pages work without a Groq key. Chat and Patch Advisor require `GROQ_API_KEY` to be set.

---

## Project Structure

```
cve-assistant/
├── app.py                    # Streamlit entry point and landing page
├── config.py                 # All settings: model names, paths, year range
├── run_pipeline.py           # Runs the full ETL pipeline in one command
├── requirements.txt          # Python dependencies
├── .env                      # API keys (not committed)
│
├── pipeline/
│   ├── download.py           # Fetches CVE data from NVD REST API 2.0
│   ├── parse.py              # Cleans and structures raw CVE JSON
│   ├── ingest.py             # Populates SQLite database
│   └── embed.py              # Generates and stores vector embeddings
│
├── core/
│   ├── retriever.py          # Semantic search (ChromaDB) and exact lookup (SQLite)
│   ├── llm.py                # Groq connection and streaming response handling
│   └── advisor.py            # Risk scoring and related CVE analysis
│
├── pages/
│   ├── 1_Chat.py             # RAG-powered natural language Q&A
│   ├── 2_Search.py           # Structured CVE search and filtering
│   ├── 3_Visualizations.py   # Interactive Plotly dashboard
│   ├── 4_Patch_Advisor.py    # AI-powered patch recommendations
│   └── 5_Stack_Analysis.py   # Tech stack matcher and AI exposure report
│
├── data/
│   ├── raw/                  # Raw JSON responses from NVD API (per year)
│   └── processed/            # Cleaned CVE records ready for ingestion
│
└── db/
    ├── cve.sqlite            # Structured CVE database (fast filtering and charts)
    └── chroma/               # ChromaDB vector store (semantic search)
```

---

## Stack Analysis

The Stack Analysis page lets you input the technologies your project uses (one per line) and automatically matches them against the local NVD dataset to find potentially relevant CVEs.

Example input:

```
django
openssl
nginx
postgresql
redis
```

The page returns:
- CVE matches per technology with severity and CVSS scores
- EPSS exploitation probability scores from the FIRST.org API
- A composite risk score per CVE (CVSS + EPSS + recency)
- An AI-generated report with cautious, version-aware advice

Known limitations:
- Very broad terms like `microsoft` or `java` may match too many rows. Use specific product names instead (e.g. `exchange`, `iis`, `spring`)
- Terms shorter than 3 characters are automatically skipped
- Results are potential matches from a limited local dataset only. Always verify against official advisories and use `pip audit`, `trivy`, or `snyk` for production environments.

---

## Data Source

**National Vulnerability Database (NVD)** — [nvd.nist.gov](https://nvd.nist.gov)

Data is fetched via the NVD REST API 2.0 and is free and publicly available under the [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use).
