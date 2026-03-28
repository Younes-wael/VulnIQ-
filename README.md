---
title: VulnLens
emoji: 🔐
colorFrom: red
colorTo: orange
sdk: docker
app_port: 7860
pinned: false
---

# VulnLens

**Vulnerability intelligence platform powered by RAG, grounded in NVD data.**

VulnLens combines a local NVD dataset with semantic search and a Groq-hosted LLM to answer vulnerability questions, score CVE exposure, monitor vendors, and generate exportable reports — without hallucinating CVE IDs.

---

## Features

| Module | Description |
|--------|-------------|
| **Chat** | RAG-powered Q&A with streaming responses and source citations. Answers are grounded in the local NVD dataset — every CVE ID cited exists in the database. |
| **Search** | Filter 200 k+ CVEs by severity, year range, vendor, CVSS score, and keyword. Results export to CSV with active filters applied. |
| **Dashboard** | Interactive charts: CVE volume per year, severity distribution, top 15 affected vendors, CVSS score histogram, severity trend over time. Watchlist alert status surfaced inline. |
| **Patch Advisor** | Enter any CVE ID to get structured risk data (CVSS, age, urgency) and streamed AI remediation advice. Exports to a formatted PDF including the AI narrative. |
| **Stack Analysis** | Submit a technology list and receive CVE exposure metrics, a top-risk technology breakdown with EPSS scores, and a streamed AI risk report. Exports to PDF. |
| **SBOM Scanner** | Upload a dependency file (requirements.txt, package.json, pom.xml, .csproj, CycloneDX JSON) and instantly surface all known CVEs across your packages. Exports to PDF. |
| **Watchlists** | Define vendors, products, or keywords to monitor. Delivers webhook alerts and configurable digest emails when new CVEs match your criteria. |

---

## Architecture

```
Browser (React/Vite)
        │  REST + SSE
        ▼
FastAPI backend  ──►  SQLite (structured CVE data)
        │        ──►  ChromaDB (vector embeddings)
        │        ──►  Groq API (LLM inference)
        │
        ▼
APScheduler (watchlist digest jobs, 24 h interval)
```

The data pipeline is a separate, one-time ETL process that populates SQLite and ChromaDB from the NVD REST API 2.0. The application layer never calls NVD at runtime.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, Vite, React Router, Tailwind CSS |
| Charts | Recharts |
| Markdown rendering | react-markdown + remark-gfm |
| API server | FastAPI, Uvicorn |
| Streaming | Server-Sent Events via FastAPI `StreamingResponse` |
| PDF export | ReportLab |
| Background jobs | APScheduler (`AsyncIOScheduler`) |
| Vector store | ChromaDB (persistent, local) |
| Structured store | SQLite (WAL mode, thread-local connection pool) |
| Embeddings | sentence-transformers `all-MiniLM-L6-v2` |
| LLM | Groq — `llama-3.3-70b-versatile` |
| Data source | NVD REST API 2.0 |
| EPSS scores | FIRST.org API |

---

## Prerequisites

- Python 3.10+
- Node.js 18+
- A free [Groq API key](https://console.groq.com)
- 4 GB RAM recommended (ChromaDB + sentence-transformers)

---

## Installation

**1. Clone the repository**

```bash
git clone <repo-url>
cd cve-assistant
```

**2. Install Python dependencies**

```bash
pip install -r requirements.txt
```

**3. Install frontend dependencies**

```bash
cd frontend && npm install && cd ..
```

**4. Configure environment**

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_key_here
```

Obtain a free key at [console.groq.com](https://console.groq.com). The `.env` file is excluded by `.gitignore` — do not commit it.

---

## Running the Application

### Quick start

```bat
start.bat
```

```powershell
.\start.ps1
```

Both scripts open two terminal windows: the FastAPI backend on port `8000` and the React dev server on port `5173`.

### Manual start

**Terminal 1 — backend:**

```bash
python -m uvicorn backend.main:app --reload
```

**Terminal 2 — frontend:**

```bash
cd frontend && npm run dev
```

Open **http://localhost:5173** in your browser.

> Search, Dashboard, SBOM Scanner, and Watchlists work without a Groq key. Chat, Patch Advisor, and Stack Analysis require `GROQ_API_KEY`.

---

## Data Pipeline

Run the full ETL pipeline once before starting the application:

```bash
python run_pipeline.py
```

| Step | Module | Action |
|------|--------|--------|
| 1 | `pipeline/download.py` | Fetches CVE JSON from NVD REST API 2.0 by year |
| 2 | `pipeline/parse.py` | Cleans and structures raw records |
| 3 | `pipeline/ingest.py` | Populates SQLite (`db/cve.sqlite`) |
| 4 | `pipeline/embed.py` | Generates embeddings and persists to ChromaDB (`db/chroma/`) |

Individual steps can be run in isolation:

```bash
python -m pipeline.download
python -m pipeline.parse
python -m pipeline.ingest
python -m pipeline.embed
```

Step 4 is incremental — already-embedded CVEs are skipped on subsequent runs.

### Year range

Configure the pipeline scope in [`config.py`](config.py):

```python
PIPELINE_START_YEAR = 2020   # adjust as needed
PIPELINE_END_YEAR   = 2024
```

For a quick test run, use a single year. For the full dataset, `2015`–`2024` covers the majority of NVD records.

---

## Export

All three export formats are generated server-side and returned as file downloads:

| Page | Format | Endpoint |
|------|--------|----------|
| Search | CSV | `GET /api/search/export` |
| Patch Advisor | PDF | `POST /api/advisor/{cve_id}/export` |
| Stack Analysis | PDF | `POST /api/stack/export` |
| SBOM Scanner | PDF | `POST /api/sbom/export` |

The Patch Advisor and Stack Analysis PDFs include the AI narrative if it has been generated in the session. The AI text is sent from the browser — the server does not re-invoke the LLM during export.

---

## Watchlists

Watchlists monitor CVE activity for a set of vendors, products, or keywords.

- **Alert delivery:** HTTP POST to a webhook URL of your choice (Slack incoming webhooks, custom endpoints, etc.)
- **Scheduling:** APScheduler runs a digest check every 24 hours on backend startup
- **Manual trigger:** Each watchlist has a "Test" action that fires an alert immediately without waiting for the scheduled run

Watchlist state is persisted in the SQLite database alongside CVE data.

---

## Stack Analysis — Usage Notes

Input technologies one per line:

```
django
openssl
nginx
postgresql
redis
```

- Use specific names rather than broad terms (`exchange` instead of `microsoft`, `spring` instead of `java`)
- Terms shorter than three characters are skipped
- Results are potential matches from a local dataset — verify against official advisories
- Use `pip audit`, `trivy`, or `snyk` for production-grade SCA

---

## Project Structure

```
cve-assistant/
├── config.py                    # Model, paths, year range
├── run_pipeline.py              # Runs the full ETL pipeline
├── requirements.txt
├── landing.html                 # Standalone marketing page (no build step)
│
├── backend/
│   ├── main.py                  # FastAPI application, router registration, scheduler lifecycle
│   ├── scheduler.py             # APScheduler setup, watchlist digest job
│   └── routers/
│       ├── chat.py              # POST /api/chat — RAG chat, SSE streaming
│       ├── search.py            # GET /api/search, GET /api/search/export
│       ├── advisor.py           # GET /api/advisor/{id}, POST /api/advisor/{id}/advice, POST /api/advisor/{id}/export
│       ├── stack.py             # POST /api/stack/analyze, POST /api/stack/report, POST /api/stack/export
│       ├── sbom.py              # POST /api/sbom/scan, POST /api/sbom/export
│       ├── watchlists.py        # CRUD /api/watchlists, webhook delivery
│       ├── stats.py             # GET /api/stats
│       └── trends.py            # GET /api/trends/*
│
├── core/
│   ├── db.py                    # SQLite connection pool, schema creation
│   ├── retriever.py             # ChromaDB semantic search, exact CVE lookup
│   ├── llm.py                   # Groq client, prompt builders, stream_response
│   ├── advisor.py               # Risk scoring, related CVE lookup
│   └── stack_analyzer.py        # Tech-to-CVE matching, EPSS enrichment, risk scoring
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Layout.jsx       # App shell, mobile sidebar
│   │   │   ├── Sidebar.jsx      # Navigation
│   │   │   ├── SeverityBadge.jsx
│   │   │   └── MetricTile.jsx
│   │   ├── pages/
│   │   │   ├── Home.jsx
│   │   │   ├── Chat.jsx
│   │   │   ├── Search.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Advisor.jsx
│   │   │   ├── StackAnalysis.jsx
│   │   │   ├── SBOMScanner.jsx
│   │   │   └── Watchlists.jsx
│   │   └── lib/
│   │       └── api.js           # Fetch helpers, SSE readers, export functions
│   └── package.json
│
├── pipeline/
│   ├── download.py
│   ├── parse.py
│   ├── ingest.py
│   └── embed.py
│
└── db/
    ├── cve.sqlite               # Structured CVE data
    └── chroma/                  # ChromaDB vector store
```

---

## Data Source

Data is sourced from the **National Vulnerability Database (NVD)** via the [NVD REST API 2.0](https://nvd.nist.gov/developers/vulnerabilities) and is freely available under the [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use). This project is not affiliated with NIST.
