# VulnLens — Vulnerability Intelligence Platform

A RAG-powered vulnerability intelligence platform built on NVD data. Ask natural language questions about CVEs, explore security trends through interactive visualizations, receive AI-driven patch recommendations, and analyze your entire tech stack — all grounded in real NVD data, no hallucinated CVE IDs.

A standalone marketing page is available at [`landing.html`](landing.html) — open it directly in any browser, no build step needed.

---

## Features

| Page | Description |
|------|-------------|
| **Home** | Live stats, recent critical CVEs, quick-action shortcuts to every tool |
| **Chat** | RAG-powered Q&A with streaming responses, source citations, and severity/vendor filters |
| **Search** | Filter 200k+ CVEs by severity, year, vendor, CVSS score, and keyword — with inline result rows and removable filter pills |
| **Dashboard** | Interactive Recharts visualizations: CVE trends, severity distributions, top vendors |
| **Patch Advisor** | Enter any CVE ID to get structured risk data and AI-generated remediation advice (streamed) |
| **Stack Analysis** | Input your tech stack and get CVE exposure metrics, top-risk technology breakdown, and a full AI risk report (streamed) |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| React UI | Vite + React 18 + React Router + Tailwind CSS |
| Markdown rendering | react-markdown v9 + remark-gfm (tables, GFM) |
| Charts | Recharts |
| API Backend | FastAPI + Uvicorn |
| Streaming | SSE (Server-Sent Events) via FastAPI `StreamingResponse` |
| Vector DB | ChromaDB (persistent, local) |
| Structured DB | SQLite |
| Embeddings | sentence-transformers (`all-MiniLM-L6-v2`) |
| LLM | Groq (`llama-3.3-70b-versatile`) |
| Data Source | NVD REST API 2.0 (nvd.nist.gov) |
| EPSS scores | FIRST.org API |
| Legacy UI | Streamlit (still functional via `streamlit run app.py`) |

---

## Prerequisites

- Python 3.10+
- Node.js 18+ (for the React frontend)
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

**3. Install React frontend dependencies**
```bash
cd frontend
npm install
cd ..
```

**4. Set your Groq API key**

Create a `.env` file in the project root:
```
GROQ_API_KEY=your_key_here
```

> Get a free API key at [console.groq.com](https://console.groq.com). Never commit your `.env` file — it is already excluded by `.gitignore`.

---

## Running the App

### Option A — Quick start (both servers at once)

```bat
start.bat
```

Or in PowerShell:
```powershell
.\start.ps1
```

This opens two terminal windows: FastAPI backend on `:8000` and React frontend on `:5173`.

### Option B — Manual (two terminals)

**Terminal 1 — FastAPI backend:**
```bash
python -m uvicorn backend.main:app --reload
```

**Terminal 2 — React frontend:**
```bash
cd frontend
npm run dev
```

Open your browser at **http://localhost:5173**

### Option C — Streamlit only (original UI)

```bash
streamlit run app.py
```

Open your browser at **http://localhost:8501**

> The Search and Dashboard pages work without a Groq key. Chat, Patch Advisor, and Stack Analysis require `GROQ_API_KEY` to be set.

---

## Configuration

All settings are in [`config.py`](config.py):

```python
GROQ_MODEL          = "llama-3.3-70b-versatile"  # LLM for chat, advisor, and stack reports
PIPELINE_START_YEAR = 2023                         # First year to download/process
PIPELINE_END_YEAR   = 2023                         # Last year (inclusive)
```

> **Tip:** For quick testing, keep the year range to a single year. For the full dataset, set `PIPELINE_START_YEAR = 2015` and `PIPELINE_END_YEAR = 2026`.

---

## Running the Data Pipeline

```bash
python run_pipeline.py
```

This runs all four steps in order:

| Step | Script | Description |
|------|--------|-------------|
| 1 | `pipeline/download.py` | Fetches CVE data from NVD REST API 2.0 per year |
| 2 | `pipeline/parse.py` | Parses and cleans raw JSON into structured CVE records |
| 3 | `pipeline/ingest.py` | Populates SQLite with structured data |
| 4 | `pipeline/embed.py` | Generates vector embeddings and stores them in ChromaDB |

You can also run individual steps:
```bash
python -m pipeline.download
python -m pipeline.parse
python -m pipeline.ingest
python -m pipeline.embed
```

> Step 4 (embedding) is slower on first run but skips already-embedded CVEs on subsequent runs.

---

## Project Structure

```
cve-assistant/
├── landing.html              # Standalone marketing page (no build needed)
├── config.py                 # All settings: model, paths, year range
├── run_pipeline.py           # Runs the full ETL pipeline in one command
├── requirements.txt          # Python dependencies
├── .env                      # API keys (not committed)
│
├── backend/
│   ├── main.py               # FastAPI app entry point
│   └── routers/
│       ├── chat.py           # /api/chat — RAG chat with SSE streaming
│       ├── search.py         # /api/search — structured CVE search
│       ├── advisor.py        # /api/advisory — Patch Advisor (SSE streaming)
│       ├── stack.py          # /api/stack — stack analysis + AI report (SSE streaming)
│       ├── stats.py          # /api/stats — aggregate counts and averages
│       └── trends.py         # /api/trends — time-series data for Dashboard charts
│
├── frontend/
│   ├── index.html
│   ├── src/
│   │   ├── components/
│   │   │   ├── Sidebar.jsx   # Navigation with SVG icons and colored accent bars
│   │   │   ├── Layout.jsx    # App shell with mobile hamburger menu
│   │   │   ├── CVECard.jsx   # Severity-colored CVE card with hover effect
│   │   │   ├── SeverityBadge.jsx  # Inline severity chip (CRITICAL/HIGH/MEDIUM/LOW)
│   │   │   └── MetricTile.jsx     # Stat tile with top accent line
│   │   ├── pages/
│   │   │   ├── Home.jsx      # Hero, live stats, recent critical CVEs, quick actions
│   │   │   ├── Chat.jsx      # Streaming chat with welcome state and example cards
│   │   │   ├── Search.jsx    # CVE search with inline rows and removable filter pills
│   │   │   ├── Dashboard.jsx # Recharts visualizations
│   │   │   ├── Advisor.jsx   # CVE lookup with streamed AI advice (ReactMarkdown)
│   │   │   └── StackAnalysis.jsx  # Stack input, top risk tech breakdown, streamed AI report
│   │   └── lib/
│   │       └── api.js        # All API calls and SSE stream readers
│   └── package.json
│
├── core/
│   ├── retriever.py          # ChromaDB semantic search and SQLite exact lookup
│   ├── llm.py                # Groq streaming, prompt builders for chat/advisor/stack
│   └── advisor.py            # Risk scoring, EPSS lookup, related CVE analysis
│
├── pipeline/
│   ├── download.py           # Fetches raw CVE JSON from NVD API 2.0
│   ├── parse.py              # Cleans and structures raw data
│   ├── ingest.py             # Loads structured data into SQLite
│   └── embed.py              # Embeds CVE text and stores in ChromaDB
│
├── pages/                    # Streamlit pages (legacy UI)
│   ├── 1_Chat.py
│   ├── 2_Search.py
│   ├── 3_Visualizations.py
│   ├── 4_Patch_Advisor.py
│   └── 5_Stack_Analysis.py
│
└── db/
    ├── cve.sqlite            # Structured CVE database
    └── chroma/               # ChromaDB vector store
```

---

## Stack Analysis

Input your technologies one per line:

```
django
openssl
nginx
postgresql
redis
```

Returns:
- CVE match counts per technology with severity breakdown
- Top-risk technology ranking (sorted by critical CVE count)
- EPSS exploitation probability scores from FIRST.org
- Composite risk score per CVE (CVSS × weight + EPSS × weight + recency)
- AI-generated risk report streamed in real-time with markdown formatting

**Known limitations:**
- Broad terms like `microsoft` or `java` match too many rows — use specific names (`exchange`, `spring`, `iis`)
- Terms shorter than 3 characters are skipped automatically
- Results are potential matches from a local dataset only — verify against official advisories and use `pip audit`, `trivy`, or `snyk` for production

---

## Data Source

**National Vulnerability Database (NVD)** — [nvd.nist.gov](https://nvd.nist.gov)

Data is fetched via the NVD REST API 2.0 and is freely available under the [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use). This project is not affiliated with NIST.
