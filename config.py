# Configuration settings for the CVE Assistant application

GROQ_MODEL = "llama-3.3-70b-versatile"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Pipeline year range — change these to control which years are processed.
# For quick testing use a single year (e.g. 2023). For full data use 2015–2026.
PIPELINE_START_YEAR = 2023
PIPELINE_END_YEAR = 2023
CHROMA_PATH = "db/chroma"
SQLITE_PATH = "db/cve.sqlite"
RAW_DATA_PATH = "data/raw"
PROCESSED_DATA_PATH = "data/processed"
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TOP_K_RETRIEVAL = 3
CHUNK_SIZE = 500
CHUNK_OVERLAP = 50