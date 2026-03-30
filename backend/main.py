"""
FastAPI backend entry point for the CVE Assistant project.
Run with: uvicorn backend.main:app --reload
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# ── Safe router imports — a broken router must not kill the whole app ─────────

_routers_loaded = {}

def _safe_import(label, import_fn):
    try:
        result = import_fn()
        _routers_loaded[label] = "OK"
        return result
    except Exception as exc:
        _routers_loaded[label] = f"FAILED: {exc}"
        print(f"[IMPORT] {label} failed to load: {exc}")
        return None

chat_router        = _safe_import("chat",          lambda: __import__("backend.routers.chat",           fromlist=["router"]).router)
search_router      = _safe_import("search",        lambda: __import__("backend.routers.search",         fromlist=["router"]).router)
viz_router         = _safe_import("visualizations",lambda: __import__("backend.routers.visualizations", fromlist=["router"]).router)
advisor_router     = _safe_import("advisor",       lambda: __import__("backend.routers.advisor",        fromlist=["router"]).router)
stack_router       = _safe_import("stack",         lambda: __import__("backend.routers.stack",          fromlist=["router"]).router)
sbom_router        = _safe_import("sbom",          lambda: __import__("backend.routers.sbom",           fromlist=["router"]).router)
watchlists_router  = _safe_import("watchlists",    lambda: __import__("backend.routers.watchlists",     fromlist=["router"]).router)

_scheduler_start = None
_scheduler_stop  = None
try:
    from backend.scheduler import start as _scheduler_start, stop as _scheduler_stop
    _routers_loaded["scheduler"] = "OK"
except Exception as exc:
    _routers_loaded["scheduler"] = f"FAILED: {exc}"
    print(f"[IMPORT] scheduler failed to load: {exc}")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="CVE Assistant API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in [chat_router, search_router, viz_router, advisor_router,
               stack_router, sbom_router, watchlists_router]:
    if router is not None:
        app.include_router(router, prefix="/api")


@app.on_event("startup")
async def _startup():
    # ── Diagnostics ──────────────────────────────────────────────────────────
    print(f"[STARTUP] Python {sys.version}")
    print(f"[STARTUP] Working directory: {os.getcwd()}")

    env_keys = ["GROQ_API_KEY", "QDRANT_URL", "QDRANT_API_KEY", "PORT", "WEBSITES_PORT"]
    for key in env_keys:
        present = key in os.environ and bool(os.environ[key])
        print(f"[STARTUP] ENV {key}: {'SET' if present else 'NOT SET'}")

    for dep in ["fastapi", "uvicorn", "groq", "qdrant_client", "sentence_transformers",
                "apscheduler", "reportlab", "pandas"]:
        try:
            __import__(dep)
            print(f"[STARTUP] DEP {dep}: OK")
        except ImportError as exc:
            print(f"[STARTUP] DEP {dep}: MISSING — {exc}")

    from config import SQLITE_PATH
    from core.db import _is_valid_sqlite
    exists = os.path.exists(SQLITE_PATH)
    if exists:
        size = os.path.getsize(SQLITE_PATH)
        valid = _is_valid_sqlite(SQLITE_PATH)
        print(f"[STARTUP] SQLite: {SQLITE_PATH} — exists=True size={size}B valid={valid}")
    else:
        print(f"[STARTUP] SQLite: {SQLITE_PATH} — NOT FOUND")

    for label, status in _routers_loaded.items():
        print(f"[STARTUP] ROUTER {label}: {status}")

    # ── Start scheduler ───────────────────────────────────────────────────────
    if _scheduler_start is not None:
        try:
            _scheduler_start()
        except Exception as exc:
            print(f"[STARTUP] scheduler start failed: {exc}")


@app.on_event("shutdown")
async def _shutdown():
    if _scheduler_stop is not None:
        try:
            _scheduler_stop()
        except Exception:
            pass


@app.get("/api/health")
def health():
    return {"status": "ok", "routers": _routers_loaded}


# ── Serve React build (must come after all /api routes) ──────────────────────

_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")

if os.path.isdir(_DIST):
    _assets = os.path.join(_DIST, "assets")
    if os.path.isdir(_assets):
        app.mount("/assets", StaticFiles(directory=_assets), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        candidate = os.path.join(_DIST, full_path)
        if os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(_DIST, "index.html"))
