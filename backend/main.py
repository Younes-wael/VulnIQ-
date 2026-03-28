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

from backend.routers import chat, search, visualizations, advisor, stack, sbom
from backend.routers import watchlists as watchlists_router
from backend.scheduler import start as scheduler_start, stop as scheduler_stop

app = FastAPI(title="CVE Assistant API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat.router,           prefix="/api")
app.include_router(search.router,         prefix="/api")
app.include_router(visualizations.router, prefix="/api")
app.include_router(advisor.router,        prefix="/api")
app.include_router(stack.router,          prefix="/api")
app.include_router(sbom.router,              prefix="/api")
app.include_router(watchlists_router.router, prefix="/api")


@app.on_event("startup")
async def _startup():
    scheduler_start()


@app.on_event("shutdown")
async def _shutdown():
    scheduler_stop()


@app.get("/api/health")
def health():
    return {"status": "ok"}
