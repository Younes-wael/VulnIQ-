"""
Chat router — SSE streaming endpoint backed by RAG pipeline.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from typing import AsyncGenerator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.retriever import retrieve, format_context
from core.llm import build_chat_prompt, stream_response

router = APIRouter(tags=["chat"])


class ChatRequest(BaseModel):
    message: str
    history: list[dict] = []
    filters: dict = {}


async def _sse_stream(message: str, filters: dict) -> AsyncGenerator[str, None]:
    try:
        results = retrieve(message, filters=filters if filters else None)
        context = format_context(results)
        system, user = build_chat_prompt(message, context)

        for token in stream_response(system, user):
            if token.startswith("Error:"):
                yield f"data: [ERROR] {token}\n\n"
                return
            yield f"data: {token}\n\n"

        if results:
            cve_ids = ",".join(r["cve_id"] for r in results)
            yield f"data: [SOURCES] {cve_ids}\n\n"

    except Exception as exc:
        yield f"data: [ERROR] {exc}\n\n"


@router.post("/chat")
def chat(req: ChatRequest):
    return StreamingResponse(
        _sse_stream(req.message, req.filters),
        media_type="text/event-stream",
    )
