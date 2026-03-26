"""
Stack router — tech stack CVE analysis and AI report streaming.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.stack_analyzer import analyze_stack
from core.llm import build_stack_report_prompt, stream_response

router = APIRouter(tags=["stack"])


class AnalyzeRequest(BaseModel):
    technologies: list[str]


class ReportRequest(BaseModel):
    technologies: list[str]
    analysis: dict


@router.post("/stack/analyze")
def stack_analyze(req: AnalyzeRequest):
    if not req.technologies:
        raise HTTPException(status_code=422, detail="technologies list must not be empty")
    try:
        return analyze_stack(req.technologies)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


async def _sse_report(technologies: list[str], analysis: dict) -> AsyncGenerator[str, None]:
    try:
        system, user = build_stack_report_prompt(analysis, technologies)
        for token in stream_response(system, user):
            if token.startswith("Error:"):
                yield f"data: [ERROR] {token}\n\n"
                return
            yield f"data: {token}\n\n"
    except Exception as exc:
        yield f"data: [ERROR] {exc}\n\n"


@router.post("/stack/report")
def stack_report(req: ReportRequest):
    if not req.technologies:
        raise HTTPException(status_code=422, detail="technologies list must not be empty")
    return StreamingResponse(
        _sse_report(req.technologies, req.analysis),
        media_type="text/event-stream",
    )
