"""
Advisor router — CVE risk advisory and streaming remediation advice.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from core.advisor import get_full_advisory
from core.llm import advise

router = APIRouter(tags=["advisor"])


@router.get("/advisor/{cve_id}")
def advisory(cve_id: str):
    data = get_full_advisory(cve_id.upper())
    if not data:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found in database")
    return data


async def _sse_advice(cve_id: str) -> AsyncGenerator[str, None]:
    try:
        for token in advise(cve_id):
            if token.startswith("Error:"):
                yield f"data: [ERROR] {token}\n\n"
                return
            yield f"data: {token.replace(chr(10), '\\n')}\n\n"
    except Exception as exc:
        yield f"data: [ERROR] {exc}\n\n"


@router.post("/advisor/{cve_id}/advice")
def stream_advice(cve_id: str):
    return StreamingResponse(
        _sse_advice(cve_id.upper()),
        media_type="text/event-stream",
    )
