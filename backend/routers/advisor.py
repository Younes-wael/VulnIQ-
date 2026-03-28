"""
Advisor router — CVE risk advisory and streaming remediation advice.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import io
import re
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

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


_URGENCY = {
    "CRITICAL": "Patch immediately",
    "HIGH":     "Patch within 7 days",
    "MEDIUM":   "Patch within 30 days",
    "LOW":      "Monitor and assess",
}

_SEV_COLORS = {
    "CRITICAL": colors.HexColor("#ef4444"),
    "HIGH":     colors.HexColor("#f97316"),
    "MEDIUM":   colors.HexColor("#eab308"),
    "LOW":      colors.HexColor("#22c55e"),
}


class AdvisorExportRequest(BaseModel):
    advice_text: str = ''


@router.post("/advisor/{cve_id}/export")
def export_pdf(cve_id: str, req: AdvisorExportRequest):
    data = get_full_advisory(cve_id.upper())
    if not data:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found in database")

    cve  = data["cve"]
    risk = data["risk_summary"]

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )
    styles = getSampleStyleSheet()

    h1 = ParagraphStyle("H1", parent=styles["Title"],
                         fontSize=20, spaceAfter=4,
                         textColor=colors.HexColor("#1e3a5f"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                         fontSize=11, spaceBefore=12, spaceAfter=6,
                         textColor=colors.HexColor("#374151"))
    body = ParagraphStyle("Body", parent=styles["Normal"],
                           fontSize=9, leading=14,
                           textColor=colors.HexColor("#374151"))
    label = ParagraphStyle("Label", parent=styles["Normal"],
                            fontSize=8, spaceAfter=2,
                            textColor=colors.gray)
    footer = ParagraphStyle("Footer", parent=styles["Normal"],
                             fontSize=7, textColor=colors.gray)

    divider = HRFlowable(width="100%", thickness=0.5,
                          color=colors.HexColor("#e2e8f0"))
    bg_head = colors.HexColor("#f1f5f9")
    bg_alt  = colors.HexColor("#f8fafc")
    grid_c  = colors.HexColor("#e2e8f0")
    sev_color = _SEV_COLORS.get(cve.get("severity", ""), colors.gray)

    story = []

    # ── Header ──
    story.append(Paragraph("VulnLens Advisory Report", h1))
    story.append(Paragraph(f"Generated for {cve.get('cve_id', cve_id.upper())}", label))
    story.append(divider)
    story.append(Spacer(1, 12))

    # ── Risk assessment ──
    story.append(Paragraph("Risk Assessment", h2))
    risk_rows = [
        ["Risk Level", "CVSS Score", "Age (days)", "Recommended Action"],
        [
            risk.get("risk_level", "—"),
            str(risk.get("cvss_score") or "—"),
            str(risk.get("age_days", "—")),
            _URGENCY.get(risk.get("risk_level", ""), "Assess manually"),
        ],
    ]
    rt = Table(risk_rows, colWidths=[3.5 * cm, 3 * cm, 3 * cm, 7 * cm])
    rt.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), bg_head),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#475569")),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_alt]),
        ("GRID",        (0, 0), (-1, -1), 0.5, grid_c),
        ("PADDING",     (0, 0), (-1, -1), 6),
        ("TEXTCOLOR",   (0, 1), (0, 1), sev_color),
        ("FONTNAME",    (0, 1), (0, 1), "Helvetica-Bold"),
    ]))
    story.append(rt)
    story.append(Spacer(1, 12))

    # ── Vulnerability details ──
    story.append(Paragraph("Vulnerability Details", h2))
    story.append(Paragraph(
        f"<b>{cve.get('cve_id', '')}</b>  ·  "
        f"Severity: <b>{cve.get('severity', '—')}</b>  ·  "
        f"CVSS: <b>{cve.get('cvss_score') or '—'}</b>",
        body,
    ))
    story.append(Spacer(1, 4))
    pub = (cve.get("published_date") or "")[:10]
    mod = (cve.get("last_modified")  or "")[:10]
    if pub or mod:
        story.append(Paragraph(
            f"Published: {pub or '—'}  ·  Last Modified: {mod or '—'}", label))
    story.append(Spacer(1, 6))
    story.append(Paragraph(cve.get("description") or "No description available.", body))
    story.append(Spacer(1, 8))

    vendors  = cve.get("vendors")  or ""
    products = cve.get("products") or ""
    if isinstance(vendors,  list): vendors  = ", ".join(vendors)
    if isinstance(products, list): products = ", ".join(products)
    if vendors:
        story.append(Paragraph(f"<b>Vendors:</b> {vendors}", body))
        story.append(Spacer(1, 4))
    if products:
        story.append(Paragraph(f"<b>Products:</b> {products}", body))
        story.append(Spacer(1, 4))

    # ── AI Remediation Advice ──
    if req.advice_text.strip():
        story.append(Paragraph("AI Remediation Advice", h2))
        clean_advice = re.sub(r'\*\*(.+?)\*\*', r'\1', req.advice_text)
        for para in clean_advice.split('\n\n'):
            para = para.strip()
            if para:
                story.append(Paragraph(para, body))
                story.append(Spacer(1, 12))

    # ── Related CVEs helper ──
    def _related_table(rows, title):
        if not rows:
            return
        story.append(Spacer(1, 8))
        story.append(Paragraph(title, h2))
        tdata = [["CVE ID", "Severity", "CVSS", "Published"]]
        for r in rows[:10]:
            tdata.append([
                r.get("cve_id", ""),
                r.get("severity", "—"),
                str(r.get("cvss_score") or "—"),
                (r.get("published_date") or "")[:10],
            ])
        t = Table(tdata, colWidths=[4 * cm, 3 * cm, 2.5 * cm, 4 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), bg_head),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#475569")),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_alt]),
            ("GRID",        (0, 0), (-1, -1), 0.5, grid_c),
            ("PADDING",     (0, 0), (-1, -1), 5),
        ]))
        story.append(t)

    _related_table(data.get("related_by_vendor",  []), "Related CVEs by Vendor")
    _related_table(data.get("related_by_product", []), "Related CVEs by Product")

    # ── Footer ──
    story.append(Spacer(1, 20))
    story.append(divider)
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Generated by VulnLens · Data sourced from NVD (nvd.nist.gov) · Not affiliated with NIST",
        footer,
    ))

    doc.build(story)
    buf.seek(0)

    filename = f"{cve_id.upper()}-advisory.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/advisor/{cve_id}/advice")
def stream_advice(cve_id: str):
    return StreamingResponse(
        _sse_advice(cve_id.upper()),
        media_type="text/event-stream",
    )
