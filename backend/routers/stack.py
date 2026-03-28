"""
Stack router — tech stack CVE analysis and AI report streaming.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import io
import re
from datetime import datetime
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from core.stack_analyzer import analyze_stack
from core.llm import build_stack_report_prompt, stream_response

_SEV_COLORS = {
    "CRITICAL": colors.HexColor("#ef4444"),
    "HIGH":     colors.HexColor("#f97316"),
    "MEDIUM":   colors.HexColor("#eab308"),
    "LOW":      colors.HexColor("#22c55e"),
}

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
            yield f"data: {token.replace(chr(10), '\\n')}\n\n"
    except Exception as exc:
        yield f"data: [ERROR] {exc}\n\n"


class StackExportRequest(BaseModel):
    tech_input: str
    results: dict
    report_text: str = ''


@router.post("/stack/export")
def stack_export(req: StackExportRequest):
    r = req.results
    top_cves = sorted(r.get("top_cves", []), key=lambda c: c.get("cvss_score") or 0, reverse=True)[:20]
    matched  = r.get("technologies_matched", [])
    clean    = r.get("technologies_clean", [])

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    bg_head = colors.HexColor("#f1f5f9")
    bg_alt  = colors.HexColor("#f8fafc")
    grid_c  = colors.HexColor("#e2e8f0")

    h1 = ParagraphStyle("SH1", parent=styles["Title"],
                         fontSize=20, spaceAfter=4,
                         textColor=colors.HexColor("#1e3a5f"))
    h2 = ParagraphStyle("SH2", parent=styles["Heading2"],
                         fontSize=11, spaceBefore=12, spaceAfter=6,
                         textColor=colors.HexColor("#374151"))
    body = ParagraphStyle("SBody", parent=styles["Normal"],
                           fontSize=9, leading=14,
                           textColor=colors.HexColor("#374151"))
    label = ParagraphStyle("SLabel", parent=styles["Normal"],
                            fontSize=8, spaceAfter=2,
                            textColor=colors.gray)
    footer_s = ParagraphStyle("SFooter", parent=styles["Normal"],
                               fontSize=7, textColor=colors.gray)
    warn_s = ParagraphStyle("SWarn", parent=styles["Normal"],
                             fontSize=9, leading=14,
                             textColor=colors.HexColor("#f97316"))
    ok_s = ParagraphStyle("SOk", parent=styles["Normal"],
                           fontSize=9, leading=14,
                           textColor=colors.HexColor("#22c55e"))

    divider = HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"))
    story = []

    # ── Header ──
    subtitle = req.tech_input if len(req.tech_input) <= 80 else req.tech_input[:77] + "..."
    story.append(Paragraph("VulnLens Stack Analysis Report", h1))
    story.append(Paragraph(f"Stack: {subtitle}", label))
    story.append(Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M UTC"), label))
    story.append(divider)
    story.append(Spacer(1, 12))

    # ── Risk Summary table ──
    story.append(Paragraph("Risk Summary", h2))
    med_low = (r.get("medium", 0) or 0) + (r.get("low", 0) or 0)
    summary_rows = [
        ["Total CVEs", "Critical", "High", "Medium / Low"],
        [
            str(r.get("total", 0) or 0),
            str(r.get("critical", 0) or 0),
            str(r.get("high", 0) or 0),
            str(med_low),
        ],
    ]
    st = Table(summary_rows, colWidths=[4 * cm, 3 * cm, 3 * cm, 3 * cm])
    style_cmds = [
        ("BACKGROUND",  (0, 0), (-1, 0), bg_head),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#475569")),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_alt]),
        ("GRID",        (0, 0), (-1, -1), 0.5, grid_c),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]
    crit_val = r.get("critical", 0) or 0
    high_val = r.get("high", 0) or 0
    if crit_val > 0:
        style_cmds.append(("TEXTCOLOR", (1, 1), (1, 1), _SEV_COLORS["CRITICAL"]))
        style_cmds.append(("FONTNAME",  (1, 1), (1, 1), "Helvetica-Bold"))
    if high_val > 0:
        style_cmds.append(("TEXTCOLOR", (2, 1), (2, 1), _SEV_COLORS["HIGH"]))
        style_cmds.append(("FONTNAME",  (2, 1), (2, 1), "Helvetica-Bold"))
    st.setStyle(TableStyle(style_cmds))
    story.append(st)
    story.append(Spacer(1, 12))

    # ── Technologies ──
    story.append(Paragraph("Technologies", h2))
    if matched:
        story.append(Paragraph(f"Affected: {', '.join(matched)}", warn_s))
        story.append(Spacer(1, 4))
    if clean:
        story.append(Paragraph(f"Clean: {', '.join(clean)}", ok_s))
        story.append(Spacer(1, 4))

    # ── Top CVEs table ──
    if top_cves:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Top CVEs by Risk Score", h2))
        cve_header = ["CVE ID", "Severity", "CVSS", "Matched Tech", "Published"]
        cve_data   = [cve_header]
        for cve in top_cves:
            cve_data.append([
                cve.get("cve_id", ""),
                cve.get("severity", "—"),
                str(round(cve.get("cvss_score") or 0, 1)),
                cve.get("matched_tech", "—"),
                (cve.get("published_date") or "")[:10],
            ])
        cve_col_w = [4 * cm, 2.5 * cm, 2 * cm, 4 * cm, 3 * cm]
        ct = Table(cve_data, colWidths=cve_col_w)
        ct_style = [
            ("BACKGROUND",  (0, 0), (-1, 0), bg_head),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#475569")),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_alt]),
            ("GRID",        (0, 0), (-1, -1), 0.5, grid_c),
            ("PADDING",     (0, 0), (-1, -1), 5),
        ]
        for i, row in enumerate(cve_data[1:], start=1):
            sev = (row[1] or "").upper()
            col = _SEV_COLORS.get(sev)
            if col:
                ct_style.append(("TEXTCOLOR", (1, i), (1, i), col))
                ct_style.append(("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"))
        ct.setStyle(TableStyle(ct_style))
        story.append(ct)

    # ── AI Risk Report ──
    if req.report_text.strip():
        story.append(Spacer(1, 8))
        story.append(Paragraph("AI Risk Report", h2))
        clean_report = re.sub(r'\*\*(.+?)\*\*', r'\1', req.report_text)
        for para in clean_report.split('\n\n'):
            para = para.strip()
            if para:
                story.append(Paragraph(para, body))
                story.append(Spacer(1, 12))

    # ── Footer ──
    story.append(Spacer(1, 20))
    story.append(divider)
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Generated by VulnLens · Data sourced from NVD (nvd.nist.gov) · Not affiliated with NIST",
        footer_s,
    ))

    doc.build(story)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=vulnlens-stack-report.pdf"},
    )


@router.post("/stack/report")
def stack_report(req: ReportRequest):
    if not req.technologies:
        raise HTTPException(status_code=422, detail="technologies list must not be empty")
    return StreamingResponse(
        _sse_report(req.technologies, req.analysis),
        media_type="text/event-stream",
    )
