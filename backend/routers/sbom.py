"""
SBOM scanner router — parses uploaded dependency/SBOM files and finds matching CVEs.

Supported formats:
  requirements.txt, package.json, pom.xml, .csproj, cyclonedx.json
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import io
import json
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from core.db import get_db

_SEV_COLORS = {
    "CRITICAL": colors.HexColor("#ef4444"),
    "HIGH":     colors.HexColor("#f97316"),
    "MEDIUM":   colors.HexColor("#eab308"),
    "LOW":      colors.HexColor("#22c55e"),
}

router = APIRouter(tags=["sbom"])

MAX_PACKAGES = 500
MAX_CVES_PER_PACKAGE = 20
_NS = re.compile(r'\{[^}]*\}')


# ─── Parsers ─────────────────────────────────────────────────────────────────

def _parse_requirements(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        line = line.split('#')[0].strip()
        if not line or line.startswith('-'):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)(?:\[.*?\])?([><=!~^].+)?$', line)
        if m:
            name = m.group(1).strip()
            version_m = re.search(r'==([^\s,;]+)', line)
            packages.append({'name': name, 'version': version_m.group(1) if version_m else None})
    return packages


def _parse_package_json(content: str) -> list[dict]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}")
    packages = []
    for section in ('dependencies', 'devDependencies', 'peerDependencies'):
        for name, version in (data.get(section) or {}).items():
            packages.append({'name': name, 'version': str(version)})
    return packages


def _parse_pom_xml(content: str) -> list[dict]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}")
    packages = []
    for dep in root.iter():
        if _NS.sub('', dep.tag) == 'dependency':
            artifact_id = version = None
            for child in dep:
                tag = _NS.sub('', child.tag)
                if tag == 'artifactId':
                    artifact_id = (child.text or '').strip()
                elif tag == 'version':
                    version = (child.text or '').strip()
            if artifact_id:
                packages.append({'name': artifact_id, 'version': version})
    return packages


def _parse_csproj(content: str) -> list[dict]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}")
    packages = []
    for elem in root.iter('PackageReference'):
        name = elem.get('Include') or elem.get('include', '')
        version = elem.get('Version') or elem.get('version', '') or None
        if name.strip():
            packages.append({'name': name.strip(), 'version': version})
    return packages


def _parse_cyclonedx(content: str) -> list[dict]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}")
    return [
        {'name': c.get('name', '').strip(), 'version': (c.get('version') or '').strip() or None}
        for c in (data.get('components') or [])
        if c.get('name', '').strip()
    ]


def _detect_and_parse(filename: str, content: str) -> list[dict]:
    name = filename.lower()
    if name.endswith('requirements.txt'):
        return _parse_requirements(content)
    if name.endswith('package.json'):
        return _parse_package_json(content)
    if name.endswith('pom.xml'):
        return _parse_pom_xml(content)
    if name.endswith('.csproj'):
        return _parse_csproj(content)
    if name.endswith('.json'):
        try:
            data = json.loads(content)
            if 'components' in data or 'bomFormat' in data:
                return _parse_cyclonedx(content)
        except (json.JSONDecodeError, ValueError):
            pass
    raise HTTPException(
        status_code=415,
        detail=(
            "Unsupported file type. Accepted: requirements.txt, package.json, "
            "pom.xml, .csproj, cyclonedx.json"
        ),
    )


# ─── PDF export ──────────────────────────────────────────────────────────────

class SBOMExportRequest(BaseModel):
    filename: str = 'uploaded-file'
    total_packages: int = 0
    vulnerable_packages: int = 0
    total_vulnerabilities: int = 0
    elapsed_ms: float = 0.0
    packages: List[dict] = []
    vulnerabilities: List[dict] = []


@router.post("/sbom/export")
def sbom_export(req: SBOMExportRequest):
    bg_head = colors.HexColor("#f1f5f9")
    bg_alt  = colors.HexColor("#f8fafc")
    grid_c  = colors.HexColor("#e2e8f0")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )
    styles = getSampleStyleSheet()

    h1 = ParagraphStyle("BH1", parent=styles["Title"],
                         fontSize=20, spaceAfter=4,
                         textColor=colors.HexColor("#1e3a5f"))
    h2 = ParagraphStyle("BH2", parent=styles["Heading2"],
                         fontSize=11, spaceBefore=12, spaceAfter=6,
                         textColor=colors.HexColor("#374151"))
    body = ParagraphStyle("BBody", parent=styles["Normal"],
                           fontSize=9, leading=14,
                           textColor=colors.HexColor("#374151"))
    label = ParagraphStyle("BLabel", parent=styles["Normal"],
                            fontSize=8, spaceAfter=2,
                            textColor=colors.gray)
    footer_s = ParagraphStyle("BFooter", parent=styles["Normal"],
                               fontSize=7, textColor=colors.gray)

    divider = HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"))
    story = []

    # ── Header ──
    story.append(Paragraph("VulnLens SBOM Scan Report", h1))
    story.append(Paragraph(f"File: {req.filename}", label))
    story.append(Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M UTC"), label))
    story.append(divider)
    story.append(Spacer(1, 12))

    # ── Summary table ──
    story.append(Paragraph("Scan Summary", h2))
    summary_rows = [
        ["Packages Scanned", "Vulnerable Packages", "Total CVEs", "Scan Time"],
        [
            str(req.total_packages),
            str(req.vulnerable_packages),
            str(req.total_vulnerabilities),
            f"{req.elapsed_ms:.0f}ms",
        ],
    ]
    st = Table(summary_rows, colWidths=[4 * cm, 4 * cm, 3 * cm, 3 * cm])
    st_style = [
        ("BACKGROUND",  (0, 0), (-1, 0), bg_head),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#475569")),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_alt]),
        ("GRID",        (0, 0), (-1, -1), 0.5, grid_c),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]
    if req.vulnerable_packages > 0:
        st_style.append(("TEXTCOLOR", (1, 1), (1, 1), _SEV_COLORS["CRITICAL"]))
        st_style.append(("FONTNAME",  (1, 1), (1, 1), "Helvetica-Bold"))
    st.setStyle(TableStyle(st_style))
    story.append(st)
    story.append(Spacer(1, 12))

    # ── Affected Packages table ──
    affected = sorted(
        [p for p in req.packages if p.get("matched")],
        key=lambda p: p.get("max_cvss") or 0,
        reverse=True,
    )
    if affected:
        story.append(Paragraph("Affected Packages", h2))
        pkg_header = ["Package", "Version", "CVEs Found", "Max CVSS", "Max Severity"]
        pkg_data   = [pkg_header]
        for p in affected:
            pkg_data.append([
                p.get("name", ""),
                p.get("version") or "—",
                str(p.get("cve_count", 0)),
                str(round(p.get("max_cvss") or 0, 1)) if p.get("max_cvss") else "—",
                p.get("max_severity") or "—",
            ])
        pt = Table(pkg_data, colWidths=[4 * cm, 3 * cm, 2.5 * cm, 2.5 * cm, 3 * cm])
        pt_style = [
            ("BACKGROUND",  (0, 0), (-1, 0), bg_head),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#475569")),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_alt]),
            ("GRID",        (0, 0), (-1, -1), 0.5, grid_c),
            ("PADDING",     (0, 0), (-1, -1), 5),
        ]
        for i, row in enumerate(pkg_data[1:], start=1):
            sev = (row[4] or "").upper()
            col = _SEV_COLORS.get(sev)
            if col:
                pt_style.append(("TEXTCOLOR", (4, i), (4, i), col))
                pt_style.append(("FONTNAME",  (4, i), (4, i), "Helvetica-Bold"))
        pt.setStyle(TableStyle(pt_style))
        story.append(pt)

    # ── CVE Details table ──
    sorted_vulns = sorted(
        req.vulnerabilities,
        key=lambda v: v.get("cvss_score") or 0,
        reverse=True,
    )[:50]
    if sorted_vulns:
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"CVE Details ({len(req.vulnerabilities)} total, showing up to 50)", h2))
        vuln_header = ["CVE ID", "Severity", "CVSS", "Matched Package", "Published", "Description"]
        vuln_data   = [vuln_header]
        for v in sorted_vulns:
            desc = (v.get("description") or "")
            desc = desc[:120] + "…" if len(desc) > 120 else desc
            vuln_data.append([
                v.get("cve_id", ""),
                v.get("severity", "—"),
                str(round(v.get("cvss_score") or 0, 1)) if v.get("cvss_score") else "—",
                v.get("matched_package", "—"),
                (v.get("published_date") or "")[:10],
                desc,
            ])
        vt = Table(vuln_data, colWidths=[3 * cm, 2.5 * cm, 1.5 * cm, 3 * cm, 2.5 * cm, 3.5 * cm])
        vt_style = [
            ("BACKGROUND",  (0, 0), (-1, 0), bg_head),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#475569")),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_alt]),
            ("GRID",        (0, 0), (-1, -1), 0.5, grid_c),
            ("PADDING",     (0, 0), (-1, -1), 4),
            ("WORDWRAP",    (5, 0), (5, -1), True),
        ]
        for i, row in enumerate(vuln_data[1:], start=1):
            sev = (row[1] or "").upper()
            col = _SEV_COLORS.get(sev)
            if col:
                vt_style.append(("TEXTCOLOR", (1, i), (1, i), col))
                vt_style.append(("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"))
        vt.setStyle(TableStyle(vt_style))
        story.append(vt)

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
        headers={"Content-Disposition": "attachment; filename=vulnlens-sbom-report.pdf"},
    )


# ─── Route ───────────────────────────────────────────────────────────────────

@router.post("/sbom/scan")
async def scan_sbom(file: UploadFile = File(...)):
    raw = await file.read()
    try:
        content = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text.")

    try:
        packages = _detect_and_parse(file.filename or '', content)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not packages:
        return {
            "packages": [],
            "vulnerabilities": [],
            "total_packages": 0,
            "vulnerable_packages": 0,
            "total_vulnerabilities": 0,
            "elapsed_ms": 0.0,
        }

    # Deduplicate by lowercase name, cap at MAX_PACKAGES
    seen: set[str] = set()
    unique_packages: list[dict] = []
    for pkg in packages:
        key = pkg['name'].lower()
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg)
        if len(unique_packages) >= MAX_PACKAGES:
            break

    start = time.time()
    cursor = get_db().cursor()

    SEV_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'NONE': 0}
    pkg_results: list[dict] = []
    all_vulns: dict[str, dict] = {}   # cve_id → vuln dict

    for pkg in unique_packages:
        try:
            rows = cursor.execute(
                "SELECT DISTINCT c.cve_id, c.description, c.published_date, "
                "c.cvss_score, c.severity "
                "FROM products p JOIN cves c ON p.cve_id = c.cve_id "
                "WHERE p.product LIKE ? "
                "ORDER BY c.cvss_score DESC NULLS LAST "
                "LIMIT ?",
                (f'%{pkg["name"]}%', MAX_CVES_PER_PACKAGE),
            ).fetchall()
        except sqlite3.Error as exc:
            raise HTTPException(status_code=500, detail=f"Database error: {exc}")

        max_cvss = None
        max_sev = None

        for cve_id, description, published_date, cvss_score, severity in rows:
            if cvss_score is not None and (max_cvss is None or cvss_score > max_cvss):
                max_cvss = cvss_score
            sev_upper = (severity or '').upper()
            if SEV_ORDER.get(sev_upper, -1) > SEV_ORDER.get((max_sev or '').upper(), -1):
                max_sev = severity
            if cve_id not in all_vulns:
                all_vulns[cve_id] = {
                    'cve_id': cve_id,
                    'description': description or '',
                    'published_date': published_date or '',
                    'cvss_score': cvss_score,
                    'severity': severity or '',
                    'matched_package': pkg['name'],
                }

        pkg_results.append({
            'name': pkg['name'],
            'version': pkg.get('version'),
            'matched': len(rows) > 0,
            'cve_count': len(rows),
            'max_severity': max_sev,
            'max_cvss': max_cvss,
        })

    elapsed_ms = round((time.time() - start) * 1000, 2)
    vulns_list = sorted(all_vulns.values(), key=lambda v: v['cvss_score'] or 0, reverse=True)

    return {
        "packages": pkg_results,
        "vulnerabilities": vulns_list,
        "total_packages": len(unique_packages),
        "vulnerable_packages": sum(1 for p in pkg_results if p['matched']),
        "total_vulnerabilities": len(vulns_list),
        "elapsed_ms": elapsed_ms,
    }
