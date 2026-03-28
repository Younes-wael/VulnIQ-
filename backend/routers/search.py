"""
Search router — CVE filtering via SQLite.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import csv
import io
import sqlite3
import time

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from core.db import get_db

router = APIRouter(tags=["search"])


@router.get("/search")
def search(
    severities: str  = Query(default=""),
    year_from:  int  = Query(default=None),
    year_to:    int  = Query(default=None),
    vendor:     str  = Query(default=""),
    cvss_min:   float = Query(default=None),
    cvss_max:   float = Query(default=None),
    keyword:    str  = Query(default=""),
    limit:      int  = Query(default=100, ge=1, le=1000),
):
    where_clauses = []
    params = []

    if severities:
        sev_list = [s.strip().upper() for s in severities.split(",") if s.strip()]
        if sev_list:
            placeholders = ",".join("?" * len(sev_list))
            where_clauses.append(f"severity IN ({placeholders})")
            params.extend(sev_list)

    if year_from is not None:
        where_clauses.append("year >= ?")
        params.append(year_from)

    if year_to is not None:
        where_clauses.append("year <= ?")
        params.append(year_to)

    if vendor.strip():
        where_clauses.append(
            "cve_id IN (SELECT cve_id FROM vendors WHERE vendor LIKE ?)"
        )
        params.append(f"%{vendor.strip()}%")

    if cvss_min is not None:
        where_clauses.append("cvss_score >= ?")
        params.append(cvss_min)

    if cvss_max is not None:
        where_clauses.append("cvss_score <= ?")
        params.append(cvss_max)

    if keyword.strip():
        kw = f"%{keyword.strip()}%"
        where_clauses.append(
            "(cves.cve_id LIKE ? OR cves.description LIKE ?"
            " OR cves.cve_id IN ("
            "SELECT cve_id FROM vendors WHERE vendor LIKE ?"
            " UNION SELECT cve_id FROM products WHERE product LIKE ?"
            "))"
        )
        params.extend([kw, kw, kw, kw])

    sql = (
        "SELECT cve_id, description, published_date, cvss_score, "
        "severity, year, vendors, products FROM cves"
    )
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)
    sql += " ORDER BY cvss_score DESC NULLS LAST LIMIT ?"
    params.append(limit)

    try:
        start = time.time()
        cursor = get_db().cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        elapsed_ms = (time.time() - start) * 1000

        results = [
            {
                "cve_id":         row[0],
                "description":    row[1],
                "published_date": row[2],
                "cvss_score":     row[3],
                "severity":       row[4],
                "year":           row[5],
                "vendors":        row[6] or "",
                "products":       row[7] or "",
            }
            for row in rows
        ]

        return {"results": results, "total": len(results), "elapsed_ms": round(elapsed_ms, 2)}

    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@router.get("/search/export")
def export_csv(
    severities: str   = Query(default=""),
    year_from:  int   = Query(default=None),
    year_to:    int   = Query(default=None),
    vendor:     str   = Query(default=""),
    cvss_min:   float = Query(default=None),
    cvss_max:   float = Query(default=None),
    keyword:    str   = Query(default=""),
):
    where_clauses = []
    params = []

    if severities:
        sev_list = [s.strip().upper() for s in severities.split(",") if s.strip()]
        if sev_list:
            placeholders = ",".join("?" * len(sev_list))
            where_clauses.append(f"severity IN ({placeholders})")
            params.extend(sev_list)

    if year_from is not None:
        where_clauses.append("year >= ?")
        params.append(year_from)

    if year_to is not None:
        where_clauses.append("year <= ?")
        params.append(year_to)

    if vendor.strip():
        where_clauses.append(
            "cve_id IN (SELECT cve_id FROM vendors WHERE vendor LIKE ?)"
        )
        params.append(f"%{vendor.strip()}%")

    if cvss_min is not None:
        where_clauses.append("cvss_score >= ?")
        params.append(cvss_min)

    if cvss_max is not None:
        where_clauses.append("cvss_score <= ?")
        params.append(cvss_max)

    if keyword.strip():
        kw = f"%{keyword.strip()}%"
        where_clauses.append(
            "(cves.cve_id LIKE ? OR cves.description LIKE ?"
            " OR cves.cve_id IN ("
            "SELECT cve_id FROM vendors WHERE vendor LIKE ?"
            " UNION SELECT cve_id FROM products WHERE product LIKE ?"
            "))"
        )
        params.extend([kw, kw, kw, kw])

    sql = (
        "SELECT cve_id, description, published_date, cvss_score, "
        "severity, year, vendors, products FROM cves"
    )
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)
    sql += " ORDER BY cvss_score DESC NULLS LAST LIMIT 10000"

    try:
        cursor = get_db().cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["CVE ID", "Severity", "CVSS Score", "Published Date", "Year", "Vendors", "Products", "Description"])
    for row in rows:
        writer.writerow([row[0], row[4], row[3], row[2], row[5], row[6] or "", row[7] or "", row[1]])

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnlens-export.csv"},
    )
