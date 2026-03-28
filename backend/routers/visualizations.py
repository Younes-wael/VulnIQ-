"""
Visualizations router — aggregated statistics for charts.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import sqlite3

from fastapi import APIRouter, HTTPException

from core.db import get_db

router = APIRouter(tags=["visualizations"])


def _query(sql: str, params: tuple = ()) -> list[tuple]:
    cursor = get_db().cursor()
    cursor.execute(sql, params)
    return cursor.fetchall()


@router.get("/stats")
def stats():
    try:
        total_cves    = _query("SELECT COUNT(*) FROM cves")[0][0]
        critical_count = _query("SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL'")[0][0]
        avg_cvss_raw  = _query("SELECT AVG(cvss_score) FROM cves WHERE cvss_score IS NOT NULL")[0][0]
        avg_cvss      = round(avg_cvss_raw, 2) if avg_cvss_raw else 0.0
        return {"total_cves": total_cves, "critical_count": critical_count, "avg_cvss": avg_cvss}
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/trends/yearly")
def trends_yearly():
    try:
        rows = _query(
            "SELECT year, COUNT(*) as count FROM cves "
            "WHERE year IS NOT NULL GROUP BY year ORDER BY year"
        )
        return [{"year": r[0], "count": r[1]} for r in rows]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/trends/severity")
def trends_severity():
    try:
        rows = _query(
            "SELECT severity, COUNT(*) as count FROM cves "
            "WHERE severity IS NOT NULL GROUP BY severity"
        )
        return [{"severity": r[0], "count": r[1]} for r in rows]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/trends/vendors")
def trends_vendors():
    try:
        rows = _query(
            "SELECT vendor, COUNT(*) as count FROM vendors "
            "GROUP BY vendor ORDER BY count DESC LIMIT 15"
        )
        return [{"vendor": r[0], "count": r[1]} for r in rows]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/trends/cvss")
def trends_cvss():
    """CVSS distribution binned into 20 buckets (0.0–10.0, step 0.5)."""
    try:
        rows = _query(
            "SELECT cvss_score FROM cves WHERE cvss_score IS NOT NULL"
        )
        scores = [r[0] for r in rows]

        buckets: dict[str, int] = {}
        step = 0.5
        for i in range(20):
            lo = round(i * step, 1)
            hi = round(lo + step, 1)
            buckets[f"{lo}-{hi}"] = 0

        for s in scores:
            idx = min(int(s / step), 19)
            lo = round(idx * step, 1)
            hi = round(lo + step, 1)
            key = f"{lo}-{hi}"
            buckets[key] = buckets.get(key, 0) + 1

        return [{"bucket": k, "count": v} for k, v in buckets.items()]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/trends/severity-by-year")
def trends_severity_by_year():
    try:
        rows = _query(
            "SELECT year, severity, COUNT(*) as count FROM cves "
            "WHERE year IS NOT NULL AND severity IS NOT NULL "
            "GROUP BY year, severity ORDER BY year"
        )
        return [{"year": r[0], "severity": r[1], "count": r[2]} for r in rows]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=str(exc))
