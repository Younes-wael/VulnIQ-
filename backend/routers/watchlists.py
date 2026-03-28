"""
Watchlists router — CRUD for saved CVE watchlists and on-demand alert testing.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import json
import sqlite3
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.db import get_db

router = APIRouter(tags=["watchlists"])


# ─── Serialization helpers ────────────────────────────────────────────────────

def _split(s: str) -> list[str]:
    return [x.strip() for x in s.split(',') if x.strip()] if s else []


def _join(lst: list[str]) -> str:
    return ','.join(lst)


def _row_to_dict(row) -> dict:
    return {
        'id':             row['id'],
        'name':           row['name'],
        'vendors':        _split(row['vendors']),
        'products':       _split(row['products']),
        'keywords':       _split(row['keywords']),
        'min_cvss':       row['min_cvss'],
        'webhook_url':    row['webhook_url'],
        'created_at':     row['created_at'],
        'last_alerted_at': row['last_alerted_at'],
    }


# ─── Webhook delivery ─────────────────────────────────────────────────────────

def _deliver_webhook(url: str, payload: dict) -> Optional[str]:
    """POST JSON payload to url with a 10-second timeout.
    Returns an error string on failure, None on success.
    """
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        urllib.request.urlopen(req, timeout=10)
        return None
    except Exception as exc:
        return str(exc)


# ─── Matching logic (shared by /test endpoint and scheduler) ──────────────────

def _find_matching_cves(
    vendors: list[str],
    products: list[str],
    keywords: list[str],
    min_cvss: float,
) -> list[dict]:
    """Return CVEs published in the last 24 h that match any filter."""
    conditions: list[str] = []
    params: list = []

    for v in vendors:
        conditions.append(
            "cve_id IN (SELECT cve_id FROM vendors WHERE vendor LIKE ?)"
        )
        params.append(f'%{v}%')

    for p in products:
        conditions.append(
            "cve_id IN (SELECT cve_id FROM products WHERE product LIKE ?)"
        )
        params.append(f'%{p}%')

    for kw in keywords:
        conditions.append("description LIKE ?")
        params.append(f'%{kw}%')

    if not conditions:
        return []

    sql = (
        "SELECT cve_id, description, published_date, cvss_score, severity "
        "FROM cves "
        "WHERE published_date >= datetime('now', '-1 day') "
        f"AND ({' OR '.join(conditions)})"
    )

    if min_cvss > 0:
        sql += " AND cvss_score >= ?"
        params.append(min_cvss)

    sql += " ORDER BY cvss_score DESC NULLS LAST LIMIT 50"

    rows = get_db().execute(sql, params).fetchall()
    return [
        {
            'cve_id':              r['cve_id'],
            'severity':            r['severity'] or '',
            'cvss_score':          r['cvss_score'],
            'published_date':      r['published_date'] or '',
            'description_preview': (r['description'] or '')[:200],
        }
        for r in rows
    ]


def _run_check(wl_id: int) -> dict:
    """Run the full alert check for one watchlist.

    Returns {"matches": N, "delivered": bool, "error": str | None}
    """
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM watchlists WHERE id = ?", (wl_id,)
    ).fetchone()
    if row is None:
        return {"matches": 0, "delivered": False, "error": "Watchlist not found"}

    vendors  = _split(row['vendors'])
    products = _split(row['products'])
    keywords = _split(row['keywords'])

    if not vendors and not products and not keywords:
        return {"matches": 0, "delivered": False, "error": None}

    matches = _find_matching_cves(vendors, products, keywords, row['min_cvss'])

    delivered = False
    error: Optional[str] = None

    if matches and row['webhook_url']:
        top_sev = matches[0]['severity'] if matches else ''
        payload = {
            "watchlist":    row['name'],
            "new_cves":     len(matches),
            "top_severity": top_sev,
            "items":        matches,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        error = _deliver_webhook(row['webhook_url'], payload)
        delivered = error is None

    if matches:
        conn.execute(
            "UPDATE watchlists SET last_alerted_at = datetime('now') WHERE id = ?",
            (wl_id,),
        )
        conn.commit()

    return {"matches": len(matches), "delivered": delivered, "error": error}


# ─── Pydantic schema ──────────────────────────────────────────────────────────

class WatchlistBody(BaseModel):
    name:        str
    vendors:     list[str] = []
    products:    list[str] = []
    keywords:    list[str] = []
    min_cvss:    float = 0.0
    webhook_url: str   = ''


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.get("/watchlists")
def list_watchlists():
    try:
        rows = get_db().execute(
            "SELECT * FROM watchlists ORDER BY created_at DESC"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@router.post("/watchlists", status_code=201)
def create_watchlist(body: WatchlistBody):
    if not body.name.strip():
        raise HTTPException(status_code=422, detail="name must not be empty")
    if not (0.0 <= body.min_cvss <= 10.0):
        raise HTTPException(status_code=422, detail="min_cvss must be between 0 and 10")

    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO watchlists (name, vendors, products, keywords, min_cvss, webhook_url) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                body.name.strip(),
                _join(body.vendors),
                _join(body.products),
                _join(body.keywords),
                body.min_cvss,
                body.webhook_url.strip(),
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM watchlists WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        return _row_to_dict(row)
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@router.put("/watchlists/{wl_id}")
def update_watchlist(wl_id: int, body: WatchlistBody):
    if not body.name.strip():
        raise HTTPException(status_code=422, detail="name must not be empty")
    if not (0.0 <= body.min_cvss <= 10.0):
        raise HTTPException(status_code=422, detail="min_cvss must be between 0 and 10")

    conn = get_db()
    try:
        if conn.execute(
            "SELECT id FROM watchlists WHERE id = ?", (wl_id,)
        ).fetchone() is None:
            raise HTTPException(status_code=404, detail="Watchlist not found")

        conn.execute(
            "UPDATE watchlists "
            "SET name=?, vendors=?, products=?, keywords=?, min_cvss=?, webhook_url=? "
            "WHERE id=?",
            (
                body.name.strip(),
                _join(body.vendors),
                _join(body.products),
                _join(body.keywords),
                body.min_cvss,
                body.webhook_url.strip(),
                wl_id,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM watchlists WHERE id = ?", (wl_id,)
        ).fetchone()
        return _row_to_dict(row)
    except HTTPException:
        raise
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@router.delete("/watchlists/{wl_id}")
def delete_watchlist(wl_id: int):
    conn = get_db()
    try:
        if conn.execute(
            "SELECT id FROM watchlists WHERE id = ?", (wl_id,)
        ).fetchone() is None:
            raise HTTPException(status_code=404, detail="Watchlist not found")
        conn.execute("DELETE FROM watchlists WHERE id = ?", (wl_id,))
        conn.commit()
        return {"deleted": True}
    except HTTPException:
        raise
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@router.post("/watchlists/{wl_id}/test")
def test_watchlist(wl_id: int):
    conn = get_db()
    if conn.execute(
        "SELECT id FROM watchlists WHERE id = ?", (wl_id,)
    ).fetchone() is None:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    return _run_check(wl_id)
