"""
stack_analyzer.py — Matching and scoring engine for Tech Stack Analysis.

Pipeline:
  1. Normalize user-supplied tech terms
  2. Query SQLite vendors/products tables for matching CVEs
  3. Fetch EPSS exploitation-probability scores from api.first.org
  4. Compute a composite risk score per CVE
  5. Return a structured risk report via analyze_stack()
"""

import re
import sqlite3
import logging
from datetime import datetime, timezone

import requests

from core.db import get_db

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100


# ---------------------------------------------------------------------------
# 1. Normalisation
# ---------------------------------------------------------------------------

def normalize_input(tech_list: list[str]) -> list[str]:
    """Lowercase, strip whitespace, replace spaces with underscores, remove SQL wildcards."""
    normalized = []
    for tech in tech_list:
        cleaned = tech.lower().strip().replace(" ", "_")
        cleaned = re.sub(r'[%_]', '', cleaned)
        if cleaned:
            normalized.append(cleaned)
    return normalized


# ---------------------------------------------------------------------------
# 2. SQLite matching
# ---------------------------------------------------------------------------

def match_cves_for_stack(tech_list: list[str]) -> list[dict]:
    """
    For each tech term query vendors.vendor and products.product with LIKE.
    Returns deduplicated CVE dicts ordered by cvss_score DESC.

    Each dict: cve_id, severity, cvss_score, published_date, description, matched_tech
    """
    normalized = normalize_input(tech_list)
    if not normalized:
        return []

    seen: dict[str, dict] = {}  # cve_id -> row dict (keeps first match per CVE)

    try:
        cur = get_db().cursor()

        for term in normalized:
            like = f"%{term}%"
            cur.execute(
                """
                SELECT DISTINCT
                    c.cve_id,
                    c.severity,
                    c.cvss_score,
                    c.published_date,
                    c.description
                FROM cves c
                WHERE c.cve_id IN (
                    SELECT cve_id FROM vendors  WHERE vendor  LIKE ?
                    UNION
                    SELECT cve_id FROM products WHERE product LIKE ?
                )
                ORDER BY c.cvss_score DESC
                """,
                (like, like),
            )
            for row in cur.fetchall():
                cve_id = row["cve_id"]
                if cve_id not in seen:
                    seen[cve_id] = {
                        "cve_id": cve_id,
                        "severity": row["severity"],
                        "cvss_score": row["cvss_score"] or 0.0,
                        "published_date": row["published_date"],
                        "description": row["description"],
                        "matched_tech": term,
                    }

    except sqlite3.Error as exc:
        logger.error("SQLite error in match_cves_for_stack: %s", exc)
        return []

    results = list(seen.values())
    results.sort(key=lambda r: r["cvss_score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# 3. EPSS scores
# ---------------------------------------------------------------------------

def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS scores from api.first.org in batches of EPSS_BATCH_SIZE.
    Returns {cve_id: epss_score}.  Returns {} on any failure.
    """
    if not cve_ids:
        return {}

    scores: dict[str, float] = {}

    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i : i + EPSS_BATCH_SIZE]
        try:
            response = requests.get(
                EPSS_API_URL,
                params={"cve": ",".join(batch)},
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                try:
                    scores[cve_id] = float(entry.get("epss", 0.0))
                except (TypeError, ValueError):
                    scores[cve_id] = 0.0
        except requests.RequestException as exc:
            logger.warning("EPSS API request failed for batch starting at %d: %s", i, exc)

    return scores


# ---------------------------------------------------------------------------
# 4. Risk score
# ---------------------------------------------------------------------------

def compute_risk_score(cvss: float, epss: float, days_old: int) -> float:
    """
    Composite risk score:
      (cvss * 0.5) + (epss * 10 * 0.4) + (recency_factor * 0.1)

    recency_factor: 10 if days_old <= 90
                     7 if days_old <= 365
                     4 if days_old <= 730
                     1 otherwise
    """
    if days_old <= 90:
        recency_factor = 10.0
    elif days_old <= 365:
        recency_factor = 7.0
    elif days_old <= 730:
        recency_factor = 4.0
    else:
        recency_factor = 1.0

    score = (cvss * 0.5) + (epss * 10 * 0.4) + (recency_factor * 0.1)
    return round(score, 2)


# ---------------------------------------------------------------------------
# 5. Main pipeline
# ---------------------------------------------------------------------------

def analyze_stack(tech_list: list[str]) -> dict:
    """
    Full pipeline: match CVEs → fetch EPSS → compute risk scores → build report.

    Returns:
    {
        "total": int,
        "critical": int,
        "high": int,
        "medium": int,
        "low": int,
        "top_cves": list[dict],          # top 20 by risk_score
        "by_technology": dict,           # tech -> [cve_id, ...]
        "technologies_matched": list,    # techs with >= 1 CVE
        "technologies_clean": list,      # techs with 0 CVEs
    }
    """
    normalized = normalize_input(tech_list)
    matched_cves = match_cves_for_stack(tech_list)

    # Build by_technology index (uses normalized terms)
    by_technology: dict[str, list[str]] = {t: [] for t in normalized}
    for cve in matched_cves:
        tech = cve["matched_tech"]
        if tech in by_technology:
            by_technology[tech].append(cve["cve_id"])

    # Fetch EPSS scores
    cve_ids = [c["cve_id"] for c in matched_cves]
    epss_scores = fetch_epss_scores(cve_ids)

    # Enrich each CVE with EPSS and risk score
    now = datetime.now(tz=timezone.utc)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    enriched: list[dict] = []

    for cve in matched_cves:
        epss = epss_scores.get(cve["cve_id"], 0.0)
        days_old = _days_since(cve["published_date"], now)
        risk_score = compute_risk_score(cve["cvss_score"], epss, days_old)

        sev = (cve["severity"] or "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

        enriched.append({
            "cve_id": cve["cve_id"],
            "severity": cve["severity"],
            "cvss_score": cve["cvss_score"],
            "epss_score": epss,
            "risk_score": risk_score,
            "matched_tech": cve["matched_tech"],
            "description": cve["description"],
            "published_date": cve["published_date"],
        })

    enriched.sort(key=lambda r: r["risk_score"], reverse=True)
    top_cves = enriched[:20]

    techs_matched = [t for t in normalized if by_technology.get(t)]
    techs_clean = [t for t in normalized if not by_technology.get(t)]

    return {
        "total": len(matched_cves),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "top_cves": top_cves,
        "by_technology": by_technology,
        "technologies_matched": techs_matched,
        "technologies_clean": techs_clean,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _days_since(published_date: str | None, now: datetime) -> int:
    """Parse ISO-style published_date string and return days elapsed."""
    if not published_date:
        return 9999
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(published_date[:len(fmt) + 3], fmt).replace(
                tzinfo=timezone.utc
            )
            return max(0, (now - dt).days)
        except ValueError:
            continue
    logger.debug("Could not parse published_date: %s", published_date)
    return 9999
