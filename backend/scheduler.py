"""
Background scheduler — runs daily CVE digest alerts for all configured watchlists.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from core.db import get_db
from backend.routers.watchlists import _split, _run_check

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def run_all_watchlist_alerts() -> None:
    """Query all watchlists and deliver digests for any that have recent matches."""
    try:
        rows = get_db().execute("SELECT * FROM watchlists").fetchall()
    except Exception as exc:
        logger.error("Scheduler: failed to fetch watchlists: %s", exc)
        return

    checked = 0
    deliveries = 0

    for row in rows:
        vendors  = _split(row['vendors'])
        products = _split(row['products'])
        keywords = _split(row['keywords'])
        if not vendors and not products and not keywords:
            continue

        result = _run_check(row['id'])
        checked += 1
        if result.get('delivered'):
            deliveries += 1

    logger.info(
        "Digest run: %d watchlists checked, %d deliveries attempted",
        checked,
        deliveries,
    )


scheduler.add_job(
    run_all_watchlist_alerts,
    "interval",
    hours=24,
    id="daily_digest",
)


def start() -> None:
    if not scheduler.running:
        scheduler.start()


def stop() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
