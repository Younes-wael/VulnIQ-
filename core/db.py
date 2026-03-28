"""Shared SQLite connection factory.

Each thread gets one persistent connection with WAL journal mode enabled.
row_factory is set to sqlite3.Row so both positional unpacking and
named column access (row["col"]) work across all callers.
"""

import sqlite3
import threading

from config import SQLITE_PATH

_local = threading.local()


def get_db() -> sqlite3.Connection:
    """Return the per-thread SQLite connection, creating it on first call."""
    if not hasattr(_local, 'conn'):
        conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    return _local.conn


def create_watchlist_tables() -> None:
    """Create watchlists table and index if they don't exist."""
    get_db().executescript("""
        CREATE TABLE IF NOT EXISTS watchlists (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,
            vendors         TEXT    NOT NULL DEFAULT '',
            products        TEXT    NOT NULL DEFAULT '',
            keywords        TEXT    NOT NULL DEFAULT '',
            min_cvss        REAL    NOT NULL DEFAULT 0.0,
            webhook_url     TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            last_alerted_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_watchlists_name ON watchlists(name);
    """)


create_watchlist_tables()
