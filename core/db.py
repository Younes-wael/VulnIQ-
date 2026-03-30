"""Shared SQLite connection factory.

Each thread gets one persistent connection with WAL journal mode enabled.
row_factory is set to sqlite3.Row so both positional unpacking and
named column access (row["col"]) work across all callers.
"""

import os
import sqlite3
import threading

from config import SQLITE_PATH

_local = threading.local()

# SQLite files start with this 16-byte magic header
_SQLITE_MAGIC = b"SQLite format 3\x00"


def _is_valid_sqlite(path: str) -> bool:
    """Return True only if path exists and starts with the SQLite magic header."""
    try:
        with open(path, "rb") as f:
            return f.read(16) == _SQLITE_MAGIC
    except Exception:
        return False


def _ensure_db_file() -> None:
    """Create an empty SQLite file if the current one is missing or invalid (e.g. an LFS pointer)."""
    if not _is_valid_sqlite(SQLITE_PATH):
        print(
            f"[DB] {SQLITE_PATH} is missing or not a valid SQLite file — "
            "creating a fresh empty database. CVE search data will be unavailable."
        )
        os.makedirs(os.path.dirname(SQLITE_PATH) or ".", exist_ok=True)
        # Remove the invalid file (LFS pointer, HTML error page, etc.) if it exists
        if os.path.exists(SQLITE_PATH):
            os.remove(SQLITE_PATH)
        # sqlite3.connect creates a valid empty database on first open
        conn = sqlite3.connect(SQLITE_PATH)
        conn.close()


def get_db() -> sqlite3.Connection:
    """Return the per-thread SQLite connection, creating it on first call."""
    if not hasattr(_local, "conn"):
        _ensure_db_file()
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


try:
    create_watchlist_tables()
except Exception as e:
    print(f"WARNING: could not create watchlist tables: {e}")
