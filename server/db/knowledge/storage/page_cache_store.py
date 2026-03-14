"""
PageCacheStore — SQLite-backed cache for scraped HTML pages.

This replaces per-URL flat files with a single indexed store to improve
reliability, lookup speed, and manageability on disk.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from server.db.knowledge.config.settings import settings


class PageCacheStore:
    """Persistent HTML cache keyed by (source, url_hash)."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or (settings.cache_dir / "pages_cache.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS page_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                url TEXT NOT NULL,
                url_hash TEXT NOT NULL,
                html TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                UNIQUE(source, url_hash)
            );

            CREATE INDEX IF NOT EXISTS idx_page_cache_source
            ON page_cache(source);
            """
        )
        self._conn.commit()

    @staticmethod
    def _url_hash(url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]

    def get(self, source: str, url: str) -> str | None:
        row = self._conn.execute(
            """
            SELECT html FROM page_cache
            WHERE source = ? AND url_hash = ?
            LIMIT 1
            """,
            (source, self._url_hash(url)),
        ).fetchone()
        return str(row["html"]) if row else None

    def set(self, source: str, url: str, html: str) -> None:
        self._conn.execute(
            """
            INSERT INTO page_cache(source, url, url_hash, html, fetched_at)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(source, url_hash)
            DO UPDATE SET
                url = excluded.url,
                html = excluded.html,
                fetched_at = excluded.fetched_at
            """,
            (source, url, self._url_hash(url), html, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def prune_source(self, source: str) -> int:
        cur = self._conn.execute("DELETE FROM page_cache WHERE source = ?", (source,))
        self._conn.commit()
        return int(cur.rowcount)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
