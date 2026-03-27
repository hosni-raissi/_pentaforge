"""
PayloadStore — SQLite-based exact-lookup store for raw payload strings.

Raw payloads (XSS vectors, SQLi strings, command injection sequences, etc.)
do not embed meaningfully into vector space. They are stored in SQLite and
queried by exact value or substring search.

Backward compatibility:
    Existing JSON files under data/payloads/<domain>/<category>.json are
    migrated on first access and then continue to work transparently.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from server.db.knowledge.config.settings import settings

logger = structlog.get_logger(__name__)


class PayloadStore:
    """SQLite store for raw payload strings (not suitable for vector embedding)."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self._base = base_dir or (settings.data_dir / "payloads")
        self._base.mkdir(parents=True, exist_ok=True)
        self._db_path = self._base / "payloads.db"
        self._conn = sqlite3.connect(self._db_path, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA busy_timeout=30000;")
        self._ensure_schema()
        self._migrate_json_payloads()

    def _ensure_schema(self) -> None:
        """Create required tables and indexes."""
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                category TEXT NOT NULL,
                payload TEXT NOT NULL,
                source TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                added TEXT NOT NULL,
                UNIQUE(domain, category, payload)
            );

            CREATE INDEX IF NOT EXISTS idx_payloads_domain_category
            ON payloads(domain, category);

            CREATE INDEX IF NOT EXISTS idx_payloads_domain
            ON payloads(domain);

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    def _is_migrated(self) -> bool:
        row = self._conn.execute(
            "SELECT value FROM metadata WHERE key = 'json_migrated'"
        ).fetchone()
        return bool(row and row["value"] == "1")

    def _set_migrated(self) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES('json_migrated', '1')"
        )
        self._conn.commit()

    def _migrate_json_payloads(self) -> None:
        """One-time migration from legacy JSON files into SQLite."""
        if self._is_migrated():
            return

        migrated = 0
        for domain_dir in sorted(self._base.iterdir()):
            if not domain_dir.is_dir():
                continue
            domain = domain_dir.name
            for json_file in sorted(domain_dir.glob("*.json")):
                category = json_file.stem
                try:
                    items = json.loads(json_file.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue

                for item in items:
                    payload = str(item.get("payload", "")).strip()
                    if not payload:
                        continue
                    source = str(item.get("source", "unknown"))
                    tags = item.get("tags", [])
                    if not isinstance(tags, list):
                        tags = []
                    added = str(item.get("added", datetime.now(timezone.utc).isoformat()))
                    cur = self._conn.execute(
                        """
                        INSERT OR IGNORE INTO payloads(domain, category, payload, source, tags_json, added)
                        VALUES(?, ?, ?, ?, ?, ?)
                        """,
                        (domain, category, payload, source, json.dumps(tags), added),
                    )
                    migrated += cur.rowcount

        self._conn.commit()
        self._set_migrated()
        if migrated:
            logger.info("payload_json_migrated", count=migrated, db=str(self._db_path))

    def _row_to_payload(self, row: sqlite3.Row) -> dict[str, Any]:
        tags = []
        try:
            parsed = json.loads(row["tags_json"])
            if isinstance(parsed, list):
                tags = parsed
        except json.JSONDecodeError:
            pass
        return {
            "payload": row["payload"],
            "tags": tags,
            "source": row["source"],
            "added": row["added"],
        }

    def add_payloads(
        self,
        domain: str,
        category: str,
        payloads: list[str],
        source: str = "unknown",
        tags: list[str] | None = None,
    ) -> int:
        """Add new payloads (deduplicates by exact string match). Returns count added."""
        now = datetime.now(timezone.utc).isoformat()

        added = 0
        for payload in payloads:
            payload = payload.strip()
            if not payload:
                continue
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO payloads(domain, category, payload, source, tags_json, added)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (domain, category, payload, source, json.dumps(tags or []), now),
            )
            added += cur.rowcount

        self._conn.commit()
        if added:
            logger.info("payloads_added", domain=domain, category=category, count=added)
        return added

    def get_payloads(
        self,
        domain: str,
        category: str,
        tag_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get payloads, optionally filtered by tag."""
        rows = self._conn.execute(
            """
            SELECT payload, tags_json, source, added
            FROM payloads
            WHERE domain = ? AND category = ?
            ORDER BY id ASC
            """,
            (domain, category),
        ).fetchall()
        payloads = [self._row_to_payload(r) for r in rows]
        if tag_filter:
            payloads = [p for p in payloads if tag_filter in p.get("tags", [])]
        return payloads

    def search_payloads(self, keyword: str, domain: str | None = None) -> list[dict[str, Any]]:
        """Search payloads by keyword across domain/categories."""
        params: list[str] = [f"%{keyword}%"]
        sql = (
            "SELECT domain, category, payload, tags_json, source, added "
            "FROM payloads WHERE payload LIKE ?"
        )
        if domain:
            sql += " AND domain = ?"
            params.append(domain)
        sql += " ORDER BY id DESC"

        rows = self._conn.execute(sql, params).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = self._row_to_payload(row)
            item["domain"] = row["domain"]
            item["category"] = row["category"]
            results.append(item)
        return results

    def get_stats(self) -> dict[str, Any]:
        """Get payload counts per domain/category."""
        rows = self._conn.execute(
            """
            SELECT domain, category, COUNT(*) AS count
            FROM payloads
            GROUP BY domain, category
            ORDER BY domain, category
            """
        ).fetchall()

        stats: dict[str, dict[str, int]] = {}
        total = 0
        for row in rows:
            domain = row["domain"]
            category = row["category"]
            count = int(row["count"])
            stats.setdefault(domain, {})[category] = count
            total += count
        return {"payloads": stats, "total": total, "db_path": str(self._db_path)}

    def delete_by_source(self, source_name: str) -> int:
        """Delete payload rows by source name. Returns deleted row count."""
        clean_source = str(source_name or "").strip()
        if not clean_source:
            return 0
        cur = self._conn.execute(
            """
            DELETE FROM payloads
            WHERE source = ?;
            """,
            (clean_source,),
        )
        deleted = int(cur.rowcount or 0)
        self._conn.commit()
        if deleted > 0:
            logger.info("payloads_deleted_by_source", source=clean_source, count=deleted)
        return deleted

    def close(self) -> None:
        """Close the SQLite connection explicitly when needed."""
        try:
            self._conn.close()
        except Exception:
            pass
