"""
IntelStateStore — SQLite store for tracking the last RAG update time per target_type.

Used by IntelAgent to decide whether the cooldown period (rag_refresh_days) has
expired before running a fresh source-fetch pipeline.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import structlog

from server.db.knowledge.config.settings import settings

logger = structlog.get_logger(__name__)


class IntelStateStore:
    """Tracks last_update timestamp for each target_type in a local SQLite database."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or (settings.data_dir / "intel_state.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS intel_state (
                target_type   TEXT PRIMARY KEY,
                last_update   TEXT NOT NULL,
                update_status TEXT NOT NULL DEFAULT 'unknown'
            );
            """
        )
        self._conn.commit()

    def get_last_update(self, target_type: str) -> datetime | None:
        """Return the last update datetime (UTC) for target_type, or None if never set."""
        row = self._conn.execute(
            "SELECT last_update FROM intel_state WHERE target_type = ?",
            (target_type,),
        ).fetchone()
        if row is None:
            return None
        try:
            dt = datetime.fromisoformat(str(row["last_update"]))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None

    def set_last_update(
        self,
        target_type: str,
        dt: datetime,
        update_status: str = "updated",
    ) -> None:
        """Upsert the last_update timestamp for target_type."""
        self._conn.execute(
            """
            INSERT INTO intel_state(target_type, last_update, update_status)
            VALUES(?, ?, ?)
            ON CONFLICT(target_type)
            DO UPDATE SET
                last_update   = excluded.last_update,
                update_status = excluded.update_status
            """,
            (target_type, dt.replace(tzinfo=timezone.utc).isoformat(), update_status),
        )
        self._conn.commit()
        logger.info(
            "intel_state_saved",
            target_type=target_type,
            last_update=dt.isoformat(),
            update_status=update_status,
        )
