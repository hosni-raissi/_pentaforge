"""Debug-only routes for inspecting and resetting runtime state."""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException

from server.api.dependencies import rate_limiter

router = APIRouter(tags=["debug"])


def _is_debug_enabled() -> bool:
    # Explicit override for local/integration testing.
    if os.getenv("RATE_LIMIT_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True

    # Local developer default: enabled when ENV is not set.
    # Production deployments should set ENV=production.
    env_raw = os.getenv("ENV")
    if env_raw is None or not env_raw.strip():
        return True
    env = env_raw.strip().lower()
    return env in {"dev", "development", "local", "test"}


def _raise_if_disabled() -> None:
    if not _is_debug_enabled():
        raise HTTPException(status_code=404, detail="Not found")


@router.get("/api/debug/rate-limit/stats")
def rate_limit_stats() -> dict:
    _raise_if_disabled()
    return rate_limiter.get_stats()


import sqlite3
from pydantic import BaseModel
from server.db.projects.config import projects_db_config

@router.post("/api/debug/rate-limit/reset")
def rate_limit_reset() -> dict[str, bool]:
    _raise_if_disabled()
    rate_limiter.reset()
    return {"ok": True}


class SqlQueryPayload(BaseModel):
    query: str
    params: list | dict | None = None
    admin_token: str | None = None


@router.post("/api/admin/sql")
def execute_admin_sql(payload: SqlQueryPayload) -> dict:
    expected_token = os.getenv("ADMIN_API_TOKEN")
    if not expected_token:
        _raise_if_disabled()
    else:
        if payload.admin_token != expected_token:
            raise HTTPException(status_code=403, detail="Forbidden: Invalid admin token")

    db_path = projects_db_config.projects_db_path
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if payload.params:
                cursor.execute(payload.query, payload.params)
            else:
                cursor.execute(payload.query)
            
            query_lower = payload.query.strip().lower()
            if query_lower.startswith("select") or query_lower.startswith("pragma"):
                rows = cursor.fetchall()
                return {"ok": True, "rows": [dict(row) for row in rows], "count": len(rows)}
            else:
                conn.commit()
                return {"ok": True, "rowcount": cursor.rowcount}
    except sqlite3.Error as exc:
        raise HTTPException(status_code=400, detail=f"Database error: {str(exc)}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Execution error: {str(exc)}")
