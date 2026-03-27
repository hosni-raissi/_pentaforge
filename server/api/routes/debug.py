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


@router.post("/api/debug/rate-limit/reset")
def rate_limit_reset() -> dict[str, bool]:
    _raise_if_disabled()
    rate_limiter.reset()
    return {"ok": True}
