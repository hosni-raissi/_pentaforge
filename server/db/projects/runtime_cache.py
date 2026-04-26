"""Redis-backed runtime cache for orchestrator scratch data."""

from __future__ import annotations

import json
from typing import Any

import structlog

from server.config.database import db_config

logger = structlog.get_logger(__name__)

_KEY_PREFIX = "pentaforge:runtime:"
_RUNTIME_CACHE_SINGLETON: "ProjectRuntimeCache | None" = None


class ProjectRuntimeCache:
    """Small sync Redis helper for short-lived orchestrator cache records."""

    def __init__(self, url: str | None = None) -> None:
        self._url = url or db_config.redis_url
        self._redis = None

    def _get_client(self):
        if self._redis is None:
            import redis

            self._redis = redis.from_url(
                self._url,
                decode_responses=True,
            )
        return self._redis

    def _full_key(self, key: str) -> str:
        return f"{_KEY_PREFIX}{str(key or '').strip()}"

    def set_json(
        self,
        key: str,
        payload: dict[str, Any],
        *,
        ttl_seconds: int | None = None,
    ) -> None:
        try:
            client = self._get_client()
            raw = json.dumps(payload, ensure_ascii=True, default=str)
            full_key = self._full_key(key)
            if ttl_seconds and int(ttl_seconds) > 0:
                client.setex(full_key, int(ttl_seconds), raw)
            else:
                client.set(full_key, raw)
        except Exception as exc:
            logger.warning(
                "project_runtime_cache_set_failed",
                key=key,
                error=str(exc),
            )

    def get_json(self, key: str) -> dict[str, Any] | None:
        try:
            client = self._get_client()
            raw = client.get(self._full_key(key))
            if not raw:
                return None
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except Exception as exc:
            logger.warning(
                "project_runtime_cache_get_failed",
                key=key,
                error=str(exc),
            )
            return None

    def pop_json(self, key: str) -> dict[str, Any] | None:
        try:
            client = self._get_client()
            full_key = self._full_key(key)
            raw = client.get(full_key)
            if not raw:
                return None
            client.delete(full_key)
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except Exception as exc:
            logger.warning(
                "project_runtime_cache_pop_failed",
                key=key,
                error=str(exc),
            )
            return None


def get_project_runtime_cache() -> ProjectRuntimeCache:
    global _RUNTIME_CACHE_SINGLETON
    if _RUNTIME_CACHE_SINGLETON is None:
        _RUNTIME_CACHE_SINGLETON = ProjectRuntimeCache()
    return _RUNTIME_CACHE_SINGLETON


__all__ = ["ProjectRuntimeCache", "get_project_runtime_cache"]
