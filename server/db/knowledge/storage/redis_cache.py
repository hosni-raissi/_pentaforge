"""
RedisCache — Cache layer for hot knowledge-base queries and recent results.

Caches serialized search results keyed by (query, domain, n_results).
Uses configurable TTL from DatabaseConfig.redis_cache_ttl.
Falls back gracefully when Redis is unavailable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import structlog

from server.config.database import db_config

logger = structlog.get_logger(__name__)

_KEY_PREFIX = "pentaforge:search:"


def _cache_key(query: str, domain: str, n_results: int) -> str:
    """Deterministic cache key from search parameters."""
    raw = f"{query}|{domain}|{n_results}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return f"{_KEY_PREFIX}{digest}"


class NullRedisCache:
    """No-op fallback when Redis is unavailable."""

    async def get(self, query: str, domain: str, n_results: int) -> list[dict[str, Any]] | None:
        return None

    async def set(self, query: str, domain: str, n_results: int, results: list[dict[str, Any]]) -> None:
        pass

    async def invalidate_domain(self, domain: str) -> None:
        pass

    async def clear(self) -> None:
        pass

    async def close(self) -> None:
        pass


class RedisCache:
    """Redis-backed cache for knowledge base search results."""

    def __init__(self, url: str | None = None, ttl: int | None = None) -> None:
        self._url = url or db_config.redis_url
        self._ttl = ttl or db_config.redis_cache_ttl
        self._redis = None

    async def _get_client(self):
        """Lazy-init async Redis client."""
        if self._redis is None:
            try:
                import redis.asyncio as aioredis
            except ImportError:
                raise RuntimeError("redis package required — pip install redis")

            self._redis = aioredis.from_url(
                self._url,
                decode_responses=True,
            )
            logger.info("redis_initialized", url=self._url.split("@")[-1])
        return self._redis

    async def get(self, query: str, domain: str, n_results: int) -> list[dict[str, Any]] | None:
        """Retrieve cached search results. Returns None on miss."""
        try:
            client = await self._get_client()
            key = _cache_key(query, domain, n_results)
            raw = await client.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:
            logger.debug("redis_get_miss", error=str(exc))
            return None

    async def set(
        self,
        query: str,
        domain: str,
        n_results: int,
        results: list[dict[str, Any]],
    ) -> None:
        """Cache search results with TTL."""
        try:
            client = await self._get_client()
            key = _cache_key(query, domain, n_results)
            await client.setex(key, self._ttl, json.dumps(results, default=str))
        except Exception as exc:
            logger.debug("redis_set_failed", error=str(exc))

    async def invalidate_domain(self, domain: str) -> None:
        """Invalidate all cached results (full scan — use sparingly)."""
        try:
            client = await self._get_client()
            cursor = 0
            while True:
                cursor, keys = await client.scan(cursor, match=f"{_KEY_PREFIX}*", count=100)
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break
            logger.info("redis_cache_invalidated", domain=domain)
        except Exception as exc:
            logger.debug("redis_invalidate_failed", error=str(exc))

    async def clear(self) -> None:
        """Clear all pentaforge search cache keys."""
        await self.invalidate_domain("all")

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.aclose()
            self._redis = None
