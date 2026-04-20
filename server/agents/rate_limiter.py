"""Rate limiter for LLM API calls to prevent Mistral 429 errors.

Mistral API limits: 4 requests per minute
This implements BOTH:
1. Per-agent rate limiter (max 3 req/min per agent)
2. Global queue-based coordination (stagger calls across all agents to stay under 4 req/min total)
3. Backup LLM fallback (when 429 occurs, temporarily use backup LLM for single call)

Architecture:
- GlobalLLMQueue: Shared async queue enforcing max 3 concurrent requests globally
- LLMRateLimiter: Per-agent rate limiter as fallback if global queue not used
- BackupLLMFallback: Creates temporary LLM client when 429 error occurs
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


class BackupLLMFallback:
    """Manages fallback to backup LLM when rate limit (429) is hit.

    When the main LLM fails with 429, this creates a temporary backup LLM client
    for a single call, then returns to the main LLM for future calls.
    """

    def __init__(self):
        self._backup_llm_client = None
        self._backup_llm = None

    async def get_backup_llm(self):
        """Get or create backup LLM client for fallback.

        Returns None if backup LLM is not configured.
        Lazy-loads the backup client to avoid initialization overhead.
        """
        if self._backup_llm_client is not None:
            return self._backup_llm_client

        try:
            from server.core.llm import get_backup_llm_config, LLMClient

            backup_config = get_backup_llm_config()
            if backup_config is None:
                logger.warning("backup_llm_not_configured", message="Backup LLM env vars not set")
                return None

            if backup_config.api_key:
                self._backup_llm = backup_config
                self._backup_llm_client = LLMClient(backup_config)
                logger.info(
                    "backup_llm_initialized",
                    provider=backup_config.provider,
                    model=backup_config.model,
                )
                return self._backup_llm_client
        except Exception as e:
            logger.error("backup_llm_initialization_failed", error=str(e))
            return None

        return None

    async def create_backup_llm_context(self):
        """Create async context for backup LLM if available."""
        backup_client = await self.get_backup_llm()
        if backup_client is not None:
            return backup_client.__aenter__()
        return None

    async def close_backup_llm_context(self, context):
        """Close async context for backup LLM."""
        if context is not None:
            try:
                await context.__aexit__(None, None, None)
            except Exception as e:
                logger.error("backup_llm_context_close_failed", error=str(e))


# Global singleton for backup LLM fallback
_backup_llm_fallback: Optional[BackupLLMFallback] = None


def get_backup_llm_fallback() -> BackupLLMFallback:
    """Get or create the backup LLM fallback singleton."""
    global _backup_llm_fallback
    if _backup_llm_fallback is None:
        _backup_llm_fallback = BackupLLMFallback()
    return _backup_llm_fallback


class GlobalLLMQueue:
    """Global queue to coordinate LLM calls across all agents.

    Ensures maximum 3 concurrent API requests (safe for Mistral 4 req/min limit).
    All agents register and await through this queue before making LLM calls.
    """

    def __init__(self, *, max_concurrent: int = 3):
        """Initialize global queue.

        Args:
            max_concurrent: Maximum concurrent LLM requests allowed (default: 3, safe for Mistral 4 req/min)
        """
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_calls: int = 0
        self._lock = asyncio.Lock()
        self._call_times: list[float] = []

    async def acquire(self, agent_name: str) -> None:
        """Acquire permission to make an LLM call.

        This is a blocking call that waits if necessary to respect rate limits.
        Call this BEFORE making any LLM API call.

        Args:
            agent_name: Name of the agent making the call (for logging)
        """
        await self._semaphore.acquire()
        self._active_calls += 1

        now = time.time()
        minute_ago = now - 60.0

        async with self._lock:
            # Clean old call times
            self._call_times = [t for t in self._call_times if t > minute_ago]
            self._call_times.append(now)

            calls_in_minute = len(self._call_times)
            logger.info(
                "global_llm_queue_acquired",
                agent=agent_name,
                active_concurrent=self._active_calls,
                max_concurrent=self._max_concurrent,
                calls_in_minute=calls_in_minute,
                max_per_minute=3,
            )

    def release(self, agent_name: str) -> None:
        """Release an LLM call slot.

        Call this AFTER your LLM API call completes (success or failure).

        Args:
            agent_name: Name of the agent releasing the call (for logging)
        """
        self._active_calls -= 1
        self._semaphore.release()
        logger.info(
            "global_llm_queue_released",
            agent=agent_name,
            active_concurrent=self._active_calls,
        )

    async def call_with_queue(
        self,
        agent_name: str,
        coro,
    ):
        """Execute a coroutine with global queue protection.

        Automatically acquires queue slot, runs the coroutine, and releases.
        This is the recommended way to use the queue.

        Args:
            agent_name: Name of the agent making the call
            coro: Coroutine to execute (typically an LLM API call)

        Returns:
            Result of the coroutine

        Raises:
            Any exception raised by the coroutine
        """
        await self.acquire(agent_name)
        try:
            result = await coro
            return result
        finally:
            self.release(agent_name)


# Global singleton instance
_global_llm_queue: Optional[GlobalLLMQueue] = None


def get_global_llm_queue() -> GlobalLLMQueue:
    """Get or create the global LLM queue singleton."""
    global _global_llm_queue
    if _global_llm_queue is None:
        _global_llm_queue = GlobalLLMQueue(max_concurrent=3)
    return _global_llm_queue


class LLMRateLimiter:
    """Per-agent rate limiter for LLM calls.

    Deprecated in favor of GlobalLLMQueue, but kept for backward compatibility.
    New implementations should use GlobalLLMQueue.get_global_llm_queue().
    """

    def __init__(self, *, max_calls_per_minute: int = 3):
        """Initialize rate limiter.

        Args:
            max_calls_per_minute: Maximum LLM calls allowed per minute (default: 3, safe for Mistral 4 req/min limit)
        """
        self._max_calls_per_minute = max_calls_per_minute
        self._call_times: list[float] = []
        self._lock = asyncio.Lock()

    async def wait_if_needed(self) -> None:
        """Wait if necessary to respect rate limit."""
        async with self._lock:
            now = time.time()
            minute_ago = now - 60.0

            # Remove calls older than 1 minute
            self._call_times = [t for t in self._call_times if t > minute_ago]

            # If we've hit the limit, wait until the oldest call drops out
            if len(self._call_times) >= self._max_calls_per_minute:
                oldest = self._call_times[0]
                wait_time = (oldest - minute_ago) + 0.1  # Small buffer
                if wait_time > 0:
                    logger.warning(
                        "llm_rate_limit_wait",
                        calls_in_minute=len(self._call_times),
                        max_allowed=self._max_calls_per_minute,
                        wait_seconds=round(wait_time, 2),
                    )
                    await asyncio.sleep(wait_time)
                    now = time.time()
                    self._call_times = [t for t in self._call_times if t > now - 60.0]

            # Record this call
            self._call_times.append(now)
            calls_in_window = len(self._call_times)
            logger.info(
                "llm_call_recorded",
                calls_in_minute=calls_in_window,
                max_allowed=self._max_calls_per_minute,
            )

    def reset(self) -> None:
        """Reset the call history."""
        self._call_times = []
        logger.info("llm_rate_limiter_reset")


class GlobalLLMQueue:
    """Global queue to coordinate LLM calls across all agents.

    Ensures maximum 3 concurrent API requests (safe for Mistral 4 req/min limit).
    All agents register and await through this queue before making LLM calls.
    """

    def __init__(self, *, max_concurrent: int = 3):
        """Initialize global queue.

        Args:
            max_concurrent: Maximum concurrent LLM requests allowed (default: 3, safe for Mistral 4 req/min)
        """
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_calls: int = 0
        self._lock = asyncio.Lock()
        self._call_times: list[float] = []

    async def acquire(self, agent_name: str) -> None:
        """Acquire permission to make an LLM call.

        This is a blocking call that waits if necessary to respect rate limits.
        Call this BEFORE making any LLM API call.

        Args:
            agent_name: Name of the agent making the call (for logging)
        """
        await self._semaphore.acquire()
        self._active_calls += 1

        now = time.time()
        minute_ago = now - 60.0

        async with self._lock:
            # Clean old call times
            self._call_times = [t for t in self._call_times if t > minute_ago]
            self._call_times.append(now)

            calls_in_minute = len(self._call_times)
            logger.info(
                "global_llm_queue_acquired",
                agent=agent_name,
                active_concurrent=self._active_calls,
                max_concurrent=self._max_concurrent,
                calls_in_minute=calls_in_minute,
                max_per_minute=3,
            )

    def release(self, agent_name: str) -> None:
        """Release an LLM call slot.

        Call this AFTER your LLM API call completes (success or failure).

        Args:
            agent_name: Name of the agent releasing the call (for logging)
        """
        self._active_calls -= 1
        self._semaphore.release()
        logger.info(
            "global_llm_queue_released",
            agent=agent_name,
            active_concurrent=self._active_calls,
        )

    async def call_with_queue(
        self,
        agent_name: str,
        coro,
    ):
        """Execute a coroutine with global queue protection.

        Automatically acquires queue slot, runs the coroutine, and releases.
        This is the recommended way to use the queue.

        Args:
            agent_name: Name of the agent making the call
            coro: Coroutine to execute (typically an LLM API call)

        Returns:
            Result of the coroutine

        Raises:
            Any exception raised by the coroutine
        """
        await self.acquire(agent_name)
        try:
            result = await coro
            return result
        finally:
            self.release(agent_name)


# Global singleton instance
_global_llm_queue: Optional[GlobalLLMQueue] = None


def get_global_llm_queue() -> GlobalLLMQueue:
    """Get or create the global LLM queue singleton."""
    global _global_llm_queue
    if _global_llm_queue is None:
        _global_llm_queue = GlobalLLMQueue(max_concurrent=3)
    return _global_llm_queue


class LLMRateLimiter:
    """Per-agent rate limiter for LLM calls.

    Deprecated in favor of GlobalLLMQueue, but kept for backward compatibility.
    New implementations should use GlobalLLMQueue.get_global_llm_queue().
    """

    def __init__(self, *, max_calls_per_minute: int = 3):
        """Initialize rate limiter.

        Args:
            max_calls_per_minute: Maximum LLM calls allowed per minute (default: 3, safe for Mistral 4 req/min limit)
        """
        self._max_calls_per_minute = max_calls_per_minute
        self._call_times: list[float] = []
        self._lock = asyncio.Lock()

    async def wait_if_needed(self) -> None:
        """Wait if necessary to respect rate limit."""
        async with self._lock:
            now = time.time()
            minute_ago = now - 60.0

            # Remove calls older than 1 minute
            self._call_times = [t for t in self._call_times if t > minute_ago]

            # If we've hit the limit, wait until the oldest call drops out
            if len(self._call_times) >= self._max_calls_per_minute:
                oldest = self._call_times[0]
                wait_time = (oldest - minute_ago) + 0.1  # Small buffer
                if wait_time > 0:
                    logger.warning(
                        "llm_rate_limit_wait",
                        calls_in_minute=len(self._call_times),
                        max_allowed=self._max_calls_per_minute,
                        wait_seconds=round(wait_time, 2),
                    )
                    await asyncio.sleep(wait_time)
                    now = time.time()
                    self._call_times = [t for t in self._call_times if t > now - 60.0]

            # Record this call
            self._call_times.append(now)
            calls_in_window = len(self._call_times)
            logger.info(
                "llm_call_recorded",
                calls_in_minute=calls_in_window,
                max_allowed=self._max_calls_per_minute,
            )

    def reset(self) -> None:
        """Reset the call history."""
        self._call_times = []
        logger.info("llm_rate_limiter_reset")
