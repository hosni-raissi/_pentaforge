"""Rate limiter for LLM API calls to prevent Mistral 429 errors.

Mistral API limits: 4 requests per minute
This limiter enforces max 3 req/min (leaving 1 as buffer)
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


class LLMRateLimiter:
    """Simple rate limiter for LLM calls per agent."""

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
