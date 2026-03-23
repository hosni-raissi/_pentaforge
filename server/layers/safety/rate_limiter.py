"""Rate Limiter — token bucket per target to prevent accidental DoS."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

import structlog

from .config import (
    RATE_LIMIT_BURST,
    RATE_LIMIT_REFILL_INTERVAL,
    RATE_LIMIT_TOKENS_PER_MINUTE,
)
from .models import ActionRequest, CheckResult, Verdict

logger = structlog.get_logger(__name__)


@dataclass
class _Bucket:
    """Single token bucket for one target."""
    tokens: float
    max_tokens: float
    refill_rate: float  # tokens per second
    last_refill: float = field(default_factory=time.monotonic)

    def try_consume(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.last_refill = now

        # Refill tokens.
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)

        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiter:
    """Token-bucket rate limiter keyed by target.

    Prevents agents from accidentally DoS-ing a target by
    enforcing a maximum request rate per target per minute.
    """

    def __init__(
        self,
        tokens_per_minute: int = RATE_LIMIT_TOKENS_PER_MINUTE,
        burst: int = RATE_LIMIT_BURST,
    ) -> None:
        self._tokens_per_minute = tokens_per_minute
        self._burst = burst
        self._refill_rate = tokens_per_minute / 60.0  # tokens per second
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def check(self, action: ActionRequest, cost: float = 1.0) -> CheckResult:
        """Try to consume a token for this action's target."""
        key = self._normalize_key(action.target)

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(
                    tokens=float(self._burst),
                    max_tokens=float(self._burst),
                    refill_rate=self._refill_rate,
                )
                self._buckets[key] = bucket

            if bucket.try_consume(cost):
                return CheckResult(
                    verdict=Verdict.ALLOW,
                    component="rate_limiter",
                    reason=f"Rate OK ({bucket.tokens:.0f} tokens remaining).",
                )

        logger.warning(
            "rate_limited",
            target=action.target,
            key=key,
            tokens_remaining=bucket.tokens,
        )
        return CheckResult(
            verdict=Verdict.DENY,
            component="rate_limiter",
            reason=(
                f"Rate limit exceeded for '{action.target}'. "
                f"Limit: {self._tokens_per_minute}/min, burst: {self._burst}."
            ),
        )

    def reset(self, target: str | None = None) -> None:
        """Reset rate limit for a target, or all targets if None."""
        with self._lock:
            if target is None:
                self._buckets.clear()
            else:
                self._buckets.pop(self._normalize_key(target), None)

    @staticmethod
    def _normalize_key(target: str) -> str:
        return target.strip().lower().rstrip("/")