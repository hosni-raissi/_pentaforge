"""Kill Switch — halts all agents instantly on demand."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from .config import KILL_SWITCH_CHANNEL, KILL_SWITCH_KEY
from .models import ActionRequest, CheckResult, Verdict

logger = structlog.get_logger(__name__)


class KillSwitch:
    """Global emergency stop.

    When engaged, every safety check returns DENY immediately.
    Uses an asyncio.Event for zero-latency in-process checks.
    Optionally broadcasts via Redis for multi-process deployments.

    Usage:
        kill_switch.engage("Emergency stop requested by pentester")
        kill_switch.disengage()
        result = kill_switch.check(action)
    """

    def __init__(self, redis_client: Any | None = None) -> None:
        self._engaged = False
        self._engaged_at: float | None = None
        self._reason: str = ""
        self._engaged_by: str = ""
        self._event = asyncio.Event()
        self._event.set()  # Set = not killed = agents can run.
        self._redis = redis_client

    @property
    def is_engaged(self) -> bool:
        return self._engaged

    @property
    def status(self) -> dict[str, Any]:
        return {
            "engaged": self._engaged,
            "reason": self._reason,
            "engaged_at": self._engaged_at,
            "engaged_by": self._engaged_by,
        }

    def check(self, action: ActionRequest) -> CheckResult:
        """Instant check — no async needed."""
        if self._engaged:
            return CheckResult(
                verdict=Verdict.DENY,
                component="kill_switch",
                reason=f"KILL SWITCH ENGAGED: {self._reason}",
                metadata={"engaged_at": self._engaged_at},
            )
        return CheckResult(
            verdict=Verdict.ALLOW,
            component="kill_switch",
            reason="Kill switch not engaged.",
        )

    async def engage(self, reason: str = "Manual kill", engaged_by: str = "system") -> None:
        """Engage the kill switch — all agents stop immediately."""
        self._engaged = True
        self._engaged_at = time.time()
        self._reason = reason
        self._engaged_by = engaged_by
        self._event.clear()  # Block any waiters.

        logger.critical(
            "kill_switch_engaged",
            reason=reason,
            engaged_by=engaged_by,
        )

        # Broadcast via Redis if available.
        if self._redis:
            try:
                await self._redis.set(KILL_SWITCH_KEY, reason)
                await self._redis.publish(KILL_SWITCH_CHANNEL, reason)
            except Exception as exc:
                logger.error("kill_switch_redis_error", error=str(exc))

    async def disengage(self, disengaged_by: str = "system") -> None:
        """Disengage the kill switch — agents can resume."""
        self._engaged = False
        self._reason = ""
        self._engaged_by = ""
        self._engaged_at = None
        self._event.set()

        logger.info("kill_switch_disengaged", disengaged_by=disengaged_by)

        if self._redis:
            try:
                await self._redis.delete(KILL_SWITCH_KEY)
            except Exception as exc:
                logger.error("kill_switch_redis_error", error=str(exc))

    async def wait_if_killed(self, timeout: float | None = None) -> bool:
        """Block until the kill switch is disengaged.

        Returns True if resumed, False if timeout expired.
        Useful for agents that want to pause instead of dying.
        """
        if not self._engaged:
            return True
        try:
            await asyncio.wait_for(self._event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def sync_from_redis(self) -> None:
        """Check Redis for persisted kill state on startup."""
        if not self._redis:
            return
        try:
            val = await self._redis.get(KILL_SWITCH_KEY)
            if val:
                self._engaged = True
                self._reason = val if isinstance(val, str) else val.decode()
                self._engaged_at = time.time()
                self._event.clear()
                logger.warning("kill_switch_restored_from_redis", reason=self._reason)
        except Exception as exc:
            logger.error("kill_switch_redis_sync_error", error=str(exc))