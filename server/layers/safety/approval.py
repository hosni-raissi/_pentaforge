"""Approval Gate — pauses before high-impact actions for human confirmation."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

import structlog

from .config import (
    APPROVAL_REQUIRED_AGENTS,
    APPROVAL_REQUIRED_SSVC,
    APPROVAL_TIMEOUT_SECONDS,
)
from .models import ActionRequest, CheckResult, EngagementScope, Verdict

logger = structlog.get_logger(__name__)


@dataclass
class ApprovalRequest:
    """Pending approval waiting for human decision."""
    id: str
    action: ActionRequest
    created_at: float
    reason: str
    resolved: bool = False
    approved: bool = False
    resolved_by: str = ""
    resolved_at: float | None = None


# Callback type for notifying the UI about pending approvals.
ApprovalNotifier = Callable[[ApprovalRequest], Awaitable[None]]


class ApprovalGate:
    """Human-in-the-loop approval for high-impact actions.

    Flow:
    1. Agent submits action → check() determines if approval needed.
    2. If needed, request_approval() creates a pending request and
       notifies the UI (via callback or Redis).
    3. Agent blocks until approve() or deny() is called, or timeout.
    4. UI calls approve(request_id) or deny(request_id).

    For testing/auto mode, set auto_approve=True.
    """

    def __init__(
        self,
        scope: EngagementScope | None = None,
        auto_approve: bool = False,
        timeout: int = APPROVAL_TIMEOUT_SECONDS,
        notifier: ApprovalNotifier | None = None,
        redis_client: Any | None = None,
    ) -> None:
        self._scope = scope
        self._auto_approve = auto_approve
        self._timeout = timeout
        self._notifier = notifier
        self._redis = redis_client

        # Pending approvals: id → (ApprovalRequest, asyncio.Event)
        self._pending: dict[str, tuple[ApprovalRequest, asyncio.Event]] = {}

    def needs_approval(self, action: ActionRequest) -> tuple[bool, str]:
        """Determine if this action requires human approval.

        Returns (needs_approval, reason).
        """
        # Auto-approve recon if scope says so.
        if (
            self._scope
            and self._scope.auto_approve_recon
            and action.agent == "recon"
        ):
            return False, ""

        # SSVC ACT level always needs approval.
        if action.ssvc_level.upper() in APPROVAL_REQUIRED_SSVC:
            return True, f"SSVC level '{action.ssvc_level}' requires human approval."

        # Exploit agent always needs approval.
        if action.agent.lower() in APPROVAL_REQUIRED_AGENTS:
            return True, f"Agent '{action.agent}' requires human approval."

        return False, ""

    def check(self, action: ActionRequest) -> CheckResult:
        """Quick synchronous check — does NOT block for approval.

        Returns ALLOW if no approval needed, PENDING if it is.
        Caller must then call request_approval() to actually wait.
        """
        if self._auto_approve:
            return CheckResult(
                verdict=Verdict.ALLOW,
                component="approval",
                reason="Auto-approve mode enabled.",
            )

        needs, reason = self.needs_approval(action)
        if not needs:
            return CheckResult(
                verdict=Verdict.ALLOW,
                component="approval",
                reason="No approval required for this action.",
            )

        return CheckResult(
            verdict=Verdict.PENDING,
            component="approval",
            reason=reason,
        )

    async def request_approval(self, action: ActionRequest) -> CheckResult:
        """Block until human approves/denies or timeout expires.

        This is the async version that actually waits.
        """
        if self._auto_approve:
            return CheckResult(
                verdict=Verdict.ALLOW,
                component="approval",
                reason="Auto-approved.",
            )

        needs, reason = self.needs_approval(action)
        if not needs:
            return CheckResult(
                verdict=Verdict.ALLOW,
                component="approval",
                reason="No approval required.",
            )

        # Create pending request.
        request_id = uuid.uuid4().hex[:12]
        request = ApprovalRequest(
            id=request_id,
            action=action,
            created_at=time.time(),
            reason=reason,
        )
        event = asyncio.Event()
        self._pending[request_id] = (request, event)

        logger.info(
            "approval_requested",
            request_id=request_id,
            agent=action.agent,
            tool=action.tool,
            target=action.target,
            reason=reason,
        )

        # Notify UI.
        if self._notifier:
            try:
                await self._notifier(request)
            except Exception as exc:
                logger.error("approval_notifier_error", error=str(exc))

        if self._redis:
            try:
                import json
                await self._redis.publish("approval.required", json.dumps({
                    "id": request_id,
                    "agent": action.agent,
                    "tool": action.tool,
                    "target": action.target,
                    "reason": reason,
                    "timestamp": request.created_at,
                }))
            except Exception as exc:
                logger.error("approval_redis_error", error=str(exc))

        # Wait for resolution.
        try:
            await asyncio.wait_for(event.wait(), timeout=self._timeout)
        except asyncio.TimeoutError:
            request.resolved = True
            request.approved = False
            request.resolved_by = "timeout"
            request.resolved_at = time.time()
            self._pending.pop(request_id, None)

            logger.warning("approval_timeout", request_id=request_id)
            return CheckResult(
                verdict=Verdict.DENY,
                component="approval",
                reason=f"Approval timed out after {self._timeout}s.",
                metadata={"request_id": request_id},
            )

        # Resolved by human.
        self._pending.pop(request_id, None)
        if request.approved:
            logger.info("approval_granted", request_id=request_id, by=request.resolved_by)
            return CheckResult(
                verdict=Verdict.ALLOW,
                component="approval",
                reason=f"Approved by {request.resolved_by}.",
                metadata={"request_id": request_id},
            )
        else:
            logger.info("approval_denied", request_id=request_id, by=request.resolved_by)
            return CheckResult(
                verdict=Verdict.DENY,
                component="approval",
                reason=f"Denied by {request.resolved_by}.",
                metadata={"request_id": request_id},
            )

    def approve(self, request_id: str, approved_by: str = "pentester") -> bool:
        """Approve a pending request (called from UI/API)."""
        entry = self._pending.get(request_id)
        if entry is None:
            return False
        request, event = entry
        request.resolved = True
        request.approved = True
        request.resolved_by = approved_by
        request.resolved_at = time.time()
        event.set()
        return True

    def deny(self, request_id: str, denied_by: str = "pentester") -> bool:
        """Deny a pending request (called from UI/API)."""
        entry = self._pending.get(request_id)
        if entry is None:
            return False
        request, event = entry
        request.resolved = True
        request.approved = False
        request.resolved_by = denied_by
        request.resolved_at = time.time()
        event.set()
        return True

    @property
    def pending_requests(self) -> list[ApprovalRequest]:
        """List all unresolved approval requests."""
        return [req for req, _ in self._pending.values() if not req.resolved]

    def clear(self) -> None:
        """Deny and clear all pending requests."""
        for request_id in list(self._pending.keys()):
            self.deny(request_id, denied_by="system_clear")
        self._pending.clear()