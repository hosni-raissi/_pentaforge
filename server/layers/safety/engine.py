"""Scope & Safety Engine — unified gateway for all safety checks.

Every agent action passes through engine.check() before execution.
This is the single import point for the rest of PentaForge.

Architecture:
    ActionRequest → KillSwitch → ScopeEnforcer → RateLimiter → ApprovalGate → ALLOW
                     ↓ DENY       ↓ DENY          ↓ DENY        ↓ DENY
                    STOP         REJECT           THROTTLE       BLOCK
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from .approval import ApprovalGate, ApprovalNotifier
from .kill_switch import KillSwitch
from .models import ActionRequest, CheckResult, EngagementScope, Verdict
from .prompt_guard import PromptInjectionGuard
from .rate_limiter import RateLimiter

logger = structlog.get_logger(__name__)


class ScopeAndSafetyEngine:
    """Unified safety boundary for the entire PentaForge platform.

    Composes five components in a fail-fast pipeline:
    1. Kill Switch   — instant global halt
    2. Scope Enforcer — target within engagement boundaries
    3. Rate Limiter   — prevent accidental DoS
    4. Approval Gate  — human confirmation for high-impact actions
    5. Prompt Guard   — sanitize tool output before LLM context

    Usage:
        engine = ScopeAndSafetyEngine(scope=engagement_scope)
        result = await engine.check(action)
        if not result.allowed:
            logger.warning("Action blocked", reason=result.reason)
            return

        # After tool execution:
        safe_output = engine.sanitize_output(raw_output, tool_name="nmap")
    """

    def __init__(
        self,
        scope: EngagementScope | None = None,
        auto_approve: bool = False,
        redis_client: Any | None = None,
        approval_notifier: ApprovalNotifier | None = None,
    ) -> None:
        self._scope_def = scope or EngagementScope()
        self._created_at = time.time()

        # Initialize components.
        self.kill_switch = KillSwitch(redis_client=redis_client)
        self.rate_limiter = RateLimiter()
        self.approval_gate = ApprovalGate(
            scope=self._scope_def,
            auto_approve=auto_approve,
            notifier=approval_notifier,
            redis_client=redis_client,
        )
        self.prompt_guard = PromptInjectionGuard()

        logger.info(
            "safety_engine_initialized",
            cidrs=len(self._scope_def.allowed_cidrs),
            domains=len(self._scope_def.allowed_domains),
            auto_approve=auto_approve,
        )

    # ── Main check pipeline ────────────────────────────────────────

    async def check(self, action: ActionRequest) -> CheckResult:
        """Run the full safety pipeline. Returns first DENY or final ALLOW.

        Order: kill_switch → scope → rate_limit → approval.
        Each stage short-circuits on DENY.
        """
        # 1. Kill switch — instant, synchronous.
        result = self.kill_switch.check(action)
        if not result.allowed:
            self._log_deny(action, result)
            return result

        # 2. Scope enforcement — is target in bounds?
        result = self.scope_enforcer.check(action)
        if not result.allowed:
            self._log_deny(action, result)
            return result

        # 3. Rate limiting — are we going too fast?
        result = self.rate_limiter.check(action)
        if not result.allowed:
            self._log_deny(action, result)
            return result

        # 4. Approval gate — does this need human sign-off?
        #    Quick check first (synchronous), then async wait if needed.
        quick_check = self.approval_gate.check(action)
        if quick_check.verdict == Verdict.PENDING:
            result = await self.approval_gate.request_approval(action)
            if not result.allowed:
                self._log_deny(action, result)
                return result
        elif not quick_check.allowed:
            self._log_deny(action, quick_check)
            return quick_check

        # All checks passed.
        logger.debug(
            "safety_check_passed",
            agent=action.agent,
            tool=action.tool,
            target=action.target,
        )
        return CheckResult(
            verdict=Verdict.ALLOW,
            component="engine",
            reason="All safety checks passed.",
        )

    def check_sync(self, action: ActionRequest) -> CheckResult:
        """Synchronous check — skips approval gate (no async wait).

        Use this for quick pre-flight checks where you only need
        kill_switch + scope + rate_limit validation.
        """
        result = self.kill_switch.check(action)
        if not result.allowed:
            return result

        result = self.scope_enforcer.check(action)
        if not result.allowed:
            return result

        result = self.rate_limiter.check(action)
        if not result.allowed:
            return result

        return CheckResult(
            verdict=Verdict.ALLOW,
            component="engine",
            reason="Pre-flight checks passed.",
        )

    # ── Prompt sanitization ────────────────────────────────────────

    def sanitize_output(self, text: str, tool_name: str = "tool") -> str:
        """Sanitize tool output before feeding to LLM context.

        Call this after every tool execution, before the result
        enters the LLM message history.
        """
        return self.prompt_guard.sanitize(text, source=tool_name)

    def scan_output(self, text: str) -> list[str]:
        """Scan tool output for injection patterns without modifying.

        Returns list of detected pattern labels.
        """
        return self.prompt_guard.scan_only(text)

    # ── Scope management ───────────────────────────────────────────

    def update_scope(self, scope: EngagementScope) -> None:
        """Update engagement scope (e.g., scope expansion mid-engagement)."""
        self._scope_def = scope
        self.scope_enforcer = ScopeEnforcer(scope)
        self.approval_gate._scope = scope
        logger.info("scope_updated", cidrs=len(scope.allowed_cidrs))

    @property
    def scope(self) -> EngagementScope:
        return self._scope_def

    # ── Convenience ────────────────────────────────────────────────

    def is_target_in_scope(self, target: str) -> bool:
        """Quick boolean check — is this target in scope?"""
        dummy = ActionRequest(agent="check", tool="check", target=target)
        return self.scope_enforcer.check(dummy).allowed

    async def emergency_stop(self, reason: str = "Emergency", by: str = "system") -> None:
        """Engage kill switch and clear all pending approvals."""
        await self.kill_switch.engage(reason=reason, engaged_by=by)
        self.approval_gate.clear()

    async def resume(self, by: str = "system") -> None:
        """Disengage kill switch."""
        await self.kill_switch.disengage(disengaged_by=by)

    # ── Internal ───────────────────────────────────────────────────

    @staticmethod
    def _log_deny(action: ActionRequest, result: CheckResult) -> None:
        logger.warning(
            "safety_action_denied",
            agent=action.agent,
            tool=action.tool,
            target=action.target,
            component=result.component,
            reason=result.reason,
        )
