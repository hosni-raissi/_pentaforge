"""PentaForge Scope & Safety Engine.

The security boundary of the entire platform.
No agent executes any action without passing through this layer.

Quick start:
    from server.safety import ScopeAndSafetyEngine, EngagementScope, ActionRequest

    scope = EngagementScope(
        allowed_cidrs=["10.0.0.0/24"],
        allowed_domains=["*.target.com"],
    )
    engine = ScopeAndSafetyEngine(scope=scope, auto_approve=True)

    action = ActionRequest(agent="recon", tool="nmap", target="10.0.0.5")
    result = await engine.check(action)
    if result.allowed:
        raw_output = await run_tool(action)
        safe_output = engine.sanitize_output(raw_output, "nmap")
"""

from .approval import ApprovalGate, ApprovalRequest
from .engine import ScopeAndSafetyEngine
from .kill_switch import KillSwitch
from .models import ActionRequest, CheckResult, EngagementScope, Verdict
from .prompt_guard import PromptInjectionGuard
from .rate_limiter import RateLimiter
from .scope import ScopeEnforcer

__all__ = [
    "ScopeAndSafetyEngine",
    "ScopeEnforcer",
    "ApprovalGate",
    "ApprovalRequest",
    "RateLimiter",
    "KillSwitch",
    "PromptInjectionGuard",
    "ActionRequest",
    "CheckResult",
    "EngagementScope",
    "Verdict",
]