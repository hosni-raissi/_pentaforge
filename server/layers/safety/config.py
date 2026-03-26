"""Scope & Safety Engine — Configuration."""

from __future__ import annotations



#------------------------------------url normalization defaults────────────────────────────────────────

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_CLIENT = "https"


# ── Rate Limiter ────────────────────────────────────────────────────
# Default tokens per target per minute.
RATE_LIMIT_TOKENS_PER_MINUTE: int = 60
# Burst: max tokens that can accumulate.
RATE_LIMIT_BURST: int = 20
# How often the bucket refills (seconds).
RATE_LIMIT_REFILL_INTERVAL: float = 1.0

# ── Approval Gate ───────────────────────────────────────────────────
# Seconds to wait for human approval before auto-denying.
APPROVAL_TIMEOUT_SECONDS: int = 300  # 5 minutes
# Actions that always require approval (by agent type or SSVC level).
APPROVAL_REQUIRED_AGENTS: frozenset[str] = frozenset({"exploit"})
APPROVAL_REQUIRED_SSVC: frozenset[str] = frozenset({"ACT"})

# ── Kill Switch ─────────────────────────────────────────────────────
# Redis channel for kill broadcast.
KILL_SWITCH_CHANNEL: str = "control.kill"
# Redis key that persists the killed state.
KILL_SWITCH_KEY: str = "pentaforge:kill_switch"

# ── Prompt Injection Guard ──────────────────────────────────────────
# Max chars of tool output allowed into LLM context.
PROMPT_GUARD_MAX_OUTPUT_CHARS: int = 4000
# Max individual line length before truncation.
PROMPT_GUARD_MAX_LINE_LENGTH: int = 500
