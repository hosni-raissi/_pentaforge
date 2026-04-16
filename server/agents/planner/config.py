"""Planner Agent — Configuration constants."""
import asyncio
from typing import FrozenSet
import httpx
MAX_LLM_REQUESTS = 2
MAX_TOOL_ROUNDS = MAX_LLM_REQUESTS

PLANNER_CALL_TIMEOUT_SECONDS: int = 90

PLANNER_MAX_TOKENS_PER_REQUEST: int = 4096
PLANNER_CONTEXT_WINDOW_MAX_TOKENS: int = 10000

MAX_TOOL_RESULT_CHARS: int = 1200

# Keep Intel checklist context small when handing off to Planner.
PLANNER_CHECKLIST_WINDOW_MAX_ITEMS: int = 28
PLANNER_CHECKLIST_WINDOW_MAX_ITEMS_PER_PHASE: int = 8
# Track high-priority items (P1=Critical, P2=High) for focused planning
PLANNER_CHECKLIST_SUMMARY_MAX_HIGH_PRIORITY_PENDING: int = 12
PLANNER_CHECKLIST_SUMMARY_MAX_CHANGED_ITEMS: int = 10

# Keep loop context bounded so Planner does not carry the full plan forever.
# 0 => uncapped (no hard truncation). Set >0 to enforce a cap.
PLANNER_LOOP_CONTEXT_MAX_STEPS_PER_PHASE: int = 0
PLANNER_LOOP_CONTEXT_MAX_SCENARIOS_PER_STEP: int = 0

_DISCOVERY_TOOLS = frozenset({"get_page", "search_kb", "search_web"})
_TRANSIENT_EXCEPTIONS = (
    asyncio.TimeoutError,
    TimeoutError,
    httpx.ReadTimeout,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
)
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 2.0
_RETRY_JITTER_MAX = 1.5
