"""Planner Agent — Configuration constants."""
import asyncio
from typing import FrozenSet
import httpx
MAX_LLM_REQUESTS = 10
MAX_TOOL_ROUNDS = MAX_LLM_REQUESTS

PLANNER_CALL_TIMEOUT_SECONDS: int = 90

PLANNER_MAX_TOKENS_PER_REQUEST: int = 4096

MAX_TOOL_RESULT_CHARS: int = 1200

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