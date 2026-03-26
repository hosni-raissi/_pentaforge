"""FastAPI middleware wrapper around the safety-layer RateLimiter."""

from __future__ import annotations

import re
from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from server.layers.safety.models import ActionRequest, Verdict
from server.layers.safety.rate_limiter import RateLimiter

_RETRY_AFTER_RE = re.compile(r"Retry after ([0-9]+(?:\.[0-9]+)?)s", re.IGNORECASE)


def _extract_source_ip(request: Request) -> str | None:
    """Best-effort source IP extraction with proxy header support."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    if request.client is not None and request.client.host:
        return request.client.host
    return None


def _extract_retry_after(reason: str) -> str | None:
    match = _RETRY_AFTER_RE.search(reason or "")
    if not match:
        return None
    try:
        seconds = float(match.group(1))
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    # Retry-After header supports integer delta-seconds.
    return str(int(seconds) + (1 if seconds % 1 else 0))


class APIRateLimitMiddleware(BaseHTTPMiddleware):
    """Applies safety-layer rate limiting to incoming API requests."""

    def __init__(
        self,
        app,
        *,
        limiter: RateLimiter | None = None,
        excluded_paths: Iterable[str] | None = None,
    ) -> None:
        super().__init__(app)
        self._limiter = limiter or RateLimiter()
        self._excluded_paths = set(excluded_paths or [])

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if path in self._excluded_paths:
            return await call_next(request)

        action = ActionRequest(
            agent="api",
            tool=f"{request.method} {path}",
            target=path,
            args={"query": request.url.query},
            phase="http",
        )
        result = self._limiter.check(
            action,
            source_ip=_extract_source_ip(request),
        )

        if result.verdict != Verdict.ALLOW:
            headers: dict[str, str] = {}
            retry_after = _extract_retry_after(result.reason)
            if retry_after is not None:
                headers["Retry-After"] = retry_after
            return JSONResponse(
                status_code=429,
                content={
                    "detail": result.reason or "Rate limit exceeded",
                    "component": result.component,
                },
                headers=headers,
            )

        return await call_next(request)

