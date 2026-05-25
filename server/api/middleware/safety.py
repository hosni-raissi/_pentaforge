"""FastAPI middleware that applies API safety controls."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import Message

from server.layers.safety.models import ActionRequest, Verdict
from server.layers.safety.rate_limiter import RateLimiter
from server.layers.safety.target_validation import IPValidator, UrlNormalizer

_RETRY_AFTER_RE = re.compile(r"Retry after ([0-9]+(?:\.[0-9]+)?)s", re.IGNORECASE)
_TARGET_VALIDATION_METHODS = {"POST", "PUT", "PATCH"}
_IP_FIELD_SEGMENTS = {"ip", "ip_address", "target_ip", "gateway", "cidr"}
_URL_FIELD_SEGMENTS = {"url", "uri", "link", "endpoint"}
_KEY_SPLIT_RE = re.compile(r"[._-]+")
_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


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


def _iter_string_fields(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            next_prefix = f"{prefix}.{key_text}" if prefix else key_text
            yield from _iter_string_fields(child, next_prefix)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            next_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            yield from _iter_string_fields(child, next_prefix)
        return
    if isinstance(value, str):
        text = value.strip()
        if text:
            yield prefix, text


def _key_segments(key: str) -> set[str]:
    return {segment for segment in _KEY_SPLIT_RE.split(key.lower()) if segment}


def _is_ip_field(key: str) -> bool:
    segments = _key_segments(key)
    return bool(_IP_FIELD_SEGMENTS & segments)


def _is_url_field(key: str) -> bool:
    segments = _key_segments(key)
    return bool(_URL_FIELD_SEGMENTS & segments)


def _is_target_field(key: str) -> bool:
    lowered = key.lower()
    return lowered == "target" or lowered.endswith(".target")


def _looks_like_local_path(value: str) -> bool:
    candidate = (value or "").strip()
    if not candidate:
        return False
    if "://" in candidate:
        return False
    return (
        candidate.startswith("/")
        or candidate.startswith("./")
        or candidate.startswith("../")
        or candidate.startswith("~/")
        or bool(_WINDOWS_PATH_RE.match(candidate))
    )


async def _extract_json_payload(request: Request) -> tuple[Request, Any | None]:
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" not in content_type:
        return request, None

    body = await request.body()

    async def receive() -> Message:
        return {"type": "http.request", "body": body, "more_body": False}

    rebuilt_request = Request(request.scope, receive)
    if not body:
        return rebuilt_request, None

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Let FastAPI/Pydantic return its own request-body errors.
        return rebuilt_request, None

    return rebuilt_request, payload


async def _normalize_string_target_field(field: str, value: str) -> tuple[str, dict[str, str] | None]:
    is_target_field = _is_target_field(field)

    if _is_ip_field(field):
        ip_result = IPValidator(value).validate()
        if not ip_result.get("valid", False):
            return value, {
                "field": field,
                "value": value,
                "reason": ip_result.get("error", "invalid IP/CIDR"),
                "type": "ip",
            }
        return value, None

    if is_target_field:
        if _looks_like_local_path(value):
            return value, None
        ip_result = IPValidator(value).validate()
        if ip_result.get("valid", False):
            return value, None

    if _is_url_field(field) or is_target_field:
        # API target validation should stay cheap and syntax-focused.
        # Live reachability probes here create noisy background traffic for
        # assistant endpoints like context-metrics and stream setup.
        url_result = await UrlNormalizer(value, probe_reachability=False).normalize()
        if not bool(url_result.get("valid")):
            return value, {
                "field": field,
                "value": value,
                "reason": url_result.get("error") or "invalid URL",
                "type": "url",
            }
        normalized = url_result.get("normalized_url") or value
        return normalized, None

    return value, None


async def _normalize_target_payload(payload: Any, prefix: str = "") -> tuple[Any, list[dict[str, str]]]:
    if isinstance(payload, dict):
        normalized: dict[str, Any] = {}
        errors: list[dict[str, str]] = []
        for key, child in payload.items():
            key_text = str(key)
            next_prefix = f"{prefix}.{key_text}" if prefix else key_text
            normalized_child, child_errors = await _normalize_target_payload(child, next_prefix)
            normalized[key] = normalized_child
            errors.extend(child_errors)
        return normalized, errors

    if isinstance(payload, list):
        normalized_items: list[Any] = []
        errors: list[dict[str, str]] = []
        for index, child in enumerate(payload):
            next_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            normalized_child, child_errors = await _normalize_target_payload(child, next_prefix)
            normalized_items.append(normalized_child)
            errors.extend(child_errors)
        return normalized_items, errors

    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return payload, []
        normalized, error = await _normalize_string_target_field(prefix, text)
        return normalized, [error] if error else []

    return payload, []


def _rebuild_json_request(request: Request, payload: Any) -> Request:
    body = json.dumps(payload).encode("utf-8")

    async def receive() -> Message:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(request.scope, receive)


class APISafetyMiddleware(BaseHTTPMiddleware):
    """Applies API safety controls (rate limiting + target validation)."""

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
            headers["X-PentaForge-Rate-Limiter"] = "active"
            return JSONResponse(
                status_code=429,
                content={
                    "detail": result.reason or "Rate limit exceeded",
                    "component": result.component,
                },
                headers=headers,
            )

        request_for_next = request
        if request.method.upper() in _TARGET_VALIDATION_METHODS:
            request_for_next, payload = await _extract_json_payload(request)
            if payload is not None:
                normalized_payload, target_errors = await _normalize_target_payload(payload)
                if target_errors:
                    return JSONResponse(
                        status_code=422,
                        content={
                            "detail": "Target validation failed",
                            "component": "target_validation",
                            "errors": target_errors,
                        },
                        headers={"X-PentaForge-Target-Validation": "active"},
                    )
                if normalized_payload != payload:
                    request_for_next = _rebuild_json_request(request, normalized_payload)

        response = await call_next(request_for_next)
        response.headers["X-PentaForge-Rate-Limiter"] = "active"
        response.headers["X-PentaForge-Target-Validation"] = "active"
        return response


# Backward-compatible alias for older imports.
APIRateLimitMiddleware = APISafetyMiddleware
