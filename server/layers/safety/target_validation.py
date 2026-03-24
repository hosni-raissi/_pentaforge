"""Target Validation / Scope Enforcer for Safety layer.

Responsibilities:
1. Validate and normalize target strings (especially URL targets).
2. Enforce engagement scope allow/exclude rules.
3. Normalize frontend scan request target fields before orchestration.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict
from fnmatch import fnmatch
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .config import MAX_TARGET_URL_LENGTH
from .models import ActionRequest, CheckResult, EngagementScope, Verdict


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _normalize_url(url: str) -> tuple[str, bool, str]:
    """Normalize URL and return (normalized, changed, error)."""
    raw = (url or "").strip()
    if not raw:
        return "", False, "empty target URL"
    if len(raw) > MAX_TARGET_URL_LENGTH:
        return "", False, f"target URL exceeds max length ({MAX_TARGET_URL_LENGTH})"

    candidate = raw
    if "://" not in candidate:
        candidate = f"http://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return "", False, "invalid URL format"

    if parsed.scheme not in {"http", "https"}:
        return "", False, "unsupported URL scheme (allowed: http, https)"
    if not parsed.netloc:
        return "", False, "URL must include host"

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return "", False, "URL host is missing"

    if " " in host:
        return "", False, "URL host contains spaces"

    port = parsed.port
    netloc = host
    if port and not (
        (parsed.scheme == "http" and port == 80)
        or (parsed.scheme == "https" and port == 443)
    ):
        netloc = f"{host}:{port}"

    path = parsed.path or "/"
    normalized = urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.query or "",
            "",  # drop fragment
        )
    )
    return normalized, normalized != raw, ""


def _extract_host_from_target(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            return (urlsplit(raw).hostname or "").strip().lower()
        except ValueError:
            return ""
    return raw.strip().lower()


def _matches_domain(host: str, pattern: str) -> bool:
    host = host.strip().lower()
    patt = pattern.strip().lower()
    if not host or not patt:
        return False
    if patt.startswith("*."):
        suffix = patt[2:]
        return host == suffix or host.endswith(f".{suffix}")
    return host == patt or fnmatch(host, patt)


class ScopeEnforcer:
    """Validates targets and enforces engagement scope boundaries."""

    def __init__(self, scope: EngagementScope | None = None) -> None:
        self._scope = scope or EngagementScope()

    def check(self, action: ActionRequest) -> CheckResult:
        """Validate + normalize target, then enforce allow/exclude scope."""
        target = (action.target or "").strip()
        if not target:
            return CheckResult(
                verdict=Verdict.DENY,
                component="target_validation",
                reason="Target is empty.",
            )

        normalized_target = target
        corrected = False

        # URL normalization when action target is URL-like.
        if "://" in target or "/" in target or target.startswith("www."):
            normalized_target, changed, error = _normalize_url(target)
            if error:
                return CheckResult(
                    verdict=Verdict.DENY,
                    component="target_validation",
                    reason=f"Invalid target URL: {error}.",
                    metadata={"target": target},
                )
            corrected = changed

        host = _extract_host_from_target(normalized_target)

        # Exclusions first.
        if host and any(
            _matches_domain(host, d) for d in self._scope.excluded_domains
        ):
            return CheckResult(
                verdict=Verdict.DENY,
                component="target_validation",
                reason=f"Target '{normalized_target}' is explicitly excluded from scope.",
                metadata={"normalized_target": normalized_target},
            )

        if _is_ip(host or normalized_target):
            ip_value = ipaddress.ip_address(host or normalized_target)
            if any(
                ip_value in ipaddress.ip_network(c, strict=False)
                for c in self._scope.excluded_cidrs
            ):
                return CheckResult(
                    verdict=Verdict.DENY,
                    component="target_validation",
                    reason=f"Target '{normalized_target}' is explicitly excluded from scope.",
                    metadata={"normalized_target": normalized_target},
                )

        # Allow rules.
        has_allow_rules = bool(
            self._scope.allowed_domains
            or self._scope.allowed_urls
            or self._scope.allowed_cidrs
        )
        if has_allow_rules:
            allowed = False

            if normalized_target in self._scope.allowed_urls:
                allowed = True

            if host and self._scope.allowed_domains and not allowed:
                allowed = any(
                    _matches_domain(host, d) for d in self._scope.allowed_domains
                )

            if self._scope.allowed_cidrs and not allowed:
                ip_candidate = host or normalized_target
                if _is_ip(ip_candidate):
                    ip_value = ipaddress.ip_address(ip_candidate)
                    allowed = any(
                        ip_value in ipaddress.ip_network(c, strict=False)
                        for c in self._scope.allowed_cidrs
                    )

            if not allowed:
                return CheckResult(
                    verdict=Verdict.DENY,
                    component="target_validation",
                    reason=(
                        f"Target '{normalized_target}' is outside engagement scope."
                    ),
                    metadata={"normalized_target": normalized_target},
                )

        metadata: dict[str, Any] = {"normalized_target": normalized_target}
        if corrected:
            metadata["corrected"] = True
            metadata["original_target"] = target

        return CheckResult(
            verdict=Verdict.ALLOW,
            component="target_validation",
            reason="Target is valid and in scope.",
            metadata=metadata,
        )

    def normalize_scan_request_target(
        self, scan_request: dict[str, Any]
    ) -> tuple[dict[str, Any], CheckResult]:
        """Normalize target fields coming from frontend scan request.

        Supports URL-bearing target types (web_app/api/mobile/repository/desktop).
        Returns (possibly-corrected payload, check result).
        """
        if not isinstance(scan_request, dict):
            return scan_request, CheckResult(
                verdict=Verdict.DENY,
                component="target_validation",
                reason="Scan request payload must be an object.",
            )

        corrected_payload = dict(scan_request)
        config = corrected_payload.get("config", {})
        if hasattr(config, "model_dump"):
            config = config.model_dump()  # pydantic model
        elif hasattr(config, "__dict__"):
            config = asdict(config) if hasattr(config, "__dataclass_fields__") else dict(config.__dict__)
        if not isinstance(config, dict):
            config = {}
        corrected_payload["config"] = config

        target_type = str(corrected_payload.get("target_type", "")).strip().lower()
        field_candidates = {
            "web_app": ["url"],
            "api": ["base_url", "spec_url"],
            "mobile": ["app_url"],
            "repository": ["repo_url"],
            "desktop": ["api_backend_url"],
        }.get(target_type, [])

        corrected_fields: list[dict[str, str]] = []
        for field_name in field_candidates:
            raw = config.get(field_name)
            if not isinstance(raw, str) or not raw.strip():
                continue
            normalized, changed, error = _normalize_url(raw)
            if error:
                return corrected_payload, CheckResult(
                    verdict=Verdict.DENY,
                    component="target_validation",
                    reason=f"Invalid '{field_name}' URL: {error}.",
                    metadata={"field": field_name, "value": raw},
                )
            if changed:
                config[field_name] = normalized
                corrected_fields.append(
                    {
                        "field": f"config.{field_name}",
                        "from": raw,
                        "to": normalized,
                    }
                )

        metadata: dict[str, Any] = {}
        if corrected_fields:
            metadata["corrected_fields"] = corrected_fields
            metadata["corrected"] = True

        return corrected_payload, CheckResult(
            verdict=Verdict.ALLOW,
            component="target_validation",
            reason="Scan request target fields are valid.",
            metadata=metadata,
        )
