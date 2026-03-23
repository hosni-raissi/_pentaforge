"""Scope Enforcer — validates every target against engagement boundaries."""

from __future__ import annotations

import ipaddress
import re
from fnmatch import fnmatch
from urllib.parse import urlparse

import structlog

from .config import MAX_TARGET_URL_LENGTH
from .models import ActionRequest, CheckResult, EngagementScope, Verdict

logger = structlog.get_logger(__name__)


class ScopeEnforcer:
    """Validates targets against CIDR ranges, domains, and exclusions.

    Rules:
    1. Target must match at least one allow rule.
    2. Target must NOT match any exclusion rule.
    3. If allowed_ports is set, port must be in the list.
    """

    def __init__(self, scope: EngagementScope) -> None:
        self._scope = scope

        # Pre-parse networks for fast matching.
        self._allowed_nets = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in scope.allowed_cidrs
        ]
        self._excluded_nets = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in scope.excluded_cidrs
        ]

        # Lowercase domains for case-insensitive matching.
        self._allowed_domains = [d.lower() for d in scope.allowed_domains]
        self._excluded_domains = [d.lower() for d in scope.excluded_domains]
        self._allowed_urls = [u.lower().rstrip("/") for u in scope.allowed_urls]
        self._allowed_ports = set(scope.allowed_ports) if scope.allowed_ports else None

    def check(self, action: ActionRequest) -> CheckResult:
        """Validate an action's target against scope boundaries."""
        target = action.target.strip()

        if not target:
            return CheckResult(
                verdict=Verdict.DENY,
                component="scope",
                reason="Empty target.",
            )

        if len(target) > MAX_TARGET_URL_LENGTH:
            return CheckResult(
                verdict=Verdict.DENY,
                component="scope",
                reason=f"Target exceeds max length ({MAX_TARGET_URL_LENGTH}).",
            )

        host, port = self._extract_host_port(target)

        # ── Port check ─────────────────────────────────────────────
        if self._allowed_ports and port and port not in self._allowed_ports:
            return CheckResult(
                verdict=Verdict.DENY,
                component="scope",
                reason=f"Port {port} not in allowed ports.",
                metadata={"port": port, "allowed": sorted(self._allowed_ports)},
            )

        # ── Exclusion check (runs first — exclusions override allows) ──
        if self._is_excluded(host):
            logger.warning("scope_excluded", target=target, host=host)
            return CheckResult(
                verdict=Verdict.DENY,
                component="scope",
                reason=f"Target '{host}' is explicitly excluded from scope.",
                metadata={"host": host},
            )

        # ── Allow check ────────────────────────────────────────────
        if self._is_allowed(host, target):
            return CheckResult(
                verdict=Verdict.ALLOW,
                component="scope",
                reason=f"Target '{host}' is in scope.",
            )

        # ── No match → deny ────────────────────────────────────────
        logger.warning("scope_denied", target=target, host=host)
        return CheckResult(
            verdict=Verdict.DENY,
            component="scope",
            reason=f"Target '{host}' is not in scope.",
            metadata={"host": host},
        )

    # ── Internal helpers ───────────────────────────────────────────

    def _extract_host_port(self, target: str) -> tuple[str, int | None]:
        """Extract hostname/IP and optional port from a target string."""
        # URL?
        if "://" in target:
            parsed = urlparse(target)
            return (parsed.hostname or "").lower(), parsed.port

        # host:port?
        if ":" in target and not target.startswith("["):
            # Avoid splitting IPv6.
            parts = target.rsplit(":", 1)
            if parts[1].isdigit():
                return parts[0].lower(), int(parts[1])

        return target.lower(), None

    def _is_ip(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _is_allowed(self, host: str, full_target: str) -> bool:
        # Check IP against allowed CIDRs.
        if self._is_ip(host):
            try:
                addr = ipaddress.ip_address(host)
                return any(addr in net for net in self._allowed_nets)
            except ValueError:
                return False

        # Check domain against allowed domains (with wildcard support).
        if any(self._domain_matches(host, pattern) for pattern in self._allowed_domains):
            return True

        # Check full URL against allowed URLs.
        normalized = full_target.lower().rstrip("/")
        if any(normalized.startswith(url) for url in self._allowed_urls):
            return True

        return False

    def _is_excluded(self, host: str) -> bool:
        # Check IP exclusions.
        if self._is_ip(host):
            try:
                addr = ipaddress.ip_address(host)
                return any(addr in net for net in self._excluded_nets)
            except ValueError:
                return False

        # Check domain exclusions.
        return any(
            self._domain_matches(host, pattern)
            for pattern in self._excluded_domains
        )

    @staticmethod
    def _domain_matches(host: str, pattern: str) -> bool:
        """Match hostname against a domain pattern.

        Supports:
          "example.com"       → matches example.com exactly
          "*.example.com"     → matches sub.example.com, a.b.example.com
          ".example.com"      → same as *.example.com
        """
        if pattern.startswith("."):
            # .example.com → match host itself and any subdomain.
            base = pattern[1:]
            return host == base or host.endswith("." + base)

        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith("." + base)

        return host == pattern