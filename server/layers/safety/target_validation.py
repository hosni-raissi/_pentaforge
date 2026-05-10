"""URL Normalizer — probe a URL and return host, port, and reachability."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit
from .config import DEFAULT_CLIENT, DEFAULT_TIMEOUT_SECONDS
import httpx
import ipaddress


_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")


class UrlNormalizer:
    """
    Give it a URL (with or without scheme), it normalizes it and returns:
        {
            "host": str,
            "port": int,
            "valid": bool,
            "normalized_url": str,
            "reachable": bool,
            "error": str,
        }

    Rules:
    - Has https://  → keep https only, port 443
    - Has http://   → keep http only,  port 80
    - No scheme     → probe both concurrently:
                        · only one works  → return that one
                        · both work       → prefer configured default
                        · neither works   → keep a syntactically valid
                                             default URL instead of hard-failing
    """

    def __init__(
        self,
        url: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        *,
        probe_reachability: bool = True,
    ) -> None:
        self.raw = (url or "").strip()
        self.timeout = timeout
        self.probe_reachability = bool(probe_reachability)

    async def normalize(self) -> dict:
        if not self.raw:
            return self._result(error="empty URL")

        raw = self.raw

        # ── explicit scheme ──────────────────────────────────────────────
        if raw.startswith("https://"):
            host = self._extract_host(raw)
            if not self._is_reasonable_host(host):
                return self._result(host=host, error="invalid host")
            valid = await self._probe(raw) if self.probe_reachability else False
            return self._result(
                host=host,
                port=urlsplit(raw).port or 443,
                valid=True,
                normalized_url=raw,
                reachable=valid,
            )

        if raw.startswith("http://"):
            host = self._extract_host(raw)
            if not self._is_reasonable_host(host):
                return self._result(host=host, error="invalid host")
            valid = await self._probe(raw) if self.probe_reachability else False
            return self._result(
                host=host,
                port=urlsplit(raw).port or 80,
                valid=True,
                normalized_url=raw,
                reachable=valid,
            )

        # ── no scheme: try both ──────────────────────────────────────────
        https_url = f"https://{raw}"
        http_url = f"http://{raw}"
        host = self._extract_host(https_url)

        if not self._is_reasonable_host(host):
            return self._result(host=host, error="invalid host")

        preferred_scheme = "http" if DEFAULT_CLIENT == "http" else "https"
        if not self.probe_reachability:
            normalized_url = https_url if preferred_scheme == "https" else http_url
            port = 443 if preferred_scheme == "https" else 80
            return self._result(
                host=host,
                port=port,
                valid=True,
                normalized_url=normalized_url,
                reachable=False,
            )

        https_ok, http_ok = await asyncio.gather(
            self._probe(https_url),
            self._probe(http_url),
        )

        if https_ok and http_ok:
            chosen_scheme = preferred_scheme
        elif https_ok:
            chosen_scheme = "https"
        elif http_ok:
            chosen_scheme = "http"
        else:
            chosen_scheme = preferred_scheme

        normalized_url = https_url if chosen_scheme == "https" else http_url
        port = 443 if chosen_scheme == "https" else 80

        return self._result(
            host=host,
            port=port,
            valid=True,
            normalized_url=normalized_url,
            reachable=https_ok or http_ok,
        )

    # ── helpers ──────────────────────────────────────────────────────────

    async def _probe(self, url: str) -> bool:
        """HEAD request — True if anything responds (even 4xx)."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.head(url)
                return resp.status_code < 500
        except Exception:
            return False

    @staticmethod
    def _extract_host(url: str) -> str:
        try:
            return (urlsplit(url).hostname or "").strip().lower()
        except ValueError:
            return ""

    @staticmethod
    def _is_reasonable_host(host: str) -> bool:
        candidate = (host or "").strip().rstrip(".")
        if not candidate:
            return False

        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            pass

        if candidate.lower() == "localhost":
            return True

        if "." not in candidate:
            return False

        labels = candidate.split(".")
        if any(not label or not _HOST_LABEL_RE.fullmatch(label) for label in labels):
            return False
        return not any(label.startswith("-") or label.endswith("-") for label in labels)

    @staticmethod
    def _result(
        *,
        host: str = "",
        port: int = 0,
        valid: bool = False,
        normalized_url: str = "",
        reachable: bool = False,
        error: str = "",
    ) -> dict:
        return {
            "host": host,
            "port": port,
            "valid": valid,
            "normalized_url": normalized_url,
            "reachable": reachable,
            "error": error,
        }
#----------------------------------------------------------------------------------------
#                     ip validation
#----------------------------------------------------------------------------------------
class IPValidator:
    """Validate an IP address, CIDR range, or hostname."""

    def __init__(self, ip: str) -> None:
        self.raw = (ip or "").strip()

    def validate(self) -> dict:
        if not self.raw:
            return self._out(error="empty input")

        # ── CIDR ──────────────────────────────────
        if "/" in self.raw:
            try:
                net = ipaddress.ip_network(self.raw, strict=False)
            except ValueError:
                return self._out(error="invalid CIDR")

            is_v4 = isinstance(net, ipaddress.IPv4Network)
            hosts = (
                max(0, net.num_addresses - 2)
                if is_v4 and net.prefixlen < 31
                else net.num_addresses
            )
            return self._out(
                valid=True,
                ip_type="cidr_v4" if is_v4 else "cidr_v6",
                ip=str(net.network_address),
                is_private=net.is_private,
                is_loopback=net.is_loopback,
                hosts=hosts,
            )

        # ── Single IP ─────────────────────────────
        try:
            addr = ipaddress.ip_address(self.raw)
        except ValueError:
            return self._out(error="not a valid IP or CIDR")

        return self._out(
            valid=True,
            ip_type=(
                "ipv4"
                if isinstance(addr, ipaddress.IPv4Address)
                else "ipv6"
            ),
            ip=str(addr),
            is_private=addr.is_private,
            is_loopback=addr.is_loopback,
        )

    def is_valid(self) -> bool:
        return self.validate()["valid"]

    def _out(
        self,
        valid: bool = False,
        ip_type: str = "invalid",
        ip: str = "",
        is_private: bool = False,
        is_loopback: bool = False,
        hosts: int | None = None,
        error: str = "",
    ) -> dict:
        return {
            "input": self.raw,
            "valid": valid,
            "type": ip_type,
            "ip": ip,
            "is_private": is_private,
            "is_loopback": is_loopback,
            "hosts": hosts,
            "error": error,
        }
