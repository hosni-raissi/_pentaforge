"""URL Normalizer — probe a URL and return host, port, and reachability."""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit
from .config import DEFAULT_CLIENT, DEFAULT_TIMEOUT_SECONDS
import httpx
import ipaddress

class UrlNormalizer:
    """
    Give it a URL (with or without scheme), it probes it and returns:
        {"host": str, "port": int, "valid": bool}

    Rules:
    - Has https://  → probe https only,  port 443
    - Has http://   → probe http only,   port 80
    - No scheme     → probe both concurrently:
                        · only one works  → return that one
                        · both work       → prefer https
                        · neither works   → valid: False
    """

    def __init__(self, url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.raw = (url or "").strip()
        self.timeout = timeout

    async def normalize(self) -> dict:
        if not self.raw:
            return {"host": "", "port": 0, "valid": False}

        raw = self.raw

        # ── explicit scheme ──────────────────────────────────────────────
        if raw.startswith("https://"):
            host = self._extract_host(raw)
            valid = await self._probe(raw)
            return {"host": host, "port": 443, "valid": valid}

        if raw.startswith("http://"):
            host = self._extract_host(raw)
            valid = await self._probe(raw)
            return {"host": host, "port": 80, "valid": valid}

        # ── no scheme: try both ──────────────────────────────────────────
        https_url = f"https://{raw}"
        http_url  = f"http://{raw}"
        host      = self._extract_host(https_url)

        https_ok, http_ok = await asyncio.gather(
            self._probe(https_url),
            self._probe(http_url),
        )

        if https_ok and DEFAULT_CLIENT == "https":                         
            return {"host": host, "port": 443, "valid": True}
        if http_ok and DEFAULT_CLIENT == "http":
            return {"host": host, "port": 80,  "valid": True}

        return {"host": host, "port": 0, "valid": False}

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

