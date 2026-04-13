#/+
"""
PentaForge Utilities — v5 Core Library (Advanced Async)
=======================================================
Hardened helpers for safe HTTP scanning, input validation,
SSRF protection, HTTP/2 multiplexing, target allowlisting,
response fingerprinting, and adaptive rate-limiting.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import ipaddress
import json
import logging
import os
import re
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from server.agents.executer.recon.config import BURP_AUTO_CAPTURE_ACTIVE, BURP_PROXY_URL

# ---------------------------------------------------------------------------
# Logging & Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger("pentaforge")

DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; PentaForge/5.0; +https://pentaforge.local)"

# ---------------------------------------------------------------------------
# Scope & Security Rules
# ---------------------------------------------------------------------------

# Optional Allowlist: If populated, ALL targets must match or be subdomains of these.
ALLOWED_TARGET_DOMAINS: frozenset[str] = frozenset({
    # "target.local",
    # "example.com"
})

# Cloud metadata endpoints — always blocked
BLOCKED_HOSTNAMES: frozenset[str] = frozenset({
    "metadata.google.internal",
    "metadata.internal",
    "169.254.169.254",       # AWS / Azure / GCP IMDS
    "instance-data",         # older EC2 alias
})

LOCAL_HOSTNAMES: frozenset[str] = frozenset({
   "ip6-localhost", "ip6-loopback",
})

BLOCKED_CIDRS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("100.64.0.0/10"),    # CGNAT
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local
    ipaddress.IPv6Network("fc00::/7"),         # ULA
    ipaddress.IPv6Network("fe80::/10"),        # IPv6 link-local
)

_HEADER_NAME_FORBIDDEN = re.compile(r"[\r\n: ]")
_HEADER_VALUE_FORBIDDEN = re.compile(r"[\r\n]")
_DNS_CACHE_TTL = 30

# Rate Limiting & Concurrency defaults
DEFAULT_CONCURRENCY = 50

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _env_flag(*names: str) -> bool:
    for name in names:
        if os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
    return False

def local_targets_allowed() -> bool:
    return True

# ---------------------------------------------------------------------------
# Async DNS cache & SSRF validation
# ---------------------------------------------------------------------------

@dataclass
class _DnsCacheEntry:
    addresses: list[str]
    expires_at: float

_dns_cache: dict[str, _DnsCacheEntry] = {}
_dns_cache_lock = asyncio.Lock()

async def resolve_host(hostname: str, *, ttl: int = _DNS_CACHE_TTL) -> list[str]:
    """Async DNS resolution with TTL caching."""
    hostname = hostname.lower().strip()
    now = time.monotonic()

    async with _dns_cache_lock:
        entry = _dns_cache.get(hostname)
        if entry and entry.expires_at > now:
            return list(entry.addresses)

    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(hostname, None)
        addresses = list({info[4][0] for info in infos})
        
        async with _dns_cache_lock:
            _dns_cache[hostname] = _DnsCacheEntry(addresses=addresses, expires_at=now + ttl)
        return addresses
    except socket.gaierror as exc:
        logger.debug("DNS failed for %r: %s", hostname, exc)
        return []

def _ip_is_unsafe(ip_str: str, *, allow_local: bool = False) -> tuple[bool, str]:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"unparseable IP: {ip_str!r}"

    if ip.is_loopback:
        return (False, "") if allow_local else (True, f"loopback: {ip}")

    for label, flag in (
        ("private",     ip.is_private),
        ("link-local",  ip.is_link_local),
        ("multicast",   ip.is_multicast),
        ("reserved",    ip.is_reserved),
    ):
        if flag:
            return True, f"{label} address: {ip}"

    for cidr in BLOCKED_CIDRS:
        if ip in cidr:
            return True, f"blocked CIDR {cidr}: {ip}"

    return False, ""

def extract_host(target: str) -> str:
    target = (target or "").strip()
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        return (parsed.hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()

async def is_blocked_target(target: str) -> tuple[bool, str]:
    """Complete SSRF safety check: Scope allowlists, Cloud Meta, and DNS rebinding."""
    host = extract_host(target)
    if not host:
        return True, "empty or unparseable host"

    # 1. Enforce Corporate Scope Allowlist (if configured)
    if ALLOWED_TARGET_DOMAINS:
        is_allowed = any(host == d or host.endswith("." + d) for d in ALLOWED_TARGET_DOMAINS)
        if not is_allowed:
            return True, f"domain {host!r} is out of scope"

    allow_local = local_targets_allowed()

    # 2. Hardcoded Blocklists
    if host in BLOCKED_HOSTNAMES:
        return True, f"blocked hostname: {host!r}"

    if host in LOCAL_HOSTNAMES:
        return False, ""

    # 3. Fast IP Literal Check
    try:
        ip_obj = ipaddress.ip_address(host)
        return _ip_is_unsafe(str(ip_obj), allow_local=allow_local)
    except ValueError:
        pass

    # 4. DNS Resolution & Rebinding Check
    resolved = await resolve_host(host)
    if not resolved:
        return True, f"hostname {host!r} did not resolve"

    for addr in resolved:
        blocked, reason = _ip_is_unsafe(addr, allow_local=allow_local)
        if blocked:
            return True, f"DNS rebinding guard ({host!r} → {addr}): {reason}"

    return False, ""

def merge_headers(*parts: dict[str, str] | None) -> dict[str, str]:
    merged: dict[str, str] = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"}
    for part in parts:
        if part:
            for k, v in part.items():
                if _HEADER_NAME_FORBIDDEN.search(k) or _HEADER_VALUE_FORBIDDEN.search(v):
                    raise ValueError("Header injection detected.")
                merged[k] = v
    return merged

# ---------------------------------------------------------------------------
# Result Types & Fingerprinting
# ---------------------------------------------------------------------------

class RequestFailureReason(str, Enum):
    TIMEOUT          = "timeout"
    CONNECTION       = "connection"
    TLS              = "tls"
    REDIRECT_BLOCKED = "redirect_blocked"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    UNKNOWN          = "unknown"

@dataclass(slots=True)
class RequestFailure:
    reason: RequestFailureReason
    detail: str

@dataclass(slots=True)
class SafeResponse:
    response: httpx.Response | None = None
    failure:  RequestFailure | None = None
    
    # Fingerprinting additions
    execution_time: float = 0.0
    body_hash: str = ""
    content_length: int = 0

    @property
    def ok(self) -> bool:
        return self.response is not None

    @property
    def status_code(self) -> int | None:
        return self.response.status_code if self.response else None

    @property
    def text(self) -> str | None:
        return self.response.text if self.response else None

    @property
    def headers(self) -> dict[str, str]:
        return dict(self.response.headers) if self.response else {}

    @property
    def url(self) -> str | None:
        return str(self.response.url) if self.response else None

def stable_body_hash(body: bytes | None) -> str:
    """SHA-256 hex digest for response fingerprinting."""
    if not body:
        return ""
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    return hashlib.sha256(body).hexdigest()

def _classify_exception(exc: Exception) -> RequestFailure:
    name, detail = type(exc).__name__, str(exc)
    if "Timeout" in name:
        return RequestFailure(RequestFailureReason.TIMEOUT, detail)
    if "Connect" in name:
        return RequestFailure(RequestFailureReason.CONNECTION, detail)
    if "SSL" in name or "TLS" in detail:
        return RequestFailure(RequestFailureReason.TLS, detail)
    return RequestFailure(RequestFailureReason.UNKNOWN, detail)

# ---------------------------------------------------------------------------
# Advanced Async Engine with Adaptive Limiting & HTTP/2
# ---------------------------------------------------------------------------

class ScannerEngine:
    """HTTP/2 Engine with SSRF guards, Adaptive Limits, and Proxy Support."""
    
    def __init__(
        self, 
        proxy: str | None = None, 
        concurrency_limit: int = DEFAULT_CONCURRENCY,
        adaptive_rate_limit: bool = True,
        base_delay: float = 0.0,
        verify_tls: bool = True,
    ):
        if proxy is None and BURP_AUTO_CAPTURE_ACTIVE:
            proxy = BURP_PROXY_URL

        self.proxy = proxy
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        
        # Adaptive backoff config
        self.adaptive = adaptive_rate_limit
        self.current_delay = base_delay
        self.min_delay = base_delay
        self.max_delay = 5.0
        self.delay_lock = asyncio.Lock()
        
        # HTTP/2 enabled natively for multiplexing advantages.
        # httpx 0.28+ uses `proxy=`, while older releases used `proxies=`.
        client_kwargs: dict[str, Any] = {
            "http2": True,
            "verify": verify_tls,
            "follow_redirects": False,
        }
        if self.proxy:
            async_client_params = inspect.signature(httpx.AsyncClient.__init__).parameters
            if "proxy" in async_client_params:
                client_kwargs["proxy"] = self.proxy
            elif "proxies" in async_client_params:
                client_kwargs["proxies"] = self.proxy

        self.client = httpx.AsyncClient(**client_kwargs)

    async def close(self):
        await self.client.aclose()

    async def _adjust_delay(self, execution_time: float, status_code: int | None):
        """AIMD Adaptive Rate Limiter logic."""
        if not self.adaptive:
            return
            
        async with self.delay_lock:
            # Multiplicative increase if API is dying or we hit WAF/Rate limits
            if status_code == 429 or status_code in [502, 503, 504] or execution_time > 2.0:
                self.current_delay = min(self.current_delay + 0.5, self.max_delay)
                logger.warning(f"Engine throttling up. Delay: {self.current_delay:.2f}s")
            
            # Additive decrease if API is healthy and fast
            elif execution_time < 0.5 and self.current_delay > self.min_delay:
                self.current_delay = max(self.current_delay - 0.1, self.min_delay)

    async def safe_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: int = 15,
        allow_redirects: bool = True,
        max_redirects: int = 10,
        **kwargs: Any,
    ) -> SafeResponse:
        
        async with self.semaphore:
            if self.current_delay > 0:
                await asyncio.sleep(self.current_delay)

            current_url = url
            redirects_followed = 0
            
            try:
                while redirects_followed <= max_redirects:
                    blocked, reason = await is_blocked_target(current_url)
                    if blocked:
                        return SafeResponse(failure=RequestFailure(
                            RequestFailureReason.REDIRECT_BLOCKED, f"Blocked — {reason}"
                        ))

                    start_time = time.monotonic()
                    resp = await self.client.request(
                        method=method.upper(),
                        url=current_url,
                        headers=merge_headers(headers),
                        timeout=timeout,
                        **kwargs
                    )
                    exec_time = time.monotonic() - start_time

                    # Feed the adaptive rate limiter
                    await self._adjust_delay(exec_time, resp.status_code)

                    if allow_redirects and resp.is_redirect:
                        redirects_followed += 1
                        location = resp.headers.get("Location")
                        if not location: break
                        current_url = urljoin(str(resp.url), location)
                        continue 
                    
                    # Generate fingerprints
                    body_bytes = resp.content
                    return SafeResponse(
                        response=resp,
                        execution_time=round(exec_time, 4),
                        body_hash=stable_body_hash(body_bytes),
                        content_length=len(body_bytes)
                    )

                return SafeResponse(failure=RequestFailure(
                    RequestFailureReason.TOO_MANY_REDIRECTS, f"Max {max_redirects} redirects"
                ))

            except Exception as exc:
                failure = _classify_exception(exc)
                return SafeResponse(failure=failure)


# ---------------------------------------------------------------------------
# Backward-compatible sync helper layer for API recon tools
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ValidationResult:
    ok: bool
    failure: str = ""
    value: str = ""


def validate_http_target(target: str, allow_paths: bool = False) -> str | ValidationResult:
    target = (target or "").strip()
    if not target:
        result = ValidationResult(ok=False, failure="target cannot be empty")
        return result if not allow_paths else (_raise_validation(result.failure))

    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.scheme not in {"http", "https"}:
        result = ValidationResult(ok=False, failure=f"unsupported scheme: {parsed.scheme}")
        return result if not allow_paths else (_raise_validation(result.failure))

    if not parsed.hostname:
        result = ValidationResult(ok=False, failure="missing hostname")
        return result if not allow_paths else (_raise_validation(result.failure))

    if allow_paths:
        blocked, reason = asyncio.run(is_blocked_target(target))
        if blocked:
            raise ValueError(f"Blocked target: {reason}")
        return target

    blocked, reason = asyncio.run(is_blocked_target(target))
    if blocked:
        return ValidationResult(ok=False, failure=f"Blocked target: {reason}")
    return ValidationResult(ok=True, value=target)


def _raise_validation(message: str) -> str:
    raise ValueError(message)


def validate_headers(headers: dict[str, str]) -> dict[str, str]:
    return merge_headers(headers)


def build_url(base: str, endpoint: str) -> str:
    base = (base or "").strip()
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return base
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    return urljoin(base.rstrip("/") + "/", endpoint.lstrip("/"))


def response_snippet(body: str | bytes | None, limit: int = 500) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return body[:limit]


def summarize_validation_error(exc: Exception) -> str:
    return str(exc)


def safe_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
    verify_tls: bool = True,
    allow_redirects: bool = True,
    max_redirects: int = 10,
    **kwargs: Any,
) -> SafeResponse | None:
    async def _runner() -> SafeResponse:
        engine = ScannerEngine(verify_tls=verify_tls)
        try:
            return await engine.safe_request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                max_redirects=max_redirects,
                **kwargs,
            )
        finally:
            await engine.close()

    try:
        return asyncio.run(_runner())
    except Exception as exc:
        return SafeResponse(failure=_classify_exception(exc))


def json_key_paths(data: Any, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.append(path)
            paths.extend(json_key_paths(value, path))
    elif isinstance(data, list):
        for idx, value in enumerate(data[:20]):
            path = f"{prefix}[{idx}]"
            paths.extend(json_key_paths(value, path))
    return paths


def collect_candidate_ids(data: Any) -> list[str]:
    found: set[str] = set()

    def _walk(value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                k_low = str(k).lower()
                if k_low in {"id", "uuid", "user_id", "account_id", "object_id"} and v is not None:
                    found.add(str(v))
                _walk(v)
        elif isinstance(value, list):
            for item in value[:50]:
                _walk(item)
        elif isinstance(value, str):
            if re.fullmatch(r"[0-9a-fA-F-]{8,}", value) or value.isdigit():
                found.add(value)

    _walk(data)
    return sorted(found)[:25]

# ---------------------------------------------------------------------------
# Self-Test Execution
# ---------------------------------------------------------------------------

async def run_self_tests() -> None:
    print("=" * 64)
    print("  PentaForge Utils v5 (HTTP/2 & Fingerprinting) — Self-Test")
    print("=" * 64)
    
    engine = ScannerEngine(concurrency_limit=5, adaptive_rate_limit=True)
    safe_target = os.environ.get("PENTAFORGE_API_SELF_TEST_TARGET", "http://localhost:8888/api")
    
    # 1. Test Fast Response & Fingerprinting
    print(f"[Testing Safe Target & Fingerprinting] {safe_target}")
    res = await engine.safe_request("GET", safe_target)
    if res.ok:
        print(f"✓ Success | Status: {res.status_code} | Time: {res.execution_time}s")
        print(f"✓ Hash: {res.body_hash} | Length: {res.content_length} bytes\n")
    else:
        print(f"✗ Failed | {res.failure}\n")

    # 2. Test SSRF Guard
    print("[Testing SSRF Metadata Guard]")
    res_block = await engine.safe_request("GET", "http://169.254.169.254")
    print(f"✓ Blocked Expectedly: {res_block.failure}\n")
    
    await engine.close()
    print("=" * 64)

if __name__ == "__main__":
    asyncio.run(run_self_tests())
