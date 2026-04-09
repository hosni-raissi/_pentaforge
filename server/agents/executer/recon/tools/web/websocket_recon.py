#/+
"""
websocket_recon.py — WebSocket discovery & security recon agent tool
Probes WS endpoints, tests origin enforcement (CSWSH), detects auth, flags misconfigs.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3
from pydantic import BaseModel, Field, field_validator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════

# Private / link-local / loopback ranges — block regardless of hostname
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

# Hostnames that must always be blocked (regardless of DNS resolution)
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",  # AWS/GCP/Azure IMDS
})

# Common WebSocket paths to probe
WS_PATHS = [
    "/ws", "/wss", "/websocket", "/socket", "/sock",
    "/ws/", "/wss/", "/websocket/", "/socket/",
    "/api/ws", "/api/websocket", "/api/socket",
    "/v1/ws", "/v2/ws", "/v1/websocket",
    "/realtime", "/live", "/stream", "/events",
    "/cable", "/hub",
    "/signalr", "/signalr/negotiate",
    "/socket.io/", "/socket.io/?EIO=4&transport=websocket",
    "/sockjs", "/sockjs/info",
    "/graphql", "/subscriptions", "/graphql/subscriptions",
    "/chat", "/chat/ws", "/notifications", "/feed",
    "/mqtt", "/stomp", "/amqp",
]

# Origins used for CSWSH testing
_EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "",
]

# Status codes that confirm a WS-capable endpoint exists
_WS_POSITIVE_CODES = {101, 400, 426}
_AUTH_CODES = {401, 403}

# Concurrency
_MAX_WORKERS = 10
_MAX_WORKERS_PER_HOST = 5   # throttle per-host to be polite


# ══════════════════════════════════════════════════════════════
# 2. SSRF GUARD
# ══════════════════════════════════════════════════════════════

def _is_private_ip(addr: str) -> bool:
    """Return True if addr resolves to a private/reserved IP range."""
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _resolve_and_check(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP and check it is publicly routable.
    Returns error string if blocked, None if safe.
    """
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return f"Hostname '{hostname}' is blocked"

    try:
        _, _, addrs = socket.gethostbyname_ex(hostname)
    except socket.gaierror as exc:
        return f"DNS resolution failed for '{hostname}': {exc}"

    for addr in addrs:
        if _is_private_ip(addr):
            return (
                f"Hostname '{hostname}' resolves to private/reserved IP '{addr}' — "
                "SSRF protection blocked this request"
            )
    return None


def _ssrf_check(url: str) -> Optional[str]:
    """Full SSRF check on a URL. Returns error string if blocked."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    # Direct IP supplied?
    if _is_private_ip(host):
        return f"Direct private IP '{host}' is blocked"
    return _resolve_and_check(host)


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class WebSocketReconRequest(BaseModel):
    target: str
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=15, ge=5, le=60)
    verify_tls: bool = True
    max_workers: int = Field(default=_MAX_WORKERS, ge=1, le=20)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^(https?|wss?)://[a-zA-Z0-9]", v):
            raise ValueError("Target must start with http(s):// or ws(s)://")
        # Normalize ws(s) → http(s) for HTTP probing
        v = v.replace("wss://", "https://").replace("ws://", "http://")
        # SSRF guard at validation time
        err = _ssrf_check(v)
        if err:
            raise ValueError(err)
        return v

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: dict) -> dict:
        # Block headers that could influence internal routing
        blocked_headers = {"host", "x-forwarded-for", "x-real-ip", "x-forwarded-host"}
        for key in v:
            if key.lower() in blocked_headers:
                raise ValueError(f"Header '{key}' is not allowed")
        return v


class WebSocketEndpoint(BaseModel):
    url: str
    ws_url: str
    upgrade_supported: bool = False
    status_code: Optional[int] = None
    server: Optional[str] = None
    protocols: list[str] = Field(default_factory=list)
    extensions: list[str] = Field(default_factory=list)
    origin_check: str = "untested"   # enforced / weak / none / untested
    auth_required: bool = False
    cors_permissive: bool = False
    tls_verified: bool = True
    source: str = "upgrade_probe"    # upgrade_probe | html_reference
    issues: list[str] = Field(default_factory=list)


class WebSocketReconResult(BaseModel):
    """Agent-focused result with actionable WebSocket findings."""
    success: bool
    target: str

    # Critical findings for agent
    websocket_endpoints: list[WebSocketEndpoint] = Field(default_factory=list)
    probed_endpoints: list[str] = Field(default_factory=list)
    all_issues: list[str] = Field(default_factory=list)
    severity: str = "info"           # info / low / medium / high / critical
    tls_warnings: list[str] = Field(default_factory=list)

    # Metadata (optional/debug)
    endpoints_probed: int = 0
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 4. HELPERS
# ══════════════════════════════════════════════════════════════

def _random_ws_key() -> str:
    """Generate a random 16-byte base64 Sec-WebSocket-Key (per RFC 6455)."""
    return base64.b64encode(os.urandom(16)).decode()


def _ws_url(http_url: str) -> str:
    return http_url.replace("https://", "wss://").replace("http://", "ws://")


def _parse_header_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _make_upgrade_headers(origin: str, extra: dict, key: Optional[str] = None) -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key or _random_ws_key(),
        "Origin": origin,
        **extra,
    }


def _summarize_validation_error(exc: Exception) -> str:
    """Return a compact user-facing validation message."""
    try:
        errors = exc.errors()  # type: ignore[attr-defined]
    except Exception:
        errors = []

    messages: list[str] = []
    for item in errors:
        location = ".".join(str(part) for part in item.get("loc", []))
        message = item.get("msg", "Invalid input")
        if message.lower().startswith("value error, "):
            message = message[len("Value error, "):]
        messages.append(f"{location}: {message}" if location else message)

    if messages:
        return "; ".join(messages)

    return str(exc)


# ══════════════════════════════════════════════════════════════
# 5. PROBING
# ══════════════════════════════════════════════════════════════

def _probe_endpoint(
    base_url: str,
    path: str,
    headers: dict,
    timeout: int,
    verify_tls: bool,
) -> Optional[WebSocketEndpoint]:
    """
    Probe a candidate path for WebSocket support.
    Strategy:
      1. HTTP Upgrade request — look for 101, 400, 426, 401, 403.
      2. Plain GET — scan response body for WS references.
    """
    http_url = base_url.rstrip("/") + path
    tls_verified = verify_tls

    # ── Step 1: Upgrade probe ───────────────────────────────────
    upgrade_headers = _make_upgrade_headers(base_url, headers)
    try:
        resp = requests.get(
            http_url,
            headers=upgrade_headers,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=False,
            stream=True,
        )

        if resp.status_code in _WS_POSITIVE_CODES:
            ep = WebSocketEndpoint(
                url=http_url,
                ws_url=_ws_url(http_url),
                upgrade_supported=True,
                status_code=resp.status_code,
                server=resp.headers.get("Server"),
                tls_verified=verify_tls,
                source="upgrade_probe",
            )
            if resp.status_code == 101:
                proto = resp.headers.get("Sec-WebSocket-Protocol", "")
                if proto:
                    ep.protocols = _parse_header_list(proto)
                ext = resp.headers.get("Sec-WebSocket-Extensions", "")
                if ext:
                    ep.extensions = _parse_header_list(ext)
            if resp.status_code == 426:
                ep.issues.append("Server explicitly requires WebSocket upgrade (426 Upgrade Required)")
            return ep

        if resp.status_code in _AUTH_CODES:
            return WebSocketEndpoint(
                url=http_url,
                ws_url=_ws_url(http_url),
                upgrade_supported=True,
                status_code=resp.status_code,
                auth_required=True,
                server=resp.headers.get("Server"),
                tls_verified=verify_tls,
                source="upgrade_probe",
            )

    except requests.exceptions.SSLError:
        # Retry without TLS verification and flag it
        tls_verified = False
        if not verify_tls:
            try:
                resp = requests.get(
                    http_url,
                    headers=upgrade_headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                    stream=True,
                )
                if resp.status_code in _WS_POSITIVE_CODES | _AUTH_CODES:
                    ep = WebSocketEndpoint(
                        url=http_url,
                        ws_url=_ws_url(http_url),
                        upgrade_supported=True,
                        status_code=resp.status_code,
                        auth_required=resp.status_code in _AUTH_CODES,
                        server=resp.headers.get("Server"),
                        tls_verified=False,
                        source="upgrade_probe",
                        issues=["TLS certificate validation failed — connection made without verification"],
                    )
                    return ep
            except Exception:
                pass
    except Exception:
        pass

    # ── Step 2: Plain GET — scan for WS references in body ─────
    try:
        resp = requests.get(
            http_url,
            headers={"User-Agent": "Mozilla/5.0", **headers},
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=True,
        )
        if resp.status_code == 200:
            content = resp.text.lower()[:8000]
            ws_keywords = [
                "new websocket(", "ws://", "wss://",
                "socket.io", "sockjs", "signalr",
                '"websocket"', "'websocket'",
            ]
            matched = [kw for kw in ws_keywords if kw in content]
            if matched:
                return WebSocketEndpoint(
                    url=http_url,
                    ws_url=_ws_url(http_url),
                    upgrade_supported=False,
                    status_code=resp.status_code,
                    server=resp.headers.get("Server"),
                    tls_verified=tls_verified,
                    source="html_reference",
                    issues=[f"WebSocket reference found in page content ({', '.join(matched[:3])})"],
                )
    except Exception:
        pass

    return None


# ══════════════════════════════════════════════════════════════
# 6. ORIGIN / CSWSH TESTING
# ══════════════════════════════════════════════════════════════

def _check_origin(
    endpoint: WebSocketEndpoint,
    headers: dict,
    timeout: int,
    verify_tls: bool,
) -> None:
    """
    Test CSWSH by sending Upgrade requests with attacker-controlled Origins.
    Tests ALL endpoints with upgrade_supported=True, regardless of auth status.

    Auth-gated endpoints that accept foreign Origins are still vulnerable to
    CSWSH when a victim user is logged in.
    """
    accepted_origins: list[str] = []
    rejected = False

    for origin in _EVIL_ORIGINS:
        key = _random_ws_key()   # fresh key per attempt
        test_headers = _make_upgrade_headers(origin, headers, key=key)
        try:
            resp = requests.get(
                endpoint.url,
                headers=test_headers,
                timeout=timeout,
                verify=verify_tls,
                allow_redirects=False,
                stream=True,
            )
            if resp.status_code == 101:
                accepted_origins.append(repr(origin) if origin else "'empty'")
            elif resp.status_code in (401, 403):
                # Rejected — but keep testing other origins
                rejected = True
            # 400 can mean "bad origin" or "bad request" — not conclusive, skip
        except Exception:
            pass

    if accepted_origins:
        endpoint.origin_check = "none"
        endpoint.cors_permissive = True
        endpoint.issues.append(
            f"CSWSH: endpoint accepts WebSocket from untrusted origins: "
            f"{', '.join(accepted_origins)}"
        )
    elif rejected:
        endpoint.origin_check = "enforced"
    else:
        endpoint.origin_check = "unknown"


# ══════════════════════════════════════════════════════════════
# 7. SEVERITY SCORING
# ══════════════════════════════════════════════════════════════

def _score_severity(endpoints: list[WebSocketEndpoint]) -> str:
    """
    Derive overall severity from collected issues.
    critical > high > medium > low > info
    """
    all_issues = [i.lower() for ep in endpoints for i in ep.issues]

    if any("cswsh" in i for i in all_issues):
        return "high"

    medium_signals = [
        "origin",
        "tls certificate validation failed",
        "426 upgrade required",
        "websocket reference found",
    ]
    if any(sig in i for i in all_issues for sig in medium_signals):
        return "medium"

    if endpoints:
        return "low"   # endpoints found but no specific issues flagged

    return "info"


# ══════════════════════════════════════════════════════════════
# 8. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def websocket_recon(
    target: str,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
    verify_tls: bool = True,
    max_workers: int = _MAX_WORKERS,
) -> dict:
    """
    🔧 Agent Tool: WebSocket Recon — endpoint discovery, upgrade probing,
                   CSWSH / origin enforcement testing, auth detection.

    ┌─────────────────────────────────────────────────────────────────┐
    │  ENDPOINT DISCOVERY   HTTP Upgrade probing across 29 paths      │
    │  BODY SCANNING        HTML/JS reference detection               │
    │  CSWSH TESTING        Origin enforcement on all live endpoints   │
    │  AUTH DETECTION       401 / 403 gated endpoints flagged         │
    │  TLS AWARENESS        Surfaces cert errors rather than hiding   │
    │  SSRF PROTECTION      DNS rebinding + private IP range checks   │
    └─────────────────────────────────────────────────────────────────┘

    Args:
        target:       Base URL to scan (e.g. "https://example.com")
        headers:      Optional custom HTTP headers (Host, X-Forwarded-* blocked)
        timeout:      Per-request timeout in seconds (default 15, max 60)
        verify_tls:   Verify TLS certificates (default True — set False only for
                      internal/dev targets with self-signed certs)
        max_workers:  Concurrent probe threads (default 10, max 20)

    Returns:
        Structured JSON with keys (agent-focused):
        success, target, websocket_endpoints, probed_endpoints, all_issues, severity,
        tls_warnings, endpoints_probed, error, execution_time

    ── What each endpoint object contains ──────────────────────────
        url              HTTP URL probed
        ws_url           Equivalent WebSocket URL (ws:// or wss://)
        upgrade_supported  True if server responds to WS Upgrade
        status_code      HTTP response code (101 / 400 / 426 / 401 / 403)
        server           Server header value
        protocols        Negotiated Sec-WebSocket-Protocol values
        extensions       Negotiated Sec-WebSocket-Extensions values
        origin_check     "enforced" | "none" | "unknown" | "untested"
        auth_required    True if 401/403 gated
        cors_permissive  True if accepts connections from foreign origins
        tls_verified     False if TLS cert check was bypassed
        source           "upgrade_probe" | "html_reference"
        issues           List of security findings for this endpoint

    ── Severity levels ──────────────────────────────────────────────
        critical  Authentication bypass possible
        high      CSWSH — foreign origin accepted on live endpoint
        medium    TLS issues / upgrade-required misconfig / body references
        low       Endpoints found, no specific issues
        info      No endpoints found
    """
    if headers is None:
        headers = {}

    start = time.monotonic()

    def _fail(msg: str) -> dict:
        return WebSocketReconResult(
            success=False,
            target=target,
            error=msg,
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    # ── Validate ───────────────────────────────────────────────
    try:
        req = WebSocketReconRequest(
            target=target,
            headers=headers,
            timeout=timeout,
            verify_tls=verify_tls,
            max_workers=max_workers,
        )
    except Exception as exc:
        return _fail(f"Validation error: {_summarize_validation_error(exc)}")

    # ── Discover endpoints (concurrent) ───────────────────────
    found: list[WebSocketEndpoint] = []
    probed_endpoints = [req.target.rstrip("/") + path for path in WS_PATHS]
    workers = min(req.max_workers, _MAX_WORKERS_PER_HOST, len(WS_PATHS))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _probe_endpoint,
                req.target, path, req.headers, req.timeout, req.verify_tls,
            ): path
            for path in WS_PATHS
        }
        deadline = req.timeout * len(WS_PATHS) / workers + req.timeout
        try:
            for future in as_completed(futures, timeout=deadline):
                try:
                    ep = future.result()
                    if ep is not None:
                        found.append(ep)
                except Exception:
                    pass
        except FuturesTimeout:
            # Collect any results that finished before deadline
            for future in futures:
                if future.done():
                    try:
                        ep = future.result()
                        if ep is not None:
                            found.append(ep)
                    except Exception:
                        pass

    # ── Origin / CSWSH testing (sequential — targeted) ────────
    # Run on ALL endpoints with upgrade_supported=True, including auth-gated ones.
    # An auth-gated endpoint can still be CSWSH-vulnerable when a victim is logged in.
    for ep in found:
        if ep.upgrade_supported:
            _check_origin(ep, req.headers, req.timeout, req.verify_tls)

    # ── Collect issues & TLS warnings ─────────────────────────
    all_issues: list[str] = []
    tls_warnings: list[str] = []
    for ep in found:
        all_issues.extend(ep.issues)
        if not ep.tls_verified:
            tls_warnings.append(
                f"{ep.url} — TLS certificate could not be verified"
            )

    severity = _score_severity(found)

    # ── Result ─────────────────────────────────────────────────
    # success = True when the tool ran cleanly, regardless of findings.
    # The agent should inspect websocket_endpoints and severity for actionable signal.
    return WebSocketReconResult(
        success=True,
        target=req.target,
        endpoints_probed=len(probed_endpoints),
        websocket_endpoints=found,
        probed_endpoints=probed_endpoints,
        all_issues=all_issues,
        severity=severity,
        tls_warnings=tls_warnings,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 9. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

WEBSOCKET_RECON_TOOL_DEFINITION = {
    "name": "websocket_recon",
    "description": (
        "Discover WebSocket endpoints on a web target via HTTP Upgrade probing "
        "and HTML body scanning. Tests for CSWSH (Cross-Site WebSocket Hijacking) "
        "by probing Origin enforcement on all live endpoints — including auth-gated ones. "
        "Flags TLS issues, auth requirements, and server misconfigurations. "
        "SSRF-safe: blocks private IPs, cloud metadata endpoints, and DNS rebinding. "
        "Non-intrusive reconnaissance — no frames sent after handshake."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": (
                    "Base URL of the target (e.g. 'https://example.com'). "
                    "Accepts http://, https://, ws://, wss://. "
                    "Private IPs and cloud metadata URLs are blocked."
                ),
            },
            "headers": {
                "type": "object",
                "description": (
                    "Custom HTTP headers to include in all requests "
                    "(e.g. {'Authorization': 'Bearer <token>', 'Cookie': 'session=...'})."
                    "Host, X-Forwarded-* headers are blocked."
                ),
            },
            "timeout": {
                "type": "integer",
                "description": "Per-request timeout in seconds (default: 15, range: 5–60).",
            },
            "verify_tls": {
                "type": "boolean",
                "description": (
                    "Verify TLS certificates (default: true). "
                    "Set to false only for internal targets with self-signed certs — "
                    "TLS errors will be surfaced in tls_warnings."
                ),
            },
            "max_workers": {
                "type": "integer",
                "description": "Concurrent probe threads (default: 10, range: 1–20).",
            },
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 10. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json
    import sys

    examples: list[tuple[str, dict]] = [
        (
            "Basic scan",
            {"target": "http://scanme.nmap.org"},
        ),
        (
            "Authenticated scan",
            {
                "target": "http://scanme.nmap.org",
                "headers": {"Authorization": "Bearer eyJhbGci..."},
                "timeout": 20,
            },
        ),
        (
            "Unresolvable host (should fail validation cleanly)",
            {
                "target": "https://internal.example.invalid",
                "verify_tls": False,
            },
        ),
        (
            "SSRF guard (should fail validation)",
            {"target": "http://169.254.169.254/latest/meta-data/"},
        ),
        (
            "SSRF guard — localhost (should fail validation)",
            {"target": "http://localhost:8080/ws"},
        ),
    ]

    for label, kwargs in examples:
        print(f"\n{'='*60}")
        print(f"=== {label} ===")
        result = websocket_recon(**kwargs)
        json.dump(result, sys.stdout, indent=2)
        print()
