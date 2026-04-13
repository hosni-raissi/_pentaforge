#/*
"""
grpc_recon_tool.py
~~~~~~~~~~~~~~~~~~
gRPC service discovery and security assessment via grpcurl + HTTP probes.

Enumerates services and methods via server reflection, probes common gRPC-web
paths, detects plaintext transport / health-check exposure, and flags sensitive
RPC names for follow-up testing.

Fully self-contained — no internal _common imports required.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import shutil
import subprocess
import time
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel, Field, field_validator

# Optional dependency — requests is used only for HTTP probes
try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("grpc_recon")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GRPC_HTTP_PROBE_PATHS: list[str] = [
    "/grpc",
    "/grpc-web",
    "/grpc.health.v1.Health/Check",
    "/healthz",
    "/health",
]

SENSITIVE_NAME_PATTERNS: list[str] = [
    "admin", "debug", "secret", "token", "password",
    "delete", "execute", "upload", "internal", "private",
]

# Blocked CIDR ranges — grpc_recon targets URLs so we validate the hostname
_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fe80::/10"),
]

# RFC-1123 hostname pattern
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# Header name validation — letters, digits, hyphens only
_HEADER_NAME_RE = re.compile(r"^[a-zA-Z0-9\-]+$")

# rpc method signature parser
RPC_RE = re.compile(
    r"rpc\s+([A-Za-z0-9_]+)\s*\(\s*(stream\s+)?([A-Za-z0-9_.]+)\s*\)"
    r"\s*returns\s*\(\s*(stream\s+)?([A-Za-z0-9_.]+)",
    re.MULTILINE,
)

_DANGEROUS: frozenset[str] = frozenset({
    "\n", "\r", "\x00", ";", "`", "$(", "&&", "||",
})


# ---------------------------------------------------------------------------
# Inlined helpers  (previously from _common)
# ---------------------------------------------------------------------------

def _validate_http_target(value: str) -> str:
    """
    Validate a gRPC/HTTP URL target.

    Accepts:
        - https://host:port  or  http://host:port  (with optional path)
        - host:port          (treated as plaintext gRPC)

    Rejects blocked IPs, invalid hostnames, and non-HTTP(S) schemes.
    """
    v = value.strip()
    if not v:
        raise ValueError("Target must not be empty")

    # If no scheme, treat as bare host:port and add http:// for parsing
    if "://" not in v:
        v = "http://" + v

    parsed = urlparse(v)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Scheme must be http or https, got {scheme!r}")

    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("Target URL must contain a hostname")

    # IP check
    try:
        ip = ipaddress.ip_address(hostname)
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                raise ValueError(f"Target hostname '{hostname}' is in a blocked range ({net})")
        return value.strip()
    except ValueError as exc:
        if "blocked range" in str(exc):
            raise

    # Hostname check
    if len(hostname) > 253:
        raise ValueError(f"Hostname too long: {hostname!r}")
    if not _HOSTNAME_RE.match(hostname.rstrip(".")):
        raise ValueError(f"Invalid hostname: {hostname!r}")

    return value.strip()


def _validate_headers(value: dict[str, str]) -> dict[str, str]:
    """Validate that header names are safe and values contain no injection chars."""
    cleaned: dict[str, str] = {}
    for name, val in value.items():
        if not _HEADER_NAME_RE.match(name):
            raise ValueError(
                f"Invalid header name {name!r} — only alphanumerics and hyphens allowed"
            )
        if any(ch in val for ch in _DANGEROUS):
            raise ValueError(f"Dangerous character in header value for {name!r}")
        cleaned[name] = val
    return cleaned


def _build_url(base: str, path: str) -> str:
    """Append *path* to *base*, normalising double slashes."""
    base = base.rstrip("/")
    path = "/" + path.lstrip("/")
    return base + path


def _response_snippet(text: str, limit: int = 500) -> Optional[str]:
    """Return up to *limit* chars of *text*, or None if empty."""
    if not text:
        return None
    return text[:limit]


def _safe_request(
    method: str,
    url: str,
    headers: dict[str, str],
    timeout: int,
    verify_tls: bool,
    allow_redirects: bool = True,
) -> Optional[Any]:
    """
    Make an HTTP request without raising.  Returns the response or None.
    Requires the `requests` library — silently returns None if unavailable.
    """
    if not _REQUESTS_AVAILABLE:
        return None
    try:
        return _requests.request(
            method,
            url,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=allow_redirects,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("HTTP probe failed for %s: %s", url, exc)
        return None


def _summarize_validation_error(exc: Exception) -> str:
    """Return a concise one-line summary of a Pydantic validation error."""
    try:
        from pydantic import ValidationError
        if isinstance(exc, ValidationError):
            msgs = [f"{e['loc'][-1]}: {e['msg']}" for e in exc.errors()]
            return "; ".join(msgs[:3])
    except Exception:  # noqa: BLE001
        pass
    return str(exc)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class GRPCReconRequest(BaseModel):
    """Validated, sanitised gRPC recon request."""

    target: str
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=30, ge=5, le=180)
    verify_tls: bool = True
    use_plaintext: bool = False

    @field_validator("target")
    @classmethod
    def check_target(cls, v: str) -> str:
        return _validate_http_target(v)

    @field_validator("headers")
    @classmethod
    def check_headers(cls, v: dict[str, str]) -> dict[str, str]:
        return _validate_headers(v)


class GRPCMethod(BaseModel):
    service: str
    name: str
    request_type: Optional[str] = None
    response_type: Optional[str] = None
    streaming: bool = False
    sensitive: bool = False


class GRPCService(BaseModel):
    name: str
    methods: list[GRPCMethod] = Field(default_factory=list)
    raw_description: Optional[str] = None
    sensitive: bool = False


class GRPCFinding(BaseModel):
    title: str
    severity: str = "info"
    description: str
    evidence: list[str] = Field(default_factory=list)


class GRPCProbe(BaseModel):
    url: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    server: Optional[str] = None
    grpc_indicators: list[str] = Field(default_factory=list)
    response_snippet: Optional[str] = None


class GRPCReconResult(BaseModel):
    """Full result returned to callers."""

    success: bool           # tool executed without fatal error
    detected: bool          # any gRPC surface was found (reflection OR probes)
    target: str
    authority: str
    reflection_enabled: bool = False
    health_service_exposed: bool = False
    grpc_web_exposed: bool = False
    plaintext_allowed: bool = False
    services: list[GRPCService] = Field(default_factory=list)
    probes: list[GRPCProbe] = Field(default_factory=list)
    findings: list[GRPCFinding] = Field(default_factory=list)
    command: str = ""
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    techniques_used: list[str] = Field(
        default_factory=lambda: ["grpcurl", "http_probe"]
    )


# ---------------------------------------------------------------------------
# Authority + TLS inference
# ---------------------------------------------------------------------------

def _authority_from_target(target: str) -> tuple[str, bool]:
    """
    Derive the grpcurl authority string and TLS flag from *target*.

    Handles:
        - https://host:port[/path]   → (host:port, True)
        - http://host:port[/path]    → (host:port, False)
        - host:port                  → (host:port, False)  ← bare form
    """
    v = target.strip()
    has_scheme = "://" in v
    if not has_scheme:
        # bare host:port — treat as plaintext
        host_part = v.split("/")[0]
        if ":" not in host_part:
            host_part += ":443"
        return host_part, False

    parsed = urlparse(v)
    host = parsed.hostname or ""
    use_tls = parsed.scheme.lower() == "https"
    default_port = 443 if use_tls else 80
    port = parsed.port or default_port
    return f"{host}:{port}", use_tls


# ---------------------------------------------------------------------------
# grpcurl execution
# ---------------------------------------------------------------------------

def _grpcurl_base_cmd(req: GRPCReconRequest) -> list[str]:
    """Build the grpcurl base command (without the subcommand / service arg)."""
    authority, inferred_tls = _authority_from_target(req.target)
    cmd = ["grpcurl", "-max-time", str(req.timeout)]

    if req.use_plaintext or not inferred_tls:
        cmd.append("-plaintext")
    elif not req.verify_tls:
        cmd.append("-insecure")

    for key, value in req.headers.items():
        cmd.extend(["-H", f"{key}: {value}"])

    cmd.append(authority)
    return cmd


def _run_grpcurl(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    """Execute *cmd*. Returns (stdout, stderr, returncode)."""
    log.debug("grpcurl: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        log.error("grpcurl not installed or not in PATH")
        return "", "grpcurl is not installed or not in PATH", 127
    except subprocess.TimeoutExpired:
        log.warning("grpcurl timed out after %ds", timeout)
        return "", f"grpcurl timed out after {timeout}s", -1
    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected grpcurl error")
        return "", str(exc), -1


# ---------------------------------------------------------------------------
# HTTP surface probing
# ---------------------------------------------------------------------------

def _probe_http_surface(req: GRPCReconRequest) -> list[GRPCProbe]:
    """Probe common gRPC-web paths via HTTP GET."""
    probes: list[GRPCProbe] = []
    for path in GRPC_HTTP_PROBE_PATHS:
        url = _build_url(req.target, path)
        response = _safe_request(
            "GET", url,
            headers=req.headers,
            timeout=min(req.timeout, 10),
            verify_tls=req.verify_tls,
            allow_redirects=True,
        )
        if response is None:
            probes.append(GRPCProbe(url=url))
            continue

        indicators: list[str] = []
        content_type = response.headers.get("content-type", "")
        server       = response.headers.get("server")
        body         = getattr(response, "text", "") or ""
        lowered      = (content_type + "\n" + body[:500]).lower()
        for marker in ("application/grpc", "grpc-status", "grpc-message", "grpc-web"):
            if marker in lowered:
                indicators.append(marker)

        probes.append(GRPCProbe(
            url=url,
            status_code=response.status_code,
            content_type=content_type or None,
            server=server or None,
            grpc_indicators=indicators,
            response_snippet=_response_snippet(body),
        ))
    return probes


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_service_description(service_name: str, raw_description: str) -> GRPCService:
    """Parse a grpcurl `describe` output into a :class:`GRPCService`."""
    methods: list[GRPCMethod] = []
    for match in RPC_RE.finditer(raw_description):
        method_name    = match.group(1)
        request_stream = bool(match.group(2))
        response_stream = bool(match.group(4))
        combined_name  = f"{service_name}.{method_name}".lower()
        methods.append(GRPCMethod(
            service=service_name,
            name=method_name,
            request_type=match.group(3),
            response_type=match.group(5),
            streaming=request_stream or response_stream,
            sensitive=any(p in combined_name for p in SENSITIVE_NAME_PATTERNS),
        ))

    sensitive_service = any(p in service_name.lower() for p in SENSITIVE_NAME_PATTERNS)
    return GRPCService(
        name=service_name,
        methods=methods,
        raw_description=_response_snippet(raw_description, limit=1200),
        sensitive=sensitive_service or any(m.sensitive for m in methods),
    )


# ---------------------------------------------------------------------------
# Finding generation
# ---------------------------------------------------------------------------

def _build_findings(result: GRPCReconResult) -> list[GRPCFinding]:
    """Derive security findings from the populated *result* object."""
    findings: list[GRPCFinding] = []

    if result.reflection_enabled:
        findings.append(GRPCFinding(
            title="gRPC server reflection enabled",
            severity="medium",
            description=(
                "The service exposes reflection metadata, making service and method "
                "enumeration trivial for any unauthenticated client."
            ),
            evidence=[s.name for s in result.services[:10]],
        ))

    if result.health_service_exposed:
        findings.append(GRPCFinding(
            title="Health check service exposed",
            severity="low",
            description="The standard gRPC health service (grpc.health.v1.Health) is reachable.",
            evidence=["grpc.health.v1.Health"],
        ))

    if result.grpc_web_exposed:
        findings.append(GRPCFinding(
            title="gRPC-web surface detected",
            severity="info",
            description=(
                "HTTP probes returned gRPC-web indicators. "
                "Review browser-accessible methods for CORS and auth gaps."
            ),
            evidence=[p.url for p in result.probes if "grpc-web" in p.grpc_indicators],
        ))

    if result.plaintext_allowed:
        findings.append(GRPCFinding(
            title="Plaintext gRPC transport allowed",
            severity="high",
            description=(
                "The target accepts unencrypted gRPC connections. "
                "All RPC calls are exposed to eavesdropping and MITM attacks."
            ),
            evidence=[result.authority],
        ))

    sensitive = [s.name for s in result.services if s.sensitive]
    if sensitive:
        findings.append(GRPCFinding(
            title="Sensitive gRPC services or methods discovered",
            severity="medium",
            description=(
                "Service or RPC names suggest admin, secret, or high-impact operations "
                "that warrant prioritised manual testing."
            ),
            evidence=sensitive[:15],
        ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def grpc_recon(
    target: str,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 30,
    verify_tls: bool = True,
    use_plaintext: bool = False,
) -> dict[str, Any]:
    """
    Discover gRPC services using grpcurl and lightweight HTTP probes.

    Parameters
    ----------
    target:
        Base URL or host:port, e.g. ``"https://api.example.com:443"`` or
        ``"grpc.example.com:50051"``.
    headers:
        Optional metadata / HTTP headers (e.g. ``{"Authorization": "Bearer …"}``).
    timeout:
        Per-operation timeout in seconds (5–180).
    verify_tls:
        Verify TLS certificates (set False for self-signed certs in test envs).
    use_plaintext:
        Force plaintext gRPC regardless of the URL scheme.

    Returns
    -------
    dict
        Serialised :class:`GRPCReconResult`.
    """
    start   = time.time()
    headers = headers or {}

    # --- Validate input -------------------------------------------------------
    try:
        req = GRPCReconRequest(
            target=target,
            headers=headers,
            timeout=timeout,
            verify_tls=verify_tls,
            use_plaintext=use_plaintext,
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Validation error: %s", exc)
        return GRPCReconResult(
            success=False, detected=False,
            target=target, authority="",
            error=_summarize_validation_error(exc),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    authority, inferred_tls = _authority_from_target(req.target)

    # --- HTTP surface probes --------------------------------------------------
    log.info("HTTP probing %s …", req.target)
    probes          = _probe_http_surface(req)
    grpc_web_exposed = any(
        "grpc-web" in ind
        for probe in probes
        for ind in probe.grpc_indicators
    )
    any_probe_hit    = any(probe.grpc_indicators for probe in probes)

    # Potential plaintext transport based on scheme/config. This only becomes
    # a security finding when a gRPC surface is actually detected.
    transport_insecure = req.use_plaintext or not inferred_tls

    # --- grpcurl not available → return partial result -----------------------
    if not shutil.which("grpcurl"):
        log.warning("grpcurl not found — returning HTTP probe results only")
        partial = GRPCReconResult(
            success=any_probe_hit,
            detected=any_probe_hit,
            target=req.target,
            authority=authority,
            grpc_web_exposed=grpc_web_exposed,
            plaintext_allowed=transport_insecure and any_probe_hit,
            probes=probes,
            command="grpcurl (not installed)",
            error="grpcurl is not installed or not in PATH",
            execution_time=round(time.time() - start, 2),
        )
        partial.findings = _build_findings(partial)
        return partial.model_dump()

    # --- grpcurl reflection enumeration ---------------------------------------
    base_cmd   = _grpcurl_base_cmd(req)
    list_cmd   = [*base_cmd, "list"]
    log.info("Running grpcurl list against %s …", authority)
    stdout, stderr, rc = _run_grpcurl(list_cmd, req.timeout)

    raw_chunks: list[str] = [stdout.strip(), stderr.strip()]
    service_names       = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    reflection_enabled  = rc == 0 and bool(service_names)
    health_service_exposed = "grpc.health.v1.Health" in service_names

    services: list[GRPCService] = []
    if reflection_enabled:
        for svc_name in service_names:
            desc_cmd = [*base_cmd, "describe", svc_name]
            d_stdout, d_stderr, _ = _run_grpcurl(desc_cmd, req.timeout)
            if d_stdout or d_stderr:
                raw_chunks.extend([d_stdout.strip(), d_stderr.strip()])
            services.append(
                _parse_service_description(svc_name, d_stdout or d_stderr)
            )
            log.debug("Described service: %s  methods=%d", svc_name, len(services[-1].methods))

    detected = reflection_enabled or any_probe_hit or grpc_web_exposed
    plaintext_allowed = transport_insecure and detected

    log.info(
        "Recon done | authority=%s reflection=%s services=%d detected=%s time=%.2fs",
        authority, reflection_enabled, len(services), detected,
        time.time() - start,
    )

    result = GRPCReconResult(
        success=detected or rc == 0,
        detected=detected,
        target=req.target,
        authority=authority,
        reflection_enabled=reflection_enabled,
        health_service_exposed=health_service_exposed,
        grpc_web_exposed=grpc_web_exposed,
        plaintext_allowed=plaintext_allowed,
        services=services,
        probes=probes,
        command=" ".join(list_cmd),
        raw_output=_response_snippet(
            "\n\n".join(c for c in raw_chunks if c), limit=5000
        ),
        error=(
            None if detected
            else (stderr[:300] if stderr else "No gRPC services discovered")
        ),
        execution_time=round(time.time() - start, 2),
    )
    result.findings = _build_findings(result)
    return result.model_dump()


# ---------------------------------------------------------------------------
# Tool definition (Anthropic / OpenAI tool-use schema)
# ---------------------------------------------------------------------------

GRPC_RECON_TOOL_DEFINITION: dict[str, Any] = {
    "name": "grpc_recon",
    "description": (
        "Discover gRPC services via grpcurl and HTTP probes. "
        "Detects server reflection, health-check exposure, gRPC-web surface, "
        "plaintext transport, and extracts service/method metadata including "
        "sensitive RPC names."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": (
                    "Base gRPC URL or host:port, e.g. 'https://api.example.com:443' "
                    "or 'grpc.example.com:50051'."
                ),
            },
            "headers": {
                "type": "object",
                "description": (
                    "Optional metadata/HTTP headers, e.g. "
                    "{'Authorization': 'Bearer <token>', 'x-api-key': '<key>'}."
                ),
                "default": {},
            },
            "timeout": {
                "type": "integer",
                "description": "Per-operation timeout in seconds (5–180).",
                "default": 30,
                "minimum": 5,
                "maximum": 180,
            },
            "verify_tls": {
                "type": "boolean",
                "description": "Verify TLS certificates (set false for self-signed certs).",
                "default": True,
            },
            "use_plaintext": {
                "type": "boolean",
                "description": "Force plaintext gRPC regardless of URL scheme.",
                "default": False,
            },
        },
        "required": ["target"],
    },
}


# ---------------------------------------------------------------------------
# Synthetic data for offline testing
# ---------------------------------------------------------------------------

_DEMO_GRPCURL_LIST = """\
grpc.health.v1.Health
helloworld.Greeter
internal.AdminService
"""

_DEMO_DESCRIBE_GREETER = """\
helloworld.Greeter is a service:
service Greeter {
  rpc SayHello ( .helloworld.HelloRequest ) returns ( .helloworld.HelloReply );
  rpc SayHelloStream ( stream .helloworld.HelloRequest ) returns ( stream .helloworld.HelloReply );
}
"""

_DEMO_DESCRIBE_ADMIN = """\
internal.AdminService is a service:
service AdminService {
  rpc DeleteUser ( .internal.DeleteRequest ) returns ( .internal.DeleteResponse );
  rpc UploadConfig ( stream .internal.ConfigChunk ) returns ( .internal.UploadStatus );
  rpc GetSecretToken ( .internal.Empty ) returns ( .internal.TokenResponse );
}
"""


# ---------------------------------------------------------------------------
# Main — local-first execution
# ---------------------------------------------------------------------------

def main() -> None:
    # ── Configure your scan here ────────────────────────────────────────────
    TARGET        = "http://localhost:8888"     # base URL or host:port
    HEADERS       = {}                           # e.g. {"Authorization": "Bearer TOKEN"}
    TIMEOUT       = 15                           # seconds
    VERIFY_TLS    = True
    USE_PLAINTEXT = False
    EMIT_JSON     = False                        # True → raw JSON output
    SHOW_RAW      = False                        # include raw grpcurl output in non-JSON mode
    RUN_SMOKE_TESTS = False                      # parser/findings synthetic checks
    RUN_VALIDATION_TESTS = False                 # expected-failure validation checks
    # ─────────────────────────────────────────────────────────────────────────

    if RUN_SMOKE_TESTS:
        print("=" * 60)
        print("  [smoke] Parser smoke-tests (synthetic grpcurl output)")
        print("=" * 60)
        for label, raw, svc_name in [
            ("Greeter service", _DEMO_DESCRIBE_GREETER, "helloworld.Greeter"),
            ("AdminService   ", _DEMO_DESCRIBE_ADMIN,   "internal.AdminService"),
        ]:
            svc = _parse_service_description(svc_name, raw)
            print(f"\n  {label} -> sensitive={svc.sensitive}  methods={len(svc.methods)}")
            for m in svc.methods:
                print(f"    {m.name:<25} streaming={m.streaming}  sensitive={m.sensitive}")

        print("\n" + "=" * 60)
        print("  [smoke] Findings builder (synthetic result)")
        print("=" * 60)
        fake_result = GRPCReconResult(
            success=True, detected=True,
            target="http://localhost:8888/api",
            authority="grpc.localhost:8888/api",
            reflection_enabled=True,
            health_service_exposed=True,
            grpc_web_exposed=True,
            plaintext_allowed=True,
            services=[
                _parse_service_description("helloworld.Greeter",    _DEMO_DESCRIBE_GREETER),
                _parse_service_description("internal.AdminService", _DEMO_DESCRIBE_ADMIN),
            ],
        )
        fake_result.findings = _build_findings(fake_result)
        for f in fake_result.findings:
            print(f"  [{f.severity.upper():<6}] {f.title}")
            print(f"           evidence: {f.evidence[:3]}")

    if RUN_VALIDATION_TESTS:
        print("\n" + "=" * 60)
        print("  [validation] Expected-failure validation tests")
        print("=" * 60)
        bad_cases = [
            ("",                           {}, 30, True,  False, "empty target"),
            ("127.0.0.1:443",              {}, 30, True,  False, "blocked loopback"),
            ("https://169.254.0.1:443",    {}, 30, True,  False, "blocked link-local"),
            ("ftp://host.example.com",     {}, 30, True,  False, "invalid scheme"),
            ("http://localhost:8888/api",  {"bad name!": "val"}, 30, True, False, "invalid header name"),
            ("http://localhost:8888/api",  {"X-Key": "val\ninjected"}, 30, True, False, "header injection"),
            ("http://localhost:8888/api",  {}, 2,  True,  False, "timeout below minimum"),
        ]
        for tgt, hdrs, tout, vtls, plain, label in bad_cases:
            r = grpc_recon(tgt, hdrs, tout, vtls, plain)
            status = "OK(rejected)" if not r["success"] else "UNEXPECTED(pass)"
            print(f"  {status:<16} [{label}]  error: {str(r.get('error', ''))[:70]!r}")

    print("\n" + "=" * 60)
    print(f"  Live scan -> {TARGET}  timeout={TIMEOUT}s  tls={VERIFY_TLS}")
    print("=" * 60)
    result = grpc_recon(
        target=TARGET,
        headers=HEADERS,
        timeout=TIMEOUT,
        verify_tls=VERIFY_TLS,
        use_plaintext=USE_PLAINTEXT,
    )

    if EMIT_JSON:
        print(json.dumps(result, indent=2, default=str))
        return

    status = "OK" if result.get("success") else "FAILED"
    print(f"\n[{status}] {result.get('target')}  ({result.get('execution_time')}s)")
    print(f"  Authority            : {result.get('authority')}")
    print(f"  gRPC detected        : {result.get('detected')}")
    print(f"  Reflection enabled   : {result.get('reflection_enabled')}")
    print(f"  Services discovered  : {len(result.get('services') or [])}")
    print(f"  HTTP probes          : {len(result.get('probes') or [])}")

    findings = result.get("findings") or []
    if findings:
        print("\n  Findings:")
        for f in findings:
            print(f"    [{str(f.get('severity', 'info')).upper():<6}] {f.get('title')}")

    if result.get("error"):
        print(f"\n  Error: {result['error']}")

    if SHOW_RAW and result.get("raw_output"):
        print("\n  Raw output:")
        print(result["raw_output"])


if __name__ == "__main__":
    main()