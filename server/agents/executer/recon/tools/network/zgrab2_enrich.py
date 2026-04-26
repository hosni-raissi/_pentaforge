#/+
"""
zgrab2_enrich_tool.py
~~~~~~~~~~~~~~~~~~~~~
Rapid post-discovery service enrichment using zgrab2.

Takes a host (typically from masscan / naabu output) and performs
application-layer banner grabbing across HTTP, SSH, FTP, TLS, Redis,
MongoDB, MQTT, and more protocols.  Returns structured findings suitable
for feeding directly into a vulnerability triage pipeline.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from server.agents.executer.recon.config import is_blocked_host

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("zgrab2_enrich")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_MODULES: frozenset[str] = frozenset({
    "banner", "http", "imap", "ftp", "modbus", "mongodb", "mqtt",
    "pop3", "postgres", "redis", "smtp", "ssh", "telnet", "tls",
})

# Modules that support TLS natively via a zgrab2 flag
_TLS_CAPABLE_MODULES: frozenset[str] = frozenset({
    "http", "imap", "pop3", "smtp", "ftp", "postgres",
})

_DANGEROUS: frozenset[str] = frozenset({
    ";", "&&", "||", "|", "`", "$(", ">>", "<<",
    ">", "<", "'", '"', "\n", "\r", "\x00",
})

# Default ports per module — banner has NO default (explicit port required)
_DEFAULT_PORTS: dict[str, int] = {
    "ftp":      21,
    "ssh":      22,
    "telnet":   23,
    "smtp":     25,
    "http":     80,
    "pop3":    110,
    "imap":    143,
    "tls":     443,
    "modbus":  502,
    "mqtt":   1883,
    "postgres": 5432,
    "redis":   6379,
    "mongodb": 27017,
}

# zgrab2 target-timeout is capped lower than our subprocess timeout
# to ensure the process always exits cleanly before we SIGKILL it.
_ZGRAB2_TIMEOUT_CAP = 90          # seconds — hard cap sent to zgrab2 --target-timeout
_SUBPROCESS_BUFFER   = 15         # extra seconds before we force-kill the process
_RAW_OUTPUT_MAX_LEN = 8000        # max chars returned in raw_output
_RAW_STRING_MAX_LEN = 1200        # max chars kept for any nested raw string

# Blocked CIDRs and Hostnames are now imported centrally from config.py

# RFC-1123 hostname pattern
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

def _validate_target(value: str) -> str:
    """Validate and normalise a scan target (IP or hostname)."""
    v = value.strip()
    if not v:
        raise ValueError("Target must not be empty")

    if len(v) > 253:
        raise ValueError(f"Hostname too long: {v!r}")

    if is_blocked_host(v.lower()):
        raise ValueError(f"Target '{v}' is blocked")

    try:
        ip = ipaddress.ip_address(v)
        return v
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(v.rstrip(".")):
        raise ValueError(f"Invalid hostname or IP: {v!r}")
    
    return v


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ZGrab2Request(BaseModel):
    """Validated, sanitised zgrab2 request."""

    target: str
    module: str = "http"
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    use_tls: bool = False
    args: list[str] = []
    timeout: int = Field(default=120, ge=10, le=1800)

    @field_validator("target")
    @classmethod
    def check_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("module")
    @classmethod
    def check_module(cls, v: str) -> str:
        norm = v.strip().lower()
        if norm not in _ALLOWED_MODULES:
            raise ValueError(f"module must be one of: {sorted(_ALLOWED_MODULES)}")
        return norm

    @field_validator("args")
    @classmethod
    def check_args(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in v:
            arg = raw.strip()
            if not arg.startswith("--"):
                raise ValueError(
                    f"Argument {arg!r} is not a valid zgrab2 flag (must start with '--')"
                )
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
            cleaned.append(arg)
        return cleaned

    @model_validator(mode="after")
    def cross_validate(self) -> "ZGrab2Request":
        # banner module requires an explicit port (it has no default)
        if self.module == "banner" and self.port is None:
            raise ValueError("module='banner' requires an explicit port (1–65535)")
        # use_tls is only meaningful for TLS-capable modules
        if self.use_tls and self.module not in _TLS_CAPABLE_MODULES:
            raise ValueError(
                f"use_tls=True is not supported for module='{self.module}'. "
                f"TLS-capable modules: {sorted(_TLS_CAPABLE_MODULES)}"
            )
        return self


class ZGrabFinding(BaseModel):
    """Structured finding from a single zgrab2 probe."""

    target: str
    module: str
    port: int
    status: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    banner: Optional[str] = None
    protocol: Optional[str] = None
    tls: Optional[dict[str, Any]] = None
    # raw stores only the top-level zgrab2 metadata, not the full data subtree
    raw_meta: Optional[dict[str, Any]] = None


class ZGrab2Result(BaseModel):
    """Full result returned to callers."""

    success: bool       # tool executed without fatal error
    enriched: bool      # a valid finding was parsed from the response
    target: str
    module: str
    command: str
    finding: Optional[ZGrabFinding] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ---------------------------------------------------------------------------
# Safe execution
# ---------------------------------------------------------------------------

def _safe_execute(
    cmd: list[str],
    timeout: int,
    stdin_data: str,
) -> tuple[str, str, int]:
    """
    Run *cmd* without a shell, feeding *stdin_data* via stdin.

    The process is given ``timeout + _SUBPROCESS_BUFFER`` seconds before we
    force-kill it, giving zgrab2 time to flush JSON output after its own
    internal timeout fires.

    Returns (stdout, stderr, returncode).
    """
    hard_timeout = timeout + _SUBPROCESS_BUFFER
    log.debug("Executing (hard timeout=%ds): %s", hard_timeout, " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=hard_timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        log.warning("zgrab2 hard-timeout (%ds) exceeded", hard_timeout)
        return "", f"Hard timeout after {hard_timeout}s", -1
    except FileNotFoundError:
        log.error("zgrab2 not installed or not in PATH")
        return "", "Tool 'zgrab2' not installed or not in PATH", -1
    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected subprocess error")
        return "", str(exc), -1


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _extract_first_json_line(output: str) -> Optional[dict[str, Any]]:
    """Return the first valid JSON object found in *output*, or None."""
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


def _sanitize_raw_payload(value: Any, key: Optional[str] = None) -> Any:
    """Trim bulky nested payload fields for compact raw_output transport."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            # HTTP bodies are usually enormous and low-signal for triage.
            if k == "body" and isinstance(v, str):
                out[k] = f"<redacted body: {len(v)} chars>"
            else:
                out[k] = _sanitize_raw_payload(v, k)
        return out
    if isinstance(value, list):
        capped = value[:100]
        return [_sanitize_raw_payload(item, key) for item in capped]
    if isinstance(value, str) and len(value) > _RAW_STRING_MAX_LEN:
        remaining = len(value) - _RAW_STRING_MAX_LEN
        return f"{value[:_RAW_STRING_MAX_LEN]}...<truncated {remaining} chars>"
    return value


def _compact_raw_output(stdout: str, stderr: str) -> Optional[str]:
    """Prefer compacted JSON payload; fallback to plain stdout/stderr snippet."""
    payload = _extract_first_json_line(stdout)
    if isinstance(payload, dict):
        try:
            compact = _sanitize_raw_payload(payload)
            return json.dumps(compact)[:_RAW_OUTPUT_MAX_LEN]
        except Exception:  # noqa: BLE001
            pass
    return (stdout or stderr)[:_RAW_OUTPUT_MAX_LEN] or None


def _parse_finding(
    target: str,
    module: str,
    port: int,
    payload: dict[str, Any],
) -> ZGrabFinding:
    """
    Extract a structured :class:`ZGrabFinding` from a raw zgrab2 JSON payload.

    Only the top-level metadata is stored in ``raw_meta`` — the potentially
    large ``data`` subtree is not persisted verbatim.
    """
    data    = payload.get("data", {})
    mod_data = data.get(module, {}) if isinstance(data, dict) else {}
    result  = mod_data.get("result", {}) if isinstance(mod_data, dict) else {}
    module_status = mod_data.get("status") if isinstance(mod_data, dict) else None

    finding = ZGrabFinding(
        target=target,
        module=module,
        port=port,
        status=(payload.get("status") or module_status),
        # Preserve top-level metadata only (ip, timestamp, domain, error)
        raw_meta={
            k: v for k, v in payload.items()
            if k not in ("data",) and not isinstance(v, (dict, list))
        },
    )

    if module == "http":
        response = result.get("response", {}) if isinstance(result, dict) else {}
        headers  = response.get("headers", {}) if isinstance(response, dict) else {}
        finding.status_code = response.get("status_code")
        finding.title       = response.get("title")
        server = headers.get("server") if isinstance(headers, dict) else None
        if isinstance(server, list):
            server = ", ".join(str(s) for s in server[:3])
        finding.banner   = str(server)[:300] if server else None
        finding.protocol = "https" if data.get("tls") else "http"

    else:
        # Generic: serialise the result block as the banner (capped at 500 chars)
        if result:
            finding.banner = json.dumps(result)[:500]
        elif mod_data:
            finding.banner = json.dumps(mod_data)[:500]
        finding.protocol = module

    # TLS metadata — present for any module that negotiated TLS
    tls_block = data.get("tls") if isinstance(data, dict) else None
    if isinstance(tls_block, dict):
        # Keep only the handshake summary, not full certificate chains
        hs = tls_block.get("result", {}).get("handshake_log", {})
        finding.tls = {
            "version":     hs.get("server_hello", {}).get("version", {}).get("name"),
            "cipher_suite": hs.get("server_hello", {}).get("cipher_suite", {}).get("name"),
            "subject":     (
                hs.get("server_certificates", {})
                  .get("certificate", {})
                  .get("parsed", {})
                  .get("subject_dn")
            ),
        }

    return finding


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------

def _build_cmd(req: ZGrab2Request, resolved_port: int) -> list[str]:
    """Construct the zgrab2 command list for *req*."""
    # Cap zgrab2's per-target timeout below our subprocess hard-timeout so it
    # always has time to flush output before we force-kill it.
    zgrab2_timeout = min(req.timeout, _ZGRAB2_TIMEOUT_CAP)

    cmd = ["zgrab2", req.module, "--port", str(resolved_port),
           "--target-timeout", f"{zgrab2_timeout}s"]

    # zgrab2 defaults to ~/.config/zgrab2/blocklist.conf when blocklist is "-".
    # Use /dev/null by default to avoid fatal errors when that file is absent.
    if not any(a.startswith("--blocklist-file") for a in req.args):
        cmd += ["--blocklist-file", "/dev/null"]

    if req.use_tls:
        if req.module == "http":
            cmd.append("--use-https")
        else:
            # For IMAP/POP3/SMTP/FTP/Postgres the flag is --starttls or --tls
            cmd.append("--starttls")

    cmd += req.args
    return cmd


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def zgrab2_enrich(
    target: str,
    module: str = "http",
    port: Optional[int] = None,
    use_tls: bool = False,
    args: Optional[list[str]] = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """
    Perform application-layer banner grabbing against *target* using zgrab2.

    Parameters
    ----------
    target:
        IPv4/IPv6 address or hostname to probe.
    module:
        zgrab2 module name, e.g. ``"http"``, ``"ssh"``, ``"redis"``.
        Defaults to ``"http"``.
    port:
        Port to connect to.  Defaults to the well-known port for *module*.
        Required for ``module="banner"``.
    use_tls:
        Wrap the connection in TLS / STARTTLS where the module supports it.
    args:
        Extra zgrab2 flags — every element must start with ``--``.
    timeout:
        Seconds before aborting (10–1800).

    Returns
    -------
    dict
        Serialised :class:`ZGrab2Result`.
    """
    start = time.time()
    args = args or []

    # --- Validate input -------------------------------------------------------
    try:
        req = ZGrab2Request(
            target=target, module=module, port=port,
            use_tls=use_tls, args=args, timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Validation error: %s", exc)
        return ZGrab2Result(
            success=False, enriched=False,
            target=target, module=module,
            command="", error=str(exc),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # --- Resolve port ---------------------------------------------------------
    resolved_port = req.port or _DEFAULT_PORTS.get(req.module)
    if not resolved_port:
        # Should only happen for 'banner' without a port, already caught above
        err = f"No default port for module='{req.module}' and no port specified"
        log.error(err)
        return ZGrab2Result(
            success=False, enriched=False,
            target=req.target, module=req.module,
            command="", error=err,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # --- Build command and execute --------------------------------------------
    cmd = _build_cmd(req, resolved_port)
    log.info("Probing %s:%d [module=%s tls=%s] …", req.target, resolved_port, req.module, req.use_tls)
    stdout, stderr, rc = _safe_execute(cmd, req.timeout, req.target + "\n")

    # --- Parse ----------------------------------------------------------------
    payload = _extract_first_json_line(stdout)
    finding = _parse_finding(req.target, req.module, resolved_port, payload) if payload else None
    module_status: Optional[str] = None
    module_error: Optional[str] = None
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, dict):
            mod_data = data.get(req.module)
            if isinstance(mod_data, dict):
                raw_status = mod_data.get("status")
                if isinstance(raw_status, str):
                    module_status = raw_status.lower()
                raw_error = mod_data.get("error")
                if isinstance(raw_error, str):
                    module_error = raw_error

    # Treat parsed output as enriched only when the module itself reports success.
    enriched = finding is not None and (module_status is None or module_status == "success")

    log.info(
        "Probe done | target=%s:%d enriched=%s rc=%d time=%.2fs",
        req.target, resolved_port, enriched, rc, time.time() - start,
    )

    return ZGrab2Result(
        success=rc == 0 or enriched,
        enriched=enriched,
        target=req.target,
        module=req.module,
        command=" ".join(cmd),
        finding=finding,
        raw_output=_compact_raw_output(stdout, stderr),
        error=(stderr[:500] if rc != 0 else None) or (module_error if not enriched else None),
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ---------------------------------------------------------------------------
# Tool definition (Anthropic / OpenAI tool-use schema)
# ---------------------------------------------------------------------------

ZGRAB2_ENRICH_TOOL_DEFINITION: dict[str, Any] = {
    "name": "zgrab2_enrich",
    "description": (
        "Rapid post-discovery service enrichment using zgrab2. "
        "Takes a host found by a port scanner and performs application-layer "
        "banner grabbing across HTTP, SSH, FTP, TLS, Redis, MongoDB, MQTT, and "
        "more protocols. Returns structured findings for vulnerability triage."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IPv4/IPv6 address or hostname to probe (public addresses only).",
            },
            "module": {
                "type": "string",
                "enum": sorted(_ALLOWED_MODULES),
                "description": "zgrab2 module / protocol to use.",
                "default": "http",
            },
            "port": {
                "type": "integer",
                "description": (
                    "Port to connect to (1–65535). Defaults to the well-known port "
                    "for the selected module. Required for module='banner'."
                ),
                "minimum": 1,
                "maximum": 65535,
            },
            "use_tls": {
                "type": "boolean",
                "description": (
                    "Wrap the connection in TLS/STARTTLS. "
                    f"Supported modules: {sorted(_TLS_CAPABLE_MODULES)}."
                ),
                "default": False,
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra zgrab2 flags (each must start with '--').",
                "default": [],
            },
            "timeout": {
                "type": "integer",
                "description": "Probe timeout in seconds (10–1800).",
                "default": 120,
                "minimum": 10,
                "maximum": 1800,
            },
        },
        "required": ["target"],
    },
}


# ---------------------------------------------------------------------------
# Synthetic outputs for offline testing
# ---------------------------------------------------------------------------

_DEMO_HTTP_PAYLOAD = {
    "ip": "203.0.113.10",
    "domain": "example.com",
    "timestamp": "2024-01-15T10:00:00Z",
    "status": "success",
    "data": {
        "http": {
            "result": {
                "response": {
                    "status_code": 200,
                    "title": "Welcome to Example.com",
                    "headers": {
                        "server": ["nginx/1.24.0"],
                        "x-powered-by": ["PHP/8.2"],
                    },
                }
            }
        }
    },
}

_DEMO_REDIS_PAYLOAD = {
    "ip": "203.0.113.11",
    "timestamp": "2024-01-15T10:00:01Z",
    "status": "success",
    "data": {
        "redis": {
            "result": {
                "version": "7.2.3",
                "mode": "standalone",
                "os": "Linux 5.15.0",
                "authenticated": False,
            }
        }
    },
}

_DEMO_SSH_PAYLOAD = {
    "ip": "203.0.113.12",
    "timestamp": "2024-01-15T10:00:02Z",
    "status": "success",
    "data": {
        "ssh": {
            "result": {
                "server_id": {"raw": "SSH-2.0-OpenSSH_9.2p1 Debian-2"},
                "algorithm_selection": {
                    "host_key": "rsa-sha2-256",
                    "client_to_server_cipher": "aes256-gcm@openssh.com",
                },
            }
        }
    },
}


# ---------------------------------------------------------------------------
# Main — hardcoded test cases
# ---------------------------------------------------------------------------

def main() -> None:
    # ── Edit these to match your test environment ────────────────────────────
    TARGET   = "10.129.29.141"    # replace with a real target IP
    MODULE   = "http"            # zgrab2 module name
    PORT     = None              # None = use default for module
    USE_TLS  = False             # wrap in TLS/STARTTLS
    ARGS     = []                # extra flags, e.g. ["--max-redirects=3"]
    TIMEOUT  = 30                # seconds
    # ─────────────────────────────────────────────────────────────────────────

    # 1. Offline parser smoke-tests (no zgrab2 binary needed)
    print("=" * 60)
    print("  [1] Parser smoke-tests (synthetic payloads)")
    print("=" * 60)
    for label, payload, mod, port in [
        ("HTTP  ", _DEMO_HTTP_PAYLOAD,  "http",  80),
        ("Redis ", _DEMO_REDIS_PAYLOAD, "redis", 6379),
        ("SSH   ", _DEMO_SSH_PAYLOAD,   "ssh",   22),
    ]:
        f = _parse_finding(payload["ip"], mod, port, payload)
        print(f"\n  {label} → status={f.status!r} code={f.status_code} "
              f"title={f.title!r} banner={f.banner!r:.60} protocol={f.protocol!r}")

    # 2. Validation tests — every call below should fail with a clear error
    print("\n" + "=" * 60)
    print("  [2] Validation tests (all expected to fail)")
    print("=" * 60)
    bad_cases = [
        ("8.8.8.8",     "tftp",   None,  False, [],                  60, "invalid module"),
        ("8.8.8.8",     "HTTP",   None,  False, [],                  60, "module case — now normalised, should pass"),
        ("8.8.8.8",     "banner", None,  False, [],                  60, "banner without port"),
        ("8.8.8.8",     "redis",  None,  True,  [],                  60, "use_tls on non-TLS module"),
        ("8.8.8.8",     "http",   None,  False, ["use-https"],       60, "arg missing -- prefix"),
        ("8.8.8.8",     "http",   None,  False, ["--path=/;id"],     60, "shell injection in arg"),
        ("8.8.8.8",     "http",   None,  False, [],                   5, "timeout below minimum"),
    ]
    for tgt, mod, port, tls, args, timeout, label in bad_cases:
        r = zgrab2_enrich(tgt, mod, port, tls, args, timeout)
        status = "✅ rejected" if not r["success"] else "✅ passed (normalised)"
        print(f"  {status}  [{label}]  error: {str(r.get('error',''))[:55]!r}")

    # 3. Live probe against the configured target
    print("\n" + "=" * 60)
    print(f"  [3] Live probe → {TARGET}  module={MODULE}  port={PORT or 'default'}  "
          f"tls={USE_TLS}  timeout={TIMEOUT}s")
    print("=" * 60)
    result = zgrab2_enrich(
        target=TARGET, module=MODULE, port=PORT,
        use_tls=USE_TLS, args=ARGS, timeout=TIMEOUT,
    )
    print(json.dumps(result, indent=2, default=str))

    print("\n" + "=" * 60)
    if result["enriched"]:
        f = result["finding"]
        print(f"  ✅  Enriched")
        print(f"      Protocol    : {f['protocol']}")
        print(f"      Status      : {f['status']}  code={f['status_code']}")
        print(f"      Title       : {f['title']}")
        print(f"      Banner      : {str(f['banner'])[:60]!r}")
        if f["tls"]:
            print(f"      TLS version : {f['tls'].get('version')}")
            print(f"      TLS cipher  : {f['tls'].get('cipher_suite')}")
    elif result["success"]:
        print("  ℹ️  Probe ran cleanly — no structured response parsed.")
    else:
        print(f"  ❌  Probe failed: {result.get('error', 'unknown error')}")
    print(f"      Time        : {result['execution_time']}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
