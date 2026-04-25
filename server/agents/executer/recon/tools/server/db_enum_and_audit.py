#/+
from __future__ import annotations

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator


COMMON_DB_PORTS: tuple[int, ...] = (
    1433,   # MSSQL
    1521,   # Oracle
    27017,  # MongoDB
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    9042,   # Cassandra
)

PORT_SERVICE_HINTS: dict[int, str] = {
    1433:  "mssql",
    1521:  "oracle",
    27017: "mongodb",
    3306:  "mysql",
    5432:  "postgresql",
    6379:  "redis",
    9042:  "cassandra",
}




# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class DbEnumRequest(BaseModel):
    target: str
    ports: list[int] = Field(default_factory=list)
    timeout: int = Field(default=20, ge=3, le=120)
    max_workers: int = Field(default=10, ge=1, le=50)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        clean = str(value or "").strip()
        if not clean:
            raise ValueError("target is required")
        host = _extract_host(clean)
        if is_blocked_host(host.lower()):
            raise ValueError(f"Target '{value}' is blocked")
        return clean

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[int]) -> list[int]:
        for port in value:
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port!r}")
        return sorted(set(value))


class DbPortFinding(BaseModel):
    port: int
    open: bool
    service_hint: str
    banner: Optional[str] = None
    risk: str = "info"


class DbEnumResult(BaseModel):
    success: bool
    target: str
    command: str
    working_dir: str
    total_checked: int
    total_open: int
    findings: list[DbPortFinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_host(value: str) -> str:
    """Strip scheme, path, and port from a URL-like string to get the bare host."""
    clean = value.strip()
    clean = re.sub(r"^\w+://", "", clean)
    clean = clean.split("/")[0].split("?")[0]
    # IPv6 literal: [::1]:port
    if clean.startswith("["):
        bracket_end = clean.find("]")
        return clean[1:bracket_end] if bracket_end != -1 else clean[1:]
    # host:port — only split if there is exactly one colon (not an IPv6 address)
    if ":" in clean and clean.count(":") == 1:
        host, maybe_port = clean.rsplit(":", 1)
        if maybe_port.isdigit():
            return host
    return clean


def _resolve_and_guard(host: str) -> str:
    """Resolve hostname to IP and re-validate against blocked ranges."""
    try:
        ip_str = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host '{host}': {exc}") from exc
    addr = ipaddress.ip_address(ip_str)
    if any(addr in net for net in _BLOCKED_NETWORKS):
        raise ValueError(
            f"Host '{host}' resolves to blocked address {ip_str}"
        )
    return ip_str


def _probe_port(host: str, port: int, timeout: float) -> DbPortFinding:
    """
    Open one connection, optionally grab a banner over the *same* socket,
    and return a finding.  All errors are caught so concurrent callers never
    see an exception.
    """
    hint = PORT_SERVICE_HINTS.get(port, "unknown")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = _read_banner(sock, port, timeout=min(2.0, timeout))
            risk = "medium" if port in PORT_SERVICE_HINTS else "low"
            return DbPortFinding(
                port=port,
                open=True,
                service_hint=hint,
                banner=banner[:180] if banner else None,
                risk=risk,
            )
    except OSError:
        return DbPortFinding(port=port, open=False, service_hint=hint)


def _read_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """
    Best-effort banner read over an *already-open* socket.
    Sends a protocol-appropriate probe for known services.
    """
    sock.settimeout(timeout)
    try:
        if port == 6379:                          # Redis
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        elif port == 5432:                        # PostgreSQL SSLRequest
            sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        elif port == 27017:                       # MongoDB OP_MSG ismaster
            # Minimal OP_MSG payload
            payload = (
                b"\x48\x00\x00\x00"  # total message length (72)
                b"\x00\x00\x00\x00"  # requestID
                b"\x00\x00\x00\x00"  # responseTo
                b"\xdd\x07\x00\x00"  # opCode OP_MSG=2013
                b"\x00\x00\x00\x00"  # flagBits
                b"\x00"              # section kind 0
                # BSON: {isMaster:1}
                b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
            )
            sock.sendall(payload)
        data = sock.recv(256)
        return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def db_enum_and_audit(
    target: str,
    ports: Optional[list[int]] = None,
    timeout: int = 20,
    max_workers: int = 10,
) -> dict:
    """
    Enumerate exposed database services on common DB ports.

    Parameters
    ----------
    target:       Host/IP or URL (host is extracted automatically).
    ports:        Ports to scan; defaults to COMMON_DB_PORTS.
    timeout:      Per-probe timeout in seconds (3–120).
    max_workers:  Thread-pool size for concurrent probing (1–50).

    Returns
    -------
    Serialised DbEnumResult dict.
    """
    started = time.monotonic()

    try:
        req = DbEnumRequest(
            target=target,
            ports=ports or [],
            timeout=timeout,
            max_workers=max_workers,
        )
    except Exception as exc:
        return DbEnumResult(
            success=False,
            target=target,
            command="",
            working_dir=str(Path.cwd()),
            total_checked=0,
            total_open=0,
            error=str(exc),
            execution_time=round(time.monotonic() - started, 2),
        ).model_dump()

    host = _extract_host(req.target)

    # DNS resolution + second-pass private-IP guard
    try:
        resolved_host = _resolve_and_guard(host)
    except ValueError as exc:
        return DbEnumResult(
            success=False,
            target=req.target,
            command="",
            working_dir=str(Path.cwd()),
            total_checked=0,
            total_open=0,
            error=str(exc),
            execution_time=round(time.monotonic() - started, 2),
        ).model_dump()

    selected_ports = req.ports or list(COMMON_DB_PORTS)
    per_probe_timeout = min(5.0, req.timeout)

    # Concurrent port probing
    findings: list[DbPortFinding] = [None] * len(selected_ports)  # type: ignore[list-item]
    with ThreadPoolExecutor(max_workers=req.max_workers) as pool:
        future_to_idx = {
            pool.submit(_probe_port, resolved_host, port, per_probe_timeout): idx
            for idx, port in enumerate(selected_ports)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                findings[idx] = future.result()
            except Exception as exc:  # should never happen; _probe_port swallows errors
                port = selected_ports[idx]
                findings[idx] = DbPortFinding(
                    port=port,
                    open=False,
                    service_hint=PORT_SERVICE_HINTS.get(port, "unknown"),
                    risk="info",
                )

    open_findings = [f for f in findings if f.open]

    warnings: list[str] = []
    if open_findings and any(
        f.port in {3306, 5432, 6379, 27017} for f in open_findings
    ):
        warnings.append(
            "One or more common database ports are externally reachable."
        )

    cmd = (
        f"socket_probe target={resolved_host} "
        f"ports={','.join(str(p) for p in selected_ports)}"
    )

    return DbEnumResult(
        success=True,
        target=req.target,
        command=cmd,
        working_dir=str(Path.cwd()),
        total_checked=len(selected_ports),
        total_open=len(open_findings),
        findings=findings,
        warnings=warnings,
        execution_time=round(time.monotonic() - started, 2),
    ).model_dump()


DB_ENUM_AND_AUDIT_TOOL_DEFINITION = {
    "name": "db_enum_and_audit",
    "description": (
        "Enumerate exposed database services on common DB ports and collect "
        "basic banner evidence when available."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target host/IP (URL also accepted; host is extracted).",
            },
            "ports": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Optional custom ports. Defaults to common DB ports.",
            },
            "timeout": {
                "type": "integer",
                "description": "Per-probe timeout budget in seconds (default 20).",
            },
            "max_workers": {
                "type": "integer",
                "description": "Concurrent probe threads (default 10, max 50).",
            },
        },
        "required": ["target"],
    },
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# ── Configure your scan here ─────────────────────────────────────────────────
TARGET      = "10.129.22.137"   # host, IP address, or full URL
PORTS       = None            # e.g. [3306, 5432] or None for all common DB ports
TIMEOUT     = 20              # per-probe timeout in seconds (3–120)
MAX_WORKERS = 10              # concurrent probe threads (1–50)
EMIT_JSON   = False           # True → raw JSON output, False → human-readable
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    import json

    result = db_enum_and_audit(
        target=TARGET,
        ports=PORTS,
        timeout=TIMEOUT,
        max_workers=MAX_WORKERS,
    )

    if EMIT_JSON:
        print(json.dumps(result, indent=2))
        return

    # Human-readable summary
    status = "OK" if result["success"] else "FAILED"
    print(f"\n[{status}] {result['target']}  ({result['execution_time']}s)\n")

    if result.get("error"):
        print(f"  Error: {result['error']}\n")
        return

    open_count = result["total_open"]
    checked_count = result["total_checked"]
    print(f"  Ports checked : {checked_count}")
    print(f"  Ports open    : {open_count}\n")

    for finding in result["findings"]:
        if not finding["open"]:
            continue
        banner_preview = ""
        if finding.get("banner"):
            snippet = finding["banner"][:60].replace("\n", " ")
            banner_preview = f'  banner="{snippet}"'
        print(
            f"  [{finding['risk'].upper():6}] "
            f"port={finding['port']:<6} "
            f"service={finding['service_hint']:<12}"
            f"{banner_preview}"
        )

    for warning in result.get("warnings", []):
        print(f"\n  [WARN] {warning}")

    print()


if __name__ == "__main__":
    main()