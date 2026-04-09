from __future__ import annotations

import re
import socket
import time
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
    1433: "mssql",
    1521: "oracle",
    27017: "mongodb",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    9042: "cassandra",
}


class DbEnumRequest(BaseModel):
    target: str
    ports: list[int] = Field(default_factory=list)
    timeout: int = Field(default=20, ge=3, le=120)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        clean = str(value or "").strip()
        if not clean:
            raise ValueError("target is required")
        host = _extract_host(clean)
        if host in {"127.0.0.1", "localhost", "0.0.0.0", "::1"}:
            raise ValueError(f"Target '{value}' is blocked")
        return clean

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[int]) -> list[int]:
        for port in value:
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port '{port}'")
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


def _extract_host(value: str) -> str:
    clean = value.strip()
    clean = re.sub(r"^\w+://", "", clean)
    clean = clean.split("/")[0]
    clean = clean.split("?")[0]
    if ":" in clean and clean.count(":") == 1:
        host, maybe_port = clean.split(":")
        if maybe_port.isdigit():
            return host
    return clean


def _banner_sample(host: str, port: int, timeout: int) -> str:
    # Best-effort banner reads for common DB protocols.
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if port == 6379:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        if port == 5432:
            # PostgreSQL SSLRequest (int32 length=8 + int32 code=80877103)
            sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        data = sock.recv(180)
        return data.decode("utf-8", errors="replace").strip()


def _probe_port(host: str, port: int, timeout: int) -> DbPortFinding:
    hint = PORT_SERVICE_HINTS.get(port, "unknown")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            banner = ""
            try:
                banner = _banner_sample(host, port, timeout=2)
            except Exception:
                banner = ""
            risk = "medium" if port in PORT_SERVICE_HINTS else "low"
            return DbPortFinding(
                port=port,
                open=True,
                service_hint=hint,
                banner=banner[:180] if banner else None,
                risk=risk,
            )
    except Exception:
        return DbPortFinding(port=port, open=False, service_hint=hint)


def db_enum_and_audit(
    target: str,
    ports: Optional[list[int]] = None,
    timeout: int = 20,
) -> dict:
    started = time.time()
    try:
        req = DbEnumRequest(target=target, ports=ports or [], timeout=timeout)
    except Exception as exc:
        return DbEnumResult(
            success=False,
            target=target,
            command="",
            working_dir=str(Path.cwd()),
            total_checked=0,
            total_open=0,
            error=str(exc),
            execution_time=round(time.time() - started, 2),
        ).model_dump()

    host = _extract_host(req.target)
    selected_ports = req.ports or list(COMMON_DB_PORTS)
    findings = [_probe_port(host, port, min(5, req.timeout)) for port in selected_ports]
    open_findings = [finding for finding in findings if finding.open]

    warnings: list[str] = []
    if open_findings and any(f.port in {3306, 5432, 6379, 27017} for f in open_findings):
        warnings.append("One or more common database ports are externally reachable.")

    cmd = f"socket_probe target={host} ports={','.join(str(p) for p in selected_ports)}"

    result = DbEnumResult(
        success=True,
        target=req.target,
        command=cmd,
        working_dir=str(Path.cwd()),
        total_checked=len(selected_ports),
        total_open=len(open_findings),
        findings=findings,
        warnings=warnings,
        execution_time=round(time.time() - started, 2),
    )
    return result.model_dump()


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
                "description": "Target host/IP (URL also accepted; host is extracted)",
            },
            "ports": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Optional custom ports. Defaults to common DB ports.",
            },
            "timeout": {
                "type": "integer",
                "description": "Overall timeout budget (seconds). Default 20.",
            },
        },
        "required": ["target"],
    },
}
