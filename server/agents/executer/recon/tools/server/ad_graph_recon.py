#/+
from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.config import is_blocked_host

_ALLOWED_TOOLS = {"bloodhound-python", "ldapdomaindump"}
_DANGEROUS = {";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n"}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ADGraphReconRequest(BaseModel):
    target: str
    tool: str = "bloodhound-python"
    domain: str
    username: str
    password: str
    nameserver: Optional[str] = None
    collection: str = "All"
    args: list[str] = []
    timeout: int = Field(default=900, ge=30, le=7200)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("target cannot be empty")
        v_lower = clean.lower()
        if is_blocked_host(v_lower):
            raise ValueError(f"Target '{clean}' is blocked")
        return clean

    @field_validator("domain", "username")
    @classmethod
    def validate_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("value cannot be empty")
        return v.strip()

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in _ALLOWED_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(_ALLOWED_TOOLS)}")
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        for arg in v:
            if any(ch in arg for ch in _DANGEROUS):
                raise ValueError(f"Dangerous arg: {arg}")
        return v


class ADGraphArtifact(BaseModel):
    name: str
    size: int
    content: Optional[str] = None


class ADGraphReconResult(BaseModel):
    success: bool
    target: str
    tool: str
    command: str
    artifacts: list[ADGraphArtifact] = []
    artifact_count: int = 0
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_execute(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=False
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as exc:
        return "", str(exc), -1


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _probe_tcp(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "open"
    except OSError as exc:
        return False, str(exc)


def _preflight_connectivity(req: ADGraphReconRequest) -> Optional[tuple[str, str]]:
    if not _is_ip(req.target):
        return None

    checks: list[tuple[str, str, int]] = []
    if req.tool == "bloodhound-python":
        dns_host = req.nameserver or req.target
        if _is_ip(dns_host):
            checks.append(("DNS", dns_host, 53))
    checks.append(("LDAP", req.target, 389))
    checks.append(("LDAPS", req.target, 636))

    results: list[str] = []
    hard_fail = True
    for label, host, port in checks:
        ok, detail = _probe_tcp(host, port)
        if ok:
            hard_fail = False
            results.append(f"{label} {host}:{port} open")
        else:
            results.append(f"{label} {host}:{port} unreachable: {detail}")

    if hard_fail:
        summary = "; ".join(results)
        return (
            "AD service preflight failed: no reachable DNS/LDAP listener on target",
            summary,
        )
    return None


def _has_flag(args: list[str], flag: str) -> bool:
    return any(a == flag or a.startswith(f"{flag}=") for a in args)


def _looks_like_dns_failure(text: str) -> bool:
    hay = (text or "").lower()
    return any(marker in hay for marker in (
        "dns.resolver.nonameservers",
        "all nameservers failed",
        "_ldap._tcp",
        "dns_resolve",
    ))


def _build_bloodhound_cmd(
    req: ADGraphReconRequest,
    out_dir: str,
    use_dns_tcp: bool = False,
    dns_timeout: int = 3,
) -> list[str]:
    cmd = [
        "bloodhound-python",
        "-u", req.username,
        "-p", req.password,
        "-d", req.domain,
        "-c", req.collection,
        "-op", out_dir,
    ]

    target_is_ip = _is_ip(req.target)
    if target_is_ip:
        cmd += ["-ns", req.nameserver or req.target]
    else:
        cmd += ["-dc", req.target]
        if req.nameserver:
            cmd += ["-ns", req.nameserver]

    user_has_dns_tcp = _has_flag(req.args, "--dns-tcp")
    user_has_dns_timeout = _has_flag(req.args, "--dns-timeout")
    if use_dns_tcp and not user_has_dns_tcp:
        cmd.append("--dns-tcp")
    if dns_timeout > 0 and not user_has_dns_timeout:
        cmd += ["--dns-timeout", str(dns_timeout)]

    cmd += req.args
    return cmd


def _build_ldapdomaindump_cmd(
    req: ADGraphReconRequest,
    out_dir: str,
    include_user_args: bool = True,
) -> list[str]:
    bind_user = f"{req.domain}\\{req.username}" if req.domain else req.username
    cmd = [
        "ldapdomaindump",
        "-u", bind_user,
        "-p", req.password,
        "-o", out_dir,
    ]
    if req.nameserver:
        cmd += ["-n", req.nameserver]
    if include_user_args:
        cmd += req.args
    cmd.append(req.target)
    return cmd


def _collect_artifacts(directory: str) -> list[ADGraphArtifact]:
    artifacts: list[ADGraphArtifact] = []
    for root, _, files in os.walk(directory):
        for name in files:
            path = Path(root) / name
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(10_000_000)  # cap at 10 MB per file
            except OSError:
                content = None
            artifacts.append(ADGraphArtifact(
                name=str(path.relative_to(directory)),
                size=path.stat().st_size,
                content=content,
            ))
    return artifacts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ad_graph_recon(
    target: str,
    tool: str = "bloodhound-python",
    domain: str = "",
    username: str = "",
    password: str = "",
    nameserver: Optional[str] = None,
    collection: str = "All",
    args: Optional[list[str]] = None,
    timeout: int = 900,
) -> dict[str, Any]:
    start = time.monotonic()
    args = args or []

    try:
        req = ADGraphReconRequest(
            target=target,
            tool=tool,
            domain=domain,
            username=username,
            password=password,
            nameserver=nameserver,
            collection=collection,
            args=args,
            timeout=timeout,
        )
    except Exception as exc:
        return ADGraphReconResult(
            success=False,
            target=target,
            tool=tool,
            command="",
            error=str(exc),
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    preflight = _preflight_connectivity(req)
    if preflight:
        error_text, raw_text = preflight
        return ADGraphReconResult(
            success=False,
            target=req.target,
            tool=req.tool,
            command="[preflight]",
            raw_output=raw_text,
            error=error_text,
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    with tempfile.TemporaryDirectory(prefix="ad_graph_") as temp_dir:
        executed_cmds: list[list[str]] = []
        combined_output: list[str] = []
        last_stderr = ""
        rc = -1
        artifacts: list[ADGraphArtifact] = []

        if req.tool == "bloodhound-python":
            cmd = _build_bloodhound_cmd(req, temp_dir, use_dns_tcp=False, dns_timeout=3)
            executed_cmds.append(cmd)
            stdout, stderr, rc = _safe_execute(cmd, req.timeout)
            last_stderr = stderr or last_stderr
            combined_output.append((stdout or stderr or "").strip())
            artifacts = _collect_artifacts(temp_dir)

            # Retry once with DNS-over-TCP when DNS resolution fails.
            if rc != 0 and not artifacts and _looks_like_dns_failure(stderr):
                retry_cmd = _build_bloodhound_cmd(
                    req, temp_dir, use_dns_tcp=True, dns_timeout=10
                )
                executed_cmds.append(retry_cmd)
                stdout, stderr, rc = _safe_execute(retry_cmd, req.timeout)
                last_stderr = stderr or last_stderr
                combined_output.append((stdout or stderr or "").strip())
                artifacts = _collect_artifacts(temp_dir)

            # If BloodHound DNS bootstrap keeps failing, fallback to ldapdomaindump.
            bh_output = "\n".join(combined_output)
            if rc != 0 and not artifacts and _looks_like_dns_failure(bh_output):
                ldap_cmd = _build_ldapdomaindump_cmd(
                    req, temp_dir, include_user_args=False
                )
                executed_cmds.append(ldap_cmd)
                stdout, stderr, rc = _safe_execute(ldap_cmd, req.timeout)
                last_stderr = stderr or last_stderr
                combined_output.append((stdout or stderr or "").strip())
                artifacts = _collect_artifacts(temp_dir)
        else:
            cmd = _build_ldapdomaindump_cmd(req, temp_dir, include_user_args=True)
            executed_cmds.append(cmd)
            stdout, stderr, rc = _safe_execute(cmd, req.timeout)
            last_stderr = stderr or last_stderr
            combined_output.append((stdout or stderr or "").strip())
            artifacts = _collect_artifacts(temp_dir)

    command_str = " || ".join(" ".join(c) for c in executed_cmds)
    raw_output = "\n\n---\n\n".join(x for x in combined_output if x)
    error_text = last_stderr if (rc != 0 and not artifacts) else None

    return ADGraphReconResult(
        success=bool(artifacts) or rc == 0,
        target=req.target,
        tool=req.tool,
        command=command_str,
        artifacts=artifacts,
        artifact_count=len(artifacts),
        raw_output=raw_output[:8000] or None,
        error=error_text[:2000] if error_text else None,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


AD_GRAPH_RECON_TOOL_DEFINITION = {
    "name": "ad_graph_recon",
    "description": "Deeper AD graph collection wrapper using bloodhound-python or ldapdomaindump.",
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# ── Configure your scan here ─────────────────────────────────────────────────
TARGET      = "10.129.30.42"       # DC hostname or IP
DOMAIN      = "corp.local"            # Active Directory domain
USERNAME    = "recon_user"            # AD username
PASSWORD    = "P@ssw0rd"              # AD password
TOOL        = "bloodhound-python"     # "bloodhound-python" or "ldapdomaindump"
NAMESERVER  = None                    # e.g. "192.168.1.1" or None to auto-detect
COLLECTION  = "All"                   # BloodHound collection method
EXTRA_ARGS  = []                      # additional CLI flags, e.g. ["--zip"]
TIMEOUT     = 900                     # max run time in seconds (30–7200)
EMIT_JSON   = False                   # True → raw JSON output, False → summary
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    import json

    result = ad_graph_recon(
        target=TARGET,
        tool=TOOL,
        domain=DOMAIN,
        username=USERNAME,
        password=PASSWORD,
        nameserver=NAMESERVER,
        collection=COLLECTION,
        args=EXTRA_ARGS,
        timeout=TIMEOUT,
    )

    if EMIT_JSON:
        print(json.dumps(result, indent=2))
        return

    status = "OK" if result["success"] else "FAILED"
    print(f"\n[{status}] {result['target']}  tool={result['tool']}  ({result['execution_time']}s)\n")

    if result.get("error"):
        print(f"  Error: {result['error']}\n")
        if result.get("raw_output"):
            preview = result["raw_output"][:1200].replace("\n", "\n  ")
            print(f"  Output preview:\n  {preview}\n")
        return

    print(f"  Artifacts collected : {result['artifact_count']}")
    for artifact in result["artifacts"]:
        size_kb = round(artifact["size"] / 1024, 1)
        print(f"    {artifact['name']}  ({size_kb} KB)")

    if result.get("raw_output"):
        preview = result["raw_output"][:400].replace("\n", "\n  ")
        print(f"\n  Output preview:\n  {preview}")

    print()


if __name__ == "__main__":
    main()
