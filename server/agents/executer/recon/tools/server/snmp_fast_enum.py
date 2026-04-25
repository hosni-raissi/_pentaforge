#/+
from __future__ import annotations

__all__ = ["snmp_fast_enum", "SNMP_FAST_ENUM_TOOL_DEFINITION"]

import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.config import is_blocked_host

# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════

_ALLOWED_TOOLS = frozenset({"onesixtyone", "snmpcheck"})
_DANGEROUS     = frozenset({";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"})
_DOMAIN_RE     = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_RAW_LIMIT  = 8_000
_ERR_LIMIT  = 500

_DEFAULT_COMMUNITIES: list[str] = [
    "public", "private", "manager", "admin",
    "community", "snmp", "monitor", "cisco",
    "secret", "write", "read", "default",
]


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class SNMPFastEnumRequest(BaseModel):
    target:      str
    tool:        str        = "onesixtyone"
    communities: list[str]  = []
    args:        list[str]  = []
    timeout:     int        = Field(default=180, ge=10, le=1800)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")

        if len(v) > 253:
            raise ValueError(f"Hostname too long: {v!r}")

        # Check hostname blocklist FIRST
        if is_blocked_host(v.lower()):
            raise ValueError(f"Target '{v}' is blocked")
        return v

        # Check domain format
        if not _DOMAIN_RE.match(v.lower()):
            raise ValueError(f"'{v}' is neither a valid IP nor a valid domain")
        return v

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in _ALLOWED_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(_ALLOWED_TOOLS)}")
        return v

    @field_validator("communities", mode="before")
    @classmethod
    def validate_communities(cls, v: list[str]) -> list[str]:
        if not v:
            return v          # empty → caller fills from _DEFAULT_COMMUNITIES
        for c in v:
            if not c or not c.strip():
                raise ValueError("community string must not be empty")
            for ch in _DANGEROUS:
                if ch in c:
                    raise ValueError(f"dangerous character {ch!r} in community: {c!r}")
        return [c.strip() for c in v]

    @field_validator("args", mode="before")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        for arg in v:
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"dangerous character {ch!r} in arg: {arg!r}")
        return v


class SNMPCommunityHit(BaseModel):
    community: str
    system:    Optional[str] = None
    details:   Optional[str] = None


class SNMPFastEnumResult(BaseModel):
    success:        bool
    target:         str
    tool:           str
    commands:       list[str]            = []
    hits:           list[SNMPCommunityHit] = []
    total_hits:     int                  = 0
    raw_output:     Optional[str]        = None
    error:          Optional[str]        = None
    execution_time: float                = 0.0


# ══════════════════════════════════════════════════════════════
# 3. EXECUTOR
# ══════════════════════════════════════════════════════════════

def _safe_execute(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return stdout, stderr, proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return (
                stdout or "",
                (stderr or "") + f"\n[timeout] killed after {timeout}s",
                -1,
            )
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", 127
    except Exception as exc:
        return "", str(exc), -1


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def _parse_onesixtyone(stdout: str) -> list[SNMPCommunityHit]:
    """
    onesixtyone -o S line format:
      <ip> [<community>] <sysDescr value>
    """
    hits: list[SNMPCommunityHit] = []
    for line in stdout.splitlines():
        line = line.strip()
        if "[" not in line or "]" not in line:
            continue
        community = line.split("[", 1)[1].split("]", 1)[0].strip()
        detail    = line.split("]", 1)[1].strip()
        if community:
            hits.append(SNMPCommunityHit(community=community, details=detail or None))
    return hits


def _parse_snmpcheck_system(stdout: str) -> Optional[str]:
    """Return first line that looks like a sysDescr."""
    for line in stdout.splitlines():
        low = line.lower()
        if "system information" in low or "sysdescr" in low or "sys description" in low:
            return line.strip()
    return None


# ══════════════════════════════════════════════════════════════
# 5. TOOL RUNNERS
# ══════════════════════════════════════════════════════════════

def _run_onesixtyone(
    req: SNMPFastEnumRequest,
) -> tuple[list[SNMPCommunityHit], list[str], str, str, int]:
    """
    Pass communities tightly via stdin directly into memory.
    """
    cmd = ["onesixtyone", "-c", "/dev/stdin"] + req.args + [req.target]
    payload = "\n".join(req.communities) + "\n"

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        try:
            stdout, stderr = proc.communicate(input=payload, timeout=req.timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            rc = -1
            stderr = (stderr or "") + f"\n[timeout] killed after {req.timeout}s"
            
        return _parse_onesixtyone(stdout), [" ".join(cmd)], stdout, stderr, rc

    except FileNotFoundError:
        return [], [" ".join(cmd)], "", f"Tool '{cmd[0]}' not installed", 127
    except Exception as exc:
        return [], [" ".join(cmd)], "", str(exc), -1


def _run_snmpcheck(
    req: SNMPFastEnumRequest,
) -> tuple[list[SNMPCommunityHit], list[str], str, str, int]:
    """
    Try every community — collect ALL hits, not just the first.
    Track every command attempted so the caller can audit the full run.
    """
    all_hits:     list[SNMPCommunityHit] = []
    all_commands: list[str]              = []
    last_stdout = last_stderr = ""
    last_rc = 1

    for community in req.communities:
        cmd = ["snmpcheck", "-t", req.target, "-c", community] + req.args
        all_commands.append(" ".join(cmd))
        stdout, stderr, rc = _safe_execute(cmd, req.timeout)
        last_stdout, last_stderr, last_rc = stdout, stderr, rc
        if stdout.strip():
            all_hits.append(SNMPCommunityHit(
                community=community,
                system=_parse_snmpcheck_system(stdout),
                details=stdout[:500] or None,
            ))

    return all_hits, all_commands, last_stdout, last_stderr, last_rc


# ══════════════════════════════════════════════════════════════
# 6. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def snmp_fast_enum(
    target:      str,
    tool:        str                  = "onesixtyone",
    communities: Optional[list[str]] = None,
    args:        Optional[list[str]] = None,
    timeout:     int                  = 180,
) -> dict[str, Any]:
    """
    SNMP community-string brute-force and device enumeration.
    Returns structured dict — never writes to disk.

    Args:
        target      : IP address or hostname to scan
        tool        : 'onesixtyone' (fast bulk) | 'snmpcheck' (detailed per-community)
        communities : Community strings to try  (default: built-in common list)
        args        : Extra CLI flags for the underlying tool
        timeout     : Max wall-clock seconds

    Returns:
        SNMPFastEnumResult as dict with keys:
        success, target, tool, commands, hits, total_hits,
        raw_output, error, execution_time
    """
    start       = time.monotonic()
    communities = communities or _DEFAULT_COMMUNITIES
    args        = args        or []

    try:
        req = SNMPFastEnumRequest(
            target=target, tool=tool,
            communities=communities, args=args, timeout=timeout,
        )
    except Exception as exc:
        return SNMPFastEnumResult(
            success=False, target=target, tool=tool, commands=[],
            error=str(exc),
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    if req.tool == "onesixtyone":
        hits, commands, stdout, stderr, rc = _run_onesixtyone(req)
    else:
        hits, commands, stdout, stderr, rc = _run_snmpcheck(req)

    raw = (stdout or stderr)[:_RAW_LIMIT] or None

    return SNMPFastEnumResult(
        success=bool(hits),
        target=req.target,
        tool=req.tool,
        commands=commands,
        hits=hits,
        total_hits=len(hits),
        raw_output=raw,
        error=stderr.strip()[:_ERR_LIMIT] if rc != 0 and not hits else None,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 7. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

SNMP_FAST_ENUM_TOOL_DEFINITION: dict[str, Any] = {
    "name": "snmp_fast_enum",
    "description": (
        "SNMP community-string brute-force and device enumeration. "
        "Uses onesixtyone for fast bulk community testing or snmpcheck for "
        "detailed per-community system info extraction. "
        "Identifies misconfigured network devices exposing SNMP with default credentials. "
        "Returns all valid community strings found and associated system descriptions."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP address or hostname (e.g. '192.168.1.1')",
            },
            "tool": {
                "type": "string",
                "enum": ["onesixtyone", "snmpcheck"],
                "default": "onesixtyone",
                "description": (
                    "onesixtyone = fast bulk community brute-force | "
                    "snmpcheck   = detailed per-community system enumeration"
                ),
            },
            "communities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Community strings to test. Defaults to built-in common list.",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra flags e.g. ['-p', '161']",
            },
            "timeout": {
                "type": "integer",
                "default": 180,
                "minimum": 10,
                "maximum": 1800,
                "description": "Max execution time in seconds.",
            },
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 8. HELPERS
# ══════════════════════════════════════════════════════════════

def _sep(char: str = "─", width: int = 60) -> str:
    return char * width


def _print_result(label: str, result: dict) -> None:
    print(f"\n{_sep()}")
    print(f"  {label}")
    print(_sep())
    print(f"  success        : {result['success']}")
    print(f"  target         : {result['target']}")
    print(f"  tool           : {result['tool']}")
    print(f"  total_hits     : {result['total_hits']}")
    print(f"  execution_time : {result['execution_time']}s")
    if result.get("commands"):
        print(f"  commands ({len(result['commands'])}):")
        for c in result["commands"][:4]:
            print(f"    $ {c}")
        if len(result["commands"]) > 4:
            print(f"    ... and {len(result['commands']) - 4} more")
    if result.get("error"):
        print(f"  error          : {result['error']}")
    if result["hits"]:
        print(f"  ✅ VALID COMMUNITIES:")
        for h in result["hits"]:
            print(f"    community : {h['community']}")
            if h.get("system"):
                print(f"    system    : {h['system'][:100]}")
            if h.get("details"):
                print(f"    details   : {h['details'][:120]}")
    else:
        print("  no valid communities found")
        if result.get("raw_output"):
            print(f"  raw_output : {result['raw_output'][:200]}")
    print(_sep())


# ══════════════════════════════════════════════════════════════
# 9. MAIN — tests against 10.129.29.141
# ══════════════════════════════════════════════════════════════

TARGET = "10.129.22.137"


def _run_validation_tests() -> bool:
    cases: list[tuple[str, dict]] = [
        ("PASS — empty target",           dict(target="")),
        ("PASS — loopback 127.0.0.1",     dict(target="127.0.0.1")),
        ("PASS — loopback ::1",           dict(target="::1")),
        ("PASS — link-local 169.254.1.1", dict(target="169.254.1.1")),
        ("PASS — unspecified 0.0.0.0",    dict(target="0.0.0.0")),
        ("PASS — invalid domain",         dict(target="not a host!!")),
        ("PASS — invalid tool",           dict(target=TARGET, tool="nmap")),
        ("PASS — injection in arg",       dict(target=TARGET, args=["ok", "bad;arg"])),
        ("PASS — injection in community", dict(target=TARGET, communities=["pub;lic"])),
        ("PASS — empty community string", dict(target=TARGET, communities=[""])),
        ("PASS — timeout out of range",   dict(target=TARGET, timeout=5)),
    ]

    print(f"\n{_sep('═')}")
    print("  VALIDATION TESTS  (all should fail with error)")
    print(_sep("═"))

    all_ok = True
    for label, kwargs in cases:
        result = snmp_fast_enum(**kwargs)
        ok = not result["success"] and bool(result["error"])
        if not ok:
            all_ok = False
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {status}  {label}")
        if not ok:
            print(f"         → unexpected result: {result}")

    verdict = "all passed ✅" if all_ok else "FAILURES DETECTED ❌"
    print(f"\n  Validation suite: {verdict}")
    return all_ok


def _run_live_tests() -> None:
    print(f"\n{_sep('═')}")
    print(f"  LIVE TESTS — target: {TARGET}")
    print(_sep("═"))

    # ── Test 1: onesixtyone default community list ─────────────
    _print_result(
        f"onesixtyone — default communities ({len(_DEFAULT_COMMUNITIES)} strings)",
        snmp_fast_enum(
            target=TARGET,
            tool="onesixtyone",
            timeout=30,
        ),
    )

    # ── Test 2: onesixtyone extended community list ────────────
    extended = _DEFAULT_COMMUNITIES + [
        "internal", "external", "test", "backup",
        "netman", "network", "switch", "router",
        "access", "root", "pass", "password",
    ]
    _print_result(
        f"onesixtyone — extended communities ({len(extended)} strings)",
        snmp_fast_enum(
            target=TARGET,
            tool="onesixtyone",
            communities=extended,
            timeout=45,
        ),
    )

    # ── Test 3: snmpcheck — only if onesixtyone found a hit ────
    # Run onesixtyone first to discover valid community strings
    discovery = snmp_fast_enum(target=TARGET, tool="onesixtyone", timeout=30)
    if discovery["hits"]:
        valid_communities = [h["community"] for h in discovery["hits"]]
        print(f"\n  ℹ️  onesixtyone found valid communities: {valid_communities}")
        print(f"  Running snmpcheck for detailed enumeration...")
        _print_result(
            "snmpcheck — detailed enumeration with valid communities",
            snmp_fast_enum(
                target=TARGET,
                tool="snmpcheck",
                communities=valid_communities,
                timeout=60,
            ),
        )
    else:
        print(f"\n  ℹ️  No valid communities found by onesixtyone — skipping snmpcheck.")

    # ── Full JSON dump of final result ─────────────────────────
    print(f"\n{_sep('═')}")
    print(f"  FULL JSON — onesixtyone {TARGET}")
    print(_sep("═"))
    result = snmp_fast_enum(target=TARGET, tool="onesixtyone", timeout=30)
    display = {k: v for k, v in result.items() if k != "raw_output"}
    print(json.dumps(display, indent=2))


def main() -> None:
    _run_validation_tests()
    _run_live_tests()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Aborted.")
        sys.exit(0)