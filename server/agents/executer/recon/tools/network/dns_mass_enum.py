#/+
from __future__ import annotations

__all__ = ["dns_mass_enum", "DNS_MASS_ENUM_TOOL_DEFINITION"]

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════

_ALLOWED_TOOLS = frozenset({"massdns", "puredns"})
_DANGEROUS = frozenset({";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"})
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_RAW_LIMIT = 8_000
_ERR_LIMIT = 500

_DEFAULT_SUBS = [
    "www", "api", "dev", "staging", "admin", "vpn", "mail",
    "smtp", "pop", "imap", "ftp", "cdn", "static", "auth",
    "login", "portal", "dashboard", "beta", "test", "app",
]
_DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class DNSMassEnumRequest(BaseModel):
    target: str
    tool: str = "massdns"
    subdomains: list[str] = []
    resolvers: list[str] = []
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=3600)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("target must not be empty")
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"Invalid domain: {v!r}")
        return v

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in _ALLOWED_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(_ALLOWED_TOOLS)}")
        return v

    @field_validator("resolvers", mode="before")
    @classmethod
    def validate_resolvers(cls, v: list[str]) -> list[str]:
        for r in v:
            r = r.strip()
            if not _IP_RE.match(r):
                raise ValueError(f"Invalid resolver IP: {r!r}")
            parts = r.split(".")
            if any(int(p) > 255 for p in parts):
                raise ValueError(f"Invalid resolver IP: {r!r}")
        return [r.strip() for r in v]

    @field_validator("args", mode="before")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        blocked = {"-o", "--write", "--write-massdns", "--resolvers-trusted"}
        for arg in v:
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
            if arg.strip() in blocked:
                raise ValueError(f"Blocked arg: {arg!r}")
        return v


class DNSMassHit(BaseModel):
    name: str
    record_type: Optional[str] = None
    value: Optional[str] = None


class DNSMassEnumResult(BaseModel):
    success: bool
    target: str
    tool: str
    command: str
    hits: list[DNSMassHit] = []
    total_hits: int = 0
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. EXECUTOR
# ══════════════════════════════════════════════════════════════

def _safe_execute(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return stdout, stderr, proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return stdout or "", (stderr or "") + f"\n[timeout] killed after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", 127
    except Exception as exc:
        return "", str(exc), -1


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def _parse_massdns(stdout: str) -> list[DNSMassHit]:
    """
    massdns -o S default format:
      name. type value (3 parts)
    With -o Snt/St:
      name. TTL IN type value (5 parts)
    """
    hits: list[DNSMassHit] = []
    for line in stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 5 and parts[2] == "IN":
            name = parts[0].rstrip(".")
            record_type = parts[3]
            value = parts[4].rstrip(".")
        elif len(parts) >= 3:
            name = parts[0].rstrip(".")
            record_type = parts[-2]
            value = parts[-1].rstrip(".")
        else:
            continue
        hits.append(DNSMassHit(name=name, record_type=record_type, value=value))
    return hits


def _parse_puredns(stdout: str) -> list[DNSMassHit]:
    """puredns resolve outputs one resolved FQDN per line."""
    hits: list[DNSMassHit] = []
    for line in stdout.splitlines():
        name = line.strip().rstrip(".")
        if name:
            hits.append(DNSMassHit(name=name))
    return hits


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def dns_mass_enum(
    target: str,
    tool: str = "massdns",
    subdomains: Optional[list[str]] = None,
    resolvers: Optional[list[str]] = None,
    args: Optional[list[str]] = None,
    timeout: int = 600,
) -> dict[str, Any]:
    start = time.monotonic()
    subdomains = subdomains or _DEFAULT_SUBS
    resolvers = resolvers or _DEFAULT_RESOLVERS
    args = args or []

    try:
        req = DNSMassEnumRequest(
            target=target, tool=tool,
            subdomains=subdomains, resolvers=resolvers,
            args=args, timeout=timeout,
        )
    except Exception as exc:
        return DNSMassEnumResult(
            success=False, target=target, tool=tool, command="",
            error=str(exc),
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    fqdn_list = [f"{sub}.{req.target}" for sub in req.subdomains]

    # FIX: delete=False + explicit finally cleanup avoids race condition
    names_fd = resolvers_fd = None
    names_path = resolvers_path = ""
    try:
        names_fd, names_path = tempfile.mkstemp(suffix=".txt", prefix="dns_names_")
        resolvers_fd, resolvers_path = tempfile.mkstemp(suffix=".txt", prefix="dns_resolvers_")

        with os.fdopen(names_fd, "w") as f:
            f.write("\n".join(fqdn_list) + "\n")
        names_fd = None  # fd now owned by fdopen, already closed

        with os.fdopen(resolvers_fd, "w") as f:
            f.write("\n".join(req.resolvers) + "\n")
        resolvers_fd = None

        if req.tool == "massdns":
            cmd = ["massdns", "-r", resolvers_path, "-o", "S", names_path] + req.args
        else:
            cmd = ["puredns", "resolve", names_path, "--resolvers", resolvers_path] + req.args

        stdout, stderr, rc = _safe_execute(cmd, req.timeout)

    finally:
        # Close raw fds if fdopen was never reached (e.g. exception mid-way)
        for fd in (names_fd, resolvers_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        for path in (names_path, resolvers_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    hits = _parse_massdns(stdout) if req.tool == "massdns" else _parse_puredns(stdout)
    raw = (stdout or stderr)[:_RAW_LIMIT] or None

    return DNSMassEnumResult(
        success=bool(hits),
        target=req.target,
        tool=req.tool,
        command=" ".join(cmd),
        hits=hits,
        total_hits=len(hits),
        raw_output=raw,
        error=stderr.strip()[:_ERR_LIMIT] if rc != 0 and not hits else None,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

DNS_MASS_ENUM_TOOL_DEFINITION: dict[str, Any] = {
    "name": "dns_mass_enum",
    "description": (
        "High-volume DNS subdomain brute-force using massdns or puredns. "
        "Resolves a wordlist of subdomains against a target domain at speed. "
        "Use massdns for full record details (type + value), puredns for clean FQDN-only output. "
        "Pair with amass_enum for OSINT discovery first, then this for fast wordlist resolution."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target domain (e.g. 'example.com')"},
            "tool": {
                "type": "string", "enum": ["massdns", "puredns"], "default": "massdns",
                "description": "massdns = full record output | puredns = resolved FQDNs only",
            },
            "subdomains": {
                "type": "array", "items": {"type": "string"},
                "description": "Subdomain labels to probe. Defaults to a built-in common list.",
            },
            "resolvers": {
                "type": "array", "items": {"type": "string"},
                "description": "Resolver IPs to use. Defaults to 1.1.1.1, 8.8.8.8, 9.9.9.9.",
            },
            "args": {
                "type": "array", "items": {"type": "string"},
                "description": "Extra flags passed to the tool e.g. ['--types', 'A,AAAA']",
            },
            "timeout": {
                "type": "integer", "default": 600, "minimum": 30, "maximum": 3600,
                "description": "Max execution time in seconds.",
            },
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 7. MAIN — test runner
# ══════════════════════════════════════════════════════════════

def _print_result(label: str, result: dict) -> None:
    sep = "─" * 56
    print(f"\n{sep}")
    print(f"  {label}")
    print(sep)
    print(f"  success        : {result['success']}")
    print(f"  target         : {result['target']}")
    print(f"  tool           : {result['tool']}")
    print(f"  total_hits     : {result['total_hits']}")
    print(f"  execution_time : {result['execution_time']}s")
    print(f"  command        : {result['command']}")
    if result.get("error"):
        print(f"  error          : {result['error']}")
    if result["hits"]:
        print(f"  hits (first 5):")
        for hit in result["hits"][:5]:
            rtype = hit.get("record_type") or "—"
            val = hit.get("value") or "—"
            print(f"    • {hit['name']}  type={rtype}  value={val}")
    print(sep)


def main() -> None:

    # ── Validation tests ───────────────────────────────────────
    validation_cases: list[tuple[str, dict]] = [
        ("PASS — empty target",              dict(target="")),
        ("PASS — invalid domain",            dict(target="not a domain!!")),
        ("PASS — invalid tool",              dict(target="example.com", tool="nmap")),
        ("PASS — blocked arg -o",            dict(target="example.com", args=["-o"])),
        ("PASS — injection in arg",          dict(target="example.com", args=["ok", "bad;arg"])),
        ("PASS — invalid resolver IP",       dict(target="example.com", resolvers=["not-an-ip"])),
        ("PASS — resolver octet > 255",      dict(target="example.com", resolvers=["999.1.1.1"])),
        ("PASS — timeout out of range",      dict(target="example.com", timeout=10)),
    ]

    print("\n══════════════════════════════════════════════════════")
    print("  VALIDATION TESTS  (all should fail with error)")
    print("══════════════════════════════════════════════════════")
    all_passed = True
    for label, kwargs in validation_cases:
        result = dns_mass_enum(**kwargs)
        ok = not result["success"] and bool(result["error"])
        status = "✅ PASS" if ok else "❌ FAIL"
        if not ok:
            all_passed = False
        print(f"  {status}  {label}")
        if not ok:
            print(f"         → unexpected result: {result}")

    print(f"\n  Validation suite: {'all passed ✅' if all_passed else 'FAILURES detected ❌'}")

    # ── Live tests (require massdns / puredns in PATH) ─────────
    live_cases: list[tuple[str, dict]] = [
        ("massdns — example.com (default subs)", dict(
            target="example.com",
            tool="massdns",
            timeout=60,
        )),
        ("massdns — example.com (custom subs)", dict(
            target="example.com",
            tool="massdns",
            subdomains=["www", "mail", "api", "dev", "admin"],
            resolvers=["1.1.1.1", "8.8.8.8"],
            timeout=60,
        )),
        ("puredns — example.com", dict(
            target="example.com",
            tool="puredns",
            subdomains=["www", "mail", "api"],
            timeout=60,
        )),
    ]

    print("\n══════════════════════════════════════════════════════")
    print("  LIVE TESTS  (require massdns / puredns in PATH)")
    print("══════════════════════════════════════════════════════")
    for label, kwargs in live_cases:
        result = dns_mass_enum(**kwargs)
        _print_result(label, result)

    # ── Full JSON dump ─────────────────────────────────────────
    print("\n══════════════════════════════════════════════════════")
    print("  FULL JSON — massdns example.com")
    print("══════════════════════════════════════════════════════")
    result = dns_mass_enum(target="example.com", tool="massdns", timeout=60)
    display = {k: v for k, v in result.items() if k != "raw_output"}
    print(json.dumps(display, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Aborted.")
        sys.exit(0)