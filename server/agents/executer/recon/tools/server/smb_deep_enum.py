#/+
from __future__ import annotations

__all__ = ["smb_deep_enum", "SMB_DEEP_ENUM_TOOL_DEFINITION"]

import ipaddress
import json
import re
import subprocess
import sys
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.config import is_blocked_host

# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════

_ALLOWED_TOOLS = frozenset({"smbmap", "enum4linux-ng"})
_DANGEROUS     = frozenset({";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"})
_DOMAIN_RE     = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_RAW_LIMIT = 8_000
_ERR_LIMIT = 500

# smbmap tabular output:
# [spaces] <share> [spaces] <perms> [spaces] <comment>
# e.g.:  "	print$          	READ ONLY	Printer Drivers"
_SMBMAP_LINE_RE = re.compile(
    r"^\s*(\S[\w\s.$-]*?)\s{2,}(READ\s*ONLY|READ[\s,/]*WRITE|NO\s*ACCESS|WRITE|READ)\s*(.*)?$",
    re.IGNORECASE,
)

# enum4linux-ng share lines look like:
#   //TARGET/ShareName  Mapping: OK  Listing: OK
#   Sharename       Type      Comment
#   ---------       ----      -------
#   ADMIN$          Disk      Remote Admin
_E4L_SHARE_RE = re.compile(
    r"^\s*(\S+)\s+(Disk|Printer|IPC|Print)\s*(.*)?$",
    re.IGNORECASE,
)


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class SMBDeepEnumRequest(BaseModel):
    target:   str
    tool:     str           = "smbmap"
    username: Optional[str] = None
    password: Optional[str] = None
    domain:   Optional[str] = None
    args:     list[str]     = []
    timeout:  int           = Field(default=300, ge=10, le=1800)

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

        if not _DOMAIN_RE.match(v.lower()):
            raise ValueError(f"'{v}' is neither a valid IP nor a valid domain")
        return v

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in _ALLOWED_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(_ALLOWED_TOOLS)}")
        return v

    @field_validator("username", "password", "domain", mode="before")
    @classmethod
    def validate_credential_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = str(v)
        for ch in _DANGEROUS:
            if ch in v:
                raise ValueError(f"Dangerous character {ch!r} in credential field")
        return v

    @field_validator("args", mode="before")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        for arg in v:
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
        return v


class SMBShare(BaseModel):
    name:        str
    share_type:  Optional[str] = None   # Disk | Printer | IPC
    permissions: Optional[str] = None
    comment:     Optional[str] = None
    readable:    bool          = False
    writable:    bool          = False


class SMBDeepEnumResult(BaseModel):
    success:        bool
    target:         str
    tool:           str
    commands:       list[str]       = []
    shares:         list[SMBShare]  = []
    total_shares:   int             = 0
    users:          list[str]       = []
    raw_output:     Optional[str]   = None
    error:          Optional[str]   = None
    execution_time: float           = 0.0


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

def _parse_smbmap(stdout: str) -> list[SMBShare]:
    """
    Parse smbmap output.  Two formats co-exist across versions:

    Version A (tabular, default):
        [+] IP:445 Name:hostname
            Disk            Permissions     Comment
            ----            -----------     -------
            print$          READ ONLY       Printer Drivers
            IPC$            NO ACCESS

    Version B (--no-banner / older):
        hostname\tprint$\tREAD ONLY\tPrinter Drivers
    """
    shares: list[SMBShare] = []
    seen: set[str] = set()

    for line in stdout.splitlines():
        line_stripped = line.strip()

        # Skip headers and separator lines
        if not line_stripped or set(line_stripped) <= {"-", " "}:
            continue
        if line_stripped.lower().startswith(("disk", "permissions", "comment", "----")):
            continue
        if line_stripped.startswith("["):
            continue

        m = _SMBMAP_LINE_RE.match(line)
        if not m:
            continue

        name  = m.group(1).strip()
        perms = m.group(2).strip().upper()
        comment = (m.group(3) or "").strip() or None

        if name in seen:
            continue
        seen.add(name)

        readable = "READ" in perms
        writable = "WRITE" in perms

        shares.append(SMBShare(
            name=name,
            permissions=perms,
            comment=comment,
            readable=readable,
            writable=writable,
        ))

    return shares


def _parse_enum4linux(stdout: str) -> tuple[list[SMBShare], list[str]]:
    """
    Parse enum4linux-ng output.
    Extracts shares from the share-listing table and users from user enumeration.
    """
    shares: list[SMBShare] = []
    users:  list[str]      = []
    seen:   set[str]       = set()
    in_share_section = False

    for line in stdout.splitlines():
        stripped = line.strip()

        # ── Section detection ───────────────────────────────
        if re.search(r"shares|smb shares|share enumeration", stripped, re.IGNORECASE):
            in_share_section = True
        if re.search(r"users|user enumeration|local users", stripped, re.IGNORECASE):
            in_share_section = False

        # ── Share lines ─────────────────────────────────────
        if in_share_section:
            m = _E4L_SHARE_RE.match(stripped)
            if m:
                name       = m.group(1).strip()
                share_type = m.group(2).strip().capitalize()
                comment    = (m.group(3) or "").strip() or None
                if name not in seen and name not in ("---", "Sharename"):
                    seen.add(name)
                    shares.append(SMBShare(
                        name=name,
                        share_type=share_type,
                        comment=comment,
                    ))

        # ── User lines ──────────────────────────────────────
        user_match = re.search(r"username:\s*(\S+)", stripped, re.IGNORECASE)
        if user_match:
            user = user_match.group(1).strip()
            if user not in users:
                users.append(user)

    return shares, users


# ══════════════════════════════════════════════════════════════
# 5. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_smbmap_cmd(req: SMBDeepEnumRequest) -> list[str]:
    cmd = ["smbmap", "-H", req.target]
    if req.username:
        cmd += ["-u", req.username, "-p", req.password or ""]
    else:
        # Explicit null session
        cmd += ["-u", "", "-p", ""]
    if req.domain:
        cmd += ["-d", req.domain]
    cmd += req.args
    return cmd


def _build_enum4linux_cmd(req: SMBDeepEnumRequest) -> list[str]:
    cmd = ["enum4linux-ng", "-A"]
    if req.username:
        cmd += ["-u", req.username, "-p", req.password or ""]
    if req.domain:
        cmd += ["-w", req.domain]
    cmd += req.args + [req.target]
    return cmd


# ══════════════════════════════════════════════════════════════
# 6. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def smb_deep_enum(
    target:   str,
    tool:     str                  = "smbmap",
    username: Optional[str]        = None,
    password: Optional[str]        = None,
    domain:   Optional[str]        = None,
    args:     Optional[list[str]]  = None,
    timeout:  int                  = 300,
) -> dict[str, Any]:
    """
    SMB share and permission enumeration.
    Returns structured dict — never writes to disk.

    Args:
        target   : Target IP or hostname (port 445)
        tool     : 'smbmap' (fast, permissions) | 'enum4linux-ng' (deep: users/groups/policies)
        username : SMB username (None = null session)
        password : SMB password
        domain   : Windows domain or workgroup
        args     : Extra CLI flags
        timeout  : Max wall-clock seconds

    Returns:
        SMBDeepEnumResult as dict with keys:
        success, target, tool, commands, shares, total_shares,
        users, raw_output, error, execution_time
    """
    start = time.monotonic()
    args  = args or []

    try:
        req = SMBDeepEnumRequest(
            target=target, tool=tool,
            username=username, password=password, domain=domain,
            args=args, timeout=timeout,
        )
    except Exception as exc:
        return SMBDeepEnumResult(
            success=False, target=target, tool=tool, commands=[],
            error=str(exc),
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    if req.tool == "smbmap":
        cmd    = _build_smbmap_cmd(req)
        stdout, stderr, rc = _safe_execute(cmd, req.timeout)
        shares = _parse_smbmap(stdout)
        users: list[str] = []
    else:
        cmd    = _build_enum4linux_cmd(req)
        stdout, stderr, rc = _safe_execute(cmd, req.timeout)
        shares, users = _parse_enum4linux(stdout)

    raw = (stdout or stderr)[:_RAW_LIMIT] or None

    return SMBDeepEnumResult(
        success=bool(shares),
        target=req.target,
        tool=req.tool,
        commands=[" ".join(cmd)],
        shares=shares,
        total_shares=len(shares),
        users=users,
        raw_output=raw,
        error=stderr.strip()[:_ERR_LIMIT] if rc != 0 and not shares else None,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 7. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

SMB_DEEP_ENUM_TOOL_DEFINITION: dict[str, Any] = {
    "name": "smb_deep_enum",
    "description": (
        "SMB share and permission enumeration via smbmap or enum4linux-ng. "
        "Discovers accessible network shares, READ/WRITE permissions, comments, "
        "and (via enum4linux-ng) users, groups, and OS details. "
        "Supports null sessions (no credentials) and authenticated scans."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP or hostname with SMB/port-445 open",
            },
            "tool": {
                "type": "string",
                "enum": ["smbmap", "enum4linux-ng"],
                "default": "smbmap",
                "description": (
                    "smbmap       = fast share listing with READ/WRITE/NO ACCESS per share | "
                    "enum4linux-ng = deep enumeration: shares + users + groups + policies"
                ),
            },
            "username": {"type": "string", "description": "SMB username (omit for null session)"},
            "password": {"type": "string", "description": "SMB password"},
            "domain":   {"type": "string", "description": "Windows domain or workgroup"},
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra flags e.g. ['--no-banner'] for smbmap",
            },
            "timeout": {
                "type": "integer",
                "default": 300,
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
    print(f"\n{_sep()}\n  {label}\n{_sep()}")
    print(f"  success        : {result['success']}")
    print(f"  target         : {result['target']}")
    print(f"  tool           : {result['tool']}")
    print(f"  total_shares   : {result['total_shares']}")
    print(f"  execution_time : {result['execution_time']}s")
    if result.get("commands"):
        for c in result["commands"]:
            print(f"  $ {c}")
    if result.get("error"):
        print(f"  error          : {result['error']}")
    if result["shares"]:
        print("  shares:")
        for s in result["shares"]:
            rw   = []
            if s.get("readable"): rw.append("READ")
            if s.get("writable"): rw.append("WRITE")
            perm = s.get("permissions") or ("|".join(rw) if rw else "—")
            cmt  = f"  # {s['comment']}" if s.get("comment") else ""
            print(f"    [{perm:20s}] {s['name']}{cmt}")
    else:
        print("  no shares found")
        if result.get("raw_output"):
            print(f"  raw_output: {result['raw_output'][:300]}")
    if result.get("users"):
        print(f"  users: {result['users']}")
    print(_sep())


# ══════════════════════════════════════════════════════════════
# 9. MAIN — tests against 10.129.29.141
# ══════════════════════════════════════════════════════════════

TARGET = "10.129.22.137"


def _run_validation_tests() -> bool:
    cases: list[tuple[str, dict]] = [
        ("PASS — empty target",              dict(target="")),
        ("PASS — loopback 127.0.0.1",        dict(target="127.0.0.1")),
        ("PASS — loopback ::1",              dict(target="::1")),
        ("PASS — link-local 169.254.1.1",    dict(target="169.254.1.1")),
        ("PASS — unspecified 0.0.0.0",       dict(target="0.0.0.0")),
        ("PASS — invalid domain",            dict(target="not a host!!")),
        ("PASS — invalid tool",              dict(target=TARGET, tool="nmap")),
        ("PASS — injection in arg",          dict(target=TARGET, args=["ok", "bad;arg"])),
        ("PASS — injection in username",     dict(target=TARGET, username="admin;whoami")),
        ("PASS — injection in password",     dict(target=TARGET, username="admin", password="pass|id")),
        ("PASS — injection in domain",       dict(target=TARGET, domain="DOM&&AIN")),
        ("PASS — timeout out of range",      dict(target=TARGET, timeout=5)),
    ]

    print(f"\n{_sep('═')}")
    print("  VALIDATION TESTS  (all should fail with error)")
    print(_sep("═"))

    all_ok = True
    for label, kwargs in cases:
        result = smb_deep_enum(**kwargs)
        ok     = not result["success"] and bool(result["error"])
        if not ok:
            all_ok = False
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}  {label}")
        if not ok:
            print(f"         → unexpected: {result}")

    print(f"\n  Validation suite: {'all passed ✅' if all_ok else 'FAILURES ❌'}")
    return all_ok


def _run_live_tests() -> None:
    print(f"\n{_sep('═')}")
    print(f"  LIVE TESTS — target: {TARGET}")
    print(_sep("═"))

    # ── Test 1: smbmap null session ────────────────────────────
    _print_result(
        "smbmap — null session (no credentials)",
        smb_deep_enum(target=TARGET, tool="smbmap", timeout=30),
    )

    # ── Test 2: smbmap with guest account ─────────────────────
    _print_result(
        "smbmap — guest session",
        smb_deep_enum(
            target=TARGET, tool="smbmap",
            username="guest", password="",
            timeout=30,
        ),
    )

    # ── Test 3: enum4linux-ng full enumeration ─────────────────
    _print_result(
        "enum4linux-ng — full enumeration (-A)",
        smb_deep_enum(target=TARGET, tool="enum4linux-ng", timeout=120),
    )

    # ── Full JSON dump ─────────────────────────────────────────
    print(f"\n{_sep('═')}")
    print(f"  FULL JSON — smbmap null session {TARGET}")
    print(_sep("═"))
    result  = smb_deep_enum(target=TARGET, tool="smbmap", timeout=30)
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