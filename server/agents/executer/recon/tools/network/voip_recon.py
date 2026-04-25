#/+
"""
voip_recon_tool.py
~~~~~~~~~~~~~~~~~~
Dedicated SIP / VoIP reconnaissance wrapper using nmap NSE scripts or sipvicious_svmap.

Scans a target for SIP endpoints on UDP/TCP 5060-5061, enumerates allowed
methods, extracts user-agent banners, and surfaces security issues such as
unauthenticated REGISTER or OPTIONS exposure.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.config import is_blocked_host

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("voip_recon")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_TOOLS: frozenset[str] = frozenset({"nmap", "sipvicious_svmap"})

_DANGEROUS: frozenset[str] = frozenset({
    ";", "&&", "||", "|", "`", "$(", ">>", "<<",
    ">", "<", "'", '"', "\n", "\r", "\x00",
})

# SIP ports scanned
_SIP_PORTS = "5060,5061"

# NSE scripts for SIP recon
_NMAP_SCRIPTS = "sip-methods,sip-enum-users,sip-call-spoof"

# SIP methods that indicate elevated risk if allowed
_RISKY_METHODS: frozenset[str] = frozenset({
    "REGISTER", "SUBSCRIBE", "NOTIFY", "REFER", "PUBLISH",
})

# RFC-1123 hostname pattern
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# sipvicious_svmap output line: "  192.168.1.10:5060   | Asterisk PBX 16.4.0"
# or plain: "192.168.1.10:5060  Asterisk PBX"
_sipvicious_svmap_LINE_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{4,5})\s*[|\s]\s*(.*)"
)


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

def _validate_target(value: str) -> str:
    """Validate and normalise a scan target (IP or hostname)."""
    v = value.strip()
    if not v:
        raise ValueError("Target must not be empty")
    if is_blocked_host(v.lower()):
        raise ValueError(f"Target '{v}' is blocked")

    try:
        ip = ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    if len(v) > 253:
        raise ValueError(f"Hostname too long: {v!r}")
    if not _HOSTNAME_RE.match(v.rstrip(".")):
        raise ValueError(f"Invalid hostname or IP: {v!r}")
    return v


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class VoIPReconRequest(BaseModel):
    """Validated, sanitised recon request."""

    target: str
    tool: str = "nmap"
    args: list[str] = []
    timeout: int = Field(default=300, ge=10, le=1800)

    @field_validator("target")
    @classmethod
    def check_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("tool")
    @classmethod
    def check_tool(cls, v: str) -> str:
        norm = v.strip().lower()
        if norm not in _ALLOWED_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(_ALLOWED_TOOLS)}")
        return norm

    @field_validator("args")
    @classmethod
    def check_args(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in v:
            arg = raw.strip()
            if not arg.startswith("--"):
                raise ValueError(
                    f"Argument {arg!r} is not a valid flag (must start with '--')"
                )
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
            cleaned.append(arg)
        return cleaned


class VoIPHost(BaseModel):
    """A discovered SIP endpoint."""

    host: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    methods: list[str] = []
    user_agent: Optional[str] = None
    issues: list[str] = []


class VoIPReconResult(BaseModel):
    """Full result returned to callers."""

    success: bool       # tool executed without fatal error
    detected: bool      # at least one SIP host was found
    target: str
    tool: str
    command: str
    hosts: list[VoIPHost] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ---------------------------------------------------------------------------
# Safe execution
# ---------------------------------------------------------------------------

def _safe_execute(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    """Run *cmd* without a shell. Returns (stdout, stderr, returncode)."""
    log.debug("Executing: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        log.warning("Command timed out after %ds", timeout)
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        log.error("Tool '%s' not installed or not in PATH", cmd[0])
        return "", f"Tool '{cmd[0]}' not installed or not in PATH", -1
    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected subprocess error")
        return "", str(exc), -1


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _extract_sip_issues(methods: list[str]) -> list[str]:
    """Flag risky SIP methods that should not be exposed unauthenticated."""
    found = [m for m in methods if m.upper() in _RISKY_METHODS]
    return [f"Risky method exposed: {m}" for m in found]


def _parse_nmap(stdout: str) -> list[VoIPHost]:
    """
    Parse nmap XML output (``-oX -``) into :class:`VoIPHost` objects.

    Anchors on ``<nmaprun`` to skip any text warnings nmap emits before
    the XML block. Extracts SIP methods and User-Agent from the
    ``sip-methods`` and ``sip-enum-users`` script outputs specifically.
    """
    hosts: list[VoIPHost] = []

    xml_start = stdout.find("<nmaprun")
    if xml_start == -1:
        log.debug("No <nmaprun> block found in nmap output")
        return hosts

    try:
        root = ET.fromstring(stdout[xml_start:])
    except ET.ParseError as exc:
        log.warning("nmap XML parse error: %s", exc)
        return hosts

    for host_elem in root.findall(".//host"):
        addr_elem = host_elem.find("address")
        ip = addr_elem.get("addr") if addr_elem is not None else None

        for port_elem in host_elem.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") not in {"open", "open|filtered"}:
                continue

            service_elem = port_elem.find("service")
            item = VoIPHost(
                host=ip,
                port=int(port_elem.get("portid", 0)),
                service=service_elem.get("name") if service_elem is not None else None,
            )

            for script in port_elem.findall("script"):
                sid = script.get("id", "")
                output = script.get("output", "")

                if sid == "sip-methods" and "Methods:" in output:
                    raw_methods = output.split("Methods:", 1)[1].strip()
                    item.methods = [m.strip() for m in raw_methods.split(",") if m.strip()]

                if "User-Agent:" in output:
                    ua_line = output.split("User-Agent:", 1)[1].splitlines()[0].strip()
                    if ua_line:
                        item.user_agent = ua_line[:200]

                # Surface vulnerability indicators
                if any(kw in output.lower() for kw in ("vulnerable", "vuln", "exploit")):
                    item.issues.append(f"{sid}: {output[:200]}")

            # Flag risky exposed methods
            item.issues.extend(_extract_sip_issues(item.methods))
            hosts.append(item)

    return hosts


def _parse_sipvicious_svmap(stdout: str) -> list[VoIPHost]:
    """
    Parse sipvicious_svmap (SIPVicious) output into :class:`VoIPHost` objects.

    sipvicious_svmap produces a table like::

        | SIP Device           | User Agent              |
        |----------------------|-------------------------|
        | 192.168.1.10:5060    | Asterisk PBX 16.4.0     |

    or a simpler plain-text format::

        192.168.1.10:5060  Asterisk PBX 16.4.0

    Both formats are handled via ``_sipvicious_svmap_LINE_RE`` which requires a full
    IPv4:port pattern — avoiding the fragile ``:506`` substring match.
    """
    hosts: list[VoIPHost] = []
    seen: set[tuple[str, int]] = set()

    for line in stdout.splitlines():
        match = _sipvicious_svmap_LINE_RE.search(line)
        if not match:
            continue
        ip, port_str, ua_raw = match.group(1), match.group(2), match.group(3).strip()
        port = int(port_str)

        # Only collect standard SIP ports to avoid false positives
        if port not in {5060, 5061}:
            continue

        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)

        ua = ua_raw.rstrip("|").strip()[:200] or None
        hosts.append(VoIPHost(
            host=ip,
            port=port,
            service="sip",
            user_agent=ua,
        ))

    return hosts


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------

def _build_cmd(req: VoIPReconRequest) -> list[str]:
    if req.tool == "sipvicious_svmap":
        # sipvicious_svmap <target> [args] — args go before target for sipvicious_svmap conventions
        return ["sipvicious_svmap"] + req.args + [req.target]
    # nmap: scan both UDP and TCP SIP ports
    # Note: -sU requires root/CAP_NET_RAW privileges
    return [
        "sudo", "nmap", "-Pn", "-sU", "-sV",
        "-p", _SIP_PORTS,
        "--script", _NMAP_SCRIPTS,
        "-oX", "-",
    ] + req.args + [req.target]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def voip_recon(
    target: str,
    tool: str = "nmap",
    args: Optional[list[str]] = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """
    Perform SIP / VoIP reconnaissance against *target*.

    Parameters
    ----------
    target:
        IPv4/IPv6 address or hostname to scan.
    tool:
        ``"nmap"`` (NSE scripts, UDP+TCP) or ``"sipvicious_svmap"`` (SIPVicious suite).
    args:
        Extra tool flags — every element must start with ``--``.
    timeout:
        Seconds before aborting (10–1800).

    Returns
    -------
    dict
        Serialised :class:`VoIPReconResult`.

    .. note::
        nmap's ``-sU`` (UDP scan) requires root or ``CAP_NET_RAW``.
        Run with ``sudo`` or grant capabilities if UDP scans fail.
    """
    start = time.time()
    args = args or []

    # --- Validate input -------------------------------------------------------
    try:
        req = VoIPReconRequest(target=target, tool=tool, args=args, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        log.error("Validation error: %s", exc)
        return VoIPReconResult(
            success=False, detected=False,
            target=target, tool=tool,
            command="", error=str(exc),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # --- Execute --------------------------------------------------------------
    cmd = _build_cmd(req)
    log.info("Scanning %s [tool=%s] …", req.target, req.tool)
    stdout, stderr, rc = _safe_execute(cmd, req.timeout)

    # Privilege hint for nmap UDP scans
    error_msg: Optional[str] = None
    if rc != 0:
        hint = ""
        if req.tool == "nmap" and (
            "requires root" in stderr.lower() or "operation not permitted" in stderr.lower()
        ):
            hint = " (Hint: -sU requires root — run with sudo)"
        error_msg = stderr[:500] + hint

    # --- Parse ----------------------------------------------------------------
    hosts = _parse_sipvicious_svmap(stdout) if req.tool == "sipvicious_svmap" else _parse_nmap(stdout)
    detected = len(hosts) > 0

    log.info(
        "Scan done | target=%s hosts=%d rc=%d time=%.2fs",
        req.target, len(hosts), rc, time.time() - start,
    )

    is_svmap_empty = req.tool == "sipvicious_svmap" and "found nothing" in str(stderr or "").lower()
    
    return VoIPReconResult(
        success=rc == 0 or detected or is_svmap_empty,
        detected=detected,
        target=req.target,
        tool=req.tool,
        command=" ".join(cmd),
        hosts=hosts,
        raw_output=(stdout or stderr)[:8000] or None,
        error=error_msg if rc != 0 and not detected and not is_svmap_empty else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ---------------------------------------------------------------------------
# Tool definition (Anthropic / OpenAI tool-use schema)
# ---------------------------------------------------------------------------

VOIP_RECON_TOOL_DEFINITION: dict[str, Any] = {
    "name": "voip_recon",
    "description": (
        "Dedicated SIP / VoIP reconnaissance wrapper using nmap NSE scripts or sipvicious_svmap. "
        "Discovers SIP endpoints on UDP/TCP 5060-5061, enumerates allowed methods, "
        "extracts user-agent banners, and flags risky exposed methods such as "
        "REGISTER, SUBSCRIBE, and REFER."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IPv4/IPv6 address or hostname to scan (public addresses only).",
            },
            "tool": {
                "type": "string",
                "enum": ["nmap", "sipvicious_svmap"],
                "description": (
                    "'nmap' uses SIP NSE scripts over UDP+TCP (requires root). "
                    "'sipvicious_svmap' uses the SIPVicious suite for SIP enumeration."
                ),
                "default": "nmap",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra tool flags (each must start with '--').",
                "default": [],
            },
            "timeout": {
                "type": "integer",
                "description": "Scan timeout in seconds (10–1800).",
                "default": 300,
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

_DEMO_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.50"/>
    <ports>
      <port protocol="udp" portid="5060">
        <state state="open"/>
        <service name="sip"/>
        <script id="sip-methods" output="Methods: INVITE,ACK,CANCEL,OPTIONS,BYE,REFER,SUBSCRIBE,NOTIFY,REGISTER"/>
        <script id="sip-enum-users" output="User-Agent: Asterisk PBX 18.6.0"/>
      </port>
      <port protocol="tcp" portid="5061">
        <state state="open"/>
        <service name="sip-tls"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

_DEMO_sipvicious_svmap_OUTPUT = """\
| SIP Device           | User Agent                    |
|----------------------|-------------------------------|
| 10.0.0.50:5060       | Asterisk PBX 18.6.0           |
| 10.0.0.51:5060       | FreeSWITCH 1.10               |
| 10.0.0.52:5061       | Cisco Unified CM 12.5         |
"""


# ---------------------------------------------------------------------------
# Main — hardcoded test cases
# ---------------------------------------------------------------------------

def main() -> None:
    # ── Edit these to match your test environment ────────────────────────────
    TARGET  = "10.129.29.141"     # replace with a real target IP
    TOOL    = "nmap"             # "nmap" or "sipvicious_svmap"
    ARGS    = []                 # extra flags, e.g. ["--version-intensity=5"]
    TIMEOUT = 60                 # seconds
    # ─────────────────────────────────────────────────────────────────────────

    # 1. Offline nmap XML parser smoke-test
    print("=" * 60)
    print("  [1] nmap XML parser smoke-test (synthetic output)")
    print("=" * 60)
    nmap_hosts = _parse_nmap(_DEMO_NMAP_XML)
    print(json.dumps([h.model_dump() for h in nmap_hosts], indent=2))

    # 2. Offline sipvicious_svmap parser smoke-test
    print("\n" + "=" * 60)
    print("  [2] sipvicious_svmap parser smoke-test (synthetic output)")
    print("=" * 60)
    sipvicious_svmap_hosts = _parse_sipvicious_svmap(_DEMO_sipvicious_svmap_OUTPUT)
    print(json.dumps([h.model_dump() for h in sipvicious_svmap_hosts], indent=2))

    # 3. Validation tests — every call below should fail with a clear error
    print("\n" + "=" * 60)
    print("  [3] Validation tests (all expected to fail)")
    print("=" * 60)
    bad_cases = [
        ("127.0.0.1",    "nmap",   [],                  60,  "blocked loopback"),
        ("169.254.1.1",  "nmap",   [],                  60,  "blocked link-local"),
        ("10.0.0.1",     "masscan", [],                 60,  "invalid tool"),
        ("NMAP",         "nmap",   [],                  60,  "invalid hostname"),
        ("10.0.0.1",     "nmap",   ["sU"],              60,  "arg missing -- prefix"),
        ("10.0.0.1",     "nmap",   ["--script=sip;id"], 60,  "shell injection in arg"),
        ("10.0.0.1",     "nmap",   [],                   5,  "timeout below minimum"),
    ]
    for tgt, tool, args, timeout, label in bad_cases:
        r = voip_recon(tgt, tool, args, timeout)
        status = "✅ rejected" if not r["success"] else "❌ PASSED (unexpected)"
        print(f"  {status}  [{label}]  error: {str(r.get('error',''))[:55]!r}")

    # 4. Live scans against the configured target using all tools
    print("\n" + "=" * 60)
    print("  [4] Live scans (All tools)")
    print("=" * 60)
    TARGET = "10.129.29.141"
    TIMEOUT = 60

    test_combinations = [
        ("nmap", []),
        ("sipvicious_svmap", []),
    ]

    for tool, args in test_combinations:
        print(f"\n--- Testing: {TARGET} | tool={tool} ---")
        result = voip_recon(target=TARGET, tool=tool, args=args, timeout=TIMEOUT)
        print(json.dumps(result, indent=2, default=str))
        if result.get("detected"):
            print(f"  ✅  Detected {len(result['hosts'])} SIP host(s)")
            for h in result["hosts"]:
                print(f"      {h['host']}:{h['port']}  service={h['service']}  ua={h['user_agent']}")
                if h["methods"]:
                    print(f"      Methods : {', '.join(h['methods'])}")
                if h["issues"]:
                    for issue in h["issues"]:
                        print(f"      ⚠️  {issue}")
        elif result.get("success"):
            print("  ℹ️  Scan completed — no SIP hosts found.")
        else:
            print(f"  ❌  Scan failed: {result.get('error', 'unknown error')}")
        print("-" * 60)


if __name__ == "__main__":
    main()