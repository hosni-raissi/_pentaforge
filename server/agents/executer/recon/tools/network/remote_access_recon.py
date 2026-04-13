#/+
"""
remote_access_recon_tool.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Dedicated RDP / VNC reconnaissance wrapper using nmap NSE scripts or rdpscan.

Scans a target for exposed remote-access services, fingerprints versions,
and surfaces known vulnerability indicators (e.g. MS12-020, BlueKeep).
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

from server.agents.executer.recon.config import BLOCKED_NETWORKS as _BLOCKED_NETWORKS

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("remote_access_recon")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_TOOLS: frozenset[str] = frozenset({"nmap", "rdpscan"})
_ALLOWED_MODES: frozenset[str] = frozenset({"rdp", "vnc"})

_DANGEROUS: frozenset[str] = frozenset({
    ";", "&&", "||", "|", "`", "$(", ">>", "<<",
    ">", "<", "'", '"', "\n", "\r", "\x00",
})

# NSE scripts per mode
_NMAP_SCRIPTS: dict[str, str] = {
    "rdp": "rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020",
    "vnc": "vnc-info,vnc-title,vnc-brute",
}

# Ports per mode
_MODE_PORTS: dict[str, str] = {
    "rdp": "3389",
    "vnc": "5900,5901,5902",
}

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
    try:
        ip = ipaddress.ip_address(v)
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                raise ValueError(f"Target '{v}' is in a blocked range ({net})")
        return v
    except ValueError as exc:
        # Re-raise only the blocked-range errors
        if "blocked range" in str(exc):
            raise
    # Hostname path
    if len(v) > 253:
        raise ValueError(f"Hostname too long: {v!r}")
    if not _HOSTNAME_RE.match(v.rstrip(".")):
        raise ValueError(f"Invalid hostname or IP: {v!r}")
    return v


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class RemoteAccessReconRequest(BaseModel):
    """Validated, sanitised scan request."""

    target: str
    mode: str = "rdp"
    tool: str = "nmap"
    args: list[str] = []
    timeout: int = Field(default=300, ge=10, le=1800)

    @field_validator("target")
    @classmethod
    def check_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("mode")
    @classmethod
    def check_mode(cls, v: str) -> str:
        norm = v.strip().lower()
        if norm not in _ALLOWED_MODES:
            raise ValueError(f"mode must be one of: {sorted(_ALLOWED_MODES)}")
        return norm

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


class RemoteEndpoint(BaseModel):
    """A discovered remote-access endpoint."""

    port: int
    service: Optional[str] = None
    version: Optional[str] = None
    scripts: dict[str, str] = {}
    issues: list[str] = []


class RemoteAccessReconResult(BaseModel):
    """Full result returned to callers."""

    success: bool       # tool executed without fatal error
    detected: bool      # at least one open endpoint was found
    target: str
    mode: str
    tool: str
    command: str
    endpoints: list[RemoteEndpoint] = []
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

def _parse_nmap(stdout: str) -> list[RemoteEndpoint]:
    """
    Parse nmap XML output (produced by ``-oX -``) into endpoint objects.

    Only ports in state ``open`` or ``open|filtered`` are returned.
    """
    endpoints: list[RemoteEndpoint] = []

    # Isolate the XML block — nmap may print a text warning line before it
    xml_start = stdout.find("<nmaprun")
    if xml_start == -1:
        log.debug("No <nmaprun> block found in nmap output")
        return endpoints

    try:
        root = ET.fromstring(stdout[xml_start:])
    except ET.ParseError as exc:
        log.warning("nmap XML parse error: %s", exc)
        return endpoints

    for port_elem in root.findall(".//port"):
        state_elem = port_elem.find("state")
        if state_elem is None or state_elem.get("state") not in {"open", "open|filtered"}:
            continue

        service_elem = port_elem.find("service")
        version_parts = []
        if service_elem is not None:
            for attr in ("product", "version", "extrainfo"):
                val = service_elem.get(attr, "").strip()
                if val:
                    version_parts.append(val)

        endpoint = RemoteEndpoint(
            port=int(port_elem.get("portid", 0)),
            service=service_elem.get("name") if service_elem is not None else None,
            version=" ".join(version_parts) or None,
        )

        for script in port_elem.findall("script"):
            sid = script.get("id", "unknown")
            output = script.get("output", "").strip()
            endpoint.scripts[sid] = output[:500]
            # Surface vulnerability indicators as issues
            if any(kw in output.lower() for kw in ("vulnerable", "vuln", "exploit")):
                endpoint.issues.append(f"{sid}: {output[:200]}")

        endpoints.append(endpoint)

    return endpoints


def _parse_rdpscan(stdout: str) -> list[RemoteEndpoint]:
    """
    Parse rdpscan plain-text output.

    rdpscan prints one line per host:
        <ip>  SAFE   - (no vulnerability)
        <ip>  VULNERABLE - ...
        <ip>  UNKNOWN - ...
    """
    endpoint = RemoteEndpoint(port=3389, service="ms-wbt-server")

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()

        if "vulnerable" in low:
            endpoint.issues.append(stripped)
        elif "unknown" in low:
            # Filter out connection failures (port closed/timeout)
            if "refused" in low or "no connection" in low or "timeout" in low:
                continue
            # Unknown usually means the host is alive but status unclear
            endpoint.scripts["rdpscan-status"] = stripped
        elif "safe" in low:
            # Host responded but is not vulnerable — still a valid detection
            endpoint.scripts["rdpscan-status"] = stripped

    # Only return an endpoint if rdpscan actually produced meaningful output
    if endpoint.issues or endpoint.scripts:
        return [endpoint]
    return []


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------

def _build_nmap_cmd(req: RemoteAccessReconRequest) -> list[str]:
    return [
        "nmap", "-Pn", "-sV",
        "-p", _MODE_PORTS[req.mode],
        "--script", _NMAP_SCRIPTS[req.mode],
        "-oX", "-",          # XML to stdout
    ] + req.args + [req.target]


def _build_rdpscan_cmd(req: RemoteAccessReconRequest) -> list[str]:
    return ["rdpscan"] + req.args + [req.target]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def remote_access_recon(
    target: str,
    mode: str = "rdp",
    tool: str = "nmap",
    args: Optional[list[str]] = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """
    Scan *target* for remote-access services.

    Parameters
    ----------
    target:
        IPv4/IPv6 address or hostname to scan.
    mode:
        ``"rdp"`` (port 3389) or ``"vnc"`` (ports 5900-5902).
    tool:
        ``"nmap"`` (NSE scripts) or ``"rdpscan"`` (BlueKeep check, RDP only).
    args:
        Extra tool flags — every element must start with ``--``.
    timeout:
        Seconds before aborting (10–1800).

    Returns
    -------
    dict
        Serialised :class:`RemoteAccessReconResult`.
    """
    start = time.time()
    args = args or []

    # --- Validate input -------------------------------------------------------
    try:
        req = RemoteAccessReconRequest(
            target=target, mode=mode, tool=tool, args=args, timeout=timeout
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Validation error: %s", exc)
        return RemoteAccessReconResult(
            success=False, detected=False,
            target=target, mode=mode, tool=tool,
            command="", error=str(exc),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # --- Cross-validate tool / mode -------------------------------------------
    if req.tool == "rdpscan" and req.mode != "rdp":
        err = f"rdpscan only supports mode='rdp', got mode='{req.mode}'"
        log.error(err)
        return RemoteAccessReconResult(
            success=False, detected=False,
            target=req.target, mode=req.mode, tool=req.tool,
            command="", error=err,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # --- Build and execute command --------------------------------------------
    cmd = _build_rdpscan_cmd(req) if req.tool == "rdpscan" else _build_nmap_cmd(req)
    log.info("Scanning %s [mode=%s tool=%s] …", req.target, req.mode, req.tool)
    stdout, stderr, rc = _safe_execute(cmd, req.timeout)

    # --- Parse ----------------------------------------------------------------
    endpoints = (
        _parse_rdpscan(stdout) if req.tool == "rdpscan" else _parse_nmap(stdout)
    )
    detected = len(endpoints) > 0

    log.info(
        "Scan done | target=%s endpoints=%d rc=%d time=%.2fs",
        req.target, len(endpoints), rc, time.time() - start,
    )

    return RemoteAccessReconResult(
        success=rc == 0 or detected,
        detected=detected,
        target=req.target,
        mode=req.mode,
        tool=req.tool,
        command=" ".join(cmd),
        endpoints=endpoints,
        raw_output=(stdout or stderr)[:8000] or None,
        error=stderr[:500] if rc != 0 and not detected else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ---------------------------------------------------------------------------
# Tool definition (Anthropic / OpenAI tool-use schema)
# ---------------------------------------------------------------------------

REMOTE_ACCESS_RECON_TOOL_DEFINITION: dict[str, Any] = {
    "name": "remote_access_recon",
    "description": (
        "Dedicated RDP / VNC reconnaissance wrapper using nmap NSE scripts or rdpscan. "
        "Fingerprints remote-access services, detects version info, and surfaces "
        "known vulnerability indicators such as MS12-020 and BlueKeep."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IPv4/IPv6 address or hostname to scan (public addresses only).",
            },
            "mode": {
                "type": "string",
                "enum": ["rdp", "vnc"],
                "description": "Protocol to target: 'rdp' (port 3389) or 'vnc' (ports 5900-5902).",
                "default": "rdp",
            },
            "tool": {
                "type": "string",
                "enum": ["nmap", "rdpscan"],
                "description": (
                    "Scanning tool: 'nmap' (NSE scripts, supports rdp+vnc) or "
                    "'rdpscan' (BlueKeep check, rdp only)."
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
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services" version="" extrainfo="Windows Server 2016"/>
        <script id="rdp-enum-encryption" output="Security layer: RDP, CredSSP"/>
        <script id="rdp-ntlm-info" output="Target_Name: CORP-DC01 NetBIOS_Domain: CORP"/>
        <script id="rdp-vuln-ms12-020" output="VULNERABLE: Remote Desktop Protocol Denial of Service"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

_DEMO_RDPSCAN_OUTPUT = """\
203.0.113.5  VULNERABLE - CVE-2019-0708 (BlueKeep)
"""


# ---------------------------------------------------------------------------
# Main — hardcoded test cases
# ---------------------------------------------------------------------------

def main() -> None:
    # 4. Live scans against the configured target using all tools/modes
    print("\n" + "=" * 60)
    print("  [4] Live scans (All modes/tools)")
    print("=" * 60)
    TARGET = "10.129.29.141"
    TIMEOUT = 60

    test_combinations = [
        ("rdp", "nmap", []),
        ("rdp", "rdpscan", []),
        ("vnc", "nmap", []),
    ]

    for mode, tool, args in test_combinations:
        print(f"\n--- Testing: {TARGET} | mode={mode} | tool={tool} ---")
        result = remote_access_recon(target=TARGET, mode=mode, tool=tool, args=args, timeout=TIMEOUT)
        print(json.dumps(result, indent=2, default=str))
        if result.get("detected"):
            print(f"  ✅  Detected {len(result['endpoints'])} endpoint(s)")
        elif result.get("success"):
            print("  ℹ️  Scan completed — no open endpoints found.")
        else:
            print(f"  ❌  Scan failed: {result.get('error', 'unknown error')}")
        print("-" * 60)


if __name__ == "__main__":
    main()