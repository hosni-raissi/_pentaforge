#/+
"""
ARP Scanner — Agent Tool
=========================
Layer-2 ARP-based host discovery for local network segments.
Wraps arp-scan and arping for fast, stealthy host enumeration
that bypasses firewall rules (operates at L2).

Features:
  - arp-scan: Full subnet sweep with OUI vendor lookup
  - arping:   Single-target ARP probe with latency measurement
  - Detects duplicate IPs, MAC vendor identification
  - Parses structured results for agent consumption
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.config import is_blocked_host

# ══════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════

logger = logging.getLogger("arp_scan")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s — %(message)s", datefmt="%H:%M:%S",
    ))
    logger.addHandler(handler)


# ══════════════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════════════

_SHELL_DANGEROUS = frozenset({";", "&&", "||", "|", "`", "$(", ">>", "'", '"'})
_VALID_TOOLS = frozenset({"arp-scan", "arping"})

_INTERFACE_RE = [re.compile(p) for p in (
    r"^any$", r"^lo\d*$", r"^eth\d+$", r"^en\d+$",
    r"^enp\d+s\d+(\w*)$", r"^ens\d+$", r"^eno\d+$",
    r"^wlan\d+$", r"^wlp\d+s\d+(\w*)$", r"^wlx[a-f0-9]+$",
    r"^docker\d+$", r"^br-[a-f0-9]+$", r"^veth[a-f0-9]+$",
    r"^bond\d+(\.\d+)?$", r"^tun\d+$", r"^tap\d+$",
)]


# ══════════════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════════════

class ArpScanRequest(BaseModel):
    tool: str = "arp-scan"
    target: str
    interface: Optional[str] = None
    count: int = Field(default=3, ge=1, le=10)
    extra_args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=120, ge=10, le=600)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in _VALID_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(_VALID_TOOLS)}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        clean = v.strip().lower()
        if is_blocked_host(clean):
            raise ValueError(f"Target '{v}' is blocked by recon config")
        return v.strip()

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not any(p.fullmatch(v) for p in _INTERFACE_RE):
            raise ValueError(f"Interface '{v}' not recognised")
        return v

    @field_validator("extra_args")
    @classmethod
    def validate_extra_args(cls, v: list[str]) -> list[str]:
        for arg in v:
            for ch in _SHELL_DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
        return v


class ArpHost(BaseModel):
    ip: str
    mac: str
    vendor: Optional[str] = None
    latency_ms: Optional[float] = None
    duplicate: bool = False


class ArpScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    interface: Optional[str] = None
    total_hosts: int = 0
    hosts: list[ArpHost] = Field(default_factory=list)
    duplicates: list[dict[str, str]] = Field(default_factory=list)
    scan_stats: Optional[dict[str, Any]] = None
    execution_time: float = 0.0
    error: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════════════

def _build_arp_scan(req: ArpScanRequest) -> list[str]:
    cmd = ["arp-scan"]
    if req.interface:
        cmd.extend(["--interface", req.interface])
    cmd.extend(["--retry", str(req.count)])
    cmd.extend(req.extra_args)
    # Target can be a CIDR or --localnet
    if req.target.lower() in ("localnet", "local", "auto"):
        cmd.append("--localnet")
    else:
        cmd.append(req.target)
    return cmd


def _build_arping(req: ArpScanRequest) -> list[str]:
    cmd = ["arping"]
    if req.interface:
        cmd.extend(["-I", req.interface])
    cmd.extend(["-c", str(req.count)])
    cmd.extend(req.extra_args)
    cmd.append(req.target)
    return cmd


_BUILDERS = {
    "arp-scan": _build_arp_scan,
    "arping":   _build_arping,
}


def _prefix_sudo(cmd: list[str]) -> list[str]:
    try:
        if os.name != "nt" and os.geteuid() != 0:
            return ["sudo", *cmd]
    except AttributeError:
        pass
    return cmd


# ══════════════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════════════

# arp-scan output:
#   192.168.1.1     00:aa:bb:cc:dd:ee     Vendor Name
#   192.168.1.1     00:aa:bb:cc:dd:ff     Other Vendor (DUP: 2)
_ARP_SCAN_LINE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+"
    r"([0-9a-fA-F:]{17})\s+"
    r"(.+?)(?:\s+\(DUP:\s*(\d+)\))?$"
)

# arp-scan footer: "N packets received by filter, 0 packets dropped by kernel"
_ARP_SCAN_STATS = re.compile(
    r"(\d+) responded.*?(\d+) packets received",
    re.IGNORECASE,
)


def _parse_arp_scan(stdout: str) -> tuple[list[ArpHost], list[dict[str, str]], dict[str, Any] | None]:
    hosts: list[ArpHost] = []
    duplicates: list[dict[str, str]] = []
    stats: dict[str, Any] | None = None

    for line in stdout.splitlines():
        m = _ARP_SCAN_LINE.match(line.strip())
        if not m:
            continue
        ip, mac, vendor, dup_num = m.group(1), m.group(2), m.group(3).strip(), m.group(4)
        is_dup = dup_num is not None
        host = ArpHost(ip=ip, mac=mac, vendor=vendor or None, duplicate=is_dup)
        hosts.append(host)
        if is_dup:
            duplicates.append({"ip": ip, "mac": mac, "vendor": vendor, "dup_index": dup_num})

    sm = _ARP_SCAN_STATS.search(stdout)
    if sm:
        stats = {"responded": int(sm.group(1)), "packets_received": int(sm.group(2))}

    return hosts, duplicates, stats


# arping output:
#   ARPING 192.168.1.1 from 192.168.1.10 eth0
#   Unicast reply from 192.168.1.1 [00:AA:BB:CC:DD:EE]  1.234ms
_ARPING_REPLY = re.compile(
    r"(?:Unicast|Broadcast) reply from (\d+\.\d+\.\d+\.\d+)"
    r"\s+\[([0-9a-fA-F:]{17})\]\s+([\d.]+)ms",
    re.IGNORECASE,
)


def _parse_arping(stdout: str) -> list[ArpHost]:
    hosts: list[ArpHost] = []
    seen: set[str] = set()

    for m in _ARPING_REPLY.finditer(stdout):
        ip, mac, latency = m.group(1), m.group(2), float(m.group(3))
        key = f"{ip}_{mac}"
        if key in seen:
            continue
        seen.add(key)
        hosts.append(ArpHost(ip=ip, mac=mac, latency_ms=latency))

    return hosts


# ══════════════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════════════

def arp_scan(
    target: str,
    tool: str = "arp-scan",
    interface: Optional[str] = None,
    count: int = 3,
    extra_args: Optional[list[str]] = None,
    timeout: int = 120,
) -> dict:
    """
    Agent Tool — ARP Scanner

    Layer-2 ARP-based host discovery for local network segments. Operates below
    the IP layer, bypassing firewalls. Discovers live hosts with MAC addresses
    and vendor identification.

    Args:
        target:     CIDR range, single IP, or "localnet" for auto-detect.
                    Examples: "192.168.1.0/24", "10.0.0.1", "localnet"
        tool:       "arp-scan" (full subnet sweep) | "arping" (single target probe)
        interface:  Network interface (eth0, en0, wlan0, …). Auto-detect if omitted.
        count:      Number of ARP probes per host (1-10). Default: 3
        extra_args: Extra CLI flags forwarded to the tool.
        timeout:    Max execution time in seconds. Default: 120

    Returns:
        ArpScanResult dict with discovered hosts, MACs, vendors, duplicates.
    """
    if extra_args is None:
        extra_args = []

    start = time.perf_counter()

    try:
        req = ArpScanRequest(
            tool=tool, target=target, interface=interface,
            count=count, extra_args=extra_args, timeout=timeout,
        )
    except Exception as exc:
        return ArpScanResult(
            success=False, tool=tool, target=target,
            command="", error=str(exc),
        ).model_dump()

    cmd = _prefix_sudo(_BUILDERS[req.tool](req))
    command_str = " ".join(cmd)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=req.timeout, shell=False,
        )
        stdout, stderr, rc = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, rc = "", f"Timed out after {req.timeout}s", -1
    except PermissionError:
        stdout, stderr, rc = "", "Permission denied — ARP scanning requires root/sudo", -1
    except FileNotFoundError:
        stdout, stderr, rc = "", f"'{req.tool}' not installed or not in PATH", -1
    except Exception as exc:
        stdout, stderr, rc = "", str(exc), -1

    elapsed = round(time.perf_counter() - start, 3)

    # Parse
    hosts: list[ArpHost] = []
    duplicates: list[dict[str, str]] = []
    scan_stats: dict[str, Any] | None = None

    if req.tool == "arp-scan":
        hosts, duplicates, scan_stats = _parse_arp_scan(stdout)
    else:
        hosts = _parse_arping(stdout)

    success = bool(hosts) or rc == 0
    error = None
    if rc != 0 and not hosts:
        error = stderr.strip()[:500] if stderr else f"Tool exited with code {rc}"

    return ArpScanResult(
        success=success,
        tool=req.tool,
        target=req.target,
        command=command_str,
        interface=req.interface,
        total_hosts=len(hosts),
        hosts=hosts,
        duplicates=duplicates,
        scan_stats=scan_stats,
        execution_time=elapsed,
        error=error,
    ).model_dump()


# ══════════════════════════════════════════════════════════════════════
# 6. LLM TOOL DEFINITION
# ══════════════════════════════════════════════════════════════════════

ARP_SCAN_TOOL_DEFINITION: dict = {
    "name": "arp_scan",
    "description": (
        "Layer-2 ARP-based host discovery for local network segments. "
        "Operates below the IP layer, bypassing firewall rules. Discovers "
        "live hosts with MAC addresses, OUI vendor identification, and "
        "duplicate IP detection. This tool executes 'arp-scan' (for full subnet sweeps) "
        "or 'arping' (for single-target probes). Provide extra arguments if needed "
        "to pass directly to the underlying arp-scan tool."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": (
                    "Target CIDR range, single IP, or 'localnet' for auto-detect. "
                    "Examples: '192.168.1.0/24', '10.0.0.1', 'localnet'"
                ),
            },
            "tool": {
                "type": "string",
                "enum": sorted(_VALID_TOOLS),
                "description": (
                    "arp-scan — full subnet ARP sweep with OUI vendor lookup. "
                    "arping — single-target ARP probe with latency."
                ),
                "default": "arp-scan",
            },
            "interface": {
                "type": "string",
                "description": "Network interface (eth0, en0, wlan0, …). Auto-detect if omitted.",
            },
            "count": {
                "type": "integer",
                "description": "Number of ARP probes per host (1-10). Default: 3.",
                "default": 3,
            },
            "extra_args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra CLI flags. arp-scan: ['--bandwidth=100k'] | arping: ['-D'] (duplicate detect)",
            },
            "timeout": {
                "type": "integer",
                "description": "Max execution time in seconds. Default: 120.",
                "default": 120,
            },
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════════════
# 7. DEMO
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  ARP Scan — localnet sweep")
    print("=" * 60)
    result = arp_scan(target="localnet", tool="arp-scan")
    print(f"  success   : {result['success']}")
    print(f"  command   : {result['command']}")
    print(f"  hosts     : {result['total_hosts']}")
    for h in result.get("hosts", [])[:10]:
        print(f"    {h['ip']:16s} {h['mac']}  {h.get('vendor', '?')}")
    if result.get("duplicates"):
        print(f"  ⚠ Duplicates: {result['duplicates']}")
    if result.get("error"):
        print(f"  ❌ ERROR: {result['error']}")
