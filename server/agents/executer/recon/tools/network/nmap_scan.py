#/+
"""
Nmap Network Scanner — Agent Tool (v6.0)
=========================================
Production-grade Nmap wrapper. Real-time scans only — no caching.

Changes in v6.0:
  - Removed all caching logic (_ScanCache, _CACHE, use_cache param)
  - Every call runs a fresh nmap scan
  - ASKPASS helper guaranteed cleanup via try/finally
  - All other v5.1 features retained
"""

from __future__ import annotations

__all__ = [
    "nmap_scan",
    "NmapScanRequest",
    "NmapScanResult",
    "HostInfo",
    "PortInfo",
    "OSMatch",
    "ScriptOutput",
    "SudoError",
    "NMAP_SCAN_TOOL_DEFINITION",
]

import base64
import csv as csv_module
import fcntl
import ipaddress
import json
import logging
import mmap
import os
import re
import subprocess
import sys
import tempfile
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Optional

# ══════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════

logger = logging.getLogger("nmap_scan")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s — %(message)s", datefmt="%H:%M:%S",
    ))
    logger.addHandler(_h)


# ══════════════════════════════════════════════════════════════════════
# 1. CONFIGURATION
# ══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class _Config:
    # Rate limiting
    DEFAULT_CPM:            float     = float(os.getenv("NMAP_CPM",        "30"))
    RATE_LOCK_FILE:         str       = os.getenv("NMAP_RATE_LOCK",         "/tmp/.nmap_scan_rate.lock")

    # Sudo
    SUDO_PWD_ENV:           str       = "NMAP_SUDO_PASSWORD"

    # Safety
    MAX_CIDR_HOSTS:         int       = int(os.getenv("NMAP_MAX_HOSTS",     "1024"))
    MAX_XML_BYTES:          int       = int(os.getenv("NMAP_MAX_XML_MB",    "50")) * 1_048_576

    # Timeouts
    DEFAULT_SCRIPT_TIMEOUT: str       = os.getenv("NMAP_SCRIPT_TIMEOUT",   "30s")
    HOST_TIMEOUT_HEADROOM:  int       = int(os.getenv("NMAP_HOST_HEADROOM", "10"))

    # Scan
    VALID_MODES:            frozenset = frozenset({
        "discovery", "syn", "tcp", "udp", "version", "aggressive", "script",
    })
    ROOT_MODES:             frozenset = frozenset({"syn", "udp", "aggressive"})

    # Output
    VALID_FORMATS:          frozenset = frozenset({"text", "json", "csv", "jsonl"})
    DEFAULT_FORMAT:         str       = "text"

    @property
    def BLOCKED_TARGETS(self) -> frozenset[str]:
        try:
            from server.agents.executer.recon.config import BLOCKED_HOSTNAMES, BLOCKED_NETWORKS
            targets: set[str] = set(BLOCKED_HOSTNAMES)
            for net in BLOCKED_NETWORKS:
                targets.add(str(net))
            return frozenset(t.lower() for t in targets)
        except ImportError:
            return frozenset()


CFG = _Config()

_SENSITIVE_RE: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in (
        r"passw(?:or)?d\s*[:=]\s*\S+",
        r"secret\s*[:=]\s*\S+",
        r"api[_\-]?key\s*[:=]\s*\S+",
        r"(?:bearer\s+|token\s*[:=]\s*)\S+",
    )
]


# ══════════════════════════════════════════════════════════════════════
# 2. PERSISTENT RATE LIMITER
# ══════════════════════════════════════════════════════════════════════

class _RateLimiter:
    _STRUCT = struct.Struct("d")

    def __init__(self, lock_path: str, cpm: float) -> None:
        self._path     = lock_path
        self._interval = 60.0 / max(cpm, 0.1)
        self._tlock    = threading.Lock()

    def reconfigure(self, cpm: float) -> None:
        with self._tlock:
            self._interval = 60.0 / max(cpm, 0.1)

    def acquire(self) -> None:
        with self._tlock:
            p = Path(self._path)
            if not p.exists():
                p.write_bytes(b"\x00" * 8)
            with open(p, "r+b") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    with mmap.mmap(fh.fileno(), 8) as mm:
                        last = self._STRUCT.unpack(mm.read(8))[0]
                        gap  = self._interval - (time.time() - last)
                        if gap > 0:
                            time.sleep(gap)
                        mm.seek(0)
                        mm.write(self._STRUCT.pack(time.time()))
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)


_RATE = _RateLimiter(CFG.RATE_LOCK_FILE, CFG.DEFAULT_CPM)


# ══════════════════════════════════════════════════════════════════════
# 3. SUDO HANDLING — ASKPASS via base64 relay
# ══════════════════════════════════════════════════════════════════════

class SudoError(RuntimeError):
    """Raised when a root-required scan cannot obtain sudo credentials."""


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _sudo_cached() -> bool:
    try:
        r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _create_askpass_helper(password: str) -> tuple[str, dict[str, str]]:
    """
    Password is base64-encoded so any special characters are safe.
    Helper self-destructs after sudo reads it, and is also cleaned up
    in a try/finally in nmap_scan().
    """
    b64 = base64.b64encode(password.encode()).decode()
    script = (
        "#!/bin/sh\n"
        f'printf "%s" "$(printf "%s" "{b64}" | base64 -d)"\n'
        'rm -f "$0"\n'
    )
    fd, path = tempfile.mkstemp(prefix=".nmap_askpass_", suffix=".sh", text=True)
    try:
        os.write(fd, script.encode())
        os.close(fd)
        os.chmod(path, 0o700)
        return path, {"SUDO_ASKPASS": path}
    except Exception:
        try:
            os.close(fd)
            os.unlink(path)
        except OSError:
            pass
        raise


def _resolve_sudo_askpass(
    cmd: list[str],
    scan_mode: str,
    sudo_password: Optional[str],
) -> tuple[list[str], dict[str, str], Optional[str]]:
    """Returns (final_cmd, env_vars, helper_path). Caller cleans up helper_path."""
    if _is_root():
        logger.debug("Running as root — no sudo needed")
        return cmd, {}, None

    if _sudo_cached():
        logger.debug("sudo credentials cached — using plain sudo")
        return ["sudo", *cmd], {}, None

    pwd = sudo_password or os.environ.get(CFG.SUDO_PWD_ENV)
    if not pwd:
        raise SudoError(
            f"scan_mode='{scan_mode}' requires root but no sudo credentials available.\n\n"
            f"Options:\n"
            f"  A) Pass sudo_password='...' to nmap_scan()\n"
            f"  B) export {CFG.SUDO_PWD_ENV}='...'\n"
            f"  C) Passwordless nmap: "
            f'echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/nmap_agent\n'
            f"  D) Run the process as root"
        )

    helper_path, env_vars = _create_askpass_helper(pwd)
    logger.debug("Using sudo ASKPASS helper: %s", helper_path)
    return ["sudo", "-A", *cmd], env_vars, helper_path


# ══════════════════════════════════════════════════════════════════════
# 4. VALIDATION
# ══════════════════════════════════════════════════════════════════════

def _validate_target(v: str) -> str:
    clean = v.strip()

    for blocked in CFG.BLOCKED_TARGETS:
        if blocked in clean.lower():
            raise ValueError(f"Target '{v}' is blocked")

    if ":" in clean and " " not in clean:
        try:
            if "/" in clean:
                net = ipaddress.ip_network(clean, strict=False)
                if net.num_addresses > CFG.MAX_CIDR_HOSTS:
                    raise ValueError(
                        f"IPv6 CIDR too large: {net.num_addresses} hosts (max {CFG.MAX_CIDR_HOSTS})"
                    )
                if net.is_loopback or net.is_unspecified or net.is_multicast:
                    raise ValueError(f"IPv6 network type not allowed: {net}")
            else:
                addr = ipaddress.ip_address(clean)
                if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                    raise ValueError(f"IPv6 address type not allowed: {addr}")
            return clean
        except ValueError as exc:
            if any(k in str(exc) for k in ("too large", "not allowed")):
                raise

    if "/" in clean:
        try:
            net = ipaddress.ip_network(clean, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {exc}") from exc
        if net.num_addresses > CFG.MAX_CIDR_HOSTS:
            raise ValueError(
                f"CIDR too large: {net.num_addresses} hosts (max {CFG.MAX_CIDR_HOSTS})"
            )
        if net.is_loopback or net.is_unspecified or net.is_multicast:
            raise ValueError(f"Network type not allowed: {net}")

    return clean


def _validate_scripts(v: Optional[str]) -> Optional[str]:
    if v is None:
        return v
    if v.startswith("/") or v.startswith("./") or v.startswith("../"):
        raise ValueError("Absolute/relative script paths blocked — use built-in script names")
    return v


def _validate_script_timeout(v: str) -> str:
    if not re.fullmatch(r"\d+(?:ms|s|m|h)?", v.strip()):
        raise ValueError(
            f"Invalid script_timeout {v!r}. Use nmap time specs: 30s, 2m, 500ms, etc."
        )
    return v.strip()


# ══════════════════════════════════════════════════════════════════════
# 5. REQUEST
# ══════════════════════════════════════════════════════════════════════

@dataclass
class NmapScanRequest:
    target:           str
    scan_mode:        str           = "tcp"
    ports:            Optional[str] = None
    top_ports:        Optional[int] = None
    scripts:          Optional[str] = None
    timing:           int           = 3
    extra_args:       list[str]     = field(default_factory=list)
    timeout:          int           = 600
    script_timeout:   str           = CFG.DEFAULT_SCRIPT_TIMEOUT
    output_format:    str           = CFG.DEFAULT_FORMAT
    output_file:      Optional[str] = None
    calls_per_minute: float         = CFG.DEFAULT_CPM
    add_reason:       bool          = True
    sudo_password:    Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.target         = _validate_target(self.target)
        self.scripts        = _validate_scripts(self.scripts)
        self.script_timeout = _validate_script_timeout(self.script_timeout)
        self.extra_args     = _validate_extra_args(list(self.extra_args))

        if self.scan_mode not in CFG.VALID_MODES:
            raise ValueError(f"scan_mode must be one of: {sorted(CFG.VALID_MODES)}")
        if not (0 <= self.timing <= 5):
            raise ValueError("timing must be 0–5")
        if not (30 <= self.timeout <= 7200):
            raise ValueError("timeout must be 30–7200 seconds")
        if self.top_ports is not None and not (1 <= self.top_ports <= 65535):
            raise ValueError("top_ports must be 1–65535")
        if self.output_format not in CFG.VALID_FORMATS:
            raise ValueError(f"output_format must be one of: {sorted(CFG.VALID_FORMATS)}")
        if self.output_file:
            raise ValueError(
                "output_file is disabled. This tool returns scan results directly and does not save result files."
            )


# ══════════════════════════════════════════════════════════════════════
# 6. RESULT DATACLASSES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ScriptOutput:
    id:     str
    output: str
    data:   dict[str, str] = field(default_factory=dict)


@dataclass
class PortInfo:
    port:        int
    protocol:    str                = "tcp"
    state:       str                = "open"
    service:     Optional[str]      = None
    product:     Optional[str]      = None
    version_str: Optional[str]      = None
    extra_info:  Optional[str]      = None
    version:     Optional[str]      = None
    cpes:        list[str]          = field(default_factory=list)
    banner:      Optional[str]      = None
    scripts:     list[ScriptOutput] = field(default_factory=list)
    reason:      Optional[str]      = None


@dataclass
class OSMatch:
    name:      Optional[str] = None
    accuracy:  Optional[int] = None
    os_family: Optional[str] = None
    vendor:    Optional[str] = None
    cpes:      list[str]     = field(default_factory=list)


@dataclass
class HostInfo:
    ip:             Optional[str]        = None
    hostname:       Optional[str]        = None
    state:          str                  = "up"
    state_reason:   Optional[str]        = None
    mac_address:    Optional[str]        = None
    mac_vendor:     Optional[str]        = None
    open_ports:     list[PortInfo]       = field(default_factory=list)
    closed_ports:   int                  = 0
    filtered_ports: int                  = 0
    os_matches:     list[OSMatch]        = field(default_factory=list)
    host_scripts:   list[ScriptOutput]   = field(default_factory=list)
    traceroute:     list[dict[str, Any]] = field(default_factory=list)
    uptime:         Optional[str]        = None
    distance:       Optional[int]        = None


@dataclass
class NmapScanResult:
    success:          bool
    target:           str
    scan_mode:        str
    command:          str
    total_hosts:      int                      = 0
    hosts_up:         int                      = 0
    total_open_ports: int                      = 0
    hosts:            list[HostInfo]           = field(default_factory=list)
    scan_info:        Optional[dict[str, Any]] = None
    execution_time:   float                    = 0.0
    warnings:         list[str]                = field(default_factory=list)
    error:            Optional[str]            = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════
# 7. COMMAND BUILDER
# ══════════════════════════════════════════════════════════════════════

_MODE_FLAGS: dict[str, list[str]] = {
    "discovery":  ["-sn"],
    "syn":        ["-sS"],
    "tcp":        ["-sT"],
    "udp":        ["-sU"],
    "version":    ["-sV"],
    "aggressive": ["-A"],
    "script":     ["-sV"],
}

_SCRIPT_TIMEOUT_FLAGS = {"--script-timeout"}
_HOST_TIMEOUT_FLAGS   = {"--host-timeout"}
_BLOCKED_OUTPUT_FLAGS = {
    "-oA", "-oG", "-oN", "-oS", "-oX", "-o", "--append-output", "--resume",
}


def _has_flag(args: list[str], flags: set[str]) -> bool:
    for arg in args:
        for flag in flags:
            if arg == flag or arg.startswith(f"{flag}="):
                return True
    return False


def _validate_extra_args(args: list[str]) -> list[str]:
    cleaned: list[str] = []
    for arg in args:
        text = str(arg).strip()
        if not text:
            continue

        if text in _BLOCKED_OUTPUT_FLAGS:
            raise ValueError(
                f"Nmap output flag '{text}' is blocked. This tool returns results directly and does not save scan artifacts to files."
            )

        if any(text.startswith(f"{flag}=") for flag in _BLOCKED_OUTPUT_FLAGS):
            raise ValueError(
                f"Nmap output flag '{text}' is blocked. This tool returns results directly and does not save scan artifacts to files."
            )

        if any(
            text.startswith(flag) and len(text) > len(flag)
            for flag in ("-oA", "-oG", "-oN", "-oS", "-oX")
        ):
            raise ValueError(
                f"Nmap output flag '{text}' is blocked. This tool returns results directly and does not save scan artifacts to files."
            )

        cleaned.append(text)
    return cleaned


def _build_cmd(req: NmapScanRequest) -> list[str]:
    cmd = ["nmap", *_MODE_FLAGS.get(req.scan_mode, ["-sT"])]

    if req.scan_mode == "script":
        cmd += ["--script", req.scripts or "default"]

    if req.scan_mode != "discovery":
        if req.ports:
            cmd += ["-p", req.ports]
        elif req.top_ports:
            cmd += ["--top-ports", str(req.top_ports)]
        if req.add_reason:
            cmd.append("--reason")

    cmd.append(f"-T{req.timing}")

    if req.scan_mode == "script" and not _has_flag(req.extra_args, _SCRIPT_TIMEOUT_FLAGS):
        cmd += ["--script-timeout", req.script_timeout]

    if not _has_flag(req.extra_args, _HOST_TIMEOUT_FLAGS):
        cmd += ["--host-timeout", f"{max(req.timeout - CFG.HOST_TIMEOUT_HEADROOM, 20)}s"]

    cmd += ["-oX", "-"]
    cmd += req.extra_args
    cmd.append(req.target)
    return cmd


# ══════════════════════════════════════════════════════════════════════
# 8. EXECUTOR
# ══════════════════════════════════════════════════════════════════════

def _execute(
    cmd: list[str],
    timeout: int,
    env_vars: Optional[dict[str, str]] = None,
) -> tuple[str, str, int]:
    logger.debug("Executing (shell=False): %s", " ".join(cmd))

    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=env,
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except PermissionError:
        return "", "Permission denied", -1
    except FileNotFoundError:
        return "", "nmap not found in PATH", -1
    except Exception as exc:
        return "", str(exc), -1


# ══════════════════════════════════════════════════════════════════════
# 9. XML PARSER
# ══════════════════════════════════════════════════════════════════════

def _sanitize(text: str) -> str:
    for pat in _SENSITIVE_RE:
        text = pat.sub("[REDACTED]", text)
    return text


def _parse_port(port_el: ET.Element) -> Optional[PortInfo]:
    state_el = port_el.find("state")
    if state_el is None:
        return None
    pstate = state_el.get("state", "")
    if pstate not in ("open", "open|filtered"):
        return None

    p = PortInfo(
        port=int(port_el.get("portid", 0)),
        protocol=port_el.get("protocol", "tcp"),
        state=pstate,
        reason=state_el.get("reason"),
    )

    svc = port_el.find("service")
    if svc is not None:
        p.service     = svc.get("name")
        p.product     = svc.get("product")   or None
        p.version_str = svc.get("version")   or None
        p.extra_info  = svc.get("extrainfo") or None
        p.banner      = svc.get("servicefp") or None
        parts = [
            p.product     or "",
            p.version_str or "",
            f"({p.extra_info})" if p.extra_info else "",
        ]
        p.version = " ".join(x for x in parts if x).strip() or None
        p.cpes = [c.text for c in svc.findall("cpe") if c.text]

    for sc in port_el.findall("script"):
        data = {
            el.get("key"): _sanitize(el.text)
            for el in sc.findall("elem")
            if el.get("key") and el.text
        }
        p.scripts.append(ScriptOutput(
            id=sc.get("id", "unknown"),
            output=_sanitize(sc.get("output", "")),
            data=data,
        ))

    return p


def _parse_host(host_el: ET.Element) -> HostInfo:
    h = HostInfo()

    for addr in host_el.findall("address"):
        atype = addr.get("addrtype", "")
        if atype in ("ipv4", "ipv6"):
            h.ip = addr.get("addr")
        elif atype == "mac":
            h.mac_address = addr.get("addr")
            h.mac_vendor  = addr.get("vendor")

    hn = host_el.find("hostnames/hostname")
    if hn is not None:
        h.hostname = hn.get("name")

    status = host_el.find("status")
    if status is not None:
        h.state        = status.get("state", "unknown")
        h.state_reason = status.get("reason")

    ports_el = host_el.find("ports")
    if ports_el is not None:
        for extra in ports_el.findall("extraports"):
            st = extra.get("state", "")
            ct = int(extra.get("count", 0))
            if st == "closed":
                h.closed_ports += ct
            elif "filtered" in st:
                h.filtered_ports += ct
        for port_el in ports_el.findall("port"):
            p = _parse_port(port_el)
            if p:
                h.open_ports.append(p)

    for om_el in host_el.findall(".//os/osmatch"):
        om = OSMatch(
            name=om_el.get("name"),
            accuracy=int(om_el.get("accuracy", 0)),
        )
        oc = om_el.find("osclass")
        if oc is not None:
            om.os_family = oc.get("osfamily")
            om.vendor    = oc.get("vendor")
            om.cpes      = [c.text for c in oc.findall("cpe") if c.text]
        h.os_matches.append(om)
    h.os_matches.sort(key=lambda x: x.accuracy or 0, reverse=True)

    hs_el = host_el.find("hostscript")
    if hs_el is not None:
        for sc in hs_el.findall("script"):
            data = {
                el.get("key"): _sanitize(el.text)
                for el in sc.findall("elem")
                if el.get("key") and el.text
            }
            h.host_scripts.append(ScriptOutput(
                id=sc.get("id", "?"),
                output=_sanitize(sc.get("output", "")),
                data=data,
            ))

    trace = host_el.find("trace")
    if trace is not None:
        h.traceroute = [
            {
                "ttl":  int(hop.get("ttl", 0)),
                "ip":   hop.get("ipaddr"),
                "rtt":  hop.get("rtt"),
                "host": hop.get("host", ""),
            }
            for hop in trace.findall("hop")
        ]

    ut = host_el.find("uptime")
    if ut is not None:
        h.uptime = f"{ut.get('seconds','?')}s (since {ut.get('lastboot','?')})"

    dist = host_el.find("distance")
    if dist is not None:
        try:
            h.distance = int(dist.get("value", 0))
        except (ValueError, TypeError):
            pass

    return h


def _parse_xml(
    xml_str: str,
) -> tuple[list[HostInfo], Optional[dict[str, Any]], list[str]]:
    warnings: list[str] = []

    if len(xml_str) > CFG.MAX_XML_BYTES:
        warnings.append(f"XML output truncated to {CFG.MAX_XML_BYTES} bytes")
        xml_str = xml_str[:CFG.MAX_XML_BYTES]

    start = next(
        (xml_str.find(m) for m in ("<?xml", "<nmaprun") if xml_str.find(m) != -1),
        -1,
    )
    if start == -1:
        return [], None, ["No XML output — nmap may need root or target is unreachable"]

    try:
        root = ET.fromstring(xml_str[start:])
    except ET.ParseError as exc:
        return [], None, [f"XML parse error: {exc}"]

    scan_info: dict[str, Any] = {}
    si = root.find(".//scaninfo")
    if si is not None:
        scan_info.update(
            type=si.get("type"),
            protocol=si.get("protocol"),
            services=si.get("services"),
        )
    fin = root.find(".//runstats/finished")
    if fin is not None:
        scan_info.update(elapsed=fin.get("elapsed"), summary=fin.get("summary"))

    hosts = [_parse_host(h) for h in root.findall(".//host")]
    return hosts, scan_info or None, warnings


# ══════════════════════════════════════════════════════════════════════
# 10. REGEX FALLBACK PARSER
# ══════════════════════════════════════════════════════════════════════

_PORT_RE      = re.compile(r"(\d+)/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)(?:\s+(.+))?")
_IP_RE        = re.compile(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)\)?")
_OS_DETAIL_RE = re.compile(r"^OS details?:\s*(.+)", re.IGNORECASE)
_OS_GUESS_RE  = re.compile(r"^Aggressive OS guesses?:\s*(.+)", re.IGNORECASE)
_OS_LINE_RE   = re.compile(r"^Running(?: \(JUST GUESSING\))?:\s*(.+)", re.IGNORECASE)
_OS_ACC_RE    = re.compile(r"^(.+?)\s+\((\d{1,3})%\)\s*$")
_MAC_RE       = re.compile(r"MAC Address:\s*([0-9A-Fa-f:]+)(?:\s+\((.+)\))?")
_CLOSED_RE    = re.compile(r"(\d+) closed")
_FILT_RE      = re.compile(r"(\d+) filtered")
_CPE_RE       = re.compile(r"^\s*(?:\|_?\s*)?cpe:/", re.IGNORECASE)
_CPE_VAL_RE   = re.compile(r"(cpe:/\S+)")


def _parse_regex(raw: str) -> list[HostInfo]:
    hosts: list[HostInfo] = []
    current: Optional[HostInfo] = None
    in_traceroute = False

    for line in raw.splitlines():
        m = _IP_RE.search(line)
        if m:
            if current is not None:
                hosts.append(current)
            current = HostInfo(hostname=m.group(1), ip=m.group(2), state="up")
            in_traceroute = False
            continue

        if current is None:
            continue

        if m := _PORT_RE.search(line):
            current.open_ports.append(PortInfo(
                port=int(m.group(1)),
                protocol=m.group(2),
                state=m.group(3),
                service=m.group(4),
                version=(m.group(5).strip() if m.group(5) else None),
            ))
            in_traceroute = False
            continue

        if m := _OS_DETAIL_RE.match(line):
            current.os_matches.append(OSMatch(name=m.group(1).strip()))
            continue

        if m := _OS_GUESS_RE.match(line):
            for part in m.group(1).split(","):
                part = part.strip()
                am = _OS_ACC_RE.match(part)
                if am:
                    try:
                        acc = int(am.group(2))
                    except ValueError:
                        acc = None
                    current.os_matches.append(OSMatch(name=am.group(1).strip(), accuracy=acc))
                elif part:
                    current.os_matches.append(OSMatch(name=part))
            continue

        if m := _OS_LINE_RE.match(line):
            if not current.os_matches:
                current.os_matches.append(OSMatch(name=m.group(1).strip()))
            continue

        if _CPE_RE.match(line):
            cpe_vals = _CPE_VAL_RE.findall(line)
            if cpe_vals:
                if current.open_ports:
                    current.open_ports[-1].cpes.extend(cpe_vals)
                elif current.os_matches:
                    current.os_matches[-1].cpes.extend(cpe_vals)
            continue

        if m := _MAC_RE.search(line):
            current.mac_address = m.group(1)
            current.mac_vendor  = m.group(2)
            continue

        if m := _CLOSED_RE.search(line):
            current.closed_ports = int(m.group(1))
        if m := _FILT_RE.search(line):
            current.filtered_ports = int(m.group(1))

        if re.match(r"TRACEROUTE", line, re.IGNORECASE):
            in_traceroute = True
            continue
        if in_traceroute:
            if m := re.match(r"\s*(\d+)\s+([\d.]+)\s+ms\s+(\S+)", line):
                current.traceroute.append({
                    "ttl": int(m.group(1)),
                    "rtt": m.group(2),
                    "ip":  m.group(3),
                    "host": "",
                })
                continue
            if line.strip() and not line[0].isspace():
                in_traceroute = False

    if current is not None:
        hosts.append(current)

    for h in hosts:
        h.os_matches.sort(key=lambda x: x.accuracy or 0, reverse=True)

    return hosts


# ══════════════════════════════════════════════════════════════════════
# 11. OUTPUT FORMATTER
# ══════════════════════════════════════════════════════════════════════

def _format(result: NmapScanResult, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2, default=str)

    if fmt == "jsonl":
        lines = [json.dumps({
            "target": result.target, "scan_mode": result.scan_mode,
            "command": result.command, "success": result.success,
            "execution_time": result.execution_time,
        }, default=str)]
        lines += [json.dumps(asdict(h), default=str) for h in result.hosts]
        return "\n".join(lines)

    if fmt == "csv":
        buf = StringIO()
        w   = csv_module.writer(buf)
        w.writerow([
            "host_ip", "hostname", "host_state",
            "port", "protocol", "state", "service",
            "product", "version", "extra_info", "cpes", "reason",
        ])
        for h in result.hosts:
            if not h.open_ports:
                w.writerow([h.ip or "", h.hostname or "", h.state,
                             "", "", "", "", "", "", "", "", ""])
            for p in sorted(h.open_ports, key=lambda x: x.port):
                w.writerow([
                    h.ip or "", h.hostname or "", h.state,
                    p.port, p.protocol, p.state, p.service or "",
                    p.product or "", p.version_str or "", p.extra_info or "",
                    "|".join(p.cpes), p.reason or "",
                ])
        return buf.getvalue()

    # ── text ──────────────────────────────────────────────────────────
    SEP = "─" * 64
    lines = [
        SEP,
        "  Nmap Scan Report  (v6.0)",
        f"  Target     : {result.target}",
        f"  Mode       : {result.scan_mode}",
        f"  Command    : {result.command}",
        f"  Hosts up   : {result.hosts_up} / {result.total_hosts}",
        f"  Open ports : {result.total_open_ports}",
        f"  Time       : {result.execution_time}s",
        SEP,
    ]

    if result.scan_mode == "aggressive":
        lines += ["  ⚡ Aggressive mode — expect IDS/IPS alerts", SEP]

    for h in result.hosts:
        label = f"{h.hostname} ({h.ip})" if h.hostname else (h.ip or "?")
        lines.append(f"\nHost: {label}  [{h.state}]")
        if h.state_reason:
            lines.append(f"  Reason  : {h.state_reason}")
        if h.mac_address:
            vendor = f"  ({h.mac_vendor})" if h.mac_vendor else ""
            lines.append(f"  MAC     : {h.mac_address}{vendor}")
        if h.os_matches:
            best = h.os_matches[0]
            acc  = f"  ({best.accuracy}%)" if best.accuracy is not None else ""
            lines.append(f"  OS      : {best.name}{acc}")
            if best.cpes:
                lines.append(f"            CPE: {best.cpes[0]}")
        if h.distance is not None:
            lines.append(f"  Dist    : {h.distance} hops")
        if h.uptime:
            lines.append(f"  Uptime  : {h.uptime}")
        if h.closed_ports or h.filtered_ports:
            lines.append(f"  Ports   : {h.closed_ports} closed, {h.filtered_ports} filtered")

        if h.open_ports:
            lines.append(
                f"\n  {'PORT':<13} {'STATE':<16} {'SERVICE':<15} {'REASON':<14} VERSION"
            )
            lines.append(f"  {'─'*13} {'─'*16} {'─'*15} {'─'*14} {'─'*20}")
            for p in sorted(h.open_ports, key=lambda x: x.port):
                lines.append(
                    f"  {f'{p.port}/{p.protocol}':<13} {p.state:<16} "
                    f"{(p.service or 'unknown'):<15} {(p.reason or ''):<14} "
                    f"{p.version or ''}"
                )
                for cpe in p.cpes:
                    lines.append(f"    CPE: {cpe}")
                for sc in p.scripts:
                    lines.append(
                        f"    [{sc.id}]: {sc.output[:120].replace(chr(10), ' ')}"
                    )

        if h.host_scripts:
            lines.append("\n  Host scripts:")
            for sc in h.host_scripts:
                lines.append(
                    f"    [{sc.id}]: {sc.output[:120].replace(chr(10), ' ')}"
                )

        if h.traceroute:
            lines.append(f"\n  Traceroute ({len(h.traceroute)} hops):")
            for hop in h.traceroute[:8]:
                ip  = (hop.get("ip")  or "?")
                rtt = (hop.get("rtt") or "?")
                lines.append(f"    {hop['ttl']:>2}.  {ip:<22} {rtt} ms")
            if len(h.traceroute) > 8:
                lines.append(f"    … {len(h.traceroute) - 8} more hops")

    if result.warnings:
        lines.append("\n⚠  Warnings:")
        for w in result.warnings:
            lines.append(f"   • {w}")
    if result.error:
        lines.append(f"\n✖  Error: {result.error}")

    lines.append(SEP)
    return "\n".join(lines)


def _atomic_write(text: str, path_str: str) -> None:
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".nmap_tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
        logger.info("Report written to %s", path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ══════════════════════════════════════════════════════════════════════
# 12. MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def nmap_scan(
    target:           str,
    scan_mode:        str                 = "tcp",
    ports:            Optional[str]       = None,
    top_ports:        Optional[int]       = None,
    scripts:          Optional[str]       = None,
    timing:           int                 = 3,
    extra_args:       Optional[list[str]] = None,
    timeout:          int                 = 600,
    script_timeout:   str                 = CFG.DEFAULT_SCRIPT_TIMEOUT,
    output_format:    str                 = CFG.DEFAULT_FORMAT,
    output_file:      Optional[str]       = None,
    calls_per_minute: float               = CFG.DEFAULT_CPM,
    add_reason:       bool                = True,
    sudo_password:    Optional[str]       = None,
) -> dict[str, Any]:
    """
    Run a real-time Nmap scan and return structured results.

    Every call executes a fresh scan — there is no caching.
    extra_args accepts valid nmap flags except file-output / resume flags.
    """
    if extra_args is None:
        extra_args = []

    t0 = time.perf_counter()

    # ── Validate ──────────────────────────────────────────────────────
    try:
        req = NmapScanRequest(
            target=target, scan_mode=scan_mode, ports=ports,
            top_ports=top_ports, scripts=scripts, timing=timing,
            extra_args=extra_args, timeout=timeout,
            script_timeout=script_timeout, output_format=output_format,
            output_file=output_file, calls_per_minute=calls_per_minute,
            add_reason=add_reason, sudo_password=sudo_password,
        )
    except (ValueError, TypeError) as exc:
        res = NmapScanResult(
            success=False, target=target, scan_mode=scan_mode,
            command="", error=str(exc),
        )
        out = res.to_dict()
        out["formatted_report"] = _format(res, output_format)
        return out

    # ── Rate limit ────────────────────────────────────────────────────
    _RATE.reconfigure(req.calls_per_minute)
    _RATE.acquire()

    # ── Build command ─────────────────────────────────────────────────
    cmd          = _build_cmd(req)
    env_vars:    dict[str, str] = {}
    helper_path: Optional[str]  = None

    if req.scan_mode in CFG.ROOT_MODES:
        try:
            cmd, env_vars, helper_path = _resolve_sudo_askpass(
                cmd, req.scan_mode, req.sudo_password
            )
        except SudoError as exc:
            res = NmapScanResult(
                success=False, target=req.target, scan_mode=req.scan_mode,
                command=" ".join(cmd), error=str(exc),
            )
            out = res.to_dict()
            out["formatted_report"] = _format(res, req.output_format)
            return out

    command_str = " ".join(cmd)

    # ── Execute — helper cleanup guaranteed via finally ───────────────
    try:
        stdout, stderr, rc = _execute(cmd, req.timeout, env_vars=env_vars or None)
    finally:
        if helper_path:
            Path(helper_path).unlink(missing_ok=True)

    elapsed = round(time.perf_counter() - t0, 3)

    # ── Parse ─────────────────────────────────────────────────────────
    hosts, scan_info, warnings = _parse_xml(stdout)

    if not hosts and (stdout or stderr):
        hosts = _parse_regex(stdout or stderr)
        if hosts:
            warnings.append("Fell back to regex parser — XML output unavailable")
        else:
            warnings.append("No hosts parsed — target may be down or all ports filtered")

    total_open = sum(len(h.open_ports) for h in hosts)
    hosts_up   = sum(1 for h in hosts if h.state == "up")
    success    = bool(hosts) or rc == 0
    error: Optional[str] = None
    if rc != 0 and not hosts:
        error = (stderr.strip()[:500] if stderr else f"nmap exited with code {rc}")

    res = NmapScanResult(
        success=success, target=req.target, scan_mode=req.scan_mode,
        command=command_str, total_hosts=len(hosts), hosts_up=hosts_up,
        total_open_ports=total_open, hosts=hosts, scan_info=scan_info,
        execution_time=elapsed, warnings=warnings, error=error,
    )

    report = _format(res, req.output_format)

    out = res.to_dict()
    out["formatted_report"] = report
    return out


# ══════════════════════════════════════════════════════════════════════
# 13. LLM TOOL DEFINITION
# ══════════════════════════════════════════════════════════════════════

NMAP_SCAN_TOOL_DEFINITION: dict[str, Any] = {
    "name": "nmap_scan",
    "description": (
        "Nmap network scanner (v6.0). Real-time scan — no caching, every call runs fresh. "
        "No-root modes: tcp, version, script, discovery. "
        "Root modes: syn, udp, aggressive (pass sudo_password or set "
        "NMAP_SUDO_PASSWORD; uses ASKPASS helper so password is never visible "
        "in process listings). "
        "extra_args accepts valid nmap flags except file output / resume flags — "
        "e.g. --script-args, --proxies, --packet-trace, -6, --data-string, "
        "--badsum, --spoof-mac, --ttl, --defeat-rst-ratelimit, etc. "
        "Results are always returned directly and are never saved to result files. "
        "Returns structured host / port / service / OS / traceroute data."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP address, hostname, or CIDR range (IPv4/IPv6, max /22 = 1024 hosts).",
            },
            "scan_mode": {
                "type": "string",
                "enum": sorted(CFG.VALID_MODES),
                "default": "tcp",
                "description": (
                    "discovery=ping sweep; tcp=connect scan (no root); "
                    "syn=stealth SYN (root); udp=UDP (root); "
                    "version=service version detection; "
                    "aggressive=OS+version+scripts (root); "
                    "script=NSE script scan."
                ),
            },
            "ports": {
                "type": "string",
                "description": "Port spec: '22,80,443', '1-1000', '1-65535', 'U:53,T:80'.",
            },
            "top_ports": {
                "type": "integer",
                "description": "Scan the N most commonly open ports. Ignored when ports is set.",
            },
            "scripts": {
                "type": "string",
                "description": (
                    "NSE script selector for script mode: 'default', 'vuln', "
                    "'http-*', 'ssl-cert,http-headers', etc."
                ),
            },
            "timing": {
                "type": "integer",
                "default": 3,
                "description": "Nmap timing template 0 (paranoid) – 5 (insane). Default 3 (normal).",
            },
            "extra_args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Additional nmap flags passed directly (shell=False). "
                    "File output / resume flags such as -oN, -oX, -oA, -oG, -oS, --append-output, and --resume are blocked. "
                    'Examples: ["--script-args", "user=admin,pass=secret"], '
                    '["--proxies", "socks4://127.0.0.1:9050"], '
                    '["--packet-trace"], ["-6"], ["--spoof-mac", "0"], '
                    '["--osscan-guess"], ["--version-intensity", "9"], '
                    '["--min-parallelism", "100"], ["--defeat-rst-ratelimit"].'
                ),
            },
            "timeout": {
                "type": "integer",
                "default": 600,
                "description": "Overall wall-clock timeout in seconds (30–7200).",
            },
            "script_timeout": {
                "type": "string",
                "default": "30s",
                "description": "Per-script timeout (30s, 2m, 500ms). Ignored if --script-timeout is in extra_args.",
            },
            "output_format": {
                "type": "string",
                "enum": sorted(CFG.VALID_FORMATS),
                "default": "text",
                "description": "text=human-readable, json=full dict, csv=spreadsheet, jsonl=streaming.",
            },
            "calls_per_minute": {
                "type": "number",
                "default": 30.0,
                "description": "Max scan invocations per minute (shared across processes via file lock).",
            },
            "add_reason": {
                "type": "boolean",
                "default": True,
                "description": "Append --reason to show why each port is in its reported state.",
            },
            "sudo_password": {
                "type": "string",
                "description": (
                    "Password for root-required modes (syn, udp, aggressive). "
                    "Delivered via ASKPASS helper — not visible in ps/top."
                ),
            },
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════════════
# 14. DEMO
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import getpass

    _sudo_pwd: Optional[str] = None
    if not _is_root() and not _sudo_cached():
        _env_pwd = os.environ.get(CFG.SUDO_PWD_ENV)
        if _env_pwd:
            print(f"[sudo] Using password from {CFG.SUDO_PWD_ENV} env var.")
            _sudo_pwd = _env_pwd
        else:
            try:
                _sudo_pwd = getpass.getpass("[sudo] Password for root-mode scans: ") or None
            except (EOFError, KeyboardInterrupt):
                print("\n  No password provided.")

    demos = [
        ("TCP scan", dict(
            target="scanme.nmap.org", scan_mode="tcp", top_ports=50,
        )),
        ("HTTP headers via NSE + script-args", dict(
            target="scanme.nmap.org", scan_mode="script", scripts="http-headers",
            ports="80,443",
            extra_args=["--script-args", 'http.useragent="Mozilla/5.0"'],
        )),
        ("SYN stealth (root required, ASKPASS)", dict(
            target="scanme.nmap.org", scan_mode="syn", top_ports=50,
            sudo_password=_sudo_pwd,
        )),
    ]

    for label, kwargs in demos:
        print(f"\n{'=' * 64}\n  {label}\n{'=' * 64}")
        try:
            res = nmap_scan(**kwargs)
            print(res.get("formatted_report", "(no report)"))
        except KeyboardInterrupt:
            print("\n  Aborted.")
            sys.exit(0)
