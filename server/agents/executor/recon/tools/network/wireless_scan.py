"""
wireless_scan.py — WiFi recon agent tool
Supports: aircrack-ng suite, wifite, bettercap, kismet
"""

from __future__ import annotations

__all__ = ["wireless_scan", "WIRELESS_SCAN_TOOL_DEFINITION"]

import csv
import io
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════

ALLOWED_TOOLS: frozenset[str] = frozenset({"aircrack-ng", "wifite", "bettercap", "kismet"})

ALLOWED_MODES: frozenset[str] = frozenset({
    "monitor_on", "monitor_off",
    "ap_scan", "channel_scan", "handshake", "deauth",
    "wifite_scan", "wifite_attack",
    "bc_scan", "bc_deauth", "bc_ap",
    "kismet_scan",
})

_SHELL_DANGEROUS: tuple[str, ...] = (
    ";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r",
)

MAX_DEAUTH_COUNT: int = 50
_HANDSHAKE_PREFIX: str = "handshake_cap"
_RAW_OUTPUT_LIMIT: int = 5_000


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class WirelessScanRequest(BaseModel):
    tool: str
    interface: str
    mode: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in ALLOWED_TOOLS:
            raise ValueError(f"Tool '{v}' not allowed. Use: {sorted(ALLOWED_TOOLS)}")
        return v

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[a-zA-Z0-9_\-]{2,20}", v):
            raise ValueError(f"Invalid interface name: '{v}'")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ALLOWED_MODES:
            raise ValueError(f"Mode '{v}' not allowed. Use: {sorted(ALLOWED_MODES)}")
        return v

    @field_validator("args", mode="before")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        """Single-pass: check for shell injection AND bare output flags."""
        result: list[str] = []
        for item in v:
            for char in _SHELL_DANGEROUS:
                if char in item:
                    raise ValueError(f"Dangerous character {char!r} in arg: {item!r}")
            if item.strip() in ("-w", "--write"):
                raise ValueError(
                    f"Bare output flag '{item}' blocked — "
                    "provide full path: ['-w', '/tmp/capture']"
                )
            result.append(item)
        return result


class APResult(BaseModel):
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    channel: Optional[int] = None
    frequency: Optional[str] = None
    encryption: Optional[str] = None
    cipher: Optional[str] = None
    auth: Optional[str] = None
    signal_dbm: Optional[int] = None
    beacon_count: Optional[int] = None
    data_frames: Optional[int] = None
    speed_mbps: Optional[int] = None
    vendor: Optional[str] = None
    wps: Optional[bool] = None
    handshake_captured: Optional[bool] = None
    handshake_file: Optional[str] = None
    extra: Optional[dict[str, Any]] = None


class ClientResult(BaseModel):
    mac: Optional[str] = None
    associated_bssid: Optional[str] = None
    associated_ssid: Optional[str] = None
    signal_dbm: Optional[int] = None
    data_frames: Optional[int] = None
    probes: Optional[list[str]] = None
    vendor: Optional[str] = None
    extra: Optional[dict[str, Any]] = None


class RogueAPResult(BaseModel):
    bssid: str
    ssid: str
    reason: str
    legitimate_bssid: Optional[str] = None


class WirelessScanResult(BaseModel):
    success: bool
    tool: str
    interface: str
    mode: str
    command: str
    total_aps: int = 0
    total_clients: int = 0
    total_rogues: int = 0
    access_points: list[APResult] = []
    clients: list[ClientResult] = []
    rogue_aps: list[RogueAPResult] = []
    handshake_files: list[str] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. HELPERS
# ══════════════════════════════════════════════════════════════

_BSSID_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def _safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (ValueError, TypeError, AttributeError):
        return default


def _safe_str(value: Any) -> Optional[str]:
    s = str(value).strip() if value is not None else ""
    return s or None


def _is_bssid(s: str) -> bool:
    return bool(_BSSID_RE.fullmatch(s.strip()))


def _extract_arg_value(args: list[str], flag: str) -> Optional[str]:
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def _is_wifi_adapter(iface: str) -> tuple[bool, str]:
    """Verify iface exists and supports wireless extensions."""
    if not os.path.exists(f"/sys/class/net/{iface}"):
        return False, f"Interface '{iface}' does not exist on this system."
    
    # 1. Sysfs check (standard for managed/monitor wifi devs)
    if (os.path.exists(f"/sys/class/net/{iface}/wireless") or 
        os.path.exists(f"/sys/class/net/{iface}/phy80211")):
        return True, ""
        
    # 2. Fallback to iw (some monitor interfaces obscure sysfs links)
    try:
        iw_res = subprocess.run(
            ["iw", "dev", iface, "info"], capture_output=True, text=True
        )
        if iw_res.returncode == 0:
            return True, ""
    except FileNotFoundError:
        pass
        
    # 3. Fallback to iwconfig
    try:
        iwc_res = subprocess.run(
            ["iwconfig", iface], capture_output=True, text=True
        )
        if "no wireless extensions" not in iwc_res.stderr.lower():
            return True, ""
    except FileNotFoundError:
        pass

    return False, f"Interface '{iface}' is not a valid WiFi adapter."


def get_available_wireless_interfaces() -> list[str]:
    """Return a list of wireless interfaces available on the system."""
    interfaces = []
    if not os.path.exists("/sys/class/net/"):
        return interfaces
    
    for iface in os.listdir("/sys/class/net/"):
        # Skip obvious non-physical / container interfaces to speed up scan
        if iface == "lo" or iface.startswith(("docker", "br-", "veth", "tun", "virbr")):
            continue
            
        is_wifi, _ = _is_wifi_adapter(iface)
        if is_wifi:
            interfaces.append(iface)
            
    return sorted(interfaces)


def _extract_eval_arg(args: list[str]) -> tuple[Optional[str], list[str]]:
    """Single-pass extraction of '-eval <value>' from args."""
    eval_value: Optional[str] = None
    remaining: list[str] = []
    it = iter(range(len(args)))
    for i in it:
        if args[i] == "-eval" and i + 1 < len(args):
            eval_value = args[i + 1]
            next(it, None)
        else:
            remaining.append(args[i])
    return eval_value, remaining


def _strip_flags(args: list[str], flags: set[str]) -> list[str]:
    """Remove *flags* and their trailing value token from args."""
    result: list[str] = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in flags and i + 1 < len(args):
            skip = True
        else:
            result.append(a)
    return result


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_airodump(stdout: str, stderr: str) -> tuple[list[APResult], list[ClientResult]]:
    aps: list[APResult] = []
    clients: list[ClientResult] = []
    raw = stdout or stderr

    csv_match = re.search(
        r"BSSID,\s*First time seen.*?\n(.*?)\r?\n\r?\n"
        r"Station MAC,.*?\n(.*)",
        raw,
        re.DOTALL | re.IGNORECASE,
    )
    if csv_match:
        ap_section = csv_match.group(1).strip()
        client_section = csv_match.group(2).strip()

        try:
            reader = csv.DictReader(
                io.StringIO(ap_section),
                fieldnames=[
                    "BSSID", "First time seen", "Last time seen", "channel",
                    "Speed", "Privacy", "Cipher", "Authentication",
                    "Power", "beacons", "IV", "LAN IP", "ID-length", "ESSID", "Key",
                ],
            )
            for row in reader:
                bssid = (row.get("BSSID") or "").strip()
                if not _is_bssid(bssid):
                    continue
                aps.append(APResult(
                    bssid=bssid,
                    ssid=_safe_str(row.get("ESSID")),
                    channel=_safe_int(row.get("channel")),
                    encryption=_safe_str(row.get("Privacy")),
                    cipher=_safe_str(row.get("Cipher")),
                    auth=_safe_str(row.get("Authentication")),
                    signal_dbm=_safe_int(row.get("Power")),
                    speed_mbps=_safe_int(row.get("Speed")),
                    beacon_count=_safe_int(row.get("beacons")),
                ))
        except Exception:
            pass

        try:
            reader = csv.DictReader(
                io.StringIO(client_section),
                fieldnames=[
                    "Station MAC", "First time seen", "Last time seen",
                    "Power", "packets", "BSSID", "Probed ESSIDs",
                ],
            )
            for row in reader:
                mac = (row.get("Station MAC") or "").strip()
                if not _is_bssid(mac):
                    continue
                probes_raw = (row.get("Probed ESSIDs") or "").strip()
                probes = [p.strip() for p in probes_raw.split(",") if p.strip()] or None
                assoc = (row.get("BSSID") or "").strip()
                clients.append(ClientResult(
                    mac=mac,
                    associated_bssid=assoc if assoc and assoc != "(not associated)" else None,
                    signal_dbm=_safe_int(row.get("Power")),
                    probes=probes,
                ))
        except Exception:
            pass

        if aps or clients:
            return aps, clients

    ap_re = re.compile(
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
        r"(-?\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+"
        r"(\d+)\s+\d+\S*\s+"
        r"(\S+)\s+(\S+)?\s*(\S+)?\s+(.*?)$",
        re.MULTILINE,
    )
    for m in ap_re.finditer(raw):
        aps.append(APResult(
            bssid=m.group(1),
            signal_dbm=_safe_int(m.group(2)),
            channel=_safe_int(m.group(3)),
            encryption=_safe_str(m.group(4)),
            cipher=_safe_str(m.group(5)),
            auth=_safe_str(m.group(6)),
            ssid=_safe_str(m.group(7)),
        ))

    client_re = re.compile(
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|not associated)\s+"
        r"(-?\d+)\s+\d+\s+\S*\s*(.*?)$",
        re.MULTILINE,
    )
    for m in client_re.finditer(raw):
        probes_raw = m.group(4).strip()
        probes = [p.strip() for p in probes_raw.split(",") if p.strip()] or None
        assoc = m.group(2)
        clients.append(ClientResult(
            mac=m.group(1),
            associated_bssid=assoc if "not associated" not in assoc else None,
            signal_dbm=_safe_int(m.group(3)),
            probes=probes,
        ))

    return aps, clients


def parse_wifite(stdout: str) -> tuple[list[APResult], list[str]]:
    aps: list[APResult] = []
    handshake_files: list[str] = []

    ap_re = re.compile(
        r"\d+\s+(.+?)\s+(\d+)\s+(\w+)\s+(-?\d+)dBm\s+(yes|no)\s+\d+",
        re.IGNORECASE,
    )
    for m in ap_re.finditer(stdout):
        aps.append(APResult(
            ssid=m.group(1).strip(),
            channel=_safe_int(m.group(2)),
            encryption=m.group(3).upper(),
            signal_dbm=_safe_int(m.group(4)),
            wps=m.group(5).lower() == "yes",
        ))

    hs_re = re.compile(r"saved handshake to\s+(\S+\.cap)", re.IGNORECASE)
    for m in hs_re.finditer(stdout):
        handshake_files.append(m.group(1))

    for ap in aps:
        if not ap.ssid:
            continue
        normalised = ap.ssid.lower().replace(" ", "")
        for hf in handshake_files:
            if normalised in hf.lower():
                ap.handshake_captured = True
                ap.handshake_file = hf
                break

    return aps, handshake_files


def parse_bettercap(
    stdout: str,
) -> tuple[list[APResult], list[ClientResult], list[RogueAPResult]]:
    aps: list[APResult] = []
    clients: list[ClientResult] = []

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            bssid = obj.get("bssid") or obj.get("BSSID")
            if bssid:
                aps.append(APResult(
                    bssid=bssid,
                    ssid=obj.get("essid") or obj.get("SSID"),
                    channel=obj.get("channel"),
                    encryption=obj.get("encryption"),
                    cipher=obj.get("cipher"),
                    signal_dbm=obj.get("rssi") or obj.get("signal"),
                    wps=obj.get("wps"),
                    vendor=obj.get("vendor"),
                ))
            elif obj.get("station") or obj.get("mac"):
                mac = obj.get("station") or obj.get("mac")
                clients.append(ClientResult(
                    mac=mac,
                    associated_bssid=obj.get("ap") or obj.get("bssid"),
                    signal_dbm=obj.get("rssi") or obj.get("signal"),
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    if not aps:
        ap_re = re.compile(
            r"wifi\.recon.*?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
            r"(-?\d+)\s+dBm\s+ch\s+(\d+)\s+(\w+)\s+(.*?)$",
            re.MULTILINE | re.IGNORECASE,
        )
        for m in ap_re.finditer(stdout):
            aps.append(APResult(
                bssid=m.group(1),
                signal_dbm=_safe_int(m.group(2)),
                channel=_safe_int(m.group(3)),
                encryption=_safe_str(m.group(4)),
                ssid=_safe_str(m.group(5)),
            ))

        client_re = re.compile(
            r"wifi\.client.*?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(-?\d+)\s+dBm",
            re.MULTILINE | re.IGNORECASE,
        )
        for m in client_re.finditer(stdout):
            clients.append(ClientResult(mac=m.group(1), signal_dbm=_safe_int(m.group(2))))

    # ── Rogue AP detection ──────────────────────────────────────
    rogues: list[RogueAPResult] = []
    ssid_map: dict[str, list[APResult]] = {}
    for ap in aps:
        if ap.ssid:
            ssid_map.setdefault(ap.ssid, []).append(ap)

    for ssid, ap_list in ssid_map.items():
        unique_bssids = list(dict.fromkeys(ap.bssid for ap in ap_list if ap.bssid))
        if len(unique_bssids) < 2:
            continue
        channels = [ap.channel for ap in ap_list if ap.channel is not None]
        reason = "duplicate SSID"
        if len(set(channels)) > 1:
            reason += " with mismatched channels"
        # FIX: guard None signal_dbm to avoid TypeError
        sorted_aps = sorted(
            ap_list,
            key=lambda a: a.signal_dbm if a.signal_dbm is not None else -999,
            reverse=True,
        )
        legitimate = sorted_aps[0]
        for rogue in sorted_aps[1:]:
            if rogue.bssid:
                rogues.append(RogueAPResult(
                    bssid=rogue.bssid,
                    ssid=ssid,
                    reason=reason,
                    legitimate_bssid=legitimate.bssid,
                ))

    return aps, clients, rogues


def parse_kismet(stdout: str, stderr: str) -> tuple[list[APResult], list[ClientResult]]:
    aps: list[APResult] = []
    clients: list[ClientResult] = []
    raw = stdout or stderr

    try:
        data = json.loads(raw)
        devices = data if isinstance(data, list) else data.get("devices", [])
        for dev in devices:
            dot11 = dev.get("dot11.device", {})
            base_signal = dev.get("kismet.device.base.signal", {})
            sig = _safe_int(base_signal.get("kismet.common.signal.last_signal"))
            if dot11:
                aps.append(APResult(
                    bssid=dev.get("kismet.device.base.macaddr"),
                    ssid=dot11.get("dot11.device.last_beaconed_ssid"),
                    channel=_safe_int(dev.get("kismet.device.base.channel")),
                    encryption=dot11.get("dot11.device.best_crypt_set"),
                    signal_dbm=sig,
                    beacon_count=_safe_int(dot11.get("dot11.device.num_beacons_seen")),
                    vendor=dev.get("kismet.device.base.manuf"),
                ))
            else:
                clients.append(ClientResult(
                    mac=dev.get("kismet.device.base.macaddr"),
                    signal_dbm=sig,
                    vendor=dev.get("kismet.device.base.manuf"),
                ))
        return aps, clients
    except (json.JSONDecodeError, TypeError, KeyError):
        pass

    ap_re = re.compile(
        r"Found AP.*?['\"](.+?)['\"].*?"
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}).*?"
        r"Ch\s+(\d+).*?(-?\d+)\s+dBm",
        re.IGNORECASE,
    )
    for m in ap_re.finditer(raw):
        aps.append(APResult(
            ssid=m.group(1),
            bssid=m.group(2),
            channel=_safe_int(m.group(3)),
            signal_dbm=_safe_int(m.group(4)),
        ))

    return aps, clients


# ══════════════════════════════════════════════════════════════
# 5. EXECUTOR
# ══════════════════════════════════════════════════════════════

class _ProcessResult:
    __slots__ = ("stdout", "stderr", "returncode", "timed_out")

    def __init__(self, stdout: str, stderr: str, returncode: int, timed_out: bool = False) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timed_out = timed_out


def safe_execute(cmd: list[str], timeout: int = 600) -> _ProcessResult:
    """
    Execute a command without shell interpolation.
    Uses subprocess's native communicate(timeout=...) — no extra thread needed.
    """
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
            return _ProcessResult(stdout, stderr, proc.returncode)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return _ProcessResult(
                stdout or "",
                (stderr or "") + f"\n[timeout] process killed after {timeout}s",
                -1,
                timed_out=True,
            )
    except FileNotFoundError:
        return _ProcessResult("", f"Tool '{cmd[0]}' not found — is it installed?", 127)
    except Exception as exc:
        return _ProcessResult("", str(exc), -1)


# ══════════════════════════════════════════════════════════════
# 6. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_aircrack_cmd(req: WirelessScanRequest) -> tuple[list[list[str]], Optional[str]]:
    iface = req.interface
    args = list(req.args)

    if req.mode == "monitor_on":
        cmds = []
        clean_args = list(args)
        if "kill" in clean_args or "check" in clean_args:
            cmds.append(["sudo", "airmon-ng", "check", "kill"])
            clean_args = [a for a in clean_args if a not in ("check", "kill")]
        cmds.append(["sudo", "airmon-ng", "start", iface] + clean_args)
        return cmds, None

    if req.mode == "monitor_off":
        return [["sudo", "airmon-ng", "stop", iface] + args], None

    if req.mode in ("ap_scan", "channel_scan"):
        if "-w" not in args:
            # FIX: mkstemp avoids TOCTOU race condition
            fd, tmp = tempfile.mkstemp(prefix="airodump_", dir="/tmp", suffix="")
            os.close(fd)
            args = ["--output-format", "csv", "-w", tmp] + args
        return [["sudo", "airodump-ng"] + args + [iface]], None

    if req.mode == "handshake":
        bssid = _extract_arg_value(args, "--bssid")
        channel = _extract_arg_value(args, "--channel") or _extract_arg_value(args, "-c")

        if not bssid:
            return [], "handshake mode requires --bssid in args"
        if not channel:
            return [], "handshake mode requires --channel (or -c) in args"
        if not _is_bssid(bssid):
            return [], f"Invalid BSSID: {bssid!r}"

        clean_args = _strip_flags(args, {"--bssid", "--channel", "-c"})

        fd, cap_path = tempfile.mkstemp(prefix=_HANDSHAKE_PREFIX + "_", dir="/tmp", suffix="")
        os.close(fd)

        if "-w" not in clean_args:
            clean_args = ["--output-format", "cap,csv", "-w", cap_path] + clean_args

        airodump_cmd = [
            "sudo", "airodump-ng",
            "--bssid", bssid,
            "--channel", channel,
        ] + clean_args + [iface]

        deauth_count_raw = _extract_arg_value(args, "--deauth-count") or "5"
        try:
            deauth_count = str(min(int(deauth_count_raw), MAX_DEAUTH_COUNT))
        except ValueError:
            deauth_count = "5"

        aireplay_cmd = ["aireplay-ng", "-0", deauth_count, "-a", bssid, iface]
        return [[airodump_cmd, aireplay_cmd]], None

    if req.mode == "deauth":
        bssid = _extract_arg_value(args, "-a")
        client = _extract_arg_value(args, "-c") or "FF:FF:FF:FF:FF:FF"
        count_raw = _extract_arg_value(args, "-0") or "5"

        if not bssid:
            return [], "deauth mode requires -a <BSSID> in args"
        if not _is_bssid(bssid):
            return [], f"Invalid AP BSSID: {bssid!r}"
        if client != "FF:FF:FF:FF:FF:FF" and not _is_bssid(client):
            return [], f"Invalid client BSSID: {client!r}"

        try:
            count = str(min(int(count_raw), MAX_DEAUTH_COUNT))
        except ValueError:
            count = "5"

        return [["sudo", "aireplay-ng", "-0", count, "-a", bssid, "-c", client, iface]], None

    return [], f"Unknown mode '{req.mode}' for aircrack-ng"


def _build_wifite_cmd(req: WirelessScanRequest) -> tuple[list[list[str]], Optional[str]]:
    if req.mode == "wifite_scan":
        return [["sudo", "wifite", "--scan", "--interface", req.interface] + list(req.args)], None
    if req.mode == "wifite_attack":
        return [["sudo", "wifite", "--interface", req.interface] + list(req.args)], None
    return [], f"Unknown mode '{req.mode}' for wifite"


def _build_bettercap_cmd(req: WirelessScanRequest) -> tuple[list[list[str]], Optional[str]]:
    defaults: dict[str, str] = {
        "bc_scan":   "wifi.recon on; sleep 15; wifi.show; quit",
        "bc_deauth": "wifi.recon on",
        "bc_ap":     "wifi.ap on",
    }
    if req.mode not in defaults:
        return [], f"Unknown mode '{req.mode}' for bettercap"
    eval_override, remaining = _extract_eval_arg(list(req.args))
    eval_cmd = eval_override or defaults[req.mode]
    return [["sudo", "bettercap", "-iface", req.interface, "-eval", eval_cmd] + remaining], None


def _build_kismet_cmd(req: WirelessScanRequest) -> tuple[list[list[str]], Optional[str]]:
    if req.mode == "kismet_scan":
        return [[
            "sudo", "kismet",
            "--source", f"{req.interface}:name=recon",
            "--no-ncurses",
            "--output-type", "json",
        ] + list(req.args)], None
    return [], f"Unknown mode '{req.mode}' for kismet"


_BUILDERS: dict[str, Any] = {
    "aircrack-ng": _build_aircrack_cmd,
    "wifite":      _build_wifite_cmd,
    "bettercap":   _build_bettercap_cmd,
    "kismet":      _build_kismet_cmd,
}


# ══════════════════════════════════════════════════════════════
# 7. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def wireless_scan(
    tool: str,
    interface: str,
    mode: str,
    args: list[str] | None = None,
) -> dict:
    """
    Agent Tool: WiFi Recon — AP Discovery, WPA Handshake Capture,
    Deauth, Rogue AP Detection, Client Enumeration.

    See WIRELESS_SCAN_TOOL_DEFINITION for full parameter docs.
    """
    if args is None:
        args = []

    start = time.monotonic()

    def _fail(msg: str, cmd: str = "") -> dict:
        return WirelessScanResult(
            success=False, tool=tool, interface=interface, mode=mode,
            command=cmd, error=msg,
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    try:
        req = WirelessScanRequest(tool=tool, interface=interface, mode=mode, args=args)
    except Exception as exc:
        return _fail(f"Validation error: {exc}")

    # Pre-flight check: ensure it's a valid WiFi adapter
    is_wifi, w_err = _is_wifi_adapter(req.interface)
    if not is_wifi:
        return _fail(w_err)

    builder = _BUILDERS.get(req.tool)
    if builder is None:
        return _fail(f"Unknown tool: {req.tool!r}")

    cmds, build_err = builder(req)
    if build_err:
        return _fail(build_err)
    if not cmds:
        return _fail("No command generated")

    all_stdout: list[str] = []
    all_stderr: list[str] = []
    final_rc = 0

    for cmd in cmds:
        res = safe_execute(cmd, req.timeout)
        if res.stdout:
            all_stdout.append(res.stdout)
        if res.stderr:
            all_stderr.append(res.stderr)
        if res.returncode != 0:
            final_rc = res.returncode
        if res.timed_out:
            all_stderr.append(f"[timeout] {' '.join(cmd)}")
            break

    combined_stdout = "\n".join(all_stdout)
    combined_stderr = "\n".join(all_stderr)
    command_str = " | ".join(" ".join(c) for c in cmds)

    aps: list[APResult] = []
    clients: list[ClientResult] = []
    rogues: list[RogueAPResult] = []
    handshake_files: list[str] = []

    if req.tool == "aircrack-ng":
        if req.mode in ("ap_scan", "channel_scan", "handshake"):
            aps, clients = parse_airodump(combined_stdout, combined_stderr)
        if req.mode == "handshake":
            cap_re = re.compile(r"/tmp/" + _HANDSHAKE_PREFIX + r"[^\s]*\.cap")
            found: list[str] = cap_re.findall(combined_stdout + combined_stderr)
            seen: set[str] = set(found)
            for p in Path("/tmp").glob(_HANDSHAKE_PREFIX + "*.cap"):
                s = str(p)
                if s not in seen:
                    found.append(s)
                    seen.add(s)
            handshake_files = found
            if handshake_files:
                for ap in aps:
                    ap.handshake_captured = True
                    ap.handshake_file = handshake_files[0]

    elif req.tool == "wifite":
        aps, handshake_files = parse_wifite(combined_stdout)

    elif req.tool == "bettercap":
        aps, clients, rogues = parse_bettercap(combined_stdout)

    elif req.tool == "kismet":
        aps, clients = parse_kismet(combined_stdout, combined_stderr)

    has_results = bool(aps or clients or handshake_files)
    action_mode = req.mode in ("monitor_on", "monitor_off", "deauth")
    success = has_results or (action_mode and final_rc == 0)

    error_msg: Optional[str] = None
    if combined_stderr.strip() and (final_rc != 0 or not has_results):
        error_msg = combined_stderr.strip()[:2_000]

    raw = (combined_stdout or combined_stderr)[:_RAW_OUTPUT_LIMIT]

    return WirelessScanResult(
        success=success,
        tool=req.tool,
        interface=req.interface,
        mode=req.mode,
        command=command_str,
        total_aps=len(aps),
        total_clients=len(clients),
        total_rogues=len(rogues),
        access_points=aps,
        clients=clients,
        rogue_aps=rogues,
        handshake_files=handshake_files,
        raw_output=raw or None,
        error=error_msg,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 8. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

WIRELESS_SCAN_TOOL_DEFINITION: dict[str, Any] = {
    "name": "wireless_scan",
    "description": (
        "WiFi recon: AP discovery, WPA handshake capture, deauth attacks, "
        "rogue AP detection, and client enumeration. "
        "Supports aircrack-ng suite, wifite, bettercap, and kismet. "
        "YOU decide the mode and args."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": sorted(ALLOWED_TOOLS),
                "description": (
                    "aircrack-ng = full manual control (monitor, scan, handshake, deauth) | "
                    "wifite      = automated WPA/WPS attack workflow | "
                    "bettercap   = recon + deauth + evil twin | "
                    "kismet      = fully passive RF recon (no TX)"
                ),
            },
            "interface": {
                "type": "string",
                "description": "Wireless interface name (e.g. 'wlan0', 'wlan1', 'mon0')",
            },
            "mode": {
                "type": "string",
                "enum": sorted(ALLOWED_MODES),
                "description": (
                    "monitor_on    → enable monitor mode\n"
                    "monitor_off   → disable monitor mode\n"
                    "ap_scan       → scan all APs + clients\n"
                    "channel_scan  → targeted channel scan\n"
                    "handshake     → capture WPA handshake (airodump + deauth, two-stage)\n"
                    "deauth        → deauth frames via aireplay-ng\n"
                    "wifite_scan   → passive wifite scan\n"
                    "wifite_attack → automated WPA/WPS attack\n"
                    "bc_scan       → bettercap wifi.recon\n"
                    "bc_deauth     → bettercap wifi.deauth\n"
                    "bc_ap         → bettercap rogue AP / evil twin\n"
                    "kismet_scan   → fully passive kismet recon"
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "ap_scan:       ['-w', '/tmp/cap', '--band', 'abg']\n"
                    "channel_scan:  ['--channel', '6', '--bssid', 'AA:BB:CC:DD:EE:FF']\n"
                    "handshake:     ['--bssid', 'AA:BB:CC:DD:EE:FF', '--channel', '6']\n"
                    "deauth:        ['-a', 'AA:BB:CC:DD:EE:FF', '-c', 'CC:DD:EE:FF:00:11', '-0', '10']\n"
                    "monitor_on:    ['check', 'kill']\n"
                    "wifite_attack: ['--wpa', '--bssid', 'AA:BB:CC:DD:EE:FF', '--dict', '/path/list.txt']\n"
                    "bc_scan:       ['-eval', 'wifi.recon.channel 6']\n"
                    "bc_deauth:     ['-eval', 'wifi.deauth AA:BB:CC:DD:EE:FF']\n"
                    "bc_ap:         ['-eval', 'set wifi.ap.ssid FreeWifi; wifi.ap on']\n"
                    "kismet_scan:   ['-c', 'wlan0:channels=1,6,11']"
                ),
            },
        },
        "required": ["tool", "interface", "mode"],
    },
}


# ══════════════════════════════════════════════════════════════
# 9. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    # Dynamically detect available interfaces instead of relying on hardcoded wlan0
    available_ifaces = get_available_wireless_interfaces()
    iface = available_ifaces[0] if available_ifaces else "wlan0"
    iface_mon = f"{iface}mon"
    
    if not available_ifaces:
        print(f"⚠️  No wireless adapters detected. Tests will run against generic '{iface}' to demonstrate validation rejections.\n")
    else:
        print(f"🔌 Auto-detected WiFi adapter: '{iface}'\n")

    examples: list[tuple[str, dict]] = [
        ("MONITOR ON",          dict(tool="aircrack-ng", interface=iface,      mode="monitor_on",    args=["check", "kill"])),
        ("AP SCAN",             dict(tool="aircrack-ng", interface=iface_mon,  mode="ap_scan",       args=["--band", "abg"])),
        ("CHANNEL SCAN",        dict(tool="aircrack-ng", interface=iface_mon,  mode="channel_scan",  args=["--channel", "6", "--bssid", "AA:BB:CC:DD:EE:FF"])),
        ("HANDSHAKE",           dict(tool="aircrack-ng", interface=iface_mon,  mode="handshake",     args=["--bssid", "AA:BB:CC:DD:EE:FF", "--channel", "6"])),
        ("DEAUTH (broadcast)",  dict(tool="aircrack-ng", interface=iface_mon,  mode="deauth",        args=["-a", "AA:BB:CC:DD:EE:FF", "-0", "10"])),
        ("DEAUTH (targeted)",   dict(tool="aircrack-ng", interface=iface_mon,  mode="deauth",        args=["-a", "AA:BB:CC:DD:EE:FF", "-c", "11:22:33:44:55:66", "-0", "5"])),
        ("WIFITE SCAN",         dict(tool="wifite",      interface=iface,      mode="wifite_scan",   args=["--kill"])),
        ("WIFITE ATTACK",       dict(tool="wifite",      interface=iface,      mode="wifite_attack", args=["--wpa", "--bssid", "AA:BB:CC:DD:EE:FF", "--dict", "/usr/share/wordlists/rockyou.txt"])),
        ("BETTERCAP SCAN",      dict(tool="bettercap",   interface=iface,      mode="bc_scan")),
        ("BETTERCAP DEAUTH",    dict(tool="bettercap",   interface=iface,      mode="bc_deauth",     args=["-eval", "wifi.deauth AA:BB:CC:DD:EE:FF"])),
        ("BETTERCAP EVIL TWIN", dict(tool="bettercap",   interface=iface,      mode="bc_ap",         args=["-eval", "set wifi.ap.ssid FreeWifi; wifi.ap on"])),
        ("KISMET PASSIVE",      dict(tool="kismet",      interface=iface,      mode="kismet_scan",   args=["-c", f"{iface}:channels=1,6,11"])),
        ("MONITOR OFF",         dict(tool="aircrack-ng", interface=iface_mon,  mode="monitor_off")),
    ]

    for label, kwargs in examples:
        r = wireless_scan(**kwargs)
        print(f"\n=== {label} ===")
        json.dump(r, sys.stdout, indent=2)
        print()