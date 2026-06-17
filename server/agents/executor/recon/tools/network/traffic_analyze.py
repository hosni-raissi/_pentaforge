#/+
"""
Traffic Analyzer — Agent Tool
==============================
Wraps tcpdump, tshark, and ngrep into a single structured, LLM-callable tool
with proper validation, credential detection, and resilient output parsing.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import shutil
import subprocess
import time
from collections import defaultdict
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# ══════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("traffic_analyzer")


# ══════════════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════════════

VALID_TOOLS = frozenset({"tcpdump", "tshark", "ngrep"})

# Predictable network interface names (Linux + macOS)
_INTERFACE_PATTERNS: list[re.Pattern] = [re.compile(p) for p in (
    r"^any$",                    # pseudo-interface
    r"^lo\d*$",                  # loopback
    r"^eth\d+$",                 # classic Ethernet
    r"^en\d+$",                  # macOS (en0, en1)
    r"^enp\d+s\d+(\w*)$",        # PCI Ethernet (enp3s0, enp3s0f1)
    r"^ens\d+$",                  # hotplug slot
    r"^eno\d+$",                  # on-board
    r"^wlan\d+$",                # legacy wireless
    r"^wlp\d+s\d+(\w*)$",        # PCI wireless (wlp0s20f3u1u2)
    r"^wlx[a-f0-9]+$",           # USB wireless
    r"^docker\d+$",
    r"^br-[a-f0-9]+$",
    r"^veth[a-f0-9]+$",
    r"^bond\d+(\.\d+)?$",        # bonded / VLAN
    r"^tun\d+$",
    r"^tap\d+$",
)]

_BPF_SAFE_KEYWORDS = frozenset({
    "host", "net", "port", "src", "dst", "tcp", "udp", "icmp",
    "and", "or", "not", "portrange", "proto", "ether", "ip", "ip6",
    "arp", "rarp", "vlan", "greater", "less", "broadcast", "multicast",
    "inbound", "outbound", "gateway",
})

_SHELL_DANGEROUS = frozenset({";", "&&", "||", "`", "$", "|", ">", "<", "()"})
_BLOCKED_FLAGS   = frozenset({"-w", "-W", "-G", "-z"})  # file-write flags


class TrafficCaptureRequest(BaseModel):
    tool: str
    interface: str = "any"
    capture_filter: Optional[str] = None
    display_filter: Optional[str] = None
    duration: int = Field(default=30, ge=5, le=300)
    packet_count: Optional[int] = Field(default=None, ge=1, le=10_000)
    args: list[str] = Field(default_factory=list)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in VALID_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(VALID_TOOLS)}")
        return v

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        if not any(p.fullmatch(v) for p in _INTERFACE_PATTERNS):
            raise ValueError(
                f"Interface '{v}' not recognised. "
                "Accepted: any, lo, eth0, en0, enp3s0, wlan0, wlp2s0, docker0, …"
            )
        return v

    @field_validator("capture_filter")
    @classmethod
    def validate_capture_filter(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        for ch in _SHELL_DANGEROUS:
            if ch in v:
                raise ValueError(f"Shell-dangerous character in capture_filter: {ch!r}")
        lower = v.lower()
        if v.strip() and not any(kw in lower for kw in _BPF_SAFE_KEYWORDS):
            raise ValueError(
                f"capture_filter must contain a BPF keyword. "
                f"Known keywords: {sorted(_BPF_SAFE_KEYWORDS)}"
            )
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        for arg in v:
            for ch in _SHELL_DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Shell-dangerous character {ch!r} in arg: {arg!r}")
            if arg.strip() in _BLOCKED_FLAGS:
                raise ValueError(f"File-output flag blocked: {arg!r}")
        return v

    @model_validator(mode="after")
    def warn_ignored_display_filter(self) -> "TrafficCaptureRequest":
        if self.display_filter and self.tool != "tshark":
            log.warning(
                "display_filter is only supported by tshark — "
                "it will be ignored for '%s'", self.tool
            )
        return self


# ── Result models ────────────────────────────────────────────────────

class Packet(BaseModel):
    timestamp: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    length: Optional[int] = None
    flags: Optional[str] = None
    info: Optional[str] = None
    payload: Optional[str] = None


class Credential(BaseModel):
    protocol: str
    username: Optional[str] = None
    password: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    timestamp: Optional[str] = None
    confidence: str = "high"
    raw_data: Optional[str] = None


class CleartextData(BaseModel):
    data_type: str
    protocol: str
    value: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    context: Optional[str] = None
    timestamp: Optional[str] = None


class TrafficAnalysisResult(BaseModel):
    """Minimal, agent-focused result for pentest operations."""
    success: bool
    tool: str
    interface: str
    command: str
    duration: float

    # Critical findings for agent
    credentials: list[Credential] = Field(default_factory=list)
    cleartext_data: list[CleartextData] = Field(default_factory=list)
    suspicious_patterns: list[dict[str, Any]] = Field(default_factory=list)

    # Network topology (for targeting)
    top_sources: list[dict[str, Any]] = Field(default_factory=list)
    top_destinations: list[dict[str, Any]] = Field(default_factory=list)
    top_conversations: list[dict[str, Any]] = Field(default_factory=list)

    # Statistics (optional/debug)
    total_packets: int = 0
    total_bytes: int = 0
    protocols: dict[str, int] = Field(default_factory=dict)

    # Error handling
    error: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════
# 2. CREDENTIAL DETECTOR
# ══════════════════════════════════════════════════════════════════════

# Pre-compiled patterns — compiled once at import time
_CRED_PATTERNS: dict[str, dict[str, re.Pattern]] = {
    "ftp": {
        "user": re.compile(rb"USER\s+([^\r\n]+)", re.IGNORECASE),
        "pass": re.compile(rb"PASS\s+([^\r\n]+)", re.IGNORECASE),
    },
    "http": {
        "basic_auth":  re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE),
        "form_user":   re.compile(rb"(?:username|user|login|email)=([^&\s]{1,128})", re.IGNORECASE),
        "form_pass":   re.compile(rb"(?:password|passwd|pwd)=([^&\s]{1,128})", re.IGNORECASE),
    },
    "smtp": {
        "auth_plain": re.compile(rb"AUTH PLAIN\s+([A-Za-z0-9+/=]+)", re.IGNORECASE),
        "auth_login": re.compile(rb"AUTH LOGIN\s+([A-Za-z0-9+/=]+)", re.IGNORECASE),
    },
    "pop3": {
        "user": re.compile(rb"USER\s+([^\r\n]+)", re.IGNORECASE),
        "pass": re.compile(rb"PASS\s+([^\r\n]+)", re.IGNORECASE),
    },
    "telnet": {
        "login":    re.compile(rb"login:\s*([^\r\n]{1,64})",    re.IGNORECASE),
        "password": re.compile(rb"Password:\s*([^\r\n]{1,64})", re.IGNORECASE),
    },
    "snmp": {
        "community": re.compile(rb"community=([^\s]{1,64})", re.IGNORECASE),
    },
}

_CLEARTEXT_PATTERNS: dict[str, re.Pattern] = {
    "cookie":         re.compile(rb"Cookie:\s*([^\r\n]{1,512})",                          re.IGNORECASE),
    "set_cookie":     re.compile(rb"Set-Cookie:\s*([^\r\n]{1,512})",                      re.IGNORECASE),
    "api_key":        re.compile(rb"(?:api[_-]?key|apikey|access[_-]?token)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,80})", re.IGNORECASE),
    "bearer_token":   re.compile(rb"Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)",  re.IGNORECASE),
    "jwt":            re.compile(rb"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"),
    "aws_key":        re.compile(rb"(AKIA[0-9A-Z]{16})"),
    "private_key":    re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "password_param": re.compile(rb"(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\s&\"']{3,64})", re.IGNORECASE),
}

_UNENCRYPTED_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP"}


def _decode(b: bytes) -> str:
    return b.decode("utf-8", errors="ignore").strip()


def _b64_decode(data: str) -> Optional[str]:
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError) as exc:
        log.debug("Base64 decode failed: %s", exc)
        return None


class CredentialDetector:
    """Extract credentials from raw packet payload bytes."""

    @staticmethod
    def detect(
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: str,
    ) -> list[Credential]:
        if not payload:
            return []

        results: list[Credential] = []
        common = dict(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, timestamp=timestamp)

        # ── FTP ──────────────────────────────────────────────────────
        if dst_port == 21 or b"USER " in payload or b"PASS " in payload:
            if m := _CRED_PATTERNS["ftp"]["user"].search(payload):
                results.append(Credential(protocol="FTP", username=_decode(m.group(1)), confidence="high", **common))
            if m := _CRED_PATTERNS["ftp"]["pass"].search(payload):
                results.append(Credential(
                    protocol="FTP", password=_decode(m.group(1)), confidence="high",
                    raw_data=_decode(payload[:200]), **common,
                ))

        # ── HTTP ─────────────────────────────────────────────────────
        if dst_port in {80, 8080, 8000, 8888} or b"HTTP" in payload:
            if m := _CRED_PATTERNS["http"]["basic_auth"].search(payload):
                decoded = _b64_decode(_decode(m.group(1)))
                if decoded and ":" in decoded:
                    username, password = decoded.split(":", 1)
                    results.append(Credential(
                        protocol="HTTP Basic Auth",
                        username=username, password=password, confidence="high", **common,
                    ))

            um = _CRED_PATTERNS["http"]["form_user"].search(payload)
            pm = _CRED_PATTERNS["http"]["form_pass"].search(payload)
            if um or pm:
                results.append(Credential(
                    protocol="HTTP Form",
                    username=_decode(um.group(1)) if um else None,
                    password=_decode(pm.group(1)) if pm else None,
                    confidence="medium", **common,
                ))

        # ── SMTP ─────────────────────────────────────────────────────
        if dst_port in {25, 587} or b"SMTP" in payload:
            if m := _CRED_PATTERNS["smtp"]["auth_plain"].search(payload):
                decoded = _b64_decode(_decode(m.group(1)))
                if decoded:
                    parts = decoded.split("\x00")
                    if len(parts) >= 3:
                        results.append(Credential(
                            protocol="SMTP AUTH PLAIN",
                            username=parts[1], password=parts[2], confidence="high", **common,
                        ))

        # ── POP3 ─────────────────────────────────────────────────────
        if dst_port == 110 or b"POP3" in payload:
            if m := _CRED_PATTERNS["pop3"]["user"].search(payload):
                results.append(Credential(protocol="POP3", username=_decode(m.group(1)), confidence="high", **common))
            if m := _CRED_PATTERNS["pop3"]["pass"].search(payload):
                results.append(Credential(protocol="POP3", password=_decode(m.group(1)), confidence="high", **common))

        # ── Telnet ───────────────────────────────────────────────────
        if dst_port == 23 or b"login:" in payload.lower():
            if m := _CRED_PATTERNS["telnet"]["login"].search(payload):
                results.append(Credential(protocol="Telnet", username=_decode(m.group(1)), confidence="medium", **common))
            if m := _CRED_PATTERNS["telnet"]["password"].search(payload):
                results.append(Credential(protocol="Telnet", password=_decode(m.group(1)), confidence="medium", **common))

        # ── SNMP ─────────────────────────────────────────────────────
        if dst_port == 161 or b"community" in payload.lower():
            if m := _CRED_PATTERNS["snmp"]["community"].search(payload):
                results.append(Credential(protocol="SNMP Community", password=_decode(m.group(1)), confidence="high", **common))

        return results


class CleartextDetector:
    """Extract sensitive cleartext values from raw payload bytes."""

    @staticmethod
    def detect(
        payload: bytes,
        protocol: str,
        src_ip: str,
        dst_ip: str,
        timestamp: str,
    ) -> list[CleartextData]:
        if not payload:
            return []

        proto = protocol or "HTTP"
        common = dict(protocol=proto, src_ip=src_ip, dst_ip=dst_ip, timestamp=timestamp)
        results: list[CleartextData] = []

        for m in _CLEARTEXT_PATTERNS["cookie"].finditer(payload):
            results.append(CleartextData(data_type="Cookie", value=_decode(m.group(1))[:200], context="HTTP Request", **common))

        for m in _CLEARTEXT_PATTERNS["set_cookie"].finditer(payload):
            results.append(CleartextData(data_type="Set-Cookie", value=_decode(m.group(1))[:200], context="HTTP Response", **common))

        for m in _CLEARTEXT_PATTERNS["api_key"].finditer(payload):
            results.append(CleartextData(data_type="API Key", value=_decode(m.group(1))[:80], **common))

        for m in _CLEARTEXT_PATTERNS["bearer_token"].finditer(payload):
            results.append(CleartextData(data_type="Bearer Token", value=_decode(m.group(1))[:80], **common))

        for m in _CLEARTEXT_PATTERNS["jwt"].finditer(payload):
            results.append(CleartextData(data_type="JWT Token", value=_decode(m.group(1))[:80] + "…", **common))

        for m in _CLEARTEXT_PATTERNS["aws_key"].finditer(payload):
            results.append(CleartextData(data_type="AWS Access Key", value=_decode(m.group(1)), **common))

        if _CLEARTEXT_PATTERNS["private_key"].search(payload):
            results.append(CleartextData(data_type="Private Key", value="[PRIVATE KEY DETECTED]", **common))

        return results


# ══════════════════════════════════════════════════════════════════════
# 3. PARSERS
# ══════════════════════════════════════════════════════════════════════

# tcpdump examples:
# "12:34:56.789 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], length 0"
# "12:34:56.789 IP6 2a02::1.1234 > 2a00::2.443: Flags [P.], length 19"
# "12:34:56.789 IP 10.0.0.1.1234 > 10.0.0.2.443: UDP, length 128"
_TCPDUMP_RE = re.compile(
    r"(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?:(?P<iface>\S+)\s+(?:(?P<direction>In|Out)\s+)?)?"
    r"(?P<net_proto>IP6?|ARP)\s+"
    r"(?P<src>.+?)\s+>\s+(?P<dst>.+?):\s+"
    r"(?:(?:Flags\s+\[(?P<flags>[^\]]*)\].*?)|(?P<udp>UDP,\s*))?"
    r"length\s+(?P<length>\d+)"
)

# ngrep header: "T 10.0.0.1:80 -> 10.0.0.2:12345 [AP]"
_NGREP_RE = re.compile(
    r"(?P<proto>[TU])\s+(?P<src_ip>[^:]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[^:]+):(?P<dst_port>\d+)\s+\[(?P<flags>[^\]]*)\]"
)

ParsedStats = dict[str, defaultdict]


def _empty_stats() -> ParsedStats:
    return {
        "protocols":     defaultdict(int),
        "src_ips":       defaultdict(int),
        "dst_ips":       defaultdict(int),
        "conversations": defaultdict(int),
    }


def _update_stats(stats: ParsedStats, p: Packet) -> None:
    if p.protocol:
        stats["protocols"][p.protocol] += 1
    if p.src_ip:
        stats["src_ips"][p.src_ip] += 1
    if p.dst_ip:
        stats["dst_ips"][p.dst_ip] += 1
    if p.src_ip and p.dst_ip:
        key = f"{p.src_ip}:{p.src_port or 0} <-> {p.dst_ip}:{p.dst_port or 0}"
        stats["conversations"][key] += 1


def _split_tcpdump_endpoint(endpoint: str) -> tuple[Optional[str], Optional[int]]:
    """
    Split tcpdump endpoint strings like:
      192.168.1.10.443
      2a02::1.443
    into (host, port).
    """
    value = str(endpoint or "").strip()
    if not value or "." not in value:
        return value or None, None
    host, maybe_port = value.rsplit(".", 1)
    if maybe_port.isdigit():
        return host, int(maybe_port)
    return value, None


def _set_packet_payload(packet: Optional[Packet], payload_lines: list[str], limit: int = 1_200) -> None:
    """Attach a bounded payload preview to a parsed packet."""
    if packet is None or not payload_lines:
        return
    payload = "\n".join(line.rstrip() for line in payload_lines).strip()
    if not payload:
        return
    if len(payload) > limit:
        payload = payload[:limit] + "\n...[TRUNCATED]..."
    packet.payload = payload


def parse_tcpdump(stdout: str) -> tuple[list[Packet], ParsedStats]:
    """
    tcpdump writes packet data to stdout (when not using -w).
    The summary line goes to stderr — these must NOT be mixed.
    Only stdout is passed here.
    """
    packets: list[Packet] = []
    stats = _empty_stats()
    current: Optional[Packet] = None
    payload_lines: list[str] = []

    def _flush() -> None:
        nonlocal current, payload_lines
        if current is None:
            payload_lines = []
            return
        _set_packet_payload(current, payload_lines)
        packets.append(current)
        _update_stats(stats, current)
        current = None
        payload_lines = []

    for line in stdout.splitlines():
        m = _TCPDUMP_RE.search(line)
        if m:
            _flush()
            src_ip, src_port = _split_tcpdump_endpoint(m.group("src"))
            dst_ip, dst_port = _split_tcpdump_endpoint(m.group("dst"))
            if not src_ip or not dst_ip:
                continue
            transport = "UDP" if m.group("udp") else "TCP" if m.group("flags") is not None else m.group("net_proto")
            current = Packet(
                timestamp=m.group("ts"),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=transport,
                length=int(m.group("length")),
                flags=m.group("flags"),
                info=line.strip(),
            )
            continue
        if current is not None and line.strip():
            payload_lines.append(line)

    _flush()

    return packets, stats


def _packet_from_tshark_record(data: Any) -> Optional[Packet]:
    if not isinstance(data, dict):
        return None

    layers = data.get("_source", {}).get("layers", {})
    if not isinstance(layers, dict):
        return None

    frame = layers.get("frame", {})
    ip = layers.get("ip", {})
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})

    if not isinstance(frame, dict):
        frame = {}
    if not isinstance(ip, dict):
        ip = {}
    if not isinstance(tcp, dict):
        tcp = {}
    if not isinstance(udp, dict):
        udp = {}

    if tcp:
        protocol = "TCP"
        src_port = int(tcp.get("tcp.srcport", 0))
        dst_port = int(tcp.get("tcp.dstport", 0))
        flags = tcp.get("tcp.flags", None)
    elif udp:
        protocol = "UDP"
        src_port = int(udp.get("udp.srcport", 0))
        dst_port = int(udp.get("udp.dstport", 0))
        flags = None
    else:
        protocol = "Other"
        src_port = dst_port = None
        flags = None

    src_ip = ip.get("ip.src") or None
    dst_ip = ip.get("ip.dst") or None

    return Packet(
        timestamp=frame.get("frame.time", ""),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=int(frame.get("frame.len", 0)),
        flags=flags,
    )


def parse_tshark_json(stdout: str) -> tuple[list[Packet], ParsedStats]:
    packets: list[Packet] = []
    stats = _empty_stats()

    def _append_record(record: Any) -> None:
        if isinstance(record, list):
            for item in record:
                _append_record(item)
            return

        packet = _packet_from_tshark_record(record)
        if packet is None:
            return
        packets.append(packet)
        _update_stats(stats, packet)

    text = stdout.strip()
    if not text:
        return packets, stats

    try:
        parsed = json.loads(text)
        _append_record(parsed)
        return packets, stats
    except json.JSONDecodeError:
        pass

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            log.debug("tshark JSON parse error: %s", exc)
            continue
        _append_record(parsed)

    return packets, stats


def parse_ngrep(stdout: str) -> tuple[list[Packet], ParsedStats]:
    packets: list[Packet] = []
    stats = _empty_stats()

    current: Optional[Packet] = None
    payload_lines: list[str] = []

    def _flush() -> None:
        _set_packet_payload(current, payload_lines)

    for line in stdout.splitlines():
        m = _NGREP_RE.search(line)
        if m:
            _flush()
            if current is not None:
                packets.append(current)
                _update_stats(stats, current)

            payload_lines = []
            proto = "TCP" if m.group("proto") == "T" else "UDP"
            current = Packet(
                src_ip=m.group("src_ip"),
                dst_ip=m.group("dst_ip"),
                src_port=int(m.group("src_port")),
                dst_port=int(m.group("dst_port")),
                protocol=proto,
                flags=m.group("flags"),
            )
        elif current is not None and line.strip() and not line.startswith("#"):
            payload_lines.append(line.strip())

    _flush()
    if current is not None:
        packets.append(current)
        _update_stats(stats, current)

    return packets, stats


# ══════════════════════════════════════════════════════════════════════
# 4. ANALYZER  (single pass — no double-counting)
# ══════════════════════════════════════════════════════════════════════

def analyze_packets(packets: list[Packet]) -> dict[str, list]:
    """
    Run credential and cleartext detection over parsed packets only.
    Does NOT re-scan raw stdout — avoids double-counting every finding.
    """
    credentials: list[Credential] = []
    cleartext: list[CleartextData] = []
    suspicious: list[dict] = []
    seen_suspicious: set[str] = set()

    for p in packets:
        payload_bytes = (p.payload or "").encode("utf-8", errors="ignore")

        if payload_bytes:
            credentials.extend(CredentialDetector.detect(
                payload_bytes,
                p.src_ip or "", p.dst_ip or "",
                p.dst_port or 0, p.timestamp or "",
            ))
            cleartext.extend(CleartextDetector.detect(
                payload_bytes,
                p.protocol or "",
                p.src_ip or "", p.dst_ip or "",
                p.timestamp or "",
            ))

        # Unencrypted protocol alert — deduplicated by (src, dst, port)
        if p.dst_port in _UNENCRYPTED_PORTS:
            key = f"{p.src_ip}>{p.dst_ip}:{p.dst_port}"
            if key not in seen_suspicious:
                seen_suspicious.add(key)
                suspicious.append({
                    "type":        "Unencrypted Protocol",
                    "protocol":    _UNENCRYPTED_PORTS[p.dst_port],
                    "description": f"Cleartext {_UNENCRYPTED_PORTS[p.dst_port]} traffic",
                    "src_ip":      p.src_ip,
                    "dst_ip":      p.dst_ip,
                    "dst_port":    p.dst_port,
                    "severity":    "medium",
                })

    return {
        "credentials":         credentials,
        "cleartext_data":      cleartext,
        "suspicious_patterns": suspicious,
    }


# ══════════════════════════════════════════════════════════════════════
# 5. EXECUTOR
# ══════════════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 310) -> tuple[str, str, int]:
    """Run a subprocess with shell=False. Returns (stdout, stderr, returncode)."""
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
        log.warning("Command timed out: %s", cmd[0])
        return "", f"Timed out after {timeout}s", -1
    except PermissionError:
        return "", "Permission denied — packet capture requires root/sudo", -1
    except FileNotFoundError:
        return "", f"Tool not installed or not in PATH: '{cmd[0]}'", -1
    except Exception as exc:  # noqa: BLE001
        return "", str(exc), -1


def _prefix_sudo(cmd: list[str]) -> list[str]:
    """
    Use sudo for packet-capture tools when we are not already root.

    Plain `sudo` lets the operator authenticate in an interactive terminal during
    manual testing. If the process is already running as root, the command is left
    unchanged.
    """
    try:
        if os.name != "nt" and os.geteuid() != 0:
            return ["sudo", *cmd]
    except AttributeError:
        pass
    return cmd


def _wrap_duration(cmd: list[str], req: TrafficCaptureRequest) -> list[str]:
    """
    Enforce capture duration for tools that otherwise run until interrupted.

    tshark already has native `-a duration:N` support, so this wrapper is only
    needed for tcpdump and ngrep when packet_count is not being used.
    """
    if req.packet_count or req.tool == "tshark":
        return cmd
    if shutil.which("timeout") is None:
        log.warning(
            "GNU timeout not found in PATH; relying on outer subprocess timeout for %s",
            req.tool,
        )
        return cmd
    return ["timeout", "--signal=INT", str(req.duration), *cmd]


def _is_expected_duration_exit(req: TrafficCaptureRequest, rc: int) -> bool:
    """
    `timeout --signal=INT` returns a non-zero status when it stops tcpdump/ngrep
    after the requested duration. Treat that as a normal completion.
    """
    return (
        req.tool in {"tcpdump", "ngrep"}
        and req.packet_count is None
        and rc in {124, 130}
    )


# ══════════════════════════════════════════════════════════════════════
# 6. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════════════

def _build_tcpdump(req: TrafficCaptureRequest) -> list[str]:
    cmd = ["tcpdump", "-i", req.interface, "-l"]  # -l = line-buffered stdout
    if req.packet_count:
        cmd += ["-c", str(req.packet_count)]
    if "-X" not in req.args and "-A" not in req.args:
        cmd.append("-A")           # ASCII payload by default
    if req.capture_filter:
        cmd.append(req.capture_filter)
    cmd += req.args
    return cmd


def _build_tshark(req: TrafficCaptureRequest) -> list[str]:
    cmd = ["tshark", "-i", req.interface]
    if req.packet_count:
        cmd += ["-c", str(req.packet_count)]
    else:
        cmd += ["-a", f"duration:{req.duration}"]
    if req.capture_filter:
        cmd += ["-f", req.capture_filter]
    if req.display_filter:
        cmd += ["-Y", req.display_filter]
    if "-T" not in " ".join(req.args):
        cmd += ["-T", "json"]      # structured output for parsing
    cmd += req.args
    return cmd


def _build_ngrep(req: TrafficCaptureRequest) -> list[str]:
    cmd = ["ngrep", "-d", req.interface]
    if req.packet_count:
        cmd += ["-n", str(req.packet_count)]
    cmd += req.args
    if req.capture_filter:
        cmd.append(req.capture_filter)
    return cmd


_BUILDERS = {
    "tcpdump": _build_tcpdump,
    "tshark":  _build_tshark,
    "ngrep":   _build_ngrep,
}

_PARSERS = {
    "tcpdump": parse_tcpdump,
    "tshark":  parse_tshark_json,
    "ngrep":   parse_ngrep,
}


# ══════════════════════════════════════════════════════════════════════
# 7. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════════════

RAW_OUTPUT_LIMIT = 5_000   # chars returned to LLM
SAMPLE_PKT_LIMIT = 50      # packets included in result


def traffic_analyze(
    tool: str,
    interface: str = "any",
    capture_filter: Optional[str] = None,
    display_filter: Optional[str] = None,
    duration: int = 30,
    packet_count: Optional[int] = None,
    args: Optional[list[str]] = None,
) -> dict:
    """
    Agent Tool — Traffic Analyzer

    Capture and analyze live network traffic using tcpdump, tshark, or ngrep.
    Detects cleartext credentials, sensitive data, and unencrypted protocols.

    Args:
        tool:           "tcpdump" | "tshark" | "ngrep"
        interface:      Network interface (any, eth0, en0, wlan0, enp3s0, …)
        capture_filter: BPF filter  — e.g. "tcp port 80", "host 10.0.0.1"
        display_filter: Wireshark display filter (tshark only)
        duration:       Seconds to capture (5-300)
        packet_count:   Stop after N packets (overrides duration)
        args:           Extra CLI flags forwarded to the tool

    Returns:
        TrafficAnalysisResult dict.
    """
    if args is None:
        args = []

    start = time.perf_counter()

    # ── Validate ──────────────────────────────────────────────────────
    try:
        req = TrafficCaptureRequest(
            tool=tool,
            interface=interface,
            capture_filter=capture_filter,
            display_filter=display_filter,
            duration=duration,
            packet_count=packet_count,
            args=args,
        )
    except Exception as exc:
        return TrafficAnalysisResult(
            success=False, tool=tool, interface=interface,
            command="", duration=0.0, error=str(exc),
        ).model_dump()

    # ── Build command ─────────────────────────────────────────────────
    cmd = _prefix_sudo(_wrap_duration(_BUILDERS[req.tool](req), req))
    command_str = " ".join(cmd)

    # ── Execute ───────────────────────────────────────────────────────
    # Add headroom so subprocess timeout > capture duration
    timeout = req.duration + 15
    stdout, stderr, rc = safe_execute(cmd, timeout)

    elapsed = round(time.perf_counter() - start, 3)

    # ── Parse (stdout only — stderr is never packet data) ─────────────
    packets, stats = _PARSERS[req.tool](stdout)

    # ── Analyze (single pass, no double-counting) ─────────────────────
    analysis = analyze_packets(packets)

    # ── Aggregate stats ───────────────────────────────────────────────
    def _top(counter: defaultdict, n: int = 10) -> list[dict]:
        return [
            {"ip": k, "packets": v}
            for k, v in sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]
        ]

    def _top_conv(counter: defaultdict, n: int = 10) -> list[dict]:
        return [
            {"conversation": k, "packets": v}
            for k, v in sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]
        ]

    total_bytes = sum(p.length or 0 for p in packets)
    has_results = bool(packets)
    expected_duration_exit = _is_expected_duration_exit(req, rc)
    success = has_results or rc == 0 or expected_duration_exit
    error = stderr.strip() if (rc != 0 and not has_results and not expected_duration_exit) else None

    return TrafficAnalysisResult(
        success=success,
        tool=req.tool,
        interface=req.interface,
        command=command_str,
        duration=elapsed,
        total_packets=len(packets),
        total_bytes=total_bytes,
        protocols=dict(stats["protocols"]),
        top_sources=_top(stats["src_ips"]),
        top_destinations=_top(stats["dst_ips"]),
        top_conversations=_top_conv(stats["conversations"]),
        credentials=analysis["credentials"],
        cleartext_data=analysis["cleartext_data"],
        suspicious_patterns=analysis["suspicious_patterns"],
        error=error,
    ).model_dump()


# ══════════════════════════════════════════════════════════════════════
# 8. LLM TOOL DEFINITION
# ══════════════════════════════════════════════════════════════════════

TRAFFIC_ANALYZE_TOOL_DEFINITION: dict = {
    "name": "traffic_analyze",
    "description": (
        "Capture and analyze live network traffic. "
        "Detects cleartext credentials (FTP, HTTP, SMTP, POP3, Telnet, SNMP), "
        "sensitive data (cookies, JWTs, API keys, AWS keys, bearer tokens, private keys), "
        "and unencrypted protocol usage. "
        "Supports tcpdump (fast, BPF), tshark (full dissection, JSON), "
        "and ngrep (regex payload matching)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": sorted(VALID_TOOLS),
                "description": (
                    "tcpdump — fast capture, BPF filters, minimal overhead. "
                    "tshark  — full Wireshark protocol dissection, JSON output. "
                    "ngrep   — regex-based payload search."
                ),
            },
            "interface": {
                "type": "string",
                "description": "Network interface: any, eth0, en0, wlan0, enp3s0, …",
                "default": "any",
            },
            "capture_filter": {
                "type": "string",
                "description": (
                    "BPF capture filter. Examples: "
                    "'tcp port 80' | 'host 192.168.1.1' | "
                    "'tcp port 21 or tcp port 23' | 'not port 22' | "
                    "'src net 10.0.0.0/8'"
                ),
            },
            "display_filter": {
                "type": "string",
                "description": (
                    "Wireshark display filter (tshark only). Examples: "
                    "'http.request.method == POST' | "
                    "'ftp.request.command == PASS' | "
                    "'http.cookie' | 'http.authorization'"
                ),
            },
            "duration": {
                "type": "integer",
                "description": "Capture duration in seconds (5-300). Ignored when packet_count is set.",
                "default": 30,
            },
            "packet_count": {
                "type": "integer",
                "description": "Stop after N packets (1-10000). Overrides duration.",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Extra CLI flags. "
                    "tcpdump: ['-v'] ['-X'] (hex+ASCII) | "
                    "tshark:  ['-V'] ['-O', 'http'] | "
                    "ngrep:   ['-q', 'password'] ['-W', 'byline']"
                ),
            },
        },
        "required": ["tool"],
    },
}


# ══════════════════════════════════════════════════════════════════════
# 9. DEMO  (requires root — replace IFACE with an interface you own)
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    IFACE = "any"   # change to your interface

    demos: list[tuple[str, dict]] = [
        ("HTTPS browser traffic (tcpdump)", dict(tool="tcpdump", interface=IFACE, capture_filter="port 443", duration=10)),
        ("FTP credentials (tshark)", dict(tool="tshark",  interface=IFACE, capture_filter="tcp port 21", display_filter="ftp", duration=10)),
        ("Password grep (ngrep)",    dict(tool="ngrep",   interface=IFACE, args=["-q", "-i", "password"], duration=10)),
    ]

    for label, kwargs in demos:
        print(f"\n{'=' * 60}\n  {label}\n{'=' * 60}")
        result = traffic_analyze(**kwargs)
        print(f"  success       : {result['success']}")
        print(f"  command       : {result['command']}")
        print(f"  duration      : {result['duration']}s")
        print(f"  total_packets : {result['total_packets']}")
        print(f"  protocols     : {result['protocols']}")

        if result["credentials"]:
            print(f"  📌 CREDENTIALS ({len(result['credentials'])}):")
            for c in result["credentials"]:
                print(f"    [{c['protocol']}] user={c.get('username')} pass={c.get('password')}")
        else:
            print(f"  ✓ No credentials detected")

        if result["cleartext_data"]:
            print(f"  📌 CLEARTEXT DATA ({len(result['cleartext_data'])}):")
            for d in result["cleartext_data"]:
                print(f"    [{d['data_type']}] {d['value'][:80]}")
        else:
            print(f"  ✓ No cleartext data detected")

        if result["suspicious_patterns"]:
            print(f"  ⚠️  SUSPICIOUS PATTERNS ({len(result['suspicious_patterns'])}):")
            for sp in result["suspicious_patterns"]:
                print(f"    [{sp['severity']}] {sp['type']}: {sp['description']}")
        else:
            print(f"  ✓ No suspicious patterns")

        if result["top_sources"]:
            print(f"  🔍 TOP SOURCES (top 5):")
            for src in result["top_sources"][:5]:
                print(f"    {src['ip']}: {src['packets']} packets")

        if result["error"]:
            print(f"  ❌ ERROR: {result['error']}")
