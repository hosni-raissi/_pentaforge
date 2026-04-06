import subprocess
import json
import re
import time
import base64
from typing import Optional, Any
from pydantic import BaseModel, Field, validator
from collections import defaultdict
import hashlib


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class TrafficCaptureRequest(BaseModel):
    tool: str
    interface: str = "any"
    capture_filter: Optional[str] = None
    display_filter: Optional[str] = None
    duration: int = Field(default=30, ge=5, le=300)  # 5s to 5min
    packet_count: Optional[int] = Field(default=None, ge=1, le=10000)
    args: list[str] = []
    
    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"tcpdump", "tshark", "ngrep"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v
    
    @validator("interface")
    def validate_interface(cls, v):
        # Allow common interfaces + "any"
        allowed_patterns = [
            r"^eth\d+$",
            r"^en[ops]\d+$",
            r"^wlan\d+$",
            r"^wlp\d+s\d+$",
            r"^lo$",
            r"^any$",
            r"^br-[a-f0-9]+$",
            r"^docker\d+$",
            r"^veth[a-f0-9]+$",
        ]
        
        if not any(re.match(p, v) for p in allowed_patterns):
            raise ValueError(f"Interface '{v}' not allowed")
        return v
    
    @validator("capture_filter")
    def validate_capture_filter(cls, v):
        if v is None:
            return v
        
        # Block dangerous BPF syntax
        dangerous = [";", "&&", "||", "`", "$", "|", ">", "<", "()", "exec"]
        for d in dangerous:
            if d in v:
                raise ValueError(f"Dangerous pattern in filter: {d}")
        
        # Only allow safe BPF keywords
        safe_keywords = [
            "host", "net", "port", "src", "dst", "tcp", "udp", "icmp",
            "and", "or", "not", "portrange", "proto", "ether", "ip", "ip6",
            "arp", "rarp", "vlan", "greater", "less"
        ]
        
        # Basic validation: check if filter uses known keywords
        filter_lower = v.lower()
        has_safe_keyword = any(kw in filter_lower for kw in safe_keywords)
        
        if not has_safe_keyword and v.strip():
            raise ValueError(f"Filter must use BPF keywords: {safe_keywords}")
        
        return v
    
    @validator("args")
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags = ["-w", "-W", "-G", "-z"]  # Block file writes
        
        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"File output blocked: {arg}")
        
        return v


class Packet(BaseModel):
    """Individual packet info"""
    timestamp: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    length: Optional[int] = None
    info: Optional[str] = None
    payload: Optional[str] = None
    flags: Optional[str] = None


class Credential(BaseModel):
    """Detected credential"""
    protocol: str
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    timestamp: Optional[str] = None
    confidence: str = "high"  # high, medium, low
    raw_data: Optional[str] = None


class CleartextData(BaseModel):
    """Cleartext sensitive data"""
    data_type: str  # cookie, token, api_key, password, etc.
    protocol: str
    value: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    context: Optional[str] = None
    timestamp: Optional[str] = None


class ProtocolStats(BaseModel):
    """Protocol statistics"""
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    unique_ips: set = Field(default_factory=set)
    ports: set = Field(default_factory=set)
    
    class Config:
        arbitrary_types_allowed = True


class TrafficAnalysisResult(BaseModel):
    """Final result"""
    success: bool
    tool: str
    interface: str
    command: str
    duration: float
    total_packets: int = 0
    total_bytes: int = 0
    
    # Protocol breakdown
    protocols: dict[str, int] = {}  # {TCP: 150, UDP: 30, ...}
    
    # Top talkers
    top_sources: list[dict[str, Any]] = []
    top_destinations: list[dict[str, Any]] = []
    top_conversations: list[dict[str, Any]] = []
    
    # Security findings
    credentials: list[Credential] = []
    cleartext_data: list[CleartextData] = []
    suspicious_patterns: list[dict[str, Any]] = []
    
    # Sample packets
    sample_packets: list[Packet] = []
    
    # Raw output (limited)
    raw_output: Optional[str] = None
    error: Optional[str] = None
    
    class Config:
        arbitrary_types_allowed = True


# ══════════════════════════════════════════════════════════════
# 2. CREDENTIAL & CLEARTEXT DETECTORS
# ══════════════════════════════════════════════════════════════

class CredentialDetector:
    """Detect credentials in packet payloads"""
    
    # Protocol patterns
    PATTERNS = {
        "ftp": {
            "user": rb"USER\s+([^\r\n]+)",
            "pass": rb"PASS\s+([^\r\n]+)"
        },
        "http": {
            "basic_auth": rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)",
            "form_user": rb"(?:username|user|login|email)=([^&\s]+)",
            "form_pass": rb"(?:password|passwd|pwd)=([^&\s]+)",
        },
        "smtp": {
            "auth_plain": rb"AUTH PLAIN\s+([A-Za-z0-9+/=]+)",
            "auth_login": rb"AUTH LOGIN\s+([A-Za-z0-9+/=]+)",
        },
        "pop3": {
            "user": rb"USER\s+([^\r\n]+)",
            "pass": rb"PASS\s+([^\r\n]+)"
        },
        "imap": {
            "login": rb"LOGIN\s+([^\r\n]+)\s+([^\r\n]+)"
        },
        "telnet": {
            "login": rb"login:\s*([^\r\n]+)",
            "password": rb"Password:\s*([^\r\n]+)"
        },
        "snmp": {
            "community": rb"community=([^\s]+)"
        },
    }
    
    @staticmethod
    def detect(payload: bytes, protocol: str, src_ip: str, dst_ip: str, dst_port: int, timestamp: str) -> list[Credential]:
        """Detect credentials in payload"""
        credentials = []
        
        if not payload:
            return credentials
        
        protocol_lower = protocol.lower() if protocol else ""
        
        # ══════════════════════════════
        # FTP
        # ══════════════════════════════
        if dst_port == 21 or b"USER " in payload or b"PASS " in payload:
            if match := re.search(CredentialDetector.PATTERNS["ftp"]["user"], payload, re.IGNORECASE):
                username = match.group(1).decode('utf-8', errors='ignore').strip()
                credentials.append(Credential(
                    protocol="FTP",
                    username=username,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    confidence="high"
                ))
            
            if match := re.search(CredentialDetector.PATTERNS["ftp"]["pass"], payload, re.IGNORECASE):
                password = match.group(1).decode('utf-8', errors='ignore').strip()
                credentials.append(Credential(
                    protocol="FTP",
                    password=password,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    confidence="high",
                    raw_data=payload[:200].decode('utf-8', errors='ignore')
                ))
        
        # ══════════════════════════════
        # HTTP
        # ══════════════════════════════
        if dst_port in [80, 8080, 8000, 8888] or b"HTTP" in payload:
            # Basic Auth
            if match := re.search(CredentialDetector.PATTERNS["http"]["basic_auth"], payload, re.IGNORECASE):
                b64_creds = match.group(1).decode('utf-8', errors='ignore')
                try:
                    decoded = base64.b64decode(b64_creds).decode('utf-8', errors='ignore')
                    if ":" in decoded:
                        username, password = decoded.split(":", 1)
                        credentials.append(Credential(
                            protocol="HTTP Basic Auth",
                            username=username,
                            password=password,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            timestamp=timestamp,
                            confidence="high"
                        ))
                except:
                    pass
            
            # Form credentials
            username_match = re.search(CredentialDetector.PATTERNS["http"]["form_user"], payload, re.IGNORECASE)
            password_match = re.search(CredentialDetector.PATTERNS["http"]["form_pass"], payload, re.IGNORECASE)
            
            if username_match or password_match:
                cred = Credential(
                    protocol="HTTP Form",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    confidence="medium"
                )
                
                if username_match:
                    cred.username = username_match.group(1).decode('utf-8', errors='ignore')
                if password_match:
                    cred.password = password_match.group(1).decode('utf-8', errors='ignore')
                
                credentials.append(cred)
        
        # ══════════════════════════════
        # SMTP
        # ══════════════════════════════
        if dst_port in [25, 587] or b"SMTP" in payload:
            if match := re.search(CredentialDetector.PATTERNS["smtp"]["auth_plain"], payload, re.IGNORECASE):
                b64_auth = match.group(1).decode('utf-8', errors='ignore')
                try:
                    decoded = base64.b64decode(b64_auth).decode('utf-8', errors='ignore')
                    parts = decoded.split('\x00')
                    if len(parts) >= 3:
                        credentials.append(Credential(
                            protocol="SMTP AUTH PLAIN",
                            username=parts[1] if len(parts) > 1 else None,
                            password=parts[2] if len(parts) > 2 else None,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            timestamp=timestamp,
                            confidence="high"
                        ))
                except:
                    pass
        
        # ══════════════════════════════
        # POP3
        # ══════════════════════════════
        if dst_port == 110 or b"POP3" in payload:
            if match := re.search(CredentialDetector.PATTERNS["pop3"]["user"], payload, re.IGNORECASE):
                credentials.append(Credential(
                    protocol="POP3",
                    username=match.group(1).decode('utf-8', errors='ignore').strip(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    confidence="high"
                ))
            
            if match := re.search(CredentialDetector.PATTERNS["pop3"]["pass"], payload, re.IGNORECASE):
                credentials.append(Credential(
                    protocol="POP3",
                    password=match.group(1).decode('utf-8', errors='ignore').strip(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    confidence="high"
                ))
        
        # ══════════════════════════════
        # Telnet
        # ══════════════════════════════
        if dst_port == 23 or b"login:" in payload.lower():
            if match := re.search(CredentialDetector.PATTERNS["telnet"]["login"], payload, re.IGNORECASE):
                credentials.append(Credential(
                    protocol="Telnet",
                    username=match.group(1).decode('utf-8', errors='ignore').strip(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    confidence="medium"
                ))
            
            if match := re.search(CredentialDetector.PATTERNS["telnet"]["password"], payload, re.IGNORECASE):
                credentials.append(Credential(
                    protocol="Telnet",
                    password=match.group(1).decode('utf-8', errors='ignore').strip(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    confidence="medium"
                ))
        
        # ══════════════════════════════
        # SNMP Community Strings
        # ══════════════════════════════
        if dst_port == 161 or b"community" in payload.lower():
            if match := re.search(CredentialDetector.PATTERNS["snmp"]["community"], payload, re.IGNORECASE):
                credentials.append(Credential(
                    protocol="SNMP",
                    password=match.group(1).decode('utf-8', errors='ignore'),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    confidence="high"
                ))
        
        return credentials


class CleartextDetector:
    """Detect sensitive cleartext data"""
    
    PATTERNS = {
        "cookie": rb"Cookie:\s*([^\r\n]+)",
        "set_cookie": rb"Set-Cookie:\s*([^\r\n]+)",
        "api_key": rb"(?:api[_-]?key|apikey|access[_-]?token)[\"\']?\s*[:=]\s*[\"\']?([a-zA-Z0-9_\-]{20,})",
        "bearer_token": rb"Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)",
        "jwt": rb"(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",
        "aws_key": rb"(AKIA[0-9A-Z]{16})",
        "private_key": rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "password_param": rb"(?:password|passwd|pwd)[\"\']?\s*[:=]\s*[\"\']?([^\s&\"\']{3,})",
    }
    
    @staticmethod
    def detect(payload: bytes, protocol: str, src_ip: str, dst_ip: str, timestamp: str) -> list[CleartextData]:
        """Detect cleartext sensitive data"""
        findings = []
        
        if not payload:
            return findings
        
        # Cookies
        for match in re.finditer(CleartextDetector.PATTERNS["cookie"], payload, re.IGNORECASE):
            findings.append(CleartextData(
                data_type="Cookie",
                protocol=protocol or "HTTP",
                value=match.group(1).decode('utf-8', errors='ignore')[:100],
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp,
                context="HTTP Request"
            ))
        
        # Set-Cookie
        for match in re.finditer(CleartextDetector.PATTERNS["set_cookie"], payload, re.IGNORECASE):
            findings.append(CleartextData(
                data_type="Set-Cookie",
                protocol=protocol or "HTTP",
                value=match.group(1).decode('utf-8', errors='ignore')[:100],
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp,
                context="HTTP Response"
            ))
        
        # API Keys
        for match in re.finditer(CleartextDetector.PATTERNS["api_key"], payload, re.IGNORECASE):
            findings.append(CleartextData(
                data_type="API Key",
                protocol=protocol or "HTTP",
                value=match.group(1).decode('utf-8', errors='ignore')[:50],
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp
            ))
        
        # Bearer Tokens
        for match in re.finditer(CleartextDetector.PATTERNS["bearer_token"], payload, re.IGNORECASE):
            findings.append(CleartextData(
                data_type="Bearer Token",
                protocol=protocol or "HTTP",
                value=match.group(1).decode('utf-8', errors='ignore')[:50],
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp
            ))
        
        # JWT
        for match in re.finditer(CleartextDetector.PATTERNS["jwt"], payload):
            findings.append(CleartextData(
                data_type="JWT Token",
                protocol=protocol or "HTTP",
                value=match.group(1).decode('utf-8', errors='ignore')[:50] + "...",
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp
            ))
        
        # AWS Keys
        for match in re.finditer(CleartextDetector.PATTERNS["aws_key"], payload):
            findings.append(CleartextData(
                data_type="AWS Access Key",
                protocol=protocol or "HTTP",
                value=match.group(1).decode('utf-8', errors='ignore'),
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp
            ))
        
        # Private Keys
        if re.search(CleartextDetector.PATTERNS["private_key"], payload):
            findings.append(CleartextData(
                data_type="Private Key",
                protocol=protocol or "Unknown",
                value="[PRIVATE KEY DETECTED]",
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp
            ))
        
        return findings


# ══════════════════════════════════════════════════════════════
# 3. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_tcpdump(output: str) -> tuple[list[Packet], dict]:
    """Parse tcpdump output"""
    packets = []
    stats = {
        "protocols": defaultdict(int),
        "src_ips": defaultdict(int),
        "dst_ips": defaultdict(int),
        "conversations": defaultdict(int),
    }
    
    # Regex for standard tcpdump line
    # 12:34:56.789012 IP 192.168.1.100.12345 > 93.184.216.34.80: Flags [S], seq 123, length 0
    pattern = r"(\d{2}:\d{2}:\d{2}\.\d+)\s+(\w+)\s+([^\s]+)\.(\d+)\s+>\s+([^\s]+)\.(\d+):\s+Flags\s+\[([^\]]+)\].*?length\s+(\d+)"
    
    for line in output.split("\n"):
        match = re.search(pattern, line)
        if match:
            timestamp, proto, src_ip, src_port, dst_ip, dst_port, flags, length = match.groups()
            
            packet = Packet(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(src_port),
                dst_port=int(dst_port),
                protocol=proto,
                length=int(length),
                flags=flags,
                info=line.strip()
            )
            packets.append(packet)
            
            # Update stats
            stats["protocols"][proto] += 1
            stats["src_ips"][src_ip] += 1
            stats["dst_ips"][dst_ip] += 1
            stats["conversations"][f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"] += 1
    
    return packets, dict(stats)


def parse_tshark_json(output: str) -> tuple[list[Packet], dict]:
    """Parse tshark JSON output"""
    packets = []
    stats = {
        "protocols": defaultdict(int),
        "src_ips": defaultdict(int),
        "dst_ips": defaultdict(int),
        "conversations": defaultdict(int),
    }
    
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        
        try:
            data = json.loads(line)
            layers = data.get("_source", {}).get("layers", {})
            
            # Frame info
            frame = layers.get("frame", {})
            timestamp = frame.get("frame.time", "")
            length = int(frame.get("frame.len", 0))
            
            # IP info
            ip_layer = layers.get("ip", {})
            src_ip = ip_layer.get("ip.src", "")
            dst_ip = ip_layer.get("ip.dst", "")
            
            # Transport layer
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            
            if tcp:
                protocol = "TCP"
                src_port = int(tcp.get("tcp.srcport", 0))
                dst_port = int(tcp.get("tcp.dstport", 0))
                flags = tcp.get("tcp.flags", "")
            elif udp:
                protocol = "UDP"
                src_port = int(udp.get("udp.srcport", 0))
                dst_port = int(udp.get("udp.dstport", 0))
                flags = None
            else:
                protocol = "Other"
                src_port = None
                dst_port = None
                flags = None
            
            packet = Packet(
                timestamp=timestamp,
                src_ip=src_ip if src_ip else None,
                dst_ip=dst_ip if dst_ip else None,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                flags=flags
            )
            packets.append(packet)
            
            # Update stats
            if protocol:
                stats["protocols"][protocol] += 1
            if src_ip:
                stats["src_ips"][src_ip] += 1
            if dst_ip:
                stats["dst_ips"][dst_ip] += 1
            if src_ip and dst_ip:
                conv = f"{src_ip}:{src_port or 0} <-> {dst_ip}:{dst_port or 0}"
                stats["conversations"][conv] += 1
        
        except json.JSONDecodeError:
            continue
    
    return packets, dict(stats)


def parse_ngrep(output: str) -> tuple[list[Packet], dict]:
    """Parse ngrep output"""
    packets = []
    stats = {
        "protocols": defaultdict(int),
        "matches": 0
    }
    
    # ngrep shows matched packets with payloads
    # T 192.168.1.100:12345 -> 93.184.216.34:80 [AP]
    pattern = r"([TU])\s+([^:]+):(\d+)\s+->\s+([^:]+):(\d+)\s+\[([^\]]+)\]"
    
    current_packet = None
    payload_lines = []
    
    for line in output.split("\n"):
        match = re.search(pattern, line)
        if match:
            # Save previous packet
            if current_packet and payload_lines:
                current_packet.payload = "\n".join(payload_lines)
                packets.append(current_packet)
                payload_lines = []
            
            # New packet
            proto_char, src_ip, src_port, dst_ip, dst_port, flags = match.groups()
            protocol = "TCP" if proto_char == "T" else "UDP"
            
            current_packet = Packet(
                timestamp="",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(src_port),
                dst_port=int(dst_port),
                protocol=protocol,
                flags=flags
            )
            
            stats["protocols"][protocol] += 1
            stats["matches"] += 1
        
        elif current_packet and line.strip() and not line.startswith("#"):
            # Payload line
            payload_lines.append(line.strip())
    
    # Save last packet
    if current_packet and payload_lines:
        current_packet.payload = "\n".join(payload_lines)
        packets.append(current_packet)
    
    return packets, dict(stats)


# ══════════════════════════════════════════════════════════════
# 4. ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_packets(packets: list[Packet], raw_output: str) -> dict:
    """Analyze packets for credentials and patterns"""
    
    credentials = []
    cleartext_data = []
    suspicious = []
    
    # Convert raw output to bytes for pattern matching
    raw_bytes = raw_output.encode('utf-8', errors='ignore')
    
    for packet in packets:
        if not packet.payload:
            continue
        
        payload_bytes = packet.payload.encode('utf-8', errors='ignore')
        
        # Detect credentials
        creds = CredentialDetector.detect(
            payload_bytes,
            packet.protocol or "",
            packet.src_ip or "",
            packet.dst_ip or "",
            packet.dst_port or 0,
            packet.timestamp or ""
        )
        credentials.extend(creds)
        
        # Detect cleartext data
        cleartext = CleartextDetector.detect(
            payload_bytes,
            packet.protocol or "",
            packet.src_ip or "",
            packet.dst_ip or "",
            packet.timestamp or ""
        )
        cleartext_data.extend(cleartext)
    
    # Also scan full raw output
    if raw_bytes:
        # Split by likely packet boundaries
        for chunk in raw_bytes.split(b'\n\n'):
            if len(chunk) < 20:
                continue
            
            # Try to extract IPs from chunk
            ip_matches = re.findall(rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', chunk)
            src_ip = ip_matches[0].decode() if len(ip_matches) > 0 else ""
            dst_ip = ip_matches[1].decode() if len(ip_matches) > 1 else ""
            
            creds = CredentialDetector.detect(chunk, "", src_ip, dst_ip, 0, "")
            credentials.extend(creds)
            
            cleartext = CleartextDetector.detect(chunk, "", src_ip, dst_ip, "")
            cleartext_data.extend(cleartext)
    
    # Detect suspicious patterns
    # Unencrypted traffic to sensitive ports
    for packet in packets:
        if packet.dst_port in [21, 23, 25, 110, 143]:  # FTP, Telnet, SMTP, POP3, IMAP
            suspicious.append({
                "type": "Unencrypted Protocol",
                "description": f"{packet.protocol} traffic to port {packet.dst_port}",
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "dst_port": packet.dst_port,
                "severity": "medium"
            })
    
    return {
        "credentials": credentials,
        "cleartext_data": cleartext_data,
        "suspicious_patterns": suspicious
    }


# ══════════════════════════════════════════════════════════════
# 5. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    """Run command safely"""
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
    except PermissionError:
        return "", "Permission denied - need root/sudo for packet capture", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 6. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def traffic_analyze(
    tool: str,
    interface: str = "any",
    capture_filter: Optional[str] = None,
    display_filter: Optional[str] = None,
    duration: int = 30,
    packet_count: Optional[int] = None,
    args: list[str] = []
) -> dict:
    """
    📡 Agent Tool: Traffic Analysis & Packet Capture
    
    Capabilities:
      ┌────────────────────────────────────────────────────────┐
      │  PACKET CAPTURE      Live traffic sniffing             │
      │  PROTOCOL ANALYSIS   Deep packet inspection            │
      │  CREDENTIAL SNIFF    FTP, HTTP, SMTP, POP3, Telnet     │
      │  CLEARTEXT DETECT    Cookies, tokens, API keys, JWT    │
      │  PATTERN MATCHING    Regex-based payload search        │
      │  STATISTICS          Top talkers, protocols, flows     │
      └────────────────────────────────────────────────────────┘
    
    Args:
        tool:             "tcpdump" | "tshark" | "ngrep"
        interface:        Network interface (eth0, wlan0, any)
        capture_filter:   BPF filter (tcpdump/tshark syntax)
        display_filter:   Wireshark display filter (tshark only)
        duration:         Capture duration in seconds (5-300)
        packet_count:     Stop after N packets
        args:             Additional tool arguments
    
    Tool Comparison:
        tcpdump  = Fast, minimal, BPF filters, binary output
        tshark   = Full Wireshark power, protocol dissection, JSON
        ngrep    = Grep for network, regex payload matching
    
    BPF Filter Examples (capture_filter):
        "tcp port 80"                    → HTTP traffic
        "host 192.168.1.1"               → Specific host
        "tcp port 21 or tcp port 23"     → FTP or Telnet
        "not port 22"                    → Exclude SSH
        "src net 192.168.1.0/24"         → Source network
        "dst port 443"                   → HTTPS destinations
        "tcp[tcpflags] & tcp-syn != 0"   → SYN packets
    
    Display Filter Examples (tshark only):
        "http.request.method == POST"    → HTTP POST
        "ftp.request.command == PASS"    → FTP passwords
        "smtp.req.command == AUTH"       → SMTP auth
        "http.cookie"                    → HTTP cookies
        "http.authorization"             → Auth headers
    
    Ngrep Pattern Examples (args):
        ["-q", "password"]               → Match "password"
        ["-q", "^GET|^POST"]             → HTTP methods
        ["-q", "Authorization"]          → Auth headers
        ["-q", "-i", "user"]             → Case-insensitive
    
    Common Args:
        tcpdump: ["-v"], ["-vv"], ["-X"]  → Verbosity, hex+ASCII
        tshark:  ["-V"], ["-O", "http"]   → Verbose, protocol tree
        ngrep:   ["-W", "byline"], ["-q"]  → Line-by-line, quiet
    
    Returns:
        Packets, credentials, cleartext data, protocol stats
    """
    
    start = time.time()
    
    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = TrafficCaptureRequest(
            tool=tool,
            interface=interface,
            capture_filter=capture_filter,
            display_filter=display_filter,
            duration=duration,
            packet_count=packet_count,
            args=args
        )
    except Exception as e:
        return TrafficAnalysisResult(
            success=False,
            tool=tool,
            interface=interface,
            command="",
            duration=0,
            error=f"Validation: {e}"
        ).model_dump()
    
    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if tool == "tcpdump":
        cmd = ["tcpdump", "-i", interface]
        
        # Duration via timeout or packet count
        if packet_count:
            cmd.extend(["-c", str(packet_count)])
        
        # BPF filter
        if capture_filter:
            cmd.append(capture_filter)
        
        # Show content
        if "-X" not in args and "-A" not in args:
            cmd.append("-A")  # ASCII payload
        
        cmd.extend(args)
    
    elif tool == "tshark":
        cmd = ["tshark", "-i", interface]
        
        # Duration
        if duration and not packet_count:
            cmd.extend(["-a", f"duration:{duration}"])
        
        # Packet count
        if packet_count:
            cmd.extend(["-c", str(packet_count)])
        
        # Capture filter (BPF)
        if capture_filter:
            cmd.extend(["-f", capture_filter])
        
        # Display filter (Wireshark syntax)
        if display_filter:
            cmd.extend(["-Y", display_filter])
        
        # JSON output for parsing
        if "-T" not in " ".join(args):
            cmd.extend(["-T", "json"])
        
        cmd.extend(args)
    
    elif tool == "ngrep":
        cmd = ["ngrep"]
        
        # Packet count
        if packet_count:
            cmd.extend(["-n", str(packet_count)])
        
        # Interface
        cmd.extend(["-d", interface])
        
        # BPF filter at end
        cmd.extend(args)
        
        if capture_filter:
            cmd.append(capture_filter)
    
    else:
        return TrafficAnalysisResult(
            success=False,
            tool=tool,
            interface=interface,
            command="",
            duration=0,
            error=f"Unknown tool: {tool}"
        ).model_dump()
    
    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    command_str = " ".join(cmd)
    
    # For duration-based capture, use timeout
    timeout = duration + 10 if duration else 310
    
    stdout, stderr, rc = safe_execute(cmd, timeout)
    
    exec_time = time.time() - start
    
    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    packets = []
    stats = {}
    
    if tool == "tcpdump":
        packets, stats = parse_tcpdump(stdout or stderr)
    elif tool == "tshark":
        packets, stats = parse_tshark_json(stdout)
    elif tool == "ngrep":
        packets, stats = parse_ngrep(stdout)
    
    # ══════════════════════════════
    # ANALYZE
    # ══════════════════════════════
    analysis = analyze_packets(packets, stdout or stderr)
    
    # ══════════════════════════════
    # BUILD STATISTICS
    # ══════════════════════════════
    protocols = stats.get("protocols", {})
    src_ips = stats.get("src_ips", {})
    dst_ips = stats.get("dst_ips", {})
    conversations = stats.get("conversations", {})
    
    # Top talkers
    top_sources = [{"ip": ip, "packets": count} for ip, count in 
                   sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    top_destinations = [{"ip": ip, "packets": count} for ip, count in 
                        sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    top_conversations = [{"conversation": conv, "packets": count} for conv, count in 
                         sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    # Total bytes
    total_bytes = sum(p.length or 0 for p in packets)
    
    # ══════════════════════════════
    # RETURN RESULT
    # ══════════════════════════════
    return TrafficAnalysisResult(
        success=len(packets) > 0 or rc == 0,
        tool=tool,
        interface=interface,
        command=command_str,
        duration=round(exec_time, 2),
        total_packets=len(packets),
        total_bytes=total_bytes,
        protocols=protocols,
        top_sources=top_sources,
        top_destinations=top_destinations,
        top_conversations=top_conversations,
        credentials=analysis["credentials"],
        cleartext_data=analysis["cleartext_data"],
        suspicious_patterns=analysis["suspicious_patterns"],
        sample_packets=packets[:50],  # First 50 packets
        raw_output=(stdout or stderr)[:5000],
        error=stderr if rc != 0 and not packets else None
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 7. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

TRAFFIC_ANALYZE_TOOL_DEFINITION = {
    "name": "traffic_analyze",
    "description": (
        "Capture and analyze network traffic. Detects credentials, cleartext data, "
        "suspicious patterns. Supports tcpdump (fast), tshark (deep), ngrep (pattern matching)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["tcpdump", "tshark", "ngrep"],
                "description": (
                    "tcpdump = fast capture, BPF filters | "
                    "tshark = full protocol analysis | "
                    "ngrep = regex payload matching"
                )
            },
            "interface": {
                "type": "string",
                "description": "Network interface (eth0, wlan0, any)",
                "default": "any"
            },
            "capture_filter": {
                "type": "string",
                "description": (
                    "BPF filter: 'tcp port 80' | 'host 192.168.1.1' | "
                    "'tcp port 21 or tcp port 23' | 'not port 22'"
                )
            },
            "display_filter": {
                "type": "string",
                "description": (
                    "Wireshark display filter (tshark only): "
                    "'http.request.method == POST' | 'ftp.request.command == PASS'"
                )
            },
            "duration": {
                "type": "integer",
                "description": "Capture duration in seconds (5-300)",
                "default": 30
            },
            "packet_count": {
                "type": "integer",
                "description": "Stop after N packets (overrides duration)"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "tcpdump: ['-v'], ['-X'] (hex dump) | "
                    "tshark: ['-V'], ['-O', 'http'] | "
                    "ngrep: ['-q', 'password'], ['-W', 'byline']"
                )
            }
        },
        "required": ["tool"]
    }
}


# ══════════════════════════════════════════════════════════════
# 8. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    
    # NOTE: Most of these require root/sudo privileges
    
    # ─────────────────────────────
    # 1. Capture HTTP traffic
    # ─────────────────────────────
    r = traffic_analyze(
        tool="tcpdump",
        interface="any",
        capture_filter="tcp port 80",
        duration=30
    )
    print("=== HTTP TRAFFIC ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 2. Sniff FTP credentials
    # ─────────────────────────────
    r = traffic_analyze(
        tool="tshark",
        interface="eth0",
        capture_filter="tcp port 21",
        display_filter="ftp",
        duration=60
    )
    print("=== FTP CREDENTIALS ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 3. Detect HTTP passwords
    # ─────────────────────────────
    r = traffic_analyze(
        tool="tshark",
        interface="any",
        display_filter="http.request.method == POST",
        duration=30
    )
    print("=== HTTP POST (passwords) ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 4. Grep for "password"
    # ─────────────────────────────
    r = traffic_analyze(
        tool="ngrep",
        interface="any",
        args=["-q", "-i", "password"],
        duration=30
    )
    print("=== PASSWORD GREP ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 5. Capture SMTP auth
    # ─────────────────────────────
    r = traffic_analyze(
        tool="tcpdump",
        interface="any",
        capture_filter="tcp port 25 or tcp port 587",
        duration=60,
        args=["-A"]
    )
    print("=== SMTP AUTH ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 6. Detect cleartext cookies
    # ─────────────────────────────
    r = traffic_analyze(
        tool="tshark",
        interface="any",
        display_filter="http.cookie",
        duration=30
    )
    print("=== CLEARTEXT COOKIES ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 7. Capture Telnet sessions
    # ─────────────────────────────
    r = traffic_analyze(
        tool="tcpdump",
        interface="any",
        capture_filter="tcp port 23",
        duration=120,
        args=["-A"]
    )
    print("=== TELNET ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 8. Grep for Authorization headers
    # ─────────────────────────────
    r = traffic_analyze(
        tool="ngrep",
        interface="any",
        args=["-q", "Authorization", "tcp port 80"],
        packet_count=100
    )
    print("=== AUTHORIZATION HEADERS ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 9. Full packet analysis
    # ─────────────────────────────
    r = traffic_analyze(
        tool="tshark",
        interface="eth0",
        capture_filter="not port 22",  # Exclude SSH
        duration=60,
        args=["-V"]  # Verbose
    )
    print("=== FULL ANALYSIS ===")
    print(json.dumps(r, indent=2, default=str))
    
    # ─────────────────────────────
    # 10. Specific host traffic
    # ─────────────────────────────
    r = traffic_analyze(
        tool="tcpdump",
        interface="any",
        capture_filter="host 192.168.1.100",
        duration=30,
        args=["-vv", "-X"]
    )
    print("=== HOST TRAFFIC ===")
    print(json.dumps(r, indent=2, default=str))