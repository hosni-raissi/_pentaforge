#/+
import subprocess
import json
import re
import os
import time
import logging
import threading
import ipaddress
import xml.etree.ElementTree as ET
from typing import Optional, Any
from functools import lru_cache
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. LOGGING CONFIGURATION
# ══════════════════════════════════════════════════════════════

logger = logging.getLogger("port_scan")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s - %(message)s",
        datefmt="%H:%M:%S"
    ))
    logger.addHandler(handler)


# ══════════════════════════════════════════════════════════════
# 2. RATE LIMITER
# ══════════════════════════════════════════════════════════════

class RateLimiter:
    """Thread-safe rate limiter using token bucket algorithm"""
    
    def __init__(self, calls_per_second: float = 0.5):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0
        self.lock = threading.Lock()
    
    def acquire(self):
        """Block until rate limit allows next call"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
            self.last_call = time.time()
    
    def reset(self):
        with self.lock:
            self.last_call = 0.0


# Global rate limiter (scans are heavy - limit to 1 per 2 seconds)
SCAN_RATE_LIMITER = RateLimiter(calls_per_second=0.5)


# ══════════════════════════════════════════════════════════════
# 3. SECURITY CONSTANTS
# ══════════════════════════════════════════════════════════════

# Shell injection characters
DANGEROUS_CHARS = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"]

# Blocked output flags (prevent file writes)
BLOCKED_OUTPUT_FLAGS = ["-oN", "-oG", "-oS", "-oA", "--append-output"]

# Dangerous nmap script categories
DANGEROUS_SCRIPT_CATEGORIES = [
    "broadcast",    # Scans entire network
    "dos",          # Denial of service
    "exploit",      # Auto exploitation
    "fuzzer",       # Can crash services
    "intrusive",    # Aggressive scripts (optional - uncomment to block)
]

# Blocked targets
BLOCKED_TARGETS = [
    "127.0.0.1", "localhost", "0.0.0.0", "::1",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",  # GCP metadata
]

# Max hosts in CIDR range
MAX_CIDR_HOSTS = 256  # /24 maximum

# Max ports for full scan warning
MAX_PORTS_WARNING = 10000

# Sensitive data patterns to redact
SENSITIVE_PATTERNS = [
    r"password\s*[:=]\s*\S+",
    r"passwd\s*[:=]\s*\S+",
    r"secret\s*[:=]\s*\S+",
    r"api[_-]?key\s*[:=]\s*\S+",
    r"token\s*[:=]\s*\S+",
    r"credential\s*[:=]\s*\S+",
    r"auth\s*[:=]\s*\S+",
]

# Max XML size (protection against XML bombs)
MAX_XML_SIZE = 50 * 1024 * 1024  # 50 MB


# ══════════════════════════════════════════════════════════════
# 4. SCHEMAS
# ══════════════════════════════════════════════════════════════

class PortScanRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"nmap", "naabu", "netcat", "masscan"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        clean = v.strip().lower()

        # Check blocklist
        for blocked in BLOCKED_TARGETS:
            if blocked in clean:
                raise ValueError(f"Target '{v}' is blocked")

        # CIDR range validation
        if "/" in clean:
            try:
                network = ipaddress.ip_network(clean, strict=False)

                # Block massive scans
                if network.num_addresses > MAX_CIDR_HOSTS:
                    raise ValueError(
                        f"CIDR range too large: {network.num_addresses} hosts "
                        f"(max {MAX_CIDR_HOSTS}). Use smaller ranges or external tool."
                    )

                # Block 0.0.0.0/0 and similar
                if network.is_unspecified:
                    raise ValueError("Unspecified network (0.0.0.0/0) blocked")

            except ValueError as e:
                if "CIDR range" in str(e) or "blocked" in str(e):
                    raise
                raise ValueError(f"Invalid CIDR notation: {v}")
        else:
            # Single IP or domain validation
            ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
            domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)*[a-zA-Z]{2,}$"
            ip_range_pattern = r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$"

            if not (re.match(ip_pattern, clean) or
                    re.match(domain_pattern, clean) or
                    re.match(ip_range_pattern, clean)):
                raise ValueError(f"Invalid target format: {v}")

        return v.strip()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        """Block shell injection and dangerous options while allowing legitimate features"""

        for arg in v:
            # Shell injection check
            for char in DANGEROUS_CHARS:
                if char in arg:
                    raise ValueError(f"Dangerous character '{repr(char)}' in: {arg}")

            # File write check
            arg_clean = arg.strip()
            for flag in BLOCKED_OUTPUT_FLAGS:
                if arg_clean == flag or arg_clean.startswith(f"{flag}="):
                    raise ValueError(f"File output flag blocked: {arg}")

            # Script validation
            if arg.startswith("--script=") or arg.startswith("-sC"):
                script_value = arg.split("=", 1)[-1] if "=" in arg else ""

                # Block file paths (custom scripts)
                if "/" in script_value or "\\" in script_value:
                    raise ValueError(
                        f"Custom script paths blocked: {script_value}. "
                        "Use built-in script names only."
                    )

                # Block dangerous script categories
                for ds in DANGEROUS_SCRIPT_CATEGORIES:
                    if ds in script_value.lower():
                        raise ValueError(f"Dangerous script category blocked: {ds}")

            # Block --script-args with file paths
            if arg.startswith("--script-args"):
                if "file=" in arg.lower() or ".txt" in arg.lower() or ".nse" in arg.lower():
                    raise ValueError(f"Script file arguments blocked: {arg}")

        return v


class PortResult(BaseModel):
    """Single port scan result"""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    scripts: Optional[dict[str, Any]] = None
    reason: Optional[str] = None  # Why port is in this state


class OSResult(BaseModel):
    """OS detection result"""
    name: Optional[str] = None
    accuracy: Optional[int] = None
    os_family: Optional[str] = None
    os_gen: Optional[str] = None
    cpe: Optional[str] = None
    vendor: Optional[str] = None


class HostResult(BaseModel):
    """Single host scan result"""
    ip: Optional[str] = None
    hostname: Optional[str] = None
    state: str = "up"
    state_reason: Optional[str] = None
    open_ports: list[PortResult] = []
    closed_ports: int = 0
    filtered_ports: int = 0
    os_matches: list[OSResult] = []
    host_scripts: Optional[dict[str, Any]] = None
    traceroute: Optional[list[dict[str, Any]]] = None
    uptime: Optional[str] = None
    distance: Optional[int] = None
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None


class ScanResult(BaseModel):
    """Complete scan result"""
    success: bool
    tool: str
    target: str
    command: str
    scan_info: Optional[dict[str, Any]] = None
    total_hosts: int = 0
    total_hosts_up: int = 0
    total_open_ports: int = 0
    hosts: list[HostResult] = []
    raw_output: str = ""
    error: Optional[str] = None
    execution_time: float = 0.0
    warnings: list[str] = []


# ══════════════════════════════════════════════════════════════
# 5. UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def sanitize_script_output(script_id: str, output: str) -> str:
    """Redact sensitive data from script output"""
    if not output:
        return output
    
    sanitized = output
    for pattern in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
    
    return sanitized


def calculate_timeout(target: str, args: list[str], base_timeout: int) -> int:
    """Auto-scale timeout based on scan scope"""
    timeout = base_timeout
    multiplier = 1.0
    
    # Check for CIDR range
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            host_count = min(network.num_addresses, MAX_CIDR_HOSTS)
            multiplier *= (host_count / 10)  # Scale with hosts
        except ValueError:
            pass
    
    # Check for full port scan
    args_str = " ".join(args)
    if "-p-" in args or "-p 1-65535" in args_str:
        multiplier *= 5  # Full port scan takes 5x longer
    elif "--top-ports" in args_str:
        for i, arg in enumerate(args):
            if arg == "--top-ports" and i + 1 < len(args):
                try:
                    port_count = int(args[i + 1])
                    multiplier *= max(1, port_count / 100)
                except ValueError:
                    pass
    
    # Check for version detection (slower)
    if "-sV" in args or "-A" in args:
        multiplier *= 1.5
    
    # Check for OS detection (slower)
    if "-O" in args or "-A" in args:
        multiplier *= 1.3
    
    # Check for script scanning (slower)
    if any("--script" in arg for arg in args) or "-sC" in args or "-A" in args:
        multiplier *= 1.5
    
    # Check for timing
    for arg in args:
        if arg.startswith("-T"):
            try:
                timing = int(arg[2])
                if timing <= 2:  # Slow/polite scan
                    multiplier *= 2
                elif timing >= 4:  # Fast/aggressive
                    multiplier *= 0.7
            except ValueError:
                pass
    
    calculated = int(timeout * multiplier)
    return min(max(calculated, 60), 7200)  # Clamp to 60s - 2h


def check_root_required(tool: str, args: list[str]) -> tuple[bool, str]:
    """Check if scan requires root privileges"""
    if tool != "nmap":
        return False, ""
    
    root_required_flags = [
        "-O",           # OS detection
        "-sS",          # SYN scan
        "-sA",          # ACK scan
        "-sW",          # Window scan
        "-sM",          # Maimon scan
        "-sN",          # NULL scan
        "-sF",          # FIN scan
        "-sX",          # Xmas scan
        "-sU",          # UDP scan
        "--traceroute", # Traceroute
        "-A",           # Aggressive (includes -O)
    ]
    
    for flag in root_required_flags:
        if flag in args:
            if os.geteuid() != 0:
                return True, f"'{flag}' requires root privileges. Run with sudo or remove flag."
    
    return False, ""


def estimate_port_count(args: list[str]) -> int:
    """Estimate number of ports to be scanned"""
    args_str = " ".join(args)
    
    if "-p-" in args or "-p 1-65535" in args_str:
        return 65535
    
    for i, arg in enumerate(args):
        if arg == "-p" and i + 1 < len(args):
            port_spec = args[i + 1]
            # Count ports in spec like "22,80,443" or "1-1000"
            count = 0
            for part in port_spec.split(","):
                if "-" in part:
                    try:
                        start, end = part.split("-")
                        count += int(end) - int(start) + 1
                    except ValueError:
                        count += 1
                else:
                    count += 1
            return count
        
        if arg == "--top-ports" and i + 1 < len(args):
            try:
                return int(args[i + 1])
            except ValueError:
                pass
    
    # Default nmap scans top 1000 ports
    return 1000


# ══════════════════════════════════════════════════════════════
# 6. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_nmap(stdout: str, stderr: str) -> tuple[list[HostResult], Optional[dict], list[str]]:
    """
    Comprehensive nmap XML parser with fallback to regex.
    
    Extracts:
    - Ports + services + versions + banners
    - NSE script output (per-port AND per-host)
    - OS detection with accuracy
    - Traceroute hops
    - CPE identifiers
    - MAC addresses
    """
    hosts = []
    scan_info = None
    warnings = []
    
    # Size check for XML bomb protection
    if len(stdout) > MAX_XML_SIZE:
        logger.warning(f"nmap output too large ({len(stdout)} bytes), truncating")
        warnings.append(f"Output truncated from {len(stdout)} to {MAX_XML_SIZE} bytes")
        stdout = stdout[:MAX_XML_SIZE]
    
    # ══════════════════════════════
    # TRY XML PARSE
    # ══════════════════════════════
    try:
        # Find XML start (skip any non-XML output)
        xml_start = stdout.find("<?xml")
        if xml_start == -1:
            xml_start = stdout.find("<nmaprun")
        
        if xml_start != -1:
            xml_content = stdout[xml_start:]
            root = ET.fromstring(xml_content)
            
            # ── Scan Info ──
            scan_info_elem = root.find(".//scaninfo")
            if scan_info_elem is not None:
                scan_info = {
                    "type": scan_info_elem.get("type"),
                    "protocol": scan_info_elem.get("protocol"),
                    "services": scan_info_elem.get("services"),
                    "numservices": scan_info_elem.get("numservices"),
                }
            
            # ── Run Stats ──
            runstats = root.find(".//runstats/finished")
            if runstats is not None:
                if scan_info is None:
                    scan_info = {}
                scan_info["elapsed"] = runstats.get("elapsed")
                scan_info["exit"] = runstats.get("exit")
            
            # ── Parse Each Host ──
            for host_elem in root.findall(".//host"):
                host = HostResult()
                
                # ── IP Address ──
                for addr in host_elem.findall("address"):
                    addr_type = addr.get("addrtype", "")
                    if addr_type == "ipv4" or addr_type == "ipv6":
                        host.ip = addr.get("addr")
                    elif addr_type == "mac":
                        host.mac_address = addr.get("addr")
                        host.mac_vendor = addr.get("vendor")
                
                # ── Hostname ──
                hostnames = host_elem.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        host.hostname = hn.get("name")
                
                # ── Host State ──
                status = host_elem.find("status")
                if status is not None:
                    host.state = status.get("state", "unknown")
                    host.state_reason = status.get("reason")
                
                # ── Ports ──
                ports_elem = host_elem.find("ports")
                if ports_elem is not None:
                    # Extra ports summary
                    extraports = ports_elem.find("extraports")
                    if extraports is not None:
                        state = extraports.get("state", "")
                        count = int(extraports.get("count", 0))
                        if state == "closed":
                            host.closed_ports = count
                        elif state == "filtered":
                            host.filtered_ports = count
                    
                    # Individual ports
                    for port_elem in ports_elem.findall("port"):
                        state_elem = port_elem.find("state")
                        svc_elem = port_elem.find("service")
                        
                        if state_elem is None:
                            continue
                        
                        port_state = state_elem.get("state", "unknown")
                        if port_state not in ("open", "open|filtered"):
                            continue
                        
                        port = PortResult(
                            port=int(port_elem.get("portid", 0)),
                            protocol=port_elem.get("protocol", "tcp"),
                            state=port_state,
                            reason=state_elem.get("reason"),
                        )
                        
                        # ── Service / Version / Banner ──
                        if svc_elem is not None:
                            port.service = svc_elem.get("name")
                            port.product = svc_elem.get("product")
                            port.extra_info = svc_elem.get("extrainfo")
                            port.banner = svc_elem.get("servicefp")
                            
                            # Build version string
                            v_parts = [
                                svc_elem.get("product", ""),
                                svc_elem.get("version", ""),
                                svc_elem.get("extrainfo", ""),
                            ]
                            port.version = " ".join(p for p in v_parts if p).strip() or None
                            
                            # CPE
                            for cpe_elem in svc_elem.findall("cpe"):
                                if cpe_elem.text:
                                    port.cpe = cpe_elem.text
                                    break
                        
                        # ── Per-Port Scripts ──
                        scripts = {}
                        for script_elem in port_elem.findall("script"):
                            script_id = script_elem.get("id", "unknown")
                            script_output = script_elem.get("output", "")
                            
                            # Sanitize sensitive data
                            script_output = sanitize_script_output(script_id, script_output)
                            
                            # Extract structured tables
                            tables = []
                            for table in script_elem.findall(".//table"):
                                table_data = {}
                                for elem in table.findall("elem"):
                                    key = elem.get("key", "")
                                    value = elem.text or ""
                                    table_data[key] = sanitize_script_output(key, value)
                                if table_data:
                                    tables.append(table_data)
                            
                            if tables:
                                scripts[script_id] = {
                                    "output": script_output,
                                    "data": tables,
                                }
                            else:
                                scripts[script_id] = script_output
                        
                        if scripts:
                            port.scripts = scripts
                        
                        host.open_ports.append(port)
                
                # ── OS Detection ──
                for os_elem in host_elem.findall(".//os"):
                    for os_match in os_elem.findall("osmatch"):
                        os_result = OSResult(
                            name=os_match.get("name"),
                            accuracy=int(os_match.get("accuracy", 0)),
                        )
                        
                        # OS class details
                        os_class = os_match.find("osclass")
                        if os_class is not None:
                            os_result.os_family = os_class.get("osfamily")
                            os_result.os_gen = os_class.get("osgen")
                            os_result.vendor = os_class.get("vendor")
                            
                            for cpe_elem in os_class.findall("cpe"):
                                if cpe_elem.text:
                                    os_result.cpe = cpe_elem.text
                                    break
                        
                        host.os_matches.append(os_result)
                
                # ── Host-Level Scripts ──
                hostscript = host_elem.find("hostscript")
                if hostscript is not None:
                    host_scripts = {}
                    for script_elem in hostscript.findall("script"):
                        script_id = script_elem.get("id", "unknown")
                        script_output = script_elem.get("output", "")
                        script_output = sanitize_script_output(script_id, script_output)
                        host_scripts[script_id] = script_output
                    host.host_scripts = host_scripts
                
                # ── Traceroute ──
                trace = host_elem.find("trace")
                if trace is not None:
                    hops = []
                    for hop in trace.findall("hop"):
                        hops.append({
                            "ttl": int(hop.get("ttl", 0)),
                            "ip": hop.get("ipaddr"),
                            "rtt": hop.get("rtt"),
                            "host": hop.get("host", ""),
                        })
                    if hops:
                        host.traceroute = hops
                
                # ── Uptime ──
                uptime_elem = host_elem.find("uptime")
                if uptime_elem is not None:
                    seconds = uptime_elem.get("seconds", "?")
                    lastboot = uptime_elem.get("lastboot", "?")
                    host.uptime = f"{seconds}s (since {lastboot})"
                
                # ── Distance ──
                distance_elem = host_elem.find("distance")
                if distance_elem is not None:
                    try:
                        host.distance = int(distance_elem.get("value", 0))
                    except ValueError:
                        pass
                
                hosts.append(host)
            
            logger.debug(f"Parsed {len(hosts)} hosts from nmap XML")
            return hosts, scan_info, warnings
    
    except ET.ParseError as e:
        logger.warning(f"nmap XML parse failed: {e}, falling back to regex")
        warnings.append(f"XML parse failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected nmap parse error: {e}")
        warnings.append(f"Parse error: {e}")
    
    # ══════════════════════════════
    # FALLBACK: REGEX PARSE
    # ══════════════════════════════
    raw = stdout or stderr
    host = HostResult()
    
    # Try to extract IP
    ip_match = re.search(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)", raw)
    if ip_match:
        host.hostname = ip_match.group(1)
        host.ip = ip_match.group(2)
    
    # ── Ports ──
    port_pattern = r"(\d+)/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.+))?"
    for m in re.finditer(port_pattern, raw):
        port = PortResult(
            port=int(m.group(1)),
            protocol=m.group(2),
            state=m.group(3),
            service=m.group(4),
            version=m.group(5).strip() if m.group(5) else None,
        )
        host.open_ports.append(port)
    
    # ── OS Detection ──
    os_match = re.search(r"OS details?:\s*(.+)", raw)
    if os_match:
        host.os_matches.append(OSResult(name=os_match.group(1).strip()))
    
    # ── MAC Address ──
    mac_match = re.search(r"MAC Address:\s*([0-9A-Fa-f:]+)(?:\s+\((.+)\))?", raw)
    if mac_match:
        host.mac_address = mac_match.group(1)
        host.mac_vendor = mac_match.group(2)
    
    # ── Script output (basic) ──
    script_blocks = re.findall(r"\|\s+(\S+):\s*\n((?:\|[^\n]*\n)*)", raw)
    if script_blocks:
        host_scripts = {}
        for script_name, script_body in script_blocks:
            cleaned = re.sub(r"^\|\s*", "", script_body, flags=re.MULTILINE).strip()
            cleaned = sanitize_script_output(script_name, cleaned)
            host_scripts[script_name] = cleaned
        host.host_scripts = host_scripts
    
    if host.open_ports or host.os_matches:
        hosts.append(host)
    
    return hosts, None, warnings


def parse_naabu(stdout: str) -> tuple[list[HostResult], list[str]]:
    """Parse naabu JSON or host:port output with deduplication"""
    ports_by_host: dict[str, set[int]] = {}
    warnings = []
    
    for line in stdout.strip().split("\n"):
        if not line.strip():
            continue
        
        try:
            # Try JSON format
            data = json.loads(line)
            host_ip = data.get("host", data.get("ip", "unknown"))
            port_num = int(data.get("port", 0))
            if port_num > 0:
                ports_by_host.setdefault(host_ip, set()).add(port_num)
        except json.JSONDecodeError:
            # Try host:port format
            if ":" in line:
                parts = line.strip().split(":")
                if len(parts) == 2:
                    host_ip = parts[0]
                    try:
                        port_num = int(parts[1])
                        ports_by_host.setdefault(host_ip, set()).add(port_num)
                    except ValueError:
                        pass
    
    # Build host results with deduplicated ports
    hosts = []
    for ip, port_nums in ports_by_host.items():
        ports = [
            PortResult(port=p, protocol="tcp", state="open")
            for p in sorted(port_nums)
        ]
        hosts.append(HostResult(ip=ip, open_ports=ports))
    
    logger.debug(f"Parsed {len(hosts)} hosts from naabu")
    return hosts, warnings


def parse_netcat(stdout: str, stderr: str) -> tuple[list[HostResult], list[str]]:
    """Parse netcat output with banner grabbing"""
    ports = []
    warnings = []
    raw = stderr or stdout
    
    patterns = [
        r"(\d+)\s+port\s+\[(\w+)/(\w+)\]\s+succeeded",
        r"]\s+(\d+)\s+\((\w+)\)\s+open",
        r"Connection to \S+\s+(\d+)\s+port.*succeeded",
        r"(\d+).*open",
        r"succeeded!.*?(\d+)",
    ]
    
    seen_ports = set()
    
    for line in raw.split("\n"):
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                port_num = int(match.group(1))
                if port_num not in seen_ports:
                    seen_ports.add(port_num)
                    
                    port = PortResult(
                        port=port_num,
                        protocol="tcp",
                        state="open",
                        service=match.group(3) if len(match.groups()) >= 3 else None,
                    )
                    
                    # Try to capture banner from stdout
                    if stdout.strip() and stdout != stderr:
                        banner = stdout.strip()[:500]
                        port.banner = sanitize_script_output("banner", banner)
                    
                    ports.append(port)
                break
    
    hosts = []
    if ports:
        hosts.append(HostResult(open_ports=ports))
    
    logger.debug(f"Parsed {len(ports)} ports from netcat")
    return hosts, warnings


def parse_masscan(stdout: str) -> tuple[list[HostResult], list[str]]:
    """Parse masscan JSON output"""
    ports_by_host: dict[str, list[PortResult]] = {}
    warnings = []
    
    # Try to parse as JSON array
    try:
        # masscan JSON output is an array
        data = json.loads(stdout)
        if isinstance(data, list):
            for item in data:
                ip = item.get("ip", "unknown")
                for port_info in item.get("ports", []):
                    port = PortResult(
                        port=int(port_info.get("port", 0)),
                        protocol=port_info.get("proto", "tcp"),
                        state=port_info.get("status", "open"),
                        service=port_info.get("service", {}).get("name"),
                        banner=port_info.get("service", {}).get("banner"),
                    )
                    ports_by_host.setdefault(ip, []).append(port)
    except json.JSONDecodeError:
        # Fallback: line-by-line JSON
        for line in stdout.strip().split("\n"):
            line = line.strip().rstrip(",")
            if not line or line in ["[", "]"]:
                continue
            try:
                item = json.loads(line)
                ip = item.get("ip", "unknown")
                for port_info in item.get("ports", []):
                    port = PortResult(
                        port=int(port_info.get("port", 0)),
                        protocol=port_info.get("proto", "tcp"),
                        state=port_info.get("status", "open"),
                    )
                    ports_by_host.setdefault(ip, []).append(port)
            except json.JSONDecodeError:
                pass
    
    hosts = []
    for ip, ports in ports_by_host.items():
        hosts.append(HostResult(ip=ip, open_ports=ports))
    
    logger.debug(f"Parsed {len(hosts)} hosts from masscan")
    return hosts, warnings


# ══════════════════════════════════════════════════════════════
# 7. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(
    cmd: list[str],
    timeout: int = 600,
    stdin_data: Optional[str] = None
) -> tuple[str, str, int]:
    """Execute command safely with no shell injection"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            input=stdin_data,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed. Install it first.", -1
    except PermissionError:
        return "", f"Permission denied executing '{cmd[0]}'", -1
    except Exception as e:
        return "", f"Execution error: {str(e)}", -1


# ══════════════════════════════════════════════════════════════
# 8. CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_port_scan(
    tool: str,
    target: str,
    args_tuple: tuple,
    timeout: int
) -> str:
    """Cached internal implementation. Returns JSON string."""
    args = list(args_tuple)
    result = _port_scan_impl(tool, target, args, timeout)
    return json.dumps(result)


def clear_cache():
    """Clear the result cache"""
    _cached_port_scan.cache_clear()


def get_cache_info():
    """Get cache statistics"""
    return _cached_port_scan.cache_info()


# ══════════════════════════════════════════════════════════════
# 9. CORE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _port_scan_impl(
    tool: str,
    target: str,
    args: list[str],
    timeout: int
) -> dict:
    """Core implementation without caching"""
    start = time.time()
    warnings = []
    
    # Rate limit
    SCAN_RATE_LIMITER.acquire()
    
    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = PortScanRequest(tool=tool, target=target, args=args, timeout=timeout)
    except Exception as e:
        return ScanResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation error: {str(e)}"
        ).model_dump()
    
    # ══════════════════════════════
    # PRE-FLIGHT CHECKS
    # ══════════════════════════════
    
    # Check root privileges
    needs_root, root_msg = check_root_required(tool, args)
    if needs_root:
        return ScanResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=root_msg
        ).model_dump()
    
    # Calculate dynamic timeout
    actual_timeout = calculate_timeout(target, args, req.timeout)
    if actual_timeout != req.timeout:
        logger.info(f"Timeout adjusted from {req.timeout}s to {actual_timeout}s based on scan scope")
        warnings.append(f"Timeout auto-adjusted to {actual_timeout}s")
    
    # Warn about large port scans
    port_count = estimate_port_count(args)
    if port_count > MAX_PORTS_WARNING:
        warnings.append(f"Scanning {port_count} ports - this may take a long time")
    
    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if tool == "nmap":
        final_args = list(args)
        
        # Auto-inject XML output for full parsing (to stdout)
        if "-oX" not in final_args and "-oX-" not in " ".join(final_args):
            final_args.extend(["-oX", "-"])
        
        # Auto-inject reason for state info
        if "--reason" not in final_args:
            final_args.append("--reason")
        
        cmd = ["nmap"] + final_args + [target]
    
    elif tool == "naabu":
        cmd = ["naabu", "-host", target] + list(args)
        if "-json" not in cmd and "-j" not in cmd:
            cmd.append("-json")
        if "-silent" not in cmd:
            cmd.append("-silent")
    
    elif tool == "netcat":
        cmd = ["nc"] + list(args) + [target]
    
    elif tool == "masscan":
        cmd = ["masscan", target] + list(args)
        if "-oJ" not in " ".join(args) and "--output-format" not in " ".join(args):
            cmd.extend(["-oJ", "-"])  # JSON to stdout
    
    else:
        return ScanResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Unknown tool: {tool}"
        ).model_dump()
    
    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    command_str = " ".join(cmd)
    logger.info(f"Executing: {command_str}")
    
    stdout, stderr, rc = safe_execute(cmd, actual_timeout)
    
    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    hosts = []
    scan_info = None
    parse_warnings = []
    
    if tool == "nmap":
        hosts, scan_info, parse_warnings = parse_nmap(stdout, stderr)
    elif tool == "naabu":
        hosts, parse_warnings = parse_naabu(stdout)
    elif tool == "netcat":
        hosts, parse_warnings = parse_netcat(stdout, stderr)
    elif tool == "masscan":
        hosts, parse_warnings = parse_masscan(stdout)
    
    warnings.extend(parse_warnings)
    
    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    total_ports = sum(len(h.open_ports) for h in hosts)
    total_hosts_up = sum(1 for h in hosts if h.state == "up")
    
    # Determine success
    success = total_ports > 0 or rc == 0
    
    # Determine error message
    error_msg = None
    if rc != 0 and not hosts:
        error_msg = stderr[:1000] if stderr else f"Command returned exit code {rc}"
    
    return ScanResult(
        success=success,
        tool=tool,
        target=target,
        command=command_str,
        scan_info=scan_info,
        total_hosts=len(hosts),
        total_hosts_up=total_hosts_up,
        total_open_ports=total_ports,
        hosts=[h.model_dump() for h in hosts],
        raw_output=(stdout or stderr)[:8000],
        error=error_msg,
        execution_time=round(time.time() - start, 2),
        warnings=warnings,
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 10. PUBLIC API
# ══════════════════════════════════════════════════════════════

def port_scan_service_enum(
    tool: str,
    target: str,
    args: list[str] = [],
    timeout: int = 600,
    use_cache: bool = True,
) -> dict:
    """
    🔧 Agent Tool: Port Scan, Service Enum, Script Scan, OS Fingerprint

    Comprehensive network scanning with structured output for agent consumption.

    ┌─────────────────────────────────────────────────────────────────────┐
    │  CAPABILITIES                                                       │
    ├─────────────────────────────────────────────────────────────────────┤
    │  • Port Scanning         TCP/UDP, SYN/Connect/ACK/FIN/NULL/Xmas    │
    │  • Service Detection     Version fingerprinting (-sV)              │
    │  • OS Fingerprinting     Operating system detection (-O)           │
    │  • Banner Grabbing       Service banners and fingerprints          │
    │  • Script Scanning       NSE scripts (--script=<category>)         │
    │  • Traceroute            Network path discovery (--traceroute)     │
    │  • CPE Extraction        For CVE correlation                       │
    │  • Rate Limiting         1 scan per 2 seconds                      │
    │  • Result Caching        LRU cache (128 entries)                   │
    │  • Auto Timeout          Scales with scan scope                    │
    └─────────────────────────────────────────────────────────────────────┘

    Args:
        tool: Scanner to use
            - "nmap"    : Full-featured (ports + services + OS + scripts)
            - "naabu"   : Fast port discovery only (ProjectDiscovery)
            - "netcat"  : Quick port check + banner grab
            - "masscan" : Ultra-fast port scanner (requires root)

        target: Target specification
            - Single IP: "10.10.10.1"
            - Domain: "example.com"
            - CIDR: "10.10.10.0/24" (max /24)
            - Range: "10.10.10.1-100"

        args: Tool-specific arguments (see examples below)

        timeout: Base timeout in seconds (auto-scales with scope)

        use_cache: Enable LRU caching (default: True)

    ═══════════════════════════════════════════════════════════════════════
    NMAP ARGS REFERENCE
    ═══════════════════════════════════════════════════════════════════════
    
    SCAN TYPES:
        ["-sS"]                     SYN scan (stealthy, requires root)
        ["-sT"]                     Connect scan (no root needed)
        ["-sU"]                     UDP scan (slow, requires root)
        ["-sA"]                     ACK scan (firewall mapping)
        ["-sN", "-sF", "-sX"]       NULL/FIN/Xmas scans (IDS evasion)

    PORT SELECTION:
        ["-p", "22,80,443"]         Specific ports
        ["-p", "1-1000"]            Port range
        ["-p-"]                     All 65535 ports (slow!)
        ["--top-ports", "100"]      Top N most common
        ["-F"]                      Fast (top 100 ports)

    SERVICE DETECTION:
        ["-sV"]                     Version detection
        ["-sV", "--version-intensity", "9"]  Aggressive version scan
        ["-sV", "--version-light"]  Quick version scan

    OS DETECTION (requires root):
        ["-O"]                      OS fingerprinting
        ["-O", "--osscan-guess"]    Aggressive OS guessing

    SCRIPT SCANNING:
        ["--script=default"]        Safe default scripts
        ["--script=vuln"]           Vulnerability checks
        ["--script=auth"]           Authentication checks
        ["--script=discovery"]      Service discovery
        ["--script=http-*"]         All HTTP scripts
        ["--script=smb-*"]          All SMB scripts
        ["--script=ssl-*"]          All SSL/TLS scripts

    TIMING:
        ["-T0"]                     Paranoid (IDS evasion, very slow)
        ["-T1"]                     Sneaky (IDS evasion)
        ["-T2"]                     Polite (reduced load)
        ["-T3"]                     Normal (default)
        ["-T4"]                     Aggressive (fast)
        ["-T5"]                     Insane (may miss ports)

    COMBOS:
        ["-A"]                      Aggressive = -sV -O -sC --traceroute
        ["-sC"]                     Default scripts = --script=default

    STEALTH:
        ["-sS", "-T2", "-f"]                    Fragmented SYN
        ["-sS", "-T2", "--data-length", "24"]   Random payload

    EVASION:
        ["-D", "RND:10"]            Decoy scan
        ["--spoof-mac", "0"]        Random MAC
        ["-S", "spoofed_ip"]        Spoof source IP

    ═══════════════════════════════════════════════════════════════════════
    NAABU ARGS REFERENCE
    ═══════════════════════════════════════════════════════════════════════
        ["-p", "80,443"]            Specific ports
        ["-top-ports", "1000"]      Top N ports
        ["-rate", "1000"]           Packets per second
        ["-c", "50"]                Concurrent connections
        ["-scan-type", "s"]         SYN scan (requires root)
        ["-scan-type", "c"]         Connect scan

    ═══════════════════════════════════════════════════════════════════════
    NETCAT ARGS REFERENCE
    ═══════════════════════════════════════════════════════════════════════
        ["-zv", "-w", "3", "80"]        Quick port check
        ["-zv", "-w", "3", "20-100"]    Port range scan
        ["-v", "-w", "3", "80"]         Banner grab (no -z)
        ["-u", "-zv", "53"]             UDP port check

    Returns:
        dict: Structured scan results including:
            - hosts: List of host results with ports, services, OS, scripts
            - total_hosts: Number of hosts discovered
            - total_open_ports: Total open ports across all hosts
            - scan_info: Scan metadata (type, protocol, timing)
            - warnings: Any issues encountered

    Example:
        >>> result = port_scan_service_enum(
        ...     tool="nmap",
        ...     target="scanme.nmap.org",
        ...     args=["-sV", "-sC", "-p", "22,80,443"]
        ... )
        >>> print(f"Found {result['total_open_ports']} open ports")
        >>> for host in result['hosts']:
        ...     for port in host['open_ports']:
        ...         print(f"  {port['port']}/{port['protocol']}: {port['service']}")
    """
    if use_cache:
        cached_json = _cached_port_scan(tool, target, tuple(args), timeout)
        return json.loads(cached_json)
    else:
        return _port_scan_impl(tool, target, args, timeout)


# ══════════════════════════════════════════════════════════════
# 11. TOOL DEFINITION (LLM Function Calling)
# ══════════════════════════════════════════════════════════════

PORT_SCAN_TOOL_DEFINITION = {
    "name": "port_scan_service_enum",
    "description": (
        "Comprehensive port scanning with service detection, OS fingerprinting, "
        "and NSE script scanning. Supports nmap (full-featured), naabu (fast discovery), "
        "netcat (banner grab), and masscan (ultra-fast). Returns structured data including "
        "ports, services, versions, banners, CPEs, scripts, OS matches, and traceroute. "
        "Includes rate limiting, caching, and auto-scaling timeouts."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["nmap", "naabu", "netcat", "masscan"],
                "description": (
                    "Scanner tool:\n"
                    "• nmap = Full-featured (ports + services + OS + scripts + traceroute)\n"
                    "• naabu = Fast port discovery only (ProjectDiscovery, good for recon)\n"
                    "• netcat = Quick port check + banner grab\n"
                    "• masscan = Ultra-fast scanner (requires root, less accurate)"
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "Target specification:\n"
                    "• Single IP: '10.10.10.1'\n"
                    "• Domain: 'example.com'\n"
                    "• CIDR: '10.10.10.0/24' (max /24 = 256 hosts)\n"
                    "• Range: '10.10.10.1-100'"
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n\n"
                    "PORT SELECTION:\n"
                    "  ['-p', '22,80,443']       Specific ports\n"
                    "  ['-p-']                   All 65535 ports\n"
                    "  ['--top-ports', '100']    Top 100 common ports\n\n"
                    "SERVICE DETECTION:\n"
                    "  ['-sV']                   Version fingerprinting\n"
                    "  ['-sV', '--version-intensity', '9']  Aggressive\n\n"
                    "OS DETECTION (requires root):\n"
                    "  ['-O']                    OS fingerprinting\n"
                    "  ['-O', '--osscan-guess']  Aggressive guessing\n\n"
                    "SCRIPTS:\n"
                    "  ['--script=default']      Safe default scripts\n"
                    "  ['--script=vuln']         Vulnerability checks\n"
                    "  ['--script=http-enum,http-headers']  Specific scripts\n"
                    "  ['--script=smb-*']        All SMB scripts\n\n"
                    "COMBOS:\n"
                    "  ['-A']                    Aggressive (sV + O + sC + traceroute)\n"
                    "  ['-T4', '-A', '-p-']      Full aggressive scan\n\n"
                    "STEALTH:\n"
                    "  ['-sS', '-T2']            Slow SYN scan\n"
                    "  ['-sS', '-f', '-T2']      Fragmented stealth\n\n"
                    "UDP:\n"
                    "  ['-sU', '-p', '53,161']   UDP scan (slow)\n"
                ),
            },
            "timeout": {
                "type": "integer",
                "description": (
                    "Base timeout in seconds (default: 600). "
                    "Auto-scales based on scan scope (ports, hosts, options)."
                ),
            },
            "use_cache": {
                "type": "boolean",
                "description": "Enable result caching (default: true)",
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 12. UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def get_rate_limiter_stats() -> dict:
    """Get rate limiter configuration"""
    return {
        "calls_per_second": SCAN_RATE_LIMITER.calls_per_second,
        "min_interval": SCAN_RATE_LIMITER.min_interval,
    }


def set_rate_limit(calls_per_second: float):
    """Adjust rate limit"""
    global SCAN_RATE_LIMITER
    SCAN_RATE_LIMITER = RateLimiter(calls_per_second=calls_per_second)


def list_blocked_script_categories() -> list[str]:
    """Return list of blocked script categories"""
    return list(DANGEROUS_SCRIPT_CATEGORIES)


def get_security_settings() -> dict:
    """Return current security settings"""
    return {
        "blocked_targets": BLOCKED_TARGETS,
        "max_cidr_hosts": MAX_CIDR_HOSTS,
        "blocked_output_flags": BLOCKED_OUTPUT_FLAGS,
        "dangerous_script_categories": DANGEROUS_SCRIPT_CATEGORIES,
        "max_xml_size": MAX_XML_SIZE,
    }


# ══════════════════════════════════════════════════════════════
# 13. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("=" * 70)
    print("PORT SCAN & SERVICE ENUMERATION — v2.0")
    print("Rate Limited | Cached | Auto-Timeout | Secure")
    print("=" * 70)

    # ─────────────────────────────────────────
    # 1. Quick port scan
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 1: Quick Port Scan")
    print("─" * 50)
    
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-T4", "--top-ports", "100"],
        use_cache=False,
    )
    
    print(f"Command:    {r['command']}")
    print(f"Success:    {r['success']}")
    print(f"Hosts:      {r['total_hosts']}")
    print(f"Open Ports: {r['total_open_ports']}")
    print(f"Exec Time:  {r['execution_time']}s")
    
    if r['hosts']:
        print("\nPorts Found:")
        for host in r['hosts']:
            ip = host.get('ip', 'unknown')
            for port in host.get('open_ports', []):
                service = port.get('service', 'unknown')
                version = port.get('version', '')
                print(f"  {ip}:{port['port']}/{port['protocol']} - {service} {version}")

    # ─────────────────────────────────────────
    # 2. Service version detection
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 2: Service Version Detection")
    print("─" * 50)
    
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-sV", "--version-intensity", "5", "-p", "22,80"],
        use_cache=False,
    )
    
    print(f"Command: {r['command']}")
    if r['hosts']:
        for host in r['hosts']:
            for port in host.get('open_ports', []):
                print(f"  Port {port['port']}:")
                print(f"    Service: {port.get('service', 'N/A')}")
                print(f"    Product: {port.get('product', 'N/A')}")
                print(f"    Version: {port.get('version', 'N/A')}")
                print(f"    CPE:     {port.get('cpe', 'N/A')}")

    # ─────────────────────────────────────────
    # 3. Script scanning
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 3: Script Scanning (default scripts)")
    print("─" * 50)
    
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["--script=default", "-sV", "-p", "22,80"],
        use_cache=False,
    )
    
    print(f"Command: {r['command']}")
    if r['hosts']:
        for host in r['hosts']:
            for port in host.get('open_ports', []):
                if port.get('scripts'):
                    print(f"\n  Port {port['port']} Scripts:")
                    for script_name, script_output in port['scripts'].items():
                        if isinstance(script_output, dict):
                            print(f"    {script_name}: [structured data]")
                        else:
                            output_preview = str(script_output)[:100].replace('\n', ' ')
                            print(f"    {script_name}: {output_preview}...")

    # ─────────────────────────────────────────
    # 4. Cache test
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 4: Cache Performance")
    print("─" * 50)
    
    # First call (cache miss)
    start = time.time()
    r1 = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-T4", "-F"],
        use_cache=True,
    )
    first_time = time.time() - start
    
    # Second call (cache hit)
    start = time.time()
    r2 = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-T4", "-F"],
        use_cache=True,
    )
    cache_time = time.time() - start
    
    print(f"First run:   {first_time:.2f}s")
    print(f"Cached run:  {cache_time:.4f}s")
    print(f"Speedup:     {first_time / cache_time:.0f}x" if cache_time > 0 else "Instant")
    
    info = get_cache_info()
    print(f"Cache stats: hits={info.hits}, misses={info.misses}, size={info.currsize}/{info.maxsize}")

    # ─────────────────────────────────────────
    # 5. Naabu fast scan
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 5: Naabu Fast Discovery")
    print("─" * 50)
    
    r = port_scan_service_enum(
        tool="naabu",
        target="scanme.nmap.org",
        args=["-top-ports", "100"],
        use_cache=False,
    )
    
    print(f"Command:    {r['command']}")
    print(f"Open Ports: {r['total_open_ports']}")
    print(f"Exec Time:  {r['execution_time']}s")

    # ─────────────────────────────────────────
    # 6. Security validation test
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 6: Security Validation")
    print("─" * 50)
    
    
    # Test blocked script
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["--script=exploit"],
    )
    print(f"Exploit scripts blocked: {'✅' if not r['success'] else '❌'}")
    print(f"  Error: {r.get('error', 'N/A')[:60]}...")
    
    # Test blocked custom script path
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["--script=/tmp/evil.nse"],
    )
    print(f"Custom script paths blocked: {'✅' if not r['success'] else '❌'}")
    print(f"  Error: {r.get('error', 'N/A')[:60]}...")

    # ─────────────────────────────────────────
    # 7. Full JSON output sample
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 7: Sample JSON Output")
    print("─" * 50)
    
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-sV", "-p", "22,80"],
        use_cache=True,
    )
    
    # Summary version for display
    summary = {
        "success": r['success'],
        "tool": r['tool'],
        "target": r['target'],
        "total_hosts": r['total_hosts'],
        "total_open_ports": r['total_open_ports'],
        "execution_time": r['execution_time'],
        "warnings": r.get('warnings', []),
        "hosts": [
            {
                "ip": h.get('ip'),
                "open_ports": [
                    {
                        "port": p['port'],
                        "service": p.get('service'),
                        "version": p.get('version'),
                    }
                    for p in h.get('open_ports', [])[:3]  # First 3 ports
                ]
            }
            for h in r.get('hosts', [])[:2]  # First 2 hosts
        ],
    }
    print(json.dumps(summary, indent=2))

    # ─────────────────────────────────────────
    # 8. Security settings
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 8: Security Settings")
    print("─" * 50)
    
    settings = get_security_settings()
    print(f"Blocked targets:      {settings['blocked_targets'][:3]}...")
    print(f"Max CIDR hosts:       {settings['max_cidr_hosts']}")
    print(f"Blocked script cats:  {settings['dangerous_script_categories']}")
    print(f"Max XML size:         {settings['max_xml_size'] / 1024 / 1024:.0f} MB")

    # ─────────────────────────────────────────
    # 9. LLM Tool Definition
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("LLM TOOL DEFINITION")
    print("─" * 50)
    print(json.dumps(PORT_SCAN_TOOL_DEFINITION, indent=2)[:2000] + "...")

    print("\n" + "=" * 70)
    print("All tests completed!")
    print("=" * 70)