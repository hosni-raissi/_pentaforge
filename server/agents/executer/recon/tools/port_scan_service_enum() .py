import subprocess
import json
import re
import time
import xml.etree.ElementTree as ET
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class PortScanRequest(BaseModel):
    tool: str
    args: list[str] = []
    target: str
    timeout: int = Field(default=600, ge=30, le=7200)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"nmap", "naabu", "netcat"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if v.strip() in blocked:
            raise ValueError(f"Target '{v}' is blocked")

        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        ip_range_pattern = r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$"

        if not (re.match(ip_pattern, v) or
                re.match(domain_pattern, v) or
                re.match(ip_range_pattern, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        """Block shell injection ONLY — let agent use ALL tool features"""
        # ── ONLY block shell injection characters ──
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']

        # ── Block file write (prevent data exfil) ──
        blocked_output_flags = ["-oN", "-oG", "-oS"]

        # ── Block dangerous nmap scripts ──
        dangerous_scripts = [
            "broadcast",    # scans entire network
            "dos",          # denial of service
            "exploit",      # auto exploitation
            "fuzzer",       # can crash services
        ]

        for arg in v:
            # shell injection check
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")

            # file write check
            for flag in blocked_output_flags:
                if arg.strip() == flag:
                    raise ValueError(f"File output blocked: {arg}")

            # dangerous script category check
            if arg.startswith("--script=") or arg.startswith("--script "):
                script_value = arg.split("=", 1)[-1] if "=" in arg else ""
                for ds in dangerous_scripts:
                    if ds in script_value:
                        raise ValueError(f"Dangerous script category blocked: {ds}")

        return v


# ── Port Result ──
class PortResult(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None                          # e.g. cpe:/a:apache:http_server:2.4.41
    scripts: Optional[dict[str, str]] = None           # {script_name: output}


# ── OS Detection Result ──
class OSResult(BaseModel):
    name: Optional[str] = None
    accuracy: Optional[int] = None
    os_family: Optional[str] = None
    os_gen: Optional[str] = None
    cpe: Optional[str] = None


# ── Host Result ──
class HostResult(BaseModel):
    ip: Optional[str] = None
    hostname: Optional[str] = None
    state: str = "up"
    open_ports: list[PortResult] = []
    os_matches: list[OSResult] = []
    host_scripts: Optional[dict[str, str]] = None       # host-level script results
    traceroute: Optional[list[dict[str, Any]]] = None   # hop info
    uptime: Optional[str] = None
    distance: Optional[int] = None                       # network hops


# ── Final Result ──
class ScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    scan_info: Optional[dict[str, Any]] = None           # scan type, protocol, services
    total_hosts: int = 0
    total_open_ports: int = 0
    hosts: list[HostResult] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_nmap(stdout: str, stderr: str) -> tuple[list[HostResult], Optional[dict]]:
    """
    Full nmap XML parser:
    - Ports + services + versions + banners
    - NSE script output (per-port AND per-host)
    - OS detection
    - Traceroute
    - CPE
    """
    hosts = []
    scan_info = None

    # ══════════════════════════════
    # TRY XML PARSE
    # ══════════════════════════════
    try:
        root = ET.fromstring(stdout)

        # ── Scan Info ──
        scan_info_elem = root.find(".//scaninfo")
        if scan_info_elem is not None:
            scan_info = {
                "type": scan_info_elem.get("type"),
                "protocol": scan_info_elem.get("protocol"),
                "services": scan_info_elem.get("services"),
            }

        # ── Parse Each Host ──
        for host_elem in root.findall(".//host"):

            host = HostResult()

            # ── IP & Hostname ──
            addr = host_elem.find("address")
            if addr is not None:
                host.ip = addr.get("addr")

            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    host.hostname = hn.get("name")

            # ── Host State ──
            status = host_elem.find("status")
            if status is not None:
                host.state = status.get("state", "unknown")

            # ── Ports ──
            for port_elem in host_elem.findall(".//port"):
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
                    cpe_elem = svc_elem.find("cpe")
                    if cpe_elem is not None and cpe_elem.text:
                        port.cpe = cpe_elem.text

                # ── Per-Port Scripts ──
                scripts = {}
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "unknown")
                    script_output = script_elem.get("output", "")

                    # Also grab structured tables if present
                    tables = []
                    for table in script_elem.findall(".//table"):
                        table_data = {}
                        for elem in table.findall("elem"):
                            key = elem.get("key", "")
                            table_data[key] = elem.text or ""
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
            for os_match in host_elem.findall(".//osmatch"):
                os_result = OSResult(
                    name=os_match.get("name"),
                    accuracy=int(os_match.get("accuracy", 0)),
                )
                os_class = os_match.find("osclass")
                if os_class is not None:
                    os_result.os_family = os_class.get("osfamily")
                    os_result.os_gen = os_class.get("osgen")
                    cpe_elem = os_class.find("cpe")
                    if cpe_elem is not None:
                        os_result.cpe = cpe_elem.text

                host.os_matches.append(os_result)

            # ── Host-Level Scripts (e.g., smb-os-discovery) ──
            hostscript = host_elem.find("hostscript")
            if hostscript is not None:
                host_scripts = {}
                for script_elem in hostscript.findall("script"):
                    script_id = script_elem.get("id", "unknown")
                    script_output = script_elem.get("output", "")
                    host_scripts[script_id] = script_output
                host.host_scripts = host_scripts

            # ── Traceroute ──
            trace = host_elem.find("trace")
            if trace is not None:
                hops = []
                for hop in trace.findall("hop"):
                    hops.append({
                        "ttl": hop.get("ttl"),
                        "ip": hop.get("ipaddr"),
                        "rtt": hop.get("rtt"),
                        "host": hop.get("host", ""),
                    })
                host.traceroute = hops

            # ── Uptime ──
            uptime_elem = host_elem.find("uptime")
            if uptime_elem is not None:
                host.uptime = f"{uptime_elem.get('seconds', '?')}s (since {uptime_elem.get('lastboot', '?')})"

            # ── Distance ──
            distance_elem = host_elem.find("distance")
            if distance_elem is not None:
                host.distance = int(distance_elem.get("value", 0))

            hosts.append(host)

        return hosts, scan_info

    except ET.ParseError:
        pass

    # ══════════════════════════════
    # FALLBACK: REGEX PARSE
    # ══════════════════════════════
    raw = stdout or stderr
    host = HostResult(ip=None)

    # ── Ports ──
    for m in re.finditer(r"(\d+)/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)\s*(.*)", raw):
        host.open_ports.append(PortResult(
            port=int(m.group(1)),
            protocol=m.group(2),
            state=m.group(3),
            service=m.group(4),
            version=m.group(5).strip() or None,
        ))

    # ── OS ──
    os_match = re.search(r"OS details?:\s*(.+)", raw)
    if os_match:
        host.os_matches.append(OSResult(name=os_match.group(1).strip()))

    # ── Script output (basic) ──
    script_blocks = re.findall(r"\|\s+(\S+):\s*\n((?:\|[^\n]*\n)*)", raw)
    if script_blocks:
        host_scripts = {}
        for script_name, script_body in script_blocks:
            cleaned = re.sub(r"^\|\s*", "", script_body, flags=re.MULTILINE).strip()
            host_scripts[script_name] = cleaned
        host.host_scripts = host_scripts

    if host.open_ports:
        hosts.append(host)

    return hosts, None


def parse_naabu(stdout: str) -> list[HostResult]:
    """Parse naabu JSON or host:port output"""
    ports_by_host: dict[str, list[PortResult]] = {}

    for line in stdout.strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            host_ip = data.get("host", data.get("ip", "unknown"))
            port = PortResult(
                port=int(data.get("port", 0)),
                protocol=data.get("protocol", "tcp"),
                state="open",
            )
            ports_by_host.setdefault(host_ip, []).append(port)
        except json.JSONDecodeError:
            if ":" in line:
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    host_ip = parts[0]
                    port = PortResult(port=int(parts[1]), state="open")
                    ports_by_host.setdefault(host_ip, []).append(port)

    hosts = []
    for ip, ports in ports_by_host.items():
        hosts.append(HostResult(ip=ip, open_ports=ports))
    return hosts


def parse_netcat(stdout: str, stderr: str) -> list[HostResult]:
    """Parse netcat output — banner grab + port check"""
    ports = []
    raw = stderr or stdout

    patterns = [
        r"(\d+)\s+port\s+\[(\w+)/(\w+)\]\s+succeeded",
        r"]\s+(\d+)\s+\((\w+)\)\s+open",
        r"(\d+).*open",
        r"succeeded!.*?(\d+)",
        r"Connection to \S+\s+(\d+)\s+port",
    ]

    for line in raw.split("\n"):
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                port = PortResult(
                    port=int(match.group(1)),
                    state="open",
                    service=match.group(3) if len(match.groups()) >= 3 else None,
                )

                # ── Try to capture banner from stdout ──
                if stdout.strip():
                    port.banner = stdout.strip()[:500]  # limit banner size

                ports.append(port)
                break

    hosts = []
    if ports:
        hosts.append(HostResult(open_ports=ports))
    return hosts


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

def port_scan_service_enum(tool: str, target: str, args: list[str] = []) -> dict:
    """
    🔧 Agent Tool: Port Scan, Service Enum, Script Scan, OS Fingerprint

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  PORT SCANNING        nmap, naabu, netcat                   │
      │  SERVICE DETECTION    nmap -sV                              │
      │  OS FINGERPRINT       nmap -O                               │
      │  BANNER GRABBING      nmap -sV, netcat                     │
      │  SCRIPT SCANNING      nmap --script=<scripts>               │
      │  TRACEROUTE           nmap --traceroute                     │
      │  AGGRESSIVE SCAN      nmap -A (all of the above)            │
      └─────────────────────────────────────────────────────────────┘

    Args:
        tool:    "nmap" | "naabu" | "netcat"
        target:  IP or domain
        args:    Raw tool arguments — agent decides

    Nmap args reference:
        Port:     ["-p", "80,443"] | ["-p-"] | ["--top-ports", "100"]
        Service:  ["-sV"] | ["-sV", "--version-intensity", "5"]
        OS:       ["-O"] | ["-O", "--osscan-guess"]
        Scripts:  ["--script=default"] | ["--script=vuln"] | ["--script=http-enum,http-headers"]
        Scan:     ["-sS"] | ["-sT"] | ["-sU"] | ["-sA"] | ["-sN"]
        Speed:    ["-T0"] ... ["-T5"]
        Combo:    ["-A"] = -sV -O -sC --traceroute
        Stealth:  ["-sS", "-T2", "-f", "--data-length", "24"]
        UDP:      ["-sU", "-p", "53,161,500"]

    Naabu args reference:
        Ports:    ["-p", "80,443"] | ["-p", "-"] | ["-top-ports", "100"]
        Speed:    ["-rate", "1000"] | ["-c", "50"]
        Type:     ["-scan-type", "s"] (SYN) | ["-scan-type", "c"] (CONNECT)

    Netcat args reference:
        Scan:     ["-zv", "-w", "3", "80"]
        Range:    ["-zv", "-w", "3", "20-100"]
        Banner:   ["-v", "-w", "3", "80"]  (without -z to grab banner)
        UDP:      ["-u", "-zv", "-w", "3", "53"]

    Returns:
        Structured JSON: hosts → ports → services → scripts → OS
    """

    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = PortScanRequest(tool=tool, target=target, args=args)
    except Exception as e:
        return ScanResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if tool == "nmap":
        final_args = list(args)

        # Auto-inject XML output for full parsing
        if "-oX" not in final_args:
            final_args.extend(["-oX", "-"])

        # Auto-inject reason for state info
        if "--reason" not in final_args:
            final_args.append("--reason")

        cmd = ["nmap"] + final_args + [target]

    elif tool == "naabu":
        cmd = ["naabu", "-host", target] + list(args)
        if "-json" not in cmd:
            cmd.append("-json")
        if "-silent" not in cmd:
            cmd.append("-silent")

    elif tool == "netcat":
        cmd = ["nc"] + list(args) + [target]

    else:
        return ScanResult(
            success=False, tool=tool, target=target,
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
    hosts = []
    scan_info = None

    if tool == "nmap":
        hosts, scan_info = parse_nmap(stdout, stderr)
    elif tool == "naabu":
        hosts = parse_naabu(stdout)
    elif tool == "netcat":
        hosts = parse_netcat(stdout, stderr)

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    total_ports = sum(len(h.open_ports) for h in hosts)

    return ScanResult(
        success=total_ports > 0 or rc == 0,
        tool=tool,
        target=target,
        command=command_str,
        scan_info=scan_info,
        total_hosts=len(hosts),
        total_open_ports=total_ports,
        hosts=hosts,
        raw_output=(stdout or stderr)[:5000],  # cap raw output
        error=stderr if rc != 0 and not hosts else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 5. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

PORT_SCAN_TOOL_DEFINITION = {
    "name": "port_scan_service_enum",
    "description": (
        "Scan target for open ports, service versions, OS fingerprint, "
        "banner grabbing, and NSE script scanning. "
        "Supports nmap (full-featured), naabu (fast port discovery), netcat (banner grab). "
        "YOU decide the args."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["nmap", "naabu", "netcat"],
                "description": (
                    "nmap = full scan (ports + services + OS + scripts + traceroute) | "
                    "naabu = fast port discovery only | "
                    "netcat = quick port check + banner grab"
                ),
            },
            "target": {
                "type": "string",
                "description": "IP or domain (e.g. '10.10.10.1', 'example.com', '192.168.1.0/24')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "Port scan:     ['-p', '80,443'] or ['-p-'] or ['--top-ports', '100'] .... etc\n"
                    "Service:       ['-sV']\n"
                    "OS:            ['-O']\n"
                    "Scripts:       ['--script=default'] or ['--script=vuln'] or ['--script=http-enum']\n"
                    "Aggressive:    ['-A'] (= -sV -O -sC --traceroute)\n"
                    "Stealth:       ['-sS', '-T2']\n"
                    "UDP:           ['-sU', '-p', '53,161']\n"
                    "Fast full:     ['-p-', '-T4', '--min-rate', '1000']\n"
                    "Banner only:   netcat ['-v', '-w', '3', '80']"
                ),
            },
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 6. USAGE EXAMPLES — WHAT AGENT CALLS
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Quick port scan
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-T4", "--top-ports", "100"]
    )
    print("=== QUICK SCAN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Service version detection
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-sV", "--version-intensity", "5", "-p", "22,80,443"]
    )
    print("=== SERVICE DETECTION ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. OS fingerprint
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-O", "--osscan-guess", "-p", "22,80"]
    )
    print("=== OS FINGERPRINT ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Script scanning
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["--script=default", "-sV", "-p", "22,80"]
    )
    print("=== DEFAULT SCRIPTS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Vuln scan scripts
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["--script=vuln", "-p", "80,443"]
    )
    print("=== VULN SCRIPTS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. Specific scripts
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=[
            "--script=http-enum,http-headers,http-methods,http-title",
            "-sV", "-p", "80,443"
        ]
    )
    print("=== HTTP SCRIPTS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. Aggressive (ALL in one)
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="scanme.nmap.org",
        args=["-A", "-T4", "-p", "22,80,443"]
    )
    print("=== AGGRESSIVE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 8. SMB enumeration
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="10.10.10.1",
        args=[
            "--script=smb-os-discovery,smb-enum-shares,smb-enum-users",
            "-p", "139,445"
        ]
    )
    print("=== SMB ENUM ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 9. Stealth scan
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="10.10.10.1",
        args=["-sS", "-T2", "-f", "--data-length", "24", "-p", "22,80,443"]
    )
    print("=== STEALTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 10. UDP scan
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="nmap",
        target="10.10.10.1",
        args=["-sU", "-sV", "-p", "53,161,162,500"]
    )
    print("=== UDP ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 11. Fast naabu discovery
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="naabu",
        target="scanme.nmap.org",
        args=["-top-ports", "1000", "-rate", "1000"]
    )
    print("=== NAABU FAST ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 12. Netcat banner grab
    # ─────────────────────────────
    r = port_scan_service_enum(
        tool="netcat",
        target="scanme.nmap.org",
        args=["-v", "-w", "3", "80"]
    )
    print("=== NETCAT BANNER ===")
    print(json.dumps(r, indent=2))