import subprocess
import json
import re
import time
import os
from typing import Optional, Any
from pydantic import BaseModel, Field, validator
from pathlib import Path


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class VulnScanRequest(BaseModel):
    tool: str
    target: str
    scan_type: str = "default"
    args: list[str] = []
    timeout: int = Field(default=1800, ge=60, le=7200)  # 30 min default
    
    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"nmap", "nuclei"}
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
    
    @validator("scan_type")
    def validate_scan_type(cls, v):
        # Nmap vuln categories
        nmap_types = {
            "default", "vuln", "exploit", "malware", "discovery",
            "eternalblue", "bluekeep", "printnightmare", "heartbleed",
            "smb-vuln", "http-vuln", "ssl-vuln", "rdp-vuln",
            "ms17-010", "cve-2019-0708", "cve-2021-34527", "cve-2014-0160"
        }
        # Nuclei templates
        nuclei_types = {
            "default", "cves", "panels", "exposures", "technologies",
            "misconfiguration", "vulnerabilities", "network",
            "cnvd", "cve", "takeovers", "iot", "wordpress"
        }
        all_types = nmap_types | nuclei_types
        if v not in all_types:
            raise ValueError(f"Unknown scan_type: {v}")
        return v
    
    @validator("args")
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags = ["-oN", "-oG", "-oS", "-iL"]
        
        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked flag: {arg}")
        
        return v


class VulnerabilityMatch(BaseModel):
    """Individual vulnerability finding"""
    vuln_id: Optional[str] = None          # CVE-2017-0143, MS17-010, etc.
    name: str                               # EternalBlue, Heartbleed, etc.
    severity: Optional[str] = None          # critical, high, medium, low, info
    description: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = "tcp"
    service: Optional[str] = None
    state: str = "VULNERABLE"               # VULNERABLE, LIKELY VULNERABLE, NOT VULNERABLE
    cvss: Optional[float] = None
    cve: list[str] = []                     # Multiple CVEs may apply
    references: list[str] = []
    exploit_available: bool = False
    extra_info: Optional[dict[str, Any]] = None
    raw_output: Optional[str] = None


class HostVulnResult(BaseModel):
    """Vulnerabilities per host"""
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vulnerabilities: list[VulnerabilityMatch] = []
    summary: Optional[dict[str, int]] = None  # {critical: 2, high: 5, ...}


class VulnScanResult(BaseModel):
    """Final result"""
    success: bool
    tool: str
    target: str
    scan_type: str
    command: str
    total_hosts: int = 0
    total_vulnerabilities: int = 0
    severity_summary: dict[str, int] = {}   # Overall severity counts
    hosts: list[HostVulnResult] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. NMAP VULN SCRIPT MAPPINGS
# ══════════════════════════════════════════════════════════════

NMAP_VULN_SCRIPTS = {
    "eternalblue": "smb-vuln-ms17-010",
    "ms17-010": "smb-vuln-ms17-010",
    "bluekeep": "rdp-vuln-ms12-020,rdp-enum-encryption",
    "cve-2019-0708": "rdp-vuln-ms12-020",
    "printnightmare": "smb-vuln-cve-2021-1675",
    "cve-2021-34527": "smb-vuln-cve-2021-1675",
    "heartbleed": "ssl-heartbleed",
    "cve-2014-0160": "ssl-heartbleed",
    
    # Categories
    "smb-vuln": "smb-vuln-*",
    "http-vuln": "http-vuln-*",
    "ssl-vuln": "ssl-*,tls-*",
    "rdp-vuln": "rdp-vuln-*",
    
    # Comprehensive
    "vuln": "vuln",
    "default": "default,vuln",
}


# ══════════════════════════════════════════════════════════════
# 3. NUCLEI TEMPLATE MAPPINGS
# ══════════════════════════════════════════════════════════════

NUCLEI_TEMPLATES = {
    "cves": ["-t", "cves/"],
    "panels": ["-t", "panels/"],
    "exposures": ["-t", "exposures/"],
    "vulnerabilities": ["-t", "vulnerabilities/"],
    "network": ["-t", "network/"],
    "misconfiguration": ["-t", "misconfiguration/"],
    "technologies": ["-t", "technologies/"],
    "cnvd": ["-t", "cnvd/"],
    "takeovers": ["-t", "takeovers/"],
    "iot": ["-t", "iot/"],
    "wordpress": ["-t", "vulnerabilities/wordpress/"],
    
    # Specific CVEs
    "eternalblue": ["-t", "cves/2017/CVE-2017-0143.yaml"],
    "ms17-010": ["-t", "cves/2017/CVE-2017-0143.yaml"],
    "printnightmare": ["-t", "cves/2021/CVE-2021-34527.yaml"],
    "heartbleed": ["-t", "cves/2014/CVE-2014-0160.yaml"],
    
    "default": ["-t", "cves/", "-t", "vulnerabilities/", "-t", "exposures/"],
}


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_nmap_vulns(xml_output: str) -> list[HostVulnResult]:
    """Parse nmap XML for vulnerability script results"""
    import xml.etree.ElementTree as ET
    
    hosts = []
    
    try:
        root = ET.fromstring(xml_output)
        
        for host_elem in root.findall(".//host"):
            host = HostVulnResult()
            
            # Get IP
            addr = host_elem.find("address")
            if addr is not None:
                host.ip = addr.get("addr")
            
            # Get hostname
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    host.hostname = hn.get("name")
            
            # Parse port-level scripts
            for port_elem in host_elem.findall(".//port"):
                port_num = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                
                service_elem = port_elem.find("service")
                service_name = service_elem.get("name") if service_elem is not None else None
                
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")
                    
                    # Only process vuln-related scripts
                    if not ("vuln" in script_id or "cve" in script_id.lower()):
                        continue
                    
                    vuln = parse_nmap_script_output(
                        script_id, script_output, script_elem,
                        port_num, protocol, service_name
                    )
                    
                    if vuln:
                        host.vulnerabilities.append(vuln)
            
            # Parse host-level scripts
            hostscript = host_elem.find("hostscript")
            if hostscript is not None:
                for script_elem in hostscript.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")
                    
                    if "vuln" in script_id or "cve" in script_id.lower():
                        vuln = parse_nmap_script_output(
                            script_id, script_output, script_elem
                        )
                        if vuln:
                            host.vulnerabilities.append(vuln)
            
            # Build summary
            if host.vulnerabilities:
                host.summary = {}
                for v in host.vulnerabilities:
                    sev = v.severity or "unknown"
                    host.summary[sev] = host.summary.get(sev, 0) + 1
                
                hosts.append(host)
        
        return hosts
    
    except ET.ParseError:
        return []


def parse_nmap_script_output(
    script_id: str,
    script_output: str,
    script_elem,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    service: Optional[str] = None
) -> Optional[VulnerabilityMatch]:
    """Parse individual nmap script result"""
    
    # Detect vulnerability state
    state = "NOT VULNERABLE"
    if any(x in script_output.upper() for x in ["VULNERABLE", "LIKELY VULNERABLE"]):
        state = "VULNERABLE"
    elif "LIKELY VULNERABLE" in script_output.upper():
        state = "LIKELY VULNERABLE"
    
    if state == "NOT VULNERABLE":
        return None
    
    # Extract CVE IDs
    cves = re.findall(r"(CVE-\d{4}-\d{4,7})", script_output, re.IGNORECASE)
    
    # Extract vuln ID from script name
    vuln_id = None
    if "ms17-010" in script_id.lower():
        vuln_id = "MS17-010"
    elif "ms12-020" in script_id.lower():
        vuln_id = "MS12-020"
    elif match := re.search(r"(CVE-\d{4}-\d{4,7})", script_id, re.IGNORECASE):
        vuln_id = match.group(1).upper()
    
    # Determine severity
    severity = "medium"
    if any(x in script_output.upper() for x in ["CRITICAL", "RCE", "REMOTE CODE"]):
        severity = "critical"
    elif any(x in script_output.upper() for x in ["HIGH", "EXPLOIT"]):
        severity = "high"
    elif "LOW" in script_output.upper():
        severity = "low"
    
    # Check exploit availability
    exploit_available = "exploit" in script_output.lower() or "metasploit" in script_output.lower()
    
    # Extract CVSS if present
    cvss = None
    if cvss_match := re.search(r"CVSS[:\s]+(\d+\.?\d*)", script_output):
        cvss = float(cvss_match.group(1))
    
    # Extract references
    references = []
    for ref in re.findall(r"https?://[^\s]+", script_output):
        references.append(ref)
    
    # Parse structured data from elem
    extra_info = {}
    for table in script_elem.findall(".//table"):
        for elem in table.findall("elem"):
            key = elem.get("key", "")
            if key:
                extra_info[key] = elem.text or ""
    
    return VulnerabilityMatch(
        vuln_id=vuln_id or cves[0] if cves else None,
        name=script_id.replace("_", " ").title(),
        severity=severity,
        description=script_output[:500].strip(),
        port=port,
        protocol=protocol,
        service=service,
        state=state,
        cvss=cvss,
        cve=cves,
        references=references,
        exploit_available=exploit_available,
        extra_info=extra_info if extra_info else None,
        raw_output=script_output
    )


def parse_nuclei_json(output: str) -> list[HostVulnResult]:
    """Parse nuclei JSONL output"""
    
    hosts_dict = {}
    
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        
        try:
            data = json.loads(line)
            
            # Extract target info
            host_ip = data.get("host", data.get("ip", "unknown"))
            matched_at = data.get("matched-at", host_ip)
            
            # Parse URL for port
            port = None
            if "://" in matched_at:
                if ":443" in matched_at or matched_at.startswith("https://"):
                    port = 443
                elif match := re.search(r":(\d+)", matched_at):
                    port = int(match.group(1))
                else:
                    port = 80
            
            # Extract vulnerability info
            info = data.get("info", {})
            
            vuln = VulnerabilityMatch(
                vuln_id=data.get("template-id"),
                name=info.get("name", data.get("template-id", "Unknown")),
                severity=info.get("severity", "unknown").lower(),
                description=info.get("description", ""),
                port=port,
                protocol="tcp",
                service=data.get("type", "http"),
                state="VULNERABLE",
                cvss=None,
                cve=info.get("classification", {}).get("cve-id", []),
                references=info.get("reference", []),
                exploit_available="exploit" in str(info.get("tags", [])).lower(),
                extra_info={
                    "matcher_name": data.get("matcher-name"),
                    "extracted_results": data.get("extracted-results"),
                    "tags": info.get("tags", []),
                },
                raw_output=json.dumps(data, indent=2)
            )
            
            # Group by host
            if host_ip not in hosts_dict:
                hosts_dict[host_ip] = HostVulnResult(ip=host_ip)
            
            hosts_dict[host_ip].vulnerabilities.append(vuln)
        
        except json.JSONDecodeError:
            continue
    
    # Build summaries
    hosts = []
    for host in hosts_dict.values():
        host.summary = {}
        for v in host.vulnerabilities:
            sev = v.severity or "unknown"
            host.summary[sev] = host.summary.get(sev, 0) + 1
        hosts.append(host)
    
    return hosts


# ══════════════════════════════════════════════════════════════
# 5. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 1800) -> tuple[str, str, int]:
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
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 6. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def network_vuln_scan(
    tool: str,
    target: str,
    scan_type: str = "default",
    args: list[str] = []
) -> dict:
    """
    🔍 Agent Tool: Network Vulnerability Scanner
    
    Scan for known CVEs and vulnerabilities:
      ┌──────────────────────────────────────────────────────────┐
      │  ETERNALBLUE       MS17-010 (SMB RCE)                   │
      │  BLUEKEEP          CVE-2019-0708 (RDP RCE)              │
      │  PRINTNIGHTMARE    CVE-2021-34527 (Print Spooler)       │
      │  HEARTBLEED        CVE-2014-0160 (OpenSSL)              │
      │  SMB VULNS         MS08-067, MS17-010, etc.             │
      │  HTTP VULNS        SQLi, XSS, LFI, RCE, etc.            │
      │  SSL/TLS VULNS     POODLE, BEAST, CRIME, etc.           │
      │  + 1000s more via nuclei templates                      │
      └──────────────────────────────────────────────────────────┘
    
    Args:
        tool:       "nmap" | "nuclei"
        target:     IP, domain, or CIDR
        scan_type:  Predefined scan (see NMAP_VULN_SCRIPTS / NUCLEI_TEMPLATES)
        args:       Additional raw args
    
    Scan Types (nmap):
        "eternalblue"      → MS17-010 / SMB RCE
        "bluekeep"         → CVE-2019-0708 / RDP
        "printnightmare"   → CVE-2021-34527
        "heartbleed"       → CVE-2014-0160 / OpenSSL
        "smb-vuln"         → All SMB vulns
        "http-vuln"        → All HTTP vulns
        "ssl-vuln"         → All SSL/TLS vulns
        "vuln"             → All vuln scripts
        "default"          → Default + vuln
    
    Scan Types (nuclei):
        "cves"             → All CVE templates
        "vulnerabilities"  → Known vulns
        "exposures"        → Exposed panels/configs
        "network"          → Network service vulns
        "eternalblue"      → Specific CVE template
        "printnightmare"   → Specific CVE template
        "heartbleed"       → Specific CVE template
        "default"          → CVEs + vulns + exposures
    
    Nmap Examples:
        args=["-p", "445", "-sV"]              → EternalBlue on SMB
        args=["-p", "3389"]                    → BlueKeep on RDP
        args=["-p", "443", "-sV"]              → Heartbleed on HTTPS
        args=["--script-args", "vulns.showall"]  → Show all (even non-vuln)
    
    Nuclei Examples:
        args=["-severity", "critical,high"]    → Only critical/high
        args=["-tags", "cve,rce"]              → CVEs + RCE vulns
        args=["-rate-limit", "150"]            → Limit requests/sec
        args=["-silent"]                       → Minimal output
    
    Returns:
        Structured JSON with vulnerabilities per host
    """
    
    start = time.time()
    
    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = VulnScanRequest(
            tool=tool,
            target=target,
            scan_type=scan_type,
            args=args
        )
    except Exception as e:
        return VulnScanResult(
            success=False, tool=tool, target=target,
            scan_type=scan_type, command="",
            error=f"Validation: {e}"
        ).model_dump()
    
    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if tool == "nmap":
        # Get script from mapping
        script = NMAP_VULN_SCRIPTS.get(scan_type, scan_type)
        
        cmd = ["nmap"]
        
        # Add script
        cmd.extend(["--script", script])
        
        # Auto-add service detection for better results
        if "-sV" not in args:
            cmd.append("-sV")
        
        # Add XML output
        cmd.extend(["-oX", "-"])
        
        # Add custom args
        cmd.extend(args)
        
        # Add target
        cmd.append(target)
    
    elif tool == "nuclei":
        cmd = ["nuclei"]
        
        # Get templates from mapping
        template_args = NUCLEI_TEMPLATES.get(scan_type, NUCLEI_TEMPLATES["default"])
        cmd.extend(template_args)
        
        # JSON output
        if "-json" not in args and "-jsonl" not in args:
            cmd.append("-jsonl")
        
        # Add target
        cmd.extend(["-u", target])
        
        # Add custom args
        cmd.extend(args)
    
    else:
        return VulnScanResult(
            success=False, tool=tool, target=target,
            scan_type=scan_type, command="",
            error=f"Unknown tool: {tool}"
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
    
    if tool == "nmap":
        hosts = parse_nmap_vulns(stdout)
    elif tool == "nuclei":
        hosts = parse_nuclei_json(stdout)
    
    # ══════════════════════════════
    # BUILD SUMMARY
    # ══════════════════════════════
    total_vulns = sum(len(h.vulnerabilities) for h in hosts)
    
    severity_summary = {}
    for host in hosts:
        for vuln in host.vulnerabilities:
            sev = vuln.severity or "unknown"
            severity_summary[sev] = severity_summary.get(sev, 0) + 1
    
    # ══════════════════════════════
    # RETURN RESULT
    # ══════════════════════════════
    return VulnScanResult(
        success=total_vulns > 0 or rc == 0,
        tool=tool,
        target=target,
        scan_type=scan_type,
        command=command_str,
        total_hosts=len(hosts),
        total_vulnerabilities=total_vulns,
        severity_summary=severity_summary,
        hosts=hosts,
        raw_output=(stdout or stderr)[:10000],  # cap output
        error=stderr if rc != 0 and not hosts else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 7. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

VULN_SCAN_TOOL_DEFINITION = {
    "name": "network_vuln_scan",
    "description": (
        "Scan for known network vulnerabilities and CVEs using nmap vuln scripts or nuclei. "
        "Detects EternalBlue, BlueKeep, PrintNightmare, Heartbleed, and 1000+ other vulns."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["nmap", "nuclei"],
                "description": (
                    "nmap = NSE vuln scripts (deep, per-service) | "
                    "nuclei = template-based (fast, broad coverage)"
                )
            },
            "target": {
                "type": "string",
                "description": "IP, domain, or CIDR (e.g. '10.10.10.1', 'example.com', '192.168.1.0/24')"
            },
            "scan_type": {
                "type": "string",
                "description": (
                    "Nmap: eternalblue | bluekeep | printnightmare | heartbleed | "
                    "smb-vuln | http-vuln | ssl-vuln | vuln | default\n"
                    "Nuclei: cves | vulnerabilities | exposures | network | "
                    "eternalblue | printnightmare | heartbleed | default"
                ),
                "default": "default"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Nmap: ['-p', '445'] | ['-sV'] | ['--script-args', 'vulns.showall']\n"
                    "Nuclei: ['-severity', 'critical,high'] | ['-tags', 'cve,rce'] | ['-rate-limit', '150']"
                )
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 8. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    
    # ─────────────────────────────
    # 1. EternalBlue (MS17-010)
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nmap",
        target="10.10.10.40",  # Blue CTF machine
        scan_type="eternalblue",
        args=["-p", "445"]
    )
    print("=== ETERNALBLUE ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 2. BlueKeep (CVE-2019-0708)
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nmap",
        target="10.10.10.1",
        scan_type="bluekeep",
        args=["-p", "3389"]
    )
    print("=== BLUEKEEP ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 3. PrintNightmare
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nuclei",
        target="10.10.10.1",
        scan_type="printnightmare"
    )
    print("=== PRINTNIGHTMARE ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 4. Heartbleed
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nmap",
        target="scanme.nmap.org",
        scan_type="heartbleed",
        args=["-p", "443"]
    )
    print("=== HEARTBLEED ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 5. All SMB vulns
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nmap",
        target="10.10.10.1",
        scan_type="smb-vuln",
        args=["-p", "139,445"]
    )
    print("=== SMB VULNS ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 6. All HTTP vulns
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nmap",
        target="10.10.10.1",
        scan_type="http-vuln",
        args=["-p", "80,443,8080"]
    )
    print("=== HTTP VULNS ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 7. Nuclei CVE scan
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nuclei",
        target="https://example.com",
        scan_type="cves",
        args=["-severity", "critical,high"]
    )
    print("=== NUCLEI CVES ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 8. Nuclei exposures
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nuclei",
        target="http://10.10.10.1",
        scan_type="exposures"
    )
    print("=== EXPOSURES ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 9. Full vuln scan (nmap)
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nmap",
        target="10.10.10.1",
        scan_type="vuln",
        args=["-sV", "-p-", "-T4"]
    )
    print("=== FULL VULN SCAN ===")
    print(json.dumps(r, indent=2))
    
    # ─────────────────────────────
    # 10. Network template (nuclei)
    # ─────────────────────────────
    r = network_vuln_scan(
        tool="nuclei",
        target="10.10.10.0/24",
        scan_type="network",
        args=["-rate-limit", "100"]
    )
    print("=== NETWORK VULNS ===")
    print(json.dumps(r, indent=2))