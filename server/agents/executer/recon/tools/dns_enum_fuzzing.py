import subprocess
import json
import re
import os
import time
import tempfile
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION (shared across all tools)
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools"""
    
    _project_dir: Optional[Path] = None
    
    WORDLISTS_DIR = "wordlists"
    OUTPUT_DIR = "output"
    TEMP_DIR = "tmp"
    LOGS_DIR = "logs"
    
    @classmethod
    def get_project_dir(cls) -> Path:
        if cls._project_dir:
            return cls._project_dir
        
        env_dir = os.environ.get("AGENT_PROJECT_DIR")
        if env_dir and os.path.isdir(env_dir):
            cls._project_dir = Path(env_dir)
            return cls._project_dir
        
        current = Path(__file__).resolve().parent
        markers = ["pyproject.toml", "setup.py", ".git", "requirements.txt", "config.yaml"]
        
        for parent in [current] + list(current.parents):
            if any((parent / marker).exists() for marker in markers):
                cls._project_dir = parent
                return cls._project_dir
        
        cls._project_dir = Path.cwd()
        return cls._project_dir
    
    @classmethod
    def set_project_dir(cls, path: str | Path):
        path = Path(path)
        if not path.is_dir():
            raise ValueError(f"Project directory does not exist: {path}")
        cls._project_dir = path
        cls._ensure_directories()
    
    @classmethod
    def _ensure_directories(cls):
        base = cls.get_project_dir()
        for subdir in [cls.WORDLISTS_DIR, cls.OUTPUT_DIR, cls.TEMP_DIR, cls.LOGS_DIR]:
            (base / subdir).mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_wordlists_dir(cls) -> Path:
        return cls.get_project_dir() / cls.WORDLISTS_DIR
    
    @classmethod
    def get_temp_dir(cls) -> Path:
        return cls.get_project_dir() / cls.TEMP_DIR


# ══════════════════════════════════════════════════════════════
# 2. DNS WORDLIST PATHS
# ══════════════════════════════════════════════════════════════

def _get_dns_wordlist_paths() -> dict[str, str]:
    """
    Get DNS wordlist paths — project dir first, then SecLists.
    """
    project_wl = ProjectConfig.get_wordlists_dir()
    
    wordlists = {
        # ── Subdomain wordlists ──
        "subdomains_short": [
            project_wl / "dns" / "subdomains_short.txt",
            project_wl / "subdomains_short.txt",
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        ],
        "subdomains_medium": [
            project_wl / "dns" / "subdomains_medium.txt",
            project_wl / "subdomains_medium.txt",
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"),
        ],
        "subdomains_large": [
            project_wl / "dns" / "subdomains_large.txt",
            project_wl / "subdomains_large.txt",
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"),
        ],
        "subdomains_full": [
            project_wl / "dns" / "subdomains_full.txt",
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"),
        ],
        
        # ── Common/default subdomains ──
        "subdomains_common": [
            project_wl / "dns" / "subdomains_common.txt",
            Path("/usr/share/seclists/Discovery/DNS/namelist.txt"),
        ],
        "subdomains_bitquark": [
            project_wl / "dns" / "bitquark.txt",
            Path("/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
        ],
        
        # ── Fierce default ──
        "fierce_default": [
            project_wl / "dns" / "fierce.txt",
            Path("/usr/share/fierce/hosts.txt"),
            Path("/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt"),
        ],
        
        # ── DNS-specific ──
        "dns_names": [
            project_wl / "dns" / "dns_names.txt",
            Path("/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"),
        ],
        "deepmagic": [
            project_wl / "dns" / "deepmagic.txt",
            Path("/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt"),
        ],
        
        # ── Resolvers (for massdns/puredns) ──
        "resolvers": [
            project_wl / "dns" / "resolvers.txt",
            project_wl / "resolvers.txt",
            Path("/usr/share/seclists/Miscellaneous/dns-resolvers.txt"),
        ],
        "resolvers_trusted": [
            project_wl / "dns" / "resolvers_trusted.txt",
            project_wl / "resolvers_trusted.txt",
        ],
    }
    
    resolved = {}
    for key, paths in wordlists.items():
        for p in paths:
            if p.is_file():
                resolved[key] = str(p)
                break
        if key not in resolved:
            resolved[key] = str(paths[0])
    
    return resolved


def get_dns_wordlists() -> dict[str, str]:
    return _get_dns_wordlist_paths()


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class DNSEnumRequest(BaseModel):
    tool: str
    args: list[str] = []
    target: str
    list_type: str = "user"
    subdomain_wordlist: Optional[list[str]] = None
    resolver_list: Optional[list[str]] = None
    builtin_subdomain_list: Optional[str] = None
    builtin_resolver_list: Optional[str] = None
    timeout: int = Field(default=600, ge=30, le=7200)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"dig", "dnsrecon", "dnsenum", "fierce", "massdns", "puredns"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip().lower()
        
        # Block local/internal
        blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
        if v in blocked:
            raise ValueError(f"Target '{v}' is blocked")
        
        # Basic domain validation
        domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
        
        if not (re.match(domain_pattern, v) or re.match(ip_pattern, v)):
            raise ValueError(f"Invalid target: {v}")
        
        return v

    @field_validator("list_type")
    @classmethod
    def validate_list_type(cls, v):
        if v not in ("user", "ia"):
            raise ValueError("list_type must be 'user' or 'ia'")
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        for arg in v:
            for char in dangerous:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
        return v

    @field_validator("subdomain_wordlist", "resolver_list")
    @classmethod
    def validate_inline_list(cls, v):
        if v is not None and len(v) > 100000:
            raise ValueError("Inline wordlist too large. Max 100,000 entries.")
        return v

    @field_validator("builtin_subdomain_list")
    @classmethod
    def validate_builtin_subdomain(cls, v):
        if v is not None:
            valid_keys = [k for k in get_dns_wordlists().keys() if k.startswith("subdomain") or k in ("dns_names", "deepmagic", "fierce_default")]
            if v not in valid_keys:
                raise ValueError(f"Unknown subdomain list '{v}'. Available: {valid_keys}")
        return v

    @field_validator("builtin_resolver_list")
    @classmethod
    def validate_builtin_resolver(cls, v):
        if v is not None:
            valid_keys = [k for k in get_dns_wordlists().keys() if k.startswith("resolver")]
            if v not in valid_keys:
                raise ValueError(f"Unknown resolver list '{v}'. Available: {valid_keys}")
        return v


# ── DNS Record Result ──
class DNSRecord(BaseModel):
    record_type: str                    # A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV
    name: str                           # subdomain or full domain
    value: str                          # IP, hostname, or text value
    ttl: Optional[int] = None
    priority: Optional[int] = None      # for MX records
    extra: Optional[dict[str, Any]] = None


# ── Subdomain Result ──
class SubdomainResult(BaseModel):
    subdomain: str                      # full subdomain: sub.example.com
    ip: Optional[str] = None
    ips: list[str] = []                 # multiple IPs if any
    cname: Optional[str] = None
    is_wildcard: bool = False
    source: Optional[str] = None        # which tool/method found it


# ── Zone Transfer Result ──
class ZoneTransferResult(BaseModel):
    success: bool
    nameserver: str
    records: list[DNSRecord] = []
    error: Optional[str] = None


# ── Full Scan Result ──
class DNSEnumResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str = ""
    
    # ── DNS Records ──
    records: list[DNSRecord] = []
    total_records: int = 0
    
    # ── Subdomains (from brute/fuzz) ──
    subdomains: list[SubdomainResult] = []
    total_subdomains: int = 0
    
    # ── Zone Transfers ──
    zone_transfers: list[ZoneTransferResult] = []
    zone_transfer_possible: bool = False
    
    # ── Nameservers ──
    nameservers: list[str] = []
    
    # ── Mail Servers ──
    mail_servers: list[dict[str, Any]] = []
    
    # ── Wildcard Detection ──
    wildcard_detected: bool = False
    wildcard_ips: list[str] = []
    
    # ── Meta ──
    raw_output: Optional[str] = None
    error: Optional[str] = None
    wordlist_used: Optional[str] = None
    resolver_used: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 4. UTILITIES
# ══════════════════════════════════════════════════════════════

def _target_in_args(target: str, args: list[str]) -> bool:
    """Check if target already exists in args"""
    if not args:
        return False

    target_clean = target.strip().lower()

    # Common domain/target flags
    target_flags = {"-d", "--domain", "-t", "--target", "-h", "--host"}

    for i, arg in enumerate(args):
        arg_lower = arg.strip().lower()

        # Exact match
        if arg_lower == target_clean:
            return True

        # Target inside arg
        if target_clean in arg_lower:
            return True

        # After target flag
        if arg_lower in target_flags and i + 1 < len(args):
            if args[i + 1].strip().lower() == target_clean:
                return True

    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    return any(arg in args for arg in flags)


def _has_flag_with_value(args: list[str], flags: list[str]) -> bool:
    for i, arg in enumerate(args):
        if arg in flags:
            return True
        for flag in flags:
            if arg.startswith(flag + "=") or (len(flag) == 2 and arg.startswith(flag) and len(arg) > 2):
                return True
    return False


# ══════════════════════════════════════════════════════════════
# 5. WORDLIST MANAGER
# ══════════════════════════════════════════════════════════════

class DNSWordlistManager:
    """Handle DNS wordlist creation — inline or built-in"""

    def __init__(self):
        self._temp_files: list[str] = []

    def get_wordlist_path(
        self,
        list_type: str,
        inline_words: Optional[list[str]],
        builtin_key: Optional[str],
        prefix: str = "dns"
    ) -> Optional[str]:
        """Returns file path to wordlist"""
        
        if list_type == "ia" and inline_words:
            return self._create_temp_file(inline_words, prefix)

        if list_type == "user" and builtin_key:
            wordlists = get_dns_wordlists()
            path = wordlists.get(builtin_key)
            if path and os.path.isfile(path):
                return path
            else:
                raise FileNotFoundError(
                    f"Builtin wordlist '{builtin_key}' not found at: {path}"
                )

        return None

    def _create_temp_file(self, words: list[str], prefix: str) -> str:
        """Write words to temp file in project dir"""
        temp_dir = ProjectConfig.get_temp_dir()
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            prefix=f"dns_{prefix}_",
            suffix=".txt",
            dir=str(temp_dir),
            delete=False
        )
        tmp.write("\n".join(words))
        tmp.close()
        self._temp_files.append(tmp.name)
        return tmp.name

    def cleanup(self):
        """Remove temp files"""
        for f in self._temp_files:
            try:
                os.unlink(f)
            except OSError:
                pass
        self._temp_files.clear()


# ══════════════════════════════════════════════════════════════
# 6. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(
    cmd: list[str],
    timeout: int = 600,
    cwd: Optional[str | Path] = None,
) -> tuple[str, str, int, str]:
    """Run command safely in project directory"""
    
    if cwd is None:
        cwd = ProjectConfig.get_project_dir()
    
    cwd = Path(cwd)
    
    if not cwd.is_dir():
        cwd.mkdir(parents=True, exist_ok=True)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=str(cwd),
        )
        return result.stdout, result.stderr, result.returncode, str(cwd)
    
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 7. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_dig(stdout: str, stderr: str) -> tuple[list[DNSRecord], list[str], list[dict]]:
    """
    Parse dig output.
    
    Example output:
        ;; ANSWER SECTION:
        example.com.    300    IN    A    93.184.216.34
        example.com.    300    IN    MX   10 mail.example.com.
    """
    records = []
    nameservers = []
    mail_servers = []
    
    raw = stdout
    
    # Parse ANSWER/AUTHORITY/ADDITIONAL sections
    record_pattern = r"^(\S+)\.\s+(\d+)\s+IN\s+(\w+)\s+(.+)$"
    
    for line in raw.split("\n"):
        line = line.strip()
        
        # Skip comments and empty
        if not line or line.startswith(";"):
            continue
        
        match = re.match(record_pattern, line)
        if match:
            name = match.group(1)
            ttl = int(match.group(2))
            rtype = match.group(3).upper()
            value = match.group(4).strip().rstrip(".")
            
            record = DNSRecord(
                record_type=rtype,
                name=name,
                value=value,
                ttl=ttl,
            )
            
            # Extract MX priority
            if rtype == "MX":
                mx_match = re.match(r"(\d+)\s+(.+)", value)
                if mx_match:
                    record.priority = int(mx_match.group(1))
                    record.value = mx_match.group(2).rstrip(".")
                    mail_servers.append({
                        "priority": record.priority,
                        "server": record.value,
                    })
            
            # Extract nameservers
            if rtype == "NS":
                nameservers.append(value)
            
            records.append(record)
    
    return records, nameservers, mail_servers


def parse_dnsrecon(stdout: str, stderr: str) -> tuple[list[DNSRecord], list[SubdomainResult], list[ZoneTransferResult], list[str], list[dict]]:
    """
    Parse dnsrecon output (text or JSON mode).
    
    dnsrecon output examples:
        [*] Performing General Enumeration of Domain: example.com
        [*]     A example.com 93.184.216.34
        [*]     NS example.com ns1.example.com
        [*]     MX example.com 10 mail.example.com
        [*] Trying Zone Transfer for example.com on ns1.example.com
        [+] Zone Transfer was successful!!
    """
    records = []
    subdomains = []
    zone_transfers = []
    nameservers = []
    mail_servers = []
    
    raw = stdout
    
    # Try JSON parse first
    try:
        if raw.strip().startswith("[") or raw.strip().startswith("{"):
            data = json.loads(raw)
            if isinstance(data, list):
                for item in data:
                    rtype = item.get("type", "").upper()
                    name = item.get("name", "")
                    value = item.get("address", item.get("target", ""))
                    
                    if rtype and name:
                        records.append(DNSRecord(
                            record_type=rtype,
                            name=name,
                            value=value,
                        ))
                        
                        if rtype == "A" or rtype == "AAAA":
                            subdomains.append(SubdomainResult(
                                subdomain=name,
                                ip=value,
                                source="dnsrecon",
                            ))
                        elif rtype == "NS":
                            nameservers.append(value)
                        elif rtype == "MX":
                            mail_servers.append({"server": value})
                
                return records, subdomains, zone_transfers, nameservers, mail_servers
    except json.JSONDecodeError:
        pass
    
    # Parse text output
    # Pattern: [*]     TYPE name value
    record_pattern = r"\[\*\]\s+(\w+)\s+(\S+)\s+(.+)"
    
    for line in raw.split("\n"):
        line = line.strip()
        
        # Zone transfer detection
        if "Zone Transfer was successful" in line:
            zone_transfers.append(ZoneTransferResult(
                success=True,
                nameserver="unknown",
            ))
        
        match = re.match(record_pattern, line)
        if match:
            rtype = match.group(1).upper()
            name = match.group(2)
            value = match.group(3).strip()
            
            # Handle MX with priority
            priority = None
            if rtype == "MX":
                mx_match = re.match(r"(\d+)\s+(.+)", value)
                if mx_match:
                    priority = int(mx_match.group(1))
                    value = mx_match.group(2)
                    mail_servers.append({"priority": priority, "server": value})
            
            records.append(DNSRecord(
                record_type=rtype,
                name=name,
                value=value,
                priority=priority,
            ))
            
            if rtype in ("A", "AAAA"):
                subdomains.append(SubdomainResult(
                    subdomain=name,
                    ip=value,
                    source="dnsrecon",
                ))
            elif rtype == "NS":
                nameservers.append(value)
    
    return records, subdomains, zone_transfers, nameservers, mail_servers


def parse_dnsenum(stdout: str, stderr: str) -> tuple[list[DNSRecord], list[SubdomainResult], list[ZoneTransferResult], list[str], list[dict]]:
    """
    Parse dnsenum output.
    
    dnsenum output example:
        -----   example.com   -----
        Host's addresses:
        __________________
        example.com.                             300      IN    A        93.184.216.34
        
        Name Servers:
        ______________
        ns1.example.com.                         300      IN    A        1.2.3.4
        
        Brute forcing with /usr/share/dnsenum/dns.txt:
        _______________________________________________
        admin.example.com.                       300      IN    A        5.6.7.8
    """
    records = []
    subdomains = []
    zone_transfers = []
    nameservers = []
    mail_servers = []
    
    raw = stdout
    
    # Generic record pattern
    record_pattern = r"(\S+)\.\s+(\d+)\s+IN\s+(\w+)\s+(.+)"
    
    current_section = None
    
    for line in raw.split("\n"):
        line = line.strip()
        
        # Detect sections
        if "Name Servers:" in line:
            current_section = "ns"
        elif "Mail (MX) Servers:" in line or "MX Records:" in line:
            current_section = "mx"
        elif "Brute forcing" in line or "Host's addresses:" in line:
            current_section = "hosts"
        elif "Zone Transfer" in line:
            current_section = "zone"
            if "successful" in line.lower():
                zone_transfers.append(ZoneTransferResult(success=True, nameserver="unknown"))
        
        # Parse records
        match = re.match(record_pattern, line)
        if match:
            name = match.group(1)
            ttl = int(match.group(2))
            rtype = match.group(3).upper()
            value = match.group(4).strip()
            
            records.append(DNSRecord(
                record_type=rtype,
                name=name,
                value=value,
                ttl=ttl,
            ))
            
            if rtype in ("A", "AAAA"):
                subdomains.append(SubdomainResult(
                    subdomain=name,
                    ip=value,
                    source="dnsenum",
                ))
            elif rtype == "NS":
                nameservers.append(value if value else name)
            elif rtype == "MX":
                mx_match = re.match(r"(\d+)\s+(.+)", value)
                if mx_match:
                    mail_servers.append({
                        "priority": int(mx_match.group(1)),
                        "server": mx_match.group(2).rstrip("."),
                    })
                else:
                    mail_servers.append({"server": value.rstrip(".")})
    
    return records, subdomains, zone_transfers, nameservers, mail_servers


def parse_fierce(stdout: str, stderr: str) -> tuple[list[SubdomainResult], list[str], bool]:
    """
    Parse fierce output.
    
    fierce output example:
        DNS Servers for example.com:
            ns1.example.com
            ns2.example.com
        
        Trying zone transfer first...
            Testing ns1.example.com
                Request timed out or transfer not allowed.
        
        Now performing 2280 test(s)...
        10.0.0.1    admin.example.com
        10.0.0.2    www.example.com
        
        Subnets found (may want to probe here using nmap or unicornscan):
            10.0.0.0-255 : 2 hostnames found.
    """
    subdomains = []
    nameservers = []
    zone_transfer_success = False
    
    raw = stdout + "\n" + stderr
    
    # Parse nameservers
    ns_section = False
    for line in raw.split("\n"):
        line = line.strip()
        
        if "DNS Servers for" in line:
            ns_section = True
            continue
        
        if ns_section:
            if line and not line.startswith("Trying") and not line.startswith("Now"):
                if re.match(r"^[\w\.\-]+$", line):
                    nameservers.append(line)
            else:
                ns_section = False
        
        # Zone transfer
        if "zone transfer" in line.lower() and "successful" in line.lower():
            zone_transfer_success = True
        
        # Subdomain results: IP    subdomain
        sub_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(\S+)$", line)
        if sub_match:
            ip = sub_match.group(1)
            subdomain = sub_match.group(2)
            subdomains.append(SubdomainResult(
                subdomain=subdomain,
                ip=ip,
                source="fierce",
            ))
    
    return subdomains, nameservers, zone_transfer_success


def parse_massdns(stdout: str, stderr: str) -> list[SubdomainResult]:
    """
    Parse massdns output.
    
    massdns output (simple format):
        admin.example.com. A 10.0.0.1
        www.example.com. A 10.0.0.2
        www.example.com. CNAME cdn.example.com.
    
    massdns JSON format:
        {"name":"admin.example.com.","type":"A","data":"10.0.0.1"}
    """
    subdomains = []
    seen = set()
    
    raw = stdout
    
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        
        # Try JSON
        try:
            data = json.loads(line)
            name = data.get("name", "").rstrip(".")
            rtype = data.get("type", "")
            value = data.get("data", "").rstrip(".")
            
            if name and name not in seen:
                seen.add(name)
                sub = SubdomainResult(subdomain=name, source="massdns")
                if rtype == "A":
                    sub.ip = value
                    sub.ips = [value]
                elif rtype == "CNAME":
                    sub.cname = value
                subdomains.append(sub)
            continue
        except json.JSONDecodeError:
            pass
        
        # Parse simple format: subdomain. TYPE value
        simple_match = re.match(r"^(\S+)\.\s+(\w+)\s+(.+)$", line)
        if simple_match:
            name = simple_match.group(1)
            rtype = simple_match.group(2).upper()
            value = simple_match.group(3).rstrip(".")
            
            if name not in seen:
                seen.add(name)
                sub = SubdomainResult(subdomain=name, source="massdns")
                if rtype == "A":
                    sub.ip = value
                    sub.ips = [value]
                elif rtype == "CNAME":
                    sub.cname = value
                subdomains.append(sub)
    
    return subdomains


def parse_puredns(stdout: str, stderr: str) -> tuple[list[SubdomainResult], bool, list[str]]:
    """
    Parse puredns output.
    
    puredns resolve output (one subdomain per line):
        admin.example.com
        www.example.com
        api.example.com
    
    puredns bruteforce output (similar)
    
    puredns also reports wildcards in stderr
    """
    subdomains = []
    wildcard_detected = False
    wildcard_ips = []
    
    raw = stdout
    
    # Check for wildcard detection in stderr
    if "wildcard" in stderr.lower():
        wildcard_detected = True
        # Extract wildcard IPs if mentioned
        ip_matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)", stderr)
        wildcard_ips = list(set(ip_matches))
    
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        
        # Simple: one subdomain per line
        if re.match(r"^[\w\.\-]+\.[a-zA-Z]{2,}$", line):
            subdomains.append(SubdomainResult(
                subdomain=line,
                source="puredns",
            ))
            continue
        
        # Or: subdomain IP format
        parts = line.split()
        if len(parts) >= 1:
            subdomain = parts[0]
            ip = parts[1] if len(parts) > 1 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]) else None
            
            if re.match(r"^[\w\.\-]+\.[a-zA-Z]{2,}$", subdomain):
                subdomains.append(SubdomainResult(
                    subdomain=subdomain,
                    ip=ip,
                    source="puredns",
                ))
    
    return subdomains, wildcard_detected, wildcard_ips


# ══════════════════════════════════════════════════════════════
# 8. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_dig_cmd(
    args: list[str],
    target: str,
) -> list[str]:
    """
    Build dig command.
    
    dig syntax:
        dig [@server] [name] [type] [options]
    
    Examples:
        dig example.com ANY
        dig example.com MX +noall +answer
        dig @8.8.8.8 example.com A
        dig example.com AXFR @ns1.example.com  (zone transfer)
    """
    cmd = ["dig"]
    final_args = list(args)
    
    # Add target if not in args
    if not _target_in_args(target, final_args):
        # Find where to insert (after @server if present, before type/options)
        insert_pos = 0
        for i, arg in enumerate(final_args):
            if arg.startswith("@"):
                insert_pos = i + 1
                break
        final_args.insert(insert_pos, target)
    
    cmd.extend(final_args)
    return cmd


def _build_dnsrecon_cmd(
    args: list[str],
    target: str,
    wordlist_path: Optional[str],
) -> list[str]:
    """
    Build dnsrecon command.
    
    dnsrecon syntax:
        dnsrecon -d DOMAIN [options]
    
    Examples:
        dnsrecon -d example.com -t std                    # Standard enum
        dnsrecon -d example.com -t brt -D wordlist.txt    # Brute force
        dnsrecon -d example.com -t axfr                   # Zone transfer
        dnsrecon -d example.com -a                        # All enum types
    """
    cmd = ["dnsrecon"]
    final_args = list(args)
    
    # Add -d target if not present
    if not _target_in_args(target, final_args) and not _has_flag_with_value(final_args, ["-d", "--domain"]):
        final_args.extend(["-d", target])
    
    # Add wordlist for brute force if -t brt and no -D
    if wordlist_path and not _has_flag_with_value(final_args, ["-D", "--dictionary"]):
        # Only add if brute force mode
        if "-t" in final_args:
            try:
                t_idx = final_args.index("-t")
                if t_idx + 1 < len(final_args) and final_args[t_idx + 1] == "brt":
                    final_args.extend(["-D", wordlist_path])
            except ValueError:
                pass
        elif "--type" in final_args:
            try:
                t_idx = final_args.index("--type")
                if t_idx + 1 < len(final_args) and final_args[t_idx + 1] == "brt":
                    final_args.extend(["-D", wordlist_path])
            except ValueError:
                pass
    
    cmd.extend(final_args)
    return cmd


def _build_dnsenum_cmd(
    args: list[str],
    target: str,
    wordlist_path: Optional[str],
) -> list[str]:
    """
    Build dnsenum command.
    
    dnsenum syntax:
        dnsenum [options] DOMAIN
    
    Examples:
        dnsenum example.com
        dnsenum --enum example.com
        dnsenum -f wordlist.txt example.com
        dnsenum --dnsserver 8.8.8.8 example.com
    """
    cmd = ["dnsenum"]
    final_args = list(args)
    
    # Add wordlist if provided and not already specified
    if wordlist_path and not _has_flag_with_value(final_args, ["-f", "--file"]):
        final_args.extend(["-f", wordlist_path])
    
    # Add target at end if not present
    if not _target_in_args(target, final_args):
        final_args.append(target)
    
    cmd.extend(final_args)
    return cmd


def _build_fierce_cmd(
    args: list[str],
    target: str,
    wordlist_path: Optional[str],
) -> list[str]:
    """
    Build fierce command.
    
    fierce syntax:
        fierce --domain DOMAIN [options]
    
    Examples:
        fierce --domain example.com
        fierce --domain example.com --subdomains www admin mail
        fierce --domain example.com --wordlist wordlist.txt
        fierce --domain example.com --dns-servers 8.8.8.8
    """
    cmd = ["fierce"]
    final_args = list(args)
    
    # Add --domain target if not present
    if not _target_in_args(target, final_args) and not _has_flag_with_value(final_args, ["--domain", "-d"]):
        final_args.extend(["--domain", target])
    
    # Add wordlist if provided
    if wordlist_path and not _has_flag_with_value(final_args, ["--wordlist", "-w"]):
        final_args.extend(["--wordlist", wordlist_path])
    
    cmd.extend(final_args)
    return cmd


def _build_massdns_cmd(
    args: list[str],
    target: str,
    wordlist_path: Optional[str],
    resolver_path: Optional[str],
) -> list[str]:
    """
    Build massdns command.
    
    massdns syntax:
        massdns -r resolvers.txt -t TYPE -o OUTPUT_FORMAT [options] wordlist.txt
    
    Examples:
        massdns -r resolvers.txt -t A -o S domains.txt
        massdns -r resolvers.txt -t A -o J domains.txt  # JSON output
        massdns -r resolvers.txt -t A -o S -w output.txt domains.txt
    
    NOTE: massdns reads SUBDOMAINS from file, not domain. 
          Need to generate subdomain list: sub.example.com
    """
    cmd = ["massdns"]
    final_args = list(args)
    
    # Add resolvers if not present
    if resolver_path and not _has_flag_with_value(final_args, ["-r", "--resolvers"]):
        final_args.extend(["-r", resolver_path])
    
    # Add output format if not present (use simple for easier parsing)
    if not _has_flag_with_value(final_args, ["-o", "--output"]):
        final_args.extend(["-o", "S"])
    
    # Add record type if not present
    if not _has_flag_with_value(final_args, ["-t", "--type"]):
        final_args.extend(["-t", "A"])
    
    # Wordlist should be at the end
    # For massdns, we need a file with FULL subdomains (sub.example.com)
    # If user provides wordlist of just subnames, we need to append domain
    if wordlist_path and wordlist_path not in final_args:
        final_args.append(wordlist_path)
    
    cmd.extend(final_args)
    return cmd


def _build_puredns_cmd(
    args: list[str],
    target: str,
    wordlist_path: Optional[str],
    resolver_path: Optional[str],
) -> list[str]:
    """
    Build puredns command.
    
    puredns syntax:
        puredns bruteforce wordlist.txt domain.com [options]
        puredns resolve domains.txt [options]
    
    Examples:
        puredns bruteforce wordlist.txt example.com -r resolvers.txt
        puredns bruteforce wordlist.txt example.com --wildcard-tests 10
        puredns resolve subdomains.txt -r resolvers.txt
    """
    cmd = ["puredns"]
    final_args = list(args)
    
    # Determine mode: bruteforce or resolve
    is_bruteforce = "bruteforce" in final_args or "brute" in final_args
    is_resolve = "resolve" in final_args
    
    # If no mode specified and wordlist given, default to bruteforce
    if not is_bruteforce and not is_resolve:
        if wordlist_path:
            final_args.insert(0, "bruteforce")
            is_bruteforce = True
        else:
            final_args.insert(0, "resolve")
            is_resolve = True
    
    # Add wordlist after mode
    if wordlist_path and wordlist_path not in final_args:
        # Find mode position
        mode_idx = -1
        for i, arg in enumerate(final_args):
            if arg in ("bruteforce", "brute", "resolve"):
                mode_idx = i
                break
        if mode_idx >= 0:
            final_args.insert(mode_idx + 1, wordlist_path)
        else:
            final_args.append(wordlist_path)
    
    # Add domain for bruteforce mode
    if is_bruteforce and not _target_in_args(target, final_args):
        # Domain goes after wordlist
        if wordlist_path:
            try:
                wl_idx = final_args.index(wordlist_path)
                final_args.insert(wl_idx + 1, target)
            except ValueError:
                final_args.append(target)
        else:
            final_args.append(target)
    
    # Add resolvers
    if resolver_path and not _has_flag_with_value(final_args, ["-r", "--resolvers"]):
        final_args.extend(["-r", resolver_path])
    
    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 9. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def dns_enum_fuzzing(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    list_type: str = "user",
    subdomain_wordlist: Optional[list[str]] = None,
    resolver_list: Optional[list[str]] = None,
    builtin_subdomain_list: Optional[str] = None,
    builtin_resolver_list: Optional[str] = None,
) -> dict:
    """
    🔧 Agent Tool: DNS Enumeration & Fuzzing

    Enumerate DNS records, discover subdomains, attempt zone transfers,
    and fuzz for hidden subdomains.

    ┌─────────────────────────────────────────────────────────────┐
    │  CAPABILITIES:                                               │
    │                                                              │
    │  DNS Record Enum     A, AAAA, MX, NS, TXT, SOA, CNAME, etc. │
    │  Zone Transfer       AXFR attempts on all nameservers       │
    │  Subdomain Brute     Dictionary-based subdomain discovery   │
    │  Wildcard Detection  Detect and filter wildcard responses   │
    │  Reverse DNS         PTR record lookups                     │
    └─────────────────────────────────────────────────────────────┘

    Args:
        tool:                 "dig" | "dnsrecon" | "dnsenum" | "fierce" | "massdns" | "puredns"
        target:               Domain name (e.g. "example.com")
        args:                 Raw tool arguments — agent decides
        list_type:            "user" (built-in) | "ia" (inline)
        subdomain_wordlist:   Inline subdomains (if list_type="ia")
        resolver_list:        Inline DNS resolvers (if list_type="ia")
        builtin_subdomain_list: Key for built-in subdomain wordlist
        builtin_resolver_list:  Key for built-in resolver list

    Built-in wordlist keys:
        Subdomains: "subdomains_short" | "subdomains_medium" | "subdomains_large" |
                    "subdomains_full" | "subdomains_common" | "subdomains_bitquark" |
                    "fierce_default" | "dns_names" | "deepmagic"
        Resolvers:  "resolvers" | "resolvers_trusted"

    ═══════════════════════════════════════════════════════════════
    DIG ARGS REFERENCE:
    ═══════════════════════════════════════════════════════════════
    Record types:   A | AAAA | MX | NS | TXT | SOA | CNAME | ANY | AXFR
    Server:         ["@8.8.8.8"] or ["@ns1.example.com"]
    Options:        ["+short"] | ["+noall", "+answer"] | ["+trace"]
    Zone transfer:  ["AXFR", "@ns1.example.com"]
    Examples:
        All records:     ["example.com", "ANY", "+noall", "+answer"]
        Zone transfer:   ["example.com", "AXFR", "@ns1.example.com"]
        Trace:           ["example.com", "+trace"]
        Short output:    ["example.com", "A", "+short"]

    ═══════════════════════════════════════════════════════════════
    DNSRECON ARGS REFERENCE:
    ═══════════════════════════════════════════════════════════════
    Enum types (-t):
        std     Standard enumeration
        brt     Brute force subdomains
        axfr    Zone transfer
        rvl     Reverse lookup of IP range
        srv     SRV records
        goo     Google search
        snoop   Cache snooping
    Options:
        ["-t", "std"]               Standard enum
        ["-t", "brt"]               Brute force (needs wordlist)
        ["-t", "axfr"]              Zone transfer attempt
        ["-a"]                      All enum types
        ["-n", "ns1.example.com"]   Specific nameserver
        ["--json", "out.json"]      JSON output
    Examples:
        Standard:        ["-t", "std"]
        Brute force:     ["-t", "brt", "-D", "wordlist.txt"]
        Zone transfer:   ["-t", "axfr"]
        All:             ["-a"]

    ═══════════════════════════════════════════════════════════════
    DNSENUM ARGS REFERENCE:
    ═══════════════════════════════════════════════════════════════
    Options:
        ["--enum"]                  Shortcut for basic enum
        ["--noreverse"]             Skip reverse lookup
        ["--nocolor"]               No color output
        ["-f", "wordlist.txt"]      Subdomain wordlist
        ["--dnsserver", "8.8.8.8"]  Custom DNS server
        ["-o", "output.xml"]        Output file
        ["--threads", "10"]         Thread count
        ["-p", "10"]                Pages to scrape from Google
        ["-s", "20"]                Max subdomains from scraping
    Examples:
        Basic enum:      ["--enum"]
        With wordlist:   ["-f", "wordlist.txt", "--threads", "10"]
        No reverse:      ["--noreverse", "--enum"]

    ═══════════════════════════════════════════════════════════════
    FIERCE ARGS REFERENCE:
    ═══════════════════════════════════════════════════════════════
    Options:
        ["--domain", "example.com"]     Target domain (auto-added)
        ["--wordlist", "wordlist.txt"]  Subdomain wordlist
        ["--dns-servers", "8.8.8.8"]    Custom DNS servers
        ["--subdomains", "www", "mail"] Specific subdomains to check
        ["--traverse", "5"]             Scan adjacent IPs
        ["--delay", "1"]                Delay between queries
        ["--connect"]                   Attempt HTTP connection
    Examples:
        Basic:           ["--domain", "example.com"]
        With wordlist:   ["--wordlist", "wordlist.txt"]
        Traverse IPs:    ["--traverse", "10"]

    ═══════════════════════════════════════════════════════════════
    MASSDNS ARGS REFERENCE:
    ═══════════════════════════════════════════════════════════════
    NOTE: massdns reads file of FULL subdomain names (sub.example.com)
    Options:
        ["-r", "resolvers.txt"]    Resolver list (REQUIRED)
        ["-t", "A"]                Record type: A, AAAA, MX, NS, etc.
        ["-o", "S"]                Output: S=simple, J=JSON, F=full
        ["-w", "output.txt"]       Write results to file
        ["-s", "10000"]            Concurrent lookups
        ["--hashmap-size", "100000"]
    Examples:
        Simple scan:     ["-r", "resolvers.txt", "-t", "A", "-o", "S", "domains.txt"]
        JSON output:     ["-r", "resolvers.txt", "-t", "A", "-o", "J", "domains.txt"]
        Fast scan:       ["-r", "resolvers.txt", "-t", "A", "-o", "S", "-s", "10000", "domains.txt"]

    ═══════════════════════════════════════════════════════════════
    PUREDNS ARGS REFERENCE:
    ═══════════════════════════════════════════════════════════════
    Modes:
        bruteforce    Brute force subdomains using wordlist
        resolve       Resolve list of subdomains
    Options:
        ["-r", "resolvers.txt"]       Resolver list
        ["--wildcard-tests", "10"]    Wildcard detection tests
        ["-w", "output.txt"]          Write results to file
        ["--rate-limit", "500"]       Queries per second
        ["-n", "8"]                   Number of resolvers
        ["--bin", "massdns"]          Path to massdns binary
    Examples:
        Brute force:     ["bruteforce", "wordlist.txt", "example.com", "-r", "resolvers.txt"]
        Resolve:         ["resolve", "subdomains.txt", "-r", "resolvers.txt"]
        With wildcard:   ["bruteforce", "wordlist.txt", "example.com", "--wildcard-tests", "20"]

    Returns:
        Structured JSON with DNS records, subdomains, zone transfers, and more.
    """

    start = time.time()
    args = list(args or [])
    wl_manager = DNSWordlistManager()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = DNSEnumRequest(
            tool=tool, target=target, args=args,
            list_type=list_type,
            subdomain_wordlist=subdomain_wordlist,
            resolver_list=resolver_list,
            builtin_subdomain_list=builtin_subdomain_list,
            builtin_resolver_list=builtin_resolver_list,
        )
    except Exception as e:
        return DNSEnumResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # ══════════════════════════════
    # RESOLVE WORDLISTS
    # ══════════════════════════════
    wordlist_path = None
    resolver_path = None
    wordlist_used = None
    resolver_used = None

    try:
        # Subdomain wordlist
        wordlist_path = wl_manager.get_wordlist_path(
            list_type, subdomain_wordlist, builtin_subdomain_list, "subdomains"
        )
        if wordlist_path:
            wordlist_used = wordlist_path

        # Resolver list
        resolver_path = wl_manager.get_wordlist_path(
            list_type, resolver_list, builtin_resolver_list, "resolvers"
        )
        if resolver_path:
            resolver_used = resolver_path

    except FileNotFoundError as e:
        wl_manager.cleanup()
        return DNSEnumResult(
            success=False, tool=tool, target=target,
            command="", error=str(e)
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    try:
        if tool == "dig":
            cmd = _build_dig_cmd(args, target)
        elif tool == "dnsrecon":
            cmd = _build_dnsrecon_cmd(args, target, wordlist_path)
        elif tool == "dnsenum":
            cmd = _build_dnsenum_cmd(args, target, wordlist_path)
        elif tool == "fierce":
            cmd = _build_fierce_cmd(args, target, wordlist_path)
        elif tool == "massdns":
            cmd = _build_massdns_cmd(args, target, wordlist_path, resolver_path)
        elif tool == "puredns":
            cmd = _build_puredns_cmd(args, target, wordlist_path, resolver_path)
        else:
            wl_manager.cleanup()
            return DNSEnumResult(
                success=False, tool=tool, target=target,
                command="", error=f"Unknown tool: {tool}"
            ).model_dump()
    except Exception as e:
        wl_manager.cleanup()
        return DNSEnumResult(
            success=False, tool=tool, target=target,
            command="", error=f"Command build error: {e}"
        ).model_dump()

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    command_str = " ".join(cmd)
    stdout, stderr, rc, working_dir = safe_execute(cmd, req.timeout)

    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    records = []
    subdomains = []
    zone_transfers = []
    nameservers = []
    mail_servers = []
    wildcard_detected = False
    wildcard_ips = []

    if tool == "dig":
        records, nameservers, mail_servers = parse_dig(stdout, stderr)

    elif tool == "dnsrecon":
        records, subdomains, zone_transfers, nameservers, mail_servers = parse_dnsrecon(stdout, stderr)

    elif tool == "dnsenum":
        records, subdomains, zone_transfers, nameservers, mail_servers = parse_dnsenum(stdout, stderr)

    elif tool == "fierce":
        subdomains, nameservers, zt_success = parse_fierce(stdout, stderr)
        if zt_success:
            zone_transfers.append(ZoneTransferResult(success=True, nameserver="unknown"))

    elif tool == "massdns":
        subdomains = parse_massdns(stdout, stderr)

    elif tool == "puredns":
        subdomains, wildcard_detected, wildcard_ips = parse_puredns(stdout, stderr)

    # ══════════════════════════════
    # CLEANUP
    # ══════════════════════════════
    wl_manager.cleanup()

    # ══════════════════════════════
    # DEDUPLICATE
    # ══════════════════════════════
    # Dedupe subdomains
    seen_subs = set()
    unique_subs = []
    for sub in subdomains:
        if sub.subdomain not in seen_subs:
            seen_subs.add(sub.subdomain)
            unique_subs.append(sub)
    subdomains = unique_subs

    # Dedupe nameservers
    nameservers = list(set(nameservers))

    # ══════════════════════════════
    # RETURN
    # ══════════════════════════════
    zone_transfer_possible = any(zt.success for zt in zone_transfers)

    return DNSEnumResult(
        success=len(records) > 0 or len(subdomains) > 0 or rc == 0,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=working_dir,
        records=records,
        total_records=len(records),
        subdomains=subdomains,
        total_subdomains=len(subdomains),
        zone_transfers=zone_transfers,
        zone_transfer_possible=zone_transfer_possible,
        nameservers=nameservers,
        mail_servers=mail_servers,
        wildcard_detected=wildcard_detected,
        wildcard_ips=wildcard_ips,
        raw_output=(stdout or stderr)[:10000],
        error=stderr if rc != 0 and not records and not subdomains else None,
        wordlist_used=wordlist_used,
        resolver_used=resolver_used,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 10. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

DNS_ENUM_TOOL_DEFINITION = {
    "name": "dns_enum_fuzzing",
    "description": (
        "Enumerate DNS records, discover subdomains, attempt zone transfers, "
        "and fuzz for hidden subdomains. "
        "Supports dig (lookups), dnsrecon (full enum), dnsenum (enum+brute), "
        "fierce (smart recon), massdns (fast mass resolution), puredns (fast brute+wildcard filtering). "
        "Can use built-in wordlists OR inline user-provided lists. "
        "YOU decide the args."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["dig", "dnsrecon", "dnsenum", "fierce", "massdns", "puredns"],
                "description": (
                    "dig = simple DNS lookups | "
                    "dnsrecon = full enumeration | "
                    "dnsenum = enum + brute | "
                    "fierce = smart recon + zone walk | "
                    "massdns = ultra-fast mass resolution | "
                    "puredns = fast brute with wildcard filtering"
                ),
            },
            "target": {
                "type": "string",
                "description": "Domain name (e.g. 'example.com')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments.\n"
                    "dig: ['ANY', '+noall', '+answer'] or ['AXFR', '@ns1.example.com']\n"
                    "dnsrecon: ['-t', 'std'] or ['-t', 'brt'] or ['-t', 'axfr']\n"
                    "dnsenum: ['--enum'] or ['-f', 'wordlist.txt', '--threads', '10']\n"
                    "fierce: ['--wordlist', 'wordlist.txt'] or ['--traverse', '10']\n"
                    "massdns: ['-r', 'resolvers.txt', '-t', 'A', '-o', 'S', 'domains.txt']\n"
                    "puredns: ['bruteforce', 'wordlist.txt', 'example.com', '-r', 'resolvers.txt']"
                ),
            },
            "list_type": {
                "type": "string",
                "enum": ["user", "ia"],
                "description": "'user' = built-in wordlists | 'ia' = inline words"
            },
            "subdomain_wordlist": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Inline subdomains to try (only if list_type='ia'). e.g. ['www','mail','admin','api']"
            },
            "resolver_list": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Inline DNS resolvers (only if list_type='ia'). e.g. ['8.8.8.8','1.1.1.1']"
            },
            "builtin_subdomain_list": {
                "type": "string",
                "enum": [
                    "subdomains_short", "subdomains_medium", "subdomains_large",
                    "subdomains_full", "subdomains_common", "subdomains_bitquark",
                    "fierce_default", "dns_names", "deepmagic"
                ],
                "description": "Built-in subdomain wordlist (only if list_type='user')"
            },
            "builtin_resolver_list": {
                "type": "string",
                "enum": ["resolvers", "resolvers_trusted"],
                "description": "Built-in resolver list (only if list_type='user')"
            },
        },
        "required": ["tool", "target"]
    }
}
