#/+
import subprocess
import json
import re
import os
import time
import tempfile
import ipaddress
import shutil
import threading
from pathlib import Path
from typing import Optional, Any
from functools import lru_cache
from pydantic import BaseModel, Field, field_validator, model_validator
from server.agents.executer.recon.config import is_blocked_host


# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools"""

    _project_dir: Optional[Path] = None

    WORDLISTS_DIR = Path("share") / "wordlists"
    ALT_WORDLISTS_DIR = Path("server") / "share" / "wordlists"

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
        cls.get_wordlists_dir().mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_wordlists_dir(cls) -> Path:
        project_dir = cls.get_project_dir()
        candidates = [
            project_dir / cls.WORDLISTS_DIR,
            project_dir / cls.ALT_WORDLISTS_DIR,
        ]

        for path in candidates:
            if path.is_dir():
                return path

        # Prefer server/share/wordlists in monorepo layout.
        default_path = candidates[1] if (project_dir / "server").is_dir() else candidates[0]
        default_path.mkdir(parents=True, exist_ok=True)
        return default_path

# ══════════════════════════════════════════════════════════════
# 2. RATE LIMITER
# ══════════════════════════════════════════════════════════════

class RateLimiter:
    """Thread-safe rate limiter for expensive DNS brute-force operations"""

    def __init__(self, calls_per_second: float = 0.5):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_call = time.time()

    def reset(self):
        with self.lock:
            self.last_call = 0.0


DNS_RATE_LIMITER = RateLimiter(calls_per_second=0.5)
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


# ══════════════════════════════════════════════════════════════
# 3. DNS WORDLIST PATHS
# ══════════════════════════════════════════════════════════════

_DEFAULT_DNS_WORDLIST_CONTENT: dict[str, str] = {
    "subdomains_short": "www\nmail\napi\nadmin\ndev\nstaging\ntest\n",
    "subdomains_medium": (
        "www\nmail\napi\nadmin\ndev\nstaging\ntest\nblog\ncdn\nportal\n"
        "dashboard\nauth\napp\nvpn\nstatus\n"
    ),
    "subdomains_large": (
        "www\nmail\napi\nadmin\ndev\nstaging\ntest\nblog\ncdn\nportal\n"
        "dashboard\nauth\napp\nvpn\nstatus\nm\nimg\nfiles\nstatic\nshop\nsupport\n"
    ),
    "subdomains_full": (
        "www\nmail\napi\nadmin\ndev\nstaging\ntest\nblog\ncdn\nportal\n"
        "dashboard\nauth\napp\nvpn\nstatus\nm\nimg\nfiles\nstatic\nshop\nsupport\n"
    ),
    "subdomains_common": "www\nmail\napi\nadmin\napp\nauth\ncdn\n",
    "subdomains_bitquark": "www\nmail\napi\nadmin\ndev\nstaging\n",
    "fierce_default": "www\nmail\nns1\nns2\nftp\nsmtp\n",
    "dns_names": "www\nmail\nns1\nns2\nmx\nftp\n",
    "deepmagic": "www\nmail\napi\nadmin\nstaging\n",
    "resolvers": "1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n",
    "resolvers_trusted": "1.1.1.1\n8.8.8.8\n9.9.9.9\n",
}


def _ensure_dns_wordlist_file(key: str, fallback_path: Path) -> str:
    """
    Ensure a local DNS wordlist exists.
    Mirrors web_fuzz behavior: if no packaged list exists, create a sane fallback
    under share/wordlists so builtin mode never crashes on missing files.
    """
    if fallback_path.is_file():
        return str(fallback_path)

    fallback_path.parent.mkdir(parents=True, exist_ok=True)
    content = _DEFAULT_DNS_WORDLIST_CONTENT.get(key, "www\napi\nadmin\n")
    fallback_path.write_text(content)
    return str(fallback_path)


def _get_dns_wordlist_paths() -> dict[str, str]:
    """Get DNS wordlist paths — shared wordlists first, then SecLists"""
    project_wl = ProjectConfig.get_wordlists_dir()

    wordlists = {
        "subdomains_short": [
            project_wl / "dns" / "subdomains_short.txt",
            project_wl / "subdomains_short.txt",
            project_wl / "dns-fuzz-small.txt",
            project_wl / "short.txt",
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        ],
        "subdomains_medium": [
            project_wl / "dns" / "subdomains_medium.txt",
            project_wl / "subdomains_medium.txt",
            project_wl / "dns-fuzz-common.txt",
            project_wl / "medium.txt",
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"),
        ],
        "subdomains_large": [
            project_wl / "dns" / "subdomains_large.txt",
            project_wl / "subdomains_large.txt",
            project_wl / "large.txt",
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"),
        ],
        "subdomains_full": [
            project_wl / "dns" / "subdomains_full.txt",
            project_wl / "subdomains_full.txt",
            project_wl / "large.txt",
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"),
        ],
        "subdomains_common": [
            project_wl / "dns" / "subdomains_common.txt",
            project_wl / "subdomains_common.txt",
            project_wl / "dns-fuzz-common.txt",
            project_wl / "medium.txt",
            Path("/usr/share/seclists/Discovery/DNS/namelist.txt"),
        ],
        "subdomains_bitquark": [
            project_wl / "dns" / "bitquark.txt",
            project_wl / "bitquark.txt",
            Path("/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
        ],
        "fierce_default": [
            project_wl / "dns" / "fierce.txt",
            project_wl / "fierce.txt",
            Path("/usr/share/fierce/hosts.txt"),
            Path("/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt"),
        ],
        "dns_names": [
            project_wl / "dns" / "dns_names.txt",
            project_wl / "dns_names.txt",
            Path("/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"),
        ],
        "deepmagic": [
            project_wl / "dns" / "deepmagic.txt",
            project_wl / "deepmagic.txt",
            Path("/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt"),
        ],
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
            # Create local fallback in share/wordlists when no candidate exists.
            resolved[key] = _ensure_dns_wordlist_file(key, Path(paths[0]))

    return resolved


def get_dns_wordlists() -> dict[str, str]:
    return _get_dns_wordlist_paths()


# ══════════════════════════════════════════════════════════════
# 4. SCHEMAS
# ══════════════════════════════════════════════════════════════

class DNSEnumRequest(BaseModel):
    tool: str
    args: list[str] = Field(default_factory=list)
    target: str

    # New naming
    wordlist_mode: str = "builtin"  # builtin | inline

    # Backward compatibility
    list_type: Optional[str] = None  # user | ia

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
        value = v.strip().lower()

        if is_blocked_host(value):
            raise ValueError(f"Target '{v}' is blocked")

        # IP/network validation
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ValueError:
            pass

        domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(domain_pattern, value):
            raise ValueError(f"Invalid target: {v}")

        return value

    @field_validator("wordlist_mode")
    @classmethod
    def validate_wordlist_mode(cls, v):
        if v not in ("builtin", "inline"):
            raise ValueError("wordlist_mode must be 'builtin' or 'inline'")
        return v

    @field_validator("list_type")
    @classmethod
    def validate_list_type(cls, v):
        if v is not None and v not in ("user", "ia"):
            raise ValueError("list_type must be 'user' or 'ia'")
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"]
        blocked_output_flags = ["-w", "--write", "-o", "--output"]

        for arg in v:
            for char in dangerous:
                if char in arg:
                    raise ValueError(f"Dangerous character '{repr(char)}' in: {arg}")

            # Prevent user-controlled output file injection
            arg_clean = arg.strip().lower()
            for flag in blocked_output_flags:
                if arg_clean == flag or arg_clean.startswith(flag + "="):
                    raise ValueError(f"Blocked output flag '{flag}' in args")

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
            valid_keys = [
                k for k in get_dns_wordlists().keys()
                if k.startswith("subdomain") or k in ("dns_names", "deepmagic", "fierce_default")
            ]
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

    @model_validator(mode="after")
    def normalize_legacy_mode(self):
        # Backward compatibility mapping
        if self.list_type == "user":
            self.wordlist_mode = "builtin"
        elif self.list_type == "ia":
            self.wordlist_mode = "inline"
        return self


class DNSRecord(BaseModel):
    record_type: str
    name: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None
    extra: Optional[dict[str, Any]] = None


class SubdomainResult(BaseModel):
    subdomain: str
    ip: Optional[str] = None
    ips: list[str] = Field(default_factory=list)
    cname: Optional[str] = None
    is_wildcard: bool = False
    source: Optional[str] = None


class ZoneTransferResult(BaseModel):
    success: bool
    nameserver: str
    records: list[DNSRecord] = Field(default_factory=list)
    error: Optional[str] = None


class DNSEnumResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str = ""

    records: list[DNSRecord] = Field(default_factory=list)
    total_records: int = 0

    subdomains: list[SubdomainResult] = Field(default_factory=list)
    total_subdomains: int = 0

    zone_transfers: list[ZoneTransferResult] = Field(default_factory=list)
    zone_transfer_possible: bool = False

    nameservers: list[str] = Field(default_factory=list)
    mail_servers: list[dict[str, Any]] = Field(default_factory=list)

    wildcard_detected: bool = False
    wildcard_ips: list[str] = Field(default_factory=list)

    raw_output: Optional[str] = None
    error: Optional[str] = None
    wordlist_used: Optional[str] = None
    resolver_used: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 5. UTILITIES
# ══════════════════════════════════════════════════════════════

def _target_in_args(target: str, args: list[str]) -> bool:
    if not args:
        return False

    target_clean = target.strip().lower()
    target_flags = {"-d", "--domain", "-t", "--target", "-h", "--host"}

    for i, arg in enumerate(args):
        arg_lower = arg.strip().lower()

        if arg_lower == target_clean:
            return True

        if target_clean in arg_lower:
            return True

        if arg_lower in target_flags and i + 1 < len(args):
            if args[i + 1].strip().lower() == target_clean:
                return True

    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    return any(arg in args for arg in flags)


def _has_flag_with_value(args: list[str], flags: list[str]) -> bool:
    for arg in args:
        if arg in flags:
            return True
        for flag in flags:
            if arg.startswith(flag + "=") or (len(flag) == 2 and arg.startswith(flag) and len(arg) > 2):
                return True
    return False


def _dedupe_records(records: list[DNSRecord]) -> list[DNSRecord]:
    seen = set()
    unique = []
    for r in records:
        key = (r.record_type, r.name, r.value, r.priority, r.ttl)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def _strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text or "")


def _clean_massdns_stream(text: str) -> str:
    """
    Remove terminal control codes and high-noise status lines from massdns output.
    Keeps actionable lines (errors, resolver failures, and actual answers).
    """
    if not text:
        return ""

    cleaned = _strip_ansi(text).replace("\r", "\n")
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]

    noisy_prefixes = (
        "Concurrency:",
        "Processed queries:",
        "Received packets:",
        "Progress:",
        "Current incoming rate:",
        "Current success rate:",
        "Finished total:",
        "Mismatched domains:",
        "Failures:",
        "Response: |",
        "OK:",
        "NXDOMAIN:",
        "SERVFAIL:",
        "REFUSED:",
        "FORMERR:",
    )

    useful: list[str] = []
    for line in lines:
        if any(line.startswith(prefix) for prefix in noisy_prefixes):
            continue
        useful.append(line)

    return "\n".join(useful)


def _build_clean_raw_output(tool: str, stdout: str, stderr: str) -> Optional[str]:
    """
    Return user-facing raw output that is concise and readable.
    """
    if tool == "massdns":
        cleaned_stdout = _clean_massdns_stream(stdout)
        cleaned_stderr = _clean_massdns_stream(stderr)
        out = cleaned_stdout or cleaned_stderr
        return out[:10000] if out else None

    out = (stdout or stderr)
    return out[:10000] if out else None


def check_tool_installed(tool: str) -> tuple[bool, str]:
    """Verify required external tool exists"""
    binary_map = {
        "dig": "dig",
        "dnsrecon": "dnsrecon",
        "dnsenum": "dnsenum",
        "fierce": "fierce",
        "massdns": "massdns",
        "puredns": "puredns",
    }

    binary = binary_map.get(tool)
    if not binary:
        return False, f"Unknown tool: {tool}"

    binary_path = shutil.which(binary)
    if binary_path is None:
        install_hints = {
            "dig": "sudo apt install dnsutils",
            "dnsrecon": "pip install dnsrecon",
            "dnsenum": "sudo apt install dnsenum",
            "fierce": "sudo apt install fierce",
            "massdns": "build/install massdns from source",
            "puredns": "go install github.com/d3mondev/puredns/v2@latest",
        }
        return False, f"Tool '{tool}' not installed. Install with: {install_hints.get(tool, 'unknown')}"

    # dnsrecon currently breaks on Python 3.14 because urllib.request.FancyURLopener
    # was removed. Detect it early and return a concise fix message.
    if tool == "dnsrecon":
        out, err, rc, _ = safe_execute([binary_path, "-h"], timeout=20)
        banner = f"{out}\n{err}"
        if "FancyURLopener" in banner:
            return (
                False,
                "Tool 'dnsrecon' is installed but incompatible with Python 3.14 "
                "(urllib.request.FancyURLopener was removed). "
                "Use a Python <= 3.13 environment for dnsrecon or install a patched version."
            )

    return True, ""


# ══════════════════════════════════════════════════════════════
# 6. WORDLIST MANAGER
# ══════════════════════════════════════════════════════════════

class DNSWordlistManager:
    """Handle DNS wordlist creation — inline or built-in"""

    def __init__(self):
        self._temp_files: list[str] = []

    def get_wordlist_path(
        self,
        mode: str,
        inline_words: Optional[list[str]],
        builtin_key: Optional[str],
        prefix: str = "dns"
    ) -> Optional[str]:
        if mode == "inline" and inline_words:
            return self._create_temp_file(inline_words, prefix)

        if mode == "builtin" and builtin_key:
            wordlists = get_dns_wordlists()
            path = wordlists.get(builtin_key)
            if path and os.path.isfile(path):
                return path
            raise FileNotFoundError(
                f"Builtin wordlist '{builtin_key}' not found at: {path}"
            )

        return None

    def _create_temp_file(self, words: list[str], prefix: str) -> str:
        # Use system temp dir; do not write under project tmp/output/logs folders.
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            prefix=f"dns_{prefix}_",
            suffix=".txt",
            delete=False
        )
        tmp.write("\n".join(words))
        tmp.close()
        self._temp_files.append(tmp.name)
        return tmp.name

    def build_massdns_fqdn_file(self, source_wordlist_path: str, domain: str) -> str:
        fqdn_entries: list[str] = []
        source = Path(source_wordlist_path)

        for line in source.read_text(errors="ignore").splitlines():
            entry = line.strip()
            if not entry:
                continue
            if entry.endswith("." + domain) or entry == domain:
                fqdn_entries.append(entry)
            else:
                fqdn_entries.append(f"{entry}.{domain}")

        return self._create_temp_file(fqdn_entries, "massdns_fqdn")

    def cleanup(self):
        for f in self._temp_files:
            try:
                os.unlink(f)
            except OSError:
                pass
        self._temp_files.clear()


# ══════════════════════════════════════════════════════════════
# 7. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(
    cmd: list[str],
    timeout: int = 600,
    cwd: Optional[str | Path] = None,
    stdin_data: Optional[str] = None,
) -> tuple[str, str, int, str]:
    """Single canonical executor"""
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
            input=stdin_data,
        )
        return result.stdout, result.stderr, result.returncode, str(cwd)

    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 8. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_dig(stdout: str, stderr: str) -> tuple[list[DNSRecord], list[str], list[dict]]:
    records = []
    nameservers = []
    mail_servers = []

    record_pattern = r"^(\S+)\.\s+(\d+)\s+IN\s+(\w+)\s+(.+)$"

    for line in stdout.split("\n"):
        line = line.strip()
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

            if rtype == "MX":
                mx_match = re.match(r"(\d+)\s+(.+)", value)
                if mx_match:
                    record.priority = int(mx_match.group(1))
                    record.value = mx_match.group(2).rstrip(".")
                    mail_servers.append({
                        "priority": record.priority,
                        "server": record.value,
                    })

            if rtype == "NS":
                nameservers.append(value)

            records.append(record)

    return records, nameservers, mail_servers


def parse_dnsrecon(stdout: str, stderr: str) -> tuple[list[DNSRecord], list[SubdomainResult], list[ZoneTransferResult], list[str], list[dict]]:
    records = []
    subdomains = []
    zone_transfers = []
    nameservers = []
    mail_servers = []

    raw = stdout

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

                        if rtype in ("A", "AAAA"):
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

    record_pattern = r"\[\*\]\s+(\w+)\s+(\S+)\s+(.+)"

    for line in raw.split("\n"):
        line = line.strip()

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
    records = []
    subdomains = []
    zone_transfers = []
    nameservers = []
    mail_servers = []

    raw = stdout
    record_pattern = r"(\S+)\.\s+(\d+)\s+IN\s+(\w+)\s+(.+)"

    for line in raw.split("\n"):
        line = line.strip()

        if "Zone Transfer" in line and "successful" in line.lower():
            zone_transfers.append(ZoneTransferResult(success=True, nameserver="unknown"))

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
    subdomains = []
    nameservers = []
    zone_transfer_success = False

    raw = stdout + "\n" + stderr

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

        if "zone transfer" in line.lower() and "successful" in line.lower():
            zone_transfer_success = True

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
    subdomains = []
    seen = set()

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

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
    subdomains = []
    wildcard_detected = False
    wildcard_ips = []

    if "wildcard" in stderr.lower():
        wildcard_detected = True
        ip_matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)", stderr)
        wildcard_ips = list(set(ip_matches))

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if re.match(r"^[\w\.\-]+\.[a-zA-Z]{2,}$", line):
            subdomains.append(SubdomainResult(
                subdomain=line,
                source="puredns",
            ))
            continue

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
# 9. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_dig_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["dig"]
    final_args = list(args)

    if not _target_in_args(target, final_args):
        insert_pos = 0
        for i, arg in enumerate(final_args):
            if arg.startswith("@"):
                insert_pos = i + 1
                break
        final_args.insert(insert_pos, target)

    cmd.extend(final_args)
    return cmd


def _build_dnsrecon_cmd(args: list[str], target: str, wordlist_path: Optional[str]) -> list[str]:
    cmd = ["dnsrecon"]
    final_args = list(args)

    if not _target_in_args(target, final_args) and not _has_flag_with_value(final_args, ["-d", "--domain"]):
        final_args.extend(["-d", target])

    if wordlist_path and not _has_flag_with_value(final_args, ["-D", "--dictionary"]):
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


def _build_dnsenum_cmd(args: list[str], target: str, wordlist_path: Optional[str]) -> list[str]:
    cmd = ["dnsenum"]
    final_args = list(args)

    if wordlist_path and not _has_flag_with_value(final_args, ["-f", "--file"]):
        final_args.extend(["-f", wordlist_path])

    if not _target_in_args(target, final_args):
        final_args.append(target)

    cmd.extend(final_args)
    return cmd


def _build_fierce_cmd(args: list[str], target: str, wordlist_path: Optional[str]) -> list[str]:
    cmd = ["fierce"]
    final_args = list(args)

    if not _target_in_args(target, final_args) and not _has_flag_with_value(final_args, ["--domain", "-d"]):
        final_args.extend(["--domain", target])

    if wordlist_path and not _has_flag_with_value(final_args, ["--wordlist", "-w"]):
        final_args.extend(["--wordlist", wordlist_path])

    cmd.extend(final_args)
    return cmd


def _build_massdns_cmd(args: list[str], fqdn_wordlist_path: Optional[str], resolver_path: Optional[str]) -> list[str]:
    cmd = ["massdns"]
    final_args = list(args)

    if resolver_path and not _has_flag_with_value(final_args, ["-r", "--resolvers"]):
        final_args.extend(["-r", resolver_path])

    if not _has_flag_with_value(final_args, ["-o", "--output"]):
        final_args.extend(["-o", "S"])

    if not _has_flag_with_value(final_args, ["-t", "--type"]):
        final_args.extend(["-t", "A"])

    if fqdn_wordlist_path and fqdn_wordlist_path not in final_args:
        final_args.append(fqdn_wordlist_path)

    cmd.extend(final_args)
    return cmd


def _build_puredns_cmd(args: list[str], target: str, wordlist_path: Optional[str], resolver_path: Optional[str]) -> list[str]:
    cmd = ["puredns"]
    final_args = list(args)

    is_bruteforce = "bruteforce" in final_args or "brute" in final_args
    is_resolve = "resolve" in final_args

    if not is_bruteforce and not is_resolve:
        if wordlist_path:
            final_args.insert(0, "bruteforce")
            is_bruteforce = True
        else:
            final_args.insert(0, "resolve")
            is_resolve = True

    if wordlist_path and wordlist_path not in final_args:
        mode_idx = -1
        for i, arg in enumerate(final_args):
            if arg in ("bruteforce", "brute", "resolve"):
                mode_idx = i
                break
        if mode_idx >= 0:
            final_args.insert(mode_idx + 1, wordlist_path)
        else:
            final_args.append(wordlist_path)

    if is_bruteforce and not _target_in_args(target, final_args):
        if wordlist_path:
            try:
                wl_idx = final_args.index(wordlist_path)
                final_args.insert(wl_idx + 1, target)
            except ValueError:
                final_args.append(target)
        else:
            final_args.append(target)

    if resolver_path and not _has_flag_with_value(final_args, ["-r", "--resolvers"]):
        final_args.extend(["-r", resolver_path])

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 10. CORE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _dns_enum_fuzzing_impl(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    wordlist_mode: str = "builtin",
    subdomain_wordlist: Optional[list[str]] = None,
    resolver_list: Optional[list[str]] = None,
    builtin_subdomain_list: Optional[str] = None,
    builtin_resolver_list: Optional[str] = None,
    timeout: int = 600,
) -> dict:
    start = time.time()
    args = list(args or [])
    wl_manager = DNSWordlistManager()
    warnings: list[str] = []

    DNS_RATE_LIMITER.acquire()

    try:
        req = DNSEnumRequest(
            tool=tool,
            target=target,
            args=args,
            wordlist_mode=wordlist_mode,
            subdomain_wordlist=subdomain_wordlist,
            resolver_list=resolver_list,
            builtin_subdomain_list=builtin_subdomain_list,
            builtin_resolver_list=builtin_resolver_list,
            timeout=timeout,
        )
    except Exception as e:
        return DNSEnumResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation: {e}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    installed, install_msg = check_tool_installed(req.tool)
    if not installed:
        return DNSEnumResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            error=install_msg,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    wordlist_path = None
    resolver_path = None
    massdns_fqdn_wordlist_path = None
    wordlist_used = None
    resolver_used = None

    try:
        wordlist_path = wl_manager.get_wordlist_path(
            req.wordlist_mode,
            req.subdomain_wordlist,
            req.builtin_subdomain_list,
            "subdomains",
        )
        if wordlist_path:
            wordlist_used = wordlist_path

        resolver_path = wl_manager.get_wordlist_path(
            req.wordlist_mode,
            req.resolver_list,
            req.builtin_resolver_list,
            "resolvers",
        )
        if resolver_path:
            resolver_used = resolver_path

        if req.tool == "massdns" and wordlist_path:
            massdns_fqdn_wordlist_path = wl_manager.build_massdns_fqdn_file(wordlist_path, req.target)
            wordlist_used = massdns_fqdn_wordlist_path

    except FileNotFoundError as e:
        wl_manager.cleanup()
        return DNSEnumResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            error=str(e),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    try:
        if req.tool == "dig":
            cmd = _build_dig_cmd(req.args, req.target)
        elif req.tool == "dnsrecon":
            cmd = _build_dnsrecon_cmd(req.args, req.target, wordlist_path)
        elif req.tool == "dnsenum":
            cmd = _build_dnsenum_cmd(req.args, req.target, wordlist_path)
        elif req.tool == "fierce":
            cmd = _build_fierce_cmd(req.args, req.target, wordlist_path)
        elif req.tool == "massdns":
            cmd = _build_massdns_cmd(req.args, massdns_fqdn_wordlist_path, resolver_path)
        elif req.tool == "puredns":
            cmd = _build_puredns_cmd(req.args, req.target, wordlist_path, resolver_path)
        else:
            wl_manager.cleanup()
            return DNSEnumResult(
                success=False,
                tool=req.tool,
                target=req.target,
                command="",
                error=f"Unknown tool: {req.tool}",
                execution_time=round(time.time() - start, 2),
            ).model_dump()
    except Exception as e:
        wl_manager.cleanup()
        return DNSEnumResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            error=f"Command build error: {e}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    command_str = " ".join(cmd)
    stdout, stderr, rc, working_dir = safe_execute(cmd, req.timeout)

    records: list[DNSRecord] = []
    subdomains: list[SubdomainResult] = []
    zone_transfers: list[ZoneTransferResult] = []
    nameservers: list[str] = []
    mail_servers: list[dict[str, Any]] = []
    wildcard_detected = False
    wildcard_ips: list[str] = []

    if req.tool == "dig":
        records, nameservers, mail_servers = parse_dig(stdout, stderr)

    elif req.tool == "dnsrecon":
        records, subdomains, zone_transfers, nameservers, mail_servers = parse_dnsrecon(stdout, stderr)

    elif req.tool == "dnsenum":
        records, subdomains, zone_transfers, nameservers, mail_servers = parse_dnsenum(stdout, stderr)

    elif req.tool == "fierce":
        subdomains, nameservers, zt_success = parse_fierce(stdout, stderr)
        if zt_success:
            zone_transfers.append(ZoneTransferResult(success=True, nameserver="unknown"))

    elif req.tool == "massdns":
        subdomains = parse_massdns(stdout, stderr)

    elif req.tool == "puredns":
        subdomains, wildcard_detected, wildcard_ips = parse_puredns(stdout, stderr)

    wl_manager.cleanup()

    records = _dedupe_records(records)

    seen_subs = set()
    unique_subs = []
    for sub in subdomains:
        if sub.subdomain not in seen_subs:
            seen_subs.add(sub.subdomain)
            unique_subs.append(sub)
    subdomains = unique_subs

    nameservers = sorted(set(nameservers))

    zone_transfer_possible = any(zt.success for zt in zone_transfers)

    # helpful warnings
    if req.tool in {"massdns", "puredns"} and not resolver_path:
        warnings.append("No resolver list explicitly provided; tool defaults may be unreliable")

    if req.tool == "dig" and not records and rc == 0:
        warnings.append("dig completed but no records were parsed")

    if req.tool == "massdns" and wordlist_path and massdns_fqdn_wordlist_path:
        warnings.append("massdns input prefixes were expanded to FQDNs automatically")

    clean_raw_output = _build_clean_raw_output(req.tool, stdout, stderr)

    return DNSEnumResult(
        success=len(records) > 0 or len(subdomains) > 0 or rc == 0,
        tool=req.tool,
        target=req.target,
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
        raw_output=clean_raw_output,
        error=stderr if rc != 0 and not records and not subdomains else None,
        wordlist_used=wordlist_used,
        resolver_used=resolver_used,
        warnings=warnings,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 11. CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_dns_enum_fuzzing(
    tool: str,
    target: str,
    args_tuple: tuple[str, ...],
    wordlist_mode: str,
    subdomain_wordlist_tuple: tuple[str, ...],
    resolver_list_tuple: tuple[str, ...],
    builtin_subdomain_list: Optional[str],
    builtin_resolver_list: Optional[str],
    timeout: int,
) -> str:
    result = _dns_enum_fuzzing_impl(
        tool=tool,
        target=target,
        args=list(args_tuple),
        wordlist_mode=wordlist_mode,
        subdomain_wordlist=list(subdomain_wordlist_tuple) if subdomain_wordlist_tuple else None,
        resolver_list=list(resolver_list_tuple) if resolver_list_tuple else None,
        builtin_subdomain_list=builtin_subdomain_list,
        builtin_resolver_list=builtin_resolver_list,
        timeout=timeout,
    )
    return json.dumps(result)


def clear_cache():
    _cached_dns_enum_fuzzing.cache_clear()


def get_cache_info():
    return _cached_dns_enum_fuzzing.cache_info()


def get_rate_limiter_stats() -> dict:
    return {
        "calls_per_second": DNS_RATE_LIMITER.calls_per_second,
        "min_interval": DNS_RATE_LIMITER.min_interval,
    }


def set_rate_limit(calls_per_second: float):
    global DNS_RATE_LIMITER
    DNS_RATE_LIMITER = RateLimiter(calls_per_second=calls_per_second)


# ══════════════════════════════════════════════════════════════
# 12. PUBLIC API
# ══════════════════════════════════════════════════════════════

def dns_enum_fuzzing(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    wordlist_mode: str = "builtin",
    subdomain_wordlist: Optional[list[str]] = None,
    resolver_list: Optional[list[str]] = None,
    builtin_subdomain_list: Optional[str] = None,
    builtin_resolver_list: Optional[str] = None,
    timeout: int = 600,
    use_cache: bool = True,

    # backward compatibility
    list_type: Optional[str] = None,
) -> dict:
    """
    🔧 Agent Tool: DNS Enumeration & Fuzzing

    Enumerate DNS records, discover subdomains, attempt zone transfers,
    and fuzz for hidden subdomains.

    Supports:
    - dig
    - dnsrecon
    - dnsenum
    - fierce
    - massdns
    - puredns

    Improvements:
    - fixed mutable defaults
    - fixed duplicate executor
    - real IP validation
    - massdns FQDN preprocessing
    - record deduplication
    - caching
    - rate limiting
    - install checks
    - clearer wordlist_mode (builtin/inline)
    """

    # backward compatibility mapping
    if list_type == "user":
        wordlist_mode = "builtin"
    elif list_type == "ia":
        wordlist_mode = "inline"

    args = args or []
    subdomain_wordlist = subdomain_wordlist or []
    resolver_list = resolver_list or []

    if use_cache:
        cached = _cached_dns_enum_fuzzing(
            tool,
            target,
            tuple(args),
            wordlist_mode,
            tuple(subdomain_wordlist),
            tuple(resolver_list),
            builtin_subdomain_list,
            builtin_resolver_list,
            timeout,
        )
        return json.loads(cached)

    return _dns_enum_fuzzing_impl(
        tool=tool,
        target=target,
        args=args,
        wordlist_mode=wordlist_mode,
        subdomain_wordlist=subdomain_wordlist if subdomain_wordlist else None,
        resolver_list=resolver_list if resolver_list else None,
        builtin_subdomain_list=builtin_subdomain_list,
        builtin_resolver_list=builtin_resolver_list,
        timeout=timeout,
    )


# ══════════════════════════════════════════════════════════════
# 13. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

DNS_ENUM_TOOL_DEFINITION = {
    "name": "dns_enum_fuzzing",
    "description": (
        "Enumerate DNS records, discover subdomains, attempt zone transfers, and fuzz hidden subdomains. "
        "Supports dig (lookups), dnsrecon (full enum), dnsenum (enum+brute), fierce (smart recon), "
        "massdns (fast mass resolution), and puredns (fast brute+wildcard filtering). "
        "Supports built-in wordlists or inline word lists. Includes caching, rate limiting, "
        "tool install checks, record deduplication, and massdns FQDN preprocessing."
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
                "description": "Domain name or public IP/CIDR"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw tool arguments"
            },
            "wordlist_mode": {
                "type": "string",
                "enum": ["builtin", "inline"],
                "description": "'builtin' = built-in wordlists | 'inline' = inline words"
            },
            "subdomain_wordlist": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Inline subdomain list if wordlist_mode='inline'"
            },
            "resolver_list": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Inline resolver list if wordlist_mode='inline'"
            },
            "builtin_subdomain_list": {
                "type": "string",
                "enum": [
                    "subdomains_short", "subdomains_medium", "subdomains_large",
                    "subdomains_full", "subdomains_common", "subdomains_bitquark",
                    "fierce_default", "dns_names", "deepmagic"
                ],
                "description": "Built-in subdomain wordlist key"
            },
            "builtin_resolver_list": {
                "type": "string",
                "enum": ["resolvers", "resolvers_trusted"],
                "description": "Built-in resolver wordlist key"
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds"
            },
            "use_cache": {
                "type": "boolean",
                "description": "Enable result caching"
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 14. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("DNS ENUMERATION & FUZZING — v3.0")
    print("Install Checks | Rate Limited | Cached | Fixed Weaknesses")
    print("=" * 70)

    # Example 1: dig
    r = dns_enum_fuzzing(
        tool="dig",
        target="scanme.nmap.org",
        args=["ANY", "+noall", "+answer"],
        use_cache=False,
    )
    print("\n=== DIG ===")
    print(json.dumps(r, indent=2))

    # Example 2: dnsrecon brute with builtin wordlist
    r = dns_enum_fuzzing(
        tool="dnsrecon",
        target="scanme.nmap.org",
        args=["-t", "brt"],
        wordlist_mode="builtin",
        builtin_subdomain_list="subdomains_short",
        use_cache=False,
    )
    print("\n=== DNSRECON BRUTE ===")
    print(json.dumps(r, indent=2))

    # Example 3: massdns with inline subdomains
    r = dns_enum_fuzzing(
        tool="massdns",
        target="scanme.nmap.org",
        args=[],
        wordlist_mode="inline",
        subdomain_wordlist=["www", "mail", "admin", "api"],
        resolver_list=["8.8.8.8", "1.1.1.1"],
        use_cache=False,
    )
    print("\n=== MASSDNS INLINE ===")
    print(json.dumps(r, indent=2))

    # Example 4: cache test
    start = time.time()
    _ = dns_enum_fuzzing("dig", "scanme.nmap.org", ["A", "+short"], use_cache=True)
    first = time.time() - start

    start = time.time()
    _ = dns_enum_fuzzing("dig", "scanme.nmap.org", ["A", "+short"], use_cache=True)
    second = time.time() - start

    print("\n=== CACHE TEST ===")
    print(f"First run:  {first:.2f}s")
    print(f"Cached run: {second:.4f}s")
    print(f"Cache info: {get_cache_info()}")

    print("\n=== RATE LIMITER ===")
    print(json.dumps(get_rate_limiter_stats(), indent=2))
