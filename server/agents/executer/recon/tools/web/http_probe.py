#/+
import subprocess
import json
import re
import os
import time
import logging
import threading
import ipaddress
import shutil
from pathlib import Path
from typing import Optional
from functools import lru_cache
from pydantic import BaseModel, Field, field_validator, model_validator

from server.agents.executer.recon.config import BLOCKED_HOSTNAMES as _BLOCKED_HOSTNAMES
from server.agents.executer.recon.config import BLOCKED_NETWORKS as _BLOCKED_NETWORKS


# ══════════════════════════════════════════════════════════════
# 1. LOGGING CONFIGURATION
# ══════════════════════════════════════════════════════════════

logger = logging.getLogger("http_probe")
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
    """Thread-safe rate limiter for HTTP probing jobs"""
    
    def __init__(self, calls_per_second: float = 1.0):
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


HTTP_PROBE_RATE_LIMITER = RateLimiter(calls_per_second=1.0)


# ══════════════════════════════════════════════════════════════
# 3. PROJECT CONFIGURATION & CONSTANTS
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools"""
    _project_dir: Optional[Path] = None
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
        markers = ["pyproject.toml", "setup.py", ".git", "requirements.txt"]
        
        for parent in [current] + list(current.parents):
            if any((parent / marker).exists() for marker in markers):
                cls._project_dir = parent
                return cls._project_dir
        
        cls._project_dir = Path.cwd()
        return cls._project_dir


# BLOCKED_TARGETS removed in favor of centralized config.

DANGEROUS_CHARS = [";", "&&", "||", "|", "`", "$(", ">", "\n", "\r", "'", '"']
MAX_TARGETS = 100000
MAX_RAW_OUTPUT = 10000

# blocked because we manage input ourselves
BLOCKED_HTTPX_FLAGS = {
    "-l",
    "-list",
    "-s",
    "-stdin",
    "-sr",
    "-store-response",
    "-irr",
    "-include-response",
    "-irh",
    "-include-response-header",
    "-jsonl",
    "-o",
    "-oa",
}


# ══════════════════════════════════════════════════════════════
# 4. TARGET / COMMAND HELPERS
# ══════════════════════════════════════════════════════════════

def normalize_target(target: str) -> str:
    clean = target.strip()
    return clean.lower() if clean else clean


def extract_host_from_target(target: str) -> str:
    clean = target.strip().lower()
    clean = re.sub(r"^\w+://", "", clean)
    clean = clean.split("/")[0]
    clean = clean.split(":")[0]
    return clean


def is_blocked_target(target: str) -> bool:
    host = extract_host_from_target(target)
    host_lower = host.lower()
    for b_host in _BLOCKED_HOSTNAMES:
        if host_lower == b_host or host_lower.endswith(f".{b_host}"):
            return True
    try:
        ip = ipaddress.ip_address(host)
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False


def is_valid_target_format(target: str) -> bool:
    clean = target.strip()
    if not clean:
        return False
    
    host = extract_host_from_target(clean)
    if not host:
        return False
    
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    
    domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)*[a-zA-Z]{2,}$"
    return bool(re.match(domain_pattern, host))


def _target_in_args(target: str, args: list[str], flags: list[str]) -> bool:
    if not args:
        return False
    
    target_clean = normalize_target(target)
    target_host = extract_host_from_target(target_clean)
    
    for i, arg in enumerate(args):
        arg_clean = normalize_target(arg)
        arg_host = extract_host_from_target(arg_clean)
        
        if arg_clean == target_clean or arg_host == target_host:
            return True
        if target_host and target_host in arg_clean:
            return True
        
        if arg_clean in flags and i + 1 < len(args):
            next_arg = normalize_target(args[i + 1])
            next_host = extract_host_from_target(next_arg)
            if next_arg == target_clean or next_host == target_host:
                return True
    
    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    for arg in args:
        for flag in flags:
            if arg == flag or arg.startswith(flag + "="):
                return True
    return False


def _looks_like_projectdiscovery_httpx(text: str) -> bool:
    body = (text or "").lower()
    # ProjectDiscovery help always contains these markers.
    return (
        "fast and multi-purpose http toolkit" in body
        or "-u, -target" in body
        or "input target host(s) to probe" in body
    )


def _candidate_httpx_binaries() -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    preferred = [
        "/usr/local/bin/httpx",
        str(Path.home() / "go" / "bin" / "httpx"),
    ]

    for candidate in preferred:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and candidate not in seen:
            ordered.append(candidate)
            seen.add(candidate)

    # Include every httpx found in PATH (helps with venv/path precedence differences).
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for path_dir in path_dirs:
        if not path_dir:
            continue
        candidate = os.path.join(path_dir, "httpx")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and candidate not in seen:
            ordered.append(candidate)
            seen.add(candidate)

    return ordered


def resolve_httpx_binary() -> tuple[Optional[str], str]:
    candidates = _candidate_httpx_binaries()
    if not candidates:
        return None, (
            "ProjectDiscovery 'httpx' not found. Install with: "
            "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        )

    rejected: list[str] = []
    for bin_path in candidates:
        out, err, _, _ = safe_execute([bin_path, "-h"], timeout=15)
        banner = (out or "") + "\n" + (err or "")
        lower = banner.lower()

        if "required dependencies were not installed" in lower:
            rejected.append(f"{bin_path} (python httpx CLI stub)")
            continue
        if "no such option" in lower and "-u" in lower:
            rejected.append(f"{bin_path} (non-ProjectDiscovery httpx)")
            continue
        if _looks_like_projectdiscovery_httpx(banner):
            return bin_path, ""

        rejected.append(f"{bin_path} (unknown flavor)")

    return None, (
        "Found 'httpx' binary names, but none matched ProjectDiscovery httpx. "
        "Rejected: "
        + ", ".join(rejected)
    )


def safe_execute(
    cmd: list[str],
    timeout: int = 600,
    stdin_data: Optional[str] = None
) -> tuple[str, str, int, str]:
    cwd = ProjectConfig.get_project_dir()
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=str(cwd),
            input=stdin_data,
        )
        return res.stdout, res.stderr, res.returncode, str(cwd)
    except subprocess.TimeoutExpired:
        return "", f"Timeout ({timeout}s)", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 5. SCHEMAS
# ══════════════════════════════════════════════════════════════

class HttpProbeRequest(BaseModel):
    target: Optional[str] = None
    targets: list[str] = Field(default_factory=list)
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=600, ge=10, le=3600)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        if v is None:
            return v
        if is_blocked_target(v):
            raise ValueError(f"Target '{v}' is blocked")
        if not is_valid_target_format(v):
            raise ValueError(f"Invalid target format: {v}")
        return v.strip()

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v):
        if len(v) > MAX_TARGETS:
            raise ValueError(f"Target list too large. Max {MAX_TARGETS} targets.")
        
        validated = []
        for target in v:
            if not target or not target.strip():
                continue
            clean = target.strip()
            if is_blocked_target(clean):
                raise ValueError(f"Target '{clean}' is blocked")
            if not is_valid_target_format(clean):
                raise ValueError(f"Invalid target format: {clean}")
            validated.append(clean)
        return validated

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        for arg in v:
            for char in DANGEROUS_CHARS:
                if char in arg:
                    raise ValueError(f"Dangerous char '{repr(char)}' in arg: {arg}")
            
            arg_clean = arg.strip().lower()
            for blocked in BLOCKED_HTTPX_FLAGS:
                if arg_clean == blocked or arg_clean.startswith(blocked + "="):
                    raise ValueError(f"Blocked flag '{blocked}' in args")
        return v

    @model_validator(mode="after")
    def validate_input_mode(self):
        if not self.target and not self.targets:
            raise ValueError("Must provide either 'target' or 'targets'")
        return self


class ProbedHost(BaseModel):
    url: str
    status_code: int
    title: Optional[str] = None
    webserver: Optional[str] = None
    tech: list[str] = Field(default_factory=list)
    content_length: int = 0
    response_time: Optional[str] = None
    content_type: Optional[str] = None
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None


class HttpProbeResult(BaseModel):
    success: bool
    hosts: list[ProbedHost] = Field(default_factory=list)
    command: str
    working_dir: str
    total_alive: int = 0
    total_input_targets: int = 0
    parse_failures: int = 0
    raw_output: str = ""
    error: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 6. PARSING
# ══════════════════════════════════════════════════════════════

def parse_httpx_output(stdout: str) -> tuple[list[ProbedHost], int]:
    alive_hosts: list[ProbedHost] = []
    parse_failures = 0
    seen_urls = set()

    for line in stdout.splitlines():
        if not line.strip():
            continue
        
        try:
            data = json.loads(line)
            url = data.get("url", "") or ""
            if not url:
                continue
            
            if url in seen_urls:
                continue
            seen_urls.add(url)
            
            tech_raw = data.get("technologies", []) or []
            tech_clean = [str(t) for t in tech_raw if str(t).strip()]
            
            alive_hosts.append(ProbedHost(
                url=url,
                status_code=int(data.get("status_code", 0) or 0),
                title=data.get("title") or None,
                webserver=data.get("webserver") or None,
                tech=tech_clean,
                content_length=int(data.get("content_length", 0) or 0),
                response_time=str(data.get("time")) if data.get("time") is not None else None,
                content_type=data.get("content_type") or None,
                scheme=data.get("scheme") or None,
                host=data.get("host") or None,
                port=int(data.get("port")) if data.get("port") is not None else None,
            ))
        except Exception:
            parse_failures += 1

    return alive_hosts, parse_failures


# ══════════════════════════════════════════════════════════════
# 7. COMMAND BUILDING
# ══════════════════════════════════════════════════════════════

def _build_httpx_command(
    req: HttpProbeRequest,
    httpx_bin: str,
) -> tuple[list[str], Optional[str], int]:
    """
    Build httpx command and stdin payload without temp files.

    Bulk mode:
    - feeds targets via stdin
    - uses -silent/-json output only
    """
    cmd = [httpx_bin]
    final_args = list(req.args)
    stdin_data = None

    # Force structured useful output
    if not _has_flag(final_args, ["-json"]):
        final_args.append("-json")
    if not _has_flag(final_args, ["-silent"]):
        final_args.append("-silent")
    if not _has_flag(final_args, ["-title"]):
        final_args.append("-title")
    if not _has_flag(final_args, ["-tech-detect"]):
        final_args.append("-tech-detect")
    if not _has_flag(final_args, ["-status-code"]):
        final_args.append("-status-code")
    if not _has_flag(final_args, ["-cl"]):
        final_args.append("-cl")
    if not _has_flag(final_args, ["-ct"]):
        final_args.append("-ct")

    total_inputs = 0

    # Bulk stdin mode
    if req.targets:
        stdin_data = "\n".join(req.targets)
        total_inputs = len(req.targets)
    elif req.target:
        total_inputs = 1
        if not _has_flag(final_args, ["-u", "-target"]) and not _target_in_args(
            req.target,
            final_args,
            ["-u", "-target"],
        ):
            # Use explicit target flag for stable behavior across httpx versions.
            final_args.extend(["-u", req.target])

    cmd.extend(final_args)
    return cmd, stdin_data, total_inputs


# ══════════════════════════════════════════════════════════════
# 8. CORE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _http_probe_impl(
    target: Optional[str] = None,
    targets: Optional[list[str]] = None,
    args: Optional[list[str]] = None,
    timeout: int = 600,
) -> dict:
    start = time.time()
    warnings: list[str] = []

    HTTP_PROBE_RATE_LIMITER.acquire()

    try:
        req = HttpProbeRequest(
            target=target,
            targets=targets or [],
            args=args or [],
            timeout=timeout,
        )
    except Exception as e:
        return HttpProbeResult(
            success=False,
            command="",
            working_dir="",
            error=f"Validation: {e}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    httpx_bin, resolve_err = resolve_httpx_binary()
    if not httpx_bin:
        return HttpProbeResult(
            success=False,
            command="",
            working_dir="",
            error=resolve_err,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    try:
        cmd, stdin_data, total_inputs = _build_httpx_command(req, httpx_bin=httpx_bin)
    except Exception as e:
        return HttpProbeResult(
            success=False,
            command="",
            working_dir="",
            error=f"Command build error: {e}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    command_str = " ".join(cmd)
    logger.info(f"Executing: {command_str}")

    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout, stdin_data=stdin_data)

    alive_hosts, parse_failures = parse_httpx_output(stdout)

    if parse_failures > 0:
        warnings.append(f"{parse_failures} output line(s) failed to parse")

    if req.targets and rc == 0 and len(alive_hosts) == 0:
        warnings.append("No alive HTTP hosts found from provided targets")

    success = rc == 0 or len(alive_hosts) > 0

    error_msg = None
    if rc != 0 and not alive_hosts:
        error_msg = (stderr or stdout)[:1000] if (stderr or stdout) else f"httpx exited with code {rc}"

    return HttpProbeResult(
        success=success,
        command=command_str,
        working_dir=cwd,
        total_alive=len(alive_hosts),
        total_input_targets=total_inputs,
        parse_failures=parse_failures,
        hosts=[host.model_dump() for host in alive_hosts],
        raw_output=(stdout or stderr)[:MAX_RAW_OUTPUT] if not alive_hosts else "",
        error=error_msg,
        warnings=warnings,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 9. CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_http_probe(
    target: Optional[str],
    targets_tuple: tuple[str, ...],
    args_tuple: tuple[str, ...],
    timeout: int,
) -> str:
    result = _http_probe_impl(
        target=target,
        targets=list(targets_tuple),
        args=list(args_tuple),
        timeout=timeout,
    )
    return json.dumps(result)


def clear_cache():
    _cached_http_probe.cache_clear()


def get_cache_info():
    return _cached_http_probe.cache_info()


# ══════════════════════════════════════════════════════════════
# 10. PUBLIC API
# ══════════════════════════════════════════════════════════════

def http_probe(
    target: Optional[str] = None,
    targets: Optional[list[str]] = None,
    args: Optional[list[str]] = None,
    timeout: int = 600,
    use_cache: bool = True,
) -> dict:
    """
    🔧 Agent Tool: HTTP Probe (httpx)

    Probe one or many targets for live HTTP/HTTPS services using httpx.

    Features:
    - single target or many targets
    - no temp files
    - stdin-based bulk probing
    - status code, title, webserver, tech, content-length, content-type
    - deduplicated results
    - parse failure reporting
    - blocked localhost/metadata targets
    - caching + rate limiting

    Args:
        target: single domain/IP/URL
        targets: list of domain/IP/URL values
        args: raw httpx arguments
        timeout: execution timeout
        use_cache: enable LRU caching

    Returns:
        Structured JSON with alive hosts and metadata.
    """
    targets = targets or []
    args = args or []

    if use_cache:
        cached = _cached_http_probe(
            target,
            tuple(targets),
            tuple(args),
            timeout,
        )
        return json.loads(cached)

    return _http_probe_impl(
        target=target,
        targets=targets,
        args=args,
        timeout=timeout,
    )


# ══════════════════════════════════════════════════════════════
# 11. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

HTTP_PROBE_TOOL_DEFINITION = {
    "name": "http_probe",
    "description": (
        "Probe domains, subdomains, IPs, or URLs to find live HTTP/HTTPS services using httpx. "
        "Returns status codes, titles, response sizes, technologies, webservers, and content types. "
        "Supports single target or a provided list of targets. Uses stdin for bulk mode and never writes temp files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Single domain, IP, or URL. Example: 'example.com' or 'https://api.example.com'"
            },
            "targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of domains, subdomains, IPs, or URLs to probe"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw httpx args. Example: "
                    "['-p', '80,443,8080,8443', '-follow-redirects', '-random-agent']"
                )
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds (default 600)"
            },
            "use_cache": {
                "type": "boolean",
                "description": "Enable result caching (default true)"
            }
        }
    }
}


# ══════════════════════════════════════════════════════════════
# 12. UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def get_rate_limiter_stats() -> dict:
    return {
        "calls_per_second": HTTP_PROBE_RATE_LIMITER.calls_per_second,
        "min_interval": HTTP_PROBE_RATE_LIMITER.min_interval,
    }


def set_rate_limit(calls_per_second: float):
    global HTTP_PROBE_RATE_LIMITER
    HTTP_PROBE_RATE_LIMITER = RateLimiter(calls_per_second=calls_per_second)


# ══════════════════════════════════════════════════════════════
# 13. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("HTTP PROBE (httpx) — v2.0")
    print("No Temp Files | Cached | Safe | Bulk via stdin")
    print("=" * 70)
    
    # Example 1: Probe a list of subdomains
    subdomains_to_check = [
        "scanme.nmap.org",
    ]
    
    r1 = http_probe(
        targets=subdomains_to_check,
        args=["-p", "80,443", "-follow-redirects"],
        use_cache=False,
    )
    print("\n=== PROBING LIST OF SUBDOMAINS ===")
    print(f"Command: {r1['command']}")
    print(f"Input Targets: {r1['total_input_targets']}")
    print(f"Alive Hosts: {r1['total_alive']}")
    print(f"Parse Failures: {r1['parse_failures']}")
    for host in r1["hosts"]:
        print(f"\n[{host['status_code']}] {host['url']}")
        print(f"  Title:  {host.get('title')}")
        print(f"  Server: {host.get('webserver')}")
        print(f"  Tech:   {', '.join(host.get('tech', [])[:3])}")
        print(f"  Size:   {host.get('content_length')} bytes")
        print(f"  Type:   {host.get('content_type')}")
    
    # Example 2: Single target
    r2 = http_probe(
        target="scanme.nmap.org",
        args=["-p", "80,443,8080", "-threads", "50"],
        use_cache=False,
    )
    print("\n=== PROBING SINGLE TARGET ===")
    print(f"Command: {r2['command']}")
    print(f"Alive Hosts: {r2['total_alive']}")
    for host in r2["hosts"]:
        print(f"[{host['status_code']}] {host['url']} - {host.get('title')}")
    
    # Example 3: Cache test
    start = time.time()
    _ = http_probe(target="hackerone.com", args=["-follow-redirects"], use_cache=True)
    first = time.time() - start

    start = time.time()
    _ = http_probe(target="hackerone.com", args=["-follow-redirects"], use_cache=True)
    second = time.time() - start

    print("\n=== CACHE TEST ===")
    print(f"First run:  {first:.2f}s")
    print(f"Cached run: {second:.4f}s")
    print(f"Cache info: {get_cache_info()}")
    
    print("\n=== FULL JSON PAYLOAD ===")
    print(json.dumps(r1, indent=2))
