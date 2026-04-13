#/+
import subprocess
import json
import re
import os
import time
import logging
import threading
import shutil
from pathlib import Path
from typing import Optional, Any
from functools import lru_cache
from urllib.parse import urlparse, parse_qs
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. LOGGING CONFIGURATION
# ══════════════════════════════════════════════════════════════

logger = logging.getLogger("param_discovery")
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
    """Thread-safe rate limiter for brute-force tools"""
    
    def __init__(self, calls_per_second: float = 0.2):
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


# Global rate limiter (1 scan per 5 seconds)
PARAM_RATE_LIMITER = RateLimiter(calls_per_second=0.2)


# ══════════════════════════════════════════════════════════════
# 3. CONFIGURATION & CONSTANTS
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
    
    @classmethod
    def get_temp_dir(cls) -> Path:
        path = cls.get_project_dir() / cls.TEMP_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path


# Security constants
DANGEROUS_CHARS = [";", "&&", "||", "|", "`", "$(", ">", "\n", "\r", "'", '"']

from server.agents.executer.recon.config import BLOCKED_HOSTNAMES as _BLOCKED_HOSTNAMES
from server.agents.executer.recon.config import BLOCKED_NETWORKS as _BLOCKED_NETWORKS

# Allowed wordlist directories
ALLOWED_WORDLIST_DIRS = [
    Path("/usr/share/seclists"),
    Path("/usr/share/wordlists"),
    Path("/opt/wordlists"),
    Path.home() / ".local/share/wordlists",
]

# Default wordlist sizes
DEFAULT_WORDLIST_SIZES = {
    "arjun": 2500,
    "x8": 500,
    "paramspider": 0,
}

# Common wordlist locations for x8
DEFAULT_X8_WORDLISTS = [
    Path("/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"),
    Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-parameters.txt"),
    Path("/usr/share/wordlists/params.txt"),
    Path.home() / ".local/share/wordlists/parameters.txt",
]

MAX_REQUESTS_WARNING = 10000


# ══════════════════════════════════════════════════════════════
# 4. SCHEMAS
# ══════════════════════════════════════════════════════════════

class ParamDiscoveryRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=900, ge=30, le=3600)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"arjun", "paramspider", "x8"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        clean = v.strip()

        domain_part = re.sub(r"^\w+://", "", clean.lower()).split('/')[0].split(':')[0]
        if not domain_part or len(domain_part) < 3:
            raise ValueError(f"Invalid target format: {v}")

        for b_host in _BLOCKED_HOSTNAMES:
            if domain_part == b_host or domain_part.endswith(f".{b_host}"):
                raise ValueError(f"Target '{v}' matches blocked hostname '{b_host}'")
        
        try:
            import ipaddress
            ip = ipaddress.ip_address(domain_part)
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    raise ValueError(f"Target '{v}' resolves to a blocked IP space")
        except ValueError as exc:
            if "blocked IP space" in str(exc):
                raise

        return clean

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        for arg in v:
            # Shell injection check
            for char in DANGEROUS_CHARS:
                if char in arg:
                    raise ValueError(f"Dangerous character '{repr(char)}' in arg: {arg}")

            # Wordlist path validation
            if arg in ["-w", "--wordlist"]:
                continue

            # Check if this is a wordlist path
            if arg.startswith("/") or arg.startswith("~"):
                wordlist_path = Path(arg).expanduser().resolve()

                # Allow project-local wordlists
                try:
                    if wordlist_path.is_relative_to(ProjectConfig.get_project_dir()):
                        continue
                except (ValueError, AttributeError):
                    pass

                # Check allowed directories
                allowed = any(
                    str(wordlist_path).startswith(str(allowed_dir))
                    for allowed_dir in ALLOWED_WORDLIST_DIRS
                    if allowed_dir.exists()
                )

                if not allowed and wordlist_path.suffix in [".txt", ".lst", ""]:
                    if not any(str(wordlist_path).startswith(str(d)) for d in ALLOWED_WORDLIST_DIRS):
                        raise ValueError(
                            f"Wordlist path not in allowed directories. "
                            f"Allowed: {[str(d) for d in ALLOWED_WORDLIST_DIRS if d.exists()]}"
                        )

        return v


class EndpointParams(BaseModel):
    """Parameters discovered for a single endpoint"""
    url: str
    method: str = "GET"
    parameters: list[str] = []
    content_type: Optional[str] = None
    param_count: int = 0

    @field_validator("param_count", mode="after")
    @classmethod
    def compute_count(cls, v, info):
        return len(info.data.get("parameters", []))


class ParamDiscoveryResult(BaseModel):
    """Complete parameter discovery result"""
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str = ""
    
    total_parameters_found: int = 0
    unique_parameters: list[str] = []
    endpoints: list[EndpointParams] = []
    
    estimated_requests: int = 0
    raw_output: str = ""
    error: Optional[str] = None
    warnings: list[str] = []
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 5. UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def check_tool_installed(tool: str) -> tuple[bool, str]:
    """Verify tool is installed before running"""
    binary_map = {
        "arjun": "arjun",
        "x8": "x8",
        "paramspider": "paramspider",
    }
    
    binary = binary_map.get(tool)
    if not binary:
        return False, f"Unknown tool: {tool}"
    
    if shutil.which(binary) is None:
        install_cmds = {
            "arjun": "pip install arjun",
            "x8": "cargo install x8 OR download from https://github.com/Sh1Yo/x8/releases",
            "paramspider": "pip install paramspider",
        }
        return False, f"Tool '{tool}' not installed. Install: {install_cmds.get(tool, 'unknown')}"
    
    return True, ""


def _target_in_args(target: str, args: list[str], flags: list[str]) -> bool:
    """Check if target already exists in args"""
    if not args:
        return False
    t_clean = target.strip().lower()
    t_domain = re.sub(r"^\w+://", "", t_clean).split('/')[0]
    
    for i, arg in enumerate(args):
        a_clean = arg.strip().lower()
        a_domain = re.sub(r"^\w+://", "", a_clean).split('/')[0]
        
        if a_clean == t_clean or a_domain == t_domain:
            return True
        if t_domain in a_clean:
            return True
        if a_clean in flags and i + 1 < len(args):
            next_arg = args[i + 1].strip().lower()
            if next_arg == t_clean or t_domain in next_arg:
                return True
    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    """Check if any flag exists in args"""
    for arg in args:
        for flag in flags:
            if arg == flag or arg.startswith(f"{flag}="):
                return True
    return False


def estimate_request_count(tool: str, args: list[str]) -> tuple[int, str]:
    """Estimate the number of requests that will be sent"""
    base_count = DEFAULT_WORDLIST_SIZES.get(tool, 1000)
    
    if tool == "paramspider":
        return 0, "Archive mining (no requests to target)"
    
    # Check for custom wordlist
    for i, arg in enumerate(args):
        if arg in ["-w", "--wordlist"] and i + 1 < len(args):
            wordlist_path = Path(args[i + 1]).expanduser()
            if wordlist_path.exists():
                try:
                    count = sum(1 for _ in open(wordlist_path, errors='ignore'))
                    return count, f"~{count} params from {wordlist_path.name}"
                except Exception:
                    pass
    
    # Check methods multiplier
    method_count = 1
    for i, arg in enumerate(args):
        if arg in ["-m", "--methods"] and i + 1 < len(args):
            methods = args[i + 1].split(",")
            method_count = len(methods)
    
    total = base_count * method_count
    return total, f"~{total} params ({method_count} method{'s' if method_count > 1 else ''})"


def calculate_timeout(tool: str, args: list[str], base_timeout: int) -> int:
    """Auto-scale timeout based on scan scope"""
    multiplier = 1.0
    
    if tool == "arjun":
        estimated, _ = estimate_request_count(tool, args)
        if estimated > 10000:
            multiplier = 2.0
        elif estimated > 5000:
            multiplier = 1.5
        
        if _has_flag(args, ["-m", "--methods"]):
            for i, arg in enumerate(args):
                if arg in ["-m", "--methods"] and i + 1 < len(args):
                    if "POST" in args[i + 1].upper():
                        multiplier *= 1.3
    
    elif tool == "x8":
        multiplier = 0.7
    
    elif tool == "paramspider":
        multiplier = 0.5
    
    calculated = int(base_timeout * multiplier)
    return min(max(calculated, 60), 3600)


def extract_domain(target: str) -> str:
    """Extract clean domain from target"""
    clean = re.sub(r"^\w+://", "", target.strip())
    return clean.split('/')[0].split(':')[0]


def find_paramspider_output(domain: str, cwd: Path) -> Optional[Path]:
    """Search multiple locations for ParamSpider output"""
    candidates = [
        Path(cwd) / "results" / f"{domain}.txt",
        Path(cwd).parent / "results" / f"{domain}.txt",
        Path(cwd).parent.parent / "results" / f"{domain}.txt",
        Path.home() / "results" / f"{domain}.txt",
        Path("/tmp") / "results" / f"{domain}.txt",
        Path.cwd() / "results" / f"{domain}.txt",
    ]
    
    for path in candidates:
        if path.exists():
            logger.debug(f"Found ParamSpider output at: {path}")
            return path
    
    # Glob fallback
    for base in [Path(cwd), Path(cwd).parent, Path(cwd).parent.parent, Path.home(), Path.cwd()]:
        results_dir = base / "results"
        if results_dir.exists():
            matches = list(results_dir.glob(f"*{domain}*"))
            if matches:
                logger.debug(f"Found ParamSpider output via glob: {matches[0]}")
                return matches[0]
    
    return None


def cleanup_paramspider_files(domain: str, cwd: Path):
    """Clean up ParamSpider files from all possible locations"""
    search_dirs = [
        Path(cwd),
        Path(cwd).parent,
        Path(cwd).parent.parent,
        Path.home(),
        Path.cwd(),
    ]
    
    for base in search_dirs:
        results_dir = base / "results"
        output_file = results_dir / f"{domain}.txt"
        
        try:
            if output_file.exists():
                output_file.unlink()
                logger.debug(f"Cleaned up: {output_file}")
            
            if results_dir.exists() and not any(results_dir.iterdir()):
                results_dir.rmdir()
        except OSError:
            pass


def safe_execute(
    cmd: list[str],
    timeout: int = 900,
    stdin_data: Optional[str] = None,
    cwd_override: Optional[Path] = None,
) -> tuple[str, str, int, str]:
    """Execute command safely in project directory"""
    cwd = cwd_override or ProjectConfig.get_project_dir()
    
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
        return "", f"Command timed out after {timeout}s", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except PermissionError:
        return "", f"Permission denied executing '{cmd[0]}'", -1, str(cwd)
    except Exception as e:
        return "", f"Execution error: {str(e)}", -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 6. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_arjun_cmd(args: list[str], target: str) -> list[str]:
    """Build arjun command - arjun writes to file, we'll parse stderr"""
    cmd = ["arjun"]
    final_args = list(args)
    
    # Arjun doesn't support /dev/stdout properly, we'll parse stderr
    # Block any output flags
    if _has_flag(final_args, ["-o", "--output", "-oJ", "-oT", "-oB"]):
        raise ValueError("Output file flags are blocked.")
    
    # Ensure URL has protocol
    target_url = target if target.startswith("http") else f"https://{target}"
    
    if not _target_in_args(target_url, final_args, ["-u", "--url"]):
        final_args.extend(["-u", target_url])
    
    # Add quiet flag to reduce noise
    if not _has_flag(final_args, ["-q", "--quiet"]):
        final_args.append("-q")
    
    cmd.extend(final_args)
    return cmd


def _build_x8_cmd(args: list[str], target: str) -> list[str]:
    """Build x8 command with wordlist validation"""
    cmd = ["x8"]
    final_args = list(args)
    
    # Block file output
    if _has_flag(final_args, ["-o", "--output"]):
        for arg in final_args:
            if arg in ["-o", "--output"] or arg.startswith("-o=") or arg.startswith("--output="):
                if "/dev/stdout" not in arg:
                    raise ValueError("Output file flags are blocked. Use stdout only.")
    
    # x8 REQUIRES a wordlist
    if not _has_flag(final_args, ["-w", "--wordlist"]):
        wordlist_found = None
        for wl in DEFAULT_X8_WORDLISTS:
            if wl.exists():
                wordlist_found = str(wl)
                break
        
        if wordlist_found:
            final_args.extend(["-w", wordlist_found])
            logger.debug(f"Using default x8 wordlist: {wordlist_found}")
        else:
            raise ValueError(
                "x8 requires a wordlist (-w). Install SecLists: "
                "sudo apt install seclists OR pip install seclists"
            )
    
    # Force JSON format
    if not _has_flag(final_args, ["-O", "--output-format"]):
        final_args.extend(["-O", "json"])
    
    # Output to stdout
    if not _has_flag(final_args, ["-o", "--output"]):
        final_args.extend(["-o", "/dev/stdout"])
    
    # Ensure URL has protocol
    target_url = target if target.startswith("http") else f"https://{target}"
    
    if not _target_in_args(target_url, final_args, ["-u", "--url"]):
        final_args.extend(["-u", target_url])
    
    cmd.extend(final_args)
    return cmd


def _build_paramspider_cmd(args: list[str], target: str) -> list[str]:
    """Build paramspider command"""
    cmd = ["paramspider"]
    final_args = list(args)
    
    clean_domain = extract_domain(target)
    
    if not _target_in_args(clean_domain, final_args, ["-d", "--domain"]):
        final_args.extend(["-d", clean_domain])
    
    # Add silent flag
    if "-s" not in final_args and "--silent" not in final_args:
        final_args.append("-s")
    
    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 7. PARSERS
# ══════════════════════════════════════════════════════════════

def _extract_json_value(raw: str) -> Optional[Any]:
    """Robustly extract JSON from potentially noisy output"""
    if not raw:
        return None
    
    # Remove ANSI codes
    text = re.sub(r'\x1b\[[0-9;]*m', '', raw).strip()
    
    if not text:
        return None
    
    # Try parsing entire output
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    
    # Find JSON markers
    decoder = json.JSONDecoder()
    
    for match in re.finditer(r'[\{\[]', text):
        idx = match.start()
        
        # Skip log timestamps
        if text[idx] == '[':
            slice_after = text[idx:idx+20]
            if re.match(r'\[\d{4}-\d{2}-\d{2}', slice_after):
                continue
            if re.match(r'\[(INFO|WARN|ERROR|DEBUG)\]', slice_after, re.IGNORECASE):
                continue
        
        try:
            value, _ = decoder.raw_decode(text, idx=idx)
            if isinstance(value, (dict, list)):
                return value
        except (json.JSONDecodeError, ValueError):
            continue
    
    return None


def parse_arjun_text(raw: str, target: str) -> tuple[list[EndpointParams], list[str]]:
    """Parse Arjun's human-readable stderr/stdout output"""
    endpoints = []
    warnings = []
    
    if not raw:
        return endpoints, warnings
    
    # Arjun outputs like:
    # [+] Parameters: id, user, page
    # or
    # [+] id
    # [+] user
    
    found_params = set()
    
    # Pattern 1: "Parameters: x, y, z"
    params_match = re.search(r'\[\+\]\s*Parameters?:\s*(.+)', raw, re.IGNORECASE)
    if params_match:
        params_str = params_match.group(1)
        params = [p.strip() for p in params_str.split(",") if p.strip()]
        found_params.update(params)
    
    # Pattern 2: Individual lines "[+] param_name"
    for match in re.finditer(r'\[\+\]\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*$', raw, re.MULTILINE):
        param = match.group(1)
        if param.lower() not in ["parameters", "parameter"]:
            found_params.add(param)
    
    if found_params:
        endpoints.append(EndpointParams(
            url=target,
            method="GET",
            parameters=sorted(list(found_params)),
            content_type="query",
        ))
    
    return endpoints, warnings


def parse_arjun(raw_json: str, raw_text: str, target: str) -> tuple[list[EndpointParams], list[str]]:
    """Parse Arjun output - try JSON first, fallback to text"""
    endpoints = []
    warnings = []
    
    # Try JSON first
    data = _extract_json_value(raw_json)
    if isinstance(data, dict):
        try:
            for url, methods in data.items():
                if not isinstance(methods, dict):
                    continue
                
                for method, params in methods.items():
                    if not isinstance(params, list):
                        continue
                    
                    content_type = "query"
                    if method.upper() == "POST":
                        content_type = "form"
                    
                    endpoints.append(EndpointParams(
                        url=url,
                        method=method.upper(),
                        parameters=[str(p) for p in params],
                        content_type=content_type,
                    ))
        except Exception as e:
            logger.error(f"Arjun JSON parse error: {e}")
            warnings.append(f"JSON parse error: {e}")
    
    # Fallback to text parsing
    if not endpoints:
        text_endpoints, text_warnings = parse_arjun_text(raw_text, target)
        endpoints.extend(text_endpoints)
        warnings.extend(text_warnings)
        if not endpoints:
            warnings.append("Could not parse arjun output")
    
    return endpoints, warnings


def parse_x8(raw_json: str) -> tuple[list[EndpointParams], list[str]]:
    """Parse x8 JSON output"""
    endpoints = []
    warnings = []
    
    data = _extract_json_value(raw_json)
    if data is None:
        if raw_json.strip():
            logger.warning("x8 output not parseable as JSON")
            warnings.append("Could not parse x8 JSON output")
        return endpoints, warnings

    try:
        if isinstance(data, dict):
            data = [data]
        
        if not isinstance(data, list):
            return endpoints, warnings
        
        for item in data:
            if not isinstance(item, dict):
                continue
            
            url = item.get("url", "")
            params = item.get("params", item.get("parameters", []))
            method = item.get("method", "GET").upper()
            param_type = item.get("type", "query")
            
            content_type_map = {
                "query": "query",
                "body": "form",
                "json": "json",
                "header": "header",
            }
            content_type = content_type_map.get(param_type, "query")
            
            if params and isinstance(params, list):
                endpoints.append(EndpointParams(
                    url=url,
                    method=method,
                    parameters=[str(p) for p in params],
                    content_type=content_type,
                ))
    
    except Exception as e:
        logger.error(f"x8 parse error: {e}")
        warnings.append(f"Parse error: {e}")

    return endpoints, warnings


def parse_paramspider(domain: str, cwd: Path) -> tuple[list[EndpointParams], list[str]]:
    """Parse ParamSpider output from filesystem"""
    endpoints = []
    warnings = []
    
    output_file = find_paramspider_output(domain, cwd)
    
    if output_file is None:
        logger.warning(f"ParamSpider output not found for: {domain}")
        warnings.append(f"Output file not found for domain: {domain}")
        return endpoints, warnings

    try:
        content = output_file.read_text(errors='ignore').strip()
        lines = content.split("\n")
        
        grouped_params: dict[str, set[str]] = {}
        
        for line in lines:
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            
            try:
                parsed = urlparse(line)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                query_params = parse_qs(parsed.query)
                
                if base_url not in grouped_params:
                    grouped_params[base_url] = set()
                
                for param in query_params.keys():
                    grouped_params[base_url].add(param)
            
            except Exception:
                continue
        
        for url, params in grouped_params.items():
            if params:
                endpoints.append(EndpointParams(
                    url=url,
                    method="GET",
                    parameters=sorted(list(params)),
                    content_type="query",
                ))
        
        logger.info(f"Parsed {len(endpoints)} endpoints from ParamSpider")
    
    except Exception as e:
        logger.error(f"ParamSpider parse error: {e}")
        warnings.append(f"Parse error: {e}")
    
    return endpoints, warnings


# ══════════════════════════════════════════════════════════════
# 8. CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_param_discovery(
    tool: str,
    target: str,
    args_tuple: tuple,
    timeout: int
) -> str:
    """Cached internal implementation. Returns JSON string."""
    args = list(args_tuple)
    result = _param_discovery_impl(tool, target, args, timeout)
    return json.dumps(result)


def clear_cache():
    """Clear the result cache"""
    _cached_param_discovery.cache_clear()


def get_cache_info():
    """Get cache statistics"""
    return _cached_param_discovery.cache_info()


# ══════════════════════════════════════════════════════════════
# 9. CORE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _param_discovery_impl(
    tool: str,
    target: str,
    args: list[str],
    timeout: int
) -> dict:
    """Core implementation without caching"""
    start = time.time()
    warnings = []
    
    # Rate limit
    PARAM_RATE_LIMITER.acquire()
    
    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = ParamDiscoveryRequest(tool=tool, target=target, args=args, timeout=timeout)
    except Exception as e:
        return ParamDiscoveryResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation error: {str(e)}"
        ).model_dump()
    
    # ══════════════════════════════
    # CHECK TOOL INSTALLED
    # ══════════════════════════════
    installed, install_msg = check_tool_installed(tool)
    if not installed:
        return ParamDiscoveryResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=install_msg,
            execution_time=round(time.time() - start, 2),
        ).model_dump()
    
    # ══════════════════════════════
    # ESTIMATE REQUESTS
    # ══════════════════════════════
    estimated_requests, estimate_msg = estimate_request_count(tool, args)
    
    if estimated_requests > MAX_REQUESTS_WARNING:
        warnings.append(f"Large scan: {estimate_msg} - this may take a long time")
        logger.info(f"Large param discovery: {estimate_msg}")
    
    # ══════════════════════════════
    # CALCULATE TIMEOUT
    # ══════════════════════════════
    actual_timeout = calculate_timeout(tool, args, req.timeout)
    if actual_timeout != req.timeout:
        logger.debug(f"Timeout adjusted: {req.timeout}s → {actual_timeout}s")
    
    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    clean_domain = extract_domain(target)
    
    try:
        if tool == "arjun":
            cmd = _build_arjun_cmd(args, target)
        elif tool == "x8":
            cmd = _build_x8_cmd(args, target)
        elif tool == "paramspider":
            cmd = _build_paramspider_cmd(args, target)
        else:
            raise ValueError(f"Unknown tool: {tool}")
    except Exception as e:
        return ParamDiscoveryResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Command build error: {str(e)}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()
    
    command_str = " ".join(cmd)
    logger.info(f"Executing: {command_str}")
    
    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    tmp_paramspider_dir: Optional[Path] = None
    if tool == "paramspider":
        tmp_paramspider_dir = ProjectConfig.get_temp_dir() / f"paramspider_{int(time.time())}"
        tmp_paramspider_dir.mkdir(parents=True, exist_ok=True)

    stdout, stderr, rc, cwd = safe_execute(
        cmd,
        actual_timeout,
        cwd_override=tmp_paramspider_dir,
    )
    
    execution_time_so_far = round(time.time() - start, 2)
    
    # Surface tool failures immediately
    if rc == -1 and execution_time_so_far < 1.0:
        return ParamDiscoveryResult(
            success=False,
            tool=tool,
            target=target,
            command=command_str,
            working_dir=cwd,
            error=stderr or f"Tool '{tool}' failed to start",
            execution_time=execution_time_so_far,
        ).model_dump()
    
    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    endpoints = []
    parse_warnings = []
    
    try:
        if tool == "arjun":
            # Arjun outputs to stderr mostly
            endpoints, parse_warnings = parse_arjun(stdout, stderr, target)
        elif tool == "x8":
            endpoints, parse_warnings = parse_x8(stdout)
        elif tool == "paramspider":
            endpoints, parse_warnings = parse_paramspider(clean_domain, Path(cwd))
            cleanup_paramspider_files(clean_domain, Path(cwd))
            if tmp_paramspider_dir is not None:
                try:
                    tmp_paramspider_dir.rmdir()
                except OSError:
                    pass
    except Exception as e:
        logger.error(f"Parse error: {e}")
        parse_warnings.append(f"Parse error: {e}")
    
    warnings.extend(parse_warnings)
    
    # ══════════════════════════════
    # COMPUTE STATISTICS
    # ══════════════════════════════
    total_params = sum(len(ep.parameters) for ep in endpoints)
    
    all_params = set()
    for ep in endpoints:
        all_params.update(ep.parameters)
    unique_params = sorted(list(all_params))
    
    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    success = rc == 0 or total_params > 0
    
    error_msg = None
    if rc != 0 and total_params == 0:
        error_msg = stderr[:1000] if stderr else f"Command returned exit code {rc}"
    
    raw_output = (stdout or stderr)[:8000]
    
    return ParamDiscoveryResult(
        success=success,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        total_parameters_found=total_params,
        unique_parameters=unique_params,
        endpoints=[ep.model_dump() for ep in endpoints],
        estimated_requests=estimated_requests,
        raw_output=raw_output if not success else "",
        error=error_msg,
        warnings=warnings,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 10. PUBLIC API
# ══════════════════════════════════════════════════════════════

def param_discovery(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    timeout: int = 900,
    use_cache: bool = True,
) -> dict:
    """
    🔧 Agent Tool: Parameter Discovery

    Discover hidden GET/POST/JSON parameters on web endpoints using
    brute-force testing or historical archive mining.

    ┌─────────────────────────────────────────────────────────────────────┐
    │  CAPABILITIES                                                       │
    ├─────────────────────────────────────────────────────────────────────┤
    │  • Brute-Force Discovery   Test wordlist of common params          │
    │  • Archive Mining          Extract params from Wayback Machine     │
    │  • Multi-Method Support    GET, POST, JSON body, headers          │
    │  • Content-Type Detection  Query vs form vs JSON                   │
    │  • Rate Limiting           1 scan per 5 seconds                    │
    │  • Result Caching          LRU cache (128 entries)                 │
    │  • Wordlist Validation     Path traversal protection               │
    │  • Tool Install Check      Automatic verification                  │
    └─────────────────────────────────────────────────────────────────────┘

    TOOL ROLES:
    
    Arjun — The Intelligent Brute-Forcer
        • Analyzes response changes to detect working params
        • Tests GET, POST, JSON body, headers
        • Low false positives (~5%)
        • Best for: Deep analysis of critical endpoints
        • Speed: Slow (minutes per endpoint)
    
    x8 — The Speed Demon  
        • Ultra-fast Rust-based fuzzing
        • Detects params via reflection/errors
        • Can scan hundreds of endpoints quickly
        • Best for: Initial recon, broad coverage
        • Speed: Ultra-fast (seconds per endpoint)
    
    ParamSpider — The Archaeologist
        • Mines Wayback Machine archives
        • Finds historical/forgotten params
        • Zero requests to target (stealth)
        • Best for: Discovering removed features
        • Speed: Fast (no target requests)

    Args:
        tool: "arjun" | "x8" | "paramspider"
        target: URL or domain
        args: Tool-specific arguments
        timeout: Base timeout (auto-scales)
        use_cache: Enable LRU caching

    Returns:
        dict: Structured discovery results
    """
    args = args or []
    
    if use_cache:
        cached_json = _cached_param_discovery(tool, target, tuple(args), timeout)
        return json.loads(cached_json)
    else:
        return _param_discovery_impl(tool, target, args, timeout)


# ══════════════════════════════════════════════════════════════
# 11. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

PARAM_DISCOVERY_TOOL_DEFINITION = {
    "name": "param_discovery",
    "description": (
        "Discover hidden GET/POST/JSON parameters. Arjun (intelligent brute-force), "
        "x8 (ultra-fast fuzzing), ParamSpider (Wayback archive mining). "
        "Returns structured data with params grouped by endpoint/method. "
        "Includes rate limiting, caching, install verification."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["arjun", "x8", "paramspider"],
                "description": (
                    "arjun = smart response analysis, deep scan\n"
                    "x8 = ultra-fast Rust fuzzer, broad coverage\n"
                    "paramspider = historical archive mining, zero target requests"
                ),
            },
            "target": {
                "type": "string",
                "description": "URL (arjun/x8: https://example.com/api) or domain (paramspider: example.com)",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "ARJUN: ['-m', 'GET,POST'], ['-t', '10'], ['--stable']\n"
                    "X8: ['-m', 'POST'], ['-t', '20'], ['-p', 'body']\n"
                    "PARAMSPIDER: ['--subs'], ['--exclude', 'css,js']"
                ),
            },
            "timeout": {"type": "integer", "description": "Timeout (auto-scales)"},
            "use_cache": {"type": "boolean", "description": "Enable caching"},
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 12. UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def get_rate_limiter_stats() -> dict:
    return {
        "calls_per_second": PARAM_RATE_LIMITER.calls_per_second,
        "min_interval": PARAM_RATE_LIMITER.min_interval,
    }


def set_rate_limit(calls_per_second: float):
    global PARAM_RATE_LIMITER
    PARAM_RATE_LIMITER = RateLimiter(calls_per_second=calls_per_second)


def get_allowed_wordlist_dirs() -> list[str]:
    return [str(d) for d in ALLOWED_WORDLIST_DIRS if d.exists()]


def get_security_settings() -> dict:
    return {
        "blocked_targets": BLOCKED_TARGETS,
        "allowed_wordlist_dirs": get_allowed_wordlist_dirs(),
        "dangerous_chars": DANGEROUS_CHARS,
        "max_requests_warning": MAX_REQUESTS_WARNING,
    }


# ══════════════════════════════════════════════════════════════
# 13. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("PARAMETER DISCOVERY — v3.0 (PRODUCTION)")
    print("Multi-Tool | Cached | Secure | Install-Validated")
    print("=" * 70)

    # Better test target (has actual parameters)
    TEST_TARGET = "http://scanme.nmap.org"
    
    print("\n" + "─" * 50)
    print("TEST 1: Arjun (Intelligent Brute-Force)")
    print("─" * 50)
    
    r1 = param_discovery(
        tool="arjun",
        target=TEST_TARGET,
        args=["-m", "GET"],
        use_cache=False,
    )
    
    print(f"Command:    {r1['command']}")
    print(f"Success:    {r1['success']}")
    print(f"Total:      {r1['total_parameters_found']} parameters")
    print(f"Unique:     {len(r1['unique_parameters'])} params")
    print(f"Exec Time:  {r1['execution_time']}s")
    
    if r1['unique_parameters']:
        print(f"Parameters: {', '.join(r1['unique_parameters'])}")
    
    if r1['warnings']:
        print(f"Warnings:   {r1['warnings']}")
    
    if r1['error']:
        print(f"Error:      {r1['error']}")

    print("\n" + "─" * 50)
    print("TEST 2: Security Validation")
    print("─" * 50)
    
    # Test blocked localhost
    """r = param_discovery("arjun", "https://127.0.0.1/api", [])
    print(f"Localhost blocked:    {'✅' if not r['success'] else '❌'}")
    if r.get('error'):
        print(f"  Reason: {r['error'][:60]}")"""
    
    # Test shell injection
    r = param_discovery("arjun", TEST_TARGET, ["--test; rm -rf /"])
    print(f"Shell injection blocked: {'✅' if not r['success'] else '❌'}")
    if r.get('error'):
        print(f"  Reason: {r['error'][:60]}")
    """
    # Test AWS metadata
    r = param_discovery("arjun", "http://169.254.169.254/latest/", [])
    print(f"AWS metadata blocked:   {'✅' if not r['success'] else '❌'}")
    if r.get('error'):
        print(f"  Reason: {r['error'][:60]}")"""

    print("\n" + "─" * 50)
    print("TEST 3: Cache Performance")
    print("─" * 50)
    
    start = time.time()
    r_first = param_discovery("arjun", TEST_TARGET, ["-m", "GET"], use_cache=True)
    first_time = time.time() - start
    
    start = time.time()
    r_cached = param_discovery("arjun", TEST_TARGET, ["-m", "GET"], use_cache=True)
    cache_time = time.time() - start
    
    print(f"First run:  {first_time:.2f}s")
    print(f"Cached:     {cache_time:.4f}s")
    if cache_time > 0:
        print(f"Speedup:    {first_time / cache_time:.0f}x")
    
    info = get_cache_info()
    print(f"Cache:      hits={info.hits}, misses={info.misses}, size={info.currsize}/128")

    print("\n" + "─" * 50)
    print("TEST 4: Tool Install Verification")
    print("─" * 50)
    
    for tool_name in ["arjun", "x8", "paramspider"]:
        installed, msg = check_tool_installed(tool_name)
        status = "✅ Installed" if installed else f"❌ {msg}"
        print(f"{tool_name:12} {status}")

    print("\n" + "=" * 70)
    print("All tests completed!")
    print("=" * 70)
