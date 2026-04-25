#/+
import subprocess
import json
import re
import os
import time
import uuid
from pathlib import Path
from typing import Optional, Any
from functools import lru_cache
from pydantic import BaseModel, Field, field_validator, model_validator
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
from server.agents.executer.recon.config import is_blocked_host

# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION & UTILITIES
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


# Tool-specific timeout defaults (in seconds)
DEFAULT_TIMEOUTS = {
    "whatweb": 120,
    "wappalyzer": 60
}


def _target_in_args(target: str, args: list[str]) -> bool:
    """Check if target already exists in args"""
    if not args:
        return False
    target_clean = target.strip().lower()
    target_stripped = re.sub(r"^\w+://", "", target_clean)
    target_stripped = re.sub(r"/.*$", "", target_stripped)

    target_flags = {"-u", "--url", "-target", "--target"}

    for i, arg in enumerate(args):
        arg_lower = arg.strip().lower()
        arg_stripped = re.sub(r"^\w+://", "", arg_lower)
        arg_stripped = re.sub(r"/.*$", "", arg_stripped)

        if arg_lower == target_clean or arg_stripped == target_stripped:
            return True
        if target_stripped in arg_lower:
            return True
        if arg_lower in target_flags and i + 1 < len(args):
            next_arg = args[i + 1].strip().lower()
            next_stripped = re.sub(r"^\w+://", "", next_arg)
            next_stripped = re.sub(r"/.*$", "", next_stripped)
            if next_stripped == target_stripped:
                return True
    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    return any(arg in args for arg in flags)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_fixed(2),
    retry=retry_if_exception_type((TimeoutError, ConnectionError))
)
def safe_execute(cmd: list[str], timeout: int = 300) -> tuple[str, str, int, str]:
    """Run command safely in project directory with retry logic"""
    cwd = ProjectConfig.get_project_dir()
    if not cwd.is_dir():
        cwd.mkdir(parents=True, exist_ok=True)
    
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=False, cwd=str(cwd)
        )
        return result.stdout, result.stderr, result.returncode, str(cwd)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Command timed out after {timeout}s")
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


def normalize_version(version: str) -> str:
    """Normalize version strings: 5.7.2-ubuntu → 5.7.2"""
    if not version:
        return version
    # Remove distribution/platform suffixes
    normalized = re.sub(r'[-_][a-z]+.*$', '', str(version), flags=re.IGNORECASE)
    # Remove leading/trailing whitespace and non-version chars
    normalized = re.sub(r'[^\d\.]', '', normalized.strip())
    return normalized if normalized else version


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from tool output."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def _is_transient_wappalyzer_error(text: str) -> bool:
    """Heuristics for transient network/DNS failures in wappalyzer output."""
    clean = _strip_ansi(text).lower()
    patterns = [
        "temporary failure in name resolution",
        "name resolution error",
        "failed to resolve",
        "max retries exceeded",
        "httpconnectionpool",
        "connection reset",
        "connection refused",
        "timed out",
        "read timed out",
    ]
    return any(pattern in clean for pattern in patterns)


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class DetectTechRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = Field(default_factory=list)
    scan_type: Optional[str] = None
    timeout: Optional[int] = None

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        allowed = {"whatweb", "wappalyzer"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        clean_v = re.sub(r"^\w+://", "", v.strip()).split('/')[0]
        if is_blocked_host(clean_v):
            raise ValueError(f"Target '{v}' is blocked")
        return v.strip()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"', ">"]
        for arg in v:
            for char in dangerous:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in arg: {arg}")
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = str(v).strip()
        if not value:
            return None
        for char in [";", "&&", "||", "|", "`", "$(", ">>", "'", '"', ">"]:
            if char in value:
                raise ValueError(f"Dangerous character '{char}' in scan_type")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("scan_type contains invalid characters")
        return value

    @model_validator(mode="after")
    def set_timeout(self) -> "DetectTechRequest":
        """Set tool-specific default timeout if not provided."""
        if self.scan_type and self.tool != "wappalyzer":
            raise ValueError("scan_type is only supported when tool='wappalyzer'")
        if self.timeout is not None:
            if self.timeout < 10 or self.timeout > 1200:
                raise ValueError("Timeout must be between 10 and 1200 seconds")
            return self
        self.timeout = DEFAULT_TIMEOUTS.get(self.tool, 120)
        return self


class Technology(BaseModel):
    name: str
    version: Optional[str] = None
    version_normalized: Optional[str] = None
    category: Optional[str] = None
    confidence: Optional[int] = Field(ge=0, le=100, default=None)

    @model_validator(mode="after")
    def normalize_version_field(self) -> "Technology":
        """Auto-normalize version on creation."""
        if self.version and not self.version_normalized:
            self.version_normalized = normalize_version(self.version)
        return self


class DetectTechResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str = ""
    http_status: Optional[int] = None
    technologies: list[Technology] = Field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_whatweb_cmd(args: list[str], target: str) -> list[str]:
    """Build whatweb command with JSON output to stdout"""
    cmd = ["whatweb"]
    # '--no-errors' hides important runtime failures; strip it for reliable reporting.
    final_args = [a for a in list(args) if a != "--no-errors"]

    # Force JSON output to stdout
    if not _has_flag(final_args, ["--log-json"]):
        final_args.extend(["--log-json", "/dev/stdout"])

    if not _target_in_args(target, final_args):
        final_args.append(target)

    cmd.extend(final_args)
    return cmd


def _build_wappalyzer_cmd(
    args: list[str],
    target: str,
    scan_type: Optional[str] = None,
) -> list[str]:
    """Build wappalyzer CLI command"""
    cmd = ["wappalyzer"]
    final_args = list(args)

    # Wappalyzer requires protocol
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"https://{target}"

    # If caller didn't provide --scan-type, inject requested scan_type.
    has_scan_type = _has_flag(final_args, ["--scan-type"]) or any(
        str(a).startswith("--scan-type=") for a in final_args
    )
    if scan_type and not has_scan_type:
        final_args.extend(["--scan-type", scan_type])

    # Prefer explicit input form used by this CLI: -i <target>
    has_input_flag = _has_flag(final_args, ["-i", "--input"])
    if not has_input_flag and not _target_in_args(target, final_args):
        final_args.extend(["-i", target])

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_whatweb(stdout: str) -> tuple[list[Technology], Optional[int]]:
    """Parse WhatWeb JSON output from stdout"""
    technologies = []
    status_code = None
    
    if not stdout.strip():
        return [], None
        
    try:
        data = _extract_json_payload(stdout)
        if data is None:
            return [], None
        
        # WhatWeb output may be:
        # - list[dict] (normal JSON mode)
        # - dict (when we salvage the first object from mixed JSON+ANSI stdout)
        if isinstance(data, list) and len(data) > 0:
            result = data[-1]
        elif isinstance(data, dict):
            result = data
        else:
            return [], None

        status_code = result.get("http_status")
        plugins = result.get("plugins", {})

        if isinstance(plugins, dict):
            for plugin_name, plugin_data in plugins.items():
                # Skip internal/generic WhatWeb plugins
                if plugin_name in ["Country", "IP", "Title"]:
                    continue
                if not isinstance(plugin_data, dict):
                    plugin_data = {}
                
                if plugin_name == "HTTPServer" and "string" in plugin_data:
                    # Extract web server as a tech
                    for s in plugin_data.get("string", []):
                        # Parse server strings like "nginx/1.18.0"
                        parts = str(s).split("/")
                        name = parts[0].strip()
                        version = parts[1].strip() if len(parts) > 1 else None
                        if name:
                            technologies.append(Technology(
                                name=name,
                                version=version,
                                category="Web Server",
                                confidence=100
                            ))
                    continue
                
                version = None
                confidence = plugin_data.get("certainty", 100)
                
                if "version" in plugin_data and isinstance(plugin_data["version"], list) and plugin_data["version"]:
                    version = str(plugin_data["version"][0])
                elif "string" in plugin_data and isinstance(plugin_data["string"], list) and plugin_data["string"]:
                    version = str(plugin_data["string"][0])

                technologies.append(Technology(
                    name=plugin_name,
                    version=version,
                    confidence=confidence
                ))
    except Exception:
        pass
            
    return technologies, status_code


def parse_wappalyzer(stdout: str) -> tuple[list[Technology], Optional[int]]:
    """Parse Wappalyzer CLI output (JSON first, plaintext fallback)."""
    technologies = []
    status_code = None
    clean_stdout = _strip_ansi(stdout)
    
    try:
        data = _extract_json_payload(clean_stdout)
        if isinstance(data, dict):
            # Get status code from urls object (last one = final destination)
            urls = data.get("urls", {})
            status_codes = []
            for _, url_data in urls.items():
                if isinstance(url_data, dict) and "status" in url_data:
                    status_codes.append(url_data["status"])
            if status_codes:
                status_code = status_codes[-1]
                    
            # Parse technologies array
            techs = data.get("technologies", [])
            for tech in techs:
                if not isinstance(tech, dict):
                    continue
                name = tech.get("name")
                
                # Versions can be an array
                versions = tech.get("versions", [])
                version = versions[0] if versions else None
                
                # Categories
                categories = tech.get("categories", [])
                category = categories[0].get("name") if categories and isinstance(categories[0], dict) else None
                
                # Confidence
                confidence = tech.get("confidence", 75)
                
                if name:
                    technologies.append(Technology(
                        name=name,
                        version=version,
                        category=category,
                        confidence=confidence
                    ))
            return technologies, status_code
        
        # Plaintext fallback, e.g.:
        # "http://target.tld Google Analytics, Apache HTTP Server v2.4.7, Ubuntu"
        for raw_line in (clean_stdout or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.lower() == "wappalyzer":
                continue
            url_and_tech = re.search(r"(https?://\S+)\s+(.+)$", line)
            if not url_and_tech:
                continue
            tech_chunk = url_and_tech.group(2).strip()
            if not tech_chunk:
                continue

            for item in [p.strip() for p in tech_chunk.split(",") if p.strip()]:
                match = re.match(r"^(.*?)(?:\s+v([0-9][\w.\-]*))?$", item)
                if match:
                    name = match.group(1).strip()
                    version = match.group(2).strip() if match.group(2) else None
                else:
                    name = item
                    version = None
                if name:
                    technologies.append(Technology(
                        name=name,
                        version=version,
                        confidence=75,
                    ))
    except Exception:
        pass
        
    return technologies, status_code


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION WITH CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_detect_tech(
    tool: str,
    target: str,
    args_tuple: tuple,
    scan_type: Optional[str],
    timeout: int,
) -> dict:
    """Internal cached version - args must be hashable (tuple)"""
    args = list(args_tuple)
    return _detect_tech_impl(tool, target, args, scan_type, timeout)


def _extract_json_payload(text: str) -> Optional[Any]:
    raw = (text or "").strip()
    if not raw:
        return None
    # Direct parse first
    try:
        return json.loads(raw)
    except Exception:
        pass

    decoder = json.JSONDecoder()
    starts: list[int] = []
    for marker in ("[", "{"):
        idx = raw.find(marker)
        if idx != -1:
            starts.append(idx)
    for idx in sorted(starts):
        try:
            payload, _ = decoder.raw_decode(raw[idx:])
            return payload
        except Exception:
            continue
    return None


def _detect_tech_impl(
    tool: str,
    target: str,
    args: list[str],
    scan_type: Optional[str],
    timeout: int,
) -> dict:
    """Core implementation without caching"""
    start = time.time()
    
    # ── VALIDATE ──
    try:
        req = DetectTechRequest(
            tool=tool,
            target=target,
            args=args,
            scan_type=scan_type,
            timeout=timeout,
        )
    except Exception as e:
        return DetectTechResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation error: {e}"
        ).model_dump()

    # ── BUILD COMMAND ──
    try:
        if tool == "whatweb":
            cmd = _build_whatweb_cmd(args, target)
        elif tool == "wappalyzer":
            cmd = _build_wappalyzer_cmd(args, target, req.scan_type)
    except Exception as e:
        return DetectTechResult(
            success=False, tool=tool, target=target,
            command="", error=f"Command build error: {e}"
        ).model_dump()

    # ── EXECUTE ──
    command_str = " ".join(cmd)
    max_attempts = 3 if tool == "wappalyzer" else 1
    stdout = ""
    stderr = ""
    rc = -1
    working_dir = ""
    combined_output = ""

    for attempt in range(1, max_attempts + 1):
        try:
            stdout, stderr, rc, working_dir = safe_execute(cmd, req.timeout)
        except TimeoutError as e:
            if attempt == max_attempts:
                return DetectTechResult(
                    success=False,
                    tool=tool,
                    target=target,
                    command=command_str,
                    error=str(e),
                ).model_dump()
            continue

        # Some tools/versions print primary findings to stderr; keep a merged view.
        combined_output = stdout
        if stderr:
            combined_output = f"{stdout}\n{stderr}" if stdout else stderr

        # Non-wappalyzer tools keep single execution behavior.
        if tool != "wappalyzer":
            break

        # If wappalyzer already produced technologies, stop retrying.
        preview_tech, _ = parse_wappalyzer(combined_output)
        if preview_tech:
            break

        # Retry only on transient failures.
        if not _is_transient_wappalyzer_error(combined_output):
            break

        if attempt < max_attempts:
            time.sleep(1.0)

    # ── PARSE ──
    technologies = []
    status_code = None

    if tool == "whatweb":
        technologies, status_code = parse_whatweb(stdout)
    elif tool == "wappalyzer":
        technologies, status_code = parse_wappalyzer(combined_output)

    # Deduplicate by name (case-insensitive) - keep highest confidence
    seen = {}
    for t in technologies:
        name_lower = t.name.lower()
        if name_lower not in seen:
            seen[name_lower] = t
        else:
            # Keep version with higher confidence
            existing = seen[name_lower]
            if (t.confidence or 0) > (existing.confidence or 0):
                seen[name_lower] = t
            # If same confidence but one has version, prefer that
            elif (t.confidence or 0) == (existing.confidence or 0) and t.version and not existing.version:
                seen[name_lower] = t

    unique_tech = list(seen.values())

    # ── RETURN ──
    has_data = len(unique_tech) > 0 or status_code is not None
    error_text = stderr if (stderr and not has_data) else None
    if (
        tool == "whatweb"
        and not has_data
        and not error_text
        and (stdout or "").strip() in {"[]", "[\n]"}
    ):
        error_text = "WhatWeb returned empty JSON with no findings."
    if tool == "wappalyzer" and not has_data and not error_text:
        clean_stdout = _strip_ansi(combined_output).strip()
        if _is_transient_wappalyzer_error(clean_stdout) or re.search(
            r"(error|exception|failed)",
            clean_stdout,
            flags=re.IGNORECASE,
        ):
            error_text = clean_stdout[:500]

    raw_output_source = combined_output if tool == "wappalyzer" else stdout

    return DetectTechResult(
        success=has_data,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=working_dir,
        http_status=status_code,
        technologies=unique_tech,
        raw_output=raw_output_source[:2000] if raw_output_source else "",  # Limit size
        error=error_text,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


def detect_tech(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    scan_type: Optional[str] = None,
    use_cache: bool = True,
) -> dict:
    """
    🔧 Agent Tool: Detect Technologies

    Fingerprint the target to discover web server, frameworks, programming
    languages, CMS, and JavaScript libraries with version detection.

    Args:
        tool:       "whatweb" | "wappalyzer"
        target:     URL or Domain (e.g. "https://example.com")
        args:       Raw tool arguments (default: [])
        scan_type:  Wappalyzer scan profile (e.g. "balanced", "fast")
        use_cache:  Enable result caching (default: True)

    Returns:
        Structured JSON with detected technologies, versions, confidence scores,
        and normalized version strings.

    Features:
        - Auto-retry on network failures (3 attempts)
        - Tool-specific timeouts (whatweb: 120s, wappalyzer: 60s)
        - Version normalization (5.7.2-ubuntu → 5.7.2)
        - Confidence scoring (0-100)
        - Intelligent deduplication
        - LRU caching for repeated scans
    """
    # Get timeout from request or use default
    args = list(args or [])
    try:
        req_timeout = DetectTechRequest(
            tool=tool,
            target=target,
            args=args,
            scan_type=scan_type,
        ).timeout
    except Exception as e:
        return DetectTechResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation error: {e}",
        ).model_dump()
    
    if use_cache:
        cached_result = _cached_detect_tech(tool, target, tuple(args), scan_type, req_timeout)
        if cached_result.get("success"):
            return cached_result

        # Prevent transient DNS/network failures from poisoning cache for wappalyzer.
        if tool == "wappalyzer":
            error_blob = (
                f"{cached_result.get('error', '')}\n{cached_result.get('raw_output', '')}"
            )
            if _is_transient_wappalyzer_error(error_blob):
                return _detect_tech_impl(tool, target, args, scan_type, req_timeout)
        return cached_result
    else:
        return _detect_tech_impl(tool, target, args, scan_type, req_timeout)


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

DETECT_TECH_TOOL_DEFINITION = {
    "name": "detect_tech",
    "description": (
        "Fingerprint web technologies, servers, CMS, frameworks, and libraries. "
        "Returns structured data with versions, confidence scores, and categories. "
        "Supports whatweb (deep Ruby scanner with redirect handling) and "
        "wappalyzer (official NodeJS CLI). Includes auto-retry, caching, and version normalization."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["whatweb", "wappalyzer"],
                "description": (
                    "whatweb = deep signatures (120s timeout), handles redirects, comprehensive | "
                    "wappalyzer = official CLI (60s timeout), category detection"
                )
            },
            "target": {
                "type": "string",
                "description": "Target URL or domain (e.g. 'https://example.com' or 'example.com'). Single target only."
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Optional tool arguments. Examples:\n"
                    "whatweb: ['-a', '3'] = aggressive mode, ['--no-errors'] = suppress errors\n"
                    "wappalyzer: ['--delay', '1000'] = rate limit"
                )
            },
            "scan_type": {
                "type": "string",
                "description": (
                    "Only for tool='wappalyzer'. Scan profile to pass as --scan-type "
                    "(e.g. 'balanced', 'fast')."
                )
            },
            "use_cache": {
                "type": "boolean",
                "description": "Enable LRU caching to avoid duplicate scans (default: true)"
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("=" * 60)
    print("TECHNOLOGY DETECTION — v2.0 WITH CACHING & CONFIDENCE")
    print("=" * 60)

    # 1. WhatWeb (Deep Scan - 120s timeout)
    print("\n=== WHATWEB (Deep Scan) ===")
    r_whatweb = detect_tech(
        tool="whatweb",
        target="http://scanme.nmap.org",
        args=["-a", "1"]
    )
    print(f"Command:   {r_whatweb['command']}")
    print(f"Status:    {r_whatweb['http_status']}")
    print(f"Exec Time: {r_whatweb['execution_time']}s")
    for t in r_whatweb['technologies']:
        ver = f" v{t['version']}" if t['version'] else ""
        norm = f" (norm: {t['version_normalized']})" if t['version_normalized'] and t['version_normalized'] != t['version'] else ""
        cat = f" [{t['category']}]" if t['category'] else ""
        conf = f" {t['confidence']}%" if t['confidence'] else ""
        print(f" - {t['name']}{ver}{norm}{cat} {conf}")

    # 2. Wappalyzer (Category-focused detection)
    print("\n=== WAPPALYZER (Category Mode) ===")
    r_wappalyzer = detect_tech(
        tool="wappalyzer",
        target="http://scanme.nmap.org",
        args=[],
        scan_type="balanced",
    )
    print(f"Command:   {r_wappalyzer['command']}")
    print(f"Status:    {r_wappalyzer['http_status']}")
    print(f"Exec Time: {r_wappalyzer['execution_time']}s")
    if r_wappalyzer.get("error"):
        print(f"Error:     {r_wappalyzer['error']}")
    for t in r_wappalyzer['technologies']:
        ver = f" v{t['version']}" if t['version'] else ""
        norm = f" (norm: {t['version_normalized']})" if t['version_normalized'] and t['version_normalized'] != t['version'] else ""
        cat = f" [{t['category']}]" if t['category'] else ""
        conf = f" {t['confidence']}%" if t['confidence'] else ""
        print(f" - {t['name']}{ver}{norm}{cat} {conf}")

    # 3. Cache Test (WhatWeb)
    print("\n=== CACHE TEST (WHATWEB) ===")
    start_whatweb = time.time()
    r_whatweb_cached = detect_tech(
        tool="whatweb",
        target="http://scanme.nmap.org",
        args=["-a", "1"],
        use_cache=True
    )
    cache_time_whatweb = time.time() - start_whatweb
    print(f"Cache hit time: {cache_time_whatweb:.4f}s (vs original {r_whatweb['execution_time']}s)")
    print(f"Technologies: {len(r_whatweb_cached['technologies'])}")

    # 4. Cache Test (Wappalyzer)
    print("\n=== CACHE TEST (WAPPALYZER) ===")
    start_wappalyzer = time.time()
    r_wappalyzer_cached = detect_tech(
        tool="wappalyzer",
        target="http://scanme.nmap.org",
        args=[],
        scan_type="balanced",
        use_cache=True
    )
    cache_time_wappalyzer = time.time() - start_wappalyzer
    print(f"Cache hit time: {cache_time_wappalyzer:.4f}s (vs original {r_wappalyzer['execution_time']}s)")
    print(f"Technologies: {len(r_wappalyzer_cached['technologies'])}")

    # 5. Full JSON Output
    print("\n=== FULL JSON PAYLOAD (WHATWEB) ===")
    print(json.dumps(r_whatweb, indent=2))

    # 6. Cache stats
    print("\n=== CACHE STATISTICS ===")
    cache_info = _cached_detect_tech.cache_info()
    print(f"Hits: {cache_info.hits}, Misses: {cache_info.misses}, Size: {cache_info.currsize}/{cache_info.maxsize}")
