#/+
import subprocess
import json
import re
import os
import time
import shutil
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from functools import lru_cache
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION & UTILITIES
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools"""
    _project_dir: Optional[Path] = None
    
    @classmethod
    def get_project_dir(cls) -> Path:
        if cls._project_dir:
            return cls._project_dir

        env_dir = os.environ.get("AGENT_PROJECT_DIR")
        if env_dir and os.path.isdir(env_dir):
            cls._project_dir = Path(env_dir)
            return cls._project_dir

        current = Path(__file__).resolve().parent
        for parent in [current] + list(current.parents):
            if any((parent / marker).exists() for marker in ["pyproject.toml", "setup.py", ".git", "requirements.txt"]):
                cls._project_dir = parent
                return cls._project_dir

        cls._project_dir = Path.cwd()
        return cls._project_dir


def _normalize_target_url(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        raise ValueError("Target must start with http:// or https://")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Target must use http or https")
    if not parsed.hostname:
        raise ValueError("Invalid target URL")
    return value


def _target_in_args(target: str, args: list[str], flags: list[str]) -> bool:
    if not args:
        return False
    t_clean = target.strip().lower()
    for i, arg in enumerate(args):
        a_clean = arg.strip().lower()
        if a_clean == t_clean:
            return True
        if a_clean in flags and i + 1 < len(args):
            if args[i + 1].strip().lower() == t_clean:
                return True
    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    for arg in args:
        for flag in flags:
            if arg == flag or arg.startswith(flag + "="):
                return True
    return False


def check_tool_installed(tool: str) -> tuple[bool, str]:
    binary_map = {
        "cmseek": "cmseek",
        "wpscan": "wpscan",
        "joomscan": "joomscan",
        "droopescan": "droopescan",
    }
    binary = binary_map.get(tool)
    if not binary:
        return False, f"Unknown tool: {tool}"

    if shutil.which(binary) is None:
        install_hints = {
            "cmseek": "git clone https://github.com/Tuhinshubhra/CMSeeK && install requirements",
            "wpscan": "gem install wpscan",
            "joomscan": "git clone https://github.com/OWASP/joomscan.git",
            "droopescan": "pip install droopescan",
        }
        return False, f"Tool '{tool}' not installed. Install with: {install_hints.get(tool, 'unknown')}"
    return True, ""


def safe_execute(cmd: list[str], timeout: int = 900) -> tuple[str, str, int, str]:
    cwd = ProjectConfig.get_project_dir()
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=str(cwd)
        )
        return res.stdout, res.stderr, res.returncode, str(cwd)
    except subprocess.TimeoutExpired:
        return "", f"Timeout ({timeout}s)", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 2. RATE LIMITER
# ══════════════════════════════════════════════════════════════

class RateLimiter:
    """Simple scan limiter for noisy CMS scanners"""

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


CMS_SCAN_RATE_LIMITER = RateLimiter(calls_per_second=0.5)


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class CmsScanRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=900, ge=10, le=3600)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"cmseek", "wpscan", "joomscan", "droopescan"}
        if v not in allowed:
            raise ValueError("Tool must be 'cmseek', 'wpscan', 'joomscan', or 'droopescan'")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        return _normalize_target_url(v)

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">", "\n", "\r", "'", '"']
        blocked_output_flags = ["-o", "--output", "-O"]

        for arg in v:
            for char in dangerous:
                if char in arg:
                    raise ValueError(f"Dangerous char '{repr(char)}' in arg")
            arg_clean = arg.strip().lower()
            for flag in blocked_output_flags:
                if arg_clean == flag or arg_clean.startswith(flag + "="):
                    raise ValueError(f"Blocked output flag: {flag}")
        return v


class CmsComponent(BaseModel):
    type: str
    name: str
    version: Optional[str] = None
    status: Optional[str] = None


class CmsFinding(BaseModel):
    title: str
    severity: str = "INFO"
    references: list[str] = Field(default_factory=list)
    component_name: Optional[str] = None


class CmsResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str

    cms_name: Optional[str] = None
    cms_version: Optional[str] = None

    components: list[CmsComponent] = Field(default_factory=list)
    findings: list[CmsFinding] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)

    raw_output: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 4. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_cmseek_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["cmseek"]
    final_args = list(args)

    if not _has_flag(final_args, ["--batch"]):
        final_args.append("--batch")
    if not _has_flag(final_args, ["--random-agent", "-r"]):
        final_args.append("--random-agent")

    if not _target_in_args(target, final_args, ["-u", "--url"]):
        final_args.extend(["-u", target])

    cmd.extend(final_args)
    return cmd


def _build_wpscan_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["wpscan"]
    final_args = list(args)

    if _has_flag(final_args, ["-o", "--output"]):
        raise ValueError("Output file flags are blocked. Use stdout output only.")

    if not _has_flag(final_args, ["-f", "--format"]):
        final_args.extend(["-f", "json"])

    if not _has_flag(final_args, ["--update"]):
        final_args.append("--no-update")

    if not _has_flag(final_args, ["-e", "--enumerate"]):
        final_args.extend(["-e", "vp,vt,tt,cb,dbe,u,m"])

    if not _target_in_args(target, final_args, ["--url"]):
        final_args.extend(["--url", target])

    cmd.extend(final_args)
    return cmd


def _build_joomscan_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["joomscan"]
    final_args = list(args)

    if not _target_in_args(target, final_args, ["-u", "--url"]):
        final_args.extend(["-u", target])

    cmd.extend(final_args)
    return cmd


def _build_droopescan_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["droopescan"]
    final_args = list(args)

    if "scan" not in final_args:
        final_args.insert(0, "scan")

    if "drupal" not in final_args and "silverstripe" not in final_args:
        scan_idx = final_args.index("scan")
        final_args.insert(scan_idx + 1, "drupal")

    if not _has_flag(final_args, ["-o", "--output"]):
        final_args.extend(["-o", "json"])

    if not _target_in_args(target, final_args, ["-u", "--url"]):
        final_args.extend(["-u", target])

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 5. PARSERS
# ══════════════════════════════════════════════════════════════

def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def _extract_json_value(raw: str) -> Optional[object]:
    text = _strip_ansi(raw).strip()
    if not text:
        return None

    try:
        return json.loads(text)
    except Exception:
        pass

    decoder = json.JSONDecoder()
    for marker in ("{", "["):
        idx = text.find(marker)
        if idx != -1:
            try:
                value, _ = decoder.raw_decode(text[idx:])
                return value
            except Exception:
                continue
    return None


def parse_cmseek(stdout: str, stderr: str) -> tuple[Optional[str], Optional[str], list[str]]:
    cms_name = None
    cms_version = None
    warnings: list[str] = []

    raw = _strip_ansi(stdout + "\n" + stderr)

    def _looks_like_placeholder(value: str) -> bool:
        v = (value or "").strip().lower()
        if not v:
            return True
        if "unknown" in v:
            return True
        if "name and/or cms url" in v or "name and cms url" in v:
            return True
        if "cmseek" in v and "version" in v:
            return True
        if v.startswith("<") and v.endswith(">"):
            return True
        return False

    patterns_name = [
        r"CMS\s*:\s*(.+)",
        r"Detected CMS\s*:\s*(.+)",
        r"Result:\s*(.+)",
    ]
    for pattern in patterns_name:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip()
            if candidate and not _looks_like_placeholder(candidate):
                cms_name = candidate
                break

    # Restrict version parsing to CMS-specific labels to avoid parsing CMSeeK's own version.
    patterns_ver = [
        r"CMS Version\s*:\s*(.+)",
        r"Detected CMS Version\s*:\s*(.+)",
        r"WordPress Version\s*:\s*(.+)",
        r"Joomla Version\s*:\s*(.+)",
        r"Drupal Version\s*:\s*(.+)",
    ]
    for pattern in patterns_ver:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip()
            if candidate and not _looks_like_placeholder(candidate) and candidate != "0":
                cms_version = candidate
                break

    # If CMS name is unknown, keep version unset to prevent false confidence.
    if not cms_name:
        cms_version = None

    if not cms_name and raw.strip():
        warnings.append("CMSeek output parsed weakly; CMS name not confidently identified")

    return cms_name, cms_version, warnings


def parse_wpscan(
    raw_json: str
) -> tuple[Optional[str], Optional[str], list[CmsComponent], list[CmsFinding], list[str], list[str]]:
    cms_name: Optional[str] = None
    cms_version = None
    components: list[CmsComponent] = []
    findings: list[CmsFinding] = []
    users: list[str] = []
    warnings: list[str] = []

    data = _extract_json_value(raw_json)
    if not isinstance(data, dict):
        return cms_name, cms_version, components, findings, users, ["WPScan output not parseable as JSON"]

    try:
        wp_evidence = False
        version_data = data.get("version", {})
        if isinstance(version_data, dict):
            cms_version = version_data.get("number")
            if cms_version:
                wp_evidence = True
            for vuln in version_data.get("vulnerabilities", []):
                findings.append(CmsFinding(
                    title=vuln.get("title", "Unknown Core Vuln"),
                    severity="HIGH",
                    references=vuln.get("references", {}).get("url", []),
                    component_name="Core",
                ))
                wp_evidence = True

        for plugin_slug, plugin_data in data.get("plugins", {}).items():
            version = plugin_data.get("version", {}).get("number") if plugin_data.get("version") else None
            out_of_date = plugin_data.get("outdated", False)
            status = "Outdated" if out_of_date else "Up to date"

            components.append(CmsComponent(
                type="plugin",
                name=plugin_slug,
                version=version,
                status=status,
            ))
            wp_evidence = True

            for vuln in plugin_data.get("vulnerabilities", []):
                findings.append(CmsFinding(
                    title=vuln.get("title", f"Vuln in {plugin_slug}"),
                    severity="HIGH",
                    references=vuln.get("references", {}).get("url", []),
                    component_name=plugin_slug,
                ))
                wp_evidence = True

        for theme_slug, theme_data in data.get("themes", {}).items():
            version = theme_data.get("version", {}).get("number") if theme_data.get("version") else None
            components.append(CmsComponent(
                type="theme",
                name=theme_slug,
                version=version,
            ))
            wp_evidence = True

        for user_key, _user_data in data.get("users", {}).items():
            users.append(user_key)
            wp_evidence = True

        # Some WPScan versions expose URL hints in interesting findings.
        if not wp_evidence:
            for finding in data.get("interesting_findings", []):
                if not isinstance(finding, dict):
                    continue
                to_find = " ".join([
                    str(finding.get("to_s", "")),
                    str(finding.get("url", "")),
                    str(finding.get("interesting_entries", "")),
                ]).lower()
                if "wp-content" in to_find or "wp-includes" in to_find or "wp-admin" in to_find:
                    wp_evidence = True
                    break

        if wp_evidence:
            cms_name = "WordPress"
        else:
            warnings.append("WPScan completed but did not confirm WordPress fingerprints")

    except Exception as e:
        warnings.append(f"WPScan parse warning: {e}")

    return cms_name, cms_version, components, findings, users, warnings


def parse_joomscan(stdout: str, stderr: str) -> tuple[Optional[str], list[CmsComponent], list[CmsFinding], list[str]]:
    cms_version = None
    components: list[CmsComponent] = []
    findings: list[CmsFinding] = []
    warnings: list[str] = []

    raw = _strip_ansi(stdout + "\n" + stderr)

    ver_patterns = [
        r"Joomla version\s*:\s*(.+)",
        r"Version Detected\s*:\s*(.+)",
    ]
    for pattern in ver_patterns:
        ver_match = re.search(pattern, raw, re.IGNORECASE)
        if ver_match:
            cms_version = ver_match.group(1).strip()
            break

    vuln_blocks = re.findall(
        r"Vulnerability\s*:\s*(.+?)\n.*?Details\s*:\s*(.+?)\n",
        raw,
        re.IGNORECASE | re.DOTALL
    )
    for title, details in vuln_blocks:
        findings.append(CmsFinding(
            title=title.strip(),
            severity="HIGH",
            references=[details.strip()],
            component_name="Core"
        ))

    # broader component parsing
    component_patterns = [
        r"Component[s]?\s*:\s*(.+)",
        r"com_([a-zA-Z0-9_\-]+)",
    ]

    seen_components = set()

    for pattern in component_patterns:
        for match in re.finditer(pattern, raw, re.IGNORECASE):
            if pattern.startswith("com_"):
                comp_name = match.group(0).strip()
            else:
                comp_name = match.group(1).strip()

            if not comp_name:
                continue

            # split comma-separated component lists
            for piece in re.split(r"[,\s]+", comp_name):
                piece = piece.strip()
                if not piece:
                    continue
                if not piece.startswith("com_") and pattern.startswith("com_"):
                    continue
                if piece not in seen_components:
                    seen_components.add(piece)
                    components.append(CmsComponent(type="plugin", name=piece))

    if not cms_version and not components and not findings and raw.strip():
        warnings.append("Joomscan output parsed weakly; limited extraction")

    return cms_version, components, findings, warnings


def parse_droopescan(stdout: str, stderr: str) -> tuple[Optional[str], list[CmsComponent], list[str]]:
    cms_version = None
    components: list[CmsComponent] = []
    warnings: list[str] = []

    data = _extract_json_value(stdout)
    if data is None:
        if _strip_ansi(stdout + stderr).strip():
            warnings.append("Droopescan output not parseable as JSON")
        return cms_version, components, warnings

    try:
        if isinstance(data, list):
            # some versions may wrap results in list
            if data:
                data = data[0]

        if not isinstance(data, dict):
            return cms_version, components, warnings

        version_data = data.get("version", [])
        if isinstance(version_data, list) and version_data:
            cms_version = ", ".join(str(v) for v in version_data)
        elif isinstance(version_data, str):
            cms_version = version_data

        for plugin in data.get("plugins", []):
            if isinstance(plugin, dict):
                components.append(CmsComponent(
                    type="plugin",
                    name=plugin.get("name", "Unknown"),
                    version=plugin.get("version"),
                ))
            elif isinstance(plugin, str):
                components.append(CmsComponent(type="plugin", name=plugin))

        for theme in data.get("themes", []):
            if isinstance(theme, dict):
                components.append(CmsComponent(
                    type="theme",
                    name=theme.get("name", "Unknown"),
                    version=theme.get("version"),
                ))
            elif isinstance(theme, str):
                components.append(CmsComponent(type="theme", name=theme))

    except Exception as e:
        warnings.append(f"Droopescan parse warning: {e}")

    return cms_version, components, warnings


# ══════════════════════════════════════════════════════════════
# 6. CORE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _cms_detect_and_scan_impl(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    timeout: int = 900,
) -> dict:
    start = time.time()
    args = list(args or [])
    warnings: list[str] = []

    CMS_SCAN_RATE_LIMITER.acquire()

    try:
        req = CmsScanRequest(tool=tool, target=target, args=args, timeout=timeout)
    except Exception as e:
        return CmsResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            working_dir="",
            error=str(e),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    installed, install_msg = check_tool_installed(req.tool)
    if not installed:
        return CmsResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            working_dir="",
            error=install_msg,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    if req.tool == "cmseek":
        cmd = _build_cmseek_cmd(req.args, req.target)
    elif req.tool == "wpscan":
        cmd = _build_wpscan_cmd(req.args, req.target)
    elif req.tool == "joomscan":
        cmd = _build_joomscan_cmd(req.args, req.target)
    elif req.tool == "droopescan":
        cmd = _build_droopescan_cmd(req.args, req.target)
    else:
        return CmsResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            working_dir="",
            error=f"Unsupported tool: {req.tool}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    command_str = " ".join(cmd)
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)

    cms_name = None
    cms_version = None
    components: list[CmsComponent] = []
    findings: list[CmsFinding] = []
    users: list[str] = []

    if req.tool == "cmseek":
        cms_name, cms_version, parse_warnings = parse_cmseek(stdout, stderr)
        warnings.extend(parse_warnings)

    elif req.tool == "wpscan":
        cms_name, cms_version, components, findings, users, parse_warnings = parse_wpscan(stdout)
        warnings.extend(parse_warnings)

    elif req.tool == "joomscan":
        cms_version, components, findings, parse_warnings = parse_joomscan(stdout, stderr)
        warnings.extend(parse_warnings)
        if cms_version or components or findings:
            cms_name = "Joomla"
        else:
            warnings.append("Joomscan completed but did not confirm Joomla fingerprints")

    elif req.tool == "droopescan":
        cms_version, components, parse_warnings = parse_droopescan(stdout, stderr)
        warnings.extend(parse_warnings)
        if cms_version or components:
            cms_name = "Drupal"
        else:
            warnings.append("Droopescan completed but did not confirm Drupal fingerprints")

    has_data = bool(cms_name or cms_version or components or findings or users)

    # keep some raw output even on success if parser warned
    raw_output = None
    if not has_data or warnings:
        raw_output = (stdout or stderr)[:5000]

    return CmsResult(
        success=rc == 0 or has_data,
        tool=req.tool,
        target=req.target,
        command=command_str,
        working_dir=cwd,
        cms_name=cms_name,
        cms_version=cms_version,
        components=[c.model_dump() for c in components],
        findings=[f.model_dump() for f in findings],
        users=users,
        raw_output=raw_output,
        warnings=warnings,
        error=stderr if rc != 0 and not has_data else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 7. CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_cms_detect_and_scan(
    tool: str,
    target: str,
    args_tuple: tuple[str, ...],
    timeout: int,
) -> str:
    result = _cms_detect_and_scan_impl(
        tool=tool,
        target=target,
        args=list(args_tuple),
        timeout=timeout,
    )
    return json.dumps(result)


def clear_cache():
    _cached_cms_detect_and_scan.cache_clear()


def get_cache_info():
    return _cached_cms_detect_and_scan.cache_info()


# ══════════════════════════════════════════════════════════════
# 8. PUBLIC API
# ══════════════════════════════════════════════════════════════

def cms_detect_and_scan(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    timeout: int = 900,
    use_cache: bool = True,
) -> dict:
    """
    🔧 Agent Tool: CMS Detection & Scanning

    Recommended flow:
    1. Run cmseek to identify CMS
    2. Run the matching dedicated scanner:
       - wpscan for WordPress
       - joomscan for Joomla
       - droopescan for Drupal

    Returns structured data:
    - detected CMS and version
    - plugins/themes/components
    - vulnerabilities
    - users
    """
    args = args or []

    if use_cache:
        cached = _cached_cms_detect_and_scan(
            tool,
            target,
            tuple(args),
            timeout,
        )
        return json.loads(cached)

    return _cms_detect_and_scan_impl(
        tool=tool,
        target=target,
        args=args,
        timeout=timeout,
    )


# ══════════════════════════════════════════════════════════════
# 9. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

CMS_SCAN_TOOL_DEFINITION = {
    "name": "cms_detect_and_scan",
    "description": (
        "Detect the CMS in use and run specific vulnerability scanners. "
        "Methodology: first run 'cmseek' to identify the CMS. Then, based on the result, "
        "run the dedicated scanner ('wpscan' for WordPress, 'joomscan' for Joomla, "
        "'droopescan' for Drupal)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["cmseek", "wpscan", "joomscan", "droopescan"],
                "description": "cmseek (CMS detector) | wpscan (WordPress) | joomscan (Joomla) | droopescan (Drupal)"
            },
            "target": {
                "type": "string",
                "description": "Target URL (e.g. 'https://example.com')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw args. Example for wpscan: ['--api-token', 'YOUR_TOKEN', '-e', 'vp,vt,u']"
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
# 10. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("CMS DETECT & SCAN — v2.1")
    print("=" * 60)

    # 1. Step 1: Detect CMS with CMSeek
    r1 = cms_detect_and_scan(
        tool="cmseek",
        target="http://scanme.nmap.org",
        use_cache=False,
    )
    print("\n=== CMSEEK (CMS Detection) ===")
    print(f"Command: {r1['command']}")
    print(f"CMS Name:    {r1['cms_name']}")
    print(f"CMS Version: {r1['cms_version']}")
    print(f"Warnings:    {r1['warnings']}")
    if r1.get("error"):
        print(f"Error:       {r1['error']}")

    detected = (r1.get("cms_name") or "").lower()
    should_run_wpscan = ("wordpress" in detected) or detected.startswith("wp")

    if should_run_wpscan:
        # 2. Step 2: WordPress Scan (only when CMSeek indicates WP)
        r2 = cms_detect_and_scan(
            tool="wpscan",
            target="http://scanme.nmap.org",
            args=["-e", "vp,vt,u"],
            use_cache=False,
        )
        print("\n=== WPSCAN (WordPress Enum) ===")
        print(f"Command: {r2['command']}")
        print(f"Version: {r2['cms_version']}")
        print(f"Plugins Found: {len([c for c in r2['components'] if c['type'] == 'plugin'])}")
        print(f"Users Found:   {len(r2['users'])}")
        if r2.get("warnings"):
            print(f"Warnings:      {r2['warnings']}")
        if r2.get("error"):
            print(f"Error:         {r2['error']}")
        for user in r2['users']:
            print(f"  - {user}")

        print("\n=== FULL JSON PAYLOAD (WPScan) ===")
        print(json.dumps(r2, indent=2))
    else:
        print("\n=== SCAN ROUTING ===")
        print("Skipping CMS-specific scanner run.")
        print("Reason: CMSeek did not confidently identify a supported CMS.")

    print("\n=== CACHE TEST ===")
    start = time.time()
    _ = cms_detect_and_scan(
        tool="cmseek",
        target="http://scanme.nmap.org",
        use_cache=True,
    )
    first = time.time() - start

    start = time.time()
    _ = cms_detect_and_scan(
        tool="cmseek",
        target="http://scanme.nmap.org",
        use_cache=True,
    )
    second = time.time() - start

    print(f"First run:  {first:.2f}s")
    print(f"Cached run: {second:.4f}s")
    print(f"Cache info: {get_cache_info()}")
