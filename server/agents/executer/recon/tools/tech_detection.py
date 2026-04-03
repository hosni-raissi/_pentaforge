import subprocess
import json
import re
import os
import time
import tempfile
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


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


def _has_flag_with_value(args: list[str], flags: list[str]) -> bool:
    for i, arg in enumerate(args):
        if arg in flags:
            return True
        for flag in flags:
            if arg.startswith(flag + "="):
                return True
    return False


def safe_execute(cmd: list[str], timeout: int = 300) -> tuple[str, str, int, str]:
    """Run command safely in project directory"""
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
        return "", f"Timed out after {timeout}s", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class DetectTechRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=300, ge=10, le=1200)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"whatweb", "httpx", "wappalyzer"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        clean_v = re.sub(r"^\w+://", "", v.strip()).split('/')[0]
        if clean_v in blocked:
            raise ValueError(f"Target '{v}' is blocked")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"', ">"]
        for arg in v:
            for char in dangerous:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in arg: {arg}")
        return v


class Technology(BaseModel):
    name: str
    version: Optional[str] = None
    category: Optional[str] = None


class DetectTechResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str = ""
    http_status: Optional[int] = None
    technologies: list[Technology] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_whatweb_cmd(args: list[str], target: str) -> tuple[list[str], Path]:
    """Build whatweb command with secure JSON file output"""
    cmd = ["whatweb"]
    final_args = list(args)
    
    # We force WhatWeb to output JSON to a temp file for clean parsing
    tmp_file = ProjectConfig.get_temp_dir() / f"whatweb_{int(time.time())}.json"
    
    if not _has_flag(final_args, ["--log-json"]):
        final_args.extend(["--log-json", str(tmp_file)])
    
    # Ensure silent mode to keep stdout clean
    if not _has_flag(final_args, ["-q", "--quiet"]):
        final_args.append("-q")

    if not _target_in_args(target, final_args):
        final_args.append(target)
        
    cmd.extend(final_args)
    return cmd, tmp_file


def _build_httpx_cmd(args: list[str], target: str) -> list[str]:
    """Build httpx command configured for tech detection"""
    cmd = ["httpx"]
    final_args = list(args)

    if not _has_flag(final_args, ["-tech-detect"]):
        final_args.append("-tech-detect")
    if not _has_flag(final_args, ["-json"]):
        final_args.append("-json")
    if not _has_flag(final_args, ["-silent"]):
        final_args.append("-silent")

    if not _target_in_args(target, final_args):
        # httpx takes target directly, or via -u
        final_args.append(target)

    cmd.extend(final_args)
    return cmd


def _build_wappalyzer_cmd(args: list[str], target: str) -> list[str]:
    """Build wappalyzer CLI command"""
    # Requires `npm install -g wappalyzer`
    cmd = ["wappalyzer"]
    final_args = list(args)

    # Wappalyzer CLI usually requires protocol
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"https://{target}"

    if not _target_in_args(target, final_args):
        final_args.append(target)

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_whatweb(tmp_file: Path) -> tuple[list[Technology], Optional[int]]:
    """Parse WhatWeb JSON output file"""
    technologies = []
    status_code = None
    
    if not tmp_file.exists():
        return [], None
        
    try:
        content = tmp_file.read_text()
        if not content.strip():
            return [], None
            
        data = json.loads(content)
        
        # WhatWeb returns a list of results (handles redirects)
        # We take the last one (final destination)
        if isinstance(data, list) and len(data) > 0:
            result = data[-1]
            status_code = result.get("http_status")
            plugins = result.get("plugins", {})
            
            for plugin_name, plugin_data in plugins.items():
                # Skip internal/generic WhatWeb plugins
                if plugin_name in ["Country", "IP", "Title", "HTTPServer"]:
                    if plugin_name == "HTTPServer" and "string" in plugin_data:
                        # Extract the web server as a tech
                        for s in plugin_data["string"]:
                            technologies.append(Technology(name=s, category="Web Server"))
                    continue
                
                version = None
                if "version" in plugin_data and isinstance(plugin_data["version"], list):
                    version = str(plugin_data["version"][0])
                elif "string" in plugin_data and isinstance(plugin_data["string"], list):
                    # Sometimes version is stored in string
                    version = str(plugin_data["string"][0])

                technologies.append(Technology(
                    name=plugin_name,
                    version=version
                ))
    except Exception:
        pass
    finally:
        # Cleanup temp file
        try:
            tmp_file.unlink()
        except OSError:
            pass
            
    return technologies, status_code


def parse_httpx(stdout: str) -> tuple[list[Technology], Optional[int]]:
    """Parse httpx JSON output"""
    technologies = []
    status_code = None
    
    for line in stdout.split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            status_code = data.get("status_code")
            
            # httpx returns a list of tech strings like ["Nginx", "PHP:7.4", "WordPress"]
            tech_list = data.get("technologies", [])
            
            for tech in tech_list:
                # Some are returned with versions separated by colons (e.g. PHP:7.4)
                parts = str(tech).split(":")
                name = parts[0]
                version = parts[1] if len(parts) > 1 else None
                technologies.append(Technology(name=name, version=version))
                
            # If there's a specific web server identified
            if "webserver" in data:
                server = data["webserver"]
                if not any(t.name == server for t in technologies):
                    technologies.append(Technology(name=server, category="Web Server"))
                    
        except json.JSONDecodeError:
            pass
            
    return technologies, status_code


def parse_wappalyzer(stdout: str) -> tuple[list[Technology], Optional[int]]:
    """Parse Wappalyzer CLI JSON output"""
    technologies = []
    status_code = None
    
    try:
        data = json.loads(stdout)
        
        # Get status code from urls object
        urls = data.get("urls", {})
        for url, url_data in urls.items():
            if "status" in url_data:
                status_code = url_data["status"]
                break
                
        # Parse technologies array
        techs = data.get("technologies", [])
        for tech in techs:
            name = tech.get("name")
            
            # Versions can be an array
            versions = tech.get("versions", [])
            version = versions[0] if versions else None
            
            # Categories
            categories = tech.get("categories", [])
            category = categories[0].get("name") if categories else None
            
            if name:
                technologies.append(Technology(
                    name=name,
                    version=version,
                    category=category
                ))
    except json.JSONDecodeError:
        pass
        
    return technologies, status_code


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def detect_tech(tool: str, target: str, args: list[str] = []) -> dict:
    """
    🔧 Agent Tool: Detect Technologies

    Fingerprint the target to discover the underlying web server, frameworks, 
    programming languages, CMS, and JavaScript libraries.

    Args:
        tool:    "whatweb" | "httpx" | "wappalyzer"
        target:  URL or Domain (e.g. "https://example.com")
        args:    Raw tool arguments

    Returns:
        Structured JSON with detected technologies, versions, and categories.
    """
    start = time.time()
    
    # ── VALIDATE ──
    try:
        req = DetectTechRequest(tool=tool, target=target, args=args)
    except Exception as e:
        return DetectTechResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation error: {e}"
        ).model_dump()

    # ── BUILD COMMAND ──
    tmp_file = None
    try:
        if tool == "whatweb":
            cmd, tmp_file = _build_whatweb_cmd(args, target)
        elif tool == "httpx":
            cmd = _build_httpx_cmd(args, target)
        elif tool == "wappalyzer":
            cmd = _build_wappalyzer_cmd(args, target)
    except Exception as e:
        return DetectTechResult(
            success=False, tool=tool, target=target,
            command="", error=f"Command build error: {e}"
        ).model_dump()

    # ── EXECUTE ──
    command_str = " ".join(cmd)
    stdout, stderr, rc, working_dir = safe_execute(cmd, req.timeout)

    # ── PARSE ──
    technologies = []
    status_code = None

    if tool == "whatweb":
        # WhatWeb parses from the securely written temp file
        if tmp_file:
            technologies, status_code = parse_whatweb(tmp_file)
    elif tool == "httpx":
        technologies, status_code = parse_httpx(stdout)
    elif tool == "wappalyzer":
        technologies, status_code = parse_wappalyzer(stdout)

    # Deduplicate technologies by name
    seen = set()
    unique_tech = []
    for t in technologies:
        if t.name.lower() not in seen:
            seen.add(t.name.lower())
            unique_tech.append(t)

    # ── RETURN ──
    return DetectTechResult(
        success=len(unique_tech) > 0 or rc == 0,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=working_dir,
        http_status=status_code,
        technologies=unique_tech,
        raw_output=None, # Keep clean, we parsed what we need
        error=stderr if rc != 0 and not unique_tech else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

DETECT_TECH_TOOL_DEFINITION = {
    "name": "detect_tech",
    "description": (
        "Fingerprint web technologies, servers, CMS, and frameworks. "
        "Supports httpx (modern Wappalyzer engine), whatweb (deep Ruby scanner), "
        "and wappalyzer (Node CLI). Returns structured JSON with versions."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["whatweb", "httpx", "wappalyzer"],
                "description": (
                    "whatweb = deep signature scan, handles redirects | "
                    "httpx = ultra-fast, modern Wappalyzer engine inside | "
                    "wappalyzer = official NodeJS CLI"
                )
            },
            "target": {
                "type": "string",
                "description": "Target URL or domain (e.g. 'https://example.com' or 'example.com')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool args. Example:\n"
                    "whatweb: ['-a', '3', '--no-errors']\n"
                    "httpx: ['-follow-redirects', '-random-agent']\n"
                    "wappalyzer: ['--delay', '1000']"
                )
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
    print("TECHNOLOGY DETECTION — EXAMPLES")
    print("=" * 60)

    # 1. HTTPX (Fast & Modern)
    print("\n=== HTTPX ===")
    r = detect_tech(
        tool="httpx",
        target="hackerone.com",
        args=["-follow-redirects"]
    )
    print(f"Command: {r['command']}")
    print(f"Status:  {r['http_status']}")
    for t in r['technologies']:
        ver = f" (v{t['version']})" if t['version'] else ""
        print(f" - {t['name']}{ver}")

    # 2. WhatWeb (Deep Scan)
    print("\n=== WHATWEB ===")
    r = detect_tech(
        tool="whatweb",
        target="https://hackerone.com",
        args=["-a", "1"] # stealthy/fast mode
    )
    print(f"Command: {r['command']}")
    print(f"Status:  {r['http_status']}")
    for t in r['technologies']:
        ver = f" (v{t['version']})" if t['version'] else ""
        cat = f" [{t['category']}]" if t['category'] else ""
        print(f" - {t['name']}{ver}{cat}")
        
    # 3. Full JSON Output
    print("\n=== FULL JSON PAYLOAD ===")
    print(json.dumps(r, indent=2))