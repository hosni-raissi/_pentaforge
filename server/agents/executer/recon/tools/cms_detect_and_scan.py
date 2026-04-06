import subprocess
import json
import re
import os
import time
from pathlib import Path
from typing import Optional, Any
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator


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
        if cls._project_dir: return cls._project_dir
        env_dir = os.environ.get("AGENT_PROJECT_DIR")
        if env_dir and os.path.isdir(env_dir):
            cls._project_dir = Path(env_dir)
            return cls._project_dir
        current = Path(__file__).resolve().parent
        for parent in [current] + list(current.parents):
            if any((parent / marker).exists() for marker in ["pyproject.toml", "setup.py", ".git"]):
                cls._project_dir = parent
                return cls._project_dir
        cls._project_dir = Path.cwd()
        return cls._project_dir
    
    @classmethod
    def get_temp_dir(cls) -> Path:
        path = cls.get_project_dir() / cls.TEMP_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path


def _target_in_args(target: str, args: list[str], flags: list[str]) -> bool:
    if not args: return False
    t_clean = target.strip().lower()
    for i, arg in enumerate(args):
        a_clean = arg.strip().lower()
        if a_clean == t_clean or t_clean in a_clean: return True
        if a_clean in flags and i + 1 < len(args):
            if args[i + 1].strip().lower() == t_clean: return True
    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    return any(arg in args for arg in flags)


def safe_execute(cmd: list[str], timeout: int = 900) -> tuple[str, str, int, str]:
    cwd = ProjectConfig.get_project_dir()
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False, cwd=str(cwd))
        return res.stdout, res.stderr, res.returncode, str(cwd)
    except subprocess.TimeoutExpired:
        return "", f"Timeout ({timeout}s)", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class CmsScanRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=900, ge=10, le=3600)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        if v not in {"cmseek", "wpscan", "joomscan", "droopescan"}: 
            raise ValueError("Tool must be 'cmseek', 'wpscan', 'joomscan', or 'droopescan'")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        if not v.startswith("http"): 
            raise ValueError("Target must be a URL (e.g. https://example.com/)")
        return v.strip()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg")
        return v


class CmsComponent(BaseModel):
    type: str  # plugin, theme, core
    name: str
    version: Optional[str] = None
    status: Optional[str] = None # e.g., out of date, vulnerable


class CmsFinding(BaseModel):
    title: str
    severity: str = "INFO"
    references: list[str] = []
    component_name: Optional[str] = None


class CmsResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str
    
    cms_name: Optional[str] = None
    cms_version: Optional[str] = None
    
    components: list[CmsComponent] = []
    findings: list[CmsFinding] = []
    users: list[str] = []
    
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_cmseek_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["cmseek"]
    final_args = list(args)

    if not _has_flag(final_args, ["--batch"]):
        final_args.append("--batch") # Skip prompts
        
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

    # Avoid updating locally on every run unless requested
    if not _has_flag(final_args, ["--update"]):
        final_args.append("--no-update")
        
    # By default, do basic enumeration if none specified
    if not _has_flag(final_args, ["-e", "--enumerate"]):
        final_args.extend(["-e", "vp,vt,tt,cb,dbe,u,m"])

    if not _target_in_args(target, final_args, ["--url"]):
        final_args.extend(["--url", target])

    cmd.extend(final_args)
    return cmd


def _build_joomscan_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["joomscan"]
    final_args = list(args)

    # Note: Joomscan uses -u or --url
    if not _target_in_args(target, final_args, ["-u", "--url"]):
        final_args.extend(["-u", target])

    cmd.extend(final_args)
    return cmd


def _build_droopescan_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["droopescan"]
    final_args = list(args)
    
    # Droopescan syntax: droopescan scan drupal -u URL
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
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_cmseek(stdout: str) -> tuple[Optional[str], Optional[str]]:
    """Parse CMSeek stdout"""
    cms_name = None
    cms_version = None
    
    # CMSeek stdout parsing
    name_match = re.search(r"CMS:\s*(.*?)(?:\n|\r)", stdout)
    if name_match:
        # Clean up ANSI codes if any
        raw_name = re.sub(r"\x1b\[.*?m", "", name_match.group(1)).strip()
        if "Unknown" not in raw_name:
            cms_name = raw_name

    version_match = re.search(r"Version:\s*(.*?)(?:\n|\r)", stdout)
    if version_match:
        raw_ver = re.sub(r"\x1b\[.*?m", "", version_match.group(1)).strip()
        if "Unknown" not in raw_ver and "0" != raw_ver:
            cms_version = raw_ver
            
    return cms_name, cms_version


def _extract_json_value(raw: str) -> Optional[Any]:
    text = (raw or "").strip()
    if not text:
        return None
    decoder = json.JSONDecoder()
    starts: list[int] = []
    for marker in ("{", "["):
        idx = text.find(marker)
        if idx != -1:
            starts.append(idx)
    for idx in sorted(starts):
        try:
            value, _ = decoder.raw_decode(text[idx:])
            return value
        except Exception:
            continue
    return None


def parse_wpscan(raw_json: str) -> tuple[Optional[str], list[CmsComponent], list[CmsFinding], list[str]]:
    """Parse WPScan JSON output from stdout."""
    cms_version = None
    components = []
    findings = []
    users = []
    data = _extract_json_value(raw_json)
    if not isinstance(data, dict):
        return cms_version, components, findings, users

    try:
        # 1. Core Version & Vulns
        version_data = data.get("version", {})
        if version_data:
            cms_version = version_data.get("number")
            for vuln in version_data.get("vulnerabilities", []):
                findings.append(CmsFinding(
                    title=vuln.get("title", "Unknown Core Vuln"),
                    severity="HIGH",
                    references=vuln.get("references", {}).get("url", []),
                    component_name="Core"
                ))

        # 2. Plugins
        for plugin_slug, plugin_data in data.get("plugins", {}).items():
            version = plugin_data.get("version", {}).get("number") if plugin_data.get("version") else None
            out_of_date = plugin_data.get("outdated", False)
            status = "Outdated" if out_of_date else "Up to date"
            
            components.append(CmsComponent(
                type="plugin", name=plugin_slug, version=version, status=status
            ))
            
            for vuln in plugin_data.get("vulnerabilities", []):
                findings.append(CmsFinding(
                    title=vuln.get("title", f"Vuln in {plugin_slug}"),
                    severity="HIGH",
                    references=vuln.get("references", {}).get("url", []),
                    component_name=plugin_slug
                ))

        # 3. Themes
        for theme_slug, theme_data in data.get("themes", {}).items():
            version = theme_data.get("version", {}).get("number") if theme_data.get("version") else None
            components.append(CmsComponent(
                type="theme", name=theme_slug, version=version
            ))

        # 4. Users
        for user_key, user_data in data.get("users", {}).items():
            users.append(user_key)

    except Exception:
        pass

    return cms_version, components, findings, users


def parse_joomscan(stdout: str) -> tuple[Optional[str], list[CmsComponent], list[CmsFinding]]:
    """Parse Joomscan text output"""
    cms_version = None
    components = []
    findings = []
    
    raw = re.sub(r"\x1b\[.*?m", "", stdout) # strip ANSI
    
    # Core version
    ver_match = re.search(r"Joomla version\s*:\s*(.+)", raw, re.IGNORECASE)
    if ver_match:
        cms_version = ver_match.group(1).strip()
        
    # Core vulnerabilities
    vuln_blocks = re.findall(r"Vulnerability\s*:\s*(.+?)\n.*?Details\s*:\s*(.+?)\n", raw, re.IGNORECASE | re.DOTALL)
    for title, details in vuln_blocks:
        findings.append(CmsFinding(
            title=title.strip(),
            severity="HIGH",
            references=[details.strip()],
            component_name="Core"
        ))
        
    # Components (Plugins)
    comp_blocks = re.findall(r"Components\s*:\s*(.+?)\n", raw, re.IGNORECASE)
    for comp in comp_blocks:
        components.append(CmsComponent(
            type="plugin",
            name=comp.strip()
        ))
        
    return cms_version, components, findings


def parse_droopescan(stdout: str) -> tuple[Optional[str], list[CmsComponent]]:
    """Parse Droopescan JSON output from stdout."""
    cms_version = None
    components = []

    raw = stdout
    try:
        data = _extract_json_value(raw)
        if not isinstance(data, dict):
            return cms_version, components
        
        # Version
        version_data = data.get("version", [])
        if version_data:
            # droopescan often returns multiple possible versions
            cms_version = ", ".join(version_data)
            
        # Plugins
        for plugin in data.get("plugins", []):
            components.append(CmsComponent(
                type="plugin",
                name=plugin.get("name", "Unknown"),
                version=plugin.get("version")
            ))
            
        # Themes
        for theme in data.get("themes", []):
            components.append(CmsComponent(
                type="theme",
                name=theme.get("name", "Unknown"),
                version=theme.get("version")
            ))
    except json.JSONDecodeError:
        pass
        
    return cms_version, components


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def cms_detect_and_scan(tool: str, target: str, args: Optional[list[str]] = None) -> dict:
    """
    🔧 Agent Tool: CMS Detection & Scanning
    """
    start = time.time()
    args = list(args or [])
    
    try:
        req = CmsScanRequest(tool=tool, target=target, args=args)
    except Exception as e:
        return CmsResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    # ── BUILD COMMAND ──
    if tool == "cmseek":
        cmd = _build_cmseek_cmd(args, target)
    elif tool == "wpscan":
        cmd = _build_wpscan_cmd(args, target)
    elif tool == "joomscan":
        cmd = _build_joomscan_cmd(args, target)
    elif tool == "droopescan":
        cmd = _build_droopescan_cmd(args, target)

    command_str = " ".join(cmd)
    
    # ── EXECUTE ──
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)

    # ── PARSE ──
    cms_name = None
    cms_version = None
    components = []
    findings = []
    users = []

    if tool == "cmseek":
        cms_name, cms_version = parse_cmseek(stdout)
    elif tool == "wpscan":
        cms_name = "WordPress"
        cms_version, components, findings, users = parse_wpscan(stdout)
    elif tool == "joomscan":
        cms_name = "Joomla"
        cms_version, components, findings = parse_joomscan(stdout)
    elif tool == "droopescan":
        cms_name = "Drupal" # Default for droopescan
        cms_version, components = parse_droopescan(stdout)

    has_data = bool(cms_name or cms_version or components or findings or users)

    # ── RETURN ──
    return CmsResult(
        success=rc == 0 or has_data,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        cms_name=cms_name,
        cms_version=cms_version,
        components=components,
        findings=findings,
        users=users,
        raw_output=(stdout or stderr)[:5000] if not has_data else None,
        error=stderr if rc != 0 and not has_data else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

CMS_SCAN_TOOL_DEFINITION = {
    "name": "cms_detect_and_scan",
    "description": (
        "Detect the CMS in use and run specific vulnerability scanners. "
        "METHODOLOGY: First run 'cmseek' to identify the CMS. Then, based on the result, "
        "run the specific scanner ('wpscan' for WordPress, 'joomscan' for Joomla, 'droopescan' for Drupal)."
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
    print("CMS DETECT & SCAN — EXAMPLES")
    print("=" * 60)
    
    # 1. Step 1: Detect CMS with CMSeek
    r1 = cms_detect_and_scan(
        tool="cmseek",
        target="https://hackerone.com",
    )
    print("\n=== CMSEEK (CMS Detection) ===")
    print(f"Command: {r1['command']}")
    print(f"CMS Name:    {r1['cms_name']}")
    print(f"CMS Version: {r1['cms_version']}")

    # 2. Step 2: WordPress Scan
    r2 = cms_detect_and_scan(
        tool="wpscan",
        target="https://example.com",
        args=["-e", "vp,vt,u"]
    )
    print("\n=== WPSCAN (WordPress Enum) ===")
    print(f"Command: {r2['command']}")
    print(f"Version: {r2['cms_version']}")
    print(f"Plugins Found: {len([c for c in r2['components'] if c['type'] == 'plugin'])}")
    print(f"Users Found:   {len(r2['users'])}")
    for user in r2['users']:
        print(f"  - {user}")

    # 3. Full JSON Output
    print("\n=== FULL JSON PAYLOAD (WPScan) ===")
    print(json.dumps(r2, indent=2))
