import subprocess
import json
import re
import os
import time
import xml.etree.ElementTree as ET
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


def _target_in_args(target: str, args: list[str], flags: list[str] = []) -> bool:
    """Universal check for target duplication"""
    if not args: return False
    target_clean = target.strip().lower()
    target_stripped = re.sub(r"^\w+://", "", target_clean).split('/')[0]
    
    for i, arg in enumerate(args):
        arg_lower = arg.strip().lower()
        arg_stripped = re.sub(r"^\w+://", "", arg_lower).split('/')[0]
        
        if arg_lower == target_clean or arg_stripped == target_stripped: return True
        if target_stripped in arg_lower: return True
        if flags and arg_lower in flags and i + 1 < len(args):
            next_arg = args[i + 1].strip().lower()
            next_stripped = re.sub(r"^\w+://", "", next_arg).split('/')[0]
            if next_stripped == target_stripped: return True
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


def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int, str]:
    """Execute safely in project dir"""
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

class WafDetectRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=300, ge=10, le=1200)

    @validator("tool")
    def validate_tool(cls, v):
        if v not in {"wafw00f", "nmap"}: 
            raise ValueError("Tool must be 'wafw00f' or 'nmap'")
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
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}'")
        return v


class WafResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str = ""
    has_waf: bool = False
    waf_name: Optional[str] = None
    manufacturer: Optional[str] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_wafw00f_cmd(args: list[str], target: str) -> tuple[list[str], Path]:
    """Build wafw00f command, forcing JSON output to a temp file"""
    cmd = ["wafw00f"]
    final_args = list(args)
    
    # Temp file for JSON output (makes parsing 100x more reliable than regexing terminal colors)
    tmp_file = ProjectConfig.get_temp_dir() / f"wafw00f_{int(time.time())}.json"
    
    if not _has_flag(final_args, ["-o", "--output"]):
        final_args.extend(["-o", str(tmp_file), "-f", "json"])
        
    # wafw00f requires the protocol scheme
    clean_target = target if target.startswith("http") else f"https://{target}"
    
    if not _target_in_args(clean_target, final_args, ["-i", "--input"]):
        final_args.append(clean_target)

    cmd.extend(final_args)
    return cmd, tmp_file


def _build_nmap_cmd(args: list[str], target: str) -> list[str]:
    """Build nmap command for WAF detection"""
    cmd = ["nmap"]
    final_args = list(args)

    if not _has_flag_with_value(final_args, ["-p"]):
        final_args.extend(["-p", "80,443"])
        
    if not _has_flag_with_value(final_args, ["--script=", "--script"]):
        final_args.append("--script=http-waf-detect,http-waf-fingerprint")
        
    if not _has_flag_with_value(final_args, ["-oX"]):
        final_args.extend(["-oX", "-"])  # Output XML directly to stdout

    if not _target_in_args(target, final_args):
        final_args.append(target)

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_wafw00f(tmp_file: Path, stdout: str) -> tuple[bool, Optional[str], Optional[str]]:
    """Parse Wafw00f JSON output"""
    has_waf = False
    waf_name = None
    manufacturer = None

    parsed = False
    if tmp_file.exists():
        try:
            content = tmp_file.read_text()
            if content.strip():
                data = json.loads(content)
                # Wafw00f returns a list of results
                if isinstance(data, list) and len(data) > 0:
                    res = data[0]
                    has_waf = res.get("detected", False)
                    if has_waf:
                        waf_name = res.get("firewall", "Unknown WAF")
                        manufacturer = res.get("manufacturer", "Unknown")
            parsed = True
        except Exception:
            pass
        finally:
            try: tmp_file.unlink()
            except OSError: pass

    # Regex Fallback (if JSON parsing failed)
    if not parsed:
        if "is behind" in stdout:
            has_waf = True
            match = re.search(r"is behind (?:a |an )?(.*?)(?: WAF| Web Application)", stdout)
            if match:
                waf_name = match.group(1).strip()
                
    return has_waf, waf_name, manufacturer


def parse_nmap_waf(stdout: str) -> tuple[bool, Optional[str], Optional[str]]:
    """Parse Nmap XML output for WAF scripts"""
    has_waf = False
    waf_name = None
    manufacturer = None

    try:
        root = ET.fromstring(stdout)
        for script in root.findall(".//script"):
            s_id = script.get("id", "")
            output = script.get("output", "")
            
            if s_id in ["http-waf-detect", "http-waf-fingerprint"]:
                if "Detected" in output or "WAF" in output or "fingerprint" in output.lower():
                    has_waf = True
                    # Look for WAF name in output
                    match = re.search(r"(?:Detected WAF|Detected):\s*(.+)", output, re.IGNORECASE)
                    if match:
                        waf_name = match.group(1).strip()
                    else:
                        # Fallback: grab the first non-empty line that isn't just "Detected"
                        lines = [l.strip() for l in output.split("\n") if l.strip()]
                        for l in lines:
                            if "WAF" not in l and "Detected" not in l:
                                waf_name = l
                                break
                        if not waf_name and lines:
                            waf_name = lines[0]
    except ET.ParseError:
        # Fallback to pure regex on raw stdout
        if "http-waf-detect" in stdout and "WAF" in stdout:
            has_waf = True
            waf_name = "Detected via Nmap (Raw Regex)"

    return has_waf, waf_name, manufacturer


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def waf_detection(tool: str, target: str, args: list[str] = []) -> dict:
    """
    🔧 Agent Tool: WAF Detection
    
    Checks if target is protected by a Web Application Firewall (Cloudflare, Akamai, Imperva).
    
    Args:
        tool:   "wafw00f" | "nmap"
        target: Target domain or URL (e.g. "example.com" or "https://example.com")
        args:   Raw tool arguments
        
    Returns:
        Structured JSON with WAF detection status and firewall details.
    """
    start = time.time()
    
    # ── VALIDATE ──
    try:
        req = WafDetectRequest(tool=tool, target=target, args=args)
    except Exception as e:
        return WafResult(
            success=False, tool=tool, target=target, command="", error=f"Validation: {e}"
        ).model_dump()

    # ── BUILD COMMAND ──
    tmp_file = None
    if tool == "wafw00f":
        cmd, tmp_file = _build_wafw00f_cmd(args, target)
    elif tool == "nmap":
        cmd = _build_nmap_cmd(args, target)

    # ── EXECUTE ──
    command_str = " ".join(cmd)
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)
    
    # ── PARSE ──
    has_waf = False
    waf_name = None
    manufacturer = None

    if tool == "wafw00f":
        has_waf, waf_name, manufacturer = parse_wafw00f(tmp_file, stdout)
    elif tool == "nmap":
        has_waf, waf_name, manufacturer = parse_nmap_waf(stdout)

    # Clean up name strings (remove ANSI color codes if they leaked through)
    if waf_name:
        waf_name = re.sub(r"\x1b\[.*?m", "", waf_name).strip()
    if manufacturer:
        manufacturer = re.sub(r"\x1b\[.*?m", "", manufacturer).strip()

    # ── RETURN ──
    return WafResult(
        success=rc == 0 or has_waf,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        has_waf=has_waf,
        waf_name=waf_name,
        manufacturer=manufacturer,
        raw_output=(stdout or stderr)[:2000] if not has_waf else None, # Return raw output only if we couldn't confidently parse
        error=stderr if rc != 0 and not has_waf else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

WAF_DETECTION_TOOL_DEFINITION = {
    "name": "waf_detection",
    "description": (
        "Check if a target is protected by a Web Application Firewall (WAF) or IPS. "
        "Supports wafw00f (highly accurate fingerprinting) and nmap (script-based detection)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["wafw00f", "nmap"],
                "description": "wafw00f (recommended, deep fingerprinting) | nmap (http-waf-detect script)"
            },
            "target": {
                "type": "string",
                "description": "Target domain or URL (e.g. 'example.com' or 'https://example.com')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw args. Example: wafw00f: ['-a'] (test all). nmap: ['-p', '443']"
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
    print("WAF DETECTION — EXAMPLES")
    print("=" * 60)
    
    # ─────────────────────────────
    # Example 1: Wafw00f (Test All WAFs)
    # ─────────────────────────────
    r1 = waf_detection(
        tool="wafw00f",
        target="hackerone.com",
        args=["-a"]
    )
    print("\n=== WAFW00F ===")
    print(f"Command:      {r1['command']}")
    print(f"WAF Detected: {r1['has_waf']}")
    if r1['has_waf']:
        print(f"WAF Name:     {r1['waf_name']}")
        print(f"Manufacturer: {r1['manufacturer']}")

    # ─────────────────────────────
    # Example 2: Nmap WAF Script
    # ─────────────────────────────
    r2 = waf_detection(
        tool="nmap",
        target="hackerone.com",
        args=["-p", "443"]
    )
    print("\n=== NMAP WAF SCRIPT ===")
    print(f"Command:      {r2['command']}")
    print(f"WAF Detected: {r2['has_waf']}")
    if r2['has_waf']:
        print(f"WAF Info:     {r2['waf_name']}")

    # ─────────────────────────────
    # Example 3: Full JSON Payload
    # ─────────────────────────────
    print("\n=== FULL JSON PAYLOAD ===")
    print(json.dumps(r1, indent=2))