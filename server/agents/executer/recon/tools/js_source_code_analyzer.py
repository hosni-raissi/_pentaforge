import subprocess
import json
import re
import os
import time
import tempfile
import urllib.request
import ssl
from pathlib import Path
from typing import Optional, Any
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


def safe_execute(cmd: list[str], timeout: int = 300) -> tuple[str, str, int, str]:
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


def download_file(url: str) -> Optional[Path]:
    """Download a JS file to a temp file for tools that only support local files"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            content = response.read()
            
        tmp_file = ProjectConfig.get_temp_dir() / f"js_dl_{int(time.time())}.js"
        tmp_file.write_bytes(content)
        return tmp_file
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class JsAnalyzerRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=300, ge=10, le=1200)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        if v not in {"getjs", "linkfinder", "secretfinder", "js-beautify"}: 
            raise ValueError("Tool must be 'getjs', 'linkfinder', 'secretfinder', or 'js-beautify'")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        clean_v = re.sub(r"^\w+://", "", v.strip()).split('/')[0]
        if clean_v in blocked:
            raise ValueError(f"Target '{v}' is blocked")
        return v.strip()


class Secret(BaseModel):
    name: str
    value: str


class JsAnalyzerResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str
    
    js_urls: list[str] = []                # from getjs
    endpoints: list[str] = []              # from linkfinder
    secrets: list[Secret] = []             # from secretfinder
    beautified_code: Optional[str] = None  # from js-beautify
    
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_getjs_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["getJS"]
    final_args = list(args)

    target_url = target if target.startswith("http") else f"https://{target}"
    
    if not _target_in_args(target_url, final_args, ["-url", "--url", "-input"]):
        final_args.extend(["-url", target_url])
        
    if not _has_flag(final_args, ["-complete"]):
        final_args.append("-complete")  # Outputs full URLs instead of relative
        
    cmd.extend(final_args)
    return cmd


def _build_linkfinder_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["linkfinder"]  # Assuming aliased or in PATH
    final_args = list(args)

    target_url = target if target.startswith("http") else f"https://{target}"

    if not _target_in_args(target_url, final_args, ["-i", "--input"]):
        final_args.extend(["-i", target_url])
        
    if not _has_flag(final_args, ["-o", "--output"]):
        final_args.extend(["-o", "cli"]) # Force CLI output for parsing
        
    cmd.extend(final_args)
    return cmd


def _build_secretfinder_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["secretfinder"] # Assuming aliased or in PATH
    final_args = list(args)

    target_url = target if target.startswith("http") else f"https://{target}"

    if not _target_in_args(target_url, final_args, ["-i", "--input"]):
        final_args.extend(["-i", target_url])
        
    if not _has_flag(final_args, ["-o", "--output"]):
        final_args.extend(["-o", "cli"]) # Force CLI output for parsing
        
    cmd.extend(final_args)
    return cmd


def _build_jsbeautify_cmd(args: list[str], target: str) -> tuple[list[str], Optional[Path]]:
    cmd = ["js-beautify"]
    final_args = list(args)
    
    tmp_file = None
    
    # js-beautify operates on local files. Download URL first.
    if target.startswith("http"):
        tmp_file = download_file(target)
        if tmp_file:
            final_args.append(str(tmp_file))
    else:
        if not _target_in_args(target, final_args, ["-f", "--file"]):
            final_args.append(target)
            
    cmd.extend(final_args)
    return cmd, tmp_file


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_getjs(stdout: str) -> list[str]:
    urls = []
    for line in stdout.split("\n"):
        line = line.strip()
        if line.startswith("http"):
            urls.append(line)
    return list(set(urls))


def parse_linkfinder(stdout: str) -> list[str]:
    endpoints = []
    # Linkfinder prints a bunch of text, but endpoints usually start with / or http
    # We strip out the banner and keep the actual paths
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or line.startswith("Running against") or line.startswith("LinkFinder") or "ERROR:" in line:
            continue
        # If it looks like a valid path or URL
        if line.startswith("/") or line.startswith("http") or re.match(r"^[\w\-]+\.(php|html|js|json|xml)", line):
            endpoints.append(line)
    return list(set(endpoints))


def parse_secretfinder(stdout: str) -> list[Secret]:
    secrets = []
    # Secretfinder outputs like: [+] Google API Key: AIzaSy...
    pattern = r"^\[\+\]\s+(.+?):\s+(.+)$"
    
    for line in stdout.split("\n"):
        line = line.strip()
        match = re.match(pattern, line)
        if match:
            secrets.append(Secret(
                name=match.group(1).strip(),
                value=match.group(2).strip()
            ))
            
    # Deduplicate secrets
    seen = set()
    unique_secrets = []
    for s in secrets:
        identifier = f"{s.name}:{s.value}"
        if identifier not in seen:
            seen.add(identifier)
            unique_secrets.append(s)
            
    return unique_secrets


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def js_source_code_analyzer(tool: str, target: str, args: list[str] = []) -> dict:
    """
    🔧 Agent Tool: JS Source Code Analyzer
    
    Collect JS files from a web page (getjs), extract endpoints (linkfinder), 
    find API keys/secrets (secretfinder), or unminify code (js-beautify).
    """
    start = time.time()
    
    try:
        req = JsAnalyzerRequest(tool=tool, target=target, args=args)
    except Exception as e:
        return JsAnalyzerResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    # ── BUILD COMMAND ──
    tmp_file = None
    if tool == "getjs":
        cmd = _build_getjs_cmd(args, target)
    elif tool == "linkfinder":
        cmd = _build_linkfinder_cmd(args, target)
    elif tool == "secretfinder":
        cmd = _build_secretfinder_cmd(args, target)
    elif tool == "js-beautify":
        cmd, tmp_file = _build_jsbeautify_cmd(args, target)
        if not tmp_file and target.startswith("http"):
            return JsAnalyzerResult(
                success=False, tool=tool, target=target, command="js-beautify", working_dir="", 
                error="Failed to download JS file for beautification"
            ).model_dump()

    command_str = " ".join(cmd)
    
    # ── EXECUTE ──
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)
    
    # Cleanup temp file if downloaded
    if tmp_file:
        try: tmp_file.unlink()
        except OSError: pass

    # ── PARSE ──
    js_urls = []
    endpoints = []
    secrets = []
    beautified_code = None

    if tool == "getjs":
        js_urls = parse_getjs(stdout)
    elif tool == "linkfinder":
        endpoints = parse_linkfinder(stdout)
    elif tool == "secretfinder":
        secrets = parse_secretfinder(stdout)
    elif tool == "js-beautify":
        # Truncate code to prevent blowing up the LLM context window (10,000 chars limit)
        if len(stdout) > 10000:
            beautified_code = stdout[:10000] + "\n\n... [TRUNCATED BY AGENT FOR CONTEXT LIMIT] ..."
        else:
            beautified_code = stdout

    # Determine success
    has_results = bool(js_urls or endpoints or secrets or beautified_code)

    return JsAnalyzerResult(
        success=rc == 0 or has_results,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        js_urls=js_urls,
        endpoints=endpoints,
        secrets=secrets,
        beautified_code=beautified_code,
        error=stderr if rc != 0 and not has_results else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

JS_ANALYZER_TOOL_DEFINITION = {
    "name": "js_source_code_analyzer",
    "description": (
        "Analyze JavaScript files. "
        "Use 'getjs' to collect all JS files from a URL. "
        "Use 'linkfinder' to extract hidden API endpoints from a JS file. "
        "Use 'secretfinder' to extract API keys/secrets from a JS file. "
        "Use 'js-beautify' to unminify obfuscated JS code."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["getjs", "linkfinder", "secretfinder", "js-beautify"],
                "description": "Select the specific JS analysis tool to run."
            },
            "target": {
                "type": "string",
                "description": "Target URL. For getjs: a webpage. For the others: a direct URL to a .js file."
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw args (Optional)."
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
    print("JS SOURCE CODE ANALYZER — EXAMPLES")
    print("=" * 60)
    
    # 1. GetJS — Find all JS files on a page
    r1 = js_source_code_analyzer(
        tool="getjs",
        target="https://hackerone.com",
    )
    print("\n=== GETJS (Extract JS URLs) ===")
    print(f"Command: {r1['command']}")
    print(f"Found {len(r1['js_urls'])} JS files.")
    for url in r1['js_urls'][:3]:
        print(f"  - {url}")

    # 2. LinkFinder — Extract endpoints from a JS file
    # (Using a hypothetical JS file that typically contains paths)
    r2 = js_source_code_analyzer(
        tool="linkfinder",
        target="https://hackerone.com/assets/core.js",
    )
    print("\n=== LINKFINDER (Extract Endpoints) ===")
    print(f"Command: {r2['command']}")
    print(f"Found {len(r2['endpoints'])} endpoints.")
    for ep in r2['endpoints'][:5]:
        print(f"  - {ep}")

    # 3. SecretFinder — Extract API Keys from a JS file
    r3 = js_source_code_analyzer(
        tool="secretfinder",
        target="https://hackerone.com/assets/core.js",
    )
    print("\n=== SECRETFINDER (Extract Keys) ===")
    print(f"Command: {r3['command']}")
    print(f"Found {len(r3['secrets'])} secrets.")
    for s in r3['secrets']:
        print(f"  - {s['name']}: {s['value']}")

    # 4. JS-Beautify — Unminify code
    r4 = js_source_code_analyzer(
        tool="js-beautify",
        target="https://hackerone.com/assets/core.js",
    )
    print("\n=== JS-BEAUTIFY (Unminify) ===")
    print(f"Command: {r4['command']}")
    if r4['beautified_code']:
        print(f"Successfully beautified code (Size: {len(r4['beautified_code'])} bytes).")
        print("Preview:")
        print(r4['beautified_code'][:200] + "...\n")