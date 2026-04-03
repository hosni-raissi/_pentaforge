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


def _target_in_args(target: str, args: list[str], flags: list[str]) -> bool:
    """Universal check for target duplication"""
    if not args: return False
    target_clean = target.strip().lower()
    target_stripped = re.sub(r"^\w+://", "", target_clean).split('/')[0]
    
    for i, arg in enumerate(args):
        arg_lower = arg.strip().lower()
        arg_stripped = re.sub(r"^\w+://", "", arg_lower).split('/')[0]
        
        if arg_lower == target_clean or arg_stripped == target_stripped: return True
        if target_stripped in arg_lower: return True
        if arg_lower in flags and i + 1 < len(args):
            next_arg = args[i + 1].strip().lower()
            next_stripped = re.sub(r"^\w+://", "", next_arg).split('/')[0]
            if next_stripped == target_stripped: return True
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

class HttpProbeRequest(BaseModel):
    target: Optional[str] = None
    target_list: Optional[list[str]] = None
    args: list[str] = []
    timeout: int = Field(default=600, ge=10, le=3600)

    @validator("args")
    def validate_args(cls, v):
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg")
        return v

    @validator("target_list")
    def validate_list(cls, v):
        if v and len(v) > 100000:
            raise ValueError("Target list too large. Max 100,000 targets.")
        return v


class ProbedHost(BaseModel):
    url: str
    status_code: int
    title: Optional[str] = None
    webserver: Optional[str] = None
    tech: list[str] = []
    content_length: int = 0
    response_time: Optional[str] = None


class HttpProbeResult(BaseModel):
    success: bool
    command: str
    working_dir: str
    total_alive: int = 0
    hosts: list[ProbedHost] = []
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def http_probe(
    target: Optional[str] = None,
    target_list: Optional[list[str]] = None,
    args: list[str] = []
) -> dict:
    """
    🔧 Agent Tool: HTTP Probe (httpx)
    
    Takes a single target or a massive list of subdomains and checks which ones 
    are actively serving HTTP/HTTPS. Returns status codes, titles, web servers, 
    and technology stacks.
    
    Args:
        target:       Single domain/IP (e.g. "example.com")
        target_list:  List of domains/IPs (e.g. ["a.com", "b.com"])
        args:         Raw httpx arguments
        
    Returns:
        Structured JSON with alive hosts and their metadata.
    """
    start = time.time()
    
    if not target and not target_list:
        return HttpProbeResult(
            success=False, command="", working_dir="", 
            error="Must provide either 'target' or 'target_list'"
        ).model_dump()

    # ── VALIDATE ──
    try:
        req = HttpProbeRequest(target=target, target_list=target_list, args=args)
    except Exception as e:
        return HttpProbeResult(
            success=False, command="", working_dir="", error=f"Validation: {e}"
        ).model_dump()

    # ── BUILD COMMAND ──
    cmd = ["httpx"]
    final_args = list(req.args)

    # Force JSON and silent output for clean parsing
    if "-json" not in final_args: final_args.append("-json")
    if "-silent" not in final_args: final_args.append("-silent")
    
    # Ensure we grab useful metadata if the agent didn't specifically ask
    if "-title" not in final_args: final_args.append("-title")
    if "-tech-detect" not in final_args: final_args.append("-tech-detect")
    if "-status-code" not in final_args: final_args.append("-status-code")
    if "-cl" not in final_args: final_args.append("-cl") # Content Length

    tmp_file = None
    
    # Handle target list vs single target
    if req.target_list:
        # Write massive list to temp file in project dir
        tmp_file = ProjectConfig.get_temp_dir() / f"httpx_probe_{int(time.time())}.txt"
        tmp_file.write_text("\n".join(req.target_list))
        
        # Inject -l list flag if not present
        if "-l" not in final_args and "-list" not in final_args:
            final_args.extend(["-l", str(tmp_file)])
            
    elif req.target:
        # Prevent target duplication
        if not _target_in_args(req.target, final_args, ["-u", "-target"]):
            final_args.append(req.target)

    cmd.extend(final_args)
    
    # ── EXECUTE ──
    command_str = " ".join(cmd)
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)
    
    # Cleanup temp file securely
    if tmp_file:
        try: tmp_file.unlink()
        except OSError: pass

    # ── PARSE ──
    alive_hosts = []
    
    for line in stdout.split("\n"):
        if not line.strip(): 
            continue
        try:
            data = json.loads(line)
            
            # Clean up technologies array (remove version tags for brevity if desired, or keep as is)
            tech_raw = data.get("technologies", [])
            tech_clean = [str(t) for t in tech_raw] 

            alive_hosts.append(ProbedHost(
                url=data.get("url", ""),
                status_code=data.get("status_code", 0),
                title=data.get("title", ""),
                webserver=data.get("webserver", ""),
                tech=tech_clean,
                content_length=data.get("content_length", 0),
                response_time=data.get("time", "")
            ))
        except json.JSONDecodeError:
            pass

    # ── RETURN ──
    return HttpProbeResult(
        success=len(alive_hosts) > 0 or rc == 0,
        command=command_str,
        working_dir=cwd,
        total_alive=len(alive_hosts),
        hosts=alive_hosts,
        error=stderr if rc != 0 and not alive_hosts else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 4. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

HTTP_PROBE_TOOL_DEFINITION = {
    "name": "http_probe",
    "description": (
        "Filter a massive list of domains/subdomains to find which ones have live HTTP/HTTPS servers. "
        "Uses httpx. Returns status codes, page titles, response sizes, technologies, and web servers."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Single target domain or IP (optional if target_list is used)"
            },
            "target_list": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Array of domains/subdomains to probe. e.g. ['admin.site.com', 'api.site.com']"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw httpx args. (e.g. ['-p', '80,443,8080,8443', '-follow-redirects', '-random-agent'])"
            }
        }
    }
}


# ══════════════════════════════════════════════════════════════
# 5. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("=" * 60)
    print("HTTP PROBE (httpx) — EXAMPLES")
    print("=" * 60)
    
    # ─────────────────────────────
    # Example 1: Probe a list of subdomains
    # ─────────────────────────────
    subdomains_to_check = [
        "hackerone.com", 
        "api.hackerone.com", 
        "this-subdomain-does-not-exist.hackerone.com", 
        "docs.hackerone.com"
    ]
    
    r1 = http_probe(
        target_list=subdomains_to_check,
        args=["-p", "80,443", "-follow-redirects"]
    )
    print("\n=== PROBING LIST OF SUBDOMAINS ===")
    print(f"Command: {r1['command']}")
    print(f"Alive Hosts found: {r1['total_alive']}")
    for host in r1['hosts']:
        print(f"\n[{host['status_code']}] {host['url']}")
        print(f"  Title:  {host['title']}")
        print(f"  Server: {host['webserver']}")
        print(f"  Tech:   {', '.join(host['tech'][:3])}{'...' if len(host['tech']) > 3 else ''}")
        print(f"  Size:   {host['content_length']} bytes")

    # ─────────────────────────────
    # Example 2: Probe a single target with custom ports
    # ─────────────────────────────
    r2 = http_probe(
        target="scanme.nmap.org",
        args=["-p", "80,443,8080", "-threads", "50"]
    )
    print("\n=== PROBING SINGLE TARGET ===")
    print(f"Command: {r2['command']}")
    print(f"Alive Hosts found: {r2['total_alive']}")
    for host in r2['hosts']:
        print(f"[{host['status_code']}] {host['url']} - {host['title']}")

    # ─────────────────────────────
    # Example 3: Full JSON Output
    # ─────────────────────────────
    print("\n=== FULL JSON PAYLOAD ===")
    print(json.dumps(r1, indent=2))