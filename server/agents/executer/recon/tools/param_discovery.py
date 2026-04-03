import subprocess
import json
import re
import os
import time
from pathlib import Path
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs
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

class ParamDiscoveryRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=900, ge=10, le=3600)

    @validator("tool")
    def validate_tool(cls, v):
        if v not in {"arjun", "paramspider", "x8"}: 
            raise ValueError("Tool must be 'arjun', 'paramspider', or 'x8'")
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
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg")
        return v


class EndpointParams(BaseModel):
    url: str
    method: str = "GET"
    parameters: list[str] = []


class ParamDiscoveryResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str
    
    total_parameters_found: int = 0
    endpoints: list[EndpointParams] = []
    
    # ParamSpider can output thousands of URLs. We save them to a file.
    full_urls_file: Optional[str] = None 
    
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_arjun_cmd(args: list[str], target: str) -> tuple[list[str], Path]:
    cmd = ["arjun"]
    final_args = list(args)

    tmp_file = ProjectConfig.get_temp_dir() / f"arjun_{int(time.time())}.json"
    
    if not _has_flag(final_args, ["-oJ"]):
        final_args.extend(["-oJ", str(tmp_file)])

    # Arjun needs a full URL
    target_url = target if target.startswith("http") else f"https://{target}"
    if not _target_in_args(target_url, final_args, ["-u"]):
        final_args.extend(["-u", target_url])

    cmd.extend(final_args)
    return cmd, tmp_file


def _build_x8_cmd(args: list[str], target: str) -> tuple[list[str], Path]:
    cmd = ["x8"]
    final_args = list(args)

    tmp_file = ProjectConfig.get_temp_dir() / f"x8_{int(time.time())}.json"
    
    if not _has_flag(final_args, ["-O", "--output-format"]):
        final_args.extend(["-O", "json"])
    if not _has_flag(final_args, ["-o", "--output"]):
        final_args.extend(["-o", str(tmp_file)])

    # x8 needs a full URL
    target_url = target if target.startswith("http") else f"https://{target}"
    if not _target_in_args(target_url, final_args, ["-u", "--url"]):
        final_args.extend(["-u", target_url])

    cmd.extend(final_args)
    return cmd, tmp_file


def _build_paramspider_cmd(args: list[str], target: str) -> tuple[list[str], Path]:
    cmd = ["paramspider"]
    final_args = list(args)

    # ParamSpider expects just the domain name, not a URL
    clean_domain = re.sub(r"^\w+://", "", target).split('/')[0]

    if not _target_in_args(clean_domain, final_args, ["-d", "--domain"]):
        final_args.extend(["-d", clean_domain])

    # Paramspider saves output to `results/{domain}.txt` in the current working directory
    # We will locate it during parsing
    expected_file = ProjectConfig.get_project_dir() / "results" / f"{clean_domain}.txt"

    cmd.extend(final_args)
    return cmd, expected_file


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_arjun(tmp_file: Path) -> list[EndpointParams]:
    """
    Arjun JSON Format:
    {
      "https://example.com/endpoint": {
        "GET": ["id", "page"],
        "POST": ["user"]
      }
    }
    """
    endpoints = []
    if not tmp_file.exists(): return endpoints

    try:
        data = json.loads(tmp_file.read_text())
        for url, methods in data.items():
            for method, params in methods.items():
                endpoints.append(EndpointParams(
                    url=url,
                    method=method.upper(),
                    parameters=params
                ))
    except Exception:
        pass
    finally:
        try: tmp_file.unlink()
        except OSError: pass

    return endpoints


def parse_x8(tmp_file: Path) -> list[EndpointParams]:
    """
    x8 JSON Format (usually an array of objects or single object):
    {
      "url": "https://example.com/",
      "params": ["id", "test"]
    }
    """
    endpoints = []
    if not tmp_file.exists(): return endpoints

    try:
        content = tmp_file.read_text()
        data = json.loads(content)
        
        # Handle both list and dict returns
        if isinstance(data, dict): data = [data]
        
        for item in data:
            url = item.get("url", "")
            params = item.get("params", [])
            if params:
                endpoints.append(EndpointParams(
                    url=url,
                    method="GET",  # x8 defaults to GET unless specified
                    parameters=params
                ))
    except Exception:
        pass
    finally:
        try: tmp_file.unlink()
        except OSError: pass

    return endpoints


def parse_paramspider(output_file: Path) -> tuple[list[EndpointParams], Optional[str]]:
    """
    ParamSpider saves a text file containing full URLs with parameters.
    Example: https://example.com/api?user=123&token=abc
    
    We parse this to extract unique parameter names for the LLM, 
    but preserve the file for the user.
    """
    endpoints = []
    file_path = None
    
    if not output_file.exists(): 
        return endpoints, file_path

    try:
        file_path = str(output_file)
        content = output_file.read_text().strip().split("\n")
        
        # Dictionary to group parameters by URL endpoint (without query string)
        grouped_params = {}

        for line in content:
            if not line.strip() or not line.startswith("http"): continue
            
            parsed_url = urlparse(line)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Extract query parameters
            query_params = parse_qs(parsed_url.query).keys()
            
            if base_url not in grouped_params:
                grouped_params[base_url] = set()
            
            for param in query_params:
                grouped_params[base_url].add(param)

        # Convert to schema
        for url, params in grouped_params.items():
            if params:
                endpoints.append(EndpointParams(
                    url=url,
                    method="GET",
                    parameters=list(params)
                ))
                
    except Exception:
        pass

    return endpoints, file_path


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def param_discovery(tool: str, target: str, args: list[str] = []) -> dict:
    """
    🔧 Agent Tool: Parameter Discovery
    
    Find hidden GET/POST/JSON parameters on endpoints using brute-force (arjun, x8) 
    or historical archive mining (paramspider).
    """
    start = time.time()
    
    try:
        req = ParamDiscoveryRequest(tool=tool, target=target, args=args)
    except Exception as e:
        return ParamDiscoveryResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    # ── BUILD COMMAND ──
    tmp_file = None
    if tool == "arjun":
        cmd, tmp_file = _build_arjun_cmd(args, target)
    elif tool == "x8":
        cmd, tmp_file = _build_x8_cmd(args, target)
    elif tool == "paramspider":
        cmd, tmp_file = _build_paramspider_cmd(args, target)

    command_str = " ".join(cmd)
    
    # ── EXECUTE ──
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)

    # ── PARSE ──
    endpoints = []
    full_urls_file = None

    if tool == "arjun":
        endpoints = parse_arjun(tmp_file)
    elif tool == "x8":
        endpoints = parse_x8(tmp_file)
    elif tool == "paramspider":
        endpoints, full_urls_file = parse_paramspider(tmp_file)

    # Count total parameters
    total_params = sum(len(ep.parameters) for ep in endpoints)

    return ParamDiscoveryResult(
        success=rc == 0 or total_params > 0,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        total_parameters_found=total_params,
        endpoints=endpoints,
        full_urls_file=full_urls_file,
        error=stderr if rc != 0 and total_params == 0 else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

PARAM_DISCOVERY_TOOL_DEFINITION = {
    "name": "param_discovery",
    "description": (
        "Discover hidden GET/POST parameters on web endpoints. "
        "Supports 'arjun' (Python, highly accurate), 'x8' (Rust, ultra-fast), "
        "and 'paramspider' (Mines Wayback Machine for historically used parameters across a whole domain)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["arjun", "x8", "paramspider"],
                "description": "arjun (brute-force single endpoint) | x8 (fast brute-force) | paramspider (mine archives for whole domain)"
            },
            "target": {
                "type": "string",
                "description": "Target URL (for arjun/x8) or Target Domain (for paramspider)."
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw args. Example Arjun: ['-m', 'GET,POST']"
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
    print("PARAMETER DISCOVERY — EXAMPLES")
    print("=" * 60)
    
    # 1. Arjun — Single endpoint GET/POST brute force
    r1 = param_discovery(
        tool="arjun",
        target="https://hackerone.com/endpoint",
        args=["-m", "GET,POST"]
    )
    print("\n=== ARJUN (Brute-Force Endpoint) ===")
    print(f"Command: {r1['command']}")
    print(f"Total Params Found: {r1['total_parameters_found']}")
    for ep in r1['endpoints']:
        print(f"  [{ep['method']}] {ep['url']} -> {', '.join(ep['parameters'])}")

    # 2. x8 — Ultra fast brute force
    r2 = param_discovery(
        tool="x8",
        target="https://hackerone.com/",
        args=[]
    )
    print("\n=== X8 (Fast Brute-Force) ===")
    print(f"Command: {r2['command']}")
    print(f"Total Params Found: {r2['total_parameters_found']}")

    # 3. ParamSpider — Mine Wayback Machine
    r3 = param_discovery(
        tool="paramspider",
        target="hackerone.com",
    )
    print("\n=== PARAMSPIDER (Archive Mining) ===")
    print(f"Command: {r3['command']}")
    print(f"Total Unique Params: {r3['total_parameters_found']}")
    print(f"Full URL Payload Saved to: {r3['full_urls_file']}")
    print("Preview of discovered parameters by endpoint:")
    for ep in r3['endpoints'][:3]:
        print(f"  {ep['url']} -> {', '.join(ep['parameters'][:5])} ...")

    # 4. Full JSON payload
    print("\n=== FULL JSON PAYLOAD ===")
    print(json.dumps(r1, indent=2))