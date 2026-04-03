import subprocess
import json
import re
import os
import time
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION & UTILITIES
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    _project_dir: Optional[Path] = None
    WORDLISTS_DIR = "wordlists"
    OUTPUT_DIR = "output"
    TEMP_DIR = "tmp"
    
    @classmethod
    def get_project_dir(cls) -> Path:
        if cls._project_dir:
            return cls._project_dir
        env_dir = os.environ.get("AGENT_PROJECT_DIR")
        if env_dir and os.path.isdir(env_dir):
            cls._project_dir = Path(env_dir)
            return cls._project_dir
        
        current = Path(__file__).resolve().parent
        markers = ["pyproject.toml", "setup.py", ".git"]
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

    @classmethod
    def get_wordlists_dir(cls) -> Path:
        return cls.get_project_dir() / cls.WORDLISTS_DIR


def _target_in_args(target: str, args: list[str], flags: list[str]) -> bool:
    """Universal check for target duplication"""
    if not args: return False
    target_clean = target.strip().lower()
    
    for i, arg in enumerate(args):
        arg_lower = arg.strip().lower()
        if arg_lower == target_clean: return True
        if target_clean in arg_lower: return True
        if arg_lower in flags and i + 1 < len(args):
            if args[i + 1].strip().lower() == target_clean: return True
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

class SubdomainRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    
    # ── Well-Known Probing ──
    probe_well_known: bool = False
    well_known_paths: list[str] = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/crossdomain.xml"]
    
    # ── Puredns Wordlists ──
    list_type: str = "mine"
    subdomain_wordlist: Optional[list[str]] = None
    builtin_subdomain_list: Optional[str] = None
    timeout: int = Field(default=900, ge=30, le=3600)

    @validator("tool")
    def val_tool(cls, v):
        allowed = {"subfinder", "amass", "crtsh", "puredns"}
        if v not in allowed: raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def val_target(cls, v):
        if v.startswith("http"): raise ValueError("Target must be a domain (example.com), not a URL")
        return v.strip().lower()

    @validator("args")
    def val_args(cls, v):
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg")
        return v


class WellKnownFile(BaseModel):
    url: str
    status_code: int
    content_length: int
    content_type: Optional[str] = None
    title: Optional[str] = None


class SubdomainResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_subdomains: int = 0
    subdomains: list[str] = []
    
    # ── Well-Known Probing Results ──
    probed_well_known: bool = False
    well_known_files: list[WellKnownFile] = []
    
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. CORE SUBDOMAIN ENUMERATION TOOLS
# ══════════════════════════════════════════════════════════════

def run_crtsh(target: str) -> tuple[list[str], str]:
    """Passive fast enum via crt.sh API (No binary needed)"""
    subs = set()
    url = f"https://crt.sh/?q=%.{target}&output=json"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    clean_sub = sub.strip().replace("*.", "").lower()
                    if clean_sub.endswith(target):
                        subs.add(clean_sub)
        return list(subs), ""
    except Exception as e:
        return [], f"crt.sh API error: {e}"


def run_cli_tool(tool: str, target: str, args: list[str], timeout: int) -> tuple[list[str], str, str]:
    """Run subfinder, amass, or puredns and parse subdomains"""
    cmd = [tool]
    final_args = list(args)
    
    # ── Tool-specific Arg Injection (with target-dupe fix) ──
    if tool == "subfinder":
        if not _target_in_args(target, final_args, ["-d", "-domain"]):
            final_args.extend(["-d", target])
        if "-silent" not in final_args: final_args.append("-silent")
        if "-all" not in final_args: final_args.append("-all")

    elif tool == "amass":
        if "enum" not in final_args and "intel" not in final_args:
            final_args.insert(0, "enum")
        if not _target_in_args(target, final_args, ["-d", "-domain"]):
            final_args.extend(["-d", target])
        if "-nocolor" not in final_args: final_args.append("-nocolor")

    elif tool == "puredns":
        is_brute = "bruteforce" in final_args or "brute" in final_args
        if is_brute and not _target_in_args(target, final_args, ["-d"]):
            final_args.append(target)
        if "--quiet" not in final_args: final_args.append("--quiet")

    cmd.extend(final_args)
    
    # Execute
    stdout, stderr, rc, _ = safe_execute(cmd, timeout)
    
    # Parse output (all tools output one subdomain per line in silent/quiet mode)
    subs = set()
    for line in stdout.split("\n"):
        line = line.strip().lower()
        if target in line and " " not in line and not line.startswith("["):
            subs.add(line)
            
    # Amass sometimes prints to stderr or specific formats, extract purely by regex fallback
    if tool == "amass" and not subs:
        pattern = r"([a-zA-Z0-9\-\.]+\." + re.escape(target) + r")"
        for match in re.finditer(pattern, stdout + stderr):
            subs.add(match.group(1).lower())

    return list(subs), " ".join(cmd), stderr if rc != 0 and not subs else ""


# ══════════════════════════════════════════════════════════════
# 4. HTTPX WELL-KNOWN PROBER
# ══════════════════════════════════════════════════════════════

def probe_well_known_files(subdomains: list[str], paths: list[str]) -> list[WellKnownFile]:
    """
    Takes discovered subdomains and uses httpx to look for robots.txt, sitemap.xml, etc.
    """
    if not subdomains or not paths:
        return []

    # 1. Write subdomains to temp file
    temp_dir = ProjectConfig.get_temp_dir()
    subs_file = temp_dir / f"subs_to_probe_{int(time.time())}.txt"
    subs_file.write_text("\n".join(subdomains))

    # 2. Build httpx command
    paths_joined = ",".join(paths)
    cmd = [
        "httpx",
        "-l", str(subs_file),
        "-path", paths_joined,
        "-mc", "200",               # Only match HTTP 200 OK
        "-silent", "-json"          # JSON output for easy parsing
    ]

    # 3. Execute
    stdout, _, _, _ = safe_execute(cmd, timeout=300)
    
    # 4. Parse JSON results
    found_files = []
    for line in stdout.split("\n"):
        if not line.strip(): continue
        try:
            data = json.loads(line)
            found_files.append(WellKnownFile(
                url=data.get("url", ""),
                status_code=data.get("status_code", 200),
                content_length=data.get("content_length", 0),
                content_type=data.get("content_type", ""),
                title=data.get("title", "")
            ))
        except json.JSONDecodeError:
            pass

    # Cleanup temp file
    try: subs_file.unlink()
    except OSError: pass

    return found_files


# ══════════════════════════════════════════════════════════════
# 5. MAIN AGENT TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def subdomain_enum(
    tool: str,
    target: str,
    args: list[str] = [],
    probe_well_known: bool = False,
    well_known_paths: list[str] = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"],
    list_type: str = "mine",
    subdomain_wordlist: Optional[list[str]] = None,
    builtin_subdomain_list: Optional[str] = None,
) -> dict:
    """
    🔧 Agent Tool: Subdomain Enumeration + Well-Known File Probing

    Discovers subdomains passively or actively.
    Optionally probes all discovered subdomains for sensitive files (robots.txt, etc).
    """
    start = time.time()
    
    try:
        req = SubdomainRequest(
            tool=tool, target=target, args=args,
            probe_well_known=probe_well_known, well_known_paths=well_known_paths,
            list_type=list_type, subdomain_wordlist=subdomain_wordlist, 
            builtin_subdomain_list=builtin_subdomain_list
        )
    except Exception as e:
        return SubdomainResult(success=False, tool=tool, target=target, command="", error=f"Validation: {e}").model_dump()

    subdomains = []
    command_str = ""
    error = ""

    # ── 1. Execute Subdomain Enum ──
    if tool == "crtsh":
        command_str = f"GET https://crt.sh/?q=%.{target}&output=json"
        subdomains, error = run_crtsh(target)
    
    else:
        # If puredns bruteforce, handle wordlist injection
        if tool == "puredns" and ("bruteforce" in args or "brute" in args):
            wl_path = None
            if list_type == "mine" and builtin_subdomain_list:
                wl_path = ProjectConfig.get_wordlists_dir() / "dns" / f"{builtin_subdomain_list}.txt"
            elif list_type == "yours" and subdomain_wordlist:
                tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, dir=ProjectConfig.get_temp_dir())
                tmp.write("\n".join(subdomain_wordlist))
                tmp.close()
                wl_path = tmp.name
                
            if wl_path and str(wl_path) not in args:
                args.insert(1, str(wl_path)) # puredns bruteforce <wordlist> <domain>
                
        subdomains, command_str, error = run_cli_tool(tool, target, args, req.timeout)

    # Clean and deduplicate
    subdomains = list(set([s.strip().lower() for s in subdomains if s.strip()]))

    # ── 2. Probe Well-Known Files (Robots.txt, Sitemap) ──
    well_known_files = []
    if probe_well_known and subdomains:
        well_known_files = probe_well_known_files(subdomains, well_known_paths)

    return SubdomainResult(
        success=len(subdomains) > 0,
        tool=tool,
        target=target,
        command=command_str,
        total_subdomains=len(subdomains),
        subdomains=sorted(subdomains),
        probed_well_known=probe_well_known,
        well_known_files=well_known_files,
        error=error if not subdomains else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

SUBDOMAIN_ENUM_TOOL_DEFINITION = {
    "name": "subdomain_enum",
    "description": (
        "Discover subdomains using passive (subfinder, crtsh) or active (amass, puredns) techniques. "
        "Also features a 'probe_well_known' flag to automatically hunt for robots.txt, sitemap.xml, "
        "and security.txt on all discovered subdomains."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["subfinder", "amass", "crtsh", "puredns"],
                "description": "subfinder (fast passive) | crtsh (API passive) | amass (thorough) | puredns (bruteforce)"
            },
            "target": {
                "type": "string",
                "description": "Target domain (e.g. 'example.com')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tool args (e.g. ['-all'] for subfinder, or ['enum', '-passive'] for amass)"
            },
            "probe_well_known": {
                "type": "boolean",
                "description": "Set to TRUE to use httpx to check for robots.txt, sitemap.xml, etc. on discovered subdomains."
            },
            "well_known_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Custom paths to probe (Default: ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt'])"
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # 1. Fast Passive Enum via subfinder (plus hunt for robots.txt)
    r1 = subdomain_enum(
        tool="subfinder",
        target="hackerone.com",
        args=["-all"],
        probe_well_known=True  # <--- THIS FINDS ROBOTS.TXT
    )
    print("=== SUBFINDER + ROBOTS.TXT PROBING ===")
    print(f"Total Subs: {r1['total_subdomains']}")
    for f in r1['well_known_files']:
        print(f"Found File: {f['url']} (Status: {f['status_code']})")

    # 2. Instant API lookup via crt.sh (no binaries needed)
    r2 = subdomain_enum(
        tool="crtsh",
        target="hackerone.com"
    )
    print("\n=== CRT.SH API ===")
    print(f"Total Subs: {r2['total_subdomains']}")
    print(f"Sample: {r2['subdomains'][:3]}")