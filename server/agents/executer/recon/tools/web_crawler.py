import subprocess
import json
import re
import os
import time
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
    def get_output_dir(cls) -> Path:
        path = cls.get_project_dir() / cls.OUTPUT_DIR
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


def safe_execute(cmd: list[str], timeout: int = 600, stdin_data: Optional[str] = None) -> tuple[str, str, int, str]:
    """Execute safely in project dir, optionally passing data to stdin"""
    cwd = ProjectConfig.get_project_dir()
    try:
        res = subprocess.run(
            cmd, 
            input=stdin_data,
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
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class WebCrawlerRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=900, ge=10, le=3600)
    max_results: int = Field(default=500, description="Max URLs returned to LLM to prevent context limit errors")

    @validator("tool")
    def validate_tool(cls, v):
        if v not in {"katana", "gospider", "hakrawler"}: 
            raise ValueError("Tool must be 'katana', 'gospider', or 'hakrawler'")
        return v

    @validator("target")
    def validate_target(cls, v):
        if not v.startswith("http"): 
            raise ValueError("Target must be a valid URL starting with http:// or https://")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg")
        return v


class WebCrawlerResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str
    
    total_found: int = 0
    urls: list[str] = []
    
    # Context protection metadata
    truncated: bool = False
    full_output_file: Optional[str] = None
    
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_katana_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["katana"]
    final_args = list(args)

    # Force JSON output for clean parsing
    if not _has_flag(final_args, ["-json"]):
        final_args.append("-json")
    if not _has_flag(final_args, ["-silent"]):
        final_args.append("-silent")

    # Add target if not present
    if not _target_in_args(target, final_args, ["-u", "-list"]):
        final_args.extend(["-u", target])

    cmd.extend(final_args)
    return cmd


def _build_gospider_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["gospider"]
    final_args = list(args)

    # Quiet mode to reduce terminal garbage
    if not _has_flag(final_args, ["-q", "--quiet"]):
        final_args.append("-q")

    # Add target if not present
    if not _target_in_args(target, final_args, ["-s", "--site", "-S", "--sites"]):
        final_args.extend(["-s", target])

    cmd.extend(final_args)
    return cmd


def _build_hakrawler_cmd(args: list[str]) -> list[str]:
    """Hakrawler takes the target via stdin (echo target | hakrawler)"""
    cmd = ["hakrawler"]
    final_args = list(args)

    # Use plain output to easily parse URLs
    if not _has_flag(final_args, ["-plain"]):
        final_args.append("-plain")

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_katana(stdout: str) -> list[str]:
    urls = set()
    for line in stdout.split("\n"):
        if not line.strip(): continue
        try:
            data = json.loads(line)
            req = data.get("request", {})
            endpoint = req.get("endpoint")
            if endpoint:
                urls.add(endpoint)
        except json.JSONDecodeError:
            pass
    return sorted(list(urls))


def parse_gospider(stdout: str) -> list[str]:
    urls = set()
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or "Out of scope" in line: 
            continue
        
        # GoSpider format: [source] - [method] - URL   OR   [source] - URL
        parts = line.split(" - ")
        if len(parts) >= 2:
            url = parts[-1].strip()
            if url.startswith("http"):
                urls.add(url)
    return sorted(list(urls))


def parse_hakrawler(stdout: str) -> list[str]:
    urls = set()
    for line in stdout.split("\n"):
        line = line.strip()
        if line.startswith("http"):
            urls.add(line)
    return sorted(list(urls))


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def web_crawler(tool: str, target: str, args: list[str] = [], max_results: int = 500) -> dict:
    """
    🔧 Agent Tool: Web Crawler & Spider
    
    Crawls a target URL to discover endpoints, files, JS assets, and parameters.
    Automatically handles context-window protection by saving massive results to a file 
    and returning a truncated preview to the LLM.
    """
    start = time.time()
    
    try:
        req = WebCrawlerRequest(tool=tool, target=target, args=args, max_results=max_results)
    except Exception as e:
        return WebCrawlerResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    # ── BUILD COMMAND ──
    stdin_data = None
    if tool == "katana":
        cmd = _build_katana_cmd(args, target)
    elif tool == "gospider":
        cmd = _build_gospider_cmd(args, target)
    elif tool == "hakrawler":
        cmd = _build_hakrawler_cmd(args)
        stdin_data = target  # Hakrawler consumes the target via stdin

    command_str = " ".join(cmd)
    if tool == "hakrawler":
        command_str = f"echo '{target}' | {command_str}"

    # ── EXECUTE ──
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout, stdin_data=stdin_data)

    # ── PARSE ──
    urls = []
    if tool == "katana":
        urls = parse_katana(stdout)
    elif tool == "gospider":
        urls = parse_gospider(stdout)
    elif tool == "hakrawler":
        urls = parse_hakrawler(stdout)

    total_found = len(urls)
    truncated = False
    full_output_file = None

    # ── CONTEXT PROTECTION & FILE SAVING ──
    if total_found > 0:
        # Save FULL list to file
        safe_domain = target.replace("https://", "").replace("http://", "").replace("/", "_")
        output_path = ProjectConfig.get_output_dir() / f"crawl_{tool}_{safe_domain}_{int(time.time())}.txt"
        
        try:
            output_path.write_text("\n".join(urls))
            full_output_file = str(output_path)
        except Exception:
            pass

        # Truncate for LLM JSON response
        if total_found > req.max_results:
            urls = urls[:req.max_results]
            truncated = True

    # ── RETURN ──
    return WebCrawlerResult(
        success=rc == 0 or total_found > 0,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        total_found=total_found,
        urls=urls,
        truncated=truncated,
        full_output_file=full_output_file,
        error=stderr if rc != 0 and total_found == 0 else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

WEB_CRAWLER_TOOL_DEFINITION = {
    "name": "web_crawler",
    "description": (
        "Crawl and spider a web application to discover endpoints, API routes, JavaScript files, and forms. "
        "Supports katana (fast, headless browser support), gospider (robust extraction), and hakrawler. "
        "Automatically saves massive outputs to a file to protect your context window."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["katana", "gospider", "hakrawler"],
                "description": "katana (modern, fast) | gospider (great for JS scraping) | hakrawler (simple)"
            },
            "target": {
                "type": "string",
                "description": "Target URL (e.g. 'https://example.com')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw args. Katana: ['-d', '3', '-jc'] | GoSpider: ['-d', '2', '-a']"
            },
            "max_results": {
                "type": "integer",
                "description": "Max URLs to return in JSON. Full list is ALWAYS saved to a file. (Default: 500)"
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
    print("WEB CRAWLER — EXAMPLES")
    print("=" * 60)
    
    # 1. Katana (Depth 2, JavaScript Parsing)
    r1 = web_crawler(
        tool="katana",
        target="https://hackerone.com",
        args=["-d", "2", "-jc"], # depth 2, parse JS context
        max_results=5
    )
    print("\n=== KATANA ===")
    print(f"Command: {r1['command']}")
    print(f"Total Found: {r1['total_found']}")
    print(f"Truncated for LLM: {r1['truncated']}")
    print(f"Full List Saved To: {r1['full_output_file']}")
    print("Preview of first 5 URLs:")
    for u in r1['urls']:
        print(f"  - {u}")

    # 2. GoSpider (Extract Other Sources)
    r2 = web_crawler(
        tool="gospider",
        target="https://hackerone.com",
        args=["-d", "1", "-a"], # depth 1, find other sources
        max_results=3
    )
    print("\n=== GOSPIDER ===")
    print(f"Command: {r2['command']}")
    print(f"Total Found: {r2['total_found']}")
    print("Preview:")
    for u in r2['urls']:
        print(f"  - {u}")

    # 3. Hakrawler (Standard depth)
    r3 = web_crawler(
        tool="hakrawler",
        target="https://hackerone.com",
        args=["-d", "2"],
        max_results=3
    )
    print("\n=== HAKRAWLER ===")
    print(f"Command: {r3['command']}")
    print(f"Total Found: {r3['total_found']}")
    print("Preview:")
    for u in r3['urls']:
        print(f"  - {u}")