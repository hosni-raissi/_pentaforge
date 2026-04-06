#/+
import subprocess
import json
import re
import os
import time
from pathlib import Path
from urllib.parse import urlparse
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
    KATANA_TIMEOUT_SECONDS = 60
    
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


MAX_DEPTH = 5


def _extract_scope_from_target(target: str) -> str:
    host = (urlparse(target).hostname or "").strip().lower()
    if not host:
        raise ValueError("Could not derive scope from target URL")
    return host


def _extract_scope_from_args(args: list[str], target: str) -> tuple[list[str], str]:
    """Extract wrapper-level --scope argument and keep tool args clean."""
    clean_args: list[str] = []
    scope = ""

    i = 0
    while i < len(args):
        arg = args[i]

        if arg in {"--scope", "-scope"}:
            if i + 1 >= len(args):
                raise ValueError("Missing value for --scope")
            scope = args[i + 1].strip().lower()
            i += 2
            continue

        if arg.startswith("--scope="):
            scope = arg.split("=", 1)[1].strip().lower()
            i += 1
            continue

        clean_args.append(arg)
        i += 1

    if not scope:
        scope = _extract_scope_from_target(target)

    scope = scope.lstrip(".")
    if not scope:
        raise ValueError("Scope cannot be empty")

    return clean_args, scope


def _clamp_depth_args(args: list[str], max_depth: int = MAX_DEPTH) -> list[str]:
    """Clamp crawler depth flags to a safe upper bound."""
    clamped = list(args)
    depth_flags = {"-d", "--depth", "-depth"}

    i = 0
    while i < len(clamped):
        arg = clamped[i]

        if arg in depth_flags:
            if i + 1 >= len(clamped):
                raise ValueError("Missing value for depth flag")
            try:
                depth_val = int(clamped[i + 1])
            except ValueError as exc:
                raise ValueError("Depth must be an integer") from exc
            clamped[i + 1] = str(max(1, min(depth_val, max_depth)))
            i += 2
            continue

        if arg.startswith("--depth="):
            try:
                depth_val = int(arg.split("=", 1)[1])
            except ValueError as exc:
                raise ValueError("Depth must be an integer") from exc
            clamped[i] = f"--depth={max(1, min(depth_val, max_depth))}"

        i += 1

    return clamped


def _strip_katana_timeout_args(args: list[str]) -> list[str]:
    """Remove katana timeout flags so wrapper policy is always enforced."""
    cleaned: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]

        # Value in next token
        if arg in {"-ct", "-crawl-duration", "-timeout"}:
            i += 2 if i + 1 < len(args) else 1
            continue

        # Value in same token
        if arg.startswith("-timeout=") or arg.startswith("-crawl-duration="):
            i += 1
            continue

        cleaned.append(arg)
        i += 1

    return cleaned


def _url_is_in_scope(url: str, scope: str) -> bool:
    host = (urlparse(url).hostname or "").strip().lower()
    if not host:
        return False
    return host == scope or host.endswith(f".{scope}")


def _filter_urls_by_scope(urls: list[str], scope: str) -> tuple[list[str], int]:
    in_scope = [u for u in urls if _url_is_in_scope(u, scope)]
    return in_scope, len(urls) - len(in_scope)


_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _extract_urls_from_text(text: str) -> set[str]:
    urls: set[str] = set()
    for match in _URL_RE.findall(text or ""):
        cleaned = match.rstrip(".,);]")
        if cleaned.startswith("http"):
            urls.add(cleaned)
    return urls


def _extract_urls_from_json(value: Any) -> set[str]:
    urls: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for v in node.values():
                visit(v)
            return
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if isinstance(node, str) and node.startswith("http"):
            urls.add(node)

    visit(value)
    return urls


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
    except subprocess.TimeoutExpired as e:
        # Preserve partial output so parsers can still extract findings.
        out = e.stdout.decode("utf-8", errors="ignore") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode("utf-8", errors="ignore") if isinstance(e.stderr, bytes) else (e.stderr or "")
        timeout_msg = f"Timeout ({timeout}s)"
        err = f"{err}\n{timeout_msg}".strip() if err else timeout_msg
        return out, err, -1, str(cwd)
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
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=900, ge=10, le=3600)
    max_results: int = Field(default=500, description="Max URLs returned to LLM to prevent context limit errors")

    @field_validator("tool")
    def validate_tool(cls, v):
        if v not in {"katana", "gospider", "hakrawler"}: 
            raise ValueError("Tool must be 'katana', 'gospider', or 'hakrawler'")
        return v

    @field_validator("target")
    def validate_target(cls, v):
        if not v.startswith("http"): 
            raise ValueError("Target must be a valid URL starting with http:// or https://")
        return v.strip()

    @field_validator("args")
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
    urls: list[str] = Field(default_factory=list)
    scope: Optional[str] = None
    out_of_scope_filtered: int = 0
    
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
    final_args = _clamp_depth_args(_strip_katana_timeout_args(args))

    if not _has_flag(final_args, ["-silent"]):
        final_args.append("-silent")
    if not _has_flag(final_args, ["-jc"]):
        final_args.append("-jc")

    # Fixed katana timeout policy: always enforce crawl duration from config.
    final_args.extend(["-ct", f"{ProjectConfig.KATANA_TIMEOUT_SECONDS}s"])

    # Add target if not present
    if not _target_in_args(target, final_args, ["-u", "-list"]):
        final_args.extend(["-u", target])

    cmd.extend(final_args)
    return cmd


def _build_gospider_cmd(args: list[str], target: str) -> list[str]:
    cmd = ["gospider"]
    final_args = _clamp_depth_args(args)

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
    final_args = _clamp_depth_args(args)

    # Follow a stable baseline profile for hakrawler runs.
    if not _has_flag(final_args, ["-d", "--depth", "-depth"]):
        final_args.extend(["-d", "3"])
    if not _has_flag(final_args, ["-t"]):
        final_args.extend(["-t", "30"])
    if not _has_flag(final_args, ["-subs"]):
        final_args.append("-subs")

    # Use JSON output for robust parsing.
    if not _has_flag(final_args, ["-json"]):
        final_args.append("-json")

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_katana(stdout: str) -> list[str]:
    urls: set[str] = set()
    for line in (stdout or "").split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            urls.update(_extract_urls_from_json(data))
        except json.JSONDecodeError:
            urls.update(_extract_urls_from_text(line))
    return sorted(list(urls))


def parse_gospider(stdout: str) -> list[str]:
    urls: set[str] = set()
    for line in (stdout or "").split("\n"):
        line = line.strip()
        if not line or "Out of scope" in line:
            continue

        # GoSpider format: [source] - [method] - URL   OR   [source] - URL
        parts = line.split(" - ")
        if len(parts) >= 2:
            url = parts[-1].strip()
            if url.startswith("http"):
                urls.add(url)
                continue

        # Fallback URL extraction for unexpected output variants.
        urls.update(_extract_urls_from_text(line))
    return sorted(list(urls))


def parse_hakrawler(stdout: str) -> list[str]:
    urls: set[str] = set()
    for line in (stdout or "").split("\n"):
        line = line.strip()

        if not line:
            continue

        # JSON mode line: {"source":"href","url":"https://..."}
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict):
                urls.update(_extract_urls_from_json(data))
                continue
        # Fallback for plain-text mode.
        if line.startswith("http"):
            urls.add(line)
            continue

        urls.update(_extract_urls_from_text(line))
    return sorted(list(urls))


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def web_crawler(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    max_results: int = 500,
    timeout: int = 120,
) -> dict:
    """
    🔧 Agent Tool: Web Crawler & Spider
    
    Crawls a target URL to discover endpoints, files, JS assets, and parameters.
    Returns results in-memory only (no result files are written).
    """
    start = time.time()
    args = list(args or [])
    
    try:
        req = WebCrawlerRequest(tool=tool, target=target, args=args, max_results=max_results, timeout=timeout)
    except Exception as e:
        return WebCrawlerResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    # ── BUILD COMMAND ──
    try:
        clean_args, scope = _extract_scope_from_args(args, target)
    except Exception as e:
        return WebCrawlerResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    stdin_data = None
    if tool == "katana":
        cmd = _build_katana_cmd(clean_args, target)
    elif tool == "gospider":
        cmd = _build_gospider_cmd(clean_args, target)
    elif tool == "hakrawler":
        cmd = _build_hakrawler_cmd(clean_args)
        stdin_data = f"{target}\n"  # Hakrawler consumes newline-delimited targets via stdin

    command_str = " ".join(cmd)
    if tool == "hakrawler":
        command_str = f"echo '{target}' | {command_str}"

    # ── EXECUTE ──
    effective_timeout = req.timeout
    if tool == "katana":
        # Ignore IA-provided timeout and enforce fixed katana timeout policy.
        effective_timeout = ProjectConfig.KATANA_TIMEOUT_SECONDS + 5

    stdout, stderr, rc, cwd = safe_execute(cmd, effective_timeout, stdin_data=stdin_data)

    # ── PARSE ──
    urls = []
    if tool == "katana":
        urls = parse_katana(stdout)
        if not urls and stderr:
            urls = parse_katana(stderr)
    elif tool == "gospider":
        urls = parse_gospider("\n".join(part for part in [stdout, stderr] if part))
    elif tool == "hakrawler":
        urls = parse_hakrawler(stdout)
        if not urls and stderr:
            urls = parse_hakrawler(stderr)

    # Enforce in-scope URLs only (same domain / subdomain)
    urls, out_of_scope_filtered = _filter_urls_by_scope(urls, scope)

    total_found = len(urls)
    truncated = False

    # ── CONTEXT PROTECTION (in-memory only) ──
    if total_found > 0:
        # Truncate response payload when needed
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
        scope=scope,
        out_of_scope_filtered=out_of_scope_filtered,
        truncated=truncated,
        full_output_file=None,
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
        "Returns findings in JSON and truncates with max_results."
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
                "description": "Raw args. Use wrapper-level scope: ['--scope', 'example.com']. Depth is auto-clamped to max 5. Katana auto-enables -jc if omitted."
            },
            "max_results": {
                "type": "integer",
                "description": "Max URLs to return in JSON response. (Default: 500)"
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout in seconds. (Default: 120, max: 3600)"
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
        args=["-d", "2", "--scope", "hackerone.com"], # depth 2, wrapper scope; katana auto-adds -jc
        max_results=50,
        timeout=60,
    )
    print("\n=== KATANA ===")
    print(f"Command: {r1['command']}")
    print(f"Total Found: {r1['total_found']}")
    print(f"Scope: {r1['scope']}")
    print(f"Out-of-scope filtered: {r1['out_of_scope_filtered']}")
    print(f"Truncated for LLM: {r1['truncated']}")
    print("Preview of first 5 URLs:")
    for u in r1['urls'][:5]:
        print(f"  - {u}")
    if r1.get("error"):
        print(f"Error: {r1['error']}")

    # 2. GoSpider (Extract Other Sources)
    r2 = web_crawler(
        tool="gospider",
        target="https://hackerone.com",
        args=[], # keep defaults close to: gospider -s https://hackerone.com -q
        max_results=30,
        timeout=60,
    )
    print("\n=== GOSPIDER ===")
    print(f"Command: {r2['command']}")
    print(f"Total Found: {r2['total_found']}")
    print("Preview of first 5 URLs:")
    for u in r2['urls'][:5]:
        print(f"  - {u}")
    if r2.get("error"):
        print(f"Error: {r2['error']}")

    # 3. Hakrawler (Standard depth)
    r3 = web_crawler(
        tool="hakrawler",
        target="https://hackerone.com",
        args=["-d", "3", "-t", "30", "-subs"],
        max_results=30,
        timeout=30,
    )
    print("\n=== HAKRAWLER ===")
    print(f"Command: {r3['command']}")
    print(f"Total Found: {r3['total_found']}")
    print("Preview of first 5 URLs:")
    for u in r3['urls'][:5]:
        print(f"  - {u}")
    if r3.get("error"):
        print(f"Error: {r3['error']}")
