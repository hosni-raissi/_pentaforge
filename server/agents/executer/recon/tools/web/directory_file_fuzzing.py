#/+
import subprocess
import json
import re
import os
import time
import shutil
import threading
import ipaddress
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
    WORDLISTS_DIR = Path("share") / "wordlists"
    ALT_WORDLISTS_DIR = Path("server") / "share" / "wordlists"
    
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

    @classmethod
    def get_wordlists_dir(cls) -> Path:
        project_dir = cls.get_project_dir()
        candidates = [
            project_dir / cls.WORDLISTS_DIR,
            project_dir / cls.ALT_WORDLISTS_DIR,
        ]
        for path in candidates:
            if path.is_dir():
                return path

        # Prefer server/share/wordlists in monorepo layout.
        default_path = candidates[1] if (project_dir / "server").is_dir() else candidates[0]
        default_path.mkdir(parents=True, exist_ok=True)
        return default_path


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
        "ffuf": "ffuf",
        "feroxbuster": "feroxbuster",
    }
    binary = binary_map.get(tool)
    if not binary:
        return False, f"Unknown tool: {tool}"
    if shutil.which(binary) is None:
        install_hints = {
            "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
            "feroxbuster": "cargo install feroxbuster",
        }
        return False, f"Tool '{tool}' not installed. Install with: {install_hints.get(tool, 'unknown')}"
    return True, ""


def safe_execute(
    cmd: list[str],
    timeout: int = 1800,
    stdin_data: Optional[str] = None,
) -> tuple[str, str, int, str]:
    cwd = ProjectConfig.get_project_dir()
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=str(cwd),
            input=stdin_data,
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
    """Simple thread-safe limiter for expensive fuzzing jobs"""
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


FUZZ_RATE_LIMITER = RateLimiter(calls_per_second=0.5)


# ══════════════════════════════════════════════════════════════
# 3. WEB WORDLISTS
# ══════════════════════════════════════════════════════════════

DEFAULT_FOLDER_WORDS = [
    "admin",
    "api",
    "assets",
    "backup",
    "config",
    "dashboard",
    "dev",
    "images",
    "js",
    "uploads",
]

DEFAULT_FILE_WORDS = [
    "index.php",
    "index.html",
    "robots.txt",
    "sitemap.xml",
    ".env",
    ".git/HEAD",
    "backup.zip",
    "config.php.bak",
    "web.config",
    "phpinfo.php",
]


def _ensure_default_web_wordlists() -> dict[str, str]:
    """
    Keep exactly two built-in web wordlists:
    - folders
    - files
    """
    base = ProjectConfig.get_wordlists_dir() / "web"
    base.mkdir(parents=True, exist_ok=True)

    folders_path = base / "folders.txt"
    files_path = base / "files.txt"

    if not folders_path.exists():
        folders_path.write_text("\n".join(DEFAULT_FOLDER_WORDS) + "\n", encoding="utf-8")
    if not files_path.exists():
        files_path.write_text("\n".join(DEFAULT_FILE_WORDS) + "\n", encoding="utf-8")

    return {
        "folders": str(folders_path),
        "files": str(files_path),
    }


def _get_web_wordlists() -> dict[str, str]:
    return _ensure_default_web_wordlists()


# ══════════════════════════════════════════════════════════════
# 4. SCHEMAS
# ══════════════════════════════════════════════════════════════

class DirFileFuzzRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = Field(default_factory=list)
    wordlist_mode: str = "builtin"     # builtin only

    # backward compatibility
    list_type: Optional[str] = None    # user | ia

    inline_wordlist: Optional[list[str]] = None
    builtin_list: Optional[str] = None
    timeout: int = Field(default=1800, ge=10, le=7200)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"ffuf", "feroxbuster"}
        if v not in allowed:
            raise ValueError("Tool must be 'ffuf' or 'feroxbuster'")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Target is required")

        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("Target must start with http:// or https://")

        parsed = urlparse(v)
        host = parsed.hostname
        if not host:
            raise ValueError("Invalid target URL")

        # validate host format but DO NOT block local/private targets
        try:
            ipaddress.ip_address(host)
        except ValueError:
            domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$"
            if not re.match(domain_pattern, host.lower()):
                raise ValueError(f"Invalid target hostname: {host}")

        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">", "\n", "\r", "'", '"']
        blocked_output_flags = ["-o", "--output", "-of", "--output-file"]

        for arg in v:
            for char in dangerous:
                if char in arg:
                    raise ValueError(f"Dangerous char '{repr(char)}' in arg")

            arg_clean = arg.strip().lower()
            for flag in blocked_output_flags:
                if arg_clean == flag or arg_clean.startswith(flag + "="):
                    raise ValueError(f"Blocked output flag: {flag}")
        return v

    @field_validator("builtin_list")
    @classmethod
    def validate_builtin(cls, v):
        if v is not None and v not in _get_web_wordlists():
            raise ValueError(f"Unknown wordlist: {v}")
        return v

    @field_validator("wordlist_mode")
    @classmethod
    def validate_wordlist_mode(cls, v):
        if v != "builtin":
            raise ValueError("wordlist_mode must be 'builtin' (inline mode disabled)")
        return v

    @field_validator("list_type")
    @classmethod
    def validate_list_type(cls, v):
        if v is not None and v not in {"user", "ia"}:
            raise ValueError("list_type must be 'user' or 'ia'")
        if v == "ia":
            raise ValueError("list_type='ia' is disabled for this tool; use built-in wordlists")
        return v

    @field_validator("inline_wordlist")
    @classmethod
    def validate_inline_wordlist(cls, v):
        if v is not None:
            raise ValueError("inline_wordlist is disabled for this tool; use builtin_list='folders' or 'files'")
        return v


class DirFileResultItem(BaseModel):
    url: str
    path: str
    status: int
    content_length: int
    words: Optional[int] = None
    lines: Optional[int] = None
    content_type: Optional[str] = None
    redirect_location: Optional[str] = None


class DirFileFuzzResult(BaseModel):
    success: bool
    target: str
    results: list[DirFileResultItem] = Field(default_factory=list)
    tool: str
    command: str
    working_dir: str
    total_found: int = 0
    wordlist_used: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 5. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_ffuf_cmd(args: list[str], target: str, wordlist_path: str) -> list[str]:
    cmd = ["ffuf"]
    final_args = list(args)

    if _has_flag(final_args, ["-o", "--output"]):
        raise ValueError("Output file flags are blocked. Use stdout output only.")
    if not _has_flag(final_args, ["-json"]):
        final_args.append("-json")

    clean_target = target
    if "FUZZ" not in clean_target:
        clean_target = f"{clean_target.rstrip('/')}/FUZZ"

    if not _target_in_args(clean_target, final_args, ["-u"]):
        final_args.extend(["-u", clean_target])

    if not _has_flag(final_args, ["-w"]):
        final_args.extend(["-w", wordlist_path])

    if not _has_flag(final_args, ["-mc", "-fc"]):
        final_args.extend(["-mc", "200,204,301,302,307,401,403"])

    cmd.extend(final_args)
    return cmd


def _build_feroxbuster_cmd(args: list[str], target: str, wordlist_path: str) -> list[str]:
    cmd = ["feroxbuster"]
    final_args = list(args)

    if _has_flag(final_args, ["-o", "--output"]):
        raise ValueError("Output file flags are blocked. Use stdout output only.")

    if not _has_flag(final_args, ["--json"]):
        final_args.append("--json")

    # Newer feroxbuster requires one of: --silent | --output | --debug-log.
    # We block output/debug-log file writes, so enforce --silent.
    if not _has_flag(final_args, ["--silent", "--output", "--debug-log"]):
        final_args.append("--silent")

    # In newer feroxbuster, --quiet conflicts with --silent.
    if _has_flag(final_args, ["--silent"]):
        final_args = [arg for arg in final_args if arg not in {"-q", "--quiet"}]

    clean_target = target.replace("FUZZ", "")
    if not _target_in_args(clean_target, final_args, ["-u", "--url"]):
        final_args.extend(["-u", clean_target])

    if not _has_flag(final_args, ["-w", "--wordlist"]):
        final_args.extend(["-w", wordlist_path])

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 6. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_ffuf(stdout: str) -> list[DirFileResultItem]:
    results: list[DirFileResultItem] = []
    raw = (stdout or "").strip()
    if not raw:
        return results

    try:
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            item = json.loads(line)
            if "url" not in item:
                continue
            results.append(DirFileResultItem(
                url=item.get("url", ""),
                path=item.get("input", {}).get("FFUF", ""),
                status=item.get("status", 0),
                content_length=item.get("length", 0),
                words=item.get("words", 0),
                lines=item.get("lines", 0),
                content_type=item.get("content-type", ""),
                redirect_location=item.get("redirectlocation", ""),
            ))
    except Exception:
        try:
            data = json.loads(raw)
            for item in data.get("results", []):
                results.append(DirFileResultItem(
                    url=item.get("url", ""),
                    path=item.get("input", {}).get("FFUF", ""),
                    status=item.get("status", 0),
                    content_length=item.get("length", 0),
                    words=item.get("words", 0),
                    lines=item.get("lines", 0),
                    content_type=item.get("content-type", ""),
                    redirect_location=item.get("redirectlocation", ""),
                ))
        except Exception:
            pass

    return results


def parse_feroxbuster(stdout: str) -> list[DirFileResultItem]:
    results: list[DirFileResultItem] = []
    raw = (stdout or "").strip()
    if not raw:
        return results

    try:
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if data.get("type") != "response":
                continue

            headers = data.get("headers", {})
            content_type = headers.get("content-type", "")
            redirect_loc = headers.get("location", "")

            results.append(DirFileResultItem(
                url=data.get("url", ""),
                path=data.get("path", ""),
                status=data.get("status", 0),
                content_length=data.get("content_length", 0),
                words=data.get("word_count", 0),
                lines=data.get("line_count", 0),
                content_type=content_type,
                redirect_location=redirect_loc
            ))
    except Exception:
        pass

    seen = set()
    unique_res = []
    for r in results:
        if r.url not in seen:
            seen.add(r.url)
            unique_res.append(r)

    return unique_res


# ══════════════════════════════════════════════════════════════
# 7. CORE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _directory_file_fuzzing_impl(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    wordlist_mode: str = "builtin",
    inline_wordlist: Optional[list[str]] = None,
    builtin_list: Optional[str] = None,
    timeout: int = 1800,
) -> dict:
    start = time.time()
    args = list(args or [])
    warnings: list[str] = []

    FUZZ_RATE_LIMITER.acquire()

    try:
        req = DirFileFuzzRequest(
            tool=tool,
            target=target,
            args=args,
            wordlist_mode=wordlist_mode,
            inline_wordlist=inline_wordlist,
            builtin_list=builtin_list,
            timeout=timeout,
        )
    except Exception as e:
        return DirFileFuzzResult(
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
        return DirFileFuzzResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            working_dir="",
            error=install_msg,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # Resolve wordlist (builtin only; no temp file materialization)
    wordlist_path = None

    # backward compatibility
    effective_mode = req.wordlist_mode
    if req.list_type == "user":
        effective_mode = "builtin"
    elif req.list_type == "ia":
        return DirFileFuzzResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            working_dir="",
            error="inline wordlist mode is disabled; use builtin_list='folders' or 'files'",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    if effective_mode != "builtin":
        return DirFileFuzzResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            working_dir="",
            error="Only builtin wordlists are supported",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    builtin_key = req.builtin_list or "folders"
    wordlist_path = _get_web_wordlists().get(builtin_key)

    if not wordlist_path:
        return DirFileFuzzResult(
            success=False,
            tool=req.tool,
            target=req.target,
            command="",
            working_dir="",
            error="No wordlist provided",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    if req.tool == "ffuf":
        cmd = _build_ffuf_cmd(req.args, req.target, wordlist_path)
    elif req.tool == "feroxbuster":
        cmd = _build_feroxbuster_cmd(req.args, req.target, wordlist_path)
    else:
        return DirFileFuzzResult(
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

    if req.tool == "ffuf":
        results = parse_ffuf(stdout)
    else:
        results = parse_feroxbuster(stdout)

    results.sort(key=lambda x: (x.status if x.status < 400 else x.status + 1000, x.url))

    return DirFileFuzzResult(
        success=rc == 0 or len(results) > 0,
        tool=req.tool,
        target=req.target,
        command=command_str,
        working_dir=cwd,
        total_found=len(results),
        results=[r.model_dump() for r in results],
        wordlist_used=wordlist_path,
        warnings=warnings,
        error=stderr if rc != 0 and not results else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 8. CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_directory_file_fuzzing(
    tool: str,
    target: str,
    args_tuple: tuple[str, ...],
    wordlist_mode: str,
    inline_wordlist_tuple: tuple[str, ...],
    builtin_list: Optional[str],
    timeout: int,
) -> str:
    result = _directory_file_fuzzing_impl(
        tool=tool,
        target=target,
        args=list(args_tuple),
        wordlist_mode=wordlist_mode,
        inline_wordlist=list(inline_wordlist_tuple) if inline_wordlist_tuple else None,
        builtin_list=builtin_list,
        timeout=timeout,
    )
    return json.dumps(result)


def clear_cache():
    _cached_directory_file_fuzzing.cache_clear()


def get_cache_info():
    return _cached_directory_file_fuzzing.cache_info()


# ══════════════════════════════════════════════════════════════
# 9. PUBLIC API
# ══════════════════════════════════════════════════════════════

def directory_file_fuzzing(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    wordlist_mode: str = "builtin",
    inline_wordlist: Optional[list[str]] = None,
    builtin_list: Optional[str] = None,
    timeout: int = 1800,
    use_cache: bool = True,

    # backward compatibility
    list_type: Optional[str] = None,
) -> dict:
    """
    🔧 Agent Tool: Directory & File Fuzzing

    Discovers hidden directories, backup files, and API endpoints using
    ffuf (highly customizable) or feroxbuster (fast, recursive).

    Notes:
    - Results are returned directly in JSON, never written to output files.
    - Inline wordlists are disabled for this tool to avoid writing temp artifacts.
    - Built-in wordlists are limited to exactly two files under share/wordlists/web:
      folders.txt and files.txt (auto-created if missing).
    - Local/private targets are allowed by design for internal testing environments.
    """

    start = time.time()

    if list_type == "user":
        wordlist_mode = "builtin"
    elif list_type == "ia":
        return DirFileFuzzResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            working_dir="",
            error="list_type='ia' is disabled for this tool; use builtin_list='folders' or 'files'",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    if wordlist_mode != "builtin":
        return DirFileFuzzResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            working_dir="",
            error="wordlist_mode must be 'builtin' for this tool",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    args = args or []
    if inline_wordlist:
        return DirFileFuzzResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            working_dir="",
            error="inline_wordlist is disabled; use builtin_list='folders' or 'files'",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    inline_wordlist = []

    if use_cache:
        cached = _cached_directory_file_fuzzing(
            tool,
            target,
            tuple(args),
            wordlist_mode,
            tuple(inline_wordlist),
            builtin_list,
            timeout,
        )
        return json.loads(cached)

    return _directory_file_fuzzing_impl(
        tool=tool,
        target=target,
        args=args,
        wordlist_mode=wordlist_mode,
        inline_wordlist=inline_wordlist if inline_wordlist else None,
        builtin_list=builtin_list,
        timeout=timeout,
    )


# ══════════════════════════════════════════════════════════════
# 10. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

DIRECTORY_FILE_FUZZING_TOOL_DEFINITION = {
    "name": "directory_file_fuzzing",
    "description": (
        "Brute force web directories, file extensions, and hidden paths. "
        "Supports ffuf (fast, exact matchers) and feroxbuster (recursive scanning). "
        "Returns structured JSON results directly, without writing scan output files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["ffuf", "feroxbuster"],
                "description": "ffuf (great for single-dir or extensions) | feroxbuster (great for deep recursive scanning)"
            },
            "target": {
                "type": "string",
                "description": "Target URL. For ffuf, FUZZ is optional and will be auto-added if missing."
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw tool args. Example: ffuf ['-e', '.php,.bak,.zip', '-t', '50'] | feroxbuster ['--depth', '2', '-x', 'php']"
            },
            "wordlist_mode": {
                "type": "string",
                "enum": ["builtin"],
                "description": "Only builtin mode is supported"
            },
            "builtin_list": {
                "type": "string",
                "enum": ["folders", "files"],
                "description": "Built-in list: folders or files"
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
# 11. EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    def _print_demo_result(title: str, result: dict) -> None:
        print(f"\n=== {title} ===")
        print(f"Success: {result.get('success')}")
        print(f"Command: {result.get('command') or '-'}")
        print(f"Wordlist: {result.get('wordlist_used') or '-'}")
        print(f"Total Found: {result.get('total_found', 0)}")
        if result.get("error"):
            print(f"Error: {result['error']}")
        if result.get("warnings"):
            print("Warnings: " + " | ".join(result["warnings"]))
        for res in (result.get("results") or [])[:3]:
            print(f"[{res['status']}] {res['url']} (Size: {res['content_length']})")

    print("=" * 60)
    print("DIRECTORY & FILE FUZZING — v2.0")
    print("=" * 60)

    r1 = directory_file_fuzzing(
        tool="ffuf",
        target="http://scanme.nmap.org/FUZZ",
        args=["-e", ".php,.bak,.zip", "-t", "50", "-mc", "200,301,403"],
        wordlist_mode="builtin",
        builtin_list="files",
        use_cache=False,
    )
    _print_demo_result("FFUF: FILE EXTENSIONS", r1)

    r2 = directory_file_fuzzing(
        tool="feroxbuster",
        target="http://scanme.nmap.org/",
        args=["--depth", "2", "-t", "50"],
        wordlist_mode="builtin",
        builtin_list="folders",
        use_cache=False,
    )
    _print_demo_result("FEROXBUSTER: RECURSIVE", r2)

    print("\n=== CACHE TEST ===")
    start = time.time()
    _ = directory_file_fuzzing(
        tool="ffuf",
        target="http://scanme.nmap.org/FUZZ",
        args=["-mc", "200,403"],
        wordlist_mode="builtin",
        builtin_list="folders",
        use_cache=True,
    )
    first = time.time() - start

    start = time.time()
    _ = directory_file_fuzzing(
        tool="ffuf",
        target="http://scanme.nmap.org/FUZZ",
        args=["-mc", "200,403"],
        wordlist_mode="builtin",
        builtin_list="folders",
        use_cache=True,
    )
    second = time.time() - start

    print(f"First run:  {first:.2f}s")
    print(f"Cached run: {second:.4f}s")
    print(f"Cache info: {get_cache_info()}")
