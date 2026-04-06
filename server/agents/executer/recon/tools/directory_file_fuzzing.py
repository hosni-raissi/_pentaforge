import subprocess
import json
import re
import os
import time
import tempfile
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION & UTILITIES
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools"""
    _project_dir: Optional[Path] = None
    WORDLISTS_DIR = "wordlists"
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

    @classmethod
    def get_wordlists_dir(cls) -> Path:
        return cls.get_project_dir() / cls.WORDLISTS_DIR


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


def safe_execute(cmd: list[str], timeout: int = 1800) -> tuple[str, str, int, str]:
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
# 2. WEB WORDLISTS
# ══════════════════════════════════════════════════════════════

def _get_web_wordlists() -> dict[str, str]:
    wl_dir = ProjectConfig.get_wordlists_dir()
    wordlists = {
        "common": [
            wl_dir / "common.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
        ],
        "raft_large_dirs": [
            wl_dir / "raft-large-directories.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt")
        ],
        "raft_large_files": [
            wl_dir / "raft-large-files.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt")
        ],
        "raft_medium_dirs": [
            wl_dir / "raft-medium-directories.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
        ],
        "raft_medium_files": [
            wl_dir / "raft-medium-files.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt")
        ],
        "big": [
            wl_dir / "big.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/big.txt")
        ],
        "dirbuster_medium": [
            wl_dir / "directory-list-2.3-medium.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"),
            Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        ]
    }
    
    resolved = {}
    for key, paths in wordlists.items():
        for p in paths:
            if p.is_file():
                resolved[key] = str(p)
                break
        if key not in resolved:
            resolved[key] = str(paths[0])
    return resolved


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class DirFileFuzzRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    list_type: str = "user"
    inline_wordlist: Optional[list[str]] = None
    builtin_list: Optional[str] = None
    timeout: int = Field(default=1800, ge=10, le=7200)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        if v not in {"ffuf", "feroxbuster"}: raise ValueError("Tool must be 'ffuf' or 'feroxbuster'")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        if not v.startswith("http"): raise ValueError("Target must be a URL (e.g. https://example.com/)")
        return v.strip()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg")
        return v

    @field_validator("builtin_list")
    @classmethod
    def validate_builtin(cls, v):
        if v is not None and v not in _get_web_wordlists():
            raise ValueError(f"Unknown wordlist: {v}")
        return v

    @field_validator("list_type")
    @classmethod
    def validate_list_type(cls, v):
        if v not in {"user", "ia"}:
            raise ValueError("list_type must be 'user' or 'ia'")
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
    tool: str
    target: str
    command: str
    working_dir: str
    total_found: int = 0
    results: list[DirFileResultItem] = []
    wordlist_used: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 4. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_ffuf_cmd(args: list[str], target: str, wordlist_path: str) -> list[str]:
    cmd = ["ffuf"]
    final_args = list(args)

    # File outputs are blocked; require stdout JSON lines.
    if _has_flag(final_args, ["-o", "--output"]):
        raise ValueError("Output file flags are blocked. Use stdout output only.")
    if not _has_flag(final_args, ["-json"]):
        final_args.append("-json")

    # Ensure FUZZ is in target
    clean_target = target
    if "FUZZ" not in clean_target:
        clean_target = f"{clean_target.rstrip('/')}/FUZZ"

    if not _target_in_args(clean_target, final_args, ["-u"]):
        final_args.extend(["-u", clean_target])

    if not _has_flag(final_args, ["-w"]):
        final_args.extend(["-w", wordlist_path])

    # Default matchers if not provided
    if not _has_flag(final_args, ["-mc", "-fc"]):
        final_args.extend(["-mc", "200,204,301,302,307,401,403"])

    cmd.extend(final_args)
    return cmd


def _build_feroxbuster_cmd(args: list[str], target: str, wordlist_path: str) -> list[str]:
    cmd = ["feroxbuster"]
    final_args = list(args)

    # File outputs are blocked; require stdout JSON lines.
    if _has_flag(final_args, ["-o", "--output"]):
        raise ValueError("Output file flags are blocked. Use stdout output only.")

    if not _has_flag(final_args, ["--json"]):
        final_args.append("--json")

    # Keep output mostly JSON lines.
    if not _has_flag(final_args, ["-q", "--quiet"]):
        final_args.append("-q")

    # Add target (remove FUZZ if it was passed by mistake)
    clean_target = target.replace("FUZZ", "")
    if not _target_in_args(clean_target, final_args, ["-u", "--url"]):
        final_args.extend(["-u", clean_target])

    if not _has_flag(final_args, ["-w", "--wordlist"]):
        final_args.extend(["-w", wordlist_path])

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 5. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_ffuf(stdout: str) -> list[DirFileResultItem]:
    results = []
    raw = (stdout or "").strip()
    if not raw:
        return results

    try:
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            item = json.loads(line)
            # ffuf -json prints one JSON object per result line.
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
        # Backward-compatible fallback for full JSON payload.
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
    results = []
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
            # Feroxbuster writes config and error lines too. We only want 'response'
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

    # Deduplicate Feroxbuster outputs (sometimes repeats due to recursive finds)
    seen = set()
    unique_res = []
    for r in results:
        if r.url not in seen:
            seen.add(r.url)
            unique_res.append(r)

    return unique_res


# ══════════════════════════════════════════════════════════════
# 6. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def directory_file_fuzzing(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    list_type: str = "user",
    inline_wordlist: Optional[list[str]] = None,
    builtin_list: Optional[str] = None,
) -> dict:
    """
    🔧 Agent Tool: Directory & File Fuzzing
    
    Discovers hidden directories, backup files, and API endpoints using 
    ffuf (highly customizable) or feroxbuster (fast, recursive).
    """
    start = time.time()
    args = list(args or [])
    
    try:
        req = DirFileFuzzRequest(
            tool=tool, target=target, args=args, list_type=list_type,
            inline_wordlist=inline_wordlist, builtin_list=builtin_list
        )
    except Exception as e:
        return DirFileFuzzResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    # ── RESOLVE WORDLIST ──
    wordlist_path = None
    tmp_wl = None

    if list_type == "user" and builtin_list:
        wordlist_path = _get_web_wordlists().get(builtin_list)
    elif list_type == "ia" and inline_wordlist:
        tmp_wl = tempfile.NamedTemporaryFile(mode="w", delete=False, dir=ProjectConfig.get_temp_dir())
        tmp_wl.write("\n".join(inline_wordlist))
        tmp_wl.close()
        wordlist_path = tmp_wl.name

    if not wordlist_path:
        return DirFileFuzzResult(success=False, tool=tool, target=target, command="", working_dir="", error="No wordlist provided").model_dump()

    # ── BUILD & EXECUTE ──
    if tool == "ffuf":
        cmd = _build_ffuf_cmd(args, target, wordlist_path)
    elif tool == "feroxbuster":
        cmd = _build_feroxbuster_cmd(args, target, wordlist_path)

    command_str = " ".join(cmd)
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)

    # ── PARSE ──
    if tool == "ffuf":
        results = parse_ffuf(stdout)
    elif tool == "feroxbuster":
        results = parse_feroxbuster(stdout)

    # Cleanup inline wordlist
    if tmp_wl:
        try: os.unlink(tmp_wl.name)
        except OSError: pass

    # ── SORT & RETURN ──
    # Sort by status code (200s first), then by URL
    results.sort(key=lambda x: (x.status if x.status < 400 else x.status + 1000, x.url))

    return DirFileFuzzResult(
        success=rc == 0 or len(results) > 0,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        total_found=len(results),
        results=results,
        wordlist_used=wordlist_path,
        error=stderr if rc != 0 and not results else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 7. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

DIRECTORY_FILE_FUZZING_TOOL_DEFINITION = {
    "name": "directory_file_fuzzing",
    "description": (
        "Brute force web directories, file extensions, and hidden paths. "
        "Supports ffuf (fast, exact matchers) and feroxbuster (recursive scanning)."
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
                "description": "Target URL. For ffuf, append FUZZ (e.g. 'https://example.com/FUZZ')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw tool args. Example: ffuf: ['-e', '.php,.bak', '-t', '50'] | feroxbuster: ['--depth', '2', '-x', 'php']"
            },
            "list_type": {
                "type": "string",
                "enum": ["user", "ia"],
                "description": "'user' = use built-in SecLists | 'ia' = provide inline list"
            },
            "inline_wordlist": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Inline paths (only if list_type='ia'). e.g. ['admin', 'backup.zip']"
            },
            "builtin_list": {
                "type": "string",
                "enum": ["common", "raft_large_dirs", "raft_large_files", "raft_medium_dirs", "raft_medium_files", "big", "dirbuster_medium"],
                "description": "Built-in SecLists wordlist (only if list_type='user')"
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 8. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("DIRECTORY & FILE FUZZING — EXAMPLES")
    print("=" * 60)
    
    # 1. FFUF - File Extension Fuzzing
    r1 = directory_file_fuzzing(
        tool="ffuf",
        target="https://hackerone.com/FUZZ",
        args=["-e", ".php,.bak,.zip", "-t", "50", "-mc", "200,301,403"],
        list_type="user",
        builtin_list="raft_small_files"
    )
    print("\n=== FFUF: FILE EXTENSIONS ===")
    print(f"Command: {r1['command']}")
    print(f"Wordlist: {r1['wordlist_used']}")
    print(f"Total Found: {r1['total_found']}")
    for res in r1['results'][:3]:
        print(f"[{res['status']}] {res['url']} (Size: {res['content_length']})")

    # 2. FEROXBUSTER - Recursive Directory Scan
    r2 = directory_file_fuzzing(
        tool="feroxbuster",
        target="https://hackerone.com/",
        args=["--depth", "2", "-t", "50"],
        list_type="user",
        builtin_list="raft_small_dirs"
    )
    print("\n=== FEROXBUSTER: RECURSIVE ===")
    print(f"Command: {r2['command']}")
    print(f"Wordlist: {r2['wordlist_used']}")
    print(f"Total Found: {r2['total_found']}")
    for res in r2['results'][:3]:
        print(f"[{res['status']}] {res['url']} (Size: {res['content_length']})")
