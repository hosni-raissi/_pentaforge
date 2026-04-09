#/+
import subprocess
import json
import os
import time
import tempfile
import base64
import uuid
import urllib.request
import urllib.error
import ssl
import concurrent.futures
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 0. PROJECT CONFIGURATION & UTILITIES
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools."""
    _project_dir: Optional[Path] = None
    WORDLISTS_DIR = Path("share") / "wordlists"
    ALT_WORDLISTS_DIR = Path("server") / "share" / "wordlists"
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
        project_dir = cls.get_project_dir()
        candidates = [
            project_dir / cls.WORDLISTS_DIR,
            project_dir / cls.ALT_WORDLISTS_DIR,
        ]

        for path in candidates:
            if path.is_dir():
                return path

        # Prefer server/share/wordlists when this is a monorepo with a server folder.
        default_path = candidates[1] if (project_dir / "server").is_dir() else candidates[0]
        default_path.mkdir(parents=True, exist_ok=True)
        return default_path


def _target_in_args(target: str, args: list[str], flags: list[str]) -> bool:
    if not args:
        return False
    t_clean = target.strip().lower()
    for i, arg in enumerate(args):
        a_clean = arg.strip().lower()
        if a_clean == t_clean or t_clean in a_clean:
            return True
        if a_clean in flags and i + 1 < len(args):
            if args[i + 1].strip().lower() == t_clean:
                return True
    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    return any(arg in args for arg in flags)


def _has_user_agent_header(args: list[str]) -> bool:
    """Detect whether ffuf args already define a User-Agent header."""
    i = 0
    while i < len(args):
        arg = args[i]

        if arg in {"-H", "--header"} and i + 1 < len(args):
            header_val = args[i + 1]
            if header_val.lower().startswith("user-agent:"):
                return True
            i += 2
            continue

        # Handle compact forms like -HUser-Agent: foo
        if arg.startswith("-H"):
            header_val = arg[2:].strip()
            if header_val.lower().startswith("user-agent:"):
                return True

        i += 1

    return False


def _decode_if_base64(value: str) -> str:
    """Decode ffuf's base64-encoded FUZZ input when present."""
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        return value

    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return value

    return text or value


MAX_THREADS = 80
DEFAULT_BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def _clamp_ffuf_threads(args: list[str], max_threads: int = MAX_THREADS) -> list[str]:
    """Clamp ffuf -t value to a safe upper bound."""
    clamped = list(args)

    for i, arg in enumerate(clamped):
        if arg != "-t":
            continue

        if i + 1 >= len(clamped):
            raise ValueError("Missing value for -t")

        try:
            thread_count = int(clamped[i + 1])
        except ValueError as exc:
            raise ValueError("Invalid thread value for -t") from exc

        # Keep 1 as the minimum valid thread count, and cap the maximum.
        thread_count = max(1, min(thread_count, max_threads))
        clamped[i + 1] = str(thread_count)

    return clamped


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
# 1. BUILT-IN WEB WORDLISTS (LOCAL SHARE/WORDLISTS)
# ══════════════════════════════════════════════════════════════

def _get_web_wordlists() -> dict[str, str]:
    wl_dir = ProjectConfig.get_wordlists_dir()
    profiles = {
        # Preferred filenames first, then backward-compatible local aliases.
        "short": ["short.txt", "web-short.txt", "dns-fuzz-small.txt"],
        "medium": ["medium.txt", "web-medium.txt", "dns-fuzz-common.txt"],
        "large": ["large.txt", "web-large.txt", "rockyou.txt"],
    }

    resolved: dict[str, str] = {}
    for profile, filenames in profiles.items():
        selected: Optional[Path] = None
        for name in filenames:
            candidate = wl_dir / name
            if candidate.is_file():
                selected = candidate
                break

        # Keep deterministic path even when the file doesn't exist yet.
        if selected is None:
            selected = wl_dir / filenames[0]

        resolved[profile] = str(selected)

    # Backward-compatible aliases for older callers.
    resolved["common"] = resolved["medium"]
    resolved["quickhits"] = resolved["short"]
    resolved["raft_small_dirs"] = resolved["medium"]
    resolved["raft_small_files"] = resolved["medium"]
    resolved["cgis"] = resolved["short"]
    return resolved


def _ensure_wordlist(name: str) -> Optional[str]:
    """Ensures a local share/wordlists entry exists, creating a tiny fallback when missing."""
    resolved = _get_web_wordlists()
    target_path = resolved.get(name)
    
    if target_path and Path(target_path).is_file():
        return target_path

    if target_path:
        fallback_path = Path(target_path)
    else:
        fallback_path = ProjectConfig.get_wordlists_dir() / f"{name}.txt"

    if fallback_path.is_file():
        return str(fallback_path)

    # Absolute last resort: write a tiny basic list so the tool doesn't crash.
    fallback_path.parent.mkdir(parents=True, exist_ok=True)
    fallback_path.write_text("index.html\nadmin\nrobots.txt\n.env\n.git/HEAD\nsitemap.xml\n")
    return str(fallback_path)


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class WebFuzzRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = Field(default_factory=list)
    list_type: str = "user"
    inline_wordlist: Optional[list[str]] = None
    builtin_list: Optional[str] = None
    timeout: int = Field(default=600, ge=10, le=7200)

    @field_validator("tool")
    def val_tool(cls, v):
        if v not in {"ffuf", "custom"}: raise ValueError("Tool must be 'ffuf' or 'custom'")
        return v

    @field_validator("target")
    def val_target(cls, v):
        if not v.startswith("http"): raise ValueError("Target must be a URL (e.g. https://example.com/FUZZ)")
        return v.strip()

    @field_validator("args")
    def val_args(cls, v):
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg")
        return v

    @field_validator("builtin_list")
    def val_builtin(cls, v):
        if v is not None and v not in _get_web_wordlists():
            raise ValueError(f"Unknown wordlist: {v}")
        return v

    @field_validator("list_type")
    def val_list_type(cls, v):
        if v not in {"user", "ia"}:
            raise ValueError("list_type must be 'user' or 'ia'")
        return v


class FuzzResultItem(BaseModel):
    url: str
    path: str
    status: int
    length: int
    words: Optional[int] = None
    lines: Optional[int] = None
    content_type: Optional[str] = None
    redirect_location: Optional[str] = None


class WebFuzzResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str
    total_found: int = 0
    results: list[FuzzResultItem] = Field(default_factory=list)
    wordlist_used: Optional[str] = None
    soft404_filtered: int = 0
    template_noise_filtered: int = 0
    soft404_baseline_lengths: list[int] = Field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. CUSTOM PROBER (FAST CONCURRENT CHECKER)
# ══════════════════════════════════════════════════════════════

def _check_single_path(base_url: str, path: str, ctx: ssl.SSLContext, timeout: int = 10) -> Optional[FuzzResultItem]:
    """Helper function to perform a single HTTP GET request."""
    path = path if path.startswith("/") else f"/{path}"
    url = f"{base_url}{path}"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            body = response.read()
            return FuzzResultItem(
                url=url,
                path=path,
                status=response.getcode(),
                length=len(body),
                content_type=response.headers.get("Content-Type", "")
            )
    except urllib.error.HTTPError as e:
        if e.code in [401, 403]:
            return FuzzResultItem(url=url, path=path, status=e.code, length=0)
    except Exception:
        pass
    
    return None


def run_custom_fuzzer(target: str, paths: list[str]) -> list[FuzzResultItem]:
    """
    Concurrent native python prober for quickly checking paths.
    """
    results = []
    base_url = target.replace("FUZZ", "").rstrip("/")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Use ThreadPoolExecutor to check paths concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_check_single_path, base_url, p, ctx) for p in paths]
        
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
                
    return results


# ══════════════════════════════════════════════════════════════
# 4. FFUF COMMAND BUILDER & PARSER
# ══════════════════════════════════════════════════════════════

def _build_ffuf_cmd(args: list[str], target: str, wordlist_path: str) -> list[str]:
    cmd = ["ffuf"]
    final_args = _clamp_ffuf_threads(args)

    if _has_flag(final_args, ["-o", "--output"]):
        raise ValueError("Output file flags are blocked. Use stdout output only.")
    if not _has_flag(final_args, ["-json"]):
        final_args.append("-json")

    # Enable ffuf calibration by default unless caller explicitly configured it.
    if not _has_flag(final_args, ["-ac", "-ach", "-acc"]):
        final_args.append("-ac")

    clean_target = target
    if "FUZZ" not in clean_target:
        clean_target = f"{clean_target.rstrip('/')}/FUZZ"

    if not _target_in_args(clean_target, final_args, ["-u"]):
        final_args.extend(["-u", clean_target])

    if not _has_flag(final_args, ["-w"]):
        final_args.extend(["-w", wordlist_path])

    # Many WAF/CDN setups block ffuf's default UA. Add a browser-like UA unless caller set one.
    if not _has_user_agent_header(final_args):
        final_args.extend(["-H", f"User-Agent: {DEFAULT_BROWSER_UA}"])
        
    if not _has_flag(final_args, ["-mc", "-fc"]):
        final_args.extend(["-mc", "200,204,301,302,307,401,403"])

    cmd.extend(final_args)
    return cmd


def _extract_ffuf_path(item: dict[str, Any]) -> str:
    input_data = item.get("input", {}) or {}
    if isinstance(input_data, dict):
        if "FUZZ" in input_data:
            return _decode_if_base64(str(input_data.get("FUZZ", "")))
        if "FFUF" in input_data:
            return _decode_if_base64(str(input_data.get("FFUF", "")))
        if input_data:
            first_value = next(iter(input_data.values()))
            return _decode_if_base64(str(first_value or ""))
    return ""


def _parse_ffuf_item(item: dict[str, Any]) -> Optional[FuzzResultItem]:
    if not isinstance(item, dict) or "url" not in item:
        return None
    return FuzzResultItem(
        url=item.get("url", ""),
        path=_extract_ffuf_path(item),
        status=item.get("status", 0),
        length=item.get("length", 0),
        words=item.get("words", 0),
        lines=item.get("lines", 0),
        content_type=item.get("content-type", ""),
        redirect_location=item.get("redirectlocation", ""),
    )


def parse_ffuf(stdout: str) -> list[FuzzResultItem]:
    """Parse ffuf output from JSON-lines (-json) or full JSON payload."""
    results: list[FuzzResultItem] = []
    raw = (stdout or "").strip()
    if not raw:
        return results

    # ffuf -json often emits one JSON object per line.
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed = _parse_ffuf_item(item)
        if parsed:
            results.append(parsed)

    if results:
        return results

    # Backward-compatible fallback for full JSON payloads containing "results".
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return results

    for item in data.get("results", []) or []:
        parsed = _parse_ffuf_item(item)
        if parsed:
            results.append(parsed)

    return results


def _dedupe_fuzz_results(results: list[FuzzResultItem]) -> list[FuzzResultItem]:
    unique: list[FuzzResultItem] = []
    seen: set[tuple[str, int, int]] = set()
    for item in results:
        key = (item.url, item.status, item.length)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _collect_soft404_baseline_signatures(
    target: str,
    samples: int = 5,
    timeout: int = 8,
) -> set[tuple[int, int, int, str]]:
    """Probe random paths and collect recurring 200-template signatures."""
    base_url = target.replace("FUZZ", "").rstrip("/")
    if not base_url:
        return set()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    signatures: list[tuple[int, int, int, str]] = []
    for _ in range(max(1, samples)):
        random_path = f"__pf_noise_{uuid.uuid4().hex}__"
        probe_url = f"{base_url}/{random_path}"
        req = urllib.request.Request(probe_url, headers={"User-Agent": DEFAULT_BROWSER_UA})

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                if response.getcode() != 200:
                    continue
                body = response.read()
                text = body.decode("utf-8", errors="ignore")
                content_type = (response.headers.get("Content-Type", "") or "").split(";", 1)[0].strip().lower()
                signatures.append((len(body), len(text.split()), text.count("\n") + (1 if text else 0), content_type))
        except urllib.error.HTTPError as e:
            # Ignore non-200 baselines for 200-result soft-404 filtering.
            _ = e
        except Exception:
            continue

    counts: dict[tuple[int, int, int, str], int] = {}
    for signature in signatures:
        counts[signature] = counts.get(signature, 0) + 1

    return {signature for signature, count in counts.items() if count >= 2}


def _filter_soft404_noise(
    results: list[FuzzResultItem],
    baseline_signatures: set[tuple[int, int, int, str]],
) -> tuple[list[FuzzResultItem], int]:
    if not baseline_signatures:
        return results, 0

    baseline_lengths = {sig[0] for sig in baseline_signatures}

    def _is_soft404(item: FuzzResultItem) -> bool:
        item_words = item.words if item.words is not None else -1
        item_lines = item.lines if item.lines is not None else -1
        item_ct = (item.content_type or "").split(";", 1)[0].strip().lower()

        # Exact template signature match.
        exact = (item.length, item_words, item_lines, item_ct)
        if exact in baseline_signatures:
            return True

        # Fuzzy fallback: very similar template shape and same content type.
        for b_len, b_words, b_lines, b_ct in baseline_signatures:
            if item_ct and b_ct and item_ct != b_ct:
                continue
            if abs(item.length - b_len) <= 12 and abs(item_words - b_words) <= 6 and abs(item_lines - b_lines) <= 3:
                return True

        # Last fallback when words/lines are unavailable: near length-only match.
        if item_words < 0 or item_lines < 0:
            return any(abs(item.length - b_len) <= 8 for b_len in baseline_lengths)

        return False

    filtered: list[FuzzResultItem] = []
    removed = 0
    for item in results:
        if item.status == 200 and _is_soft404(item):
            removed += 1
            continue
        filtered.append(item)

    return filtered, removed


def _filter_dominant_template_noise(
    results: list[FuzzResultItem],
    min_cluster_size: int = 8,
    min_cluster_ratio: float = 0.35,
    length_window: int = 24,
) -> tuple[list[FuzzResultItem], int]:
    """Remove dominant same-template 200 pages (common SPA/router noise)."""
    two_hundreds = [r for r in results if r.status == 200 and r.words is not None and r.lines is not None]
    if not two_hundreds:
        return results, 0

    clusters: dict[tuple[int, int, str], list[FuzzResultItem]] = {}
    for item in two_hundreds:
        content_type = (item.content_type or "").split(";", 1)[0].strip().lower()
        key = (item.words or 0, item.lines or 0, content_type)
        clusters.setdefault(key, []).append(item)

    dominant_key = None
    dominant_items: list[FuzzResultItem] = []
    for key, items in clusters.items():
        if len(items) > len(dominant_items):
            dominant_key = key
            dominant_items = items

    if not dominant_key or len(dominant_items) < min_cluster_size:
        return results, 0

    ratio = len(dominant_items) / max(1, len(two_hundreds))
    if ratio < min_cluster_ratio:
        return results, 0

    lengths = sorted(i.length for i in dominant_items)
    median_len = lengths[len(lengths) // 2]

    filtered: list[FuzzResultItem] = []
    removed = 0
    dominant_set = {id(i) for i in dominant_items}
    for item in results:
        if id(item) not in dominant_set:
            filtered.append(item)
            continue

        if abs(item.length - median_len) <= length_window:
            removed += 1
            continue
        filtered.append(item)

    return filtered, removed


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def web_fuzz(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    list_type: str = "user",
    inline_wordlist: Optional[list[str]] = None,
    builtin_list: Optional[str] = None,
) -> dict:
    start = time.time()
    args = list(args or [])
    
    try:
        req = WebFuzzRequest(
            tool=tool, target=target, args=args, list_type=list_type,
            inline_wordlist=inline_wordlist, builtin_list=builtin_list
        )
    except Exception as e:
        return WebFuzzResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    # ── 1. CUSTOM PROBER (FAST) ──
    if tool == "custom":
        paths = inline_wordlist if inline_wordlist else [
            "robots.txt", "sitemap.xml", ".well-known/security.txt", 
            "crossdomain.xml", ".git/HEAD", ".env"
        ]
        
        results = run_custom_fuzzer(target, paths)
        return WebFuzzResult(
            success=True, tool=tool, target=target, command="native python request (concurrent)",
            working_dir=str(ProjectConfig.get_project_dir()),
            total_found=len(results), results=results,
            execution_time=round(time.time() - start, 2)
        ).model_dump()


    # ── 2. FFUF (HEAVY BRUTE FORCE) ──
    wordlist_path = None
    tmp_wl = None

    if list_type == "user" and not builtin_list:
        builtin_list = "medium"

    if list_type == "user" and builtin_list:
        wordlist_path = _ensure_wordlist(builtin_list)
    elif list_type == "ia" and inline_wordlist:
        tmp_wl = tempfile.NamedTemporaryFile(mode="w", delete=False, dir=ProjectConfig.get_temp_dir())
        tmp_wl.write("\n".join(inline_wordlist))
        tmp_wl.close()
        wordlist_path = tmp_wl.name

    if not wordlist_path:
        return WebFuzzResult(success=False, tool=tool, target=target, command="", working_dir="", error="No wordlist provided").model_dump()

    cmd = _build_ffuf_cmd(args, target, wordlist_path)
    command_str = " ".join(cmd)
    
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)
    results = parse_ffuf(stdout)
    results = _dedupe_fuzz_results(results)
    soft404_filtered = 0
    template_noise_filtered = 0
    soft404_baseline_lengths: list[int] = []

    # Auto-filter obvious soft-404 noise unless caller already controls response-shape filters.
    if not _has_flag(args, ["-fs", "--filter-size", "-fw", "--filter-words", "-fl", "--filter-lines"]):
        baseline_signatures = _collect_soft404_baseline_signatures(target)
        soft404_baseline_lengths = sorted({sig[0] for sig in baseline_signatures})
        results, soft404_filtered = _filter_soft404_noise(results, baseline_signatures)
        results, template_noise_filtered = _filter_dominant_template_noise(results)

    if tmp_wl:
        try: os.unlink(tmp_wl.name)
        except OSError: pass

    return WebFuzzResult(
        success=rc == 0 or len(results) > 0,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        total_found=len(results),
        results=results,
        wordlist_used=wordlist_path,
        soft404_filtered=soft404_filtered,
        template_noise_filtered=template_noise_filtered,
        soft404_baseline_lengths=soft404_baseline_lengths,
        error=stderr if rc != 0 and not results else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

WEB_FUZZ_TOOL_DEFINITION = {
    "name": "web_fuzz",
    "description": (
        "Brute force directories, files, or parameters using ffuf, or use 'custom' to instantly check "
        "well-known paths (robots.txt, sitemap.xml, etc). Hint: Adjust threads (-t) or add custom headers "
        "(-H 'User-Agent: ...') to evade WAF blocks."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["ffuf", "custom"],
                "description": "ffuf (heavy wordlists) | custom (fast native concurrent python check for well-known files)"
            },
            "target": {
                "type": "string",
                "description": "Target URL. For ffuf, append FUZZ (e.g. 'https://example.com/FUZZ')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "ffuf args. Remember to use -t or custom headers if stealth is needed. (e.g. ['-e', '.php,.bak', '-t', '50'])"
            },
            "list_type": {
                "type": "string",
                "enum": ["user", "ia"],
                "description": "'user' = local share/wordlists profiles | 'ia' = inline paths"
            },
            "inline_wordlist": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Inline paths (e.g. ['robots.txt', '.env'])"
            },
            "builtin_list": {
                "type": "string",
                "enum": ["short", "medium", "large"],
                "description": "Local built-in wordlist profile from share/wordlists"
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
    print("WEB FUZZING — EXAMPLES")
    print("=" * 60)
    
    # 1. Custom Fast Prober (robots.txt, sitemap)
    r1 = web_fuzz(
        tool="custom",
        target="https://hackerone.com",
        list_type="ia",
        inline_wordlist=["robots.txt", "sitemap.xml", ".well-known/security.txt", ".git/HEAD"]
    )
    print("\n=== CUSTOM QUICK PROBER ===")
    for item in r1['results']:
        print(f"[{item['status']}] {item['url']} (Length: {item['length']})")

    # 2. Ffuf with Built-in list
    r2 = web_fuzz(
        tool="ffuf",
        target="https://hackerone.com/FUZZ",
        args=["-t", "50", "-mc", "200"],
        list_type="user",
        builtin_list="medium"
    )
    print("\n=== FFUF BRUTE FORCE ===")
    print(f"Command: {r2['command']}")
    print(f"Wordlist: {r2['wordlist_used']}")
    print(f"Total Found: {r2['total_found']}")
    print(f"Soft404 Filtered: {r2.get('soft404_filtered', 0)}")
    print(f"Template Noise Filtered: {r2.get('template_noise_filtered', 0)}")
    if r2.get("soft404_baseline_lengths"):
        print(f"Soft404 Baseline Lengths: {r2['soft404_baseline_lengths']}")
    if r2.get("results"):
        grouped: dict[str, list[str]] = {}
        for item in r2["results"]:
            status = str(item.get("status", 0))
            entry = item.get("path") or item.get("url", "")
            grouped.setdefault(status, [])
            if entry and entry not in grouped[status]:
                grouped[status].append(entry)

        print("Grouped Results By Status:")
        print(json.dumps(grouped, indent=2))

    if r2.get("error"):
        print(f"Error: {r2['error']}")