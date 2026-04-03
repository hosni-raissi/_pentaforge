import subprocess
import json
import os
import time
import tempfile
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. BUILT-IN WEB WORDLISTS
# ══════════════════════════════════════════════════════════════

def _get_web_wordlists() -> dict[str, str]:
    wl_dir = ProjectConfig.get_wordlists_dir()
    wordlists = {
        "common": [
            wl_dir / "common.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
        ],
        "raft_small_dirs": [
            wl_dir / "raft-small-directories.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt")
        ],
        "raft_small_files": [
            wl_dir / "raft-small-files.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt")
        ],
        "quickhits": [
            wl_dir / "quickhits.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/quickhits.txt")
        ],
        "cgis": [
            wl_dir / "cgis.txt",
            Path("/usr/share/seclists/Discovery/Web-Content/cgis.txt")
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
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class WebFuzzRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    list_type: str = "mine"
    inline_wordlist: Optional[list[str]] = None
    builtin_list: Optional[str] = None
    timeout: int = Field(default=600, ge=10, le=7200)

    @validator("tool")
    def val_tool(cls, v):
        if v not in {"ffuf", "custom"}: raise ValueError("Tool must be 'ffuf' or 'custom'")
        return v

    @validator("target")
    def val_target(cls, v):
        if not v.startswith("http"): raise ValueError("Target must be a URL (e.g. https://example.com/FUZZ)")
        return v.strip()

    @validator("args")
    def val_args(cls, v):
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg")
        return v

    @validator("builtin_list")
    def val_builtin(cls, v):
        if v is not None and v not in _get_web_wordlists():
            raise ValueError(f"Unknown wordlist: {v}")
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
    results: list[FuzzResultItem] = []
    wordlist_used: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. CUSTOM PROBER (FAST WELL-KNOWN CHECKER)
# ══════════════════════════════════════════════════════════════

def run_custom_fuzzer(target: str, paths: list[str]) -> list[FuzzResultItem]:
    """
    Native python prober for quickly checking well-known paths 
    without the overhead of ffuf.
    """
    results = []
    base_url = target.replace("FUZZ", "").rstrip("/")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for path in paths:
        path = path if path.startswith("/") else f"/{path}"
        url = f"{base_url}{path}"
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                body = response.read()
                results.append(FuzzResultItem(
                    url=url,
                    path=path,
                    status=response.getcode(),
                    length=len(body),
                    content_type=response.headers.get("Content-Type", "")
                ))
        except urllib.error.HTTPError as e:
            # We often care about 403s or 401s in pentesting
            if e.code in [401, 403]:
                results.append(FuzzResultItem(
                    url=url,
                    path=path,
                    status=e.code,
                    length=0
                ))
        except Exception:
            pass
            
    return results


# ══════════════════════════════════════════════════════════════
# 4. FFUF COMMAND BUILDER & PARSER
# ══════════════════════════════════════════════════════════════

def _build_ffuf_cmd(args: list[str], target: str, wordlist_path: str) -> tuple[list[str], Path]:
    cmd = ["ffuf"]
    final_args = list(args)

    # 1. Force JSON output to file
    tmp_file = ProjectConfig.get_temp_dir() / f"ffuf_{int(time.time())}.json"
    if not _has_flag(final_args, ["-o"]):
        final_args.extend(["-o", str(tmp_file), "-of", "json"])

    # 2. Append FUZZ keyword if missing
    clean_target = target
    if "FUZZ" not in clean_target:
        clean_target = f"{clean_target.rstrip('/')}/FUZZ"

    # 3. Add target
    if not _target_in_args(clean_target, final_args, ["-u"]):
        final_args.extend(["-u", clean_target])

    # 4. Add wordlist (ffuf syntax: -w wordlist.txt)
    if not _has_flag(final_args, ["-w"]):
        final_args.extend(["-w", wordlist_path])
        
    # 5. Default matchers (if agent didn't provide any)
    if not _has_flag(final_args, ["-mc", "-fc"]):
        final_args.extend(["-mc", "200,204,301,302,307,401,403"])

    cmd.extend(final_args)
    return cmd, tmp_file


def parse_ffuf(tmp_file: Path) -> list[FuzzResultItem]:
    results = []
    if not tmp_file.exists():
        return results

    try:
        data = json.loads(tmp_file.read_text())
        for item in data.get("results", []):
            results.append(FuzzResultItem(
                url=item.get("url", ""),
                path=item.get("input", {}).get("FFUF", ""), # The word that matched
                status=item.get("status", 0),
                length=item.get("length", 0),
                words=item.get("words", 0),
                lines=item.get("lines", 0),
                content_type=item.get("content-type", ""),
                redirect_location=item.get("redirectlocation", "")
            ))
    except Exception:
        pass
    finally:
        try: tmp_file.unlink()
        except OSError: pass

    return results


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def web_fuzz(
    tool: str,
    target: str,
    args: list[str] = [],
    list_type: str = "mine",
    inline_wordlist: Optional[list[str]] = None,
    builtin_list: Optional[str] = None,
) -> dict:
    """
    🔧 Agent Tool: Web Fuzzing & Well-Known File Checking
    
    Tools:
      - 'ffuf': Full directory/file brute forcing.
      - 'custom': Rapid native python checker for a short list of specific files 
                  (robots.txt, sitemap.xml) without needing wordlists.
    """
    start = time.time()
    
    try:
        req = WebFuzzRequest(
            tool=tool, target=target, args=args, list_type=list_type,
            inline_wordlist=inline_wordlist, builtin_list=builtin_list
        )
    except Exception as e:
        return WebFuzzResult(success=False, tool=tool, target=target, command="", working_dir="", error=str(e)).model_dump()

    # ── 1. CUSTOM PROBER (FAST) ──
    if tool == "custom":
        # Default well-known paths if none provided
        paths = inline_wordlist if inline_wordlist else [
            "robots.txt", "sitemap.xml", ".well-known/security.txt", 
            "crossdomain.xml", ".git/HEAD", ".env"
        ]
        
        results = run_custom_fuzzer(target, paths)
        return WebFuzzResult(
            success=True, tool=tool, target=target, command="native python request",
            working_dir=str(ProjectConfig.get_project_dir()),
            total_found=len(results), results=results,
            execution_time=round(time.time() - start, 2)
        ).model_dump()


    # ── 2. FFUF (HEAVY BRUTE FORCE) ──
    wordlist_path = None
    tmp_wl = None

    if list_type == "mine" and builtin_list:
        wordlist_path = _get_web_wordlists().get(builtin_list)
    elif list_type == "yours" and inline_wordlist:
        tmp_wl = tempfile.NamedTemporaryFile(mode="w", delete=False, dir=ProjectConfig.get_temp_dir())
        tmp_wl.write("\n".join(inline_wordlist))
        tmp_wl.close()
        wordlist_path = tmp_wl.name

    if not wordlist_path:
        return WebFuzzResult(success=False, tool=tool, target=target, command="", working_dir="", error="No wordlist provided").model_dump()

    cmd, json_out_file = _build_ffuf_cmd(args, target, wordlist_path)
    command_str = " ".join(cmd)
    
    # Execute
    _, stderr, rc, cwd = safe_execute(cmd, req.timeout)

    # Parse
    results = parse_ffuf(json_out_file)

    # Cleanup inline wordlist
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
        "well-known paths (robots.txt, sitemap.xml, etc)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["ffuf", "custom"],
                "description": "ffuf (heavy wordlists) | custom (fast native python check for well-known files)"
            },
            "target": {
                "type": "string",
                "description": "Target URL. For ffuf, append FUZZ (e.g. 'https://example.com/FUZZ')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "ffuf args (e.g. ['-e', '.php,.bak', '-t', '50'])"
            },
            "list_type": {
                "type": "string",
                "enum": ["mine", "yours"],
                "description": "'mine' = SecLists | 'yours' = inline paths"
            },
            "inline_wordlist": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Inline paths (e.g. ['robots.txt', '.env'])"
            },
            "builtin_list": {
                "type": "string",
                "enum": ["common", "raft_small_dirs", "raft_small_files", "quickhits", "cgis"],
                "description": "Built-in SecLists wordlist"
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
        list_type="yours",
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
        list_type="mine",
        builtin_list="common"
    )
    print("\n=== FFUF BRUTE FORCE ===")
    print(f"Command: {r2['command']}")
    print(f"Wordlist: {r2['wordlist_used']}")
    print(f"Total Found: {r2['total_found']}")