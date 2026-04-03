import subprocess
import json
import re
import time
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class VHostRequest(BaseModel):
    tool: str
    target: str                        # IP or base domain
    domain: str                        # Base domain for Host header fuzzing
    wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"ffuf", "gobuster"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if v.strip() in blocked:
            raise ValueError(f"Target '{v}' is blocked")

        ip_pattern     = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"

        if not (re.match(ip_pattern, v) or re.match(domain_pattern, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @validator("domain")
    def validate_domain(cls, v):
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        if not re.match(domain_pattern, v):
            raise ValueError(f"Invalid domain: {v}")
        return v.strip()

    @validator("wordlist")
    def validate_wordlist(cls, v):
        # Block path traversal / shell injection in wordlist path
        dangerous = [";", "&&", "||", "|", "`", "$(", "..", "'", '"']
        for char in dangerous:
            if char in v:
                raise ValueError(f"Dangerous character '{char}' in wordlist path")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        """Block shell injection ONLY — let agent use ALL tool features"""
        dangerous_chars  = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags    = ["-o", "--output"]  # prevent file write / exfil

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Output flag blocked: {arg}")
        return v


# ── Single VHost Result ──
class VHostResult(BaseModel):
    vhost: str                          # Discovered virtual host (e.g. dev.example.com)
    status_code: Optional[int]  = None
    content_length: Optional[int] = None
    content_words: Optional[int] = None
    content_lines: Optional[int] = None
    redirect_location: Optional[str] = None
    response_time: Optional[float] = None   # ms
    extra: Optional[dict[str, Any]] = None  # tool-specific extras


# ── Final Result ──
class VHostScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    domain: str
    command: str
    wordlist: str
    total_found: int = 0
    vhosts: list[VHostResult] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_ffuf(stdout: str) -> list[VHostResult]:
    """
    Parse ffuf output.

    Supports two formats:
      1. JSON (--of json)   — structured, preferred
      2. Plain text         — regex fallback
    """
    results: list[VHostResult] = []

    # ══════════════════════════════
    # TRY JSON PARSE  (--of json)
    # ══════════════════════════════
    try:
        data = json.loads(stdout)
        for entry in data.get("results", []):
            results.append(VHostResult(
                vhost=entry.get("input", {}).get("FUZZ", entry.get("host", "unknown")),
                status_code=entry.get("status"),
                content_length=entry.get("length"),
                content_words=entry.get("words"),
                content_lines=entry.get("lines"),
                redirect_location=entry.get("redirectlocation") or None,
                response_time=entry.get("duration"),
                extra={
                    "url":      entry.get("url"),
                    "position": entry.get("position"),
                } if entry.get("url") else None,
            ))
        return results
    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    # ══════════════════════════════
    # FALLBACK: REGEX PARSE
    # ══════════════════════════════
    # Sample line:
    # dev                     [Status: 200, Size: 4321, Words: 123, Lines: 56, Duration: 42ms]
    pattern = re.compile(
        r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)"
        r"(?:,\s*Duration:\s*([\d.]+)ms)?",
        re.MULTILINE,
    )
    for m in pattern.finditer(stdout):
        results.append(VHostResult(
            vhost=m.group(1),
            status_code=int(m.group(2)),
            content_length=int(m.group(3)),
            content_words=int(m.group(4)),
            content_lines=int(m.group(5)),
            response_time=float(m.group(6)) if m.group(6) else None,
        ))

    return results


def parse_gobuster(stdout: str) -> list[VHostResult]:
    """
    Parse gobuster vhost output.

    Supports two formats:
      1. JSON (--no-progress -o /dev/stdout -z ... actually --format json in newer builds)
      2. Plain text (default)

    Typical plain-text line:
      Found: dev.example.com (Status: 200) [Size: 4321]
    or (newer gobuster):
      Found: dev.example.com Status: 200 [Length: 4321]
    """
    results: list[VHostResult] = []

    # ══════════════════════════════
    # TRY JSON PARSE
    # ══════════════════════════════
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append(VHostResult(
                vhost=obj.get("vhost", obj.get("found", "unknown")),
                status_code=obj.get("statusCode") or obj.get("status"),
                content_length=obj.get("size") or obj.get("length"),
            ))
            continue
        except (json.JSONDecodeError, TypeError):
            pass

        # ══════════════════════════════
        # FALLBACK: PLAIN TEXT
        # ══════════════════════════════
        patterns = [
            # Found: dev.example.com (Status: 200) [Size: 1234]
            r"Found:\s+(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]",
            # Found: dev.example.com Status: 200 [Length: 1234]
            r"Found:\s+(\S+)\s+Status:\s*(\d+)\s+\[Length:\s*(\d+)\]",
            # dev.example.com [200]
            r"^(\S+\.\S+)\s+\[(\d+)\]",
        ]
        for pat in patterns:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                results.append(VHostResult(
                    vhost=m.group(1),
                    status_code=int(m.group(2)) if len(m.groups()) >= 2 else None,
                    content_length=int(m.group(3)) if len(m.groups()) >= 3 else None,
                ))
                break

    return results


# ══════════════════════════════════════════════════════════════
# 3. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run command safely — no shell, no injection"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 4. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def vhost_discovery(
    tool: str,
    target: str,
    domain: str,
    wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    args: list[str] = [],
) -> dict:
    """
    🔧 Agent Tool: Virtual Host Discovery via Host Header Fuzzing

    Discovers virtual hosts (vhosts) running on the same IP by fuzzing
    the HTTP Host header with a wordlist. Each subdomain candidate is
    sent as:  Host: <candidate>.<domain>

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  VHOST FUZZING        ffuf (fast, JSON output)              │
      │  VHOST ENUM           gobuster vhost mode                   │
      │  FILTER BY SIZE       ffuf -fs <size>                       │
      │  FILTER BY STATUS     ffuf -fc <codes> / gobuster           │
      │  HTTPS SUPPORT        ffuf -u https:// / gobuster -k        │
      │  RATE LIMITING        ffuf -rate / gobuster --delay         │
      └─────────────────────────────────────────────────────────────┘

    Args:
        tool:      "ffuf" | "gobuster"
        target:    IP or domain of the web server (e.g. "10.10.10.1", "example.com")
        domain:    Base domain for Host header (e.g. "example.com")
                   Fuzzes as: Host: FUZZ.example.com
        wordlist:  Path to subdomain wordlist
        args:      Raw tool arguments — agent decides

    ffuf args reference:
        Filter size:    ["-fs", "4242"]           filter out default page size
        Filter status:  ["-fc", "404,302"]        filter response codes
        Match status:   ["-mc", "200,301"]        only show matched codes
        HTTPS:          ["-u", "https://TARGET"]  override URL scheme
        Threads:        ["-t", "50"]              concurrent threads (default 40)
        Rate limit:     ["-rate", "100"]          requests/second
        Timeout:        ["-timeout", "10"]        per-request timeout (seconds)
        Delay:          ["-p", "0.1"]             delay between requests
        Proxy:          ["-x", "http://127.0.0.1:8080"]

    gobuster args reference:
        HTTPS:          ["-k"]                    skip TLS verification
        Threads:        ["-t", "30"]
        Delay:          ["--delay", "200ms"]
        User-agent:     ["-a", "Mozilla/5.0"]
        Proxy:          ["--proxy", "http://127.0.0.1:8080"]
        Append domain:  ["--append-domain"]       append .domain to each wordlist entry
        Status filter:  ["--exclude-length", "0"] exclude by content length

    Returns:
        Structured JSON: vhosts → status_code, content_length, redirect, response_time
    """

    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = VHostRequest(
            tool=tool,
            target=target,
            domain=domain,
            wordlist=wordlist,
            args=args,
        )
    except Exception as e:
        return VHostScanResult(
            success=False, tool=tool, target=target, domain=domain,
            command="", wordlist=wordlist, error=f"Validation: {e}"
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if tool == "ffuf":
        # ffuf Host header fuzzing:
        # ffuf -w wordlist -u http://TARGET -H "Host: FUZZ.domain" -of json
        cmd = [
            "ffuf",
            "-w", req.wordlist,
            "-u", f"http://{req.target}",
            "-H", f"Host: FUZZ.{req.domain}",
            "-of", "json",   # structured output for reliable parsing
        ] + list(req.args)

    elif tool == "gobuster":
        # gobuster vhost mode:
        # gobuster vhost -u http://TARGET -w wordlist --domain domain
        cmd = [
            "gobuster", "vhost",
            "-u", f"http://{req.target}",
            "-w", req.wordlist,
            "--domain", req.domain,
            "--no-progress",           # cleaner output for parsing
        ] + list(req.args)

    else:
        return VHostScanResult(
            success=False, tool=tool, target=target, domain=domain,
            command="", wordlist=wordlist, error=f"Unknown tool: {tool}"
        ).model_dump()

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    command_str = " ".join(cmd)
    stdout, stderr, rc = safe_execute(cmd, req.timeout)

    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    vhosts: list[VHostResult] = []

    if tool == "ffuf":
        vhosts = parse_ffuf(stdout)
    elif tool == "gobuster":
        vhosts = parse_gobuster(stdout)

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    return VHostScanResult(
        success=len(vhosts) > 0 or rc == 0,
        tool=tool,
        target=target,
        domain=domain,
        command=command_str,
        wordlist=wordlist,
        total_found=len(vhosts),
        vhosts=vhosts,
        raw_output=(stdout or stderr)[:5000],
        error=stderr if rc != 0 and not vhosts else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 5. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

VHOST_DISCOVERY_TOOL_DEFINITION = {
    "name": "vhost_discovery",
    "description": (
        "Discover virtual hosts running on the same IP by fuzzing the HTTP Host header. "
        "Sends wordlist entries as Host: FUZZ.<domain> and identifies unique responses. "
        "Supports ffuf (fast, JSON-native) and gobuster (vhost mode). "
        "YOU decide the args, especially filter flags (-fs / --exclude-length) to remove noise."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["ffuf", "gobuster"],
                "description": (
                    "ffuf = fast HTTP fuzzer with JSON output (preferred) | "
                    "gobuster = vhost enumeration mode"
                ),
            },
            "target": {
                "type": "string",
                "description": "IP or domain of the web server (e.g. '10.10.10.1', 'example.com')",
            },
            "domain": {
                "type": "string",
                "description": (
                    "Base domain for Host header fuzzing. "
                    "Wordlist entries are sent as: Host: FUZZ.<domain> "
                    "(e.g. 'example.com' → Host: dev.example.com)"
                ),
            },
            "wordlist": {
                "type": "string",
                "description": (
                    "Full path to subdomain wordlist. "
                    "Defaults to SecLists top-5000 subdomains. "
                    "Example: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'"
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "ffuf filter size:   ['-fs', '4242']           ← REQUIRED to remove noise\n"
                    "ffuf filter codes:  ['-fc', '404,302']\n"
                    "ffuf threads:       ['-t', '50']\n"
                    "ffuf rate limit:    ['-rate', '100']\n"
                    "ffuf HTTPS:         ['-u', 'https://TARGET']   ← overrides default URL\n"
                    "gobuster HTTPS:     ['-k']\n"
                    "gobuster threads:   ['-t', '30']\n"
                    "gobuster delay:     ['--delay', '200ms']\n"
                    "gobuster ex-len:    ['--exclude-length', '0']  ← filter by content length\n"
                    "gobuster proxy:     ['--proxy', 'http://127.0.0.1:8080']"
                ),
            },
        },
        "required": ["tool", "target", "domain"],
    },
}


# ══════════════════════════════════════════════════════════════
# 6. USAGE EXAMPLES — WHAT AGENT CALLS
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Basic ffuf vhost discovery
    # ─────────────────────────────
    r = vhost_discovery(
        tool="ffuf",
        target="10.10.10.1",
        domain="example.com",
        args=["-fs", "4242", "-t", "50"],
    )
    print("=== FFUF BASIC ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. ffuf with status + size filter
    # ─────────────────────────────
    r = vhost_discovery(
        tool="ffuf",
        target="10.10.10.1",
        domain="example.com",
        args=["-fc", "404,302", "-fs", "4242", "-t", "100", "-rate", "200"],
    )
    print("=== FFUF FILTERED ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. ffuf HTTPS target
    # ─────────────────────────────
    r = vhost_discovery(
        tool="ffuf",
        target="10.10.10.1",
        domain="example.com",
        args=["-u", "https://10.10.10.1", "-fs", "1234", "-t", "40"],
    )
    print("=== FFUF HTTPS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. ffuf with custom wordlist
    # ─────────────────────────────
    r = vhost_discovery(
        tool="ffuf",
        target="10.10.10.1",
        domain="example.com",
        wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        args=["-fs", "4242", "-t", "80"],
    )
    print("=== FFUF CUSTOM WORDLIST ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. gobuster vhost basic
    # ─────────────────────────────
    r = vhost_discovery(
        tool="gobuster",
        target="10.10.10.1",
        domain="example.com",
        args=["-t", "30"],
    )
    print("=== GOBUSTER BASIC ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. gobuster HTTPS + skip TLS
    # ─────────────────────────────
    r = vhost_discovery(
        tool="gobuster",
        target="10.10.10.1",
        domain="example.com",
        args=["-k", "-t", "30"],
    )
    print("=== GOBUSTER HTTPS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. gobuster with delay (stealth)
    # ─────────────────────────────
    r = vhost_discovery(
        tool="gobuster",
        target="10.10.10.1",
        domain="example.com",
        args=["--delay", "200ms", "-t", "10"],
    )
    print("=== GOBUSTER STEALTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 8. gobuster exclude by length
    # ─────────────────────────────
    r = vhost_discovery(
        tool="gobuster",
        target="10.10.10.1",
        domain="example.com",
        args=["--exclude-length", "0", "-t", "30"],
    )
    print("=== GOBUSTER EXCLUDE LENGTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 9. ffuf via proxy (Burp)
    # ─────────────────────────────
    r = vhost_discovery(
        tool="ffuf",
        target="10.10.10.1",
        domain="example.com",
        args=["-fs", "4242", "-x", "http://127.0.0.1:8080"],
    )
    print("=== FFUF BURP PROXY ===")
    print(json.dumps(r, indent=2))