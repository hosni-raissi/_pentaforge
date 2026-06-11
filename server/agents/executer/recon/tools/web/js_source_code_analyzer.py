#/+
"""
JS Source Code Analyzer — Agent Tool
=====================================
Wraps secretfinder and js-beautify into a single
structured, LLM-callable tool with proper validation, SSRF protection,
and resilient output parsing.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# ══════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("js_analyzer")


# ══════════════════════════════════════════════════════════════════════
# 1. PROJECT CONFIG
# ══════════════════════════════════════════════════════════════════════

class ProjectConfig:
    """Resolves the project root and manages temp directories."""

    _project_dir: Optional[Path] = None
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
        for candidate in [current, *current.parents]:
            if any(
                (candidate / m).exists()
                for m in ("pyproject.toml", "setup.py", ".git")
            ):
                cls._project_dir = candidate
                return cls._project_dir

        cls._project_dir = Path.cwd()
        return cls._project_dir

    @classmethod
    def get_temp_dir(cls) -> Path:
        path = cls.get_project_dir() / cls.TEMP_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path


# ══════════════════════════════════════════════════════════════════════
# 2. SSRF GUARD
# ══════════════════════════════════════════════════════════════════════

from server.agents.executer.recon.config import is_blocked_host


def _is_ssrf_safe(hostname: str) -> tuple[bool, str]:
    """
    Resolve the hostname and verify it does not point to an internal
    or reserved IP address. Returns (is_safe, reason).
    """
    if is_blocked_host(hostname):
        return False, f"Blocked hostname: {hostname}"

    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        # Unresolvable host — block it; we cannot verify it's safe.
        return False, f"DNS resolution failed: {exc}"

    for _, _, _, _, sockaddr in results:
        raw_ip = sockaddr[0]
        if is_blocked_host(raw_ip):
            return False, f"IP {raw_ip} is blocked"

    return True, ""


# ══════════════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════════════

VALID_TOOLS = frozenset({"secretfinder", "js-beautify"})


class JsAnalyzerRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=300, ge=10, le=1200)

    @model_validator(mode="before")
    @classmethod
    def validate_required_url_scheme(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data

        tool = str(data.get("tool", "")).strip()
        target = str(data.get("target", "")).strip()
        if (
            tool in {"secretfinder"}
            and target
            and not target.startswith(("http://", "https://"))
        ):
            raise ValueError(
                f"{tool} requires a full target URL starting with http:// or https://"
            )

        return data

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in VALID_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(VALID_TOOLS)}")
        return v


    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")

        # Strip scheme to extract hostname
        hostname = re.sub(r"^\w+://", "", v).split("/")[0].split("?")[0].split(":")[0]

        safe, reason = _is_ssrf_safe(hostname)
        if not safe:
            raise ValueError(f"SSRF check failed for '{v}': {reason}")

        return v

    @model_validator(mode="after")
    def validate_args_no_shell_injection(self) -> "JsAnalyzerRequest":
        dangerous = {";", "&&", "||", "|", "`", "$", ">", "<", "\n"}
        for arg in self.args:
            if any(ch in arg for ch in dangerous):
                raise ValueError(f"Suspicious shell character in args: {arg!r}")
        return self


class Secret(BaseModel):
    name: str
    value: str


class JsAnalyzerResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str

    js_urls: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    beautified_code: Optional[str] = None

    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════════════
# 4. UTILITIES
# ══════════════════════════════════════════════════════════════════════

def _has_flag(args: list[str], *flags: str) -> bool:
    return any(arg in args for arg in flags)


def _target_in_args(target: str, args: list[str], *flags: str) -> bool:
    """Return True if target already appears in args, either bare or after a flag."""
    t = target.strip().lower()
    flag_set = set(flags)
    for i, arg in enumerate(args):
        a = arg.strip().lower()
        if a == t or t in a:
            return True
        if a in flag_set and i + 1 < len(args) and args[i + 1].strip().lower() == t:
            return True
    return False


def safe_execute(
    cmd: list[str],
    timeout: int = 300,
) -> tuple[str, str, int, str]:
    """Run a subprocess safely via run_custom in the sandbox. Returns (stdout, stderr, returncode, cwd)."""
    cwd = str(ProjectConfig.get_project_dir())
    log.debug("Executing via run_custom: %s", " ".join(cmd))
    try:
        from server.agents.tools.run_custom import run_custom
        
        # If the command is js-beautify and involves a local temp file,
        # we can't easily pass it to the sandbox since the file is on the backend.
        # But wait! If we rewrite the command to use curl for js-beautify in run_custom?
        # Actually, if secretfinder is used, it takes a URL natively.
        
        result = run_custom(
            command=cmd[0],
            reason=f"Internal js analysis execution of {cmd[0]}",
            args=cmd[1:],
            timeout=timeout,
        )
        rc = result.get("return_code", -1)
        stdout = str(result.get("stdout") or "")
        stderr = str(result.get("error") or result.get("stderr") or "")
        if rc != 0 and "not found" in stderr.lower():
            return "", f"Tool not installed or not in PATH: '{cmd[0]}'", -1, cwd
        return stdout, stderr, rc, cwd
    except Exception as exc:
        return "", str(exc), -1, cwd


def download_file(url: str) -> tuple[Optional[Path], Optional[str]]:
    """
    Download a remote JS file to a temporary local path.
    TLS verification is *enabled*. If the server has an invalid cert, the
    download will fail and the caller should handle the error gracefully.
    """
    try:
        ctx = ssl.create_default_context()  # verify_mode=CERT_REQUIRED by default
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (JS-Analyzer-Agent/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            content = resp.read()

        # Use the shared cache directory so the sandbox can access the downloaded file
        cache_dir = ProjectConfig.get_project_dir() / "server" / "cache" / "tmp"
        cache_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = cache_dir / f"js_{int(time.time() * 1000)}.js"
        tmp_path.write_bytes(content)
        log.debug("Downloaded %d bytes → %s", len(content), tmp_path)
        return tmp_path, None

    except ssl.SSLError as exc:
        log.error("TLS error downloading %s: %s", url, exc)
        return None, str(exc)
    except Exception as exc:  # noqa: BLE001
        log.error("Failed to download %s: %s", url, exc)
        return None, str(exc)


def _build_secretfinder_cmd(target: str, args: list[str]) -> list[str]:
    extra: list[str] = []
    if not _target_in_args(target, args, "-i", "--input"):
        extra += ["-i", target]
    if not _has_flag(args, "-o", "--output"):
        extra += ["-o", "cli"]
    return ["secretfinder", *extra, *args]


def _build_jsbeautify_cmd(
    target: str, args: list[str]
) -> tuple[list[str], Optional[Path], Optional[str]]:
    """Returns (cmd, tmp_file, download_error)."""
    tmp_file: Optional[Path] = None
    download_error: Optional[str] = None
    extra: list[str] = []

    if target.startswith(("http://", "https://")):
        tmp_file, download_error = download_file(target)
        if tmp_file:
            extra.append(str(tmp_file))
        # If download failed, we still build the cmd; caller checks tmp_file.
    else:
        if not _target_in_args(target, args, "-f", "--file"):
            extra.append(target)

    return ["js-beautify", *extra, *args], tmp_file, download_error


# ══════════════════════════════════════════════════════════════════════
# 6. PARSERS
# ══════════════════════════════════════════════════════════════════════

_URL_RE = re.compile(r"^https?://\S+$")
_ENDPOINT_RE = re.compile(r"^(?:/[\w/\-%.?=&]*|https?://\S+|[\w\-]+\.(php|html|js|json|xml))$")
_BANNER_PATTERNS = re.compile(
    r"(running against|linkfinder|error:|^\s*$)", re.IGNORECASE
)
_SECRET_RE = re.compile(r"^\[\+\]\s*(?P<name>[^:]+?):\s*(?P<value>.+)$")


def _deduplicate(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_secretfinder(stdout: str) -> list[Secret]:
    seen: set[str] = set()
    secrets: list[Secret] = []
    for line in stdout.splitlines():
        m = _SECRET_RE.match(line.strip())
        if not m:
            continue
        name = m.group("name").strip()
        value = m.group("value").strip()
        key = f"{name}:{value}"
        if key not in seen:
            seen.add(key)
            secrets.append(Secret(name=name, value=value))
    return secrets


# ══════════════════════════════════════════════════════════════════════
# 7. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════════════

BEAUTIFY_CHAR_LIMIT = 10_000


def _pick_demo_js_url(js_urls: list[str]) -> Optional[str]:
    candidates = [url for url in js_urls if ".js" in url.lower()]
    if not candidates:
        return None
    return sorted(candidates, key=lambda url: ("?" in url, len(url), url))[0]


def js_source_code_analyzer(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
) -> dict:
    """
    Agent Tool — JS Source Code Analyzer

    Dispatches to one of the supported JS analysis tools and returns structured results.

    Args:
        tool:   One of 'secretfinder' or 'js-beautify'.
        target: A URL for secretfinder, or a URL/local file path for js-beautify.
        args:   Optional extra CLI flags to forward to the underlying tool.

    Returns:
        A JsAnalyzerResult dict ready for LLM consumption.
    """
    # Defensive default — avoids the mutable-default-argument footgun
    if args is None:
        args = []

    start = time.perf_counter()

    # ── Validate input ──────────────────────────────────────────────
    try:
        req = JsAnalyzerRequest(tool=tool, target=target, args=args)
    except Exception as exc:
        return JsAnalyzerResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            working_dir="",
            error=str(exc),
        ).model_dump()

    # ── Build command ───────────────────────────────────────────────
    tmp_file: Optional[Path] = None
    download_error: Optional[str] = None

    if req.tool == "secretfinder":
        cmd = _build_secretfinder_cmd(req.target, req.args)
    elif req.tool == "js-beautify":
        cmd, tmp_file, download_error = _build_jsbeautify_cmd(req.target, req.args)
        if tmp_file is None and req.target.startswith(("http://", "https://")):
            return JsAnalyzerResult(
                success=False,
                tool=req.tool,
                target=req.target,
                command="js-beautify",
                working_dir=str(ProjectConfig.get_project_dir()),
                error=(
                    "Failed to download JS file for beautification: "
                    f"{download_error or 'unknown error'}"
                ),
            ).model_dump()
    else:
        # Unreachable — Pydantic validates 'tool' — but keeps mypy happy
        raise AssertionError(f"Unhandled tool: {req.tool!r}")

    command_str = " ".join(cmd)

    # ── Execute ─────────────────────────────────────────────────────
    try:
        stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)
    finally:
        # Always clean up the temp file, even on unexpected errors
        if tmp_file:
            try:
                tmp_file.unlink(missing_ok=True)
            except OSError as exc:
                log.warning("Could not remove temp file %s: %s", tmp_file, exc)

    # ── Parse results ───────────────────────────────────────────────
    js_urls: list[str] = []
    endpoints: list[str] = []
    secrets: list[Secret] = []
    beautified_code: Optional[str] = None

    if req.tool == "secretfinder":
        secrets = parse_secretfinder(stdout)
    elif req.tool == "js-beautify":
        if len(stdout) > BEAUTIFY_CHAR_LIMIT:
            beautified_code = (
                stdout[:BEAUTIFY_CHAR_LIMIT]
                + "\n\n... [TRUNCATED — context window limit] ..."
            )
        else:
            beautified_code = stdout or None

    has_results = bool(js_urls or endpoints or secrets or beautified_code)
    success = (rc == 0) or has_results

    # Only surface stderr when we have nothing useful to show
    error = stderr.strip() if (rc != 0 and not has_results) else None

    return JsAnalyzerResult(
        success=success,
        tool=req.tool,
        target=req.target,
        command=command_str,
        working_dir=cwd,
        js_urls=js_urls,
        endpoints=endpoints,
        secrets=secrets,
        beautified_code=beautified_code,
        error=error,
        execution_time=round(time.perf_counter() - start, 3),
    ).model_dump()


# ══════════════════════════════════════════════════════════════════════
# 8. TOOL DEFINITION  (Anthropic / OpenAI function-calling format)
# ══════════════════════════════════════════════════════════════════════

JS_ANALYZER_TOOL_DEFINITION: dict = {
    "name": "js_source_code_analyzer",
    "description": (
        "Analyze JavaScript files from a target web application. "
        "Use 'secretfinder' to find API keys, tokens, and secrets embedded in JS. "
        "Use 'js-beautify' to unminify/deobfuscate a JS file for manual review."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": sorted(VALID_TOOLS),
                "description": "The JS analysis tool to invoke.",
            },
            "target": {
                "type": "string",
                "description": (
                    "Target URL. For 'secretfinder', "
                    "provide a full URL starting with http:// or https://. "
                    "For 'js-beautify', provide either a full URL or a local file path."
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Additional CLI flags to forward to the underlying tool (optional).",
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════════════
# 9. DEMO
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # ⚠️  Replace with a domain you own or have written authorisation to test.
    TEST_TARGET = "https://hackerone.com"
    first_result = js_source_code_analyzer(tool="secretfinder", target=TEST_TARGET, args=[])

    print(f"\n{'=' * 60}")
    print(f"  SECRETFINDER  →  {TEST_TARGET}")
    print("=" * 60)
    print(f"  Success : {first_result['success']}")
    print(f"  Command : {first_result['command']}")
    print(f"  Time    : {first_result['execution_time']}s")
    if first_result.get("error"):
        print(f"  Error   : {first_result['error']}")
    if first_result["secrets"]:
        print(f"  Secrets ({len(first_result['secrets'])}):")
        for item in first_result["secrets"][:5]:
            print(f"    - {item['name']}: {item['value']}")

    demo_js = TEST_TARGET
    if not demo_js:
        print("\nSkipping follow-up demos: no usable JS target was selected.")
        raise SystemExit(0)

    demos = [("js-beautify", demo_js, [])]

    for tool_name, tgt, extra_args in demos:
        print(f"\n{'=' * 60}")
        print(f"  {tool_name.upper()}  →  {tgt}")
        print("=" * 60)
        result = js_source_code_analyzer(tool=tool_name, target=tgt, args=extra_args)
        print(f"  Success : {result['success']}")
        print(f"  Command : {result['command']}")
        print(f"  Time    : {result['execution_time']}s")
        if result.get("error"):
            print(f"  Error   : {result['error']}")
        if result["js_urls"]:
            print(f"  JS URLs ({len(result['js_urls'])}):")
            for u in result["js_urls"][:5]:
                print(f"    - {u}")
        if result["endpoints"]:
            print(f"  Endpoints ({len(result['endpoints'])}):")
            for e in result["endpoints"][:5]:
                print(f"    - {e}")
        if result["secrets"]:
            print(f"  Secrets ({len(result['secrets'])}):")
            for s in result["secrets"]:
                print(f"    - {s['name']}: {s['value']}")
        if result["beautified_code"]:
            preview = result["beautified_code"][:300].replace("\n", " ")
            print(f"  Code preview: {preview}...")
