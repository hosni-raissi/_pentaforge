#/+
"""
Run Python Code — Agent Tool
==============================
Sandboxed Python code execution for agents. Creates temporary .py files,
runs them in isolated subprocess, auto-detects dependencies, and enforces
a concurrency limit of 2 simultaneous executions.

Features:
  - Writes code to temp files (auto-cleaned)
  - Detects required pip packages from imports
  - Optionally auto-installs missing dependencies
  - Enforces max 2 concurrent scripts (semaphore)
  - Captures stdout, stderr, return code
  - Timeout protection
  - Blocked dangerous modules / operations
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

# ══════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════

logger = logging.getLogger("run_python")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s — %(message)s", datefmt="%H:%M:%S",
    ))
    logger.addHandler(_handler)


# ══════════════════════════════════════════════════════════════════════
# 1. CONCURRENCY GATE  — max 2 scripts at a time
# ══════════════════════════════════════════════════════════════════════

_MAX_CONCURRENT = 2
_SEMAPHORE = threading.Semaphore(_MAX_CONCURRENT)
_ACTIVE_COUNT_LOCK = threading.Lock()
_ACTIVE_COUNT = 0


def _acquire_slot(timeout: float = 30.0) -> bool:
    """Try to acquire an execution slot. Returns False if all slots are busy."""
    return _SEMAPHORE.acquire(timeout=timeout)


def _release_slot() -> None:
    _SEMAPHORE.release()


def _active_count() -> int:
    with _ACTIVE_COUNT_LOCK:
        return _MAX_CONCURRENT - _SEMAPHORE._value  # type: ignore[attr-defined]


# ══════════════════════════════════════════════════════════════════════
# 2. SECURITY CONSTANTS
# ══════════════════════════════════════════════════════════════════════

# Modules the agent is NOT allowed to import
_BLOCKED_MODULES = frozenset({
    "ctypes", "ctypes.util",
    "subprocess",                       # use run_custom tool instead
    "shutil",                           # no file manipulation
    "pty",                              # no pseudo-terminals
    "resource",                         # no resource manipulation
    "signal",                           # no signal manipulation
    "multiprocessing",                  # no forking
    "webbrowser",                       # no browser opening
    "_thread",                          # no raw threads
    "code", "codeop",                   # no interactive interpreters
    "importlib",                        # no dynamic imports
    "runpy",                            # no module running
    "compileall",                       # no bytecode compilation
    "ensurepip",                        # no pip bootstrapping
})

# Patterns that are never allowed in code (shell escapes, etc.)
_BLOCKED_CODE_PATTERNS = [
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"os\.popen\s*\(", re.IGNORECASE),
    re.compile(r"os\.exec[a-z]*\s*\(", re.IGNORECASE),
    re.compile(r"os\.spawn[a-z]*\s*\(", re.IGNORECASE),
    re.compile(r"os\.fork\s*\(", re.IGNORECASE),
    re.compile(r"os\.kill\s*\(", re.IGNORECASE),
    re.compile(r"os\.remove\s*\(", re.IGNORECASE),
    re.compile(r"os\.unlink\s*\(", re.IGNORECASE),
    re.compile(r"os\.rmdir\s*\(", re.IGNORECASE),
    re.compile(r"os\.rename\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"compile\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"open\s*\([^)]*['\"]w['\"]", re.IGNORECASE),  # write mode
    re.compile(r"open\s*\([^)]*['\"]a['\"]", re.IGNORECASE),  # append mode
]

# Well-known import → pip package mapping
_IMPORT_TO_PACKAGE: dict[str, str] = {
    "bs4":          "beautifulsoup4",
    "cv2":          "opencv-python",
    "dateutil":     "python-dateutil",
    "dns":          "dnspython",
    "dotenv":       "python-dotenv",
    "git":          "gitpython",
    "googleapiclient": "google-api-python-client",
    "jose":         "python-jose",
    "jwt":          "pyjwt",
    "ldap":         "python-ldap",
    "lxml":         "lxml",
    "magic":        "python-magic",
    "nmap":         "python-nmap",
    "PIL":          "Pillow",
    "pysnmp":       "pysnmp",
    "scapy":        "scapy",
    "shodan":       "shodan",
    "sklearn":      "scikit-learn",
    "socks":        "pysocks",
    "whois":        "python-whois",
    "yaml":         "pyyaml",
    "zmq":          "pyzmq",
    "Crypto":       "pycryptodome",
    "Cryptodome":   "pycryptodome",
    "paramiko":     "paramiko",
    "requests":     "requests",
    "httpx":        "httpx",
    "aiohttp":      "aiohttp",
    "rich":         "rich",
    "tabulate":     "tabulate",
    "pandas":       "pandas",
    "numpy":        "numpy",
    "matplotlib":   "matplotlib",
    "netaddr":      "netaddr",
    "ipwhois":      "ipwhois",
    "censys":       "censys",
    "masscan":      "python-masscan",
    "impacket":     "impacket",
    "ldap3":        "ldap3",
    "xmltodict":    "xmltodict",
    "defusedxml":   "defusedxml",
    "netifaces":    "netifaces",
    "psutil":       "psutil",
}

# Standard library modules (no pip install needed)
_STDLIB_MODULES = frozenset({
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
    "asyncore", "atexit", "base64", "binascii", "binhex", "bisect",
    "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk", "cmath",
    "cmd", "codecs", "collections", "colorsys", "configparser",
    "contextlib", "contextvars", "copy", "copyreg", "cProfile",
    "csv", "curses", "dataclasses", "datetime", "dbm", "decimal",
    "difflib", "dis", "distutils", "doctest", "email", "encodings",
    "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
    "fnmatch", "formatter", "fractions", "ftplib", "functools", "gc",
    "getopt", "getpass", "gettext", "glob", "grp", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr",
    "inspect", "io", "ipaddress", "itertools", "json",
    "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
    "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
    "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
    "numbers", "operator", "optparse", "os", "ossaudiodev",
    "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
    "platform", "plistlib", "poplib", "posix", "posixpath", "pprint",
    "profile", "pstats", "pwd", "py_compile", "pyclbr",
    "pydoc", "queue", "quopri", "random", "re", "readline", "reprlib",
    "rlcompleter", "sched", "secrets", "select", "selectors",
    "shelve", "shlex", "smtpd", "smtplib", "sndhdr",
    "socket", "socketserver", "sqlite3", "ssl", "stat", "statistics",
    "string", "stringprep", "struct", "sysconfig",
    "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile",
    "termios", "test", "textwrap", "threading", "time", "timeit",
    "tkinter", "token", "tokenize", "tomllib", "trace", "traceback",
    "tracemalloc", "tty", "turtle", "turtledemo", "types", "typing",
    "unicodedata", "unittest", "urllib", "uu", "uuid", "venv",
    "warnings", "wave", "weakref", "winreg", "winsound", "wsgiref",
    "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
    "sys", "os", "collections", "typing", "typing_extensions",
    "__future__",
})


# ══════════════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════════════

class RunPythonRequest(BaseModel):
    code: str
    reason: str
    install_deps: bool = True
    timeout: int = Field(default=120, ge=5, le=600)

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Code cannot be empty")
        if len(v) > 50_000:
            raise ValueError("Code too large (max 50,000 characters)")

        # Block dangerous patterns
        for pattern in _BLOCKED_CODE_PATTERNS:
            match = pattern.search(v)
            if match:
                raise ValueError(
                    f"Blocked code pattern detected: '{match.group().strip()}'. "
                    "Use dedicated tools instead of shell escapes."
                )

        # AST-level import validation
        try:
            tree = ast.parse(v)
        except SyntaxError as exc:
            raise ValueError(f"Python syntax error: {exc}")

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_module = alias.name.split(".")[0]
                    if top_module in _BLOCKED_MODULES:
                        raise ValueError(f"Import '{alias.name}' is blocked for security")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top_module = node.module.split(".")[0]
                    if top_module in _BLOCKED_MODULES:
                        raise ValueError(f"Import from '{node.module}' is blocked for security")

        return v

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 8:
            raise ValueError("Reason must be at least 8 characters")
        return v


class DependencyInfo(BaseModel):
    package: str
    import_name: str
    installed: bool = False
    install_error: Optional[str] = None


class RunPythonResult(BaseModel):
    success: bool
    code: str
    reason: str
    script_path: str = ""
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    return_code: Optional[int] = None
    dependencies: list[DependencyInfo] = Field(default_factory=list)
    installed_packages: list[str] = Field(default_factory=list)
    active_slots: str = ""
    execution_time: float = 0.0
    error: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════
# 4. DEPENDENCY DETECTION
# ══════════════════════════════════════════════════════════════════════

def _extract_imports(code: str) -> list[str]:
    """Extract all top-level module names from Python code via AST."""
    modules: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return modules

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in modules:
                    modules.append(top)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                if top not in modules:
                    modules.append(top)

    return modules


def _is_installed(module_name: str) -> bool:
    """Check if a Python module is importable."""
    try:
        result = subprocess.run(
            [sys.executable, "-c", f"import {module_name}"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _detect_dependencies(code: str) -> list[DependencyInfo]:
    """Detect pip dependencies from code imports."""
    imports = _extract_imports(code)
    deps: list[DependencyInfo] = []

    for module in imports:
        # Skip stdlib
        if module in _STDLIB_MODULES:
            continue
        # Skip blocked
        if module in _BLOCKED_MODULES:
            continue

        pip_package = _IMPORT_TO_PACKAGE.get(module, module)
        installed = _is_installed(module)

        deps.append(DependencyInfo(
            package=pip_package,
            import_name=module,
            installed=installed,
        ))

    return deps


def _install_package(package: str) -> tuple[bool, str]:
    """Install a pip package. Returns (success, error_msg)."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--no-input", package],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()[:500]
    except subprocess.TimeoutExpired:
        return False, f"pip install timed out for {package}"
    except Exception as exc:
        return False, str(exc)


# ══════════════════════════════════════════════════════════════════════
# 5. TEMP FILE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

def _get_temp_dir() -> Path:
    """Get or create the temp directory for Python scripts."""
    # Use project temp if available, else system temp
    env_dir = os.environ.get("AGENT_PROJECT_DIR")
    if env_dir and Path(env_dir).is_dir():
        temp = Path(env_dir) / "tmp" / "python_scripts"
    else:
        temp = Path(tempfile.gettempdir()) / "pentaforge_python"
    temp.mkdir(parents=True, exist_ok=True)
    return temp


def _write_script(code: str, slot_id: int) -> Path:
    """Write code to a temp .py file (slot 0 or 1)."""
    temp_dir = _get_temp_dir()
    script_path = temp_dir / f"agent_script_{slot_id}.py"
    script_path.write_text(code, encoding="utf-8")
    return script_path


def _cleanup_script(path: Path) -> None:
    """Remove a temp script file."""
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════
# 6. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════════════

def run_python(
    code: str,
    reason: str,
    install_deps: bool = True,
    timeout: int = 120,
) -> dict:
    """
    Agent Tool — Run Python Code

    Execute arbitrary Python code in a sandboxed subprocess. Creates temporary
    .py files, auto-detects and optionally installs missing pip dependencies,
    and enforces a concurrency limit of 2 simultaneous executions.

    Args:
        code:         Python source code to execute.
        reason:       Required explanation of what this code does and why it's needed.
        install_deps: If True, auto-install missing pip packages before execution. Default: True
        timeout:      Max execution time in seconds (5-600). Default: 120

    Returns:
        RunPythonResult dict with stdout, stderr, return code, and dependency info.

    Security:
        - Blocked modules: subprocess, ctypes, shutil, pty, etc.
        - Blocked patterns: os.system(), eval(), exec(), file write via open()
        - No shell execution — subprocess.run(shell=False)
        - Max 2 concurrent scripts
        - Auto-cleaned temp files
    """
    start = time.perf_counter()

    # ── Validate ──────────────────────────────────────────────────
    try:
        req = RunPythonRequest(
            code=code, reason=reason,
            install_deps=install_deps, timeout=timeout,
        )
    except Exception as exc:
        return RunPythonResult(
            success=False, code=code[:2000], reason=reason,
            error=f"Validation error: {exc}",
        ).model_dump()

    # ── Detect dependencies ──────────────────────────────────────
    deps = _detect_dependencies(req.code)
    installed_packages: list[str] = []

    # ── Install missing deps ─────────────────────────────────────
    if req.install_deps:
        for dep in deps:
            if not dep.installed:
                logger.info("Installing missing package: %s", dep.package)
                ok, err = _install_package(dep.package)
                dep.installed = ok
                dep.install_error = err if not ok else None
                if ok:
                    installed_packages.append(dep.package)

    # ── Acquire execution slot ───────────────────────────────────
    slot_acquired = _acquire_slot(timeout=10.0)
    if not slot_acquired:
        active = _active_count()
        return RunPythonResult(
            success=False, code=req.code[:2000], reason=req.reason,
            dependencies=deps,
            active_slots=f"{active}/{_MAX_CONCURRENT}",
            error=(
                f"All {_MAX_CONCURRENT} execution slots are busy. "
                "Wait for a running script to finish before starting a new one."
            ),
        ).model_dump()

    slot_id = 0 if _SEMAPHORE._value == 1 else 1  # type: ignore[attr-defined]
    script_path: Optional[Path] = None

    try:
        # ── Write temp file ──────────────────────────────────────
        script_path = _write_script(req.code, slot_id)
        logger.info("Written script to %s (slot %d)", script_path, slot_id)

        # ── Execute ──────────────────────────────────────────────
        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=req.timeout,
                shell=False,
                cwd=str(script_path.parent),
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONUNBUFFERED": "1",
                },
            )
            stdout = result.stdout
            stderr = result.stderr
            rc = result.returncode
        except subprocess.TimeoutExpired:
            stdout, stderr, rc = "", f"Script timed out after {req.timeout}s", -1
        except Exception as exc:
            stdout, stderr, rc = "", str(exc), -1

        elapsed = round(time.perf_counter() - start, 3)
        active = _active_count()

        return RunPythonResult(
            success=(rc == 0),
            code=req.code,
            reason=req.reason,
            script_path=str(script_path),
            stdout=stdout[:20_000] if stdout else None,
            stderr=stderr[:5_000] if stderr else None,
            return_code=rc,
            dependencies=deps,
            installed_packages=installed_packages,
            active_slots=f"{active}/{_MAX_CONCURRENT}",
            execution_time=elapsed,
            error=None if rc == 0 else f"Script exited with code {rc}",
        ).model_dump()

    finally:
        # ── Cleanup ──────────────────────────────────────────────
        if script_path:
            _cleanup_script(script_path)
        _release_slot()


# ══════════════════════════════════════════════════════════════════════
# 7. LLM TOOL DEFINITION
# ══════════════════════════════════════════════════════════════════════

RUN_PYTHON_TOOL_DEFINITION: dict = {
    "name": "run_python",
    "description": (
        "Execute Python code in a sandboxed subprocess. Creates temporary .py "
        "files, auto-detects required pip packages from imports, and optionally "
        "installs missing dependencies before execution. Returns stdout, stderr, "
        "return code, and full dependency report. Max 2 concurrent scripts. "
        "Use this when you need to run custom analysis, parse data, compute "
        "values, or use a Python library that no existing tool covers. "
        "Blocked: subprocess, ctypes, shutil, eval(), exec(), os.system(), "
        "file writes. Use dedicated tools for shell commands and file I/O."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": (
                    "Python source code to execute. Must be valid Python 3. "
                    "Use print() for output. Example:\n"
                    "```python\n"
                    "import requests\n"
                    "r = requests.get('https://api.ipify.org?format=json')\n"
                    "print(r.json())\n"
                    "```"
                ),
            },
            "reason": {
                "type": "string",
                "description": (
                    "Required explanation of what this code does and why. "
                    "Example: 'Parse Nmap XML output to extract vulnerable services'"
                ),
            },
            "install_deps": {
                "type": "boolean",
                "description": (
                    "If true, auto-install missing pip packages before running. "
                    "Default: true. Set false if deps are already installed."
                ),
                "default": True,
            },
            "timeout": {
                "type": "integer",
                "description": "Max execution time in seconds (5-600). Default: 120.",
                "default": 120,
            },
        },
        "required": ["code", "reason"],
    },
}


# ══════════════════════════════════════════════════════════════════════
# 8. DEMO
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  Demo 1: Basic computation")
    print("=" * 60)
    r = run_python(
        code="""
import json
import hashlib

data = {"ip": "192.168.1.1", "ports": [22, 80, 443]}
fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
print(json.dumps({"data": data, "fingerprint": fingerprint}, indent=2))
""",
        reason="Generate a SHA256 fingerprint of scan data for deduplication",
    )
    print(f"  success: {r['success']}")
    print(f"  stdout:  {r.get('stdout', '')[:200]}")
    print(f"  deps:    {r['dependencies']}")
    print(f"  slots:   {r['active_slots']}")
    print(f"  time:    {r['execution_time']}s")
    if r.get("error"):
        print(f"  ❌ {r['error']}")

    print("\n" + "=" * 60)
    print("  Demo 2: With external dependency")
    print("=" * 60)
    r = run_python(
        code="""
import ipaddress
import json

network = ipaddress.ip_network('10.0.0.0/24')
hosts = [str(ip) for ip in list(network.hosts())[:10]]
print(json.dumps({"network": str(network), "first_10_hosts": hosts, "total": network.num_addresses}))
""",
        reason="Enumerate hosts in a CIDR range for target list generation",
    )
    print(f"  success: {r['success']}")
    print(f"  stdout:  {r.get('stdout', '')[:300]}")
    print(f"  deps:    {r['dependencies']}")
    if r.get("error"):
        print(f"  ❌ {r['error']}")

    print("\n" + "=" * 60)
    print("  Demo 3: Blocked code")
    print("=" * 60)
    r = run_python(
        code="import subprocess; subprocess.run(['ls'])",
        reason="Testing blocked module detection",
    )
    print(f"  success: {r['success']}")
    print(f"  error:   {r.get('error', '')[:200]}")
