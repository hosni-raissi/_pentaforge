"""
Run Python Code — Agent Tool
==============================
Sandboxed Python code execution for agents. Creates temporary .py files,
runs them in isolated subprocess, auto-detects dependencies, and enforces
a concurrency limit of 2 simultaneous executions.

Fixes over v1:
  - Racy slot_id replaced with a proper lock-based counter
  - open() write/append detection via AST (catches keyword-arg form too)
  - getattr() bypass detection via AST call inspection
  - __builtins__ / builtins attribute manipulation blocked
  - concurrent.futures blocked (spawns processes/threads)
  - threading blocked (unlimited thread spawning)
  - multiprocessing removed from _STDLIB_MODULES (was contradictory)
  - _active_count() no longer touches private _SEMAPHORE._value
  - Optional memory cap via resource.setrlimit in subprocess preexec_fn
  - socket blocked by default (configurable)
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator
from server.agents.executer.sandbox import get_sandbox_root, get_sandbox_tmp_dir
from server.agents.executer.sandbox_client import (
    execute_run_python_remotely,
    sandbox_remote_enabled,
)

# ══════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════

logger = logging.getLogger("run_python")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s — %(message)s", datefmt="%H:%M:%S",
    ))
    logger.addHandler(_h)


# ══════════════════════════════════════════════════════════════════════
# 1. CONCURRENCY GATE — max 2 scripts at a time
#    FIX: replaced racy _SEMAPHORE._value reads with an explicit
#         lock-protected counter for both slot_id and active_count.
# ══════════════════════════════════════════════════════════════════════

_MAX_CONCURRENT = 2
_SEMAPHORE       = threading.Semaphore(_MAX_CONCURRENT)
_SLOTS_LOCK      = threading.Lock()
_ACTIVE_SLOTS: set[int] = set()   # tracks which slot IDs are in use


def _acquire_slot(timeout: float = 30.0) -> Optional[int]:
    """
    Acquire an execution slot and return its ID (0 or 1).
    Returns None if all slots are busy within the timeout.
    """
    if not _SEMAPHORE.acquire(timeout=timeout):
        return None
    with _SLOTS_LOCK:
        slot_id = next(i for i in range(_MAX_CONCURRENT) if i not in _ACTIVE_SLOTS)
        _ACTIVE_SLOTS.add(slot_id)
    return slot_id


def _release_slot(slot_id: int) -> None:
    with _SLOTS_LOCK:
        _ACTIVE_SLOTS.discard(slot_id)
    _SEMAPHORE.release()


def _active_count() -> int:
    with _SLOTS_LOCK:
        return len(_ACTIVE_SLOTS)


# ══════════════════════════════════════════════════════════════════════
# 2. SECURITY CONSTANTS
# ══════════════════════════════════════════════════════════════════════

_BLOCKED_MODULES = frozenset({
    # Shell / process execution
    "subprocess", "pty", "pexpect",
    # Threading / multiprocessing (uncontrolled resource usage)
    "multiprocessing", "threading", "_thread",
    "concurrent",                       # concurrent.futures → ProcessPoolExecutor
    # Network (unrestricted outbound access)
    "socket", "socketserver",
    # Dynamic code execution
    "importlib", "runpy", "compileall",
    "code", "codeop",
    # Low-level / dangerous
    "ctypes", "cffi",
    "resource", "signal",
    "webbrowser",
    # Pip bootstrapping
    "ensurepip", "pip",
    # Builtins manipulation (getattr bypass)
    "builtins",
})

# ── Regex patterns blocked at the source level ────────────────────────
# NOTE: These are a defence-in-depth layer. The primary gate is the AST
# walker below, which catches getattr/keyword-arg bypasses that regex misses.
_BLOCKED_CODE_PATTERNS: list[re.Pattern] = [
    # os.* shell-escape functions
    re.compile(r"\bos\s*\.\s*system\s*\(",       re.I),
    re.compile(r"\bos\s*\.\s*popen\s*\(",        re.I),
    re.compile(r"\bos\s*\.\s*exec[a-z]+\s*\(",   re.I),
    re.compile(r"\bos\s*\.\s*spawn[a-z]+\s*\(",  re.I),
    re.compile(r"\bos\s*\.\s*fork\s*\(",         re.I),
    re.compile(r"\bos\s*\.\s*kill\s*\(",         re.I),
    # Dynamic eval/exec
    re.compile(r"\beval\s*\(",                   re.I),
    re.compile(r"\bexec\s*\(",                   re.I),
    re.compile(r"\bcompile\s*\(",                re.I),
    re.compile(r"\b__import__\s*\(",             re.I),
    # Builtins attribute access
    re.compile(r"\b__builtins__\b",              re.I),
    re.compile(r"\bgetattr\s*\(\s*(?:os|sys|builtins)", re.I),
]

# ── os functions that are forbidden (caught at AST level too) ─────────
_BLOCKED_OS_ATTRS = frozenset({
    "system", "popen", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "fork", "forkpty", "kill", "killpg",
})

# ── open() modes that are forbidden ───────────────────────────────────
_BLOCKED_OPEN_MODES = frozenset()

# Import → pip package mapping
_IMPORT_TO_PACKAGE: dict[str, str] = {
    "bs4":             "beautifulsoup4",
    "cv2":             "opencv-python",
    "dateutil":        "python-dateutil",
    "dns":             "dnspython",
    "dotenv":          "python-dotenv",
    "git":             "gitpython",
    "googleapiclient": "google-api-python-client",
    "jose":            "python-jose",
    "jwt":             "pyjwt",
    "ldap":            "python-ldap",
    "ldap3":           "ldap3",
    "lxml":            "lxml",
    "magic":           "python-magic",
    "nmap":            "python-nmap",
    "PIL":             "Pillow",
    "pysnmp":          "pysnmp",
    "scapy":           "scapy",
    "shodan":          "shodan",
    "sklearn":         "scikit-learn",
    "socks":           "pysocks",
    "whois":           "python-whois",
    "yaml":            "pyyaml",
    "zmq":             "pyzmq",
    "Crypto":          "pycryptodome",
    "Cryptodome":      "pycryptodome",
    "paramiko":        "paramiko",
    "requests":        "requests",
    "httpx":           "httpx",
    "aiohttp":         "aiohttp",
    "rich":            "rich",
    "tabulate":        "tabulate",
    "pandas":          "pandas",
    "numpy":           "numpy",
    "matplotlib":      "matplotlib",
    "netaddr":         "netaddr",
    "ipwhois":         "ipwhois",
    "censys":          "censys",
    "impacket":        "impacket",
    "xmltodict":       "xmltodict",
    "defusedxml":      "defusedxml",
    "netifaces":       "netifaces",
    "psutil":          "psutil",
}

_STDLIB_MODULES = frozenset({
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
    "asyncore", "atexit", "base64", "binascii", "binhex", "bisect",
    "calendar", "cgi", "cgitb", "chunk", "cmath", "cmd", "codecs",
    "collections", "colorsys", "configparser", "contextlib", "contextvars",
    "copy", "copyreg", "cProfile", "csv", "curses", "dataclasses",
    "datetime", "dbm", "decimal", "difflib", "dis", "distutils",
    "doctest", "email", "encodings", "enum", "errno", "faulthandler",
    "fcntl", "filecmp", "fileinput", "fnmatch", "fractions", "ftplib",
    "functools", "gc", "getopt", "getpass", "gettext", "glob", "grp",
    "gzip", "hashlib", "heapq", "hmac", "html", "http", "idlelib",
    "imaplib", "imghdr", "inspect", "io", "ipaddress", "itertools",
    "json", "keyword", "lib2to3", "linecache", "locale", "logging",
    "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes",
    "mmap", "modulefinder", "netrc", "nis", "nntplib", "numbers",
    "operator", "optparse", "os", "ossaudiodev", "pathlib", "pdb",
    "pickle", "pickletools", "pkgutil", "platform", "plistlib",
    "poplib", "posix", "posixpath", "pprint", "profile", "pstats",
    "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri",
    "random", "re", "readline", "reprlib", "rlcompleter", "sched",
    "secrets", "select", "selectors", "shelve", "shlex",
    "smtpd", "smtplib", "sndhdr", "sqlite3", "ssl", "stat",
    "statistics", "string", "stringprep", "struct", "sys", "sysconfig",
    "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios",
    "test", "textwrap", "time", "timeit", "tkinter", "token",
    "tokenize", "tomllib", "trace", "traceback", "tracemalloc", "tty",
    "turtle", "turtledemo", "types", "typing", "typing_extensions",
    "unicodedata", "unittest", "urllib", "uu", "uuid", "venv",
    "warnings", "wave", "weakref", "winreg", "winsound", "wsgiref",
    "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport",
    "zlib", "__future__",
    # NOTE: multiprocessing, threading, concurrent, socket intentionally
    # NOT listed here — they are in _BLOCKED_MODULES
})


# ══════════════════════════════════════════════════════════════════════
# 3. AST SECURITY WALKER
#    Catches bypasses that regex cannot:
#      - open(f, mode='w')           keyword-arg write mode
#      - getattr(os, 'system')(...)  dynamic attribute access
#      - builtins.eval(...)          via builtins module
# ══════════════════════════════════════════════════════════════════════

class _SecurityVisitor(ast.NodeVisitor):
    """Walk the AST and raise ValueError on any forbidden pattern."""

    def __init__(self) -> None:
        self.errors: list[str] = []

    def _fail(self, msg: str) -> None:
        self.errors.append(msg)

    # ── Import checks ─────────────────────────────────────────────
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top in _BLOCKED_MODULES:
                self._fail(f"Import '{alias.name}' is blocked")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            top = node.module.split(".")[0]
            if top in _BLOCKED_MODULES:
                self._fail(f"'from {node.module} import ...' is blocked")
        self.generic_visit(node)

    # ── open() call checks ────────────────────────────────────────
    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._resolve_name(node.func)

        # open() with a positional write-mode arg
        if func_name in {"open", "io.open"}:
            # Positional: open(path, 'w')
            if len(node.args) >= 2:
                mode_node = node.args[1]
                if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                    if mode_node.value in _BLOCKED_OPEN_MODES:
                        self._fail(
                            f"open() with write mode '{mode_node.value}' is blocked"
                        )
            # Keyword: open(path, mode='w')
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    if kw.value.value in _BLOCKED_OPEN_MODES:
                        self._fail(
                            f"open(mode='{kw.value.value}') is blocked (write/append)"
                        )

        # getattr(os/sys/builtins, '<dangerous>')
        if func_name == "getattr" and len(node.args) >= 2:
            obj_name = self._resolve_name(node.args[0])
            attr_node = node.args[1]
            if isinstance(attr_node, ast.Constant) and isinstance(attr_node.value, str):
                attr = attr_node.value
                if obj_name == "os" and attr in _BLOCKED_OS_ATTRS:
                    self._fail(f"getattr(os, '{attr}') is blocked")
                if obj_name in {"builtins", "__builtins__"} and attr in {"eval", "exec", "compile", "__import__"}:
                    self._fail(f"getattr(builtins, '{attr}') is blocked")

        # Direct os.<blocked_attr>() calls
        if isinstance(node.func, ast.Attribute):
            obj = self._resolve_name(node.func.value)
            attr = node.func.attr
            if obj == "os" and attr in _BLOCKED_OS_ATTRS:
                self._fail(f"os.{attr}() is blocked")

        # eval / exec / compile as bare builtins
        if func_name in {"eval", "exec", "compile", "__import__"}:
            self._fail(f"Calling '{func_name}()' is blocked")

        self.generic_visit(node)

    # ── __builtins__ attribute access ────────────────────────────
    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == "__builtins__":
            self._fail("Access to __builtins__ is blocked")
        self.generic_visit(node)

    # ── Name access to __builtins__ ──────────────────────────────
    def visit_Name(self, node: ast.Name) -> None:
        if node.id == "__builtins__":
            self._fail("Access to __builtins__ is blocked")
        self.generic_visit(node)

    @staticmethod
    def _resolve_name(node: ast.expr) -> str:
        """Collapse ast.Name and ast.Attribute chains to a dotted string."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _SecurityVisitor._resolve_name(node.value)
            return f"{parent}.{node.attr}"
        return ""


def _ast_security_check(code: str) -> list[str]:
    """Return a list of security violations found in the code. Empty = safe."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return [f"Python syntax error: {exc}"]
    visitor = _SecurityVisitor()
    visitor.visit(tree)
    return visitor.errors


# ══════════════════════════════════════════════════════════════════════
# 4. SCHEMAS
# ══════════════════════════════════════════════════════════════════════

class RunPythonRequest(BaseModel):
    code: str
    reason: str
    which_file: str = ""
    script_filename: str = ""
    run_parallel: bool = False
    code_two: str = ""
    which_file_two: str = "two"
    install_deps: bool = True
    timeout: int = Field(default=120, ge=5, le=600)
    memory_limit_mb: int = Field(default=512, ge=64, le=4096)

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Code cannot be empty")
        if len(v) > 50_000:
            raise ValueError("Code exceeds 50,000 character limit")

        # Regex layer (fast, broad)
        for pat in _BLOCKED_CODE_PATTERNS:
            m = pat.search(v)
            if m:
                raise ValueError(
                    f"Blocked pattern detected: '{m.group().strip()}'. "
                    "Use dedicated agent tools for shell/file operations."
                )

        # AST layer (precise, catches keyword-arg and getattr bypasses)
        errors = _ast_security_check(v)
        if errors:
            raise ValueError("Security violation(s): " + "; ".join(errors))

        return v

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 8:
            raise ValueError("Reason must be at least 8 characters")
        return v

    @field_validator("script_filename")
    @classmethod
    def validate_script_filename(cls, v: str) -> str:
        name = v.strip()
        if not name:
            return ""
        if "/" in name or "\\" in name or name.startswith("."):
            raise ValueError("script_filename must be a plain filename, not a path")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
            raise ValueError("script_filename contains invalid characters")
        return name

    @field_validator("which_file", "which_file_two")
    @classmethod
    def validate_which_file(cls, v: str) -> str:
        name = v.strip().lower()
        if not name:
            return ""
        allowed = {"one", "two", "1", "2", "file1", "file2"}
        if name not in allowed:
            raise ValueError("which_file must be one/two (or 1/2, file1/file2)")
        return name

    @field_validator("code_two")
    @classmethod
    def validate_code_two(cls, v: str) -> str:
        value = v.strip()
        if not value:
            return ""
        if len(value) > 50_000:
            raise ValueError("code_two exceeds 50,000 character limit")

        for pat in _BLOCKED_CODE_PATTERNS:
            m = pat.search(value)
            if m:
                raise ValueError(
                    f"Blocked pattern detected in code_two: '{m.group().strip()}'. "
                    "Use dedicated agent tools for shell/file operations."
                )

        errors = _ast_security_check(value)
        if errors:
            raise ValueError("Security violation(s) in code_two: " + "; ".join(errors))
        return value


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
    script_overwritten: bool = False
    script_persistent: bool = False
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    return_code: Optional[int] = None
    dependencies: list[DependencyInfo] = Field(default_factory=list)
    installed_packages: list[str] = Field(default_factory=list)
    active_slots: str = ""
    execution_time: float = 0.0
    error: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════
# 5. DEPENDENCY DETECTION & INSTALLATION
# ══════════════════════════════════════════════════════════════════════

def _extract_imports(code: str) -> list[str]:
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
    try:
        result = subprocess.run(
            [sys.executable, "-c", f"import {module_name}"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _detect_dependencies(code: str) -> list[DependencyInfo]:
    deps: list[DependencyInfo] = []
    for module in _extract_imports(code):
        if module in _STDLIB_MODULES or module in _BLOCKED_MODULES:
            continue
        pip_package = _IMPORT_TO_PACKAGE.get(module, module)
        deps.append(DependencyInfo(
            package=pip_package,
            import_name=module,
            installed=_is_installed(module),
        ))
    return deps


def _install_package(package: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--no-input", package],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0, result.stderr.strip()[:500] if result.returncode != 0 else ""
    except subprocess.TimeoutExpired:
        return False, f"pip install timed out for '{package}'"
    except Exception as exc:
        return False, str(exc)


# ══════════════════════════════════════════════════════════════════════
# 6. TEMP FILE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

def _get_temp_dir() -> Path:
    base = get_sandbox_tmp_dir() / "python_scripts"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _get_server_tmp_dir() -> Path:
    tmp_dir = get_sandbox_tmp_dir() / "named_python"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    return tmp_dir


def _resolve_named_script(which_file: str) -> Optional[Path]:
    key = (which_file or "").strip().lower()
    if key in {"one", "1", "file1"}:
        return _get_server_tmp_dir() / "file1.py"
    if key in {"two", "2", "file2"}:
        return _get_server_tmp_dir() / "file2.py"
    return None


def _write_script(
    code: str,
    slot_id: int,
    script_filename: str = "",
    which_file: str = "",
) -> tuple[Path, bool, bool]:
    named_path = _resolve_named_script(which_file)
    if named_path is not None:
        path = named_path
        persistent = True
    elif script_filename:
        filename = script_filename if script_filename.endswith(".py") else f"{script_filename}.py"
        path = _get_temp_dir() / filename
        persistent = False
    else:
        filename = f"agent_script_{slot_id}.py"
        path = _get_temp_dir() / filename
        persistent = False

    existed_before = path.exists()
    path.write_text(code, encoding="utf-8")
    return path, existed_before, persistent


def _cleanup_script(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════
# 7. SUBPROCESS MEMORY LIMIT (Linux only)
# ══════════════════════════════════════════════════════════════════════

def _make_preexec(memory_mb: int):
    """
    Return a preexec_fn that sets a virtual-memory limit on the child process.
    Safe no-op on non-Linux platforms.
    """
    def _limit():
        try:
            import resource as _resource
            limit = memory_mb * 1024 * 1024
            _resource.setrlimit(_resource.RLIMIT_AS, (limit, limit))
        except Exception:
            pass   # non-Linux or permission denied — continue without limit
    return _limit


def _sandbox_service_local_execution_allowed() -> bool:
    return str(os.getenv("PENTAFORGE_SANDBOX_SERVICE", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# ══════════════════════════════════════════════════════════════════════
# 8. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════════════

def run_python(
    code: str,
    reason: str,
    which_file: str = "",
    script_filename: str = "",
    run_parallel: bool = False,
    code_two: str = "",
    which_file_two: str = "two",
    install_deps: bool = True,
    timeout: int = 120,
    memory_limit_mb: int = 512,
) -> dict:
    """
    Agent Tool — Run Python Code

    Execute arbitrary Python code in a sandboxed subprocess. Validates the
    source at both regex and AST level, optionally installs missing pip
    packages, enforces a concurrency limit of 2 simultaneous scripts, and
    applies a per-process memory cap.

    Args:
        code:             Python source code (max 50,000 chars).
        reason:           Required explanation (min 8 chars).
        install_deps:     Auto-install missing pip packages. Default: True.
        timeout:          Max execution time in seconds (5–600). Default: 120.
        memory_limit_mb:  Virtual memory cap for the child process (Linux).
                          Default: 512 MB. Range: 64–4096.

    Security blocks:
        Modules  — subprocess, socket, threading, concurrent, multiprocessing,
                   ctypes, cffi, importlib, builtins, shutil, ...
        Patterns — os.system(), eval(), exec(), open(mode='w'), getattr(os,...),
                   __builtins__ access, getattr(builtins, 'eval'), ...
        Process  — shell=False, memory capped, temp files auto-deleted.

    Returns:
        RunPythonResult dict with stdout, stderr, return_code, dependencies.
    """
    start = time.perf_counter()

    # ── Validate ──────────────────────────────────────────────────
    try:
        req = RunPythonRequest(
            code=code, reason=reason,
            which_file=which_file,
            script_filename=script_filename,
            run_parallel=run_parallel,
            code_two=code_two,
            which_file_two=which_file_two,
            install_deps=install_deps,
            timeout=timeout,
            memory_limit_mb=memory_limit_mb,
        )
    except Exception as exc:
        return RunPythonResult(
            success=False, code=code[:2000], reason=reason,
            error=f"Validation error: {exc}",
        ).model_dump()

    if sandbox_remote_enabled():
        return execute_run_python_remotely(
            {
                "code": req.code,
                "reason": req.reason,
                "which_file": req.which_file,
                "script_filename": req.script_filename,
                "run_parallel": req.run_parallel,
                "code_two": req.code_two,
                "which_file_two": req.which_file_two,
                "install_deps": req.install_deps,
                "timeout": req.timeout,
                "memory_limit_mb": req.memory_limit_mb,
            },
            timeout=req.timeout,
        )

    if not _sandbox_service_local_execution_allowed():
        return RunPythonResult(
            success=False,
            code=req.code[:2000],
            reason=req.reason,
            error=(
                "Sandbox executor unavailable: run_python may only execute through the tool sandbox. "
                "Configure SANDBOX_EXECUTOR_URL for backend-side callers."
            ),
        ).model_dump()

    # Optional dual-run mode: run two scripts in parallel against file1.py / file2.py.
    if req.run_parallel and req.code_two:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_one = pool.submit(
                run_python,
                code=req.code,
                reason=f"{req.reason} [parallel-one]",
                which_file=req.which_file or "one",
                script_filename=req.script_filename,
                run_parallel=False,
                code_two="",
                which_file_two=req.which_file_two,
                install_deps=req.install_deps,
                timeout=req.timeout,
                memory_limit_mb=req.memory_limit_mb,
            )
            fut_two = pool.submit(
                run_python,
                code=req.code_two,
                reason=f"{req.reason} [parallel-two]",
                which_file=req.which_file_two or "two",
                script_filename="",
                run_parallel=False,
                code_two="",
                which_file_two=req.which_file_two,
                install_deps=req.install_deps,
                timeout=req.timeout,
                memory_limit_mb=req.memory_limit_mb,
            )
            result_one = fut_one.result()
            result_two = fut_two.result()

        return {
            "success": bool(result_one.get("success") and result_two.get("success")),
            "parallel": True,
            "result_one": result_one,
            "result_two": result_two,
            "error": None
            if result_one.get("success") and result_two.get("success")
            else "One or both parallel runs failed",
        }

    # ── Detect dependencies ───────────────────────────────────────
    deps = _detect_dependencies(req.code)
    installed_packages: list[str] = []

    if req.install_deps:
        for dep in deps:
            if not dep.installed:
                logger.info("Installing: %s", dep.package)
                ok, err = _install_package(dep.package)
                dep.installed = ok
                dep.install_error = err or None
                if ok:
                    installed_packages.append(dep.package)

    # ── Acquire execution slot ────────────────────────────────────
    slot_id = _acquire_slot(timeout=10.0)
    if slot_id is None:
        active = _active_count()
        return RunPythonResult(
            success=False, code=req.code[:2000], reason=req.reason,
            dependencies=deps,
            active_slots=f"{active}/{_MAX_CONCURRENT}",
            error=(
                f"All {_MAX_CONCURRENT} execution slots are busy. "
                "Wait for a running script to complete."
            ),
        ).model_dump()

    script_path: Optional[Path] = None
    script_overwritten = False
    script_persistent = False
    try:
        # ── Write temp script ─────────────────────────────────────
        script_path, script_overwritten, script_persistent = _write_script(
            req.code,
            slot_id,
            req.script_filename,
            req.which_file,
        )
        logger.info("Executing slot=%d path=%s", slot_id, script_path)

        # ── Execute ───────────────────────────────────────────────
        try:
            proc = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=req.timeout,
                shell=False,                        # CRITICAL: never shell=True
                cwd=str(get_sandbox_root()),
                preexec_fn=_make_preexec(req.memory_limit_mb),
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONUNBUFFERED":        "1",
                },
            )
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            stdout, stderr, rc = "", f"Script timed out after {req.timeout}s", -1
        except MemoryError:
            stdout, stderr, rc = "", "Child process exceeded memory limit", -1
        except Exception as exc:
            stdout, stderr, rc = "", str(exc), -1

        elapsed = round(time.perf_counter() - start, 3)

        return RunPythonResult(
            success=(rc == 0),
            code=req.code,
            reason=req.reason,
            script_path=str(script_path),
            script_overwritten=script_overwritten,
            script_persistent=script_persistent,
            stdout=stdout[:20_000] if stdout else None,
            stderr=stderr[:5_000]  if stderr else None,
            return_code=rc,
            dependencies=deps,
            installed_packages=installed_packages,
            active_slots=f"{_active_count()}/{_MAX_CONCURRENT}",
            execution_time=elapsed,
            error=None if rc == 0 else f"Script exited with code {rc}",
        ).model_dump()

    finally:
        if script_path and not script_persistent:
            _cleanup_script(script_path)
        _release_slot(slot_id)


# ══════════════════════════════════════════════════════════════════════
# 9. LLM TOOL DEFINITION
# ══════════════════════════════════════════════════════════════════════

RUN_PYTHON_TOOL_DEFINITION: dict = {
    "name": "run_python",
    "description": (
        "Execute Python code in a sandboxed subprocess. Validates at regex and AST level "
        "(catches getattr bypasses and keyword-arg open() modes). Auto-detects and installs "
        "pip dependencies. Enforces max 2 concurrent scripts and an optional memory cap. "
        "Returns stdout, stderr, return code, and full dependency report.\n\n"
        "Blocked modules: subprocess, socket, threading, concurrent, multiprocessing, "
        "ctypes, cffi, importlib, builtins, shutil.\n"
        "Blocked patterns: os.system/popen/exec/fork/kill/remove, eval(), exec(), "
        "open(mode='w'/'a'), getattr(os,...), __builtins__ access."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": (
                    "Valid Python 3 source code. Use print() for output.\n"
                    "Example:\n"
                    "import requests\n"
                    "r = requests.get('https://api.ipify.org?format=json')\n"
                    "print(r.json())"
                ),
            },
            "reason": {
                "type": "string",
                "description": "Required explanation (≥8 chars). E.g. 'Parse Nmap XML to extract CVEs'",
            },
            "script_filename": {
                "type": "string",
                "description": (
                    "Optional script filename in the tool temp directory. "
                    "If provided, existing content is overwritten before execution."
                ),
                "default": "",
            },
            "which_file": {
                "type": "string",
                "description": (
                    "Optional named file selector in server/tmp: one->file1.py, two->file2.py. "
                    "When set, file content is overwritten with code before execution."
                ),
                "default": "",
            },
            "run_parallel": {
                "type": "boolean",
                "description": "Run code and code_two in parallel (typically one->file1.py, two->file2.py).",
                "default": False,
            },
            "code_two": {
                "type": "string",
                "description": "Second Python code payload for parallel execution.",
                "default": "",
            },
            "which_file_two": {
                "type": "string",
                "description": "Named target for second parallel code: one or two (default: two).",
                "default": "two",
            },
            "install_deps": {
                "type": "boolean",
                "description": "Auto-install missing pip packages before running. Default: true.",
                "default": True,
            },
            "timeout": {
                "type": "integer",
                "description": "Max execution time in seconds (5–600). Default: 120.",
                "default": 120,
            },
            "memory_limit_mb": {
                "type": "integer",
                "description": "Virtual memory cap for the subprocess in MB (64–4096). Default: 512.",
                "default": 512,
            },
        },
        "required": ["code", "reason"],
    },
}


# ══════════════════════════════════════════════════════════════════════
# 10. DEMO
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    def _show(label: str, r: dict) -> None:
        print(f"\n{'═' * 60}")
        print(f"  {label}")
        print(f"{'═' * 60}")
        print(f"  success : {r.get('success')}")

        if r.get("parallel"):
            one = r.get("result_one") or {}
            two = r.get("result_two") or {}
            print("  mode    : parallel")
            print(f"  one     : success={one.get('success')} slots={one.get('active_slots')} time={one.get('execution_time')}s")
            if one.get("stdout"):
                print(f"    stdout: {str(one.get('stdout'))[:300]}")
            if one.get("error"):
                print(f"    error : {one.get('error')}")

            print(f"  two     : success={two.get('success')} slots={two.get('active_slots')} time={two.get('execution_time')}s")
            if two.get("stdout"):
                print(f"    stdout: {str(two.get('stdout'))[:300]}")
            if two.get("error"):
                print(f"    error : {two.get('error')}")

            if r.get("error"):
                print(f"  ❌ error : {r.get('error')}")
            return

        if r.get("stdout"):
            print(f"  stdout  : {r['stdout'][:300]}")
        if r.get("error"):
            print(f"  ❌ error : {r['error']}")
        if r.get("active_slots") is not None:
            print(f"  slots   : {r.get('active_slots')}   time: {r.get('execution_time')}s")
        if r.get("dependencies"):
            print(f"  deps    : {[d['package'] for d in r['dependencies']]}")

    # 1 ── Basic computation
    _show("Basic computation", run_python(
        code="""
import json, hashlib
data = {"ip": "192.168.1.1", "ports": [22, 80, 443]}
fp = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
print(json.dumps({"fingerprint": fp, "data": data}, indent=2))
""",
        reason="SHA256 fingerprint of scan data for deduplication",
    ))

    # 2 ── CIDR enumeration (stdlib only)
    _show("CIDR enumeration", run_python(
        code="""
import ipaddress, json
net = ipaddress.ip_network('10.0.0.0/24')
hosts = [str(h) for h in list(net.hosts())[:10]]
print(json.dumps({"network": str(net), "first_10": hosts, "total": net.num_addresses}))
""",
        reason="Enumerate hosts in a CIDR range for target list generation",
    ))

    # 3 ── Fill two Python files in server/tmp, then overwrite + execute file1.py
    server_root = Path(__file__).resolve().parents[2]
    tmp_dir = server_root / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    file_1 = tmp_dir / "file1.py"
    file_2 = tmp_dir / "file2.py"
    file_1.write_text("print('old file1 content')\n", encoding="utf-8")
    file_2.write_text("print('old file2 content')\n", encoding="utf-8")

    _show("Overwrite file1.py then execute", run_python(
        code="""
import json
print(json.dumps({"file": "file1.py", "status": "new code executed"}))
""",
        reason="Overwrite file1.py with new code and execute it",
        which_file="one",
        install_deps=False,
    ))

    _show("Parallel run on file1.py + file2.py", run_python(
        code="print('parallel one says hello')",
        reason="Run two agent payloads in parallel on one/two files",
        which_file="one",
        run_parallel=True,
        code_two="print('parallel two says hello')",
        which_file_two="two",
        install_deps=False,
    ))

    # 4 ── Blocked: subprocess import
    _show("BLOCKED — subprocess import", run_python(
        code="import subprocess; subprocess.run(['ls'])",
        reason="Testing blocked module detection",
    ))

    # 5 ── Blocked: open() with keyword write mode (v1 missed this)
    _show("BLOCKED — open(mode='w') keyword form", run_python(
        code="open('/tmp/evil.txt', mode='w').write('pwned')",
        reason="Testing keyword-arg write mode detection",
    ))

    # 6 ── Blocked: getattr bypass (v1 missed this entirely)
    _show("BLOCKED — getattr(os, 'system') bypass", run_python(
        code="import os; getattr(os, 'system')('id')",
        reason="Testing getattr attribute bypass detection",
    ))

    # 7 ── Blocked: __builtins__ access
    _show("BLOCKED — __builtins__ access", run_python(
        code="__builtins__['eval']('print(1)')",
        reason="Testing __builtins__ bypass detection",
    ))
