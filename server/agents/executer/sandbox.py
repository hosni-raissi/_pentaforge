"""Shared sandbox helpers for executer runtime paths and subprocess isolation."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


def get_sandbox_root() -> Path:
    root = Path(__file__).resolve().parents[2] / "sandbox"
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_sandbox_home_dir() -> Path:
    path = get_sandbox_root() / "home"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_sandbox_environment() -> Path:
    root = get_sandbox_root()
    tmp_dir = root / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = root / ".cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    os.environ["AGENT_PROJECT_DIR"] = str(root)
    os.environ["HOME"] = str(get_sandbox_home_dir())
    os.environ["TMPDIR"] = str(tmp_dir)
    os.environ["XDG_CACHE_HOME"] = str(cache_dir)
    return root


def get_sandbox_tmp_dir() -> Path:
    path = ensure_sandbox_environment() / "tmp"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass(frozen=True)
class SandboxExecutionPolicy:
    cpu_seconds: int = 120
    max_file_size_bytes: int = 16 * 1024 * 1024
    max_processes: int = 2048  # Increased to prevent thread creation failures per UID
    max_open_files: int = 256
    max_memory_bytes: int = 768 * 1024 * 1024
    umask: int = 0o077


_SAFE_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_INHERITED_ENV_KEYS = {
    "LANG",
    "LC_ALL",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "TERM",
}


def build_sandbox_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    root = ensure_sandbox_environment()
    sandbox_home = get_sandbox_home_dir()
    sandbox_tmp = get_sandbox_tmp_dir()
    env: dict[str, str] = {
        key: value
        for key, value in os.environ.items()
        if key in _INHERITED_ENV_KEYS and isinstance(value, str)
    }
    env.update(
        {
            "AGENT_PROJECT_DIR": str(root),
            "HOME": str(sandbox_home),
            "TMPDIR": str(sandbox_tmp),
            "TEMP": str(sandbox_tmp),
            "TMP": str(sandbox_tmp),
            "XDG_CACHE_HOME": str(root / ".cache"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )

    for key, value in (extra_env or {}).items():
        clean_key = str(key or "").strip()
        clean_value = str(value or "")
        if not clean_key or not _SAFE_ENV_NAME.fullmatch(clean_key):
            continue
        if len(clean_value) > 4096:
            continue
        env[clean_key] = clean_value
    return env


def resolve_sandbox_cwd(cwd: str | None = None) -> str:
    root = get_sandbox_root().resolve()
    if not cwd:
        return str(root)
    try:
        candidate = Path(cwd).expanduser().resolve()
    except Exception:
        return str(root)
    try:
        candidate.relative_to(root)
    except ValueError:
        return str(root)
    candidate.mkdir(parents=True, exist_ok=True)
    return str(candidate)


def build_sandbox_preexec(
    policy: SandboxExecutionPolicy | None = None,
) -> Callable[[], None] | None:
    active_policy = policy or SandboxExecutionPolicy()
    if os.name != "posix":
        return None

    def _preexec() -> None:
        import resource

        def _apply_limit(limit_name: int, desired: int) -> None:
            try:
                current_soft, current_hard = resource.getrlimit(limit_name)
                hard_cap = current_hard if current_hard >= 0 else desired
                next_limit = min(desired, hard_cap)
                resource.setrlimit(limit_name, (next_limit, hard_cap))
            except (OSError, ValueError):
                return

        os.umask(active_policy.umask)
        _apply_limit(resource.RLIMIT_CPU, active_policy.cpu_seconds)
        _apply_limit(resource.RLIMIT_FSIZE, active_policy.max_file_size_bytes)
        _apply_limit(resource.RLIMIT_NOFILE, active_policy.max_open_files)
        # NOTE: Do not apply RLIMIT_NPROC here when not using Docker/Namespaces.
        # It applies to the entire user UID globally, and will block thread
        # creation (e.g., DNS resolution in curl/dig) if the user has a desktop
        # environment (VSCode, browser, etc.) open that already exceeds the limit.
        # _apply_limit(resource.RLIMIT_NPROC, active_policy.max_processes)
        
        _apply_limit(resource.RLIMIT_CORE, 0)
        _apply_limit(resource.RLIMIT_AS, active_policy.max_memory_bytes)

    return _preexec
