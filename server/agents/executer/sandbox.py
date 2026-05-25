"""Shared sandbox helpers for executer runtime paths and subprocess isolation."""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit


def get_sandbox_root() -> Path:
    configured = str(os.getenv("PENTAFORGE_SANDBOX_ROOT", "")).strip()
    root = Path(configured).expanduser() if configured else Path(__file__).resolve().parents[2] / "sandbox"
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_sandbox_home_dir() -> Path:
    path = get_sandbox_root() / "home"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_sandbox_share_dir() -> Path:
    configured = str(os.getenv("PENTAFORGE_SANDBOX_SHARE_DIR", "")).strip()
    path = Path(configured).expanduser() if configured else get_sandbox_root() / "share"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_project_workspace_dir(project_id: str) -> Path:
    safe_project_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(project_id or "").strip())
    if not safe_project_id:
        return get_sandbox_root()
    path = get_sandbox_root() / "projects" / safe_project_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def _legacy_repository_clone_candidates(project_payload: dict | None) -> list[Path]:
    if not isinstance(project_payload, dict):
        return []
    target_type = str(project_payload.get("targetType", "")).strip().lower()
    if target_type != "repository":
        return []

    target_config = project_payload.get("targetConfig")
    if not isinstance(target_config, dict):
        return []

    repo_url = str(target_config.get("repo_url") or project_payload.get("target") or "").strip()
    if not repo_url:
        return []

    parsed = urlsplit(repo_url)
    raw_path = parsed.path.rstrip("/")
    parts = [part for part in raw_path.split("/") if part]
    if not parts:
        return []

    repo_name = parts[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    owner = parts[-2] if len(parts) >= 2 else ""

    root = get_sandbox_root().resolve()
    candidates: list[Path] = []
    if owner and repo_name:
        candidates.append((root / "repos" / owner / repo_name).resolve())
    if repo_name:
        candidates.append((root / repo_name).resolve())

    deduped: list[Path] = []
    seen: set[str] = set()
    for item in candidates:
        text = str(item)
        if text in seen:
            continue
        seen.add(text)
        deduped.append(item)
    return deduped


def delete_project_workspace(project_id: str, project_payload: dict | None = None) -> dict[str, int]:
    removed = 0
    root = get_sandbox_root().resolve()
    workspace = root / "projects" / re.sub(r"[^A-Za-z0-9._-]", "_", str(project_id or "").strip())
    candidates = [workspace.resolve(), *_legacy_repository_clone_candidates(project_payload)]

    seen: set[str] = set()
    for candidate in candidates:
        text = str(candidate)
        if text in seen:
            continue
        seen.add(text)
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if not candidate.exists():
            continue
        shutil.rmtree(candidate, ignore_errors=True)
        if not candidate.exists():
            removed += 1

    return {"sandbox_paths_removed": removed}


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
        # In the dedicated Docker sandbox service, the container boundary is the
        # primary memory isolation. Applying RLIMIT_AS here has caused Go-based
        # tools such as ffuf to fail thread creation (`pthread_create failed`)
        # even at very low concurrency. Keep the tighter address-space limit for
        # non-service/local fallback execution, but let the container enforce
        # memory inside the sandbox service itself.
        if str(os.getenv("PENTAFORGE_SANDBOX_SERVICE", "")).strip().lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }:
            _apply_limit(resource.RLIMIT_AS, active_policy.max_memory_bytes)

    return _preexec
