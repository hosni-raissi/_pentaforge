"""Server entrypoint for running the FastAPI app with uvicorn."""

from __future__ import annotations

import atexit
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import uvicorn

# Python 3.10+ compatibility monkeypatch for older dependencies (like hyperframe)
import collections
import collections.abc
if not hasattr(collections, "MutableSet"):
    collections.MutableSet = collections.abc.MutableSet
if not hasattr(collections, "MutableMapping"):
    collections.MutableMapping = collections.abc.MutableMapping
if not hasattr(collections, "MutableSequence"):
    collections.MutableSequence = collections.abc.MutableSequence
if not hasattr(collections, "Mapping"):
    collections.Mapping = collections.abc.Mapping
if not hasattr(collections, "Sequence"):
    collections.Sequence = collections.abc.Sequence
if not hasattr(collections, "Iterable"):
    collections.Iterable = collections.abc.Iterable
if not hasattr(collections, "Callable"):
    collections.Callable = collections.abc.Callable


def _env_flag(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


_LOCAL_SANDBOX_URL = "http://127.0.0.1:8010"
_SANDBOX_PROC: subprocess.Popen[str] | None = None


def _sandbox_executor_url() -> str:
    return str(os.getenv("SANDBOX_EXECUTOR_URL", "")).strip().rstrip("/")


def _sandbox_service_mode() -> bool:
    return _env_flag("PENTAFORGE_SANDBOX_SERVICE", False)


def _port_accepting_connections(port: int, host: str = "127.0.0.1", timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _cleanup_sandbox_proc() -> None:
    global _SANDBOX_PROC
    proc = _SANDBOX_PROC
    _SANDBOX_PROC = None
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:
            pass


def _start_local_sandbox_service() -> None:
    global _SANDBOX_PROC

    if _sandbox_service_mode():
        return
    if _sandbox_executor_url():
        return
    if not _env_flag("PENTAFORGE_AUTO_START_SANDBOX", True):
        return
    if _port_accepting_connections(8010):
        os.environ["SANDBOX_EXECUTOR_URL"] = _LOCAL_SANDBOX_URL
        return

    env = os.environ.copy()
    env["PENTAFORGE_SANDBOX_SERVICE"] = "1"

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "server.sandbox_service.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8010",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    _SANDBOX_PROC = proc
    atexit.register(_cleanup_sandbox_proc)

    deadline = time.time() + 8.0
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        if _port_accepting_connections(8010):
            os.environ["SANDBOX_EXECUTOR_URL"] = _LOCAL_SANDBOX_URL
            return
        time.sleep(0.1)

    _cleanup_sandbox_proc()
    raise RuntimeError(
        "Failed to start the local tool sandbox on 127.0.0.1:8010. "
        "You can disable auto-start with PENTAFORGE_AUTO_START_SANDBOX=0 and run "
        "`uvicorn server.sandbox_service.app:app --host 127.0.0.1 --port 8010` manually."
    )


def main() -> None:
    _start_local_sandbox_service()
    repo_root = Path(__file__).resolve().parent.parent
    reload_enabled = _env_flag("PENTAFORGE_RELOAD", True)
    reload_dirs = [
        str(repo_root / "server"),
    ]
    reload_excludes = [
        "server/db/knowledge/data/repos/*",
        "server/cache/*",
        "server/db/projects/postgres_data/*",
        "client/ui/dist/*",
        ".git/*",
    ]
    uvicorn.run(
        "server.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=reload_enabled,
        reload_dirs=reload_dirs if reload_enabled else None,
        reload_excludes=reload_excludes if reload_enabled else None,
    )


if __name__ == "__main__":
    main()
