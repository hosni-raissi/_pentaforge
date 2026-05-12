"""Server entrypoint for running the FastAPI app with uvicorn."""

from __future__ import annotations

import os
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


def main() -> None:
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
