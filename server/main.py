"""Server entrypoint for running the FastAPI app with uvicorn."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn


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
