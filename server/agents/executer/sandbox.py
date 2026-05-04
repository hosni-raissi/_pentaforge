"""Shared sandbox helpers for executer runtime paths."""

from __future__ import annotations

import os
from pathlib import Path


def get_sandbox_root() -> Path:
    root = Path(__file__).resolve().parents[2] / "sandbox"
    root.mkdir(parents=True, exist_ok=True)
    return root


def ensure_sandbox_environment() -> Path:
    root = get_sandbox_root()
    os.environ["AGENT_PROJECT_DIR"] = str(root)
    return root


def get_sandbox_tmp_dir() -> Path:
    path = ensure_sandbox_environment() / "tmp"
    path.mkdir(parents=True, exist_ok=True)
    return path
