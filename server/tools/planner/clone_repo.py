"""
clone_repo — Clone a Git repository and list / read its files.

Used by the planner to fetch the latest security research when the
knowledge base doesn't cover a topic, or to inspect a target repo.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import structlog

from server.core.tool import tool

logger = structlog.get_logger(__name__)

_CLONE_ROOT = Path(tempfile.gettempdir()) / "pentaforge_clones"


@tool(
    name="clone_repo",
    description=(
        "Clone a public Git repository (shallow, depth 1) and return a listing "
        "of markdown / yaml files, optionally reading specific files. "
        "Use this to fetch the latest security research or inspect a target repo."
    ),
)
async def clone_repo(
    url: str,
    read_file: str = "",
    branch: str = "master",
) -> str:
    """Clone a repo and return its file tree, or read a specific file.

    Args:
        url: HTTPS URL of the repo (e.g. https://github.com/org/repo).
        read_file: Relative path of a file to read (empty = return file listing).
        branch: Branch to clone.
    """
    _CLONE_ROOT.mkdir(parents=True, exist_ok=True)

    # Derive a safe directory name from the URL
    repo_name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    repo_dir = _CLONE_ROOT / repo_name

    if not (repo_dir / ".git").exists():
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.version",
            "GIT_CONFIG_VALUE_0": "HTTP/1.1",
        }
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--branch", branch,
            "--single-branch", url, str(repo_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return f"Error: clone timed out after 120s for {url}"
        if proc.returncode != 0:
            return f"Error cloning {url}: {stderr.decode(errors='replace')[:500]}"

    # If a specific file is requested, read it
    if read_file:
        target = repo_dir / read_file
        if not target.is_file():
            return f"File not found: {read_file}"
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
            # Truncate very large files
            if len(content) > 15_000:
                content = content[:15_000] + "\n\n... [truncated]"
            return content
        except Exception as exc:
            return f"Error reading {read_file}: {exc}"

    # Otherwise return a file listing (markdown, yaml, json, txt)
    extensions = {".md", ".yaml", ".yml", ".json", ".txt"}
    files: list[str] = []
    for path in sorted(repo_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in extensions:
            files.append(str(path.relative_to(repo_dir)))
    if not files:
        return f"No readable files found in {repo_name}."
    return f"Files in {repo_name} ({len(files)} total):\n" + "\n".join(files[:200])
