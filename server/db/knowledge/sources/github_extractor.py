"""
GitHubRepoExtractor — Clones a GitHub repository and extracts markdown files.

Handles:
  - HackTricks (src/ subdirectory, mdbook format)
  - PayloadsAllTheThings (each vuln class is a folder with README.md)
  - OWASP WSTG (document/ subdirectory)
  - InternalAllTheThings, HardwareAllTheThings
  - SecLists (README index only — wordlists are too large)
  - KeyHacks, secrets-patterns-db
  - wifi-cracking
  - OWASP MASTG
  - awesome-mobile-security
"""

from __future__ import annotations

import asyncio
import fnmatch
import os
import re
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path

import structlog

from server.db.knowledge.config.settings import settings
from server.db.knowledge.config.sources import SourceConfig
from server.db.knowledge.models.document import (
    KnowledgeDocument,
    SourceMetadata,
    SourceType,
)
from server.db.knowledge.sources.base import BaseExtractor

logger = structlog.get_logger(__name__)

# Tracks repos already cloned/pulled in this process run to avoid redundant git operations
# when many sources share the same clone_id.
_ensured_repos: set[str] = set()


class GitHubRepoExtractor(BaseExtractor):
    """
    Clones a GitHub repo (shallow) and walks matching files to produce documents.
    """

    def __init__(self, config: SourceConfig) -> None:
        super().__init__(config)
        self._repo_dir: Path | None = None

    @property
    def repo_dir(self) -> Path:
        """Local path where the repo is / will be cloned.

        When clone_id is set, multiple sources share one local clone
        (e.g. all PayloadsAllTheThings subdirectory sources point to the same checkout).
        """
        key = self.config.clone_id or self.config.name
        return settings.clone_dir / key

    async def extract(self) -> AsyncIterator[KnowledgeDocument]:
        """Clone (or pull) and walk the repo yielding documents."""
        await self._ensure_repo()

        root = self.repo_dir
        if self.config.subdirectory:
            root = root / self.config.subdirectory

        if not root.exists():
            logger.error("subdirectory_not_found", path=str(root), source=self.source_name)
            return

        file_count = 0
        for file_path in self._walk_files(root):
            if file_count >= self.config.max_pages:
                logger.info(
                    "source_document_cap_reached",
                    source=self.source_name,
                    max_pages=self.config.max_pages,
                )
                break

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                logger.warning("file_read_error", file=str(file_path), error=str(exc))
                continue

            rel_path = str(file_path.relative_to(self.repo_dir))
            title = self._extract_title(content, file_path)
            tags = self._extract_tags(rel_path, content)

            doc = KnowledgeDocument(
                title=title,
                content=content,
                content_type=self._detect_content_type(file_path),
                domain=self.config.domain,
                category=self.config.category,
                tags=list(set(self.config.tags + tags)),
                metadata=SourceMetadata(
                    source_name=self.config.name,
                    source_type=SourceType.GITHUB_REPO,
                    source_url=self.config.url,
                    file_path=rel_path,
                    branch=self.config.branch,
                    commit_sha=self._get_commit_sha(),
                    license=self.config.license,
                ),
            )

            if doc.is_meaningful():
                file_count += 1
                yield doc

        logger.info(
            "extraction_complete",
            source=self.source_name,
            documents=file_count,
        )

    async def health_check(self) -> bool:
        """Check if the repo URL is reachable via git ls-remote."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "ls-remote", "--exit-code", self.config.url,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            code = await proc.wait()
            return code == 0
        except Exception:
            return False

    # ── Private helpers ───────────────────────────────────────────────────

    async def _ensure_repo(self) -> None:
        """Clone if missing, pull if exists. Falls back to 'main' if configured branch fails.

        Skips redundant git operations when the same repo_dir was already
        ensured in this process run (common with clone_id sharing).
        """
        repo = self.repo_dir
        repo_key = str(repo)

        if repo_key in _ensured_repos:
            logger.debug("repo_already_ensured", source=self.source_name, path=repo_key)
            return

        if repo.exists() and (repo / ".git").exists():
            # Recover from interrupted git operations that leave stale lock files.
            self._clear_git_locks(repo)
            logger.info("pulling_repo", source=self.source_name, path=str(repo))
            ok = await self._run_git("git", "-C", str(repo), "pull", "--ff-only")
            if not ok or self._repo_needs_reclone(repo):
                logger.warning("repo_reclone_required", source=self.source_name, path=str(repo))
                self._safe_rmtree(repo)
                ok = await self._clone_with_fallback(repo)
            if ok:
                _ensured_repos.add(repo_key)
        else:
            repo.parent.mkdir(parents=True, exist_ok=True)
            logger.info("cloning_repo", source=self.source_name, url=self.config.url)
            ok = await self._clone_with_fallback(repo)
            if ok:
                _ensured_repos.add(repo_key)

    async def _clone_with_fallback(self, repo: Path) -> bool:
        """Clone with configured branch first, then fallback to main/master."""
        success = await self._run_git(
            "git", "clone",
            "--depth", str(settings.git_depth),
            "--branch", self.config.branch,
            "--single-branch",
            self.config.url,
            str(repo),
        )
        # Fallback: try 'main' if configured branch (e.g. 'master') failed
        if not success:
            if repo.exists():
                self._safe_rmtree(repo)
            fallback = "main" if self.config.branch != "main" else "master"
            logger.info("clone_fallback", source=self.source_name, fallback_branch=fallback)
            success = await self._run_git(
                "git", "clone",
                "--depth", str(settings.git_depth),
                "--branch", fallback,
                "--single-branch",
                self.config.url,
                str(repo),
            )
        return success

    @staticmethod
    def _clear_git_locks(repo: Path) -> None:
        """Remove stale git lock files from interrupted operations."""
        git_dir = repo / ".git"
        if not git_dir.exists():
            return
        for lock_file in git_dir.rglob("*.lock"):
            try:
                lock_file.unlink(missing_ok=True)
            except Exception:
                continue

    @staticmethod
    def _repo_needs_reclone(repo: Path) -> bool:
        """Detect a broken checkout (e.g. only .git exists, no working tree files)."""
        try:
            # If there are no non-hidden entries except .git, checkout is unusable.
            entries = [p for p in repo.iterdir() if p.name != ".git"]
            return len(entries) == 0
        except Exception:
            return True

    @staticmethod
    def _safe_rmtree(path: Path) -> None:
        """Best-effort recursive delete for corrupted clones."""
        import shutil

        shutil.rmtree(path, ignore_errors=True)

    async def _run_git(self, *cmd: str) -> bool:
        """Run a git command. Returns True on success."""
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            # Force HTTP/1.1 — avoids curl 92 "HTTP/2 stream not closed cleanly" in Docker
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "http.version",
            "GIT_CONFIG_VALUE_0": "HTTP/1.1",
            "GIT_CONFIG_KEY_1": "http.postBuffer",
            "GIT_CONFIG_VALUE_1": "524288000",  # 500 MB
        }
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=settings.git_clone_timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.error(
                "git_command_timeout",
                cmd=" ".join(cmd),
                timeout=settings.git_clone_timeout,
            )
            return False
        if proc.returncode != 0:
            logger.error(
                "git_command_failed",
                cmd=" ".join(cmd),
                stderr=stderr.decode(errors="replace")[:500],
            )
            return False
        return True

    @staticmethod
    def _match_glob(rel: str, pattern: str) -> bool:
        """Match a relative file path against a glob pattern.

        Handles ``**/`` as zero-or-more directories so that root-level files
        (e.g. ``README.md``) are matched by patterns like ``**/*.md``.
        """
        if fnmatch.fnmatch(rel, pattern):
            return True
        if "**/" in pattern:
            return fnmatch.fnmatch(rel, pattern.replace("**/", "", 1))
        return False

    def _walk_files(self, root: Path) -> list[Path]:
        """Walk directory and filter by include/exclude patterns."""
        all_files: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            rel = str(path.relative_to(root))
            # Include check
            included = any(
                self._match_glob(rel, pat) for pat in self.config.include_patterns
            )
            if not included:
                continue
            # Exclude check
            excluded = any(
                self._match_glob(rel, pat) for pat in self.config.exclude_patterns
            )
            if excluded:
                continue
            all_files.append(path)

        return sorted(all_files)

    @staticmethod
    def _extract_title(content: str, file_path: Path) -> str:
        """Extract title from first H1 heading or fallback to filename."""
        match = re.search(r"^#\s+(.+)", content, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return file_path.stem.replace("-", " ").replace("_", " ").title()

    @staticmethod
    def _extract_tags(rel_path: str, content: str) -> list[str]:
        """Auto-extract tags from path components and content patterns."""
        tags: list[str] = []
        # Path-based tags
        parts = Path(rel_path).parts
        for part in parts[:-1]:  # skip filename
            clean = part.lower().replace("-", "_").replace(" ", "_")
            if len(clean) > 2 and clean not in {"src", "docs", "document", "readme"}:
                tags.append(clean)

        # Content-based: detect MITRE techniques
        mitre_ids = re.findall(r"T\d{4}(?:\.\d{3})?", content)
        tags.extend(mitre_ids[:10])

        # Content-based: detect CVE references
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", content)
        tags.extend(cve_ids[:10])

        return tags

    def _get_commit_sha(self) -> str | None:
        """Get current HEAD commit SHA."""
        head_file = self.repo_dir / ".git" / "HEAD"
        try:
            ref = head_file.read_text().strip()
            if ref.startswith("ref: "):
                ref_file = self.repo_dir / ".git" / ref[5:]
                return ref_file.read_text().strip()[:12]
            return ref[:12]
        except Exception:
            return None

    @staticmethod
    def _detect_content_type(file_path: Path) -> str:
        suffix = file_path.suffix.lower()
        return {
            ".md": "markdown",
            ".json": "json",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".txt": "text",
        }.get(suffix, "text")
