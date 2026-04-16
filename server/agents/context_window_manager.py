"""Shared per-agent context window persistence and compression."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog

from server.core.llm import ChatMessage, LLMClient
from server.db.projects import ProjectsStore

logger = structlog.get_logger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def estimate_tokens(value: Any) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    return max(1, len(text) // 4)


def _truncate_text(text: str, limit: int = 800) -> str:
    clean = str(text or "").strip()
    if len(clean) <= limit:
        return clean
    return clean[:limit] + "..."


@dataclass
class ContextWindowSnapshot:
    agent: str
    max_tokens: int
    estimated_tokens: int
    compression_count: int
    updated_at: str
    entries: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "max_tokens": self.max_tokens,
            "estimated_tokens": self.estimated_tokens,
            "compression_count": self.compression_count,
            "updated_at": self.updated_at,
            "entries": list(self.entries),
        }


class ContextWindowManager:
    """Persist a compact rolling memory per agent and project."""

    def __init__(
        self,
        *,
        project_id: str,
        agent_key: str,
        max_tokens: int,
        llm: LLMClient | None = None,
        projects_store: ProjectsStore | None = None,
    ) -> None:
        self._project_id = str(project_id or "").strip()
        self._agent_key = str(agent_key or "").strip()
        self._max_tokens = max(512, int(max_tokens or 0))
        self._llm = llm
        self._projects_store = projects_store or ProjectsStore()
        self._loaded = False
        self._entries: list[dict[str, Any]] = []
        self._compression_count = 0

    async def ensure_loaded(self) -> None:
        if self._loaded or not self._project_id or not self._agent_key:
            self._loaded = True
            return
        try:
            windows = self._projects_store.get_project_context_windows(self._project_id)
            current = windows.get(self._agent_key, {})
            if isinstance(current, dict):
                entries = current.get("entries", [])
                if isinstance(entries, list):
                    self._entries = [entry for entry in entries if isinstance(entry, dict)]
                self._compression_count = int(current.get("compression_count", 0) or 0)
        except Exception as exc:
            logger.warning(
                "context_window_load_failed",
                project_id=self._project_id,
                agent=self._agent_key,
                error=str(exc),
            )
        self._loaded = True

    def snapshot(self) -> dict[str, Any]:
        estimated = sum(int(entry.get("tokens", 0) or 0) for entry in self._entries)
        return ContextWindowSnapshot(
            agent=self._agent_key,
            max_tokens=self._max_tokens,
            estimated_tokens=estimated,
            compression_count=self._compression_count,
            updated_at=_utc_now_iso(),
            entries=list(self._entries),
        ).to_dict()

    async def persist(self) -> None:
        if not self._project_id or not self._agent_key:
            return
        await self.ensure_loaded()
        try:
            self._projects_store.upsert_project_context_window(
                self._project_id,
                self._agent_key,
                self.snapshot(),
            )
        except Exception as exc:
            logger.warning(
                "context_window_persist_failed",
                project_id=self._project_id,
                agent=self._agent_key,
                error=str(exc),
            )

    async def clear(self) -> None:
        self._entries = []
        self._compression_count = 0
        if not self._project_id or not self._agent_key:
            return
        try:
            self._projects_store.clear_project_context_windows(
                self._project_id,
                self._agent_key,
            )
        except Exception as exc:
            logger.warning(
                "context_window_clear_failed",
                project_id=self._project_id,
                agent=self._agent_key,
                error=str(exc),
            )

    async def record(
        self,
        *,
        kind: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        tokens: int | None = None,
    ) -> None:
        if not self._project_id or not self._agent_key:
            return
        await self.ensure_loaded()
        text = _truncate_text(str(content or ""))
        if not text:
            return
        self._entries.append(
            {
                "kind": str(kind or "note"),
                "role": str(role or "assistant"),
                "content": text,
                "tokens": int(tokens if tokens is not None else estimate_tokens(text)),
                "metadata": dict(metadata or {}),
                "created_at": _utc_now_iso(),
            }
        )
        await self._compress_if_needed()
        await self.persist()

    async def record_llm_turn(
        self,
        *,
        prompt_excerpt: str,
        response_excerpt: str,
        usage: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        prompt_tokens = 0
        completion_tokens = 0
        if isinstance(usage, dict):
            prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
            completion_tokens = int(usage.get("completion_tokens", 0) or 0)
        await self.record(
            kind="llm_prompt",
            role="user",
            content=prompt_excerpt,
            metadata=metadata,
            tokens=prompt_tokens or estimate_tokens(prompt_excerpt),
        )
        await self.record(
            kind="llm_response",
            role="assistant",
            content=response_excerpt,
            metadata=metadata,
            tokens=completion_tokens or estimate_tokens(response_excerpt),
        )

    async def ensure_token_budget(self, *, threshold_tokens: int | None = None) -> dict[str, Any]:
        """
        Ensure the context window stays under the given token threshold.
        If no threshold is provided, uses this manager's configured max.
        """
        await self.ensure_loaded()
        threshold = max(512, int(threshold_tokens or self._max_tokens))
        changed = False

        while True:
            estimated = sum(int(entry.get("tokens", 0) or 0) for entry in self._entries)
            if estimated <= threshold:
                break
            compressed = await self._compress_once()
            if not compressed:
                break
            changed = True

        if changed:
            await self.persist()
        return self.snapshot()

    async def _compress_if_needed(self) -> None:
        estimated = sum(int(entry.get("tokens", 0) or 0) for entry in self._entries)
        if estimated <= self._max_tokens:
            return
        await self._compress_once()

    async def _compress_once(self) -> bool:
        keep_count = min(6, len(self._entries))
        keep_entries = self._entries[-keep_count:]
        old_entries = self._entries[:-keep_count]
        if not old_entries:
            return False

        summary_text = await self._compress_entries(old_entries)
        summary_entry = {
            "kind": "compressed_summary",
            "role": "system",
            "content": summary_text,
            "tokens": estimate_tokens(summary_text),
            "metadata": {
                "compressed_entries": len(old_entries),
            },
            "created_at": _utc_now_iso(),
        }
        self._entries = [summary_entry, *keep_entries]
        self._compression_count += 1
        return True

    async def _compress_entries(self, entries: list[dict[str, Any]]) -> str:
        raw = "\n".join(
            f"[{entry.get('kind', 'note')}/{entry.get('role', 'assistant')}] "
            f"{_truncate_text(str(entry.get('content', '')), 500)}"
            for entry in entries
        )
        if not raw.strip():
            return "Compressed context summary unavailable."

        if self._llm is None:
            return _truncate_text(raw, 1200)

        try:
            response = await self._llm.chat(
                [
                    ChatMessage(
                        role="system",
                        content=(
                            "Compress the following agent working memory into a concise durable summary. "
                            "Keep confirmed facts, decisions, constraints, unresolved needs, and important evidence. "
                            "Use plain text bullets."
                        ),
                    ),
                    ChatMessage(role="user", content=raw),
                ],
                temperature=0.1,
                max_tokens=min(1200, max(256, self._max_tokens // 4)),
                use_config_max_tokens=False,
            )
            compressed = _truncate_text(str(response.content or "").strip(), 1600)
            if compressed:
                return compressed
        except Exception as exc:
            logger.warning(
                "context_window_compress_failed",
                project_id=self._project_id,
                agent=self._agent_key,
                error=str(exc),
            )
        return _truncate_text(raw, 1200)
