from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from server.db.knowledge.processing.chunker import MarkdownChunker
from server.db.knowledge.storage.embedding import EmbeddingGenerator
from server.db.knowledge.storage.payload_store import PayloadStore
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore


@dataclass
class IntelContext:
    """Shared context for all Intel tools to avoid repeated heavy init."""

    embedder: EmbeddingGenerator = field(default_factory=EmbeddingGenerator)
    vector_store: QdrantVectorStore = field(default_factory=QdrantVectorStore)
    payload_store: PayloadStore = field(default_factory=PayloadStore)
    chunker: MarkdownChunker = field(default_factory=MarkdownChunker)
    _initialized: bool = False

    async def ensure_ready(self) -> None:
        if self._initialized:
            return
        self.vector_store.ensure_all_collections()
        self._initialized = True
        # Keep async contract for callers that await context readiness.
        await asyncio.sleep(0)


_ctx: IntelContext = IntelContext()


def set_context(ctx: IntelContext) -> None:
    """Replace module-level tool context (called by IntelAgent)."""
    global _ctx
    _ctx = ctx


def get_context() -> IntelContext:
    return _ctx
