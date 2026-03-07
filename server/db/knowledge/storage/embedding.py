"""
EmbeddingGenerator — Produces vector embeddings for text chunks.

Supports:
  - LOCAL mode (default) — sentence-transformers all-MiniLM-L6-v2 (384 dims, no API key needed)
  - OPENAI mode          — text-embedding-3-small (1536 dims, requires OPENAI_API_KEY)

Set KNOWLEDGE_EMBEDDING_PROVIDER=openai in .env to use OpenAI.
Default is local (works offline, no costs).
"""

from __future__ import annotations

import asyncio
from typing import Optional

import structlog

from server.db.knowledge.config.settings import settings

logger = structlog.get_logger(__name__)


class EmbeddingGenerator:
    """
    Generates embeddings via local sentence-transformers (default) or OpenAI API.
    Designed for batch processing with automatic retry.
    """

    def __init__(
        self,
        model: str | None = None,
        dimensions: int | None = None,
        batch_size: int = 128,
        max_retries: int = 3,
        provider: str | None = None,
    ) -> None:
        self.provider = provider or settings.embedding_provider
        self.model = model or settings.embedding_model
        self.dimensions = dimensions or settings.embedding_dimensions
        self.batch_size = batch_size
        self.max_retries = max_retries
        self._local_model: object | None = None
        self._openai_client: object | None = None

    # ── Local (sentence-transformers) ─────────────────────────────────────

    def _get_local_model(self):
        """Lazy-init local sentence-transformers model."""
        if self._local_model is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError:
                raise RuntimeError(
                    "sentence-transformers required — pip install sentence-transformers"
                )
            local_model_name = (
                self.model
                if self.provider == "local"
                else "all-MiniLM-L6-v2"
            )
            self._local_model = SentenceTransformer(local_model_name)
            logger.info("local_embedding_model_loaded", model=local_model_name)
        return self._local_model

    def _embed_local(self, texts: list[str]) -> list[list[float]]:
        """Embed using local model (synchronous, CPU)."""
        model = self._get_local_model()
        embeddings = model.encode(texts, show_progress_bar=False, normalize_embeddings=True)
        return [emb.tolist() for emb in embeddings]

    # ── OpenAI API ────────────────────────────────────────────────────────

    async def _get_openai_client(self):
        """Lazy-init OpenAI async client."""
        if self._openai_client is None:
            try:
                from openai import AsyncOpenAI
            except ImportError:
                raise RuntimeError("openai package required — pip install openai")
            self._openai_client = AsyncOpenAI()
            logger.info("openai_client_initialized", model=self.model)
        return self._openai_client

    async def _embed_openai_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed via OpenAI with retry."""
        client = await self._get_openai_client()
        for attempt in range(1, self.max_retries + 1):
            try:
                response = await client.embeddings.create(
                    input=texts,
                    model=self.model,
                    dimensions=self.dimensions,
                )
                return [item.embedding for item in response.data]
            except Exception as exc:
                if attempt == self.max_retries:
                    logger.error("embedding_failed", error=str(exc))
                    raise
                wait = 2**attempt
                logger.warning("embedding_retry", attempt=attempt, wait=wait, error=str(exc))
                await asyncio.sleep(wait)
        return []

    # ── Public API ────────────────────────────────────────────────────────

    async def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """
        Generate embeddings for a list of texts.
        Routes to local or OpenAI based on settings.embedding_provider.
        """
        all_embeddings: list[list[float]] = []

        for i in range(0, len(texts), self.batch_size):
            batch = texts[i : i + self.batch_size]

            if self.provider == "openai":
                embeddings = await self._embed_openai_batch(batch)
            else:
                # Local — run in executor to avoid blocking event loop
                loop = asyncio.get_event_loop()
                embeddings = await loop.run_in_executor(None, self._embed_local, batch)

            all_embeddings.extend(embeddings)

            if (i // self.batch_size) % 5 == 0 and i > 0:
                logger.debug(
                    "embedding_progress",
                    done=i + len(batch),
                    total=len(texts),
                    provider=self.provider,
                )

        return all_embeddings

    async def embed_single(self, text: str) -> list[float]:
        """Embed a single text."""
        results = await self.embed_texts([text])
        return results[0]
