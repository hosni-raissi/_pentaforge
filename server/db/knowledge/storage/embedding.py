"""
EmbeddingGenerator — Produces vector embeddings for text chunks.

Supports:
  - LOCAL mode (default) — nomic-embed-text-v2-moe (768 dims, 8192 token context, no API key needed)
  - OPENAI mode          — text-embedding-3-small (1536 dims, requires OPENAI_API_KEY)

The local model uses task prefixes:
  - "search_document: " for indexing documents
  - "search_query: " for search queries

Set KNOWLEDGE_EMBEDDING_PROVIDER=openai in .env to use OpenAI.
Default is local (works offline, no costs).
"""

from __future__ import annotations

import asyncio
import time
import warnings
from typing import Optional

import structlog

from server.db.knowledge.config.settings import settings

logger = structlog.get_logger(__name__)


class EmbeddingGenerator:
    """
    Generates embeddings via local sentence-transformers (default) or OpenAI API.
    Designed for batch processing with automatic retry.
    """

    _shared_local_models: dict[tuple[str, str], object] = {}
    _shared_local_encode_devices: dict[tuple[str, str], str | None] = {}
    _shared_openai_clients: dict[str, object] = {}

    def __init__(
        self,
        model: str | None = None,
        dimensions: int | None = None,
        batch_size: int | None = None,
        max_retries: int = 3,
        provider: str | None = None,
    ) -> None:
        self.provider = provider or settings.embedding_provider
        self.model = model or settings.embedding_model
        self.dimensions = dimensions or settings.embedding_dimensions
        self.batch_size = batch_size or settings.embedding_batch_size
        self.max_retries = max_retries
        self._local_model: object | None = None
        self._openai_client: object | None = None
        self._local_encode_device: str | None = None
        # Adaptive local encode batch size (learned after first OOM).
        self._adaptive_local_batch_size = self.batch_size

    def _local_cache_key(self) -> tuple[str, str]:
        local_model_name = (
            self.model
            if self.provider == "local"
            else "nomic-ai/nomic-embed-text-v2-moe"
        )
        return (self.provider, local_model_name)

    # ── Local (sentence-transformers) ─────────────────────────────────────

    # Nomic task prefixes — required for nomic-embed-text-v2-moe
    DOCUMENT_PREFIX = "search_document: "
    QUERY_PREFIX = "search_query: "

    @staticmethod
    def _load_sentence_transformer(local_model_name: str, device: str | None = None):
        """Load SentenceTransformer while silencing optional megablocks speed warning.

        The warning is informational and appears on every load when megablocks is not installed.
        """
        from sentence_transformers import SentenceTransformer

        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r"Install Nomic's megablocks fork for better speed:.*",
                category=UserWarning,
            )
            kwargs: dict[str, object] = {"trust_remote_code": True}
            if device is not None:
                kwargs["device"] = device
            return SentenceTransformer(local_model_name, **kwargs)

    def _get_local_model(self):
        """Lazy-init local sentence-transformers model."""
        cache_key = self._local_cache_key()
        if self._local_model is None:
            shared_model = self.__class__._shared_local_models.get(cache_key)
            if shared_model is not None:
                self._local_model = shared_model
                self._local_encode_device = self.__class__._shared_local_encode_devices.get(cache_key)
                return self._local_model
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError:
                raise RuntimeError(
                    "sentence-transformers required — pip install sentence-transformers"
                )
            local_model_name = (
                self.model
                if self.provider == "local"
                else "nomic-ai/nomic-embed-text-v2-moe"
            )
            try:
                self._local_model = self._load_sentence_transformer(local_model_name)
            except Exception as exc:
                if not self._is_cuda_oom(exc):
                    raise
                self._clear_cuda_cache()
                # If CUDA cannot host the model at load time, force CPU model load.
                self._local_model = self._load_sentence_transformer(local_model_name, device="cpu")
                self._local_encode_device = "cpu"
                logger.warning("local_embedding_model_loaded_on_cpu_after_oom")
            self.__class__._shared_local_models[cache_key] = self._local_model
            self.__class__._shared_local_encode_devices[cache_key] = self._local_encode_device
            logger.info("local_embedding_model_loaded", model=local_model_name)
        return self._local_model

    def _embed_local(
        self,
        texts: list[str],
        prefix: str = "",
        *,
        encode_batch_size: int | None = None,
        device: str | None = None,
    ) -> list[list[float]]:
        """Embed using local model (synchronous)."""
        model = self._get_local_model()
        prefixed = [f"{prefix}{t}" for t in texts] if prefix else texts
        target_device = device or self._local_encode_device
        kwargs: dict[str, object] = {
            "show_progress_bar": False,
            "normalize_embeddings": True,
        }
        if encode_batch_size is not None:
            kwargs["batch_size"] = encode_batch_size
        if target_device is not None:
            kwargs["device"] = target_device

        embeddings = model.encode(prefixed, **kwargs)
        return [emb.tolist() for emb in embeddings]

    @staticmethod
    def _is_cuda_oom(exc: Exception) -> bool:
        msg = str(exc).lower()
        return "cuda out of memory" in msg or "outofmemoryerror" in exc.__class__.__name__.lower()

    @staticmethod
    def _clear_cuda_cache() -> None:
        try:
            import torch

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                # Best-effort memory defragmentation for long-running ingestion loops.
                try:
                    torch.cuda.ipc_collect()
                except Exception:
                    pass
        except Exception:
            pass

    def _force_local_model_to_cpu(self) -> None:
        if self._local_encode_device == "cpu":
            return
        model = self._get_local_model()
        try:
            model.to("cpu")
        except Exception:
            # Some wrappers may not expose .to(); still force CPU during encode.
            pass
        self._local_encode_device = "cpu"
        self.__class__._shared_local_encode_devices[self._local_cache_key()] = "cpu"
        self._clear_cuda_cache()
        logger.warning("local_embedding_fallback_cpu")

    def _embed_local_with_recovery(self, texts: list[str], prefix: str = "") -> list[list[float]]:
        """Retry local embedding on OOM by shrinking batch size, then fallback to CPU."""
        encode_batch_size = min(self._adaptive_local_batch_size, max(1, len(texts)))
        attempted_cpu_fallback = self._local_encode_device == "cpu"

        while True:
            try:
                embeddings = self._embed_local(
                    texts,
                    prefix,
                    encode_batch_size=encode_batch_size,
                )
                if encode_batch_size != self._adaptive_local_batch_size:
                    logger.info(
                        "local_embedding_batch_size_adapted",
                        previous_batch_size=self._adaptive_local_batch_size,
                        new_batch_size=encode_batch_size,
                    )
                    self._adaptive_local_batch_size = encode_batch_size
                return embeddings
            except Exception as exc:
                if not self._is_cuda_oom(exc):
                    raise

                self._clear_cuda_cache()

                if encode_batch_size > 1:
                    new_batch_size = max(1, encode_batch_size // 2)
                    if new_batch_size < self._adaptive_local_batch_size:
                        self._adaptive_local_batch_size = new_batch_size
                    logger.warning(
                        "local_embedding_oom_retry",
                        current_batch_size=encode_batch_size,
                        new_batch_size=new_batch_size,
                        texts=len(texts),
                    )
                    encode_batch_size = new_batch_size
                    continue

                if not attempted_cpu_fallback:
                    attempted_cpu_fallback = True
                    self._force_local_model_to_cpu()
                    logger.warning("local_embedding_retry_on_cpu", texts=len(texts))
                    continue

                raise

    # ── OpenAI API ────────────────────────────────────────────────────────

    async def _get_openai_client(self):
        """Lazy-init OpenAI async client."""
        if self._openai_client is None:
            shared_client = self.__class__._shared_openai_clients.get(self.model)
            if shared_client is not None:
                self._openai_client = shared_client
                return self._openai_client
            try:
                from openai import AsyncOpenAI
            except ImportError:
                raise RuntimeError("openai package required — pip install openai")
            self._openai_client = AsyncOpenAI()
            self.__class__._shared_openai_clients[self.model] = self._openai_client
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

    async def embed_texts(
        self, texts: list[str], *, is_query: bool = False,
    ) -> list[list[float]]:
        """
        Generate embeddings for a list of texts.
        Routes to local or OpenAI based on settings.embedding_provider.

        Args:
            is_query: If True, uses the "search_query" prefix (for search).
                      If False (default), uses "search_document" prefix (for indexing).
        """
        all_embeddings: list[list[float]] = []
        prefix = (
            self.QUERY_PREFIX if is_query else self.DOCUMENT_PREFIX
        ) if self.provider == "local" else ""
        start_time = time.monotonic()
        total = len(texts)

        for i in range(0, len(texts), self.batch_size):
            batch = texts[i : i + self.batch_size]

            if self.provider == "openai":
                embeddings = await self._embed_openai_batch(batch)
            else:
                # Local — run in executor to avoid blocking event loop
                loop = asyncio.get_event_loop()
                embeddings = await loop.run_in_executor(
                    None, self._embed_local_with_recovery, batch, prefix,
                )

            all_embeddings.extend(embeddings)

            if (i // self.batch_size) % 5 == 0 and i > 0:
                done = i + len(batch)
                elapsed = max(0.001, time.monotonic() - start_time)
                rate = done / elapsed
                eta = max(0.0, (total - done) / rate) if rate > 0 else None
                logger.debug(
                    "embedding_progress",
                    done=done,
                    total=total,
                    provider=self.provider,
                    rate_texts_per_sec=round(rate, 2),
                    eta_seconds=round(eta, 1) if eta is not None else None,
                )

        return all_embeddings

    async def embed_single(
        self, text: str, *, is_query: bool = False,
    ) -> list[float]:
        """Embed a single text."""
        results = await self.embed_texts([text], is_query=is_query)
        return results[0]
