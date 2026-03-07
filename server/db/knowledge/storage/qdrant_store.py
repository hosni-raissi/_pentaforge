"""
QdrantVectorStore — Multi-index Qdrant adapter.

Each domain maps to its own collection (pentaforge_shared, pentaforge_web, etc.).
Supports:
  - Per-domain upsert and search
  - Cross-domain search (query multiple indexes)
  - Filtered similarity search (by source, domain, tags)
  - Collection management per domain
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)

from server.config.database import db_config
from server.db.knowledge.models.chunk import KnowledgeChunk

logger = structlog.get_logger(__name__)


class QdrantVectorStore:
    """Qdrant adapter with per-domain collections."""

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        collection_prefix: str | None = None,
    ) -> None:
        self._url = url or db_config.qdrant_url
        self._api_key = api_key or db_config.qdrant_api_key or None
        self._prefix = collection_prefix or db_config.qdrant_collection_prefix
        self._dimensions = db_config.embedding_dimensions
        self._client: QdrantClient | None = None
        self._ensured_collections: set[str] = set()

    # ── Connection ────────────────────────────────────────────────────────

    def _get_client(self) -> QdrantClient:
        """Lazy-init Qdrant client."""
        if self._client is None:
            kwargs: dict[str, Any] = {"url": self._url}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = QdrantClient(**kwargs)
            logger.info("qdrant_initialized", url=self._url)
        return self._client

    def _collection_name(self, domain: str) -> str:
        """Derive collection name: 'web' → 'pentaforge_web'."""
        return f"{self._prefix}_{domain}"

    def _ensure_collection(self, domain: str) -> str:
        """Create collection if it doesn't exist. Returns collection name."""
        col_name = self._collection_name(domain)
        if col_name in self._ensured_collections:
            return col_name

        client = self._get_client()
        existing = {c.name for c in client.get_collections().collections}
        if col_name not in existing:
            client.create_collection(
                collection_name=col_name,
                vectors_config=VectorParams(
                    size=self._dimensions,
                    distance=Distance.COSINE,
                ),
            )
            logger.info("qdrant_collection_created", collection=col_name, dimensions=self._dimensions)

        self._ensured_collections.add(col_name)
        return col_name

    # ── Upsert ────────────────────────────────────────────────────────────

    def upsert_chunks(
        self,
        chunks: list[KnowledgeChunk],
        embeddings: list[list[float]],
        domain: str = "shared",
    ) -> int:
        """Upsert chunks into the domain's collection. Returns count."""
        if not chunks:
            return 0

        col_name = self._ensure_collection(domain)
        client = self._get_client()

        points = [
            PointStruct(
                id=str(c.id),
                vector=emb,
                payload={
                    "content": c.content,
                    **c.to_vector_metadata(),
                },
            )
            for c, emb in zip(chunks, embeddings)
        ]

        batch_size = 500
        total = 0
        for i in range(0, len(points), batch_size):
            batch = points[i : i + batch_size]
            client.upsert(collection_name=col_name, points=batch)
            total += len(batch)

        logger.info("chunks_upserted", domain=domain, count=total)
        return total

    # ── Search ────────────────────────────────────────────────────────────

    def search(
        self,
        query_embedding: list[float],
        domain: str = "shared",
        n_results: int = 10,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Similarity search within a single domain's collection."""
        col_name = self._ensure_collection(domain)
        client = self._get_client()

        query_filter = self._build_filter(where) if where else None

        hits = client.search(
            collection_name=col_name,
            query_vector=query_embedding,
            limit=n_results,
            query_filter=query_filter,
        )
        return self._format_results(hits)

    def search_multi(
        self,
        query_embedding: list[float],
        domains: list[str],
        n_results: int = 10,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Search across multiple domain collections, merge by score."""
        all_results: list[dict[str, Any]] = []
        for domain in domains:
            try:
                hits = self.search(query_embedding, domain=domain, n_results=n_results, where=where)
                all_results.extend(hits)
            except Exception:
                continue

        # Sort by score (descending = more similar for cosine)
        all_results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return all_results[:n_results]

    def search_with_shared(
        self,
        query_embedding: list[float],
        domain: str,
        n_results: int = 10,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Search a domain + shared, deduplicated by id."""
        domains = [domain]
        if domain != "shared":
            domains.append("shared")
        return self.search_multi(query_embedding, domains, n_results, where)

    # ── Delete ────────────────────────────────────────────────────────────

    def delete_by_source(self, source_name: str, domain: str | None = None) -> None:
        """Delete chunks by source_name. If domain is None, checks all existing collections."""
        client = self._get_client()

        source_filter = Filter(
            must=[FieldCondition(key="source_name", match=MatchValue(value=source_name))]
        )

        if domain:
            col_name = self._collection_name(domain)
            try:
                client.delete(collection_name=col_name, points_selector=source_filter)
            except Exception:
                pass
            logger.info("chunks_deleted_by_source", source_name=source_name, domain=domain)
        else:
            for col in client.get_collections().collections:
                try:
                    client.delete(collection_name=col.name, points_selector=source_filter)
                except Exception:
                    pass
            logger.info("chunks_deleted_by_source", source_name=source_name, domain="all")

    # ── Stats ─────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Statistics per domain collection."""
        client = self._get_client()
        stats: dict[str, Any] = {"url": self._url, "collections": {}}
        total = 0
        for col in client.get_collections().collections:
            info = client.get_collection(col.name)
            count = info.points_count or 0
            stats["collections"][col.name] = count
            total += count
        stats["total_chunks"] = total
        return stats

    # ── Reset ─────────────────────────────────────────────────────────────

    def reset(self, domain: str | None = None) -> None:
        """Delete and re-create collection(s)."""
        client = self._get_client()

        if domain:
            col_name = self._collection_name(domain)
            try:
                client.delete_collection(col_name)
            except Exception:
                pass
            self._ensured_collections.discard(col_name)
            self._ensure_collection(domain)
            logger.warning("collection_reset", collection=col_name)
        else:
            for col in client.get_collections().collections:
                if col.name.startswith(self._prefix):
                    client.delete_collection(col.name)
            self._ensured_collections.clear()
            logger.warning("all_collections_reset")

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _build_filter(where: dict[str, Any]) -> Filter:
        """Convert a simple {key: value} dict to a Qdrant Filter."""
        conditions = [
            FieldCondition(key=k, match=MatchValue(value=v))
            for k, v in where.items()
        ]
        return Filter(must=conditions)

    @staticmethod
    def _format_results(hits: list) -> list[dict[str, Any]]:
        """Normalize Qdrant ScoredPoint results to a standard dict format."""
        output: list[dict[str, Any]] = []
        for hit in hits:
            payload = hit.payload or {}
            output.append({
                "id": str(hit.id),
                "content": payload.pop("content", ""),
                "metadata": payload,
                "score": hit.score,
            })
        return output
