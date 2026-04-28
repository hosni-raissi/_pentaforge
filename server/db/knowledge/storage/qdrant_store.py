"""
QdrantVectorStore — Content-type-based Qdrant adapter.

Architecture:
  5 collections by CONTENT TYPE (not domain):
    - pentaforge_strategies  — methodology, techniques, attack flows
    - pentaforge_exploits    — PoCs, CVEs, exploit code, vulnerability details
    - pentaforge_tools       — tool documentation and usage guides
    - pentaforge_standards   — compliance frameworks, checklists, best practices
    - pentaforge_attack_types — attack categories, kill-chain phases, TTPs

  Domain is stored as a METADATA FILTER (not a separate collection).
  This yields 5 collections instead of 80+.

  Payloads (raw strings like XSS vectors, SQLi strings) are NOT stored here —
  they go into a JSON payload store since they don't embed meaningfully.

Supports:
  - Per-content-type upsert and search with domain filtering
  - Cross-collection search (query multiple content types)
  - Filtered similarity search (by domain, source, tags, content_type)
  - Collection management per content type
"""

from __future__ import annotations

import os
import uuid
import warnings
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

# The 5 canonical content-type collections
CONTENT_TYPES = ("strategies", "exploits", "tools", "standards", "attack_types")


class QdrantVectorStore:
    """Qdrant adapter with per-content-type collections and domain metadata filtering."""

    _shared_clients: dict[tuple[str, str | None], QdrantClient] = {}
    _shared_ensured_collections: dict[tuple[str, str | None, str], set[str]] = {}

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
        shared_key = (self._url, self._api_key, self._prefix)
        self._ensured_collections = self.__class__._shared_ensured_collections.setdefault(shared_key, set())

    # ── Connection ────────────────────────────────────────────────────────

    def _get_client(self) -> QdrantClient:
        """Lazy-init Qdrant client."""
        if self._client is None:
            shared_key = (self._url, self._api_key)
            shared_client = self.__class__._shared_clients.get(shared_key)
            if shared_client is not None:
                self._client = shared_client
                return self._client
            kwargs: dict[str, Any] = {"url": self._url}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            suppress_insecure_warning = os.getenv("QDRANT_SUPPRESS_INSECURE_WARNING", "1").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            if suppress_insecure_warning and self._api_key:
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        message="Api key is used with an insecure connection.",
                    )
                    self._client = QdrantClient(**kwargs)
            else:
                self._client = QdrantClient(**kwargs)
            self.__class__._shared_clients[shared_key] = self._client
            logger.info("qdrant_initialized", url=self._url)
        return self._client

    def _collection_name(self, content_type: str) -> str:
        """Derive collection name: 'strategies' → 'pentaforge_strategies'."""
        return f"{self._prefix}_{content_type}"

    def _ensure_collection(self, content_type: str) -> str:
        """Create collection if it doesn't exist. Returns collection name."""
        col_name = self._collection_name(content_type)
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

    def ensure_all_collections(self) -> None:
        """Pre-create all 5 content-type collections."""
        for ct in CONTENT_TYPES:
            self._ensure_collection(ct)

    # ── Upsert ────────────────────────────────────────────────────────────

    def upsert_chunks(
        self,
        chunks: list[KnowledgeChunk],
        embeddings: list[list[float]],
        content_type: str = "strategies",
    ) -> int:
        """Upsert chunks into a content-type collection. Domain is in metadata. Returns count."""
        if not chunks:
            return 0

        col_name = self._ensure_collection(content_type)
        client = self._get_client()

        points = [
            PointStruct(
                id=str(c.id),
                vector=emb,
                payload={
                    "content": c.content,
                    "domain": c.domain,
                    "content_type": content_type,
                    **c.to_vector_metadata(),
                    **self._sanitize_extra_payload(c.extra),
                    "doc_content_hash": c.extra.get("doc_content_hash", c.content_hash),
                },
            )
            for c, emb in zip(chunks, embeddings)
        ]

        batch_size = 500
        total = 0
        for i in range(0, len(points), batch_size):
            batch = points[i : i + batch_size]
            client.upsert(collection_name=col_name, points=batch, wait=True)
            total += len(batch)

        logger.info("chunks_upserted", content_type=content_type, count=total)
        return total

    # ── Search ────────────────────────────────────────────────────────────

    def search(
        self,
        query_embedding: list[float],
        content_type: str = "strategies",
        domain: str | None = None,
        n_results: int = 10,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Similarity search within a content-type collection, optionally filtered by domain."""
        col_name = self._ensure_collection(content_type)
        client = self._get_client()

        conditions: dict[str, Any] = {}
        if domain:
            conditions["domain"] = domain
        if where:
            conditions.update(where)

        query_filter = self._build_filter(conditions) if conditions else None

        response = client.query_points(
            collection_name=col_name,
            query=query_embedding,
            limit=n_results,
            query_filter=query_filter,
        )
        return self._format_results(response.points)

    def search_multi(
        self,
        query_embedding: list[float],
        content_types: list[str] | None = None,
        domain: str | None = None,
        n_results: int = 10,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Search across multiple content-type collections, merge by score."""
        types = content_types or list(CONTENT_TYPES)
        all_results: list[dict[str, Any]] = []
        for ct in types:
            try:
                hits = self.search(query_embedding, content_type=ct, domain=domain, n_results=n_results, where=where)
                all_results.extend(hits)
            except Exception:
                continue

        all_results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return all_results[:n_results]

    # ── Delete ────────────────────────────────────────────────────────────

    def delete_by_source(self, source_name: str, content_type: str | None = None) -> None:
        """Delete chunks by source_name. If content_type is None, checks all collections."""
        client = self._get_client()

        source_filter = Filter(
            must=[FieldCondition(key="source_name", match=MatchValue(value=source_name))]
        )

        if content_type:
            col_name = self._collection_name(content_type)
            try:
                client.delete(collection_name=col_name, points_selector=source_filter)
            except Exception:
                pass
            logger.info("chunks_deleted_by_source", source_name=source_name, content_type=content_type)
        else:
            for ct in CONTENT_TYPES:
                col_name = self._collection_name(ct)
                try:
                    client.delete(collection_name=col_name, points_selector=source_filter)
                except Exception:
                    pass
            logger.info("chunks_deleted_by_source", source_name=source_name, content_type="all")

    # ── Deduplication ─────────────────────────────────────────────────────

    def exists_by_hash(self, content_hash: str, content_type: str) -> bool:
        """Check if a chunk with this content_hash already exists."""
        col_name = self._collection_name(content_type)
        client = self._get_client()
        try:
            result = client.scroll(
                collection_name=col_name,
                scroll_filter=Filter(
                    must=[FieldCondition(key="content_hash", match=MatchValue(value=content_hash))]
                ),
                limit=1,
            )
            points, _ = result
            return len(points) > 0
        except Exception:
            return False

    def get_source_doc_hashes(
        self, source_name: str, content_type: str,
    ) -> dict[str, dict[str, int | str | None]]:
        """Return {doc_identity: state} for all docs from this source.

        State fields:
          - doc_content_hash: document-level hash
          - chunk_count: observed number of stored chunks for this doc
          - doc_chunk_total: expected number of chunks (if available)

        doc_identity = file_path if non-empty, else source_url.
        """
        col_name = self._collection_name(content_type)
        client = self._get_client()
        doc_map: dict[str, dict[str, int | str | None]] = {}

        try:
            offset = None
            while True:
                points, offset = client.scroll(
                    collection_name=col_name,
                    scroll_filter=Filter(
                        must=[FieldCondition(key="source_name", match=MatchValue(value=source_name))]
                    ),
                    limit=500,
                    offset=offset,
                    with_payload=["file_path", "source_url", "doc_content_hash", "doc_chunk_total"],
                )
                for pt in points:
                    p = pt.payload or {}
                    identity = p.get("file_path") or p.get("source_url", "")
                    if not identity:
                        continue

                    state = doc_map.get(identity)
                    if state is None:
                        state = {
                            "doc_content_hash": p.get("doc_content_hash", ""),
                            "chunk_count": 0,
                            "doc_chunk_total": p.get("doc_chunk_total"),
                        }
                        doc_map[identity] = state

                    state["chunk_count"] = int(state.get("chunk_count", 0)) + 1
                    if not state.get("doc_content_hash"):
                        state["doc_content_hash"] = p.get("doc_content_hash", "")
                    if state.get("doc_chunk_total") is None and p.get("doc_chunk_total") is not None:
                        state["doc_chunk_total"] = p.get("doc_chunk_total")
                if offset is None:
                    break
        except Exception as exc:
            logger.warning("get_source_doc_hashes_error", source=source_name, error=str(exc))

        return doc_map

    def delete_by_doc_identity(
        self, source_name: str, doc_identity: str, content_type: str,
    ) -> None:
        """Delete all chunks for a specific doc (identified by source_name + file_path or source_url)."""
        col_name = self._collection_name(content_type)
        client = self._get_client()

        # Try file_path first, then source_url
        for key in ("file_path", "source_url"):
            try:
                client.delete(
                    collection_name=col_name,
                    points_selector=Filter(
                        must=[
                            FieldCondition(key="source_name", match=MatchValue(value=source_name)),
                            FieldCondition(key=key, match=MatchValue(value=doc_identity)),
                        ]
                    ),
                )
                return
            except Exception:
                continue

    # ── Stats ─────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Statistics per content-type collection."""
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

    def reset(self, content_type: str | None = None) -> None:
        """Delete and re-create collection(s)."""
        client = self._get_client()

        if content_type:
            col_name = self._collection_name(content_type)
            try:
                client.delete_collection(col_name)
            except Exception:
                pass
            self._ensured_collections.discard(col_name)
            self._ensure_collection(content_type)
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

    @staticmethod
    def _sanitize_extra_payload(extra: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(extra, dict):
            return {}

        safe: dict[str, Any] = {}
        for key, value in extra.items():
            clean_key = str(key or "").strip()
            if not clean_key or clean_key in {"content", "domain", "content_type"}:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                safe[clean_key] = value
                continue
            if isinstance(value, list):
                normalized = [
                    item
                    for item in value
                    if isinstance(item, (str, int, float, bool)) or item is None
                ]
                safe[clean_key] = normalized[:20]
        return safe
