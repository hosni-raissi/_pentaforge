"""search_kb — Search the PentaForge knowledge base."""

from __future__ import annotations

from typing import Any

import structlog

from server.core.tool import tool
from server.db.knowledge.storage.embedding import EmbeddingGenerator
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore

logger = structlog.get_logger(__name__)

_EMBEDDER: EmbeddingGenerator | None = None
_VECTOR_STORE: QdrantVectorStore | None = None


def _get_embedder() -> EmbeddingGenerator:
    global _EMBEDDER
    if _EMBEDDER is None:
        _EMBEDDER = EmbeddingGenerator()
    return _EMBEDDER


def _get_vector_store() -> QdrantVectorStore:
    global _VECTOR_STORE
    if _VECTOR_STORE is None:
        _VECTOR_STORE = QdrantVectorStore()
    return _VECTOR_STORE


def _merge_results(primary: list[dict[str, Any]], secondary: list[dict[str, Any]], n_results: int) -> list[dict[str, Any]]:
    seen_ids: set[str] = set()
    merged: list[dict[str, Any]] = []
    for hit in sorted(primary + secondary, key=lambda h: h.get("score", 0), reverse=True):
        hit_id = str(hit.get("id", ""))
        if hit_id and hit_id in seen_ids:
            continue
        if hit_id:
            seen_ids.add(hit_id)
        merged.append(hit)
        if len(merged) >= n_results:
            break
    return merged


@tool(
    name="search_kb",
    description="Search knowledge base for techniques, methods, and vulnerabilities. Domains: web, api, cloud, network, shared, etc.",
)
async def search_kb(query: str, domain: str = "shared", n_results: int = 5) -> str:
    """Search the knowledge base.

    Args:
        query: Search query.
        domain: Security domain (web, api, cloud, shared, etc.).
        n_results: Results count (1-20).
    """
    n_results = max(1, min(8, n_results))

    try:
        embedder = _get_embedder()
        vector_store = _get_vector_store()
        vector_store.ensure_all_collections()
        embedding = await embedder.embed_single(query, is_query=True)

        if domain == "shared":
            all_hits = vector_store.search_multi(query_embedding=embedding, domain="shared", n_results=n_results)
        else:
            domain_hits = vector_store.search_multi(query_embedding=embedding, domain=domain, n_results=n_results)
            shared_hits = vector_store.search_multi(query_embedding=embedding, domain="shared", n_results=n_results)
            all_hits = _merge_results(domain_hits, shared_hits, n_results)

    except Exception as exc:
        logger.error("search_kb_error", error=str(exc))
        return f"Search failed: {exc}"

    if not all_hits:
        return f"No results for '{query}' in '{domain}'."

    parts: list[str] = [f"{len(all_hits)} results for '{query}' (domain: {domain}):\n"]
    for i, hit in enumerate(all_hits, 1):
        meta = hit.get("metadata", {})
        source = meta.get("source_name", "?")
        title = meta.get("heading", "")
        content = hit.get("content", "")[:250]
        score = float(hit.get("score", 0))
        parts.append(f"[{i}] {source}: {title} (score:{score:.2f})\n{content}\n")

    return "\n".join(parts)
