"""
search_kb — Search the PentaForge knowledge base.

Queries Qdrant vector indexes to find relevant attack techniques,
methodologies, payloads, and vulnerability references.
"""

from __future__ import annotations

import structlog

from server.core.tool import tool

logger = structlog.get_logger(__name__)


def _get_qdrant_client():
    """Lazy import to avoid heavy init at import time."""
    from qdrant_client import QdrantClient

    from server.config.database import db_config

    kwargs: dict = {"url": db_config.qdrant_url}
    if db_config.qdrant_api_key:
        kwargs["api_key"] = db_config.qdrant_api_key
    return QdrantClient(**kwargs)


def _get_embedder():
    """Lazy import the embedding model."""
    from sentence_transformers import SentenceTransformer

    from server.config.database import db_config

    return SentenceTransformer(db_config.embedding_model)


@tool(
    name="search_kb",
    description=(
        "Search the PentaForge knowledge base for attack techniques, methodologies, "
        "payloads, and vulnerability references. Returns the most relevant chunks "
        "from indexed security sources (HackTricks, PayloadsAllTheThings, OWASP, etc.). "
        "Use domain parameter to narrow results: web, api, mobile, cloud, infrastructure, "
        "iot, network, recon, binary, web3, identity, supply_chain, red_team, compliance, shared."
    ),
)
async def search_kb(query: str, domain: str = "shared", n_results: int = 5) -> str:
    """Search the knowledge base and return matching chunks.

    Args:
        query: Natural language search query.
        domain: Security domain to search (e.g. "web", "cloud", "shared").
        n_results: Number of results to return (1-20).
    """
    from server.config.database import db_config

    n_results = max(1, min(20, n_results))

    try:
        embedder = _get_embedder()
        client = _get_qdrant_client()

        embedding = embedder.encode(query).tolist()

        # Search the domain-specific collection + shared
        collections = [db_config.qdrant_collection(domain)]
        if domain != "shared":
            collections.append(db_config.qdrant_collection("shared"))

        all_hits = []
        for collection_name in collections:
            try:
                results = client.search(
                    collection_name=collection_name,
                    query_vector=embedding,
                    limit=n_results,
                )
                all_hits.extend(results)
            except Exception:
                # Collection may not exist yet
                continue

        # Sort by score descending and deduplicate
        all_hits.sort(key=lambda h: h.score, reverse=True)
        all_hits = all_hits[:n_results]

    except Exception as exc:
        logger.error("search_kb_error", error=str(exc))
        return f"Knowledge base search failed: {exc}"

    if not all_hits:
        return f"No results found for '{query}' in domain '{domain}'."

    parts: list[str] = [f"Found {len(all_hits)} results for '{query}' (domain: {domain}):\n"]
    for i, hit in enumerate(all_hits, 1):
        payload = hit.payload or {}
        source = payload.get("source_name", "unknown")
        title = payload.get("title", "")
        content = payload.get("content", "")[:800]
        parts.append(
            f"--- Result {i} [source: {source}, title: {title}, score: {hit.score:.3f}] ---\n"
            f"{content}\n"
        )

    return "\n".join(parts)
