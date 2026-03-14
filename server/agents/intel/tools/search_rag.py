from __future__ import annotations

import json
from typing import Any

from server.core.tool import tool

from .context import get_context


def _merge_hits(primary: list[dict[str, Any]], shared: list[dict[str, Any]], n_results: int) -> list[dict[str, Any]]:
    seen_ids: set[str] = set()
    merged: list[dict[str, Any]] = []
    for hit in sorted(primary + shared, key=lambda h: h.get("score", 0), reverse=True):
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
    name="search_rag",
    description=(
        "Search the RAG knowledge base by semantic similarity. "
        "Supports domain filter and content_type routing (strategies, exploits, tools, standards, attack_types). "
        "Returns top matching hits with metadata and score."
    ),
)
async def search_rag(
    query: str,
    domain: str = "shared",
    content_type: str = "strategies",
    n_results: int = 8,
    include_shared: bool = True,
) -> str:
    ctx = get_context()
    await ctx.ensure_ready()

    n_results = max(1, min(25, int(n_results)))

    query_embedding = await ctx.embedder.embed_single(query, is_query=True)

    primary = ctx.vector_store.search(
        query_embedding=query_embedding,
        content_type=content_type,
        domain=domain,
        n_results=n_results,
    )

    if include_shared and domain != "shared":
        shared = ctx.vector_store.search(
            query_embedding=query_embedding,
            content_type=content_type,
            domain="shared",
            n_results=n_results,
        )
        hits = _merge_hits(primary, shared, n_results)
    else:
        hits = primary

    compact = []
    for h in hits:
        metadata = h.get("metadata", {}) or {}
        compact.append(
            {
                "id": h.get("id"),
                "score": h.get("score", 0),
                "content": (h.get("content") or "")[:800],
                "metadata": {
                    "source_name": metadata.get("source_name", ""),
                    "domain": metadata.get("domain", ""),
                    "heading": metadata.get("heading", ""),
                    "tags": metadata.get("tags", []),
                    "file_path": metadata.get("file_path", ""),
                    "source_url": metadata.get("source_url", ""),
                },
            }
        )

    return json.dumps(
        {
            "query": query,
            "domain": domain,
            "content_type": content_type,
            "total": len(compact),
            "hits": compact,
        },
        ensure_ascii=True,
    )
