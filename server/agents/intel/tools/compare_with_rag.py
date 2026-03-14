from __future__ import annotations

import json
from typing import Any

import structlog

from server.core.tool import tool

from .context import get_context

logger = structlog.get_logger(__name__)


@tool(
    name="compare_with_rag",
    description=(
        "Compare fetched items against the existing RAG knowledge base using "
        "similarity search. Returns which items are NEW (not in RAG) and which "
        "are EXISTING (already embedded). Use this for deduplication before embedding. "
        "content_type must be one of: strategies, exploits, tools, standards, attack_types."
    ),
)
async def compare_with_rag(
    items: str,
    content_type: str = "exploits",
    domain: str | None = None,
) -> str:
    ctx = get_context()
    await ctx.ensure_ready()
    try:
        item_list = json.loads(items) if isinstance(items, str) else items
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in items parameter"})

    if not isinstance(item_list, list):
        return json.dumps({"error": "items must be a JSON array"})

    new_items: list[dict[str, Any]] = []
    existing_items: list[dict[str, Any]] = []
    similarity_threshold = 0.85

    for item in item_list:
        title = item.get("title", "")
        content = item.get("content", "")
        search_text = f"{title} {content}"[:500]

        try:
            query_emb = await ctx.embedder.embed_single(search_text, is_query=True)
            hits = ctx.vector_store.search(
                query_embedding=query_emb,
                content_type=content_type,
                domain=domain,
                n_results=3,
            )
        except Exception as exc:
            logger.warning("compare_search_error", error=str(exc))
            new_items.append({**item, "reason": "search_error"})
            continue

        best_score = max((h.get("score", 0) for h in hits), default=0)
        if best_score >= similarity_threshold:
            existing_items.append(
                {
                    **item,
                    "best_match_score": round(best_score, 4),
                    "best_match": hits[0].get("content", "")[:200] if hits else "",
                }
            )
        else:
            new_items.append({**item, "best_match_score": round(best_score, 4) if hits else 0})

    result = {
        "new_count": len(new_items),
        "existing_count": len(existing_items),
        "new_items": new_items,
        "existing_items": existing_items,
    }
    logger.info("compare_with_rag_done", new=len(new_items), existing=len(existing_items), content_type=content_type)
    return json.dumps(result, default=str)
