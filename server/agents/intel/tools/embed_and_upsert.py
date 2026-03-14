from __future__ import annotations

import json
from typing import Any

import structlog

from server.core.tool import tool
from server.db.knowledge.config.sources import ContentType
from server.db.knowledge.models.document import KnowledgeDocument, SourceMetadata, SourceType
from server.db.knowledge.processing.cleaner import ContentCleaner

from .constants import DOMAIN_CONTENT_TYPE
from .context import get_context

logger = structlog.get_logger(__name__)


def _parse_items_input(items: str) -> list[dict[str, Any]] | str:
    try:
        item_list = json.loads(items) if isinstance(items, str) else items
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in items parameter"})
    if not isinstance(item_list, list):
        return json.dumps({"error": "items must be a JSON array"})
    return item_list


def _resolve_content_type(item: dict[str, Any], default: str = "exploits") -> str:
    explicit = item.get("content_type")
    if explicit and explicit in {ct.value for ct in ContentType}:
        return explicit
    domain = item.get("domain", "shared")
    return DOMAIN_CONTENT_TYPE.get(domain, default)


def _build_documents(
    item_list: list[dict],
    source_name: str,
    content_type: str,
) -> tuple[list[KnowledgeDocument], dict[str, str]]:
    ctx = get_context()
    documents: list[KnowledgeDocument] = []
    doc_content_types: dict[str, str] = {}
    for item in item_list:
        resolved_ct = _resolve_content_type(item, default=content_type)
        doc = KnowledgeDocument(
            title=item.get("title", "Untitled"),
            content=item.get("content", ""),
            content_type="markdown",
            domain=item.get("domain", "shared"),
            category=item.get("category", "intelligence"),
            tags=item.get("tags", []),
            metadata=SourceMetadata(
                source_name=source_name,
                source_type=SourceType.API,
                source_url=item.get("url", ""),
            ),
        )
        if not doc.is_meaningful():
            continue
        if ctx.vector_store.exists_by_hash(doc.content_hash, resolved_ct):
            continue
        doc.content = ContentCleaner.clean(doc.content, source_name)
        documents.append(doc)
        doc_content_types[str(doc.id)] = resolved_ct
    return documents, doc_content_types


@tool(
    name="embed_and_upsert",
    description=(
        "Embed and upsert new knowledge items into the RAG vector store. "
        "Accepts a JSON array of {title, content, domain, category, tags, content_type}. "
        "content_type routes to the correct Qdrant collection (strategies, exploits, tools, standards, attack_types). "
        "Only stores genuinely new entries (deduplicates via content hash)."
    ),
)
async def embed_and_upsert(
    items: str,
    source_name: str = "intel-agent",
    content_type: str = "exploits",
) -> str:
    ctx = get_context()
    await ctx.ensure_ready()

    parsed = _parse_items_input(items)
    if isinstance(parsed, str):
        return parsed

    documents, doc_content_types = _build_documents(parsed, source_name, content_type)
    if not documents:
        return json.dumps({"embedded": 0, "message": "No new items to embed (all duplicates or too short)."})

    all_chunks = ctx.chunker.chunk_documents(documents)
    if not all_chunks:
        return json.dumps({"embedded": 0, "message": "Chunking produced no chunks."})

    for chunk in all_chunks:
        if not chunk.domain:
            chunk.domain = documents[0].domain

    embeddings = await ctx.embedder.embed_texts([c.content for c in all_chunks])

    ct_chunks: dict[str, tuple[list, list]] = {}
    for chunk, emb in zip(all_chunks, embeddings):
        ct = doc_content_types.get(str(chunk.document_id))
        if ct is None:
            ct = _resolve_content_type({"domain": chunk.domain}, default=content_type)
        ct_chunks.setdefault(ct, ([], []))
        ct_chunks[ct][0].append(chunk)
        ct_chunks[ct][1].append(emb)

    total_upserted = sum(
        ctx.vector_store.upsert_chunks(chunks, embs, content_type=ct)
        for ct, (chunks, embs) in ct_chunks.items()
    )

    result = {"embedded": total_upserted, "documents": len(documents), "chunks": len(all_chunks)}
    logger.info("embed_and_upsert_done", **result)
    return json.dumps(result)
