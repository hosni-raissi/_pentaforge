from __future__ import annotations

import json
from typing import Any

from server.core.tool import tool

from .context import get_context


_DOMAIN_ALIASES: dict[str, str] = {
    "web": "web_app",
    "web3": "web_app",
    "infrastructure": "infra",
    "infra": "infra",
    "identity": "linux_server",
    "binary": "desktop",
    "supply_chain": "repository",
    "recon": "shared",
    "red_team": "shared",
    "cve_exploit": "shared",
    "container": "cloud",
    "database": "infra",
    "db": "infra",
}

_DOMAIN_SEARCH_EXPANSIONS: dict[str, tuple[str, ...]] = {
    "web_app": ("web_app", "web"),
    "infra": ("infra", "linux_server", "infrastructure", "identity", "database"),
    "linux_server": ("linux_server", "infra", "infrastructure", "identity", "database"),
    "cloud": ("cloud", "container"),
    "repository": ("repository", "supply_chain"),
}

_CONTENT_TYPE_ALIASES: dict[str, str] = {
    "strategy": "strategies",
    "strategies": "strategies",
    "method": "strategies",
    "methods": "strategies",
    "methodology": "strategies",
    "methodologies": "strategies",
    "exploit": "exploits",
    "exploits": "exploits",
    "vulnerability": "exploits",
    "vulnerabilities": "exploits",
    "vuln": "exploits",
    "vulns": "exploits",
    "weakness_classes": "exploits",
    "tool": "tools",
    "tools": "tools",
    "standard": "standards",
    "standards": "standards",
    "checklist": "standards",
    "checklists": "standards",
    "attack_type": "attack_types",
    "attack_types": "attack_types",
    "technique": "attack_types",
    "techniques": "attack_types",
    "ttp": "attack_types",
    "ttps": "attack_types",
}


def _normalize_domain(value: str) -> str:
    clean = str(value or "").strip().lower().replace("-", "_")
    if not clean:
        return "shared"
    return _DOMAIN_ALIASES.get(clean, clean)


def _candidate_domains(value: str) -> list[str]:
    raw = str(value or "").strip().lower().replace("-", "_")
    normalized = _normalize_domain(value)

    candidates: list[str] = []
    for item in (normalized, raw, *_DOMAIN_SEARCH_EXPANSIONS.get(normalized, ())):
        clean = str(item or "").strip().lower().replace("-", "_")
        if not clean or clean in candidates:
            continue
        candidates.append(clean)
    return candidates or ["shared"]


def _normalize_content_type(value: str) -> str:
    clean = str(value or "").strip().lower().replace("-", "_")
    return _CONTENT_TYPE_ALIASES.get(clean, "strategies")


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
    normalized_domain = _normalize_domain(domain)
    normalized_content_type = _normalize_content_type(content_type)
    candidate_domains = _candidate_domains(domain)

    query_embedding = await ctx.embedder.embed_single(query, is_query=True)

    primary: list[dict[str, Any]] = []
    for candidate in candidate_domains:
        primary.extend(
            ctx.vector_store.search(
                query_embedding=query_embedding,
                content_type=normalized_content_type,
                domain=candidate,
                n_results=n_results,
            )
        )

    if include_shared and normalized_domain != "shared":
        shared = ctx.vector_store.search(
            query_embedding=query_embedding,
            content_type=normalized_content_type,
            domain="shared",
            n_results=n_results,
        )
        hits = _merge_hits(primary, shared, n_results)
    else:
        hits = _merge_hits(primary, [], n_results)

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
            "domain": normalized_domain,
            "domains_searched": candidate_domains + (["shared"] if include_shared and normalized_domain != "shared" else []),
            "content_type": normalized_content_type,
            "total": len(compact),
            "hits": compact,
        },
        ensure_ascii=True,
    )
