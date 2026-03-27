from __future__ import annotations

import json
import re
from typing import Any

from server.core.tool import tool

from .context import get_context


_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web": "web_app",
    "web3": "web_app",
    "infrastructure": "linux_server",
    "binary": "desktop",
    "identity": "linux_server",
    "supply_chain": "repository",
    "recon": "shared",
    "red_team": "shared",
    "cve_exploit": "shared",
}

_TARGET_TO_RAG_DOMAIN: dict[str, str] = {
    "container": "cloud",
    "database": "linux_server",
}


def _normalize_target_type(value: str) -> str:
    clean = str(value or "").strip().lower().replace("-", "_")
    if not clean:
        return "all"
    return _TARGET_TYPE_ALIASES.get(clean, clean)


def _rag_domain_for_target(target_type: str) -> str:
    normalized = _normalize_target_type(target_type)
    if normalized in {"", "all"}:
        return "shared"
    return _TARGET_TO_RAG_DOMAIN.get(normalized, normalized)


def _framework_for_hit(hit: dict[str, Any]) -> str:
    metadata = hit.get("metadata", {}) if isinstance(hit.get("metadata", {}), dict) else {}
    source_name = str(metadata.get("source_name", "")).lower()
    heading = str(metadata.get("heading", "")).lower()
    content = str(hit.get("content", "")).lower()
    merged = f"{source_name} {heading} {content}"
    if "wstg" in merged or "owasp" in merged:
        return "OWASP"
    if "ptes" in merged:
        return "PTES"
    if "mitre" in merged or "att&ck" in merged or "attack" in merged:
        return "MITRE ATT&CK"
    return "RAG"


def _phase_for_text(value: str) -> str:
    lowered = value.lower()
    if any(k in lowered for k in ("recon", "enumeration", "discovery", "osint")):
        return "reconnaissance"
    if any(k in lowered for k in ("auth", "session", "account", "access control", "idor", "bola")):
        return "access_and_auth"
    if any(k in lowered for k in ("sqli", "xss", "ssrf", "ssti", "xxe", "injection")):
        return "injection_and_input"
    if any(k in lowered for k in ("exploit", "rce", "lateral", "pivot", "privesc", "post")):
        return "exploitation"
    if any(k in lowered for k in ("verify", "validate", "evidence", "proof")):
        return "verification"
    if any(k in lowered for k in ("report", "remediation", "risk")):
        return "reporting"
    return "assessment"


def _extract_candidate_lines(text: str) -> list[str]:
    candidates: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("- ", "* ", "• ")):
            line = line[2:].strip()
        elif re.match(r"^\d+[\.\)]\s+", line):
            line = re.sub(r"^\d+[\.\)]\s+", "", line).strip()
        else:
            continue
        if len(line) < 8:
            continue
        if len(line) > 180:
            line = line[:180].rstrip()
        candidates.append(line)
    return candidates


async def _domain_search_hits(
    *,
    ctx: Any,
    query: str,
    target_domain: str,
    content_type: str,
    n_results: int,
) -> list[dict[str, Any]]:
    query_embedding = await ctx.embedder.embed_single(query, is_query=True)
    primary = ctx.vector_store.search(
        query_embedding=query_embedding,
        content_type=content_type,
        domain=target_domain,
        n_results=n_results,
    )
    if target_domain == "shared":
        return primary
    shared = ctx.vector_store.search(
        query_embedding=query_embedding,
        content_type=content_type,
        domain="shared",
        n_results=n_results,
    )
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for hit in sorted(primary + shared, key=lambda h: h.get("score", 0), reverse=True):
        hit_id = str(hit.get("id", "")).strip()
        if hit_id and hit_id in seen:
            continue
        if hit_id:
            seen.add(hit_id)
        merged.append(hit)
        if len(merged) >= n_results:
            break
    return merged


@tool(
    name="get_checklists",
    description=(
        "Build a target-specific pentest checklist from OWASP/PTES/MITRE-aware RAG sources. "
        "Returns normalized checklist items with phase/category/source metadata."
    ),
)
async def get_checklists(
    target_type: str,
    info: str = "",
    n_items: int = 24,
) -> str:
    ctx = get_context()
    await ctx.ensure_ready()

    target = _normalize_target_type(target_type)
    target_domain = _rag_domain_for_target(target)
    max_items = max(6, min(80, int(n_items)))

    queries: list[tuple[str, str, str]] = [
        ("OWASP checklist testing guide", "standards", "framework"),
        ("PTES pentest phases checklist", "strategies", "framework"),
        ("MITRE ATT&CK techniques for pentest mapping", "attack_types", "mapping"),
        (f"{target} pentest checklist methodology", "strategies", "target"),
    ]
    if info.strip():
        queries.append((f"{target} checklist {info[:160]}", "attack_types", "context"))

    collected_hits: list[dict[str, Any]] = []
    for query, content_type, _kind in queries:
        hits = await _domain_search_hits(
            ctx=ctx,
            query=query,
            target_domain=target_domain,
            content_type=content_type,
            n_results=10,
        )
        collected_hits.extend(hits)

    items: list[dict[str, Any]] = []
    seen_titles: set[str] = set()

    for hit in collected_hits:
        metadata = hit.get("metadata", {}) if isinstance(hit.get("metadata", {}), dict) else {}
        source_name = str(metadata.get("source_name", "")).strip() or "unknown"
        heading = str(metadata.get("heading", "")).strip()
        content = str(hit.get("content", "")).strip()
        framework = _framework_for_hit(hit)

        seed_titles: list[str] = []
        if heading:
            seed_titles.append(heading)
        seed_titles.extend(_extract_candidate_lines(content)[:4])

        for title in seed_titles:
            clean_title = re.sub(r"\s+", " ", title).strip(" -:*")
            if len(clean_title) < 8:
                continue
            key = clean_title.lower()
            if key in seen_titles:
                continue
            seen_titles.add(key)
            items.append(
                {
                    "id": f"CHK-{len(items) + 1:03d}",
                    "title": clean_title,
                    "phase": _phase_for_text(clean_title),
                    "category": "test_case",
                    "framework": framework,
                    "source": source_name,
                    "rationale": f"Derived from {source_name}",
                }
            )
            if len(items) >= max_items:
                break
        if len(items) >= max_items:
            break

    return json.dumps(
        {
            "target_type": target,
            "total": len(items),
            "items": items,
        },
        ensure_ascii=True,
    )
