from __future__ import annotations

import json
import re
from typing import Any

from server.core.tool import tool
from server.db.knowledge.orchestrator import KnowledgeOrchestrator
from server.db.knowledge.storage.embedding import EmbeddingGenerator
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore
from server.utils.known_vuln_intelligence import (
    build_known_vuln_query,
    canonicalize_product_name,
    confidence_label,
    normalize_version_text,
    recommend_nuclei_hints,
    recommend_run_custom_tools,
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _coerce_products(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return []
        return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []
    return []


async def _extract_local_signals(
    *,
    query: str,
    product: str,
    version: str,
    max_results: int,
) -> list[dict[str, Any]]:
    embedder = EmbeddingGenerator()
    vector_store = QdrantVectorStore()
    vector_store.ensure_all_collections()
    embedding = await embedder.embed_single(query, is_query=True)
    hits = vector_store.search_multi(
        query_embedding=embedding,
        domain="shared",
        n_results=max_results,
    )

    signals: list[dict[str, Any]] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        content = str(hit.get("content", "")).strip()
        metadata = hit.get("metadata", {}) if isinstance(hit.get("metadata"), dict) else {}
        title = str(metadata.get("heading", metadata.get("title", ""))).strip()
        combined = f"{title}\n{content}".lower()
        if product and product.lower() not in combined:
            continue
        if version and version.lower() not in combined and not _CVE_RE.search(combined):
            continue
        cves = sorted(set(match.upper() for match in _CVE_RE.findall(combined)))
        source_name = str(metadata.get("source_name", "")).strip()
        signals.append(
            {
                "product": product,
                "version": version,
                "cve": cves[0] if cves else "",
                "title": title or source_name or query,
                "severity": "",
                "cisa_kev": "kev" in combined or "known exploited" in combined or source_name.lower() == "cisa-kev",
                "source": source_name or "knowledge_base",
                "summary": content[:220].strip(),
                "confidence_label": "high" if cves else "medium",
            }
        )
        if len(signals) >= max_results:
            break
    return signals


async def _extract_nvd_signals(
    *,
    query: str,
    product: str,
    version: str,
    severity: str,
    max_results: int,
) -> list[dict[str, Any]]:
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.initialize()
    result = await orchestrator.nvd.search_product(
        query,
        severity=severity or None,
        max_results=max_results,
    )

    signals: list[dict[str, Any]] = []
    for doc in result.documents[:max_results]:
        title = str(doc.title or "").strip()
        content = str(doc.content or "").strip()
        combined = f"{title}\n{content}"
        cves = sorted(set(match.upper() for match in _CVE_RE.findall(combined)))
        if version and version not in combined and not cves:
            continue
        signals.append(
            {
                "product": product,
                "version": version,
                "cve": cves[0] if cves else "",
                "title": title or query,
                "severity": str(doc.extra.get("severity", "")).strip().upper() if isinstance(doc.extra, dict) else "",
                "cisa_kev": bool(doc.extra.get("cisa_kev", False)) if isinstance(doc.extra, dict) else False,
                "source": str(doc.metadata.source_name).strip(),
                "summary": content[:220].strip(),
                "confidence_label": "high" if cves else confidence_label(0.7),
            }
        )
    return signals


@tool(
    name="known_vuln_lookup",
    description=(
        "Look up known vulnerabilities for detected products and versions using local knowledge plus on-demand NVD enrichment. "
        "Returns compact vulnerability signals and nuclei/tool-selection hints."
    ),
)
async def known_vuln_lookup(
    products: list[dict[str, Any]] | str,
    target_type: str = "web_app",
    severity: str = "HIGH",
    max_results_per_product: int = 4,
) -> str:
    product_rows = _coerce_products(products)
    if not product_rows:
        return json.dumps(
            {
                "success": False,
                "target_type": target_type,
                "products": [],
                "signals": [],
                "nuclei_hints": {},
                "recommended_run_custom_tools": [],
                "error": "no products supplied",
            },
            ensure_ascii=True,
        )

    normalized_products: list[dict[str, Any]] = []
    all_signals: list[dict[str, Any]] = []
    seen_signal_keys: set[str] = set()

    for row in product_rows[:10]:
        product = canonicalize_product_name(row.get("product", row.get("name", "")))
        version = normalize_version_text(row.get("version_normalized") or row.get("version"))
        if not product:
            continue
        normalized_products.append(
            {
                "product": product,
                "version": version,
                "confidence_label": str(row.get("confidence_label", "")).strip() or "medium",
                "source_count": int(row.get("source_count", 0) or 0),
                "kb_query": str(
                    row.get("kb_query")
                    or build_known_vuln_query(
                        product=product,
                        version=version,
                        target_type=target_type,
                    )
                ).strip(),
            }
        )

    for row in normalized_products:
        query = str(row.get("kb_query", "")).strip()
        product = str(row.get("product", "")).strip()
        version = str(row.get("version", "")).strip()
        try:
            local_signals = await _extract_local_signals(
                query=query,
                product=product,
                version=version,
                max_results=max_results_per_product,
            )
        except Exception as exc:
            local_signals = [
                {
                    "product": product,
                    "version": version,
                    "cve": "",
                    "title": query,
                    "severity": "",
                    "cisa_kev": False,
                    "source": "knowledge_base_error",
                    "summary": str(exc)[:220],
                    "confidence_label": "low",
                }
            ]
        for signal in local_signals:
            key = "|".join(
                [
                    str(signal.get("product", "")).strip(),
                    str(signal.get("version", "")).strip(),
                    str(signal.get("cve", "")).strip(),
                    str(signal.get("title", "")).strip().lower(),
                    str(signal.get("source", "")).strip().lower(),
                ]
            )
            if key not in seen_signal_keys:
                seen_signal_keys.add(key)
                all_signals.append(signal)

        try:
            nvd_signals = await _extract_nvd_signals(
                query=query,
                product=product,
                version=version,
                severity=severity,
                max_results=max_results_per_product,
            )
        except Exception as exc:
            nvd_signals = [
                {
                    "product": product,
                    "version": version,
                    "cve": "",
                    "title": query,
                    "severity": "",
                    "cisa_kev": False,
                    "source": "nvd_runtime_error",
                    "summary": str(exc)[:220],
                    "confidence_label": "low",
                }
            ]
        for signal in nvd_signals:
            key = "|".join(
                [
                    str(signal.get("product", "")).strip(),
                    str(signal.get("version", "")).strip(),
                    str(signal.get("cve", "")).strip(),
                    str(signal.get("title", "")).strip().lower(),
                    str(signal.get("source", "")).strip().lower(),
                ]
            )
            if key not in seen_signal_keys:
                seen_signal_keys.add(key)
                all_signals.append(signal)

    payload = {
        "success": True,
        "target_type": target_type,
        "products": normalized_products,
        "signals": all_signals[:40],
        "nuclei_hints": recommend_nuclei_hints(normalized_products),
        "recommended_run_custom_tools": recommend_run_custom_tools(normalized_products),
    }
    return json.dumps(payload, ensure_ascii=True)
