"""
IntelAgent — Threat-intelligence updater that keeps the RAG knowledge base fresh.

Execution model:
    1. Run update pipeline and RAG snapshot pipeline in parallel
    2. Hand both outputs to LLM formatter for final organization
    3. Allow optional formatter-time `search_rag` and `search_web` tool calls only

Workflow:
  User (or scheduler) provides a target type (e.g. "web", "network", "all").
    The static pipeline autonomously:
        - Fetches fresh methodology, payload techniques, and exploit techniques from trusted sources
        - Verifies source integrity
        - Compares against existing RAG data (deduplication)
        - Embeds missing/new entries for target-relevant sources
        - Notifies the Planner agent via Redis
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from server.config.agent import (
    LocalLLMConfig,
    PlannerLLMConfig,
    local_llm_config,
    planner_llm_config,
    planner_llm_mode,
)
from server.core.llm import ChatMessage, LLMClient
from server.core.llm_local import LocalLLMClient
from server.core.tool import Tool

from .tools import ALL_INTEL_TOOLS, IntelContext, set_context

from server.db.knowledge.config.settings import settings
from server.db.knowledge.storage.intel_state_store import IntelStateStore

logger = structlog.get_logger(__name__)

FORMATTER_ROUNDS = 3
FORMATTER_CALL_TIMEOUT_SECONDS = 45


def _skipped_update_report(target_type: str, info: str) -> dict[str, Any]:
    """Minimal update report returned when the RAG refresh cooldown is still active."""
    stats = _default_stats()
    stats["update_status"] = "skipped"
    stats["domains_updated"] = [target_type] if target_type != "all" else ["shared"]
    return {
        "target_type": target_type,
        "info": info,
        "verified_sources": [],
        "stats": stats,
        "summary": f"RAG refresh cooldown active for {target_type}; skipping source update.",
        "domains_considered": [],
    }


def _default_stats() -> dict[str, Any]:
    return {
        "new_payloads": 0,
        "new_exploits": 0,
        "total_embedded": 0,
        "content_types_updated": [],
        "domains_updated": [],
        "update_status": "no_new_data",
        "rate_limited": False,
        "source_errors": [],
    }


def _normalize_stats(stats: dict[str, Any] | None) -> dict[str, Any]:
    merged = _default_stats()
    if not isinstance(stats, dict):
        return merged
    merged.update(stats)
    if not isinstance(merged.get("content_types_updated"), list):
        merged["content_types_updated"] = []
    if not isinstance(merged.get("domains_updated"), list):
        merged["domains_updated"] = []
    if not isinstance(merged.get("update_status"), str):
        merged["update_status"] = "no_new_data"
    merged["rate_limited"] = bool(merged.get("rate_limited", False))
    if not isinstance(merged.get("source_errors"), list):
        merged["source_errors"] = []
    return merged


def _build_deterministic_summary(pipeline_report: dict[str, Any]) -> str:
    stats = _normalize_stats(pipeline_report.get("stats"))
    target_type = pipeline_report.get("target_type", "unknown")
    rag_snapshot = pipeline_report.get("rag_snapshot", {})
    results = rag_snapshot.get("results", {}) if isinstance(rag_snapshot, dict) else {}
    methods = len(results.get("strategies", [])) if isinstance(results, dict) else 0
    techniques = len(results.get("attack_types", [])) if isinstance(results, dict) else 0
    vulns = len(results.get("exploits", [])) if isinstance(results, dict) else 0
    return (
        f"Static pipeline complete for {target_type}. "
        f"update_status={stats['update_status']}. "
        f"new_payloads={stats['new_payloads']}, new_exploits={stats['new_exploits']}, "
        f"total_embedded={stats['total_embedded']}. "
        f"RAG snapshot: methods={methods}, techniques={techniques}, vulnerabilities={vulns}."
    )


def _summary_is_suspicious(summary: str) -> bool:
    lowered = summary.lower()
    suspicious_markers = [
        "cve-",
        "critical vulnerabilities",
        "immediate patching",
    ]
    return any(marker in lowered for marker in suspicious_markers)


def _safe_hits_count(tool_result: dict[str, Any]) -> int:
    if not isinstance(tool_result, dict):
        return 0
    hits = tool_result.get("hits", [])
    if not isinstance(hits, list):
        return 0
    return len(hits)


def _compact_hits(hits: list[dict[str, Any]], limit: int = 4) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for hit in hits[:limit]:
        if not isinstance(hit, dict):
            continue
        metadata = hit.get("metadata", {}) if isinstance(hit.get("metadata", {}), dict) else {}
        compact.append(
            {
                "score": round(float(hit.get("score", 0) or 0), 4),
                "source": metadata.get("source_name", ""),
                "heading": metadata.get("heading", ""),
                "tags": metadata.get("tags", []),
                "snippet": str(hit.get("content", ""))[:180],
            }
        )
    return compact


def _build_formatter_payload(report: dict[str, Any]) -> dict[str, Any]:
    """Reduce report size to avoid local-LLM timeout on huge prompts."""
    stats = _normalize_stats(report.get("stats"))
    verified_sources = report.get("verified_sources", [])
    verified_compact: list[dict[str, Any]] = []
    for item in verified_sources[:10] if isinstance(verified_sources, list) else []:
        if not isinstance(item, dict):
            continue
        verified_compact.append(
            {
                "source_name": item.get("source_name", ""),
                "verified": bool(item.get("verified", False)),
                "trust_score": item.get("trust_score", 0),
            }
        )

    rag_snapshot = report.get("rag_snapshot", {}) if isinstance(report.get("rag_snapshot", {}), dict) else {}
    rag_results = rag_snapshot.get("results", {}) if isinstance(rag_snapshot.get("results", {}), dict) else {}
    rag_compact = {
        "query": rag_snapshot.get("query", ""),
        "domain": rag_snapshot.get("domain", "shared"),
        "strategies": _compact_hits(rag_results.get("strategies", []) if isinstance(rag_results.get("strategies", []), list) else []),
        "attack_types": _compact_hits(rag_results.get("attack_types", []) if isinstance(rag_results.get("attack_types", []), list) else []),
        "exploits": _compact_hits(rag_results.get("exploits", []) if isinstance(rag_results.get("exploits", []), list) else []),
    }

    prefetch = report.get("formatter_prefetch", {}) if isinstance(report.get("formatter_prefetch", {}), dict) else {}
    coverage = prefetch.get("coverage_counts", {}) if isinstance(prefetch.get("coverage_counts", {}), dict) else {}
    web_fallback = prefetch.get("web_fallback", {}) if isinstance(prefetch.get("web_fallback", {}), dict) else {}
    web_results = web_fallback.get("results", []) if isinstance(web_fallback.get("results", []), list) else []
    web_compact = []
    for row in web_results[:6]:
        if not isinstance(row, dict):
            continue
        web_compact.append(
            {
                "title": row.get("title", ""),
                "url": row.get("url", ""),
                "snippet": str(row.get("snippet", ""))[:180],
            }
        )

    return {
        "target_type": report.get("target_type", "unknown"),
        "info": report.get("info", ""),
        "summary": report.get("summary", ""),
        "stats": stats,
        "verified_sources": verified_compact,
        "coverage_counts": coverage,
        "rag_snapshot": rag_compact,
        "web_fallback": {
            "used": bool(web_fallback.get("used", False)),
            "query": web_fallback.get("query", ""),
            "results": web_compact,
        },
    }


@dataclass
class IntelResult:
    """Structured output from the Intel agent."""

    status: str = "incomplete"
    summary: str = ""
    stats: dict = field(default_factory=_default_stats)


def _parse_intel_output(raw: str) -> IntelResult:
    """Parse the LLM's final text into an IntelResult.

        Accepts:
            - Pure JSON: {"status": "complete", "summary": "...", "stats": {...}}
            - Markdown with a ```json block containing the above

        Any non-JSON formatter output is ignored (empty summary), so the caller can
        safely fallback to deterministic pipeline summary.
    """
    text = raw.strip()

    # Strip <think>...</think> blocks (reasoning models)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # Extract JSON from code block
    json_str = text
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start) if "```" in text[start:] else len(text)
        json_str = text[start:end].strip()
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start) if "```" in text[start:] else len(text)
        json_str = text[start:end].strip()

    try:
        data = json.loads(json_str)
        if isinstance(data, dict):
            stats = data.get("stats", {})
            stats = _normalize_stats(stats)
            return IntelResult(
                status=data.get("status", "complete"),
                summary=data.get("summary", ""),
                stats=stats,
            )
    except json.JSONDecodeError:
        pass

    # Non-JSON outputs are treated as unusable formatter responses.
    return IntelResult(status="complete", summary="")


class IntelAgent:
    """Threat-intelligence agent that fetches, compares, and updates the RAG."""

    def __init__(
        self,
        tools: list[Tool] | None = None,
        config: PlannerLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        mode: str | None = None,
        context: IntelContext | None = None,
    ) -> None:
        self._mode = mode or planner_llm_mode.mode

        # Initialise shared tool context
        self._context = context or IntelContext()
        set_context(self._context)

        # State store for tracking last RAG update time
        self._state_store = IntelStateStore()

        # Register tools
        tool_list = tools or ALL_INTEL_TOOLS
        self._tools = {t.name: t for t in tool_list}
        self._formatter_tool_schemas = [
            t.schema() for t in tool_list if t.name in {"search_rag", "search_web"}
        ]

        # LLM backend
        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LocalLLMClient(self._local_config)
            logger.info("intel_using_local_llm", model=self._local_config.model)
        else:
            self._config = config or planner_llm_config
            self._llm = LLMClient(self._config)
            logger.info("intel_using_public_llm", model=self._config.model)

    async def run(self, target_type: str = "all", info: str = "") -> IntelResult:
        """Run update and RAG pipelines in parallel, then LLM formatting.

        Args:
            target_type: One of "web", "api", "network", "mobile", "cloud",
                         "iot", "binary", "identity", "supply_chain", "web3", "all".
        """
        await self._context.ensure_ready()

        # ── RAG refresh cooldown check ────────────────────────────────────
        now = datetime.now(timezone.utc)
        last_update = self._state_store.get_last_update(target_type)
        refresh_seconds = settings.rag_refresh_days * 86400
        cooldown_active = (
            last_update is not None
            and (now - last_update).total_seconds() < refresh_seconds
        )

        if cooldown_active:
            elapsed_hours = int((now - last_update).total_seconds() // 3600)
            logger.info(
                "intel_rag_cooldown_active",
                target_type=target_type,
                elapsed_hours=elapsed_hours,
                refresh_days=settings.rag_refresh_days,
            )
            update_report = _skipped_update_report(target_type=target_type, info=info)
            rag_snapshot = await self._collect_rag_snapshot(target_type=target_type)
        else:
            update_task = asyncio.create_task(
                self._run_update_pipeline(target_type=target_type, info=info)
            )
            rag_task = asyncio.create_task(
                self._collect_rag_snapshot(target_type=target_type)
            )
            update_report, rag_snapshot = await asyncio.gather(update_task, rag_task)

            # Persist the update timestamp so the cooldown starts from now
            update_status = update_report.get("stats", {}).get("update_status", "no_new_data")
            self._state_store.set_last_update(target_type, now, update_status)

        pipeline_report = {
            **update_report,
            "rag_snapshot": rag_snapshot,
        }
        pipeline_report["formatter_prefetch"] = await self._prepare_formatter_context(
            target_type=target_type,
            pipeline_report=pipeline_report,
        )
        llm_result = await self._run_formatter(target_type=target_type, info=info, pipeline_report=pipeline_report)

        # Source of truth for update status is deterministic pipeline stats.
        pipeline_stats = _normalize_stats(pipeline_report.get("stats"))
        result_stats = _normalize_stats(llm_result.stats)
        result_stats.update(pipeline_stats)

        summary = llm_result.summary.strip()
        deterministic_summary = _build_deterministic_summary(pipeline_report)
        if not summary or _summary_is_suspicious(summary):
            summary = deterministic_summary

        status = llm_result.status or "complete"
        return IntelResult(status=status, summary=summary, stats=result_stats)

    async def _run_formatter(self, target_type: str, info: str, pipeline_report: dict[str, Any]) -> IntelResult:
        """Use LLM only to organize/format deterministic pipeline outputs."""
        formatter_system_prompt = (
            "You are Intel Formatter. The static intel pipeline has already executed. "
            "Your objective is maximum coverage for the target: methods, strategies, techniques, and vulnerabilities. "
            "Use RAG evidence first. If evidence is missing in RAG, you may use search_web to query MITRE ATT&CK context. "
            "Do not fetch/update sources again. You may only use search_rag and search_web. "
            "Return pure JSON: {\"status\":\"complete\",\"summary\":\"...\",\"stats\":{...}}"
        )

        formatter_payload = _build_formatter_payload(pipeline_report)
        user_message = (
            f"Target type: {target_type}\n\n"
            f"Additional info: {info or 'none'}\n\n"
            f"Pipeline report JSON (compact):\n{json.dumps(formatter_payload, ensure_ascii=True)}\n\n"
            "Produce a comprehensive intel result for this target. "
            "Include as much supported coverage as possible for methods/strategies/vulnerabilities from RAG evidence. "
            "If formatter_prefetch indicates low coverage, use available tools to search RAG again and/or MITRE/web context. "
            "Keep stats consistent with pipeline report."
        )

        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=formatter_system_prompt),
            ChatMessage(role="user", content=user_message),
        ]

        for round_num in range(1, FORMATTER_ROUNDS + 1):
            logger.info("intel_round", round=round_num, messages=len(messages))

            try:
                response = await asyncio.wait_for(
                    self._llm.chat(
                        messages,
                        tools=self._formatter_tool_schemas if self._formatter_tool_schemas else None,
                        temperature=0.2,
                        max_tokens=900,
                    ),
                    timeout=FORMATTER_CALL_TIMEOUT_SECONDS,
                )
            except Exception as exc:
                logger.warning(
                    "intel_formatter_llm_error",
                    error=repr(exc),
                    timeout_seconds=FORMATTER_CALL_TIMEOUT_SECONDS,
                )
                return IntelResult(
                    status="complete",
                    summary=_build_deterministic_summary(pipeline_report),
                    stats=_normalize_stats(pipeline_report.get("stats")),
                )

            if not response.tool_calls:
                logger.info("intel_complete", rounds=round_num, usage=response.usage)
                result = _parse_intel_output(response.content or "")
                logger.info("intel_result", status=result.status, stats=result.stats)
                return result

            messages.append(
                ChatMessage(
                    role="assistant",
                    content=response.content,
                    tool_calls=response.tool_calls,
                )
            )

            # Execute tool calls and collect responses
            tool_messages = await self._execute_tool_calls(response.tool_calls)
            messages.extend(tool_messages)

        logger.warning("intel_formatter_max_rounds", max=FORMATTER_ROUNDS)
        return IntelResult(
            status="incomplete",
            summary=f"Reached maximum formatter rounds ({FORMATTER_ROUNDS}) without final answer.",
        )

    async def _run_update_pipeline(self, target_type: str, info: str) -> dict[str, Any]:
        """Deterministic update pipeline: check updates -> ingest -> notify."""
        domains = [target_type] if target_type != "all" else ["shared", "web", "api", "network", "mobile", "cloud", "iot", "binary", "identity", "supply_chain", "web3"]

        verify_sources = {
            "web": ["OWASP-WSTG", "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"],
            "api": ["OWASP-APISecurity", "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"],
        }
        source_list = verify_sources.get(target_type, ["PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"])

        verified: list[dict[str, Any]] = []
        for source_name in source_list:
            res = await self._call_tool_json("verify_source", source_name=source_name)
            verified.append(res)

        trusted = [v for v in verified if isinstance(v, dict) and v.get("verified")]

        category_map = {
            "web": [
                "XSS Injection",
                "SQL Injection",
                "Server Side Request Forgery",
                "Command Injection",
                "Request Smuggling",
            ],
            "api": ["GraphQL Injection", "JSON Web Token", "OAuth Misconfiguration"],
        }
        categories = category_map.get(target_type, [""])

        stats = _default_stats()
        rate_limited = False
        source_errors: list[str] = []
        if target_type != "all":
            stats["domains_updated"] = [target_type]
        else:
            stats["domains_updated"] = ["shared"]
        content_types_updated: set[str] = set()

        # 1) Check source updates and fetch latest payload techniques
        payload_candidates: list[dict[str, Any]] = []
        if trusted:
            for category in categories:
                fetched = await self._call_tool_json(
                    "fetch_payloads",
                    category=category,
                    days_back=14,
                    max_results=25,
                )
                if isinstance(fetched, dict):
                    rate_limited = rate_limited or bool(fetched.get("rate_limited", False))
                    errors = fetched.get("errors", [])
                    if isinstance(errors, list):
                        source_errors.extend([str(e) for e in errors if e])
                for item in fetched.get("payloads", []) if isinstance(fetched, dict) else []:
                    payload_candidates.append(
                        {
                            "title": f"{item.get('repo', 'repo')}::{item.get('path', 'path')}",
                            "content": (
                                f"Source: {item.get('repo', '')}\\n"
                                f"Path: {item.get('path', '')}\\n"
                                f"Commit: {item.get('commit_message', '')}"
                            ),
                            "domain": target_type if target_type != "all" else "shared",
                            "category": "payload-technique",
                            "tags": ["payload", "technique", target_type],
                            "url": item.get("raw_url", ""),
                            "content_type": "attack_types",
                        }
                    )

        # 2) Fetch exploit techniques and compare/embed
        exploit_candidates: list[dict[str, Any]] = []
        if trusted:
            fetched_exploits = await self._call_tool_json(
                "fetch_exploits",
                keyword=target_type,
                days_back=14,
                max_results=25,
            )
            if isinstance(fetched_exploits, dict):
                rate_limited = rate_limited or bool(fetched_exploits.get("rate_limited", False))
                errors = fetched_exploits.get("errors", [])
                if isinstance(errors, list):
                    source_errors.extend([str(e) for e in errors if e])
            for item in fetched_exploits.get("exploits", []) if isinstance(fetched_exploits, dict) else []:
                exploit_candidates.append(
                    {
                        "title": item.get("name", "Unknown exploit"),
                        "content": (
                            f"Description: {item.get('description', '')}\\n"
                            f"Language: {item.get('language', '')}\\n"
                            f"Updated at: {item.get('updated_at', '')}"
                        ),
                        "domain": target_type if target_type != "all" else "shared",
                        "category": "exploit-technique",
                        "tags": ["exploit", target_type],
                        "url": item.get("url", ""),
                        "content_type": "exploits",
                    }
                )

        payload_new_items = await self._compare_new_items(payload_candidates, content_type="attack_types", domain=target_type if target_type != "all" else "shared")
        exploit_new_items = await self._compare_new_items(exploit_candidates, content_type="exploits", domain=target_type if target_type != "all" else "shared")

        payload_upserted = await self._embed_items(payload_new_items, source_name="intel-static-payloads", content_type="attack_types")
        exploit_upserted = await self._embed_items(exploit_new_items, source_name="intel-static-exploits", content_type="exploits")

        if payload_upserted > 0:
            content_types_updated.add("attack_types")
        if exploit_upserted > 0:
            content_types_updated.add("exploits")

        stats["new_payloads"] = len(payload_new_items)
        stats["new_exploits"] = len(exploit_new_items)
        stats["total_embedded"] = payload_upserted + exploit_upserted
        stats["content_types_updated"] = sorted(content_types_updated)
        stats["rate_limited"] = rate_limited
        stats["source_errors"] = source_errors[:10]

        if stats["total_embedded"] > 0:
            stats["update_status"] = "updated"
        elif rate_limited:
            stats["update_status"] = "rate_limited"
        elif not trusted:
            stats["update_status"] = "source_unavailable"
        else:
            stats["update_status"] = "no_new_data"

        summary = (
            f"Static pipeline complete for {target_type}: "
            f"update_status={stats['update_status']}, "
            f"new_payloads={stats['new_payloads']}, "
            f"new_exploits={stats['new_exploits']}, "
            f"total_embedded={stats['total_embedded']}."
        )

        await self._call_tool_json(
            "notify_planner",
            summary=summary,
            updated_domains=",".join(stats["domains_updated"]),
            new_payload_count=stats["new_payloads"],
            new_exploit_count=stats["new_exploits"],
        )

        return {
            "target_type": target_type,
            "info": info,
            "verified_sources": verified,
            "stats": stats,
            "summary": summary,
            "domains_considered": domains,
        }

    async def _compare_new_items(self, items: list[dict[str, Any]], content_type: str, domain: str) -> list[dict[str, Any]]:
        if not items:
            return []
        result = await self._call_tool_json(
            "compare_with_rag",
            items=json.dumps(items, ensure_ascii=True),
            content_type=content_type,
            domain=domain,
        )
        new_items = result.get("new_items", []) if isinstance(result, dict) else []
        if not isinstance(new_items, list):
            return []
        return [i for i in new_items if isinstance(i, dict)]

    async def _embed_items(self, items: list[dict[str, Any]], source_name: str, content_type: str) -> int:
        if not items:
            return 0
        result = await self._call_tool_json(
            "embed_and_upsert",
            items=json.dumps(items, ensure_ascii=True),
            source_name=source_name,
            content_type=content_type,
        )
        if isinstance(result, dict):
            return int(result.get("embedded", 0) or 0)
        return 0

    async def _collect_rag_snapshot(self, target_type: str) -> dict[str, Any]:
        query = f"{target_type} methodology techniques vulnerabilities"
        domain = target_type if target_type != "all" else "shared"
        out: dict[str, Any] = {"query": query, "domain": domain, "results": {}}
        for ct in ("strategies", "attack_types", "exploits"):
            tool_result = await self._call_tool_json(
                "search_rag",
                query=query,
                domain=domain,
                content_type=ct,
                n_results=6,
            )
            out["results"][ct] = tool_result.get("hits", []) if isinstance(tool_result, dict) else []
        return out

    async def _prepare_formatter_context(
        self,
        target_type: str,
        pipeline_report: dict[str, Any],
    ) -> dict[str, Any]:
        """Prefetch extra RAG/web context so formatter can maximize coverage quality."""
        rag_snapshot = pipeline_report.get("rag_snapshot", {})
        rag_domain = "shared"
        if isinstance(rag_snapshot, dict):
            rag_domain = str(rag_snapshot.get("domain", "shared"))

        queries = {
            "methods": {
                "query": f"{target_type} security testing methodology strategy OWASP",
                "content_type": "strategies",
            },
            "techniques": {
                "query": f"{target_type} attack techniques TTP MITRE ATT&CK",
                "content_type": "attack_types",
            },
            "vulnerabilities": {
                "query": f"{target_type} vulnerabilities exploit patterns",
                "content_type": "exploits",
            },
        }

        rag_prefetch: dict[str, Any] = {}
        for key, cfg in queries.items():
            rag_prefetch[key] = await self._call_tool_json(
                "search_rag",
                query=cfg["query"],
                domain=rag_domain,
                content_type=cfg["content_type"],
                n_results=10,
            )

        methods_n = _safe_hits_count(rag_prefetch.get("methods", {}))
        techniques_n = _safe_hits_count(rag_prefetch.get("techniques", {}))
        vulns_n = _safe_hits_count(rag_prefetch.get("vulnerabilities", {}))

        needs_web_fallback = techniques_n == 0 or vulns_n == 0
        web_fallback: dict[str, Any] = {
            "used": False,
            "query": "",
            "results": [],
        }
        if needs_web_fallback:
            fallback_query = (
                f"site:attack.mitre.org {target_type} ATT&CK techniques vulnerabilities "
                f"OWASP"
            )
            web_result = await self._call_tool_json(
                "search_web",
                query=fallback_query,
                max_results=8,
            )
            web_fallback = {
                "used": True,
                "query": fallback_query,
                "results": web_result.get("results", []) if isinstance(web_result, dict) else [],
            }

        return {
            "rag_prefetch": rag_prefetch,
            "coverage_counts": {
                "methods": methods_n,
                "techniques": techniques_n,
                "vulnerabilities": vulns_n,
            },
            "web_fallback": web_fallback,
        }

    async def _call_tool_json(self, tool_name: str, **kwargs: Any) -> dict[str, Any]:
        tool = self._tools.get(tool_name)
        if tool is None:
            return {"error": f"unknown tool: {tool_name}"}
        try:
            raw = await tool.execute(**kwargs)
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
                return {"data": parsed}
            except json.JSONDecodeError:
                return {"raw": raw}
        except Exception as exc:
            logger.error("intel_static_tool_error", tool=tool_name, error=str(exc))
            return {"error": str(exc)}

    async def _execute_tool_calls(self, tool_calls: list[dict]) -> list[ChatMessage]:
        """Execute a batch of tool calls and return the corresponding ChatMessages."""
        results: list[ChatMessage] = []
        for tc in tool_calls:
            tool_name = tc["function"]["name"]
            raw_args = tc["function"].get("arguments", "{}")
            call_id = tc["id"]

            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                args = {}
            if not isinstance(args, dict):
                args = {}

            tool = self._tools.get(tool_name)
            if tool is None:
                result_str = f"Error: unknown tool '{tool_name}'"
                logger.warning("intel_unknown_tool", tool=tool_name)
            else:
                logger.info("intel_tool_call", tool=tool_name, args=args)
                try:
                    result_str = await tool.execute(**args)
                except Exception as exc:
                    result_str = f"Error executing {tool_name}: {exc}"
                    logger.error("intel_tool_error", tool=tool_name, error=str(exc))

            results.append(
                ChatMessage(role="tool", content=result_str, tool_call_id=call_id, name=tool_name)
            )
        return results
