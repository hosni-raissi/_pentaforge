"""
IntelAgent — Threat-intelligence updater that keeps the RAG knowledge base fresh.

Cooldown: controlled by RAG_REFRESH_DAYS (default 3), per target_type.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

import structlog

from server.config.agent import (
    LocalLLMConfig,
    PublicLLMConfig,
    local_llm_config,
    public_llm_config,
    llm_mode,
)
from server.core.llm import ChatMessage, LLMClient
from server.core.llm_local import LocalLLMClient
from server.core.tool import Tool, coerce_args_from_schema

from .tools import ALL_INTEL_TOOLS, IntelContext, set_context
from server.agents.intel.config import (
    FORMATTER_ROUNDS,
    FORMATTER_CALL_TIMEOUT_SECONDS,
    FORMATTER_ALLOWED_TOOLS,
    FORMATTER_TOOL_MAX_RETRIES,
    RAG_REFRESH_DAYS,
    UPDATE_DAYS_BACK,
    UPDATE_MAX_RESULTS,
    MAX_SOURCE_ERRORS,
    MAX_VERIFIED_COMPACT,
    MAX_WEB_COMPACT,
    COMPACT_HITS_LIMIT,
    COMPACT_SNIPPET_LENGTH,
)
from server.db.knowledge.storage.intel_state_store import IntelStateStore
from .prompts import FORMATTER_SYSTEM_PROMPT, build_user_message

logger = structlog.get_logger(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# CALLBACK PROTOCOL
# ═════════════════════════════════════════════════════════════════════════════

class IntelCallback(Protocol):
    """Optional callback for step-by-step progress reporting."""

    def on_step(self, message: str) -> None: ...
    def on_done(self, message: str) -> None: ...
    def on_warn(self, message: str) -> None: ...


class _NoOpCallback:
    """Default callback that does nothing."""
    def on_step(self, message: str) -> None: pass
    def on_done(self, message: str) -> None: pass
    def on_warn(self, message: str) -> None: pass


# ═════════════════════════════════════════════════════════════════════════════
# UPDATE CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

VERIFY_SOURCES: dict[str, list[str]] = {
    "web": ["OWASP-WSTG", "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"],
    "api": ["OWASP-APISecurity", "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"],
    "network": ["MITRE-ATTACK", "PayloadsAllTheThings", "HackTricks"],
    "cloud": ["HackTricks", "MITRE-ATTACK", "PayloadsAllTheThings"],
    "mobile": ["OWASP-MASTG", "HackTricks", "MITRE-ATTACK"],
    "iot": ["OWASP-FSTM", "HackTricks", "PayloadsAllTheThings"],
    "binary": ["PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"],
    "identity": ["HackTricks", "MITRE-ATTACK", "PayloadsAllTheThings"],
    "supply_chain": ["MITRE-ATTACK", "PayloadsAllTheThings", "HackTricks"],
    "web3": ["PayloadsAllTheThings", "HackTricks"],
}

DEFAULT_VERIFY_SOURCES: list[str] = [
    "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK",
]


# ═════════════════════════════════════════════════════════════════════════════
# STATS HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _default_stats() -> dict[str, Any]:
    return {
        "new_payloads": 0, "new_exploits": 0, "total_embedded": 0,
        "content_types_updated": [], "domains_updated": [],
        "update_status": "no_new_data", "rate_limited": False, "source_errors": [],
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


def _safe_hits_count(tool_result: dict[str, Any]) -> int:
    if not isinstance(tool_result, dict):
        return 0
    hits = tool_result.get("hits", [])
    return len(hits) if isinstance(hits, list) else 0


def _compact_hits(hits: list[dict[str, Any]], limit: int = COMPACT_HITS_LIMIT) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for hit in hits[:limit]:
        if not isinstance(hit, dict):
            continue
        metadata = hit.get("metadata", {}) if isinstance(hit.get("metadata", {}), dict) else {}
        compact.append({
            "score": round(float(hit.get("score", 0) or 0), 4),
            "source": metadata.get("source_name", ""),
            "heading": metadata.get("heading", ""),
            "tags": metadata.get("tags", []),
            "snippet": str(hit.get("content", ""))[:COMPACT_SNIPPET_LENGTH],
        })
    return compact


# ═════════════════════════════════════════════════════════════════════════════
# FORMATTER PAYLOAD BUILDER
# ═════════════════════════════════════════════════════════════════════════════

def _build_formatter_payload(report: dict[str, Any]) -> dict[str, Any]:
    def _safe_list(val: Any) -> list:
        return val if isinstance(val, list) else []

    stats = _normalize_stats(report.get("stats"))
    verified_sources = report.get("verified_sources", [])
    verified_compact: list[dict[str, Any]] = []
    for item in (verified_sources[:MAX_VERIFIED_COMPACT] if isinstance(verified_sources, list) else []):
        if isinstance(item, dict):
            verified_compact.append({"source_name": item.get("source_name", ""), "verified": bool(item.get("verified", False)), "trust_score": item.get("trust_score", 0)})

    rag_snapshot = report.get("rag_snapshot", {}) if isinstance(report.get("rag_snapshot", {}), dict) else {}
    rag_results = rag_snapshot.get("results", {}) if isinstance(rag_snapshot.get("results", {}), dict) else {}
    rag_compact = {
        "query": rag_snapshot.get("query", ""), "domain": rag_snapshot.get("domain", "shared"),
        "strategies": _compact_hits(_safe_list(rag_results.get("strategies"))),
        "attack_types": _compact_hits(_safe_list(rag_results.get("attack_types"))),
        "exploits": _compact_hits(_safe_list(rag_results.get("exploits"))),
    }

    prefetch = report.get("formatter_prefetch", {}) if isinstance(report.get("formatter_prefetch", {}), dict) else {}
    coverage = prefetch.get("coverage_counts", {}) if isinstance(prefetch.get("coverage_counts", {}), dict) else {}
    web_fallback = prefetch.get("web_fallback", {}) if isinstance(prefetch.get("web_fallback", {}), dict) else {}
    web_compact: list[dict[str, Any]] = []
    for row in _safe_list(web_fallback.get("results"))[:MAX_WEB_COMPACT]:
        if isinstance(row, dict):
            web_compact.append({"title": row.get("title", ""), "url": row.get("url", ""), "snippet": str(row.get("snippet", ""))[:COMPACT_SNIPPET_LENGTH]})

    return {
        "target_type": report.get("target_type", "unknown"), "info": report.get("info", ""), "summary": report.get("summary", ""),
        "stats": stats, "verified_sources": verified_compact, "coverage_counts": coverage,
        "rag_snapshot": rag_compact,
        "web_fallback": {"used": bool(web_fallback.get("used", False)), "query": web_fallback.get("query", ""), "results": web_compact},
    }


# ═════════════════════════════════════════════════════════════════════════════
# INTEL RESULT
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class IntelResult:
    status: str = "incomplete"
    summary: str = ""
    stats: dict[str, Any] = field(default_factory=_default_stats)


# ═════════════════════════════════════════════════════════════════════════════
# LLM OUTPUT PARSER
# ═════════════════════════════════════════════════════════════════════════════

def _format_list_section(label: str, items: Any) -> str:
    if not isinstance(items, list) or not items:
        return f"{label}:\n- (none found)"
    lines = [f"{label}:"]
    for item in items:
        if isinstance(item, dict):
            name = item.get("name", item.get("title", ""))
            desc = item.get("description", "")
            text = f"{name} — {desc}" if name and desc else str(name) if name else str(next(iter(item.values()), ""))
        else:
            text = str(item).strip() if item else ""
        if text.strip():
            lines.append(f"- {text.strip()}")
    return "\n".join(lines)


def _build_summary_from_sections(data: dict[str, Any]) -> str:
    sections: list[str] = []
    for keys, label in [
        (("methods", "strategies", "methodologies", "testing_methods"), "METHODS"),
        (("techniques", "attack_techniques", "attack_types", "ttps"), "TECHNIQUES"),
        (("vulnerabilities", "vulnerability_types", "vulns", "exploits", "weakness_classes"), "VULNERABILITIES"),
        (("gaps", "coverage_gaps", "missing", "not_covered"), "GAPS"),
    ]:
        for key in keys:
            val = data.get(key)
            if isinstance(val, list) and val:
                sections.append(_format_list_section(label, val))
                break
            if isinstance(val, str) and val.strip():
                sections.append(f"{label}:\n{val.strip()}")
                break
    return "\n\n".join(sections)


def _extract_stats_from_alt_keys(data: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("stats", "pipeline_stats", "statistics", "pipeline_statistics"):
        val = data.get(key)
        if isinstance(val, dict):
            return val
    return None


def _parse_json_intel(data: dict[str, Any]) -> IntelResult:
    data_lower = {k.lower(): v for k, v in data.items()}
    summary_val = data_lower.get("summary")
    if isinstance(summary_val, str) and summary_val.strip():
        return IntelResult(status=data_lower.get("status", "complete"), summary=summary_val.strip(), stats=_normalize_stats(data_lower.get("stats", {})))
    if isinstance(summary_val, dict):
        summary_lower = {k.lower(): v for k, v in summary_val.items()}
        summary_text = _build_summary_from_sections(summary_lower)
        if summary_text.strip():
            return IntelResult(status=data_lower.get("status", "complete"), summary=summary_text, stats=_normalize_stats(_extract_stats_from_alt_keys(data_lower)))
    section_keys = {"methods", "techniques", "vulnerabilities", "strategies", "attack_techniques", "attack_types", "vulns", "gaps", "methodologies", "testing_methods", "ttps", "vulnerability_types", "weakness_classes"}
    if any(k in data_lower and isinstance(data_lower[k], (list, str)) for k in section_keys):
        summary = _build_summary_from_sections(data_lower)
        if summary.strip():
            return IntelResult(status=data_lower.get("status", "complete"), summary=summary, stats=_normalize_stats(_extract_stats_from_alt_keys(data_lower)))
    return IntelResult(status="complete", summary="")


def _extract_markdown_sections(text: str) -> str:
    methods, techniques, vulns = [], [], []
    method_re = re.compile(r"(?:method|strateg|approach|assessment|testing\s+guide|ptes|wstg)", re.IGNORECASE)
    technique_re = re.compile(r"(?:technique|attack\s+vector|bypass|injection|xss|ssrf|csrf|smuggling|traversal|ssti|rce|lfi|rfi|xxe|idor|deserialization)", re.IGNORECASE)
    vuln_re = re.compile(r"(?:vulnerabilit|weakness|exploit|cve-|misconfigur|broken\s+access|insecure)", re.IGNORECASE)
    current = "techniques"
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith("**"):
            heading = stripped.lstrip("#* ").rstrip("*: ")
            if method_re.search(heading): current = "methods"
            elif vuln_re.search(heading): current = "vulns"
            elif technique_re.search(heading): current = "techniques"
            continue
        if stripped.startswith("- ") or stripped.startswith("* "):
            item = stripped[2:].strip()
            if item and len(item) >= 3:
                {"methods": methods, "vulns": vulns, "techniques": techniques}[current].append(item)
    sections = []
    if methods: sections.append(_format_list_section("METHODS", methods))
    if techniques: sections.append(_format_list_section("TECHNIQUES", techniques))
    if vulns: sections.append(_format_list_section("VULNERABILITIES", vulns))
    return "\n\n".join(sections) if len(methods) + len(techniques) + len(vulns) >= 3 else ""


def _parse_intel_output(raw: str) -> IntelResult:
    text = raw.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
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
            result = _parse_json_intel(data)
            if result.summary:
                return result
    except json.JSONDecodeError:
        pass
    if len(text) > 50:
        summary = _extract_markdown_sections(text)
        if summary:
            return IntelResult(status="complete", summary=summary, stats=_default_stats())
    return IntelResult(status="complete", summary="")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _needs_nothink(model_name: str) -> bool:
    lowered = model_name.lower()
    return "qwen3" in lowered or "qwen-3" in lowered


def _get_valid_params(tool: Tool) -> set[str] | None:
    try:
        sig = inspect.signature(tool.execute)
        params = set()
        for name, param in sig.parameters.items():
            if name == "self": continue
            if param.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY):
                params.add(name)
            elif param.kind == inspect.Parameter.VAR_KEYWORD:
                return None
        return params if params else None
    except (ValueError, TypeError):
        return None


# ═════════════════════════════════════════════════════════════════════════════
# INTEL AGENT
# ═════════════════════════════════════════════════════════════════════════════

class IntelAgent:
    """Threat-intelligence agent that fetches, compares, and updates the RAG."""

    def __init__(
        self,
        tools: list[Tool] | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        mode: str | None = None,
        context: IntelContext | None = None,
        callback: IntelCallback | None = None,
    ) -> None:
        self._mode = mode or llm_mode.mode
        self._cb = callback or _NoOpCallback()
        self._context = context or IntelContext()
        set_context(self._context)

        self._state_store = IntelStateStore()
        self._background_tasks: set[asyncio.Task] = set()

        tool_list = tools or ALL_INTEL_TOOLS
        self._tools = {t.name: t for t in tool_list}
        self._formatter_tool_schemas = [t.schema() for t in tool_list if t.name in FORMATTER_ALLOWED_TOOLS]
        self._tool_valid_params: dict[str, set[str] | None] = {t.name: _get_valid_params(t) for t in tool_list}

        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LocalLLMClient(self._local_config)
            self._model_name = self._local_config.model
        else:
            self._config = config or public_llm_config
            self._llm = LLMClient(self._config)
            self._model_name = self._config.model

        logger.info("intel_initialized", mode=self._mode, model=self._model_name)

    # ── Public API ─────────────────────────────────────────────────────

    async def run(self, target_type: str = "all", info: str = "") -> IntelResult:
        self._cb.on_step(f"Intel Agent starting for target_type='{target_type}'")
        await self._context.ensure_ready()

        # Check cooldown
        now = datetime.now(timezone.utc)
        last_update = self._state_store.get_last_update(target_type)
        refresh_seconds = RAG_REFRESH_DAYS * 86400
        if last_update is None or (now - last_update).total_seconds() >= refresh_seconds:
            self._cb.on_step("RAG update needed — starting background pipeline")
            task = asyncio.create_task(
                self._run_update_pipeline(target_type=target_type, info=info),
                name=f"intel_update_{target_type}",
            )
            self._background_tasks.add(task)
            task.add_done_callback(self._on_background_update_done)
        else:
            days_ago = (now - last_update).total_seconds() / 86400
            self._cb.on_done(f"RAG is fresh (updated {days_ago:.1f} days ago) — skipping update")

        # Foreground: snapshot → prefetch → format
        self._cb.on_step("Collecting RAG snapshot")
        rag_snapshot = await self._collect_rag_snapshot(target_type=target_type)
        results = rag_snapshot.get("results", {})
        self._cb.on_done(
            f"RAG snapshot: strategies={len(results.get('strategies', []))}, "
            f"attack_types={len(results.get('attack_types', []))}, "
            f"exploits={len(results.get('exploits', []))}"
        )

        self._cb.on_step("Prefetching formatter context")
        pipeline_report: dict[str, Any] = {"target_type": target_type, "info": info, "rag_snapshot": rag_snapshot}
        pipeline_report["formatter_prefetch"] = await self._prepare_formatter_context(target_type=target_type, pipeline_report=pipeline_report)
        counts = pipeline_report["formatter_prefetch"].get("coverage_counts", {})
        web_used = pipeline_report["formatter_prefetch"].get("web_fallback", {}).get("used", False)
        self._cb.on_done(
            f"Prefetch: methods={counts.get('methods', 0)}, techniques={counts.get('techniques', 0)}, "
            f"vulns={counts.get('vulnerabilities', 0)}, web_fallback={'yes' if web_used else 'no'}"
        )

        llm_result = await self._run_formatter(target_type=target_type, info=info, pipeline_report=pipeline_report)

        result_stats = _normalize_stats(llm_result.stats)
        summary = llm_result.summary.strip() or _build_deterministic_summary(pipeline_report)
        self._cb.on_done(f"Intel Agent complete — status={llm_result.status}")
        return IntelResult(status=llm_result.status or "complete", summary=summary, stats=result_stats)

    # ── Background Task ────────────────────────────────────────────────

    def _on_background_update_done(self, task: asyncio.Task) -> None:
        self._background_tasks.discard(task)
        if task.cancelled():
            self._cb.on_warn("Background update cancelled")
            return
        exc = task.exception()
        if exc:
            self._cb.on_warn(f"Background update failed: {exc}")
            logger.error("intel_background_update_failed", task=task.get_name(), error=repr(exc))
        else:
            self._cb.on_done("Background RAG update completed")

    # ── LLM Formatter ──────────────────────────────────────────────────

    async def _run_formatter(self, target_type: str, info: str, pipeline_report: dict[str, Any]) -> IntelResult:
        self._cb.on_step(f"LLM formatter starting ({FORMATTER_ROUNDS} rounds max)")
        formatter_payload = _build_formatter_payload(pipeline_report)

        system_content = FORMATTER_SYSTEM_PROMPT
        if _needs_nothink(self._model_name):
            system_content = "/nothink\n" + system_content

        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=system_content),
            ChatMessage(role="user", content=build_user_message(target_type, info, formatter_payload, current_round=1, max_rounds=FORMATTER_ROUNDS)),
        ]

        total_tool_calls = 0

        for round_num in range(1, FORMATTER_ROUNDS + 1):
            self._cb.on_step(f"LLM Round {round_num}/{FORMATTER_ROUNDS}")

            try:
                response = await asyncio.wait_for(
                    self._llm.chat(messages, tools=self._formatter_tool_schemas or None, temperature=0.2, max_tokens=8000),
                    timeout=FORMATTER_CALL_TIMEOUT_SECONDS,
                )
            except Exception as exc:
                self._cb.on_warn(f"LLM error: {exc}")
                return IntelResult(status="complete", summary=_build_deterministic_summary(pipeline_report), stats=_normalize_stats(pipeline_report.get("stats")))

            # Final response
            if not response.tool_calls:
                raw_content = response.content or ""
                self._cb.on_done(f"LLM Round {round_num}: Final answer ({len(raw_content)} chars)")
                logger.info("intel_complete", rounds=round_num, total_tool_calls=total_tool_calls, tools_used=total_tool_calls > 0, usage=response.usage)

                result = _parse_intel_output(raw_content)
                if not result.summary:
                    self._cb.on_warn("LLM returned unparseable output — using fallback")

                self._cb.on_done(f"Formatter done: {total_tool_calls} tool calls across {round_num} rounds")
                return result

            # Tool calls
            tool_names = [tc["function"]["name"] for tc in response.tool_calls]
            total_tool_calls += len(response.tool_calls)
            self._cb.on_step(f"LLM Round {round_num}: Calling tools → {tool_names}")

            messages.append(ChatMessage(role="assistant", content=response.content, tool_calls=response.tool_calls))

            for tc in response.tool_calls:
                tool_name = tc["function"]["name"]
                raw_args = tc["function"].get("arguments", "{}")
                call_id = tc["id"]

                if tool_name not in FORMATTER_ALLOWED_TOOLS:
                    self._cb.on_warn(f"Tool '{tool_name}' blocked — not in allowed list")
                    messages.append(ChatMessage(role="tool", content=f"Error: tool '{tool_name}' not permitted.", tool_call_id=call_id, name=tool_name))
                    continue

                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except json.JSONDecodeError:
                    args = {}
                if not isinstance(args, dict):
                    args = {}
                args = self._filter_tool_args(tool_name, args)

                query_preview = str(args.get("query", ""))[:50]
                content_type = args.get("content_type", "")
                self._cb.on_step(f"  {tool_name}(query='{query_preview}...', type='{content_type}')")

                tool = self._tools.get(tool_name)
                if tool is None:
                    result_str = f"Error: unknown tool '{tool_name}'"
                else:
                    result_str = await self._execute_with_retry(tool, **args)

                # Report hits count
                try:
                    parsed = json.loads(result_str)
                    hits = len(parsed.get("hits", [])) if isinstance(parsed, dict) else 0
                    self._cb.on_done(f"  → {hits} hits returned")
                except (json.JSONDecodeError, TypeError):
                    self._cb.on_done(f"  → {len(result_str)} chars returned")

                messages.append(ChatMessage(role="tool", content=result_str, tool_call_id=call_id, name=tool_name))

            # Budget reminder
            next_round = round_num + 1
            if next_round <= FORMATTER_ROUNDS:
                rounds_left = FORMATTER_ROUNDS - next_round
                if rounds_left == 0:
                    budget_msg = "⚠ THIS IS YOUR LAST ROUND. Return your final JSON now. Do NOT call any more tools."
                else:
                    budget_msg = f"Round {next_round}/{FORMATTER_ROUNDS}. {rounds_left} rounds remaining ({max(0, rounds_left - 1)} for tools + 1 for final answer)."
                messages.append(ChatMessage(role="user", content=budget_msg))

        self._cb.on_warn(f"Reached max rounds ({FORMATTER_ROUNDS}) without final answer")
        return IntelResult(status="incomplete", summary=f"Reached maximum formatter rounds ({FORMATTER_ROUNDS}) without final answer.")

    # ── Update Pipeline ────────────────────────────────────────────────

    async def _run_update_pipeline(self, target_type: str, info: str) -> dict[str, Any]:
        domain = target_type if target_type != "all" else "shared"
        self._cb.on_step(f"Update: Verifying sources for '{target_type}'")

        source_list = VERIFY_SOURCES.get(target_type, DEFAULT_VERIFY_SOURCES)
        verified: list[dict[str, Any]] = []
        for source_name in source_list:
            res = await self._call_tool_json("verify_source", source_name=source_name)
            verified.append(res)
        trusted = [v for v in verified if isinstance(v, dict) and v.get("verified")]
        self._cb.on_done(f"Update: {len(trusted)}/{len(source_list)} sources verified")

        categories = await self._discover_categories(target_type, domain)
        self._cb.on_done(f"Update: {len(categories)} categories discovered")

        stats = _default_stats()
        rate_limited = False
        source_errors: list[str] = []
        stats["domains_updated"] = [domain]
        content_types_updated: set[str] = set()
        payload_candidates: list[dict[str, Any]] = []
        exploit_candidates: list[dict[str, Any]] = []

        if trusted:
            self._cb.on_step(f"Update: Fetching payloads ({len(categories)} categories) + exploits")
            payload_tasks = [self._call_tool_json("fetch_payloads", category=cat, days_back=UPDATE_DAYS_BACK, max_results=UPDATE_MAX_RESULTS) for cat in categories]
            exploit_coro = self._call_tool_json("fetch_exploits", keyword=target_type, days_back=UPDATE_DAYS_BACK, max_results=UPDATE_MAX_RESULTS)
            all_results = await asyncio.gather(*payload_tasks, exploit_coro, return_exceptions=True)
            payload_results = all_results[:-1]
            exploit_result = all_results[-1]

            for idx, fetched in enumerate(payload_results):
                if isinstance(fetched, BaseException):
                    source_errors.append(f"payload_fetch: {fetched}")
                    continue
                if not isinstance(fetched, dict):
                    continue
                rate_limited = rate_limited or bool(fetched.get("rate_limited", False))
                if isinstance(fetched.get("errors", []), list):
                    source_errors.extend(str(e) for e in fetched["errors"] if e)
                for item in fetched.get("payloads", []):
                    if not isinstance(item, dict):
                        continue
                    payload_candidates.append({
                        "title": f"{item.get('repo', 'repo')}::{item.get('path', 'path')}",
                        "content": f"Source: {item.get('repo', '')}\nPath: {item.get('path', '')}\nCommit: {item.get('commit_message', '')}",
                        "domain": domain, "category": "payload-technique",
                        "tags": ["payload", "technique", target_type],
                        "url": item.get("raw_url", ""), "content_type": "attack_types",
                    })

            if isinstance(exploit_result, BaseException):
                source_errors.append(f"exploit_fetch: {exploit_result}")
            elif isinstance(exploit_result, dict):
                rate_limited = rate_limited or bool(exploit_result.get("rate_limited", False))
                if isinstance(exploit_result.get("errors", []), list):
                    source_errors.extend(str(e) for e in exploit_result["errors"] if e)
                for item in exploit_result.get("exploits", []):
                    if not isinstance(item, dict):
                        continue
                    exploit_candidates.append({
                        "title": item.get("name", "Unknown exploit"),
                        "content": f"Description: {item.get('description', '')}\nLanguage: {item.get('language', '')}\nUpdated at: {item.get('updated_at', '')}",
                        "domain": domain, "category": "exploit-technique",
                        "tags": ["exploit", target_type],
                        "url": item.get("url", ""), "content_type": "exploits",
                    })

            self._cb.on_done(f"Update: Found {len(payload_candidates)} payload candidates, {len(exploit_candidates)} exploit candidates")

        payload_new = await self._compare_new_items(payload_candidates, content_type="attack_types", domain=domain)
        exploit_new = await self._compare_new_items(exploit_candidates, content_type="exploits", domain=domain)
        payload_upserted = await self._embed_items(payload_new, source_name="intel-static-payloads", content_type="attack_types")
        exploit_upserted = await self._embed_items(exploit_new, source_name="intel-static-exploits", content_type="exploits")

        if payload_upserted > 0:
            content_types_updated.add("attack_types")
        if exploit_upserted > 0:
            content_types_updated.add("exploits")

        stats.update({
            "new_payloads": len(payload_new), "new_exploits": len(exploit_new),
            "total_embedded": payload_upserted + exploit_upserted,
            "content_types_updated": sorted(content_types_updated),
            "rate_limited": rate_limited, "source_errors": source_errors[:MAX_SOURCE_ERRORS],
        })
        if stats["total_embedded"] > 0:
            stats["update_status"] = "updated"
        elif rate_limited:
            stats["update_status"] = "rate_limited"
        elif not trusted:
            stats["update_status"] = "source_unavailable"

        self._cb.on_done(f"Update: embedded={stats['total_embedded']}, status={stats['update_status']}")

        summary = f"Static pipeline complete for {target_type}: update_status={stats['update_status']}, new_payloads={stats['new_payloads']}, new_exploits={stats['new_exploits']}, total_embedded={stats['total_embedded']}."
        await self._call_tool_json("notify_planner", summary=summary, updated_domains=",".join(stats["domains_updated"]), new_payload_count=stats["new_payloads"], new_exploit_count=stats["new_exploits"])
        self._state_store.set_last_update(target_type, datetime.now(timezone.utc))

        return {"target_type": target_type, "info": info, "verified_sources": verified, "stats": stats, "summary": summary, "domains_considered": [domain]}

    # ── Category Discovery ─────────────────────────────────────────────

    async def _discover_categories(self, target_type: str, domain: str) -> list[str]:
        result = await self._call_tool_json("search_rag", query=f"{target_type} attack techniques categories payloads", domain=domain, content_type="attack_types", n_results=25)
        hits = result.get("hits", []) if isinstance(result, dict) else []
        seen: set[str] = set()
        categories: list[str] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            metadata = hit.get("metadata", {})
            if not isinstance(metadata, dict):
                continue
            heading = metadata.get("heading", "")
            if isinstance(heading, str) and heading and heading not in seen:
                seen.add(heading)
                categories.append(heading)
        if categories:
            return categories
        return [target_type]

    # ── RAG Helpers ────────────────────────────────────────────────────

    async def _compare_new_items(self, items: list[dict[str, Any]], content_type: str, domain: str) -> list[dict[str, Any]]:
        if not items:
            return []
        result = await self._call_tool_json("compare_with_rag", items=json.dumps(items, ensure_ascii=True), content_type=content_type, domain=domain)
        new_items = result.get("new_items", []) if isinstance(result, dict) else []
        return [i for i in new_items if isinstance(i, dict)] if isinstance(new_items, list) else []

    async def _embed_items(self, items: list[dict[str, Any]], source_name: str, content_type: str) -> int:
        if not items:
            return 0
        result = await self._call_tool_json("embed_and_upsert", items=json.dumps(items, ensure_ascii=True), source_name=source_name, content_type=content_type)
        return int(result.get("embedded", 0) or 0) if isinstance(result, dict) else 0

    async def _collect_rag_snapshot(self, target_type: str) -> dict[str, Any]:
        query = f"{target_type} methodology techniques vulnerabilities"
        domain = target_type if target_type != "all" else "shared"
        out: dict[str, Any] = {"query": query, "domain": domain, "results": {}}
        for ct in ("strategies", "attack_types", "exploits"):
            tool_result = await self._call_tool_json("search_rag", query=query, domain=domain, content_type=ct, n_results=6)
            out["results"][ct] = tool_result.get("hits", []) if isinstance(tool_result, dict) else []
        return out

    async def _prepare_formatter_context(self, target_type: str, pipeline_report: dict[str, Any]) -> dict[str, Any]:
        rag_snapshot = pipeline_report.get("rag_snapshot", {})
        rag_domain = str(rag_snapshot.get("domain", "shared")) if isinstance(rag_snapshot, dict) else "shared"
        queries = {
            "methods": {"query": f"{target_type} security testing methodology strategy OWASP", "content_type": "strategies"},
            "techniques": {"query": f"{target_type} attack techniques TTP MITRE ATT&CK", "content_type": "attack_types"},
            "vulnerabilities": {"query": f"{target_type} vulnerabilities exploit patterns", "content_type": "exploits"},
        }
        rag_prefetch: dict[str, Any] = {}
        for key, cfg in queries.items():
            rag_prefetch[key] = await self._call_tool_json("search_rag", query=cfg["query"], domain=rag_domain, content_type=cfg["content_type"], n_results=10)
        methods_n = _safe_hits_count(rag_prefetch.get("methods", {}))
        techniques_n = _safe_hits_count(rag_prefetch.get("techniques", {}))
        vulns_n = _safe_hits_count(rag_prefetch.get("vulnerabilities", {}))
        web_fallback: dict[str, Any] = {"used": False, "query": "", "results": []}
        if techniques_n == 0 or vulns_n == 0:
            fallback_query = f"site:attack.mitre.org {target_type} ATT&CK techniques vulnerabilities OWASP"
            web_result = await self._call_tool_json("search_web", query=fallback_query, max_results=8)
            web_fallback = {"used": True, "query": fallback_query, "results": web_result.get("results", []) if isinstance(web_result, dict) else []}
        return {"rag_prefetch": rag_prefetch, "coverage_counts": {"methods": methods_n, "techniques": techniques_n, "vulnerabilities": vulns_n}, "web_fallback": web_fallback}

    # ── Tool Execution ─────────────────────────────────────────────────

    async def _call_tool_json(self, tool_name: str, **kwargs: Any) -> dict[str, Any]:
        tool = self._tools.get(tool_name)
        if tool is None:
            return {"error": f"unknown tool: {tool_name}"}
        try:
            raw = await tool.execute(**kwargs)
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {"data": parsed}
            except json.JSONDecodeError:
                return {"raw": raw}
        except Exception as exc:
            logger.error("intel_static_tool_error", tool=tool_name, error=str(exc))
            return {"error": str(exc)}

    def _filter_tool_args(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        valid_params = self._tool_valid_params.get(tool_name)
        filtered = args if valid_params is None else {k: v for k, v in args.items() if k in valid_params}
        dropped = set(args.keys()) - set(filtered.keys())
        if dropped:
            logger.warning("intel_tool_args_filtered", tool=tool_name, dropped=sorted(dropped))
        tool = self._tools.get(tool_name)
        if tool is None:
            return filtered
        return coerce_args_from_schema(tool.parameters, filtered)

    async def _execute_tool_calls(self, tool_calls: list[dict]) -> list[ChatMessage]:
        results: list[ChatMessage] = []
        for tc in tool_calls:
            tool_name = tc["function"]["name"]
            raw_args = tc["function"].get("arguments", "{}")
            call_id = tc["id"]
            if tool_name not in FORMATTER_ALLOWED_TOOLS:
                results.append(ChatMessage(role="tool", content=f"Error: tool '{tool_name}' not permitted.", tool_call_id=call_id, name=tool_name))
                continue
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                args = {}
            if not isinstance(args, dict):
                args = {}
            args = self._filter_tool_args(tool_name, args)
            tool = self._tools.get(tool_name)
            result_str = await self._execute_with_retry(tool, **args) if tool else f"Error: unknown tool '{tool_name}'"
            results.append(ChatMessage(role="tool", content=result_str, tool_call_id=call_id, name=tool_name))
        return results

    async def _execute_with_retry(self, tool: Tool, max_retries: int = FORMATTER_TOOL_MAX_RETRIES, **kwargs: Any) -> str:
        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                return await tool.execute(**kwargs)
            except Exception as exc:
                last_error = exc
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
        return f"Error executing {tool.name} after {max_retries + 1} attempts: {last_error}"
