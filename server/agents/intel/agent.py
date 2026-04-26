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
    get_public_agent_config,
    llm_mode,
)
from server.core.llm import ChatMessage, LLMClient
from server.core.tool import Tool, coerce_args_from_schema
from server.agents.rate_limiter import get_backup_llm_fallback

from .tools import ALL_INTEL_TOOLS, IntelContext, set_context
from .tools.get_checklists import (
    build_deterministic_checklist_payload,
    clean_checklists_with_llm,
    _clamp_priority,
)
from server.agents.intel.config import (
    FORMATTER_ROUNDS,
    FORMATTER_CALL_TIMEOUT_SECONDS,
    FORMATTER_MAX_TOOLS_PER_ROUND,
    MIN_SYNTH_CHECKLIST_ITEMS,
    FORMATTER_ALLOWED_TOOLS,
    FORMATTER_TOOL_MAX_RETRIES,
    VERIFY_SOURCES,
    DEFAULT_VERIFY_SOURCES,
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
from server.db.projects import ProjectsStore
from .prompts import (
    FORMATTER_SYSTEM_PROMPT,
    PRIORITY_REPROMPT_SYSTEM_PROMPT,
    build_priority_reprompt_prompt,
    build_user_message,
)
from .context_window import build_intel_context_window

logger = structlog.get_logger(__name__)

_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web": "web_app",
    "web3": "web_app",
    "infrastructure": "infra",
    "infra": "infra",
    "database": "infra",
    "db": "infra",
    "binary": "desktop",
    "identity": "linux_server",
    "supply_chain": "repository",
    "recon": "shared",
    "red_team": "shared",
    "cve_exploit": "shared",
}

_TARGET_TO_RAG_DOMAIN: dict[str, str] = {
    "infra": "linux_server",
    "container": "cloud",
}


def _normalize_target_type(value: str) -> str:
    clean = str(value or "").strip().lower().replace("-", "_")
    if not clean:
        return "all"
    return _TARGET_TYPE_ALIASES.get(clean, clean)


def _resolve_rag_domain(target_type: str) -> str:
    normalized = _normalize_target_type(target_type)
    if normalized in {"", "all"}:
        return "shared"
    return _TARGET_TO_RAG_DOMAIN.get(normalized, normalized)


def _target_query_text(target_type: str) -> str:
    normalized = _normalize_target_type(target_type)
    labels = {
        "web_app": "web application",
        "api": "API",
        "mobile": "mobile app",
        "infra": "infrastructure",
        "network": "network",
        "iot": "IoT device",
        "linux_server": "linux server",
        "desktop": "desktop application",
        "cloud": "cloud environment",
        "container": "container platform",
        "repository": "source code repository",
        "shared": "shared security knowledge",
    }
    return labels.get(normalized, normalized.replace("_", " "))


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
# STATS HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _default_stats() -> dict[str, Any]:
    return {
        "new_payloads": 0, "new_exploits": 0, "total_embedded": 0,
        "payload_store_added": 0,
        "sources_total": 0, "sources_verified": 0,
        "rag_sources_processed": 0, "rag_sources_changed": 0,
        "rag_documents_ingested": 0, "rag_chunks_embedded": 0,
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


def _normalize_intel_status(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"complete", "completed", "ok", "success", "succeeded", "done"}:
        return "complete"
    if normalized in {"incomplete", "partial"}:
        return "incomplete"
    if normalized in {"error", "failed", "failure"}:
        return "error"
    return "complete"


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
        f"total_embedded={stats['total_embedded']}, payload_store_added={stats.get('payload_store_added', 0)}. "
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
    vulnerabilities: list[str] = field(default_factory=list)
    # Structured checklist in the same format as get_checklists / clean_checklists_with_llm:
    # {"target_type": str, "available_total": int, "checklist": [...]}
    checklist: dict[str, Any] = field(default_factory=dict)


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


_GENERIC_VULNERABILITY_NAMES = frozenset(
    {
        "vulnerability reproduction",
        "vulnerability reproduce",
        "reproduction",
        "exploit",
        "exploitation",
        "vulnerability",
    }
)

_KNOWN_VULNERABILITY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("sql injection", "SQL Injection"),
    ("stored cross site scripting", "Stored XSS"),
    ("reflected cross site scripting", "Reflected XSS"),
    ("dom based cross site scripting", "DOM XSS"),
    ("cross site scripting", "Cross-Site Scripting (XSS)"),
    ("xss", "Cross-Site Scripting (XSS)"),
    ("server-side request forgery", "Server-Side Request Forgery (SSRF)"),
    ("ssrf", "Server-Side Request Forgery (SSRF)"),
    ("server-side template injection", "Server-Side Template Injection (SSTI)"),
    ("ssti", "Server-Side Template Injection (SSTI)"),
    ("command injection", "Command Injection"),
    ("code injection", "Code Injection"),
    ("xml injection", "XML Injection"),
    ("xxe", "XML External Entity (XXE)"),
    ("ldap injection", "LDAP Injection"),
    ("xpath injection", "XPath Injection"),
    ("csrf", "Cross-Site Request Forgery (CSRF)"),
    ("cross site request forgery", "Cross-Site Request Forgery (CSRF)"),
    ("idor", "Insecure Direct Object Reference (IDOR)"),
    ("insecure direct object references", "Insecure Direct Object Reference (IDOR)"),
    ("insecure direct object reference", "Insecure Direct Object Reference (IDOR)"),
    ("mass assignment", "Mass Assignment"),
    ("oauth", "OAuth Weaknesses"),
    ("json web tokens", "JWT Weaknesses"),
    ("jwt", "JWT Weaknesses"),
    ("path traversal", "Path Traversal"),
    ("directory traversal", "Directory Traversal"),
    ("file include", "File Inclusion"),
    ("deserialization", "Insecure Deserialization"),
    ("request smuggling", "HTTP Request Smuggling"),
    ("host header injection", "Host Header Injection"),
    ("prototype pollution", "Prototype Pollution"),
    ("clickjacking", "Clickjacking"),
    ("open redirect", "Open Redirect"),
    ("file upload", "Unrestricted File Upload"),
    ("privilege escalation", "Privilege Escalation"),
    ("authentication schema", "Authentication Bypass"),
    ("authorization schema", "Authorization Bypass"),
    ("default credentials", "Default Credentials"),
    ("weak password", "Weak Password Policy"),
)

_EXCLUSION_TOPICS: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "label": "SQL Injection",
        "terms": ("sql injection", "sqli"),
    },
    "xss": {
        "label": "XSS",
        "terms": (
            "xss",
            "cross site scripting",
            "cross-site scripting",
            "dom xss",
            "stored xss",
            "reflected xss",
            "dom based cross site scripting",
        ),
    },
    "ssrf": {
        "label": "SSRF",
        "terms": ("ssrf", "server-side request forgery", "server side request forgery"),
    },
    "ssti": {
        "label": "SSTI",
        "terms": ("ssti", "server-side template injection", "server side template injection"),
    },
    "csrf": {
        "label": "CSRF",
        "terms": ("csrf", "cross site request forgery", "cross-site request forgery"),
    },
    "idor": {
        "label": "IDOR",
        "terms": ("idor", "insecure direct object reference", "insecure direct object references"),
    },
    "xxe": {
        "label": "XXE",
        "terms": ("xxe", "xml external entity"),
    },
    "command_injection": {
        "label": "Command Injection",
        "terms": ("command injection",),
    },
    "file_upload": {
        "label": "File Upload",
        "terms": ("file upload", "upload of malicious files", "upload of unexpected file types"),
    },
}

_EXCLUSION_PREFIXES: tuple[str, ...] = (
    "no ",
    "without ",
    "exclude ",
    "excluding ",
    "skip ",
    "ignore ",
    "do not test ",
    "don't test ",
    "dont test ",
    "no testing for ",
)


def _normalize_known_vulnerability(value: str) -> str:
    clean = re.sub(r"\s+", " ", str(value or "").strip(" -\t\r\n:;,")).strip()
    if not clean:
        return ""

    lowered = clean.lower()
    if lowered in _GENERIC_VULNERABILITY_NAMES:
        return ""
    if re.search(r"\bcve-\d{4}-\d{4,7}\b", lowered, flags=re.IGNORECASE):
        return clean

    for needle, label in _KNOWN_VULNERABILITY_PATTERNS:
        if needle in lowered:
            return label
    return ""


def _filter_known_vulnerabilities(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = _normalize_known_vulnerability(value)
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def _dedupe_vulnerabilities_against_checklist(
    vulnerabilities: list[str],
    checklist: dict[str, Any],
) -> list[str]:
    if not vulnerabilities:
        return []
    checklist_names: set[str] = set()
    checklist_vulns: set[str] = set()
    for block in checklist.get("checklist", []):
        if not isinstance(block, dict):
            continue
        for item in block.get("items", []):
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
            else:
                name = str(item).strip()
            if not name:
                continue
            checklist_names.add(name.lower())
            normalized = _normalize_known_vulnerability(name)
            if normalized:
                checklist_vulns.add(normalized.lower())

    deduped: list[str] = []
    for vuln in vulnerabilities:
        clean = str(vuln or "").strip()
        if not clean:
            continue
        if clean.lower() in checklist_names:
            continue
        if clean.lower() in checklist_vulns:
            continue
        normalized = _normalize_known_vulnerability(clean)
        if normalized and normalized.lower() in checklist_vulns:
            continue
        deduped.append(clean)
    return deduped


def _extract_excluded_topics(info: str) -> dict[str, str]:
    lowered = re.sub(r"\s+", " ", str(info or "").lower())
    excluded: dict[str, str] = {}
    for topic, config in _EXCLUSION_TOPICS.items():
        for term in config.get("terms", ()):
            term_text = str(term or "").strip().lower()
            if not term_text:
                continue
            if any(f"{prefix}{term_text}" in lowered for prefix in _EXCLUSION_PREFIXES):
                excluded[topic] = str(config.get("label", topic))
                break
    return excluded


def _matches_excluded_topic(text: str, excluded_topics: dict[str, str]) -> bool:
    lowered = str(text or "").lower()
    if not lowered or not excluded_topics:
        return False
    for topic in excluded_topics:
        topic_config = _EXCLUSION_TOPICS.get(topic, {})
        for term in topic_config.get("terms", ()):
            if str(term or "").lower() in lowered:
                return True
    return False


def _filter_checklist_section_block(block: str, excluded_topics: dict[str, str]) -> str:
    if not block.strip() or not excluded_topics:
        return block.strip()

    blocks: list[list[str]] = []
    current: list[str] = []
    for line in block.splitlines():
        if line.startswith("- [ ] "):
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append(current)

    kept: list[str] = []
    for checklist_block in blocks:
        title = checklist_block[0][6:].strip() if checklist_block and checklist_block[0].startswith("- [ ] ") else ""
        if _matches_excluded_topic(title, excluded_topics):
            continue
        kept.append("\n".join(checklist_block).strip())
    return "\n".join(kept).strip()


def _apply_info_constraints_to_summary(summary: str, info: str) -> str:
    raw = str(summary or "").strip()
    if not raw:
        return raw

    excluded_topics = _extract_excluded_topics(info)
    if not excluded_topics:
        return raw

    sections = _parse_summary_sections(raw)
    if not sections:
        return raw

    summary_sections: list[str] = []

    vulnerability_candidates = _extract_block_items(sections.get("known_vulnerabilities", ""))
    vulnerability_candidates.extend(_extract_block_items(sections.get("vulnerabilities", "")))
    kept_vulnerabilities = [
        item
        for item in _filter_known_vulnerabilities(vulnerability_candidates)
        if not _matches_excluded_topic(item, excluded_topics)
    ]
    if kept_vulnerabilities:
        summary_sections.append(_format_list_section("KNOWN VULNERABILITIES", kept_vulnerabilities))

    filtered_checklist = _filter_checklist_section_block(sections.get("checklist", ""), excluded_topics)
    if filtered_checklist:
        summary_sections.append("CHECKLIST:\n" + filtered_checklist)
    else:
        summary_sections.append("CHECKLIST:\n- (none found)")

    gap_items = _extract_block_items(sections.get("gaps", ""))
    if sections.get("gaps", "").strip() and not gap_items:
        gap_items = [sections["gaps"].strip()]
    excluded_labels = ", ".join(sorted(excluded_topics.values()))
    gap_items.append(f"Excluded by target info: {excluded_labels}.")
    summary_sections.append(_format_list_section("GAPS", _dedupe_keep_order(gap_items)))
    return "\n\n".join(summary_sections)


def _phase_block_title(phase: str) -> str:
    return {
        "1": "Reconnaissance",
        "2": "Enumeration",
        "3": "Configuration & Infrastructure Testing",
        "4": "Authentication, Authorization & Injection Testing",
        "5": "Session Management Testing",
        "6": "Exploitation & Validation",
        "7": "Post-Exploitation",
        "8": "Reporting",
    }.get(str(phase).strip(), f"Phase {phase or 'unknown'}")


def _build_deterministic_formatter_checklist_payload(checklist_data: dict[str, Any], info: str) -> dict[str, Any]:
    cats = checklist_data.get("cats", {})
    available_total = int(checklist_data.get("available_total", checklist_data.get("total", 0)) or 0)
    excluded_topics = _extract_excluded_topics(info)

    phase_map: dict[str, list[dict[str, str]]] = {}
    known_vulnerabilities: list[str] = []

    if isinstance(cats, dict):
        for cat_id, cat_data in cats.items():
            if not isinstance(cat_data, dict):
                continue
            phase = str(cat_data.get("p", "unknown")).strip() or "unknown"
            items = cat_data.get("items", [])
            if not isinstance(items, list):
                continue
            for row in items:
                if not isinstance(row, list) or len(row) < 2:
                    continue
                ref = str(row[0]).strip()
                name = str(row[1]).strip()
                if not ref or not name:
                    continue
                if _matches_excluded_topic(name, excluded_topics):
                    continue
                phase_map.setdefault(phase, []).append({"ref": ref, "name": name, "category": str(cat_id)})
                normalized_vuln = _normalize_known_vulnerability(name)
                if normalized_vuln and not _matches_excluded_topic(normalized_vuln, excluded_topics):
                    known_vulnerabilities.append(normalized_vuln)

    phase_blocks = [
        {
            "phase": phase,
            "title": _phase_block_title(phase),
            "items": phase_map[phase],
        }
        for phase in sorted(phase_map.keys(), key=_phase_sort_key)
    ]

    gaps = []
    if excluded_topics:
        gaps.append(f"Excluded by target info: {', '.join(sorted(excluded_topics.values()))}.")
    if not gaps:
        gaps.append("No major checklist generation gaps detected.")

    return {
        "target_type": checklist_data.get("t", ""),
        "available_total": available_total,
        "known_vulnerabilities": _dedupe_keep_order(known_vulnerabilities)[:14],
        "phase_blocks": phase_blocks,
        "gaps": gaps,
    }


def _build_checklist_llm_input(checklist_data: dict[str, Any], info: str) -> str:
    payload = _build_deterministic_formatter_checklist_payload(checklist_data, info)
    lines = [
        f"Target type: {payload.get('target_type', '')}",
        f"Target info: {info or 'none'}",
        f"Available checklist items: {payload.get('available_total', 0)}",
        "",
        "Candidate checklist blocks:",
    ]
    for block in payload.get("phase_blocks", []):
        if not isinstance(block, dict):
            continue
        phase = str(block.get("phase", ""))
        title = str(block.get("title", "")).strip()
        lines.append(f"Phase {phase} - {title}")
        for item in block.get("items", []):
            if not isinstance(item, dict):
                continue
            lines.append(f"- {item.get('ref', '')}: {item.get('name', '')}")
        lines.append("")
    return "\n".join(lines).strip()


_CUSTOM_CHECKLIST_PHASE_TITLES: dict[str, str] = {
    "1": "Reconnaissance & Surface Mapping",
    "2": "Technology & Entry Point Enumeration",
    "3": "Authentication & Access Control Review",
    "4": "Authentication, Authorization & Injection Testing",
    "5": "Post-Exploitation, Impact & Reporting Follow-up",
}


def _parse_custom_checklist_text(
    raw_text: str,
    *,
    target_type: str,
) -> dict[str, Any]:
    text = str(raw_text or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.strip() for line in text.split("\n")]

    blocks: list[dict[str, Any]] = []
    current_phase = "4"
    current_title = _CUSTOM_CHECKLIST_PHASE_TITLES[current_phase]
    current_items: list[dict[str, Any]] = []

    def flush_block() -> None:
        nonlocal current_items
        seen: set[str] = set()
        normalized_items: list[dict[str, Any]] = []
        for item in current_items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized_items.append({"name": name})
        if normalized_items:
            blocks.append(
                {
                    "phase": current_phase,
                    "title": current_title,
                    "items": normalized_items,
                }
            )
        current_items = []

    for raw_line in lines:
        if not raw_line:
            continue

        phase_match = re.match(
            r"^(?:phase\s*)?([1-5])(?:\s*[-:.)]\s*|\s+)(.+)$",
            raw_line,
            flags=re.IGNORECASE,
        )
        if raw_line.lower().startswith("phase ") and phase_match:
            flush_block()
            current_phase = phase_match.group(1)
            maybe_title = phase_match.group(2).strip(" -:\t")
            current_title = maybe_title or _CUSTOM_CHECKLIST_PHASE_TITLES.get(
                current_phase,
                "Imported Checklist",
            )
            continue

        heading_match = re.match(r"^(?:#+\s*|\*\*\s*)(.+?)(?:\*\*)?$", raw_line)
        if heading_match and not raw_line.startswith(("-", "*", "[", "1.", "2.", "3.", "4.", "5.")):
            heading_text = heading_match.group(1).strip(" -:\t")
            if heading_text and len(heading_text.split()) <= 12:
                flush_block()
                current_title = heading_text
                continue

        item_text = re.sub(r"^(?:[-*•]\s+|\[\s?\]\s+|\d+\.\s+)", "", raw_line).strip()
        if item_text:
            current_items.append({"name": item_text})

    flush_block()

    return {
        "target_type": str(target_type or "").strip(),
        "available_total": sum(
            len(block.get("items", []))
            for block in blocks
            if isinstance(block, dict) and isinstance(block.get("items", []), list)
        ),
        "checklist": blocks,
    }


def _build_custom_checklist_llm_input(raw_text: str, *, target_type: str, info: str) -> str:
    lines = [
        f"Target type: {target_type}",
        f"Target info: {info or 'none'}",
        "Operator-supplied checklist text (.txt upload):",
        "",
        str(raw_text or "").strip(),
    ]
    return "\n".join(lines).strip()


def _format_structured_checklist_for_formatter(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Target type: {payload.get('target_type', '')}")
    lines.append(f"Available checklist items: {payload.get('available_total', 0)}")
    lines.append("")
    lines.append("Current cleaned checklist:")
    for block in payload.get("checklist", []):
        if not isinstance(block, dict):
            continue
        phase = str(block.get("phase", "")).strip()
        title = str(block.get("title", "")).strip()
        if not phase or not title:
            continue
        lines.append(f"Phase {phase} - {title}")
        for item in block.get("items", []):
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                if name:
                    lines.append(f"- {name}")
            elif isinstance(item, str):
                name = item.strip()
                if name:
                    lines.append(f"- {name}")
        lines.append("")
    return "\n".join(lines).strip()


def _is_structured_checklist_payload(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    blocks = payload.get("checklist")
    if not isinstance(blocks, list) or not blocks:
        return False
    for block in blocks:
        if not isinstance(block, dict):
            return False
        phase = str(block.get("phase", "")).strip()
        title = str(block.get("title", "")).strip()
        items = block.get("items")
        if not phase or not title or not isinstance(items, list):
            return False
    return True


def _default_priority_for_phase(phase: str) -> int:
    phase_str = str(phase or "").strip()
    if phase_str == "4":
        return 4
    if phase_str in {"3", "5"}:
        return 3
    if phase_str == "1":
        return 2
    return 3


def _priority_for_item_name(name: str, phase: str) -> int:
    title = str(name or "").strip().lower()
    if not title:
        return _default_priority_for_phase(phase)

    critical_markers = (
        "sql injection",
        "command injection",
        "code injection",
        "server-side request forgery",
        "ssrf",
        "insecure direct object references",
        "idor",
        "privilege escalation",
        "bypassing authorization",
        "default credentials",
        "upload of malicious files",
        "directory traversal",
        "bypassing authentication",
    )
    if any(marker in title for marker in critical_markers):
        return 5

    high_markers = (
        "cross site scripting",
        "xss",
        "cross site request forgery",
        "csrf",
        "server-side template injection",
        "ssti",
        "mass assignment",
        "host header injection",
        "oauth weaknesses",
        "weak password policy",
        "jwt",
        "graphql",
    )
    if any(marker in title for marker in high_markers):
        return 4

    return _default_priority_for_phase(phase)


def _checklist_all_items_have_priority(payload: dict[str, Any]) -> bool:
    if not _is_structured_checklist_payload(payload):
        return False
    found_items = 0
    for block in payload.get("checklist", []):
        if not isinstance(block, dict):
            continue
        items = block.get("items", [])
        if not isinstance(items, list):
            continue
        for item in items:
            found_items += 1
            if not isinstance(item, dict):
                return False
            raw_priority = item.get("priority")
            has_priority = (
                isinstance(raw_priority, int)
                or (isinstance(raw_priority, str) and raw_priority.strip().isdigit())
            )
            if not has_priority:
                return False
    return found_items > 0


def _normalize_llm_priorities_only(payload: dict[str, Any]) -> dict[str, Any]:
    if not _is_structured_checklist_payload(payload):
        return payload

    normalized_blocks: list[dict[str, Any]] = []
    raw_blocks = payload.get("checklist", [])
    if not isinstance(raw_blocks, list):
        raw_blocks = []

    for raw_block in raw_blocks:
        if not isinstance(raw_block, dict):
            continue
        phase = str(raw_block.get("phase", "")).strip()
        title = str(raw_block.get("title", "")).strip()
        items = raw_block.get("items", [])
        if not phase or not title or not isinstance(items, list):
            continue

        normalized_items: list[dict[str, Any] | str] = []
        seen: set[str] = set()
        for item in items:
            if isinstance(item, dict):
                name = str(item.get("name", item.get("title", ""))).strip()
                if not name:
                    continue
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                if "priority" in item:
                    normalized_items.append(
                        {
                            "name": name,
                            "priority": _clamp_priority(item.get("priority", 3), default=3),
                        }
                    )
                else:
                    normalized_items.append(name)
            elif isinstance(item, str):
                name = item.strip()
                if not name:
                    continue
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                normalized_items.append(name)

        if normalized_items:
            normalized_blocks.append(
                {
                    "phase": phase,
                    "title": title,
                    "items": normalized_items,
                }
            )

    return {
        "target_type": str(payload.get("target_type", "")).strip(),
        "available_total": int(payload.get("available_total", 0) or 0),
        "checklist": normalized_blocks,
    }


def _strip_checklist_priorities(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the same checklist structure with priority fields removed from all items."""
    if not _is_structured_checklist_payload(payload):
        return payload

    stripped_blocks: list[dict[str, Any]] = []
    raw_blocks = payload.get("checklist", [])
    if not isinstance(raw_blocks, list):
        raw_blocks = []

    for raw_block in raw_blocks:
        if not isinstance(raw_block, dict):
            continue
        phase = str(raw_block.get("phase", "")).strip()
        title = str(raw_block.get("title", "")).strip()
        items = raw_block.get("items", [])
        if not phase or not title or not isinstance(items, list):
            continue

        normalized_items: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in items:
            if isinstance(item, dict):
                name = str(item.get("name", item.get("title", ""))).strip()
            else:
                name = str(item).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized_items.append({"name": name})

        if normalized_items:
            stripped_blocks.append(
                {
                    "phase": phase,
                    "title": title,
                    "items": normalized_items,
                }
            )

    return {
        "target_type": str(payload.get("target_type", "")).strip(),
        "available_total": int(payload.get("available_total", 0) or 0),
        "checklist": stripped_blocks,
    }


def _ensure_checklist_priorities(payload: dict[str, Any]) -> dict[str, Any]:
    if not _is_structured_checklist_payload(payload):
        return payload

    checklist_blocks: list[dict[str, Any]] = []
    raw_blocks = payload.get("checklist", [])
    if not isinstance(raw_blocks, list):
        raw_blocks = []

    for raw_block in raw_blocks:
        if not isinstance(raw_block, dict):
            continue
        phase = str(raw_block.get("phase", "")).strip()
        title = str(raw_block.get("title", "")).strip()
        default_priority = _default_priority_for_phase(phase)
        items = raw_block.get("items", [])
        ranked_by_name: dict[str, int] = {}
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    name = str(item.get("name", item.get("title", ""))).strip()
                    if not name:
                        continue
                    computed_default = _priority_for_item_name(name, phase)
                    priority = _clamp_priority(item.get("priority", computed_default), default=computed_default)
                    ranked_by_name[name] = max(ranked_by_name.get(name, 0), priority)
                elif isinstance(item, str):
                    name = item.strip()
                    if not name:
                        continue
                    ranked_by_name[name] = max(
                        ranked_by_name.get(name, 0),
                        _priority_for_item_name(name, phase),
                    )
        if not phase or not title or not ranked_by_name:
            continue
        checklist_blocks.append(
            {
                "phase": phase,
                "title": title,
                "items": [
                    {"name": item_name, "priority": item_priority}
                    for item_name, item_priority in sorted(
                        ranked_by_name.items(),
                        key=lambda kv: (-kv[1], kv[0].lower()),
                    )
                ],
            }
        )

    return {
        "target_type": str(payload.get("target_type", "")).strip(),
        "available_total": int(payload.get("available_total", 0) or 0),
        "checklist": checklist_blocks,
    }


def _flatten_checklist_item_names(payload: dict[str, Any]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for block in payload.get("checklist", []):
        if not isinstance(block, dict):
            continue
        items = block.get("items", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
            else:
                name = str(item).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(name)
    return names


def _structured_checklist_item_count(payload: dict[str, Any]) -> int:
    if not _is_structured_checklist_payload(payload):
        return 0
    return len(_flatten_checklist_item_names(payload))


def _merge_structured_checklist_payloads(*payloads: dict[str, Any]) -> dict[str, Any]:
    merged_target_type = ""
    merged_blocks: dict[str, dict[str, Any]] = {}

    for payload in payloads:
        if not _is_structured_checklist_payload(payload):
            continue
        if not merged_target_type:
            merged_target_type = str(payload.get("target_type", "")).strip()

        for raw_block in payload.get("checklist", []):
            if not isinstance(raw_block, dict):
                continue
            phase = str(raw_block.get("phase", "")).strip()
            title = str(raw_block.get("title", "")).strip() or _phase_block_title(phase)
            items = raw_block.get("items", [])
            if not phase or not isinstance(items, list):
                continue

            bucket = merged_blocks.setdefault(
                phase,
                {
                    "phase": phase,
                    "title": title,
                    "items": {},
                },
            )
            if not bucket.get("title"):
                bucket["title"] = title

            ranked_items = bucket["items"]
            if not isinstance(ranked_items, dict):
                ranked_items = {}
                bucket["items"] = ranked_items

            for item in items:
                if isinstance(item, dict):
                    name = str(item.get("name", item.get("title", ""))).strip()
                    raw_priority = item.get("priority", _priority_for_item_name(name, phase))
                else:
                    name = str(item).strip()
                    raw_priority = _priority_for_item_name(name, phase)
                if not name:
                    continue
                priority = _clamp_priority(raw_priority, default=_priority_for_item_name(name, phase))
                ranked_items[name] = max(int(ranked_items.get(name, 0) or 0), priority)

    checklist_blocks: list[dict[str, Any]] = []
    total_items = 0
    for phase in sorted(merged_blocks.keys(), key=_phase_sort_key):
        bucket = merged_blocks[phase]
        ranked_items = bucket.get("items", {})
        if not isinstance(ranked_items, dict) or not ranked_items:
            continue
        sorted_items = sorted(
            ranked_items.items(),
            key=lambda kv: (-int(kv[1]), kv[0].lower()),
        )
        total_items += len(sorted_items)
        checklist_blocks.append(
            {
                "phase": phase,
                "title": str(bucket.get("title", "")).strip() or _phase_block_title(phase),
                "items": [
                    {"name": item_name, "priority": int(item_priority)}
                    for item_name, item_priority in sorted_items
                ],
            }
        )

    return {
        "target_type": merged_target_type,
        "available_total": total_items,
        "checklist": checklist_blocks,
    }


def _limit_structured_checklist_items(payload: dict[str, Any], max_items: int | None) -> dict[str, Any]:
    if not _is_structured_checklist_payload(payload):
        return payload
    if max_items is None or int(max_items) <= 0:
        return payload

    remaining = int(max_items)
    limited_blocks: list[dict[str, Any]] = []
    total_items = 0

    for raw_block in payload.get("checklist", []):
        if remaining <= 0:
            break
        if not isinstance(raw_block, dict):
            continue
        phase = str(raw_block.get("phase", "")).strip()
        title = str(raw_block.get("title", "")).strip()
        items = raw_block.get("items", [])
        if not phase or not title or not isinstance(items, list) or not items:
            continue

        normalized_items: list[dict[str, Any]] = []
        for item in items:
            if remaining <= 0:
                break
            if isinstance(item, dict):
                name = str(item.get("name", item.get("title", ""))).strip()
                priority = _clamp_priority(
                    item.get("priority", _priority_for_item_name(name, phase)),
                    default=_priority_for_item_name(name, phase),
                )
            else:
                name = str(item).strip()
                priority = _priority_for_item_name(name, phase)
            if not name:
                continue
            normalized_items.append({"name": name, "priority": priority})
            remaining -= 1

        if normalized_items:
            total_items += len(normalized_items)
            limited_blocks.append(
                {
                    "phase": phase,
                    "title": title,
                    "items": normalized_items,
                }
            )

    return {
        "target_type": str(payload.get("target_type", "")).strip(),
        "available_total": total_items,
        "checklist": limited_blocks,
    }


def _ensure_structured_checklist_min_items(
    payload: dict[str, Any],
    *,
    min_items: int,
    fallback_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not _is_structured_checklist_payload(payload):
        return payload

    target_min = max(0, int(min_items or 0))
    if target_min <= 0:
        return payload

    current_count = _structured_checklist_item_count(payload)
    if current_count >= target_min:
        return payload

    if _is_structured_checklist_payload(fallback_payload):
        merged = _merge_structured_checklist_payloads(payload, fallback_payload)
        if _structured_checklist_item_count(merged) > current_count:
            return merged

    return payload


def _build_nist_baseline_checklist_payload(
    target_type: str,
    info: str,
) -> dict[str, Any]:
    lowered = str(info or "").lower()
    normalized_target = _normalize_target_type(target_type)

    phase_items: dict[str, list[str]] = {
        "1": [
            "Asset inventory and exposed service validation for the in-scope target",
        ],
        "3": [
            "Security configuration, error handling, and debug artifact exposure review",
            "Sensitive data protection review for transport, storage, and logging paths",
        ],
        "4": [
            "Least-privilege and authorization enforcement review on exposed interfaces",
            "Server-side input validation review on dynamic endpoints and workflows",
        ],
        "5": [
            "Session, token, and abuse-control review for authenticated flows",
        ],
    }

    if normalized_target in {"web_app", "api"}:
        phase_items["1"].append("Client-side route, dependency, and API surface exposure review")
        phase_items["3"].append("Security headers, CORS, and trust-boundary configuration review")
        phase_items["4"].append("Access-control review for exposed API objects, admin routes, and business actions")

    if "graphql" in lowered:
        phase_items["4"].append("GraphQL schema exposure, resolver authorization, and introspection review")
    if any(marker in lowered for marker in ("websocket", "socket.io", "ws://", "wss://")):
        phase_items["4"].append("WebSocket authentication, authorization, and message trust review")
    if any(marker in lowered for marker in ("upload", "file-processing", "file processing", "multipart", "attachment")):
        phase_items["4"].append("File upload, content validation, and storage isolation review")
    if any(marker in lowered for marker in ("api-docs", "swagger", "/api", "rest api", "endpoint")):
        phase_items["4"].append("Exposed API documentation, object enumeration, and rate-control review")
    if any(marker in lowered for marker in ("login", "auth", "session", "cookie", "jwt", "token")):
        phase_items["5"].append("Authentication flow, credential handling, and token lifecycle review")
    if any(marker in lowered for marker in ("admin", "debug", "internal")):
        phase_items["3"].append("Administrative and debug interface exposure review")
    if any(marker in lowered for marker in ("cors", "cross-origin")):
        phase_items["3"].append("Cross-origin trust boundary and browser-enforced policy review")

    checklist_blocks: list[dict[str, Any]] = []
    total_items = 0
    for phase in sorted(phase_items.keys(), key=_phase_sort_key):
        seen: set[str] = set()
        normalized_items: list[dict[str, Any]] = []
        for name in phase_items[phase]:
            clean = str(name or "").strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized_items.append(
                {
                    "name": clean,
                    "priority": _priority_for_item_name(clean, phase),
                }
            )
        if not normalized_items:
            continue
        total_items += len(normalized_items)
        checklist_blocks.append(
            {
                "phase": phase,
                "title": _phase_block_title(phase),
                "items": normalized_items,
            }
        )

    return {
        "target_type": normalized_target,
        "available_total": total_items,
        "checklist": checklist_blocks,
    }


def _compact_search_results_for_formatter(parsed: dict[str, Any]) -> str:
    hits = parsed.get("hits", [])
    compact_hits: list[dict[str, Any]] = []
    if isinstance(hits, list):
        for hit in hits[:6]:
            if not isinstance(hit, dict):
                continue
            metadata = hit.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
            compact_hits.append(
                {
                    "score": round(float(hit.get("score", 0) or 0), 4),
                    "source": metadata.get("source_name", ""),
                    "heading": metadata.get("heading", ""),
                    "tags": metadata.get("tags", []),
                }
            )
    return json.dumps(
        {
            "query": parsed.get("query", ""),
            "domain": parsed.get("domain", ""),
            "content_type": parsed.get("content_type", ""),
            "total": parsed.get("total", len(compact_hits)),
            "hits": compact_hits,
        },
        ensure_ascii=True,
    )


_SUMMARY_HEADING_MAP: dict[str, str] = {
    "methods": "methods",
    "strategies": "methods",
    "techniques": "techniques",
    "known vulnerabilities": "known_vulnerabilities",
    "vulnerabilities": "vulnerabilities",
    "checklist": "checklist",
    "gaps": "gaps",
}


def _parse_summary_sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current: str | None = None
    buffer: list[str] = []

    for line in str(text or "").splitlines():
        stripped = line.strip()
        mapped = ""
        if stripped.endswith(":"):
            heading = stripped[:-1].strip().lower()
            mapped = _SUMMARY_HEADING_MAP.get(heading, "")
        if mapped:
            if current is not None:
                sections[current] = "\n".join(buffer).strip()
            current = mapped
            buffer = []
            continue
        if current is not None:
            buffer.append(line)

    if current is not None:
        sections[current] = "\n".join(buffer).strip()
    return sections


def _extract_block_items(block: str) -> list[str]:
    items: list[str] = []
    for raw in str(block or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("- ", "* ", "• ")):
            items.append(line[2:].strip())
        elif re.match(r"^\d+[\.\)]\s+", line):
            items.append(re.sub(r"^\d+[\.\)]\s+", "", line).strip())
    return _dedupe_keep_order(items)


def _sanitize_summary_text(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""

    sections = _parse_summary_sections(raw)
    if not sections:
        return raw

    summary_sections: list[str] = []

    vulnerability_candidates = _extract_block_items(sections.get("known_vulnerabilities", ""))
    vulnerability_candidates.extend(_extract_block_items(sections.get("vulnerabilities", "")))
    known_vulnerabilities = _filter_known_vulnerabilities(vulnerability_candidates)
    if known_vulnerabilities:
        summary_sections.append(_format_list_section("KNOWN VULNERABILITIES", known_vulnerabilities))

    checklist_block = sections.get("checklist", "").strip()
    if checklist_block:
        summary_sections.append("CHECKLIST:\n" + checklist_block)

    gap_items = _extract_block_items(sections.get("gaps", ""))
    if sections.get("gaps", "").strip() and not gap_items:
        gap_items = [sections["gaps"].strip()]
    summary_sections.append(_format_list_section("GAPS", gap_items))
    return "\n\n".join(summary_sections)


def _build_summary_from_sections(data: dict[str, Any]) -> str:
    sections: list[str] = []
    vulnerability_values: list[str] = []
    for key in ("vulnerabilities", "vulnerability_types", "vulns", "exploits", "weakness_classes", "known_vulnerabilities"):
        val = data.get(key)
        if isinstance(val, list):
            vulnerability_values.extend(str(item) for item in val if str(item or "").strip())
        elif isinstance(val, str) and val.strip():
            vulnerability_values.extend(_extract_block_items(val) or [val.strip()])
    known_vulnerabilities = _filter_known_vulnerabilities(vulnerability_values)
    if known_vulnerabilities:
        sections.append(_format_list_section("KNOWN VULNERABILITIES", known_vulnerabilities))

    for key in ("checklist", "checklist_items", "target_checklist", "tests"):
        val = data.get(key)
        if isinstance(val, list) and val:
            sections.append(_format_list_section("CHECKLIST", val))
            break
        if isinstance(val, str) and val.strip():
            sections.append(f"CHECKLIST:\n{val.strip()}")
            break

    for key in ("gaps", "coverage_gaps", "missing", "not_covered"):
        val = data.get(key)
        if isinstance(val, list) and val:
            sections.append(_format_list_section("GAPS", val))
            break
        if isinstance(val, str) and val.strip():
            sections.append(_format_list_section("GAPS", _extract_block_items(val) or [val.strip()]))
            break
    return "\n\n".join(sections)


_PLACEHOLDER_TOKEN_RE = re.compile(
    r"\b(?:method|technique|gap|checklist item|item)\s*\d+\b",
    re.IGNORECASE,
)
_REFERENCE_TOKEN_RE = re.compile(
    r"\b(?:WSTG-[A-Z]+-\d+|API\d{1,2}\s*:\s*20\d{2}|T\d{4}(?:\.\d{3})?|CVE-\d{4}-\d{4,7})\b",
    re.IGNORECASE,
)


def _is_low_quality_summary(text: str) -> bool:
    """Reject synthetic placeholder-style summaries from the formatter."""
    raw = str(text or "").strip()
    if not raw:
        return True

    lowered = raw.lower()
    placeholder_hits = len(_PLACEHOLDER_TOKEN_RE.findall(raw))
    if placeholder_hits >= 2:
        return True

    if "[ ] checklist item" in lowered:
        return True

    if "checklist:" in lowered:
        has_checklist_shape = "phase" in lowered and "reference" in lowered and "objective" in lowered
        if not has_checklist_shape:
            return True

    if "methods:" in lowered and "techniques:" in lowered and "vulnerabilities:" in lowered:
        if not _REFERENCE_TOKEN_RE.search(raw):
            return True

    return False


def _count_checklist_items(text: str) -> int:
    return len(re.findall(r"^\s*-\s*\[\s*\]\s+", str(text or ""), flags=re.MULTILINE))


def _dedupe_keep_order(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = str(v or "").strip()
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _phase_sort_key(phase: str) -> int:
    try:
        return int(str(phase).strip())
    except Exception:
        return 99


def _objective_from_test_name(name: str) -> str:
    clean = re.sub(r"^\s*Testing\s+for\s+", "", str(name or ""), flags=re.IGNORECASE).strip()
    clean = re.sub(r"^\s*Test\s+", "", clean, flags=re.IGNORECASE).strip()
    if not clean:
        clean = str(name or "").strip()
    return f"Validate whether {clean.lower()} is exploitable."


def _steps_for_test_name(name: str) -> str:
    low = str(name or "").lower()
    if "sql injection" in low:
        return (
            "1. Send safe SQLi probes across parameters and bodies.\n"
            "               2. Confirm behavior differences/errors and data exposure.\n"
            "               3. Capture reproducible request/response evidence."
        )
    if "cross site scripting" in low or "xss" in low:
        return (
            "1. Inject reflected/stored/DOM payloads in reachable sinks.\n"
            "               2. Confirm script execution context and impact.\n"
            "               3. Record PoC payload, trigger path, and screenshot evidence."
        )
    if "authorization" in low or "idor" in low:
        return (
            "1. Test horizontal/vertical access with altered identifiers.\n"
            "               2. Verify unauthorized data/action access.\n"
            "               3. Save before/after responses proving broken access control."
        )
    if "ssrf" in low:
        return (
            "1. Probe SSRF sinks with controlled callback endpoints.\n"
            "               2. Validate internal/network metadata reachability.\n"
            "               3. Preserve callback logs and affected request traces."
        )
    return (
        "1. Reproduce the test case with controlled malicious input.\n"
        "               2. Confirm security impact and exploitability.\n"
        "               3. Capture precise PoC evidence and affected parameters."
    )


def _extract_rag_headings(report: dict[str, Any], content_type: str, limit: int = 12) -> list[str]:
    rag = report.get("rag_snapshot", {})
    if not isinstance(rag, dict):
        return []
    results = rag.get("results", {})
    if not isinstance(results, dict):
        return []
    hits = results.get(content_type, [])
    if not isinstance(hits, list):
        return []

    out: list[str] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        metadata = hit.get("metadata", {})
        heading = ""
        if isinstance(metadata, dict):
            heading = str(metadata.get("heading", "")).strip()
        if not heading:
            heading = str(hit.get("content", "")).strip().split("\n")[0][:120]
        if heading:
            out.append(heading)
        if len(out) >= limit:
            break
    return _dedupe_keep_order(out)


def _build_grounded_summary_from_checklists(
    *,
    target_type: str,
    checklist_data: dict[str, Any],
    pipeline_report: dict[str, Any],
    max_items: int = 18,
) -> str:
    cats = checklist_data.get("cats", {})
    if not isinstance(cats, dict) or not cats:
        return ""

    checklist_rows: list[tuple[int, str, str, str]] = []
    derived_techniques: list[str] = []
    checklist_names: list[str] = []
    for cat_id, cat_data in cats.items():
        if not isinstance(cat_data, dict):
            continue
        phase = str(cat_data.get("p", "4")).strip() or "4"
        items = cat_data.get("items", [])
        if not isinstance(items, list):
            continue
        for row in items:
            if not isinstance(row, list) or len(row) < 2:
                continue
            ref = str(row[0]).strip()
            name = str(row[1]).strip()
            if not ref or not name:
                continue
            checklist_names.append(name)
            clean_tech = re.sub(r"^\s*Testing\s+for\s+", "", name, flags=re.IGNORECASE).strip()
            clean_tech = re.sub(r"^\s*Test\s+", "", clean_tech, flags=re.IGNORECASE).strip()
            if clean_tech:
                derived_techniques.append(clean_tech)
            checklist_rows.append((_phase_sort_key(phase), phase, ref, name))

    checklist_rows.sort(key=lambda x: (x[0], x[2], x[3]))
    checklist_rows = checklist_rows[:max_items]

    rag_vulns = _extract_rag_headings(pipeline_report, "exploits", limit=14)
    vulnerabilities = _filter_known_vulnerabilities(rag_vulns + derived_techniques + checklist_names)[:14]

    checklist_lines: list[str] = []
    for _, phase, ref, name in checklist_rows:
        checklist_lines.append(
            f"- [ ] {name}\n"
            f"    Phase     : {phase}\n"
            f"    Reference : {ref}\n"
            f"    Objective : {_objective_from_test_name(name)}\n"
            f"    Steps     : {_steps_for_test_name(name)}"
        )

    gaps: list[str] = []
    rag_techniques = _extract_rag_headings(pipeline_report, "attack_types", limit=14)
    if not rag_techniques:
        gaps.append("RAG attack_types coverage is thin; rely mostly on OWASP checklist mapping.")
    if not checklist_rows:
        gaps.append(f"No checklist rows could be built for target_type={target_type}.")
    if not vulnerabilities:
        gaps.append(f"No specific known vulnerabilities were recovered for {target_type}; prioritize the checklist coverage.")
    if not gaps:
        gaps.append("No major checklist generation gaps detected.")

    def _section(title: str, rows: list[str]) -> str:
        if not rows:
            return f"{title}:\n- (none found)"
        return "\n".join([f"{title}:", *[f"- {r}" for r in rows]])

    return "\n\n".join(
        ([ _section("KNOWN VULNERABILITIES", vulnerabilities) ] if vulnerabilities else [])
        + [
            "CHECKLIST:\n" + ("\n".join(checklist_lines) if checklist_lines else "- (none found)"),
            _section("GAPS", gaps),
        ]
    )


def _extract_stats_from_alt_keys(data: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("stats", "pipeline_stats", "statistics", "pipeline_statistics"):
        val = data.get(key)
        if isinstance(val, dict):
            return val
    return None


def _parse_json_intel(data: dict[str, Any]) -> IntelResult:
    data_lower = {k.lower(): v for k, v in data.items()}
    checklist_json = data.get("checklist")
    if not isinstance(checklist_json, dict):
        checklist_json = data.get("checklist_json")
    if not isinstance(checklist_json, dict):
        checklist_json = {}
    if not _is_structured_checklist_payload(checklist_json):
        checklist_json = {}

    return IntelResult(
        status=data_lower.get("status", "complete"),
        summary="",
        stats=_normalize_stats(_extract_stats_from_alt_keys(data_lower)),
        vulnerabilities=[],
        checklist=checklist_json,
    )


def _extract_markdown_sections(text: str) -> str:
    vulns, checklist, gaps = [], [], []
    vuln_re = re.compile(r"(?:vulnerabilit|weakness|exploit|cve-|misconfigur|broken\s+access|insecure)", re.IGNORECASE)
    checklist_re = re.compile(r"(?:checklist|test\s*cases?|test\s*plan|validation\s*list)", re.IGNORECASE)
    gap_re = re.compile(r"(?:gap|missing|not covered|coverage)", re.IGNORECASE)
    current = "checklist"
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith("**"):
            heading = stripped.lstrip("#* ").rstrip("*: ")
            if vuln_re.search(heading): current = "vulns"
            elif checklist_re.search(heading): current = "checklist"
            elif gap_re.search(heading): current = "gaps"
            continue
        if stripped.startswith("- ") or stripped.startswith("* "):
            item = stripped[2:].strip()
            if item and len(item) >= 3:
                {"vulns": vulns, "checklist": checklist, "gaps": gaps}[current].append(item)
    sections = []
    known_vulnerabilities = _filter_known_vulnerabilities(vulns)
    if known_vulnerabilities: sections.append(_format_list_section("KNOWN VULNERABILITIES", known_vulnerabilities))
    if checklist: sections.append(_format_list_section("CHECKLIST", checklist))
    if gaps: sections.append(_format_list_section("GAPS", gaps))
    return "\n\n".join(sections) if len(known_vulnerabilities) + len(checklist) + len(gaps) >= 2 else ""


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
            return _parse_json_intel(data)
    except json.JSONDecodeError:
        pass
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
        project_id: str | None = None,
    ) -> None:
        self._mode = mode or llm_mode.mode
        self._cb = callback or _NoOpCallback()
        self._context = context or IntelContext()
        set_context(self._context)

        self._state_store = IntelStateStore()
        self._projects_store = ProjectsStore()
        try:
            self._projects_store.init_schema()
        except Exception as exc:
            logger.warning("intel_projects_store_init_failed", error=str(exc))
        self._background_tasks: set[asyncio.Task] = set()

        tool_list = tools or ALL_INTEL_TOOLS
        self._tools = {t.name: t for t in tool_list}
        self._formatter_tool_schemas = [t.schema() for t in tool_list if t.name in FORMATTER_ALLOWED_TOOLS]
        self._tool_valid_params: dict[str, set[str] | None] = {t.name: _get_valid_params(t) for t in tool_list}

        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LLMClient(self._local_config, mode="local")
            self._model_name = self._local_config.model
        else:
            self._config = config or get_public_agent_config("intel")
            self._llm = LLMClient(self._config, mode="public")
            self._model_name = self._config.model

        self._context_window = build_intel_context_window(
            project_id=project_id,
            llm=self._llm,
        )

        logger.info("intel_initialized", mode=self._mode, model=self._model_name)

    # ── Public API ─────────────────────────────────────────────────────

    async def run(
        self,
        target_type: str = "all",
        info: str = "",
        *,
        custom_checklist_text: str = "",
        merge_custom_checklist: bool = False,
        max_checklist_items: int | None = None,
        force_update: bool = False,
        refresh_days_override: int | None = None,
        update_only: bool = False,
        skip_rag_check: bool = False,
    ) -> IntelResult:
        target_type = _normalize_target_type(target_type)
        self._cb.on_step(f"Intel Agent starting for target_type='{target_type}'")
        if self._context_window is not None:
            await self._context_window.record(
                kind="run_input",
                role="user",
                content=(
                    f"target_type={target_type}\ninfo={info}\n"
                    f"custom_checklist={'yes' if custom_checklist_text.strip() else 'no'}"
                ),
                metadata={"agent": "intel", "target_type": target_type},
            )
        await self._context.ensure_ready()

        if skip_rag_check:
            # RAG was already checked/updated at warmup start — skip redundant check
            self._cb.on_step("RAG check skipped — already verified before warmup recon")
            logger.info("intel_rag_check_skipped", target_type=target_type, reason="skip_rag_check_flag")
        else:
            # Check cooldown
            now = datetime.now(timezone.utc)
            last_update = self._state_store.get_last_update(target_type)
            refresh_days = RAG_REFRESH_DAYS
            if refresh_days_override is not None and int(refresh_days_override) > 0:
                refresh_days = int(refresh_days_override)
            elif self._projects_store is not None:
                try:
                    custom_days = self._projects_store.get_intel_refresh_days(target_type)
                    if custom_days and custom_days > 0:
                        refresh_days = custom_days
                except Exception as exc:
                    logger.warning("intel_refresh_days_read_failed", target_type=target_type, error=str(exc))

            refresh_seconds = refresh_days * 86400
            needs_update = (
                force_update
                or last_update is None
                or (now - last_update).total_seconds() >= refresh_seconds
            )
            last_update_text = last_update.isoformat() if last_update else "none"
            age_days = (now - last_update).total_seconds() / 86400 if last_update else None
            age_text = f"{age_days:.2f} days" if age_days is not None else "n/a"
            self._cb.on_step(
                f"RAG update check: last_update={last_update_text}, age={age_text}, needs_update={'yes' if needs_update else 'no'}"
            )
            logger.info(
                "intel_rag_update_check",
                target_type=target_type,
                last_update=last_update_text,
                age_days=age_days,
                needs_update=needs_update,
                refresh_days=refresh_days,
            )
            if update_only:
                if not needs_update and last_update is not None:
                    days_ago = (now - last_update).total_seconds() / 86400
                    self._cb.on_done(
                        f"RAG is fresh (updated {days_ago:.1f} days ago, interval={refresh_days}d) — skipping update"
                    )
                    logger.info(
                        "intel_rag_update_skipped",
                        target_type=target_type,
                        reason="fresh_data",
                        age_days=days_ago,
                        refresh_days=refresh_days,
                    )
                    return IntelResult(
                        status="complete",
                        stats=_default_stats(),
                    )
                if force_update:
                    self._cb.on_step(f"Force update requested — bypassing cooldown ({refresh_days} day window)")
                self._cb.on_step("Update-only mode: running Intel update pipeline")
                logger.info("intel_rag_update_start", target_type=target_type, mode="update_only")
                pipeline_report = await self._run_update_pipeline(target_type=target_type, info=info)
                stats = _normalize_stats(pipeline_report.get("stats"))
                self._cb.on_done("Update-only run complete")
                logger.info("intel_rag_update_done", target_type=target_type, mode="update_only")
                return IntelResult(status="complete", stats=stats)

            if needs_update:
                if force_update:
                    self._cb.on_step(f"Force update requested — bypassing cooldown ({refresh_days} day window)")
                # CRITICAL FIX: RAG update MUST be await (blocking) before checklist approval
                # Previously was background task, causing Planner to start before RAG ready
                # Now: Intel waits for RAG → checklist ready → Planner starts with full context
                self._cb.on_step("RAG update needed — updating knowledge base (blocking until complete)")
                logger.info("intel_rag_update_start", target_type=target_type, mode="blocking")
                try:
                    await self._run_update_pipeline(target_type=target_type, info=info)
                    self._cb.on_step("RAG update complete — knowledge base ready for Planner")
                    logger.info("intel_rag_update_done", target_type=target_type, mode="blocking")
                except Exception as rag_exc:
                    logger.warning(
                        "intel_rag_update_error",
                        error=str(rag_exc)[:200],
                        message="RAG update error, continuing with existing knowledge base",
                    )
                    self._cb.on_warn(f"RAG update error (continuing): {str(rag_exc)[:100]}")
            else:
                days_ago = (now - last_update).total_seconds() / 86400
                self._cb.on_done(
                    f"RAG is fresh (updated {days_ago:.1f} days ago, interval={refresh_days}d) — skipping update"
                )
                logger.info(
                    "intel_rag_update_skipped",
                    target_type=target_type,
                    reason="fresh_data",
                    age_days=days_ago,
                    refresh_days=refresh_days,
                )

        cleaned_payload: dict[str, Any] = {}
        base_checklist: dict[str, Any] = {}
        structured_checklist: dict[str, Any] = {}
        final_status = "complete"
        custom_checklist_clean = str(custom_checklist_text or "").strip()
        parsed_custom_payload: dict[str, Any] = {}
        if custom_checklist_clean:
            parsed_custom_payload = _parse_custom_checklist_text(
                custom_checklist_clean,
                target_type=target_type,
            )
            if not _is_structured_checklist_payload(parsed_custom_payload):
                raise RuntimeError(
                    "Uploaded custom checklist could not be parsed into a valid checklist structure."
                )

        if custom_checklist_clean and not merge_custom_checklist:
            self._cb.on_step(
                "Skipping static RAG snapshot; custom checklist path will reuse uploaded checklist directly"
            )
            self._cb.on_step(
                "Custom checklist detected — skipping Intel checklist generation and formatter enrichment; using uploaded .txt checklist directly"
            )
            cleaned_payload = parsed_custom_payload
            base_checklist = {
                "target_type": target_type,
                "source": "project_custom_checklist",
                "raw_text_length": len(custom_checklist_clean),
            }
            structured_checklist = cleaned_payload
        else:
            # Foreground: checklist → clean → format (OWASP checklist synthesis only)
            if custom_checklist_clean and merge_custom_checklist:
                self._cb.on_step(
                    "Custom checklist detected — merging uploaded checklist with OWASP resources before synthesis"
                )
            self._cb.on_step("Formatter will use recon evidence plus merged OWASP and NIST-style checklist baseline")
            self._cb.on_step("Fetching base checklist")
            base_checklist = await self._call_tool_json("get_checklists", target_type=target_type, info=info[:250])
            if isinstance(base_checklist, dict):
                try:
                    cleaned_json = await asyncio.wait_for(
                        clean_checklists_with_llm(
                            checklist_data=base_checklist,
                            target_type=target_type,
                            info=info,
                            llm=self._llm,
                        ),
                        timeout=FORMATTER_CALL_TIMEOUT_SECONDS,
                    )
                    cleaned_payload = json.loads(cleaned_json)
                except Exception as exc:
                    logger.warning("intel_clean_checklist_failed", error=str(exc), target_type=target_type)
                    cleaned_payload = build_deterministic_checklist_payload(base_checklist, info)

            nist_baseline_payload = _build_nist_baseline_checklist_payload(
                target_type,
                info,
            )
            if _is_structured_checklist_payload(nist_baseline_payload):
                cleaned_payload = _merge_structured_checklist_payloads(
                    cleaned_payload,
                    nist_baseline_payload,
                )
                self._cb.on_step(
                    "Merged NIST-style baseline controls into the Intel checklist seed"
                )

            if custom_checklist_clean and merge_custom_checklist:
                cleaned_payload = _merge_structured_checklist_payloads(
                    cleaned_payload,
                    parsed_custom_payload,
                )
                self._cb.on_step(
                    "Merged custom checklist with base checklist before formatter synthesis"
                )

            base_checklist_text = (
                _format_structured_checklist_for_formatter(cleaned_payload)
                if cleaned_payload
                else _build_checklist_llm_input(base_checklist, info)
            )

        pipeline_report: dict[str, Any] = {
            "target_type": target_type,
            "info": info,
            "rag_snapshot": {"query": "", "domain": _resolve_rag_domain(target_type), "results": {}},
            "base_checklist": base_checklist,
            "formatter_prefetch": {
                "coverage_counts": {"methods": 0, "techniques": 0, "vulnerabilities": 0},
                "web_fallback": {"used": False, "query": "", "results": []},
            },
        }

        if not custom_checklist_clean:
            llm_result = await self._run_formatter(
                target_type=target_type,
                info=info,
                pipeline_report=pipeline_report,
                base_checklist_text=base_checklist_text,
                base_checklist_payload=cleaned_payload or None,
            )
            structured_checklist = llm_result.checklist or cleaned_payload
            final_status = _normalize_intel_status(llm_result.status)

        # ── Priority resolution ─────────────────────────────────────────
        # Prefer LLM-priority ownership, but fail open if the refinement
        # call times out/fails so Intel can continue and unblock the flow.
        if not _is_structured_checklist_payload(structured_checklist):
            message = "Intel checklist payload is invalid; stopping scan in strict LLM-priority mode."
            self._cb.on_warn(message)
            logger.error("intel_checklist_invalid_strict_failure", target_type=target_type)
            raise RuntimeError(message)

        if _is_structured_checklist_payload(structured_checklist):
            # Enforce re-prompt-only priority ownership: strip any existing priorities first.
            structured_checklist = _strip_checklist_priorities(structured_checklist)

            self._cb.on_step(
                "Sending Intel checklist result to LLM to add priorities and re-phase"
            )
            refined = await self._fix_missing_priorities(
                structured_checklist, target_type, info
            )
            if refined:
                structured_checklist = refined
                self._cb.on_done("Checklist priorities/phases refined by LLM")
                logger.info("intel_priority_refined_by_llm", target_type=target_type)
            else:
                structured_checklist = _ensure_checklist_priorities(
                    structured_checklist
                )
                message = (
                    "LLM priority refinement failed or timed out; "
                    "used deterministic priority fallback and continuing."
                )
                self._cb.on_warn(message)
                logger.warning(
                    "intel_priority_refinement_fallback_applied",
                    target_type=target_type,
                )

            self._cb.on_step("Auto-normalizing checklist with set_checklist")
            checklist_names = _flatten_checklist_item_names(structured_checklist)
            auto_set = await self._call_tool_json(
                "set_checklist",
                target_type=target_type,
                checklist="\n".join(checklist_names),
                checklist_json=structured_checklist,
            )
            set_checklist_json = auto_set.get("checklist_json", {}) if isinstance(auto_set, dict) else {}
            if isinstance(set_checklist_json, dict) and _is_structured_checklist_payload(set_checklist_json):
                structured_checklist = set_checklist_json
                self._cb.on_done("Checklist normalized by set_checklist")

        if _is_structured_checklist_payload(structured_checklist):
            before_backfill = _structured_checklist_item_count(structured_checklist)
            structured_checklist = _ensure_structured_checklist_min_items(
                structured_checklist,
                min_items=MIN_SYNTH_CHECKLIST_ITEMS,
                fallback_payload=cleaned_payload if _is_structured_checklist_payload(cleaned_payload) else None,
            )
            after_backfill = _structured_checklist_item_count(structured_checklist)
            if after_backfill > before_backfill:
                self._cb.on_step(
                    "Checklist backfilled from OWASP baseline to "
                    f"{after_backfill} items (minimum target={MIN_SYNTH_CHECKLIST_ITEMS})"
                )

        if _is_structured_checklist_payload(structured_checklist):
            structured_checklist = _limit_structured_checklist_items(
                structured_checklist,
                max_checklist_items,
            )
            if max_checklist_items:
                self._cb.on_step(
                    "Checklist capped to "
                    f"{_structured_checklist_item_count(structured_checklist)} prioritized items"
                )

        self._cb.on_done(f"Intel Agent complete — status={final_status}")
        return IntelResult(
            status=final_status,
            stats=_normalize_stats(pipeline_report.get("stats")),
            vulnerabilities=[],
            checklist=structured_checklist,
        )

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

    async def _rebuild_summary_from_checklists(
        self,
        *,
        target_type: str,
        info: str,
        pipeline_report: dict[str, Any],
    ) -> str:
        checklist_data = await self._call_tool_json(
            "get_checklists",
            target_type=target_type,
            info=info[:250],
        )
        if not isinstance(checklist_data, dict):
            return ""
        rebuilt = _build_grounded_summary_from_checklists(
            target_type=target_type,
            checklist_data=checklist_data,
            pipeline_report=pipeline_report,
            max_items=18,
        )
        return rebuilt.strip()

    # ── Priority Fixer ─────────────────────────────────────────────────

    async def _fix_missing_priorities(
        self,
        checklist: dict[str, Any],
        target_type: str,
        info: str,
    ) -> dict[str, Any]:
        """
        Single focused LLM call to add missing priorities to checklist items.

        Sends the checklist as-is and asks only for priorities to be filled.
        Returns a fully-prioritized payload on success, or an empty dict on failure.
        """
        prompt = build_priority_reprompt_prompt(
            checklist=checklist,
            target_type=target_type,
            info=info,
        )

        def _extract_json_object_at(text: str, start_idx: int) -> str | None:
            if start_idx < 0 or start_idx >= len(text) or text[start_idx] != "{":
                return None
            depth = 0
            in_string = False
            escape = False
            for idx in range(start_idx, len(text)):
                ch = text[idx]
                if escape:
                    escape = False
                    continue
                if ch == "\\":
                    escape = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return text[start_idx : idx + 1]
            return None

        def _parse_json_best_effort(raw_text: str) -> Any | None:
            text = re.sub(r"<think>.*?</think>", "", str(raw_text or ""), flags=re.DOTALL).strip()
            if not text:
                return None

            candidates: list[str] = [text]
            for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE):
                candidate = block.strip()
                if candidate:
                    candidates.append(candidate)

            first_brace = text.find("{")
            if first_brace >= 0:
                obj_text = _extract_json_object_at(text, first_brace)
                if obj_text:
                    candidates.append(obj_text)

            for candidate in candidates:
                probe = candidate
                for _ in range(3):
                    try:
                        parsed = json.loads(probe)
                    except (json.JSONDecodeError, TypeError):
                        break

                    if isinstance(parsed, dict):
                        return parsed
                    if isinstance(parsed, list):
                        return parsed
                    if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
                        return parsed[0]
                    if isinstance(parsed, str):
                        next_probe = parsed.strip()
                        if not next_probe or next_probe == probe:
                            break
                        probe = next_probe
                        continue
                    break
            return None

        def _has_sequential_phases(payload: dict[str, Any]) -> bool:
            if not _is_structured_checklist_payload(payload):
                return False
            blocks = payload.get("checklist", [])
            if not isinstance(blocks, list) or not blocks:
                return False
            phases: list[str] = []
            for block in blocks:
                if not isinstance(block, dict):
                    return False
                phase = str(block.get("phase", "")).strip()
                if not phase.isdigit():
                    return False
                phases.append(phase)
            expected = [str(idx) for idx in range(1, len(phases) + 1)]
            return phases == expected

        priority_messages = [
            ChatMessage(
                role="system",
                content=PRIORITY_REPROMPT_SYSTEM_PROMPT,
            ),
            ChatMessage(role="user", content=prompt),
        ]

        def _parse_priority_response(content: str) -> dict[str, Any]:
            parsed = _parse_json_best_effort(content or "")
            if parsed is not None:
                if isinstance(parsed, dict) and _is_structured_checklist_payload(parsed):
                    normalized = _normalize_llm_priorities_only(parsed)
                    if _checklist_all_items_have_priority(normalized) and _has_sequential_phases(normalized):
                        return normalized
            return {}

        try:
            response = await asyncio.wait_for(
                self._llm.chat(
                    priority_messages,
                    temperature=0,
                    max_tokens=11000,
                ),
                timeout=60,
            )
            normalized = _parse_priority_response(response.content or "")
            if normalized:
                return normalized

            # If the model returns malformed/partial payload, fail softly so caller fallback applies.
            logger.info("intel_fix_priorities_unusable_payload", target_type=target_type)

        except Exception as exc:
            logger.warning(
                "intel_fix_priorities_failed",
                error=str(exc),
                error_type=type(exc).__name__,
                error_repr=repr(exc),
                target_type=target_type,
            )

            backup_llm = await get_backup_llm_fallback().get_backup_llm()
            if backup_llm is not None:
                self._cb.on_warn(
                    "Intel priority refinement failed; retrying once with backup LLM."
                )
                try:
                    backup_response = await asyncio.wait_for(
                        backup_llm.chat(
                            priority_messages,
                            temperature=0,
                            max_tokens=11000,
                        ),
                        timeout=60,
                    )
                    normalized = _parse_priority_response(backup_response.content or "")
                    if normalized:
                        logger.info(
                            "intel_fix_priorities_backup_success",
                            target_type=target_type,
                        )
                        return normalized
                    logger.info(
                        "intel_fix_priorities_backup_unusable_payload",
                        target_type=target_type,
                    )
                except Exception as backup_exc:
                    logger.warning(
                        "intel_fix_priorities_backup_failed",
                        error=str(backup_exc),
                        error_type=type(backup_exc).__name__,
                        target_type=target_type,
                    )

        # Signal failure — caller runs strict stop behavior.
        return {}

    # ── LLM Formatter ──────────────────────────────────────────────────

    async def _run_formatter(
        self,
        target_type: str,
        info: str,
        pipeline_report: dict[str, Any],
        base_checklist_text: str = "",
        base_checklist_payload: dict[str, Any] | None = None,
    ) -> IntelResult:
        self._cb.on_step(f"LLM formatter starting ({FORMATTER_ROUNDS} rounds max)")
        formatter_payload = _build_formatter_payload(pipeline_report)

        system_content = FORMATTER_SYSTEM_PROMPT
        if _needs_nothink(self._model_name):
            system_content = "/nothink\n" + system_content

        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=system_content),
            ChatMessage(role="user", content=build_user_message(target_type, info, formatter_payload, current_round=1, max_rounds=FORMATTER_ROUNDS, base_checklist_text=base_checklist_text)),
        ]

        total_tool_calls = 0
        last_set_checklist: dict[str, Any] | None = None

        for round_num in range(1, FORMATTER_ROUNDS + 1):
            self._cb.on_step(f"LLM Round {round_num}/{FORMATTER_ROUNDS}")

            try:
                response = await asyncio.wait_for(
                    self._llm.chat(messages, tools=self._formatter_tool_schemas or None, temperature=0.2, max_tokens=1800),
                    timeout=FORMATTER_CALL_TIMEOUT_SECONDS,
                )
            except Exception as exc:
                self._cb.on_warn(f"LLM error: {exc}")
                return IntelResult(status="complete", stats=_normalize_stats(pipeline_report.get("stats")))

            # Final response
            if not response.tool_calls:
                raw_content = response.content or ""
                if self._context_window is not None:
                    await self._context_window.record_llm_turn(
                        prompt_excerpt=build_user_message(
                            target_type,
                            info,
                            formatter_payload,
                            current_round=round_num,
                            max_rounds=FORMATTER_ROUNDS,
                            base_checklist_text=base_checklist_text,
                        )[:1200],
                        response_excerpt=raw_content or "formatter final answer",
                        usage=response.usage if isinstance(response.usage, dict) else {},
                        metadata={"agent": "intel", "round": round_num, "stage": "formatter"},
                    )
                self._cb.on_done(f"LLM Round {round_num}: Final answer ({len(raw_content)} chars)")
                logger.info("intel_complete", rounds=round_num, total_tool_calls=total_tool_calls, tools_used=total_tool_calls > 0, usage=response.usage)

                result = _parse_intel_output(raw_content)
                if (not result.checklist or not _is_structured_checklist_payload(result.checklist)) and last_set_checklist:
                    maybe_checklist = last_set_checklist.get("checklist_json", {}) or {}
                    if _is_structured_checklist_payload(maybe_checklist):
                        result.checklist = maybe_checklist
                if not result.checklist and base_checklist_payload:
                    result.checklist = base_checklist_payload
                result.vulnerabilities = []
                if self._context_window is not None:
                    await self._context_window.record(
                        kind="run_result",
                        role="assistant",
                        content=result.summary or raw_content or result.status,
                        metadata={
                            "agent": "intel",
                            "status": result.status,
                            "tool_calls": total_tool_calls,
                        },
                    )

                self._cb.on_done(f"Formatter done: {total_tool_calls} tool calls across {round_num} rounds")
                return result

            # Tool calls
            tool_calls_this_round = list(response.tool_calls or [])
            if len(tool_calls_this_round) > FORMATTER_MAX_TOOLS_PER_ROUND:
                skipped = len(tool_calls_this_round) - FORMATTER_MAX_TOOLS_PER_ROUND
                self._cb.on_warn(
                    f"LLM Round {round_num}: tool-call cap reached ({FORMATTER_MAX_TOOLS_PER_ROUND}); skipping {skipped} extra call(s)"
                )
                tool_calls_this_round = tool_calls_this_round[:FORMATTER_MAX_TOOLS_PER_ROUND]

            tool_names = [tc["function"]["name"] for tc in tool_calls_this_round]
            total_tool_calls += len(tool_calls_this_round)
            if self._context_window is not None:
                await self._context_window.record_llm_turn(
                    prompt_excerpt=f"formatter round {round_num}",
                    response_excerpt=response.content or f"tool_calls={tool_names}",
                    usage=response.usage if isinstance(response.usage, dict) else {},
                    metadata={
                        "agent": "intel",
                        "round": round_num,
                        "stage": "formatter",
                        "tool_calls": tool_names,
                    },
                )
            self._cb.on_step(f"LLM Round {round_num}: Calling tools → {tool_names}")

            messages.append(ChatMessage(role="assistant", content=response.content, tool_calls=tool_calls_this_round))

            for tc in tool_calls_this_round:
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
                if tool_name == "fetch_page":
                    target_preview = str(args.get("target_type", target_type))
                    url_preview = str(args.get("url", ""))[:80]
                    self._cb.on_step(
                        f"  {tool_name}(target='{target_preview}', url='{url_preview}...')"
                    )
                elif tool_name == "set_checklist":
                    target_preview = str(args.get("target_type", target_type))
                    checklist_preview = str(args.get("checklist", ""))[:50]
                    self._cb.on_step(
                        f"  {tool_name}(target='{target_preview}', checklist='{checklist_preview}...')"
                    )
                else:
                    self._cb.on_step(f"  {tool_name}(query='{query_preview}...', type='{content_type}')")

                tool = self._tools.get(tool_name)
                if tool is None:
                    result_str = f"Error: unknown tool '{tool_name}'"
                else:
                    result_str = await self._execute_with_retry(tool, **args)

                parsed_for_formatter: dict[str, Any] | None = None
                try:
                    parsed = json.loads(result_str)
                    parsed_for_formatter = parsed if isinstance(parsed, dict) else None
                    if isinstance(parsed, dict):
                        if tool_name == "set_checklist":
                            counts = parsed.get("counts", {})
                            checklist_count = counts.get("checklist", 0) if isinstance(counts, dict) else 0
                            vuln_count = counts.get("vulnerabilities", 0) if isinstance(counts, dict) else 0
                            gap_count = counts.get("gaps", 0) if isinstance(counts, dict) else 0
                            last_set_checklist = parsed
                            self._cb.on_done(
                                f"  → checklist={int(checklist_count)}, vulnerabilities={int(vuln_count)}, gaps={int(gap_count)}"
                            )
                            tool_message_content = await self._compact_tool_message_for_formatter(
                                tool_name=tool_name,
                                parsed=parsed,
                                raw_content=result_str,
                                target_type=target_type,
                                info=info,
                            )
                            messages.append(ChatMessage(role="tool", content=tool_message_content, tool_call_id=call_id, name=tool_name))
                            continue
                        else:
                            hit_rows = parsed.get("hits")
                            if not isinstance(hit_rows, list):
                                hit_rows = parsed.get("results", [])
                            if not isinstance(hit_rows, list):
                                hit_rows = parsed.get("items", [])
                            if not isinstance(hit_rows, list):
                                hit_rows = parsed.get("checklist", [])
                            hits = len(hit_rows) if isinstance(hit_rows, list) else 0
                    else:
                        hits = 0
                    self._cb.on_done(f"  → {hits} hits returned")
                except (json.JSONDecodeError, TypeError):
                    self._cb.on_done(f"  → {len(result_str)} chars returned")

                tool_message_content = await self._compact_tool_message_for_formatter(
                    tool_name=tool_name,
                    parsed=parsed_for_formatter,
                    raw_content=result_str,
                    target_type=target_type,
                    info=info,
                )
                messages.append(ChatMessage(role="tool", content=tool_message_content, tool_call_id=call_id, name=tool_name))

            # Budget reminder
            next_round = round_num + 1
            if next_round <= FORMATTER_ROUNDS:
                rounds_left = FORMATTER_ROUNDS - next_round
                if rounds_left == 0:
                    budget_msg = (
                        "⚠ THIS IS YOUR LAST ROUND. Return your final JSON now. "
                        "Do NOT call any more tools. "
                        "Every checklist item MUST be an object with keys: name, priority. "
                        "priority MUST be integer 1-5 for every item."
                    )
                else:
                    budget_msg = f"Round {next_round}/{FORMATTER_ROUNDS}. {rounds_left} rounds remaining ({max(0, rounds_left - 1)} for tools + 1 for final answer)."
                messages.append(ChatMessage(role="user", content=budget_msg))

        self._cb.on_warn(f"Reached max rounds ({FORMATTER_ROUNDS}) without final answer")
        result = IntelResult(status="incomplete")
        if last_set_checklist:
            maybe_checklist = last_set_checklist.get("checklist_json", {}) or {}
            if _is_structured_checklist_payload(maybe_checklist):
                result.checklist = maybe_checklist
        if not result.checklist and base_checklist_payload:
            result.checklist = base_checklist_payload
        result.vulnerabilities = []
        return result

    # ── Update Pipeline ────────────────────────────────────────────────

    def _collect_source_entries(self, target_type: str) -> list[dict[str, Any]]:
        from server.db.knowledge.config.sources import INTEL_UPDATABLE_SOURCES, get_source_by_name

        updatable_builtin_names = {str(name).strip().lower() for name in INTEL_UPDATABLE_SOURCES}
        configured_names = VERIFY_SOURCES.get(target_type, DEFAULT_VERIFY_SOURCES)
        source_entries: list[dict[str, Any]] = []
        for source_name in configured_names:
            clean_name = str(source_name or "").strip()
            if not clean_name:
                continue
            source_cfg = get_source_by_name(clean_name)
            source_entries.append(
                {
                    "name": clean_name,
                    "url": str(getattr(source_cfg, "url", "") or ""),
                    "content_type": str(getattr(source_cfg, "content_type", "mixed") or "mixed").strip().lower(),
                    "source_kind": "builtin",
                    "update_mode": "every_3_days" if clean_name.lower() in updatable_builtin_names else "static",
                    "updatable": clean_name.lower() in updatable_builtin_names,
                }
            )

        try:
            custom_sources = self._projects_store.list_intel_resources(enabled_only=True)
        except Exception as exc:
            logger.warning("intel_custom_source_read_failed", error=str(exc))
            custom_sources = []

        for row in custom_sources:
            row_target = _normalize_target_type(str(row.get("target_type", "all")))
            if not row_target:
                row_target = "all"
            if target_type == "all":
                pass
            elif row_target not in {"all", target_type}:
                continue
            update_mode = str(row.get("update_mode", "every_3_days") or "every_3_days").strip().lower()
            if update_mode != "every_3_days":
                continue
            source_entries.append(
                {
                    "name": str(row.get("name", "")).strip(),
                    "url": str(row.get("url", "")).strip(),
                    "content_type": str(row.get("content_type", "strategies") or "strategies").strip().lower(),
                    "source_kind": "custom",
                    "update_mode": update_mode,
                    "updatable": True,
                }
            )

        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for entry in source_entries:
            source_name = str(entry.get("name", "")).strip()
            source_url = str(entry.get("url", "")).strip()
            if not source_name:
                continue
            key = (source_name.lower(), source_url.lower())
            if key in seen:
                continue
            seen.add(key)
            deduped.append(
                {
                    "name": source_name,
                    "url": source_url,
                    "content_type": str(entry.get("content_type", "mixed") or "mixed").strip().lower(),
                    "source_kind": str(entry.get("source_kind", "builtin") or "builtin").strip().lower(),
                    "update_mode": str(entry.get("update_mode", "every_3_days") or "every_3_days").strip().lower(),
                    "updatable": bool(entry.get("updatable", False)),
                }
            )

        return deduped

    async def _run_update_pipeline(self, target_type: str, info: str) -> dict[str, Any]:
        domain = _resolve_rag_domain(target_type)
        self._cb.on_step(f"Update: Verifying sources for '{target_type}'")

        source_list = self._collect_source_entries(target_type)
        verified: list[dict[str, Any]] = []
        for source_entry in source_list:
            res = await self._call_tool_json(
                "verify_source",
                source_name=source_entry["name"],
                url=source_entry["url"],
            )
            verified.append(
                {
                    **(res if isinstance(res, dict) else {}),
                    "source_name": source_entry["name"],
                    "url": source_entry["url"],
                    "content_type": source_entry["content_type"],
                    "source_kind": source_entry["source_kind"],
                    "update_mode": source_entry["update_mode"],
                    "updatable": bool(source_entry["updatable"]),
                }
            )
        trusted = [v for v in verified if isinstance(v, dict) and v.get("verified")]
        self._cb.on_done(f"Update: {len(trusted)}/{len(source_list)} sources verified")

        categories = await self._discover_categories(target_type, domain)
        max_categories = 8
        if len(categories) > max_categories:
            self._cb.on_warn(
                f"Update: limiting payload categories from {len(categories)} to {max_categories}"
            )
            categories = categories[:max_categories]
        self._cb.on_done(f"Update: {len(categories)} categories discovered")

        stats = _default_stats()
        rate_limited = False
        source_errors: list[str] = []
        stats["domains_updated"] = [domain]
        content_types_updated: set[str] = set()
        stats["sources_total"] = len(source_list)
        stats["sources_verified"] = len(trusted)
        payload_store_added = 0
        payload_candidates: list[dict[str, Any]] = []
        exploit_candidates: list[dict[str, Any]] = []

        trusted_builtin_sources = [
            entry
            for entry in trusted
            if str(entry.get("source_kind", "")).strip().lower() == "builtin"
            and bool(entry.get("updatable", False))
        ]
        if trusted_builtin_sources:
            self._cb.on_step(
                f"Update: Refreshing verified RAG sources ({len(trusted_builtin_sources)})"
            )
            rag_sync = await self._sync_verified_rag_sources(trusted_builtin_sources)
            stats["rag_sources_processed"] = int(rag_sync.get("processed", 0) or 0)
            stats["rag_sources_changed"] = int(rag_sync.get("changed", 0) or 0)
            stats["rag_documents_ingested"] = int(rag_sync.get("documents", 0) or 0)
            stats["rag_chunks_embedded"] = int(rag_sync.get("chunks", 0) or 0)
            rag_errors = rag_sync.get("errors", [])
            if isinstance(rag_errors, list):
                source_errors.extend(str(e) for e in rag_errors if e)
            for content_type in rag_sync.get("content_types_updated", []):
                if content_type:
                    content_types_updated.add(str(content_type))
            self._cb.on_done(
                "Update: RAG sources refreshed "
                f"(processed={stats['rag_sources_processed']}, changed={stats['rag_sources_changed']}, docs={stats['rag_documents_ingested']}, "
                f"chunks={stats['rag_chunks_embedded']})"
            )

        if trusted:
            self._cb.on_step(f"Update: Syncing payload store for '{target_type}'")
            payload_sync = await self._sync_payload_store(target_type=target_type, domain=domain)
            payload_store_added = int(payload_sync.get("added", 0) or 0)
            sync_errors = payload_sync.get("errors", [])
            if isinstance(sync_errors, list):
                source_errors.extend(str(e) for e in sync_errors if e)
            self._cb.on_done(f"Update: payload store synced (+{payload_store_added})")

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
            "total_embedded": stats.get("rag_chunks_embedded", 0) + payload_upserted + exploit_upserted,
            "payload_store_added": payload_store_added,
            "content_types_updated": sorted(content_types_updated),
            "rate_limited": rate_limited, "source_errors": source_errors[:MAX_SOURCE_ERRORS],
        })
        if stats["total_embedded"] > 0 or payload_store_added > 0 or stats.get("rag_sources_changed", 0) > 0:
            stats["update_status"] = "updated"
        elif rate_limited:
            stats["update_status"] = "rate_limited"
        elif not trusted:
            stats["update_status"] = "source_unavailable"

        self._cb.on_done(
            "Update: embedded="
            f"{stats['total_embedded']}, payload_store_added={payload_store_added}, "
            f"status={stats['update_status']}"
        )

        summary = (
            f"Static pipeline complete for {target_type}: "
            f"update_status={stats['update_status']}, "
            f"new_payloads={stats['new_payloads']}, "
            f"new_exploits={stats['new_exploits']}, "
            f"total_embedded={stats['total_embedded']}, "
            f"payload_store_added={payload_store_added}."
        )
        await self._call_tool_json("notify_planner", summary=summary, updated_domains=",".join(stats["domains_updated"]), new_payload_count=stats["new_payloads"], new_exploit_count=stats["new_exploits"])
        self._state_store.set_last_update(target_type, datetime.now(timezone.utc))

        return {"target_type": target_type, "info": info, "verified_sources": verified, "stats": stats, "summary": summary, "domains_considered": [domain]}

    async def _sync_verified_rag_sources(self, source_entries: list[dict[str, Any]]) -> dict[str, Any]:
        from server.db.knowledge.config.sources import get_source_by_name
        from server.db.knowledge.orchestrator import KnowledgeOrchestrator

        orchestrator = KnowledgeOrchestrator()
        processed = 0
        changed = 0
        documents = 0
        chunks = 0
        errors: list[str] = []
        content_types_updated: set[str] = set()
        seen_names: set[str] = set()
        try:
            for entry in source_entries:
                source_name = str(entry.get("source_name") or entry.get("name") or "").strip()
                if not source_name:
                    continue
                key = source_name.lower()
                if key in seen_names:
                    continue
                seen_names.add(key)
                source_cfg = get_source_by_name(source_name)
                if source_cfg is None:
                    continue
                try:
                    result = await orchestrator.ingest_source(source_name)
                except Exception as exc:
                    errors.append(f"{source_name}: {exc}")
                    continue
                processed += 1
                documents += int(getattr(result, "documents_extracted", 0) or 0)
                chunks += int(getattr(result, "chunks_embedded", 0) or getattr(result, "chunks_created", 0) or 0)
                if (
                    int(getattr(result, "chunks_embedded", 0) or 0) > 0
                    or int(getattr(result, "chunks_created", 0) or 0) > 0
                    or int(getattr(result, "replaced_existing", 0) or 0) > 0
                ):
                    changed += 1
                    content_types_updated.add(
                        str(getattr(source_cfg, "content_type", "") or "").strip().lower()
                    )
                if getattr(result, "errors", None):
                    errors.extend(str(item) for item in result.errors if item)
        finally:
            await orchestrator.close()

        return {
            "processed": processed,
            "changed": changed,
            "documents": documents,
            "chunks": chunks,
            "errors": errors,
            "content_types_updated": sorted(ct for ct in content_types_updated if ct),
        }

    async def _sync_payload_store(self, *, target_type: str, domain: str) -> dict[str, Any]:
        from server.db.knowledge.orchestrator import KnowledgeOrchestrator

        ingest_domains: list[str | None]
        if target_type == "all":
            ingest_domains = [None]
        elif domain == "shared":
            ingest_domains = ["shared"]
        else:
            ingest_domains = [domain, "shared"]

        added_total = 0
        errors: list[str] = []
        orchestrator = KnowledgeOrchestrator(payload_only=True)
        try:
            for ingest_domain in ingest_domains:
                try:
                    rows = await orchestrator.ingest_payloads(domain=ingest_domain)
                except Exception as exc:
                    errors.append(
                        f"payload_store_sync({ingest_domain or 'all'}): {exc}"
                    )
                    continue
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    added_total += int(row.get("payloads_added", 0) or 0)
                    if row.get("error"):
                        errors.append(str(row["error"]))
        finally:
            await orchestrator.close()

        return {"added": added_total, "errors": errors}

    # ── Category Discovery ─────────────────────────────────────────────

    async def _discover_categories(self, target_type: str, domain: str) -> list[str]:
        query_target = _target_query_text(target_type)
        result = await self._call_tool_json("search_rag", query=f"{query_target} attack techniques categories payloads", domain=domain, content_type="attack_types", n_results=25)
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
        query = f"{_target_query_text(target_type)} methodology techniques vulnerabilities"
        domain = _resolve_rag_domain(target_type)
        out: dict[str, Any] = {"query": query, "domain": domain, "results": {}}
        for ct in ("strategies", "attack_types", "exploits"):
            tool_result = await self._call_tool_json("search_rag", query=query, domain=domain, content_type=ct, n_results=6)
            out["results"][ct] = tool_result.get("hits", []) if isinstance(tool_result, dict) else []
        return out

    async def _prepare_formatter_context(self, target_type: str, pipeline_report: dict[str, Any]) -> dict[str, Any]:
        rag_snapshot = pipeline_report.get("rag_snapshot", {})
        rag_domain = str(rag_snapshot.get("domain", "shared")) if isinstance(rag_snapshot, dict) else "shared"
        query_target = _target_query_text(target_type)
        queries = {
            "methods": {"query": f"{query_target} security testing methodology strategy OWASP", "content_type": "strategies"},
            "techniques": {"query": f"{query_target} attack techniques TTP MITRE ATT&CK", "content_type": "attack_types"},
            "vulnerabilities": {"query": f"{query_target} vulnerabilities exploit patterns", "content_type": "exploits"},
        }
        rag_prefetch: dict[str, Any] = {}
        for key, cfg in queries.items():
            rag_prefetch[key] = await self._call_tool_json("search_rag", query=cfg["query"], domain=rag_domain, content_type=cfg["content_type"], n_results=10)
        methods_n = _safe_hits_count(rag_prefetch.get("methods", {}))
        techniques_n = _safe_hits_count(rag_prefetch.get("techniques", {}))
        vulns_n = _safe_hits_count(rag_prefetch.get("vulnerabilities", {}))
        web_fallback: dict[str, Any] = {"used": False, "query": "", "results": []}
        return {"rag_prefetch": rag_prefetch, "coverage_counts": {"methods": methods_n, "techniques": techniques_n, "vulnerabilities": vulns_n}, "web_fallback": web_fallback}

    # ── Tool Execution ─────────────────────────────────────────────────

    async def _refine_checklists_for_formatter(
        self,
        *,
        checklist_data: dict[str, Any],
        target_type: str,
        info: str,
    ) -> str:
        try:
            return await asyncio.wait_for(
                clean_checklists_with_llm(
                    checklist_data=checklist_data,
                    target_type=target_type,
                    info=info,
                    llm=self._llm,
                ),
                timeout=FORMATTER_CALL_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.warning("intel_checklist_refine_failed", error=str(exc), target_type=target_type)
        return json.dumps(build_deterministic_checklist_payload(checklist_data, info), ensure_ascii=True)

    async def _compact_tool_message_for_formatter(
        self,
        *,
        tool_name: str,
        parsed: dict[str, Any] | None,
        raw_content: str,
        target_type: str,
        info: str,
    ) -> str:
        if not isinstance(parsed, dict):
            return raw_content
        if tool_name == "get_checklists":
            return await self._refine_checklists_for_formatter(
                checklist_data=parsed,
                target_type=target_type,
                info=info,
            )
        if tool_name == "search_rag":
            return _compact_search_results_for_formatter(parsed)
        if tool_name == "set_checklist":
            counts = parsed.get("counts", {}) if isinstance(parsed.get("counts", {}), dict) else {}
            return json.dumps(
                {
                    "target_type": parsed.get("target_type", target_type),
                    "counts": counts,
                    "summary": parsed.get("summary", ""),
                },
                ensure_ascii=True,
            )
        return raw_content

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
