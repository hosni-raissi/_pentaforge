"""Prompts for the Intel Agent formatter LLM."""

from __future__ import annotations

import json
from typing import Any

from server.agents.intel.config import FORMATTER_ROUNDS



def _target_query_text(target_type: str) -> str:
    normalized = str(target_type or "").strip().lower().replace("-", "_")
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
        "database": "database",
        "repository": "source code repository",
    }
    return labels.get(normalized, normalized.replace("_", " "))


FORMATTER_SYSTEM_PROMPT = (
    "Role: Intel agent for aggressive pentest checklist generation.\n"
    "Goal: maximize vulnerability coverage for the target by optimizing the provided baseline checklist.\n"
    "\n"
    "Tools: search_rag, set_checklist.\n"
    "Required usage:\n"
    "1) Review the provided current checklist for the target.\n"
    "2) Call search_rag only if it improves checklist coverage or surfaces specific, relevant vulnerability classes.\n"
    "3) Respect explicit scope exclusions from the target info (for example: no SQL injection, do not test XSS).\n"
    "4) Call set_checklist in the final round to update the checklist with your optimized and aggressive pentest manipulation.\n"
    "\n"

    f"Budget: {FORMATTER_ROUNDS} rounds total; keep last round for final JSON.\n"
    "Return strict JSON only. Copy pipeline stats exactly.\n"
    "```json\n"
    
    "```"
)


def _format_entries(entries: list[dict[str, Any]], label: str) -> str:
    """Format RAG entries into readable numbered list for the LLM."""
    if not entries:
        return f"  (no {label} data in RAG)"
    lines: list[str] = []
    for i, entry in enumerate(entries[:8], 1):
        if not isinstance(entry, dict):
            continue
        source = entry.get("source", "")
        heading = entry.get("heading", "")
        snippet = entry.get("snippet", "")
        tags = entry.get("tags", [])
        line = f"  {i}. [{source}] {heading}"
        if tags and isinstance(tags, list):
            line += f" | tags: {', '.join(str(t) for t in tags)}"
        if snippet:
            line += f"\n     {snippet}"
        lines.append(line)
    if len(entries) > 8:
        lines.append(f"  ... and {len(entries) - 8} more entries")
    return "\n".join(lines)


def build_user_message(
    target_type: str,
    info: str,
    formatter_payload: dict[str, Any],
    current_round: int = 1,
    max_rounds: int = FORMATTER_ROUNDS,
    base_checklist_text: str = "",
) -> str:
    """Build the user message for the formatter LLM call."""
    target_query = _target_query_text(target_type)

    coverage = formatter_payload.get("coverage_counts", {})
    if not isinstance(coverage, dict):
        coverage = {}
    methods_n = coverage.get("methods", 0)
    techniques_n = coverage.get("techniques", 0)
    vulns_n = coverage.get("vulnerabilities", 0)

    rag = formatter_payload.get("rag_snapshot", {})
    if not isinstance(rag, dict):
        rag = {}
    rag_domain = str(rag.get("domain", target_type) or target_type)
    strategies = rag.get("strategies", [])
    attack_types = rag.get("attack_types", [])
    exploits = rag.get("exploits", [])

    stats = formatter_payload.get("stats", {})

    # Build search suggestions
    search_suggestions: list[str] = []
    if techniques_n + len(attack_types) < 5:
        search_suggestions.append(
            f'search_rag(query="{target_query} attack paths, injections, authorization bypass, SSRF, SSTI", '
            f'content_type="attack_types", domain="{rag_domain}", n_results=10)'
        )
    if vulns_n + len(exploits) < 5:
        search_suggestions.append(
            f'search_rag(query="{target_query} known vulnerability classes like SQL injection, XSS, SSRF, IDOR, auth bypass", '
            f'content_type="exploits", domain="{rag_domain}", n_results=10)'
        )
    search_suggestions.append(
        f'set_checklist(target_type="{target_type}", checklist="...", techniques="...", vulnerabilities="...", methods="...", gaps="...")'
    )

    suggestions_text = "\n".join(f"  → {s}" for s in search_suggestions[:6])

    techniques_text = _format_entries(attack_types, "techniques")
    vulns_text = _format_entries(exploits, "vulnerabilities/exploits")

    # Round budget info
    rounds_remaining = max_rounds - current_round
    tool_calls_remaining = max(0, rounds_remaining - 1)

    if rounds_remaining <= 1:
        budget_text = (
            "⚠ THIS IS YOUR LAST ROUND. You MUST return your final JSON now.\n"
            "Do NOT call any tools. Return the JSON output immediately."
        )
    else:
        budget_text = (
            f"Round {current_round}/{max_rounds}. "
            f"You have {rounds_remaining} rounds remaining "
            f"({tool_calls_remaining} for tools + 1 for final answer)."
        )

    return (
        f"Target: {target_type}\n"
        f"Info: {info or 'none'}\n"
        f"This is the current check list for this target:\n"
        f"{base_checklist_text}\n\n"
        f"{budget_text}\n\n"
        "Coverage snapshot:\n"
        f"- techniques: {techniques_n + len(attack_types)}\n"
        f"- vulnerabilities: {vulns_n + len(exploits)}\n\n"
        "RAG techniques:\n"
        f"{techniques_text}\n\n"
        "RAG vulnerabilities:\n"
        f"{vulns_text}\n\n"
        "Recommended tool calls:\n"
        f"{suggestions_text}\n\n"
        "Required flow:\n"
        "1) search_rag only if it adds useful attack coverage or specific known vulnerabilities.\n"
        "2) respect explicit scope exclusions from the info.\n"
        "3) set_checklist once in the final round.\n"
        "4) final JSON.\n\n"
        "Pipeline stats (copy as-is):\n"
        f"```json\n{json.dumps(stats, ensure_ascii=True)}\n```"
    )



_CHECKLIST_CLEANER_SYSTEM_PROMPT = (
    "You refine a structured pentest checklist.\n"
    "Use the target info to remove clearly irrelevant checklist items.\n"
    "Do not invent checklist items or references.\n"
    "Keep broad coverage; only remove items explicitly excluded by target info.\n"
    "Return strict JSON only. No markdown fences, no prose, no leading text.\n"
    "Use double quotes for all keys and strings. No trailing commas.\n"
    "Required keys: target_type, available_total, checklist.\n"
    "checklist must be a list of blocks with keys: phase, title, items.\n"
    "items must be a list of objects with keys: name, priority.\n"
    "priority must be an integer from 1 to 5 (5 is highest priority).\n"
)
