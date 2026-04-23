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
        "repository": "source code repository",
    }
    return labels.get(normalized, normalized.replace("_", " "))


FORMATTER_SYSTEM_PROMPT = (
    "Role: Intel agent for prioritized pentest checklist generation.\n"
    "Goal: build the best target-specific checklist by combining recon evidence, target info, and OWASP checklist coverage.\n"
    "\n"
    "Tools: get_checklists.\n"
    "Required usage:\n"
    "1) Review the target info, current recon plan, latest Perceptor cache, and current checklist.\n"
    "2) Treat the latest recon plan and Perceptor cache as the source of truth for what the target actually exposes.\n"
    "3) Use get_checklists only for OWASP checklist coverage. Do not use RAG-style reasoning or invent off-scope work.\n"
    "4) Respect explicit scope exclusions from the target info (for example: no SQL injection, do not test XSS).\n"
    "5) Output a strong target-specific checklist with 15-20 items total.\n"
    "6) Prioritize checklist items using this order of trust: Perceptor cache -> current recon plan -> target info/scope -> uploaded checklist -> OWASP checklist coverage.\n"
    "\n"

    f"Budget: {FORMATTER_ROUNDS} rounds total; keep last round for final JSON.\n"
    "Return strict JSON only. No markdown fences or extra text.\n"
    "Your final JSON must include: status, checklist.\n"
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
        f"Target context:\n{info or 'none'}\n\n"
        "Prioritization order:\n"
        "1. Latest Perceptor cache and discovered target artifacts\n"
        "2. Current recon plan\n"
        "3. Target info and scope constraints\n"
        "4. Uploaded or baseline checklist items\n"
        "5. OWASP checklist coverage\n\n"
        "Current checklist:\n"
        f"{base_checklist_text}\n\n"
        f"{budget_text}\n\n"
        "Required flow:\n"
        "1) infer what the target actually exposes from the recon plan and Perceptor cache.\n"
        "2) if you need OWASP coverage help, call get_checklists only.\n"
        "3) keep the checklist narrow, target-specific, and strictly within scope.\n"
        "4) produce between 15 and 20 checklist items total.\n"
        "5) give each item concrete wording tied to observed target details where possible.\n"
        "6) return final JSON with keys: status, checklist.\n"
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
    "phase must be a numeric string and sequential with no skips (1,2,3,... in checklist order).\n"
    "items must be a list of names or objects with key: name.\n"
)


PRIORITY_REPROMPT_SYSTEM_PROMPT = (
    "Return strict JSON only. No markdown fences, no prose. "
    "Do not drop blocks or items. Add/fix priority fields and output explicit sequential phases."
)


def build_priority_reprompt_prompt(
    *,
    checklist: dict[str, Any],
    target_type: str,
    info: str,
) -> str:
    return (
        "Add priorities and re-phase the checklist blocks.\n"
        "Return strict JSON only as a full checklist object with this shape:\n"
        "{\"target_type\":\"...\",\"available_total\":0,\"checklist\":[{\"phase\":\"1\",\"title\":\"...\",\"items\":[{\"name\":\"...\",\"priority\":1}]}]}\n\n"
        "Rules:\n"
        "- priority must be integer 1..5\n"
        "- do not remove blocks or items\n"
        "- set explicit phase numbers on all blocks as strings and do not skip numbers\n"
        "- phase numbering must be sequential in checklist order: 1,2,3,...\n"
        "- no markdown, no prose\n\n"
        "Severity scale:\n"
        "S1 / priority 1 = Critical -> SQLi, RCE, SSRF, Command Injection, Privilege Escalation\n"
        "S2 / priority 2 = High -> XSS, SSTI, Auth Bypass, IDOR, File Upload\n"
        "S3 / priority 3 = Medium -> TLS, Headers, Config, Error Handling\n"
        "S4 / priority 4 = Low -> Info leakage, clickjacking, cache weakness\n"
        "S5 / priority 5 = Info -> Fingerprinting, recon items\n\n"
        f"Target: {target_type}\n"
        f"Info: {info or 'none'}\n\n"
        f"Intel checklist JSON:\n{json.dumps(checklist, ensure_ascii=True)}"
    )
