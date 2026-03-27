"""Prompts for the Intel Agent formatter LLM."""

from __future__ import annotations

import json
from typing import Any

from server.agents.intel.config import FORMATTER_ROUNDS


FORMATTER_SYSTEM_PROMPT = (
    "You are a senior penetration testing intelligence analyst.\n"
    "\n"
    "You will receive RAG knowledge base data about a specific target type.\n"
    "Your job is to produce a COMPLETE attack intelligence brief covering:\n"
    "\n"
    "1. METHODS — Every testing methodology and strategy to assess this target\n"
    "   (e.g., OWASP WSTG chapters, PTES phases, specific assessment approaches)\n"
    "\n"
    "2. TECHNIQUES — Every specific attack technique applicable to this target\n"
    "   (e.g., SQL injection, SSRF, Kerberoasting, container escape — be specific)\n"
    "\n"
    "3. VULNERABILITIES — Every vulnerability type and weakness class this target can have\n"
    "   (e.g., broken access control, insecure deserialization, misconfigured CORS)\n"
    "\n"
    "4. CHECKLIST — A custom target-specific pentest checklist\n"
    "   (actionable test items that planner/executors can run)\n"
    "\n"
    "## Mandatory Tool Usage\n"
    "You MUST call search_rag at least once before producing your final output.\n"
    "You SHOULD call get_checklists to build evidence-backed checklist items.\n"
    "The RAG data provided is only a snapshot — the knowledge base contains more.\n"
    "Search for what is MISSING from the provided data.\n"
    "\n"
    "Step 1: Read the provided RAG data.\n"
    "Step 2: Identify which methods, techniques, or vulnerability types are NOT covered.\n"
    "Step 3: Call search_rag with a specific query to find the missing entries.\n"
    "Step 4: If search_rag still has gaps, refine the query and call search_rag again.\n"
    "Step 5: Build a custom checklist from retrieved evidence.\n"
    "Step 6: Combine everything and return the final JSON.\n"
    "\n"
    "## Budget\n"
    f"You have {FORMATTER_ROUNDS} rounds total (1 round = 1 response from you).\n"
    "Each tool call costs 1 round. Your final JSON answer costs 1 round.\n"
    f"So you can make at most {FORMATTER_ROUNDS - 1} tool calls, then you MUST return your final answer.\n"
    "Plan your tool calls carefully — do not waste rounds.\n"
    "\n"
    "## Rules\n"
    "- Be EXHAUSTIVE. List everything relevant. Miss nothing.\n"
    f"- Maximum {FORMATTER_ROUNDS - 1} tool calls total (you need 1 round for the final answer).\n"
    "- ONLY report real methods, techniques, vulnerabilities, and checklist items. Never invent or guess.\n"
    "- If a category has no data even after searching, say so in GAPS.\n"
    "\n"
    "## Output\n"
    "After your tool calls, return ONLY this JSON:\n"
    "```json\n"
    "{\n"
    '  "status": "complete",\n'
    '  "summary": "METHODS:\\n- ...\\n\\nTECHNIQUES:\\n- ...\\n\\nVULNERABILITIES:\\n- ...\\n\\nCHECKLIST:\\n- ...\\n\\nGAPS:\\n- ...",\n'
    '  "stats": {\n'
    '    "new_payloads": 0,\n'
    '    "new_exploits": 0,\n'
    '    "total_embedded": 0,\n'
    '    "content_types_updated": [],\n'
    '    "domains_updated": [],\n'
    '    "update_status": "no_new_data",\n'
    '    "rate_limited": false,\n'
    '    "source_errors": []\n'
    "  }\n"
    "}\n"
    "```\n"
    "Copy stats from pipeline data exactly. Do not change the numbers.\n"
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
) -> str:
    """Build the user message for the formatter LLM call."""

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
    if methods_n + len(strategies) < 5:
        search_suggestions.append(
            f'search_rag(query="{target_type} OWASP testing methodology PTES assessment", '
            f'content_type="strategies", domain="{rag_domain}", n_results=10)'
        )
    else:
        search_suggestions.append(
            f'search_rag(query="{target_type} advanced attack techniques bypass evasion", '
            f'content_type="attack_types", domain="{rag_domain}", n_results=10)'
        )

    if techniques_n + len(attack_types) < 5:
        search_suggestions.append(
            f'search_rag(query="{target_type} injection XSS SSRF RCE exploit technique", '
            f'content_type="attack_types", domain="{rag_domain}", n_results=10)'
        )

    if vulns_n + len(exploits) < 5:
        search_suggestions.append(
            f'search_rag(query="{target_type} vulnerability weakness misconfiguration", '
            f'content_type="exploits", domain="{rag_domain}", n_results=10)'
        )
    search_suggestions.append(
        f'get_checklists(target_type="{target_type}", info="{(info or "")[:120]}", n_items=24)'
    )

    suggestions_text = "\n".join(f"  → {s}" for s in search_suggestions[:4])

    strategies_text = _format_entries(strategies, "methods/strategies")
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
        f"## Target: {target_type}\n"
        f"Info: {info or 'none'}\n"
        f"\n"
        f"## Round Budget\n"
        f"{budget_text}\n"
        f"\n"
        f"## Task\n"
        f"Find ALL methods, techniques, vulnerability types, and a custom checklist for "
        f"'{target_type}' target.\n"
        f"The data below is only a PARTIAL snapshot. You MUST search for more.\n"
        f"\n"
        f"## RAG Data — Methods & Strategies "
        f"({methods_n + len(strategies)} entries, likely incomplete)\n"
        f"{strategies_text}\n"
        f"\n"
        f"## RAG Data — Attack Techniques "
        f"({techniques_n + len(attack_types)} entries, likely incomplete)\n"
        f"{techniques_text}\n"
        f"\n"
        f"## RAG Data — Vulnerabilities & Exploits "
        f"({vulns_n + len(exploits)} entries, likely incomplete)\n"
        f"{vulns_text}\n"
        f"\n"
        f"## Recommended Searches (call at least one)\n"
        f"{suggestions_text}\n"
        f"\n"
        f"## Pipeline Stats (copy these exactly into your output)\n"
        f"```json\n"
        f"{json.dumps(stats, ensure_ascii=True)}\n"
        f"```\n"
        f"\n"
        f"## Steps\n"
        f"1. Read the RAG data above — note what categories are thin.\n"
        f"2. Call search_rag with one of the recommended queries above (REQUIRED).\n"
        f"3. Call get_checklists to generate a target checklist from OWASP/PTES/MITRE-aware sources.\n"
        f"4. If coverage is still thin, refine your query and call search_rag again.\n"
        f"5. Combine ALL results into the final JSON.\n"
    )
