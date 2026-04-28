"""Adaptive prompts for system-memory preparation and organization."""

from __future__ import annotations

import json
from typing import Any


PREPARE_BLOCK_SYSTEM_PROMPT = """\
Role: system-memory preparation assistant for grouped static target-info gathering.

Your job is to lightly normalize one already-selected gathering block before execution.

Rules:
- Keep the block narrow and faithful to the provided target, scope, and block intent.
- Do not invent findings, assets, or target details.
- Preserve the original block unless a small cleanup is clearly justified.
- Return strict JSON only with keys:
  name, goal, interaction, selection_rationale, skipped_tools.
""".strip()


ORGANIZE_BLOCK_SYSTEM_PROMPT = """\
Role: system-memory organization assistant for grouped static target-info gathering.

Your job is to summarize one completed gathering block into durable system memory.

Rules:
- Use only the provided block metadata and raw tool results.
- Never invent findings, endpoints, hosts, vulnerabilities, credentials, or impact.
- Prefer concrete observed artifacts over generic narration.
- Summary must be short human prose, not raw JSON, Python dicts, or copied tool output.
- If a tool returns structured JSON, translate it into a concise sentence with the key outcome.
- Keep `key_findings`, `risk_signals`, `open_questions`, and `artifacts` short and specific.
- Do not copy giant blobs, stack traces, or full command outputs into summary fields.
- Preserve uncertainty honestly. Distinguish observed behavior from possible impact.
- Do not upgrade a clue into an exploit claim unless the evidence already proves the prerequisite.
- Wildcard CORS alone does not prove CSRF, credential leakage, or sensitive-data exposure; state the dependency if impact is unconfirmed.
- Missing CSP alone does not prove exploitable XSS; mention that an input or reflection vector still needs validation when true.
- "No session tokens collected" means token security remains unassessed, not that the application is vulnerable or safe.
- Mark status as:
  - completed: at least one useful result exists
  - partial: mixed useful/error output
  - skipped: no useful execution happened
- Return strict JSON only with keys:
  status, summary, key_findings, risk_signals, open_questions, artifacts, results.
- `results` must be a list of objects with keys:
  tool, status, summary, artifacts.
""".strip()


COMPRESS_MEMORY_SYSTEM_PROMPT = """\
Role: system-memory compression assistant.

Your job is to compress an oversized runtime memory markdown snapshot into a smaller,
durable context block that preserves the most decision-relevant facts.

Rules:
- Use only the provided memory content.
- Do not invent findings, hosts, endpoints, vulnerabilities, credentials, or impact.
- Keep concrete observed facts over narration.
- Preserve target, scope, the most important gathered findings, critical open questions,
  and the current checklist/reporting context when present.
- Return markdown only.
- Aim to stay under the requested token budget.
""".strip()


def build_prepare_block_prompt(
    *,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    block: dict[str, Any],
) -> str:
    return (
        f"Target: {target}\n"
        f"Target type: {target_type}\n"
        f"Scope: {scope or '(not provided)'}\n"
        f"Info: {info or '(not provided)'}\n\n"
        "Block:\n"
        f"{json.dumps(block, ensure_ascii=True, indent=2)}\n"
    )


def build_organize_block_prompt(
    *,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    block: dict[str, Any],
    raw_results: list[dict[str, Any]],
) -> str:
    return (
        f"Target: {target}\n"
        f"Target type: {target_type}\n"
        f"Scope: {scope or '(not provided)'}\n"
        f"Info: {info or '(not provided)'}\n\n"
        "Executed block:\n"
        f"{json.dumps(block, ensure_ascii=True, indent=2)}\n\n"
        "Raw tool results:\n"
        f"{json.dumps(raw_results, ensure_ascii=True, indent=2)}\n"
    )


def build_compress_memory_prompt(
    *,
    token_budget: int,
    current_tokens: int,
    memory_markdown: str,
) -> str:
    return (
        f"Current estimated tokens: {current_tokens}\n"
        f"Target token budget: {token_budget}\n\n"
        "Current system memory markdown:\n"
        f"{memory_markdown}\n"
    )
