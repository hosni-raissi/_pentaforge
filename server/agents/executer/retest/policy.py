"""Retest scenario-packet and context formatting policy helpers."""

from __future__ import annotations

from .config import (
    MAX_TOOL_ROUNDS,
    RETEST_CONTEXT_WINDOW_MAX_TOKENS,
    RETEST_MAX_TOOL_CALLS_PER_ROUND,
)
from .catalog import RETEST_TOOLS


def format_retest_context_for_packet(snapshot: dict[str, object], max_entries: int = 8) -> str:
    estimated = int(snapshot.get("estimated_tokens", 0) or 0)
    max_t = int(snapshot.get("max_tokens", RETEST_CONTEXT_WINDOW_MAX_TOKENS) or RETEST_CONTEXT_WINDOW_MAX_TOKENS)
    entries = snapshot.get("entries", []) if isinstance(snapshot, dict) else []
    if not isinstance(entries, list) or not entries:
        return f"Context window tokens: {estimated}/{max_t}\nNo stored context window entries."

    lines: list[str] = [f"Context window tokens: {estimated}/{max_t}"]
    for item in entries[-max_entries:]:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind", "note"))
        role = str(item.get("role", "assistant"))
        content = str(item.get("content", "")).strip()
        if len(content) > 260:
            content = content[:260] + "..."
        if content:
            lines.append(f"- [{kind}/{role}] {content}")
    if len(lines) == 1:
        lines.append("No stored context window entries.")
    return "\n".join(lines)


def build_retest_scenario_packet(
    *,
    scenario_and_target: str,
    context_block: str,
    available_tools: list[str],
) -> str:
    catalog_names = ", ".join(sorted(RETEST_TOOLS.keys()))
    return (
        "Retest scenario packet:\n"
        "1) Finding/scenario details follow below.\n"
        "2) Use scoped retest tools to validate remediation quality.\n"
        f"3) Max tool executions per round: {RETEST_MAX_TOOL_CALLS_PER_ROUND}. "
        f"Max rounds per scenario: {MAX_TOOL_ROUNDS}.\n"
        "4) Always update context window with replay/mutation outcomes each round.\n\n"
        "Current context window:\n"
        f"{context_block}\n\n"
        "Available callable tools in this run:\n"
        f"{', '.join(available_tools)}\n\n"
        "run_custom catalog tools for retest scope:\n"
        f"{catalog_names}\n"
        "Use these via run_custom(command=..., args=[...], reason=...).\n\n"
        "Scenario + target info:\n"
        f"{scenario_and_target}"
    )
