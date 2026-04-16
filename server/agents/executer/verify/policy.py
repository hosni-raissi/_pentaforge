"""Verify scenario-packet and context formatting policy helpers."""

from __future__ import annotations

from .config import VERIFY_CONTEXT_WINDOW_MAX_TOKENS
from .catalog import VERIFY_TOOLS


def format_verify_context_for_packet(snapshot: dict[str, object], max_entries: int = 8) -> str:
    estimated = int(snapshot.get("estimated_tokens", 0) or 0)
    max_t = int(snapshot.get("max_tokens", VERIFY_CONTEXT_WINDOW_MAX_TOKENS) or VERIFY_CONTEXT_WINDOW_MAX_TOKENS)
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


def build_verify_scenario_packet(
    *,
    scenario_and_target: str,
    context_block: str,
    available_tools: list[str],
) -> str:
    catalog_names = ", ".join(sorted(VERIFY_TOOLS.keys()))
    return (
        "Verify scenario packet:\n"
        "1) Verification target details follow below.\n"
        "2) Use scoped verify tools to confirm/reject findings with evidence.\n"
        "3) Max tool executions per round: 2. Max rounds per scenario: 5.\n"
        "4) Always update context window with verification evidence each round.\n\n"
        "Current context window:\n"
        f"{context_block}\n\n"
        "Available callable tools in this run:\n"
        f"{', '.join(available_tools)}\n\n"
        "run_custom catalog tools for verify scope:\n"
        f"{catalog_names}\n"
        "Use these via run_custom(command=..., args=[...], reason=...).\n\n"
        "Scenario + target info:\n"
        f"{scenario_and_target}"
    )
