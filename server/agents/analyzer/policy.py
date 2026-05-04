"""Scenario packet helpers for Analyzer execution."""

from __future__ import annotations

from .config import ANALYZER_MAX_TOOL_CALLS_PER_ROUND, ANALYZER_MAX_TOOL_ROUNDS


def build_analyzer_packet(
    *,
    scenario_and_target: str,
    context_block: str,
    available_tools: list[str],
    mode: str,
) -> str:
    return (
        f"Analyzer {mode} packet:\n"
        "1) The scoped target details follow below.\n"
        "2) Use focused tools only when they add decisive verification or PoC evidence.\n"
        f"3) Max tool executions per round: {ANALYZER_MAX_TOOL_CALLS_PER_ROUND}. "
        f"Max rounds per scenario: {ANALYZER_MAX_TOOL_ROUNDS}.\n"
        "4) Keep the work tightly grounded in the provided finding.\n\n"
        "Current project memory context:\n"
        f"{context_block}\n\n"
        "Available callable tools in this run:\n"
        f"{', '.join(available_tools)}\n\n"
        "Scenario + target info:\n"
        f"{scenario_and_target}"
    )
