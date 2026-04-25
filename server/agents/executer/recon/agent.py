"""Recon executer agent."""

from __future__ import annotations

from server.agents.executer.base import BaseExecuterAgent, ExecuterCallback, ExecuterResult
from server.agents.executer.target_tool_routing import (
    filter_tools_for_target_types,
    normalize_target_types,
)
from server.config.agent import LocalLLMConfig, PublicLLMConfig

from .config import (
    LLM_CALL_TIMEOUT_SECONDS,
    MAX_TOOL_ROUNDS,
    RECON_CONTEXT_WINDOW_MAX_TOKENS,
    RECON_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS,
    RECON_MAX_TOOL_CALLS_PER_ROUND,
    RECON_TOOL_EXECUTION_TIMEOUT_SECONDS,
    WARMUP_RECON_MAX_TOOL_CALLS_PER_ROUND,
)
from .context_window import RECON_CONTEXT_WINDOW_KEY
from .prompts import SYSTEM_PROMPT
from .tools import ALL_RECON_TOOLS


class ReconExecuterAgent(BaseExecuterAgent):
    """
    Executes reconnaissance scenarios with stealth capabilities.

    Orchestrates passive and active reconnaissance including:
    - Port scanning (Nmap, Masscan) with stealth adaptation
    - Subdomain enumeration (Amass, Subfinder)
    - OSINT collection (Shodan, certificate transparency)
    - Technology detection (WhatWeb, header analysis)
    - Secret discovery (TruffleHog, Gitleaks)

    Features a Stealth Analyzer sub-component that:
    - Detects honeypot indicators
    - Identifies tarpit behavior
    - Dynamically adapts scan cadence
    - Avoids detection patterns
    """

    def __init__(
        self,
        *,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        target_types: list[str] | None = None,
        project_id: str | None = None,
    ) -> None:
        self._target_types = list(target_types or [])
        scoped_tools = filter_tools_for_target_types(
            role="recon",
            tools=ALL_RECON_TOOLS,
            target_types=target_types,
        )
        scope_text = ", ".join(str(x).strip() for x in (target_types or []) if str(x).strip())
        scoped_prompt = SYSTEM_PROMPT
        if scope_text:
            scoped_prompt = (
                f"{SYSTEM_PROMPT}\n\n"
                f"Target surface scope for this run: {scope_text}. "
                "Only work on active surfaces unless tool evidence discovers a new surface."
            )
        super().__init__(
            role="recon",
            system_prompt=scoped_prompt,
            tools=scoped_tools,
            max_tool_rounds=MAX_TOOL_ROUNDS,
            max_tool_calls_per_round=RECON_MAX_TOOL_CALLS_PER_ROUND,
            call_timeout_seconds=LLM_CALL_TIMEOUT_SECONDS,
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
            project_id=project_id,
            context_window_key=RECON_CONTEXT_WINDOW_KEY,
            context_window_max_tokens=RECON_CONTEXT_WINDOW_MAX_TOKENS,
        )

    async def run(self, user_message: str) -> ExecuterResult:
        context_block = "Context window disabled (missing project_id)."
        if self._context_window is not None:
            await self._context_window.ensure_token_budget(
                threshold_tokens=RECON_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS
            )
            snapshot = self._context_window.snapshot()
            context_block = format_recon_context_for_packet(snapshot)

        available_tools = sorted(self._tools.keys())
        normalized_targets = normalize_target_types(self._target_types)
        max_tool_calls_for_run = _max_tool_calls_per_round_for_message(user_message)
        packet = build_recon_scenario_packet(
            scenario_and_target=user_message,
            context_block=context_block,
            available_tools=available_tools,
            target_types=normalized_targets,
            max_tool_calls_per_round=max_tool_calls_for_run,
        )
        previous_timeout_cap = self._execution_tool_timeout_cap_seconds
        previous_max_tool_calls = self._max_tool_calls_per_round
        self._execution_tool_timeout_cap_seconds = _tool_timeout_cap_for_message(user_message)
        self._max_tool_calls_per_round = max_tool_calls_for_run
        try:
            return await super().run(packet)
        finally:
            self._execution_tool_timeout_cap_seconds = previous_timeout_cap
            self._max_tool_calls_per_round = previous_max_tool_calls


def _tool_timeout_cap_for_message(user_message: str) -> int | None:
    message = str(user_message or "")
    if "Warmup scenario batch" in message or "Warmup mode:" in message:
        return RECON_TOOL_EXECUTION_TIMEOUT_SECONDS
    return None


def _max_tool_calls_per_round_for_message(user_message: str) -> int:
    message = str(user_message or "")
    if "Warmup scenario batch" in message or "Warmup mode:" in message:
        return WARMUP_RECON_MAX_TOOL_CALLS_PER_ROUND
    return RECON_MAX_TOOL_CALLS_PER_ROUND


def format_recon_context_for_packet(snapshot: dict[str, object], max_entries: int = 8) -> str:
    estimated = int(snapshot.get("estimated_tokens", 0) or 0)
    max_t = int(snapshot.get("max_tokens", RECON_CONTEXT_WINDOW_MAX_TOKENS) or RECON_CONTEXT_WINDOW_MAX_TOKENS)
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


def build_recon_scenario_packet(
    *,
    scenario_and_target: str,
    context_block: str,
    available_tools: list[str],
    target_types: list[str],
    max_tool_calls_per_round: int,
) -> str:
    return (
        "Recon scenario packet:\n"
        "1) Scenario + target info from operator follows below.\n"
        "   Operator info may include prior execution history for this agent.\n"
        "2) Use scoped recon tools to maximize useful recon signal for this scenario.\n"
        f"3) Max tool executions per round: {max_tool_calls_per_round}. Max rounds per scenario: 3.\n"
        "4) Always update context window with new findings each round.\n\n"
        "Current context window:\n"
        f"{context_block}\n\n"
        f"Target surface scope for this run: {', '.join(target_types) if target_types else 'unspecified'}\n\n"
        "Available callable tools in this run:\n"
        f"{', '.join(available_tools)}\n\n"
        "Scenario + target info:\n"
        f"{scenario_and_target}"
    )
