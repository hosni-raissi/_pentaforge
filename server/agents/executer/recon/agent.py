"""Recon executer agent."""

from __future__ import annotations

from server.agents.executer.base import BaseExecuterAgent, ExecuterCallback
from server.agents.executer.target_tool_routing import filter_tools_for_target_types
from server.config.agent import LocalLLMConfig, PublicLLMConfig

from .config import LLM_CALL_TIMEOUT_SECONDS, MAX_TOOL_ROUNDS
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
    ) -> None:
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
            call_timeout_seconds=LLM_CALL_TIMEOUT_SECONDS,
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
        )
