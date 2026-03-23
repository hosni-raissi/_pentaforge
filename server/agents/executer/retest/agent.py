"""Retest executer agent."""

from __future__ import annotations

from server.agents.executer.base import BaseExecuterAgent, ExecuterCallback
from server.config.agent import LocalLLMConfig, PublicLLMConfig

from .config import LLM_CALL_TIMEOUT_SECONDS, MAX_TOOL_ROUNDS
from .prompts import SYSTEM_PROMPT
from .tools import ALL_RETEST_TOOLS


class RetestExecuterAgent(BaseExecuterAgent):
    """Executes retest scenarios."""

    def __init__(
        self,
        *,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
    ) -> None:
        super().__init__(
            role="retest",
            system_prompt=SYSTEM_PROMPT,
            tools=ALL_RETEST_TOOLS,
            max_tool_rounds=MAX_TOOL_ROUNDS,
            call_timeout_seconds=LLM_CALL_TIMEOUT_SECONDS,
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
        )
