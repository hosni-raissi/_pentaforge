"""Verify executer agent."""

from __future__ import annotations

from server.agents.executer.base import BaseExecuterAgent, ExecuterCallback, ExecuterResult
from server.config.agent import LocalLLMConfig, PublicLLMConfig

from .config import (
    LLM_CALL_TIMEOUT_SECONDS,
    MAX_TOOL_ROUNDS,
    VERIFY_CONTEXT_WINDOW_MAX_TOKENS,
    VERIFY_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS,
    VERIFY_MAX_TOOL_CALLS_PER_ROUND,
)
from .context_window import VERIFY_CONTEXT_WINDOW_KEY
from .policy import (
    build_verify_scenario_packet,
    format_verify_context_for_packet,
)
from .prompts import SYSTEM_PROMPT
from .tools import ALL_VERIFY_TOOLS


class VerifyExecuterAgent(BaseExecuterAgent):
    """
    Validates exploitation findings and eliminates false positives.

    Receives exploitation_success events from Exploit Agent and:
    - Captures Playwright screenshots of exploitation results (NOT payloads)
    - Submits screenshots to vision model for false positive validation
    - Annotates evidence with bounding boxes
    - Creates SHA-256 signed evidence chain

    Security features:
    - Never captures actual payloads in screenshots
    - Redacts sensitive URL parameters automatically
    - Creates cryptographically signed evidence chain
    - Provides confidence scores for automated triage
    """

    def __init__(
        self,
        *,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        project_id: str | None = None,
    ) -> None:
        super().__init__(
            role="verify",
            system_prompt=SYSTEM_PROMPT,
            tools=ALL_VERIFY_TOOLS,
            max_tool_rounds=MAX_TOOL_ROUNDS,
            max_tool_calls_per_round=VERIFY_MAX_TOOL_CALLS_PER_ROUND,
            call_timeout_seconds=LLM_CALL_TIMEOUT_SECONDS,
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
            project_id=project_id,
            context_window_key=VERIFY_CONTEXT_WINDOW_KEY,
            context_window_max_tokens=VERIFY_CONTEXT_WINDOW_MAX_TOKENS,
        )

    async def run(self, user_message: str) -> ExecuterResult:
        context_block = "Context window disabled (missing project_id)."
        if self._context_window is not None:
            await self._context_window.ensure_token_budget(
                threshold_tokens=VERIFY_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS
            )
            snapshot = self._context_window.snapshot()
            context_block = format_verify_context_for_packet(snapshot)

        packet = build_verify_scenario_packet(
            scenario_and_target=user_message,
            context_block=context_block,
            available_tools=sorted(self._tools.keys()),
        )
        return await super().run(packet)
