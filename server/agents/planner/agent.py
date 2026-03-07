"""
PlannerAgent — Tool-calling agent that builds penetration-testing plans.

Implements a ReAct-style loop:
  1. Send messages + tool schemas to the LLM
  2. If the LLM returns tool_calls → execute them and append results
  3. Loop until the LLM produces a final text response (no tool_calls)
"""

from __future__ import annotations

import json

import structlog

from server.config.agent import PlannerLLMConfig, planner_llm_config
from server.core.llm import ChatMessage, LLMClient
from server.core.tool import Tool

from .prompts import SYSTEM_PROMPT

logger = structlog.get_logger(__name__)

MAX_TOOL_ROUNDS = 15  # Safety cap to prevent infinite loops


class PlannerAgent:
    """Planner agent that uses tool calling to research and build pentest plans."""

    def __init__(
        self,
        tools: list[Tool],
        config: PlannerLLMConfig | None = None,
    ) -> None:
        self._config = config or planner_llm_config
        self._tools = {t.name: t for t in tools}
        self._tool_schemas = [t.schema() for t in tools]
        self._llm = LLMClient(self._config)

    async def run(self, user_message: str) -> str:
        """Run the agent on a user message and return the final plan/response."""
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
            ChatMessage(role="user", content=user_message),
        ]

        for round_num in range(1, MAX_TOOL_ROUNDS + 1):
            logger.info("planner_round", round=round_num, messages=len(messages))

            response = await self._llm.chat(
                messages,
                tools=self._tool_schemas if self._tools else None,
            )

            # If no tool calls, we have the final response
            if not response.tool_calls:
                logger.info(
                    "planner_complete",
                    rounds=round_num,
                    usage=response.usage,
                )
                return response.content or ""

            # Append the assistant message with tool_calls
            messages.append(
                ChatMessage(
                    role="assistant",
                    content=response.content,
                    tool_calls=response.tool_calls,
                )
            )

            # Execute each tool call and append results
            for tc in response.tool_calls:
                tool_name = tc["function"]["name"]
                raw_args = tc["function"].get("arguments", "{}")
                call_id = tc["id"]

                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except json.JSONDecodeError:
                    args = {}
                if not isinstance(args, dict):
                    args = {}

                tool = self._tools.get(tool_name)
                if tool is None:
                    result = f"Error: unknown tool '{tool_name}'"
                    logger.warning("unknown_tool", tool=tool_name)
                else:
                    logger.info("tool_call", tool=tool_name, args=args)
                    try:
                        result = await tool.execute(**args)
                    except Exception as exc:
                        result = f"Error executing {tool_name}: {exc}"
                        logger.error("tool_error", tool=tool_name, error=str(exc))

                messages.append(
                    ChatMessage(
                        role="tool",
                        content=result,
                        tool_call_id=call_id,
                        name=tool_name,
                    )
                )

        logger.warning("planner_max_rounds", max=MAX_TOOL_ROUNDS)
        return "Plan generation reached maximum iterations. Returning partial result."

    async def close(self) -> None:
        await self._llm.close()

    async def __aenter__(self) -> PlannerAgent:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
