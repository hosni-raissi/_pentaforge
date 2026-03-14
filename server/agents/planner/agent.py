"""
PlannerAgent — Tool-calling agent that builds penetration-testing plans.

Implements a ReAct-style loop:
  1. Send messages + tool schemas to the LLM
  2. If the LLM returns tool_calls → execute them and append results
  3. Loop until the LLM produces a final text response (no tool_calls)
  4. Parse the final response into a PlannerResult with scenarios for the executor
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import structlog

from server.config.agent import (
    LocalLLMConfig,
    PlannerLLMConfig,
    local_llm_config,
    planner_llm_config,
    planner_llm_mode,
)
from server.core.llm import ChatMessage, LLMClient
from server.core.llm_local import LocalLLMClient
from server.core.tool import Tool

from .prompts import SYSTEM_PROMPT

logger = structlog.get_logger(__name__)

MAX_TOOL_ROUNDS = 15  # Safety cap to prevent infinite loops


@dataclass
class PlannerResult:
    """Structured output from the planner agent.

    scenarios — max 3 scenarios to dispatch to executor agents in parallel.
    needs     — if scenarios is empty, this lists what the planner still needs
                (e.g. {"tool": "search_kb", "query": "XSS techniques for Django"}).
    summary   — brief text explanation from the planner.
    """

    scenarios: list[dict] = field(default_factory=list)
    needs: list[dict] = field(default_factory=list)
    summary: str = ""


def _parse_planner_output(raw: str) -> PlannerResult:
    """Parse the LLM's final text into a PlannerResult.

    Accepts either:
      - Pure JSON: {"scenarios": [...], "needs": [...], "summary": "..."}
      - Markdown with a ```json block containing the above
      - Plain text (fallback — treated as summary, no scenarios)

    Also strips <think>...</think> blocks produced by reasoning models (e.g. qwen3).
    """
    text = raw.strip()

    # Strip <think>...</think> blocks (qwen3 reasoning models)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # Try to extract JSON from a markdown code block first
    json_str = text
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start) if "```" in text[start:] else len(text)
        json_str = text[start:end].strip()
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start) if "```" in text[start:] else len(text)
        json_str = text[start:end].strip()

    try:
        data = json.loads(json_str)
        if isinstance(data, dict):
            scenarios = data.get("scenarios", [])
            if not isinstance(scenarios, list):
                scenarios = []
            # Normalize: accept "tools" or "recommended_tools" → always "recommended_tools"
            for s in scenarios:
                if isinstance(s, dict) and "tools" in s and "recommended_tools" not in s:
                    s["recommended_tools"] = s.pop("tools")
            needs = data.get("needs", [])
            if not isinstance(needs, list):
                needs = []
            summary = data.get("summary", "")
            return PlannerResult(
                scenarios=scenarios[:3],  # enforce max 3
                needs=needs,
                summary=summary,
            )
    except (json.JSONDecodeError, ValueError):
        pass

    # Fallback: treat the whole text as summary
    return PlannerResult(summary=text)


class PlannerAgent:
    """Planner agent that uses tool calling to research and build pentest plans."""

    def __init__(
        self,
        tools: list[Tool],
        config: PlannerLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        mode: str | None = None,
    ) -> None:
        self._mode = mode or planner_llm_mode.mode  # "public" or "local"
        self._tools = {t.name: t for t in tools}
        self._tool_schemas = [t.schema() for t in tools]

        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LocalLLMClient(self._local_config)
            logger.info("planner_using_local_llm", model=self._local_config.model)
        else:
            self._config = config or planner_llm_config
            self._llm = LLMClient(self._config)
            logger.info("planner_using_public_llm", model=self._config.model)

    async def run(self, user_message: str) -> PlannerResult:
        """Run the agent and return a PlannerResult with scenarios for executor."""
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

            # If no tool calls, we have the final response — parse it
            if not response.tool_calls:
                logger.info(
                    "planner_complete",
                    rounds=round_num,
                    usage=response.usage,
                )
                result = _parse_planner_output(response.content or "")
                logger.info(
                    "planner_result",
                    scenarios=len(result.scenarios),
                    needs=len(result.needs),
                )
                return result

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
                    result_str = f"Error: unknown tool '{tool_name}'"
                    logger.warning("unknown_tool", tool=tool_name)
                else:
                    logger.info("tool_call", tool=tool_name, args=args)
                    try:
                        result_str = await tool.execute(**args)
                    except Exception as exc:
                        result_str = f"Error executing {tool_name}: {exc}"
                        logger.error("tool_error", tool=tool_name, error=str(exc))

                messages.append(
                    ChatMessage(
                        role="tool",
                        content=result_str,
                        tool_call_id=call_id,
                        name=tool_name,
                    )
                )

        logger.warning("planner_max_rounds", max=MAX_TOOL_ROUNDS)
        return PlannerResult(summary="Plan generation reached maximum iterations.")

    async def close(self) -> None:
        await self._llm.close()

    async def __aenter__(self) -> PlannerAgent:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
