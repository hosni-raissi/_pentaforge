"""
Shared base implementation for executer agents.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

from server.config.agent import (
    LocalLLMConfig,
    PublicLLMConfig,
    llm_mode,
    local_llm_config,
    public_llm_config,
)
from server.core.llm import ChatMessage, LLMClient
from server.core.tool import Tool, coerce_args_from_schema

logger = structlog.get_logger(__name__)


class ExecuterCallback(Protocol):
    """Optional callback for progress updates."""

    def on_step(self, message: str) -> None: ...
    def on_done(self, message: str) -> None: ...
    def on_warn(self, message: str) -> None: ...


class _NoOpCallback:
    def on_step(self, message: str) -> None:
        pass

    def on_done(self, message: str) -> None:
        pass

    def on_warn(self, message: str) -> None:
        pass


@dataclass
class ExecuterResult:
    status: str = "incomplete"
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    needs: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    next_hypotheses: list[str] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)


def _dict_to_msg(d: dict[str, Any]) -> ChatMessage:
    return ChatMessage(
        role=d.get("role", "user"),
        content=d.get("content", ""),
        tool_calls=d.get("tool_calls"),
        tool_call_id=d.get("tool_call_id"),
        name=d.get("name"),
    )


def _needs_nothink(model_name: str) -> bool:
    lowered = model_name.lower()
    return "qwen3" in lowered or "qwen-3" in lowered


def _extract_json_from_text(raw: str) -> dict[str, Any]:
    text = raw.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    json_blob = text

    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start) if "```" in text[start:] else len(text)
        json_blob = text[start:end].strip()
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start) if "```" in text[start:] else len(text)
        json_blob = text[start:end].strip()

    try:
        parsed = json.loads(json_blob)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return {}


def _parse_executer_output(raw: str) -> ExecuterResult:
    parsed = _extract_json_from_text(raw)
    if not parsed:
        summary = raw.strip() or "No response generated."
        return ExecuterResult(status="incomplete", summary=summary)

    status = parsed.get("status", "incomplete")
    findings = parsed.get("findings", [])
    evidence = parsed.get("evidence", [])
    needs = parsed.get("needs", [])
    summary = parsed.get("summary", "")
    next_hypotheses = parsed.get("next_hypotheses", [])

    if not isinstance(findings, list):
        findings = []
    if not isinstance(evidence, list):
        evidence = []
    if not isinstance(needs, list):
        needs = []
    if not isinstance(next_hypotheses, list):
        next_hypotheses = []

    return ExecuterResult(
        status=str(status),
        findings=findings,
        evidence=evidence,
        needs=needs,
        summary=str(summary),
        next_hypotheses=[str(item) for item in next_hypotheses],
    )


def _get_valid_params(tool: Tool) -> set[str] | None:
    try:
        sig = inspect.signature(tool.execute)
        params = set()
        for name, param in sig.parameters.items():
            if name == "self":
                continue
            if param.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            ):
                params.add(name)
            elif param.kind == inspect.Parameter.VAR_KEYWORD:
                return None
        return params if params else None
    except (ValueError, TypeError):
        return None


class BaseExecuterAgent:
    """Tool-calling executer agent shared by all roles."""

    def __init__(
        self,
        *,
        role: str,
        system_prompt: str,
        tools: list[Tool],
        max_tool_rounds: int,
        call_timeout_seconds: int,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
    ) -> None:
        self._role = role
        self._system_prompt = system_prompt
        self._max_tool_rounds = max_tool_rounds
        self._call_timeout_seconds = call_timeout_seconds
        self._mode = mode or llm_mode.mode
        self._cb = callback or _NoOpCallback()

        self._tools = {t.name: t for t in tools}
        self._tool_schemas = [t.schema() for t in tools]
        self._tool_valid_params = {t.name: _get_valid_params(t) for t in tools}

        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LLMClient(self._local_config, mode="local")
            self._model_name = self._local_config.model
        else:
            self._config = config or public_llm_config
            self._llm = LLMClient(self._config, mode="public")
            self._model_name = self._config.model

        logger.info(
            "executer_initialized",
            role=self._role,
            mode=self._mode,
            model=self._model_name,
            tools=len(self._tools),
        )

    def _filter_tool_args(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        valid_params = self._tool_valid_params.get(tool_name)
        filtered = args if valid_params is None else {k: v for k, v in args.items() if k in valid_params}
        tool = self._tools.get(tool_name)
        if tool is None:
            return filtered
        return coerce_args_from_schema(tool.parameters, filtered)

    def _format_tool_results(self, tool_results: list[dict[str, Any]]) -> str:
        """Build a compact aggregated text block for sequential tool outputs."""
        if not tool_results:
            return ""
        lines = [f"Executed {len(tool_results)} tool call(s) sequentially:"]
        for idx, item in enumerate(tool_results, 1):
            tool_name = str(item.get("name", "?"))
            call_id = str(item.get("tool_call_id", ""))
            result = str(item.get("result", ""))
            lines.append(f"[{idx}] {tool_name} (call_id={call_id})")
            lines.append(result)
            lines.append("")
        return "\n".join(lines).strip()

    async def _run_tools(
        self,
        tool_calls: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        tool_messages: list[dict[str, Any]] = []
        tool_results: list[dict[str, Any]] = []

        for tc in tool_calls:
            tool_name = tc.get("function", {}).get("name", "")
            raw_args = tc.get("function", {}).get("arguments", "{}")
            call_id = tc.get("id", "")

            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                args = {}
            if not isinstance(args, dict):
                args = {}

            args = self._filter_tool_args(tool_name, args)
            tool = self._tools.get(tool_name)
            if tool is None:
                result = f"Error: unknown tool '{tool_name}'"
                self._cb.on_warn(f"[{self._role}] unknown tool: {tool_name}")
            else:
                self._cb.on_step(f"[{self._role}] tool call: {tool_name}")
                try:
                    result = await tool.execute(**args)
                    self._cb.on_done(
                        f"[{self._role}] {tool_name} completed ({len(result)} chars)"
                    )
                except Exception as exc:
                    logger.error(
                        "executer_tool_error",
                        role=self._role,
                        tool=tool_name,
                        error=repr(exc),
                    )
                    result = f"Error executing {tool_name}: {exc}"
                    self._cb.on_warn(f"[{self._role}] tool error: {exc}")

            tool_messages.append(
                {
                    "role": "tool",
                    "content": result,
                    "tool_call_id": call_id,
                    "name": tool_name,
                },
            )
            tool_results.append(
                {
                    "tool_call_id": call_id,
                    "name": tool_name,
                    "args": args,
                    "result": result,
                },
            )

        return tool_messages, tool_results

    async def run(self, user_message: str) -> ExecuterResult:
        self._cb.on_step(f"[{self._role}] starting run")

        system_prompt = self._system_prompt
        if _needs_nothink(self._model_name):
            system_prompt = "/nothink\n" + system_prompt

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        last_content = ""
        all_tool_results: list[dict[str, Any]] = []

        for round_index in range(1, self._max_tool_rounds + 1):
            self._cb.on_step(
                f"[{self._role}] LLM round {round_index}/{self._max_tool_rounds}"
            )
            try:
                response = await asyncio.wait_for(
                    self._llm.chat(
                        [_dict_to_msg(m) for m in messages],
                        tools=self._tool_schemas if self._tools else None,
                        temperature=0.2,
                        max_tokens=4000,
                    ),
                    timeout=self._call_timeout_seconds,
                )
            except Exception as exc:
                logger.error(
                    "executer_llm_error",
                    role=self._role,
                    error=repr(exc),
                )
                self._cb.on_warn(f"[{self._role}] LLM error: {exc}")
                return ExecuterResult(
                    status="failed",
                    summary=f"LLM error: {exc}",
                )

            last_content = response.content or ""
            tool_calls = response.tool_calls or []
            messages.append(
                {
                    "role": "assistant",
                    "content": last_content,
                    "tool_calls": tool_calls,
                },
            )

            if not tool_calls:
                result = _parse_executer_output(last_content)
                result.tool_results = all_tool_results
                self._cb.on_done(
                    f"[{self._role}] completed with status={result.status}"
                )
                return result

            tool_messages, tool_results = await self._run_tools(tool_calls)
            messages.extend(tool_messages)
            all_tool_results.extend(tool_results)

            # If we consumed the final allowed round, return the aggregated tool output.
            if round_index >= self._max_tool_rounds:
                break

        self._cb.on_warn(
            f"[{self._role}] reached max rounds ({self._max_tool_rounds})"
        )
        if all_tool_results:
            return ExecuterResult(
                status="incomplete",
                summary=self._format_tool_results(all_tool_results),
                tool_results=all_tool_results,
            )
        return _parse_executer_output(last_content)

    async def close(self) -> None:
        await self._llm.close()

    async def __aenter__(self) -> BaseExecuterAgent:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
