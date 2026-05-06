"""Lightweight assistant agent used by the frontend AI chat panel."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator

import httpx
import structlog

from server.agents.rate_limiter import get_backup_llm_fallback, get_global_llm_queue
from server.agents.report.report_generator import generate_report
from server.config.agent import get_public_agent_config
from server.core.llm import ChatMessage, LLMClient, LLMResponse
from server.core.tool import coerce_args_from_schema
from server.layers.safety.prompt_guard import PromptInjectionGuard
from server.utils.target_scope import describe_url_scope_issue, extract_target_host_port

from .tools import (
    ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION,
    ASSISTANT_GET_PAGE_TOOL_DEFINITION,
    ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION,
    ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION,
    ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION,
    add_finding_to_brain as assistant_add_finding_to_brain,
    get_page as assistant_get_page,
    mark_false_positive as assistant_mark_false_positive,
    run_custom as assistant_run_custom,
    search_project_vectors as assistant_search_project_vectors,
)

from .prompts import CONTEXT_COMPRESSION_PROMPT, SYSTEM_PROMPT

logger = structlog.get_logger(__name__)

_MAX_TOOL_ROUNDS = 2
_MAX_TOOL_CALLS_PER_ROUND = 1
_MAX_REPLY_TOKENS = 2200
_MAX_CONTEXT_CHARS = 1400
_DIRECT_COMMAND_BINARIES = {
    "curl", "nmap", "ffuf", "sqlmap", "nikto", "wget", "git",
    "openssl", "whois", "dig", "nslookup", "httpx", "ftp", "hydra",
    "whatweb", "arjun", "dalfox", "katana", "feroxbuster", "gobuster",
    "nuclei",
}
_VAGUE_COMMAND_TOKENS = {
    "it", "that", "this", "them", "result", "results", "output", "command",
}
_ASSISTANT_NETWORK_COMMANDS = {
    "arjun",
    "cat",
    "curl",
    "dalfox",
    "dig",
    "feroxbuster",
    "ffuf",
    "find",
    "ftp",
    "grep",
    "head",
    "httpx",
    "hydra",
    "katana",
    "ls",
    "netstat",
    "nikto",
    "nmap",
    "nslookup",
    "openssl",
    "ps",
    "pwd",
    "sqlmap",
    "ss",
    "tail",
    "whatweb",
    "wget",
    "whois",
    "gobuster",
    "nuclei",
}
_ASSISTANT_CAPABILITY_QUESTION_PATTERNS = (
    "what tools do you have",
    "what tools can you use",
    "which tools can you use",
    "what tools have you",
    "what commands can you run",
    "which commands can you run",
    "what do you have access to",
    "what access do you have",
    "what can you access",
    "list your tools",
    "list the tools",
    "security tools",
    "available tools",
)
_ASSISTANT_REPORT_INTENT_PATTERNS = (
    "generate a report",
    "generate report",
    "create a report",
    "create report",
    "write a report",
    "write report",
    "make a report",
    "make report",
    "pentest report",
    "generate the report",
    "create the report",
    "build a report",
    "build report",
    "produce a report",
    "produce report",
)
_ASSISTANT_SCOPE_QUESTION_PATTERNS = (
    "access to other projects",
    "access other projects",
    "other projects",
    "other project",
    "other targets",
    "another target",
    "current target only",
)

_RUN_CUSTOM_SCHEMA = {
    "type": "function",
    "function": {
        "name": ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION["name"],
        "description": ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION["description"],
        "parameters": ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION["parameters"],
    },
}

_SEARCH_PROJECT_VECTORS_SCHEMA = {
    "type": "function",
    "function": {
        "name": ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION["name"],
        "description": ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION["description"],
        "parameters": ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION["parameters"],
    },
}

_GET_PAGE_SCHEMA = {
    "type": "function",
    "function": {
        "name": ASSISTANT_GET_PAGE_TOOL_DEFINITION["name"],
        "description": ASSISTANT_GET_PAGE_TOOL_DEFINITION["description"],
        "parameters": ASSISTANT_GET_PAGE_TOOL_DEFINITION["parameters"],
    },
}

_ADD_FINDING_TO_BRAIN_SCHEMA = {
    "type": "function",
    "function": {
        "name": ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION["name"],
        "description": ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION["description"],
        "parameters": ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION["parameters"],
    },
}

_MARK_FALSE_POSITIVE_SCHEMA = {
    "type": "function",
    "function": {
        "name": ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION["name"],
        "description": ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION["description"],
        "parameters": ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION["parameters"],
    },
}


@dataclass
class AssistantResult:
    reply: str
    blocked: bool = False
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    next_context: str = ""


class AssistantAgent:
    """Small tool-using assistant for the frontend chat panel."""

    def __init__(self) -> None:
        self._config = get_public_agent_config("assistant")
        self._llm = LLMClient(self._config, client_name="assistant")
        self._queue = get_global_llm_queue()
        self._backup = get_backup_llm_fallback()
        self._guard = PromptInjectionGuard()

    async def close(self) -> None:
        await self._llm.close()

    async def answer(
        self,
        *,
        prompt: str,
        project_id: str | None = None,
        target: str = "",
        target_type: str = "",
        context: str = "",
        saved_context: str = "",
        history: list[dict[str, Any]] | None = None,
    ) -> AssistantResult:
        """Standard non-streaming answer (backward compatibility)."""
        reply = ""
        tool_results = []
        next_context = ""
        
        async for event in self.stream_answer(
            prompt=prompt,
            project_id=project_id,
            target=target,
            target_type=target_type,
            context=context,
            saved_context=saved_context,
            history=history,
        ):
            if event["type"] == "reply":
                reply = event["data"]["text"]
            elif event["type"] == "tool_output":
                tool_results.append(event["data"]["output"])
            elif event["type"] == "context":
                next_context = event["data"]["next_context"]
        
        return AssistantResult(
            reply=reply,
            tool_results=tool_results,
            next_context=next_context,
        )

    async def stream_answer(
        self,
        *,
        prompt: str,
        project_id: str | None = None,
        target: str = "",
        target_type: str = "",
        context: str = "",
        saved_context: str = "",
        history: list[dict[str, Any]] | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Async generator yielding real-time tool progress and the final answer."""
        scope_reply = self._answer_scope_question(prompt, target=target, target_type=target_type)
        if scope_reply is not None:
            next_context = await self._build_next_context(
                saved_context=saved_context,
                history=history,
                prompt=prompt,
                reply=scope_reply,
                tool_results=[],
                target=target,
                target_type=target_type,
            )
            yield {"type": "reply", "data": {"text": scope_reply}}
            yield {"type": "context", "data": {"next_context": next_context}}
            return

        capability_reply = self._answer_capability_question(prompt, target=target, target_type=target_type)
        if capability_reply is not None:
            next_context = await self._build_next_context(
                saved_context=saved_context,
                history=history,
                prompt=prompt,
                reply=capability_reply,
                tool_results=[],
                target=target,
                target_type=target_type,
            )
            yield {"type": "reply", "data": {"text": capability_reply}}
            yield {"type": "context", "data": {"next_context": next_context}}
            return

        report_reply = await self._handle_report_intent(
            prompt,
            project_id=project_id,
            target=target,
            target_type=target_type,
        )
        if report_reply is not None:
            next_context = await self._build_next_context(
                saved_context=saved_context,
                history=history,
                prompt=prompt,
                reply=report_reply,
                tool_results=[],
                target=target,
                target_type=target_type,
            )
            yield {"type": "reply", "data": {"text": report_reply}}
            yield {"type": "context", "data": {"next_context": next_context}}
            return

        follow_up_direct = self._resolve_follow_up_command_from_history(
            prompt,
            history=history,
        )
        if follow_up_direct is not None:
            yield {
                "type": "tool_start", 
                "data": {
                    "tool": "run_custom", 
                    "input": f"{follow_up_direct.get('command')} {' '.join(follow_up_direct.get('args', []))}",
                    "reason": follow_up_direct.get("reason")
                }
            }
            tool_result = await self._execute_run_custom(follow_up_direct, target=target)
            yield {"type": "tool_output", "data": {"tool": "run_custom", "output": tool_result}}
            
            reply = self._format_direct_command_reply(tool_result)
            next_context = await self._build_next_context(
                saved_context=saved_context,
                history=history,
                prompt=prompt,
                reply=reply,
                tool_results=[tool_result],
                target=target,
                target_type=target_type,
            )
            yield {"type": "reply", "data": {"text": reply}}
            yield {"type": "context", "data": {"next_context": next_context}}
            return

        direct = self._parse_direct_command_prompt(prompt, target=target)
        if direct is not None:
            cmd_payload = {
                "command": direct["command"],
                "args": direct["args"],
                "reason": direct["reason"],
            }
            yield {
                "type": "tool_start", 
                "data": {
                    "tool": "run_custom", 
                    "input": f"{direct['command']} {' '.join(direct['args'])}",
                    "reason": direct["reason"]
                }
            }
            tool_result = await self._execute_run_custom(cmd_payload, target=target)
            yield {"type": "tool_output", "data": {"tool": "run_custom", "output": tool_result}}
            
            reply = self._format_direct_command_reply(tool_result)
            next_context = await self._build_next_context(
                saved_context=saved_context,
                history=history,
                prompt=prompt,
                reply=reply,
                tool_results=[tool_result],
                target=target,
                target_type=target_type,
            )
            yield {"type": "reply", "data": {"text": reply}}
            yield {"type": "context", "data": {"next_context": next_context}}
            return

        context_block = self._build_context_block(
            project_id=project_id,
            target=target,
            target_type=target_type,
            context=context,
            saved_context=saved_context,
        )
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
            ChatMessage(role="user", content=f"{context_block}\n\nOperator prompt:\n{prompt.strip()}"),
        ]

        tool_results: list[dict[str, Any]] = []
        for round_index in range(1, _MAX_TOOL_ROUNDS + 1):
            yield {"type": "ping", "data": {"step": f"round_{round_index}_thinking"}}
            response = await self._chat_with_fallback(messages)
            tool_calls = list(response.tool_calls or [])[:_MAX_TOOL_CALLS_PER_ROUND]
            if not tool_calls:
                embedded_tool_call = self._extract_embedded_tool_call(response.content or "")
                if embedded_tool_call is not None:
                    tool_calls = [embedded_tool_call]

            if not tool_calls:
                reply = self._sanitize_reply_text(response.content or "")
                if not reply:
                    reply = "No useful answer was produced."
                next_context = await self._build_next_context(
                    saved_context=saved_context,
                    history=history,
                    prompt=prompt,
                    reply=reply,
                    tool_results=tool_results,
                    target=target,
                    target_type=target_type,
                )
                yield {"type": "reply", "data": {"text": reply}}
                yield {"type": "context", "data": {"next_context": next_context}}
                return

            # Ensure tool calls have 'type': 'function' as required by some providers
            normalized_tool_calls = []
            for tc in tool_calls:
                if isinstance(tc, dict):
                    ntc = tc.copy()
                    if "type" not in ntc:
                        ntc["type"] = "function"
                    normalized_tool_calls.append(ntc)
                else:
                    normalized_tool_calls.append(tc)

            messages.append(
                ChatMessage(
                    role="assistant",
                    content=response.content or "",
                    tool_calls=normalized_tool_calls,
                )
            )

            for idx, tool_call in enumerate(tool_calls):
                tool_call_id = tool_call.get("id") or f"call_{idx}_{int(time.time())}"
                tool_name = (
                    tool_call.get("function", {}).get("name", "")
                    if isinstance(tool_call, dict)
                    else ""
                )
                
                # Emit tool start event
                tool_input = ""
                tool_reason = ""
                if tool_name == "run_custom":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION["parameters"],
                    )
                    cmd = raw_args.get("command", "")
                    args = raw_args.get("args", [])
                    tool_input = f"{cmd} {' '.join(args)}".strip()
                    tool_reason = raw_args.get("reason", "")
                elif tool_name == "search_project_vectors":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION["parameters"],
                    )
                    tool_input = raw_args.get("query", "")
                    tool_reason = f"Searching project vectors for: {tool_input}"
                elif tool_name == "get_page":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_GET_PAGE_TOOL_DEFINITION["parameters"],
                    )
                    tool_input = raw_args.get("url", "")
                    tool_reason = f"Inspecting page: {tool_input}"
                elif tool_name == "add_finding_to_brain":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION["parameters"],
                    )
                    tool_input = raw_args.get("finding", "")
                    tool_reason = "Updating project brain"
                elif tool_name == "mark_false_positive":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION["parameters"],
                    )
                    tool_input = raw_args.get("finding_id", "")
                    tool_reason = raw_args.get("reason", "")
                else:
                    try:
                        func = tool_call.get("function", {})
                        args_str = func.get("arguments", "{}")
                        args_obj = args_str if isinstance(args_str, dict) else json.loads(args_str)
                        tool_input = str(args_obj.get("query") or args_obj.get("url") or args_obj.get("command") or "")
                        tool_reason = str(args_obj.get("reason") or "")
                    except:
                        tool_input = ""
                        tool_reason = ""

                yield {
                    "type": "tool_start",
                    "data": {
                        "call_id": tool_call_id,
                        "tool": tool_name,
                        "input": tool_input,
                        "reason": tool_reason,
                    }
                }

                if tool_name not in {
                    "run_custom",
                    "search_project_vectors",
                    "get_page",
                    "add_finding_to_brain",
                    "mark_false_positive",
                }:
                    tool_payload = {
                        "success": False,
                        "error": f"Unsupported tool: {tool_name}",
                    }
                elif tool_name == "search_project_vectors":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION["parameters"],
                    )
                    tool_payload = await self._execute_search_project_vectors(
                        raw_args,
                        project_id=project_id,
                        target=target,
                        target_type=target_type,
                    )
                elif tool_name == "get_page":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_GET_PAGE_TOOL_DEFINITION["parameters"],
                    )
                    tool_payload = await self._execute_get_page(raw_args, target=target)
                elif tool_name == "add_finding_to_brain":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION["parameters"],
                    )
                    tool_payload = await self._execute_add_finding_to_brain(
                        raw_args,
                        project_id=project_id,
                    )
                elif tool_name == "mark_false_positive":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION["parameters"],
                    )
                    tool_payload = await self._execute_mark_false_positive(
                        raw_args,
                        project_id=project_id,
                    )
                else:
                    # Fallback to run_custom
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION["parameters"],
                    )
                    tool_payload = await self._execute_run_custom(raw_args, target=target)
                
                tool_results.append(tool_payload)
                yield {
                    "type": "tool_output",
                    "data": {
                        "call_id": tool_call_id,
                        "tool": tool_name,
                        "output": tool_payload
                    }
                }

                messages.append(
                    ChatMessage(
                        role="tool",
                        name=tool_name or "assistant_tool",
                        tool_call_id=str(tool_call.get("id", "")),
                        content=self._guard.sanitize(
                            json.dumps(tool_payload, ensure_ascii=True),
                            source=f"assistant_{tool_name or 'tool'}",
                        ),
                    )
                )

        yield {"type": "ping", "data": {"step": "generating_final_reply"}}
        final_response = await self._chat_with_fallback(messages, allow_tools=False)
        reply = self._sanitize_reply_text(final_response.content or "") or self._format_tool_only_reply(tool_results)
        yield {"type": "reply", "data": {"text": reply}}

        next_context = await self._build_next_context(
            saved_context=saved_context,
            history=history,
            prompt=prompt,
            reply=reply,
            tool_results=tool_results,
            target=target,
            target_type=target_type,
        )
        yield {"type": "context", "data": {"next_context": next_context}}

    def _build_context_block(
        self,
        *,
        project_id: str | None,
        target: str,
        target_type: str,
        context: str,
        saved_context: str,
    ) -> str:
        parts = [
            "Frontend assistant context:",
            f"- project_id: {project_id or ''}",
            f"- target: {target or ''}",
            f"- target_type: {target_type or ''}",
        ]
        if saved_context.strip():
            parts.append("- saved_context:")
            parts.append(saved_context.strip())
        if context.strip():
            parts.append(f"- live_context: {context.strip()}")
        return "\n".join(parts)

    async def _chat_with_fallback(
        self,
        messages: list[ChatMessage],
        *,
        allow_tools: bool = True,
    ):
        tool_payload = (
            [
                _RUN_CUSTOM_SCHEMA,
                _SEARCH_PROJECT_VECTORS_SCHEMA,
                _GET_PAGE_SCHEMA,
                _ADD_FINDING_TO_BRAIN_SCHEMA,
                _MARK_FALSE_POSITIVE_SCHEMA,
            ]
            if allow_tools
            else None
        )

        async def _call_primary():
            return await self._llm.chat(
                messages,
                tools=tool_payload,
                temperature=0.2,
                max_tokens=_MAX_REPLY_TOKENS,
                max_retries=0,
            )

        try:
            return await self._queue.call_with_queue("assistant", _call_primary())
        except Exception as exc:
            error_text = str(exc).lower()
            is_rate_limit = "429" in error_text or "rate limit" in error_text
            
            if isinstance(exc, httpx.HTTPStatusError):
                recovered = self._recover_from_failed_generation(exc)
                if recovered is not None:
                    logger.warning("assistant_recovered_failed_generation_tool_call")
                    return recovered

            if not is_rate_limit:
                raise

            backup_llm = await self._backup.get_backup_llm()
            if backup_llm is None:
                raise

            logger.info("assistant_backup_llm_fallback", error=error_text)
            return await backup_llm.chat(
                messages,
                tools=tool_payload,
                temperature=0.2,
                max_tokens=_MAX_REPLY_TOKENS,
            )

    @staticmethod
    def _parse_tool_call_args(
        tool_call: dict[str, Any],
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        function = tool_call.get("function", {}) if isinstance(tool_call, dict) else {}
        raw_args = function.get("arguments", "{}")
        if isinstance(raw_args, dict):
            args = raw_args
        else:
            try:
                args = json.loads(str(raw_args or "{}"))
            except json.JSONDecodeError:
                args = {}
        return coerce_args_from_schema(schema, args)

    async def _execute_run_custom(self, args: dict[str, Any], *, target: str) -> dict[str, Any]:
        command = str(args.get("command", "")).strip()
        reason = str(args.get("reason", "")).strip() or "User-requested diagnostic command"
        raw_args = args.get("args", [])
        if not isinstance(raw_args, list):
            raw_args = []
        timeout = args.get("timeout", 300)
        env = args.get("env", {})
        cwd = args.get("cwd")
        normalized_args = [str(item) for item in raw_args]

        scope_issue = self._assistant_scope_issue_for_command(
            command=command,
            args=normalized_args,
            target=target,
        )
        if scope_issue:
            return {
                "success": False,
                "command": command,
                "args": normalized_args,
                "reason": reason,
                "error": scope_issue,
                "return_code": -1,
                "execution_time": 0.0,
                "logged": False,
            }

        return await asyncio.to_thread(
            assistant_run_custom,
            command=command,
            args=normalized_args,
            reason=reason,
            timeout=int(timeout) if str(timeout).strip() else 300,
            env=env if isinstance(env, dict) else {},
            cwd=str(cwd) if cwd else None,
        )

    async def _execute_search_project_vectors(
        self,
        args: dict[str, Any],
        *,
        project_id: str | None,
        target: str,
        target_type: str,
    ) -> dict[str, Any]:
        resolved_project_id = str(project_id or "").strip()
        raw_limit = args.get("limit", 5)
        raw_kinds = args.get("kinds", [])
        if not isinstance(raw_kinds, list):
            raw_kinds = []
        return await assistant_search_project_vectors(
            project_id=resolved_project_id,
            query=str(args.get("query", "")).strip(),
            limit=int(raw_limit) if str(raw_limit).strip() else 5,
            kinds=[str(item).strip() for item in raw_kinds if str(item).strip()],
            target=target,
            target_type=target_type,
        )

    async def _execute_get_page(self, args: dict[str, Any], *, target: str) -> dict[str, Any]:
        url = str(args.get("url", "")).strip()
        scope_issue = describe_url_scope_issue(url, target)
        if scope_issue:
            return {
                "success": False,
                "url": url,
                "css_selector": str(args.get("css_selector", "")).strip(),
                "error": (
                    "Assistant page access is limited to the current target. "
                    f"{scope_issue}"
                ),
            }
        return await assistant_get_page(
            url=url,
            css_selector=str(args.get("css_selector", "")).strip(),
        )

    async def _execute_add_finding_to_brain(
        self,
        args: dict[str, Any],
        *,
        project_id: str | None,
    ) -> dict[str, Any]:
        from server.api.dependencies import projects_store
        title = str(args.get("title", "")).strip()
        description = str(args.get("description", "")).strip()
        severity = str(args.get("severity", "info")).strip()
        status = str(args.get("status", "not_done")).strip()
        
        return assistant_add_finding_to_brain(
            project_id=str(project_id or "").strip(),
            title=title,
            description=description,
            severity=severity,
            status=status,
            project_store=projects_store,
        )

    async def _execute_mark_false_positive(
        self,
        args: dict[str, Any],
        *,
        project_id: str | None,
    ) -> dict[str, Any]:
        from server.api.dependencies import projects_store
        finding_id = str(args.get("finding_id", "")).strip()
        reason = str(args.get("reason", "")).strip()
        return await assistant_mark_false_positive(
            project_id=str(project_id or "").strip(),
            finding_id=finding_id,
            reason=reason,
            project_store=projects_store,
        )

    def _assistant_scope_issue_for_command(
        self,
        *,
        command: str,
        args: list[str],
        target: str,
    ) -> str | None:
        normalized_command = str(command or "").strip().lower()
        if normalized_command not in _ASSISTANT_NETWORK_COMMANDS:
            return (
                "Assistant command execution is limited to current-target network diagnostics. "
                f"'{normalized_command or command}' is not allowed in assistant chat."
            )
        target_host, target_port = extract_target_host_port(target)
        matched_target = False
        skip_next = False
        for i, token in enumerate(args):
            if skip_next:
                skip_next = False
                continue

            clean = str(token or "").strip().strip("'\"")
            if not clean:
                continue

            # Handle flags that take non-target arguments (like credentials)
            if clean.startswith("-"):
                # curl -u, wget --user, etc.
                if normalized_command == "curl" and clean in {"-u", "--user", "-E", "--cert", "-x", "--proxy", "-U", "--proxy-user"}:
                    skip_next = True
                elif normalized_command == "wget" and clean in {"--user", "--password", "--proxy-user", "--proxy-password"}:
                    skip_next = True
                elif normalized_command == "ffuf" and clean in {"-w", "-H", "-X", "-p", "-d", "-r", "-ac", "-acc", "-ach", "-ack", "-acs", "-act", "-af", "-ao", "-as", "-cc", "-ck", "-cs", "-ct", "-d", "-h", "-header", "-p", "-proxy", "-r", "-v", "-w", "-X"}:
                    # ffuf has many flags, some take values we should skip.
                    # Especially -w (wordlist), -H (header), -X (method), -p (pause/proxy), -d (data).
                    if clean in {"-w", "-H", "-X", "-p", "-d", "-proxy", "-header"}:
                        skip_next = True
                elif normalized_command == "sqlmap" and clean in {"--data", "--header", "--cookie", "--user-agent", "--referer", "--proxy", "--proxy-cred", "--auth-type", "--auth-cred"}:
                    skip_next = True
                elif normalized_command == "gobuster" and clean in {"-w", "-H", "-P", "-U", "-a", "-c", "-p", "-s", "-t"}:
                    if clean in {"-w", "-H", "-P", "-U", "-p"}:
                        skip_next = True
                elif normalized_command == "nuclei" and clean in {"-t", "-tags", "-et", "-it", "-author", "-severity"}:
                    if clean in {"-t", "-tags", "-et", "-it"}:
                        skip_next = True
                continue

            if " " in clean:
                continue
            if clean.lower() in {
                "port",
                "host",
                "target",
                "url",
                "ip",
                "user",
                "pass",
                "password",
                "username",
                "service",
                "version",
                "path",
            }:
                continue
            issue = describe_url_scope_issue(clean, target)
            if issue:
                return (
                    "Assistant command execution is limited to the current target. "
                    f"{issue}"
                )
            if not target_host:
                continue
            if clean == target_host:
                matched_target = True
                continue
            if target_port is not None and clean == f"{target_host}:{target_port}":
                matched_target = True
                continue
            if target_host in clean and ("://" in clean or clean.startswith(f"{target_host}/")):
                matched_target = True
                continue
            if "__IP_" in clean or "__HOST_" in clean:
                matched_target = True
                continue
            if normalized_command in {"dig", "nslookup", "nmap"} and ("." in clean or ":" in clean):
                return (
                    "Assistant command execution is limited to the current target. "
                    f"'{clean}' does not match the active target {target_host}."
                )
            if normalized_command == "openssl" and clean == "-connect":
                continue
        if target_host and not matched_target:
            return (
                "Assistant command execution is limited to the current target. "
                f"Include the active target host {target_host} in the command."
            )
        return None

    @staticmethod
    def _parse_direct_command_prompt(
        prompt: str,
        *,
        target: str = "",
    ) -> dict[str, Any] | None:
        text = str(prompt or "").strip()
        if not text:
            return None

        lowered = text.lower()
        normalized_target = str(target or "").strip()

        if "nmap" in lowered and "script vuln" in lowered and normalized_target:
            return {
                "command": "nmap",
                "args": ["-sV", "--script", "vuln", normalized_target],
                "reason": "User-requested assistant vulnerability scan with Nmap against the configured target",
            }

        prefixes = ("run ", "execute ", "run command ", "execute command ")
        command_text = ""
        for prefix in prefixes:
            if lowered.startswith(prefix):
                command_text = text[len(prefix):].strip()
                break
        if not command_text and text.split(" ", 1)[0] in _DIRECT_COMMAND_BINARIES:
            command_text = text

        if not command_text:
            return None

        # Let the LLM/tool path interpret vague natural-language requests instead
        # of sending prose fragments directly to the shell.
        if lowered.startswith(prefixes) and not any(
            marker in command_text for marker in ("-", "--", "/")
        ):
            prose_markers = (" with ", " to ", " for ", " using ", " against ", " on the target")
            if any(marker in f" {command_text.lower()} " for marker in prose_markers):
                return None

        try:
            parts = shlex.split(command_text)
        except ValueError:
            return None
        if not parts:
            return None
        first = str(parts[0]).strip().lower()
        if not first or first in _VAGUE_COMMAND_TOKENS:
            return None
        if lowered.startswith(prefixes):
            if first not in _DIRECT_COMMAND_BINARIES and not any(ch in first for ch in ("-", "/", ".")):
                return None

        return {
            "command": parts[0],
            "args": parts[1:],
            "reason": f"User-requested command execution from assistant chat: {parts[0]}",
        }

    @staticmethod
    def _extract_embedded_tool_call(content: str) -> dict[str, Any] | None:
        _, tool_calls = AssistantAgent._extract_inline_tool_calls(content)
        if tool_calls:
            return tool_calls[0]

        text = str(content or "").strip()
        if not text:
            return None

        match = re.search(
            r"<function/(?P<name>[a-zA-Z0-9_]+)>\s*(?P<args>\{.*\})\s*</function>",
            text,
            flags=re.DOTALL,
        )
        if not match:
            return None

        tool_name = str(match.group("name") or "").strip()
        raw_args = str(match.group("args") or "").strip()
        if not tool_name or not raw_args:
            return None

        try:
            parsed_args = json.loads(raw_args)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed_args, dict):
            return None

        return {
            "id": f"embedded-{tool_name}",
            "type": "function",
            "function": {
                "name": tool_name,
                "arguments": json.dumps(parsed_args, ensure_ascii=True),
            },
        }

    @staticmethod
    def _extract_inline_tool_calls(raw_content: str) -> tuple[str, list[dict[str, Any]]]:
        text = str(raw_content or "").strip()
        if not text:
            return raw_content, []

        patterns = [
            re.compile(
                r"<function>\s*(?P<name>[a-zA-Z0-9_]+)\s*(?P<args>\{.*?\})\s*</function>",
                flags=re.DOTALL,
            ),
            re.compile(
                r"<function\((?P<name>[a-zA-Z0-9_]+)\)\s*>?\s*(?P<args>\{.*?\})\s*</function>",
                flags=re.DOTALL,
            ),
            re.compile(
                r"<function=(?P<name>[a-zA-Z0-9_]+)\s*>?\s*(?P<args>\{.*?\})\s*</function>",
                flags=re.DOTALL,
            ),
            re.compile(
                r"<function=(?P<name>[a-zA-Z0-9_]+)\s*(?P<args>\{.*?\})\s*</function>",
                flags=re.DOTALL,
            ),
            re.compile(
                r"<function=(?P<name>[a-zA-Z0-9_]+)\s*>?\s*(?P<args>\{.+)",
                flags=re.DOTALL,
            ),
        ]

        for pattern in patterns:
            match = pattern.search(text)
            if not match:
                continue
            tool_name = str(match.group("name") or "").strip()
            raw_args = str(match.group("args") or "").strip()
            if not tool_name or not raw_args:
                continue
            try:
                parsed_args = json.loads(raw_args)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed_args, dict):
                continue
            tool_calls = [
                {
                    "id": f"embedded-{tool_name}",
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(parsed_args, ensure_ascii=True),
                    },
                }
            ]
            cleaned_text = pattern.sub("", text).strip()
            return cleaned_text, tool_calls
        return raw_content, []

    @classmethod
    def _sanitize_reply_text(cls, raw_content: str) -> str:
        text, _ = cls._extract_inline_tool_calls(raw_content)
        cleaned = str(text or "").strip()
        if not cleaned:
            return ""
        cleaned = re.sub(r"<function/[^>]+>\s*\{.*?\}\s*</function>", "", cleaned, flags=re.DOTALL).strip()
        cleaned = re.sub(r"<function>\s*[a-zA-Z0-9_]+\s*\{.*?\}\s*</function>", "", cleaned, flags=re.DOTALL).strip()
        return cleaned

    @classmethod
    def _recover_from_failed_generation(cls, exc: httpx.HTTPStatusError) -> LLMResponse | None:
        try:
            err_payload = exc.response.json()
        except Exception:
            return None
        if not isinstance(err_payload, dict):
            return None
        error = err_payload.get("error", {})
        if not isinstance(error, dict):
            return None
        if str(error.get("code", "")).strip().lower() != "tool_use_failed":
            return None
        failed_gen = str(error.get("failed_generation", "")).strip()
        if not failed_gen:
            return None
        cleaned_content, inline_tool_calls = cls._extract_inline_tool_calls(failed_gen)
        if not inline_tool_calls:
            return None
        return LLMResponse(
            content=cleaned_content,
            tool_calls=inline_tool_calls,
            finish_reason="tool_calls",
            usage={},
        )

    @staticmethod
    def _answer_scope_question(prompt: str, *, target: str, target_type: str) -> str | None:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return None
        if not any(marker in lowered for marker in _ASSISTANT_SCOPE_QUESTION_PATTERNS):
            return None
        active_target = str(target or "").strip() or "the current target"
        active_type = str(target_type or "").strip() or "target"
        return (
            f"No. Echo is scoped to the current project and current target only: "
            f"{active_target} ({active_type}). It should not read or answer from other projects or targets."
        )

    @staticmethod
    def _answer_capability_question(prompt: str, *, target: str, target_type: str) -> str | None:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return None
        heuristic_match = (
            ("tool" in lowered and any(token in lowered for token in ("have", "use", "available", "access")))
            or ("command" in lowered and any(token in lowered for token in ("have", "run", "available")))
            or ("access" in lowered and any(token in lowered for token in ("what", "which", "have")))
        )
        if not heuristic_match and not any(marker in lowered for marker in _ASSISTANT_CAPABILITY_QUESTION_PATTERNS):
            return None

        target_label = str(target or "").strip() or "the current target"
        type_label = str(target_type or "").strip() or "target"
        
        return (
            f"I am Echo, your PentaForge assistant for {target_label} ({type_label}).\n\n"
            "I have access to the current project's security findings, verified evidence, and diagnostic tools "
            "required to help you interpret scan results and plan your next steps. My access is strictly "
            "limited to the active target to ensure a secure and focused pentesting environment.\n\n"
            "How can I help you with the current report or target analysis today?"
        )

    async def _handle_report_intent(
        self,
        prompt: str,
        *,
        project_id: str | None = None,
        target: str = "",
        target_type: str = "",
    ) -> str | None:
        """Detect report-generation intent and generate a report."""
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return None
        if not any(pattern in lowered for pattern in _ASSISTANT_REPORT_INTENT_PATTERNS):
            return None
        if not project_id:
            return (
                "I can generate a pentest report, but no project is currently active. "
                "Please select a project first, then ask me again."
            )

        try:
            from server.api.dependencies import projects_store

            project = projects_store.get_project(project_id)
            if not isinstance(project, dict):
                return "I couldn't find the project to generate a report for. Please check that the project exists."

            result = await generate_report(project_id, projects_store)
            report_id = str(result["report_id"])
            content = str(result["content"])
            created_at = str(result["created_at"])
            metadata = result.get("metadata", {})

            # Save markdown report.
            projects_store.save_report(
                project_id,
                report_id=report_id,
                format="markdown",
                content=content,
                metadata=metadata,
            )

            # Generate and save HTML report.
            from server.api.routes.reports import _markdown_to_html

            target_label = str(metadata.get("target", target)).strip() or project_id
            html_content = _markdown_to_html(content, target=target_label, generated_at=created_at)
            projects_store.save_report(
                project_id,
                report_id=str(uuid.uuid4()),
                format="html",
                content=html_content,
                metadata=metadata,
            )

            verified = metadata.get("verified_findings", 0)
            total = metadata.get("total_findings", 0)

            return (
                f"I've generated a comprehensive penetration testing report for **{target_label}**.\n\n"
                f"📊 **Report Summary**: {total} total findings, {verified} verified vulnerabilities.\n\n"
                "The report is now available on the **Reports** page where you can:\n"
                "- 📄 **View** the full report in Markdown or HTML format\n"
                "- ⬇️ **Download** it as PDF, HTML, or Markdown\n\n"
                "Head to the Reports tab to view and download your report."
            )

        except Exception as exc:
            logger.warning(
                "assistant_report_generation_failed",
                project_id=project_id,
                error=str(exc),
                exc_info=True,
            )
            return (
                f"I tried to generate a report but encountered an error: {str(exc).strip() or type(exc).__name__}. "
                "You can also try generating it from the Reports page directly."
            )

    @staticmethod
    def _resolve_follow_up_command_from_history(
        prompt: str,
        *,
        history: list[dict[str, Any]] | None,
    ) -> dict[str, Any] | None:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return None

        follow_up_markers = (
            "run it",
            "execute it",
            "give me the result",
            "show me the result",
            "run that",
            "execute that",
        )
        if not any(marker in lowered for marker in follow_up_markers):
            return None
        if not isinstance(history, list):
            return None

        for item in reversed(history):
            if not isinstance(item, dict):
                continue
            if str(item.get("role", "")).strip().lower() != "assistant":
                continue
            text = str(item.get("text", "")).strip()
            if not text:
                continue

            embedded = AssistantAgent._extract_embedded_tool_call(text)
            if embedded is not None:
                function = embedded.get("function", {})
                raw_args = function.get("arguments", "{}")
                try:
                    parsed = json.loads(str(raw_args or "{}"))
                except json.JSONDecodeError:
                    parsed = {}
                if isinstance(parsed, dict):
                    command = str(parsed.get("command", "")).strip()
                    if command:
                        return {
                            "command": command,
                            "args": [str(arg) for arg in parsed.get("args", []) if str(arg).strip()],
                            "reason": str(parsed.get("reason", "")).strip() or "Follow-up execution of the assistant's previously proposed command",
                            "timeout": int(parsed.get("timeout", 120) or 120),
                        }

            command_match = re.search(r"Command:\s*`([^`]+)`", text)
            if not command_match:
                continue
            try:
                parts = shlex.split(command_match.group(1))
            except ValueError:
                continue
            if not parts:
                continue
            first = str(parts[0]).strip().lower()
            if not first or first in _VAGUE_COMMAND_TOKENS:
                continue
            return {
                "command": parts[0],
                "args": parts[1:],
                "reason": "Follow-up execution of the assistant's previously referenced command",
            }

        return None

    @staticmethod
    def _format_direct_command_reply(result: dict[str, Any]) -> str:
        command = str(result.get("full_command") or result.get("command") or "").strip()
        success = bool(result.get("success"))
        stdout = str(result.get("stdout") or "").strip()
        stderr = str(result.get("stderr") or "").strip()
        error = str(result.get("error") or "").strip()

        parts = [f"Command: `{command}`", f"Status: {'success' if success else 'failed'}"]
        if stdout:
            parts.append(f"Stdout:\n```\n{stdout[:6000]}\n```")
        if stderr:
            parts.append(f"Stderr:\n```\n{stderr[:3000]}\n```")
        if error and not stderr:
            parts.append(f"Error: {error}")
        return "\n\n".join(parts)

    @staticmethod
    def _format_tool_only_reply(tool_results: list[dict[str, Any]]) -> str:
        if not tool_results:
            return "No useful answer was produced."
        result = tool_results[-1]
        if isinstance(result, dict) and "results" in result:
            rows = result.get("results", [])
            if isinstance(rows, list) and rows:
                lines = ["I searched the web and found:"]
                for row in rows[:5]:
                    if not isinstance(row, dict):
                        continue
                    title = str(row.get("title", "")).strip() or "Result"
                    url = str(row.get("url", "")).strip()
                    snippet = str(row.get("snippet", "")).strip()
                    lines.append(f"- {title}")
                    if url:
                        lines.append(f"  {url}")
                    if snippet:
                        lines.append(f"  {snippet}")
                return "\n".join(lines)
        if isinstance(result, dict) and "url" in result and "text" in result:
            page_text = str(result.get("text", "")).strip()
            page_url = str(result.get("url", "")).strip()
            if page_text:
                prefix = f"I fetched {page_url}." if page_url else "I fetched the requested page."
                return f"{prefix}\n\n{page_text[:3000]}"
        matches = result.get("matches", [])
        if isinstance(matches, list) and matches:
            lines = ["I searched the saved project knowledge and found:"]
            for match in matches[:5]:
                if not isinstance(match, dict):
                    continue
                title = str(match.get("title", "")).strip() or "Project knowledge match"
                kind = str(match.get("kind", "")).strip() or "artifact"
                excerpt = str(match.get("excerpt", "")).strip()
                lines.append(f"- [{kind}] {title}")
                if excerpt:
                    lines.append(f"  {excerpt}")
            return "\n".join(lines)
        return AssistantAgent._format_direct_command_reply(result)

    async def _build_next_context(
        self,
        *,
        saved_context: str,
        history: list[dict[str, Any]] | None,
        prompt: str,
        reply: str,
        tool_results: list[dict[str, Any]],
        target: str,
        target_type: str,
    ) -> str:
        history_excerpt: list[str] = []
        if isinstance(history, list):
            for item in history[-6:]:
                if not isinstance(item, dict):
                    continue
                role = str(item.get("role", "")).strip().lower()
                text = str(item.get("text", "")).strip()
                if role not in {"user", "assistant"} or not text:
                    continue
                history_excerpt.append(f"{role}: {text[:260]}")

        tool_summaries: list[str] = []
        for row in tool_results[-4:]:
            if not isinstance(row, dict):
                continue
            if "matches" in row:
                matches = row.get('matches', [])
                summary_parts = [f"project_vector_hits={len(matches)}"]
                for m in matches[:3]:
                    m_id = str(m.get('metadata', {}).get('record_id') or m.get('id', '')).strip()
                    m_title = str(m.get('title', '')).strip()[:60]
                    if m_id:
                        summary_parts.append(f"hit_id={m_id} title=\"{m_title}\"")
                tool_summaries.append(" ".join(summary_parts))
                continue
            if "results" in row:
                tool_summaries.append(f"web_results={len(row.get('results', []))}")
                continue
            if "url" in row and "text" in row:
                tool_summaries.append(f"page_fetch={str(row.get('url', '')).strip()}")
                continue
            command = str(row.get("full_command") or row.get("command") or "").strip()
            if command:
                tool_summaries.append(f"command={command}")

        user_content = "\n".join(
            [
                f"Target: {target}",
                f"Target type: {target_type}",
                "Existing compressed context:",
                saved_context.strip() or "(none)",
                "",
                "Recent history excerpt:",
                "\n".join(history_excerpt) or "(none)",
                "",
                f"Latest user prompt: {prompt.strip()}",
                f"Latest assistant reply: {reply.strip()}",
                "Latest tool summary:",
                "\n".join(tool_summaries) or "(none)",
            ]
        )
        try:
            response = await self._chat_with_fallback(
                [
                    ChatMessage(role="system", content=CONTEXT_COMPRESSION_PROMPT),
                    ChatMessage(role="user", content=user_content),
                ],
                allow_tools=False,
            )
            text = str(response.content or "").strip()
            if text:
                return text[:_MAX_CONTEXT_CHARS].strip()
        except Exception:
            logger.warning("assistant_context_compression_failed", exc_info=True)

        fallback_lines = [
            f"- target: {target or '(unknown)'}",
            f"- target_type: {target_type or '(unknown)'}",
        ]
        if saved_context.strip():
            fallback_lines.append(f"- prior_context: {saved_context.strip()[:420]}")
        fallback_lines.append(f"- latest_user_goal: {prompt.strip()[:260]}")
        fallback_lines.append(f"- latest_answer: {reply.strip()[:420]}")
        if tool_summaries:
            fallback_lines.append(f"- latest_tools: {', '.join(tool_summaries[:4])}")
        return "\n".join(fallback_lines)[:_MAX_CONTEXT_CHARS].strip()
