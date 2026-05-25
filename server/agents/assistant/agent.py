"""Lightweight assistant agent used by the frontend AI chat panel."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import shlex
import time
from urllib.parse import urlparse
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator

import httpx
import structlog

from server.agents.rate_limiter import get_backup_llm_fallback, get_global_llm_queue
from server.agents.report.report_generator import generate_report
from server.agents.tool_output_parsers import parse_ffuf_findings, summarize_tool_output
from server.config.agent import get_public_agent_config
from server.core.llm import ChatMessage, LLMClient, LLMResponse
from server.core.tool import coerce_args_from_schema
from server.layers.safety.prompt_guard import PromptInjectionGuard
from server.utils.target_scope import describe_url_scope_issue, extract_target_host_port, normalize_target_scope

from .tools import (
    ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION,
    ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION,
    ASSISTANT_GET_PAGE_TOOL_DEFINITION,
    ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION,
    ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION,
    ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION,
    ASSISTANT_SEARCH_WEB_TOOL_DEFINITION,
    add_finding_to_brain as assistant_add_finding_to_brain,
    fetch_url_content as assistant_fetch_url_content,
    get_page as assistant_get_page,
    mark_false_positive as assistant_mark_false_positive,
    run_custom as assistant_run_custom,
    search_project_vectors as assistant_search_project_vectors,
    search_web as assistant_search_web,
)
 
from .prompts import CONTEXT_COMPRESSION_PROMPT, SYSTEM_PROMPT
from .security_tools import (
    ASSISTANT_ALLOWED_NETWORK_COMMANDS,
    ASSISTANT_TARGET_OPTIONAL_COMMANDS,
)
from .config import (
    _HISTORY_TOKEN_LIMIT ,
    _MAX_TOOL_ROUNDS,
    _MAX_TOOL_CALLS_PER_ROUND,
    _MAX_TOTAL_TOOL_CALLS,
    _MAX_REPLY_TOKENS,
    _MAX_CONTEXT_CHARS,
    _MAX_PROJECT_STATE_CHARS,
)
logger = structlog.get_logger(__name__)

_ASSISTANT_BLOCKED_COMMANDS = {
    "apt",
    "apt-get",
    "apk",
    "brew",
    "bun",
    "cargo",
    "composer",
    "dnf",
    "gem",
    "go",
    "make",
    "mkdir",
    "node",
    "npm",
    "npx",
    "patch",
    "perl",
    "php",
    "pip",
    "pip3",
    "poetry",
    "python",
    "python3",
    "ruby",
    "rustc",
    "sed",
    "sh",
    "tar",
    "touch",
    "unzip",
    "vi",
    "vim",
    "yarn",
    "zsh",
    "bash",
}
_ASSISTANT_BLOCKED_ARG_FLAGS = {
    "--in-place",
    "--write-out",
    "--create-dirs",
    "--output-dir",
}

_PRIVILEGE_RETRY_COMMANDS = {
    "nmap",
    "ike-scan",
    "arp-scan",
    "tcpdump",
    "tshark",
    "masscan",
    "mtr",
}
_VAGUE_COMMAND_TOKENS = {
    "it", "that", "this", "them", "result", "results", "output", "command",
}
_ASSISTANT_NETWORK_COMMANDS = ASSISTANT_ALLOWED_NETWORK_COMMANDS
_ASSISTANT_SANDBOX_PATH_REWRITES = {
    "../share/wordlists/short.txt": "wordlists/short.txt",
    "../share/wordlists/medium.txt": "wordlists/medium.txt",
    "../share/wordlists/large.txt": "wordlists/large.txt",
    "../share/wordlists/rockyou.txt": "wordlists/rockyou.txt",
    "../share/wordlists/dns-fuzz-common.txt": "wordlists/dns-fuzz-common.txt",
    "../share/seclists": "seclists",
    "/usr/share/wordlists/pentaforge/short.txt": "wordlists/short.txt",
    "/usr/share/wordlists/pentaforge/medium.txt": "wordlists/medium.txt",
    "/usr/share/wordlists/pentaforge/large.txt": "wordlists/large.txt",
    "/usr/share/wordlists/pentaforge/rockyou.txt": "wordlists/rockyou.txt",
    "/usr/share/wordlists/pentaforge/dns-fuzz-common.txt": "wordlists/dns-fuzz-common.txt",
    "/usr/share/seclists/pentaforge": "seclists",
    "/app/server/sandbox/share/wordlists/short.txt": "wordlists/short.txt",
    "/app/server/sandbox/share/wordlists/medium.txt": "wordlists/medium.txt",
    "/app/server/sandbox/share/wordlists/large.txt": "wordlists/large.txt",
    "/app/server/sandbox/share/wordlists/rockyou.txt": "wordlists/rockyou.txt",
    "/app/server/sandbox/share/wordlists/dns-fuzz-common.txt": "wordlists/dns-fuzz-common.txt",
    "/app/server/sandbox/share/seclists": "seclists",
}
_ASSISTANT_COMMAND_REWRITES = {
    "fuf": "ffuf",
}


def _assistant_policy_error(
    command: str,
    args: list[str],
    cwd: str | None,
) -> str | None:
    normalized_command = str(command or "").strip().lower()
    if normalized_command in _ASSISTANT_BLOCKED_COMMANDS:
        return (
            f"Assistant policy blocks '{normalized_command}' because it can modify the local machine, "
            "the project, or execute arbitrary local code."
        )

    normalized_args = [str(arg or "").strip() for arg in args]
    for arg in normalized_args:
        if arg in _ASSISTANT_BLOCKED_ARG_FLAGS:
            return f"Assistant policy blocks argument '{arg}' because it can write locally."
        lowered = arg.lower()
        if lowered.startswith("--output=") or lowered.startswith("--output-file="):
            return f"Assistant policy blocks argument '{arg}' because it can write locally."
        if lowered.startswith("--directory-prefix=") or lowered.startswith("--output-dir="):
            return f"Assistant policy blocks argument '{arg}' because it can write locally."

    if cwd:
        return "Assistant policy blocks custom working directories. Commands must run without changing local workspace context."

    return None


_ASSISTANT_CAPABILITY_QUESTION_PATTERNS = (
    "who are you",
    "what are you",
    "introduce yourself",
    "what can you do",
    "what do you do",
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

_EXTERNAL_RESEARCH_INTENT_PATTERNS = (
    "search the internet",
    "search in internet",
    "search on internet",
    "search the web",
    "search in web",
    "search on web",
    "search web",
    "search internet",
    "search online",
    "look up online",
    "look it up",
    "google it",
    "google for",
    "google this",
    "find online",
    "check online",
    "browse the web",
    "browse online",
    "use the web",
    "check the latest",
    "find the latest",
    "latest cve",
    "latest advisory",
    "official docs",
    "vendor docs",
    "current information",
    "recent information",
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
_OPERATOR_MODES = ("Ask", "Investigate", "Retest", "Report")
_EXECUTION_LANES = ("lightweight", "investigation")
_RESPONSE_STYLES = ("natural", "structured", "report")
_RETEST_INTENT_PATTERNS = (
    "retest",
    "test again",
    "check again",
    "run again",
    "verify again",
    "confirm again",
    "re-verify",
    "recheck",
    "validate again",
    "still vulnerable",
)
_INVESTIGATE_INTENT_PATTERNS = (
    "investigate",
    "look into",
    "dig into",
    "figure out",
    "why is",
    "why did",
    "check",
    "scan",
    "inspect",
    "enumerate",
    "triage",
    "diagnose",
    "analyze",
    "analyse",
    "probe",
)
_CORRECTION_INTENT_PATTERNS = (
    "that's wrong",
    "that is wrong",
    "incorrect",
    "not correct",
    "actually",
    "instead",
    "don't do that",
    "do not do that",
    "false positive",
    "wrong finding",
    "bad result",
    "that's not right",
)
_CONNECTIVITY_FAILURE_PATTERNS = (
    "could not resolve host",
    "temporary failure in name resolution",
    "name or service not known",
    "failed to connect",
    "connection refused",
    "connection reset",
    "connection timed out",
    "operation timed out",
    "network is unreachable",
    "no route to host",
    "tls handshake",
    "ssl certificate",
    "certificate verify failed",
    "peer certificate",
    "handshake failure",
    "http 000",
    "returned 000",
    "status code 000",
    "timed out",
)
_RAW_TOOL_TRACE_NAMES = (
    "run_custom",
    "search_project_vectors",
    "get_page",
    "fetch_url_content",

    "add_finding_to_brain",
    "mark_false_positive",
    "search_web",
)
_RERUN_ALLOWANCE_PATTERNS = (
    "again",
    "rerun",
    "re-run",
    "retest",
    "recheck",
    "retry",
    "run it",
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
_FTP_AUTH_CONTEXT_MARKERS = (
    "ftp",
    "ftp://",
    "port 21",
    "-p21",
    " 21",
    "anonymous access",
    "vsftpd",
)
_LIGHTWEIGHT_GREETING_PATTERNS = (
    "hi",
    "hello",
    "hey",
    "yo",
    "sup",
    "good morning",
    "good afternoon",
    "good evening",
)

_STRUCTURED_FINDING_ANALYSIS_MARKERS = (
    '"finding_id"',
    '"title"',
    '"description"',
    "confirmation commands",
    "tools used",
    "verification methods",
)
_STRUCTURED_FINDING_ANALYSIS_INTENTS = (
    "explain",
    "expalne",
    "analyze",
    "analyse",
    "retest",
    "confirm",
    "verify",
    "is this real",
    "is it real",
)
_FFUF_NO_MATCH_REPLY_MARKERS = (
    "no hidden files or directories were discovered",
    "returned no matches",
    "no matches",
    "all requests returned 404",
    "no accessible pages or endpoints were identified",
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

_FETCH_URL_CONTENT_SCHEMA = {
    "type": "function",
    "function": {
        "name": ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION["name"],
        "description": ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION["description"],
        "parameters": ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION["parameters"],
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

_SEARCH_WEB_SCHEMA = {
    "type": "function",
    "function": {
        "name": ASSISTANT_SEARCH_WEB_TOOL_DEFINITION["name"],
        "description": ASSISTANT_SEARCH_WEB_TOOL_DEFINITION["description"],
        "parameters": ASSISTANT_SEARCH_WEB_TOOL_DEFINITION["parameters"],
    },
}


@dataclass
class AssistantResult:
    reply: str
    blocked: bool = False
    mode: str = "Ask"
    lane: str = "lightweight"
    style: str = "natural"
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    next_context: str = ""
    learning_signals: dict[str, Any] = field(default_factory=dict)


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

    @staticmethod
    def _normalize_lane(value: str) -> str:
        lane = str(value or "").strip().lower()
        return lane if lane in _EXECUTION_LANES else "investigation"

    @staticmethod
    def _normalize_style(value: str) -> str:
        style = str(value or "").strip().lower()
        return style if style in _RESPONSE_STYLES else "structured"

    @classmethod
    def _resolve_execution_lane(cls, *, prompt: str, operator_mode: str) -> str:
        if cls._should_use_lightweight_lane(prompt=prompt, operator_mode=operator_mode):
            return "lightweight"
        return "investigation"

    @classmethod
    def _resolve_response_style(cls, *, operator_mode: str, execution_lane: str, prompt: str) -> str:
        if operator_mode == "Report":
            return "report"
        lowered = str(prompt or "").strip().lower()
        if any(token in lowered for token in _ASSISTANT_REPORT_INTENT_PATTERNS):
            return "report"
        # Force natural style for conversational questions even if in investigation lane
        natural_triggers = (
            "what ", "how ", "why ", "when ", "who ", "where ", 
            "can you ", "could you ", "are you ", "is ", "hi", "hello", "hey",
            "explain ", "describe ", "tell me ", "summarize ", "summary ", "summarise ", "sum up ", "what's ", "how's ",
            "give ", "show ", "list ", "status ", "brief "
        )
        if lowered.startswith(natural_triggers):
            return "natural"
        return "structured"

    @staticmethod
    def _grounding_detail_for_lane(*, execution_lane: str, operator_mode: str, response_style: str) -> str:
        if response_style == "report":
            return "report"
        if execution_lane == "lightweight":
            return "minimal"
        if operator_mode == "Ask":
            return "minimal"
        return "full"

    @classmethod
    def _should_use_lightweight_lane(cls, *, prompt: str, operator_mode: str) -> bool:
        if operator_mode != "Ask":
            return False
        if cls._is_capability_question(prompt) or cls._is_scope_question(prompt):
            return True
        if cls._is_recent_turn_recall_question(prompt):
            return True
        return cls._is_lightweight_greeting(prompt)

    @staticmethod
    def _is_lightweight_greeting(prompt: str) -> bool:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return False
        compact = re.sub(r"[!?.,]+", "", lowered).strip()
        if compact in _LIGHTWEIGHT_GREETING_PATTERNS:
            return True
        return compact in {"hi there", "hello there", "hey there"}

    @staticmethod
    def _is_recent_turn_recall_question(prompt: str) -> bool:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return False
        recall_markers = (
            "last three message",
            "last 3 message",
            "last three messages",
            "last 3 messages",
            "last message",
            "previous message",
            "previous prompt",
            "my last prompt",
            "what i asked you about",
            "what did i ask",
            "what were my last",
            "what did i say",
        )
        return any(marker in lowered for marker in recall_markers)

    async def compress_history(self, history: list[dict[str, Any]]) -> str:
        """Compresses a long conversation history into a single summary block."""
        if not history:
            return ""

        history_text = "\n".join([
            f"{'User' if m.get('role') == 'user' else 'Assistant'}: {m.get('text', '')}"
            for m in history
            if m.get('text')
        ])

        user_content = (
            "Please summarize our conversation so far. Focus on:\n"
            "1. Verified vulnerabilities and evidence discovered.\n"
            "2. Tool results and investigation findings.\n"
            "3. Pending tasks or goals discussed.\n"
            "4. Technical decisions made.\n\n"
            "Conversation History:\n"
            f"{history_text}\n\n"
            "Summary:"
        )

        try:
            response = await self._chat_with_fallback(
                [
                    ChatMessage(role="system", content="You are a professional security analyst. Summarize the following pentest conversation history into a concise, high-density bulleted report that preserves all critical technical facts and discovered evidence."),
                    ChatMessage(role="user", content=user_content),
                ],
                allow_tools=False,
            )
            return str(response.content or "").strip()
        except Exception as exc:
            logger.exception("assistant_history_compression_failed")
            return f"History compression failed. (Error: {str(exc)})"

    @classmethod
    def _normalize_context_memory_payload(
        cls,
        text: str,
        *,
        operator_mode: str,
        execution_lane: str,
        response_style: str,
        learning_signals: dict[str, Any] | None = None,
    ) -> str | None:
        clean_text = str(text or "").strip()
        if not clean_text:
            return None
        try:
            parsed = json.loads(clean_text)
        except json.JSONDecodeError:
            return clean_text[:_MAX_CONTEXT_CHARS].strip()
        if not isinstance(parsed, dict):
            return clean_text[:_MAX_CONTEXT_CHARS].strip()

        normalized: dict[str, Any] = {}
        mode_value = str(parsed.get("operator_mode", "")).strip()
        normalized["operator_mode"] = mode_value if mode_value in _OPERATOR_MODES else operator_mode
        lane_value = str(parsed.get("execution_lane", "")).strip().lower()
        normalized["execution_lane"] = lane_value if lane_value in _EXECUTION_LANES else execution_lane
        style_value = str(parsed.get("response_style", "")).strip().lower()
        normalized["response_style"] = style_value if style_value in _RESPONSE_STYLES else response_style
        for key in (
            "target_facts",
            "operator_goals",
            "recent_dialogue",
            "investigation_plan",
            "hypotheses",
            "verified_evidence",
            "verdicts",
            "project_state_signals",
            "unresolved_questions",
            "next_steps",
            "recent_checks",
            "operator_corrections",
            "lessons_learned",
        ):
            raw_items = parsed.get(key, [])
            if not isinstance(raw_items, list):
                raw_items = [raw_items] if raw_items else []
            normalized[key] = [str(item).strip()[:240] for item in raw_items if str(item).strip()][:4]

        signals = learning_signals if isinstance(learning_signals, dict) else {}
        for key, values in signals.items():
            if key not in normalized or not isinstance(normalized[key], list):
                normalized[key] = []
            if not isinstance(values, list):
                values = [values] if values else []
            for value in values[:4]:
                text_value = str(value).strip()
                if text_value and text_value not in normalized[key]:
                    normalized[key].append(text_value[:240])
            normalized[key] = normalized[key][:4]
        return json.dumps(normalized, ensure_ascii=True)

    async def compress_working_memory(self, saved_context: str) -> str:
        raw = str(saved_context or "").strip()
        if not raw:
            return ""

        parsed = self._parse_saved_context_json(raw)
        operator_mode = str(parsed.get("operator_mode", "Ask")).strip()
        if operator_mode not in _OPERATOR_MODES:
            operator_mode = "Ask"
        execution_lane = self._normalize_lane(str(parsed.get("execution_lane", "investigation")).strip().lower())
        response_style = self._normalize_style(str(parsed.get("response_style", "natural")).strip().lower())
        rendered_memory = self._render_working_memory(raw) or raw[:_MAX_CONTEXT_CHARS].strip()

        user_content = "\n".join(
            [
                f"Operator mode: {operator_mode}",
                f"Execution lane: {execution_lane}",
                f"Response style: {response_style}",
                "Current structured working memory:",
                rendered_memory or "(none)",
                "",
                "Compress this working memory while preserving:",
                "1. Verified evidence and concrete technical facts.",
                "2. Active operator goals, open questions, and next steps.",
                "3. Important recent checks, corrections, and lessons learned.",
                "4. A tiny recent dialogue trace so short-term recap questions stay accurate.",
                "",
                "Return the refreshed working memory in the same structured JSON format.",
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
            normalized = self._normalize_context_memory_payload(
                str(response.content or "").strip(),
                operator_mode=operator_mode,
                execution_lane=execution_lane,
                response_style=response_style,
            )
            if normalized:
                return normalized
        except Exception:
            logger.warning("assistant_working_memory_compression_failed", exc_info=True)

        normalized = self._normalize_context_memory_payload(
            raw,
            operator_mode=operator_mode,
            execution_lane=execution_lane,
            response_style=response_style,
        )
        return normalized or rendered_memory[:_MAX_CONTEXT_CHARS].strip()

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
        mode = "Ask"
        lane = "lightweight"
        style = "natural"
        tool_results = []
        next_context = ""
        learning_signals: dict[str, Any] = {}
        
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
                mode = str(event["data"].get("mode", "Ask") or "Ask").strip() or "Ask"
                lane = str(event["data"].get("lane", "lightweight") or "lightweight").strip() or "lightweight"
                style = str(event["data"].get("style", "natural") or "natural").strip() or "natural"
            elif event["type"] == "tool_output":
                tool_results.append(event["data"]["output"])
            elif event["type"] == "learning":
                learning_signals = event["data"] if isinstance(event["data"], dict) else {}
            elif event["type"] == "context":
                next_context = event["data"]["next_context"]
        
        return AssistantResult(
            reply=reply,
            mode=mode,
            lane=lane,
            style=style,
            tool_results=tool_results,
            next_context=next_context,
            learning_signals=learning_signals,
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
        operator_mode = self._detect_operator_mode(prompt, history=history)
        execution_lane = self._resolve_execution_lane(prompt=prompt, operator_mode=operator_mode)
        response_style = self._resolve_response_style(
            operator_mode=operator_mode,
            execution_lane=execution_lane,
            prompt=prompt,
        )
        learning_signals = self._extract_learning_signals(prompt=prompt, history=history)

        if execution_lane == "lightweight" and operator_mode == "Ask":
            reply = await self._answer_lightweight_lane_prompt(
                prompt=prompt,
                target=target,
                target_type=target_type,
                project_id=project_id,
                saved_context=saved_context,
                history=history,
            )
            reply = self._normalize_reply_for_style(
                reply,
                response_style=response_style,
                prompt=prompt,
                target=target,
                tool_results=[],
            )
            next_context = await self._build_next_context(
                project_id=project_id,
                saved_context=saved_context,
                history=history,
                prompt=prompt,
                reply=reply,
                tool_results=[],
                target=target,
                target_type=target_type,
                execution_lane=execution_lane,
                response_style=response_style,
                operator_mode=operator_mode,
            )
            yield {"type": "reply", "data": {"text": reply, "route": "assistant", "mode": operator_mode, "lane": execution_lane, "style": response_style, "blocked": False}}
            yield {"type": "learning", "data": learning_signals}
            yield {"type": "context", "data": {"next_context": next_context}}
            return

        report_reply = await self._handle_report_intent(
            prompt,
            project_id=project_id,
            target=target,
            target_type=target_type,
        )
        if report_reply is not None:
            report_reply = self._normalize_reply_for_style(
                report_reply,
                response_style="report",
                prompt=prompt,
                target=target,
                tool_results=[],
            )
            next_context = await self._build_next_context(
                project_id=project_id,
                saved_context=saved_context,
                history=history,
                prompt=prompt,
                reply=report_reply,
                tool_results=[],
                target=target,
                target_type=target_type,
                execution_lane="investigation",
                response_style="report",
                operator_mode="Report",
            )
            yield {"type": "reply", "data": {"text": report_reply, "route": "assistant", "mode": "Report", "lane": "investigation", "style": "report", "blocked": False}}
            yield {"type": "learning", "data": learning_signals}
            yield {"type": "context", "data": {"next_context": next_context}}
            return

        # Prompt-driven execution shortcuts are intentionally disabled.
        # Echo should let the LLM decide whether to call tools for operator input.


        # Working-memory management (two-storage logic)
        # 1. Full history (for UI) stays intact.
        # 2. Saved backend context (for the LLM) is refreshed when near the token limit.
        compressed_history_summary = None
        history_text = "\n".join([str(m.get('text', '')) for m in (history or [])])
        parsed_context = self._parse_saved_context_json(saved_context)
        context_metrics = self.estimate_effective_context_metrics(
            project_id=project_id,
            target=target,
            target_type=target_type,
            prompt=prompt,
            context=context,
            saved_context=saved_context,
            history=history,
        )

        if context_metrics.get("should_compress_before_send") and str(saved_context or "").strip():
            yield {"type": "ping", "data": {"step": "optimizing_context"}}
            saved_context = await self.compress_working_memory(saved_context)
            parsed_context = self._parse_saved_context_json(saved_context)
            yield {"type": "context", "data": {"next_context": saved_context}}
        elif context_metrics.get("should_compress_before_send") and history:
            yield {"type": "ping", "data": {"step": "optimizing_context"}}
            
            # Generate a new summary that includes the previous one + recent history
            # We don't truncate history here; we just update the background context.
            new_summary = await self.compress_history(history)
            parsed_context["rolling_summary"] = new_summary
            saved_context = json.dumps(parsed_context)
            
            # Yield event to update the background context (working memory)
            yield {"type": "context", "data": {"next_context": saved_context}}
            
            # We also add a transient notification that WON'T be persisted to history 
            # to avoid cluttering the database with compression logs, but we still 
            # need to tell the LLM that context has changed.
            compressed_history_summary = new_summary

        context_block = self._build_context_block(
            project_id=project_id,
            target=target,
            target_type=target_type,
            prompt=prompt,
            context=context,
            saved_context=saved_context,
            external_research_allowed=self._allows_external_research(prompt),
            operator_mode=operator_mode,
            execution_lane=execution_lane,
            response_style=response_style,
            history=history,
        )
        if compressed_history_summary:
            # We just optimized in this turn
            context_block = f"PRIOR CONVERSATION SUMMARY (JUST UPDATED):\n{compressed_history_summary}\n\n{context_block}"
        elif parsed_context.get("rolling_summary"):
            # Use the existing background summary
            context_block = f"PRIOR CONVERSATION SUMMARY:\n{parsed_context.get('rolling_summary')}\n\n{context_block}"
        elif history and any(m.get("isCompressionSummary") for m in history):
            # Fallback for legacy compression messages
            summary_msg = next((m for m in history if m.get("isCompressionSummary")), None)
            if summary_msg:
                context_block = f"PRIOR CONVERSATION SUMMARY:\n{summary_msg.get('text', '')}\n\n{context_block}"

        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
            ChatMessage(role="user", content=f"{context_block}\n\nOperator prompt:\n{prompt.strip()}"),
        ]

        tool_results: list[dict[str, Any]] = []
        allow_external_research = self._allows_external_research(prompt)
        executed_signatures: set[str] = set()
        executed_repeat_guard_signatures: set[str] = set()
        stalled_rounds = 0
        total_tool_calls = 0
        prior_tool_memory = self._recent_tool_memory_from_history(history)
        allow_repeat_tools = self._should_allow_repeat_tools(prompt=prompt, operator_mode=operator_mode)
        for round_index in range(1, _MAX_TOOL_ROUNDS + 1):
            yield {"type": "ping", "data": {"step": f"round_{round_index}_thinking"}}
            try:
                response = await self._chat_with_fallback(
                    messages,
                    allow_external_research=allow_external_research,
                )
            except Exception as exc:
                if tool_results:
                    reply = self._reply_from_tool_results_after_llm_failure(
                        exc,
                        tool_results=tool_results,
                        response_style=response_style,
                        prompt=prompt,
                        target=target,
                    )
                    next_context = await self._build_next_context(
                        project_id=project_id,
                        saved_context=saved_context,
                        history=history,
                        prompt=prompt,
                        reply=reply,
                        tool_results=tool_results,
                        target=target,
                        target_type=target_type,
                        execution_lane=execution_lane,
                        response_style=response_style,
                        operator_mode=operator_mode,
                    )
                    yield {"type": "reply", "data": {"text": reply, "route": "assistant", "mode": operator_mode, "lane": execution_lane, "style": response_style, "blocked": False}}
                    yield {"type": "learning", "data": learning_signals}
                    yield {"type": "context", "data": {"next_context": next_context}}
                    return
                raise
            tool_calls = list(response.tool_calls or [])[:_MAX_TOOL_CALLS_PER_ROUND]
            if not tool_calls:
                embedded_tool_call = self._extract_embedded_tool_call(response.content or "")
                if embedded_tool_call is not None:
                    tool_calls = [embedded_tool_call]

            if not tool_calls:
                reply = self._sanitize_reply_text(response.content or "")
                if not reply:
                    reply = "No useful answer was produced."
                reply = self._normalize_reply_for_style(
                    reply,
                    response_style=response_style,
                    prompt=prompt,
                    target=target,
                    tool_results=tool_results,
                )
                next_context = await self._build_next_context(
                    project_id=project_id,
                    saved_context=saved_context,
                    history=history,
                    prompt=prompt,
                    reply=reply,
                    tool_results=tool_results,
                    target=target,
                    target_type=target_type,
                    execution_lane=execution_lane,
                    response_style=response_style,
                    operator_mode=operator_mode,
                )
                yield {"type": "reply", "data": {"text": reply, "route": "assistant", "mode": operator_mode, "lane": execution_lane, "style": response_style, "blocked": False}}
                yield {"type": "learning", "data": learning_signals}
                yield {"type": "context", "data": {"next_context": next_context}}
                return

            # Ensure tool calls have 'type': 'function' as required by some providers
            normalized_tool_calls = []
            for idx, tc in enumerate(tool_calls):
                if isinstance(tc, dict):
                    ntc = tc.copy()
                    if "type" not in ntc:
                        ntc["type"] = "function"
                    if not str(ntc.get("id", "")).strip():
                        ntc["id"] = f"call_{idx}_{int(time.time() * 1000)}"
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

            round_made_progress = False
            for idx, tool_call in enumerate(normalized_tool_calls):
                if total_tool_calls >= _MAX_TOTAL_TOOL_CALLS:
                    break
                tool_call_id = str(tool_call.get("id") or f"call_{idx}_{int(time.time() * 1000)}").strip()
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
                    cmd = self._normalize_run_custom_command(str(raw_args.get("command", "")))
                    args = self._normalize_run_custom_args(
                        str(cmd),
                        raw_args.get("args", []) if isinstance(raw_args.get("args", []), list) else [],
                    )
                    tool_input = self._render_run_custom_preview(str(cmd), args)
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
                elif tool_name == "fetch_url_content":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION["parameters"],
                    )
                    tool_input = raw_args.get("url", "")
                    tool_reason = f"Fetching external URL: {tool_input}"
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
                elif tool_name == "search_web":
                    raw_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_SEARCH_WEB_TOOL_DEFINITION["parameters"],
                    )
                    tool_input = raw_args.get("query", "")
                    tool_reason = "Searching the public web for current external information"
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

                if tool_name == "run_custom":
                    parsed_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION["parameters"],
                    )
                    parsed_args["command"] = self._normalize_run_custom_command(
                        str(parsed_args.get("command", ""))
                    )
                    parsed_args["args"] = self._normalize_run_custom_args(
                        str(parsed_args.get("command", "")),
                        parsed_args.get("args", []) if isinstance(parsed_args.get("args", []), list) else [],
                    )
                elif tool_name == "search_project_vectors":
                    parsed_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION["parameters"],
                    )
                elif tool_name == "get_page":
                    parsed_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_GET_PAGE_TOOL_DEFINITION["parameters"],
                    )
                elif tool_name == "fetch_url_content":
                    parsed_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION["parameters"],
                    )
                elif tool_name == "add_finding_to_brain":
                    parsed_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION["parameters"],
                    )
                elif tool_name == "mark_false_positive":
                    parsed_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION["parameters"],
                    )
                elif tool_name == "search_web":
                    parsed_args = self._parse_tool_call_args(
                        tool_call,
                        ASSISTANT_SEARCH_WEB_TOOL_DEFINITION["parameters"],
                    )
                else:
                    parsed_args = {}

                signature = self._tool_call_signature(tool_name, parsed_args)
                repeat_guard_signature = self._tool_repeat_guard_signature(tool_name, parsed_args)
                if signature in executed_signatures:
                    tool_payload = self._blocked_tool_payload(
                        tool_name=tool_name,
                        parsed_args=parsed_args,
                        target=target,
                        operator_mode=operator_mode,
                        error=f"Duplicate tool call blocked to prevent loops: {tool_name}",
                    )
                elif repeat_guard_signature and repeat_guard_signature in executed_repeat_guard_signatures:
                    tool_payload = self._blocked_tool_payload(
                        tool_name=tool_name,
                        parsed_args=parsed_args,
                        target=target,
                        operator_mode=operator_mode,
                        error=f"Near-duplicate tool call blocked because this check was already completed: {tool_name}",
                    )
                elif not allow_repeat_tools and signature in prior_tool_memory:
                    tool_payload = self._blocked_tool_payload(
                        tool_name=tool_name,
                        parsed_args=parsed_args,
                        target=target,
                        operator_mode=operator_mode,
                        error=f"Repeated check avoided because this was already attempted recently: {tool_name}",
                        previous_attempt=prior_tool_memory.get(signature),
                    )
                elif tool_name in {"search_web", "fetch_url_content", "get_page"} and not allow_external_research:
                    tool_payload = self._blocked_tool_payload(
                        tool_name=tool_name,
                        parsed_args=parsed_args,
                        target=target,
                        operator_mode=operator_mode,
                        error=(
                            f"External {tool_name.replace('_', ' ')} is disabled for this turn. "
                            "Ask explicitly to search the web or look something up online to allow it."
                        ),
                    )
                else:
                    executed_signatures.add(signature)
                    if repeat_guard_signature:
                        executed_repeat_guard_signatures.add(repeat_guard_signature)
                    total_tool_calls += 1
                    if tool_name not in {
                        "run_custom",
                        "search_project_vectors",
                        "get_page",
                        "fetch_url_content",
                        "add_finding_to_brain",
                        "mark_false_positive",
                        "search_web",
                    }:
                        tool_payload = {
                            "success": False,
                            "error": f"Unsupported tool: {tool_name}",
                        }
                    elif tool_name == "search_project_vectors":
                        tool_payload = await self._execute_search_project_vectors(
                            parsed_args,
                            project_id=project_id,
                            target=target,
                            target_type=target_type,
                        )
                    elif tool_name == "get_page":
                        tool_payload = await self._execute_get_page(parsed_args, target=target)
                    elif tool_name == "fetch_url_content":
                        tool_payload = await self._execute_fetch_url_content(parsed_args)
                    elif tool_name == "add_finding_to_brain":
                        tool_payload = await self._execute_add_finding_to_brain(
                            parsed_args,
                            project_id=project_id,
                        )
                    elif tool_name == "mark_false_positive":
                        false_positive_issue = self._mark_false_positive_safety_issue(
                            tool_results=tool_results,
                        )
                        if false_positive_issue:
                            tool_payload = self._blocked_tool_payload(
                                tool_name=tool_name,
                                parsed_args=parsed_args,
                                target=target,
                                operator_mode=operator_mode,
                                error=false_positive_issue,
                            )
                        else:
                            tool_payload = await self._execute_mark_false_positive(
                                parsed_args,
                                project_id=project_id,
                            )
                    elif tool_name == "search_web":
                        tool_payload = await self._execute_search_web(parsed_args)
                    else:
                        tool_payload = await self._execute_run_custom(parsed_args, target=target, project_id=project_id)
                
                tool_results.append(tool_payload)
                round_made_progress = round_made_progress or self._tool_result_has_signal(tool_payload)
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
                        tool_call_id=tool_call_id,
                        content=self._guard.sanitize(
                            json.dumps(tool_payload, ensure_ascii=True),
                            source=f"assistant_{tool_name or 'tool'}",
                        ),
                    )
                )

            if total_tool_calls >= _MAX_TOTAL_TOOL_CALLS:
                break
            if round_made_progress:
                stalled_rounds = 0
            else:
                stalled_rounds += 1
                if stalled_rounds >= 2:
                    break

        yield {"type": "ping", "data": {"step": "generating_final_reply"}}
        if self._prompt_is_direct_run_custom_request(prompt) and tool_results:
            last_result = tool_results[-1]
            if isinstance(last_result, dict) and (
                str(last_result.get("full_command", "")).strip()
                or str(last_result.get("command", "")).strip()
            ):
                reply = self._format_direct_command_reply(last_result)
            else:
                reply = self._format_tool_only_reply(tool_results)
        else:
            try:
                final_response = await self._chat_with_fallback(
                    messages,
                    allow_tools=False,
                    allow_external_research=allow_external_research,
                )
                reply = self._sanitize_reply_text(final_response.content or "") or self._format_tool_only_reply(tool_results)
            except Exception as exc:
                if not tool_results:
                    raise
                reply = self._reply_from_tool_results_after_llm_failure(
                    exc,
                    tool_results=tool_results,
                    response_style=response_style,
                    prompt=prompt,
                    target=target,
                )
        reply = self._normalize_reply_for_style(
            reply,
            response_style=response_style,
            prompt=prompt,
            target=target,
            tool_results=tool_results,
        )
        learning_signals = self._extract_learning_signals(
            prompt=prompt,
            history=history,
            tool_results=tool_results,
            reply=reply,
        )
        yield {"type": "reply", "data": {"text": reply, "route": "assistant", "mode": operator_mode, "lane": execution_lane, "style": response_style, "blocked": False}}
        yield {"type": "learning", "data": learning_signals}

        next_context = await self._build_next_context(
            project_id=project_id,
            saved_context=saved_context,
            history=history,
            prompt=prompt,
            reply=reply,
            tool_results=tool_results,
            target=target,
            target_type=target_type,
            execution_lane=execution_lane,
            response_style=response_style,
            operator_mode=operator_mode,
        )
        yield {"type": "context", "data": {"next_context": next_context}}

    async def _answer_lightweight_lane_prompt(
        self,
        *,
        prompt: str,
        target: str,
        target_type: str,
        project_id: str | None,
        saved_context: str,
        history: list[dict[str, Any]] | None,
    ) -> str:
        wants_findings_context = self._lightweight_prompt_requests_findings_context(prompt)
        prompt_lines = [
            "Lightweight assistant prompt.",
            f"Project ID: {str(project_id or '').strip() or '(none)'}",
            f"Target: {target or '(unknown)'}",
            f"Target type: {target_type or '(unknown)'}",
            f"Findings context requested: {'yes' if wants_findings_context else 'no'}",
        ]

        if wants_findings_context:
            project_state = self._render_project_state_summary(
                project_id=project_id,
                target=target,
                target_type=target_type,
                detail_level="minimal",
            )
            if project_state:
                prompt_lines.extend(["", "Minimal project state:", project_state])

            working_memory = self._render_working_memory(saved_context)
            if working_memory:
                prompt_lines.extend(["", "Working memory:", working_memory])

        recent_turns = self._render_recent_turns_text(history, limit_turns=5, max_chars=320)
        if recent_turns:
            prompt_lines.extend(["", "Recent conversation turns:", recent_turns])

        prompt_lines.extend(
            [
                "",
                "Answer briefly and naturally. Do not use tools unless the operator explicitly asks for live investigation.",
                "",
                "Operator prompt:",
                prompt.strip(),
            ]
        )

        try:
            response = await self._chat_with_fallback(
                [
                    ChatMessage(role="system", content=SYSTEM_PROMPT),
                    ChatMessage(role="user", content="\n".join(prompt_lines).strip()),
                ],
                allow_tools=False,
            )
        except Exception as exc:
            logger.warning(
                "assistant_lightweight_lane_llm_failed",
                error=repr(exc),
                project_id=project_id,
                target=target,
            )
            return "I’m having trouble reaching the model right now. Please try again in a moment."
        return self._sanitize_reply_text(str(response.content or "").strip()) or "No useful answer was produced."

    def _build_context_block(
        self,
        *,
        project_id: str | None,
        target: str,
        target_type: str,
        prompt: str,
        context: str,
        saved_context: str,
        external_research_allowed: bool,
        operator_mode: str,
        execution_lane: str,
        response_style: str,
        history: list[dict[str, Any]] | None,
    ) -> str:
        parts = [
            "Frontend assistant context:",
            f"- project_id: {project_id or ''}",
            f"- target: {target or ''}",
            f"- target_type: {target_type or ''}",
            f"- operator_mode: {operator_mode}",
            f"- execution_lane: {execution_lane}",
            f"- response_style: {response_style}",
            f"- external_research_allowed: {'yes' if external_research_allowed else 'no'}",
        ]
        grounding_detail = self._grounding_detail_for_lane(
            execution_lane=execution_lane,
            operator_mode=operator_mode,
            response_style=response_style,
        )
        project_state = self._render_project_state_summary(
            project_id=project_id,
            target=target,
            target_type=target_type,
            detail_level=grounding_detail,
        )
        if project_state:
            parts.append("- unified_project_state:")
            parts.append(project_state)
        rendered_memory = self._render_working_memory(saved_context)
        has_working_memory = bool(rendered_memory.strip())
        if rendered_memory:
            parts.append("- working_memory:")
            parts.append(rendered_memory)
        investigation_brief = self._build_investigation_brief(
            prompt=prompt,
            operator_mode=operator_mode,
            target=target,
            saved_context=saved_context,
        )
        if investigation_brief:
            parts.append("- investigation_brief:")
            parts.append(investigation_brief)
        recent_turns = self._render_recent_turns_text(
            history,
            limit_turns=4 if has_working_memory else 5,
            max_chars=220 if has_working_memory else 800,
        )
        if recent_turns:
            parts.append("- recent_conversation_turns:")
            parts.append(recent_turns)
        if not has_working_memory:
            recent_checks = self._render_recent_checks_from_history(history)
            if recent_checks:
                parts.append("- recent_completed_checks:")
                parts.append(recent_checks)
            
        if context.strip():
            parts.append(f"- live_context: {context.strip()}")
        return "\n".join(parts)

    @staticmethod
    def _estimate_text_tokens(text: str) -> int:
        return max(0, math.ceil(len(str(text or "")) / 4))

    def estimate_effective_context_metrics(
        self,
        *,
        project_id: str | None,
        target: str,
        target_type: str,
        prompt: str,
        context: str,
        saved_context: str,
        history: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        operator_mode = self._detect_operator_mode(prompt, history=history)
        execution_lane = self._resolve_execution_lane(prompt=prompt, operator_mode=operator_mode)
        response_style = self._resolve_response_style(
            operator_mode=operator_mode,
            execution_lane=execution_lane,
            prompt=prompt,
        )

        context_block = self._build_context_block(
            project_id=project_id,
            target=target,
            target_type=target_type,
            prompt=prompt,
            context=context,
            saved_context=saved_context,
            external_research_allowed=self._allows_external_research(prompt),
            operator_mode=operator_mode,
            execution_lane=execution_lane,
            response_style=response_style,
            history=history,
        )
        parsed_context = self._parse_saved_context_json(saved_context)
        if parsed_context.get("rolling_summary"):
            context_block = f"PRIOR CONVERSATION SUMMARY:\n{parsed_context.get('rolling_summary')}\n\n{context_block}"
        elif history and any(m.get("isCompressionSummary") for m in history):
            summary_msg = next((m for m in history if m.get("isCompressionSummary")), None)
            if summary_msg:
                context_block = f"PRIOR CONVERSATION SUMMARY:\n{summary_msg.get('text', '')}\n\n{context_block}"

        user_content = f"{context_block}\n\nOperator prompt:\n{prompt.strip()}"
        effective_tokens = self._estimate_text_tokens(SYSTEM_PROMPT) + self._estimate_text_tokens(user_content)
        display_parts: list[str] = []
        normalized_saved_context = str(saved_context or "").strip()
        if normalized_saved_context:
            display_parts.append(normalized_saved_context)
        elif history:
            recent_checks = self._render_recent_checks_from_history(history)
            if recent_checks:
                display_parts.append(recent_checks)
            recent_turns = self._render_recent_turns_text(history)
            if recent_turns:
                display_parts.append(recent_turns)
        display_tokens = self._estimate_text_tokens("\n\n".join(part for part in display_parts if part.strip()))
        threshold_tokens = int(_HISTORY_TOKEN_LIMIT * 0.95)
        return {
            "display_tokens": display_tokens,
            "effective_tokens": effective_tokens,
            "limit_tokens": _HISTORY_TOKEN_LIMIT,
            "threshold_tokens": threshold_tokens,
            "should_compress_before_send": effective_tokens > threshold_tokens,
            "operator_mode": operator_mode,
            "execution_lane": execution_lane,
            "response_style": response_style,
            "has_working_memory": bool(str(saved_context or "").strip()),
            "uses_recent_history_fallback": (not str(saved_context or "").strip()) and bool(history),
        }

    @staticmethod
    def _parse_saved_context_json(saved_context: str) -> dict[str, Any]:
        raw = str(saved_context or "").strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @classmethod
    def _build_investigation_brief(
        cls,
        *,
        prompt: str,
        operator_mode: str,
        target: str,
        saved_context: str,
    ) -> str:
        if operator_mode not in {"Investigate", "Retest"}:
            return ""
        parsed = cls._parse_saved_context_json(saved_context)
        unresolved = parsed.get("unresolved_questions", []) if isinstance(parsed.get("unresolved_questions"), list) else []
        hypotheses = parsed.get("hypotheses", []) if isinstance(parsed.get("hypotheses"), list) else []
        prior_verdicts = parsed.get("verdicts", []) if isinstance(parsed.get("verdicts"), list) else []

        focus = str(prompt or "").strip()[:240]
        lines = [f"  focus: {focus or 'Active target investigation'}"]
        if hypotheses:
            lines.append(f"  prior_hypothesis: {str(hypotheses[0]).strip()[:180]}")
        if unresolved:
            lines.append(f"  open_question: {str(unresolved[0]).strip()[:180]}")
        if prior_verdicts:
            lines.append(f"  previous_verdict: {str(prior_verdicts[0]).strip()[:180]}")

        if operator_mode == "Retest":
            steps = [
                "Compare the request against the strongest saved evidence or prior verdict.",
                f"Run one narrow confirmation step on {target or 'the active target'} instead of repeating broad checks.",
                "Revise the verdict to confirmed, false_positive, or needs_retest based on the new result.",
            ]
        else:
            steps = [
                "Ground the question in saved findings, scan memory, reports, and recent observability first.",
                f"Collect one or two safe live checks on {target or 'the active target'} only where the answer depends on fresh evidence.",
                "Revise the conclusion and choose the best-supported verdict before proposing the next step.",
            ]
        for index, step in enumerate(steps, start=1):
            lines.append(f"  step_{index}: {step}")
        return "\n".join(lines)[:900]

    @classmethod
    def _render_project_state_summary(
        cls,
        *,
        project_id: str | None,
        target: str,
        target_type: str,
        detail_level: str = "full",
    ) -> str:
        safe_project_id = str(project_id or "").strip()
        if not safe_project_id:
            return ""
        try:
            from server.api.dependencies import projects_store
        except Exception:
            logger.warning("assistant_project_store_import_failed", exc_info=True)
            return ""

        try:
            project = projects_store.get_project(safe_project_id)
            if not isinstance(project, dict):
                return ""
            lines: list[str] = []
            findings_lines = cls._render_findings_summary(
                project,
                target=target,
                limit=2 if detail_level == "minimal" else 6,
            )
            if findings_lines:
                lines.append("  findings:")
                lines.extend(f"  - {line}" for line in findings_lines)
            memory_lines = cls._render_scan_memory_summary(
                project,
                compact=(detail_level == "minimal"),
            )
            if memory_lines:
                lines.append("  scan_memory:")
                lines.extend(f"  - {line}" for line in memory_lines)
            report_lines = cls._render_report_summary(project_id=safe_project_id, project=project, projects_store=projects_store)
            if report_lines:
                lines.append("  reports:")
                lines.extend(f"  - {line}" for line in report_lines)
            if detail_level != "minimal":
                observability_lines = cls._render_observability_summary(project_id=safe_project_id, project=project, projects_store=projects_store)
                if observability_lines:
                    lines.append("  observability:")
                    lines.extend(f"  - {line}" for line in observability_lines)
                run_lines = cls._render_task_run_summary(project_id=safe_project_id, target=target, target_type=target_type, projects_store=projects_store)
                if run_lines:
                    lines.append("  task_runs:")
                    lines.extend(f"  - {line}" for line in run_lines)
            return "\n".join(lines)[:_MAX_PROJECT_STATE_CHARS].strip()
        except Exception:
            logger.warning("assistant_project_state_summary_failed", project_id=safe_project_id, exc_info=True)
            return ""

    @staticmethod
    def _finding_matches_target(finding: dict[str, Any], target: str) -> bool:
        finding_target = str(finding.get("target", "") or finding.get("url", "")).strip()
        if not target or not finding_target:
            return True
        return describe_url_scope_issue(finding_target, target) is None

    @staticmethod
    def _finding_verdict_label(status: str) -> str:
        normalized = str(status or "").strip().lower()
        if normalized in {"false_positive", "dismissed"}:
            return "false_positive"
        if normalized in {"verified", "confirmed", "real_vulnerability"}:
            return "confirmed"
        if normalized in {"open", "observed"}:
            return "observed"
        if normalized in {"needs_retest", "retest"}:
            return "needs_retest"
        if normalized in {"likely", "suspected"}:
            return "likely"
        return normalized or "observed"

    @classmethod
    def _render_findings_summary(cls, project: dict[str, Any], *, target: str, limit: int = 6) -> list[str]:
        findings = project.get("findings", [])
        if not isinstance(findings, list):
            return []
        rows: list[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if not cls._finding_matches_target(finding, target):
                continue
            title = str(finding.get("title", "")).strip()
            if not title:
                continue
            finding_id = str(finding.get("id", "")).strip() or "unknown"
            citation = f"[project:finding:{finding_id}]"
            verdict = cls._finding_verdict_label(str(finding.get("status", "")).strip())
            severity = str(finding.get("severity", "")).strip().lower()
            description = str(finding.get("description", "")).strip()
            line = f"{title} {citation} verdict={verdict}"
            if severity:
                line += f" severity={severity}"
            if description:
                line += f": {description[:160]}"
            rows.append(line)
        return rows[:max(1, limit)]

    @staticmethod
    def _load_target_memory_from_project(project: dict[str, Any]) -> dict[str, Any]:
        last_scan = project.get("lastScan", {})
        if not isinstance(last_scan, dict):
            return {}
        result = last_scan.get("result", {})
        if not isinstance(result, dict):
            return {}
        memory = result.get("targetMemory")
        if not isinstance(memory, dict):
            memory = result.get("system_memory", {})
        if not isinstance(memory, dict):
            return {}

        path_candidates = [
            str(memory.get("json", "")).strip(),
            str((memory.get("paths", {}) or {}).get("json", "")).strip() if isinstance(memory.get("paths"), dict) else "",
        ]
        for path in path_candidates:
            if not path or not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    loaded = json.load(handle)
                if isinstance(loaded, dict):
                    return loaded
            except Exception:
                logger.warning("assistant_target_memory_read_failed", path=path, exc_info=True)
        return memory

    @classmethod
    def _render_scan_memory_summary(cls, project: dict[str, Any], *, compact: bool = False) -> list[str]:
        memory = cls._load_target_memory_from_project(project)
        if not isinstance(memory, dict) or not memory:
            return []
        rows: list[str] = []
        overview = str(memory.get("overview") or memory.get("target_overview") or "").strip()
        if overview:
            rows.append(f"overview: {overview[:180]}")
        tech_stack = memory.get("tech_stack")
        if isinstance(tech_stack, list) and tech_stack:
            rows.append(f"tech_stack: {', '.join(str(item).strip() for item in tech_stack[:8] if str(item).strip())}")
        elif isinstance(tech_stack, str) and tech_stack.strip():
            rows.append(f"tech_stack: {tech_stack.strip()[:180]}")
        observed_routes = memory.get("observed_routes", [])
        if isinstance(observed_routes, list) and observed_routes and not compact:
            rows.append(f"observed_routes={len(observed_routes)} sample={', '.join(str(route).strip() for route in observed_routes[:3])}")
        verified_findings = memory.get("verified_findings", [])
        if isinstance(verified_findings, list):
            for item in verified_findings[: (1 if compact else 3)]:
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title", "")).strip()
                claim_status = str(item.get("claim_status", "")).strip() or cls._finding_verdict_label(str(item.get("status", "")).strip())
                citations = item.get("cited_tool_output_ids", [])
                cited = ", ".join(str(c).strip() for c in citations[:3] if str(c).strip()) if isinstance(citations, list) else ""
                if title:
                    line = f"memory_finding: {title} verdict={claim_status}"
                    if cited:
                        line += f" cited_tool_output_ids={cited}"
                    rows.append(line)
        tool_observations = memory.get("tool_observations", [])
        if isinstance(tool_observations, list) and tool_observations and not compact:
            recent = []
            for observation in tool_observations[-2:]:
                if not isinstance(observation, dict):
                    continue
                tool_name = str(observation.get("tool", "")).strip()
                status = str(observation.get("status", "")).strip()
                if tool_name:
                    recent.append(f"{tool_name}:{status or 'observed'}")
            if recent:
                rows.append(f"recent_tool_observations: {', '.join(recent)}")
        return rows[: (3 if compact else 6)]

    @classmethod
    def _render_report_summary(
        cls,
        *,
        project_id: str,
        project: dict[str, Any],
        projects_store: Any,
    ) -> list[str]:
        report_status = projects_store.list_report_status(project_id)
        report = projects_store.get_report(project_id, format="markdown")
        rows: list[str] = []
        if isinstance(report_status, dict):
            rows.append(
                "availability: "
                f"markdown={'yes' if report_status.get('markdown') else 'no'} "
                f"html={'yes' if report_status.get('html') else 'no'} "
                f"pdf={'yes' if report_status.get('pdf') else 'no'}"
            )
            generated_at = str(report_status.get("generated_at", "")).strip()
            if generated_at:
                rows.append(f"latest_generated_at: {generated_at}")
        if isinstance(report, dict):
            metadata = report.get("metadata", {})
            if isinstance(metadata, dict):
                verified = metadata.get("verified_findings")
                total = metadata.get("total_findings")
                if verified is not None or total is not None:
                    rows.append(f"report_counts: verified={verified if verified is not None else '?'} total={total if total is not None else '?'}")
            content = str(report.get("content", "")).strip()
            first_heading = ""
            for line in content.splitlines():
                stripped = line.strip().lstrip("#").strip()
                if stripped:
                    first_heading = stripped
                    break
            if first_heading:
                rows.append(f"latest_report_heading: {first_heading[:180]}")
        elif isinstance(project.get("findings"), list):
            rows.append(f"report_absent_findings_present={len(project.get('findings', []))}")
        return rows[:4]

    @classmethod
    def _render_observability_summary(
        cls,
        *,
        project_id: str,
        project: dict[str, Any],
        projects_store: Any,
    ) -> list[str]:
        last_scan = project.get("lastScan", {})
        scan_id = str(last_scan.get("scanId", "")).strip() if isinstance(last_scan, dict) else ""
        snapshot = projects_store.get_scan_observability_snapshot(project_id, scan_id=scan_id or None, limit=20)
        if not isinstance(snapshot, dict):
            return []
        rows: list[str] = []
        metrics = snapshot.get("metrics", {})
        if isinstance(metrics, dict) and metrics:
            metric_parts: list[str] = []
            for key in (
                "verified_vulnerability_count",
                "false_positive_count",
                "tool_failure_rate",
                "resume_success_rate",
            ):
                if key in metrics:
                    metric_parts.append(f"{key}={metrics.get(key)}")
            if metric_parts:
                rows.append("metrics: " + ", ".join(metric_parts))
        timeline = snapshot.get("timeline", [])
        if isinstance(timeline, list) and timeline:
            interesting = []
            for event in timeline[-4:]:
                if not isinstance(event, dict):
                    continue
                label = str(event.get("event", "")).strip() or "event"
                message = str(event.get("message", "")).strip()
                if message:
                    interesting.append(f"{label}: {message[:120]}")
            if interesting:
                rows.append("recent_timeline: " + " | ".join(interesting[:3]))
        return rows[:3]

    @classmethod
    def _render_task_run_summary(
        cls,
        *,
        project_id: str,
        target: str,
        target_type: str,
        projects_store: Any,
    ) -> list[str]:
        rows: list[str] = []
        active_runs = projects_store.list_active_task_runs(project_id)
        if isinstance(active_runs, list) and active_runs:
            active_labels = []
            for run in active_runs[:3]:
                if not isinstance(run, dict):
                    continue
                task_type = str(run.get("task_type", "")).strip() or "task"
                status = str(run.get("status", "")).strip() or "unknown"
                active_labels.append(f"{task_type}:{status}")
            if active_labels:
                rows.append("active=" + ", ".join(active_labels))
        scope_key = normalize_target_scope(target, target_type)
        latest_assistant = projects_store.get_latest_task_run(
            project_id,
            task_type="assistant",
            scope_key=scope_key or None,
            statuses=["completed", "running", "failed", "cancelled"],
        )
        if isinstance(latest_assistant, dict):
            rows.append(
                "latest_assistant="
                f"{str(latest_assistant.get('status', '')).strip() or 'unknown'}"
            )
        latest_report = projects_store.get_latest_task_run(
            project_id,
            task_type="report",
            statuses=["completed", "running", "failed"],
        )
        if isinstance(latest_report, dict):
            rows.append(f"latest_report_run={str(latest_report.get('status', '')).strip() or 'unknown'}")
        return rows[:3]

    @staticmethod
    def _render_working_memory(saved_context: str) -> str:
        raw = str(saved_context or "").strip()
        if not raw:
            return ""
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return raw[:_MAX_CONTEXT_CHARS].strip()
        if not isinstance(parsed, dict):
            return raw[:_MAX_CONTEXT_CHARS].strip()

        ordered_fields = (
            ("operator_mode", "operator mode"),
            ("execution_lane", "execution lane"),
            ("response_style", "response style"),
            ("target_facts", "target facts"),
            ("operator_goals", "operator goals"),
            ("recent_dialogue", "recent dialogue"),
            ("investigation_plan", "investigation plan"),
            ("hypotheses", "hypotheses"),
            ("verified_evidence", "verified evidence"),
            ("verdicts", "verdicts"),
            ("project_state_signals", "project state signals"),
            ("unresolved_questions", "unresolved questions"),
            ("next_steps", "next steps"),
            ("recent_checks", "recent checks"),
            ("operator_corrections", "operator corrections"),
            ("lessons_learned", "lessons learned"),
        )
        lines: list[str] = []
        for key, label in ordered_fields:
            raw_items = parsed.get(key, [])
            if isinstance(raw_items, str):
                clean_items = [raw_items.strip()] if raw_items.strip() else []
            elif isinstance(raw_items, list):
                clean_items = [str(item).strip() for item in raw_items if str(item).strip()]
            else:
                continue
            if not clean_items:
                continue
            lines.append(f"  {label}:")
            for item in clean_items[:4]:
                lines.append(f"  - {item}")
        return "\n".join(lines)[:_MAX_CONTEXT_CHARS].strip()

    @staticmethod
    def _render_recent_checks_from_history(history: list[dict[str, Any]] | None) -> str:
        if not isinstance(history, list):
            return ""
        rows: list[str] = []
        for item in history[-8:]:
            if not isinstance(item, dict):
                continue
            if str(item.get("role", "")).strip().lower() != "assistant":
                continue
            tool_logs = item.get("toolLogs", [])
            if not isinstance(tool_logs, list):
                continue
            for log in tool_logs[-3:]:
                if not isinstance(log, dict):
                    continue
                status = str(log.get("status", "")).strip().lower()
                tool = str(log.get("tool", "")).strip()
                raw_input = log.get("input")
                rendered_input = raw_input if isinstance(raw_input, str) else json.dumps(raw_input, ensure_ascii=True)
                if tool and rendered_input and status == "done":
                    rows.append(f"  - {tool}: {rendered_input[:180]}")
        return "\n".join(rows[-6:])

    @staticmethod
    def _render_recent_turns_text(
        history: list[dict[str, Any]] | None,
        *,
        limit_turns: int = 5,
        max_chars: int = 800,
    ) -> str:
        if not isinstance(history, list) or not history:
            return ""

        turns: list[str] = []
        for m in history[-max(1, limit_turns):]:
            if not isinstance(m, dict):
                continue
            if m.get("isCompressionSummary"):
                continue
            role = "User" if str(m.get("role", "")).lower() == "user" else "Assistant"
            text = str(m.get("text", "")).strip()
            if text:
                turns.append(f"{role}: {text[:max(60, max_chars)]}")

    @staticmethod
    def _tool_schemas_for_turn(*, allow_external_research: bool) -> list[dict[str, Any]]:
        schemas = [
            _RUN_CUSTOM_SCHEMA,
            _SEARCH_PROJECT_VECTORS_SCHEMA,
            _GET_PAGE_SCHEMA,
            _ADD_FINDING_TO_BRAIN_SCHEMA,
            _MARK_FALSE_POSITIVE_SCHEMA,
        ]
        if allow_external_research:
            schemas.append(_FETCH_URL_CONTENT_SCHEMA)
            schemas.append(_SEARCH_WEB_SCHEMA)
        return schemas

    async def _chat_with_fallback(
        self,
        messages: list[ChatMessage],
        *,
        allow_tools: bool = True,
        allow_external_research: bool = False,
        allow_backup_fallback: bool = True,
    ):
        tool_payload = self._tool_schemas_for_turn(allow_external_research=allow_external_research) if allow_tools else None

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
            fallback_statuses = {429, 500, 502, 503, 504}
            status_code = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None else None
            is_transient_provider_failure = (
                status_code in fallback_statuses
                or "429" in error_text
                or "rate limit" in error_text
                or "503" in error_text
                or "service unavailable" in error_text
            )

            if isinstance(exc, httpx.HTTPStatusError):
                recovered = self._recover_from_failed_generation(exc)
                if recovered is not None:
                    logger.warning("assistant_recovered_failed_generation_tool_call")
                    return recovered

            if not is_transient_provider_failure:
                raise

            if not allow_backup_fallback:
                raise

            backup_llm = await self._backup.get_backup_llm()
            if backup_llm is None:
                raise

            logger.info("assistant_backup_llm_fallback", error=error_text, status=status_code)
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

    @staticmethod
    def _normalize_run_custom_command(command: str) -> str:
        normalized = str(command or "").strip()
        if not normalized:
            return ""
        return _ASSISTANT_COMMAND_REWRITES.get(normalized.lower(), normalized)

    @classmethod
    def _prompt_is_direct_run_custom_request(cls, prompt: str) -> bool:
        text = str(prompt or "").strip()
        if not text or "\n" in text:
            return False
        try:
            parts = shlex.split(text)
        except ValueError:
            return False
        if not parts:
            return False
        command = cls._normalize_run_custom_command(parts[0]).strip().lower()
        if not command:
            return False
        if command == "sudo" and len(parts) > 1:
            command = cls._normalize_run_custom_command(parts[1]).strip().lower()
        return command in (_ASSISTANT_NETWORK_COMMANDS | set(_ASSISTANT_COMMAND_REWRITES.values()) | {"sudo"})

    @staticmethod
    def _normalize_run_custom_args(command: str, args: list[str]) -> list[str]:
        normalized_command = str(command or "").strip().lower()
        normalized_args: list[str] = []
        for item in list(args or []):
            raw = str(item)
            if not raw:
                continue
            for piece in raw.splitlines():
                cleaned_piece = piece.strip()
                if cleaned_piece:
                    if " " in cleaned_piece and cleaned_piece.startswith(("-", "http://", "https://", "ftp://")):
                        try:
                            expanded = [part.strip() for part in shlex.split(cleaned_piece) if str(part).strip()]
                        except ValueError:
                            expanded = []
                        if expanded:
                            normalized_args.extend(expanded)
                            continue
                    normalized_args.append(
                        _ASSISTANT_SANDBOX_PATH_REWRITES.get(cleaned_piece, cleaned_piece)
                    )
        if normalized_command == "ffuf":
            has_t = False
            idx = 0
            while idx < len(normalized_args):
                if normalized_args[idx] == "-t" and idx + 1 < len(normalized_args):
                    has_t = True
                    try:
                        t_val = int(normalized_args[idx + 1])
                        if t_val > 10:
                            normalized_args[idx + 1] = "5"
                    except (ValueError, TypeError):
                        normalized_args[idx + 1] = "5"
                idx += 1
            if not has_t:
                normalized_args.extend(["-t", "5"])

        if normalized_command != "curl":
            return normalized_args

        repaired: list[str] = []
        i = 0
        while i < len(normalized_args):
            token = normalized_args[i].strip()
            if token in {"-w", "--write-out"} and i + 1 < len(normalized_args):
                repaired.append(token)
                i += 1
                fmt_parts: list[str] = []
                while i < len(normalized_args):
                    current = normalized_args[i].strip()
                    if fmt_parts and (
                        current.startswith(("http://", "https://", "ftp://"))
                        or (current.startswith("-") and not current.startswith("%{"))
                    ):
                        break
                    fmt_parts.append(current)
                    i += 1
                repaired.append(
                    AssistantAgent._clean_curl_write_out_format(
                        " ".join(part for part in fmt_parts if part).strip()
                    )
                )
                continue
            repaired.append(token)
            i += 1
        return repaired

    @staticmethod
    def _clean_curl_write_out_format(value: str) -> str:
        cleaned = str(value or "")
        cleaned = cleaned.replace("\\r", " ").replace("\\n", " ")
        cleaned = cleaned.replace("\r", " ").replace("\n", " ")
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned

    @staticmethod
    def _mask_cli_secret(value: str) -> str:
        clean = str(value or "").strip()
        if not clean:
            return clean
        if ":" in clean:
            user, secret = clean.split(":", 1)
            if user and secret:
                return f"{user}:****"
        return "****"

    @classmethod
    def _redact_sensitive_run_custom_args(cls, command: str, args: list[str]) -> list[str]:
        normalized_command = str(command or "").strip().lower()
        redacted: list[str] = []
        skip_redact_next = False
        for token in [str(arg or "").strip() for arg in list(args or []) if str(arg or "").strip()]:
            if skip_redact_next:
                redacted.append(cls._mask_cli_secret(token))
                skip_redact_next = False
                continue
            if normalized_command == "curl" and token in {"-u", "--user"}:
                redacted.append(token)
                skip_redact_next = True
                continue
            redacted.append(re.sub(r"://([^:/@\s]+):([^@/\s]+)@", r"://\1:****@", token))
        return redacted

    @classmethod
    def _render_run_custom_preview(cls, command: str, args: list[str]) -> str:
        normalized_command = str(command or "").strip()
        preview_args = cls._redact_sensitive_run_custom_args(
            normalized_command,
            [str(arg or "").strip() for arg in list(args or []) if str(arg or "").strip()],
        )
        if normalized_command.lower() == "curl":
            preview_args = list(preview_args)
            for index, token in enumerate(preview_args[:-1]):
                if token in {"-w", "--write-out"}:
                    preview_args[index + 1] = cls._clean_curl_write_out_format(preview_args[index + 1])
        if not normalized_command:
            return shlex.join(preview_args)
        return shlex.join([normalized_command, *preview_args])

    @classmethod
    def _sanitize_run_custom_result_for_display(cls, result: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(result, dict):
            return result
        command = str(result.get("command", "")).strip()
        raw_args = result.get("args", [])
        if not isinstance(raw_args, list):
            raw_args = []
        redacted_args = cls._redact_sensitive_run_custom_args(command, [str(arg) for arg in raw_args])
        payload = dict(result)
        payload["args"] = redacted_args
        if command:
            payload["full_command"] = cls._render_run_custom_preview(command, redacted_args)
        structured = summarize_tool_output(payload)
        if structured.get("observations") and not payload.get("observations"):
            payload["observations"] = structured.get("observations")
        if structured.get("output_parser") and not payload.get("output_parser"):
            payload["output_parser"] = structured.get("output_parser")
        if str(command).strip().lower() == "ffuf":
            payload["parsed_findings"] = cls._parse_ffuf_findings(payload)
        return payload

    @classmethod
    def _parse_ffuf_findings(cls, result: dict[str, Any]) -> list[dict[str, Any]]:
        return parse_ffuf_findings(result)

    async def _execute_run_custom(self, args: dict[str, Any], *, target: str, project_id: str | None = None) -> dict[str, Any]:
        command = self._normalize_run_custom_command(str(args.get("command", "")).strip())
        reason = str(args.get("reason", "")).strip() or "User-requested diagnostic command"
        raw_args = args.get("args", [])
        if not isinstance(raw_args, list):
            raw_args = []
        timeout = args.get("timeout", 300)
        env = args.get("env", {})
        cwd = args.get("cwd")
        normalized_args = self._normalize_run_custom_args(
            command,
            [str(item) for item in raw_args],
        )
        policy_error = _assistant_policy_error(command, normalized_args, str(cwd) if cwd else None)
        if policy_error:
            payload = self._blocked_tool_payload(
                tool_name="run_custom",
                parsed_args={
                    "command": command,
                    "args": normalized_args,
                    "reason": reason,
                },
                target=target,
                operator_mode="Investigate",
                error=policy_error,
            )
            payload.update(
                {
                    "command": command,
                    "args": normalized_args,
                    "reason": reason,
                    "return_code": -1,
                    "execution_time": 0.0,
                    "logged": False,
                }
            )
            return payload

        scope_issue = self._assistant_scope_issue_for_command(
            command=command,
            args=normalized_args,
            target=target,
        )
        if scope_issue:
            payload = self._blocked_tool_payload(
                tool_name="run_custom",
                parsed_args={
                    "command": command,
                    "args": normalized_args,
                    "reason": reason,
                },
                target=target,
                operator_mode="Investigate",
                error=scope_issue,
            )
            payload.update(
                {
                    "command": command,
                    "args": normalized_args,
                    "reason": reason,
                    "return_code": -1,
                    "execution_time": 0.0,
                    "logged": False,
                }
            )
            return payload

        from server.agents.executer.base import _executer_tool_context
        
        # Resolve target host/port for placeholder replacement
        target_host, target_port = extract_target_host_port(target)
        
        # Replace common placeholders in arguments if they weren't caught by PrivacyGate
        final_args: list[str] = []
        for arg in normalized_args:
            replaced = str(arg)
            if target_host:
                replaced = re.sub(r"__IP_\d+__", target_host, replaced)
                replaced = re.sub(r"__HOST_\d+__", target_host, replaced)
            if target_port is not None:
                replaced = replaced.replace("__PORT__", str(target_port))
            final_args.append(replaced)

        ctx = {
            "project_id": project_id,
            "target_url": target,
            "role": "assistant",
        }
        ctx_token = _executer_tool_context.set(ctx)

        try:
            result = await asyncio.to_thread(
                assistant_run_custom,
                command=command,
                args=final_args,
                reason=reason,
                timeout=int(timeout) if str(timeout).strip() else 300,
                env=env if isinstance(env, dict) else {},
                cwd=str(cwd) if cwd else None,
            )
        finally:
            _executer_tool_context.reset(ctx_token)

        if self._should_retry_with_sudo(command, normalized_args, result):
            sudo_args = ["-S", command, *normalized_args]
            retried = await asyncio.to_thread(
                assistant_run_custom,
                command="sudo",
                args=sudo_args,
                reason=f"{reason} (privileged retry)",
                timeout=int(timeout) if str(timeout).strip() else 300,
                env=env if isinstance(env, dict) else {},
                cwd=None,
            )
            return self._sanitize_run_custom_result_for_display(
                self._augment_command_failure_payload("sudo", sudo_args, retried)
            )
        return self._sanitize_run_custom_result_for_display(
            self._augment_command_failure_payload(command, normalized_args, result)
        )

    @classmethod
    def _augment_command_failure_payload(
        cls,
        command: str,
        args: list[str],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(result, dict) or bool(result.get("success")):
            return result

        payload = dict(result)
        likely_cause = cls._infer_command_failure_cause(command, args, payload)
        if likely_cause:
            payload["likely_cause"] = likely_cause
            current_error = str(payload.get("error", "")).strip()
            if not current_error:
                payload["error"] = likely_cause
            elif "likely cause:" not in current_error.lower():
                payload["error"] = f"{current_error}. Likely cause: {likely_cause}"
        return payload

    @classmethod
    def _infer_command_failure_cause(
        cls,
        command: str,
        args: list[str],
        result: dict[str, Any],
    ) -> str:
        normalized_command = str(command or "").strip().lower()
        return_code = int(result.get("return_code", -1) or -1)
        haystack = " ".join(
            str(result.get(key, "") or "").strip().lower()
            for key in ("stderr", "error", "stdout")
        )
        normalized_args = [str(arg or "").strip() for arg in list(args or [])]

        if "sandbox executor unavailable" in haystack:
            return (
                "The command never reached the target because backend-side command execution is configured "
                "to run only through the tool sandbox, and that sandbox executor was unavailable."
            )
        if normalized_command == "curl":
            if "getaddrinfo() thread failed to start" in haystack:
                return (
                    "The request failed inside the assistant environment while starting the hostname "
                    "resolution thread, so this is an environment-side resolver failure rather than proof "
                    "that the target hostname itself is wrong."
                )
            if "could not resolve host" in haystack or return_code == 6:
                return "The assistant environment could not resolve the target hostname, so this is a reachability problem rather than proof that the finding is false."
            if any(marker in haystack for marker in ("ssl certificate", "certificate verify failed", "peer certificate")) or return_code in {35, 51, 60}:
                return "The request failed during TLS negotiation or certificate validation, so the target may still be up even though this check did not complete."
            if "timed out" in haystack or return_code == 28:
                return "The target did not respond before the timeout, so the result is inconclusive."
        if normalized_command == "ffuf" and return_code == 2:
            if "pthread_create failed" in haystack or "runtime/cgo" in haystack:
                return (
                    "FFUF reached the sandbox but crashed while creating runtime threads, "
                    "which points to a sandbox resource limit rather than bad ffuf CLI syntax."
                )
            if any("?" in arg for arg in normalized_args):
                return "FFUF likely rejected the argument syntax; query-style probes like '?wsdl' usually need their own URL path or wordlist entry instead of the -e extension list."
            return "FFUF exit code 2 usually means invalid CLI usage or an unsupported flag/value combination."
        if cls._is_connectivity_failure_text(haystack):
            return "The latest live check failed because of connectivity or environment reachability, so the result is inconclusive."
        return ""

    @staticmethod
    def _should_retry_with_sudo(
        command: str,
        args: list[str],
        result: dict[str, Any],
    ) -> bool:
        normalized_command = str(command or "").strip().lower()
        if not normalized_command or normalized_command == "sudo":
            return False
        if normalized_command not in _PRIVILEGE_RETRY_COMMANDS:
            return False
        if bool(result.get("success")):
            return False

        haystack = " ".join(
            str(result.get(key, "") or "").strip().lower()
            for key in ("error", "stderr", "stdout")
        )
        if not haystack:
            return False

        privilege_markers = (
            "requires root",
            "required root",
            "root privileges",
            "must be root",
            "need root",
            "permission denied",
            "operation not permitted",
            "you requested a scan type which requires root privileges",
            "are you root",
            "sudo",
        )
        if not any(marker in haystack for marker in privilege_markers):
            return False

        joined_args = " ".join(args).lower()
        if normalized_command == "nmap":
            if not any(flag in joined_args for flag in ("-su", "-ss", "-o", "--traceroute", "-a")):
                if "root privileges" not in haystack and "requires root" not in haystack:
                    return False

        return True

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
        payload = await assistant_search_project_vectors(
            project_id=resolved_project_id,
            query=str(args.get("query", "")).strip(),
            limit=int(raw_limit) if str(raw_limit).strip() else 5,
            kinds=[str(item).strip() for item in raw_kinds if str(item).strip()],
            target=target,
            target_type=target_type,
        )
        return self._normalize_vector_search_payload(payload)

    async def _execute_get_page(self, args: dict[str, Any], *, target: str) -> dict[str, Any]:
        url = str(args.get("url", "")).strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            payload = self._blocked_tool_payload(
                tool_name="get_page",
                parsed_args={"url": url, "css_selector": str(args.get("css_selector", "")).strip()},
                target=target,
                operator_mode="Ask",
                error=(
                    "Assistant page access requires a complete http(s) URL on the current target. "
                    f"Received: {url or '<empty>'}"
                ),
            )
            payload["url"] = url
            payload["css_selector"] = str(args.get("css_selector", "")).strip()
            return payload
        scope_issue = describe_url_scope_issue(url, target)
        if scope_issue:
            payload = self._blocked_tool_payload(
                tool_name="get_page",
                parsed_args={"url": url, "css_selector": str(args.get("css_selector", "")).strip()},
                target=target,
                operator_mode="Ask",
                error=(
                    "Assistant page access is limited to the current target. "
                    f"{scope_issue}"
                ),
            )
            payload["url"] = url
            payload["css_selector"] = str(args.get("css_selector", "")).strip()
            return payload
        return await assistant_get_page(
            url=url,
            css_selector=str(args.get("css_selector", "")).strip(),
        )

    async def _execute_fetch_url_content(self, args: dict[str, Any]) -> dict[str, Any]:
        url = str(args.get("url", "")).strip()
        return await assistant_fetch_url_content(
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

    async def _execute_search_web(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).strip()
        raw_limit = args.get("max_results", 5)
        result = await assistant_search_web(
            query=query,
            max_results=int(raw_limit) if str(raw_limit).strip() else 5,
        )
        if isinstance(result, dict):
            result["approval_mode"] = "explicit_user_request"
            result["query"] = query
        return result

    @classmethod
    def _mark_false_positive_safety_issue(
        cls,
        *,
        tool_results: list[dict[str, Any]],
    ) -> str:
        if not cls._tool_results_include_connectivity_failure(tool_results):
            return ""
        if cls._tool_results_have_explicit_contradictory_evidence(tool_results):
            return ""
        return (
            "Automatic false-positive marking is blocked because the latest live evidence only shows "
            "DNS, TLS, timeout, or connectivity failure. This should stay in needs_retest until you "
            "have direct contradictory evidence."
        )

    @staticmethod
    def _detect_operator_mode(prompt: str, *, history: list[dict[str, Any]] | None = None) -> str:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return "Ask"
        if any(pattern in lowered for pattern in _ASSISTANT_REPORT_INTENT_PATTERNS):
            return "Report"
        if any(pattern in lowered for pattern in _RETEST_INTENT_PATTERNS):
            return "Retest"
        if any(pattern in lowered for pattern in _INVESTIGATE_INTENT_PATTERNS):
            return "Investigate"
        if isinstance(history, list):
            for item in reversed(history[-4:]):
                if not isinstance(item, dict):
                    continue
                prior_mode = str(item.get("mode", "")).strip()
                if prior_mode in _OPERATOR_MODES:
                    return prior_mode
        return "Ask"

    @staticmethod
    def _should_allow_repeat_tools(*, prompt: str, operator_mode: str) -> bool:
        lowered = str(prompt or "").strip().lower()
        if operator_mode == "Retest":
            return True
        return any(token in lowered for token in _RERUN_ALLOWANCE_PATTERNS)

    @classmethod
    def _recent_tool_memory_from_history(cls, history: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
        memory: dict[str, dict[str, Any]] = {}
        if not isinstance(history, list):
            return memory
        for item in history[-10:]:
            if not isinstance(item, dict):
                continue
            if str(item.get("role", "")).strip().lower() != "assistant":
                continue
            timestamp = str(item.get("timestamp", "")).strip()
            tool_logs = item.get("toolLogs", [])
            if not isinstance(tool_logs, list):
                continue
            for log in tool_logs:
                if not isinstance(log, dict):
                    continue
                tool = str(log.get("tool", "")).strip()
                if not tool:
                    continue
                raw_input = log.get("input")
                if tool == "run_custom" and isinstance(raw_input, str):
                    try:
                        parts = shlex.split(raw_input)
                    except ValueError:
                        parts = raw_input.split()
                    args = {
                        "command": parts[0] if parts else "",
                        "args": parts[1:] if len(parts) > 1 else [],
                    }
                elif tool == "search_project_vectors":
                    args = {"query": str(raw_input or "").strip()}
                elif tool == "get_page":
                    args = {"url": str(raw_input or "").strip()}
                elif tool == "fetch_url_content":
                    args = {"url": str(raw_input or "").strip()}
                elif tool == "search_web":
                    args = {"query": str(raw_input or "").strip()}
                else:
                    args = {"input": raw_input}
                signature = cls._tool_call_signature(tool, args)
                memory[signature] = {
                    "tool": tool,
                    "input": raw_input,
                    "timestamp": timestamp,
                    "output": log.get("output"),
                }
        return memory

    @classmethod
    def _extract_learning_signals(
        cls,
        *,
        prompt: str,
        history: list[dict[str, Any]] | None = None,
        tool_results: list[dict[str, Any]] | None = None,
        reply: str = "",
    ) -> dict[str, Any]:
        lowered = str(prompt or "").strip().lower()
        corrections: list[str] = []
        lessons: list[str] = []

        if any(pattern in lowered for pattern in _CORRECTION_INTENT_PATTERNS):
            corrections.append(str(prompt or "").strip()[:240])
        if "false positive" in lowered:
            lessons.append("The operator flagged a prior result or finding as a false positive; require stronger evidence before treating similar claims as confirmed.")
        if "don't" in lowered or "do not" in lowered:
            lessons.append(str(prompt or "").strip()[:240])

        for row in list(tool_results or [])[-4:]:
            if not isinstance(row, dict):
                continue
            if bool(row.get("success")) and str(row.get("status", "")).strip().lower() == "done":
                title = str(row.get("title", "")).strip()
                if title:
                    lessons.append(f"Operator-added finding recorded: {title}.")
            if bool(row.get("success")) and str(row.get("status", "")).strip().lower() == "false_positive":
                title = str(row.get("title", "")).strip()
                lessons.append(
                    f"Finding {title or 'unknown finding'} was marked false positive; avoid re-promoting it without new evidence."
                )
            error = str(row.get("error", "")).strip()
            recommendation = row.get("recommendation", {})
            if error and isinstance(recommendation, dict):
                suggested = str(recommendation.get("summary", "")).strip()
                if suggested:
                    lessons.append(f"When blocked, pivot to: {suggested}")

        if isinstance(history, list):
            for item in reversed(history[-5:]):
                if not isinstance(item, dict):
                    continue
                learning = item.get("learningSignals")
                if isinstance(learning, dict):
                    for text in learning.get("operator_corrections", [])[:2]:
                        value = str(text).strip()
                        if value:
                            corrections.append(value[:240])
                    for text in learning.get("lessons_learned", [])[:2]:
                        value = str(text).strip()
                        if value:
                            lessons.append(value[:240])
                    break

        deduped_corrections = cls._dedupe_short_lines(corrections, limit=4)
        deduped_lessons = cls._dedupe_short_lines(lessons + ([reply[:240]] if "false positive" in reply.lower() else []), limit=4)
        return {
            "operator_corrections": deduped_corrections,
            "lessons_learned": deduped_lessons,
        }

    @staticmethod
    def _dedupe_short_lines(lines: list[str], *, limit: int) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for line in lines:
            normalized = " ".join(str(line or "").split()).strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(normalized[:240])
            if len(result) >= limit:
                break
        return result

    @classmethod
    def _blocked_tool_payload(
        cls,
        *,
        tool_name: str,
        parsed_args: dict[str, Any],
        target: str,
        operator_mode: str,
        error: str,
        previous_attempt: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        recommendation = cls._recommendation_for_blocked_action(
            tool_name=tool_name,
            parsed_args=parsed_args,
            target=target,
            operator_mode=operator_mode,
            previous_attempt=previous_attempt,
            error=error,
        )
        return {
            "success": False,
            "blocked": True,
            "tool": tool_name,
            "error": error,
            "recommendation": recommendation,
            "previous_attempt": previous_attempt or {},
        }

    @classmethod
    def _recommendation_for_blocked_action(
        cls,
        *,
        tool_name: str,
        parsed_args: dict[str, Any],
        target: str,
        operator_mode: str,
        previous_attempt: dict[str, Any] | None,
        error: str,
    ) -> dict[str, Any]:
        safe_target = str(target or "").strip() or "the active target"
        summary = ""
        suggested_command = ""
        if tool_name == "run_custom":
            command = str(parsed_args.get("command", "")).strip().lower()
            if command in {"python", "python3", "bash", "sh", "zsh"}:
                summary = "Pivot to a read-only network diagnostic instead of a local interpreter."
                suggested_command = f"curl -I {safe_target}" if "http" in safe_target else f"nmap -F -T4 -n {safe_target}"
            elif "scope" in error.lower() or "current target" in error.lower():
                summary = "Retry the check against the active target instead of a different host."
                suggested_command = f"nmap -F -T4 -n {safe_target}" if "http" not in safe_target else f"curl -I {safe_target}"
            elif previous_attempt:
                summary = "Build on the previous attempt instead of repeating the exact same check."
                suggested_command = cls._next_command_after_previous_attempt(previous_attempt, safe_target)
            else:
                summary = "Use the smallest safe command that can answer the current question."
                suggested_command = f"curl -I {safe_target}" if "http" in safe_target else f"nmap -F -T4 -n {safe_target}"
        elif tool_name == "get_page":
            summary = "Fetch a concrete page on the active target with a full URL."
            suggested_command = f"curl -I {safe_target}" if "http" in safe_target else ""
        elif tool_name == "search_web":
            summary = "Explicitly ask for external research if you want current public-web information."
        elif tool_name == "search_project_vectors":
            summary = "Narrow the query to a specific finding, endpoint, or evidence type."
        else:
            summary = "Use a narrower, target-scoped diagnostic step."

        next_step = summary
        if operator_mode == "Retest":
            next_step = "Compare the blocked path against the last verified evidence and choose a single confirmation check."
        elif operator_mode == "Report":
            next_step = "Summarize the blocker and cite the strongest verified evidence instead of forcing another run."

        return {
            "summary": summary or "Choose a safer next step.",
            "suggested_command": suggested_command,
            "next_step": next_step,
        }

    @staticmethod
    def _next_command_after_previous_attempt(previous_attempt: dict[str, Any], target: str) -> str:
        tool = str(previous_attempt.get("tool", "")).strip().lower()
        raw_input = str(previous_attempt.get("input", "")).strip()
        if tool == "run_custom" and raw_input.startswith("curl "):
            return f"nmap -F -T4 -n {target}" if target else "nmap -F -T4 -n <target>"
        if tool == "run_custom" and raw_input.startswith("nmap "):
            return f"curl -I {target}" if "http" in target else "openssl s_client -connect <host>:443 -brief"
        if tool == "get_page":
            return f"curl -I {target}" if "http" in target else ""
        return f"curl -I {target}" if "http" in target else f"nmap -F -T4 -n {target}"

    @staticmethod
    def _allows_external_research(prompt: str) -> bool:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return False
        
        # Explicit block if user wants to stay offline
        if any(token in lowered for token in ("offline", "no internet", "without internet", "local only")):
            return False
            
        # Allow by default if any web-related intent is detected, 
        # or just allow by default for assistant-style queries.
        web_tokens = (
            "search", "web", "online", "google", "find", "look up", "research",
            "cve", "vuln", "advisory", "latest", "current", "recent", "news",
            "browse", "internet", "sourch", # Added sourch for the user's typo
        )
        if any(token in lowered for token in web_tokens):
            return True
            
        # Default to False for very short or non-research queries to save tokens/latency
        if len(lowered.split()) < 3:
            return False
            
        return True

    @staticmethod
    def _tool_call_signature(tool_name: str, args: dict[str, Any]) -> str:
        safe_name = str(tool_name or "").strip().lower()
        safe_args = dict(args or {})
        if "reason" in safe_args:
            safe_args["reason"] = str(safe_args.get("reason", "")).strip()[:120]
        return f"{safe_name}:{json.dumps(safe_args, sort_keys=True, ensure_ascii=True)}"

    @classmethod
    def _tool_repeat_guard_signature(cls, tool_name: str, args: dict[str, Any]) -> str:
        safe_name = str(tool_name or "").strip().lower()
        if safe_name != "run_custom":
            return ""
        command = str((args or {}).get("command", "")).strip().lower()
        raw_args = (args or {}).get("args", [])
        norm_args = raw_args if isinstance(raw_args, list) else []
        if command == "hydra":
            fingerprint = cls._hydra_attempt_fingerprint(norm_args)
            if fingerprint:
                return f"run_custom:hydra:{json.dumps(fingerprint, sort_keys=True, ensure_ascii=True)}"
        normalized_args = [str(arg).strip() for arg in norm_args if str(arg).strip()]
        if not command:
            return ""
        return f"run_custom:exact:{json.dumps({'command': command, 'args': normalized_args}, sort_keys=True, ensure_ascii=True)}"

    @staticmethod
    def _hydra_attempt_fingerprint(args: list[Any]) -> dict[str, str]:
        tokens = [str(arg).strip() for arg in args if str(arg).strip()]
        if not tokens:
            return {}
        login = ""
        password = ""
        host = ""
        service = ""
        port = ""
        idx = 0
        positionals: list[str] = []
        while idx < len(tokens):
            token = tokens[idx]
            if token in {"-l", "-L", "-p", "-P", "-s", "-m", "-t"}:
                value = tokens[idx + 1] if idx + 1 < len(tokens) else ""
                if token == "-l":
                    login = value
                elif token == "-p":
                    password = value
                elif token == "-s":
                    port = value
                idx += 2
                continue
            if token.startswith("-"):
                idx += 1
                continue
            positionals.append(token)
            idx += 1
        if positionals:
            host = positionals[0]
        if len(positionals) > 1:
            service = positionals[1].lower()
        fingerprint = {
            "login": login,
            "password": password,
            "host": host,
            "service": service,
            "port": port,
        }
        return {key: value for key, value in fingerprint.items() if value}

    @staticmethod
    def _tool_result_has_signal(result: dict[str, Any]) -> bool:
        if not isinstance(result, dict):
            return False
        if bool(result.get("success")):
            if any(isinstance(result.get(key), list) and result.get(key) for key in ("matches", "results")):
                return True
            if any(str(result.get(key, "")).strip() for key in ("stdout", "text", "reply", "citation", "summary")):
                return True
            if "count" in result and int(result.get("count", 0) or 0) > 0:
                return True
        if any(str(result.get(key, "")).strip() for key in ("stdout", "text")):
            return True
        return False

    @staticmethod
    def _tool_result_text_haystack(result: dict[str, Any]) -> str:
        if not isinstance(result, dict):
            return ""
        parts = [
            str(result.get("error", "")).strip(),
            str(result.get("stderr", "")).strip(),
            str(result.get("stdout", "")).strip(),
            str(result.get("text", "")).strip(),
            str(result.get("likely_cause", "")).strip(),
        ]
        return " ".join(part for part in parts if part).lower()

    @staticmethod
    def _is_connectivity_failure_text(text: str) -> bool:
        lowered = str(text or "").strip().lower()
        if not lowered:
            return False
        return any(marker in lowered for marker in _CONNECTIVITY_FAILURE_PATTERNS)

    @classmethod
    def _tool_result_indicates_connectivity_failure(cls, result: dict[str, Any]) -> bool:
        return cls._is_connectivity_failure_text(cls._tool_result_text_haystack(result))

    @classmethod
    def _tool_result_indicates_sandbox_execution_blocker(cls, result: dict[str, Any]) -> bool:
        haystack = cls._tool_result_text_haystack(result)
        return "sandbox executor unavailable" in haystack or (
            "tool sandbox" in haystack and "configure sandbox_executor_url" in haystack
        )

    @classmethod
    def _tool_results_include_connectivity_failure(cls, tool_results: list[dict[str, Any]]) -> bool:
        return any(
            cls._tool_result_indicates_connectivity_failure(result)
            for result in tool_results
            if isinstance(result, dict)
        )

    @classmethod
    def _tool_results_include_sandbox_execution_blocker(cls, tool_results: list[dict[str, Any]]) -> bool:
        return any(
            cls._tool_result_indicates_sandbox_execution_blocker(result)
            for result in tool_results
            if isinstance(result, dict)
        )

    @classmethod
    def _tool_results_have_explicit_contradictory_evidence(cls, tool_results: list[dict[str, Any]]) -> bool:
        for result in tool_results:
            if not isinstance(result, dict):
                continue
            if cls._tool_result_indicates_connectivity_failure(result):
                continue
            if bool(result.get("success")) and (
                str(result.get("stdout", "")).strip()
                or str(result.get("text", "")).strip()
                or str(result.get("summary", "")).strip()
            ):
                return True
            if str(result.get("status", "")).strip().lower() in {"false_positive", "confirmed", "verified"}:
                return True
        return False

    @staticmethod
    def _normalize_vector_search_payload(payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return payload
        matches = payload.get("matches", [])
        if not isinstance(matches, list):
            return payload

        normalized_matches: list[dict[str, Any]] = []
        for match in matches:
            if not isinstance(match, dict):
                continue
            metadata = match.get("metadata", {}) if isinstance(match.get("metadata"), dict) else {}
            kind = str(match.get("kind") or metadata.get("artifact_kind") or "project_artifact").strip()
            record_id = str(
                metadata.get("record_id")
                or metadata.get("recordId")
                or match.get("id")
                or metadata.get("id")
                or "unknown"
            ).strip()
            citation = f"[project:{kind}:{record_id}]"
            normalized = dict(match)
            normalized["citation"] = citation
            normalized["record_id"] = record_id
            normalized["source_label"] = str(metadata.get("title") or match.get("title") or kind).strip()
            normalized_matches.append(normalized)

        enriched = dict(payload)
        enriched["matches"] = normalized_matches
        enriched["citations"] = [row.get("citation") for row in normalized_matches if str(row.get("citation", "")).strip()]
        return enriched

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
                "Assistant command execution is limited to current-target diagnostics and approved local artifact inspection commands. "
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

            # Handle flags that take values. Some carry the target, others are harmless metadata.
            if clean.startswith("-"):
                flag_role = self._assistant_flag_value_role(normalized_command, clean)
                if flag_role and i + 1 < len(args):
                    next_value = str(args[i + 1] or "").strip().strip("'\"")
                    if flag_role == "target" and next_value:
                        issue = self._assistant_validate_target_argument(
                            next_value,
                            command=normalized_command,
                            target=target,
                            target_host=target_host,
                            target_port=target_port,
                            arg_index=i + 1,
                            total_args=len(args),
                        )
                        if issue:
                            return issue
                        matched_target = True
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
            issue = self._assistant_validate_target_argument(
                clean,
                command=normalized_command,
                target=target,
                target_host=target_host,
                target_port=target_port,
                arg_index=i,
                total_args=len(args),
            )
            if issue:
                return issue
            if self._assistant_arg_looks_target_like(
                clean,
                command=normalized_command,
                target_host=target_host,
                target_port=target_port,
                arg_index=i,
                total_args=len(args),
            ):
                matched_target = True
        if target_host and not matched_target and normalized_command not in ASSISTANT_TARGET_OPTIONAL_COMMANDS:
            return (
                "Assistant command execution is limited to the current target. "
                f"Include the active target host {target_host} in the command."
            )
        return None

    @staticmethod
    def _assistant_flag_value_role(command: str, flag: str) -> str:
        command_name = str(command or "").strip().lower()
        flag_name = str(flag or "").strip()
        target_flags: dict[str, set[str]] = {
            "curl": {"--url"},
            "ffuf": {"-u", "--url"},
            "sqlmap": {"-u", "--url"},
            "gobuster": {"-u", "--url"},
            "nuclei": {"-u", "--target", "-l", "-list"},
            "arjun": {"-u", "--url"},
            "katana": {"-u", "--url"},
            "feroxbuster": {"-u", "--url"},
            "httpx": {"-u", "-l"},
            "dalfox": {"-u", "--url"},
            "openssl": {"-connect"},
        }
        skip_flags: dict[str, set[str]] = {
            "curl": {"-u", "--user", "-E", "--cert", "-x", "--proxy", "-U", "--proxy-user", "-A", "--user-agent", "-H", "--header", "-d", "--data"},
            "wget": {"--user", "--password", "--proxy-user", "--proxy-password", "--header", "--post-data", "--method"},
            "ffuf": {"-w", "-H", "-X", "-p", "-d", "-proxy", "-header", "-e", "-request", "-request-proto", "-request-file"},
            "sqlmap": {"--data", "--header", "--cookie", "--user-agent", "--referer", "--proxy", "--proxy-cred", "--auth-type", "--auth-cred", "-r"},
            "gobuster": {"-w", "-H", "-P", "-U", "-a", "-c", "-p", "-x"},
            "nuclei": {"-t", "-tags", "-et", "-it", "-author", "-severity", "-H", "-header"},
            "arjun": {"-H", "--headers", "-d", "--data"},
            "katana": {"-list", "-H", "-header", "-d", "-data"},
            "feroxbuster": {"-w", "-H", "-x", "-X"},
            "httpx": {"-H", "-header"},
            "dalfox": {"-H", "--header", "-d", "--data"},
            "openssl": {"-servername"},
            "hydra": {"-l", "-L", "-p", "-P", "-s", "-m"},
        }
        if flag_name in target_flags.get(command_name, set()):
            return "target"
        if flag_name in skip_flags.get(command_name, set()):
            return "skip"
        return ""

    def _assistant_validate_target_argument(
        self,
        value: str,
        *,
        command: str,
        target: str,
        target_host: str,
        target_port: int | None,
        arg_index: int,
        total_args: int,
    ) -> str | None:
        clean = str(value or "").strip().strip("'\"")
        if not self._assistant_arg_looks_target_like(
            clean,
            command=command,
            target_host=target_host,
            target_port=target_port,
            arg_index=arg_index,
            total_args=total_args,
        ):
            return None
        issue = describe_url_scope_issue(clean, target)
        if issue:
            return (
                "Assistant command execution is limited to the current target. "
                f"{issue}"
            )
        return None

    @staticmethod
    def _assistant_arg_looks_target_like(
        value: str,
        *,
        command: str,
        target_host: str,
        target_port: int | None,
        arg_index: int,
        total_args: int,
    ) -> bool:
        clean = str(value or "").strip().strip("'\"")
        if not clean or " " in clean:
            return False
        if clean.startswith(("/", "./", "../", ".")):
            return False
        if clean.startswith("@") or clean.startswith("$"):
            return False
        if "," in clean and "://" not in clean:
            return False
        if "__IP_" in clean or "__HOST_" in clean:
            return True
        if "://" in clean:
            return True
        if target_host and clean == target_host:
            return True
        if target_host and target_port is not None and clean == f"{target_host}:{target_port}":
            return True
        if target_host and target_host in clean:
            return True

        strict_bare_host_commands = {"curl", "wget", "nmap", "dig", "nslookup", "whois", "openssl", "hydra", "whatweb", "nikto", "httpx"}
        if command not in strict_bare_host_commands and arg_index != total_args - 1:
            return False

        bare = clean
        if "/" in bare:
            bare = bare.split("/", 1)[0]
        if ":" in bare and bare.count(":") == 1:
            host_part, port_part = bare.rsplit(":", 1)
            if port_part.isdigit():
                bare = host_part
        if not bare or bare.startswith("."):
            return False
        if bare == "localhost":
            return True
        if bare.count(":") >= 2:
            return True
        if "." not in bare:
            return False
        labels = [segment for segment in bare.split(".") if segment]
        if len(labels) < 2:
            return False
        if not all(re.fullmatch(r"[A-Za-z0-9-]+", segment) for segment in labels):
            return False
        return True

    # DECOMMISSIONED: Direct command fast-path methods removed.
    # LLM now consistently handles intent analysis for all prompts.


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
            # Support the [tool_name]\n"query" fallback style seen occasionally
            re.compile(
                r"\[(?P<name>[a-zA-Z0-9_]+)\]\s*(?:```json\s*)?(?P<args>\{.*?\})(?:\s*```)?",
                flags=re.DOTALL,
            ),
            re.compile(
                r"\[(?P<name>[a-zA-Z0-9_]+)\]\s*\"(?P<query>[^\"]+)\"",
                flags=re.DOTALL,
            ),
        ]

        for pattern in patterns:
            match = pattern.search(text)
            if not match:
                continue
            tool_name = str(match.group("name") or "").strip()
            
            # Handle the specific `[tool_name] "query"` fallback regex group
            if "query" in match.groupdict() and match.group("query"):
                parsed_args = {"query": match.group("query")}
                raw_args = json.dumps(parsed_args)
            else:
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
        # Remove [TOOL_OUTPUT] delimiters leaked by the LLM
        cleaned = re.sub(r"\[TOOL_OUTPUT[^\]]*\].*?\[/TOOL_OUTPUT\]", "", cleaned, flags=re.DOTALL).strip()
        cleaned = re.sub(r"\[TOOL_OUTPUT[^\]]*\]", "", cleaned).strip()
        
        # Remove any lingering raw [search_web] blocks if the LLM dumped them without arguments
        cleaned = re.sub(r"\[search_web\]\s*", "", cleaned).strip()

        return cls._strip_raw_tool_trace_lines(cleaned)

    @staticmethod
    def _strip_raw_tool_trace_lines(text: str) -> str:
        lines = str(text or "").splitlines()
        if not lines:
            return ""
        tool_markers = {f"[{name}]" for name in _RAW_TOOL_TRACE_NAMES}
        cleaned_lines: list[str] = []
        skip_quoted_after_tool = False
        for raw_line in lines:
            line = raw_line.strip()
            lowered = line.lower()
            if lowered in tool_markers:
                skip_quoted_after_tool = True
                continue
            if skip_quoted_after_tool and line and (
                (line.startswith('"') and line.endswith('"'))
                or (line.startswith("'") and line.endswith("'"))
            ):
                continue
            skip_quoted_after_tool = False
            cleaned_lines.append(raw_line)
        return "\n".join(cleaned_lines).strip()

    @staticmethod
    def _looks_like_raw_tool_trace(text: str) -> bool:
        lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
        if not lines:
            return False
        tool_markers = {f"[{name}]" for name in _RAW_TOOL_TRACE_NAMES}
        tool_lines = 0
        quoted_lines = 0
        for line in lines:
            if line.lower() in tool_markers:
                tool_lines += 1
                continue
            if len(line) < 260 and ((line.startswith('"') and line.endswith('"')) or (line.startswith("'") and line.endswith("'"))):
                quoted_lines += 1
                continue
        return tool_lines >= 1 and tool_lines + quoted_lines == len(lines)

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
    def _is_scope_question(prompt: str) -> bool:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return False
        return any(marker in lowered for marker in _ASSISTANT_SCOPE_QUESTION_PATTERNS)

    @staticmethod
    def _is_capability_question(prompt: str) -> bool:
        raw_prompt = str(prompt or "").strip()
        lowered = raw_prompt.lower()
        if not lowered:
            return False

        # Do not mistake structured finding payloads or explicit analysis requests
        # for a capability question just because they mention "tools" or "access".
        if (
            ("{" in raw_prompt and '"title"' in raw_prompt)
            or ("confirmation commands" in lowered)
            or ("tools used" in lowered)
            or any(
                marker in lowered
                for marker in (
                    "explain this",
                    "explain the finding",
                    "retest it",
                    "retest this",
                    "confirm it",
                    "confirm this",
                    "analyze this",
                    "analyse this",
                    "verify this",
                    "verify it",
                )
            )
        ):
            return False

        is_question_like = (
            "?" in raw_prompt
            or lowered.startswith(("what ", "which ", "can you ", "do you ", "have you ", "list ", "who "))
        )
        heuristic_match = (
            is_question_like and (
                ("who are you" in lowered)
                or ("what are you" in lowered)
                or ("introduce yourself" in lowered)
                or ("what can you do" in lowered)
                or ("what do you do" in lowered)
                or
                ("tool" in lowered and any(token in lowered for token in ("have", "use", "available", "access")))
                or ("command" in lowered and any(token in lowered for token in ("have", "run", "available")))
                or ("access" in lowered and any(token in lowered for token in ("what", "which", "have")))
            )
        )
        return heuristic_match or any(marker in lowered for marker in _ASSISTANT_CAPABILITY_QUESTION_PATTERNS)

    @staticmethod
    def _lightweight_prompt_requests_findings_context(prompt: str) -> bool:
        lowered = str(prompt or "").strip().lower()
        if not lowered:
            return False
        findings_markers = (
            "finding",
            "findings",
            "vulnerability",
            "vulnerabilities",
            "report",
            "summary",
            "status",
            "what have you found",
            "what did you find",
            "current project",
            "active target",
        )
        return any(marker in lowered for marker in findings_markers)

    @classmethod
    def _resolve_direct_ftp_auth_attempt(
        cls,
        prompt: str,
        *,
        target: str,
        history: list[dict[str, Any]] | None,
    ) -> dict[str, Any] | None:
        username, password = cls._extract_prompt_credentials(prompt)
        if not username or not password:
            return None
        if not cls._prompt_or_history_suggests_ftp(prompt, history=history):
            return None
        target_host, target_port = extract_target_host_port(target)
        if not target_host:
            return None
        ftp_url = f"ftp://{target_host}/"
        if target_port is not None and target_port != 21:
            ftp_url = f"ftp://{target_host}:{target_port}/"
        return {
            "command": "curl",
            "args": ["-u", f"{username}:{password}", ftp_url],
            "reason": "Attempt authenticated FTP access with the operator-provided credentials.",
            "timeout": 60,
        }

    @staticmethod
    def _extract_prompt_credentials(prompt: str) -> tuple[str, str]:
        text = str(prompt or "").strip()
        if not text:
            return "", ""
        user_match = re.search(
            r"\b(?:login|username|user(?:name)?)\b(?:\s+as|\s+with|\s*[:=])?\s+([^\s,;]+)",
            text,
            flags=re.IGNORECASE,
        )
        pass_match = re.search(
            r"\bpassword\b(?:\s+is|\s+as|\s+with|\s*[:=])?\s+([^\s,;]+)",
            text,
            flags=re.IGNORECASE,
        )
        username = str(user_match.group(1) if user_match else "").strip().strip("'\"")
        password = str(pass_match.group(1) if pass_match else "").strip().strip("'\"")
        return username, password

    @classmethod
    def _prompt_or_history_suggests_ftp(
        cls,
        prompt: str,
        *,
        history: list[dict[str, Any]] | None,
    ) -> bool:
        lowered_prompt = str(prompt or "").strip().lower()
        if any(marker in lowered_prompt for marker in _FTP_AUTH_CONTEXT_MARKERS):
            return True
        if not isinstance(history, list):
            return False
        for item in reversed(history[-8:]):
            if not isinstance(item, dict):
                continue
            text = str(item.get("text", "")).strip().lower()
            if any(marker in text for marker in _FTP_AUTH_CONTEXT_MARKERS):
                return True
            tool_logs = item.get("toolLogs", [])
            if not isinstance(tool_logs, list):
                continue
            for log in reversed(tool_logs[-4:]):
                if not isinstance(log, dict):
                    continue
                raw_input = str(log.get("input", "")).strip().lower()
                if any(marker in raw_input for marker in _FTP_AUTH_CONTEXT_MARKERS):
                    return True
        return False



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
        likely_cause = str(result.get("likely_cause") or "").strip()
        recommendation = result.get("recommendation", {}) if isinstance(result.get("recommendation"), dict) else {}

        parts = [f"Command: `{command}`", f"Status: {'success' if success else 'failed'}"]
        if stdout:
            parts.append(f"Stdout:\n```\n{stdout[:6000]}\n```")
        if stderr:
            parts.append(f"Stderr:\n```\n{stderr[:3000]}\n```")
        if likely_cause:
            parts.append(f"Likely cause: {likely_cause}")
        if error and not stderr:
            parts.append(f"Error: {error}")
        if recommendation:
            summary = str(recommendation.get("summary", "")).strip()
            suggested_command = str(recommendation.get("suggested_command", "")).strip()
            next_step = str(recommendation.get("next_step", "")).strip()
            if summary:
                parts.append(f"Recommendation: {summary}")
            if suggested_command:
                parts.append(f"Suggested command: `{suggested_command}`")
            if next_step:
                parts.append(f"Next step: {next_step}")
        return "\n\n".join(parts)

    @staticmethod
    def _format_tool_only_reply(tool_results: list[dict[str, Any]]) -> str:
        if not tool_results:
            return "No useful answer was produced."
        result = tool_results[-1]
        if isinstance(result, dict) and "results" in result:
            rows = result.get("results", [])
            if isinstance(rows, list) and rows:
                query = str(result.get("query", "")).strip()
                engine = str(result.get("engine", "")).strip()
                prefix = "I searched the web and found:"
                if query:
                    prefix = f'Web search for "{query}" returned {len(rows)} relevant result(s)'
                    if engine:
                        prefix += f" via {engine}"
                    prefix += ":"
                lines = [prefix]
                for row in rows[:5]:
                    if not isinstance(row, dict):
                        continue
                    title = str(row.get("title", "")).strip() or "Result"
                    url = str(row.get("url", "")).strip()
                    snippet = str(row.get("snippet", "")).strip()
                    lines.append(f"- {title}")
                    if url:
                        lines.append(f"  URL: {url}")
                    if snippet:
                        lines.append(f"  Summary: {snippet}")
                return "\n".join(lines)
            error = str(result.get("error", "")).strip()
            if error:
                query = str(result.get("query", "")).strip() or "the requested topic"
                return f'I tried a web search for "{query}", but it did not return usable results. Reason: {error}'
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
                citation = str(match.get("citation", "")).strip()
                label = f"[{kind}] {title}"
                if citation:
                    label = f"{label} {citation}"
                if excerpt:
                    label = f"{label}: {excerpt}"
                lines.append(f"- {label}")
            return "\n".join(lines)
        recommendation = result.get("recommendation", {}) if isinstance(result.get("recommendation"), dict) else {}
        if recommendation:
            summary = str(recommendation.get("summary", "")).strip() or "The requested action was blocked."
            suggested_command = str(recommendation.get("suggested_command", "")).strip()
            next_step = str(recommendation.get("next_step", "")).strip()
            parts = [summary]
            if suggested_command:
                parts.append(f"Suggested command: `{suggested_command}`")
            if next_step:
                parts.append(next_step)
            return "\n".join(parts)
        return AssistantAgent._format_direct_command_reply(result)

    @staticmethod
    def _reply_has_required_sections(reply: str) -> bool:
        lowered = str(reply or "").lower()
        return all(
            marker in lowered
            for marker in ("summary", "verdict", "evidence", "unknowns", "next step", "confidence")
        )

    @staticmethod
    def _clean_section_text(text: str) -> str:
        cleaned = str(text or "").strip()
        cleaned = re.sub(r"^(summary|verdict|evidence|unknowns|next step|confidence)\s*:\s*", "", cleaned, flags=re.IGNORECASE)
        return cleaned.strip()

    @staticmethod
    def _salient_prompt_keywords(prompt: str) -> set[str]:
        stopwords = {
            "the", "this", "that", "with", "from", "into", "about", "what", "does", "mean",
            "tell", "them", "they", "their", "there", "here", "have", "your", "will", "would",
            "could", "should", "please", "current", "target", "whether", "actually", "which",
            "when", "where", "while", "after", "before", "then", "than", "just", "more",
            "less", "very", "also", "only", "over", "under", "again", "check", "investigate",
            "verify", "retest", "finding", "findings", "endpoint", "report", "update",
        }
        keywords: set[str] = set()
        for token in re.findall(r"[a-zA-Z0-9_/?.-]+", str(prompt or "").lower()):
            normalized = token.strip(".,:;!?()[]{}")
            if len(normalized) < 3 or normalized in stopwords:
                continue
            keywords.add(normalized)
        return keywords

    @classmethod
    def _reply_matches_prompt_focus(cls, reply: str, prompt: str) -> bool:
        keywords = cls._salient_prompt_keywords(prompt)
        if not keywords:
            return True
        lowered_reply = str(reply or "").lower()
        return any(keyword in lowered_reply for keyword in keywords)

    @classmethod
    def _structured_reply_needs_repair(
        cls,
        reply: str,
        *,
        prompt: str,
        tool_results: list[dict[str, Any]],
    ) -> bool:
        text = str(reply or "").strip()
        if not text:
            return True
        if cls._looks_like_raw_tool_trace(text):
            return True
        evidence_lines = cls._build_evidence_lines(tool_results)
        lowered = text.lower()
        if cls._tool_results_include_sandbox_execution_blocker(tool_results):
            if "sandbox" not in lowered and "executor" not in lowered:
                return True
            if "get_page(" in lowered or "attempt to fetch the page content using the get_page tool" in lowered:
                return True
        if cls._tool_results_include_ffuf_findings(tool_results):
            if cls._reply_denies_ffuf_findings(reply):
                return True
            if not cls._reply_covers_ffuf_findings(reply, tool_results):
                return True
        if evidence_lines and "no direct evidence was collected in this turn" in lowered:
            return True
        if not tool_results and cls._reply_claims_live_checks_without_evidence(text):
            return True
        if not cls._reply_matches_prompt_focus(text, prompt):
            return True
        return False

    @classmethod
    def _tool_results_include_ffuf_findings(cls, tool_results: list[dict[str, Any]]) -> bool:
        for result in tool_results:
            if not isinstance(result, dict):
                continue
            command = str(result.get("command", "")).strip().lower()
            if command != "ffuf":
                continue
            parsed = result.get("parsed_findings", [])
            if isinstance(parsed, list) and parsed:
                return True
            if cls._parse_ffuf_findings(result):
                return True
        return False

    @staticmethod
    def _reply_denies_ffuf_findings(reply: str) -> bool:
        lowered = " ".join(str(reply or "").strip().lower().split())
        return any(marker in lowered for marker in _FFUF_NO_MATCH_REPLY_MARKERS)

    @classmethod
    def _reply_covers_ffuf_findings(cls, reply: str, tool_results: list[dict[str, Any]]) -> bool:
        lowered = " ".join(str(reply or "").strip().lower().split())
        findings: list[dict[str, Any]] = []
        for result in tool_results:
            if not isinstance(result, dict):
                continue
            command = str(result.get("command", "")).strip().lower()
            if command != "ffuf":
                continue
            parsed = result.get("parsed_findings", [])
            if not isinstance(parsed, list) or not parsed:
                parsed = cls._parse_ffuf_findings(result)
            for finding in parsed:
                if isinstance(finding, dict):
                    findings.append(finding)
        if not findings:
            return True

        required = min(2, len(findings))
        covered = 0
        for finding in findings[:4]:
            path = str(finding.get("path", "")).strip().lower()
            if not path:
                continue
            variants = {path}
            normalized = path.lstrip("/")
            if normalized:
                variants.add(normalized)
                variants.add(f"/{normalized}")
                if not normalized.endswith("/"):
                    variants.add(f"/{normalized}/")
            if any(variant and variant in lowered for variant in variants):
                covered += 1
        return covered >= max(1, required)

    @staticmethod
    def _reply_claims_live_checks_without_evidence(reply: str) -> bool:
        lowered = str(reply or "").lower()
        suspicious_markers = (
            "live check",
            "i ran",
            "i checked",
            "i tested",
            "curl check",
            "http 200",
            "http 401",
            "http 403",
            "http 404",
            "http 500",
            "returned 404",
            "returned 200",
            "response code",
            "no evidence was observed in this initial check",
            "you asked two things",
        )
        return any(marker in lowered for marker in suspicious_markers)

    @classmethod
    def _build_evidence_lines(cls, tool_results: list[dict[str, Any]]) -> list[str]:
        lines: list[str] = []
        for result in tool_results[-6:]:
            if not isinstance(result, dict):
                continue
            command = str(result.get("full_command") or result.get("command") or "").strip()
            normalized_command = str(result.get("command", "")).strip().lower()
            structured = summarize_tool_output(result)
            observations = structured.get("observations", [])
            if normalized_command == "ffuf":
                parsed_findings = result.get("parsed_findings", [])
                if not isinstance(parsed_findings, list) or not parsed_findings:
                    parsed_findings = cls._parse_ffuf_findings(result)
                for finding in parsed_findings[:4]:
                    if not isinstance(finding, dict):
                        continue
                    path = str(finding.get("path", "")).strip()
                    status = str(finding.get("status", "")).strip()
                    size = str(finding.get("size", "")).strip()
                    words = str(finding.get("words", "")).strip()
                    if path and status:
                        line = f"ffuf matched `{path}` with HTTP {status}"
                        if size and words:
                            line += f" (size={size}, words={words})"
                        lines.append(line)
            elif isinstance(observations, list):
                prefix = f"`{command}`" if command else f"`{normalized_command}`" if normalized_command else "Tool output"
                for observation in observations[:3]:
                    text = str(observation or "").strip()
                    if text:
                        lines.append(f"{prefix} observed: {text}")
            matches = result.get("matches", [])
            if isinstance(matches, list):
                for match in matches[:3]:
                    if not isinstance(match, dict):
                        continue
                    title = str(match.get("title", "")).strip() or "Project evidence"
                    citation = str(match.get("citation", "")).strip()
                    excerpt = str(match.get("excerpt", "")).strip()
                    line = title
                    if citation:
                        line = f"{line} {citation}"
                    if excerpt:
                        line = f"{line}: {excerpt}"
                    lines.append(line)
            results = result.get("results", [])
            if isinstance(results, list):
                if results:
                    query = str(result.get("query", "")).strip()
                    engine = str(result.get("engine", "")).strip()
                    search_line = "Web search returned relevant public references"
                    if query:
                        search_line = f'Web search for "{query}" returned {len(results[:2])} relevant result(s)'
                    if engine:
                        search_line += f" via {engine}"
                    lines.append(search_line)
                for row in results[:2]:
                    if not isinstance(row, dict):
                        continue
                    title = str(row.get("title", "")).strip() or "Web result"
                    url = str(row.get("url", "")).strip()
                    snippet = str(row.get("snippet", "")).strip()
                    line = title
                    if url:
                        line = f"{line} ({url})"
                    if snippet:
                        line = f"{line}: {snippet}"
                    lines.append(line)
            if str(result.get("url", "")).strip() and str(result.get("text", "")).strip():
                page_line = f"Fetched {str(result.get('url', '')).strip()}: {str(result.get('text', '')).strip()[:240]}"
                lines.append(page_line)
            stdout = str(result.get("stdout", "")).strip()
            likely_cause = str(result.get("likely_cause", "")).strip()
            if command and stdout:
                lines.append(f"`{command}` observed: {stdout[:240]}")
            elif command and likely_cause:
                lines.append(f"`{command}` failed: {likely_cause}")

        deduped: list[str] = []
        seen: set[str] = set()
        for line in lines:
            normalized = " ".join(line.split()).lower()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(line)
        return deduped[:5]

    @classmethod
    def _reply_from_tool_results_after_llm_failure(
        cls,
        exc: Exception,
        *,
        tool_results: list[dict[str, Any]],
        response_style: str,
        prompt: str,
        target: str,
    ) -> str:
        last_result = tool_results[-1] if tool_results else {}
        if (
            isinstance(last_result, dict)
            and (str(last_result.get("full_command", "")).strip() or str(last_result.get("command", "")).strip())
        ):
            base_reply = cls._format_direct_command_reply(last_result)
        else:
            base_reply = cls._format_tool_only_reply(tool_results)
        error_text = str(exc).strip() or type(exc).__name__
        fallback_reply = (
            f"{base_reply}\n\n"
            "Note: I could not complete the follow-up LLM synthesis cleanly, so this reply is a direct summary "
            f"of the completed tool results. Backend detail: {error_text}"
        )
        return cls._normalize_reply_for_style(
            fallback_reply,
            response_style=response_style,
            prompt=prompt,
            target=target,
            tool_results=tool_results,
        )

    @staticmethod
    def _build_unknown_lines(tool_results: list[dict[str, Any]], summary: str) -> list[str]:
        lines: list[str] = []
        for result in tool_results[-6:]:
            if not isinstance(result, dict):
                continue
            if AssistantAgent._tool_result_indicates_sandbox_execution_blocker(result):
                lines.append("The command execution lane is blocked because the tool sandbox is unavailable.")
            if bool(result.get("success")) and not str(result.get("error", "")).strip():
                if any(isinstance(result.get(key), list) and result.get(key) for key in ("matches", "results")):
                    continue
                if any(str(result.get(key, "")).strip() for key in ("stdout", "text")):
                    continue
            error = str(result.get("error", "")).strip()
            likely_cause = str(result.get("likely_cause", "")).strip()
            if error:
                lines.append(error)
            if likely_cause:
                lines.append(f"Likely cause: {likely_cause}")
            recommendation = result.get("recommendation", {}) if isinstance(result.get("recommendation"), dict) else {}
            if recommendation:
                summary = str(recommendation.get("summary", "")).strip()
                if summary:
                    lines.append(f"Recommended pivot: {summary}")
        if not lines and "unknown" in str(summary or "").lower():
            lines.append("Some requested details remain unverified in the available evidence.")
        if not lines:
            lines.append("No major unresolved blockers surfaced in this turn, but untested assumptions should still be verified.")
        return lines[:4]

    @staticmethod
    def _estimate_confidence(tool_results: list[dict[str, Any]], unknowns: list[str]) -> str:
        strong_evidence = 0
        weak_evidence = 0
        for result in tool_results:
            if not isinstance(result, dict):
                continue
            if bool(result.get("success")) and (
                (isinstance(result.get("matches"), list) and result.get("matches"))
                or (isinstance(result.get("results"), list) and result.get("results"))
                or str(result.get("stdout", "")).strip()
                or str(result.get("text", "")).strip()
            ):
                strong_evidence += 1
            elif str(result.get("error", "")).strip():
                weak_evidence += 1
        if strong_evidence >= 2 and len(unknowns) <= 1:
            return "High - based on multiple grounded tool results."
        if strong_evidence >= 1:
            return "Medium - grounded in at least one direct tool result, with some remaining uncertainty."
        if weak_evidence:
            return "Low - the turn produced limited or conflicting evidence."
        return "Low - this answer is mostly interpretive and should be verified with direct evidence."

    @classmethod
    def _estimate_verdict(
        cls,
        tool_results: list[dict[str, Any]],
        unknowns: list[str],
        *,
        prompt: str,
    ) -> str:
        if cls._tool_results_include_sandbox_execution_blocker(tool_results):
            return "needs_retest"
        if cls._tool_results_include_connectivity_failure(tool_results) and not cls._tool_results_have_explicit_contradictory_evidence(tool_results):
            return "needs_retest"

        strong_evidence = 0
        confirmed_signals = 0
        blocked_or_failed = 0
        lowered_prompt = str(prompt or "").strip().lower()

        for result in tool_results:
            if not isinstance(result, dict):
                continue
            status = str(result.get("status", "")).strip().lower()
            kind = str(result.get("kind", "")).strip().lower()
            error = str(result.get("error", "")).strip()
            if status == "false_positive":
                return "false_positive"
            if bool(result.get("blocked")) or error:
                blocked_or_failed += 1
            if bool(result.get("success")) and (
                (isinstance(result.get("matches"), list) and result.get("matches"))
                or (isinstance(result.get("results"), list) and result.get("results"))
                or str(result.get("stdout", "")).strip()
                or str(result.get("text", "")).strip()
            ):
                strong_evidence += 1
            matches = result.get("matches", [])
            if isinstance(matches, list):
                for match in matches[:4]:
                    if not isinstance(match, dict):
                        continue
                    match_kind = str(match.get("kind", "")).strip().lower()
                    if match_kind == "verified_vulnerability":
                        confirmed_signals += 1
            if status in {"confirmed", "verified"} or kind == "verified_vulnerability":
                confirmed_signals += 1

        if "false positive" in lowered_prompt:
            return "false_positive"
        if strong_evidence >= 2 and len(unknowns) <= 1:
            return "confirmed"
        if confirmed_signals >= 1 and strong_evidence >= 1:
            return "confirmed"
        if strong_evidence >= 1 and len(unknowns) <= 1:
            return "observed"
        if strong_evidence >= 1:
            return "likely"
        if blocked_or_failed or any("recommended pivot" in row.lower() for row in unknowns):
            return "needs_retest"
        if "retest" in lowered_prompt or "verify again" in lowered_prompt or "check again" in lowered_prompt:
            return "needs_retest"
        return "likely"

    @classmethod
    def _normalize_reply_for_style(
        cls,
        reply: str,
        *,
        response_style: str,
        prompt: str,
        target: str,
        tool_results: list[dict[str, Any]],
    ) -> str:
        style = cls._normalize_style(response_style)
        text = cls._sanitize_reply_text(reply or "")
        if cls._looks_like_raw_tool_trace(text):
            text = ""
        if style == "structured":
            if text:
                return text.strip()
            if tool_results:
                fallback = cls._format_tool_only_reply(tool_results)
                return str(fallback or "").strip() or "No useful answer was produced."
            return "No useful answer was produced."
        if style == "report":
            if not text:
                text = "No report update was produced."
            return text.strip()

        text = re.sub(r"\*\*(summary|verdict|evidence|unknowns|next step|confidence)\*\*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"(?im)^(summary|verdict|evidence|unknowns|next step|confidence)\s*:\s*", "", text)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text.strip() or "No useful answer was produced."

    @staticmethod
    def _should_use_llm_context_compression(
        *,
        execution_lane: str,
        response_style: str,
        operator_mode: str,
        tool_results: list[dict[str, Any]],
        prompt: str,
        reply: str,
    ) -> bool:
        if execution_lane == "lightweight" or response_style == "natural":
            return False
        if operator_mode == "Report":
            return True
        if len(tool_results) >= 2:
            return True
        if len(str(reply or "")) >= 900:
            return True
        if len(str(prompt or "")) >= 320 and operator_mode in {"Investigate", "Retest"}:
            return True
        return False

    @classmethod
    def _ensure_structured_reply(
        cls,
        reply: str,
        *,
        tool_results: list[dict[str, Any]],
        prompt: str,
        target: str,
    ) -> str:
        text = str(reply or "").strip() or "No useful answer was produced."
        if cls._reply_has_required_sections(text):
            if not cls._structured_reply_needs_repair(
                text,
                prompt=prompt,
                tool_results=tool_results,
            ):
                return text
            text = ""

        summary = cls._clean_section_text(text.splitlines()[0] if text else "")
        if not summary:
            trimmed_prompt = " ".join(str(prompt or "").strip().split())
            if trimmed_prompt:
                summary = f"Requested action: {trimmed_prompt[:220]}"
            else:
                summary = f"Processed the request for {target or 'the active target'}, but the answer needs further validation."

        evidence_lines = cls._build_evidence_lines(tool_results)
        unknown_lines = cls._build_unknown_lines(tool_results, summary)
        verdict = cls._estimate_verdict(tool_results, unknown_lines, prompt=prompt)
        if cls._tool_results_include_sandbox_execution_blocker(tool_results):
            next_step = (
                "Restore the tool-sandbox execution path first, then rerun the blocked command. "
                "Verify SANDBOX_EXECUTOR_URL and confirm the tool-sandbox service is healthy before drawing target conclusions."
            )
        elif verdict == "false_positive":
            next_step = "Keep the finding dismissed unless new contradictory evidence appears, and document why it was ruled out."
        elif verdict == "confirmed":
            next_step = "Use the confirmed evidence to drive remediation, reporting, or one final scope-limited confirmation if the operator asks for it."
        elif evidence_lines:
            next_step = "Validate the strongest evidence path further and close the remaining unknowns."
        elif cls._allows_external_research(prompt):
            next_step = "Use the web-backed results to narrow the investigation, then verify the most relevant lead against the active target."
        else:
            next_step = f"Run one narrow verification step against {target or 'the active target'} to replace assumptions with direct evidence."
        confidence = cls._estimate_confidence(tool_results, unknown_lines)

        evidence_block = "\n".join(f"- {line}" for line in (evidence_lines or ["No direct evidence was collected in this turn."]))
        unknowns_block = "\n".join(f"- {line}" for line in unknown_lines)
        return (
            f"**Summary**\n{summary}\n\n"
            f"**Verdict**\n{verdict}\n\n"
            f"**Evidence**\n{evidence_block}\n\n"
            f"**Unknowns**\n{unknowns_block}\n\n"
            f"**Next Step**\n{next_step}\n\n"
            f"**Confidence**\n{confidence}"
        )

    async def _build_next_context(
        self,
        *,
        project_id: str | None,
        saved_context: str,
        history: list[dict[str, Any]] | None,
        prompt: str,
        reply: str,
        tool_results: list[dict[str, Any]],
        target: str,
        target_type: str,
        execution_lane: str,
        response_style: str,
        operator_mode: str,
    ) -> str:
        rendered_prior_memory = self._render_working_memory(saved_context)
        execution_lane = self._normalize_lane(execution_lane)
        response_style = self._normalize_style(response_style)
        project_state_summary = self._render_project_state_summary(
            project_id=project_id,
            target=target,
            target_type=target_type,
            detail_level=self._grounding_detail_for_lane(
                execution_lane=execution_lane,
                operator_mode=operator_mode,
                response_style=response_style,
            ),
        )
        investigation_brief = self._build_investigation_brief(
            prompt=prompt,
            operator_mode=operator_mode,
            target=target,
            saved_context=saved_context,
        )
        learning_signals = self._extract_learning_signals(
            prompt=prompt,
            history=history,
            tool_results=tool_results,
            reply=reply,
        )
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
                    m_id = str(m.get('record_id') or m.get('metadata', {}).get('record_id') or m.get('id', '')).strip()
                    m_title = str(m.get('title', '')).strip()[:60]
                    m_citation = str(m.get('citation', '')).strip()
                    if m_id:
                        summary_parts.append(f"hit_id={m_id} title=\"{m_title}\"")
                    if m_citation:
                        summary_parts.append(f"citation={m_citation}")
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

        if not self._should_use_llm_context_compression(
            execution_lane=execution_lane,
            response_style=response_style,
            operator_mode=operator_mode,
            tool_results=tool_results,
            prompt=prompt,
            reply=reply,
        ):
            return self._build_local_context_memory(
                operator_mode=operator_mode,
                execution_lane=execution_lane,
                response_style=response_style,
                prompt=prompt,
                reply=reply,
                target=target,
                target_type=target_type,
                project_state_summary=project_state_summary,
                investigation_brief=investigation_brief,
                tool_summaries=tool_summaries,
                learning_signals=learning_signals,
                tool_results=tool_results,
            )

        user_content = "\n".join(
            [
                f"Operator mode: {operator_mode}",
                f"Target: {target}",
                f"Target type: {target_type}",
                "Unified project state:",
                project_state_summary or "(none)",
                "",
                "Existing structured working memory:",
                rendered_prior_memory or "(none)",
                "",
                "Investigation brief:",
                investigation_brief or "(none)",
                "",
                "Recent history excerpt:",
                "\n".join(history_excerpt) or "(none)",
                "",
                f"Latest user prompt: {prompt.strip()}",
                f"Latest assistant reply: {reply.strip()}",
                "Latest tool summary:",
                "\n".join(tool_summaries) or "(none)",
                "",
                "Learning signals:",
                json.dumps(learning_signals, ensure_ascii=True),
            ]
        )
        try:
            response = await self._chat_with_fallback(
                [
                    ChatMessage(role="system", content=CONTEXT_COMPRESSION_PROMPT),
                    ChatMessage(role="user", content=user_content),
                ],
                allow_tools=False,
                allow_backup_fallback=False,
            )
            text = str(response.content or "").strip()
            if text:
                normalized = self._normalize_context_memory_payload(
                    text,
                    operator_mode=operator_mode,
                    execution_lane=execution_lane,
                    response_style=response_style,
                    learning_signals=learning_signals,
                )
                if normalized:
                    return normalized
        except Exception as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None and exc.response.status_code == 429:
                logger.warning(
                    "assistant_context_compression_rate_limited",
                    provider=getattr(self._llm, "_provider", ""),
                    status=exc.response.status_code,
                )
            else:
                logger.warning("assistant_context_compression_failed", exc_info=True)

        return self._build_local_context_memory(
            operator_mode=operator_mode,
            execution_lane=execution_lane,
            response_style=response_style,
            prompt=prompt,
            reply=reply,
            target=target,
            target_type=target_type,
            project_state_summary=project_state_summary,
            investigation_brief=investigation_brief,
            tool_summaries=tool_summaries,
            learning_signals=learning_signals,
            tool_results=tool_results,
        )

    @classmethod
    def _build_local_context_memory(
        cls,
        *,
        operator_mode: str,
        execution_lane: str,
        response_style: str,
        prompt: str,
        reply: str,
        target: str,
        target_type: str,
        project_state_summary: str,
        investigation_brief: str,
        tool_summaries: list[str],
        learning_signals: dict[str, Any],
        tool_results: list[dict[str, Any]] | None = None,
    ) -> str:
        fallback_memory = {
            "operator_mode": operator_mode,
            "execution_lane": cls._normalize_lane(execution_lane),
            "response_style": cls._normalize_style(response_style),
            "target_facts": [
                f"target={target or '(unknown)'}",
                f"target_type={target_type or '(unknown)'}",
            ],
            "operator_goals": [prompt.strip()[:240]] if prompt.strip() else [],
            "recent_dialogue": [
                line
                for line in (
                    f"user: {prompt.strip()[:220]}" if prompt.strip() else "",
                    f"assistant: {reply.strip()[:220]}" if reply.strip() else "",
                )
                if line
            ][:4],
            "investigation_plan": [line.strip()[:240] for line in investigation_brief.splitlines()[:3] if line.strip()],
            "hypotheses": [],
            "verified_evidence": tool_summaries[:4],
            "verdicts": [cls._estimate_verdict(tool_results or [], [], prompt=prompt)],
            "project_state_signals": [line.strip()[:240] for line in project_state_summary.splitlines()[:4] if line.strip()],
            "unresolved_questions": [],
            "next_steps": [reply.strip()[:240]] if reply.strip() else [],
            "recent_checks": tool_summaries[:4],
            "operator_corrections": learning_signals.get("operator_corrections", [])[:4] if isinstance(learning_signals, dict) else [],
            "lessons_learned": learning_signals.get("lessons_learned", [])[:4] if isinstance(learning_signals, dict) else [],
        }
        return json.dumps(fallback_memory, ensure_ascii=True)[:_MAX_CONTEXT_CHARS].strip()
