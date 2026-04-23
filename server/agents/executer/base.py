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

from server.agents.context_window_manager import ContextWindowManager
from server.agents.rate_limiter import LLMRateLimiter, get_global_llm_queue, get_backup_llm_fallback
from server.agents.executer.target_tool_routing import extract_discovered_target_types
from server.config.agent import (
    LocalLLMConfig,
    PublicLLMConfig,
    llm_mode,
    local_llm_config,
    public_llm_config,
    get_public_agent_config,
)
from server.core.llm import ChatMessage, LLMClient
from server.core.tool import Tool, coerce_args_from_schema

logger = structlog.get_logger(__name__)

_EXECUTER_LLM_RETRY_MAX = 3
_EXECUTER_LLM_RETRY_BASE_SECONDS = 1.5
_GENERIC_FILE_OUTPUT_FLAGS = {
    "--output",
    "--output-file",
    "--out",
    "--outfile",
    "--report",
    "--report-file",
    "--report-dir",
    "--outdir",
    "--jsonfile",
    "--json_out",
    "--log-json",
    "--xml",
    "--xml-output",
    "--save-report",
    "--write-report",
}
_GENERIC_FILE_OUTPUT_PREFIXES = tuple(f"{flag}=" for flag in _GENERIC_FILE_OUTPUT_FLAGS)
_RUN_CUSTOM_SHORT_FILE_OUTPUT_FLAGS: dict[str, set[str]] = {
    "curl": {"-o"},
    "wget": {"-o", "-O"},
    "nmap": set(),
    "ffuf": {"-o", "-od"},
    "nuclei": {"-o", "-report-db"},
    "hydra": {"-o", "-O"},
    "nikto": {"-output"},
}
_RUN_CUSTOM_COMBINED_FILE_OUTPUT_PREFIXES: dict[str, tuple[str, ...]] = {
    "nmap": ("-oA", "-oN", "-oX", "-oG"),
}
_TOOL_RESULT_MAX_STRING_CHARS = 600
_TOOL_RESULT_MAX_TOTAL_CHARS = 12000
_TOOL_RESULT_MAX_LIST_ITEMS = 40
_TOOL_RESULT_MAX_NESTED_LIST_ITEMS = 12
_TOOL_RESULT_MAX_DICT_KEYS = 40
_TOOL_RESULT_MAX_DEPTH = 4


class ExecuterCallback(Protocol):
    """Optional callback for progress updates."""

    def on_step(self, message: str) -> None: ...
    def on_done(self, message: str) -> None: ...
    def on_warn(self, message: str) -> None: ...
    def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool | dict[str, Any] | str | Any: ...


class _NoOpCallback:
    def on_step(self, message: str) -> None:
        pass

    def on_done(self, message: str) -> None:
        pass

    def on_warn(self, message: str) -> None:
        pass

    def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        # Secure-by-default: explicit approval integration is required.
        return False


@dataclass
class ExecuterResult:
    status: str = "incomplete"
    confidence: float | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    needs: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    next_hypotheses: list[str] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    discovered_target_types: list[str] = field(default_factory=list)
    rounds_executed: int = 0
    round_labels: list[str] = field(default_factory=list)
    scenario_summaries: list[dict[str, Any]] = field(default_factory=list)


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


def _truncate_tool_text(value: str, limit: int = _TOOL_RESULT_MAX_STRING_CHARS) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    remaining = len(text) - limit
    return f"{text[:limit]}... [truncated {remaining} chars]"


def _compact_tool_value(
    value: Any,
    *,
    depth: int = 0,
    parent_key: str = "",
) -> Any:
    if depth >= _TOOL_RESULT_MAX_DEPTH:
        if isinstance(value, dict):
            return {"truncated": True, "type": "dict", "keys": len(value)}
        if isinstance(value, list):
            return {"truncated": True, "type": "list", "items": len(value)}
        if isinstance(value, str):
            return _truncate_tool_text(value)
        return value

    if isinstance(value, str):
        return _truncate_tool_text(value)

    if isinstance(value, list):
        limit = _TOOL_RESULT_MAX_LIST_ITEMS if depth == 0 else _TOOL_RESULT_MAX_NESTED_LIST_ITEMS
        compacted = [
            _compact_tool_value(item, depth=depth + 1, parent_key=parent_key)
            for item in value[:limit]
        ]
        if len(value) > limit:
            compacted.append(
                {
                    "truncated": True,
                    "omitted_items": len(value) - limit,
                    "original_items": len(value),
                }
            )
        return compacted

    if isinstance(value, dict):
        compacted_dict: dict[str, Any] = {}
        list_keys: dict[str, int] = {}
        keys = list(value.keys())
        for key in keys[:_TOOL_RESULT_MAX_DICT_KEYS]:
            item = value.get(key)
            if isinstance(item, list):
                list_keys[str(key)] = len(item)
            compacted_dict[str(key)] = _compact_tool_value(
                item,
                depth=depth + 1,
                parent_key=str(key),
            )
        if list_keys:
            compacted_dict.setdefault(
                "_counts",
                {key: count for key, count in sorted(list_keys.items())},
            )
        if len(keys) > _TOOL_RESULT_MAX_DICT_KEYS:
            compacted_dict["_truncated_keys"] = len(keys) - _TOOL_RESULT_MAX_DICT_KEYS
        return compacted_dict

    return value


def _compact_tool_result_payload(result: str) -> str:
    raw = str(result or "")
    parsed: Any = None
    if raw[:1] in {"{", "["}:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None

    if parsed is not None:
        compacted = _compact_tool_value(parsed)
        encoded = json.dumps(compacted, ensure_ascii=True, separators=(",", ":"))
        if len(encoded) <= _TOOL_RESULT_MAX_TOTAL_CHARS:
            return encoded
        return _truncate_tool_text(encoded, _TOOL_RESULT_MAX_TOTAL_CHARS)

    return _truncate_tool_text(raw, _TOOL_RESULT_MAX_TOTAL_CHARS)


def _extract_json_from_text(raw: str) -> dict[str, Any]:
    text = raw.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # SANITIZE: Convert Unicode fancy quotes to regular ASCII quotes
    # This fixes issues where LLM outputs « » or " " instead of "
    text = text.replace('"', '"').replace('"', '"')  # "" → "
    text = text.replace('«', '"').replace('»', '"')  # « » → "
    text = text.replace(''', "'").replace(''', "'")  # '' → '

    json_blob = text

    # Try markdown code blocks first
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start) if "```" in text[start:] else len(text)
        json_blob = text[start:end].strip()
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start) if "```" in text[start:] else len(text)
        json_blob = text[start:end].strip()
    else:
        # Try to find raw JSON object (starts with { and ends with })
        if "{" in text:
            start = text.index("{")
            # Find the last closing brace
            end = text.rfind("}")
            if end > start:
                json_blob = text[start:end + 1].strip()

    try:
        parsed = json.loads(json_blob)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return {}


def _parse_executer_output(raw: str, role: str = "unknown") -> ExecuterResult:
    parsed = _extract_json_from_text(raw)

    # CRITICAL FIX: If JSON parsing failed completely, try to extract verdict field directly from raw text
    # This handles cases where Verify agent outputs {"verdict": "..."} but JSON parsing fails
    if not parsed:
        # Try direct regex extraction for verdict field (Verify agent Round 3)
        verdict_match = re.search(r'"verdict"\s*:\s*"([^"]+)"', raw, re.IGNORECASE)
        if verdict_match:
            verdict_value = verdict_match.group(1).strip().lower()
            if verdict_value in {"real_vulnerability", "false_positive", "inconclusive"}:
                # Successfully extracted verdict from raw text
                logger.info(
                    "executer_verdict_extracted_from_raw",
                    role=role,
                    verdict=verdict_value,
                    raw_length=len(raw),
                )
                summary = raw.strip() or "No structured response."
                return ExecuterResult(
                    status=verdict_value,
                    confidence=None,
                    summary=summary,
                )

        # If consolidation role (verify/retest) and no verdict found, default to inconclusive
        # instead of incomplete (incomplete means agent still has work to do)
        if role in {"verify", "retest"}:
            logger.warning(
                "executer_consolidation_no_verdict",
                role=role,
                raw_output_length=len(raw),
                raw_output_preview=raw[:300] if raw else "EMPTY",
                defaulting_to="inconclusive",
            )
            summary = (
                raw.strip() or
                "Verification inconclusive - unable to determine if vulnerability is real or false positive."
            )
            return ExecuterResult(status="inconclusive", summary=summary)

        # For other roles, treat as incomplete
        logger.warning(
            "executer_output_parsing_failed",
            role=role,
            raw_output_length=len(raw),
            raw_output_preview=raw[:300] if raw else "EMPTY",
            has_json_markers="{" in raw and "}" in raw,
            has_verdict_marker='"verdict"' in raw,
        )
        summary = raw.strip() or "No response generated."
        return ExecuterResult(status="incomplete", summary=summary)

    # CRITICAL FIX: Check for "verdict" field (Verify agent) or "status" field (other agents)
    status = parsed.get("status")
    if not status:
        # Verify agent uses "verdict" instead of "status"
        status = parsed.get("verdict", "incomplete")

    # Ensure status is a string (handle lists, dicts, etc. defensively)
    if isinstance(status, list):
        status = status[0] if status else "incomplete"
    status = str(status).strip() if status else "incomplete"
    status = status.lower()

    # Validate status based on role
    if role in {"verify", "retest"}:
        # Verify/Retest: verdict field (real_vulnerability, false_positive, inconclusive)
        if status not in {"real_vulnerability", "false_positive", "inconclusive"}:
            logger.warning(
                "executer_invalid_verdict_format",
                role=role,
                received_verdict=status,
                valid_values=["real_vulnerability", "false_positive", "inconclusive"],
            )
            status = "inconclusive"
    elif role == "recon":
        # Recon: complete, blocked, or failed
        if status not in {"complete", "blocked", "failed"}:
            logger.warning(
                "executer_invalid_recon_status",
                role=role,
                received_status=status,
                valid_values=["complete", "blocked", "failed"],
            )
            status = "failed"
    elif role == "exploit":
        # Exploit: vulnerable, not_vulnerable, blocked, or inconclusive
        if status not in {"vulnerable", "not_vulnerable", "blocked", "inconclusive"}:
            logger.warning(
                "executer_invalid_exploit_status",
                role=role,
                received_status=status,
                valid_values=["vulnerable", "not_vulnerable", "blocked", "inconclusive"],
            )
            status = "inconclusive"

    findings = parsed.get("findings", [])
    evidence = parsed.get("evidence", [])
    needs = parsed.get("needs", [])
    summary = parsed.get("summary", "")
    next_hypotheses = parsed.get("next_hypotheses", [])
    scenario_summaries = parsed.get("scenario_summaries", [])
    raw_confidence = parsed.get("confidence")
    confidence: float | None = None
    try:
        if raw_confidence is not None:
            confidence = float(raw_confidence)
            if confidence < 0:
                confidence = 0.0
            elif confidence > 1:
                confidence = 1.0
    except (TypeError, ValueError):
        confidence = None

    if not isinstance(findings, list):
        findings = []
    if not isinstance(evidence, list):
        evidence = []
    if not isinstance(needs, list):
        needs = []
    if not isinstance(next_hypotheses, list):
        next_hypotheses = []
    if not isinstance(scenario_summaries, list):
        scenario_summaries = []

    # Ensure summary is a string
    if isinstance(summary, list):
        summary = " ".join(str(s) for s in summary) if summary else ""
    summary = str(summary) if summary else ""

    return ExecuterResult(
        status=status,
        confidence=confidence,
        findings=findings,
        evidence=evidence,
        needs=needs,
        summary=summary,
        next_hypotheses=[str(item) for item in next_hypotheses],
        scenario_summaries=[
            item for item in scenario_summaries if isinstance(item, dict)
        ],
    )


def _default_status_for_failed_consolidation(role: str) -> str:
    normalized = str(role or "").strip().lower()
    if normalized in {"verify", "retest", "exploit"}:
        return "inconclusive"
    if normalized == "recon":
        return "failed"
    return "incomplete"


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
        max_tool_calls_per_round: int = 0,
        call_timeout_seconds: int,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        project_id: str | None = None,
        context_window_key: str | None = None,
        context_window_max_tokens: int = 0,
    ) -> None:
        self._role = role
        self._system_prompt = system_prompt
        self._max_tool_rounds = max_tool_rounds
        self._max_tool_calls_per_round = max(0, int(max_tool_calls_per_round or 0))
        self._call_timeout_seconds = call_timeout_seconds
        self._mode = mode or llm_mode.mode
        self._cb = callback or _NoOpCallback()

        self._tools = {t.name: t for t in tools}
        self._tool_schemas = [t.schema() for t in tools]
        self._tool_valid_params = {t.name: _get_valid_params(t) for t in tools}
        self._execution_tool_timeout_cap_seconds: int | None = None

        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LLMClient(self._local_config, mode="local")
            self._model_name = self._local_config.model
        else:
            self._config = config or get_public_agent_config(self._role)
            self._llm = LLMClient(self._config, mode="public")
            self._model_name = self._config.model

        self._context_window: ContextWindowManager | None = None
        if str(project_id or "").strip() and str(context_window_key or "").strip():
            self._context_window = ContextWindowManager(
                project_id=str(project_id),
                agent_key=str(context_window_key),
                max_tokens=max(512, int(context_window_max_tokens or 0)),
                llm=self._llm,
            )

        # Initialize rate limiter to prevent Mistral 429 errors (4 req/min limit)
        # We limit to 3 req/min to leave buffer
        self._rate_limiter = LLMRateLimiter(max_calls_per_minute=3)

        logger.info(
            "executer_initialized",
            role=self._role,
            mode=self._mode,
            model=self._model_name,
            tools=len(self._tools),
        )

    def reset_context_window_for_cycle(self) -> None:
        """Clear context window entries to start fresh for this cycle.

        Called at the start of each execution cycle to ensure agents don't carry
        forward stale information from previous cycles. Only Planner keeps context.
        """
        if self._context_window is not None:
            # Clear the in-memory entries (don't save - let DB reset)
            self._context_window._entries = []
            self._context_window._compression_count = 0
            logger.info(
                "executer_context_reset",
                role=self._role,
                reason="cycle_start_fresh_context",
            )

    async def clear_context_window(self) -> None:
        """Clear persisted and in-memory context window state for this agent."""
        if self._context_window is None:
            return
        await self._context_window.clear()
        self._context_window._entries = []
        self._context_window._compression_count = 0
        logger.info(
            "executer_context_cleared",
            role=self._role,
            reason="phase_transition_fresh_context",
        )

    def _filter_tool_args(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        valid_params = self._tool_valid_params.get(tool_name)
        filtered = args if valid_params is None else {k: v for k, v in args.items() if k in valid_params}
        tool = self._tools.get(tool_name)
        if tool is None:
            return filtered
        coerced = coerce_args_from_schema(tool.parameters, filtered)
        return self._apply_execution_tool_policies(tool_name, coerced)

    def _apply_execution_tool_policies(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(args, dict):
            return {}

        timeout_cap = self._execution_tool_timeout_cap_seconds
        if timeout_cap is None or timeout_cap <= 0:
            return args

        tool = self._tools.get(tool_name)
        if tool is None:
            return args

        properties = tool.parameters.get("properties", {}) if isinstance(tool.parameters, dict) else {}
        if "timeout" not in properties:
            return args

        updated = dict(args)
        current_timeout = updated.get("timeout")
        parsed_timeout: int | None = None
        if isinstance(current_timeout, bool):
            parsed_timeout = None
        elif isinstance(current_timeout, int):
            parsed_timeout = current_timeout
        elif isinstance(current_timeout, float):
            parsed_timeout = int(current_timeout)
        elif isinstance(current_timeout, str):
            stripped = current_timeout.strip()
            if stripped.isdigit():
                parsed_timeout = int(stripped)

        if parsed_timeout is None or parsed_timeout > timeout_cap:
            updated["timeout"] = timeout_cap

        return updated

    def _format_tool_results(self, tool_results: list[dict[str, Any]]) -> str:
        """Build a compact aggregated text block for sequential tool outputs."""
        if not tool_results:
            return ""
        lines = [f"Executed {len(tool_results)} tool call(s) sequentially:"]
        for idx, item in enumerate(tool_results, 1):
            tool_name = str(item.get("name", "?"))
            call_id = str(item.get("tool_call_id", ""))
            result = _compact_tool_result_payload(str(item.get("result", "")))
            lines.append(f"[{idx}] {tool_name} (call_id={call_id})")
            lines.append(result)
            lines.append("")
        return "\n".join(lines).strip()

    def _is_allowed_output_sink(self, value: str) -> bool:
        lowered = value.strip().lower()
        return lowered in {
            "-",
            "json",
            "jsonl",
            "xml",
            "csv",
            "yaml",
            "yml",
            "cli",
            "stdout",
            "/dev/stdout",
            "/dev/fd/1",
        }

    def _looks_like_file_sink(self, value: str) -> bool:
        val = str(value or "").strip()
        if not val:
            return True
        if self._is_allowed_output_sink(val):
            return False
        lowered = val.lower()
        if lowered.startswith(("http://", "https://")):
            return False
        if "=" in val and "/" not in val and "\\" not in val:
            left, _, right = val.partition("=")
            if left.strip() and right.strip():
                return False
        if val.startswith("-"):
            return False
        if "/" in val or "\\" in val:
            return True
        if re.search(
            r"\.(txt|json|jsonl|xml|csv|log|out|html|yaml|yml|cap|pcap)$",
            lowered,
        ):
            return True
        return True

    def _scan_args_for_file_output(self, tokens: list[str]) -> str | None:
        return self._scan_args_for_file_output_for_command(tokens)

    def _scan_args_for_file_output_for_command(
        self,
        tokens: list[str],
        *,
        command: str = "",
    ) -> str | None:
        normalized_command = str(command or "").strip().lower()
        short_flags = _RUN_CUSTOM_SHORT_FILE_OUTPUT_FLAGS.get(normalized_command, set())
        combined_prefixes = _RUN_CUSTOM_COMBINED_FILE_OUTPUT_PREFIXES.get(normalized_command, ())

        for idx, raw in enumerate(tokens):
            token = str(raw or "").strip()
            if not token:
                continue
            if token in short_flags or token in _GENERIC_FILE_OUTPUT_FLAGS or token == "-o":
                next_value = str(tokens[idx + 1]).strip() if idx + 1 < len(tokens) else ""
                if self._looks_like_file_sink(next_value):
                    return f"{token} {next_value}".strip()
                continue
            if any(token.startswith(prefix) for prefix in _GENERIC_FILE_OUTPUT_PREFIXES):
                if "=" in token:
                    _, value = token.split("=", 1)
                else:
                    value = ""
                if self._looks_like_file_sink(value):
                    return token
            for prefix in combined_prefixes:
                if token == prefix:
                    next_value = str(tokens[idx + 1]).strip() if idx + 1 < len(tokens) else ""
                    if self._looks_like_file_sink(next_value):
                        return f"{token} {next_value}".strip()
                    break
                if token.startswith(prefix):
                    value = token[len(prefix) :].strip()
                    if self._looks_like_file_sink(value):
                        return token
        return None

    def _sanitize_known_file_output_args(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        if not isinstance(args, dict) or tool_name != "run_custom":
            return args, []

        command = str(args.get("command", "")).strip().lower()
        tool_args = args.get("args")
        if not command or not isinstance(tool_args, list):
            return args, []

        short_flags = _RUN_CUSTOM_SHORT_FILE_OUTPUT_FLAGS.get(command, set())
        combined_prefixes = _RUN_CUSTOM_COMBINED_FILE_OUTPUT_PREFIXES.get(command, ())
        if not short_flags and not combined_prefixes and not any(
            token in _GENERIC_FILE_OUTPUT_FLAGS or any(token.startswith(prefix) for prefix in _GENERIC_FILE_OUTPUT_PREFIXES)
            for token in [str(item or "").strip() for item in tool_args]
        ):
            return args, []

        cleaned: list[str] = []
        stripped: list[str] = []
        idx = 0
        while idx < len(tool_args):
            token = str(tool_args[idx] or "").strip()
            if not token:
                idx += 1
                continue
            if token in short_flags or token in _GENERIC_FILE_OUTPUT_FLAGS:
                stripped.append(token)
                next_value = str(tool_args[idx + 1]).strip() if idx + 1 < len(tool_args) else ""
                if next_value and self._looks_like_file_sink(next_value):
                    stripped.append(next_value)
                    idx += 2
                else:
                    idx += 1
                continue
            matched_combined = False
            for prefix in combined_prefixes:
                if token == prefix:
                    stripped.append(token)
                    next_value = str(tool_args[idx + 1]).strip() if idx + 1 < len(tool_args) else ""
                    if next_value and self._looks_like_file_sink(next_value):
                        stripped.append(next_value)
                        idx += 2
                    else:
                        idx += 1
                    matched_combined = True
                    break
                if token.startswith(prefix):
                    suffix = token[len(prefix) :].strip()
                    if self._looks_like_file_sink(suffix):
                        stripped.append(token)
                        idx += 1
                        matched_combined = True
                        break
            if matched_combined:
                continue
            if any(token.startswith(prefix) for prefix in _GENERIC_FILE_OUTPUT_PREFIXES):
                value = token.split("=", 1)[1] if "=" in token else ""
                if self._looks_like_file_sink(value):
                    stripped.append(token)
                    idx += 1
                    continue
            cleaned.append(str(tool_args[idx]))
            idx += 1

        if not stripped:
            return args, []
        updated = dict(args)
        updated["args"] = cleaned
        return updated, stripped

    def _detect_disallowed_file_output(self, tool_name: str, args: dict[str, Any]) -> str | None:
        if not isinstance(args, dict):
            return None

        tool_args = args.get("args")
        if isinstance(tool_args, list):
            command = str(args.get("command", "")).strip().lower() if tool_name == "run_custom" else ""
            reason = self._scan_args_for_file_output_for_command(
                [str(x) for x in tool_args],
                command=command,
            )
            if reason:
                return reason

        extra_args = args.get("extra_args")
        if isinstance(extra_args, dict):
            for maybe_list in extra_args.values():
                if isinstance(maybe_list, list):
                    reason = self._scan_args_for_file_output([str(x) for x in maybe_list])
                    if reason:
                        return reason

        return None

    def _build_tool_invocation_signature(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        scenario_id: str,
    ) -> str:
        try:
            args_blob = json.dumps(args, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        except TypeError:
            args_blob = repr(args)
        return f"{scenario_id.strip().lower()}::{tool_name.strip().lower()}::{args_blob}"

    def _recover_tool_invocation(
        self,
        tool_name: str,
        raw_args: Any,
    ) -> tuple[str, dict[str, Any], str]:
        normalized_name = str(tool_name or "").strip()
        recovered_args: dict[str, Any] = {}
        recovered_scenario_id = ""

        try:
            parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except json.JSONDecodeError:
            parsed_args = {}
        if isinstance(parsed_args, dict):
            recovered_args = parsed_args

        if normalized_name in self._tools:
            return normalized_name, recovered_args, recovered_scenario_id

        if normalized_name.strip().startswith("{"):
            return normalized_name, recovered_args, recovered_scenario_id

        matched_tool_name = ""
        for candidate in sorted(self._tools.keys(), key=len, reverse=True):
            if normalized_name.startswith(candidate):
                matched_tool_name = candidate
                break
        if not matched_tool_name:
            return normalized_name, recovered_args, recovered_scenario_id

        suffix = normalized_name[len(matched_tool_name) :].strip()
        if not suffix:
            return normalized_name, recovered_args, recovered_scenario_id

        scenario_match = re.search(r'_scenario_id\s*=\s*"([^"]+)"', suffix)
        if scenario_match:
            recovered_scenario_id = scenario_match.group(1).strip()

        json_start = suffix.find("{")
        json_end = suffix.rfind("}")
        if json_start != -1 and json_end > json_start:
            embedded_json = suffix[json_start : json_end + 1]
            try:
                embedded_args = json.loads(embedded_json)
            except json.JSONDecodeError:
                embedded_args = {}
            if isinstance(embedded_args, dict):
                merged = dict(embedded_args)
                merged.update(recovered_args)
                recovered_args = merged

        if recovered_args or recovered_scenario_id:
            return matched_tool_name, recovered_args, recovered_scenario_id
        return normalized_name, recovered_args, recovered_scenario_id

    async def _run_tools(
        self,
        tool_calls: list[dict[str, Any]],
        previous_tool_results: list[dict[str, Any]] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], bool]:
        tool_messages: list[dict[str, Any]] = []
        tool_results: list[dict[str, Any]] = []
        discovered_target_types: set[str] = set()
        halted_for_approval = False
        seen_invocations: set[str] = set()

        for previous in previous_tool_results or []:
            if not isinstance(previous, dict):
                continue
            seen_invocations.add(
                self._build_tool_invocation_signature(
                    tool_name=str(previous.get("name", "")),
                    args=previous.get("args", {}) if isinstance(previous.get("args", {}), dict) else {},
                    scenario_id=str(previous.get("scenario_id", "")),
                )
            )

        for tc in tool_calls:
            tool_name = tc.get("function", {}).get("name", "")
            raw_args = tc.get("function", {}).get("arguments", "{}")
            call_id = tc.get("id", "")

            tool_name, args, recovered_scenario_id = self._recover_tool_invocation(
                str(tool_name),
                raw_args,
            )

            # DEFENSE: Detect if LLM output tool spec as JSON string instead of proper tool call
            if isinstance(tool_name, str) and tool_name.strip().startswith("{"):
                logger.warning(
                    "llm_output_tool_spec_as_json",
                    role=self._role,
                    tool_spec_preview=tool_name[:200],
                )
                self._cb.on_warn(
                    f"[{self._role}] LLM output tool specification as JSON instead of calling tool. Skipping malformed tool call."
                )
                continue

            if not isinstance(args, dict):
                args = {}

            scenario_id = str(
                args.get("_scenario_id")
                or args.get("scenario_id")
                or args.get("_scenario_ref")
                or recovered_scenario_id
                or ""
            ).strip()
            args = {
                key: value
                for key, value in args.items()
                if key not in {"_scenario_id", "scenario_id", "_scenario_ref"}
            }

            if recovered_scenario_id and tool_name in self._tools:
                self._cb.on_warn(
                    f"[{self._role}] recovered malformed tool call for {tool_name}"
                )

            args = self._filter_tool_args(tool_name, args)
            args, sanitized_output_flags = self._sanitize_known_file_output_args(tool_name, args)
            if sanitized_output_flags:
                self._cb.on_warn(
                    f"[{self._role}] removed file-output args for {tool_name}: {' '.join(sanitized_output_flags[:4])}"
                )
            output_arg_issue = self._detect_disallowed_file_output(tool_name, args)
            if output_arg_issue:
                result = json.dumps(
                    {
                        "success": False,
                        "error": (
                            "File output arguments are blocked by policy. "
                            "Re-run without saving to disk and return results via stdout/stdin only."
                        ),
                        "blocked_arg": output_arg_issue,
                        "role": self._role,
                        "tool": tool_name,
                    },
                    ensure_ascii=True,
                )
                self._cb.on_warn(
                    f"[{self._role}] blocked output-file arg for {tool_name}: {output_arg_issue}"
                )
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
                        "scenario_id": scenario_id,
                        "result": result,
                        "discovered_target_types": extract_discovered_target_types(result),
                        "approval_required": False,
                    },
                )
                continue

            invocation_signature = self._build_tool_invocation_signature(
                tool_name=tool_name,
                args=args,
                scenario_id=scenario_id,
            )
            if invocation_signature in seen_invocations:
                result = json.dumps(
                    {
                        "success": False,
                        "error": (
                            "Duplicate tool invocation suppressed. "
                            "Use a different tool or materially different arguments."
                        ),
                        "role": self._role,
                        "tool": tool_name,
                        "scenario_id": scenario_id,
                    },
                    ensure_ascii=True,
                )
                self._cb.on_warn(
                    f"[{self._role}] duplicate tool call suppressed"
                    f"{f' [{scenario_id}]' if scenario_id else ''}: {tool_name}"
                )
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
                        "scenario_id": scenario_id,
                        "result": result,
                        "discovered_target_types": [],
                        "approval_required": False,
                    },
                )
                continue

            tool = self._tools.get(tool_name)
            if tool is None:
                result = f"Error: unknown tool '{tool_name}'"
                self._cb.on_warn(f"[{self._role}] unknown tool: {tool_name}")
            else:
                result = ""
                if self._tool_requires_user_approval(tool_name):
                    approved = await self._request_tool_approval(
                        tool_name=tool_name,
                        args=args,
                        call_id=str(call_id),
                    )
                    if not approved:
                        result = json.dumps(
                            {
                                "success": False,
                                "error": "User approval required before executing tool",
                                "approval_required": True,
                                "role": self._role,
                                "tool": tool_name,
                                "call_id": call_id,
                                "args": args,
                            },
                            ensure_ascii=True,
                        )
                        self._cb.on_warn(
                            f"[{self._role}] blocked pending user approval: {tool_name}"
                        )
                        halted_for_approval = True
                    else:
                        self._cb.on_step(
                            f"[{self._role}] user approved tool: {tool_name}"
                        )

                if halted_for_approval:
                    pass
                elif result:
                    pass
                else:
                    cmd_preview = ""
                    if tool_name == "run_custom":
                        base_cmd = str(args.get("command", "")).strip()
                        arg_list = args.get("args", [])
                        if base_cmd:
                            if isinstance(arg_list, list):
                                joined_args = " ".join(str(x) for x in arg_list)
                                cmd_preview = f"{base_cmd} {joined_args}".strip()
                            else:
                                cmd_preview = base_cmd
                    if cmd_preview:
                        self._cb.on_step(
                            f"[{self._role}] tool call"
                            f"{f' [{scenario_id}]' if scenario_id else ''}: "
                            f"{tool_name} -> {cmd_preview}"
                        )
                    else:
                        self._cb.on_step(
                            f"[{self._role}] tool call"
                            f"{f' [{scenario_id}]' if scenario_id else ''}: {tool_name}"
                        )
                    try:
                        raw_result = await tool.execute(**args)
                        result = _compact_tool_result_payload(str(raw_result or ""))
                        done_message = (
                            f"[{self._role}] "
                            f"{f'[{scenario_id}] ' if scenario_id else ''}"
                            f"{tool_name} completed ({len(result)} chars"
                        )
                        if isinstance(raw_result, str) and len(raw_result) > len(result):
                            done_message += f", compacted from {len(raw_result)}"
                        done_message += ")"
                        if tool_name == "run_custom":
                            try:
                                parsed = json.loads(result) if isinstance(result, str) else {}
                            except json.JSONDecodeError:
                                parsed = {}
                            full_command = (
                                str(parsed.get("full_command", "")).strip()
                                if isinstance(parsed, dict)
                                else ""
                            )
                            if full_command:
                                done_message = (
                                    f"[{self._role}] run_custom completed: {full_command}"
                                )
                        self._cb.on_done(done_message)
                    except Exception as exc:
                        logger.error(
                            "executer_tool_error",
                            role=self._role,
                            tool=tool_name,
                            error=repr(exc),
                        )
                        result = f"Error executing {tool_name}: {exc}"
                        self._cb.on_warn(f"[{self._role}] tool error: {exc}")

            for discovered in extract_discovered_target_types(result):
                discovered_target_types.add(discovered)

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
                    "scenario_id": scenario_id,
                    "result": result,
                    "discovered_target_types": extract_discovered_target_types(result),
                    "approval_required": bool(
                        isinstance(result, str)
                        and '"approval_required": true' in result.lower()
                    ),
                },
            )
            seen_invocations.add(invocation_signature)

            if halted_for_approval:
                break

        return (
            tool_messages,
            tool_results,
            sorted(discovered_target_types),
            halted_for_approval,
        )

    def _tool_requires_user_approval(self, tool_name: str) -> bool:
        # Any Exploit execution requires explicit approval.
        if self._role == "exploit":
            return True
        # run_custom is powerful even in recon and must be explicitly approved.
        return tool_name == "run_custom"

    async def _request_tool_approval(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        callback_fn = getattr(self._cb, "request_tool_approval", None)
        if not callable(callback_fn):
            return False

        try:
            decision = callback_fn(
                role=self._role,
                tool_name=tool_name,
                args=args,
                call_id=call_id,
            )
        except TypeError:
            # Backward-compatible fallback if callback signature is positional.
            decision = callback_fn(self._role, tool_name, args, call_id)

        if inspect.isawaitable(decision):
            decision = await decision

        if isinstance(decision, dict):
            if "approved" in decision:
                return bool(decision.get("approved"))
            if "allow" in decision:
                return bool(decision.get("allow"))
            return False
        if isinstance(decision, str):
            return decision.strip().lower() in {"approve", "approved", "allow", "yes", "true", "1"}
        return bool(decision)

    def _build_consolidation_reminder(self, round_index: int) -> str:
        """
        Build an explicit reminder for consolidation-only rounds.
        This prevents context drift after seeing tool output and reinforces the JSON-only requirement.
        """
        role_templates = {
            "verify": (
                f"[CONSOLIDATION ROUND {round_index}] This is your FINAL round (Round {round_index}/3). "
                "You have analyzed all verification results. Now output ONLY valid JSON with two fields: "
                '"verdict" (real_vulnerability|false_positive|inconclusive) and "summary" (1-2 sentences). '
                "NO prose before or after JSON. NO markdown. Start with { and end with }. Example:\n"
                '{"verdict": "real_vulnerability", "summary": "The vulnerability was confirmed through payload testing."}'
            ),
            "recon": (
                f"[CONSOLIDATION ROUND {round_index}] This is your FINAL round (Round {round_index}/3). "
                "You have completed reconnaissance. Now output ONLY valid JSON with three fields: "
                '"status" (complete|blocked|failed), "findings" (array), and "summary" (1-2 sentences). '
                "NO prose before or after JSON. NO markdown. Start with { and end with }."
            ),
            "exploit": (
                f"[CONSOLIDATION ROUND {round_index}] This is your FINAL round (Round {round_index}/3). "
                "You have completed exploitation testing. Now output ONLY valid JSON with three fields: "
                '"status" (vulnerable|not_vulnerable|blocked|inconclusive), "findings" (array), and "summary" (1-2 sentences). '
                "NO prose before or after JSON. NO markdown. Start with { and end with }."
            ),
        }
        default_msg = (
            f"[CONSOLIDATION ROUND {round_index}] This is your FINAL consolidation round ({round_index}/{self._max_tool_rounds}). "
            "Output ONLY valid JSON. NO tools. NO prose. NO markdown. Start with { and end with }."
        )
        return role_templates.get(self._role, default_msg)

    def _build_forced_consolidation_prompt(
        self,
        *,
        round_index: int,
        last_content: str,
        tool_results: list[dict[str, Any]],
    ) -> str:
        recent_tool_output = self._format_tool_results(tool_results[-8:])
        if len(recent_tool_output) > 5000:
            recent_tool_output = recent_tool_output[-5000:]

        role_specific = {
            "verify": (
                "You attempted tool calls in the final consolidation round, which is not allowed.\n"
                "Do NOT call tools. Use only the already collected verification evidence below.\n"
                'Return ONLY strict JSON with: {"verdict":"real_vulnerability|false_positive|inconclusive","summary":"..."}'
            ),
            "retest": (
                "You attempted tool calls in the final consolidation round, which is not allowed.\n"
                "Do NOT call tools. Use only the already collected retest evidence below.\n"
                'Return ONLY strict JSON with: {"verdict":"real_vulnerability|false_positive|inconclusive","summary":"..."}'
            ),
            "recon": (
                "You attempted tool calls in the final consolidation round, which is not allowed.\n"
                "Do NOT call tools. Use only the already collected reconnaissance evidence below.\n"
                'Return ONLY strict JSON with: {"status":"complete|blocked|failed","findings":[],"summary":"..."}'
            ),
            "exploit": (
                "You attempted tool calls in the final consolidation round, which is not allowed.\n"
                "Do NOT call tools. Use only the already collected exploitation evidence below.\n"
                'Return ONLY strict JSON with: {"status":"vulnerable|not_vulnerable|blocked|inconclusive","findings":[],"summary":"..."}'
            ),
        }.get(
            self._role,
            "Do NOT call tools. Return ONLY strict JSON using the evidence already collected.",
        )

        sections = [
            f"[FORCED FINAL CONSOLIDATION] Round {round_index}/{self._max_tool_rounds}",
            role_specific,
        ]
        if last_content.strip():
            sections.extend(
                [
                    "",
                    "Your previous assistant output before this forced retry:",
                    last_content.strip(),
                ]
            )
        if recent_tool_output.strip():
            sections.extend(
                [
                    "",
                    "Collected tool evidence to consolidate:",
                    recent_tool_output,
                ]
            )
        return "\n".join(sections).strip()

    async def _force_final_consolidation(
        self,
        *,
        messages: list[dict[str, Any]],
        round_index: int,
        last_content: str,
        all_tool_results: list[dict[str, Any]],
    ) -> ExecuterResult:
        self._cb.on_warn(
            f"[{self._role}] final round emitted tool calls; forcing one last JSON-only consolidation pass"
        )

        fallback_messages = list(messages[:-1]) if messages else []
        if str(last_content or "").strip():
            fallback_messages.append({"role": "assistant", "content": last_content})
        fallback_messages.append(
            {
                "role": "user",
                "content": self._build_forced_consolidation_prompt(
                    round_index=round_index,
                    last_content=last_content,
                    tool_results=all_tool_results,
                ),
            }
        )

        global_queue = get_global_llm_queue()
        response = None
        llm_exc: Exception | None = None

        try:
            await global_queue.acquire(self._role)
            try:
                response = await asyncio.wait_for(
                    self._llm.chat(
                        [_dict_to_msg(m) for m in fallback_messages],
                        tools=None,
                        temperature=0.1,
                        max_tokens=1800,
                    ),
                    timeout=self._call_timeout_seconds,
                )
            finally:
                global_queue.release(self._role)
        except Exception as exc:
            llm_exc = exc

        if response is None or llm_exc is not None:
            summary = (
                "Final consolidation failed after the model attempted tool calls in the last round "
                f"and the forced JSON-only retry errored: {llm_exc}"
            )
            logger.error(
                "executer_forced_final_consolidation_failed",
                role=self._role,
                round=round_index,
                error=repr(llm_exc),
            )
            return ExecuterResult(
                status=_default_status_for_failed_consolidation(self._role),
                summary=summary,
                rounds_executed=round_index,
                round_labels=[f"r{n}" for n in range(1, round_index + 1)],
            )

        forced_raw = response.content or ""
        if self._context_window is not None:
            await self._context_window.record_llm_turn(
                prompt_excerpt=f"{self._role} forced final consolidation round {round_index}",
                response_excerpt=forced_raw or "forced final answer",
                usage=response.usage if isinstance(response.usage, dict) else {},
                metadata={
                    "role": self._role,
                    "round": round_index,
                    "forced_final_consolidation": True,
                },
            )

        result = _parse_executer_output(forced_raw, role=self._role)
        if result.status == "incomplete":
            summary = forced_raw.strip() or (
                "Final consolidation retry did not return valid JSON after a final-round tool-call attempt."
            )
            result = ExecuterResult(
                status=_default_status_for_failed_consolidation(self._role),
                summary=summary,
                rounds_executed=round_index,
                round_labels=[f"r{n}" for n in range(1, round_index + 1)],
            )
        return result

    async def run(self, user_message: str) -> ExecuterResult:
        self._cb.on_step(f"[{self._role}] starting run")
        if self._context_window is not None:
            await self._context_window.record(
                kind="run_input",
                role="user",
                content=user_message,
                metadata={"role": self._role},
            )

        system_prompt = self._system_prompt
        if _needs_nothink(self._model_name):
            system_prompt = "/nothink\n" + system_prompt

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        last_content = ""
        all_tool_results: list[dict[str, Any]] = []
        all_discovered_target_types: set[str] = set()
        rounds_executed = 0

        async def _finalize_result(result: ExecuterResult) -> ExecuterResult:
            result.tool_results = all_tool_results
            merged_target_types = set(result.discovered_target_types or [])
            merged_target_types.update(all_discovered_target_types)
            if merged_target_types:
                result.discovered_target_types = sorted(merged_target_types)
            if result.rounds_executed <= 0:
                result.rounds_executed = rounds_executed
            if not result.round_labels and result.rounds_executed > 0:
                result.round_labels = [
                    f"r{n}" for n in range(1, result.rounds_executed + 1)
                ]
            if self._context_window is not None:
                await self._context_window.record(
                    kind="run_result",
                    role="assistant",
                    content=result.summary or last_content or result.status,
                    metadata={
                        "role": self._role,
                        "status": result.status,
                        "tool_results": len(all_tool_results),
                    },
                )
            self._cb.on_done(f"[{self._role}] completed with status={result.status}")
            return result

        for round_index in range(1, self._max_tool_rounds + 1):
            rounds_executed = round_index
            self._cb.on_step(
                f"[{self._role}] LLM round {round_index}/{self._max_tool_rounds}"
            )

            # CRITICAL: Before final consolidation round, inject explicit reminder to force JSON-only output
            # This prevents LLM context drift after seeing hundreds of lines of tool output
            is_final_round = round_index >= self._max_tool_rounds
            if is_final_round and len(messages) > 2:  # Only inject if we have tool results to consolidate
                consolidation_reminder = self._build_consolidation_reminder(round_index)
                messages.append({"role": "user", "content": consolidation_reminder})
                self._cb.on_step(
                    f"[{self._role}] injected Round {round_index} consolidation reminder"
                )

            response = None
            llm_exc: Exception | None = None
            # Enhanced rate limit handling: Wait longer for 429 errors
            # - First attempt: immediate
            # - Rate limit (429): wait 30s, retry
            # - Still limited: wait 60s, retry
            # - Still limited: fail with circuit breaker
            max_attempts = 3  # 1 initial + 2 retries on rate limit
            rate_limit_attempts = 0
            global_queue = get_global_llm_queue()
            backup_fallback = get_backup_llm_fallback()

            for attempt in range(1, max_attempts + 1):
                response = None
                llm_exc = None
                used_backup_llm = False

                try:
                    # GLOBAL RATE LIMITER: Coordinate across all agents (max 3 concurrent)
                    # This prevents Recon/Exploit/Verify/Planner/Retest from hammering API simultaneously
                    await global_queue.acquire(self._role)
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
                    finally:
                        global_queue.release(self._role)

                    llm_exc = None
                    break

                except Exception as exc:
                    llm_exc = exc
                    text = str(exc).lower()
                    is_rate_limited = "429" in text or "rate limit" in text

                    # BACKUP LLM FALLBACK: On 429, try backup LLM for single call
                    if is_rate_limited and attempt <= 1:
                        backup_llm = await backup_fallback.get_backup_llm()
                        if backup_llm is not None:
                            try:
                                logger.info(
                                    "backup_llm_fallback_attempt",
                                    role=self._role,
                                    round=round_index,
                                    reason="main_llm_429",
                                )
                                self._cb.on_warn(
                                    f"[{self._role}] Using backup LLM (main hit 429); "
                                    f"single call, then return to main LLM"
                                )

                                response = await asyncio.wait_for(
                                    backup_llm.chat(
                                        [_dict_to_msg(m) for m in messages],
                                        tools=self._tool_schemas if self._tools else None,
                                        temperature=0.2,
                                        max_tokens=4000,
                                    ),
                                    timeout=self._call_timeout_seconds,
                                )
                                used_backup_llm = True
                                llm_exc = None
                                logger.info(
                                    "backup_llm_fallback_success",
                                    role=self._role,
                                    round=round_index,
                                )
                                break

                            except Exception as backup_exc:
                                # Backup LLM also failed, continue with original exception
                                logger.warning(
                                    "backup_llm_fallback_failed",
                                    role=self._role,
                                    round=round_index,
                                    error=str(backup_exc)[:100],
                                )
                                llm_exc = exc  # Use original exception for retry logic

                    # Regular retry logic: wait and retry main LLM
                    if is_rate_limited and attempt < max_attempts and not used_backup_llm:
                        rate_limit_attempts += 1
                        # Progressive wait: 30s first, 60s second
                        wait_seconds = 30.0 if rate_limit_attempts == 1 else 60.0
                        self._cb.on_warn(
                            f"[{self._role}] LLM rate-limited (attempt {attempt}/{max_attempts}); "
                            f"retrying in {wait_seconds:.0f}s to allow quota reset"
                        )
                        logger.warning(
                            "llm_rate_limit_backoff",
                            role=self._role,
                            round=round_index,
                            attempt=attempt,
                            wait_seconds=wait_seconds,
                        )
                        await asyncio.sleep(wait_seconds)
                        continue
                    break

            if response is None or llm_exc is not None:
                logger.error(
                    "executer_llm_error",
                    role=self._role,
                    round=round_index,
                    error=repr(llm_exc),
                    circuit_breaker_triggered=True,
                )
                self._cb.on_warn(f"[{self._role}] LLM error (round {round_index}); circuit breaker triggered: {llm_exc}")
                return ExecuterResult(
                    status="failed",
                    summary=f"LLM error after {max_attempts} attempt(s): {llm_exc}",
                    rounds_executed=round_index,
                    round_labels=[f"r{n}" for n in range(1, round_index + 1)],
                )

            last_content = response.content or ""
            tool_calls = response.tool_calls or []

            # DEBUG: Log LLM response IMMEDIATELY after receiving
            logger.info(
                "llm_response_received",
                role=self._role,
                round=round_index,
                content_length=len(last_content),
                tool_calls_count=len(tool_calls),
                timestamp="now",
            )

            if self._max_tool_calls_per_round > 0 and len(tool_calls) > self._max_tool_calls_per_round:
                self._cb.on_warn(
                    f"[{self._role}] limiting tool calls this round: "
                    f"{len(tool_calls)} -> {self._max_tool_calls_per_round}"
                )
                tool_calls = tool_calls[: self._max_tool_calls_per_round]

            # DEBUG: Log after limiting tool calls
            logger.info(
                "tool_calls_prepared",
                role=self._role,
                round=round_index,
                tool_calls_after_limit=len(tool_calls),
            )

            if self._context_window is not None:
                logger.info("context_window_recording_start", role=self._role, round=round_index)
                await self._context_window.record_llm_turn(
                    prompt_excerpt=user_message if round_index == 1 else f"{self._role} round {round_index}",
                    response_excerpt=last_content or f"tool_calls={len(tool_calls)}",
                    usage=response.usage if isinstance(response.usage, dict) else {},
                    metadata={
                        "role": self._role,
                        "round": round_index,
                        "tool_calls": len(tool_calls),
                    },
                )
                logger.info("context_window_recording_done", role=self._role, round=round_index)
            messages.append(
                {
                    "role": "assistant",
                    "content": last_content,
                    "tool_calls": tool_calls,
                },
            )

            # CRITICAL: Round 3 consolidation is mandatory for ALL roles
            # Final round (Round 3/3) must ONLY output JSON, not execute tools
            is_final_round = round_index >= self._max_tool_rounds
            is_consolidation_role = self._role in ("verify", "retest")

            # ALL roles skip tools in final round (consolidation-only)
            skip_tools_this_round = bool(is_final_round and tool_calls)

            # DEBUG: Log consolidation decision
            logger.info(
                "consolidation_decision",
                role=self._role,
                round=round_index,
                max_rounds=self._max_tool_rounds,
                is_final_round=is_final_round,
                is_consolidation_role=is_consolidation_role,
                has_tool_calls=bool(tool_calls),
                skip_tools_this_round=skip_tools_this_round,
            )

            # CRITICAL: Enforce round progression to final consolidation
            # If skip_tools_this_round: we're on final round with tool calls → consolidate now
            # If is_final_round + no tools: we're on final round without tools → consolidate now
            # If NOT final round + no tools: continue to NEXT round (don't exit early)
            if skip_tools_this_round:
                result = await self._force_final_consolidation(
                    messages=messages,
                    round_index=round_index,
                    last_content=last_content,
                    all_tool_results=all_tool_results,
                )
                return await _finalize_result(result)

            if not tool_calls:
                if is_final_round:
                    # Final round with no tool calls: consolidate now
                    result = _parse_executer_output(last_content, role=self._role)
                    return await _finalize_result(result)
                else:
                    # Non-final round with no tool calls: force next iteration to reach final consolidation
                    self._cb.on_warn(
                        f"[{self._role}] No tool calls on non-final round {round_index}; continuing to next round"
                    )
                    continue

            tool_messages, tool_results, discovered, halted_for_approval = await self._run_tools(
                tool_calls,
                previous_tool_results=all_tool_results,
            )
            messages.extend(tool_messages)
            all_tool_results.extend(tool_results)
            all_discovered_target_types.update(discovered)

            if halted_for_approval:
                if self._context_window is not None:
                    await self._context_window.record(
                        kind="run_result",
                        role="assistant",
                        content="Execution paused awaiting user approval for a tool call.",
                        metadata={"role": self._role, "status": "awaiting_user_approval"},
                    )
                return ExecuterResult(
                    status="awaiting_user_approval",
                    summary="Execution paused awaiting user approval for a tool call.",
                    tool_results=all_tool_results,
                    discovered_target_types=sorted(all_discovered_target_types),
                    rounds_executed=round_index,
                    round_labels=[f"r{n}" for n in range(1, round_index + 1)],
                )

            # If we consumed the final allowed round, return the aggregated tool output.
            if round_index >= self._max_tool_rounds:
                result = _parse_executer_output(last_content, role=self._role)
                if result.status == "incomplete" and all_tool_results:
                    result.summary = self._format_tool_results(all_tool_results)
                return await _finalize_result(result)

        if all_tool_results:
            return await _finalize_result(
                ExecuterResult(
                status="incomplete",
                summary=self._format_tool_results(all_tool_results),
                tool_results=all_tool_results,
                discovered_target_types=sorted(all_discovered_target_types),
                rounds_executed=self._max_tool_rounds,
                round_labels=[f"r{n}" for n in range(1, self._max_tool_rounds + 1)],
            )
            )
        result = _parse_executer_output(last_content, role=self._role)
        result.discovered_target_types = extract_discovered_target_types(last_content)
        return await _finalize_result(result)

    async def close(self) -> None:
        await self._llm.close()

    async def __aenter__(self) -> BaseExecuterAgent:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
