"""
Shared base implementation for executer agents.
"""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import json
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

from server.agents.rate_limiter import LLMRateLimiter, get_global_llm_queue, get_backup_llm_fallback
from server.agents.executer.sandbox import ensure_sandbox_environment
from server.agents.executer.tool_safety import (
    get_run_custom_command_profile,
    get_tool_safety_profile,
    requires_approval_for_execution,
)
from server.agents.executer.target_tool_routing import extract_discovered_target_types
from server.agents.tool_output_parsers import summarize_tool_output, _short_text
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

_executer_callback_context: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "executer_callback_context",
    default=None,
)
_executer_tool_context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "executer_tool_context",
    default={},
)

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
_RUN_CUSTOM_URL_TARGET_FLAGS = {
    "-u",
    "--url",
    "--target",
    "--uri",
}
_RUN_CUSTOM_URL_TARGET_PREFIXES = (
    "-u=",
    "--url=",
    "--target=",
    "--uri=",
)
_RUN_CUSTOM_IGNORE_URL_VALUE_FLAGS = {
    "-h",
    "--header",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "-b",
    "--cookie",
    "-e",
    "--referer",
    "-a",
    "--user-agent",
    "--proxy-header",
}
_RUN_CUSTOM_HEADER_STYLE_FLAGS = {
    "-h",
    "--header",
    "--proxy-header",
}
_TOOL_RESULT_MAX_STRING_CHARS = 600
_TOOL_RESULT_MAX_TOTAL_CHARS = 12000
_TOOL_RESULT_MAX_LIST_ITEMS = 40
_TOOL_RESULT_MAX_NESTED_LIST_ITEMS = 12
_TOOL_RESULT_MAX_DICT_KEYS = 40
_TOOL_RESULT_MAX_DEPTH = 4


def _is_rate_limit_error(exc: Exception | None) -> bool:
    text = str(exc or "").lower()
    return "429" in text or "rate limit" in text


def _is_transient_llm_error(exc: Exception | None) -> bool:
    text = str(exc or "").lower()
    transient_markers = (
        "temporary failure in name resolution",
        "name or service not known",
        "try again",
        "connection reset",
        "connection refused",
        "connection aborted",
        "network is unreachable",
        "timed out",
        "timeout",
        "dns",
    )
    return any(marker in text for marker in transient_markers)


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
    def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None | Any: ...


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

    def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        return None


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


def _structured_result_excerpt(raw_result: Any) -> str:
    text = str(raw_result or "").strip()
    if not text:
        return ""
    payload: Any = text
    if text[:1] in {"{", "["}:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = text
    summary = summarize_tool_output(payload)
    observations = summary.get("observations", [])
    if not isinstance(observations, list) or not observations:
        return ""
    return " ".join(str(item).strip() for item in observations[:3] if str(item).strip())


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


def _extract_verify_verdict_from_text(raw: str) -> dict[str, Any]:
    parsed = _extract_json_from_text(raw)
    if isinstance(parsed, dict):
        verdict = str(parsed.get("verdict", "")).strip().lower()
        if verdict in {"real_vulnerability", "false_positive", "inconclusive"}:
            return parsed

    verdict_match = re.search(r'"verdict"\s*:\s*"([^"]+)"', raw, re.IGNORECASE)
    if not verdict_match:
        return {}

    verdict_value = verdict_match.group(1).strip().lower()
    if verdict_value not in {"real_vulnerability", "false_positive", "inconclusive"}:
        return {}

    summary = ""
    summary_match = re.search(r'"summary"\s*:\s*"((?:\\.|[^"\\])*)"', raw, re.IGNORECASE)
    if summary_match:
        try:
            summary = json.loads(f'"{summary_match.group(1)}"')
        except json.JSONDecodeError:
            summary = summary_match.group(1)

    confidence: float | None = None
    confidence_match = re.search(r'"confidence"\s*:\s*([0-9]*\.?[0-9]+)', raw, re.IGNORECASE)
    if confidence_match:
        try:
            confidence = max(0.0, min(1.0, float(confidence_match.group(1))))
        except ValueError:
            confidence = None

    payload: dict[str, Any] = {
        "verdict": verdict_value,
        "summary": summary or raw.strip(),
    }
    if confidence is not None:
        payload["confidence"] = confidence
    return payload


def _coerce_optional_confidence(value: Any) -> float | None:
    try:
        if value is None:
            return None
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, confidence))


def _recon_summary_implies_completion(summary: Any) -> bool:
    text = str(summary or "").strip().lower()
    if not text:
        return False

    blocked_markers = (
        "blocked",
        "restriction",
        "restricted",
        "prevented",
        "policy",
        "localhost",
        "127.0.0.1",
        "insufficient",
        "limited",
        "unable to",
        "could not",
        "failed to",
        "no evidence",
    )
    if any(marker in text for marker in blocked_markers):
        return False

    completion_markers = (
        "completed",
        "complete",
        "confirmed",
        "successfully",
        "fingerprinted",
        "mapped",
        "identified",
        "discovered",
        "enumerated",
        "extracted",
        "synthesized",
        "validated",
        "reviewed",
        "analyzed",
    )
    return any(marker in text for marker in completion_markers)


def _recon_scenario_summary_implies_completion(
    *,
    task: Any,
    summary: Any,
    findings: Any = None,
    tools: Any = None,
) -> bool:
    task_text = str(task or "").strip().lower()
    summary_text = str(summary or "").strip().lower()
    findings_list = findings if isinstance(findings, list) else []
    tools_list = tools if isinstance(tools, list) else []
    if not task_text or not summary_text:
        return False

    findings_text = " ".join(
        f"{str(item.get('title', '')).strip()} {str(item.get('details', '')).strip()}".lower()
        for item in findings_list
        if isinstance(item, dict)
    )
    tools_text = " ".join(str(item).strip().lower() for item in tools_list if str(item).strip())
    evidence_text = " ".join(part for part in [summary_text, findings_text, tools_text] if part).strip()
    if not evidence_text:
        return False

    task_markers: dict[str, tuple[str, ...]] = {
        "structural content discovery": (
            "robots.txt",
            "sitemap",
            "swagger",
            "openapi",
            "api-docs",
            "portal",
            "metadata",
            "hidden path",
            "hidden paths",
            "directory",
            "directories",
            "admin",
            "debug",
            ".git",
            ".env",
            "backup",
        ),
        "api & endpoint extraction": (
            "swagger",
            "openapi",
            "api-docs",
            "graphql",
            "endpoint",
            "endpoints",
            "route",
            "routes",
            "websocket",
            "socket",
            "rest",
            "/api",
            "schema",
        ),
        "input & parameter profiling": (
            "parameter",
            "parameters",
            "input field",
            "input fields",
            "form",
            "forms",
            "query param",
            "body param",
            "json body",
            "hidden parameter",
            "hidden parameters",
        ),
        "identity & access analysis": (
            "auth",
            "login",
            "session",
            "cookie",
            "cookies",
            "token",
            "tokens",
            "bearer",
            "oauth",
            "oidc",
            "authentication",
            "authorization",
            "access control",
        ),
        "local web app perimeter mapping": (
            "service",
            "services",
            "port",
            "ports",
            "reachable",
            "accessible",
            "endpoint",
            "route",
        ),
        "defensive & tech fingerprinting": (
            "tech stack",
            "angular",
            "react",
            "vue",
            "node",
            "express",
            "typescript",
            "cors",
            "security header",
            "headers",
            "waf",
            "framework",
            "fingerprinted",
        ),
    }

    matched_task = next(
        (name for name in task_markers if name in task_text),
        "",
    )
    if not matched_task:
        return False

    return any(marker in evidence_text for marker in task_markers[matched_task])


def _parse_executer_output(raw: str, role: str = "unknown") -> ExecuterResult:
    parsed = _extract_json_from_text(raw)

    # CRITICAL FIX: If JSON parsing failed completely, try to extract verdict field directly from raw text
    # This handles cases where Verify agent outputs {"verdict": "..."} but JSON parsing fails
    if not parsed:
        extracted_verdict = _extract_verify_verdict_from_text(raw)
        if extracted_verdict:
            verdict_value = str(extracted_verdict.get("verdict", "")).strip().lower()
            logger.info(
                "executer_verdict_extracted_from_raw",
                role=role,
                verdict=verdict_value,
                raw_length=len(raw),
            )
            return ExecuterResult(
                status=verdict_value,
                confidence=_coerce_optional_confidence(extracted_verdict.get("confidence")),
                summary=str(extracted_verdict.get("summary", "")).strip() or raw.strip(),
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

    scenario_summaries = parsed.get("scenario_summaries") or []
    if not isinstance(scenario_summaries, list):
        scenario_summaries = []

    def _normalize_recon_status_value(
        value: Any,
        *,
        summary: Any = "",
        findings: Any = None,
        tools: Any = None,
        default: str = "failed",
    ) -> str:
        raw_status = str(value or "").strip().lower()
        summary_text = str(summary or "").strip().lower()
        findings_list = findings if isinstance(findings, list) else []
        tools_list = tools if isinstance(tools, list) else []
        has_findings = any(isinstance(item, dict) for item in findings_list)
        has_tools = any(str(item).strip() for item in tools_list)
        useful_summary_markers = (
            "discovered",
            "identified",
            "found",
            "revealed",
            "mapped",
            "enumerated",
            "fingerprinted",
            "observed",
            "detected",
            "collected",
            "exposed",
            "located",
        )
        blocked_summary_markers = (
            "blocked",
            "restriction",
            "restricted",
            "prevented",
            "policy",
            "localhost",
            "127.0.0.1",
            "insufficient",
            "limited",
        )
        if raw_status in {"complete", "completed", "done", "success", "succeeded"}:
            return "complete"
        if raw_status in {
            "blocked",
            "partial",
            "partially_complete",
            "partially completed",
            "partial_success",
            "partially_successful",
            "incomplete",
            "limited",
        }:
            return "blocked"
        if raw_status in {"failed", "failure", "error"}:
            if has_findings or has_tools or any(marker in summary_text for marker in useful_summary_markers):
                return "blocked"
            return "failed"
        if any(marker in summary_text for marker in blocked_summary_markers):
            return "blocked"
        has_useful_summary = any(marker in summary_text for marker in useful_summary_markers)
        if has_findings or has_useful_summary:
            return "complete"
        if has_tools and has_useful_summary:
            return "complete"
        if has_tools:
            return "blocked"
        return default

    normalized_scenario_summaries: list[dict[str, Any]] = []
    for item in scenario_summaries:
        if not isinstance(item, dict):
            continue
        normalized_item = dict(item)
        if role == "recon":
            normalized_item["status"] = _normalize_recon_status_value(
                normalized_item.get("status"),
                summary=normalized_item.get("summary"),
                findings=normalized_item.get("findings"),
                tools=normalized_item.get("tools"),
                default="blocked",
            )
        summary_value = normalized_item.get("summary", "")
        if isinstance(summary_value, list):
            summary_value = " ".join(str(x) for x in summary_value if str(x).strip())
        normalized_item["summary"] = str(summary_value or "").strip()
        findings_value = normalized_item.get("findings", [])
        normalized_item["findings"] = findings_value if isinstance(findings_value, list) else []
        tools_value = normalized_item.get("tools", [])
        normalized_item["tools"] = [
            str(x).strip() for x in tools_value if str(x).strip()
        ] if isinstance(tools_value, list) else []
        if (
            role == "recon"
            and normalized_item.get("status") in {"blocked", "failed"}
            and _recon_scenario_summary_implies_completion(
                task=normalized_item.get("task", ""),
                summary=normalized_item.get("summary", ""),
                findings=normalized_item.get("findings", []),
                tools=normalized_item.get("tools", []),
            )
        ):
            normalized_item["status"] = "complete"
        normalized_scenario_summaries.append(normalized_item)
    summary_statuses = [
        str(item.get("status", "")).strip().lower()
        for item in normalized_scenario_summaries
        if str(item.get("status", "")).strip()
    ]

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
        status = _normalize_recon_status_value(
            status,
            summary=parsed.get("summary", ""),
            findings=parsed.get("findings", []),
            tools=[
                tool_name
                for item in normalized_scenario_summaries
                if isinstance(item, dict)
                for tool_name in (
                    item.get("tools", []) if isinstance(item.get("tools", []), list) else []
                )
            ],
            default=status,
        )
        if summary_statuses:
            if all(item == "complete" for item in summary_statuses):
                status = "complete"
            elif any(item in {"complete", "blocked"} for item in summary_statuses):
                status = "blocked"
            else:
                status = "failed"
        elif (
            status == "blocked"
            and parsed.get("findings")
            and _recon_summary_implies_completion(parsed.get("summary", ""))
        ):
            status = "complete"
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

    findings = parsed.get("findings") or []
    evidence = parsed.get("evidence") or []
    needs = parsed.get("needs") or []
    summary = parsed.get("summary", "")
    next_hypotheses = parsed.get("next_hypotheses") or []
    raw_confidence = parsed.get("confidence")
    confidence = _coerce_optional_confidence(raw_confidence)

    if not isinstance(findings, list):
        findings = []
    if not isinstance(evidence, list):
        evidence = []
    if not isinstance(needs, list):
        needs = []
    if not isinstance(next_hypotheses, list):
        next_hypotheses = []

    # Ensure summary is a string
    if isinstance(summary, list):
        summary = " ".join(str(s) for s in summary) if summary else ""
    summary = str(summary) if summary else ""

    if role in {"verify", "retest"} and summary:
        embedded_verdict = _extract_verify_verdict_from_text(summary)
        embedded_status = str(embedded_verdict.get("verdict", "")).strip().lower()
        if embedded_status in {"real_vulnerability", "false_positive", "inconclusive"}:
            status = embedded_status
            summary = str(embedded_verdict.get("summary", "")).strip() or summary
            confidence = _coerce_optional_confidence(
                embedded_verdict.get("confidence", confidence)
            )

    return ExecuterResult(
        status=status,
        confidence=confidence,
        findings=findings,
        evidence=evidence,
        needs=needs,
        summary=summary,
        next_hypotheses=[str(item) for item in next_hypotheses],
        scenario_summaries=normalized_scenario_summaries,
    )


def _default_status_for_failed_consolidation(role: str) -> str:
    normalized = str(role or "").strip().lower()
    if normalized in {"verify", "retest", "exploit"}:
        return "inconclusive"
    if normalized == "recon":
        return "failed"
    return "incomplete"


def _role_uses_tool_round_model(role: str) -> bool:
    return str(role or "").strip().lower() in {"recon", "exploit"}


def _get_valid_params(tool: Tool) -> set[str] | None:
    parameters = tool.parameters if isinstance(tool.parameters, dict) else {}
    properties = parameters.get("properties", {}) if isinstance(parameters, dict) else {}
    if isinstance(properties, dict) and properties:
        return {str(name) for name in properties.keys() if str(name).strip()}

    try:
        sig = inspect.signature(tool.fn)
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
        project_cache_dir: str | None = None,
        approval_mode: str = "custom",
    ) -> None:
        self._sandbox_root = ensure_sandbox_environment()
        self._role = role
        self._system_prompt = system_prompt
        self._max_tool_rounds = max_tool_rounds
        self._max_tool_calls_per_round = max(0, int(max_tool_calls_per_round or 0))
        self._call_timeout_seconds = call_timeout_seconds
        self._mode = mode or llm_mode.mode
        self._cb = callback or _NoOpCallback()
        self._project_id = str(project_id or "").strip()
        self._project_cache_dir = str(project_cache_dir or "").strip()
        self._approval_mode = str(approval_mode or "custom").lower().strip()

        self._tools = {t.name: t for t in tools}
        self._tool_schemas = [t.schema() for t in tools]
        self._tool_valid_params = {t.name: _get_valid_params(t) for t in tools}
        self._execution_tool_timeout_cap_seconds: int | None = None
        self._current_user_message: str = ""
        self._run_max_tool_rounds_override: int | None = None

        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LLMClient(self._local_config, mode="local", client_name=self._role)
            self._model_name = self._local_config.model
        else:
            self._config = config or get_public_agent_config(self._role)
            self._llm = LLMClient(self._config, mode="public", client_name=self._role)
            self._model_name = self._config.model

        # Initialize rate limiter to prevent Mistral 429 errors (4 req/min limit)
        # We limit to 3 req/min to leave buffer
        self._rate_limiter = LLMRateLimiter(max_calls_per_minute=3)

        logger.info(
            "executer_initialized",
            role=self._role,
            mode=self._mode,
            model=self._model_name,
            tools=len(self._tools),
            sandbox=str(self._sandbox_root),
        )

    def _effective_max_tool_rounds(self) -> int:
        override = self._run_max_tool_rounds_override
        if isinstance(override, int) and override > 0:
            return override
        return self._max_tool_rounds

    def reset_context_window_for_cycle(self) -> None:
        """Legacy hook retained as a no-op after context-window removal."""
        return

    async def clear_context_window(self) -> None:
        """Legacy hook retained as a no-op after context-window removal."""
        return

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

    def _stringify_tool_arg_value(
        self,
        value: Any,
        *,
        depth: int = 0,
        string_limit: int = 80,
    ) -> str:
        if depth >= 2:
            return "..."
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            text = value.strip()
            if string_limit > 0 and len(text) > string_limit:
                text = text[: max(string_limit - 3, 1)] + "..."
            return text
        if isinstance(value, list):
            preview = [
                self._stringify_tool_arg_value(item, depth=depth + 1, string_limit=string_limit)
                for item in value[:4]
            ]
            if len(value) > 4:
                preview.append("...")
            return f"[{', '.join(preview)}]"
        if isinstance(value, dict):
            preview_parts: list[str] = []
            for idx, (key, item) in enumerate(value.items()):
                if idx >= 4:
                    preview_parts.append("...")
                    break
                preview_parts.append(
                    f"{key}={self._stringify_tool_arg_value(item, depth=depth + 1, string_limit=string_limit)}"
                )
            return "{" + ", ".join(preview_parts) + "}"
        text = str(value).strip()
        if string_limit > 0 and len(text) > string_limit:
            return text[: max(string_limit - 3, 1)] + "..."
        return text

    def _format_tool_invocation_preview(self, tool_name: str, args: dict[str, Any]) -> str:
        clean_tool = str(tool_name or "").strip() or "unknown_tool"
        if not isinstance(args, dict) or not args:
            return clean_tool

        if clean_tool == "run_custom":
            base_cmd = str(args.get("command", "")).strip()
            arg_list = args.get("args") if isinstance(args.get("args"), list) else []
            rendered_args = " ".join(str(item).strip() for item in arg_list if str(item).strip())
            full = f"{base_cmd} {rendered_args}".strip()
            return full or clean_tool

        rendered_parts: list[str] = []
        for key, value in args.items():
            if key.startswith("_"):
                continue
            string_limit = 0 if clean_tool == "run_python" and key == "code" else 80
            rendered = self._stringify_tool_arg_value(value, string_limit=string_limit)
            if rendered:
                rendered_parts.append(f"{key}={rendered}")
            if len(rendered_parts) >= 5:
                break

        if not rendered_parts:
            return clean_tool
        return f"{clean_tool}({', '.join(rendered_parts)})"

    def _tool_result_excerpt(self, raw_result: Any, limit: int = 220) -> str:
        text = str(raw_result or "").strip()
        if not text:
            return "No output returned."
        structured_excerpt = _structured_result_excerpt(text)
        if structured_excerpt:
            return _short_text(structured_excerpt, limit=limit)
        compacted = _compact_tool_result_payload(text)
        flattened = re.sub(r"\s+", " ", compacted).strip()
        if len(flattened) <= limit:
            return flattened
        return flattened[: limit - 3] + "..."

    def _build_round_execution_summary(
        self,
        *,
        round_index: int,
        tool_results: list[dict[str, Any]],
    ) -> str:
        if not tool_results:
            return f"Round {round_index}: no tools executed."
        tool_names = [str(item.get("name", "?")).strip() for item in tool_results]
        joined_tools = ", ".join(name for name in tool_names if name) or "unknown tools"
        evidence_bits: list[str] = []
        for item in tool_results[:3]:
            tool_name = str(item.get("name", "?")).strip() or "unknown"
            evidence_bits.append(
                f"{tool_name}: {self._tool_result_excerpt(item.get('result', ''))}"
            )
        return (
            f"Round {round_index} executed {len(tool_results)} tool(s) [{joined_tools}]. "
            f"Observed evidence: {' | '.join(evidence_bits)}"
        )

    def _build_tool_round_model_result(
        self,
        *,
        rounds_executed: int,
        round_summaries: list[dict[str, Any]],
        tool_results: list[dict[str, Any]],
    ) -> ExecuterResult:
        normalized_role = str(self._role or "").strip().lower()
        status = "inconclusive" if normalized_role == "exploit" else ("complete" if tool_results else "failed")

        findings: list[dict[str, Any]] = []
        summary_lines: list[str] = []
        for item in round_summaries:
            if not isinstance(item, dict):
                continue
            round_index = int(item.get("round", 0) or 0)
            summary_text = str(item.get("summary", "")).strip()
            tools = item.get("tools", [])
            if summary_text:
                summary_lines.append(summary_text)
                findings.append(
                    {
                        "title": f"Round {round_index} evidence",
                        "severity": "info",
                        "details": summary_text,
                        "tools": tools if isinstance(tools, list) else [],
                    }
                )

        if not summary_lines and tool_results:
            fallback_summary = self._format_tool_results(tool_results)
            summary_lines.append(fallback_summary)
            findings.append(
                {
                    "title": "Collected tool evidence",
                    "severity": "info",
                    "details": fallback_summary,
                    "tools": [
                        str(item.get("name", "?")).strip()
                        for item in tool_results
                        if str(item.get("name", "")).strip()
                    ],
                }
            )

        opener = (
            f"Collected exploit evidence across {rounds_executed} tool round(s). Forwarding raw evidence and per-round summaries for verdicting."
            if normalized_role == "exploit"
            else f"Collected reconnaissance evidence across {rounds_executed} tool round(s). Forwarding raw evidence and per-round summaries for analysis."
        )
        joined_summary = "\n".join(summary_lines[:3]).strip()
        summary = opener if not joined_summary else f"{opener}\n{joined_summary}"
        return ExecuterResult(
            status=status,
            findings=findings,
            summary=summary,
            rounds_executed=rounds_executed,
            round_labels=[f"r{n}" for n in range(1, rounds_executed + 1)],
        )

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

    def _declared_target_url(self) -> str:
        message = str(getattr(self, "_current_user_message", "") or "")
        match = re.search(r"^Target:\s*(\S+)", message, flags=re.MULTILINE)
        return match.group(1).strip() if match else ""

    def _url_host_port(self, value: str) -> tuple[str, int | None, str]:
        parsed = urlparse(str(value or "").strip())
        host = (parsed.hostname or "").strip().lower()
        scheme = (parsed.scheme or "").strip().lower()
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is None and scheme == "http":
            port = 80
        elif port is None and scheme == "https":
            port = 443
        return host, port, scheme

    def _is_loopback_hostname(self, host: str) -> bool:
        normalized = str(host or "").strip().lower()
        return normalized in {"localhost", "127.0.0.1", "::1"}

    def _looks_like_network_url(self, value: str) -> bool:
        stripped = str(value or "").strip().strip("'\"")
        return stripped.lower().startswith(("http://", "https://", "ws://", "wss://"))

    def _consume_non_target_flag_value_tokens(
        self,
        tokens: list[str],
        idx: int,
        flag: str,
    ) -> int:
        next_idx = idx + 1
        if next_idx >= len(tokens):
            return next_idx

        if flag in _RUN_CUSTOM_HEADER_STYLE_FLAGS:
            header_value = str(tokens[next_idx] or "").strip()
            if (
                header_value.endswith(":")
                and next_idx + 1 < len(tokens)
                and not str(tokens[next_idx + 1] or "").strip().startswith("-")
            ):
                return next_idx + 2
        return next_idx + 1

    def _extract_urls_from_run_custom(self, args: dict[str, Any]) -> list[str]:
        if not isinstance(args, dict):
            return []
        command = str(args.get("command", "") or "").strip().lower()
        _ = command  # command-specific handling may be expanded without changing callers.
        tokens = [str(value or "").strip() for value in (args.get("args") or [])]
        urls: list[str] = []
        idx = 0
        while idx < len(tokens):
            token = tokens[idx]
            lowered = token.lower()
            if not token:
                idx += 1
                continue

            if lowered in _RUN_CUSTOM_IGNORE_URL_VALUE_FLAGS:
                idx = self._consume_non_target_flag_value_tokens(tokens, idx, lowered)
                continue

            if lowered in _RUN_CUSTOM_URL_TARGET_FLAGS:
                next_value = tokens[idx + 1] if idx + 1 < len(tokens) else ""
                if self._looks_like_network_url(next_value):
                    urls.append(next_value.strip("'\""))
                idx += 2
                continue

            matched_prefix = next(
                (prefix for prefix in _RUN_CUSTOM_URL_TARGET_PREFIXES if lowered.startswith(prefix)),
                None,
            )
            if matched_prefix is not None:
                value = token[len(matched_prefix) :].strip().strip("'\"")
                if self._looks_like_network_url(value):
                    urls.append(value)
                idx += 1
                continue

            if self._looks_like_network_url(token):
                urls.append(token.strip("'\""))
            idx += 1
        return urls

    def _detect_out_of_scope_run_custom_url(self, tool_name: str, args: dict[str, Any]) -> str | None:
        if tool_name != "run_custom" or not isinstance(args, dict):
            return None

        target_url = self._declared_target_url()
        target_host, target_port, _ = self._url_host_port(target_url)
        if not target_host:
            return None

        for url in self._extract_urls_from_run_custom(args):
            url_host, url_port, _ = self._url_host_port(url)
            if not url_host:
                continue

            same_host = url_host == target_host
            same_loopback_family = (
                self._is_loopback_hostname(url_host)
                and self._is_loopback_hostname(target_host)
            )
            if not (same_host or same_loopback_family):
                return f"{url} is outside target host {target_host}"
            if target_port is not None and url_port is not None and url_port != target_port:
                return f"{url} uses port {url_port}, expected {target_port}"

        return None

    def _build_tool_invocation_signature(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        scenario_id: str,
    ) -> str:
        semantic_tool_names = {
            "js_source_code_analyzer",
            "http_probe",
            "api_passive_enum",
            "api_endpoint_discovery",
            "api_response_analyzer",
            "api_service_recon",
            "passive_web_recon",
            "session_token_analysis",
            "websocket_recon",
        }
        if tool_name.strip().lower() in semantic_tool_names:
            normalized_target = str(
                args.get("target")
                or args.get("url")
                or args.get("endpoint")
                or args.get("host")
                or ""
            ).strip().lower()
            if normalized_target:
                return (
                    f"{scenario_id.strip().lower()}::"
                    f"{tool_name.strip().lower()}::semantic::{normalized_target}"
                )
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

            if tool_name == "run_custom" and isinstance(args, dict):
                from server.agents.tools.run_custom import RunCustomRequest
                try:
                    # Normalize and resolve paths via RunCustomRequest validation
                    validated = RunCustomRequest(**args)
                    args = validated.model_dump()
                except Exception:
                    pass

            args = self._filter_tool_args(tool_name, args)
            args, sanitized_output_flags = self._sanitize_known_file_output_args(tool_name, args)
            if sanitized_output_flags:
                self._cb.on_step(
                    f"[{self._role}] normalized {tool_name}: removed file-output args {' '.join(sanitized_output_flags[:4])}"
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

            target_scope_issue = self._detect_out_of_scope_run_custom_url(tool_name, args)
            if target_scope_issue:
                result = json.dumps(
                    {
                        "success": False,
                        "error": (
                            "Command target is outside the current scenario target. "
                            "Re-run against the exact target host and port from the operator packet."
                        ),
                        "blocked_target": target_scope_issue,
                        "role": self._role,
                        "tool": tool_name,
                    },
                    ensure_ascii=True,
                )
                self._cb.on_warn(
                    f"[{self._role}] blocked out-of-scope target for {tool_name}: {target_scope_issue}"
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
                if self._tool_requires_user_approval_with_args(tool_name, args):
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
                    cmd_preview = self._format_tool_invocation_preview(tool_name, args)
                    if cmd_preview:
                        self._cb.on_step(
                            f"[{self._role}] tool call"
                            f"{f' [{scenario_id}]' if scenario_id else ''}: "
                            f"{cmd_preview}"
                        )
                    else:
                        self._cb.on_step(
                            f"[{self._role}] tool call"
                            f"{f' [{scenario_id}]' if scenario_id else ''}: {tool_name}"
                        )
                    try:
                        callback_token = _executer_callback_context.set(self._cb)
                        tool_context_token = _executer_tool_context.set(
                            {
                                "project_id": self._project_id,
                                "project_cache_dir": self._project_cache_dir,
                                "role": self._role,
                                "tool": tool_name,
                                "target_url": self._declared_target_url(),
                                "approval_mode": self._approval_mode,
                                "safety_profile": (
                                    get_run_custom_command_profile(
                                        str(args.get("command", "")).strip().lower(),
                                        role=self._role,
                                    ).to_dict()
                                    if tool_name == "run_custom"
                                    else get_tool_safety_profile(tool_name, role=self._role).to_dict()
                                ),
                            }
                        )
                        try:
                            raw_result = await tool.execute(**args)
                        finally:
                            _executer_tool_context.reset(tool_context_token)
                            _executer_callback_context.reset(callback_token)
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
                    "safety_profile": (
                        get_run_custom_command_profile(
                            str(args.get("command", "")).strip().lower(),
                            role=self._role,
                        ).to_dict()
                        if tool_name == "run_custom"
                        else get_tool_safety_profile(tool_name, role=self._role).to_dict()
                    ),
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
        return self._tool_requires_user_approval_with_args(tool_name, {})

    def _tool_requires_user_approval_with_args(self, tool_name: str, args: dict[str, Any]) -> bool:
        approval_mode = self._approval_mode
        get_mode_fn = getattr(self._cb, "get_approval_mode", None)
        if callable(get_mode_fn):
            try:
                latest_mode = get_mode_fn()
                if latest_mode:
                    approval_mode = latest_mode
            except Exception:
                pass

        if str(tool_name or "").strip().lower() == "run_custom":
            command_name = str(args.get("command", "")).strip().lower() if isinstance(args, dict) else ""
            profile = get_run_custom_command_profile(command_name, role=self._role)
            result = requires_approval_for_execution(
                profile=profile,
                approval_mode=approval_mode,
                role=self._role,
                tool_name="run_custom",
            )
            logger.info(
                "tool_approval_check",
                tool_name=tool_name,
                command=command_name,
                approval_mode=approval_mode,
                role=self._role,
                requires_approval=result,
                callback_type=type(self._cb).__name__,
                has_request_tool_approval=hasattr(self._cb, "request_tool_approval"),
            )
            return result

        profile = get_tool_safety_profile(tool_name, role=self._role)
        return requires_approval_for_execution(
            profile=profile,
            approval_mode=approval_mode,
            role=self._role,
            tool_name=tool_name,
        )

    async def _request_tool_approval(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        callback_fn = getattr(self._cb, "request_tool_approval", None)
        if not callable(callback_fn):
            logger.warning(
                "tool_approval_no_callback",
                tool_name=tool_name,
                callback_type=type(self._cb).__name__,
            )
            return False

        logger.info(
            "tool_approval_requesting",
            tool_name=tool_name,
            role=self._role,
            callback_type=type(self._cb).__name__,
        )

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

        logger.info(
            "tool_approval_decision_received",
            tool_name=tool_name,
            decision_type=type(decision).__name__,
            decision_value=str(decision)[:200] if decision is not None else "None",
        )

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
        max_rounds = self._effective_max_tool_rounds()
        warmup_batch_mode = "Warmup scenario batch" in str(
            getattr(self, "_current_user_message", "") or ""
        )
        role_templates = {
            "verify": (
                f"[CONSOLIDATION ROUND {round_index}] This is your FINAL round (Round {round_index}/{max_rounds}). "
                "You have analyzed all verification results. Now output ONLY valid JSON with two fields: "
                '"verdict" (real_vulnerability|false_positive|inconclusive) and "summary" (1-2 sentences). '
                "NO prose before or after JSON. NO markdown. Start with { and end with }. Example:\n"
                '{"verdict": "real_vulnerability", "summary": "The vulnerability was confirmed through payload testing."}'
            ),
            "recon": (
                f"[CONSOLIDATION ROUND {round_index}] This is your FINAL round (Round {round_index}/{max_rounds}). "
                "You have completed reconnaissance. "
                + (
                    "Because this is warmup batch mode, output ONLY valid JSON with four top-level fields: "
                    '"status" (complete|blocked|failed), "findings" (array), "summary" (1-2 sentences), '
                    'and "scenario_summaries" (array). Each scenario_summaries item must contain '
                    '"scenario_id", "task", "status" (complete|blocked|failed), "summary", "findings", and "tools". '
                    if warmup_batch_mode
                    else "Now output ONLY valid JSON with three fields: "
                    '"status" (complete|blocked|failed), "findings" (array), and "summary" (1-2 sentences). '
                )
                + "NO prose before or after JSON. NO markdown. Start with { and end with }."
            ),
            "exploit": (
                f"[CONSOLIDATION ROUND {round_index}] This is your FINAL round (Round {round_index}/{max_rounds}). "
                "You have completed exploitation testing. Now output ONLY valid JSON with three fields: "
                '"status" (vulnerable|not_vulnerable|blocked|inconclusive), "findings" (array), and "summary" (1-2 sentences). '
                "NO prose before or after JSON. NO markdown. Start with { and end with }."
            ),
        }
        default_msg = (
            f"[CONSOLIDATION ROUND {round_index}] This is your FINAL consolidation round ({round_index}/{self._effective_max_tool_rounds()}). "
            "Output ONLY valid JSON. NO tools. NO prose. NO markdown. Start with { and end with }."
        )
        return role_templates.get(self._role, default_msg)

    def _build_forced_consolidation_prompt(
        self,
        *,
        round_index: int,
        last_content: str,
        tool_results: list[dict[str, Any]],
        forced_due_to_final_round_tool_calls: bool,
    ) -> str:
        recent_tool_output = self._format_tool_results(tool_results[-8:])
        if len(recent_tool_output) > 5000:
            recent_tool_output = recent_tool_output[-5000:]
        warmup_batch_mode = "Warmup scenario batch" in str(
            getattr(self, "_current_user_message", "") or ""
        )
        prefix = (
            "You attempted tool calls in the final consolidation round, which is not allowed.\n"
            if forced_due_to_final_round_tool_calls
            else "Use only the already collected evidence below.\n"
        )

        role_specific = {
            "verify": (
                prefix
                + "Do NOT call tools. Use only the already collected verification evidence below.\n"
                'Return ONLY strict JSON with: {"verdict":"real_vulnerability|false_positive|inconclusive","summary":"..."}'
            ),
            "retest": (
                prefix
                + "Do NOT call tools. Use only the already collected retest evidence below.\n"
                'Return ONLY strict JSON with: {"verdict":"real_vulnerability|false_positive|inconclusive","summary":"..."}'
            ),
            "recon": (
                prefix
                + "Do NOT call tools. Use only the already collected reconnaissance evidence below.\n"
                + (
                    'Return ONLY strict JSON with: {"status":"complete|blocked|failed","findings":[],"summary":"...","scenario_summaries":[{"scenario_id":"s1","task":"...","status":"complete|blocked|failed","summary":"...","findings":[],"tools":[]}]}'
                    if warmup_batch_mode
                    else 'Return ONLY strict JSON with: {"status":"complete|blocked|failed","findings":[],"summary":"..."}'
                )
            ),
            "exploit": (
                prefix
                + "Do NOT call tools. Use only the already collected exploitation evidence below.\n"
                'Return ONLY strict JSON with: {"status":"vulnerable|not_vulnerable|blocked|inconclusive","findings":[],"summary":"..."}'
            ),
        }.get(
            self._role,
            "Do NOT call tools. Return ONLY strict JSON using the evidence already collected.",
        )

        sections = [
            f"[FORCED FINAL CONSOLIDATION] Round {round_index}/{self._effective_max_tool_rounds()}",
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
        forced_due_to_final_round_tool_calls: bool = True,
    ) -> ExecuterResult:
        if forced_due_to_final_round_tool_calls:
            self._cb.on_warn(
                f"[{self._role}] final round emitted tool calls; forcing one last JSON-only consolidation pass"
            )
        else:
            self._cb.on_step(
                f"[{self._role}] consolidating collected evidence into final JSON"
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
                    forced_due_to_final_round_tool_calls=forced_due_to_final_round_tool_calls,
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
            if forced_due_to_final_round_tool_calls:
                summary = (
                    "Final consolidation failed after the model attempted tool calls in the last round "
                    f"and the forced JSON-only retry errored: {llm_exc}"
                )
            else:
                summary = (
                    "Final evidence consolidation failed after tool execution "
                    f"because the JSON-only retry errored: {llm_exc}"
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

    async def run(
        self,
        user_message: str,
        *,
        max_tool_rounds_override: int | None = None,
    ) -> ExecuterResult:
        self._cb.on_step(f"[{self._role}] starting run")
        self._current_user_message = str(user_message or "")
        previous_round_override = self._run_max_tool_rounds_override
        if max_tool_rounds_override is None:
            self._run_max_tool_rounds_override = None
        else:
            self._run_max_tool_rounds_override = min(3, max(1, int(max_tool_rounds_override)))
        warmup_batch_mode = "Warmup scenario batch" in self._current_user_message

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
        round_execution_summaries: list[dict[str, Any]] = []
        tool_round_model = _role_uses_tool_round_model(self._role)

        async def _finalize_result(result: ExecuterResult) -> ExecuterResult:
            try:
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
                self._cb.on_done(f"[{self._role}] finished with status={result.status}")
                return result
            finally:
                self._run_max_tool_rounds_override = previous_round_override

        effective_max_tool_rounds = self._effective_max_tool_rounds()
        for round_index in range(1, effective_max_tool_rounds + 1):
            rounds_executed = round_index
            self._cb.on_step(
                f"[{self._role}] LLM round {round_index}/{effective_max_tool_rounds}"
            )

            # CRITICAL: Before final consolidation round, inject explicit reminder to force JSON-only output
            # This prevents LLM context drift after seeing hundreds of lines of tool output
            is_final_round = round_index >= effective_max_tool_rounds
            if (
                not tool_round_model
                and is_final_round
                and len(messages) > 2
            ):  # Only inject if we have tool results to consolidate
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
                    is_rate_limited = _is_rate_limit_error(exc)
                    is_transient_error = _is_transient_llm_error(exc)

                    # BACKUP LLM FALLBACK: On 429 or transient network/DNS errors,
                    # try backup LLM for a single call if configured.
                    if (is_rate_limited or is_transient_error) and attempt <= 1:
                        backup_llm = await backup_fallback.get_backup_llm()
                        if backup_llm is not None:
                            try:
                                logger.info(
                                    "backup_llm_fallback_attempt",
                                    role=self._role,
                                    round=round_index,
                                    reason="main_llm_429" if is_rate_limited else "main_llm_transient_error",
                                )
                                self._cb.on_warn(
                                    f"[{self._role}] Using backup LLM (main hit {'429' if is_rate_limited else 'temporary error'}); "
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
                    if is_transient_error and attempt < max_attempts and not used_backup_llm:
                        wait_seconds = 5.0 if attempt == 1 else 12.0
                        self._cb.on_warn(
                            f"[{self._role}] LLM temporary network/DNS error "
                            f"(attempt {attempt}/{max_attempts}); retrying in {wait_seconds:.0f}s"
                        )
                        logger.warning(
                            "llm_transient_error_backoff",
                            role=self._role,
                            round=round_index,
                            attempt=attempt,
                            wait_seconds=wait_seconds,
                            error=str(exc)[:160],
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
                self._run_max_tool_rounds_override = previous_round_override
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

            messages.append(
                {
                    "role": "assistant",
                    "content": last_content,
                    "tool_calls": tool_calls,
                },
            )

            # CRITICAL: Round 3 consolidation is mandatory for ALL roles
            # Final round (Round 3/3) must ONLY output JSON, not execute tools
            is_final_round = round_index >= effective_max_tool_rounds
            is_consolidation_role = self._role in ("verify", "retest")

            # ALL roles skip tools in final round (consolidation-only)
            skip_tools_this_round = bool(
                (not tool_round_model)
                and is_final_round
                and tool_calls
                and effective_max_tool_rounds > 1
            )

            # DEBUG: Log consolidation decision
            logger.info(
                "consolidation_decision",
                role=self._role,
                round=round_index,
                max_rounds=effective_max_tool_rounds,
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
                    if tool_round_model and all_tool_results:
                        result = self._build_tool_round_model_result(
                            rounds_executed=round_index,
                            round_summaries=round_execution_summaries,
                            tool_results=all_tool_results,
                        )
                        return await _finalize_result(result)
                    # Final round with no tool calls: consolidate now
                    result = _parse_executer_output(last_content, role=self._role)
                    return await _finalize_result(result)
                else:
                    # Non-final round with no tool calls: force next iteration to reach final consolidation
                    if warmup_batch_mode and self._role == "recon":
                        nudge = (
                            "Warmup batch mode requires active evidence collection. "
                            "You did not invoke any tools this non-final round. In your next response, call at least one "
                            "focused scenario-locked recon tool with `_scenario_id`, unless every assigned scenario is "
                            "objectively impossible for this target. For loopback/local web targets, prefer focused "
                            "local tools such as http_probe, directory_file_fuzzing, api_endpoint_discovery, "
                            "api_passive_enum, api_response_analyzer, api_service_recon, js_source_code_analyzer, "
                            "passive_web_recon, websocket_recon, or session_token_analysis. "
                            "Do not spend another non-final round only thinking."
                        )
                    else:
                        nudge = (
                            "You did not invoke any tools this round. Please continue your analysis and invoke focused "
                            "tools if another tool round is needed."
                        )
                    no_tool_message = (
                        f"[{self._role}] No tool calls on non-final round {round_index}; continuing to next round"
                    )
                    if warmup_batch_mode and self._role == "recon":
                        self._cb.on_warn(no_tool_message)
                    else:
                        self._cb.on_step(no_tool_message)
                    messages.append({
                        "role": "user",
                        "content": nudge,
                    })
                    continue

            tool_messages, tool_results, discovered, halted_for_approval = await self._run_tools(
                tool_calls,
                previous_tool_results=all_tool_results,
            )
            messages.extend(tool_messages)
            all_tool_results.extend(tool_results)
            all_discovered_target_types.update(discovered)

            if tool_results:
                round_summary = self._build_round_execution_summary(
                    round_index=round_index,
                    tool_results=tool_results,
                )
                round_execution_summaries.append(
                    {
                        "round": round_index,
                        "summary": round_summary,
                        "tools": [
                            str(item.get("name", "?")).strip()
                            for item in tool_results
                            if str(item.get("name", "")).strip()
                        ],
                    }
                )
                if tool_round_model and round_index < effective_max_tool_rounds:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                f"Round {round_index} evidence summary:\n{round_summary}\n\n"
                                "If another tool round is useful, carry forward the most important findings from this "
                                "summary and then choose the next focused tools or payloads. Do not produce final JSON; "
                                "after the last allowed tool round, the system will forward all collected evidence and "
                                "summaries to the perceptor."
                            ),
                        }
                    )

            if halted_for_approval:
                self._run_max_tool_rounds_override = previous_round_override
                return ExecuterResult(
                    status="awaiting_user_approval",
                    summary="Execution paused awaiting user approval for a tool call.",
                    tool_results=all_tool_results,
                    discovered_target_types=sorted(all_discovered_target_types),
                    rounds_executed=round_index,
                    round_labels=[f"r{n}" for n in range(1, round_index + 1)],
                )

            # If we consumed the final allowed round, return the aggregated tool output.
            if round_index >= effective_max_tool_rounds:
                if tool_round_model and all_tool_results:
                    result = self._build_tool_round_model_result(
                        rounds_executed=round_index,
                        round_summaries=round_execution_summaries,
                        tool_results=all_tool_results,
                    )
                    return await _finalize_result(result)
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
                rounds_executed=effective_max_tool_rounds,
                round_labels=[f"r{n}" for n in range(1, effective_max_tool_rounds + 1)],
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
