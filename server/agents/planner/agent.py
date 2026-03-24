"""
PlannerAgent — LangGraph-based agent that builds penetration-testing plans.

Graph:
  START → reason → (has tool_calls?) ─yes─→ execute_tools → reason (loop)
                                      ─no──→ parse_output → END
"""

from __future__ import annotations

import asyncio
import difflib
import inspect
import json
import random
import re
import uuid
from dataclasses import dataclass, field
from operator import add
from typing import Annotated, Any, Protocol, TypedDict

import structlog
import httpx
from langgraph.graph import END, START, StateGraph

from server.config.agent import (
    LocalLLMConfig,
    PublicLLMConfig,
    local_llm_config,
    public_llm_config,
    llm_mode,
)
from server.core.llm import ChatMessage, LLMClient
from server.core.llm_local import LocalLLMClient
from server.core.tool import Tool, coerce_args_from_schema
from .config import (
    MAX_TOOL_ROUNDS,
    MAX_TOOL_RESULT_CHARS,
    PLANNER_CALL_TIMEOUT_SECONDS,
    PLANNER_MAX_TOKENS_PER_REQUEST,
    _DISCOVERY_TOOLS,
    _MAX_RETRIES,
    _RETRY_BACKOFF_BASE,
    _RETRY_JITTER_MAX,
    _TRANSIENT_EXCEPTIONS,
)
from .prompts import INITIAL_SYSTEM_PROMPT, LOOP_SYSTEM_PROMPT
from .tools import ALL_PLANNER_TOOLS
from .tools.pentest_plan import _current_plan

logger = structlog.get_logger(__name__)



# ═════════════════════════════════════════════════════════════════════════════
# CALLBACK PROTOCOL
# ═════════════════════════════════════════════════════════════════════════════


class PlannerCallback(Protocol):
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


# ═════════════════════════════════════════════════════════════════════════════
# GRAPH STATE
# ═════════════════════════════════════════════════════════════════════════════


class PlannerState(TypedDict):
    messages: Annotated[list[dict[str, Any]], add]
    tool_schemas: list[dict[str, Any]]
    round_count: int
    total_tool_calls: int
    last_response: str
    last_tool_calls: list[dict[str, Any]]
    last_tool_results: list[dict[str, Any]]
    stop_after_tools: bool
    is_loop: bool
    plan_result: dict[str, Any]
    error: str
    recovery_attempted: bool


# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ═════════════════════════════════════════════════════════════════════════════


@dataclass
class PlannerResult:
    scenarios: list[dict] = field(default_factory=list)
    needs: list[dict] = field(default_factory=list)
    summary: str = ""
    tool_results: list[dict[str, Any]] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS — Message conversion
# ═════════════════════════════════════════════════════════════════════════════


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


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS — Tool introspection
# ═════════════════════════════════════════════════════════════════════════════


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


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS — Text / JSON utilities
# ═════════════════════════════════════════════════════════════════════════════


def _truncate_result(result_str: str, max_chars: int = MAX_TOOL_RESULT_CHARS) -> str:
    if len(result_str) <= max_chars:
        return result_str
    return result_str[:max_chars] + f"\n[TRUNCATED — first {max_chars} chars]"


def _normalized_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def _is_successful_tool_output(content: Any) -> bool:
    if not isinstance(content, str):
        return False
    text = content.strip()
    if not text:
        return False
    lowered = text.lower()
    return not (lowered.startswith("error") or lowered.startswith("rejected"))


def _repair_truncated_json(raw: str) -> dict[str, Any] | None:
    """Repair truncated JSON by closing open brackets/braces.

    Handles the common case where Groq's failed_generation cuts off
    mid-JSON. Strips trailing incomplete tokens, closes brackets.
    """
    text = raw.strip()
    if not text or text[0] != "{":
        return None

    # Strip trailing incomplete key-value pairs and dangling commas.
    text = re.sub(r',\s*"[^"]*"?\s*:?\s*$', "", text)
    text = re.sub(r',\s*$', "", text)
    # Strip trailing incomplete string values: ,"key":"partial...
    text = re.sub(r',\s*"[^"]*"\s*:\s*"[^"]*$', "", text)

    open_braces = 0
    open_brackets = 0
    in_string = False
    escape = False

    for ch in text:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            open_braces += 1
        elif ch == "}":
            open_braces -= 1
        elif ch == "[":
            open_brackets += 1
        elif ch == "]":
            open_brackets -= 1

    if open_braces == 0 and open_brackets == 0:
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None

    if in_string:
        text += '"'

    text += "]" * max(0, open_brackets) + "}" * max(0, open_braces)

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _deep_repair_plan_from_truncated(raw_args: dict[str, Any]) -> dict[str, Any]:
    """Post-process a repaired truncated plan to ensure structural validity.

    After _repair_truncated_json closes brackets, the last phase/step/scenario
    may be incomplete. This function:
    - Ensures all 5 phases exist.
    - Removes scenarios missing required keys.
    - Ensures steps have valid structure.
    """
    plan = dict(raw_args)

    # Guarantee target and scope.
    plan.setdefault("target", "")
    plan.setdefault("scope", "")
    plan.setdefault("target_types", ["web"])
    plan.setdefault("notes", "Plan recovered from truncated LLM output.")

    phases = plan.get("phases", [])
    if not isinstance(phases, list):
        phases = []

    # Ensure phases are dicts with required keys.
    cleaned_phases: list[dict[str, Any]] = []
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        phase.setdefault("name", "Unknown")
        phase.setdefault("priority", len(cleaned_phases) + 1)
        steps = phase.get("steps", [])
        if not isinstance(steps, list):
            steps = []
        valid_steps: list[dict[str, Any]] = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            step.setdefault("id", f"step-{uuid.uuid4().hex[:6]}")
            step.setdefault("description", "")
            scenarios = step.get("scenarios", [])
            if not isinstance(scenarios, list):
                scenarios = []
            valid_scenarios = [
                s
                for s in scenarios
                if isinstance(s, dict) and isinstance(s.get("task"), str) and s["task"].strip()
            ]
            # Fill defaults on each scenario.
            for sc in valid_scenarios:
                sc.setdefault("agent", "recon")
                sc.setdefault("priority", 3)
                sc.setdefault("details", "")
                sc.setdefault("methods", [])
                sc.setdefault("done", False)
                sc.pop("tools", None)
                sc.pop("recommended_tools", None)
            step["scenarios"] = valid_scenarios
            if valid_scenarios or step["description"]:
                valid_steps.append(step)
        phase["steps"] = valid_steps
        cleaned_phases.append(phase)

    # Ensure exactly 5 phases with canonical names.
    required_phases = [
        ("Reconnaissance", 1),
        ("Enumeration", 2),
        ("Exploitation", 3),
        ("Post-Exploitation", 4),
        ("Reporting", 5),
    ]
    existing_names = {p["name"].strip().lower() for p in cleaned_phases}
    for name, priority in required_phases:
        if name.lower() not in existing_names:
            empty_steps: list[dict[str, Any]] = []
            cleaned_phases.append(
                {"name": name, "priority": priority, "steps": empty_steps}
            )

    # Sort by priority.
    cleaned_phases.sort(key=lambda p: p.get("priority", 99))
    plan["phases"] = cleaned_phases
    return plan


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS — Inline tool-call extraction
# ═════════════════════════════════════════════════════════════════════════════


def _extract_inline_tool_calls(
    raw_content: str,
) -> tuple[str, list[dict[str, Any]]]:
    """Parse pseudo tool-call text from providers like Groq.

    Handles:
      <function(name){...}</function>
      <function=name>{...}</function>
      <function=name>{...}  (no closing tag / truncated)
    """
    text = (raw_content or "").strip()
    if not text:
        return raw_content, []

    patterns = [
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
        # Truncated — no closing tag; greedy capture of remaining JSON.
        re.compile(
            r"<function=(?P<name>[a-zA-Z0-9_]+)\s*>?\s*(?P<args>\{.+)",
            flags=re.DOTALL,
        ),
    ]

    for pattern in patterns:
        match = pattern.search(text)
        if not match:
            continue
        name = match.group("name")
        raw_args = match.group("args")
        args_obj: dict[str, Any]
        try:
            parsed = json.loads(raw_args)
            args_obj = parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            repaired = _repair_truncated_json(raw_args)
            if repaired is not None:
                # For plan updates, do deep structural repair.
                if name == "update_pentest_plan" and "phases" in repaired:
                    repaired = _deep_repair_plan_from_truncated(repaired)
                args_obj = repaired
            else:
                args_obj = {}

        tool_calls = [
            {
                "id": f"inline_{uuid.uuid4().hex[:10]}",
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(args_obj, ensure_ascii=True),
                },
            },
        ]
        cleaned_text = pattern.sub("", text).strip()
        return cleaned_text, tool_calls

    return raw_content, []


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS — Retry with exponential backoff + jitter
# ═════════════════════════════════════════════════════════════════════════════


async def _retry_with_backoff(
    coro_factory,
    *,
    max_retries: int = _MAX_RETRIES,
    base_delay: float = _RETRY_BACKOFF_BASE,
    jitter_max: float = _RETRY_JITTER_MAX,
    timeout: float = PLANNER_CALL_TIMEOUT_SECONDS,
    on_retry=None,
):
    """Execute an async callable with exponential backoff on transient errors.

    Args:
        coro_factory: Callable returning a coroutine (called fresh each attempt).
        max_retries: Total attempts (including the first).
        base_delay: Base delay for exponential backoff.
        jitter_max: Max random jitter added to each delay.
        timeout: Per-attempt timeout in seconds.
        on_retry: Optional callback(attempt, exc) called before each retry sleep.

    Returns:
        The result of the successful call.

    Raises:
        The last exception if all retries are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            return await asyncio.wait_for(coro_factory(), timeout=timeout)
        except _TRANSIENT_EXCEPTIONS as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                delay = base_delay * (2**attempt) + random.uniform(0, jitter_max)
                if on_retry:
                    on_retry(attempt + 1, exc)
                await asyncio.sleep(delay)
            else:
                raise
        except httpx.HTTPStatusError as exc:
            # 400 errors are NOT retried — they need arg/payload fixes.
            # 429/5xx ARE retried.
            if exc.response is not None and exc.response.status_code in (429, 500, 502, 503, 504):
                last_exc = exc
                if attempt < max_retries - 1:
                    delay = base_delay * (2**attempt) + random.uniform(0, jitter_max)
                    if on_retry:
                        on_retry(attempt + 1, exc)
                    await asyncio.sleep(delay)
                else:
                    raise
            else:
                raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("_retry_with_backoff: unreachable")


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS — Target/scope extraction
# ═════════════════════════════════════════════════════════════════════════════


def _extract_initial_target_scope(
    messages: list[dict[str, Any]],
) -> tuple[str, str]:
    user_msgs = [
        m for m in messages if isinstance(m, dict) and m.get("role") == "user"
    ]
    if not user_msgs:
        return "", ""
    text = str(user_msgs[0].get("content", "") or "")
    target = ""
    scope = ""
    for line in text.splitlines():
        low = line.lower().strip()
        if not target and low.startswith("target:"):
            target = line.split(":", 1)[1].strip()
        elif not scope and low.startswith("scope:"):
            scope = line.split(":", 1)[1].strip()
    # Fallback: extract first URL-like token as target.
    if not target:
        url_match = re.search(r"https?://\S+", text)
        if url_match:
            target = url_match.group(0).rstrip("/.,;:)")
    return target, scope


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS — Context compression for retry
# ═════════════════════════════════════════════════════════════════════════════


def _compress_messages_for_retry(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compress message history to reduce token count for retry attempts.

    Keeps system prompt and user message intact. Summarizes tool results
    to their first 500 chars. Removes assistant reasoning text.
    """
    compressed: list[dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "")
        if role == "system":
            compressed.append(msg)
        elif role == "user":
            compressed.append(msg)
        elif role == "tool":
            content = str(msg.get("content", ""))
            compressed.append(
                {
                    **msg,
                    "content": content[:500] + ("..." if len(content) > 500 else ""),
                }
            )
        elif role == "assistant":
            # Keep tool_calls but strip verbose content.
            new_msg = dict(msg)
            if msg.get("tool_calls"):
                new_msg["content"] = ""
            else:
                content = str(msg.get("content", ""))
                new_msg["content"] = content[:200] + (
                    "..." if len(content) > 200 else ""
                )
            compressed.append(new_msg)
        else:
            compressed.append(msg)
    return compressed


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS — Scenario processing
# ═════════════════════════════════════════════════════════════════════════════


def _strip_scenario_tool_fields(scenario: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(scenario, dict):
        return scenario
    cleaned = dict(scenario)
    cleaned.pop("tools", None)
    cleaned.pop("recommended_tools", None)
    cleaned["done"] = bool(cleaned.get("done", False))
    return _normalize_scenario_agent(cleaned)


def _normalize_scenario_agent(scenario: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(scenario)
    agent = str(normalized.get("agent", "")).strip().lower()
    if agent in {"report", "retest"}:
        return normalized

    task = str(normalized.get("task", "")).lower()
    details = str(normalized.get("details", "")).lower()
    methods = normalized.get("methods", [])
    method_text = (
        " ".join(m.lower() for m in methods if isinstance(m, str))
        if isinstance(methods, list)
        else ""
    )
    text = f"{task} {details} {method_text}"

    verify_cues = ("verify", "validate", "confirm", "false positive", "triage")
    recon_cues = (
        "identify",
        "enumerate",
        "discover",
        "scan",
        "fingerprint",
        "analyze",
        "osint",
        "map",
        "crawl",
        "spider",
        "directory",
        "endpoint",
        "tech stack",
        "technology",
        "service",
        "open port",
        "vulnerab",
    )
    exploit_cues = (
        "exploit",
        "payload",
        "bypass",
        "inject",
        "sqli",
        "xss",
        "ssrf",
        "rce",
        "command execution",
        "shell",
        "privilege escalation",
        "privesc",
    )

    has_verify = any(cue in text for cue in verify_cues)
    has_recon = any(cue in text for cue in recon_cues)
    has_exploit = any(cue in text for cue in exploit_cues)

    if has_verify:
        normalized["agent"] = "verify"
    elif has_recon and not has_exploit:
        normalized["agent"] = "recon"
    elif has_exploit and agent not in {"verify", "report", "retest"}:
        normalized["agent"] = "exploit"
    elif not agent:
        normalized["agent"] = "recon"

    return normalized


def _phase_scenarios(
    plan: dict[str, Any],
    phase_names: set[str],
    *,
    only_pending: bool,
) -> list[dict[str, Any]]:
    phases = plan.get("phases", [])
    out: list[dict[str, Any]] = []
    if not isinstance(phases, list):
        return out
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        name = str(phase.get("name", "")).strip().lower()
        if name not in phase_names:
            continue
        steps = phase.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios", [])
            if not isinstance(scenarios, list):
                continue
            for scenario in scenarios:
                if not isinstance(scenario, dict):
                    continue
                cleaned = _strip_scenario_tool_fields(scenario)
                if only_pending and cleaned.get("done", False):
                    continue
                out.append(cleaned)
    return out


def _enforce_phase_gate(
    scenarios: list[dict[str, Any]],
    *,
    is_loop: bool,
) -> list[dict[str, Any]]:
    cleaned = [
        _strip_scenario_tool_fields(s) for s in scenarios if isinstance(s, dict)
    ]
    pending_recon_enum = _phase_scenarios(
        _current_plan,
        {"reconnaissance", "enumeration"},
        only_pending=True,
    )

    if pending_recon_enum:
        canonical_by_task = {
            str(s.get("task", "")).strip().lower(): s
            for s in pending_recon_enum
            if isinstance(s.get("task"), str)
        }
        allowed = set(canonical_by_task.keys())
        gated: list[dict[str, Any]] = []
        for s in cleaned:
            task_key = str(s.get("task", "")).strip().lower()
            if task_key in allowed:
                gated.append(dict(canonical_by_task.get(task_key, s)))
        if not gated:
            return pending_recon_enum[:3]
        merged = gated[:3]
        if len(merged) < 3:
            seen = {
                str(s.get("task", "")).strip().lower()
                for s in merged
                if isinstance(s.get("task"), str)
            }
            for candidate in pending_recon_enum:
                task = str(candidate.get("task", "")).strip().lower()
                if task not in seen:
                    merged.append(candidate)
                    seen.add(task)
                    if len(merged) >= 3:
                        break
        return merged[:3]

    if not is_loop:
        early_agents = {"recon", "verify"}
        early = [
            s
            for s in cleaned
            if str(s.get("agent", "")).strip().lower() in early_agents
        ]
        if early:
            return early[:3]

    return cleaned[:3]


def _format_tool_batch_results(tool_results: list[dict[str, Any]]) -> str:
    if not tool_results:
        return ""
    lines = [f"Executed {len(tool_results)} tool call(s):"]
    for idx, item in enumerate(tool_results, 1):
        name = str(item.get("name", "?"))
        call_id = str(item.get("tool_call_id", ""))
        result = str(item.get("result", ""))
        lines.append(f"[{idx}] {name} (id={call_id})")
        lines.append(result)
        lines.append("")
    return "\n".join(lines).strip()


def _build_loop_plan_context_message() -> str:
    """Build a deterministic loop-context message with the current plan JSON."""
    plan = _current_plan if isinstance(_current_plan, dict) else {}
    if not plan:
        return (
            "Current plan context (JSON):\n"
            "{\"target\":\"\",\"scope\":\"\",\"target_types\":[],\"phases\":[],\"notes\":\"\"}"
        )
    return "Current plan context (JSON):\n" + json.dumps(
        plan, ensure_ascii=True
    )


def _parse_planner_output(raw: str) -> PlannerResult:
    text = raw.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

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
            data_lower = {k.lower(): v for k, v in data.items()}
            scenarios = data_lower.get("scenarios", [])
            if not isinstance(scenarios, list):
                scenarios = []
            scenarios = [
                _strip_scenario_tool_fields(s)
                for s in scenarios
                if isinstance(s, dict)
            ]
            needs = data_lower.get("needs", [])
            if not isinstance(needs, list):
                needs = []
            summary = data_lower.get("summary", "")
            if isinstance(summary, dict):
                summary = json.dumps(summary)
            return PlannerResult(
                scenarios=scenarios[:3], needs=needs, summary=str(summary)
            )
    except (json.JSONDecodeError, ValueError):
        pass

    if text:
        return PlannerResult(summary=text)
    return PlannerResult(summary="No plan generated.")


def _is_plan_payload(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    phases = data.get("phases")
    return isinstance(phases, list)


def _extract_json_object_at(text: str, start_idx: int) -> str | None:
    if start_idx < 0 or start_idx >= len(text) or text[start_idx] != "{":
        return None
    depth = 0
    in_string = False
    escape = False
    for idx in range(start_idx, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start_idx : idx + 1]
    return None


def _extract_plan_from_text(raw: str) -> dict[str, Any] | None:
    text = (raw or "").strip()
    if not text:
        return None
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # 1) Full text is JSON
    try:
        parsed = json.loads(text)
        if _is_plan_payload(parsed):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass

    # 2) JSON fenced blocks
    for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text):
        candidate = block.strip()
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            if _is_plan_payload(parsed):
                return parsed
        except (json.JSONDecodeError, TypeError):
            continue

    # 3) Embedded object in prose, anchored around phases/target
    for marker in ('"phases"', '"target"'):
        marker_idx = text.find(marker)
        if marker_idx < 0:
            continue
        start = text.rfind("{", 0, marker_idx)
        while start >= 0:
            obj_text = _extract_json_object_at(text, start)
            if not obj_text:
                break
            try:
                parsed = json.loads(obj_text)
                if _is_plan_payload(parsed):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
            start = text.rfind("{", 0, start)

    return None


def _has_successful_plan_update(messages: list[dict[str, Any]]) -> bool:
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") != "tool":
            continue
        if msg.get("name") != "update_pentest_plan":
            continue
        content = str(msg.get("content", "")).strip().lower()
        if content.startswith("plan updated"):
            return True
    return False


# ═════════════════════════════════════════════════════════════════════════════
# PLANNER AGENT
# ═════════════════════════════════════════════════════════════════════════════


class PlannerAgent:
    """LangGraph-based planner that builds pentest plans with tool calling.

    Modes:
        - Initial (is_loop=False): Builds a complete plan from scratch.
        - Loop (is_loop=True): Receives executor results, returns next scenarios.
    """

    def __init__(
        self,
        tools: list[Tool] | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        mode: str | None = None,
        callback: PlannerCallback | None = None,
    ) -> None:
        self._mode = mode or llm_mode.mode
        self._cb = callback or _NoOpCallback()

        tool_list = tools or ALL_PLANNER_TOOLS
        self._tools = {t.name: t for t in tool_list}
        self._tool_schemas = [t.schema() for t in tool_list]
        self._tool_valid_params: dict[str, set[str] | None] = {
            t.name: _get_valid_params(t) for t in tool_list
        }

        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LocalLLMClient(self._local_config)
            self._model_name = self._local_config.model
        else:
            self._config = config or public_llm_config
            self._llm = LLMClient(self._config)
            self._model_name = self._config.model

        logger.info("planner_initialized", mode=self._mode, model=self._model_name)
        self._graph = self._build_graph()

    def _tool_schemas_for_mode(self, is_loop: bool) -> list[dict[str, Any]]:
        if not is_loop:
            return self._tool_schemas
        return [
            schema
            for schema in self._tool_schemas
            if schema.get("function", {}).get("name")
            not in {"remove_target_type", "get_pentest_plan"}
        ]

    # ── Graph ──────────────────────────────────────────────────────

    def _build_graph(self) -> Any:
        graph = StateGraph(PlannerState)
        graph.add_node("reason", self._reason_node)
        graph.add_node("execute_tools", self._execute_tools_node)
        graph.add_node("parse_output", self._parse_output_node)
        graph.add_edge(START, "reason")
        graph.add_conditional_edges(
            "reason",
            self._route_after_reason,
            {"execute_tools": "execute_tools", "parse_output": "parse_output"},
        )
        graph.add_edge("execute_tools", "reason")
        graph.add_edge("parse_output", END)
        return graph.compile()

    # ── Reason Node ────────────────────────────────────────────────

    async def _reason_node(self, state: PlannerState) -> dict[str, Any]:
        # After tools executed + stop flag, emit results without another LLM call.
        if state.get("stop_after_tools"):
            return {
                "last_tool_calls": [],
                "last_response": _format_tool_batch_results(
                    state.get("last_tool_results", []),
                ),
                "stop_after_tools": False,
            }

        round_count = state["round_count"] + 1
        self._cb.on_step(f"LLM Round {round_count}/{MAX_TOOL_ROUNDS}")

        # Determine if we should compress context (retry recovery).
        messages_raw = state["messages"]
        if state.get("recovery_attempted"):
            messages_raw = _compress_messages_for_retry(messages_raw)
        messages = [_dict_to_msg(m) for m in messages_raw]

        # Adaptive token budget: allow more tokens in later rounds for plan output.
        token_budget = PLANNER_MAX_TOKENS_PER_REQUEST
        if round_count >= 2:
            # Round 2+ likely needs to generate the full plan JSON.
            token_budget = max(token_budget, 4096)

        try:

            def _on_retry(attempt: int, exc: Exception) -> None:
                self._cb.on_warn(
                    f"LLM transient error (attempt {attempt}/{_MAX_RETRIES}): "
                    f"{type(exc).__name__}; backing off..."
                )

            response = await _retry_with_backoff(
                lambda: self._llm.chat(
                    messages,
                    tools=state.get("tool_schemas") if self._tools else None,
                    temperature=0.3,
                    max_tokens=token_budget,
                ),
                timeout=PLANNER_CALL_TIMEOUT_SECONDS,
                on_retry=_on_retry,
            )

        except httpx.HTTPStatusError as exc:
            return self._handle_http_error(exc, state, round_count)

        except _TRANSIENT_EXCEPTIONS as exc:
            return self._handle_transient_timeout(exc, state, round_count)

        except Exception as exc:
            err_text = str(exc).strip() or repr(exc) or type(exc).__name__
            self._cb.on_warn(f"LLM error: {err_text}")
            logger.error("planner_llm_error", error=repr(exc))
            return {
                "round_count": round_count,
                "last_response": f"LLM error: {err_text}",
                "last_tool_calls": [],
                "error": err_text,
            }

        raw_content = response.content or ""
        tool_calls = response.tool_calls or []

        # Recover inline function calls from content text.
        if not tool_calls and raw_content:
            cleaned_content, inline_calls = _extract_inline_tool_calls(raw_content)
            if inline_calls:
                tool_calls = inline_calls
                raw_content = cleaned_content
                self._cb.on_warn("Recovered inline function-call from text.")

        # If model returned a textual plan JSON instead of tool-calling, auto-convert
        # it into update_pentest_plan so the plan is persisted before session ends.
        if not tool_calls and raw_content and not _has_successful_plan_update(state["messages"]):
            recovered_plan = _extract_plan_from_text(raw_content)
            if recovered_plan is not None:
                tool_calls = [
                    {
                        "id": f"autosave_{uuid.uuid4().hex[:10]}",
                        "type": "function",
                        "function": {
                            "name": "update_pentest_plan",
                            "arguments": json.dumps(recovered_plan, ensure_ascii=True),
                        },
                    },
                ]
                self._cb.on_warn(
                    "Recovered plan JSON from final text; auto-saving via update_pentest_plan."
                )

        if tool_calls:
            tool_names = [tc["function"]["name"] for tc in tool_calls]
            self._cb.on_step(
                f"LLM Round {round_count}: Calling tools → {tool_names}"
            )
        else:
            self._cb.on_done(
                f"LLM Round {round_count}: Final answer ({len(raw_content)} chars)"
            )

        return {
            "round_count": round_count,
            "last_response": raw_content,
            "last_tool_calls": tool_calls,
        }

    # ── Error Handlers ─────────────────────────────────────────────

    def _handle_http_error(
        self,
        exc: httpx.HTTPStatusError,
        state: PlannerState,
        round_count: int,
    ) -> dict[str, Any]:
        body = exc.response.text[:1500] if exc.response is not None else ""
        status = exc.response.status_code if exc.response is not None else 0
        self._cb.on_warn(f"LLM HTTP {status}: {body[:200]}")

        # ── 400: Groq tool_use_failed recovery ──
        if status == 400:
            recovered = self._recover_from_failed_generation(exc, state, round_count)
            if recovered is not None:
                return recovered

        # ── All other HTTP errors: surface as planner error ──
        return self._fallback_or_error(
            exc, state, round_count, f"HTTP {status} error"
        )

    def _handle_transient_timeout(
        self,
        exc: Exception,
        state: PlannerState,
        round_count: int,
    ) -> dict[str, Any]:
        self._cb.on_warn(
            f"LLM timeout after {_MAX_RETRIES} attempts: {type(exc).__name__}"
        )
        return self._fallback_or_error(
            exc, state, round_count, "Timeout after retries"
        )

    def _recover_from_failed_generation(
        self,
        exc: httpx.HTTPStatusError,
        state: PlannerState,
        round_count: int,
    ) -> dict[str, Any] | None:
        """Attempt to recover a usable tool call from Groq's failed_generation."""
        try:
            err_payload = exc.response.json()
            failed_gen = (
                err_payload.get("error", {}).get("failed_generation", "")
                if isinstance(err_payload, dict)
                else ""
            )
        except Exception:
            return None

        if not isinstance(failed_gen, str) or not failed_gen.strip():
            return None

        cleaned_content, inline_tool_calls = _extract_inline_tool_calls(failed_gen)
        if not inline_tool_calls:
            return None

        # Validate the recovered tool call has substance.
        for tc in inline_tool_calls:
            fn = tc.get("function", {})
            if fn.get("name") == "update_pentest_plan":
                try:
                    args = json.loads(fn.get("arguments", "{}"))
                except (json.JSONDecodeError, TypeError):
                    args = {}

                phases = args.get("phases", [])
                if isinstance(phases, list) and len(phases) > 0:
                    # Verify at least one phase has scenarios.
                    has_scenarios = any(
                        isinstance(step, dict)
                        and len(step.get("scenarios", [])) > 0
                        for phase in phases
                        if isinstance(phase, dict)
                        for step in (phase.get("steps", []) if isinstance(phase.get("steps"), list) else [])
                    )
                    if has_scenarios:
                        self._cb.on_warn(
                            f"Recovered plan from failed_generation "
                            f"({len(phases)} phases found)."
                        )
                        return {
                            "round_count": round_count,
                            "last_response": cleaned_content,
                            "last_tool_calls": inline_tool_calls,
                        }
                    else:
                        self._cb.on_warn(
                            "Recovered plan from failed_generation but "
                            "no scenarios found; continuing planning."
                        )
                else:
                    self._cb.on_warn(
                        "Recovered tool call from failed_generation but "
                        "phases empty/missing; continuing planning."
                    )
                # Recovery produced empty plan → fall through.
                return None

        # Non-update tool calls recovered — let them execute.
        self._cb.on_warn("Recovered non-plan tool call from failed_generation.")
        return {
            "round_count": round_count,
            "last_response": cleaned_content,
            "last_tool_calls": inline_tool_calls,
        }

    def _fallback_or_error(
        self,
        exc: Exception,
        state: PlannerState,
        round_count: int,
        context: str,
    ) -> dict[str, Any]:
        """Surface planner error without injecting static fallback plan data."""
        err_text = str(exc).strip() or repr(exc) or type(exc).__name__
        logger.error("planner_llm_error", error=repr(exc), context=context)
        return {
            "round_count": round_count,
            "last_response": f"Planning failed: {context}",
            "last_tool_calls": [],
            "error": f"{context}: {err_text}",
        }

    def _has_discovery_data(self, state: PlannerState) -> bool:
        return any(
            isinstance(m, dict)
            and m.get("role") == "tool"
            and m.get("name") in _DISCOVERY_TOOLS
            and _is_successful_tool_output(m.get("content"))
            for m in state.get("messages", [])
        )

    # ── Routing ────────────────────────────────────────────────────

    def _route_after_reason(self, state: PlannerState) -> str:
        if state.get("error"):
            return "parse_output"
        if state["last_tool_calls"]:
            if state["round_count"] >= MAX_TOOL_ROUNDS:
                self._cb.on_warn(
                    f"Reached max rounds ({MAX_TOOL_ROUNDS}); forcing output."
                )
                return "parse_output"
            return "execute_tools"
        return "parse_output"

    # ── Execute Tools Node ─────────────────────────────────────────

    async def _execute_tools_node(self, state: PlannerState) -> dict[str, Any]:
        tool_calls = state["last_tool_calls"]

        # Loop mode: single tool per round.
        if state.get("is_loop") and len(tool_calls) > 1:
            self._cb.on_warn(
                "Loop mode: executing first tool call only."
            )
            tool_calls = tool_calls[:1]

        total = state["total_tool_calls"] + len(tool_calls)
        batch_results: list[dict[str, Any]] = []

        new_messages: list[dict[str, Any]] = [
            {
                "role": "assistant",
                "content": state["last_response"],
                "tool_calls": tool_calls,
            }
        ]

        update_succeeded = False
        has_prior_discovery = self._has_discovery_data(state)

        for idx, tc in enumerate(tool_calls):
            raw_tool_name = tc["function"]["name"]
            raw_args = tc["function"].get("arguments", "{}")
            call_id = tc["id"]

            try:
                args = (
                    json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                )
            except json.JSONDecodeError:
                args = {}
            if not isinstance(args, dict):
                args = {}

            tool_name, corrected = self._resolve_compatible_tool_name(raw_tool_name)
            if corrected:
                self._cb.on_warn(
                    f"Auto-corrected tool '{raw_tool_name}' → '{tool_name}'."
                )
            args = self._repair_tool_args(tool_name, args)
            args = self._filter_tool_args(tool_name, args)

            tool = self._tools.get(tool_name)
            if tool is None:
                result_str = f"Error: unknown tool '{raw_tool_name}'"
                self._cb.on_warn(f"Unknown tool: {raw_tool_name}")
            elif (
                not state.get("is_loop")
                and tool_name == "update_pentest_plan"
                and not has_prior_discovery
            ):
                result_str = (
                    "Rejected: run at least one discovery tool "
                    "(get_page/search_kb/search_web) before update_pentest_plan."
                )
                self._cb.on_warn(
                    "Rejected update_pentest_plan: no prior discovery."
                )
            else:
                self._report_tool_start(tool_name, args)
                try:
                    result_str = await tool.execute(**args)
                    result_str = _truncate_result(result_str)
                    self._report_tool_result(tool_name, result_str)

                    if (
                        tool_name in _DISCOVERY_TOOLS
                        and _is_successful_tool_output(result_str)
                    ):
                        has_prior_discovery = True

                    if tool_name == "update_pentest_plan":
                        lowered = result_str.strip().lower()
                        if lowered.startswith("rejected"):
                            self._cb.on_warn(
                                "update_pentest_plan rejected; "
                                "planner will continue and try again."
                            )
                        elif lowered.startswith("error"):
                            self._cb.on_warn(
                                "update_pentest_plan errored; "
                                "planner will continue and try again."
                            )
                        else:
                            update_succeeded = True
                except Exception as exc:
                    result_str = f"Error executing {tool_name}: {exc}"
                    self._cb.on_warn(f"  Tool error: {exc}")
                    logger.error(
                        "planner_tool_error", tool=tool_name, error=str(exc)
                    )

            new_messages.append(
                {
                    "role": "tool",
                    "content": result_str,
                    "tool_call_id": call_id,
                    "name": tool_name,
                }
            )
            batch_results.append(
                {
                    "tool_call_id": call_id,
                    "name": tool_name,
                    "requested_name": raw_tool_name,
                    "args": args,
                    "result": result_str,
                }
            )

            # Hard stop after update_pentest_plan.
            if tool_name == "update_pentest_plan":
                remaining = len(tool_calls) - (idx + 1)
                if remaining > 0:
                    self._cb.on_warn(
                        f"Skipping {remaining} tool(s) after "
                        f"update_pentest_plan (hard stop)."
                    )
                break

        return {
            "messages": new_messages,
            "total_tool_calls": total,
            "last_tool_calls": [],
            "last_tool_results": batch_results,
            "stop_after_tools": (
                update_succeeded or state["round_count"] >= MAX_TOOL_ROUNDS
            ),
        }

    # ── Parse Output Node ─────────────────────────────────────────

    async def _parse_output_node(self, state: PlannerState) -> dict[str, Any]:
        content = state["last_response"]
        total_tools = state["total_tool_calls"]
        rounds = state["round_count"]

        if state.get("error"):
            self._cb.on_warn(f"Planning failed: {state['error']}")
            return {
                "plan_result": {
                    "scenarios": [],
                    "needs": [],
                    "summary": f"Planning failed: {state['error']}",
                }
            }

        result = _parse_planner_output(content)

        # Planner runs in plan-only mode: never return scenario batches here.
        result.scenarios = []

        self._cb.on_done(
            f"Planner complete: {len(result.scenarios)} scenarios, "
            f"{total_tools} tool calls, {rounds} rounds"
        )
        if result.needs:
            self._cb.on_step(f"Planner needs more data: {len(result.needs)} items")

        return {
            "plan_result": {
                "scenarios": result.scenarios,
                "needs": result.needs,
                "summary": result.summary,
                "tool_results": state.get("last_tool_results", []),
            }
        }

    # ── Tool reporting ─────────────────────────────────────────────

    def _report_tool_start(self, tool_name: str, args: dict[str, Any]) -> None:
        if tool_name == "update_pentest_plan":
            try:
                plan_data = (
                    args
                    if isinstance(args.get("phases"), list)
                    else json.loads(args.get("plan_json", "{}"))
                )
                phases = len(plan_data.get("phases", []))
                target = plan_data.get("target", "?")
                total_scenarios = sum(
                    len(step.get("scenarios", []))
                    for phase in plan_data.get("phases", [])
                    if isinstance(phase, dict)
                    for step in (
                        phase.get("steps", [])
                        if isinstance(phase.get("steps"), list)
                        else []
                    )
                    if isinstance(step, dict)
                )
                self._cb.on_step(
                    f"  {tool_name}: saving plan "
                    f"({phases} phases, {total_scenarios} scenarios, "
                    f"target={target})"
                )
            except (json.JSONDecodeError, TypeError):
                self._cb.on_step(f"  {tool_name}: saving plan")
        elif tool_name in {"add_target_type", "remove_target_type"}:
            self._cb.on_step(
                f"  {tool_name}: {args.get('target_type', '?')}"
            )
        elif tool_name == "get_target_types":
            self._cb.on_step(f"  {tool_name}: reading target types")
        elif tool_name == "get_page":
            url = str(args.get("url", "?"))[:60]
            self._cb.on_step(f"  {tool_name}: fetching {url}")
        elif tool_name == "get_pentest_plan":
            self._cb.on_step(f"  {tool_name}: reading current plan")
        else:
            preview = ", ".join(
                f"{k}={str(v)[:30]}" for k, v in list(args.items())[:3]
            )
            self._cb.on_step(f"  {tool_name}({preview})")

    def _report_tool_result(self, tool_name: str, result_str: str) -> None:
        try:
            parsed = json.loads(result_str)
            if isinstance(parsed, dict) and "phases" in parsed:
                self._cb.on_done(
                    f"  → Plan ({len(parsed.get('phases', []))} phases)"
                )
            elif isinstance(parsed, dict) and "target_types" in parsed:
                self._cb.on_done(
                    f"  → Target types: {parsed['target_types']}"
                )
            else:
                self._cb.on_done(f"  → {len(result_str)} chars")
        except (json.JSONDecodeError, TypeError):
            truncated = " [truncated]" if "[TRUNCATED" in result_str else ""
            self._cb.on_done(f"  → {len(result_str)} chars{truncated}")

    # ── Tool name resolution & arg repair ──────────────────────────

    def _filter_tool_args(
        self, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        valid_params = self._tool_valid_params.get(tool_name)
        filtered = (
            args
            if valid_params is None
            else {k: v for k, v in args.items() if k in valid_params}
        )
        dropped = set(args.keys()) - set(filtered.keys())
        if dropped:
            logger.warning(
                "planner_tool_args_filtered",
                tool=tool_name,
                dropped=sorted(dropped),
            )
        tool = self._tools.get(tool_name)
        if tool is None:
            return filtered
        return coerce_args_from_schema(tool.parameters, filtered)

    def _resolve_compatible_tool_name(
        self, tool_name: str
    ) -> tuple[str, bool]:
        if tool_name in self._tools:
            return tool_name, False

        aliases = {
            "searchweb": "search_web",
            "websearch": "search_web",
            "searchkb": "search_kb",
            "kbsearch": "search_kb",
            "getpage": "get_page",
            "fetchpage": "get_page",
            "readpage": "get_page",
            "updateplan": "update_pentest_plan",
            "saveplan": "update_pentest_plan",
            "updatepentestplan": "update_pentest_plan",
            "getplan": "get_pentest_plan",
            "readplan": "get_pentest_plan",
            "getpentestplan": "get_pentest_plan",
            "targettypes": "get_target_types",
            "gettargettypes": "get_target_types",
            "addtargettype": "add_target_type",
        }
        token = _normalized_token(tool_name)
        if token in aliases and aliases[token] in self._tools:
            return aliases[token], True

        close = difflib.get_close_matches(
            tool_name, list(self._tools.keys()), n=1, cutoff=0.72
        )
        if close:
            return close[0], True
        return tool_name, False

    def _repair_tool_args(
        self, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        fixed = dict(args) if isinstance(args, dict) else {}

        if tool_name == "search_web":
            if "query" not in fixed:
                for key in ("url", "target", "q"):
                    if isinstance(fixed.get(key), str) and fixed[key].strip():
                        fixed["query"] = fixed[key]
                        break
            if "max_results" not in fixed and "n_results" in fixed:
                fixed["max_results"] = fixed["n_results"]
            if "max_results" in fixed:
                try:
                    fixed["max_results"] = max(1, min(5, int(fixed["max_results"])))
                except Exception:
                    fixed["max_results"] = 5

        elif tool_name == "get_page":
            if "url" not in fixed and isinstance(fixed.get("query"), str):
                fixed["url"] = fixed["query"]

        elif tool_name == "search_kb":
            if "query" not in fixed:
                for key in ("url", "q", "target"):
                    if isinstance(fixed.get(key), str) and fixed[key].strip():
                        fixed["query"] = fixed[key]
                        break
            if "n_results" not in fixed and "max_results" in fixed:
                fixed["n_results"] = fixed["max_results"]
            if "n_results" in fixed:
                try:
                    fixed["n_results"] = max(1, min(5, int(fixed["n_results"])))
                except Exception:
                    fixed["n_results"] = 5

        elif tool_name == "update_pentest_plan":
            # Flatten nested "plan" key.
            plan_obj = fixed.get("plan")
            if isinstance(plan_obj, dict):
                fixed.pop("plan", None)
                for k, v in plan_obj.items():
                    fixed.setdefault(k, v)

            # Decode stringified JSON fields.
            for key in ("target_types", "phases"):
                if isinstance(fixed.get(key), str):
                    try:
                        fixed[key] = json.loads(fixed[key])
                    except json.JSONDecodeError:
                        pass

            # Ensure plan_json is a string if present.
            if "plan_json" in fixed and not isinstance(
                fixed.get("plan_json"), str
            ):
                try:
                    fixed["plan_json"] = json.dumps(
                        fixed["plan_json"], ensure_ascii=True
                    )
                except Exception:
                    fixed["plan_json"] = str(fixed["plan_json"])
            elif isinstance(fixed.get("plan_json"), str):
                raw_plan_json = fixed["plan_json"].strip()
                candidate = raw_plan_json
                if candidate.startswith("```"):
                    candidate = re.sub(
                        r"^```(?:json)?\s*",
                        "",
                        candidate,
                        flags=re.IGNORECASE,
                    )
                    candidate = re.sub(r"\s*```$", "", candidate).strip()

                recovered: dict[str, Any] | None = None
                try:
                    parsed = json.loads(candidate)
                    if isinstance(parsed, dict):
                        recovered = parsed
                except json.JSONDecodeError:
                    obj_start = candidate.find("{")
                    extracted: str | None = None
                    if obj_start >= 0:
                        extracted = _extract_json_object_at(
                            candidate, obj_start
                        )
                    if extracted:
                        try:
                            parsed = json.loads(extracted)
                            if isinstance(parsed, dict):
                                recovered = parsed
                        except json.JSONDecodeError:
                            recovered = _repair_truncated_json(extracted)
                    else:
                        recovered = _repair_truncated_json(candidate)

                if recovered is not None:
                    fixed["plan_json"] = json.dumps(recovered, ensure_ascii=True)
                elif any(
                    key in fixed
                    for key in ("target", "scope", "target_types", "phases", "notes")
                ):
                    # Avoid hard failure in tool: rely on direct fields when available.
                    fixed.pop("plan_json", None)

        return fixed

    # ── Public API ─────────────────────────────────────────────────

    async def run(
        self, user_message: str, is_loop: bool = False
    ) -> PlannerResult:
        mode_label = "loop re-entry" if is_loop else "initial plan"
        self._cb.on_step(f"Planner Agent starting ({mode_label})")

        system_content = LOOP_SYSTEM_PROMPT if is_loop else INITIAL_SYSTEM_PROMPT
        if _needs_nothink(self._model_name):
            system_content = "/nothink\n" + system_content

        initial_state: PlannerState = {
            "messages": [
                {"role": "system", "content": system_content},
                *(
                    [
                        {
                            "role": "user",
                            "content": _build_loop_plan_context_message(),
                        }
                    ]
                    if is_loop
                    else []
                ),
                {"role": "user", "content": user_message},
            ],
            "tool_schemas": self._tool_schemas_for_mode(is_loop),
            "round_count": 0,
            "total_tool_calls": 0,
            "last_response": "",
            "last_tool_calls": [],
            "last_tool_results": [],
            "stop_after_tools": False,
            "is_loop": is_loop,
            "plan_result": {},
            "error": "",
            "recovery_attempted": False,
        }

        final_state = await self._graph.ainvoke(initial_state)

        plan_data = final_state.get("plan_result") or {}
        return PlannerResult(
            scenarios=plan_data.get("scenarios", []),
            needs=plan_data.get("needs", []),
            summary=plan_data.get("summary", ""),
            tool_results=plan_data.get("tool_results", []),
        )

    async def close(self) -> None:
        await self._llm.close()

    async def __aenter__(self) -> PlannerAgent:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
