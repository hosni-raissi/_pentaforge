"""
PlannerAgent — LangGraph-based agent that builds penetration-testing plans.

Graph:
  START → reason → (has tool_calls?) ─yes─→ execute_tools → reason (loop)
                                      ─no──→ parse_output → END
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import random
import re
import uuid
from dataclasses import dataclass, field
from operator import add
from typing import Annotated, Any, Protocol, TypedDict
from copy import deepcopy

import structlog
import httpx
from langgraph.graph import END, START, StateGraph

from server.agents.executer.target_tool_routing import (
    mapped_tool_names_for_target_type,
    normalize_target_type,
    normalize_target_types,
)
from server.config.agent import (
    LocalLLMConfig,
    PublicLLMConfig,
    local_llm_config,
    public_llm_config,
    get_public_agent_config,
    llm_mode,
)
from server.core.llm import ChatMessage, LLMClient
from server.core.tool import Tool, coerce_args_from_schema
from server.agents.rate_limiter import get_global_llm_queue, get_backup_llm_fallback
from .config import (
    CHECKLIST_MAX_TOOL_ROUNDS,
    PLANNER_CHECKLIST_WINDOW_MAX_ITEMS,
    PLANNER_CHECKLIST_WINDOW_MAX_ITEMS_PER_PHASE,
    PLANNER_CHECKLIST_SUMMARY_MAX_CHANGED_ITEMS,
    PLANNER_CHECKLIST_SUMMARY_MAX_HIGH_PRIORITY_PENDING,
    PLANNER_LOOP_CONTEXT_MAX_SCENARIOS_PER_STEP,
    PLANNER_LOOP_CONTEXT_MAX_STEPS_PER_PHASE,
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
from .context_builder import PlannerContextBuilder
from .prompts import (
    CHECKLIST_GENERATOR_SYSTEM_PROMPT,
    PLAN_CREATE_UPDATE_SYSTEM_PROMPT,
    render_planner_prompt,
)
from .tools import ALL_PLANNER_TOOLS
from .tools.pentest_plan import _current_plan, update_pentest_plan
from .tools.get_checklists import _default_priority_for_item

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
    world_state_hash: str
    intel_checklist_overview: dict[str, Any]
    intel_checklist_windows: list[dict[str, Any]]
    intel_checklist_compact_summary: dict[str, Any]
    planning_round_cap: int


# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ═════════════════════════════════════════════════════════════════════════════


@dataclass
class PlannerResult:
    scenarios: list[dict] = field(default_factory=list)
    needs: list[dict] = field(default_factory=list)
    summary: str = ""
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    action_plan: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlannerChecklistResult:
    status: str = "complete"
    summary: str = ""
    checklist: dict[str, Any] = field(default_factory=dict)


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


def _planner_kb_domain_for_target_type(target_type: str) -> str:
    normalized = normalize_target_type(target_type) or "shared"
    if normalized == "infra":
        return "linux_server"
    if normalized == "container":
        return "cloud"
    return normalized if normalized != "desktop" else "shared"


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
                default_rounds = 1 if str(sc.get("agent", "recon")).strip().lower() != "exploit" else 2
                try:
                    sc["max_rounds"] = min(3, max(1, int(sc.get("max_rounds", default_rounds))))
                except (TypeError, ValueError):
                    sc["max_rounds"] = default_rounds
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
    if agent in {"verify", "retest"}:
        normalized["agent"] = "exploit"
        return normalized
    if agent in {"reporting", "report"}:
        normalized["agent"] = "exploit"
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

    has_recon = any(cue in text for cue in recon_cues)
    has_exploit = any(cue in text for cue in exploit_cues)

    if has_recon and not has_exploit:
        normalized["agent"] = "recon"
    elif has_exploit:
        normalized["agent"] = "exploit"
    elif not agent:
        normalized["agent"] = "recon"
    elif agent not in {"recon", "exploit"}:
        normalized["agent"] = "exploit" if has_exploit else "recon"

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
        early_agents = {"recon", "exploit"}
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
    """Build a deterministic, compact loop-context message."""
    plan = _current_plan if isinstance(_current_plan, dict) else {}
    if not plan:
        return (
            "Current plan context (JSON):\n"
            "{\"target\":\"\",\"scope\":\"\",\"target_types\":[],\"phases\":[],\"notes\":\"\"}"
        )

    step_cap = max(0, int(PLANNER_LOOP_CONTEXT_MAX_STEPS_PER_PHASE or 0))
    scenario_cap = max(0, int(PLANNER_LOOP_CONTEXT_MAX_SCENARIOS_PER_STEP or 0))

    compact_phases: list[dict[str, Any]] = []
    for phase in plan.get("phases", []):
        if not isinstance(phase, dict):
            continue
        raw_steps = phase.get("steps", [])
        steps: list[dict[str, Any]] = []
        pending_scenarios = 0
        done_scenarios = 0

        if isinstance(raw_steps, list):
            for step in raw_steps:
                if not isinstance(step, dict):
                    continue
                raw_scenarios = step.get("scenarios", [])
                if not isinstance(raw_scenarios, list):
                    continue
                for scenario in raw_scenarios:
                    if not isinstance(scenario, dict):
                        continue
                    if bool(scenario.get("done", False)):
                        done_scenarios += 1
                    else:
                        pending_scenarios += 1

            steps_source = raw_steps if step_cap == 0 else raw_steps[:step_cap]
            for step in steps_source:
                if not isinstance(step, dict):
                    continue
                raw_scenarios = step.get("scenarios", [])
                scenarios: list[dict[str, Any]] = []
                if isinstance(raw_scenarios, list):
                    for scenario in raw_scenarios:
                        if not isinstance(scenario, dict):
                            continue
                        is_done = bool(scenario.get("done", False))
                        if scenario_cap > 0 and len(scenarios) >= scenario_cap:
                            continue
                        scenarios.append(
                            {
                                "task": str(scenario.get("task", "")),
                                "agent": str(scenario.get("agent", "")),
                                "priority": scenario.get("priority", 3),
                                "done": is_done,
                            }
                        )

                steps.append(
                    {
                        "id": str(step.get("id", "")),
                        "description": str(step.get("description", "")),
                        "scenarios": scenarios,
                    }
                )

        compact_phases.append(
            {
                "name": str(phase.get("name", "")),
                "priority": phase.get("priority", 0),
                "step_count": len(raw_steps) if isinstance(raw_steps, list) else 0,
                "pending_scenarios": pending_scenarios,
                "done_scenarios": done_scenarios,
                "steps": steps,
            }
        )

    compact_plan = {
        "target": str(plan.get("target", "")),
        "scope": str(plan.get("scope", "")),
        "target_types": plan.get("target_types", []),
        "notes": str(plan.get("notes", "")),
        "phases": compact_phases,
        "context_window": {
            "steps_per_phase": step_cap,
            "scenarios_per_step": scenario_cap,
            "mode": "compact",
            "note": "0 means uncapped",
        },
    }
    return "Current plan context (JSON, compact window):\n" + json.dumps(
        compact_plan, ensure_ascii=True
    )


def _compute_world_state_hash(
    *,
    user_message: str,
    is_loop: bool,
    checklist_compact_summary: dict[str, Any],
) -> str:
    canonical = {
        "is_loop": bool(is_loop),
        "user_message": str(user_message or "").strip(),
        "checklist_compact_summary": checklist_compact_summary
        if isinstance(checklist_compact_summary, dict)
        else {},
        "current_plan": _current_plan if isinstance(_current_plan, dict) else {},
    }
    raw = json.dumps(canonical, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _normalize_action_plan(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize mutation-instruction action plan payload."""
    if not isinstance(payload, dict):
        return {}

    def _as_list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    normalized: dict[str, Any] = {
        "loop": payload.get("loop"),
        "engagement_id": str(payload.get("engagement_id", "") or ""),
        "checklist_updates": [x for x in _as_list(payload.get("checklist_updates")) if isinstance(x, dict)],
        "checklist_additions": [x for x in _as_list(payload.get("checklist_additions")) if isinstance(x, dict)],
        "plan_modifications": [x for x in _as_list(payload.get("plan_modifications")) if isinstance(x, dict)],
        "dispatch": [x for x in _as_list(payload.get("dispatch")) if isinstance(x, dict)],
        "target_type_additions": [
            t for t in normalize_target_types(_as_list(payload.get("target_type_additions")))
            if t
        ],
        "phase_advance": bool(payload.get("phase_advance", False)),
        "phase_advance_blocked_by": [
            str(x).strip() for x in _as_list(payload.get("phase_advance_blocked_by"))
            if str(x).strip()
        ],
        "rationale": str(payload.get("rationale", "") or "").strip(),
    }

    # Optional nested/attached plan payload.
    plan_obj = payload.get("plan")
    if isinstance(plan_obj, dict):
        normalized["plan"] = plan_obj

    return normalized


def _normalize_dispatch_items(dispatch_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in dispatch_items:
        if not isinstance(item, dict):
            continue
        entry = dict(item)
        agent = str(entry.get("agent") or entry.get("role") or "").strip().lower()
        if agent == "reporting":
            agent = "exploit"
        if agent not in {"recon", "exploit"}:
            continue
        entry["agent"] = agent
        target_type = normalize_target_type(
            entry.get("target_type") or entry.get("surface") or ""
        )
        if target_type:
            entry["target_type"] = target_type
        if target_type and agent in {"recon", "exploit"}:
            if not isinstance(entry.get("tool_candidates"), list) or not entry.get("tool_candidates"):
                entry["tool_candidates"] = mapped_tool_names_for_target_type(
                    role=agent,
                    target_type=target_type,
                )
        normalized.append(entry)
    return normalized


def _auto_dispatch_for_target_types(
    *,
    dispatch: list[dict[str, Any]],
    target_types: list[str],
) -> list[dict[str, Any]]:
    out = list(dispatch)
    seen_pairs = {
        (
            str(item.get("agent", "")).strip().lower(),
            normalize_target_type(item.get("target_type") or ""),
        )
        for item in out
        if isinstance(item, dict)
    }

    for target_type in normalize_target_types(target_types):
        for agent in ("recon", "exploit"):
            pair = (agent, target_type)
            if pair in seen_pairs:
                continue
            tool_candidates = mapped_tool_names_for_target_type(
                role=agent,
                target_type=target_type,
            )
            if not tool_candidates:
                continue
            out.append(
                {
                    "agent": agent,
                    "target_type": target_type,
                    "tool_candidates": tool_candidates,
                    "reason": (
                        "Auto-added by target surface routing. "
                        "If this surface is no longer relevant, mark it blocked in planner rationale."
                    ),
                }
            )
            seen_pairs.add(pair)
    return out


def _extract_action_plan_from_text(raw: str) -> dict[str, Any] | None:
    text = (raw or "").strip()
    if not text:
        return None
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    candidates: list[dict[str, Any]] = []

    def _collect_candidate(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        if "action_plan" in obj and isinstance(obj.get("action_plan"), dict):
            candidates.append(obj["action_plan"])
            return
        keys = {
            "checklist_updates",
            "checklist_additions",
            "plan_modifications",
            "dispatch",
            "phase_advance",
            "phase_advance_blocked_by",
            "rationale",
        }
        if any(k in obj for k in keys):
            candidates.append(obj)

    try:
        parsed = json.loads(text)
        _collect_candidate(parsed)
    except (json.JSONDecodeError, TypeError):
        pass

    if not candidates:
        for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text):
            candidate = block.strip()
            if not candidate:
                continue
            try:
                parsed = json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                continue
            _collect_candidate(parsed)

    if not candidates:
        for marker in ('"action_plan"', '"checklist_updates"', '"dispatch"'):
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
                except (json.JSONDecodeError, TypeError):
                    parsed = None
                if parsed is not None:
                    _collect_candidate(parsed)
                    if candidates:
                        break
                start = text.rfind("{", 0, start)
            if candidates:
                break

    if not candidates:
        return None

    normalized = _normalize_action_plan(candidates[0])
    return normalized or None


def _parse_planner_output(raw: str) -> PlannerResult:
    text = raw.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    action_plan = _extract_action_plan_from_text(text) or {}

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
            if not summary and action_plan:
                summary = str(action_plan.get("rationale", "") or "")
            return PlannerResult(
                scenarios=scenarios[:3],
                needs=needs,
                summary=str(summary),
                action_plan=action_plan,
            )
    except (json.JSONDecodeError, ValueError):
        pass

    if text:
        fallback_summary = (
            str(action_plan.get("rationale", "") or "").strip()
            if action_plan
            else text
        )
        return PlannerResult(summary=fallback_summary or text, action_plan=action_plan)
    return PlannerResult(summary="No plan generated.", action_plan=action_plan)


def _is_plan_payload(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    phases = data.get("phases")
    return isinstance(phases, list)


def _extract_plan_candidate_from_parsed(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    if _is_plan_payload(data):
        return data

    plan_obj = data.get("plan")
    if _is_plan_payload(plan_obj):
        return plan_obj

    action_plan = data.get("action_plan")
    if isinstance(action_plan, dict):
        nested_plan = action_plan.get("plan")
        if _is_plan_payload(nested_plan):
            return nested_plan

    return None


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
        extracted = _extract_plan_candidate_from_parsed(parsed)
        if extracted is not None:
            return extracted
    except (json.JSONDecodeError, TypeError):
        pass

    # 2) JSON fenced blocks
    for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text):
        candidate = block.strip()
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            extracted = _extract_plan_candidate_from_parsed(parsed)
            if extracted is not None:
                return extracted
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
                extracted = _extract_plan_candidate_from_parsed(parsed)
                if extracted is not None:
                    return extracted
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


def _coerce_checklist_priority(value: Any) -> int | None:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= p <= 5:
        return p
    return None


def _calibrate_checklist_priority(name: str, phase: str, priority: int) -> int:
    title = str(name or "").strip().lower()
    phase_str = str(phase or "").strip()
    calibrated = int(priority)

    if "x-recruiting" in title:
        calibrated = max(calibrated, 4)

    if "cors" in title and any(
        needle in title
        for needle in (
            "csrf",
            "credentialed",
            "bypass same-origin",
            "extract sensitive data",
            "sensitive data",
        )
    ):
        calibrated = max(calibrated, 3)

    if any(
        needle in title
        for needle in (
            "maintain access",
            "persistence",
            "extract admin credential",
            "extract admin token",
            "escalate privileges",
            "escalate from low-privilege",
        )
    ):
        calibrated = max(calibrated, 3)

    if phase_str in {"1", "2"} and any(
        needle in title for needle in ("review ", "analyze ", "map ", "check ", "verify ")
    ):
        calibrated = max(calibrated, 2)

    return min(5, max(1, calibrated))


def _default_checklist_phase_title(phase: str) -> str:
    return {
        "1": "Reconnaissance",
        "2": "Enumeration",
        "3": "Configuration & Infrastructure Testing",
        "4": "Authentication, Authorization & Injection Testing",
        "5": "Session Management Testing",
        "6": "Exploitation & Validation",
        "7": "Post-Exploitation",
        "8": "Reporting",
    }.get(str(phase).strip(), f"Phase {phase or 'unknown'}")


def _normalize_structured_checklist_payload(
    payload: dict[str, Any] | None,
    *,
    fallback_target_type: str,
    fallback_checklist: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fallback = fallback_checklist if isinstance(fallback_checklist, dict) else {}
    if not isinstance(payload, dict):
        payload = {}
    candidate = payload.get("checklist") if isinstance(payload.get("checklist"), dict) else payload

    raw_blocks = candidate.get("checklist", [])
    blocks: list[dict[str, Any]] = []
    if isinstance(raw_blocks, list):
        for idx, raw_block in enumerate(raw_blocks, start=1):
            if not isinstance(raw_block, dict):
                continue
            phase = str(raw_block.get("phase", idx)).strip() or str(idx)
            title = str(raw_block.get("title", "")).strip() or _default_checklist_phase_title(phase)
            raw_items = raw_block.get("items", [])
            if not isinstance(raw_items, list):
                continue
            items: list[dict[str, Any]] = []
            seen: set[str] = set()
            for item in raw_items:
                if isinstance(item, dict):
                    name = str(item.get("name", item.get("title", ""))).strip()
                    raw_priority = item.get("priority")
                else:
                    name = str(item).strip()
                    raw_priority = None
                if not name:
                    continue
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                priority = _coerce_checklist_priority(raw_priority)
                if priority is None:
                    priority = _default_priority_for_item(name, phase)
                priority = _calibrate_checklist_priority(name, phase, priority)
                items.append({"name": name, "priority": priority})
            if items:
                blocks.append(
                    {
                        "phase": str(len(blocks) + 1),
                        "title": title,
                        "items": items,
                    }
                )

    if not blocks and isinstance(fallback.get("checklist"), list):
        blocks = fallback["checklist"]

    available_total = sum(
        len(block.get("items", []))
        for block in blocks
        if isinstance(block, dict)
    )
    return {
        "target_type": str(candidate.get("target_type", "") or fallback.get("target_type", "") or fallback_target_type),
        "available_total": int(available_total),
        "checklist": blocks,
    }


def _extract_checklist_result_from_text(
    raw: str,
    *,
    fallback_target_type: str,
    fallback_checklist: dict[str, Any] | None = None,
) -> PlannerChecklistResult:
    text = re.sub(r"<think>.*?</think>", "", str(raw or ""), flags=re.DOTALL).strip()
    if not text:
        return PlannerChecklistResult(
            status="failed",
            summary="Planner checklist generator returned empty output.",
            checklist=_normalize_structured_checklist_payload(
                {},
                fallback_target_type=fallback_target_type,
                fallback_checklist=fallback_checklist,
            ),
        )

    candidates: list[dict[str, Any]] = []

    def _collect(obj: Any) -> None:
        if isinstance(obj, dict):
            candidates.append(obj)

    try:
        _collect(json.loads(text))
    except (json.JSONDecodeError, TypeError):
        pass

    if not candidates:
        for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE):
            candidate = block.strip()
            if not candidate:
                continue
            try:
                _collect(json.loads(candidate))
            except (json.JSONDecodeError, TypeError):
                continue

    if not candidates:
        marker_idx = text.find('"checklist"')
        if marker_idx >= 0:
            start = text.rfind("{", 0, marker_idx)
            while start >= 0:
                obj_text = _extract_json_object_at(text, start)
                if not obj_text:
                    break
                try:
                    parsed = json.loads(obj_text)
                    _collect(parsed)
                    if candidates:
                        break
                except (json.JSONDecodeError, TypeError):
                    pass
                start = text.rfind("{", 0, start)

    payload = candidates[0] if candidates else {}
    status = str(payload.get("status", "complete")).strip().lower() if isinstance(payload, dict) else "complete"
    if status not in {"complete", "blocked", "failed"}:
        status = "complete"
    checklist = _normalize_structured_checklist_payload(
        payload,
        fallback_target_type=fallback_target_type,
        fallback_checklist=fallback_checklist,
    )
    summary = (
        f"Planner checklist ready with {checklist.get('available_total', 0)} items."
        if checklist.get("checklist")
        else "Planner checklist generation returned no items."
    )
    return PlannerChecklistResult(status=status, summary=summary, checklist=checklist)


def _normalize_intel_checklist(
    checklist_payload: dict[str, Any],
) -> dict[str, Any]:
    phases_raw = checklist_payload.get("checklist", [])
    phases: list[dict[str, Any]] = []
    if isinstance(phases_raw, list):
        for phase in phases_raw:
            if not isinstance(phase, dict):
                continue
            phase_id = str(phase.get("phase", "")).strip()
            title = str(phase.get("title", "")).strip() or phase_id or "Phase"
            raw_items = phase.get("items", [])
            items: list[dict[str, Any]] = []
            if isinstance(raw_items, list):
                for item in raw_items:
                    if isinstance(item, str):
                        name = item.strip()
                        if name:
                            items.append({"name": name})
                        continue
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name", "")).strip()
                    if not name:
                        continue
                    entry: dict[str, Any] = {"name": name}
                    priority = _coerce_checklist_priority(item.get("priority"))
                    if priority is not None:
                        entry["priority"] = priority
                    items.append(entry)
            if items:
                items.sort(key=lambda x: x.get("priority", 0), reverse=True)
            phases.append({"phase": phase_id, "title": title, "items": items})

    available_total_raw = checklist_payload.get("available_total")
    try:
        available_total = int(available_total_raw)
    except (TypeError, ValueError):
        available_total = sum(len(p.get("items", [])) for p in phases)

    return {
        "target_type": str(checklist_payload.get("target_type", "") or ""),
        "available_total": available_total,
        "phases": phases,
    }


def _build_intel_checklist_windows(
    checklist_payload: dict[str, Any],
    *,
    max_items: int = PLANNER_CHECKLIST_WINDOW_MAX_ITEMS,
    max_items_per_phase: int = PLANNER_CHECKLIST_WINDOW_MAX_ITEMS_PER_PHASE,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Create round-robin checklist windows so planner can eventually see all items."""
    normalized = _normalize_intel_checklist(checklist_payload)
    phases = normalized.get("phases", [])
    if not isinstance(phases, list) or not phases:
        overview = {
            "target_type": normalized.get("target_type", ""),
            "available_total": int(normalized.get("available_total", 0)),
            "phase_counts": [],
            "windows_total": 0,
        }
        return overview, []

    cursors = [0] * len(phases)
    windows: list[dict[str, Any]] = []
    safety_limit = 512
    iterations = 0

    while iterations < safety_limit:
        iterations += 1
        remaining_total = 0
        for idx, phase in enumerate(phases):
            items = phase.get("items", [])
            if isinstance(items, list):
                remaining_total += max(0, len(items) - cursors[idx])
        if remaining_total <= 0:
            break

        selected_by_phase: list[list[dict[str, Any]]] = [[] for _ in phases]
        taken_total = 0

        # Pass 1: balanced slice per phase.
        for idx, phase in enumerate(phases):
            if taken_total >= max_items:
                break
            items = phase.get("items", [])
            if not isinstance(items, list):
                continue
            cursor = cursors[idx]
            if cursor >= len(items):
                continue
            take = min(max_items_per_phase, len(items) - cursor, max_items - taken_total)
            if take <= 0:
                continue
            selected_by_phase[idx].extend(items[cursor: cursor + take])
            cursors[idx] += take
            taken_total += take

        # Pass 2: fill remaining room if still under max_items.
        progressed = True
        while taken_total < max_items and progressed:
            progressed = False
            for idx, phase in enumerate(phases):
                if taken_total >= max_items:
                    break
                items = phase.get("items", [])
                if not isinstance(items, list):
                    continue
                cursor = cursors[idx]
                if cursor >= len(items):
                    continue
                selected_by_phase[idx].append(items[cursor])
                cursors[idx] += 1
                taken_total += 1
                progressed = True
                if taken_total >= max_items:
                    break

        window_phases: list[dict[str, Any]] = []
        for idx, phase in enumerate(phases):
            chosen = selected_by_phase[idx]
            if not chosen:
                continue
            window_phases.append(
                {
                    "phase": phase.get("phase", ""),
                    "title": phase.get("title", ""),
                    "items": chosen,
                }
            )

        if not window_phases:
            break

        remaining_after = 0
        for idx, phase in enumerate(phases):
            items = phase.get("items", [])
            if isinstance(items, list):
                remaining_after += max(0, len(items) - cursors[idx])

        windows.append(
            {
                "window_index": len(windows) + 1,
                "window_items": taken_total,
                "remaining_items_after_window": remaining_after,
                "checklist": window_phases,
            }
        )

    phase_counts = [
        {
            "phase": p.get("phase", ""),
            "title": p.get("title", ""),
            "items": len(p.get("items", []))
            if isinstance(p.get("items", []), list)
            else 0,
        }
        for p in phases
    ]
    overview = {
        "target_type": normalized.get("target_type", ""),
        "available_total": int(normalized.get("available_total", 0)),
        "phase_counts": phase_counts,
        "windows_total": len(windows),
    }
    return overview, windows


def _build_intel_checklist_compact_summary(
    checklist_payload: dict[str, Any],
    *,
    max_high_priority_pending: int = PLANNER_CHECKLIST_SUMMARY_MAX_HIGH_PRIORITY_PENDING,
    max_changed: int = PLANNER_CHECKLIST_SUMMARY_MAX_CHANGED_ITEMS,
) -> dict[str, Any]:
    """Build a token-efficient checklist summary for planner context.

    Priority scale (lower = more severe, industry standard):
      P1 = Critical (SQLi, RCE, SSRF, Command Injection)
      P2 = High (XSS, Auth Bypass, SSTI)
      P3 = Medium (TLS, Headers, Config)
      P4 = Low (Info leakage)
      P5 = Info (Recon, Enumeration)

    The source checklist from Intel is usually status-less (all pending), but this
    keeps a stable schema that can later include real deltas from DB-backed runtime
    checklist states.
    """
    normalized = _normalize_intel_checklist(checklist_payload)
    phases = normalized.get("phases", [])
    if not isinstance(phases, list):
        phases = []

    totals = {
        "pending": 0,
        "in_progress": 0,
        "done": 0,
        "skipped": 0,
        "failed": 0,
    }
    # Track high-priority items (P1=Critical, P2=High) for focused planning
    high_priority_pending: list[dict[str, Any]] = []
    phase_counts: list[dict[str, Any]] = []

    for phase in phases:
        if not isinstance(phase, dict):
            continue
        phase_id = str(phase.get("phase", "")).strip()
        title = str(phase.get("title", "")).strip() or phase_id or "Phase"
        items = phase.get("items", [])
        if not isinstance(items, list):
            items = []
        phase_counts.append(
            {
                "phase": phase_id,
                "title": title,
                "items": len(items),
            }
        )

        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            # Intel baseline has no runtime status; default to pending.
            totals["pending"] += 1
            priority = _coerce_checklist_priority(item.get("priority"))
            # Capture high-priority items (P1=Critical, P2=High) for focus
            if priority in (1, 2) and len(high_priority_pending) < max_high_priority_pending:
                high_priority_pending.append(
                    {
                        "key": _normalized_token(name),
                        "phase": phase_id or title,
                        "label": name,
                        "priority": priority,
                    }
                )

    available_total = int(normalized.get("available_total", 0) or 0)
    if available_total <= 0:
        available_total = totals["pending"]

    return {
        "target_type": str(normalized.get("target_type", "") or ""),
        "available_total": available_total,
        "totals": totals,
        "high_priority_pending": high_priority_pending,  # P1/P2 items to prioritize
        # Reserved fields for DB/runtime checklist deltas.
        "in_progress": [],
        "just_completed": [],
        "failed": [],
        "phase_counts": phase_counts,
        "max_changed_items": max_changed,
    }


def _build_intel_checklist_compact_message(summary: dict[str, Any]) -> str:
    if not isinstance(summary, dict) or not summary:
        return ""
    payload = {
        "target_type": str(summary.get("target_type", "")),
        "available_total": int(summary.get("available_total", 0) or 0),
        "totals": summary.get("totals", {}),
        "high_priority_pending": summary.get("high_priority_pending", []),
        "in_progress": summary.get("in_progress", []),
        "just_completed": summary.get("just_completed", []),
        "failed": summary.get("failed", []),
        "phase_counts": summary.get("phase_counts", []),
    }
    return (
        "Checklist compact state (JSON). Priority scale: P1=Critical, P2=High, P3=Medium, P4=Low, P5=Info. "
        "Focus on high_priority_pending items (P1/P2) first. "
        "Mutate via action_plan.checklist_updates/checklist_additions:\n"
        + json.dumps(payload, ensure_ascii=True)
    )


def _build_intel_checklist_window_message(
    checklist_overview: dict[str, Any],
    checklist_windows: list[dict[str, Any]],
    round_count: int,
) -> str:
    if not checklist_windows:
        return ""
    idx = min(max(round_count - 1, 0), len(checklist_windows) - 1)
    payload = {
        "checklist_overview": checklist_overview,
        "window_index": idx + 1,
        "window_total": len(checklist_windows),
        "window": checklist_windows[idx],
    }
    return (
        "Intel checklist runtime context window (JSON). "
        "Use this window plus discovery evidence to maintain full coverage:\n"
        + json.dumps(payload, ensure_ascii=True)
    )


# ═════════════════════════════════════════════════════════════════════════════
# PLANNER AGENT
# ═════════════════════════════════════════════════════════════════════════════


class PlannerAgent:
    """LangGraph-based planner that builds pentest plans with tool calling.

    Modes:
        - Warmup: Builds the first recon-only startup plan.
        - Full: Builds the first full plan after Intel synthesis.
        - Loop: Receives executor results, returns updated scenarios.
    """

    def __init__(
        self,
        tools: list[Tool] | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        mode: str | None = None,
        callback: PlannerCallback | None = None,
        project_id: str | None = None,
        projects_store: Any | None = None,
        vector_store: Any | None = None,
    ) -> None:
        self._mode = mode or llm_mode.mode
        self._cb = callback or _NoOpCallback()
        self._project_id = project_id or ""
        self._projects_store = projects_store
        self._vector_store = vector_store

        tool_list = tools or ALL_PLANNER_TOOLS
        # Planner LLM should not call update_pentest_plan directly.
        # Plan persistence is applied statically in parse-output step.
        tool_list = [t for t in tool_list if t.name != "update_pentest_plan"]
        self._tools = {t.name: t for t in tool_list}
        self._tool_schemas = [t.schema() for t in tool_list]
        self._tool_valid_params: dict[str, set[str] | None] = {
            t.name: _get_valid_params(t) for t in tool_list
        }

        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LLMClient(self._local_config, mode="local", client_name="planner")
            self._model_name = self._local_config.model
        else:
            self._config = config or get_public_agent_config("planner")
            self._llm = LLMClient(self._config, mode="public", client_name="planner")
            self._model_name = self._config.model

        self._context_window = None

        # Initialize context builder if stores are available
        if self._projects_store and self._vector_store:
            self._context_builder = PlannerContextBuilder(
                projects_store=self._projects_store,
                vector_store=self._vector_store,
                system_prompt=PLAN_CREATE_UPDATE_SYSTEM_PROMPT,
            )
        else:
            self._context_builder = None

        logger.info(
            "planner_initialized",
            mode=self._mode,
            model=self._model_name,
            provider=(self._local_config.provider if self._mode == "local" else self._config.provider),
        )
        self._graph = self._build_graph()
        self._last_state_hash: str = ""
        self._last_plan_result: PlannerResult | None = None

    async def generate_checklist(
        self,
        user_message: str,
        *,
        current_checklist: dict[str, Any] | None = None,
        target_type: str = "",
    ) -> PlannerChecklistResult:
        self._cb.on_step("Planner checklist generator starting")

        project = self._projects_store.get_project(self._project_id) if self._projects_store else {}
        if not isinstance(project, dict): project = {}
        engagement_type = project.get("engagement_type", "pentest")
        target = project.get("target", "")
        scope = project.get("scope", "")
        last_scan = project.get("lastScan", {}) if isinstance(project.get("lastScan"), dict) else {}
        scan_result = last_scan.get("result", {}) if isinstance(last_scan.get("result"), dict) else {}
        brain = scan_result.get("system_memory", {}) if isinstance(scan_result.get("system_memory"), dict) else {}
        plan_state = last_scan.get("plan", {}) if isinstance(last_scan.get("plan"), dict) else {}
        fallback_checklist = current_checklist if isinstance(current_checklist, dict) else {}
        
        system_content = render_planner_prompt(
            CHECKLIST_GENERATOR_SYSTEM_PROMPT,
            engagement_type=engagement_type,
            target=target,
            scope=scope,
            brain=brain,
            checklist_state=fallback_checklist,
            plan_state=plan_state,
        )
        if _needs_nothink(self._model_name):
            system_content = "/nothink\n" + system_content

        checklist_tool_schemas = self._checklist_tool_schemas()
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_message},
        ]
        round_cap = max(1, int(CHECKLIST_MAX_TOOL_ROUNDS))
        last_content = ""

        try:
            for round_count in range(1, round_cap + 1):
                self._cb.on_step(
                    f"Checklist LLM Round {round_count}/{round_cap}"
                )

                round_messages = list(messages)
                tools_for_call = checklist_tool_schemas
                if round_count >= round_cap:
                    round_messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Final round: return strict JSON now with keys "
                                "`status` and `checklist`. Do not call any tools."
                            ),
                        }
                    )
                    tools_for_call = None

                response = await self._llm.chat(
                    [_dict_to_msg(m) for m in round_messages],
                    tools=tools_for_call,
                    temperature=0,
                    max_tokens=min(PLANNER_MAX_TOKENS_PER_REQUEST, 5000),
                )

                raw_content = response.content or ""
                tool_calls = response.tool_calls or []
                if not tool_calls and raw_content:
                    cleaned_content, inline_calls = _extract_inline_tool_calls(raw_content)
                    if inline_calls:
                        tool_calls = inline_calls
                        raw_content = cleaned_content
                        self._cb.on_warn("Recovered inline checklist tool-call from text.")

                last_content = raw_content
                if tool_calls and tools_for_call:
                    tool_names = [tc["function"]["name"] for tc in tool_calls]
                    self._cb.on_step(
                        f"Checklist round {round_count}: Calling tools → {tool_names}"
                    )
                    batch_results = await self._execute_checklist_tool_calls(
                        tool_calls,
                        target_type=target_type,
                        info=user_message,
                    )
                    messages.append(
                        {
                            "role": "assistant",
                            "content": raw_content,
                            "tool_calls": tool_calls,
                        }
                    )
                    for item in batch_results:
                        messages.append(
                            {
                                "role": "tool",
                                "content": str(item.get("result", "")),
                                "tool_call_id": str(item.get("tool_call_id", "")),
                                "name": str(item.get("name", "")),
                            }
                        )
                    continue

                result = _extract_checklist_result_from_text(
                    raw_content,
                    fallback_target_type=target_type,
                    fallback_checklist=fallback_checklist,
                )
                self._cb.on_done(result.summary)
                return result

            result = _extract_checklist_result_from_text(
                last_content,
                fallback_target_type=target_type,
                fallback_checklist=fallback_checklist,
            )
            self._cb.on_done(result.summary)
            return result
        except Exception as exc:
            logger.warning("planner_checklist_generation_failed", error=str(exc))
            checklist = _normalize_structured_checklist_payload(
                {},
                fallback_target_type=target_type,
                fallback_checklist=fallback_checklist,
            )
            return PlannerChecklistResult(
                status="failed",
                summary="Planner checklist generation failed; using fallback checklist state.",
                checklist=checklist,
            )

    def _tool_schemas_for_mode(self, is_loop: bool) -> list[dict[str, Any]]:
        if not is_loop:
            return self._tool_schemas
        return [
            schema
            for schema in self._tool_schemas
            if schema.get("function", {}).get("name")
            not in {"remove_target_type", "get_pentest_plan", "get_checklists"}
        ]

    def _checklist_tool_schemas(self) -> list[dict[str, Any]]:
        allowed = {"get_checklists", "get_page", "search_kb", "search_web"}
        return [
            schema
            for schema in self._tool_schemas
            if schema.get("function", {}).get("name") in allowed
        ]

    async def _execute_checklist_tool_calls(
        self,
        tool_calls: list[dict[str, Any]],
        *,
        target_type: str,
        info: str,
    ) -> list[dict[str, Any]]:
        batch_results: list[dict[str, Any]] = []
        default_domain = _planner_kb_domain_for_target_type(target_type)

        for tc in tool_calls:
            raw_tool_name = tc["function"]["name"]
            raw_args = tc["function"].get("arguments", "{}")
            call_id = tc["id"]

            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                args = {}
            if not isinstance(args, dict):
                args = {}

            tool_name, corrected = self._resolve_compatible_tool_name(raw_tool_name)
            if corrected:
                self._cb.on_warn(
                    f"Auto-corrected checklist tool '{raw_tool_name}' → '{tool_name}'."
                )

            args = self._repair_tool_args(tool_name, args)
            if tool_name == "get_checklists":
                if target_type and not str(args.get("target_type", "")).strip():
                    args["target_type"] = target_type
                if info and not str(args.get("info", "")).strip():
                    args["info"] = info
            elif tool_name == "search_kb":
                if not str(args.get("domain", "")).strip():
                    args["domain"] = default_domain

            args = self._filter_tool_args(tool_name, args)
            tool = self._tools.get(tool_name)

            if tool is None:
                result_str = f"Error: unknown tool '{raw_tool_name}'"
                self._cb.on_warn(f"Unknown checklist tool: {raw_tool_name}")
            else:
                self._report_tool_start(tool_name, args)
                try:
                    result_str = _truncate_result(await tool.execute(**args))
                    self._report_tool_result(tool_name, result_str)
                except Exception as exc:
                    result_str = f"Error executing {tool_name}: {exc}"
                    self._cb.on_warn(f"Checklist tool error: {exc}")
                    logger.error(
                        "planner_checklist_tool_error",
                        tool=tool_name,
                        error=str(exc),
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

        return batch_results

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
        round_cap = int(state.get("planning_round_cap", MAX_TOOL_ROUNDS) or MAX_TOOL_ROUNDS)
        self._cb.on_step(f"LLM Round {round_count}/{round_cap}")

        # Determine if we should compress context (retry recovery).
        messages_raw = state["messages"]
        if state.get("recovery_attempted"):
            messages_raw = _compress_messages_for_retry(messages_raw)

        # For initial planning, inject compact checklist state once.
        # This keeps context bounded and avoids re-injecting large windows every round.
        if not state.get("is_loop"):
            if round_count == 1:
                compact_summary = state.get("intel_checklist_compact_summary", {})
                if isinstance(compact_summary, dict) and compact_summary:
                    checklist_ctx = _build_intel_checklist_compact_message(compact_summary)
                    if checklist_ctx:
                        self._cb.on_step("Planner checklist planning context prepared")
                        messages_raw = [
                            *messages_raw,
                            {"role": "user", "content": checklist_ctx},
                        ]
                else:
                    # Fallback path: if compact summary missing, use first checklist window.
                    checklist_windows = state.get("intel_checklist_windows", [])
                    if isinstance(checklist_windows, list) and checklist_windows:
                        checklist_overview = state.get("intel_checklist_overview", {})
                        checklist_ctx = _build_intel_checklist_window_message(
                            checklist_overview if isinstance(checklist_overview, dict) else {},
                            checklist_windows,
                            1,
                        )
                        if checklist_ctx:
                            self._cb.on_step("Planner checklist fallback window injected 1/1")
                            messages_raw = [
                                *messages_raw,
                                {"role": "user", "content": checklist_ctx},
                            ]

        if round_count >= round_cap:
            # Final planning round: force a strict JSON answer and disable tools.
            messages_raw = [
                *messages_raw,
                {
                    "role": "user",
                    "content": (
                        "Final round: return strict JSON now with keys "
                        "`summary`, `needs`, `plan`, `action_plan`. "
                        "Do not call any tools."
                    ),
                },
            ]
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

            tools_for_call = None if state.get("disable_tools") else (state.get("tool_schemas") if self._tools else None)
            if round_count >= round_cap:
                tools_for_call = None

            # Global queue coordination: prevent concurrent calls from exceeding Mistral 4 req/min limit
            global_queue = get_global_llm_queue()
            backup_fallback = get_backup_llm_fallback()

            response = None
            try:
                await global_queue.acquire("planner")
                try:
                    response = await _retry_with_backoff(
                        lambda: self._llm.chat(
                            messages,
                            tools=tools_for_call,
                            temperature=0.3,
                            max_tokens=token_budget,
                        ),
                        timeout=PLANNER_CALL_TIMEOUT_SECONDS,
                        on_retry=_on_retry,
                    )
                finally:
                    global_queue.release("planner")

            except Exception as exc:
                # BACKUP LLM FALLBACK: On 429 or Timeout, try backup LLM for single call
                text = str(exc).lower()
                is_rate_limited = "429" in text or "rate limit" in text
                is_timeout = isinstance(exc, (_TRANSIENT_EXCEPTIONS, TimeoutError, asyncio.TimeoutError)) or "timeout" in text

                if is_rate_limited or is_timeout:
                    backup_llm = await backup_fallback.get_backup_llm()
                    if backup_llm is not None:
                        try:
                            reason_log = "main_llm_429" if is_rate_limited else "main_llm_timeout"
                            logger.info(
                                "planner_backup_llm_fallback",
                                reason=reason_log,
                            )
                            reason_msg = "main hit 429" if is_rate_limited else "main timed out"
                            self._cb.on_warn(
                                f"Planner using backup LLM ({reason_msg}); single call, then return to main LLM"
                            )

                            response = await asyncio.wait_for(
                                backup_llm.chat(
                                    messages,
                                    tools=tools_for_call,
                                    temperature=0.3,
                                    max_tokens=token_budget,
                                ),
                                timeout=PLANNER_CALL_TIMEOUT_SECONDS,
                            )
                            logger.info("planner_backup_llm_success")

                        except Exception as backup_exc:
                            logger.warning(
                                "planner_backup_llm_failed",
                                error=str(backup_exc)[:100],
                            )
                            raise exc  # Raise original exception to be handled below

                    else:
                        raise  # No backup LLM available, re-raise original exception
                else:
                    raise  # Not rate limited, re-raise as-is

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
        round_cap = int(state.get("planning_round_cap", MAX_TOOL_ROUNDS) or MAX_TOOL_ROUNDS)
        if state["last_tool_calls"]:
            if state["round_count"] >= round_cap:
                self._cb.on_warn(
                    f"Reached max rounds ({round_cap}); forcing output."
                )
                return "parse_output"
            return "execute_tools"
        return "parse_output"

    # ── Execute Tools Node ─────────────────────────────────────────

    async def _execute_tools_node(self, state: PlannerState) -> dict[str, Any]:
        tool_calls = state["last_tool_calls"]

        # Execute all planned tools - do NOT restrict in loop mode
        # Planner needs full tool-calling capability in every cycle for effective replanning

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
        action_plan = _extract_action_plan_from_text(content) or {}
        previous_target_types = normalize_target_types(
            _current_plan.get("target_types", [])
            if isinstance(_current_plan, dict)
            else []
        )

        if state.get("error"):
            self._cb.on_warn(f"Planning failed: {state['error']}")
            return {
                "plan_result": {
                    "scenarios": [],
                    "needs": [],
                    "summary": f"Planning failed: {state['error']}",
                    "action_plan": {},
                }
            }

        plan_payload = _extract_plan_from_text(content)
        if plan_payload is None and action_plan:
            action_plan_plan = action_plan.get("plan")
            if isinstance(action_plan_plan, dict):
                plan_payload = action_plan_plan

        if plan_payload is not None:
            persist_status = await update_pentest_plan.execute(
                target=plan_payload.get("target", ""),
                scope=plan_payload.get("scope", ""),
                target_types=plan_payload.get("target_types"),
                phases=plan_payload.get("phases"),
                notes=plan_payload.get("notes", ""),
                planner_round=rounds,
            )
            lowered = str(persist_status).strip().lower()
            if not lowered.startswith("plan updated"):
                err_msg = str(persist_status).strip() or "invalid plan payload"
                self._cb.on_warn(f"Planning failed: {err_msg}")
                return {
                    "plan_result": {
                        "scenarios": [],
                        "needs": [],
                        "summary": f"Planning failed: {err_msg}",
                        "action_plan": {},
                    }
                }
            self._cb.on_done("Planner plan persisted (static apply).")

        result = _parse_planner_output(content)
        if action_plan and not result.action_plan:
            result.action_plan = action_plan
        action_plan_payload = (
            result.action_plan if isinstance(result.action_plan, dict) else {}
        )
        action_plan_payload = _normalize_action_plan(action_plan_payload)
        effective_target_types = normalize_target_types(
            _current_plan.get("target_types", [])
            if isinstance(_current_plan, dict)
            else []
        )
        if not effective_target_types and plan_payload and isinstance(plan_payload, dict):
            effective_target_types = normalize_target_types(plan_payload.get("target_types", []))

        discovered_additions = [
            tt for tt in effective_target_types
            if tt not in set(previous_target_types)
        ]
        existing_additions = normalize_target_types(
            action_plan_payload.get("target_type_additions", [])
            if isinstance(action_plan_payload, dict)
            else []
        )
        action_plan_payload["target_type_additions"] = normalize_target_types(
            [*existing_additions, *discovered_additions]
        )

        dispatch = _normalize_dispatch_items(
            action_plan_payload.get("dispatch", [])
            if isinstance(action_plan_payload.get("dispatch", []), list)
            else []
        )
        action_plan_payload["dispatch"] = _auto_dispatch_for_target_types(
            dispatch=dispatch,
            target_types=effective_target_types,
        )
        action_plan_payload["target_types"] = effective_target_types

        # Planner runs in plan-only mode: never return scenario batches here.
        result.scenarios = []

        # Calculate actual scenario count from the persisted plan (for accurate logging)
        actual_scenario_count = sum(
            len(step.get("scenarios", []))
            for phase in _current_plan.get("phases", [])
            if isinstance(phase, dict)
            for step in (
                phase.get("steps", [])
                if isinstance(phase.get("steps"), list)
                else []
            )
            if isinstance(step, dict)
        )

        self._cb.on_done(
            f"Planner complete: {actual_scenario_count} scenarios persisted "
            f"({total_tools} tool calls, {rounds} rounds)"
        )
        if result.needs:
            self._cb.on_step(f"Planner needs more data: {len(result.needs)} items")

        return {
            "plan_result": {
                "scenarios": result.scenarios,
                "needs": result.needs,
                "summary": result.summary,
                "tool_results": state.get("last_tool_results", []),
                "action_plan": action_plan_payload,
                "checklist_updates": action_plan_payload.get("checklist_updates", []),
                "checklist_additions": action_plan_payload.get("checklist_additions", []),
                "plan_modifications": action_plan_payload.get("plan_modifications", []),
                "dispatch": action_plan_payload.get("dispatch", []),
                "phase_advance": bool(action_plan_payload.get("phase_advance", False)),
                "phase_advance_blocked_by": action_plan_payload.get("phase_advance_blocked_by", []),
                "rationale": action_plan_payload.get("rationale", ""),
                "world_state_hash": state.get("world_state_hash", ""),
            }
        }

    # ── Tool reporting ─────────────────────────────────────────────

    def _report_tool_start(self, tool_name: str, args: dict[str, Any]) -> None:
        if tool_name == "update_pentest_plan":
            try:
                plan_data = args
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
        return (tool_name, False) if tool_name in self._tools else (tool_name, False)

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

            # Strip legacy plan_json hallucination and flatten it if present.
            plan_json_val = fixed.pop("plan_json", None)
            if plan_json_val:
                try:
                    if isinstance(plan_json_val, str):
                        parsed = json.loads(plan_json_val)
                    elif isinstance(plan_json_val, dict):
                        parsed = plan_json_val
                    else:
                        parsed = None
                        
                    if isinstance(parsed, dict):
                        for k, v in parsed.items():
                            fixed.setdefault(k, v)
                except Exception:
                    pass

            # Decode stringified JSON fields.
            for key in ("target_types", "phases"):
                if isinstance(fixed.get(key), str):
                    try:
                        fixed[key] = json.loads(fixed[key])
                    except json.JSONDecodeError:
                        pass

        return fixed

    # ── Public API ─────────────────────────────────────────────────

    async def run(
        self,
        user_message: str,
        is_loop: bool = False,
        intel_checklist: dict[str, Any] | None = None,
        plan_mode: str | None = None,
    ) -> PlannerResult:
        normalized_plan_mode = str(plan_mode or "").strip().lower()
        if is_loop:
            normalized_plan_mode = "loop"
        elif normalized_plan_mode not in {"warmup", "full"}:
            normalized_plan_mode = "warmup" if "warmup recon stage" in user_message.lower() else "full"

        mode_label = {
            "warmup": "warmup recon plan",
            "full": "full plan",
            "loop": "loop re-entry",
        }.get(normalized_plan_mode, "full plan")
        self._cb.on_step(f"Planner Agent starting ({mode_label})")
        if normalized_plan_mode == "loop":
            system_content = PLAN_CREATE_UPDATE_SYSTEM_PROMPT
        else:
            system_content = PLAN_CREATE_UPDATE_SYSTEM_PROMPT

        # For loop rounds, use the 6-part context builder if available
        if normalized_plan_mode == "loop" and self._context_builder:
            try:
                system_content = await self._context_builder.build_context(
                    project_id=self._project_id,
                    engagement_data={},  # TODO: Pass target/detected_tech if available
                    user_message=None,  # User message will be appended separately
                )
                self._cb.on_step("Planner context built (6-part window)")
            except Exception as exc:
                logger.warning("context_builder_failed", error=str(exc))
                # Fall back to static prompt if context builder fails
                system_content = PLAN_CREATE_UPDATE_SYSTEM_PROMPT

        project = self._projects_store.get_project(self._project_id) if self._projects_store else {}
        if not isinstance(project, dict): project = {}
        engagement_type = project.get("engagement_type", "pentest")
        target = project.get("target", "")
        scope = project.get("scope", "")
        last_scan = project.get("lastScan", {}) if isinstance(project.get("lastScan"), dict) else {}
        scan_result = last_scan.get("result", {}) if isinstance(last_scan.get("result"), dict) else {}
        brain = scan_result.get("system_memory", {}) if isinstance(scan_result.get("system_memory"), dict) else {}
        plan_state = last_scan.get("plan", {}) if isinstance(last_scan.get("plan"), dict) else {}
        checklist_state = project.get("checklist", {}) if isinstance(project.get("checklist"), dict) else {}

        checklist_payload = intel_checklist if isinstance(intel_checklist, dict) else {}
        checklist_compact_summary = _build_intel_checklist_compact_summary(checklist_payload)
        checklist_overview, checklist_windows = _build_intel_checklist_windows(
            checklist_payload
        )
        
        # Filter out completed plan items to reduce noise
        filtered_plan_state = deepcopy(plan_state)
        if "phases" in filtered_plan_state:
            for phase in filtered_plan_state.get("phases", []):
                if isinstance(phase, dict) and "scenarios" in phase:
                    # Heavily truncate completed scenarios to prevent amnesia while saving tokens
                    filtered_scenarios = []
                    for s in phase.get("scenarios", []):
                        if not isinstance(s, dict): continue
                        if str(s.get("status", "")).strip().lower() == "completed" or s.get("done", False):
                            filtered_scenarios.append({
                                "id": s.get("id"),
                                "task": s.get("task"),
                                "status": s.get("status"),
                                "done": s.get("done")
                            })
                        else:
                            filtered_scenarios.append(s)
                    phase["scenarios"] = filtered_scenarios

        system_content = render_planner_prompt(
            system_content,
            engagement_type=engagement_type,
            target=target,
            scope=scope,
            brain=brain,
            checklist_state=checklist_compact_summary if checklist_compact_summary else checklist_state,
            plan_state=filtered_plan_state,
        )

        if _needs_nothink(self._model_name):
            system_content = "/nothink\n" + system_content
        if normalized_plan_mode in {"warmup", "full"} and checklist_compact_summary:
            self._cb.on_step(
                "Planner checklist compact state prepared: "
                f"items={checklist_compact_summary.get('available_total', 0)} "
                f"high_priority_tracked={len(checklist_compact_summary.get('high_priority_pending', []))}"
            )

        world_state_hash = _compute_world_state_hash(
            user_message=user_message,
            is_loop=normalized_plan_mode == "loop",
            checklist_compact_summary=checklist_compact_summary,
        )
        if self._last_state_hash and self._last_state_hash == world_state_hash:
            if self._last_plan_result is not None:
                self._cb.on_done(
                    "Planner world-state unchanged; reusing previous ActionPlan (0 LLM tokens)."
                )
                return self._last_plan_result

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
                    if normalized_plan_mode == "loop"
                    else []
                ),
                {"role": "user", "content": user_message},
            ],
            "tool_schemas": self._tool_schemas_for_mode(normalized_plan_mode == "loop"),
            "disable_tools": normalized_plan_mode == "warmup",
            "round_count": 0,
            "total_tool_calls": 0,
            "last_response": "",
            "last_tool_calls": [],
            "last_tool_results": [],
            "stop_after_tools": False,
            "is_loop": normalized_plan_mode == "loop",
            "plan_result": {},
            "error": "",
            "recovery_attempted": False,
            "world_state_hash": world_state_hash,
            "intel_checklist_overview": checklist_overview,
            "intel_checklist_windows": checklist_windows,
            "intel_checklist_compact_summary": checklist_compact_summary,
            "planning_round_cap": (
                min(MAX_TOOL_ROUNDS, 4)
                if normalized_plan_mode != "loop"
                else MAX_TOOL_ROUNDS
            ),
        }

        final_state = await self._graph.ainvoke(initial_state)

        plan_data = final_state.get("plan_result") or {}
        result = PlannerResult(
            scenarios=plan_data.get("scenarios", []),
            needs=plan_data.get("needs", []),
            summary=plan_data.get("summary", ""),
            tool_results=plan_data.get("tool_results", []),
            action_plan=plan_data.get("action_plan", {}),
        )
        self._last_state_hash = world_state_hash
        self._last_plan_result = result
        return result

    async def close(self) -> None:
        await self._llm.close()

    async def __aenter__(self) -> PlannerAgent:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
