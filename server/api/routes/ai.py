"""Frontend AI assist routes (non-scan interaction path)."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from server.nodes.architect.agent import ArchitectAgent
from server.agents.assistant import AssistantAgent
from server.api.dependencies import projects_store, scan_orchestrator
from server.api.routes.settings import has_saved_usable_llm_profile, llm_required_response
from server.layers.safety.prompt_guard import PromptInjectionGuard
from server.nodes.system_memory import (
    build_system_memory_prompt_block as build_target_memory_prompt_block,
    load_system_memory,
)
from server.utils.target_scope import normalize_target_scope

router = APIRouter(tags=["ai"])

_prompt_guard = PromptInjectionGuard()
_assistant_agent = AssistantAgent()
_MAX_PROMPT_LEN = 8000
logger = structlog.get_logger(__name__)
_ASSISTANT_RUN_TTL_SECONDS = 60 * 60
_KEEPALIVE_INTERVAL_SECONDS = 15.0
_architect_refresh_tasks: dict[str, asyncio.Task[Any]] = {}
_architect_refresh_lock = asyncio.Lock()


def _ensure_llm_profile_configured() -> None:
    if not has_saved_usable_llm_profile():
        raise HTTPException(status_code=409, detail=llm_required_response())


def _ensure_project_payload(project: dict[str, Any]) -> dict[str, Any]:
    payload = project.get("payload")
    if not isinstance(payload, dict):
        payload = {}
        project["payload"] = payload
    return payload


def _set_architect_refresh_state(
    project: dict[str, Any],
    *,
    status: str,
    phase: str | None = None,
    error: str = "",
) -> None:
    payload = _ensure_project_payload(project)
    current = payload.get("architecture_refresh")
    current_state = current if isinstance(current, dict) else {}
    now_iso = datetime.now(timezone.utc).isoformat()
    started_at = str(current_state.get("started_at") or "").strip() or now_iso
    refresh_state: dict[str, Any] = {
        "status": status,
        "phase": phase or status,
        "updated_at": now_iso,
    }
    if status == "running":
        refresh_state["started_at"] = started_at
        refresh_state["owner_pid"] = os.getpid()
    elif started_at:
        refresh_state["started_at"] = started_at
        refresh_state["completed_at"] = now_iso
    if error:
        refresh_state["error"] = error[:400]
    payload["architecture_refresh"] = refresh_state


async def _run_architect_refresh(project_id: str) -> None:
    try:
        project = projects_store.get_project(project_id)
        if not project:
            return

        target = str(project.get("target") or "").strip()
        target_type = str(project.get("targetType") or "web_app").strip()

        info = str(project.get("info") or "").strip()
        scope = ""
        for raw_line in info.splitlines():
            if raw_line.lower().startswith("scope:"):
                scope = raw_line.split(":", 1)[1].strip()
                break

        cache_root = (Path(__file__).resolve().parents[2] / "cache" / "project_runs").resolve()
        latest_run_dir = None
        if cache_root.exists():
            matching = [d for d in cache_root.iterdir() if d.is_dir() and d.name.startswith(project_id)]
            if matching:
                matching.sort(key=lambda d: d.stat().st_mtime, reverse=True)
                latest_run_dir = str(matching[0])

        if not latest_run_dir:
            logger.warning("architect_manual_refresh_no_cache_dir", project_id=project_id)
            target_memory = {}
        else:
            target_memory = load_system_memory(latest_run_dir)

        planner_memory_block = build_target_memory_prompt_block(target_memory)
        assistant_memory_block = _build_architect_assistant_memory_block(
            project,
            scope_key=normalize_target_scope(target, target_type),
        )
        memory_block = "\n\n".join(
            part for part in (planner_memory_block, assistant_memory_block) if str(part).strip()
        )
        vulnerabilities_block = _build_architect_vulnerabilities_block(project)

        def emit_architect_event(event_type: str, data: dict[str, Any]):
            latest_project = projects_store.get_project(project_id)
            if latest_project:
                if event_type == "architect_synthesizing":
                    _set_architect_refresh_state(latest_project, status="running", phase="synthesizing")
                    projects_store.upsert_project(latest_project)
                elif event_type == "architect_compressing":
                    _set_architect_refresh_state(latest_project, status="running", phase="compressing")
                    projects_store.upsert_project(latest_project)

            scan_orchestrator.emit_event(
                project_id,
                event=event_type,
                scan_id="manual",
                level="info",
                message=f"Architect [working] {event_type.replace('_', ' ')}...",
                data=data,
            )

        architect = ArchitectAgent(
            project_id=project_id,
            project_cache_dir=latest_run_dir,
            on_event=emit_architect_event,
        )

        previous_draft = project.get("payload", {}).get("architecture_draft")
        architecture_draft = await architect.synthesize(
            target=target,
            target_type=target_type,
            scope=scope,
            memory_block=memory_block,
            vulnerabilities_block=vulnerabilities_block,
            previous_draft=previous_draft,
        )

        latest_project = projects_store.get_project(project_id) or project
        if architecture_draft and isinstance(architecture_draft, dict) and architecture_draft.get("hosts"):
            payload = _ensure_project_payload(latest_project)
            payload["architecture_draft"] = architecture_draft
            _set_architect_refresh_state(latest_project, status="idle", phase="idle")
            projects_store.upsert_project(latest_project)
            emit_architect_event("architect_updated", {"architecture_draft": architecture_draft})
        else:
            logger.warning(
                "architect_manual_refresh_no_update",
                project_id=project_id,
                has_previous_draft=bool(previous_draft),
            )
            _set_architect_refresh_state(latest_project, status="idle", phase="idle")
            projects_store.upsert_project(latest_project)
            emit_architect_event(
                "architect_no_update",
                {
                    "project_id": project_id,
                    "has_previous_draft": bool(previous_draft),
                },
            )
    except Exception as exc:
        logger.exception("architect_manual_refresh_failed", project_id=project_id)
        project = projects_store.get_project(project_id)
        if project:
            _set_architect_refresh_state(
                project,
                status="error",
                phase="error",
                error=str(exc),
            )
            projects_store.upsert_project(project)
        scan_orchestrator.emit_event(
            project_id,
            event="architect_failed",
            scan_id="manual",
            level="error",
            message="Architect refresh failed.",
            data={"project_id": project_id, "error": str(exc)[:400]},
        )
    finally:
        async with _architect_refresh_lock:
            task = _architect_refresh_tasks.get(project_id)
            if task and task.done():
                _architect_refresh_tasks.pop(project_id, None)


def _build_architect_assistant_memory_block(project: dict[str, Any], *, scope_key: str) -> str:
    sections: list[str] = []

    if str(project.get("copilotContextScope", "")).strip() == scope_key:
        working_memory = str(project.get("copilotContext", "") or "").strip()
        if working_memory:
            sections.extend(["### ASSISTANT WORKING MEMORY", working_memory[:6000]])

    if str(project.get("copilotHistoryScope", "")).strip() == scope_key:
        history = project.get("copilotHistory", [])
        if isinstance(history, list):
            recent_turns: list[str] = []
            for item in history[-6:]:
                if not isinstance(item, dict):
                    continue
                role = str(item.get("role", "")).strip().lower()
                text = str(item.get("text", "") or "").strip()
                if role not in {"user", "assistant"} or not text:
                    continue
                recent_turns.append(f"{role}: {text[:220]}")
            if recent_turns:
                sections.extend(["### RECENT ASSISTANT DISCUSSION", *recent_turns])

    return "\n".join(sections).strip()


def _build_architect_vulnerabilities_block(project: dict[str, Any]) -> str:
    lines: list[str] = []
    findings = project.get("findings", [])
    if not isinstance(findings, list):
        return ""

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        status = str(finding.get("status", "")).strip().lower()
        user_status = str(finding.get("user_contribution_status", "")).strip().lower()
        if status not in {"confirmed", "verified"} and user_status != "done":
            continue
        title = str(finding.get("title", "") or "").strip()
        description = str(finding.get("description", "") or "").strip()
        severity = str(finding.get("severity", "") or "").strip().lower() or "unknown"
        target = str(finding.get("target", "") or "").strip()
        finding_id = str(finding.get("id", "") or "").strip()
        parts = [title] if title else []
        if severity:
            parts.append(f"severity={severity}")
        if target:
            parts.append(f"target={target}")
        if finding_id:
            parts.append(f"id={finding_id}")
        summary = " | ".join(parts)
        if description:
            summary = f"{summary}: {description[:260]}" if summary else description[:260]
        if summary:
            lines.append(f"- {summary}")
    return "\n".join(lines[:24])


@dataclass
class AssistantRun:
    request_id: str
    project_id: str
    scope_key: str
    prompt: str
    target: str
    target_type: str
    created_at: str
    updated_at: str
    status: str = "running"
    reply: str = ""
    route: str = "assistant"
    mode: str = "Ask"
    lane: str = "lightweight"
    style: str = "natural"
    blocked: bool = False
    next_context: str = ""
    backlog: list[dict[str, Any]] = field(default_factory=list)
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    toolLogs: list[dict[str, Any]] = field(default_factory=list)
    password_requests: list[dict[str, Any]] = field(default_factory=list)
    learning_signals: dict[str, Any] = field(default_factory=dict)
    callback: Any | None = None
    task: asyncio.Task[Any] | None = None


_assistant_runs: dict[str, AssistantRun] = {}
_assistant_scope_index: dict[str, str] = {}
_assistant_runs_lock = asyncio.Lock()


class AssistantExecuterCallback:
    def __init__(self, run: AssistantRun, loop: asyncio.AbstractEventLoop):
        self.run = run
        self.loop = loop
        self.password_waiters: dict[str, asyncio.Future[str | None]] = {}

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
        return True  # Assistant tools are pre-approved by the agent logic

    def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        from server.api.dependencies import projects_store
        
        # Check global system settings for automation password
        project = projects_store.get_project(self.run.project_id) if self.run.project_id else None
        approval_mode = "custom"
        if isinstance(project, dict):
            approval_mode = str(project.get("approval_mode", "custom")).lower().strip()
            
        if approval_mode == "auto":
            import os
            if os.geteuid() == 0:
                return ""  # Auto-approve silently without a password when running as root

        global_settings = projects_store.get_project("global_system_settings")
        if isinstance(global_settings, dict):
            sudo_pwd = global_settings.get("sudo_password")
            if sudo_pwd and approval_mode == "auto":
                return str(sudo_pwd)

        future = asyncio.run_coroutine_threadsafe(
            self._request_password_async(prompt, reason, call_id),
            self.loop
        )
        try:
            return future.result()
        except Exception:
            return None

    async def _request_password_async(self, prompt: str, reason: str, call_id: str) -> str | None:
        waiter = self.loop.create_future()
        self.password_waiters[call_id] = waiter
        
        _publish_run_event(self.run, "password_request", {
            "call_id": call_id,
            "prompt": prompt,
            "reason": reason
        })
        
        try:
            # Wait for user input (timeout 2 mins)
            return await asyncio.wait_for(waiter, timeout=120)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return None
        finally:
            self.password_waiters.pop(call_id, None)


class AIAssistPayload(BaseModel):
    prompt: str = Field(min_length=1, max_length=_MAX_PROMPT_LEN)
    project_id: str | None = Field(default=None, max_length=200)
    target: str = Field(default="", max_length=2048)
    target_type: str = Field(default="", max_length=120)
    context: str = Field(default="", max_length=12000)
    request_id: str | None = Field(default=None, max_length=200)


class AIAssistContextMetricsPayload(BaseModel):
    prompt: str = Field(default="", max_length=_MAX_PROMPT_LEN)
    project_id: str | None = Field(default=None, max_length=200)
    target: str = Field(default="", max_length=2048)
    target_type: str = Field(default="", max_length=120)
    context: str = Field(default="", max_length=12000)
    saved_context_override: str = Field(default="", max_length=40000)


class AIClearConversationPayload(BaseModel):
    project_id: str = Field(min_length=1, max_length=200)
    target: str = Field(default="", max_length=2048)
    target_type: str = Field(default="", max_length=120)


class AICancelAssistResponse(BaseModel):
    ok: bool = True
    request_id: str
    status: str


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scope_run_key(project_id: str | None, scope_key: str) -> str:
    return f"{str(project_id or '').strip()}::{scope_key}"


def _assistant_run_payload(run: AssistantRun) -> dict[str, Any]:
    return {
        "prompt": run.prompt,
        "target": run.target,
        "target_type": run.target_type,
        "reply": run.reply,
        "route": run.route,
        "mode": run.mode,
        "lane": run.lane,
        "style": run.style,
        "blocked": run.blocked,
        "next_context": run.next_context,
        "backlog": run.backlog[-200:],
        "toolLogs": run.toolLogs,
        "password_requests": run.password_requests,
        "learning_signals": run.learning_signals,
    }


def _persist_assistant_run(run: AssistantRun) -> None:
    if not run.project_id:
        return
    try:
        projects_store.upsert_task_run(
            run_id=run.request_id,
            project_id=run.project_id,
            task_type="assistant",
            status=run.status,
            scope_key=run.scope_key,
            payload=_assistant_run_payload(run),
        )
    except Exception:
        logger.exception("assistant_run_persist_failed", request_id=run.request_id)


def _restore_assistant_run(record: dict[str, Any]) -> AssistantRun | None:
    if str(record.get("task_type", "")).strip().lower() != "assistant":
        return None
    payload = record.get("payload", {})
    if not isinstance(payload, dict):
        payload = {}
    run = AssistantRun(
        request_id=str(record.get("run_id", "")).strip(),
        project_id=str(record.get("project_id", "")).strip(),
        scope_key=str(record.get("scope_key", "")).strip(),
        prompt=str(payload.get("prompt", "") or "").strip(),
        target=str(payload.get("target", "") or "").strip(),
        target_type=str(payload.get("target_type", "") or "").strip(),
        created_at=str(record.get("created_at", "") or _utc_now_iso()),
        updated_at=str(record.get("updated_at", "") or _utc_now_iso()),
        status=str(record.get("status", "") or "failed").strip().lower() or "failed",
        reply=str(payload.get("reply", "") or "").strip(),
        route=str(payload.get("route", "") or "assistant").strip() or "assistant",
        mode=str(payload.get("mode", "") or "Ask").strip() or "Ask",
        lane=str(payload.get("lane", "") or "lightweight").strip() or "lightweight",
        style=str(payload.get("style", "") or "natural").strip() or "natural",
        blocked=bool(payload.get("blocked", False)),
        next_context=str(payload.get("next_context", "") or "").strip(),
        backlog=[
            item for item in payload.get("backlog", [])
            if isinstance(item, dict)
        ],
        toolLogs=[
            item for item in payload.get("toolLogs", [])
            if isinstance(item, dict)
        ],
        password_requests=[
            item for item in payload.get("password_requests", [])
            if isinstance(item, dict)
        ],
        learning_signals=payload.get("learning_signals", {}) if isinstance(payload.get("learning_signals"), dict) else {},
    )
    if not run.request_id:
        return None
    return run


def _prune_finished_runs() -> None:
    now = datetime.now(timezone.utc)
    expired_ids: list[str] = []
    for request_id, run in _assistant_runs.items():
        if run.status == "running":
            continue
        try:
            updated_at = datetime.fromisoformat(run.updated_at)
        except Exception:
            updated_at = now
        age_seconds = max(0.0, (now - updated_at).total_seconds())
        if age_seconds > _ASSISTANT_RUN_TTL_SECONDS:
            expired_ids.append(request_id)

    for request_id in expired_ids:
        run = _assistant_runs.pop(request_id, None)
        if not run:
            continue
        scope_run_key = _scope_run_key(run.project_id, run.scope_key)
        if _assistant_scope_index.get(scope_run_key) == request_id:
            _assistant_scope_index.pop(scope_run_key, None)


def _queue_run_event(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
    if queue.full():
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:
        pass


def _publish_run_event(run: AssistantRun, event_type: str, data: dict[str, Any]) -> None:
    payload = {
        "type": event_type,
        "data": json.loads(json.dumps(data, ensure_ascii=True)),
    }
    run.updated_at = _utc_now_iso()
    run.backlog.append(payload)
    if len(run.backlog) > 200:
        run.backlog = run.backlog[-200:]
    _persist_assistant_run(run)
    for queue in tuple(run.subscribers):
        _queue_run_event(queue, payload)


async def _load_saved_assistant_context(
    *,
    project_id: str | None,
    scope_key: str,
) -> tuple[str, list[dict[str, object]]]:
    saved_context = ""
    saved_history: list[dict[str, object]] = []
    if project_id:
        project = projects_store.get_project(project_id)
        if isinstance(project, dict):
            if str(project.get("copilotContextScope", "")).strip() == scope_key:
                saved_context = str(project.get("copilotContext", "") or "").strip()
            raw_history = project.get("copilotHistory", [])
            if (
                str(project.get("copilotHistoryScope", "")).strip() == scope_key
                and isinstance(raw_history, list)
            ):
                saved_history = [
                    item for item in raw_history
                    if isinstance(item, dict)
                ]
    return saved_context, saved_history


async def _execute_assistant_run(
    run: AssistantRun,
    *,
    prompt: str,
    guard_context: str,
    live_context: str,
    saved_context: str,
    saved_history: list[dict[str, object]],
) -> None:
    from server.agents.executor.base import _executer_callback_context
    
    loop = asyncio.get_running_loop()
    callback = AssistantExecuterCallback(run, loop)
    run.callback = callback
    token = _executer_callback_context.set(callback)
    
    try:
        decision = await _prompt_guard.classify_user_prompt(
            prompt,
            context=guard_context,
            use_llm=True,
        )

        if decision.is_injection:
            reply = (
                "Potential prompt-injection detected. "
                f"Request blocked by safety guard. Reason: {decision.reason}"
            )
            run.reply = reply
            run.route = "blocked"
            run.mode = "Ask"
            run.lane = "lightweight"
            run.style = "natural"
            run.blocked = True
            run.status = "completed"
            _persist_assistant_run(run)
            _publish_run_event(
                run,
                "reply",
                {"text": reply, "route": "blocked", "mode": run.mode, "lane": run.lane, "style": run.style, "blocked": True},
            )
            if run.project_id:
                projects_store.append_project_copilot_history(
                    run.project_id,
                    [
                        {"id": f"u-{run.request_id}", "requestId": run.request_id, "role": "user", "text": prompt},
                        {
                            "id": f"a-{run.request_id}",
                            "requestId": run.request_id,
                            "role": "assistant",
                            "text": reply,
                            "route": "blocked",
                            "mode": run.mode,
                            "lane": run.lane,
                            "style": run.style,
                            "blocked": True,
                        },
                    ],
                    scope_key=run.scope_key,
                )
            return

        async for event in _assistant_agent.stream_answer(
            prompt=prompt,
            project_id=run.project_id or None,
            target=run.target,
            target_type=run.target_type,
            context=live_context,
            saved_context=saved_context,
            history=saved_history,
        ):
            event_type = str(event.get("type", "")).strip()
            event_data = event.get("data", {})
            if not isinstance(event_data, dict):
                event_data = {}
            if event_type == "reply":
                run.reply = str(event_data.get("text", "")).strip()
                run.route = str(event_data.get("route", "assistant") or "assistant").strip() or "assistant"
                run.mode = str(event_data.get("mode", "Ask") or "Ask").strip() or "Ask"
                run.lane = str(event_data.get("lane", "lightweight") or "lightweight").strip() or "lightweight"
                run.style = str(event_data.get("style", "natural") or "natural").strip() or "natural"
                run.blocked = bool(event_data.get("blocked", False))
            elif event_type == "history_compressed":
                # We no longer overwrite the UI history with the compressed version.
                # Instead, we keep the full history and use a rolling summary in the background context.
                pass
            elif event_type == "context":
                run.next_context = str(event_data.get("next_context", "") or "").strip()
            elif event_type == "learning":
                run.learning_signals = event_data if isinstance(event_data, dict) else {}
            elif event_type == "tool_start":
                run.toolLogs.append({
                    "id": event_data.get("call_id"),
                    "tool": event_data.get("tool"),
                    "input": event_data.get("input"),
                    "status": "running"
                })
            elif event_type == "tool_output":
                call_id = event_data.get("call_id")
                for log in run.toolLogs:
                    if log.get("id") == call_id:
                        log["output"] = event_data.get("output")
                        log["status"] = "done"
                        break
            elif event_type == "password_request":
                run.password_requests.append(event_data)

            _publish_run_event(run, event_type, event_data)

        run.status = "completed"
        _persist_assistant_run(run)
        if run.project_id:
            projects_store.append_project_copilot_history(
                run.project_id,
                [
                    {"id": f"u-{run.request_id}", "requestId": run.request_id, "role": "user", "text": prompt},
                    {
                        "id": f"a-{run.request_id}",
                        "requestId": run.request_id,
                        "role": "assistant",
                        "text": run.reply,
                        "route": run.route,
                        "mode": run.mode,
                        "lane": run.lane,
                        "style": run.style,
                        "blocked": run.blocked,
                        "toolLogs": run.toolLogs,
                        "learningSignals": run.learning_signals,
                    },
                ],
                scope_key=run.scope_key,
            )
            projects_store.update_project_copilot_context(
                run.project_id,
                run.next_context,
                scope_key=run.scope_key,
            )

    except asyncio.CancelledError:
        run.status = "cancelled"
        _persist_assistant_run(run)
        _publish_run_event(
            run,
            "error",
            {"detail": "Assistant request was cancelled."},
        )
        raise
    except Exception as exc:
        logger.exception("assistant_stream_failed", request_id=run.request_id)
        run.status = "error"
        _persist_assistant_run(run)
        _publish_run_event(
            run,
            "error",
            {"detail": f"Streaming error: {str(exc)}"},
        )
    finally:
        _executer_callback_context.reset(token)
        run.updated_at = _utc_now_iso()
        _persist_assistant_run(run)


async def _resolve_or_create_run(
    payload: AIAssistPayload,
    *,
    prompt: str,
    scope_key: str,
    guard_context: str,
    live_context: str,
    saved_context: str,
    saved_history: list[dict[str, object]],
) -> AssistantRun:
    requested_id = str(payload.request_id or "").strip()
    scope_run_key = _scope_run_key(payload.project_id, scope_key)

    async with _assistant_runs_lock:
        _prune_finished_runs()

        if requested_id:
            existing = _assistant_runs.get(requested_id)
            if existing is not None:
                return existing
            stored = projects_store.get_task_run(requested_id)
            restored = _restore_assistant_run(stored) if isinstance(stored, dict) else None
            if restored is not None:
                _assistant_runs[requested_id] = restored
                _assistant_scope_index[scope_run_key] = requested_id
                return restored

        run_id = requested_id or str(uuid.uuid4())
        now_iso = _utc_now_iso()
        run = AssistantRun(
            request_id=run_id,
            project_id=str(payload.project_id or "").strip(),
            scope_key=scope_key,
            prompt=prompt,
            target=payload.target,
            target_type=payload.target_type,
            created_at=now_iso,
            updated_at=now_iso,
        )
        _assistant_runs[run_id] = run
        _assistant_scope_index[scope_run_key] = run_id
        _persist_assistant_run(run)
        run.task = asyncio.create_task(
            _execute_assistant_run(
                run,
                prompt=prompt,
                guard_context=guard_context,
                live_context=live_context,
                saved_context=saved_context,
                saved_history=saved_history,
            ),
            name=f"assistant_run_{run_id}",
        )
        return run


async def _subscribe_run_events(run: AssistantRun, request: Request):
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
    backlog = list(run.backlog)
    run.subscribers.add(queue)
    try:
        yield f"event: run\ndata: {json.dumps({'request_id': run.request_id, 'status': run.status})}\n\n"
        for item in backlog:
            yield f"event: {item['type']}\ndata: {json.dumps(item['data'])}\n\n"

        while True:
            if await request.is_disconnected():
                break
            if run.status != "running" and queue.empty():
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=_KEEPALIVE_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                yield f"event: keepalive\ndata: {json.dumps({'timestamp': _utc_now_iso(), 'request_id': run.request_id})}\n\n"
                continue
            yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"
    finally:
        run.subscribers.discard(queue)


@router.post("/api/ai/assist/stream")
async def ai_assist_stream(payload: AIAssistPayload, request: Request) -> StreamingResponse:
    _ensure_llm_profile_configured()
    prompt = payload.prompt.strip()
    request_id = str(payload.request_id or "").strip()
    if not prompt and not request_id:
        raise HTTPException(status_code=400, detail="prompt is required")

    scope_key = normalize_target_scope(payload.target, payload.target_type)
    saved_context, saved_history = await _load_saved_assistant_context(
        project_id=payload.project_id,
        scope_key=scope_key,
    )

    guard_context_parts = [
        f"project_id={payload.project_id or ''}",
        f"target={payload.target}",
        f"target_type={payload.target_type}",
        saved_context,
        payload.context,
    ]
    guard_context = "\n".join(part for part in guard_context_parts if part.strip())
    live_context = str(payload.context or "").strip()

    run = await _resolve_or_create_run(
        payload,
        prompt=prompt,
        scope_key=scope_key,
        guard_context=guard_context,
        live_context=live_context,
        saved_context=saved_context,
        saved_history=saved_history,
    )

    return StreamingResponse(
        _subscribe_run_events(run, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/ai/assist/context-metrics")
async def ai_assist_context_metrics(payload: AIAssistContextMetricsPayload) -> dict[str, Any]:
    scope_key = normalize_target_scope(payload.target, payload.target_type)
    saved_context, saved_history = await _load_saved_assistant_context(
        project_id=payload.project_id,
        scope_key=scope_key,
    )
    saved_context_override = str(payload.saved_context_override or "").strip()
    if saved_context_override:
        saved_context = saved_context_override
    return _assistant_agent.estimate_effective_context_metrics(
        project_id=payload.project_id,
        target=payload.target,
        target_type=payload.target_type,
        prompt=str(payload.prompt or ""),
        context=str(payload.context or "").strip(),
        saved_context=saved_context,
        history=saved_history,
    )


@router.post("/api/ai/assist/{request_id}/cancel")
async def cancel_ai_assist(request_id: str) -> AICancelAssistResponse:
    clean_request_id = str(request_id or "").strip()
    run = _assistant_runs.get(clean_request_id)
    if run is None:
        stored = projects_store.get_task_run(clean_request_id)
        restored = _restore_assistant_run(stored) if isinstance(stored, dict) else None
        if restored is not None:
            _assistant_runs[clean_request_id] = restored
            run = restored
    if run is None:
        raise HTTPException(status_code=404, detail="Assistant request not found")

    if run.task is not None and not run.task.done():
        run.task.cancel()
    run.status = "cancelled"
    run.updated_at = _utc_now_iso()
    _persist_assistant_run(run)
    return AICancelAssistResponse(
        ok=True,
        request_id=run.request_id,
        status=run.status,
    )


class AIAssistInputPayload(BaseModel):
    call_id: str = Field(min_length=1, max_length=200)
    value: str = Field(default="", max_length=1000)
    denied: bool = False


@router.post("/api/ai/assist/{request_id}/input")
async def ai_assist_input(request_id: str, payload: AIAssistInputPayload) -> dict[str, bool]:
    clean_request_id = str(request_id or "").strip()
    run = _assistant_runs.get(clean_request_id)
    if run is None:
        stored = projects_store.get_task_run(clean_request_id)
        restored = _restore_assistant_run(stored) if isinstance(stored, dict) else None
        if restored is not None:
            _assistant_runs[clean_request_id] = restored
            run = restored
    if run is None:
        raise HTTPException(status_code=404, detail="Assistant request not found")

    if not hasattr(run, "callback") or run.callback is None:
         raise HTTPException(status_code=400, detail="No active callback for this run")
         
    callback: AssistantExecuterCallback = run.callback
    waiter = callback.password_waiters.get(payload.call_id)
    if waiter is None or waiter.done():
        raise HTTPException(status_code=400, detail="No active password request for this call_id")

    if payload.denied:
        waiter.set_result(None)
    else:
        waiter.set_result(payload.value)

    return {"ok": True}


class ArchitectSynthesizePayload(BaseModel):
    project_id: str = Field(min_length=1, max_length=200)


@router.post("/api/ai/architect/synthesize")
async def ai_architect_synthesize(payload: ArchitectSynthesizePayload) -> dict[str, Any]:
    _ensure_llm_profile_configured()
    project_id = payload.project_id
    project = projects_store.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    async with _architect_refresh_lock:
        existing_task = _architect_refresh_tasks.get(project_id)
        if existing_task and not existing_task.done():
            return {
                "ok": True,
                "status": "running",
                "already_running": True,
                "architecture_draft": project.get("payload", {}).get("architecture_draft"),
            }

        _set_architect_refresh_state(project, status="running", phase="synthesizing")
        projects_store.upsert_project(project)
        task = asyncio.create_task(
            _run_architect_refresh(project_id),
            name=f"architect_refresh_{project_id}",
        )
        _architect_refresh_tasks[project_id] = task

    return {
        "ok": True,
        "status": "running",
        "started": True,
        "architecture_draft": project.get("payload", {}).get("architecture_draft"),
    }


@router.post("/api/ai/assist")
async def ai_assist(payload: AIAssistPayload) -> dict[str, object]:
    _ensure_llm_profile_configured()
    prompt = payload.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")
    turn_id = str(payload.request_id or "").strip() or str(uuid.uuid4())

    scope_key = normalize_target_scope(payload.target, payload.target_type)
    saved_context = ""
    saved_history: list[dict[str, object]] = []
    if payload.project_id:
        project = projects_store.get_project(payload.project_id)
        if isinstance(project, dict):
            if str(project.get("copilotContextScope", "")).strip() == scope_key:
                saved_context = str(project.get("copilotContext", "") or "").strip()
            raw_history = project.get("copilotHistory", [])
            if (
                str(project.get("copilotHistoryScope", "")).strip() == scope_key
                and isinstance(raw_history, list)
            ):
                saved_history = [
                    item for item in raw_history
                    if isinstance(item, dict)
                ]

    guard_context_parts = [
        f"project_id={payload.project_id or ''}",
        f"target={payload.target}",
        f"target_type={payload.target_type}",
        saved_context,
        payload.context,
    ]
    guard_context = "\n".join(part for part in guard_context_parts if part.strip())
    live_context = str(payload.context or "").strip()

    decision = await _prompt_guard.classify_user_prompt(
        prompt,
        context=guard_context,
        use_llm=True,
    )

    if decision.is_injection:
        reply = (
            "Potential prompt-injection detected. "
            f"Request blocked by safety guard. Reason: {decision.reason}"
        )
        if payload.project_id:
            projects_store.append_project_copilot_history(
                payload.project_id,
                [
                    {"id": f"u-{turn_id}", "requestId": turn_id, "role": "user", "text": prompt},
                    {
                        "id": f"a-{turn_id}",
                        "requestId": turn_id,
                        "role": "assistant",
                        "text": reply,
                        "route": "blocked",
                        "mode": "Ask",
                        "lane": "lightweight",
                        "style": "natural",
                        "blocked": True,
                    },
                ],
                scope_key=scope_key,
            )
        return {
            "ok": True,
            "blocked": True,
            "route": "blocked",
            "mode": "Ask",
            "lane": "lightweight",
            "style": "natural",
            "reply": reply,
            "classification": {
                "reason": decision.reason,
                "confidence": decision.confidence,
                "classifier": decision.classifier,
                "detections": decision.detections,
            },
        }

    try:
        result = await _assistant_agent.answer(
            prompt=prompt,
            project_id=payload.project_id,
            target=payload.target,
            target_type=payload.target_type,
            context=live_context,
            saved_context=saved_context,
            history=saved_history,
        )
    except Exception as exc:
        logger.exception("assistant_ai_assist_failed")
        reply = f"I couldn't complete that assistant request cleanly. Backend error: {str(exc).strip() or type(exc).__name__}"
        return {
            "ok": True,
            "blocked": False,
            "route": "assistant",
            "mode": "Ask",
            "lane": "lightweight",
            "style": "natural",
            "reply": reply,
            "classification": {
                "reason": decision.reason,
                "confidence": decision.confidence,
                "classifier": decision.classifier,
                "detections": decision.detections,
            },
        }

    if payload.project_id:
        projects_store.append_project_copilot_history(
            payload.project_id,
            [
                {"id": f"u-{turn_id}", "requestId": turn_id, "role": "user", "text": prompt},
                {
                    "id": f"a-{turn_id}",
                    "requestId": turn_id,
                    "role": "assistant",
                    "text": result.reply,
                    "route": "assistant",
                    "mode": result.mode,
                    "lane": result.lane,
                    "style": result.style,
                    "blocked": False,
                    "learningSignals": result.learning_signals,
                },
            ],
            scope_key=scope_key,
        )
        projects_store.update_project_copilot_context(
            payload.project_id,
            result.next_context,
            scope_key=scope_key,
        )

    return {
        "ok": True,
        "blocked": False,
        "route": "assistant",
        "mode": result.mode,
        "lane": result.lane,
        "style": result.style,
        "reply": result.reply,
        "next_context": result.next_context,
        "learning_signals": result.learning_signals,
        "classification": {
            "reason": decision.reason,
            "confidence": decision.confidence,
            "classifier": decision.classifier,
            "detections": decision.detections,
        },
    }


class AICompressPayload(BaseModel):
    history: list[dict[str, Any]] = Field(default_factory=list)
    context: str = ""


@router.post("/api/ai/assist/compress")
async def ai_compress_history(payload: AICompressPayload) -> dict[str, str]:
    _ensure_llm_profile_configured()
    if str(payload.context or "").strip():
        context = await _assistant_agent.compress_working_memory(payload.context)
        return {"context": context}
    summary = await _assistant_agent.compress_history(payload.history)
    return {"summary": summary}


@router.post("/api/ai/clear-conversation")
async def clear_ai_conversation(payload: AIClearConversationPayload) -> dict[str, object]:
    scope_key = normalize_target_scope(payload.target, payload.target_type)
    project = projects_store.get_project(payload.project_id)
    if not isinstance(project, dict):
        raise HTTPException(status_code=404, detail="project not found")

    projects_store.clear_project_copilot_state(
        payload.project_id,
        scope_key=scope_key,
    )
    return {
        "ok": True,
        "project_id": payload.project_id,
        "scope_key": scope_key,
        "cleared": True,
    }
