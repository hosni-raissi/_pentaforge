"""Frontend AI assist routes (non-scan interaction path)."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from server.agents.assistant import AssistantAgent
from server.api.dependencies import projects_store
from server.layers.safety.prompt_guard import PromptInjectionGuard
from server.utils.target_scope import normalize_target_scope

router = APIRouter(tags=["ai"])

_prompt_guard = PromptInjectionGuard()
_assistant_agent = AssistantAgent()
_MAX_PROMPT_LEN = 8000
logger = structlog.get_logger(__name__)
_ASSISTANT_RUN_TTL_SECONDS = 60 * 60
_KEEPALIVE_INTERVAL_SECONDS = 15.0


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
    context: str,
    saved_context: str,
    saved_history: list[dict[str, object]],
) -> None:
    from server.agents.executer.base import _executer_callback_context
    
    loop = asyncio.get_running_loop()
    callback = AssistantExecuterCallback(run, loop)
    run.callback = callback
    token = _executer_callback_context.set(callback)
    
    try:
        decision = await _prompt_guard.classify_user_prompt(
            prompt,
            context=context,
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
                        {"role": "user", "text": prompt},
                        {"role": "assistant", "text": reply, "route": "blocked", "mode": run.mode, "lane": run.lane, "style": run.style, "blocked": True},
                    ],
                    scope_key=run.scope_key,
                )
            return

        async for event in _assistant_agent.stream_answer(
            prompt=prompt,
            project_id=run.project_id or None,
            target=run.target,
            target_type=run.target_type,
            context=context,
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
                    {"role": "user", "text": prompt},
                    {
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
    context: str,
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
                context=context,
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
    prompt = payload.prompt.strip()
    request_id = str(payload.request_id or "").strip()
    if not prompt and not request_id:
        raise HTTPException(status_code=400, detail="prompt is required")

    scope_key = normalize_target_scope(payload.target, payload.target_type)
    saved_context, saved_history = await _load_saved_assistant_context(
        project_id=payload.project_id,
        scope_key=scope_key,
    )

    context_parts = [
        f"project_id={payload.project_id or ''}",
        f"target={payload.target}",
        f"target_type={payload.target_type}",
        saved_context,
        payload.context,
    ]
    context = "\n".join(part for part in context_parts if part.strip())

    run = await _resolve_or_create_run(
        payload,
        prompt=prompt,
        scope_key=scope_key,
        context=context,
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

    # Find the callback task from the running run
    # This is a bit hacky because we don't store the callback on the run object directly
    # but we can look it up if we modify AssistantRun or use a global registry.
    # Let's add 'callback' to AssistantRun.
    
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

@router.post("/api/ai/assist")
async def ai_assist(payload: AIAssistPayload) -> dict[str, object]:
    prompt = payload.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")

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

    context_parts = [
        f"project_id={payload.project_id or ''}",
        f"target={payload.target}",
        f"target_type={payload.target_type}",
        saved_context,
        payload.context,
    ]
    context = "\n".join(part for part in context_parts if part.strip())

    decision = await _prompt_guard.classify_user_prompt(
        prompt,
        context=context,
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
                    {"role": "user", "text": prompt},
                    {"role": "assistant", "text": reply, "route": "blocked", "mode": "Ask", "lane": "lightweight", "style": "natural", "blocked": True},
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
            context=context,
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
                {"role": "user", "text": prompt},
                {
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


@router.post("/api/ai/assist/compress")
async def ai_compress_history(payload: AICompressPayload) -> dict[str, str]:
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
