"""Frontend AI assist routes (non-scan interaction path)."""

from __future__ import annotations

import structlog
from fastapi import APIRouter, HTTPException
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


class AIAssistPayload(BaseModel):
    prompt: str = Field(min_length=1, max_length=_MAX_PROMPT_LEN)
    project_id: str | None = Field(default=None, max_length=200)
    target: str = Field(default="", max_length=2048)
    target_type: str = Field(default="", max_length=120)
    context: str = Field(default="", max_length=12000)


class AIClearConversationPayload(BaseModel):
    project_id: str = Field(min_length=1, max_length=200)
    target: str = Field(default="", max_length=2048)
    target_type: str = Field(default="", max_length=120)

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
                    {
                        "role": "user",
                        "text": prompt,
                    },
                    {
                        "role": "assistant",
                        "text": reply,
                        "route": "blocked",
                        "blocked": True,
                    },
                ],
                scope_key=scope_key,
            )
        return {
            "ok": True,
            "blocked": True,
            "route": "blocked",
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
        logger.exception(
            "assistant_ai_assist_failed",
            project_id=payload.project_id,
            target=payload.target,
            target_type=payload.target_type,
        )
        reply = (
            "I couldn't complete that assistant request cleanly. "
            f"Backend error: {str(exc).strip() or type(exc).__name__}"
        )
        if payload.project_id:
            projects_store.append_project_copilot_history(
                payload.project_id,
                [
                    {
                        "role": "user",
                        "text": prompt,
                    },
                    {
                        "role": "assistant",
                        "text": reply,
                        "route": "assistant",
                        "blocked": False,
                    },
                ],
                scope_key=scope_key,
            )
            projects_store.update_project_copilot_context(
                payload.project_id,
                saved_context,
                scope_key=scope_key,
            )
        return {
            "ok": True,
            "blocked": False,
            "route": "assistant",
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
                {
                    "role": "user",
                    "text": prompt,
                },
                {
                    "role": "assistant",
                    "text": result.reply,
                    "route": "assistant",
                    "blocked": False,
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
        "reply": result.reply,
        "next_context": result.next_context,
        "classification": {
            "reason": decision.reason,
            "confidence": decision.confidence,
            "classifier": decision.classifier,
            "detections": decision.detections,
        },
    }


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
