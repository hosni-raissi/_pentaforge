"""Frontend AI assist routes (non-scan interaction path)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from server.layers.safety.prompt_guard import PromptInjectionGuard

router = APIRouter(tags=["ai"])

_prompt_guard = PromptInjectionGuard()
_MAX_PROMPT_LEN = 8000


class AIAssistPayload(BaseModel):
    prompt: str = Field(min_length=1, max_length=_MAX_PROMPT_LEN)
    project_id: str | None = Field(default=None, max_length=200)
    target: str = Field(default="", max_length=2048)
    target_type: str = Field(default="", max_length=120)
    context: str = Field(default="", max_length=12000)


def _build_assistant_reply(
    *,
    route: Literal["planner", "reporting", "blocked"],
    blocked: bool,
    reason: str,
    prompt: str,
) -> str:
    if blocked or route == "blocked":
        return (
            "Potential prompt-injection detected. "
            f"Request blocked by safety guard. Reason: {reason}"
        )

    if route == "planner":
        return (
            "Planner route selected. I can help transform this into actionable "
            "scan tasks, ordered by priority and safety constraints."
        )

    prompt_preview = " ".join(prompt.split())[:120]
    return (
        "Reporting route selected. I can answer questions, summarize status, "
        "and draft client-facing explanations.\n"
        f"Prompt focus: {prompt_preview}"
    )


@router.post("/api/ai/assist")
async def ai_assist(payload: AIAssistPayload) -> dict[str, object]:
    prompt = payload.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")

    context_parts = [
        f"project_id={payload.project_id or ''}",
        f"target={payload.target}",
        f"target_type={payload.target_type}",
        payload.context,
    ]
    context = "\n".join(part for part in context_parts if part.strip())

    decision = await _prompt_guard.classify_user_prompt(
        prompt,
        context=context,
        use_llm=True,
    )

    reply = _build_assistant_reply(
        route=decision.route,
        blocked=decision.is_injection,
        reason=decision.reason,
        prompt=prompt,
    )

    return {
        "ok": True,
        "blocked": decision.is_injection,
        "route": decision.route,
        "reply": reply,
        "classification": {
            "reason": decision.reason,
            "confidence": decision.confidence,
            "classifier": decision.classifier,
            "detections": decision.detections,
        },
    }
