"""Scan orchestration routes."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from server.api.dependencies import scan_orchestrator

router = APIRouter(tags=["scans"])


class StartScanPayload(BaseModel):
    project_id: str = Field(min_length=1, max_length=200)
    target: str | None = Field(default=None, max_length=2048)
    target_config: dict[str, Any] | None = None
    scope: str = Field(default="", max_length=4000)
    info: str = Field(default="", max_length=8000)
    resume: bool = False
    force: bool = False


class StopScanPayload(BaseModel):
    project_id: str = Field(min_length=1, max_length=200)
    mode: str = Field(default="pause", max_length=20)


class ApproveToolPayload(BaseModel):
    approval_id: str = Field(min_length=1, max_length=200)
    action: str = Field(default="approve", max_length=20)


class PasswordResponsePayload(BaseModel):
    password_id: str = Field(min_length=1, max_length=200)
    password: str = Field(max_length=512)
    approved: bool = Field(default=True)


class ApproveInformationGatheringPayload(BaseModel):
    modified_program: list[dict[str, Any]] | None = None


def _sse_message(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=True)}\n\n"


@router.post("/api/scans/start")
async def start_scan(payload: StartScanPayload) -> dict[str, Any]:
    try:
        result = await scan_orchestrator.start_scan(
            payload.project_id,
            target=payload.target or "",
            target_config=payload.target_config,
            scope=payload.scope,
            info=payload.info,
            resume=payload.resume,
            force=payload.force,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {exc}") from exc

    return {
        "ok": True,
        **result,
    }


@router.post("/api/scans/stop")
async def stop_scan(payload: StopScanPayload) -> dict[str, Any]:
    try:
        result = await scan_orchestrator.stop_scan(payload.project_id, mode=payload.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to stop scan: {exc}") from exc

    return result


@router.post("/api/scans/{project_id}/approve-planner")
async def approve_planner(project_id: str) -> dict[str, Any]:
    try:
        result = await scan_orchestrator.approve_planner(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to approve planner: {exc}") from exc

    return result


@router.post("/api/scans/{project_id}/approve-information-gathering")
async def approve_information_gathering(project_id: str, payload: ApproveInformationGatheringPayload | None = None) -> dict[str, Any]:
    try:
        modified_program = payload.modified_program if payload else None
        result = await scan_orchestrator.approve_information_gathering(project_id, modified_program=modified_program)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to approve information gathering: {exc}") from exc

    return result


@router.post("/api/scans/{project_id}/approve-tool")
async def approve_tool(project_id: str, payload: ApproveToolPayload) -> dict[str, Any]:
    try:
        result = await scan_orchestrator.approve_executer_tool(
            project_id,
            approval_id=payload.approval_id,
            action=payload.action,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to approve tool: {exc}") from exc

    return result


@router.post("/api/scans/{project_id}/password-response")
async def approve_password(project_id: str, payload: PasswordResponsePayload) -> dict[str, Any]:
    try:
        result = await scan_orchestrator.approve_executer_password(
            project_id,
            password_id=payload.password_id,
            password=payload.password,
            approved=payload.approved,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to handle password response: {exc}") from exc

    return result


@router.get("/api/scans/{project_id}/events")
async def stream_scan_events(project_id: str, request: Request) -> StreamingResponse:
    try:
        queue = scan_orchestrator.subscribe_events(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to open scan stream: {exc}") from exc

    async def _event_stream():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    keepalive = {"timestamp": datetime.now(timezone.utc).isoformat()}
                    yield _sse_message("keepalive", keepalive)
                    continue
                yield _sse_message("scan_event", payload)
        finally:
            scan_orchestrator.unsubscribe_events(project_id, queue)

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/api/scans/{project_id}")
async def get_scan_status(project_id: str) -> dict[str, Any]:
    try:
        result = scan_orchestrator.get_scan_status(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read scan status: {exc}") from exc

    return {
        "ok": True,
        **result,
    }


@router.post("/api/scans/{project_id}/events/clear")
async def clear_scan_events(project_id: str) -> dict[str, Any]:
    try:
        cleared = scan_orchestrator.clear_event_cache(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to clear scan event cache: {exc}") from exc

    return {
        "ok": True,
        "project_id": project_id,
        "cleared": cleared,
    }


@router.get("/api/scans/{project_id}/events/recent")
async def list_scan_events(
    project_id: str,
    limit: int = Query(default=180, ge=1, le=2000),
) -> dict[str, Any]:
    try:
        events = scan_orchestrator.list_event_cache(project_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read scan events: {exc}") from exc

    return {
        "ok": True,
        "project_id": project_id,
        "events": events,
    }


@router.get("/api/scans/{project_id}/observability")
async def get_scan_observability(
    project_id: str,
    limit: int = Query(default=120, ge=10, le=500),
    scan_id: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        snapshot = scan_orchestrator.get_scan_observability(
            project_id,
            scan_id=scan_id,
            limit=limit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to build scan observability snapshot: {exc}") from exc

    return {
        "ok": True,
        "project_id": project_id,
        "scan_id": scan_id or "",
        **snapshot,
    }
