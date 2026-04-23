"""Target-type metadata routes for project creation forms."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from server.api.dependencies import projects_store
from server.app.orchestrator import _build_static_recon_plan, _resolve_static_recon_plan
from server.constants.target_types import (
    TARGET_TYPES,
    get_target_schema_fields,
    get_target_type_options,
)

router = APIRouter(tags=["project-metadata"])


class StaticReconPlanPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    target_type: str
    max_items: int = Field(default=20, ge=1, le=50)
    generated_from: str = Field(default="ui")
    scenarios: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/api/project-target-types")
def list_project_target_types() -> dict[str, list[dict[str, str]]]:
    return {"target_types": get_target_type_options()}


@router.get("/api/project-target-types/{target_type}/fields")
def list_project_target_fields(
    target_type: str,
    required_only: bool = False,
) -> dict[str, Any]:
    if target_type not in TARGET_TYPES:
        raise HTTPException(status_code=404, detail=f"Unknown target type: {target_type}")
    return {
        "target_type": target_type,
        "fields": get_target_schema_fields(target_type, required_only=required_only),
    }


@router.get("/api/project-target-types/static-recon-plans")
def list_static_recon_plans() -> dict[str, list[dict[str, Any]]]:
    plans_by_target_type: list[dict[str, Any]] = []
    for target_type in TARGET_TYPES:
        plan = _resolve_static_recon_plan(projects_store, target_type)
        plans_by_target_type.append(plan)
    return {"plans": plans_by_target_type}


@router.get("/api/project-target-types/{target_type}/static-recon-plan")
def get_static_recon_plan(target_type: str) -> dict[str, Any]:
    if target_type not in TARGET_TYPES:
        raise HTTPException(status_code=404, detail=f"Unknown target type: {target_type}")
    plan = _resolve_static_recon_plan(projects_store, target_type)
    return {"plan": plan}


@router.put("/api/project-target-types/{target_type}/static-recon-plan")
def update_static_recon_plan(
    target_type: str,
    payload: StaticReconPlanPayload,
) -> dict[str, Any]:
    if target_type not in TARGET_TYPES:
        raise HTTPException(status_code=404, detail=f"Unknown target type: {target_type}")
    body = payload.model_dump(mode="json")
    body["target_type"] = target_type
    try:
        saved = projects_store.upsert_static_recon_plan(
            target_type=target_type,
            payload=body,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save static recon plan: {exc}") from exc
    return {"ok": True, "plan": saved}


@router.delete("/api/project-target-types/{target_type}/static-recon-plan")
def reset_static_recon_plan(target_type: str) -> dict[str, Any]:
    if target_type not in TARGET_TYPES:
        raise HTTPException(status_code=404, detail=f"Unknown target type: {target_type}")
    try:
        projects_store.delete_static_recon_plan(target_type)
        restored = projects_store.upsert_static_recon_plan(
            target_type=target_type,
            payload=_build_static_recon_plan(target_type),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to reset static recon plan: {exc}") from exc
    return {"ok": True, "plan": restored}
