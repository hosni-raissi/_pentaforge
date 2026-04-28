"""Target-type metadata routes for project creation forms."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from server.api.dependencies import projects_store
from server.app.orchestrator import _build_default_target_info_profile, _resolve_target_info_profile
from server.constants.target_types import (
    TARGET_TYPES,
    get_target_schema_fields,
    get_target_type_options,
)

router = APIRouter(tags=["project-metadata"])


class TargetInfoProfilePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    target_type: str
    version: str = Field(default="1.0")
    generated_from: str = Field(default="ui")
    max_blocks: int = Field(default=4, ge=1, le=50)
    blocks: list[dict[str, Any]] = Field(default_factory=list)


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


@router.get("/api/project-target-types/information-gathering-profiles")
def list_information_gathering_profiles() -> dict[str, list[dict[str, Any]]]:
    profiles_by_target_type: list[dict[str, Any]] = []
    for target_type in TARGET_TYPES:
        profile = _resolve_target_info_profile(projects_store, target_type)
        profiles_by_target_type.append(profile)
    return {"profiles": profiles_by_target_type}


@router.get("/api/project-target-types/{target_type}/information-gathering-profile")
def get_information_gathering_profile(target_type: str) -> dict[str, Any]:
    if target_type not in TARGET_TYPES:
        raise HTTPException(status_code=404, detail=f"Unknown target type: {target_type}")
    profile = _resolve_target_info_profile(projects_store, target_type)
    return {"profile": profile}


@router.put("/api/project-target-types/{target_type}/information-gathering-profile")
def update_information_gathering_profile(
    target_type: str,
    payload: TargetInfoProfilePayload,
) -> dict[str, Any]:
    if target_type not in TARGET_TYPES:
        raise HTTPException(status_code=404, detail=f"Unknown target type: {target_type}")
    body = payload.model_dump(mode="json")
    body["target_type"] = target_type
    body["max_blocks"] = len(body.get("blocks", []))
    try:
        saved = projects_store.upsert_target_info_profile(
            target_type=target_type,
            payload=body,
        )
        projects_store.delete_static_recon_plan(target_type)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save information gathering profile: {exc}") from exc
    return {"ok": True, "profile": saved}


@router.delete("/api/project-target-types/{target_type}/information-gathering-profile")
def reset_information_gathering_profile(target_type: str) -> dict[str, Any]:
    if target_type not in TARGET_TYPES:
        raise HTTPException(status_code=404, detail=f"Unknown target type: {target_type}")
    try:
        projects_store.delete_static_recon_plan(target_type)
        projects_store.delete_target_info_profile(target_type)
        restored = projects_store.upsert_target_info_profile(
            target_type=target_type,
            payload=_build_default_target_info_profile(target_type),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to reset information gathering profile: {exc}") from exc
    return {"ok": True, "profile": restored}
