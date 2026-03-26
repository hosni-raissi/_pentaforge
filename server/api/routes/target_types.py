"""Target-type metadata routes for project creation forms."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from server.constants.target_types import (
    TARGET_TYPES,
    get_target_schema_fields,
    get_target_type_options,
)

router = APIRouter(tags=["project-metadata"])


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

