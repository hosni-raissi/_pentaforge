"""Project CRUD routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from server.api.dependencies import projects_store

router = APIRouter(tags=["projects"])


class ProjectPayload(BaseModel):
    """Loose project payload to match current UI shape."""

    model_config = ConfigDict(extra="allow")
    id: str


@router.get("/api/projects")
def list_projects() -> dict[str, list[dict[str, Any]]]:
    try:
        return {"projects": projects_store.list_projects()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list projects: {exc}") from exc


@router.post("/api/projects")
def upsert_project(project: ProjectPayload) -> dict[str, Any]:
    payload = project.model_dump(mode="json")
    try:
        projects_store.upsert_project(payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save project: {exc}") from exc
    return {"ok": True, "id": payload["id"]}


@router.delete("/api/projects/{project_id}")
def delete_project(project_id: str) -> dict[str, Any]:
    try:
        projects_store.delete_project(project_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete project: {exc}") from exc
    return {"ok": True, "id": project_id}

