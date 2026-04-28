"""Project CRUD routes."""

from __future__ import annotations

import json
import shutil
from typing import Any
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from server.api.dependencies import projects_store

router = APIRouter(tags=["projects"])


class ProjectPayload(BaseModel):
    """Loose project payload to match current UI shape."""

    model_config = ConfigDict(extra="allow")
    id: str


def _cache_root() -> Path:
    return (Path(__file__).resolve().parents[2] / "cache").resolve()


def _delete_project_cache_artifacts(project_id: str) -> dict[str, int]:
    safe_project_id = str(project_id or "").strip()
    if not safe_project_id:
        return {"project_runs_removed": 0, "project_findings_removed": 0}

    cache_root = _cache_root()
    project_runs_root = cache_root / "project_runs"
    project_findings_root = cache_root / "project_findings"
    project_runs_removed = 0
    project_findings_removed = 0

    findings_path = project_findings_root / f"{safe_project_id}.json"
    if findings_path.exists():
        findings_path.unlink()
        project_findings_removed += 1

    if project_runs_root.exists():
        for run_dir in project_runs_root.iterdir():
            if not run_dir.is_dir():
                continue
            memory_json = run_dir / "system_memory" / "memory.json"
            if not memory_json.exists():
                continue
            try:
                payload = json.loads(memory_json.read_text(encoding="utf-8"))
            except Exception:
                continue
            overview = payload.get("overview", {}) if isinstance(payload, dict) else {}
            if str(overview.get("project_id", "")).strip() != safe_project_id:
                continue
            shutil.rmtree(run_dir, ignore_errors=True)
            project_runs_removed += 1

    return {
        "project_runs_removed": project_runs_removed,
        "project_findings_removed": project_findings_removed,
    }


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
        deleted_cache = _delete_project_cache_artifacts(project_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete project: {exc}") from exc
    return {"ok": True, "id": project_id, **deleted_cache}
