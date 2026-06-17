"""Project CRUD routes."""

from __future__ import annotations

import json
import os
import shutil
import re
from typing import Any
from pathlib import Path
from datetime import datetime, timezone

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict

from server.api.dependencies import projects_store
from server.agents.assistant.tools.mark_false_positive import mark_false_positive as mark_project_finding_false_positive
from server.agents.executor.sandbox import delete_project_workspace
from server.db.projects.config import projects_db_config

router = APIRouter(tags=["projects"])


class ProjectPayload(BaseModel):
    """Loose project payload to match current UI shape."""

    model_config = ConfigDict(extra="allow")
    id: str


class FalsePositivePayload(BaseModel):
    finding_id: str
    reason: str | None = None


def _cache_root() -> Path:
    return (Path(__file__).resolve().parents[2] / "cache").resolve()


def _projects_artifacts_root() -> Path:
    db_path = Path(projects_db_config.projects_db_path).expanduser().resolve()
    return db_path.parent / "artifacts"


def _sanitize_artifact_name(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    return clean.strip("._") or "artifact"


def _delete_project_uploaded_artifacts(project_id: str) -> dict[str, int]:
    safe_project_id = str(project_id or "").strip()
    if not safe_project_id:
        return {"uploaded_artifacts_removed": 0}
    project_root = _projects_artifacts_root() / safe_project_id
    if not project_root.exists():
        return {"uploaded_artifacts_removed": 0}
    count = sum(1 for path in project_root.rglob("*") if path.is_file())
    shutil.rmtree(project_root, ignore_errors=True)
    return {"uploaded_artifacts_removed": count}


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


def _delete_project_runtime_artifacts(project_id: str, project_payload: dict[str, Any] | None = None) -> dict[str, int]:
    deleted_cache = _delete_project_cache_artifacts(project_id)
    deleted_sandbox = delete_project_workspace(project_id, project_payload=project_payload)
    return {
        **deleted_cache,
        **deleted_sandbox,
    }


def _normalize_architecture_refresh_state(project: dict[str, Any]) -> bool:
    payload = project.get("payload")
    if not isinstance(payload, dict):
        return False

    refresh = payload.get("architecture_refresh")
    if not isinstance(refresh, dict):
        return False

    status = str(refresh.get("status", "")).strip().lower()
    if status != "running":
        return False

    owner_pid = refresh.get("owner_pid")
    current_pid = os.getpid()
    if isinstance(owner_pid, int) and owner_pid == current_pid:
        return False

    now_iso = datetime.now(timezone.utc).isoformat()
    payload["architecture_refresh"] = {
        **refresh,
        "status": "error",
        "phase": "server_stopped",
        "error": "Architecture refresh stopped because the previous server process ended.",
        "updated_at": now_iso,
        "completed_at": now_iso,
    }
    return True


@router.get("/api/projects")
def list_projects() -> dict[str, list[dict[str, Any]]]:
    try:
        projects = projects_store.list_projects()
        dirty = False
        for project in projects:
            if isinstance(project, dict) and _normalize_architecture_refresh_state(project):
                projects_store.upsert_project(project)
                dirty = True
        if dirty:
            projects = projects_store.list_projects()
        return {"projects": projects}
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
        project = projects_store.get_project(project_id)
        projects_store.delete_project(project_id)
        deleted_cache = _delete_project_runtime_artifacts(
            project_id,
            project_payload=project if isinstance(project, dict) else None,
        )
        deleted_uploads = _delete_project_uploaded_artifacts(project_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete project: {exc}") from exc
    return {
        "ok": True,
        "id": project_id,
        **deleted_cache,
        **deleted_uploads,
    }


@router.post("/api/projects/{project_id}/reset-runtime")
def reset_project_runtime(project_id: str) -> dict[str, Any]:
    try:
        project = projects_store.reset_project_runtime_state(project_id)
        deleted_cache = _delete_project_runtime_artifacts(project_id, project_payload=project)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to reset project runtime: {exc}") from exc
    return {
        "ok": True,
        "project": project,
        "id": project_id,
        **deleted_cache,
    }


@router.get("/api/projects/{project_id}/runs/active")
def get_active_project_runs(project_id: str) -> dict[str, Any]:
    try:
        project = projects_store.get_project(project_id)
        if not isinstance(project, dict):
            raise HTTPException(status_code=404, detail="Project not found")
        if _normalize_architecture_refresh_state(project):
            projects_store.upsert_project(project)

        runs = projects_store.list_active_task_runs(project_id)
        last_scan = project.get("lastScan", {})
        if not isinstance(last_scan, dict):
            last_scan = {}
        scan_status = str(last_scan.get("status", "")).strip().lower()
        scan_run: dict[str, Any] | None = None
        if scan_status in {"pending", "running", "paused"}:
            scan_run = {
                "run_id": str(last_scan.get("scanId", "")).strip(),
                "task_type": "scan",
                "status": scan_status,
                "scope_key": "",
                "created_at": str(last_scan.get("startedAt", "")).strip(),
                "updated_at": str(project.get("updatedAt", "")).strip(),
                "payload": last_scan,
            }
        return {
            "ok": True,
            "project_id": project_id,
            "runs": runs,
            "scan": scan_run,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read active runs: {exc}") from exc


@router.post("/api/projects/{project_id}/findings/mark-false-positive")
async def mark_finding_false_positive(
    project_id: str,
    payload: FalsePositivePayload,
) -> dict[str, Any]:
    try:
        result = await mark_project_finding_false_positive(
            project_id=project_id,
            finding_id=payload.finding_id,
            reason=payload.reason or "Operator marked as false positive from dashboard.",
            project_store=projects_store,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to mark finding as false positive: {exc}") from exc

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=str(result.get("error") or "Unable to mark finding as false positive"))
    return {"ok": True, **result}


@router.post("/api/projects/{project_id}/artifacts/mobile-upload")
async def upload_mobile_artifact(
    project_id: str,
    file: UploadFile = File(...),
    target_type: str = Form(default="mobile"),
) -> dict[str, Any]:
    safe_project_id = str(project_id or "").strip()
    if not safe_project_id:
        raise HTTPException(status_code=400, detail="Project id is required.")

    if str(target_type or "").strip().lower() != "mobile":
        raise HTTPException(status_code=400, detail="This upload route only accepts mobile project artifacts.")

    original_name = str(file.filename or "").strip()
    if not original_name:
        raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

    extension = Path(original_name).suffix.lower()
    if extension not in {".apk", ".aab", ".ipa"}:
        raise HTTPException(status_code=400, detail="Only .apk, .aab, and .ipa mobile artifacts are supported.")

    safe_name = _sanitize_artifact_name(Path(original_name).name)
    destination_dir = _projects_artifacts_root() / safe_project_id / "mobile"
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination_path = destination_dir / safe_name

    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        destination_path.write_bytes(content)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store uploaded artifact: {exc}") from exc

    return {
        "ok": True,
        "project_id": safe_project_id,
        "filename": safe_name,
        "path": str(destination_path),
        "size": destination_path.stat().st_size,
        "content_type": str(file.content_type or ""),
    }


class RepoClonePayload(BaseModel):
    repo_url: str
    branch: str | None = None
    auth_token: str | None = None


@router.post("/api/projects/{project_id}/artifacts/repo-clone")
def clone_repo_artifact(project_id: str, payload: RepoClonePayload) -> dict[str, Any]:
    import subprocess
    safe_project_id = str(project_id or "").strip()
    if not safe_project_id:
        raise HTTPException(status_code=400, detail="Project id is required.")

    destination_dir = _projects_artifacts_root() / safe_project_id / "repository"
    shutil.rmtree(destination_dir, ignore_errors=True)
    destination_dir.mkdir(parents=True, exist_ok=True)
    
    repo_url = payload.repo_url.strip()
    if payload.auth_token:
        if repo_url.startswith("https://"):
            repo_url = repo_url.replace("https://", f"https://oauth2:{payload.auth_token}@")
            
    cmd = ["git", "clone", "--depth", "1"]
    if payload.branch:
        cmd.extend(["-b", payload.branch.strip()])
    cmd.extend([repo_url, str(destination_dir)])
    
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to clone repository: {e.stderr}")
        
    return {
        "ok": True,
        "project_id": safe_project_id,
        "path": str(destination_dir),
    }

