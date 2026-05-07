from __future__ import annotations

import structlog
from typing import Any, Dict
from datetime import datetime, timezone
from server.db.projects import ProjectsStore

logger = structlog.get_logger(__name__)

from .utils import _utc_now_iso

class ScanPersistenceService:
    """Encapsulates all project storage and in-memory scan state synchronization."""

    def __init__(self, projects_store: ProjectsStore):
        self._store = projects_store
        self._runs: Dict[str, Dict[str, Any]] = {}

    def get_project(self, project_id: str) -> Dict[str, Any] | None:
        return self._store.get_project(project_id)

    def upsert_project(self, project: Dict[str, Any]) -> None:
        self._store.upsert_project(project)

    def get_run_state(self, project_id: str) -> Dict[str, Any] | None:
        return self._runs.get(project_id)

    def set_run_state(self, project_id: str, state: Dict[str, Any]) -> None:
        state["updated_at"] = _utc_now_iso()
        self._runs[project_id] = state

    def pop_run_state(self, project_id: str) -> Dict[str, Any] | None:
        return self._runs.pop(project_id, None)

    def update_project_status(
        self, 
        project_id: str, 
        status: str, 
        progress: int | None = None, 
        meta: Dict[str, Any] | None = None
    ) -> None:
        project = self.get_project(project_id)
        if not project:
            return

        project["status"] = status
        if progress is not None:
            project["scanProgress"] = progress
        
        now = _utc_now_iso()
        project["updatedAt"] = now
        
        if meta:
            last_scan = project.get("lastScan", {})
            if not isinstance(last_scan, dict):
                last_scan = {}
            last_scan.update(meta)
            project["lastScan"] = last_scan

        self.upsert_project(project)
        
        # Sync to run_state if it exists
        run_state = self.get_run_state(project_id)
        if isinstance(run_state, dict):
            run_state["status"] = status
            if progress is not None:
                run_state["progress"] = progress
            run_state["updated_at"] = now
            self.set_run_state(project_id, run_state)

    def get_approval_mode(self, project_id: str) -> str:
        project = self.get_project(project_id)
        if not project:
            return "custom"
        return str(project.get("approval_mode") or "custom").lower().strip()

    def get_scan_status(self, project_id: str) -> Dict[str, Any]:
        project_key = str(project_id or "").strip()
        run = self.get_run_state(project_key)
        if run:
            return dict(run)

        project = self.get_project(project_key)
        if not project:
            return {"status": "idle", "error": "Project not found"}

        last_scan = project.get("lastScan")
        if not isinstance(last_scan, dict):
            last_scan = {}

        return {
            "scan_id": str(last_scan.get("scanId", "")),
            "project_id": project_key,
            "status": str(project.get("status", "idle")),
            "started_at": last_scan.get("startedAt"),
            "updated_at": str(project.get("updatedAt", "")) or None,
            "finished_at": last_scan.get("finishedAt"),
            "error": str(last_scan.get("error", "")),
            "awaiting_information_gathering_approval": bool(last_scan.get("awaitingInformationGatheringApproval")),
            "awaiting_planner_approval": bool(last_scan.get("awaitingPlannerApproval")),
            "awaiting_tool_approval": bool(last_scan.get("awaitingToolApproval")),
            "pending_tool_approval": last_scan.get("pendingToolApproval"),
            "already_running": False,
        }
    def reset_project_runtime_state(self, project_id: str) -> None:
        """Resets agent and phase status fields in the project record to idle/pending."""
        project = self.get_project(project_id)
        if not project:
            return

        agents = project.get("agents")
        if isinstance(agents, list):
            for agent in agents:
                if not isinstance(agent, dict):
                    continue
                agent["state"] = "idle"
                agent["progress"] = 0
                agent["currentTask"] = ""
                agent["lastUpdate"] = ""

        phases = project.get("phases")
        if isinstance(phases, list):
            for phase in phases:
                if not isinstance(phase, dict):
                    continue
                phase["status"] = "pending"
                phase["progress"] = 0
                phase["startedAt"] = ""
                phase["completedAt"] = ""
        
        project["status"] = "idle"
        project["scanProgress"] = 0
        project["updatedAt"] = _utc_now_iso()
        
        last_scan = project.get("lastScan")
        if isinstance(last_scan, dict):
            last_scan["awaitingToolApproval"] = False
            last_scan["pendingToolApproval"] = None
            project["lastScan"] = last_scan
            
        # We optionally remove lastScan entirely on full reset/cancel if needed, 
        # but here we just clear the approval flags.
        
        self.upsert_project(project)
