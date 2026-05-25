from __future__ import annotations

import asyncio
import uuid
import structlog
from typing import Any, Dict, Optional, TYPE_CHECKING

from server.agents.executer.sandbox import delete_project_workspace

from .types import ScanStatus
from .utils import (
    _utc_now_iso, 
    _extract_target, 
    _normalize_target_type,
    _merge_scan_metadata
)

if TYPE_CHECKING:
    from .persistence import ScanPersistenceService
    from .events import ScanEventService
    from .runner import PhaseRunnerService
    from .approval import ApprovalGateService

logger = structlog.get_logger(__name__)

class ScanLifecycleService:
    """Manages high-level scan operations and coordinates phase execution."""

    def __init__(
        self, 
        persistence: ScanPersistenceService,
        events: ScanEventService,
        runner: PhaseRunnerService,
        approval: ApprovalGateService
    ):
        self._persistence = persistence
        self._events = events
        self._runner = runner
        self._approval = approval
        self._locks: Dict[str, asyncio.Lock] = {}
        self._tasks: Dict[str, asyncio.Task[None]] = {}

    def _get_lock(self, project_id: str) -> asyncio.Lock:
        if project_id not in self._locks:
            self._locks[project_id] = asyncio.Lock()
        return self._locks[project_id]

    async def start_scan(
        self,
        project_id: str,
        *,
        target: str = "",
        target_config: Dict[str, Any] | None = None,
        scope: str = "",
        info: str = "",
        resume: bool = False,
        force: bool = False,
    ) -> Dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._persistence.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        current_status = str(project.get("status", "") or "").strip().lower()
        last_scan = project.get("lastScan")
        last_scan_id = str(last_scan.get("scanId", "")).strip() if isinstance(last_scan, dict) else ""

        if current_status == "completed" and not force:
            return {
                "scan_id": last_scan_id,
                "project_id": project_key,
                "status": "completed",
                "started_at": last_scan.get("startedAt") if isinstance(last_scan, dict) else None,
                "updated_at": project.get("updatedAt"),
                "finished_at": last_scan.get("finishedAt") if isinstance(last_scan, dict) else None,
                "error": "",
                "already_running": True,
            }

        async with self._get_lock(project_key):
            run_state = self._persistence.get_run_state(project_key)
            if run_state and run_state.get("status") == "running":
                return {"ok": False, "error": "Scan already running"}

            project_target = _extract_target(project)
            effective_target = target or project_target
            if not effective_target:
                raise ValueError("project target is missing")

            if target:
                project["target"] = target
            if target_config is not None:
                project["targetConfig"] = target_config
            if target or target_config is not None:
                project["updatedAt"] = _utc_now_iso()
                self._persistence.upsert_project(project)

            effective_target_type = _normalize_target_type(project.get("targetType"))
            
            scan_id = str(uuid.uuid4())
            now = _utc_now_iso()
            approval_mode = str(project.get("approval_mode") or "custom").lower().strip()
            
            new_state = {
                "scan_id": scan_id,
                "project_id": project_key,
                "target": effective_target,
                "target_type": effective_target_type,
                "status": "running",
                "approval_mode": approval_mode,
                "started_at": now,
                "updated_at": now,
                "awaiting_tool_approval": False,
                "pending_tool_approval": None,
            }
            self._persistence.set_run_state(project_key, new_state)

            scan_meta = {
                "scanId": scan_id,
                "startedAt": now,
                "status": "running",
                "error": ""
            }
            # Merge with existing lastScan if any
            existing_last_scan = project.get("lastScan")
            merged_meta = _merge_scan_metadata(existing_last_scan, scan_meta)

            self._persistence.update_project_status(
                project_key, 
                "running", 
                progress=5,
                meta=merged_meta
            )

            self._events.emit(
                project_key,
                "scan_started",
                scan_id=scan_id,
                level="info",
                message=(
                    "Scan resumed from paused state."
                    if resume
                    else f"Scan started for {effective_target}."
                ),
                data={
                    "status": "running",
                    "target": effective_target,
                    "target_type": effective_target_type,
                    "resume_restored": bool(resume),
                    "reason_code": "resume_restored" if resume else "scan_started",
                },
            )

            # Start the background task
            task = asyncio.create_task(self._run_full_scan(project_key, scan_id))
            self._tasks[project_key] = task

            return {
                "ok": True,
                "scan_id": scan_id,
                "status": "running",
                "project_id": project_key,
                "started_at": now,
            }

    async def _run_full_scan(self, project_id: str, scan_id: str):
        """Internal background task for the entire scan sequence."""
        try:
            # Phase 1: Intel
            intel_res = await self._runner.run_intel_phase(project_id, scan_id)
            if not intel_res.success:
                await self._handle_scan_failure(project_id, scan_id, f"Intel phase failed: {intel_res.error}")
                return

            # Phase 2: Warmup Recon
            warmup_res = await self._runner.run_warmup_recon_phase(project_id, scan_id)
            if not warmup_res.success:
                await self._handle_scan_failure(project_id, scan_id, f"Warmup Recon phase failed: {warmup_res.error}")
                return

            # The post-warmup pipeline is not fully wired in this lifecycle yet.
            # Do not report overall scan success until planner/executer/analyzer
            # are actually executed from this code path.
            await self._handle_scan_failure(
                project_id,
                scan_id,
                "Scan pipeline incomplete: Intel finished, but planner/executer/analyzer phases were not executed by the active lifecycle.",
            )

        except asyncio.CancelledError:
            logger.info("scan_task_cancelled", project_id=project_id, scan_id=scan_id)
            # Cleanup already handled by stop_scan
            raise
        except Exception as exc:
            logger.exception("scan_execution_crashed", project_id=project_id, error=str(exc))
            await self._handle_scan_failure(project_id, scan_id, f"Internal crash: {str(exc)}")
        finally:
            self._tasks.pop(project_id, None)

    async def _handle_scan_success(self, project_id: str, scan_id: str):
        self._persistence.update_project_status(project_id, "completed", progress=100)
        self._persistence.pop_run_state(project_id)
        self._events.emit(project_id, "scan_completed", scan_id, level="success", message="Scan completed successfully.")

    async def _handle_scan_failure(self, project_id: str, scan_id: str, error: str):
        self._persistence.update_project_status(project_id, "failed", meta={"error": error})
        self._persistence.pop_run_state(project_id)
        self._events.emit(project_id, "scan_failed", scan_id, level="error", message=error)

    async def stop_scan(self, project_id: str, *, mode: str = "pause") -> Dict[str, Any]:
        """Pauses or cancels an active scan."""
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        mode_clean = str(mode or "").strip().lower()
        if mode_clean not in {"pause", "cancel"}:
            raise ValueError("mode must be 'pause' or 'cancel'")

        # 1. Cancel the task
        task = self._tasks.get(project_key)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # 2. Clear approval gates
        self._approval.clear_gates(project_key)

        now_iso = _utc_now_iso()
        run_state = self._persistence.get_run_state(project_key)
        scan_id = str(run_state.get("scan_id") or "") if run_state else ""

        if mode_clean == "pause":
            if run_state:
                run_state["status"] = "paused"
                run_state["finished_at"] = now_iso
                self._persistence.set_run_state(project_key, run_state)
            
            self._persistence.update_project_status(
                project_key,
                status="paused",
                meta={"status": "paused", "finishedAt": now_iso}
            )
            
            self._events.emit(
                project_key,
                event="scan_paused",
                scan_id=scan_id,
                level="warn",
                message="Scan paused by user.",
                data={"status": "paused"}
            )
            return {"ok": True, "project_id": project_key, "scan_id": scan_id, "status": "paused"}

        # Cancel mode
        self._persistence.pop_run_state(project_key)
        self._persistence.reset_project_runtime_state(project_key)
        project_for_cleanup = self._persistence.get_project(project_key)
        if isinstance(project_for_cleanup, dict):
            delete_project_workspace(project_key, project_payload=project_for_cleanup)
        
        self._events.emit(
            project_key,
            event="scan_cancelled",
            scan_id=scan_id,
            level="warn",
            message="Scan cancelled by user.",
            data={"status": "idle"}
        )
        return {"ok": True, "project_id": project_key, "scan_id": scan_id, "status": "idle"}

    async def cancel_scan(self, project_id: str) -> Dict[str, Any]:
        """Legacy alias for stop_scan(mode='cancel')."""
        return await self.stop_scan(project_id, mode="cancel")
