"""App-level scan orchestrator facade.

This module keeps the modern import path stable while delegating real scan
execution to the restored full orchestrator implementation.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from server.db.projects import ProjectsStore

from ._full_orchestrator_impl import (
    ScanOrchestratorService as _FullScanOrchestratorService,
)

if TYPE_CHECKING:
    from .scan.approval import ApprovalGateService
    from .scan.events import ScanEventService
    from .scan.lifecycle import ScanLifecycleService
    from .scan.persistence import ScanPersistenceService
    from .scan.runner import PhaseRunnerService


class ScanOrchestratorService:
    """Compatibility facade over the restored full scan orchestrator."""

    def __init__(
        self,
        projects_store: ProjectsStore,
        *,
        persistence_service: Optional[ScanPersistenceService] = None,
        event_service: Optional[ScanEventService] = None,
        approval_service: Optional[ApprovalGateService] = None,
        runner_service: Optional[PhaseRunnerService] = None,
        lifecycle_service: Optional[ScanLifecycleService] = None,
    ) -> None:
        self._projects_store = projects_store
        self._persistence = persistence_service
        self._events = event_service
        self._approval = approval_service
        self._runner = runner_service
        self._lifecycle = lifecycle_service
        self._full = _FullScanOrchestratorService(projects_store)

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
        return await self._full.start_scan(
            project_id,
            target=target,
            target_config=target_config,
            scope=scope,
            info=info,
            resume=resume,
            force=force,
        )

    async def stop_scan(self, project_id: str, *, mode: str = "pause") -> Dict[str, Any]:
        return self._full.stop_scan(project_id, mode=mode)

    async def cancel_scan(self, project_id: str) -> Dict[str, Any]:
        return self._full.stop_scan(project_id, mode="cancel")

    async def approve_information_gathering(
        self,
        project_id: str,
        modified_program: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        return await self._full.approve_information_gathering(
            project_id,
            modified_program=modified_program,
        )

    async def approve_planner(self, project_id: str) -> Dict[str, Any]:
        return await self._full.approve_planner(project_id)

    async def request_executer_tool_approval(
        self,
        *,
        project_id: str,
        scan_id: str,
        role: str,
        tool_name: str,
        args: Dict[str, Any],
        call_id: str,
    ) -> bool:
        return await self._full.request_executer_tool_approval(
            project_id=project_id,
            scan_id=scan_id,
            role=role,
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )

    async def approve_executer_tool(
        self,
        project_id: str,
        *,
        approval_id: str,
        action: str,
    ) -> Dict[str, Any]:
        return await self._full.approve_executer_tool(
            project_id,
            approval_id=approval_id,
            action=action,
        )

    async def request_executer_password(
        self,
        *,
        project_id: str,
        scan_id: str,
        tool_name: str,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        return await self._full.request_executer_password(
            project_id=project_id,
            scan_id=scan_id,
            tool_name=tool_name,
            prompt=prompt,
            reason=reason,
            call_id=call_id,
        )

    async def approve_executer_password(
        self,
        project_id: str,
        *,
        password_id: str,
        password: str,
        approved: bool,
    ) -> Dict[str, Any]:
        return await self._full.approve_executer_password(
            project_id,
            password_id=password_id,
            password=password,
            approved=approved,
        )

    def get_scan_status(self, project_id: str) -> Dict[str, Any]:
        return self._full.get_scan_status(project_id)

    def subscribe_events(self, project_id: str) -> asyncio.Queue[Dict[str, Any]]:
        return self._full.subscribe_events(project_id)

    def unsubscribe_events(self, project_id: str, queue: asyncio.Queue[Dict[str, Any]]) -> None:
        self._full.unsubscribe_events(project_id, queue)

    def subscribe(self, project_id: str) -> asyncio.Queue[Dict[str, Any]]:
        return self.subscribe_events(project_id)

    def unsubscribe(self, project_id: str, queue: asyncio.Queue[Dict[str, Any]]) -> None:
        self.unsubscribe_events(project_id, queue)

    def clear_event_cache(self, project_id: str) -> int:
        return self._full.clear_event_cache(project_id)

    def list_event_cache(self, project_id: str, limit: int = 200) -> list[Dict[str, Any]]:
        return self._full.list_event_cache(project_id, limit=limit)

    def get_scan_observability(
        self,
        project_id: str,
        *,
        scan_id: str | None = None,
        limit: int = 200,
    ) -> Dict[str, Any]:
        return self._projects_store.get_scan_observability_snapshot(
            project_id,
            scan_id=scan_id,
            limit=limit,
        )

    def emit_event(
        self,
        project_id: str,
        *,
        event: str,
        scan_id: str | None = None,
        level: str = "info",
        message: str = "",
        data: Dict[str, Any] | None = None,
    ) -> None:
        self._full._emit_event(
            project_id,
            event=event,
            scan_id=scan_id,
            level=level,
            message=message,
            data=data,
        )
