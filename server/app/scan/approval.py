from __future__ import annotations

import asyncio
import time
import uuid
import structlog
from typing import Any, Dict, Optional, TYPE_CHECKING

from server.agents.executer.tool_safety import (
    get_run_custom_command_profile,
    get_tool_safety_profile,
)
from .types import PendingToolApproval, PendingPasswordRequest

if TYPE_CHECKING:
    from .persistence import ScanPersistenceService
    from .events import ScanEventService

logger = structlog.get_logger(__name__)


def _approval_prefix_for_role(role: str) -> str:
    normalized = str(role or "").strip().lower().replace("-", "_")
    if "intel" in normalized:
        return "Intel"
    if "planner" in normalized:
        return "Planner"
    if "information_gathering" in normalized or "information gathering" in normalized:
        return "Information Gathering"
    if "analyzer" in normalized or "verify" in normalized or "retest" in normalized:
        return "Analyzer"
    return "Executer"

class ApprovalGateService:
    """Manages manual approval gates for tools, plans, and passwords."""

    def __init__(
        self, 
        persistence: ScanPersistenceService, 
        events: ScanEventService
    ):
        self._persistence = persistence
        self._events = events
        
        # In-memory maps for active events
        self._tool_approvals: Dict[str, Dict[str, PendingToolApproval]] = {}
        self._password_requests: Dict[str, Dict[str, PendingPasswordRequest]] = {}
        self._planner_gates: Dict[str, asyncio.Event] = {}
        self._info_gates: Dict[str, asyncio.Event] = {}

    async def request_tool_approval(
        self,
        *,
        project_id: str,
        scan_id: str,
        role: str,
        tool_name: str,
        args: Dict[str, Any],
        call_id: str,
    ) -> bool:
        approval_mode = self._persistence.get_approval_mode(project_id)
        require_manual = bool(args.get("_require_manual_approval")) if isinstance(args, dict) else False
        display_prefix = _approval_prefix_for_role(role)
        
        if approval_mode == "auto" and not require_manual:
            logger.info("tool_auto_approved", project_id=project_id, tool_name=tool_name)
            return True

        approval_id = str(uuid.uuid4())
        if str(tool_name or "").strip().lower() == "run_custom":
            run_custom_args = args.get("args", []) if isinstance(args, dict) else []
            if not isinstance(run_custom_args, list):
                run_custom_args = []
            safety_profile = get_run_custom_command_profile(
                str(args.get("command", "")).strip().lower() if isinstance(args, dict) else "",
                role=role,
                args=[str(item) for item in run_custom_args],
            ).to_dict()
        else:
            safety_profile = get_tool_safety_profile(tool_name, role=role).to_dict()
        pending = PendingToolApproval(
            approval_id=approval_id,
            scan_id=scan_id,
            role=role,
            tool_name=tool_name,
            args=args,
            call_id=call_id
        )
        
        project_approvals = self._tool_approvals.setdefault(project_id, {})
        project_approvals[approval_id] = pending

        run_state = self._persistence.get_run_state(project_id)
        if isinstance(run_state, dict):
            run_state["awaiting_tool_approval"] = True
            run_state["pending_tool_approval"] = {
                "approval_id": approval_id,
                "scan_id": scan_id,
                "role": role,
                "tool_name": tool_name,
                "call_id": call_id,
                "args": args,
                "safety_profile": safety_profile,
            }
            self._persistence.set_run_state(project_id, run_state)

        self._events.emit(
            project_id,
            event="executer_tool_waiting_approval",
            scan_id=scan_id,
            level="warn",
            message=f"{display_prefix} [waiting approval] {role} requested tool '{tool_name}'.",
            data={
                "stage": "executer",
                "kind": "waiting_tool_approval",
                "awaiting_user_approval": True,
                "approval_id": approval_id,
                "role": role,
                "tool_name": tool_name,
                "call_id": call_id,
                "args": args,
                "safety_profile": safety_profile,
            },
        )

        TOOL_TIMEOUTS = {
            "hydra_bruteforce": 1800,
            "nuclei_vuln_scan": 1200,
            "sqlmap": 1200,
            "run_custom": 900,
            "run_python": 600,
            "payload_generator": 300,
        }
        TIMEOUT = TOOL_TIMEOUTS.get(tool_name, 60)

        try:
            start_time = time.time()
            while not pending.event.is_set():
                remaining = TIMEOUT - (time.time() - start_time)
                if remaining <= 0:
                    raise asyncio.TimeoutError()

                try:
                    await asyncio.wait_for(pending.event.wait(), timeout=min(60, remaining))
                    break
                except asyncio.TimeoutError:
                    if time.time() - start_time >= TIMEOUT:
                        raise
                    
                    elapsed = int(time.time() - start_time)
                    self._events.emit(
                        project_id,
                        event="executer_tool_approval_waiting",
                        scan_id=scan_id,
                        message=f"{display_prefix} [approval waiting] {role} tool '{tool_name}' ({elapsed}s/{TIMEOUT}s)",
                        data={
                            "stage": "executer",
                            "kind": "tool_approval_waiting",
                            "approval_id": approval_id,
                            "role": role,
                            "tool_name": tool_name,
                        }
                    )

        except asyncio.TimeoutError:
            pending.decision = "skip"
            logger.warning("tool_approval_timeout", project_id=project_id, tool_name=tool_name)

        # Cleanup
        project_approvals.pop(approval_id, None)
        if not project_approvals:
            self._tool_approvals.pop(project_id, None)

        run_state = self._persistence.get_run_state(project_id)
        if isinstance(run_state, dict):
            if project_approvals:
                next_id, next_pending = next(iter(project_approvals.items()))
                run_state["awaiting_tool_approval"] = True
                run_state["pending_tool_approval"] = {
                    "approval_id": next_id,
                    "scan_id": next_pending.scan_id,
                    "role": next_pending.role,
                    "tool_name": next_pending.tool_name,
                    "call_id": next_pending.call_id,
                    "args": next_pending.args,
                }
            else:
                run_state["awaiting_tool_approval"] = False
                run_state["pending_tool_approval"] = None
            self._persistence.set_run_state(project_id, run_state)

        approved = pending.decision == "approve"
        return approved

    async def request_password(
        self,
        *,
        project_id: str,
        scan_id: str,
        tool_name: str,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        password_id = str(uuid.uuid4())
        pending = PendingPasswordRequest(
            password_id=password_id,
            scan_id=scan_id,
            tool_name=tool_name,
            prompt=prompt,
            reason=reason,
            call_id=call_id
        )
        
        project_requests = self._password_requests.setdefault(project_id, {})
        project_requests[password_id] = pending

        self._events.emit(
            project_id,
            event="executer_password_request",
            scan_id=scan_id,
            message=f"Executer [password required] {tool_name} needs authentication",
            data={
                "stage": "executer",
                "kind": "password_request",
                "tool_name": tool_name,
                "prompt": prompt,
                "reason": reason,
                "call_id": call_id,
                "password_id": password_id,
            },
        )

        TIMEOUT = 600
        try:
            start_time = time.time()
            while not pending.event.is_set():
                remaining = TIMEOUT - (time.time() - start_time)
                if remaining <= 0:
                    raise asyncio.TimeoutError()

                try:
                    await asyncio.wait_for(pending.event.wait(), timeout=min(30, remaining))
                    break
                except asyncio.TimeoutError:
                    if time.time() - start_time >= TIMEOUT:
                        raise
                    # Keepalive heartbeat
                    continue
        except asyncio.TimeoutError:
            logger.warning("password_request_timeout", project_id=project_id, tool_name=tool_name)

        project_requests.pop(password_id, None)
        return pending.password if pending.approved else None

    def approve_tool(self, project_id: str, approval_id: str, action: str) -> bool:
        project_approvals = self._tool_approvals.get(project_id, {})
        pending = project_approvals.get(approval_id)
        if not pending:
            return False
        
        pending.decision = action.lower().strip()
        pending.event.set()
        return True

    def approve_password(self, project_id: str, password_id: str, password: str, approved: bool) -> bool:
        project_requests = self._password_requests.get(project_id, {})
        pending = project_requests.get(password_id)
        if not pending:
            return False
        
        pending.approved = approved
        pending.password = password if approved else None
        pending.event.set()
        return True

    async def approve_info_gathering(
        self, 
        project_id: str, 
        modified_program: list[Dict[str, Any]] | None = None
    ) -> Dict[str, Any]:
        project_key = str(project_id or "").strip()
        run_state = self._persistence.get_run_state(project_key)
        if not run_state:
            raise ValueError("no active scan for project")

        scan_id = run_state.get("scan_id", "")
        waiting = bool(run_state.get("awaiting_information_gathering_approval"))

        if waiting:
            if modified_program is not None:
                memory = run_state.get("active_memory")
                if isinstance(memory, dict):
                    gathering = memory.get("gathering", {})
                    gathering["program"] = modified_program
                    memory["gathering"] = gathering
            
            gate = self._info_gates.get(project_key)
            if gate:
                gate.set()
            
            run_state["awaiting_information_gathering_approval"] = False
            self._persistence.set_run_state(project_key, run_state)

            self._events.emit(
                project_key,
                event="target_info_gathering_approval_received",
                scan_id=scan_id,
                level="success",
                message="Information Gathering [approved] Static gathering program approved.",
                data={
                    "stage": "information_gathering",
                    "kind": "approved",
                    "status": "running",
                    "awaiting_user_approval": False,
                },
            )

        return {
            "ok": True,
            "project_id": project_key,
            "scan_id": scan_id,
            "status": "running",
            "awaiting_information_gathering_approval": False,
            "already_approved": not waiting,
        }

    async def approve_planner(self, project_id: str) -> Dict[str, Any]:
        project_key = str(project_id or "").strip()
        run_state = self._persistence.get_run_state(project_key)
        if not run_state:
            raise ValueError("no active scan for project")

        scan_id = run_state.get("scan_id", "")
        waiting = bool(run_state.get("awaiting_planner_approval"))

        if waiting:
            gate = self._planner_gates.get(project_key)
            if gate:
                gate.set()
            
            run_state["awaiting_planner_approval"] = False
            self._persistence.set_run_state(project_key, run_state)

            self._events.emit(
                project_key,
                event="planner_approval_received",
                scan_id=scan_id,
                level="success",
                message="Planner [approved] Checklist approved by pentester.",
                data={
                    "stage": "planner",
                    "kind": "approved",
                    "status": "running",
                    "awaiting_user_approval": False,
                },
            )

        return {
            "ok": True,
            "project_id": project_key,
            "scan_id": scan_id,
            "status": "running",
            "awaiting_planner_approval": False,
            "already_approved": not waiting,
        }
    def clear_gates(self, project_id: str) -> None:
        """Force-clears all pending approvals and requests for a project."""
        project_key = str(project_id or "").strip()
        
        # Clear tool approvals
        tool_approvals = self._tool_approvals.pop(project_key, {})
        for pending in tool_approvals.values():
            pending.decision = "skip"
            pending.event.set()
            
        # Clear password requests
        password_requests = self._password_requests.pop(project_key, {})
        for pending in password_requests.values():
            pending.approved = False
            pending.event.set()
            
        # Clear planner gates
        gate = self._planner_gates.pop(project_key, None)
        if gate:
            gate.set()
            
        # Clear info gates
        gate = self._info_gates.pop(project_key, None)
        if gate:
            gate.set()
