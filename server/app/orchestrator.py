"""App-level scan orchestrator service.

This service is the API entrypoint for scan execution:
1. Resolve project details from storage
2. Run Intel Agent to produce pentest checklist intelligence
3. Run Planner Agent to build/store the initial pentest plan
4. Persist scan lifecycle/status back to the project record
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

import structlog

from server.db.projects import ProjectsStore

logger = structlog.get_logger(__name__)

_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web": "web_app",
    "web3": "web_app",
    "infrastructure": "infra",
    "infra": "infra",
    "binary": "desktop",
    "identity": "linux_server",
    "supply_chain": "repository",
    "recon": "shared",
    "red_team": "shared",
    "cve_exploit": "shared",
}

_TARGET_CONFIG_KEYS = (
    "url",
    "base_url",
    "host",
    "target_ip",
    "gateway",
    "cidr",
    "repo_url",
    "targets.ip_address",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_target_type(value: Any) -> str:
    clean = str(value or "").strip().lower().replace("-", "_")
    if not clean:
        return "web_app"
    return _TARGET_TYPE_ALIASES.get(clean, clean)


def _nested_get(data: dict[str, Any], dotted_key: str) -> str:
    current: Any = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return ""
        current = current.get(part)
    return str(current).strip() if isinstance(current, str) else ""


def _extract_target(project: dict[str, Any]) -> str:
    primary = project.get("target")
    if isinstance(primary, str) and primary.strip():
        return primary.strip()

    target_config = project.get("targetConfig")
    if not isinstance(target_config, dict):
        return ""

    for key in _TARGET_CONFIG_KEYS:
        value = _nested_get(target_config, key)
        if value:
            return value
    return ""


def _ensure_intel_agent_importable() -> None:
    """Raise a clear runtime error when Intel Agent deps are missing."""
    try:
        from server.agents.intel.agent import IntelAgent as _IntelAgent  # noqa: F401
    except ModuleNotFoundError as exc:
        missing = str(exc.name or "").strip() or "unknown"
        raise RuntimeError(
            "intel dependency is missing: "
            f"{missing}. Install full backend dependencies with "
            "`python -m pip install -r server/requirements.txt`.",
        ) from exc


def _ensure_planner_agent_importable() -> None:
    """Raise a clear runtime error when Planner Agent deps are missing."""
    try:
        from server.agents.planner.agent import PlannerAgent as _PlannerAgent  # noqa: F401
    except ModuleNotFoundError as exc:
        missing = str(exc.name or "").strip() or "unknown"
        raise RuntimeError(
            "planner dependency is missing: "
            f"{missing}. Install full backend dependencies with "
            "`python -m pip install -r server/requirements.txt`.",
        ) from exc


def _is_truthy_env(name: str, default: str = "") -> bool:
    value = os.getenv(name, default).strip().lower()
    return value in {"1", "true", "yes", "on"}


def _count_checklist_items(payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    blocks = payload.get("checklist")
    if not isinstance(blocks, list):
        return 0
    total = 0
    for block in blocks:
        if not isinstance(block, dict):
            continue
        items = block.get("items")
        if isinstance(items, list):
            total += len(items)
    return total


def _classify_intel_log_kind(message: str) -> str:
    raw = str(message or "").strip()
    lowered = raw.lower()

    if "intel agent starting" in lowered:
        return "start"
    if "intel agent complete" in lowered:
        return "completed"
    if "rag is fresh" in lowered or "skipping update" in lowered:
        return "skip_rag_update"

    if "calling tools" in lowered or re.match(r"^[a-z0-9_]+\(", lowered):
        return "run_tool"

    if "final answer" in lowered or lowered.startswith("formatter done") or lowered.startswith("→"):
        return "result"

    if (
        "rag update needed" in lowered
        or lowered.startswith("update:")
        or "collecting rag snapshot" in lowered
        or lowered.startswith("rag snapshot:")
        or "prefetching formatter context" in lowered
        or lowered.startswith("prefetch:")
    ):
        return "updating_resources"

    if lowered.startswith("llm formatter starting") or lowered.startswith("llm round"):
        return "thinking"

    return "thinking"


def _classify_planner_log_kind(message: str) -> str:
    raw = str(message or "").strip()
    lowered = raw.lower()

    if "planner agent starting" in lowered:
        return "start"
    if "planner agent complete" in lowered:
        return "completed"
    if "calling tools" in lowered or re.match(r"^[a-z0-9_]+\(", lowered):
        return "run_tool"
    if lowered.startswith("llm round"):
        return "thinking"
    if lowered.startswith("executed ") or lowered.startswith("final answer"):
        return "result"
    if "error" in lowered or "failed" in lowered:
        return "warn"
    return "thinking"


def _build_planner_kickoff_message(
    *,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    intel_status: str,
    intel_vulnerabilities: list[str],
    intel_stats: dict[str, Any],
    checklist_overview: dict[str, Any],
) -> str:
    return (
        f"Target: {target}\n"
        f"Target type: {target_type}\n"
        f"Scope: {scope}\n"
        f"Info: {info}\n\n"
        "## Intel Input\n"
        f"Intel status: {intel_status}\n"
        f"Vulnerabilities: {intel_vulnerabilities}\n"
        f"Checklist overview: {checklist_overview}\n"
        f"Intel stats: {intel_stats}\n\n"
        "## Planner Task\n"
        "1. FIRST STEP: create a great pentest plan for this target.\n"
        "2. Use available tools and checklist guidance, but keep responses token-efficient.\n"
        "3. Treat checklist as state machine guidance: prioritize S5 (critical severity) gaps first.\n"
        "4. Return strict JSON with keys: summary, needs, plan, action_plan.\n"
        "5. action_plan must include: checklist_updates, checklist_additions, "
        "plan_modifications, dispatch, phase_advance, phase_advance_blocked_by, rationale.\n"
    )


class PrintCallback:
    """Print step-by-step output in the same style as test_intel_agent."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        on_log: Callable[[str, str], None] | None = None,
    ) -> None:
        self._start = time.perf_counter()
        self._enabled = enabled
        self._on_log = on_log

    def _ts(self) -> str:
        return f"[{time.perf_counter() - self._start:.1f}s]"

    def on_step(self, message: str) -> None:
        if self._enabled:
            print(f"  → {message} {self._ts()}", flush=True)
        if self._on_log is not None:
            self._on_log("info", message)

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  ✓ {message}", flush=True)
        if self._on_log is not None:
            self._on_log("success", message)

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ⚠ {message}", flush=True)
        if self._on_log is not None:
            self._on_log("warn", message)

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        if self._enabled:
            print(
                f"  ⚠ approval required: role={role} tool={tool_name} call_id={call_id}",
                flush=True,
            )
        if self._on_log is not None:
            self._on_log(
                "warn",
                (
                    f"Tool approval required: role={role} "
                    f"tool={tool_name} call_id={call_id} args={args}"
                ),
            )
        # Secure default: deny unless orchestration layer explicitly approves.
        return False


@dataclass
class _PendingToolApproval:
    scan_id: str
    role: str
    tool_name: str
    args: dict[str, Any]
    call_id: str
    event: asyncio.Event
    decision: str | None = None


class ScanOrchestratorService:
    """Runs and tracks orchestrated scan executions per project."""

    def __init__(self, projects_store: ProjectsStore) -> None:
        self._projects_store = projects_store
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._runs: dict[str, dict[str, Any]] = {}
        self._planner_approval_events: dict[str, asyncio.Event] = {}
        self._tool_approval_events: dict[str, dict[str, _PendingToolApproval]] = {}
        self._event_subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}
        self._lock = asyncio.Lock()

    async def start_scan(
        self,
        project_id: str,
        *,
        target: str = "",
        target_config: dict[str, Any] | None = None,
        scope: str = "",
        info: str = "",
        resume: bool = False,
        force: bool = False,
    ) -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._projects_store.get_project(project_key)
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
        if current_status == "paused" and not resume:
            return {
                "scan_id": last_scan_id,
                "project_id": project_key,
                "status": "paused",
                "started_at": last_scan.get("startedAt") if isinstance(last_scan, dict) else None,
                "updated_at": project.get("updatedAt"),
                "finished_at": last_scan.get("finishedAt") if isinstance(last_scan, dict) else None,
                "error": "",
                "already_running": True,
            }

        provided_target = str(target or "").strip()
        provided_target_config = target_config if isinstance(target_config, dict) else None
        if not provided_target and provided_target_config is not None:
            provided_target = _extract_target({"targetConfig": provided_target_config})

        project_target = _extract_target(project)
        effective_target = provided_target or project_target
        if not effective_target:
            raise ValueError("project target is missing")

        if provided_target:
            project["target"] = provided_target
        if provided_target_config is not None:
            project["targetConfig"] = provided_target_config
        if provided_target or provided_target_config is not None:
            project["updatedAt"] = _utc_now_iso()
            self._projects_store.upsert_project(project)

        effective_target_type = _normalize_target_type(project.get("targetType"))
        scope_payload = str(scope or "").strip()
        project_description = str(project.get("description", "")).strip()
        custom_info = str(info or "").strip() or project_description
        info_parts = [
            f"Target: {effective_target}",
            f"Scope: {scope_payload}" if scope_payload else "",
            custom_info,
        ]
        info_payload = "\n".join(part for part in info_parts if part).strip()
        _ensure_intel_agent_importable()
        _ensure_planner_agent_importable()

        async with self._lock:
            active_task = self._tasks.get(project_key)
            if active_task is not None and not active_task.done():
                current = dict(self._runs.get(project_key, {}))
                current["already_running"] = True
                return current

            if not resume:
                try:
                    self._projects_store.clear_scan_event_cache(project_key)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "scan_event_cache_clear_failed",
                        project_id=project_key,
                        error=str(exc),
                    )

            scan_id = str(uuid.uuid4())
            started_at = _utc_now_iso()
            run_state = {
                "scan_id": scan_id,
                "project_id": project_key,
                "status": "running",
                "started_at": started_at,
                "updated_at": started_at,
                "finished_at": None,
                "error": "",
                "awaiting_planner_approval": False,
                "awaiting_tool_approval": False,
                "pending_tool_approval": None,
                "already_running": False,
            }
            self._runs[project_key] = run_state
            self._persist_project_status(
                project_key,
                status="running",
                scan_progress=5,
                scan_meta={
                    "scanId": scan_id,
                    "status": "running",
                    "startedAt": started_at,
                },
            )
            self._emit_event(
                project_key,
                event="scan_started",
                scan_id=scan_id,
                level="info",
                message=f"Scan started for {effective_target}.",
                data={
                    "target": effective_target,
                    "target_type": effective_target_type,
                    "status": "running",
                    "scan_progress": 5,
                },
            )

            task = asyncio.create_task(
                self._run_scan(
                    project_id=project_key,
                    scan_id=scan_id,
                    target=effective_target,
                    target_type=effective_target_type,
                    started_at=started_at,
                    info=info_payload,
                ),
                name=f"scan_orchestrator_{project_key}",
            )
            task.add_done_callback(
                lambda done_task, pid=project_key: self._on_task_done(pid, done_task),
            )
            self._tasks[project_key] = task

            return dict(run_state)

    def subscribe_events(self, project_id: str) -> asyncio.Queue[dict[str, Any]]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        self._event_subscribers.setdefault(project_key, set()).add(queue)

        try:
            cached = self._projects_store.list_scan_event_cache(project_key, limit=180)
        except Exception as exc:  # pragma: no cover - defensive
            cached = []
            logger.warning(
                "scan_event_cache_load_failed",
                project_id=project_key,
                error=str(exc),
            )
        for payload in cached:
            self._push_event(queue, payload)

        status_snapshot = self.get_scan_status(project_key)
        self._push_event(
            queue,
            {
                "event": "scan_status_snapshot",
                "project_id": project_key,
                "scan_id": str(status_snapshot.get("scan_id", "")),
                "level": "info",
                "message": f"Current scan status: {status_snapshot.get('status', 'idle')}.",
                "timestamp": _utc_now_iso(),
                "data": {
                    "status": status_snapshot.get("status", "idle"),
                    "scan_progress": int(project.get("scanProgress", 0) or 0),
                    "scan": status_snapshot,
                },
            },
        )
        return queue

    def unsubscribe_events(self, project_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        project_key = str(project_id or "").strip()
        if not project_key:
            return
        subscribers = self._event_subscribers.get(project_key)
        if not subscribers:
            return
        subscribers.discard(queue)
        if not subscribers:
            self._event_subscribers.pop(project_key, None)

    def _push_event(
        self,
        queue: asyncio.Queue[dict[str, Any]],
        payload: dict[str, Any],
    ) -> None:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            pass

    def _emit_event(
        self,
        project_id: str,
        *,
        event: str,
        message: str,
        level: str = "info",
        scan_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "event": event,
            "project_id": project_id,
            "scan_id": scan_id or "",
            "level": level,
            "message": message,
            "timestamp": _utc_now_iso(),
            "data": data or {},
        }

        try:
            self._projects_store.append_scan_event_cache(project_id, payload)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "scan_event_cache_append_failed",
                project_id=project_id,
                event=event,
                error=str(exc),
            )

        subscribers = tuple(self._event_subscribers.get(project_id, set()))
        if not subscribers:
            return

        for queue in subscribers:
            self._push_event(queue, payload)

    def clear_event_cache(self, project_id: str) -> int:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")
        return self._projects_store.clear_scan_event_cache(project_key)

    def list_event_cache(self, project_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")
        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")
        return self._projects_store.list_scan_event_cache(project_key, limit=limit)

    def _reset_project_runtime_state(self, project: dict[str, Any]) -> None:
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

    def stop_scan(self, project_id: str, *, mode: str = "pause") -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        mode_clean = str(mode or "").strip().lower()
        if mode_clean not in {"pause", "cancel"}:
            raise ValueError("mode must be 'pause' or 'cancel'")

        task = self._tasks.get(project_key)
        if task is not None and not task.done():
            task.cancel()
        gate = self._planner_approval_events.get(project_key)
        if gate is not None:
            gate.set()

        now_iso = _utc_now_iso()
        run_state = self._runs.get(project_key, {})
        scan_id = str(run_state.get("scan_id") or project.get("lastScan", {}).get("scanId", "") or "")

        if mode_clean == "pause":
            self._runs[project_key] = {
                "scan_id": scan_id,
                "project_id": project_key,
                "status": "paused",
                "started_at": run_state.get("started_at"),
                "updated_at": now_iso,
                "finished_at": now_iso,
                "error": "",
                "awaiting_planner_approval": False,
                "awaiting_tool_approval": False,
                "pending_tool_approval": None,
                "already_running": False,
            }
            last_scan = project.get("lastScan")
            if isinstance(last_scan, dict):
                last_scan["status"] = "paused"
                last_scan["finishedAt"] = last_scan.get("finishedAt") or now_iso
                project["lastScan"] = last_scan
            project["status"] = "paused"
            project["updatedAt"] = now_iso
            self._projects_store.upsert_project(project)
            self._emit_event(
                project_key,
                event="scan_paused",
                scan_id=scan_id,
                level="warn",
                message="Scan paused by user.",
                data={"status": "paused"},
            )
            return {
                "ok": True,
                "project_id": project_key,
                "scan_id": scan_id,
                "status": "paused",
            }

        # cancel
        self._runs[project_key] = {
            "scan_id": scan_id,
            "project_id": project_key,
            "status": "idle",
            "started_at": run_state.get("started_at"),
            "updated_at": now_iso,
            "finished_at": now_iso,
            "error": "",
            "awaiting_planner_approval": False,
            "awaiting_tool_approval": False,
            "pending_tool_approval": None,
            "already_running": False,
        }
        project["status"] = "idle"
        project["scanProgress"] = 0
        project["updatedAt"] = now_iso
        project.pop("lastScan", None)
        self._reset_project_runtime_state(project)
        self._projects_store.upsert_project(project)
        try:
            self._projects_store.clear_scan_event_cache(project_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "scan_event_cache_clear_failed",
                project_id=project_key,
                error=str(exc),
            )
        self._emit_event(
            project_key,
            event="scan_cancelled",
            scan_id=scan_id,
            level="warn",
            message="Scan cancelled by user.",
            data={"status": "idle"},
        )
        return {
            "ok": True,
            "project_id": project_key,
            "scan_id": scan_id,
            "status": "idle",
        }

    async def approve_planner(self, project_id: str) -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        async with self._lock:
            run_state = self._runs.get(project_key)
            if not isinstance(run_state, dict):
                raise ValueError("no active scan for project")

            scan_id = str(run_state.get("scan_id", "")).strip()
            status = str(run_state.get("status", "")).strip().lower()
            waiting = bool(run_state.get("awaiting_planner_approval"))

            if status != "running":
                raise ValueError("scan is not running")

            if waiting:
                gate = self._planner_approval_events.get(project_key)
                if gate is not None:
                    gate.set()
                now_iso = _utc_now_iso()
                run_state["awaiting_planner_approval"] = False
                run_state["updated_at"] = now_iso
                self._runs[project_key] = run_state

                self._emit_event(
                    project_key,
                    event="planner_approval_received",
                    scan_id=scan_id,
                    level="success",
                    message="Planner [approved] Checklist approved by pentester. Starting planner now.",
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

    async def request_executer_tool_approval(
        self,
        *,
        project_id: str,
        scan_id: str,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        project_key = str(project_id or "").strip()
        if not project_key:
            return False

        approval_id = str(uuid.uuid4())
        pending = _PendingToolApproval(
            scan_id=str(scan_id or ""),
            role=str(role or ""),
            tool_name=str(tool_name or ""),
            args=dict(args or {}),
            call_id=str(call_id or ""),
            event=asyncio.Event(),
        )
        project_pending = self._tool_approval_events.setdefault(project_key, {})
        project_pending[approval_id] = pending

        run_state = self._runs.get(project_key)
        if isinstance(run_state, dict):
            run_state["awaiting_tool_approval"] = True
            run_state["pending_tool_approval"] = {
                "approval_id": approval_id,
                "scan_id": pending.scan_id,
                "role": pending.role,
                "tool_name": pending.tool_name,
                "call_id": pending.call_id,
            }
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_key] = run_state

        self._emit_event(
            project_key,
            event="executer_tool_waiting_approval",
            scan_id=pending.scan_id,
            level="warn",
            message=(
                f"Executer [waiting approval] {pending.role} requested "
                f"tool '{pending.tool_name}'. Approve or skip."
            ),
            data={
                "stage": "executer",
                "kind": "waiting_tool_approval",
                "awaiting_user_approval": True,
                "approval_id": approval_id,
                "role": pending.role,
                "tool_name": pending.tool_name,
                "call_id": pending.call_id,
                "args": pending.args,
            },
        )

        await pending.event.wait()
        approved = pending.decision == "approve"

        project_pending = self._tool_approval_events.get(project_key, {})
        project_pending.pop(approval_id, None)
        if not project_pending:
            self._tool_approval_events.pop(project_key, None)

        run_state = self._runs.get(project_key)
        if isinstance(run_state, dict):
            run_state["awaiting_tool_approval"] = False
            run_state["pending_tool_approval"] = None
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_key] = run_state

        self._emit_event(
            project_key,
            event="executer_tool_approval_decision",
            scan_id=pending.scan_id,
            level="success" if approved else "warn",
            message=(
                f"Executer [approval {'approved' if approved else 'skipped'}] "
                f"{pending.role} tool '{pending.tool_name}'."
            ),
            data={
                "stage": "executer",
                "kind": "tool_approval_decision",
                "approved": approved,
                "decision": pending.decision,
                "role": pending.role,
                "tool_name": pending.tool_name,
                "call_id": pending.call_id,
            },
        )
        return approved

    async def approve_executer_tool(
        self,
        project_id: str,
        *,
        approval_id: str,
        action: str,
    ) -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")
        action_clean = str(action or "").strip().lower()
        if action_clean not in {"approve", "skip"}:
            raise ValueError("action must be 'approve' or 'skip'")

        pending_by_id = self._tool_approval_events.get(project_key, {})
        pending = pending_by_id.get(str(approval_id or "").strip())
        if pending is None:
            raise ValueError("tool approval request not found")

        pending.decision = action_clean
        pending.event.set()

        return {
            "ok": True,
            "project_id": project_key,
            "approval_id": approval_id,
            "action": action_clean,
            "role": pending.role,
            "tool_name": pending.tool_name,
            "scan_id": pending.scan_id,
        }

    def _emit_intel_callback_event(
        self,
        *,
        project_id: str,
        scan_id: str,
        level: str,
        raw_message: str,
    ) -> None:
        kind = _classify_intel_log_kind(raw_message)
        # Start/completed/crashed have dedicated top-level events.
        if kind in {"start", "completed", "crashed"}:
            return
        safe_message = str(raw_message or "").strip()
        if not safe_message:
            safe_message = kind.replace("_", " ")
        display_kind = kind.replace("_", " ")
        self._emit_event(
            project_id,
            event=f"intel_{kind}",
            scan_id=scan_id,
            level=level,
            message=f"Intel [{display_kind}] {safe_message}",
            data={
                "stage": "intel",
                "kind": kind,
                "raw_message": raw_message,
            },
        )

    def _emit_planner_callback_event(
        self,
        *,
        project_id: str,
        scan_id: str,
        level: str,
        raw_message: str,
    ) -> None:
        kind = _classify_planner_log_kind(raw_message)
        if kind in {"start", "completed", "crashed"}:
            return
        safe_message = str(raw_message or "").strip() or kind.replace("_", " ")
        display_kind = kind.replace("_", " ")
        self._emit_event(
            project_id,
            event=f"planner_{kind}",
            scan_id=scan_id,
            level=level,
            message=f"Planner [{display_kind}] {safe_message}",
            data={
                "stage": "planner",
                "kind": kind,
                "raw_message": raw_message,
            },
        )

    def get_scan_status(self, project_id: str) -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        run = self._runs.get(project_key)
        if run is not None:
            return dict(run)

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

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
            "awaiting_planner_approval": bool(last_scan.get("awaitingPlannerApproval")),
            "awaiting_tool_approval": bool(last_scan.get("awaitingToolApproval")),
            "pending_tool_approval": last_scan.get("pendingToolApproval"),
            "already_running": False,
        }

    def _on_task_done(self, project_id: str, task: asyncio.Task[None]) -> None:
        self._tasks.pop(project_id, None)
        self._planner_approval_events.pop(project_id, None)
        self._tool_approval_events.pop(project_id, None)
        try:
            task.result()
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("scan_orchestrator_task_crashed", project_id=project_id, error=repr(exc))

    async def _run_scan(
        self,
        *,
        project_id: str,
        scan_id: str,
        target: str,
        target_type: str,
        started_at: str,
        info: str,
    ) -> None:
        logger.info(
            "scan_orchestrator_start",
            project_id=project_id,
            scan_id=scan_id,
            target_type=target_type,
            target=target,
        )
        self._emit_event(
            project_id,
            event="intel_started",
            scan_id=scan_id,
            level="info",
            message=f"Intel [start] agent started for target type '{target_type}'.",
            data={"stage": "intel", "status": "running", "kind": "start"},
        )

        try:
            # Lazy import avoids loading heavy agent modules at app boot.
            from server.agents.intel.agent import IntelAgent

            print_steps = _is_truthy_env("INTEL_PRINT_STEPS", "1")
            callback = PrintCallback(
                enabled=print_steps,
                on_log=lambda level, message: self._emit_intel_callback_event(
                    project_id=project_id,
                    scan_id=scan_id,
                    level=level,
                    raw_message=message,
                ),
            )
            intel_agent = IntelAgent(callback=callback)
            intel_result = await intel_agent.run(
                target_type=target_type,
                info=info,
            )
        except asyncio.CancelledError:
            current = self._runs.get(project_id, {})
            if str(current.get("status")) in {"paused", "idle"}:
                logger.info("scan_orchestrator_cancelled", project_id=project_id, scan_id=scan_id)
                return
            self._mark_failed(project_id, scan_id, "scan cancelled")
            return
        except Exception as exc:
            self._emit_event(
                project_id,
                event="intel_crashed",
                scan_id=scan_id,
                level="error",
                message=f"Intel [crashed] {exc}",
                data={
                    "stage": "intel",
                    "kind": "crashed",
                    "error": str(exc),
                },
            )
            self._mark_failed(project_id, scan_id, f"intel runtime error: {exc}")
            return

        intel_summary = intel_result.summary
        intel_status = intel_result.status
        intel_stats: dict[str, Any] = intel_result.stats
        intel_checklist = intel_result.checklist if isinstance(intel_result.checklist, dict) else {}
        checklist_items_count = _count_checklist_items(intel_checklist)
        self._emit_event(
            project_id,
            event="intel_complete",
            scan_id=scan_id,
            level="success",
            message="Intel [completed] agent completed successfully.",
            data={
                "stage": "intel",
                "kind": "completed",
                "intel_status": intel_status,
                "summary_length": len(intel_summary),
                # Keep full intel summary in event cache so UI can rehydrate
                # agent result after reload, and clear it with event cache.
                "summary": intel_summary,
                "checklist": intel_checklist,
                "checklist_items_count": checklist_items_count,
            },
        )

        scope_text = ""
        for raw_line in info.splitlines():
            if raw_line.lower().startswith("scope:"):
                scope_text = raw_line.split(":", 1)[1].strip()
                break

        partial_intel_scan_meta = {
            "scanId": scan_id,
            "status": "awaiting_planner_approval",
            "startedAt": started_at,
            "finishedAt": None,
            "error": "",
            "awaitingPlannerApproval": True,
            "result": {
                "target": target,
                "targetType": target_type,
                "intel": {
                    "status": intel_status,
                    "summary": intel_summary,
                    "stats": intel_stats,
                    "checklist": intel_checklist,
                },
            },
        }
        self._persist_project_status(
            project_id,
            status="running",
            scan_progress=60,
            scan_meta=partial_intel_scan_meta,
        )

        run_state = self._runs.get(project_id)
        if isinstance(run_state, dict):
            run_state["awaiting_planner_approval"] = True
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_id] = run_state

        gate = asyncio.Event()
        self._planner_approval_events[project_id] = gate
        self._emit_event(
            project_id,
            event="planner_waiting_approval",
            scan_id=scan_id,
            level="warn",
            message=(
                "Planner [waiting approval] Intel checklist is ready. "
                "Review/edit checklist, then click Continue to Planner."
            ),
            data={
                "stage": "planner",
                "kind": "waiting_approval",
                "status": "running",
                "awaiting_user_approval": True,
                "checklist_items_count": checklist_items_count,
            },
        )
        logger.info(
            "scan_orchestrator_waiting_planner_approval",
            project_id=project_id,
            scan_id=scan_id,
            checklist_items_count=checklist_items_count,
        )

        try:
            await gate.wait()
        except asyncio.CancelledError:
            current = self._runs.get(project_id, {})
            if str(current.get("status")) in {"paused", "idle"}:
                logger.info("scan_orchestrator_cancelled", project_id=project_id, scan_id=scan_id)
                return
            self._mark_failed(project_id, scan_id, "scan cancelled")
            return
        finally:
            self._planner_approval_events.pop(project_id, None)

        run_state = self._runs.get(project_id)
        if isinstance(run_state, dict):
            run_state["awaiting_planner_approval"] = False
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_id] = run_state

        latest_project = self._projects_store.get_project(project_id)
        if isinstance(latest_project, dict):
            latest_last_scan = latest_project.get("lastScan")
            if isinstance(latest_last_scan, dict):
                latest_result = latest_last_scan.get("result")
                if isinstance(latest_result, dict):
                    latest_intel = latest_result.get("intel")
                    if isinstance(latest_intel, dict):
                        latest_checklist = latest_intel.get("checklist")
                        if isinstance(latest_checklist, dict):
                            intel_checklist = latest_checklist
                            checklist_items_count = _count_checklist_items(intel_checklist)

        self._persist_project_status(
            project_id,
            status="running",
            scan_progress=70,
            scan_meta={
                "scanId": scan_id,
                "status": "running",
                "startedAt": started_at,
                "finishedAt": None,
                "error": "",
                "awaitingPlannerApproval": False,
                "result": {
                    "target": target,
                    "targetType": target_type,
                    "intel": {
                        "status": intel_status,
                        "summary": intel_summary,
                        "stats": intel_stats,
                        "checklist": intel_checklist,
                    },
                },
            },
        )

        planner_input = _build_planner_kickoff_message(
            target=target,
            target_type=target_type,
            scope=scope_text,
            info=info,
            intel_status=intel_status,
            intel_vulnerabilities=list(intel_result.vulnerabilities),
            intel_stats=intel_stats,
            checklist_overview={
                "target_type": str(intel_checklist.get("target_type", "") or target_type),
                "available_total": int(intel_checklist.get("available_total", 0) or 0),
                "items_count": checklist_items_count,
            },
        )
        self._emit_event(
            project_id,
            event="planner_started",
            scan_id=scan_id,
            level="info",
            message="Planner [start] agent started to build pentest plan.",
            data={"stage": "planner", "status": "running", "kind": "start"},
        )

        try:
            from server.agents.planner.agent import PlannerAgent
            from server.agents.planner.tools.pentest_plan import _current_plan, _reset_plan

            planner_callback = PrintCallback(
                enabled=print_steps,
                on_log=lambda level, message: self._emit_planner_callback_event(
                    project_id=project_id,
                    scan_id=scan_id,
                    level=level,
                    raw_message=message,
                ),
            )
            async with PlannerAgent(callback=planner_callback) as planner_agent:
                _reset_plan()
                planner_result = await planner_agent.run(
                    planner_input,
                    is_loop=False,
                    intel_checklist=intel_checklist,
                )
                plan_data = dict(_current_plan) if isinstance(_current_plan, dict) else {}
        except asyncio.CancelledError:
            current = self._runs.get(project_id, {})
            if str(current.get("status")) in {"paused", "idle"}:
                logger.info("scan_orchestrator_cancelled", project_id=project_id, scan_id=scan_id)
                return
            self._mark_failed(project_id, scan_id, "scan cancelled")
            return
        except Exception as exc:
            self._emit_event(
                project_id,
                event="planner_crashed",
                scan_id=scan_id,
                level="error",
                message=f"Planner [crashed] {exc}",
                data={
                    "stage": "planner",
                    "kind": "crashed",
                    "error": str(exc),
                },
            )
            self._mark_failed(project_id, scan_id, f"planner runtime error: {exc}")
            return

        planner_summary = str(planner_result.summary or "").strip()
        planner_summary_lower = planner_summary.lower()
        plan_phases = plan_data.get("phases", [])
        plan_phase_count = len(plan_phases) if isinstance(plan_phases, list) else 0
        planner_failed = planner_summary_lower.startswith("planning failed:")
        if planner_failed:
            failure_reason = planner_summary or "planner did not persist a valid plan"
            self._emit_event(
                project_id,
                event="planner_failed",
                scan_id=scan_id,
                level="warn",
                message=f"Planner [failed] {failure_reason}",
                data={
                    "stage": "planner",
                    "kind": "failed",
                    "summary": planner_summary,
                    "plan_phase_count": plan_phase_count,
                },
            )
            self._mark_failed(project_id, scan_id, f"planner failed: {failure_reason}")
            return

        if plan_phase_count <= 0:
            self._emit_event(
                project_id,
                event="planner_incomplete",
                scan_id=scan_id,
                level="warn",
                message=(
                    "Planner [warn] No persisted plan phases; "
                    "continuing with checklist-only summary."
                ),
                data={
                    "stage": "planner",
                    "kind": "incomplete",
                    "summary": planner_summary,
                    "plan_phase_count": 0,
                },
            )

        self._emit_event(
            project_id,
            event="planner_complete",
            scan_id=scan_id,
            level="success",
            message="Planner [completed] agent completed successfully.",
            data={
                "stage": "planner",
                "kind": "completed",
                "summary_length": len(planner_summary),
                "scenario_count": len(planner_result.scenarios),
                "needs_count": len(planner_result.needs),
                "checklist_updates_count": len(
                    planner_result.action_plan.get("checklist_updates", [])
                    if isinstance(planner_result.action_plan, dict)
                    else []
                ),
                "checklist_additions_count": len(
                    planner_result.action_plan.get("checklist_additions", [])
                    if isinstance(planner_result.action_plan, dict)
                    else []
                ),
                "plan_phase_count": plan_phase_count,
                "summary": planner_result.summary,
                "scenarios": planner_result.scenarios,
                "needs": planner_result.needs,
                "action_plan": planner_result.action_plan,
                "plan_data": plan_data,
            },
        )

        finished_at = _utc_now_iso()

        scan_meta = {
            "scanId": scan_id,
            "status": "completed",
            "startedAt": started_at,
            "finishedAt": finished_at,
            "error": "",
            "result": {
                "target": target,
                "targetType": target_type,
                "intel": {
                    "status": intel_status,
                    "summary": intel_summary,
                    "stats": intel_stats,
                    "checklist": intel_checklist,
                },
                "planner": {
                    "summary": str(planner_result.summary),
                    "scenarios": list(planner_result.scenarios),
                    "needs": list(planner_result.needs),
                    "action_plan": (
                        dict(planner_result.action_plan)
                        if isinstance(planner_result.action_plan, dict)
                        else {}
                    ),
                    "plan_data": plan_data,
                },
            },
        }

        self._runs[project_id] = {
            "scan_id": scan_id,
            "project_id": project_id,
            "status": "completed",
            "started_at": started_at,
            "updated_at": finished_at,
            "finished_at": finished_at,
            "error": "",
            "awaiting_planner_approval": False,
            "awaiting_tool_approval": False,
            "pending_tool_approval": None,
            "already_running": False,
        }
        self._persist_project_status(
            project_id,
            status="completed",
            scan_progress=100,
            scan_meta=scan_meta,
        )
        self._emit_event(
            project_id,
            event="scan_completed",
            scan_id=scan_id,
            level="success",
            message="Scan completed successfully.",
            data={"status": "completed", "scan_progress": 100},
        )
        logger.info("scan_orchestrator_complete", project_id=project_id, scan_id=scan_id)

    def _mark_failed(
        self,
        project_id: str,
        scan_id: str,
        error_message: str,
        *,
        finished_at: str | None = None,
    ) -> None:
        finish_time = finished_at or _utc_now_iso()
        logger.warning(
            "scan_orchestrator_failed",
            project_id=project_id,
            scan_id=scan_id,
            error=error_message,
        )
        self._runs[project_id] = {
            "scan_id": scan_id,
            "project_id": project_id,
            "status": "error",
            "started_at": self._runs.get(project_id, {}).get("started_at", finish_time),
            "updated_at": finish_time,
            "finished_at": finish_time,
            "error": error_message,
            "awaiting_planner_approval": False,
            "awaiting_tool_approval": False,
            "pending_tool_approval": None,
            "already_running": False,
        }
        self._persist_project_status(
            project_id,
            status="error",
            scan_progress=0,
            scan_meta={
                "scanId": scan_id,
                "status": "error",
                "finishedAt": finish_time,
                "error": error_message,
            },
        )
        self._emit_event(
            project_id,
            event="scan_failed",
            scan_id=scan_id,
            level="warn",
            message=f"Scan failed: {error_message}",
            data={"status": "error", "scan_progress": 0, "error": error_message},
        )

    def _persist_project_status(
        self,
        project_id: str,
        *,
        status: str,
        scan_progress: int,
        scan_meta: dict[str, Any],
    ) -> None:
        project = self._projects_store.get_project(project_id)
        if project is None:
            return

        project["status"] = status
        project["scanProgress"] = scan_progress
        project["updatedAt"] = _utc_now_iso()
        project["lastScan"] = scan_meta
        self._projects_store.upsert_project(project)
        self._emit_event(
            project_id,
            event="project_status",
            scan_id=str(scan_meta.get("scanId", "")),
            level="warn" if status == "error" else "success" if status == "completed" else "info",
            message=f"Project status updated to {status}.",
            data={
                "status": status,
                "scan_progress": scan_progress,
            },
        )
