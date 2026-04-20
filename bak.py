"""App-level scan orchestrator service.

This service is the API entrypoint for scan execution:
1. Resolve project details from storage
2. Run Intel Agent to produce pentest checklist intelligence
3. Run Planner Agent to build/store the initial pentest plan
4. Persist scan lifecycle/status back to the project record
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Callable

import structlog

from server.db.projects import ProjectsStore
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore

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


def _coerce_priority(value: Any) -> int | None:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= p <= 5:
        return p
    return None


def _normalize_priority(value: Any) -> int:
    parsed = _coerce_priority(value)
    return parsed if parsed is not None else 3


def _extract_prioritized_exec_scenarios(
    plan_data: dict[str, Any],
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    phases = plan_data.get("phases", [])
    if not isinstance(phases, list):
        return []

    indexed: list[tuple[int, int, int, int, dict[str, Any]]] = []
    for phase_idx, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue
        phase_name = str(phase.get("name", "")).strip()
        steps = phase.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            step_id = str(step.get("id", "")).strip()
            scenarios = step.get("scenarios", [])
            if not isinstance(scenarios, list):
                continue
            for scen_idx, scenario in enumerate(scenarios):
                if not isinstance(scenario, dict):
                    continue
                if bool(scenario.get("done", False)):
                    continue
                agent = str(scenario.get("agent", "")).strip().lower()
                if agent not in {"recon", "exploit"}:
                    continue
                priority = _normalize_priority(scenario.get("priority", 3))
                enriched = dict(scenario)
                enriched["priority"] = priority
                enriched["agent"] = agent
                enriched["_phase"] = phase_name
                enriched["_step_id"] = step_id
                enriched["_phase_index"] = phase_idx
                enriched["_step_index"] = step_idx
                enriched["_scenario_index"] = scen_idx
                indexed.append((priority, phase_idx, step_idx, scen_idx, enriched))

    indexed.sort(key=lambda row: (row[0], row[1], row[2], row[3]))
    return [row[4] for row in indexed[: max(0, int(limit))]]


def _select_recon_exploit_parallel_scenarios(plan_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Pick at most one recon and one exploit scenario (highest priority each)."""
    candidates = _extract_prioritized_exec_scenarios(plan_data, limit=50)
    best_recon: dict[str, Any] | None = None
    best_exploit: dict[str, Any] | None = None

    for scenario in candidates:
        role = str(scenario.get("agent", "")).strip().lower()
        if role == "recon" and best_recon is None:
            best_recon = scenario
        elif role == "exploit" and best_exploit is None:
            best_exploit = scenario
        if best_recon is not None and best_exploit is not None:
            break

    selected = [s for s in [best_recon, best_exploit] if isinstance(s, dict)]
    selected.sort(key=lambda s: _normalize_priority(s.get("priority", 3)))
    return selected


def _mark_scenario_done_in_plan(plan_data: dict[str, Any], scenario: dict[str, Any]) -> bool:
    """Mark a scenario as done in plan_data using stored indexes (fallback to matching)."""
    phases = plan_data.get("phases")
    if not isinstance(phases, list):
        return False

    phase_idx = scenario.get("_phase_index")
    step_idx = scenario.get("_step_index")
    scen_idx = scenario.get("_scenario_index")
    if isinstance(phase_idx, int) and isinstance(step_idx, int) and isinstance(scen_idx, int):
        try:
            target = phases[phase_idx]["steps"][step_idx]["scenarios"][scen_idx]
            if isinstance(target, dict):
                target["done"] = True
                target["status"] = "completed"
                return True
        except (IndexError, KeyError, TypeError):
            pass

    target_task = str(scenario.get("task", "")).strip().lower()
    target_agent = str(scenario.get("agent", "")).strip().lower()
    target_priority = _normalize_priority(scenario.get("priority", 3))
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios")
            if not isinstance(scenarios, list):
                continue
            for item in scenarios:
                if not isinstance(item, dict):
                    continue
                if bool(item.get("done", False)):
                    continue
                task = str(item.get("task", "")).strip().lower()
                agent = str(item.get("agent", "")).strip().lower()
                priority = _normalize_priority(item.get("priority", 3))
                if task == target_task and agent == target_agent and priority == target_priority:
                    item["done"] = True
                    item["status"] = "completed"
                    return True
    return False


def _normalize_scenario_status(value: Any, *, done: bool = False) -> str:
    if done:
        return "completed"
    normalized = str(value or "").strip().lower()
    if normalized in {"completed", "complete", "done"}:
        return "completed"
    if normalized in {"working", "running", "in_progress", "in progress"}:
        return "working"
    return "not yet"


def _normalize_round_label(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("r") and raw[1:].isdigit():
        return raw
    if raw.isdigit():
        return f"r{raw}"
    return ""


def _locate_scenario_in_plan(plan_data: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any] | None:
    phases = plan_data.get("phases")
    if not isinstance(phases, list):
        return None

    phase_idx = scenario.get("_phase_index")
    step_idx = scenario.get("_step_index")
    scen_idx = scenario.get("_scenario_index")
    if isinstance(phase_idx, int) and isinstance(step_idx, int) and isinstance(scen_idx, int):
        try:
            target = phases[phase_idx]["steps"][step_idx]["scenarios"][scen_idx]
            if isinstance(target, dict):
                return target
        except (IndexError, KeyError, TypeError):
            pass

    target_task = str(scenario.get("task", "")).strip().lower()
    target_agent = str(scenario.get("agent", "")).strip().lower()
    target_priority = _normalize_priority(scenario.get("priority", 3))
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios")
            if not isinstance(scenarios, list):
                continue
            for item in scenarios:
                if not isinstance(item, dict):
                    continue
                task = str(item.get("task", "")).strip().lower()
                agent = str(item.get("agent", "")).strip().lower()
                priority = _normalize_priority(item.get("priority", 3))
                if task == target_task and agent == target_agent and priority == target_priority:
                    return item
    return None


def _update_scenario_runtime_state(
    plan_data: dict[str, Any],
    scenario: dict[str, Any],
    *,
    status: str | None = None,
    done: bool | None = None,
    round_label: str | None = None,
    round_labels: list[str] | None = None,
    route: str | None = None,
) -> bool:
    target = _locate_scenario_in_plan(plan_data, scenario)
    if not isinstance(target, dict):
        return False

    effective_done = bool(done) if done is not None else bool(target.get("done", False))
    if status is not None:
        target["status"] = _normalize_scenario_status(status, done=effective_done)
    elif "status" not in target:
        target["status"] = _normalize_scenario_status(target.get("status"), done=effective_done)

    if done is not None:
        target["done"] = bool(done)
        if bool(done):
            target["status"] = "completed"

    normalized_round_label = _normalize_round_label(round_label)
    if normalized_round_label:
        target["last_round"] = normalized_round_label

    if isinstance(round_labels, list) and round_labels:
        normalized_rounds = [
            label
            for label in (_normalize_round_label(item) for item in round_labels)
            if label
        ]
        if normalized_rounds:
            target["rounds_seen"] = normalized_rounds
            target["last_round"] = normalized_rounds[-1]

    if route:
        target["last_route"] = str(route).strip().lower()

    return True


def _sanitize_plan_remove_forbidden_agents(plan_data: dict[str, Any]) -> dict[str, Any]:
    """Remove any scenarios with forbidden agents (verify, retest, perceptor) from plan.

    Returns cleaned plan_data with only recon/exploit/report scenarios.
    """
    if not isinstance(plan_data, dict):
        return plan_data

    FORBIDDEN_AGENTS = {"verify", "retest", "perceptor"}
    cleaned_plan = dict(plan_data)
    phases = cleaned_plan.get("phases", [])

    if not isinstance(phases, list):
        return cleaned_plan

    for phase in phases:
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios", [])
            if not isinstance(scenarios, list):
                continue

            # Filter out forbidden agents
            cleaned_scenarios = [
                s for s in scenarios
                if isinstance(s, dict) and s.get("agent", "").strip().lower() not in FORBIDDEN_AGENTS
            ]

            if len(cleaned_scenarios) != len(scenarios):
                step["scenarios"] = cleaned_scenarios

    return cleaned_plan


async def _batch_verify_findings(
    findings: list[dict[str, Any]],
    verify_agent: Any,
    target: str,
    target_type: str,
    scope: str,
) -> list[dict[str, Any]]:
    """Verify all findings in parallel (not sequential per-finding).

    Returns list of dicts with verdict, verify_data, compact_summary for each finding.
    """
    verified = []

    # Build all verify tasks
    verify_tasks = []
    for finding in findings:
        scenario = finding.get("scenario", {})
        compact_summary = str(finding.get("compact_summary", "")).strip()
        row = finding.get("execution_row", {})

        verify_message = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"Original scenario: {json.dumps(scenario, ensure_ascii=True)}\n\n"
            "Finding to verify:\n"
            f"{compact_summary}\n\n"
            "Execution row:\n"
            f"{json.dumps(row, ensure_ascii=True)}"
        )
        verify_tasks.append((finding, verify_agent.run(verify_message)))

    # Run all verify agents in parallel
    if verify_tasks:
        results = await asyncio.gather(
            *[task for _, task in verify_tasks],
            return_exceptions=True
        )

        for (finding, _), result in zip(verify_tasks, results):
            if isinstance(result, Exception):
                verdict = "inconclusive"
                verify_data = {"error": str(result), "verdict": "inconclusive"}
            else:
                # Convert ExecuterResult to dict
                verify_data = asdict(result) if hasattr(result, '__dataclass_fields__') else result
                verdict = str(verify_data.get("verdict", verify_data.get("summary", "inconclusive"))).strip().lower()

            verified.append({
                "finding": finding,
                "verdict": verdict,
                "verify_data": verify_data,
                "compact_summary": str(finding.get("compact_summary", "")).strip(),
            })

    return verified


def _route_followup_from_assessment(assessment: dict[str, Any]) -> str:
    """Route perceptor assessment to appropriate next phase: verify, planner, or skip.

    Args:
        assessment: Perceptor assessment with finding_type and overall.ssvc fields

    Returns:
        str: "verify" (gate findings), "planner" (info/recon), or "skip"
    """
    finding_type = assessment.get("finding_type", "").strip().lower()

    # Vulnerabilities go to verify (gate to filter false positives)
    if "vulnerability" in finding_type or finding_type in {"vuln", "vulnerability"}:
        return "verify"

    # Info-only findings go to planner (update plan with evidence)
    if "info" in finding_type or finding_type in {"recon", "info_only", "information", "enumeration"}:
        return "planner"

    # Unknown types default to planner
    return "planner"


def _organize_findings_by_verdict(
    verified_findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Organize findings by verdict type for routing.

    Returns: {"real_vulnerability": [...], "false_positive": [...], "inconclusive": [...], "info_only": [...]}
    """
    organized = {
        "real_vulnerability": [],
        "false_positive": [],
        "inconclusive": [],
        "info_only": [],
    }

    for verified in verified_findings:
        finding = verified.get("finding", {})
        finding_type = str(finding.get("finding_type", "info")).strip().lower()
        verdict = verified.get("verdict", "inconclusive")

        # Route based on finding_type + verdict
        if finding_type == "vulnerability":
            if verdict == "real_vulnerability":
                organized["real_vulnerability"].append(verified)
            elif verdict == "false_positive":
                organized["false_positive"].append(verified)
            else:
                organized["inconclusive"].append(verified)
        else:
            # Info findings don't go to verify, just to planner
            organized["info_only"].append(verified)

    return organized
    overall = assessment.get("overall", {}) if isinstance(assessment, dict) else {}
    if not isinstance(overall, dict):
        return "planner"
    ssvc = str(overall.get("ssvc", "TRACK")).strip().upper()
    confidence = str(overall.get("confidence", "low")).strip().lower()

    if ssvc == "ACT":
        return "verify"
    if ssvc == "ATTEND" and confidence in {"medium", "high"}:
        return "retest"
    return "planner"


def _extract_failed_execution_rows(
    execution_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    failed: list[dict[str, Any]] = []
    for row in execution_rows:
        if not isinstance(row, dict):
            continue
        result = row.get("result")
        if not isinstance(result, dict):
            continue
        status = str(result.get("status", "")).strip().lower()
        if status in {"failed", "error"}:
            failed.append(row)
    return failed


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


class ExecuterScanCallback:
    """Executer callback bridged to scan event bus + approval workflow."""

    def __init__(
        self,
        *,
        service: "ScanOrchestratorService",
        project_id: str,
        scan_id: str,
        enabled: bool = True,
    ) -> None:
        self._service = service
        self._project_id = project_id
        self._scan_id = scan_id
        self._enabled = enabled
        self._start = time.perf_counter()

    def _ts(self) -> str:
        return f"[{time.perf_counter() - self._start:.1f}s]"

    def on_step(self, message: str) -> None:
        if self._enabled:
            print(f"  → {message} {self._ts()}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_step",
            scan_id=self._scan_id,
            level="info",
            message=f"Executer [step] {message}",
            data={"stage": "executer", "kind": "step", "raw_message": message},
        )

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  ✓ {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_done",
            scan_id=self._scan_id,
            level="success",
            message=f"Executer [done] {message}",
            data={"stage": "executer", "kind": "done", "raw_message": message},
        )

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ⚠ {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_warn",
            scan_id=self._scan_id,
            level="warn",
            message=f"Executer [warn] {message}",
            data={"stage": "executer", "kind": "warn", "raw_message": message},
        )

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        return await self._service.request_executer_tool_approval(
            project_id=self._project_id,
            scan_id=self._scan_id,
            role=role,
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )

    async def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        return await self._service.request_executer_password(
            project_id=self._project_id,
            scan_id=self._scan_id,
            tool_name="ssh",  # Default to ssh, can be extracted from prompt
            prompt=prompt,
            reason=reason,
            call_id=call_id,
        )


@dataclass
class _PendingToolApproval:
    scan_id: str
    role: str
    tool_name: str
    args: dict[str, Any]
    call_id: str
    event: asyncio.Event
    decision: str | None = None


@dataclass
class _PendingPasswordRequest:
    scan_id: str
    tool_name: str
    prompt: str
    reason: str
    call_id: str
    event: asyncio.Event
    password: str | None = None
    approved: bool = False


class ScanOrchestratorService:
    """Runs and tracks orchestrated scan executions per project."""

    def __init__(self, projects_store: ProjectsStore) -> None:
        self._projects_store = projects_store
        self._vector_store = QdrantVectorStore()
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._runs: dict[str, dict[str, Any]] = {}
        self._planner_approval_events: dict[str, asyncio.Event] = {}
        self._tool_approval_events: dict[str, dict[str, _PendingToolApproval]] = {}
        self._password_request_events: dict[str, dict[str, _PendingPasswordRequest]] = {}
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
                try:
                    self._projects_store.clear_project_context_windows(project_key)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "project_context_windows_clear_failed",
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
        project.pop("contextWindows", None)
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
        try:
            self._projects_store.clear_project_context_windows(project_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "project_context_windows_clear_failed",
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

        # Tools with long execution times need longer approval timeouts
        # Tool-specific timeouts: hydra/nuclei/sqlmap can take 10-20+ minutes
        TOOL_TIMEOUTS = {
            "hydra_bruteforce": 1800,      # 30 minutes - brute force takes time
            "nuclei_vuln_scan": 1200,      # 20 minutes - template scanning
            "sqlmap": 1200,                # 20 minutes - SQL injection testing
            "run_custom": 900,             # 15 minutes - generic CLI commands
            "run_python": 600,             # 10 minutes - Python scripts
        }
        # OPTIMIZATION: Default to 60 seconds for approval timeout (was 1800s/30min)
        # This prevents artificial delays while keeping tool-specific longer timeouts
        APPROVAL_TIMEOUT = TOOL_TIMEOUTS.get(pending.tool_name, 60)

        try:
            # Wait with heartbeat messages every 60 seconds to keep connection alive
            start_time = time.time()
            HEARTBEAT_INTERVAL = 60  # Send keepalive every 60 seconds
            next_heartbeat = start_time + HEARTBEAT_INTERVAL

            while not pending.event.is_set():
                remaining = APPROVAL_TIMEOUT - (time.time() - start_time)
                if remaining <= 0:
                    raise asyncio.TimeoutError()

                # Wait for event or heartbeat interval, whichever is shorter
                wait_time = min(HEARTBEAT_INTERVAL, remaining)
                try:
                    await asyncio.wait_for(pending.event.wait(), timeout=wait_time)
                    break  # Event was set, exit loop
                except asyncio.TimeoutError:
                    # Check if total timeout exceeded
                    if time.time() - start_time >= APPROVAL_TIMEOUT:
                        raise
                    # Send keepalive message
                    elapsed = int(time.time() - start_time)
                    self._emit_event(
                        project_key,
                        event="executer_tool_approval_waiting",
                        scan_id=pending.scan_id,
                        level="info",
                        message=(
                            f"Executer [approval waiting] {pending.role} tool '{pending.tool_name}' "
                            f"waiting for approval... ({elapsed}s/{APPROVAL_TIMEOUT}s)"
                        ),
                        data={
                            "stage": "executer",
                            "kind": "tool_approval_waiting",
                            "approval_id": approval_id,
                            "role": pending.role,
                            "tool_name": pending.tool_name,
                            "elapsed_seconds": elapsed,
                            "timeout_seconds": APPROVAL_TIMEOUT,
                        },
                    )
                    continue

        except asyncio.TimeoutError:
            # Timeout - auto-skip the tool
            pending.decision = "skip"
            logger.warning(
                "tool_approval_timeout",
                project_id=project_key,
                approval_id=approval_id,
                tool_name=pending.tool_name,
                timeout_seconds=APPROVAL_TIMEOUT,
            )
            self._emit_event(
                project_key,
                event="executer_tool_approval_timeout",
                scan_id=pending.scan_id,
                level="warn",
                message=(
                    f"Executer [approval timeout] {pending.role} tool '{pending.tool_name}' "
                    f"timeout after {APPROVAL_TIMEOUT}s - skipping tool"
                ),
                data={
                    "stage": "executer",
                    "kind": "tool_approval_timeout",
                    "approval_id": approval_id,
                    "role": pending.role,
                    "tool_name": pending.tool_name,
                    "call_id": pending.call_id,
                    "timeout_seconds": APPROVAL_TIMEOUT,
                },
            )

        approved = pending.decision == "approve"

        project_pending = self._tool_approval_events.get(project_key, {})
        project_pending.pop(approval_id, None)
        if not project_pending:
            self._tool_approval_events.pop(project_key, None)

        run_state = self._runs.get(project_key)
        if isinstance(run_state, dict):
            if project_pending:
                next_id, next_pending = next(iter(project_pending.items()))
                run_state["awaiting_tool_approval"] = True
                run_state["pending_tool_approval"] = {
                    "approval_id": next_id,
                    "scan_id": next_pending.scan_id,
                    "role": next_pending.role,
                    "tool_name": next_pending.tool_name,
                    "call_id": next_pending.call_id,
                }
            else:
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
        """Request password from user for tools like SSH/sudo."""
        project_key = str(project_id or "").strip()
        if not project_key:
            return None

        password_id = str(uuid.uuid4())
        pending = _PendingPasswordRequest(
            scan_id=str(scan_id or ""),
            tool_name=str(tool_name or ""),
            prompt=str(prompt or ""),
            reason=str(reason or ""),
            call_id=str(call_id or ""),
            event=asyncio.Event(),
        )
        project_pending = self._password_request_events.setdefault(project_key, {})
        project_pending[password_id] = pending

        # Emit password request event to frontend
        self._emit_event(
            project_key,
            event="executer_password_request",
            scan_id=pending.scan_id,
            level="info",
            message=f"Executer [password required] {pending.tool_name} needs authentication",
            data={
                "stage": "executer",
                "kind": "password_request",
                "tool_name": pending.tool_name,
                "prompt": pending.prompt,
                "reason": pending.reason,
                "call_id": pending.call_id,
                "password_id": password_id,
            },
        )

        # Wait for password response with generous timeout and heartbeat
        PASSWORD_TIMEOUT = 600  # 10 minutes - user needs time to enter password
        try:
            start_time = time.time()
            HEARTBEAT_INTERVAL = 30  # Send keepalive every 30 seconds

            while not pending.event.is_set():
                remaining = PASSWORD_TIMEOUT - (time.time() - start_time)
                if remaining <= 0:
                    raise asyncio.TimeoutError()

                wait_time = min(HEARTBEAT_INTERVAL, remaining)
                try:
                    await asyncio.wait_for(pending.event.wait(), timeout=wait_time)
                    break  # Event was set, exit loop
                except asyncio.TimeoutError:
                    # Check if total timeout exceeded
                    if time.time() - start_time >= PASSWORD_TIMEOUT:
                        raise
                    # Send keepalive message
                    elapsed = int(time.time() - start_time)
                    self._emit_event(
                        project_key,
                        event="executer_password_waiting",
                        scan_id=pending.scan_id,
                        level="info",
                        message=(
                            f"Executer [password waiting] {pending.tool_name} "
                            f"waiting for password input... ({elapsed}s/{PASSWORD_TIMEOUT}s)"
                        ),
                        data={
                            "stage": "executer",
                            "kind": "password_waiting",
                            "password_id": password_id,
                            "tool_name": pending.tool_name,
                            "elapsed_seconds": elapsed,
                            "timeout_seconds": PASSWORD_TIMEOUT,
                        },
                    )
                    continue

        except asyncio.TimeoutError:
            logger.warning(
                "password_request_timeout",
                project_id=project_key,
                password_id=password_id,
                tool_name=pending.tool_name,
                timeout_seconds=PASSWORD_TIMEOUT,
            )
            self._emit_event(
                project_key,
                event="executer_password_timeout",
                scan_id=pending.scan_id,
                level="warn",
                message=f"Password request timed out after {PASSWORD_TIMEOUT}s",
                data={
                    "stage": "executer",
                    "kind": "password_timeout",
                    "tool_name": pending.tool_name,
                    "timeout_seconds": PASSWORD_TIMEOUT,
                },
            )
            project_pending = self._password_request_events.get(project_key, {})
            project_pending.pop(password_id, None)
            return None

        # Clean up
        project_pending = self._password_request_events.get(project_key, {})
        project_pending.pop(password_id, None)
        if not project_pending:
            self._password_request_events.pop(project_key, None)

        return pending.password if pending.approved else None

    async def approve_executer_password(
        self,
        project_id: str,
        *,
        password_id: str,
        password: str,
        approved: bool = True,
    ) -> dict[str, Any]:
        """Handle password response from frontend."""
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        pending_by_id = self._password_request_events.get(project_key, {})
        pending = pending_by_id.get(str(password_id or "").strip())
        if pending is None:
            raise ValueError("password request not found")

        pending.approved = approved
        pending.password = password if approved else None
        pending.event.set()

        return {
            "ok": True,
            "project_id": project_key,
            "password_id": password_id,
            "approved": approved,
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

    def _build_executer_message(
        self,
        *,
        scenario: dict[str, Any],
        target: str,
        target_type: str,
        scope: str,
        info: str,
    ) -> str:
        return (
            f"Scenario: {str(scenario.get('task', '')).strip()}\n"
            f"Agent: {str(scenario.get('agent', '')).strip()}\n"
            f"Priority: {_normalize_priority(scenario.get('priority', 3))}\n"
            f"Details: {str(scenario.get('details', '')).strip()}\n"
            f"Methods: {json.dumps(scenario.get('methods', []), ensure_ascii=True)}\n"
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"Extra info: {info}\n"
        )

    async def _run_retest_background(
        self,
        *,
        item: dict[str, Any],
        retest_agent: Any,
        retest_message: str,
        project_id: str,
        scan_id: str,
        target: str,
        target_type: str,
    ) -> None:
        """Run Retest agent in background and save findings to database.

        This method runs independently and does NOT block other operations.
        - Takes verified vulnerability description
        - Executes PoC to gather evidence
        - Saves report entry to project database
        - Emits event for UI
        """
        try:
            # Run retest agent (takes screenshot + detailed PoC)
            retest_result = await retest_agent.run(retest_message)

            # Build database entry from retest result
            retest_summary = str(retest_result.summary or "").strip()
            retest_data = (
                asdict(retest_result)
                if hasattr(retest_result, '__dataclass_fields__')
                else retest_result
            )

            db_entry = {
                "id": str(uuid.uuid4()),
                "vulnerability_type": item["scenario"].get("vulnerability_type", "unknown"),
                "endpoint": item["scenario"].get("endpoint", ""),
                "target": target,
                "target_type": target_type,
                "severity": item["scenario"].get("priority", "medium"),
                "verify_summary": item["verify_summary"],
                "retest_summary": retest_summary,
                "evidence": retest_data.get("evidence", {}),
                "findings": retest_data.get("findings", []),
                "tool_results": retest_data.get("tool_results", []),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "verified_and_documented",
            }

            # Save to project database
            project_key = str(project_id or "").strip()
            current_project = self._projects_store.get_project(project_key)

            if "findings" not in current_project:
                current_project["findings"] = []
            if "verified_vulnerabilities" not in current_project:
                current_project["verified_vulnerabilities"] = []

            current_project["findings"].append(db_entry)
            current_project["verified_vulnerabilities"].append(db_entry)
            current_project["findings_count"] = len(current_project.get("findings", []))
            current_project["last_findings_updated"] = datetime.now(timezone.utc).isoformat()

            self._projects_store.upsert_project(current_project)

            # Emit event for UI
            self._emit_event(
                project_id,
                event="retest_finding_saved",
                scan_id=scan_id,
                level="info",
                message=f"Saved verified finding: {item['verify_summary'][:80]}",
                data={
                    "stage": "retest",
                    "kind": "finding_saved",
                    "finding_id": db_entry["id"],
                    "vulnerability_type": db_entry["vulnerability_type"],
                    "endpoint": db_entry["endpoint"],
                    "retest_summary": retest_summary,
                },
            )

            logger.info(
                "retest_background_finding_saved",
                project_id=project_id,
                scan_id=scan_id,
                finding_id=db_entry["id"],
                vulnerability_type=db_entry["vulnerability_type"],
            )

        except Exception as e:
            logger.error(
                "retest_background_error",
                project_id=project_id,
                error=str(e),
            )
            self._emit_event(
                project_id,
                event="retest_finding_error",
                scan_id=scan_id,
                level="error",
                message=f"Retest failed: {str(e)[:100]}",
                data={
                    "stage": "retest",
                    "kind": "error",
                    "error": str(e),
                },
            )

    async def _execute_scenario_with_agent(
        self,
        *,
        scenario: dict[str, Any],
        recon_agent: Any,
        exploit_agent: Any,
        target: str,
        target_type: str,
        scope: str,
        info: str,
    ) -> dict[str, Any]:
        message = self._build_executer_message(
            scenario=scenario,
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
        )
        role = str(scenario.get("agent", "recon")).strip().lower()
        if role == "exploit":
            result = await exploit_agent.run(message)
        else:
            role = "recon"
            result = await recon_agent.run(message)
        return {
            "scenario": dict(scenario),
            "executor_agent": role,
            "result": {
                "status": result.status,
                "summary": result.summary,
                "findings": result.findings,
                "evidence": result.evidence,
                "needs": result.needs,
                "tool_results": result.tool_results,
                "discovered_target_types": result.discovered_target_types,
                "rounds_executed": result.rounds_executed,
                "round_labels": result.round_labels,
            },
        }

    async def _run_execution_cycle(
        self,
        *,
        project_id: str,
        scan_id: str,
        plan_data: dict[str, Any],
        recon_agent: Any,
        exploit_agent: Any,
        verify_agent: Any,
        retest_agent: Any,
        perceptor_agent: Any,
        loop_planner: Any,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        intel_checklist: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """
        Execute one full cycle: select scenarios → run parallel → perceptor decides → verify/retest/plan.

        Returns: (should_continue, updated_plan_data)
            should_continue=False means Planner said "done"
        """
        # Select at most 1 recon + 1 exploit from pending scenarios
        selected = _select_recon_exploit_parallel_scenarios(plan_data)

        # Log what scenarios were selected for debugging
        available_scenarios = _extract_prioritized_exec_scenarios(plan_data, limit=20)

        # Count total scenarios in plan
        total_scenarios = 0
        done_scenarios = 0
        phases = plan_data.get("phases", [])
        for phase in phases:
            if isinstance(phase, dict):
                for step in phase.get("steps", []):
                    if isinstance(step, dict):
                        for scenario in step.get("scenarios", []):
                            if isinstance(scenario, dict):
                                total_scenarios += 1
                                if scenario.get("done"):
                                    done_scenarios += 1

        logger.info(
            "execution_cycle_selection",
            total_scenarios_in_plan=total_scenarios,
            done_scenarios=done_scenarios,
            pending_scenarios=total_scenarios - done_scenarios,
            available_count=len(available_scenarios),
            selected_count=len(selected),
            selected_agents=[s.get("agent") for s in selected] if selected else [],
            available_agents=[s.get("agent") for s in available_scenarios] if available_scenarios else [],
        )

        if not selected:
            # No more scenarios - ask planner if done
            return await self._check_planner_completion(
                project_id=project_id,
                scan_id=scan_id,
                loop_planner=loop_planner,
                plan_data=plan_data,
                target=target,
                target_type=target_type,
                scope=scope,
                info=info,
                intel_checklist=intel_checklist,
            )

        # Mark selected scenarios as working and emit state change
        for scenario in selected:
            _update_scenario_runtime_state(
                plan_data,
                scenario,
                status="working",
                done=False,
            )
            self._emit_event(
                project_id,
                event="scenario_state_change",
                scan_id=scan_id,
                level="info",
                message=f"Scenario started execution: {scenario.get('task', 'unknown')}",
                data={
                    "stage": "executer",
                    "kind": "scenario_working",
                    "scenario_task": scenario.get("task", ""),
                    "agent": scenario.get("agent", ""),
                    "state": "working",
                    "plan_data": plan_data,
                },
            )

        # Run selected scenarios in parallel (true async with asyncio.gather)
        execution_rows: list[dict[str, Any]] = []
        if selected:
            results = await asyncio.gather(*[
                self._execute_scenario_with_agent(
                    scenario=scenario,
                    recon_agent=recon_agent,
                    exploit_agent=exploit_agent,
                    target=target,
                    target_type=target_type,
                    scope=scope,
                    info=info,
                )
                for scenario in selected
            ])
            execution_rows.extend(results)

        # ============================================================================
        # PHASE 1: Perceptor analyzes findings (SEQUENTIAL - Verify depends on this)
        # ============================================================================
        perceptor_rows: list[dict[str, Any]] = []
        planner_loop_rows: list[dict[str, Any]] = []

        # Organize findings by assessment type as we process them
        assessments_organized: dict[str, list[dict[str, Any]]] = {
            "vulnerabilities": [],  # Will be verified in Phase 2
            "info_only": [],        # Direct to planner in Phase 3
        }

        for idx, row in enumerate(execution_rows, start=1):
            row_result = row.get("result", {}) if isinstance(row, dict) else {}
            row_status = str(row_result.get("status", "")).strip().lower() if isinstance(row_result, dict) else ""

            # FIX: Process ALL rows including failed ones (classify failed as INFO)
            # Previously skipped failed rows entirely, causing Perceptor to never run
            # when both agents failed. This prevented proper assessment.

            scenario = row.get("scenario", {})
            tool_results = (
                row.get("result", {}).get("tool_results", [])
                if isinstance(row.get("result"), dict)
                else []
            )

            # Perceptor analyzes findings (sequential - required for Verify)
            assessment = await perceptor_agent.assess_tool_results(
                scenario=scenario if isinstance(scenario, dict) else {},
                tool_results=tool_results if isinstance(tool_results, list) else [],
                asset_context={
                    "criticality": (
                        "high"
                        if _normalize_priority((scenario or {}).get("priority", 3)) <= 2
                        else "medium"
                    ),
                    "internet_exposed": target_type in {"web_app", "api"},
                },
            )
            perceptor_rows.append(assessment)

            compact_summary = str(assessment.get("compact_summary", "")).strip()
            finding_type = str(assessment.get("finding_type", "info")).strip().lower()

            # CRITICAL FIX: If status is failed/error, force to info
            # This ensures failed execution results in info classification, not skipped
            if row_status in {"failed", "error"}:
                finding_type = "info"
                compact_summary = f"[FAILED] {scenario.get('description', 'Unknown')} - {row_result.get('error', 'No error message')}"

            # CRITICAL FIX: If parent agent (exploit) returned "not_vulnerable", downgrade to info
            # This prevents Verify from being called unnecessarily
            agent_role = str(scenario.get("agent", "")).strip().lower() if isinstance(scenario, dict) else ""
            if agent_role == "exploit" and row_status == "not_vulnerable":
                # Exploit agent explicitly said not vulnerable, override Perceptor classification
                finding_type = "info"

            # Emit perceptor_classified event
            self._emit_event(
                project_id,
                event="perceptor_classified",
                scan_id=scan_id,
                level="info",
                message=(
                    f"Perceptor [classified] scenario #{idx} → "
                    f"{assessment.get('overall', {}).get('ssvc', 'TRACK')} "
                    f"(type={finding_type})"
                ),
                data={
                    "stage": "perceptor",
                    "kind": "classified",
                    "iteration": idx,
                    "assessment": assessment,
                },
            )

            # Organize by type for batch processing
            if finding_type == "vulnerability":
                assessments_organized["vulnerabilities"].append({
                    "idx": idx,
                    "assessment": assessment,
                    "row": row,
                    "scenario": scenario,
                    "row_result": row_result,
                    "compact_summary": compact_summary,
                })
            else:
                assessments_organized["info_only"].append({
                    "idx": idx,
                    "assessment": assessment,
                    "row": row,
                    "scenario": scenario,
                    "row_result": row_result,
                    "compact_summary": compact_summary,
                })

        # ============================================================================
        # PHASE 2-3: Verify → Planner → Retest (WRAPPED IN EXCEPTION HANDLER)
        # ============================================================================
        verify_results_organized: dict[str, list[dict[str, Any]]] = {
            "real_vulnerabilities": [],
            "false_positives": [],
            "inconclusives": [],
        }

        try:
            logger.info(
                "phase2_verify_start",
                vulnerabilities_count=len(assessments_organized["vulnerabilities"]),
            )

            if assessments_organized["vulnerabilities"]:
                for verify_index, item in enumerate(
                    assessments_organized["vulnerabilities"],
                    start=1,
                ):
                    verify_agent.reset_context_window_for_cycle()
                    self._emit_event(
                        project_id,
                        event="verify_batch_progress",
                        scan_id=scan_id,
                        level="info",
                        message=(
                            f"Verify [batch] processing finding {verify_index}/"
                            f"{len(assessments_organized['vulnerabilities'])}."
                        ),
                        data={
                            "stage": "verify",
                            "kind": "batch_progress",
                            "current": verify_index,
                            "total": len(assessments_organized["vulnerabilities"]),
                            "scenario_task": str(item.get("scenario", {}).get("task", "")),
                        },
                    )

                    verify_message = (
                        f"Target: {target}\n"
                        f"Target type: {target_type}\n"
                        f"Scope: {scope}\n"
                        f"Original scenario: {json.dumps(item['scenario'], ensure_ascii=True)}\n\n"
                        "Finding to verify:\n"
                        f"{item['compact_summary']}\n\n"
                        "Execution row:\n"
                        f"{json.dumps(item['row'], ensure_ascii=True)}"
                    )

                    try:
                        verify_result = await verify_agent.run(verify_message)
                    except Exception as verify_exc:
                        logger.error(
                            "verify_task_exception",
                            task_index=verify_index - 1,
                            error=str(verify_exc),
                            error_type=type(verify_exc).__name__,
                        )
                        self._emit_event(
                            project_id,
                            event="verify_task_failed",
                            scan_id=scan_id,
                            level="warn",
                            message=f"Verify task {verify_index} failed: {str(verify_exc)[:100]}",
                            data={"task_index": verify_index - 1, "error": str(verify_exc)},
                        )
                        continue

                    try:
                        verify_data = asdict(verify_result) if hasattr(verify_result, '__dataclass_fields__') else verify_result

                        # CRITICAL FIX: Defensive verdict extraction with fallback mapping
                        # Handles: status=incomplete, verdict=..., summary=..., unknown fields
                        verdict = str(verify_data.get("verdict", "")).strip().lower()
                        status = str(verify_data.get("status", "")).strip().lower()
                        summary = str(verify_data.get("summary", "")).strip()

                        logger.warning(
                            "verify_result_raw",
                            item_idx=item["idx"],
                            verdict_field=verdict,
                            status_field=status,
                            summary_field=summary,
                            all_keys=list(verify_data.keys()) if isinstance(verify_data, dict) else [],
                        )

                        if not verdict:
                            if status in {"real_vulnerability", "false_positive", "inconclusive"}:
                                verdict = status
                            elif status in {"incomplete", "not_vulnerable", "unknown", "error"}:
                                verdict = "inconclusive"
                            else:
                                verdict = "inconclusive"

                        if not verdict:
                            verdict = "inconclusive"

                        if verdict not in {"real_vulnerability", "false_positive", "inconclusive"}:
                            logger.warning(
                                "verify_invalid_verdict",
                                item_idx=item["idx"],
                                original_verdict=verdict,
                                status=status,
                            )
                            self._emit_event(
                                project_id,
                                event="verify_warning",
                                scan_id=scan_id,
                                level="warn",
                                message=f"Verify returned unexpected verdict: {verdict} → inconclusive",
                                data={"original_verdict": verdict, "status": status},
                            )
                            verdict = "inconclusive"

                        logger.info(
                            "verify_verdict_assigned",
                            item_idx=item["idx"],
                            final_verdict=verdict,
                            from_status=status,
                        )

                        verify_summary = summary if summary else f"[{status}] Verification incomplete - treating as inconclusive"

                        organized_item = {
                            "idx": item["idx"],
                            "assessment": item["assessment"],
                            "row": item["row"],
                            "scenario": item["scenario"],
                            "row_result": item["row_result"],
                            "compact_summary": item["compact_summary"],
                            "verdict": verdict,
                            "verify_summary": verify_summary,
                            "verify_data": verify_data,
                        }

                        if verdict == "real_vulnerability":
                            verify_results_organized["real_vulnerabilities"].append(organized_item)
                        elif verdict == "false_positive":
                            verify_results_organized["false_positives"].append(organized_item)
                        else:
                            verify_results_organized["inconclusives"].append(organized_item)

                    except Exception as item_error:
                        logger.error(
                            "verify_result_processing_error",
                            item_idx=item.get("idx", "unknown"),
                            error=str(item_error),
                        )
                        verify_results_organized["inconclusives"].append({
                            "idx": item.get("idx", -1),
                            "verdict": "inconclusive",
                            "verify_summary": f"[ERROR] Verification processing failed: {str(item_error)[:100]}",
                            "verify_data": {},
                            "compact_summary": item.get("compact_summary", "Unknown"),
                        })

            # Log final verdict organization
            logger.info(
                "verify_batch_complete",
                real_vulns=len(verify_results_organized["real_vulnerabilities"]),
                false_positives=len(verify_results_organized["false_positives"]),
                inconclusives=len(verify_results_organized["inconclusives"]),
            )

        except Exception as phase2_exc:
            logger.error(
                "phase2_verify_batch_failed",
                error=str(phase2_exc),
                error_type=type(phase2_exc).__name__,
            )
            self._emit_event(
                project_id,
                event="verify_batch_error",
                scan_id=scan_id,
                level="warn",
                message=f"Verify batch processing failed: {str(phase2_exc)[:100]}",
                data={"error": str(phase2_exc)},
            )
            # Continue with empty results

        # ============================================================================
        # PHASE 3A: Launch Retest (PARALLEL - fire and forget)
        # PHASE 3B: Launch Planner (PARALLEL - immediate)
        # ============================================================================
        # Both run independently and concurrently

        # Create Retest tasks (fire-and-forget, non-blocking)
        retest_background_tasks = []
        if verify_results_organized["real_vulnerabilities"]:
            for item in verify_results_organized["real_vulnerabilities"]:
                retest_message = (
                    f"Target: {target}\n"
                    f"Target type: {target_type}\n"
                    f"Scope: {scope}\n\n"
                    "VERIFIED VULNERABILITY - Build Report Entry:\n"
                    f"{item['verify_summary']}\n\n"
                    "Verify Evidence:\n"
                    f"{json.dumps(item['verify_data'].get('evidence', {}), ensure_ascii=True)}\n\n"
                    "Instructions:\n"
                    "1. Take screenshot of vulnerability\n"
                    "2. Capture detailed PoC proof (request/response/output)\n"
                    "3. Build report entry with all details\n"
                    "4. Return structured JSON for database storage"
                )

                # Create task but don't await it yet
                retest_task = asyncio.create_task(
                    self._run_retest_background(
                        item=item,
                        retest_agent=retest_agent,
                        retest_message=retest_message,
                        project_id=project_id,
                        scan_id=scan_id,
                        target=target,
                        target_type=target_type,
                    )
                )
                retest_background_tasks.append(retest_task)

        # Build aggregated planner message with all findings
        planner_sections = []

        # Add real vulnerabilities section
        if verify_results_organized["real_vulnerabilities"]:
            real_vuln_section = "VERIFIED REAL VULNERABILITIES (confirmed by Verify agent):\n"
            for item in verify_results_organized["real_vulnerabilities"]:
                real_vuln_section += f"\n- [{item['idx']}] {item['verify_summary']}"
            planner_sections.append(real_vuln_section)

        # Add false positives section
        if verify_results_organized["false_positives"]:
            false_pos_section = "FALSE POSITIVES (filtered out):\n"
            for item in verify_results_organized["false_positives"]:
                false_pos_section += f"\n- [{item['idx']}] {item['verify_summary']}"
            planner_sections.append(false_pos_section)

        # Add inconclusives section
        if verify_results_organized["inconclusives"]:
            inconc_section = "INCONCLUSIVE FINDINGS (need manual review):\n"
            for item in verify_results_organized["inconclusives"]:
                inconc_section += f"\n- [{item['idx']}] {item['compact_summary']}"
            planner_sections.append(inconc_section)

        # Add info-only section
        if assessments_organized["info_only"]:
            info_section = "RECONNAISSANCE FINDINGS (informational only):\n"
            for item in assessments_organized["info_only"]:
                info_section += f"\n- [{item['idx']}] {item['compact_summary']}"
            planner_sections.append(info_section)

        # Build single aggregated message
        aggregated_planner_message = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n\n"
            "BATCH FINDINGS SUMMARY:\n"
            + ("\n\n".join(planner_sections) if planner_sections else "No findings classified in this cycle. Continue enumeration.")
            + "\n\n"
            "Review all findings above. Update plan accordingly:\n"
            "- For real vulnerabilities: mark as discovered and continue testing\n"
            "- For false positives: acknowledge and move forward\n"
            "- For inconclusives: add to review queue or continue testing\n"
            "- For recon info: integrate into plan and continue enumeration"
        )

        # Log Phase 3 start
        logger.info(
            "phase3_planner_retest_start",
            real_vulns=len(verify_results_organized["real_vulnerabilities"]),
            false_positives=len(verify_results_organized["false_positives"]),
            inconclusives=len(verify_results_organized["inconclusives"]),
            info_only=len(assessments_organized["info_only"]),
        )
        self._emit_event(
            project_id,
            event="planner_batch_handoff",
            scan_id=scan_id,
            level="info",
            message="Planner [thinking] Aggregating batch findings for replanning.",
            data={
                "stage": "planner",
                "kind": "batch_handoff",
                "real_vulnerabilities_count": len(verify_results_organized["real_vulnerabilities"]),
                "false_positives_count": len(verify_results_organized["false_positives"]),
                "inconclusives_count": len(verify_results_organized["inconclusives"]),
                "info_only_count": len(assessments_organized["info_only"]),
            },
        )

        # Call planner IMMEDIATELY (while Retest runs in background)
        # Wrapped in try/except to ensure loop continues even if planner fails
        planner_loop_result = None
        try:
            logger.info("planner_calling", phase="3_aggregation")
            planner_loop_result = await loop_planner.run(
                aggregated_planner_message,
                is_loop=True,
                intel_checklist=intel_checklist,
            )
        except Exception as planner_exc:
            self._emit_event(
                project_id,
                event="planner_error",
                scan_id=scan_id,
                level="warn",
                message=f"Planner error (continuing): {str(planner_exc)[:200]}",
                data={"error": str(planner_exc)},
            )
            # Create minimal planner result to continue loop
            planner_loop_result = type('obj', (object,), {
                'summary': 'Planner encountered error; continuing with next cycle',
                'plan': {}
            })()

        # Capture updated plan immediately after planner runs
        from server.agents.planner.tools.pentest_plan import _current_plan as current
        plan_data = dict(current) if isinstance(current, dict) else plan_data
        plan_data = _sanitize_plan_remove_forbidden_agents(plan_data)

        # Log single planner update
        logger.info(
            "planner_batch_findings_processed",
            real_vulns_count=len(verify_results_organized["real_vulnerabilities"]),
            false_positives_count=len(verify_results_organized["false_positives"]),
            inconclusives_count=len(verify_results_organized["inconclusives"]),
            info_only_count=len(assessments_organized["info_only"]),
            planner_summary=str(planner_loop_result.summary or "")[:100],
        )

        # Emit single plan update event for UI
        self._emit_event(
            project_id,
            event="plan_updated_by_planner",
            scan_id=scan_id,
            level="success",
            message=f"Planner processed batch: {len(verify_results_organized['real_vulnerabilities'])} real, "
                    f"{len(verify_results_organized['false_positives'])} false pos, "
                    f"{len(verify_results_organized['inconclusives'])} inconc, "
                    f"{len(assessments_organized['info_only'])} info",
            data={
                "stage": "planner",
                "kind": "batch_findings_processed",
                "real_vulnerabilities_count": len(verify_results_organized["real_vulnerabilities"]),
                "false_positives_count": len(verify_results_organized["false_positives"]),
                "inconclusives_count": len(verify_results_organized["inconclusives"]),
                "info_only_count": len(assessments_organized["info_only"]),
                "summary": str(planner_loop_result.summary or "").strip(),
                "plan_data": plan_data,
            },
        )

        # ============================================================================
        # PHASE 3C: Retest continues in background (already running)
        # ============================================================================
        # Retest tasks are already executing while Planner updates plan
        # No need to wait for them here - they save to database independently

        # Add false positives to log
        for item in verify_results_organized["false_positives"]:
            planner_loop_rows.append({
                "iteration": item["idx"],
                "route": "verify->planner(false_positive,batch)",
                "verdict": "false_positive",
                "false_positive_reason": item["verify_summary"],
                "planner_summary": str(planner_loop_result.summary or "").strip(),
                "compact_bridge": item["compact_summary"],
            })

        # Add inconclusives to log
        for item in verify_results_organized["inconclusives"]:
            planner_loop_rows.append({
                "iteration": item["idx"],
                "route": "verify->planner(inconclusive,batch)",
                "verdict": "inconclusive",
                "planner_summary": str(planner_loop_result.summary or "").strip(),
                "compact_bridge": item["compact_summary"],
            })

        # Add info-only findings to log
        for item in assessments_organized["info_only"]:
            planner_loop_rows.append({
                "iteration": item["idx"],
                "route": "perceptor->planner(info_only,batch)",
                "summary": str(planner_loop_result.summary or "").strip(),
                "compact_bridge": item["compact_summary"],
            })

        # ============================================================================
        # PHASE 5: Mark ALL scenarios as done
        # ============================================================================
        for row in execution_rows:
            row_result = row.get("result", {}) if isinstance(row, dict) else {}
            row_status = str(row_result.get("status", "")).strip().lower() if isinstance(row_result, dict) else ""
            if row_status in {"failed", "error"}:
                continue

            scenario = row.get("scenario", {})
            if isinstance(scenario, dict):
                rounds_executed = int(row_result.get("rounds_executed", 0) or 0)
                round_labels = row_result.get("round_labels", [])

                # Determine route based on what happened to this scenario's findings
                route = "batch_processed"
                for item in verify_results_organized["real_vulnerabilities"]:
                    if item["scenario"] == scenario:
                        route = "verify->planner+retest(batch)"
                        break
                for item in verify_results_organized["false_positives"]:
                    if item["scenario"] == scenario:
                        route = "verify->planner(false_positive,batch)"
                        break
                if route == "batch_processed":
                    for item in verify_results_organized["inconclusives"]:
                        if item["scenario"] == scenario:
                            route = "verify->planner(inconclusive,batch)"
                            break
                if route == "batch_processed":
                    for item in assessments_organized["info_only"]:
                        if item["scenario"] == scenario:
                            route = "perceptor->planner(info_only,batch)"
                            break

                _update_scenario_runtime_state(
                    plan_data,
                    scenario,
                    status="completed",
                    done=True,
                    round_label=f"r{rounds_executed}" if rounds_executed > 0 else None,
                    round_labels=round_labels if isinstance(round_labels, list) else None,
                    route=route,
                )
                _mark_scenario_done_in_plan(plan_data, scenario)
                self._emit_event(
                    project_id,
                    event="scenario_state_change",
                    scan_id=scan_id,
                    level="info",
                    message=f"Scenario completed: {scenario.get('task', 'unknown')}",
                    data={
                        "stage": "executer",
                        "kind": "scenario_done",
                        "scenario_task": scenario.get("task", ""),
                        "agent": scenario.get("agent", ""),
                        "state": "completed",
                        "route": route,
                        "round_label": f"r{rounds_executed}" if rounds_executed > 0 else "",
                        "rounds_seen": round_labels if isinstance(round_labels, list) else [],
                        "plan_data": plan_data,
                    },
                )

        # Capture updated plan from planner (scenarios may have been modified/added)
        from server.agents.planner.tools.pentest_plan import _current_plan
        updated_plan = dict(_current_plan) if isinstance(_current_plan, dict) else plan_data
        updated_plan = _sanitize_plan_remove_forbidden_agents(updated_plan)

        # CRITICAL FIX: Check if Planner indicated completion during batch processing
        # If any planner result says "done" or "complete", return False to stop looping
        should_stop = False
        for row in planner_loop_rows:
            summary = str(row.get("planner_summary") or row.get("summary", "")).strip().lower()
            if summary.startswith("pentest complete") or summary == "complete":
                should_stop = True
                logger.info("planner_batch_stop_signal", reason="planner_said_done", summary=summary)
                break

        # Continue to next cycle, or stop if Planner indicated completion
        # Safety: Always return True by default (continue loop) unless Planner explicitly says stop
        logger.info(
            "execution_cycle_complete",
            cycle_should_stop=should_stop,
            planner_summary=str(planner_loop_result.summary if planner_loop_result else "")[:100],
        )
        try:
            return not should_stop, updated_plan
        except Exception as return_exc:
            logger.error("execution_cycle_return_error", error=str(return_exc))
            # Safety fallback: Continue loop on any error
            return True, plan_data

    async def _check_planner_completion(
        self,
        *,
        project_id: str,
        scan_id: str,
        loop_planner: Any,
        plan_data: dict[str, Any],
        target: str,
        target_type: str,
        scope: str,
        info: str,
        intel_checklist: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Ask planner if pentest is complete."""
        completion_message = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n\n"
            "No more pending scenarios. Review plan:\n"
            "- If any critical P1-P2 items remain untested, return updated plan with new scenarios\n"
            "- If all critical items tested, return summary: 'Pentest complete.'"
        )

        plan_result = await loop_planner.run(
            completion_message,
            is_loop=True,
            intel_checklist=intel_checklist,
        )

        from server.agents.planner.tools.pentest_plan import _current_plan as current

        updated_plan = dict(current) if isinstance(current, dict) else plan_data
        updated_plan = _sanitize_plan_remove_forbidden_agents(updated_plan)
        summary = str(plan_result.summary or "").strip()
        normalized_summary = re.sub(r"\s+", " ", summary.lower()).strip()
        is_done = normalized_summary.startswith("pentest complete") or normalized_summary == "complete"

        if not is_done:
            self._emit_event(
                project_id,
                event="plan_updated_by_planner",
                scan_id=scan_id,
                level="info",
                message="Planner refreshed plan after empty-scenario completion check.",
                data={
                    "stage": "planner",
                    "kind": "plan_updated_after_completion_check",
                    "summary": summary,
                    "plan_data": updated_plan,
                },
            )

        return not is_done, updated_plan

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
            project = self._projects_store.get_project(project_id) or {}
            custom_checklist_text = (
                str(project.get("customChecklistText", "")).strip()
                if isinstance(project, dict)
                else ""
            )
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
            intel_agent = IntelAgent(callback=callback, project_id=project_id)
            intel_result = await intel_agent.run(
                target_type=target_type,
                info=info,
                custom_checklist_text=custom_checklist_text,
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

            planner_callback = PrintCallback(
                enabled=print_steps,
                on_log=lambda level, message: self._emit_planner_callback_event(
                    project_id=project_id,
                    scan_id=scan_id,
                    level=level,
                    raw_message=message,
                ),
            )
            async with PlannerAgent(
                callback=planner_callback,
                project_id=project_id,
                projects_store=self._projects_store,
                vector_store=self._vector_store,
            ) as planner_agent:
                planner_result = await planner_agent.run(
                    planner_input,
                    is_loop=False,
                    intel_checklist=intel_checklist,
                )
                # Plan data is maintained in pentest_plan module and retrieved via import
                from server.agents.planner.tools.pentest_plan import _current_plan
                plan_data = dict(_current_plan) if isinstance(_current_plan, dict) else {}
                # Sanitize plan: remove any forbidden agents (verify, retest, perceptor)
                plan_data = _sanitize_plan_remove_forbidden_agents(plan_data)

                # Log plan structure for debugging (why 0 scenarios?)
                phases = plan_data.get("phases", [])
                scenario_counts = {}
                for phase_idx, phase in enumerate(phases):
                    if isinstance(phase, dict):
                        steps = phase.get("steps", [])
                        if isinstance(steps, list):
                            for step_idx, step in enumerate(steps):
                                if isinstance(step, dict):
                                    scenarios = step.get("scenarios", [])
                                    agent_counts = {}
                                    for scen in scenarios:
                                        if isinstance(scen, dict):
                                            agent = scen.get("agent", "unknown")
                                            agent_counts[agent] = agent_counts.get(agent, 0) + 1
                                    if agent_counts:
                                        key = f"{phase.get('name', 'Phase')}:step{step_idx}"
                                        scenario_counts[key] = agent_counts

                logger.info(
                    "plan_loaded_from_planner",
                    target=plan_data.get("target", ""),
                    phases_count=len(phases),
                    scenario_breakdown=scenario_counts if scenario_counts else "NO SCENARIOS FOUND",
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

        execution_rows: list[dict[str, Any]] = []
        perceptor_rows: list[dict[str, Any]] = []
        planner_loop_rows: list[dict[str, Any]] = []
        exec_scope = scope_text
        executer_error: str = ""

        self._emit_event(
            project_id,
            event="executer_started",
            scan_id=scan_id,
            level="info",
            message="Executer [start] starting first prioritized scenario wave.",
            data={"stage": "executer", "kind": "start"},
        )

        try:
            from server.agents.executer.recon.agent import ReconExecuterAgent
            from server.agents.executer.exploit.agent import ExploitExecuterAgent
            from server.agents.executer.verify.agent import VerifyExecuterAgent
            from server.agents.executer.retest.agent import RetestExecuterAgent
            from server.agents.perceptor.agent import PerceptorAgent
            from server.agents.planner.agent import PlannerAgent

            executer_callback = ExecuterScanCallback(
                service=self,
                project_id=project_id,
                scan_id=scan_id,
                enabled=print_steps,
            )

            recon_agent = ReconExecuterAgent(
                callback=executer_callback,
                target_types=[target_type],
                project_id=project_id,
            )
            exploit_agent = ExploitExecuterAgent(
                callback=executer_callback,
                target_types=[target_type],
                project_id=project_id,
            )
            verify_agent = VerifyExecuterAgent(
                callback=executer_callback,
                project_id=project_id,
            )
            retest_agent = RetestExecuterAgent(
                callback=executer_callback,
                project_id=project_id,
            )
            perceptor_agent = PerceptorAgent(project_id=project_id)
            loop_planner_callback = PrintCallback(
                enabled=print_steps,
                on_log=lambda level, message: self._emit_planner_callback_event(
                    project_id=project_id,
                    scan_id=scan_id,
                    level=level,
                    raw_message=message,
                ),
            )
            loop_planner = PlannerAgent(
                callback=loop_planner_callback,
                project_id=project_id,
                projects_store=self._projects_store,
                vector_store=self._vector_store,
            )

            try:
                execution_rows: list[dict[str, Any]] = []
                perceptor_rows: list[dict[str, Any]] = []
                planner_loop_rows: list[dict[str, Any]] = []
                exec_scope = scope_text

                self._emit_event(
                    project_id,
                    event="executer_started",
                    scan_id=scan_id,
                    level="info",
                    message="Executer [start] entering cyclic execution loop.",
                    data={"stage": "executer", "kind": "start"},
                )

                # CYCLIC EXECUTION LOOP with explicit state tracking
                cycle_count = 0
                max_cycles = 20  # Safety limit
                scenario_execution_state: dict[str, int] = {}  # Track scenario task → cycle_executed

                while cycle_count < max_cycles:
                    cycle_count += 1

                    # FRESH CONTEXT PER CYCLE: Reset context windows for executer agents
                    # (only Planner keeps context across cycles)
                    recon_agent.reset_context_window_for_cycle()
                    exploit_agent.reset_context_window_for_cycle()
                    verify_agent.reset_context_window_for_cycle()
                    retest_agent.reset_context_window_for_cycle()
                    perceptor_agent.reset_context_window_for_cycle()

                    self._emit_event(
                        project_id,
                        event="executer_cycle_start",
                        scan_id=scan_id,
                        level="info",
                        message=f"Executer [cycle {cycle_count}] starting scenario selection (executed={len(scenario_execution_state)}).",
                        data={
                            "stage": "executer",
                            "kind": "cycle_start",
                            "cycle": cycle_count,
                            "scenarios_executed_total": len(scenario_execution_state),
                        },
                    )

                    try:
                        should_continue, updated_plan = await self._run_execution_cycle(
                            project_id=project_id,
                            scan_id=scan_id,
                            plan_data=plan_data,
                            recon_agent=recon_agent,
                            exploit_agent=exploit_agent,
                            verify_agent=verify_agent,
                            retest_agent=retest_agent,
                            perceptor_agent=perceptor_agent,
                            loop_planner=loop_planner,
                            target=target,
                            target_type=target_type,
                            scope=exec_scope,
                            info=info,
                            intel_checklist=intel_checklist,
                        )
                    except Exception as cycle_exc:
                        # Safety: If execution cycle fails, emit warning and continue loop
                        logger.error(
                            "executer_cycle_exception",
                            cycle=cycle_count,
                            error=str(cycle_exc)[:200],
                        )
                        self._emit_event(
                            project_id,
                            event="executer_cycle_error",
                            scan_id=scan_id,
                            level="warn",
                            message=f"Executer cycle error (continuing): {str(cycle_exc)[:200]}",
                            data={"error": str(cycle_exc)},
                        )
                        should_continue = True  # Always continue on error
                        updated_plan = plan_data

                    plan_data = updated_plan

                    # OPTIMIZATION: Compress Planner context window between cycles (after cycle 1)
                    # to prevent token bloat while keeping critical plan history
                    if cycle_count > 1 and loop_planner._context_window is not None:
                        from server.agents.planner.context_compression import (
                            compress_planner_context_window,
                        )

                        try:
                            compress_planner_context_window(
                                loop_planner._context_window, cycle_count
                            )
                        except Exception as compression_exc:
                            logger.warning(
                                "planner_context_compression_skipped",
                                cycle=cycle_count,
                                error=str(compression_exc),
                            )

                    if not should_continue:
                        self._emit_event(
                            project_id,
                            event="executer_planner_says_done",
                            scan_id=scan_id,
                            level="success",
                            message="Executer [done signal] Planner returned completion.",
                            data={
                                "stage": "executer",
                                "kind": "planner_done",
                                "cycle": cycle_count,
                            },
                        )
                        break

                self._emit_event(
                    project_id,
                    event="executer_complete",
                    scan_id=scan_id,
                    level="success",
                    message=f"Executer [completed] finished after {cycle_count} cycle(s).",
                    data={
                        "stage": "executer",
                        "kind": "completed",
                        "cycle_count": cycle_count,
                        "execution_count": len(execution_rows),
                        "perceptor_count": len(perceptor_rows),
                        "planner_loop_count": len(planner_loop_rows),
                    },
                )
            finally:
                await recon_agent.close()
                await exploit_agent.close()
                await verify_agent.close()
                await retest_agent.close()
                await perceptor_agent.close()
                await loop_planner.close()
        except Exception as exc:
            executer_error = str(exc)
            self._emit_event(
                project_id,
                event="executer_crashed",
                scan_id=scan_id,
                level="warn",
                message=f"Executer [crashed] {exc}",
                data={
                    "stage": "executer",
                    "kind": "crashed",
                    "error": str(exc),
                },
            )
        if executer_error:
            self._mark_failed(
                project_id,
                scan_id,
                f"executer runtime error: {executer_error}",
            )
            return

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
                "execution": execution_rows,
                "perceptor": perceptor_rows,
                "plannerLoops": planner_loop_rows,
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
        if isinstance(scan_meta, dict):
            result = scan_meta.get("result", {})
            if not isinstance(result, dict):
                result = {}
            context_windows = project.get("contextWindows", {})
            if isinstance(context_windows, dict) and context_windows:
                result["contextWindows"] = dict(context_windows)
            scan_meta["result"] = result
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
