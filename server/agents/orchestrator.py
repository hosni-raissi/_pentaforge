"""
Orchestrator — LangGraph-based pipeline that coordinates all agents.

Current flow:
    START → intel_refresh → build_planner_input → plan → collect → END

Intel Agent produces checklist-focused target intelligence for the target.
Planner Agent uses that intelligence to build a structured pentest plan
with scenarios for executor agents.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from typing import Any, TypedDict

import structlog
from langgraph.graph import END, START, StateGraph

from server.agents.intel.agent import IntelAgent, IntelResult
from server.agents.planner.agent import PlannerAgent, PlannerResult
from server.agents.planner.config import (
    PLANNER_CHECKLIST_WINDOW_MAX_ITEMS,
    PLANNER_CHECKLIST_WINDOW_MAX_ITEMS_PER_PHASE,
)
from server.agents.planner.tools.pentest_plan import (
    _current_plan,
    _reset_plan,
)
from server.config.agent import llm_mode

logger = structlog.get_logger(__name__)


class _SilentAgentCallback:
    """Suppress agent callback chatter when orchestrated."""
    def on_step(self, message: str) -> None:
        pass

    def on_done(self, message: str) -> None:
        pass

    def on_warn(self, message: str) -> None:
        pass


def _coerce_priority(value: Any) -> int | None:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= p <= 5:
        return p
    return None


def _extract_checklist_window(
    checklist_payload: dict[str, Any],
    *,
    max_items: int = PLANNER_CHECKLIST_WINDOW_MAX_ITEMS,
    max_items_per_phase: int = PLANNER_CHECKLIST_WINDOW_MAX_ITEMS_PER_PHASE,
) -> dict[str, Any]:
    """Build a compact checklist window for planner prompt token control."""
    raw_phases = checklist_payload.get("checklist", [])
    phases: list[dict[str, Any]] = []
    if isinstance(raw_phases, list):
        for phase in raw_phases:
            if not isinstance(phase, dict):
                continue
            phase_id = str(phase.get("phase", "")).strip()
            title = str(phase.get("title", "")).strip() or phase_id or "Phase"
            raw_items = phase.get("items", [])
            normalized_items: list[dict[str, Any]] = []
            if isinstance(raw_items, list):
                for item in raw_items:
                    if isinstance(item, str):
                        name = item.strip()
                        if name:
                            normalized_items.append({"name": name})
                        continue
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name", "")).strip()
                    if not name:
                        continue
                    entry: dict[str, Any] = {"name": name}
                    priority = _coerce_priority(item.get("priority"))
                    if priority is not None:
                        entry["priority"] = priority
                    normalized_items.append(entry)
            if normalized_items:
                normalized_items.sort(
                    key=lambda x: x.get("priority", 0),
                    reverse=True,
                )
            phases.append(
                {
                    "phase": phase_id,
                    "title": title,
                    "items": normalized_items,
                }
            )

    available_total_raw = checklist_payload.get("available_total")
    try:
        available_total = int(available_total_raw)
    except (TypeError, ValueError):
        available_total = sum(len(p.get("items", [])) for p in phases)

    selected: list[dict[str, Any]] = []
    included_count = 0
    for phase in phases:
        items = phase.get("items", [])
        if not isinstance(items, list):
            continue
        if included_count >= max_items:
            break
        remaining = max_items - included_count
        chosen = items[: min(max_items_per_phase, remaining)]
        if not chosen:
            continue
        selected.append(
            {
                "phase": phase.get("phase", ""),
                "title": phase.get("title", ""),
                "items": chosen,
            }
        )
        included_count += len(chosen)

    return {
        "target_type": str(checklist_payload.get("target_type", "") or ""),
        "available_total": available_total,
        "window_items": included_count,
        "window_max_items": max_items,
        "window_max_items_per_phase": max_items_per_phase,
        "truncated": bool(available_total > included_count),
        "checklist": selected,
    }


def _extract_checklist_overview(checklist_payload: dict[str, Any]) -> dict[str, Any]:
    raw_phases = checklist_payload.get("checklist", [])
    phases_overview: list[dict[str, Any]] = []
    derived_total = 0

    if isinstance(raw_phases, list):
        for phase in raw_phases:
            if not isinstance(phase, dict):
                continue
            phase_id = str(phase.get("phase", "")).strip()
            title = str(phase.get("title", "")).strip() or phase_id or "Phase"
            raw_items = phase.get("items", [])
            item_count = len(raw_items) if isinstance(raw_items, list) else 0
            derived_total += item_count
            phases_overview.append(
                {
                    "phase": phase_id,
                    "title": title,
                    "items": item_count,
                }
            )

    available_total_raw = checklist_payload.get("available_total")
    try:
        available_total = int(available_total_raw)
    except (TypeError, ValueError):
        available_total = derived_total

    return {
        "target_type": str(checklist_payload.get("target_type", "") or ""),
        "available_total": available_total,
        "phases": phases_overview,
    }


# ── Graph state ────────────────────────────────────────────────────────

class OrchestratorState(TypedDict):
    """State flowing through the orchestrator graph."""

    target_type: str
    target_url: str
    scope: str
    info: str
    intel_result: dict[str, Any]
    planner_input: str
    planner_result: dict[str, Any]
    plan_data: dict[str, Any]
    error: str


# ── Output dataclass ───────────────────────────────────────────────────

@dataclass
class OrchestratorResult:
    """Final output from the orchestrator pipeline."""

    intel: IntelResult | None = None
    plan: PlannerResult | None = None
    plan_data: dict[str, Any] = field(default_factory=dict)
    error: str = ""


# ── Orchestrator ───────────────────────────────────────────────────────

class Orchestrator:
    """LangGraph orchestrator: Intel → Planner → (future: Executors).

    Graph:
        START → intel_refresh → build_planner_input → plan → collect → END
    """

    def __init__(self, mode: str | None = None) -> None:
        self._mode = mode or llm_mode.mode
        silent_cb = _SilentAgentCallback()
        self._intel_agent = IntelAgent(mode=self._mode, callback=silent_cb)
        self._planner_agent = PlannerAgent(mode=self._mode, callback=silent_cb)
        self._graph = self._build_graph()

        logger.info("orchestrator_initialized", mode=self._mode)

    # ── Graph construction ─────────────────────────────────────────

    def _build_graph(self) -> Any:
        """Build the orchestrator state graph."""
        graph = StateGraph(OrchestratorState)

        graph.add_node("intel_refresh", self._intel_node)
        graph.add_node("build_planner_input", self._build_planner_input_node)
        graph.add_node("plan", self._plan_node)
        graph.add_node("collect", self._collect_node)

        graph.add_edge(START, "intel_refresh")
        graph.add_conditional_edges(
            "intel_refresh",
            self._route_after_intel,
            {
                "build_planner_input": "build_planner_input",
                "collect": "collect",
            },
        )
        graph.add_edge("build_planner_input", "plan")
        graph.add_edge("plan", "collect")
        graph.add_edge("collect", END)

        return graph.compile()

    # ── Graph nodes ────────────────────────────────────────────────

    async def _intel_node(self, state: OrchestratorState) -> dict[str, Any]:
        """Run Intel Agent to gather attack intelligence."""
        target_type = state["target_type"]
        target_url = state.get("target_url", "")
        scope = state.get("scope", "")
        info = state.get("info", "")
        intel_info = (
            f"Target URL: {target_url}\n"
            f"Scope: {scope}\n"
            f"{info}".strip()
        )

        logger.info(
            "orchestrator_intel_start", target_type=target_type,
        )

        try:
            result = await self._intel_agent.run(
                target_type=target_type, info=intel_info,
            )

            logger.info(
                "orchestrator_intel_complete",
                target_type=target_type,
                status=result.status,
                vulnerability_count=len(result.vulnerabilities),
            )

            return {
                "intel_result": {
                    "status": result.status,
                    "stats": result.stats,
                    "vulnerabilities": result.vulnerabilities,
                    "checklist": result.checklist,
                },
            }

        except Exception as exc:
            logger.error(
                "orchestrator_intel_error",
                error=repr(exc),
                target_type=target_type,
            )
            return {
                "intel_result": {
                    "status": "error",
                    "stats": {},
                    "vulnerabilities": [],
                    "checklist": {},
                },
                "error": f"Intel Agent failed: {exc}",
            }

    def _route_after_intel(self, state: OrchestratorState) -> str:
        """Skip planner if intel failed critically."""
        if state.get("error"):
            return "collect"
        return "build_planner_input"

    async def _build_planner_input_node(
        self, state: OrchestratorState,
    ) -> dict[str, Any]:
        """Build the user message for the Planner using Intel results."""
        target_url = state.get("target_url", "")
        target_type = state["target_type"]
        scope = state.get("scope", "")
        intel = state.get("intel_result", {})
        intel_vulnerabilities = intel.get("vulnerabilities", [])
        intel_checklist = intel.get("checklist", {})
        checklist_overview = (
            _extract_checklist_overview(intel_checklist)
            if isinstance(intel_checklist, dict)
            else _extract_checklist_overview({})
        )

        intel_status = intel.get("status", "")
        intel_stats = intel.get("stats", {})
        planner_message = (
            f"Target: {target_url}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"\n"
            f"## Intelligence Brief (from Intel Agent)\n"
            f"Status: {intel_status}\n"
            f"Vulnerabilities: {json.dumps(intel_vulnerabilities, ensure_ascii=True)}\n"
            f"Checklist Overview: {json.dumps(checklist_overview, ensure_ascii=True)}\n"
            f"\n"
            f"Stats: {json.dumps(intel_stats, ensure_ascii=True)}\n"
            f"\n"
            f"## Instructions\n"
            f"1. FIRST STEP: create a great, target-specific pentest plan for this engagement.\n"
            f"2. Use available tools and checklist guidance with token-efficient context.\n"
            f"3. Treat checklist as state-machine guidance and prioritize S5 (critical severity) risk coverage.\n"
            f"4. Return strict JSON with keys: summary, needs, plan, action_plan.\n"
            f"5. action_plan must include checklist_updates, checklist_additions, "
            f"plan_modifications, dispatch, phase_advance, phase_advance_blocked_by, rationale.\n"
            f"6. Focus on reconnaissance first — we need attack-surface evidence before exploitation.\n"
        )

        logger.debug(
            "orchestrator_planner_input_built",
            message_length=len(planner_message),
            checklist_available_total=checklist_overview.get("available_total", 0),
            checklist_phase_count=len(checklist_overview.get("phases", []))
            if isinstance(checklist_overview.get("phases", []), list)
            else 0,
        )

        return {"planner_input": planner_message}

    async def _plan_node(self, state: OrchestratorState) -> dict[str, Any]:
        """Run Planner Agent to build the pentest plan."""
        planner_input = state["planner_input"]

        logger.info("orchestrator_plan_start")

        try:
            _reset_plan()

            intel_checklist = state.get("intel_result", {}).get("checklist", {})
            result = await self._planner_agent.run(
                planner_input,
                is_loop=False,
                intel_checklist=intel_checklist
                if isinstance(intel_checklist, dict)
                else {},
            )

            plan_data = dict(_current_plan)

            logger.info(
                "orchestrator_plan_complete",
                scenarios=len(result.scenarios),
                needs=len(result.needs),
                plan_phases=len(plan_data.get("phases", [])),
                summary_length=len(result.summary),
                checklist_updates=len(result.action_plan.get("checklist_updates", []))
                if isinstance(result.action_plan, dict)
                else 0,
                checklist_additions=len(result.action_plan.get("checklist_additions", []))
                if isinstance(result.action_plan, dict)
                else 0,
            )

            return {
                "planner_result": {
                    "scenarios": result.scenarios,
                    "needs": result.needs,
                    "summary": result.summary,
                    "action_plan": (
                        dict(result.action_plan)
                        if isinstance(result.action_plan, dict)
                        else {}
                    ),
                },
                "plan_data": plan_data,
            }

        except Exception as exc:
            logger.error("orchestrator_plan_error", error=repr(exc))
            return {
                "planner_result": {
                    "scenarios": [],
                    "needs": [],
                    "summary": f"Planning failed: {exc}",
                    "action_plan": {},
                },
                "plan_data": {},
                "error": f"Planner failed: {exc}",
            }

    async def _collect_node(self, state: OrchestratorState) -> dict[str, Any]:
        """Final node — logs completion."""
        logger.info(
            "orchestrator_complete",
            has_intel=bool(state.get("intel_result", {}).get("checklist")),
            has_plan=bool(state.get("planner_result", {}).get("scenarios")),
            has_error=bool(state.get("error")),
        )
        return {}

    # ── Public API ─────────────────────────────────────────────────

    async def run(
        self,
        target_url: str,
        target_type: str = "web_app",
        scope: str = "",
        info: str = "",
    ) -> OrchestratorResult:
        """Run the full pipeline: Intel → Planner.

        Args:
            target_url:  Target URL or IP address
            target_type: Attack surface type (web_app, api, network, etc.)
            scope:       Scope description for the engagement
            info:        Additional context for the Intel Agent

        Returns:
            OrchestratorResult with intel, plan, and any errors
        """
        initial_state: OrchestratorState = {
            "target_type": target_type,
            "target_url": target_url,
            "scope": scope,
            "info": info,
            "intel_result": {},
            "planner_input": "",
            "planner_result": {},
            "plan_data": {},
            "error": "",
        }

        final_state = await self._graph.ainvoke(initial_state)

        # Reconstruct typed results
        intel_data = final_state.get("intel_result", {})
        intel_result = IntelResult(
            status=intel_data.get("status", ""),
            stats=intel_data.get("stats", {}),
            vulnerabilities=intel_data.get("vulnerabilities", []),
            checklist=intel_data.get("checklist", {}),
        )

        planner_data = final_state.get("planner_result", {})
        planner_result = PlannerResult(
            scenarios=planner_data.get("scenarios", []),
            needs=planner_data.get("needs", []),
            summary=planner_data.get("summary", ""),
            action_plan=planner_data.get("action_plan", {}),
        )

        return OrchestratorResult(
            intel=intel_result,
            plan=planner_result,
            plan_data=final_state.get("plan_data", {}),
            error=final_state.get("error", ""),
        )

    async def close(self) -> None:
        """Close all agent LLM clients."""
        await self._planner_agent.close()
        close_intel = getattr(self._intel_agent, "close", None)
        if callable(close_intel):
            maybe_coro = close_intel()
            if inspect.isawaitable(maybe_coro):
                await maybe_coro

    async def __aenter__(self) -> Orchestrator:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
