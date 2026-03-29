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
                summary_length=len(result.summary),
            )

            return {
                "intel_result": {
                    "status": result.status,
                    "summary": result.summary,
                    "stats": result.stats,
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
                    "summary": "",
                    "stats": {},
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
        intel_summary = intel.get("summary", "")

        intel_status = intel.get("status", "")
        intel_stats = intel.get("stats", {})
        planner_message = (
            f"Target: {target_url}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"\n"
            f"## Intelligence Brief (from Intel Agent)\n"
            f"Status: {intel_status}\n"
            f"{intel_summary}\n"
            f"\n"
            f"Stats: {json.dumps(intel_stats, ensure_ascii=True)}\n"
            f"\n"
            f"## Instructions\n"
            f"1. Use the intelligence above to build a complete pentest plan.\n"
            f"2. Call update_pentest_plan to store the plan.\n"
            f"3. Return the first batch of scenarios (max 3) for the "
            f"executor agents to run.\n"
            f"4. Focus on reconnaissance first — we need to discover "
            f"the attack surface before exploitation.\n"
        )

        logger.debug(
            "orchestrator_planner_input_built",
            message_length=len(planner_message),
        )

        return {"planner_input": planner_message}

    async def _plan_node(self, state: OrchestratorState) -> dict[str, Any]:
        """Run Planner Agent to build the pentest plan."""
        planner_input = state["planner_input"]

        logger.info("orchestrator_plan_start")

        try:
            _reset_plan()

            result = await self._planner_agent.run(planner_input, is_loop=False)

            plan_data = dict(_current_plan)

            logger.info(
                "orchestrator_plan_complete",
                scenarios=len(result.scenarios),
                needs=len(result.needs),
                plan_phases=len(plan_data.get("phases", [])),
                summary_length=len(result.summary),
            )

            return {
                "planner_result": {
                    "scenarios": result.scenarios,
                    "needs": result.needs,
                    "summary": result.summary,
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
                },
                "plan_data": {},
                "error": f"Planner failed: {exc}",
            }

    async def _collect_node(self, state: OrchestratorState) -> dict[str, Any]:
        """Final node — logs completion."""
        logger.info(
            "orchestrator_complete",
            has_intel=bool(state.get("intel_result", {}).get("summary")),
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
            summary=intel_data.get("summary", ""),
            stats=intel_data.get("stats", {}),
        )

        planner_data = final_state.get("planner_result", {})
        planner_result = PlannerResult(
            scenarios=planner_data.get("scenarios", []),
            needs=planner_data.get("needs", []),
            summary=planner_data.get("summary", ""),
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
