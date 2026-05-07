from __future__ import annotations

import re
from typing import Any

from server.nodes.system_memory import Brain

from .utils import (
    _build_target_execution_guidance,
    _build_warmup_scenario_tool_guidance,
    _format_agent_execution_history_for_prompt,
)
from .warmup import _scenario_max_rounds


class WorkerPrefixCallback:
    def __init__(
        self,
        *,
        events: Any,
        persistence: Any,
        approval: Any,
        project_id: str,
        scan_id: str,
        worker_index: int,
    ) -> None:
        self._events = events
        self._persistence = persistence
        self._approval = approval
        self._project_id = project_id
        self._scan_id = scan_id
        self._prefix = f"[worker][{worker_index}]"
        self._role_re = re.compile(r"^\[(?:recon|exploit)\]\s*")

    def on_step(self, message: str) -> None:
        clean = self._role_re.sub("", message)
        self._events.emit(
            self._project_id,
            event="executer_step",
            scan_id=self._scan_id,
            message=f"{self._prefix} {clean}",
            data={"stage": "recon", "kind": "step", "raw_message": message},
        )

    def on_done(self, message: str) -> None:
        clean = self._role_re.sub("", message)
        self._events.emit(
            self._project_id,
            event="executer_done",
            scan_id=self._scan_id,
            message=f"{self._prefix} {clean}",
            level="success",
            data={"stage": "recon", "kind": "done", "raw_message": message},
        )

    def on_warn(self, message: str) -> None:
        clean = self._role_re.sub("", message)
        self._events.emit(
            self._project_id,
            event="executer_warn",
            scan_id=self._scan_id,
            message=f"{self._prefix} {clean}",
            level="warn",
            data={"stage": "recon", "kind": "warn", "raw_message": message},
        )

    def get_approval_mode(self) -> str:
        return self._persistence.get_approval_mode(self._project_id)

    def request_tool_approval(self, **kwargs: Any) -> Any:
        return self._approval.request_tool_approval(
            project_id=self._project_id,
            scan_id=self._scan_id,
            **kwargs,
        )


def build_executer_message(
    *,
    plan_data: dict[str, Any],
    scenario: dict[str, Any],
    target: str,
    target_type: str,
    scope: str,
    info: str,
    target_memory: dict[str, Any] | None = None,
) -> str:
    history_block = _format_agent_execution_history_for_prompt(
        plan_data,
        agent_role=str(scenario.get("agent", "")).strip().lower() or "recon",
        active_scenarios=[scenario],
    )
    target_guidance = _build_target_execution_guidance(
        target=target,
        scenario_tasks=[str(scenario.get("task", "")).strip()],
    )
    brain = Brain.from_system_memory(target_memory or {})
    return (
        f"TARGET: {target}\n"
        f"TARGET TYPE: {target_type}\n"
        f"SCOPE: {scope}\n"
        f"ADDITIONAL INFO: {info}\n\n"
        f"SCENARIO TASK: {scenario.get('task', '')}\n"
        f"SCENARIO DETAILS: {scenario.get('details', '')}\n\n"
        f"{history_block}\n\n"
        f"{target_guidance}\n\n"
        f"{_build_warmup_scenario_tool_guidance(scenario.get('task', ''))}\n\n"
        f"BRAIN CONTEXT:\n{brain.summary()}"
    )


async def execute_scenario_with_agent(
    *,
    plan_data: dict[str, Any],
    scenario: dict[str, Any],
    recon_agent: Any,
    recon_agent_worker_1: Any | None,
    exploit_agent: Any,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    target_memory: dict[str, Any] | None = None,
    recon_worker_index: int | None = None,
) -> dict[str, Any]:
    message = build_executer_message(
        plan_data=plan_data,
        scenario=scenario,
        target=target,
        target_type=target_type,
        scope=scope,
        info=info,
        target_memory=target_memory,
    )
    role = str(scenario.get("agent", "recon")).strip().lower()
    if role == "exploit" and exploit_agent:
        return await exploit_agent.run(
            message,
            max_tool_rounds_override=_scenario_max_rounds(scenario, default=2),
        )
    selected_agent = (
        recon_agent_worker_1
        if recon_worker_index == 1 and recon_agent_worker_1
        else recon_agent
    )
    return await selected_agent.run(
        message,
        max_tool_rounds_override=_scenario_max_rounds(scenario, default=1),
    )
