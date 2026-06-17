from __future__ import annotations

import asyncio
import structlog
from typing import Any, TYPE_CHECKING

from server.nodes.intel import IntelNode
from .execution import WorkerPrefixCallback, execute_scenario_with_agent
from .types import PhaseResult
from .warmup import (
    WARMUP_RECON_CYCLES,
    WARMUP_RECON_WORKERS,
    _display_cycle_number,
    _select_warmup_recon_batches,
)

if TYPE_CHECKING:
    from .persistence import ScanPersistenceService
    from .events import ScanEventService
    from .approval import ApprovalGateService

logger = structlog.get_logger(__name__)

class PhaseRunnerService:
    """Manages the execution of individual scan phases."""

    def __init__(
        self, 
        persistence: ScanPersistenceService,
        events: ScanEventService,
        approval: ApprovalGateService
    ):
        self._persistence = persistence
        self._events = events
        self._approval = approval

    async def run_intel_phase(self, project_id: str, scan_id: str) -> PhaseResult:
        """Run the Intel phase to generate target intelligence and checklist."""
        logger.info("phase_intel_start", project_id=project_id, scan_id=scan_id)
        
        run_state = self._persistence.get_run_state(project_id)
        if not run_state:
            return PhaseResult("intel", False, error="No active run state")

        target = run_state.get("target", "")
        target_type = run_state.get("target_type", "")
        info = run_state.get("info", "")
        force_update = run_state.get("force_intel_update", False)

        def _on_step(msg: str) -> None:
            self._events.emit(
                project_id,
                event="intel_step",
                scan_id=scan_id,
                message=msg,
                data={"stage": "intel", "kind": "step"}
            )

        self._events.emit(
            project_id,
            event="intel_started",
            scan_id=scan_id,
            message="Intel [started] Analyzing target to build scenario checklist.",
            data={"stage": "intel", "kind": "started"}
        )

        try:
            from types import SimpleNamespace

            async def _request_intel_refresh_approval(
                *,
                role: str,
                tool_name: str,
                args: dict[str, Any],
                call_id: str,
            ) -> bool:
                return await self._approval.request_tool_approval(
                    project_id=project_id,
                    scan_id=scan_id,
                    role=role,
                    tool_name=tool_name,
                    args=args,
                    call_id=call_id,
                )

            callback = SimpleNamespace(
                on_step=_on_step,
                on_done=_on_step,
                on_warn=_on_step,
                request_tool_approval=_request_intel_refresh_approval,
            )
            intel_node = IntelNode(callback=callback, project_id=project_id)
            intel_result = await intel_node.run(
                target=target,
                target_type=target_type,
                project_id=project_id,
                force_update=force_update
            )
            
            # Update run state with intel results
            run_state["intel_result"] = intel_result
            self._persistence.set_run_state(project_id, run_state)

            self._events.emit(
                project_id,
                event="intel_completed",
                scan_id=scan_id,
                message="Intel [completed] Target intelligence gathered.",
                data={"stage": "intel", "kind": "completed", "result": intel_result}
            )
            
            return PhaseResult("intel", True, data=intel_result)
            
        except Exception as exc:
            logger.error("intel_phase_failed", project_id=project_id, error=str(exc))
            return PhaseResult("intel", False, error=str(exc))

    async def run_warmup_recon_phase(self, project_id: str, scan_id: str) -> PhaseResult:
        """Run the Warmup Recon phase with parallel workers."""
        from server.agents.analyzer import AnalyzerAgent
        from server.agents.executor.recon.agent import ReconExecuterAgent
        from server.config.agent import get_public_agent_config

        logger.info("phase_warmup_start", project_id=project_id, scan_id=scan_id)
        run_state = self._persistence.get_run_state(project_id)
        if not run_state:
            return PhaseResult("warmup_recon", False, error="No active run state")

        target = run_state.get("target", "")
        target_type = run_state.get("target_type", "")
        scope = run_state.get("scope", "")
        info = run_state.get("info", "")
        plan_data = run_state.get("plan", {})
        project_cache_dir = run_state.get("project_cache_dir", "")

        warmup_recon_agents = []
        for i in range(WARMUP_RECON_WORKERS):
            override_config = None
            if i % 2 == 1:
                try: override_config = get_public_agent_config("exploit")
                except Exception: pass

            worker_cb = WorkerPrefixCallback(
                events=self._events,
                persistence=self._persistence,
                approval=self._approval,
                project_id=project_id,
                scan_id=scan_id,
                worker_index=i,
            )
            warmup_recon_agents.append(
                ReconExecuterAgent(
                    callback=worker_cb,
                    target_types=[target_type],
                    project_id=None,
                    project_cache_dir=project_cache_dir,
                    config=override_config,
                    approval_mode=self._persistence.get_approval_mode(project_id),
                )
            )

        analyzer_agent = None
        analyzer_lock = asyncio.Lock()
        cached_summaries: list[dict[str, Any]] = []

        try:
            analyzer_agent = AnalyzerAgent()
            for cycle_number in range(1, WARMUP_RECON_CYCLES + 1):
                display_cycle = _display_cycle_number(cycle_number, prior_cycles=0)
                batches = _select_warmup_recon_batches(plan_data)
                if not batches:
                    break

                self._events.emit(
                    project_id, event="executer_cycle_start", scan_id=scan_id,
                    message=f"Executer [cycle {display_cycle}] starting warmup scenario selection.",
                    data={"stage": "executer", "kind": "cycle_start", "cycle": display_cycle, "warmup": True}
                )

                worker_tasks = []
                for worker_idx, batch in enumerate(batches, start=1):
                    if worker_idx - 1 < len(warmup_recon_agents):
                        warmup_recon_agents[worker_idx - 1].reset_context_window_for_cycle()
                    worker_tasks.append(
                        self._run_warmup_recon_worker(
                            project_id=project_id, scan_id=scan_id, plan_data=plan_data,
                            recon_agent=warmup_recon_agents[worker_idx - 1],
                            analyzer_agent=analyzer_agent, analyzer_lock=analyzer_lock,
                            scenarios=batch, target=target, target_type=target_type,
                            scope=scope, info=info, cycle_number=cycle_number, worker_number=worker_idx
                        )
                    )

                batch_results = await asyncio.gather(*worker_tasks)
                
                # Cache results (simplified for now)
                for worker_idx, worker_output in enumerate(batch_results):
                    for scenario, row_result in worker_output:
                        # Caching logic would go here
                        pass

                self._events.emit(
                    project_id, event="warmup_cycle_completed", scan_id=scan_id,
                    message=f"Warmup [cycle {display_cycle}] completed.", level="success",
                    data={"stage": "warmup", "kind": "cycle_completed", "cycle": display_cycle, "plan_data": plan_data}
                )

            return PhaseResult("warmup_recon", True, data={"plan": plan_data, "summaries": cached_summaries})
        finally:
            for agent in warmup_recon_agents:
                await agent.close()
            if analyzer_agent:
                await analyzer_agent.close()

    async def _run_warmup_recon_worker(
        self,
        project_id: str,
        scan_id: str,
        plan_data: dict[str, Any],
        recon_agent: Any,
        analyzer_agent: Any,
        analyzer_lock: asyncio.Lock,
        scenarios: list[dict[str, Any]],
        target: str,
        target_type: str,
        scope: str,
        info: str,
        cycle_number: int,
        worker_number: int,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        results = []
        for scenario in scenarios:
            exec_result = await execute_scenario_with_agent(
                plan_data=plan_data, scenario=scenario, recon_agent=recon_agent,
                recon_agent_worker_1=None, exploit_agent=None,
                target=target, target_type=target_type, scope=scope, info=info
            )
            results.append((scenario, exec_result))
        return results
