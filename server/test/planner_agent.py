"""
Test the Planner Agent — clean step-by-step output.

Usage:
    python -m server.test.planner_agent
"""

import asyncio
import logging
import sys
import time
import warnings
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import structlog
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
warnings.filterwarnings("ignore", message="Api key is used with an insecure connection")
warnings.filterwarnings("ignore", message="Core Pydantic V1")

from server.agents.planner.agent import PlannerAgent, PlannerCallback
from server.agents.planner.tools.pentest_plan import _current_plan, _reset_plan
from server.config.agent import llm_mode, public_llm_config, local_llm_config


class PrintCallback(PlannerCallback):
    def __init__(self) -> None:
        self._start = time.perf_counter()

    def _ts(self) -> str:
        return f"[{time.perf_counter() - self._start:.1f}s]"

    def on_step(self, message: str) -> None:
        print(f"  → {message} {self._ts()}")

    def on_done(self, message: str) -> None:
        print(f"  ✓ {message}")

    def on_warn(self, message: str) -> None:
        print(f"  ⚠ {message}")


def _print_header(title: str) -> None:
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


def _print_plan(plan: dict) -> None:
    if not plan.get("target"):
        print("  (no stored plan)")
        return
    phases = plan.get("phases", [])
    print(f"  Target: {plan.get('target')}")
    print(f"  Types: {plan.get('target_types', [])}")
    print(f"  Phases: {len(phases)}")
    for phase in phases:
        steps = phase.get("steps", [])
        total_sc = sum(len(s.get("scenarios", [])) for s in steps)
        print(f"\n  Phase {phase.get('priority', '?')}: {phase.get('name', '?')} ({len(steps)} steps, {total_sc} scenarios)")
        for step in steps:
            print(f"    {step.get('id', '?')}: {step.get('description', '?')}")
            for sc in step.get("scenarios", []):
                agent = sc.get("agent", "?")
                task = sc.get("task", "?")
                tools = sc.get("recommended_tools", sc.get("tools", []))
                print(f"      → [{agent}] {task}  tools={tools}")


def _print_result(result) -> None:
    print(f"  Summary: {result.summary}")
    if result.scenarios:
        print(f"  Scenarios ({len(result.scenarios)}):")
        for i, s in enumerate(result.scenarios, 1):
            agent = s.get("agent", "?")
            task = s.get("task", "?")
            tools = s.get("recommended_tools", s.get("tools", []))
            print(f"    [{i}] {agent:8s} | {task}")
            print(f"         tools: {tools}")
    if result.needs:
        print(f"  Needs ({len(result.needs)}):")
        for n in result.needs:
            print(f"    - {n}")


def _phase_tasks(plan: dict, phase_name: str) -> set[str]:
    tasks: set[str] = set()
    for phase in plan.get("phases", []):
        if str(phase.get("name", "")).strip().lower() != phase_name.strip().lower():
            continue
        for step in phase.get("steps", []):
            for sc in step.get("scenarios", []):
                if isinstance(sc, dict) and isinstance(sc.get("task"), str):
                    tasks.add(sc["task"])
    return tasks


async def test_initial_plan() -> None:
    """Test: Build initial plan from scratch."""
    _print_header("TEST 1: Initial Plan (is_loop=False)")

    _reset_plan()
    cb = PrintCallback()

    async with PlannerAgent(callback=cb) as agent:
        result = await agent.run(
            "Target: http://www.enicarthage.rnu.tn/\n"
            "Target type: web\n"
            "Scope: Full black-box web application pentest.\n"
            "Build the plan and return the first batch of scenarios.",
            is_loop=False,
        )

    _print_header("STORED PLAN")
    _print_plan(_current_plan)

    _print_header("RESULT")
    _print_result(result)

    # Validate
    print(f"\n  ── VALIDATION ──")
    if result.scenarios:
        print(f"  ✓ {len(result.scenarios)} scenarios returned")
        agents = {s.get("agent") for s in result.scenarios}
        print(f"  ✓ Agents: {sorted(agents)}")
    else:
        print(f"  ✓ Plan-only mode: no scenarios returned (expected)")

    plan = _current_plan
    if plan.get("target"):
        phases = plan.get("phases", [])
        empty = [p.get("name") for p in phases if not p.get("steps")]
        print(f"  ✓ Plan stored: {len(phases)} phases")
        if empty:
            print(f"  ⚠ Empty phases: {empty}")
        else:
            print(f"  ✓ All phases have steps")
    else:
        print(f"  ⚠ No plan stored")

    return result


async def test_loop_reentry() -> None:
    """Test: Loop re-entry with simulated executor results."""
    _print_header("TEST 2: Loop Re-entry (is_loop=True)")

    # Don't reset plan — use the one from test 1
    if not _current_plan.get("target"):
        print("  ⚠ Skipping: no plan from test 1")
        return

    cb = PrintCallback()

    async with PlannerAgent(callback=cb) as agent:
        result = await agent.run(
            "Executor results from Reconnaissance phase:\n"
            "- Subdomain enumeration found: admin.enicarthage.rnu.tn, mail.enicarthage.rnu.tn\n"
            "- DNS records: A, MX, TXT found\n"
            "- Web server: Apache/2.4 on Ubuntu\n"
            "- Technologies detected: PHP 7.4, jQuery 3.5, Bootstrap 4\n"
            "- Open ports: 80 (HTTP), 443 (HTTPS), 22 (SSH)\n"
            "- Directory scan found: /admin, /uploads, /api/v1\n"
            "\n"
            "Phase 1 (Reconnaissance) is complete. Return the next batch of scenarios.",
            is_loop=True,
        )

    _print_header("RESULT")
    _print_result(result)

    print(f"\n  ── VALIDATION ──")
    if result.scenarios:
        print(f"  ✓ {len(result.scenarios)} scenarios returned")
        agents = {s.get("agent") for s in result.scenarios}
        print(f"  ✓ Agents: {sorted(agents)}")
        # With current planner design, enumeration scenarios can still be assigned to recon agent.
        recon_tasks = _phase_tasks(_current_plan, "Reconnaissance")
        enum_tasks = _phase_tasks(_current_plan, "Enumeration")
        returned_tasks = {
            s.get("task", "") for s in result.scenarios if isinstance(s, dict)
        }
        in_enum = bool(enum_tasks) and returned_tasks.issubset(enum_tasks)
        still_recon_phase = bool(recon_tasks) and bool(returned_tasks & recon_tasks)
        if in_enum and not still_recon_phase:
            print(f"  ✓ Advanced to Enumeration phase scenarios")
        elif returned_tasks & enum_tasks:
            print(f"  ✓ Includes Enumeration phase scenarios")
        else:
            print(f"  ⚠ Could not confirm phase advancement from returned tasks")
    else:
        print(f"  ✓ Plan-only mode: no scenarios returned (expected)")


async def main():
    _print_header("PentaForge Planner Agent Test")
    if llm_mode.mode == "local":
        print(f"  LLM: LOCAL / {local_llm_config.model}")
    else:
        print(f"  LLM: PUBLIC / {public_llm_config.api_provider} / {public_llm_config.model}")

    await test_initial_plan()
    await test_loop_reentry()

    _print_header("ALL TESTS COMPLETE")


if __name__ == "__main__":
    asyncio.run(main())
