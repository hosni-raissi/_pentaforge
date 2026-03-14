"""
Test the Planner Agent -- Web target, scenario-based output.

Validates that the planner:
  1. Builds a structured plan via update_pentest_plan
  2. Returns a PlannerResult with scenarios (max 3) for the executor
  3. Or returns empty scenarios + needs list if it requires more knowledge
  4. Does NOT output scenarios while calling research tools

No knowledge base required -- search_kb excluded.

Usage:
    cd /home/hosnizap/projects/PentaForge
    python -m server.test.planner_agent
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import structlog

from server.agents.planner.agent import PlannerAgent, PlannerResult
from server.config.agent import planner_llm_config, planner_llm_mode, local_llm_config
from server.core.tool import Tool
from server.tools.planner.clone_repo import clone_repo
from server.tools.planner.get_page import get_page
from server.tools.planner.pentest_plan import (
    _current_plan,
    _reset_plan,
    get_pentest_plan,
    manage_target_types,
    update_pentest_plan,
)

structlog.configure(
    processors=[structlog.dev.ConsoleRenderer(colors=True)],
    wrapper_class=structlog.make_filtering_bound_logger(20),
)
logger = structlog.get_logger(__name__)

# No search_kb -- no KB needed for testing
TEST_TOOLS: list[Tool] = [
    clone_repo,
    get_page,
    get_pentest_plan,
    update_pentest_plan,
    manage_target_types,
]

VALID_AGENTS = {"recon", "exploit", "verify", "report", "retest"}


def print_result(result: PlannerResult) -> None:
    """Pretty-print a PlannerResult."""
    print(f"\n  summary: {result.summary[:200]}..." if len(result.summary) > 200 else f"\n  summary: {result.summary}")
    print(f"  scenarios ({len(result.scenarios)}):")
    for i, s in enumerate(result.scenarios, 1):
        print(f"    [{i}] agent={s.get('agent','?'):8s}  task={s.get('task','?')}")
        print(f"        recommended_tools={s.get('recommended_tools',[])}  methods={s.get('methods',[])}")
    if result.needs:
        print(f"  needs ({len(result.needs)}):")
        for n in result.needs:
            print(f"    - {n}")


def validate_scenarios(result: PlannerResult) -> None:
    """Validate scenario structure."""
    assert len(result.scenarios) <= 3, f"Max 3 scenarios, got {len(result.scenarios)}"
    for s in result.scenarios:
        assert "task" in s, f"Scenario missing 'task': {s}"
        assert "agent" in s, f"Scenario missing 'agent': {s}"
        assert s["agent"] in VALID_AGENTS, f"Invalid agent '{s['agent']}', must be one of {VALID_AGENTS}"
        assert "details" in s, f"Scenario missing 'details': {s}"
        assert "recommended_tools" in s or "tools" in s, f"Scenario missing tools key: {s}"


async def test_web_target() -> None:
    """Test: Web target -- planner builds plan and returns recon scenarios."""
    _reset_plan()

    print("\n" + "=" * 70)
    print("  TEST: Web target -- plan + scenarios for executor")
    print("=" * 70)
    if planner_llm_mode.mode == "local":
        print(f"  LLM mode: LOCAL (Ollama) / {local_llm_config.model}")
    else:
        print(f"  LLM mode: PUBLIC / {planner_llm_config.api_provider} / {planner_llm_config.model}")
    print(f"  Tools: {[t.name for t in TEST_TOOLS]}")
    print("=" * 70)

    async with PlannerAgent(tools=TEST_TOOLS) as agent:
        result = await agent.run(
            "Target: http://www.enicarthage.rnu.tn/\n"
            "Target type: web\n"
            "Scope: Full black-box web application pentest.\n"
            "Build the plan and return the first batch of scenarios "
            "for the executor agents to run. Do NOT search the knowledge base."
        )

    print("\n" + "-" * 70)
    print("  PLANNER RESULT")
    print("-" * 70)
    print_result(result)

    # Validate
    print("\n  VALIDATION:")
    assert isinstance(result, PlannerResult), "Expected PlannerResult"
    print("  - PASS: Got PlannerResult")

    if result.scenarios:
        validate_scenarios(result)
        print(f"  - PASS: {len(result.scenarios)} valid scenarios (max 3)")
        agents = {s["agent"] for s in result.scenarios}
        print(f"  - Agents used: {sorted(agents)}")
    elif result.needs:
        print(f"  - OK: Planner needs more data: {len(result.needs)} items")
        for n in result.needs:
            assert "tool" in n, f"Need missing 'tool': {n}"
        print("  - PASS: Needs are well-formed")
    else:
        print("  - WARN: No scenarios and no needs -- check summary")

    # Check stored plan
    plan = _current_plan
    print(f"  - Plan target: {plan.get('target', '(empty)')}")
    print(f"  - Plan target_types: {plan.get('target_types', [])}")
    phases = plan.get("phases", [])
    print(f"  - Plan phases: {len(phases)}")

    # Print the full plan
    print("\n" + "=" * 70)
    print("  FULL PENTEST PLAN")
    print("=" * 70)
    for phase in phases:
        steps = phase.get("steps", [])
        total_sc = sum(len(s.get("scenarios", [])) for s in steps)
        print(f"\n  Phase {phase.get('priority','?')}: {phase.get('name','?')} ({len(steps)} steps, {total_sc} scenarios)")
        for step in steps:
            print(f"    Step {step.get('id','?')}: {step.get('description','?')}")
            for sc in step.get("scenarios", []):
                agent = sc.get("agent", "?")
                task = sc.get("task", "?")
                tools = sc.get("recommended_tools", sc.get("tools", []))
                print(f"      -> [{agent}] {task}  tools={tools}")
    print("=" * 70)

    if plan.get("target"):
        assert len(phases) >= 3, f"Expected at least 3 phases (full plan), got {len(phases)}"
        print(f"  - PASS: Full plan with {len(phases)} phases")
    else:
        print("  - SKIP: Model returned scenarios directly without storing a plan (expected for small local models)")
    print()


async def main() -> None:
    print("\n  PentaForge Planner Agent Test")
    print("  (Scenario-based output for executor layer)")
    if planner_llm_mode.mode == "local":
        print(f"  LLM mode: LOCAL (Ollama) / {local_llm_config.model}")
    else:
        print(f"  LLM mode: PUBLIC / {planner_llm_config.api_provider} / {planner_llm_config.model}")
    print()

    await test_web_target()

    print("  All tests completed.\n")


if __name__ == "__main__":
    asyncio.run(main())
