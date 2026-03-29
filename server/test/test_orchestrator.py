"""
Test the Orchestrator — Intel → Planner pipeline.

Validates that:
  1. Intel Agent produces vulnerabilities + a clean checklist
  2. Planner receives intel and builds a structured plan
  3. Planner returns scenarios for executor agents
  4. Full plan is stored via update_pentest_plan

Usage:
    cd /home/hosnizap/projects/PentaForge
    python -m server.test.test_orchestrator
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import structlog

structlog.configure(
    processors=[structlog.dev.ConsoleRenderer(colors=True)],
    wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
)

from server.agents.orchestrator import Orchestrator, OrchestratorResult
from server.config.agent import llm_mode, public_llm_config, local_llm_config

VALID_AGENTS = {"recon", "exploit", "verify", "report", "retest"}


def print_section(title: str) -> None:
    """Print a section header."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def print_intel(result: OrchestratorResult) -> None:
    """Print Intel Agent results."""
    print_section("INTEL AGENT RESULTS")
    intel = result.intel
    if not intel:
        print("  (no intel result)")
        return
    print(f"  Status: {intel.status}")
    print(f"  Vulnerabilities: {len(intel.vulnerabilities)}")
    if intel.vulnerabilities:
        print("\n  Vulnerability preview:")
        for item in intel.vulnerabilities[:12]:
            print(f"    - {item}")

    stats = intel.stats or {}
    print(f"\n  Stats:")
    print(f"    update_status: {stats.get('update_status', '?')}")
    print(f"    new_payloads: {stats.get('new_payloads', 0)}")
    print(f"    new_exploits: {stats.get('new_exploits', 0)}")
    print(f"    total_embedded: {stats.get('total_embedded', 0)}")
    print(f"\n  Checklist present: {bool(intel.checklist)}")


def print_plan(result: OrchestratorResult) -> None:
    """Print Planner Agent results."""
    print_section("PLANNER AGENT RESULTS")
    plan = result.plan
    if not plan:
        print("  (no plan result)")
        return

    print(f"  Summary: {plan.summary[:200]}..." if len(plan.summary) > 200 else f"  Summary: {plan.summary}")
    print(f"  Scenarios: {len(plan.scenarios)}")
    print(f"  Needs: {len(plan.needs)}")

    if plan.scenarios:
        print(f"\n  Scenarios for executor:")
        for i, s in enumerate(plan.scenarios, 1):
            agent = s.get("agent", "?")
            task = s.get("task", "?")
            tools = s.get("recommended_tools", s.get("tools", []))
            methods = s.get("methods", [])
            print(f"    [{i}] agent={agent:8s}  task={task}")
            print(f"         tools={tools}")
            if methods:
                print(f"         methods={methods}")

    if plan.needs:
        print(f"\n  Needs (planner wants more data):")
        for n in plan.needs:
            print(f"    - {n}")

    # Print stored plan
    plan_data = result.plan_data
    if plan_data and plan_data.get("target"):
        print_section("STORED PENTEST PLAN")
        print(f"  Target: {plan_data.get('target', '?')}")
        print(f"  Target types: {plan_data.get('target_types', [])}")
        phases = plan_data.get("phases", [])
        print(f"  Phases: {len(phases)}")
        for phase in phases:
            steps = phase.get("steps", [])
            total_sc = sum(len(s.get("scenarios", [])) for s in steps)
            print(f"\n  Phase {phase.get('priority', '?')}: {phase.get('name', '?')} ({len(steps)} steps, {total_sc} scenarios)")
            for step in steps:
                print(f"    Step {step.get('id', '?')}: {step.get('description', '?')}")
                for sc in step.get("scenarios", []):
                    agent = sc.get("agent", "?")
                    task = sc.get("task", "?")
                    tools = sc.get("recommended_tools", sc.get("tools", []))
                    print(f"      -> [{agent}] {task}  tools={tools}")
    else:
        print("\n  (no stored plan — model returned scenarios directly)")


def validate(result: OrchestratorResult) -> None:
    """Validate the orchestrator result."""
    print_section("VALIDATION")

    # Check error
    if result.error:
        print(f"  ⚠ Error: {result.error}")

    # Intel validation
    assert result.intel is not None, "Expected intel result"
    print("  ✓ Intel Agent produced a result")

    if result.intel.checklist:
        print("  ✓ Intel checklist present")
    else:
        print("  ⚠ Intel checklist is empty")

    # Plan validation
    assert result.plan is not None, "Expected plan result"
    print("  ✓ Planner Agent produced a result")

    if result.plan.scenarios:
        assert len(result.plan.scenarios) <= 3, (
            f"Max 3 scenarios, got {len(result.plan.scenarios)}"
        )
        print(f"  ✓ {len(result.plan.scenarios)} scenarios (max 3)")

        agents_used = set()
        for s in result.plan.scenarios:
            assert "task" in s, f"Scenario missing 'task': {s}"
            assert "agent" in s, f"Scenario missing 'agent': {s}"
            agents_used.add(s["agent"])
        print(f"  ✓ Agents: {sorted(agents_used)}")

        # Check if plan was stored
        if result.plan_data and result.plan_data.get("phases"):
            phases = result.plan_data["phases"]
            print(f"  ✓ Full plan stored: {len(phases)} phases")
        else:
            print("  ⚠ No stored plan (model returned scenarios directly)")

    elif result.plan.needs:
        print(f"  ✓ Planner needs more data: {len(result.plan.needs)} items")
    else:
        print("  ⚠ No scenarios and no needs")

    print()


async def test_web_target() -> None:
    """Test: Full pipeline — Intel → Planner for a web target (no loop mode)."""
    print_section("TEST: Web Target — Intel → Planner Pipeline")

    if llm_mode.mode == "local":
        print(f"  LLM mode: LOCAL / {local_llm_config.model}")
    else:
        print(f"  LLM mode: PUBLIC / {public_llm_config.api_provider} / {public_llm_config.model}")

    async with Orchestrator() as orch:
        result = await orch.run(
            target_url="http://www.enicarthage.rnu.tn/",
            target_type="web",
            scope="Full black-box web application pentest.",
            info="Target profile: public web app, auth flows, file upload and API-backed pages.",
        )

    print_intel(result)
    print_plan(result)
    validate(result)


async def test_api_target() -> None:
    """Test: Full pipeline — Intel → Planner for an API target (no loop mode)."""
    print_section("TEST: API Target — Intel → Planner Pipeline")

    if llm_mode.mode == "local":
        print(f"  LLM mode: LOCAL / {local_llm_config.model}")
    else:
        print(f"  LLM mode: PUBLIC / {public_llm_config.api_provider} / {public_llm_config.model}")

    async with Orchestrator() as orch:
        result = await orch.run(
            target_url="https://api.example.com/v1",
            target_type="api",
            scope="REST API security assessment.",
            info="GraphQL endpoint available at /graphql. JWT authentication.",
        )

    print_intel(result)
    print_plan(result)
    validate(result)


async def main() -> None:
    print("\n  PentaForge Orchestrator Test")
    print("  Intel Agent → Planner Agent Pipeline (single pass, no planner loop)")
    if llm_mode.mode == "local":
        print(f"  LLM mode: LOCAL / {local_llm_config.model}")
    else:
        print(f"  LLM mode: PUBLIC / {public_llm_config.api_provider} / {public_llm_config.model}")
    print()

    await test_web_target()
    await test_api_target()

    print("  All orchestrator tests completed.\n")


if __name__ == "__main__":
    asyncio.run(main())
