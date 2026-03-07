"""
Test the Planner Agent — No knowledge base required.

Uses only the plan management tools (get/update pentest plan) + get_page + clone_repo.
search_kb is excluded to avoid needing Qdrant / sentence-transformers.

Usage:
    cd /home/hosnizap/projects/PentaForge
    python -m server.test.planner_agent
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Ensure project root is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import structlog

from server.agents.planner.agent import PlannerAgent
from server.config.agent import planner_llm_config
from server.core.tool import Tool
from server.tools.planner.clone_repo import clone_repo
from server.tools.planner.get_page import get_page
from server.tools.planner.pentest_plan import (
    _reset_plan,
    get_pentest_plan,
    update_pentest_plan,
)

structlog.configure(
    processors=[
        structlog.dev.ConsoleRenderer(colors=True),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO+
)
logger = structlog.get_logger(__name__)

# Tools available to the planner (no search_kb — no KB needed)
TEST_TOOLS: list[Tool] = [
    clone_repo,
    get_page,
    get_pentest_plan,
    update_pentest_plan,
]


async def test_plan_creation() -> None:
    """Ask the planner to create a pentest plan for a sample web app."""
    _reset_plan()

    print("\n" + "=" * 70)
    print("  TEST: Planner Agent — Create a pentest plan (no KB)")
    print("=" * 70)
    print(f"  LLM: {planner_llm_config.api_provider} / {planner_llm_config.model}")
    print(f"  Tools: {[t.name for t in TEST_TOOLS]}")
    print("=" * 70 + "\n")

    async with PlannerAgent(tools=TEST_TOOLS) as agent:
        result = await agent.run(
            "Create a penetration testing plan for a web application at https://example.com. "
            "The target is a Django-based REST API with JWT authentication, "
            "PostgreSQL database, and running behind Nginx on AWS EC2. "
            "Scope: full black-box external pentest. "
            "Do NOT search the knowledge base — just use your training knowledge "
            "and the plan tools to build the plan."
        )

    print("\n" + "-" * 70)
    print("  RESULT")
    print("-" * 70)
    print(result)
    print("-" * 70 + "\n")


async def test_plan_update() -> None:
    """Ask the planner to read then update an existing plan."""
    _reset_plan()

    print("\n" + "=" * 70)
    print("  TEST: Planner Agent — Read & update plan")
    print("=" * 70 + "\n")

    async with PlannerAgent(tools=TEST_TOOLS) as agent:
        result = await agent.run(
            "First get the current pentest plan. Then update it: "
            "set target to 'api.example.com', scope to 'REST API endpoints only', "
            "and add two phases: "
            "1) 'Reconnaissance' with tasks: DNS enumeration, port scan, tech fingerprinting. "
            "2) 'Authentication Testing' with tasks: brute force, JWT token analysis, session management. "
            "Then get the plan again and show me the final result."
        )

    print("\n" + "-" * 70)
    print("  RESULT")
    print("-" * 70)
    print(result)
    print("-" * 70 + "\n")


async def main() -> None:
    print("\n  Planner Agent Test Suite (no knowledge base)")
    print("  Using .env from:", Path(planner_llm_config.model_config.get("env_file", "??")))
    print()

    await test_plan_creation()

    # Pause between tests to avoid Groq rate limits
    print("  Waiting 5s before next test (rate limit cooldown)...\n")
    await asyncio.sleep(5)

    await test_plan_update()

    print("\n  All tests completed.\n")


if __name__ == "__main__":
    asyncio.run(main())
