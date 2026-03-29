"""
Tool-only checklist cleaner demo.

Usage:
    python -m server.test.test_intel_suite
"""

from __future__ import annotations

import asyncio
import importlib
import json
from typing import Any

checklists_module = importlib.import_module("server.agents.intel.tools.get_checklists")


async def main() -> None:
    target_type = "web_app"
    scenarios: list[dict[str, Any]] = [
        {
            "name": "exclude-sqli-xss",
            "info": "Public web target. No SQL injection. Don't test XSS.",
        },
    ]

    print("\n=== get_checklists -> llm clean tool test ===")
    print(f"target: {target_type}")

    for idx, scenario in enumerate(scenarios, start=1):
        info = str(scenario.get("info", ""))
        print(f"\n[{idx}] scenario: {scenario.get('name', 'unnamed')}")
        print(f"info: {info}")

        raw = await checklists_module.get_checklists.execute(
            target_type=target_type,
            n_items=0,
            info=info,
        )
        parsed = json.loads(raw)

        cleaned_raw = await checklists_module.clean_checklists_with_llm(
            checklist_data=parsed,
            target_type=target_type,
            info=info,
        )
        cleaned = json.loads(cleaned_raw)

        print(f"available_total: {parsed.get('available_total', parsed.get('total', 0))}")
        print("--- cleaned checklist ---")
        print(json.dumps(cleaned, indent=2, ensure_ascii=False))

    print()


if __name__ == "__main__":
    asyncio.run(main())
