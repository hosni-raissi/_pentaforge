"""
Live IntelAgent run — final output only.
Usage:
    python -m server.test.test_intel_agent_live
    python -m server.test.test_intel_agent_live web_app "target details"
"""
from __future__ import annotations

import asyncio
import json
import sys

from server.agents.intel.agent import IntelAgent
from server.config.agent import llm_mode, local_llm_config, public_llm_config


async def _run_live(target_type: str, info: str) -> None:
    print("=== IntelAgent Live Test ===")
    if llm_mode.mode == "local":
        print(f"LLM mode: local ({local_llm_config.model})")
    else:
        print(f"LLM mode: public ({public_llm_config.model})")
    print(f"Target   : {target_type}")
    print(f"Info     : {info}")
    print()

    agent = IntelAgent()
    result = await agent.run(target_type=target_type, info=info)

    print("=== Final Intel Output ===")
    print(f"status: {result.status}")
    print(f"stats : {result.stats}")

    print("\nvulnerabilities:")
    if result.vulnerabilities:
        for item in result.vulnerabilities:
            print(f"- {item}")
    else:
        print("(empty)")

    print("\nchecklist:")
    if result.checklist:
        print(json.dumps(result.checklist, indent=2, ensure_ascii=False))
    else:
        print("(empty)")


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "web_app"
    info = (
        sys.argv[2]
        if len(sys.argv) > 2
        else "Live Intel test run: auth flows, upload, API-backed endpoints."
    )
    asyncio.run(_run_live(target, info))


if __name__ == "__main__":
    main()
