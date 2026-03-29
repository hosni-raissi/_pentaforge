"""
Live IntelAgent run with verbose tool-call tracing.

Usage:
    python -m server.test.test_intel_agent_live
    python -m server.test.test_intel_agent_live web_app "target details"
"""

from __future__ import annotations

import asyncio
import sys
import time

from server.agents.intel.agent import IntelAgent, IntelCallback
from server.config.agent import llm_mode, local_llm_config, public_llm_config


class TraceCallback(IntelCallback):
    def __init__(self) -> None:
        self._start = time.perf_counter()

    def _t(self) -> str:
        return f"{time.perf_counter() - self._start:6.2f}s"

    def on_step(self, message: str) -> None:
        print(f"[STEP {self._t()}] {message}")

    def on_done(self, message: str) -> None:
        print(f"[DONE {self._t()}] {message}")

    def on_warn(self, message: str) -> None:
        print(f"[WARN {self._t()}] {message}")


async def _run_live(target_type: str, info: str) -> None:
    print("=== IntelAgent Live Test ===")
    if llm_mode.mode == "local":
        print(f"LLM mode: local ({local_llm_config.model})")
    else:
        print(f"LLM mode: public ({public_llm_config.model})")
    print(f"Target   : {target_type}")
    print(f"Info     : {info}")
    print()

    agent = IntelAgent(callback=TraceCallback())
    result = await agent.run(target_type=target_type, info=info)

    print("\n=== Final Intel Output ===")
    print(f"status: {result.status}")
    print(f"stats : {result.stats}")
    print("summary:")
    print(result.summary or "(empty)")


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

