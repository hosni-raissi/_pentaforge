"""
Test the Intel Agent — clean step-by-step output.

Usage:
    python -m server.test.test_intel_agent
"""

import asyncio
import logging
import sys
import time
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import structlog
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from server.agents.intel.agent import IntelAgent, IntelCallback
from server.config.agent import llm_mode, public_llm_config, local_llm_config
import warnings
warnings.filterwarnings("ignore", message="Api key is used with an insecure connection")

TARGET_TYPE = "web"
INFO = "Target profile: public web app, auth flows, file upload and API-backed pages."


class PrintCallback(IntelCallback):
    """Prints clean step-by-step progress."""

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


async def main():
    print(f"\n{'═' * 60}")
    print("  PentaForge Intel Agent Test")
    print(f"{'═' * 60}")
    if llm_mode.mode == "local":
        print(f"  LLM: LOCAL / {local_llm_config.model}")
    else:
        print(f"  LLM: PUBLIC / {public_llm_config.api_provider} / {public_llm_config.model}")
    print(f"  Target: {TARGET_TYPE}")

    cb = PrintCallback()
    agent = IntelAgent(callback=cb)
    result = await agent.run(target_type=TARGET_TYPE, info=INFO)

    print(f"\n{'═' * 60}")
    print("  RESULT")
    print(f"{'═' * 60}")
    print(f"  Status: {result.status}")
    print(f"  Stats: update_status={result.stats.get('update_status', '?')}")

    print(f"\n  ── SUMMARY ──")
    for line in result.summary.split("\n"):
        print(f"  {line}")

    print(f"\n{'═' * 60}")


if __name__ == "__main__":
    asyncio.run(main())