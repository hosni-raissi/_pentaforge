"""
Test the Recon Agent — 3-round execution with single tool per round.

Scenarios:
1. Enumerate subdomains for scanme.nmap.org
2. Detect technologies on http://scanme.nmap.org

Usage:
    python -m server.test.test_recon_agent
"""

import asyncio
import json
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

from server.agents.executer.recon.agent import ReconExecuterAgent, ExecuterCallback
from server.config.agent import llm_mode, public_llm_config, local_llm_config


class PrintCallback(ExecuterCallback):
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
    print(f"\n{'═' * 70}")
    print(f"  {title}")
    print(f"{'═' * 70}")


def _print_result(result) -> None:
    """Pretty print agent result."""
    if not result:
        print("  (No result)")
        return

    summary = str(result.summary or "").strip()
    if summary:
        print(f"\nSummary:\n{summary}\n")

    findings = result.findings or []
    if findings:
        print(f"Findings ({len(findings)}):")
        for finding in findings[:5]:  # Show first 5
            title = finding.get("title", "Unknown") if isinstance(finding, dict) else getattr(finding, "title", "Unknown")
            severity = finding.get("severity", "unknown") if isinstance(finding, dict) else getattr(finding, "severity", "unknown")
            print(f"  • {title} [{severity}]")
        if len(findings) > 5:
            print(f"  ... and {len(findings) - 5} more")

    tool_calls = result.tool_results or []
    if tool_calls:
        print(f"\nTools Used: {len(tool_calls)} tool executions")

    print(f"Status: {result.status if result else 'failed'}")




async def test_recon_scenario_2():
    """Scenario 2: Network reconnaissance on IP 10.129.32.166"""
    _print_header("SCENARIO 2: Network Reconnaissance for IP 10.129.32.166")

    agent = ReconExecuterAgent(
        mode=llm_mode.mode,
        config=public_llm_config,
        local_config=local_llm_config,
        callback=PrintCallback(),
        target_types=["network", "server"],
    )

    scenario = {
        "task": "Perform network reconnaissance on 10.129.32.166",
        "agent": "recon",
        "priority": 1,
        "details": "Scan target IP for open ports, identify services, detect OS/technologies, enumerate network information",
        "methods": ["Port scanning", "Service detection", "OS fingerprinting", "ARP enumeration"],
        "target": "10.129.32.166",
        "target_type": "network"
    }

    message = (
        f"Target: {scenario['target']}\n"
        f"Target type: {scenario['target_type']}\n\n"
        f"Scenario: {scenario['task']}\n"
        f"Priority: P{scenario['priority']}\n"
        f"Details: {scenario['details']}\n\n"
    )

    print("\nExecuting Recon Agent...")
    result = await agent.run(message)

    print("\n" + "─" * 70)
    _print_result(result)

    return result



async def main():
    """Run all recon scenarios."""
    print("\n" + "╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  RECON AGENT TEST — 3-ROUND WORKFLOW".center(68) + "║")
    print("║" + "  Network Reconnaissance on IP 10.129.32.166".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")

    results = []

    try:
        # Scenario: Network reconnaissance
        result = await test_recon_scenario_2()
        results.append(("Network Reconnaissance", result))
        await asyncio.sleep(2)

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return



if __name__ == "__main__":
    asyncio.run(main())
