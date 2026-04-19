"""
Test retest agent with step-by-step output for report entry generation.

Uses Mistral LLM (configured in server/.env for RETEST role group)
Shows full 3-round flow with PoC execution, screenshot capture, and report building.
"""

import asyncio
import json

from server.agents.executer.retest.agent import RetestExecuterAgent
from server.agents.executer.base import ExecuterCallback
from server.config.agent import get_public_agent_config


class DetailedCallback(ExecuterCallback):
    """Callback to capture detailed round-by-round output."""

    def __init__(self):
        self.steps = []
        self.warnings = []
        self.tool_approvals = []

    def on_step(self, message: str) -> None:
        """Capture step messages."""
        print(f"  → {message}")
        self.steps.append(message)

    def on_done(self, message: str) -> None:
        """Capture done messages."""
        print(f"  ✅ {message}")
        self.steps.append(f"[DONE] {message}")

    def on_warn(self, message: str) -> None:
        """Capture warning messages."""
        print(f"  ⚠️  {message}")
        self.warnings.append(message)

    def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict,
        call_id: str,
    ) -> bool:
        """Auto-approve tools for testing."""
        approval_msg = f"[AUTO-APPROVE] {role} tool '{tool_name}' (call_id={call_id})"
        print(f"  🔓 {approval_msg}")

        if args:
            print(f"    → Tool args: {json.dumps(args, indent=6)}")

        self.tool_approvals.append({
            "role": role,
            "tool": tool_name,
            "call_id": call_id,
            "args": args,
        })
        return True

    def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        """No password needed for retest agent tests."""
        return None


async def test_retest_agent_xss():
    """Test retest agent on XSS report entry generation."""

    print("\n" + "=" * 80)
    print("RETEST AGENT TEST - XSS REPORT BUILDING")
    print("=" * 80)

    callback = DetailedCallback()
    config = get_public_agent_config(agent_role="retest")
    retest = RetestExecuterAgent(config=config, callback=callback)

    verified_vuln = {
        "type": "reflected_xss",
        "target": "GET /search",
        "parameter": "q",
        "payload": "<script>alert('XSS')</script>",
        "severity": "high",
        "endpoint": "/search",
        "description": "Reflected XSS in search parameter - payload not encoded in response",
    }

    user_message = f"""
CONFIRMED VULNERABILITY - Build Report Entry

Target: {verified_vuln['target']}
Finding: Cross-Site Scripting (XSS)

**Verified Finding Details:**
Type: {verified_vuln['type']}
Endpoint: {verified_vuln['endpoint']}
Parameter: {verified_vuln['parameter']}
Severity: {verified_vuln['severity']}
Payload: {verified_vuln['payload']}

**Your Mission:**
1. Execute XSS payload against the endpoint
2. Capture browser screenshot showing alert execution
3. Gather request/response logs
4. Build comprehensive report entry
5. Return JSON for database storage

Report Entry must include:
- XSS type (reflected/stored)
- Affected endpoint
- Payload that triggers vulnerability
- Browser screenshot proof
- Remediation: Input validation and output encoding
"""

    print("\n📋 VERIFIED VULNERABILITY:")
    print(f"  Type: {verified_vuln['type']}")
    print(f"  Endpoint: {verified_vuln['endpoint']}")
    print(f"  Parameter: {verified_vuln['parameter']}")
    print(f"  Severity: {verified_vuln['severity']}")

    print("\n🚀 STARTING RETEST AGENT RUN (3-ROUND FLOW)...")
    print("-" * 80)

    try:
        result = await retest.run(user_message)

        print("\n" + "=" * 80)
        print("✅ RETEST AGENT COMPLETED")
        print("=" * 80)

        print("\n📊 REPORT GENERATION STATUS:")
        print(f"  Status: {result.status}")
        print(f"  Completed Rounds: {result.rounds_executed}")

        if result.round_labels:
            print(f"  Round Details:")
            for i, label in enumerate(result.round_labels, 1):
                print(f"    Round {i}: {label}")

        print(f"\n🔧 TOOLS USED ({len(result.tool_results) if result.tool_results else 0}):")
        if result.tool_results:
            for i, tool in enumerate(result.tool_results, 1):
                print(f"  Tool {i}: {tool.get('name', 'unknown')}")

        if result.summary:
            print(f"\n📝 REPORT SUMMARY:")
            summary_preview = str(result.summary)[:300]
            print(f"  {summary_preview}")

        print(f"\n💬 CALLBACK STEPS ({len(callback.steps)}):")
        for i, step in enumerate(callback.steps, 1):
            if i <= 15:
                print(f"  {i}. {step}")
        if len(callback.steps) > 15:
            print(f"  ... and {len(callback.steps) - 15} more steps")

        print("\n" + "=" * 80)
        print("📦 REPORT ENTRY STRUCTURE:")
        print("=" * 80)

        result_dict = {
            "status": result.status,
            "rounds_executed": result.rounds_executed,
            "findings_count": len(result.findings) if result.findings else 0,
            "evidence_count": len(result.evidence) if result.evidence else 0,
            "summary": result.summary,
        }

        print(json.dumps(result_dict, indent=2))

    except Exception as e:
        print(f"\n❌ ERROR: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()


async def main():
    """Run all retest agent tests."""
    print("\n" + "=" * 100)
    print("RETEST AGENT UNIT TESTS - FULL 3-ROUND FLOW")
    print("=" * 100)

    await test_retest_agent_xss()

    print("\n" + "=" * 100)
    print("ALL RETEST AGENT TESTS COMPLETED")
    print("=" * 100 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
