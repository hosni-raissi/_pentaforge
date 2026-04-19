"""
Test verify agent with step-by-step output for vulnerability verification.

Uses Mistral LLM (configured in server/.env for VERIFY role group)
Shows full 3-round flow with findings verification, false positive detection, and final verdict.
"""

import asyncio
import json

from server.agents.executer.verify.agent import VerifyExecuterAgent
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

        # SHOW TOOL ARGUMENTS FOR DEBUGGING
        if args:
            print(f"    → Tool args: {json.dumps(args, indent=6)}")

        self.tool_approvals.append({
            "role": role,
            "tool": tool_name,
            "call_id": call_id,
            "args": args,
        })
        return True  # Auto-approve

    def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        """No password needed for verify agent tests."""
        return None


async def test_verify_agent_xss():
    """Test verify agent on XSS finding."""

    print("\n" + "=" * 80)
    print("VERIFY AGENT TEST - XSS VERIFICATION")
    print("=" * 80)

    callback = DetailedCallback()
    config = get_public_agent_config(agent_role="verify")
    verify = VerifyExecuterAgent(config=config, callback=callback)

    # Create test finding - XSS to verify
    finding = {
        "type": "reflected_xss",
        "target": "GET /search?q=<script>alert('xss')</script>",
        "parameter": "q",
        "payload_type": "reflected",
        "severity": "high",
        "endpoint": "/search",
        "description": "Reflected XSS in search parameter - payload not encoded in response",
    }

    user_message = f"""
Verify this XSS finding:

**Finding Type:** {finding['type']}
**Target:** {finding['target']}
**Parameter:** {finding['parameter']}
**Payload Type:** {finding['payload_type']}
**Severity:** {finding['severity']}
**Endpoint:** {finding['endpoint']}
**Description:** {finding['description']}

Follow the 3-round verification process:
- Round 1/3: Attempt to reproduce the XSS with verification tools
- Round 2/3: Analyze Round 1 results, create summary, execute additional payload variations
- Round 3/3: Consolidate evidence into FINAL VERDICT JSON only

Return verdict: real_vulnerability | false_positive | inconclusive
Include confidence level (0.0-1.0), evidence chain, and routing information for orchestrator.
"""

    print("\n📋 FINDING TO VERIFY:")
    print(f"  Type: {finding['type']}")
    print(f"  Target: {finding['target']}")
    print(f"  Parameter: {finding['parameter']}")
    print(f"  Severity: {finding['severity']}")

    print("\n🚀 STARTING VERIFY AGENT RUN (3-ROUND FLOW)...")
    print("-" * 80)

    try:
        result = await verify.run(user_message)

        print("\n" + "=" * 80)
        print("✅ VERIFY AGENT COMPLETED")
        print("=" * 80)

        print("\n📊 FINAL VERDICT:")
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

        print(f"\n🎯 FINDINGS ({len(result.findings) if result.findings else 0}):")
        if result.findings:
            for i, finding in enumerate(result.findings, 1):
                print(f"\n  Finding #{i}:")
                print(f"    Type: {finding.get('type', 'N/A')}")
                print(f"    Severity: {finding.get('severity', 'N/A')}")

        if result.summary:
            print(f"\n📝 VERIFICATION SUMMARY:")
            print(f"  {result.summary}")

        print(f"\n💬 CALLBACK STEPS ({len(callback.steps)}):")
        for i, step in enumerate(callback.steps, 1):
            if i <= 15:
                print(f"  {i}. {step}")
        if len(callback.steps) > 15:
            print(f"  ... and {len(callback.steps) - 15} more steps")

        print("\n" + "=" * 80)
        print("📦 FINAL VERDICT STRUCTURE:")
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
    """Run all verify agent tests."""
    print("\n" + "=" * 100)
    print("VERIFY AGENT UNIT TESTS - FULL 3-ROUND FLOW")
    print("=" * 100)

    await test_verify_agent_xss()

    print("\n" + "=" * 100)
    print("ALL VERIFY AGENT TESTS COMPLETED")
    print("=" * 100 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
