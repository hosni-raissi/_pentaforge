from __future__ import annotations

import asyncio
import json

from server.agents.executer.base import BaseExecuterAgent, _NoOpCallback
from server.core.tool import Tool


class _ApproveAllCallback(_NoOpCallback):
    def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, object],
        call_id: str,
    ) -> bool:
        return True


def _build_agent(
    *,
    role: str,
    tool_name: str,
    tool_fn,
    callback,
) -> BaseExecuterAgent:
    agent = object.__new__(BaseExecuterAgent)
    tool = Tool(
        name=tool_name,
        description="test tool",
        fn=tool_fn,
        parameters={"type": "object", "properties": {}},
    )
    agent._role = role
    agent._cb = callback
    agent._tools = {tool_name: tool}
    agent._tool_valid_params = {tool_name: None}
    return agent


def test_exploit_tool_is_blocked_without_user_approval():
    executed = {"value": False}

    def _fn() -> str:
        executed["value"] = True
        return json.dumps({"success": True})

    agent = _build_agent(
        role="exploit",
        tool_name="fake_exploit_tool",
        tool_fn=_fn,
        callback=_NoOpCallback(),
    )

    tool_calls = [
        {"id": "call-1", "function": {"name": "fake_exploit_tool", "arguments": "{}"}},
    ]
    _, tool_results, _, halted = asyncio.run(agent._run_tools(tool_calls))

    assert halted is True
    assert executed["value"] is False
    assert tool_results
    assert tool_results[0]["approval_required"] is True


def test_run_custom_is_blocked_in_recon_without_user_approval():
    executed = {"value": False}

    def _fn() -> str:
        executed["value"] = True
        return json.dumps({"success": True})

    agent = _build_agent(
        role="recon",
        tool_name="run_custom",
        tool_fn=_fn,
        callback=_NoOpCallback(),
    )

    tool_calls = [
        {"id": "call-2", "function": {"name": "run_custom", "arguments": "{}"}},
    ]
    _, tool_results, _, halted = asyncio.run(agent._run_tools(tool_calls))

    assert halted is True
    assert executed["value"] is False
    assert tool_results[0]["approval_required"] is True


def test_exploit_tool_runs_after_approval():
    executed = {"value": False}

    def _fn() -> str:
        executed["value"] = True
        return json.dumps({"success": True, "msg": "ran"})

    agent = _build_agent(
        role="exploit",
        tool_name="fake_exploit_tool",
        tool_fn=_fn,
        callback=_ApproveAllCallback(),
    )

    tool_calls = [
        {"id": "call-3", "function": {"name": "fake_exploit_tool", "arguments": "{}"}},
    ]
    _, tool_results, _, halted = asyncio.run(agent._run_tools(tool_calls))

    assert halted is False
    assert executed["value"] is True
    assert tool_results
    assert tool_results[0]["approval_required"] is False
