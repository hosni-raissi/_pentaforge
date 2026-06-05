from __future__ import annotations

import json

from server.agents.executer.base import BaseExecuterAgent
from server.agents.executer.global_cache import GlobalToolCache


def test_global_tool_cache_returns_completed_result(tmp_path) -> None:
    cache = GlobalToolCache(str(tmp_path), "recon")
    signature = "run_custom::demo"

    blocked, reason = cache.check_or_lock_signature(
        signature,
        "run_custom",
        {"command": "curl", "args": ["-I", "http://example.test"]},
        "scenario-one",
    )
    assert blocked is False
    assert reason == ""

    old_result = json.dumps({"success": True, "stdout": "HTTP/1.1 200 OK"}, ensure_ascii=True)
    cache.unlock_and_update(signature, "HTTP 200 observed", old_result)

    blocked, reason = cache.check_or_lock_signature(
        signature,
        "run_custom",
        {"command": "curl", "args": ["-I", "http://example.test"]},
        "scenario-two",
    )
    assert blocked is True
    assert "cached result" in reason

    cached = cache.get_completed_result(signature)
    assert cached is not None
    assert cached["status"] == "COMPLETED"
    assert cached["summary"] == "HTTP 200 observed"
    assert cached["result"] == old_result


def test_tool_invocation_signature_ignores_scenario_and_run_custom_reason() -> None:
    agent = BaseExecuterAgent.__new__(BaseExecuterAgent)

    first = agent._build_tool_invocation_signature(
        tool_name="run_custom",
        args={
            "command": "curl",
            "args": ["-I", "http://example.test"],
            "reason": "first scenario reason",
            "timeout": 30,
        },
        scenario_id="scenario-one",
    )
    second = agent._build_tool_invocation_signature(
        tool_name="run_custom",
        args={
            "command": "curl",
            "args": ["-I", "http://example.test"],
            "reason": "different scenario reason",
            "timeout": 120,
        },
        scenario_id="scenario-two",
    )

    assert first == second
