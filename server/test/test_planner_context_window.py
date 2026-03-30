"""Unit tests for planner context-window behavior."""

from __future__ import annotations

import json
from copy import deepcopy

from server.agents.orchestrator import _extract_checklist_window
from server.agents.planner.agent import (
    _build_intel_checklist_windows,
    _build_loop_plan_context_message,
)
from server.agents.planner.config import (
    PLANNER_CHECKLIST_WINDOW_MAX_ITEMS,
    PLANNER_CHECKLIST_WINDOW_MAX_ITEMS_PER_PHASE,
    PLANNER_LOOP_CONTEXT_MAX_SCENARIOS_PER_STEP,
    PLANNER_LOOP_CONTEXT_MAX_STEPS_PER_PHASE,
)
from server.agents.planner.tools.pentest_plan import _current_plan


def _parse_json_from_prefixed_message(message: str) -> dict:
    start = message.find("{")
    assert start >= 0, "Expected JSON object in message."
    parsed = json.loads(message[start:])
    assert isinstance(parsed, dict)
    return parsed


def test_extract_checklist_window_limits_total_and_per_phase() -> None:
    payload = {
        "target_type": "web_app",
        "available_total": 120,
        "checklist": [
            {
                "phase": "1",
                "title": "Reconnaissance",
                "items": [
                    {"name": f"Recon item {i}", "priority": (i % 5) + 1}
                    for i in range(1, 30)
                ],
            },
            {
                "phase": "3",
                "title": "Configuration Review",
                "items": [
                    {"name": f"Config item {i}", "priority": (i % 5) + 1}
                    for i in range(1, 30)
                ],
            },
            {
                "phase": "4",
                "title": "Exploitation & Validation",
                "items": [
                    {"name": f"Exploit item {i}", "priority": (i % 5) + 1}
                    for i in range(1, 30)
                ],
            },
        ],
    }

    window = _extract_checklist_window(payload)
    assert window["target_type"] == "web_app"
    assert window["available_total"] == 120
    assert window["truncated"] is True
    assert window["window_items"] <= PLANNER_CHECKLIST_WINDOW_MAX_ITEMS
    assert len(window["checklist"]) > 0

    total_selected = 0
    for phase in window["checklist"]:
        items = phase.get("items", [])
        assert len(items) <= PLANNER_CHECKLIST_WINDOW_MAX_ITEMS_PER_PHASE
        total_selected += len(items)
    assert total_selected == window["window_items"]


def test_extract_checklist_window_supports_string_items() -> None:
    payload = {
        "target_type": "web_app",
        "checklist": [
            {
                "phase": "1",
                "title": "Reconnaissance",
                "items": ["Fingerprint Web Server", "Identify Entry Points"],
            }
        ],
    }
    window = _extract_checklist_window(payload)
    assert window["window_items"] == 2
    selected = window["checklist"][0]["items"]
    assert selected[0]["name"] == "Fingerprint Web Server"
    assert "priority" not in selected[0]


def test_loop_context_message_is_compact_windowed() -> None:
    original_plan = deepcopy(_current_plan)
    try:
        _current_plan.clear()
        _current_plan.update(
            {
                "target": "https://example.com",
                "scope": "web scope",
                "target_types": ["web"],
                "notes": "planner notes",
                "phases": [
                    {
                        "name": "Reconnaissance",
                        "priority": 1,
                        "steps": [
                            {
                                "id": f"recon-{i}",
                                "description": f"step {i}",
                                "scenarios": [
                                    {
                                        "task": f"recon task {i}-{j}",
                                        "agent": "recon",
                                        "priority": 2,
                                        "done": j % 2 == 0,
                                    }
                                    for j in range(1, 8)
                                ],
                            }
                            for i in range(1, 6)
                        ],
                    }
                ],
            }
        )

        msg = _build_loop_plan_context_message()
        compact = _parse_json_from_prefixed_message(msg)

        assert compact["target"] == "https://example.com"
        assert compact["context_window"]["mode"] == "compact"
        assert compact["context_window"]["steps_per_phase"] == (
            PLANNER_LOOP_CONTEXT_MAX_STEPS_PER_PHASE
        )
        assert compact["context_window"]["scenarios_per_step"] == (
            PLANNER_LOOP_CONTEXT_MAX_SCENARIOS_PER_STEP
        )

        phase = compact["phases"][0]
        assert phase["step_count"] == 5
        assert len(phase["steps"]) <= PLANNER_LOOP_CONTEXT_MAX_STEPS_PER_PHASE
        assert phase["pending_scenarios"] + phase["done_scenarios"] == 35

        for step in phase["steps"]:
            assert len(step["scenarios"]) <= PLANNER_LOOP_CONTEXT_MAX_SCENARIOS_PER_STEP
    finally:
        _current_plan.clear()
        _current_plan.update(original_plan)


def test_intel_checklist_windows_cover_all_items_without_duplicates() -> None:
    payload = {
        "target_type": "web_app",
        "available_total": 46,
        "checklist": [
            {
                "phase": "1",
                "title": "Reconnaissance",
                "items": [
                    {"name": f"Recon {i}", "priority": 2}
                    for i in range(1, 18)
                ],
            },
            {
                "phase": "3",
                "title": "Configuration Review",
                "items": [
                    {"name": f"Config {i}", "priority": 3}
                    for i in range(1, 16)
                ],
            },
            {
                "phase": "4",
                "title": "Exploitation & Validation",
                "items": [
                    {"name": f"Exploit {i}", "priority": 5}
                    for i in range(1, 15)
                ],
            },
        ],
    }

    overview, windows = _build_intel_checklist_windows(payload)
    assert overview["available_total"] == 46
    assert windows, "Expected at least one checklist window."

    seen: set[str] = set()
    for window in windows:
        for phase in window.get("checklist", []):
            for item in phase.get("items", []):
                name = str(item.get("name", "")).strip()
                assert name, "Checklist item name must not be empty."
                assert name not in seen, f"Duplicate checklist item across windows: {name}"
                seen.add(name)

    assert len(seen) == 46, "All checklist items should be represented across windows."


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
