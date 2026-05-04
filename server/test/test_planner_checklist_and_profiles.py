from __future__ import annotations

import asyncio
import json
from pathlib import Path

from server.agents.planner.prompts import trim_brain
from server.agents.planner.tools.pentest_plan import _apply_scenario_evidence_gating
from server.app.orchestrator import (
    _display_cycle_number,
    _extract_prioritized_exec_scenarios,
    _scenario_missing_prerequisites,
)
from server.agents.executer.recon.tools import ALL_RECON_TOOLS
from server.agents.planner.agent import PlannerAgent
from server.core.llm import LLMResponse
from server.core.tool import tool


def test_target_info_profiles_only_reference_registered_recon_tools() -> None:
    profile = json.loads(
        Path("server/nodes/information_gathering/target_info_profiles.json").read_text(
            encoding="utf-8"
        )
    )
    known_tools = {tool.name for tool in ALL_RECON_TOOLS}

    missing: list[tuple[str, str, str]] = []
    for target_type, blocks in profile.items():
        for block in blocks:
            for tool_name in block.get("tools", []):
                if tool_name not in known_tools:
                    missing.append((target_type, str(block.get("id", "")), tool_name))

    assert not missing, f"Missing target-info recon tools: {missing}"


def test_generate_checklist_can_use_tools_before_finalizing() -> None:
    seen_tool_args: dict[str, object] = {}

    @tool(name="get_checklists", description="Fetch checklist data.")
    async def fake_get_checklists(
        target_type: str,
        n_items: int = 0,
        info: str = "",
    ) -> str:
        seen_tool_args["target_type"] = target_type
        seen_tool_args["n_items"] = n_items
        seen_tool_args["info"] = info
        return json.dumps(
            {
                "target_type": target_type,
                "available_total": 1,
                "checklist": [
                    {
                        "phase": "1",
                        "title": "Reconnaissance",
                        "items": [{"name": "Review observed routes", "priority": 3}],
                    }
                ],
            }
        )

    @tool(name="search_kb", description="Search internal knowledge.")
    async def fake_search_kb(query: str, domain: str = "shared", n_results: int = 5) -> str:
        return json.dumps({"query": query, "domain": domain, "n_results": n_results})

    @tool(name="search_web", description="Search the public web.")
    async def fake_search_web(query: str, max_results: int = 5) -> str:
        return json.dumps({"query": query, "max_results": max_results, "results": []})

    @tool(name="get_page", description="Fetch a page.")
    async def fake_get_page(url: str, css_selector: str = "") -> str:
        return f"page:{url}:{css_selector}"

    class FakeLLM:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        async def chat(self, messages, tools=None, temperature=0, max_tokens=None):
            self.calls.append(
                {
                    "messages": messages,
                    "tools": tools,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
            )
            if len(self.calls) == 1:
                return LLMResponse(
                    content="",
                    tool_calls=[
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "get_checklists",
                                "arguments": json.dumps({"n_items": 8}),
                            },
                        }
                    ],
                    finish_reason="tool_calls",
                    usage={},
                )
            return LLMResponse(
                content=json.dumps(
                    {
                        "status": "complete",
                        "checklist": {
                            "target_type": "web_app",
                            "available_total": 2,
                            "checklist": [
                                {
                                    "phase": "1",
                                    "title": "Reconnaissance",
                                    "items": [
                                        {
                                            "name": "Review observed routes and JavaScript endpoints",
                                            "priority": 2,
                                        }
                                    ],
                                },
                                {
                                    "phase": "2",
                                    "title": "Vulnerability Discovery",
                                    "items": [
                                        {
                                            "name": "Validate whether exposed parameters reflect input",
                                            "priority": 1,
                                        }
                                    ],
                                },
                            ],
                        },
                    }
                ),
                tool_calls=[],
                finish_reason="stop",
                usage={},
            )

    planner = PlannerAgent(
        tools=[
            fake_get_checklists,
            fake_search_kb,
            fake_search_web,
            fake_get_page,
        ],
        project_id="test-project",
    )
    fake_llm = FakeLLM()
    planner._llm = fake_llm  # type: ignore[assignment]

    result = asyncio.run(
        planner.generate_checklist(
            "Target: https://example.com\nScope: web app\nObserved: login route and JS assets.",
            current_checklist={},
            target_type="web_app",
        )
    )

    first_call_tools = fake_llm.calls[0]["tools"]
    tool_names = {
        entry["function"]["name"] for entry in first_call_tools if isinstance(entry, dict)
    }

    assert {"get_checklists", "search_kb", "search_web", "get_page"} == tool_names
    assert seen_tool_args["target_type"] == "web_app"
    assert "https://example.com" in str(seen_tool_args["info"])
    assert result.status == "complete"
    assert result.checklist.get("available_total") == 2


def test_trim_brain_keeps_routes_blocked_context_and_hints() -> None:
    payload = {
        "target_info": {"target": "https://example.com"},
        "tech_stack": {"server": "nginx", "backend_language": "php"},
        "confirmed_vulns": [{"name": "SQL injection", "endpoint": "/login"}],
        "recent_info": [{"name": "About page", "endpoint": "/about.php"}],
        "false_positives": [{"name": "Fake DVWA path"}],
        "anonymous_routes": ["/", "/about.php", "/login.php"],
        "authenticated_routes": ["/account"],
        "blocked_routes": ["/dvwa/login.php"],
        "blocked_route_prefixes": ["/dvwa"],
        "parameter_hints": ["id", "name", "page"],
        "tool_efficiency": {"http_probe": 0.5},
        "tool_false_positive_rates": {"run_custom": 0.9},
    }

    rendered = trim_brain(payload)

    assert "/about.php" in rendered
    assert "/dvwa/login.php" in rendered
    assert "\"parameter_hints\": [\"id\", \"name\", \"page\"]" in rendered
    assert "\"tool_false_positive_rates\"" in rendered


def test_scenario_evidence_gating_adds_metadata_and_demotes_hypothesized_exploit() -> None:
    scenario = {
        "task": "Validate whether POST /login email parameter is vulnerable to SQL injection",
        "agent": "exploit",
        "priority": 1,
        "details": "Hypothesized from login form and reflected SQL error text.",
        "methods": ["Blind SQLi validation"],
    }

    gated = _apply_scenario_evidence_gating("Exploitation", scenario)

    assert gated["evidence_tier"] == "hypothesized"
    assert gated["confidence_label"] == "low"
    assert "route_observed" in gated["prerequisites"]
    assert "parameter_observed" in gated["prerequisites"]
    assert gated["agent"] == "recon"
    assert gated["priority"] >= 3


def test_prerequisite_check_and_selection_prefer_confirmed_high_confidence() -> None:
    scenario = {
        "task": "Exploit reflected XSS on /about.php name parameter",
        "details": "Try to execute script payload in reflected sink.",
        "methods": ["Reflected XSS validation"],
        "prerequisites": ["route_observed", "parameter_observed", "input_or_reflection_observed"],
    }
    target_memory = {
        "anonymous_routes": ["/about.php?name=test"],
        "parameter_hints": ["name"],
    }

    missing = _scenario_missing_prerequisites(scenario, target_memory=target_memory)
    assert missing == ["input_or_reflection_observed"]

    plan_data = {
        "phases": [
            {
                "name": "Reconnaissance",
                "steps": [
                    {
                        "id": "s1",
                        "scenarios": [
                            {
                                "task": "Confirm SQLi on /login email parameter",
                                "agent": "recon",
                                "priority": 2,
                                "evidence_tier": "confirmed",
                                "confidence_label": "high",
                                "done": False,
                            },
                            {
                                "task": "Hypothesize XSS on /about.php",
                                "agent": "recon",
                                "priority": 2,
                                "evidence_tier": "hypothesized",
                                "confidence_label": "low",
                                "done": False,
                            },
                        ],
                    }
                ],
            }
        ]
    }

    ordered = _extract_prioritized_exec_scenarios(plan_data, limit=2)
    assert ordered[0]["task"] == "Confirm SQLi on /login email parameter"


def test_selection_prefers_high_value_sink_family_over_low_signal_branch() -> None:
    plan_data = {
        "phases": [
            {
                "name": "Reconnaissance",
                "steps": [
                    {
                        "id": "s1",
                        "scenarios": [
                            {
                                "task": "Re-test /eval for HTTP header injection using refined payloads",
                                "agent": "recon",
                                "priority": 2,
                                "evidence_tier": "observed",
                                "confidence_label": "high",
                                "done": False,
                            },
                            {
                                "task": "Validate whether POST /query id parameter is vulnerable to SQL injection",
                                "agent": "recon",
                                "priority": 2,
                                "evidence_tier": "observed",
                                "confidence_label": "high",
                                "done": False,
                            },
                        ],
                    }
                ],
            }
        ]
    }

    ordered = _extract_prioritized_exec_scenarios(plan_data, limit=2)
    assert ordered[0]["task"] == "Validate whether POST /query id parameter is vulnerable to SQL injection"


def test_selection_penalizes_repeated_dead_family_branches() -> None:
    plan_data = {
        "phases": [
            {
                "name": "Reconnaissance",
                "steps": [
                    {
                        "id": "s1",
                        "scenarios": [
                            {
                                "task": "Re-test /eval for HTTP header injection using refined payloads",
                                "agent": "recon",
                                "priority": 1,
                                "evidence_tier": "observed",
                                "confidence_label": "medium",
                                "execution_history": [
                                    {"cycle": 4, "status": "blocked", "summary": "No header processing"},
                                    {"cycle": 5, "status": "blocked", "summary": "Static response"},
                                ],
                                "done": False,
                            },
                            {
                                "task": "Validate whether /fetch url parameter enables SSRF to internal metadata endpoints",
                                "agent": "recon",
                                "priority": 2,
                                "evidence_tier": "observed",
                                "confidence_label": "high",
                                "done": False,
                            },
                        ],
                    }
                ],
            }
        ]
    }

    ordered = _extract_prioritized_exec_scenarios(plan_data, limit=2)
    assert ordered[0]["task"] == "Validate whether /fetch url parameter enables SSRF to internal metadata endpoints"


def test_display_cycle_number_starts_main_loop_at_one_without_warmup_offset() -> None:
    assert _display_cycle_number(1) == 1
    assert _display_cycle_number(2) == 2
    assert _display_cycle_number(1, prior_cycles=2) == 3
