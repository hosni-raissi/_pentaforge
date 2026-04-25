import pytest
import asyncio
import json

from server.app.orchestrator import (
    _build_verified_finding_entry,
    _build_post_warmup_intel_info,
    _build_planner_kickoff_message,
    _build_static_recon_plan,
    _build_target_execution_guidance,
    _append_scenario_execution_history,
    _format_agent_execution_history_for_prompt,
    _format_structured_checklist_for_prompt,
    _build_warmup_planner_message,
    _build_warmup_recon_plan,
    _normalize_scenario_status,
    _normalize_perceptor_classification,
    ScanOrchestratorService,
    _format_static_recon_plan_for_prompt,
    _select_warmup_recon_batches,
    _should_trigger_retest,
    _write_project_findings_cache,
)
from server.agents.executer.base import BaseExecuterAgent
from server.agents.executer.base import _default_status_for_failed_consolidation
from server.agents.executer.base import _compact_tool_result_payload
from server.agents.executer.base import _get_valid_params
from server.agents.executer.base import _parse_executer_output
from server.agents.executer.recon.agent import (
    _max_tool_calls_per_round_for_message,
    _tool_timeout_cap_for_message,
    build_recon_scenario_packet,
)
from server.agents.executer.recon.tools.all.run_custom import strip_output_file_flags
from server.agents.intel.agent import (
    _ensure_structured_checklist_min_items,
    _limit_structured_checklist_items,
    _merge_structured_checklist_payloads,
)
from server.agents.planner.tools.pentest_plan import _merge_phases
from server.core.tool import Tool


def _count_plan_scenarios(plan_data: dict) -> int:
    total = 0
    for phase in plan_data.get("phases", []):
        if not isinstance(phase, dict):
            continue
        for step in phase.get("steps", []):
            if not isinstance(step, dict):
                continue
            total += len(step.get("scenarios", []))
    return total


def test_build_warmup_recon_plan_normalizes_to_exactly_eight_recon_scenarios():
    seed = [
        {"task": f"Recon task {idx}", "agent": "recon", "priority": 1 + (idx % 3)}
        for idx in range(1, 5)
    ]

    plan = _build_warmup_recon_plan(
        target="http://example.com",
        scope="example scope",
        target_type="web_app",
        seed_scenarios=seed,
    )

    assert _count_plan_scenarios(plan) == 8

    all_agents = []
    for phase in plan["phases"]:
        for step in phase.get("steps", []):
            for scenario in step.get("scenarios", []):
                all_agents.append(scenario["agent"])

    assert all(agent == "recon" for agent in all_agents)


def test_select_warmup_recon_batches_splits_first_four_recon_scenarios():
    plan_data = {
        "phases": [
            {
                "name": "Reconnaissance",
                "steps": [
                    {
                        "id": "s1",
                        "scenarios": [
                            {"task": "A", "agent": "recon", "priority": 1, "done": False},
                            {"task": "B", "agent": "recon", "priority": 1, "done": False},
                            {"task": "C", "agent": "exploit", "priority": 1, "done": False},
                            {"task": "D", "agent": "recon", "priority": 2, "done": False},
                            {"task": "E", "agent": "recon", "priority": 2, "done": False},
                        ],
                    }
                ],
            }
        ]
    }

    batches = _select_warmup_recon_batches(plan_data)

    assert len(batches) == 2
    assert [[scenario["task"] for scenario in batch] for batch in batches] == [
        ["A", "B"],
        ["D", "E"],
    ]


def test_merge_and_limit_structured_checklists_dedupes_and_caps():
    payload_a = {
        "target_type": "web_app",
        "available_total": 2,
        "checklist": [
            {
                "phase": "1",
                "title": "Reconnaissance",
                "items": [
                    {"name": "Technology Fingerprinting", "priority": 3},
                    {"name": "Header Review", "priority": 2},
                ],
            }
        ],
    }
    payload_b = {
        "target_type": "web_app",
        "available_total": 3,
        "checklist": [
            {
                "phase": "1",
                "title": "Reconnaissance",
                "items": [
                    {"name": "Technology Fingerprinting", "priority": 4},
                    {"name": "Parameter Discovery", "priority": 5},
                ],
            },
            {
                "phase": "4",
                "title": "Authentication, Authorization & Injection Testing",
                "items": [
                    {"name": "SQL Injection", "priority": 5},
                ],
            },
        ],
    }

    merged = _merge_structured_checklist_payloads(payload_a, payload_b)
    limited = _limit_structured_checklist_items(merged, 3)

    assert merged["available_total"] == 4
    recon_items = limited["checklist"][0]["items"]
    assert recon_items[0]["name"] == "Parameter Discovery"
    assert any(item["name"] == "Technology Fingerprinting" and item["priority"] == 4 for item in recon_items)
    assert sum(len(block["items"]) for block in limited["checklist"]) == 3


def test_static_recon_plan_is_capped_and_promptable():
    static_plan = _build_static_recon_plan("web_app")

    assert static_plan["target_type"] == "web_app"
    assert len(static_plan["scenarios"]) <= 20

    prompt_block = _format_static_recon_plan_for_prompt(static_plan)
    assert "External Perimeter Mapping" in prompt_block
    assert "Operational Synthesis" in prompt_block


def test_warmup_planner_message_uses_target_description_and_disables_tools():
    static_plan = _build_static_recon_plan("web_app")

    message = _build_warmup_planner_message(
        target="http://example.com",
        target_type="web_app",
        scope="Allowed: recon and safe enumeration only. Not allowed: brute force or denial of service.",
        info=(
            "Production customer portal with login, admin panel, and GraphQL API.\n"
            "High-value customer data is present.\n"
            "Allowed: non-destructive testing.\n"
            "Not allowed: credential attacks."
        ),
        static_recon_plan=static_plan,
    )

    assert "## Target Profile" in message
    assert "Asset value / criticality" in message
    assert "## Scope Rules" in message
    assert "Allowed / in-scope actions" in message
    assert "Not allowed / out-of-scope actions" in message
    assert "Start from the stored static recon template" in message
    assert "Preserve the original static scenario task names" in message
    assert "Preserve the original static methods" in message
    assert "## Available Recon Tooling" in message
    assert "burp_suite" in message
    assert "Do NOT use tools in this planner pass." in message


def test_full_planner_kickoff_message_includes_checklist_and_warmup_evidence():
    static_plan = _build_static_recon_plan("web_app")
    message = _build_planner_kickoff_message(
        target="http://example.com",
        target_type="web_app",
        scope="example scope",
        info="Public app with login and admin panel.",
        intel_status="complete",
        intel_vulnerabilities=["Apache version disclosure", "Missing security headers"],
        intel_stats={"sources": 3},
        intel_checklist={
            "target_type": "web_app",
            "available_total": 2,
            "checklist": [
                {
                    "phase": "1",
                    "title": "Authentication",
                    "items": [
                        {"name": "Test default credentials", "priority": 2},
                        {"name": "Review session token entropy", "priority": 3},
                    ],
                }
            ],
        },
        checklist_overview={
            "target_type": "web_app",
            "available_total": 2,
            "items_count": 2,
        },
        static_recon_plan=static_plan,
        warmup_summaries=[
            {
                "task": "Defensive & Tech Fingerprinting",
                "finding_type": "info",
                "compact_summary": "Apache/2.4.7 and missing HSTS discovered.",
            }
        ],
    )

    assert "## Synthesized Checklist" in message
    assert "P2 Test default credentials" in message
    assert "P3 Review session token entropy" in message
    assert "## Warmup Recon Results" in message
    assert "Apache/2.4.7 and missing HSTS discovered." in message
    assert "Treat warmup recon results as the source of truth" in message


def test_structured_checklist_prompt_includes_all_items_not_just_first_slice():
    checklist = {
        "target_type": "linux_server",
        "available_total": 10,
        "checklist": [
            {
                "phase": "1",
                "title": "Reconnaissance",
                "items": [
                    {"name": f"Checklist item {idx}", "priority": (idx % 5) + 1}
                    for idx in range(1, 11)
                ],
            }
        ],
    }

    rendered = _format_structured_checklist_for_prompt(checklist)

    assert "Checklist item 1" in rendered
    assert "Checklist item 10" in rendered
    assert "Total checklist items: 10" in rendered
    assert "... and" not in rendered


def test_post_warmup_intel_info_includes_recon_plan_and_latest_cycle_cache():
    info = _build_post_warmup_intel_info(
        info="Public app with login, admin panel, and GraphQL endpoint.",
        recon_plan_data={
            "phases": [
                {
                    "name": "Reconnaissance",
                    "steps": [
                        {
                            "id": "warmup-recon-01",
                            "scenarios": [
                                {
                                    "task": "Technology Fingerprinting",
                                    "agent": "recon",
                                    "priority": 1,
                                    "status": "completed",
                                    "details": "Map headers, frameworks, and visible services.",
                                },
                                {
                                    "task": "GraphQL Surface Discovery",
                                    "agent": "recon",
                                    "priority": 2,
                                    "status": "not yet",
                                    "details": "Identify GraphQL endpoint shape and schema hints.",
                                },
                            ],
                        }
                    ],
                }
            ]
        },
        warmup_summaries=[
            {
                "task": "Technology Fingerprinting",
                "priority": 1,
                "cycle": 1,
                "finding_type": "info",
                "compact_summary": "Earlier cache that should be omitted.",
            },
            {
                "task": "GraphQL Surface Discovery",
                "priority": 2,
                "cycle": 2,
                "finding_type": "info",
                "compact_summary": "Discovered /graphql with introspection hints and admin-linked mutations.",
            },
        ],
    )

    assert "This is the recon plan to find max reconnaissance:" in info
    assert "[completed] Technology Fingerprinting" in info
    assert "This is the result (Perceptor cache) from cycle 2:" in info
    assert "Discovered /graphql with introspection hints and admin-linked mutations." in info
    assert "Earlier cache that should be omitted." not in info


def test_intel_backfills_checklist_to_minimum_from_fallback_payload():
    synthesized = {
        "target_type": "linux_server",
        "available_total": 9,
        "checklist": [
            {
                "phase": "1",
                "title": "Reconnaissance",
                "items": [
                    {"name": f"Observed item {idx}", "priority": 2}
                    for idx in range(1, 10)
                ],
            }
        ],
    }
    fallback = {
        "target_type": "linux_server",
        "available_total": 16,
        "checklist": [
            {
                "phase": "1",
                "title": "Reconnaissance",
                "items": [
                    {"name": f"Observed item {idx}", "priority": 2}
                    for idx in range(1, 10)
                ]
                + [
                    {"name": f"OWASP item {idx}", "priority": 3}
                    for idx in range(10, 17)
                ],
            }
        ],
    }

    backfilled = _ensure_structured_checklist_min_items(
        synthesized,
        min_items=15,
        fallback_payload=fallback,
    )

    item_names = []
    for block in backfilled["checklist"]:
        for item in block["items"]:
            item_names.append(item["name"])

    assert len(item_names) >= 15
    assert "Observed item 1" in item_names
    assert "OWASP item 16" in item_names


def test_normalize_perceptor_classification_downgrades_blocked_and_inconclusive_rows():
    finding_type, summary = _normalize_perceptor_classification(
        agent_role="recon",
        row_status="blocked",
        finding_type="vulnerability",
        compact_summary="suspicious",
        row_result={"summary": "Need credentials before continuing."},
        scenario={"task": "Enumerate services"},
    )
    assert finding_type == "info"
    assert "[BLOCKED]" in summary

    finding_type, summary = _normalize_perceptor_classification(
        agent_role="exploit",
        row_status="inconclusive",
        finding_type="vulnerability",
        compact_summary="suspicious",
        row_result={"summary": "Enumeration found SUID binaries but exploitation was not confirmed."},
        scenario={"task": "Exploit SUID binaries"},
    )
    assert finding_type == "info"
    assert "[INCONCLUSIVE]" in summary


def test_base_executer_builds_forced_consolidation_prompt_with_prior_content_and_tool_results():
    agent = object.__new__(BaseExecuterAgent)
    agent._role = "recon"
    agent._max_tool_rounds = 3

    prompt = agent._build_forced_consolidation_prompt(
        round_index=3,
        last_content="I tried to call another tool.",
        tool_results=[
            {
                "tool_call_id": "call-1",
                "name": "dummy_tool",
                "result": '{"ok":true,"evidence":"service list"}',
            }
        ],
    )

    assert "[FORCED FINAL CONSOLIDATION]" in prompt
    assert "I tried to call another tool." in prompt
    assert "Collected tool evidence to consolidate:" in prompt
    assert "dummy_tool" in prompt
    assert "Return ONLY strict JSON" in prompt


def test_compact_tool_result_payload_truncates_large_lists_and_strings():
    raw = json.dumps(
        {
            "success": True,
            "tool": "linux_privesc_audit",
            "writable_paths": [{"path": f"/tmp/path-{idx}"} for idx in range(120)],
            "raw_output": "A" * 20000,
        }
    )

    compacted = _compact_tool_result_payload(raw)
    parsed = json.loads(compacted)

    assert parsed["tool"] == "linux_privesc_audit"
    assert len(parsed["writable_paths"]) <= 41
    assert parsed["writable_paths"][-1]["truncated"] is True
    assert "truncated" in parsed["raw_output"]


def test_failed_consolidation_default_statuses_are_safe():
    assert _default_status_for_failed_consolidation("verify") == "inconclusive"
    assert _default_status_for_failed_consolidation("retest") == "inconclusive"
    assert _default_status_for_failed_consolidation("exploit") == "inconclusive"
    assert _default_status_for_failed_consolidation("recon") == "failed"


def test_planner_merge_preserves_working_and_completed_runtime_scenarios():
    existing = [
        {
            "name": "Reconnaissance",
            "priority": 1,
            "steps": [
                {
                    "id": "recon-01",
                    "description": "Existing step",
                    "scenarios": [
                        {
                            "task": "Map SSH surface",
                            "agent": "recon",
                            "priority": 2,
                            "done": False,
                            "status": "working",
                            "last_round": "r3",
                        },
                        {
                            "task": "Review banners",
                            "agent": "recon",
                            "priority": 3,
                            "done": True,
                            "status": "completed",
                            "last_round": "r2",
                        },
                    ],
                }
            ],
        }
    ]
    incoming = [
        {
            "name": "Reconnaissance",
            "priority": 1,
            "steps": [
                {
                    "id": "recon-01",
                    "description": "Existing step",
                    "scenarios": [],
                }
            ],
        }
    ]

    merged = _merge_phases(existing, incoming)
    scenarios = merged[0]["steps"][0]["scenarios"]

    assert any(item["task"] == "Map SSH surface" and item["status"] == "working" for item in scenarios)
    assert any(item["task"] == "Review banners" and item["status"] == "completed" and item["done"] is True for item in scenarios)


def test_warmup_recon_messages_enable_timeout_cap():
    assert _tool_timeout_cap_for_message("Warmup scenario batch:\nScenario ID: s1") == 240
    assert _tool_timeout_cap_for_message("Extra info: foo\nWarmup mode: recon-only surface discovery.") == 240
    assert _tool_timeout_cap_for_message("Normal recon scenario") is None


def test_warmup_recon_messages_raise_tool_budget_to_three():
    assert _max_tool_calls_per_round_for_message("Warmup scenario batch:\nScenario ID: s1") == 3
    assert _max_tool_calls_per_round_for_message("Extra info: foo\nWarmup mode: recon-only surface discovery.") == 3
    assert _max_tool_calls_per_round_for_message("Normal recon scenario") == 2


def test_recon_scenario_packet_reflects_runtime_tool_budget():
    packet = build_recon_scenario_packet(
        scenario_and_target="Warmup scenario batch:\nScenario ID: s1\nTask: enumerate services",
        context_block="No stored context window entries.",
        available_tools=["nmap_scan", "linux_config_audit"],
        target_types=["linux_server"],
        max_tool_calls_per_round=3,
    )

    assert "Max tool executions per round: 3. Max rounds per scenario: 3." in packet


def test_base_executer_injects_and_clamps_warmup_timeout():
    tool = Tool(
        name="dummy_timeout_tool",
        description="dummy",
        fn=lambda target, timeout=900: {"target": target, "timeout": timeout},
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target"],
        },
    )
    agent = object.__new__(BaseExecuterAgent)
    agent._role = "recon"
    agent._tools = {"dummy_timeout_tool": tool}
    agent._tool_valid_params = {"dummy_timeout_tool": {"target", "timeout"}}
    agent._execution_tool_timeout_cap_seconds = 240

    injected = agent._filter_tool_args("dummy_timeout_tool", {"target": "http://example.com"})
    clamped = agent._filter_tool_args(
        "dummy_timeout_tool",
        {"target": "http://example.com", "timeout": 900},
    )
    preserved = agent._filter_tool_args(
        "dummy_timeout_tool",
        {"target": "http://example.com", "timeout": 60},
    )

    assert injected["timeout"] == 240
    assert clamped["timeout"] == 240
    assert preserved["timeout"] == 60


def test_run_custom_output_flag_strip_is_command_aware():
    cleaned, stripped = strip_output_file_flags(
        "curl",
        ["-o", "scan.txt", "http://example.com"],
    )
    assert cleaned == ["http://example.com"]
    assert stripped == ["-o", "scan.txt"]

    ssh_cleaned, ssh_stripped = strip_output_file_flags(
        "ssh",
        ["-o", "BatchMode=yes", "user@10.0.0.5"],
    )
    assert ssh_cleaned == ["-o", "BatchMode=yes", "user@10.0.0.5"]
    assert ssh_stripped == []


def test_base_executer_preserves_valid_ssh_dash_o_and_sanitizes_known_output_flags():
    agent = object.__new__(BaseExecuterAgent)
    agent._role = "recon"
    agent._tools = {}
    agent._tool_valid_params = {}
    agent._execution_tool_timeout_cap_seconds = None

    ssh_args, ssh_stripped = agent._sanitize_known_file_output_args(
        "run_custom",
        {"command": "ssh", "args": ["-o", "BatchMode=yes", "user@10.0.0.5"]},
    )
    assert ssh_stripped == []
    assert ssh_args["args"] == ["-o", "BatchMode=yes", "user@10.0.0.5"]
    assert agent._detect_disallowed_file_output("run_custom", ssh_args) is None

    curl_args, curl_stripped = agent._sanitize_known_file_output_args(
        "run_custom",
        {"command": "curl", "args": ["-o", "scan.txt", "http://example.com"]},
    )
    assert curl_stripped == ["-o", "scan.txt"]
    assert curl_args["args"] == ["http://example.com"]
    assert agent._detect_disallowed_file_output("run_custom", curl_args) is None


def test_base_executer_suppresses_duplicate_tool_invocations():
    tool = Tool(
        name="dummy_dupe_tool",
        description="dummy",
        fn=lambda target: {"target": target, "ok": True},
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
            },
            "required": ["target"],
        },
    )

    class DummyCallback:
        def __init__(self) -> None:
            self.warns: list[str] = []

        def on_step(self, message: str) -> None:
            return None

        def on_done(self, message: str) -> None:
            return None

        def on_warn(self, message: str) -> None:
            self.warns.append(message)

        def request_tool_approval(self, **kwargs) -> bool:
            return True

    agent = object.__new__(BaseExecuterAgent)
    agent._role = "recon"
    agent._tools = {"dummy_dupe_tool": tool}
    agent._tool_valid_params = {"dummy_dupe_tool": {"target"}}
    agent._execution_tool_timeout_cap_seconds = None
    agent._cb = DummyCallback()

    tool_messages, tool_results, discovered, halted = asyncio.run(
        agent._run_tools(
            [
                {
                    "id": "call-2",
                    "function": {
                        "name": "dummy_dupe_tool",
                        "arguments": '{"target":"http://example.com","_scenario_id":"s1"}',
                    },
                }
            ],
            previous_tool_results=[
                {
                    "name": "dummy_dupe_tool",
                    "args": {"target": "http://example.com"},
                    "scenario_id": "s1",
                    "result": '{"ok": true}',
                }
            ],
        )
    )

    assert not halted
    assert discovered == []
    assert len(tool_messages) == 1
    assert len(tool_results) == 1
    assert "Duplicate tool invocation suppressed" in tool_results[0]["result"]
    assert any("duplicate tool call suppressed" in item for item in agent._cb.warns)


def test_build_verified_finding_entry_includes_commands_and_cve_candidates():
    finding = _build_verified_finding_entry(
        target="10.129.39.165",
        item={
            "verify_summary": "OpenSSH vulnerable to CVE-2023-38408 confirmed via targeted verification.",
            "verify_confidence": 0.93,
            "scenario": {
                "task": "Validate SSH service exposure",
                "details": "Confirm the SSH issue with focused version and behavior checks.",
                "priority": 1,
                "vulnerability_type": "SSH Exposure",
                "endpoint": "22/tcp",
                "remediation": "",
            },
            "verify_data": {
                "tool_results": [
                    {
                        "name": "run_custom",
                        "args": {
                            "command": "nmap",
                            "args": ["-sV", "-p", "22", "10.129.39.165"],
                        },
                        "result": '{"full_command":"nmap -sV -p 22 10.129.39.165"}',
                    }
                ],
                "evidence": {"banner": "OpenSSH 9.x"},
            },
        },
    )

    assert finding["target"] == "10.129.39.165"
    assert finding["cve"] == "CVE-2023-38408"
    assert "Confirmation Commands:" in finding["description"]
    assert "nmap -sV -p 22 10.129.39.165" in finding["description"]
    assert "commands" in finding["evidence"]


def test_write_project_findings_cache_writes_project_snapshot(tmp_path):
    cache_path = _write_project_findings_cache(
        project_id="project-123",
        findings=[
            {
                "id": "finding-1",
                "title": "Verified finding",
                "severity": "critical",
                "category": "ssh",
                "target": "10.129.39.165",
                "status": "verified",
                "description": "desc",
                "timestamp": "2026-04-23T12:00:00+00:00",
            }
        ],
        cache_dir=str(tmp_path),
    )

    with open(cache_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    assert payload["project_id"] == "project-123"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["title"] == "Verified finding"


def test_base_executer_does_not_inject_timeout_for_tools_without_timeout_schema():
    tool = Tool(
        name="dummy_no_timeout_tool",
        description="dummy",
        fn=lambda target, scan_type=None: {"target": target, "scan_type": scan_type},
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scan_type": {"type": "string"},
            },
            "required": ["target"],
        },
    )
    agent = object.__new__(BaseExecuterAgent)
    agent._role = "recon"
    agent._tools = {"dummy_no_timeout_tool": tool}
    agent._tool_valid_params = {"dummy_no_timeout_tool": {"target", "scan_type"}}
    agent._execution_tool_timeout_cap_seconds = 240

    filtered = agent._filter_tool_args(
        "dummy_no_timeout_tool",
        {"target": "http://example.com", "scan_type": "balanced"},
    )

    assert "timeout" not in filtered


def test_base_executer_filters_unexpected_tool_args_from_schema():
    tool = Tool(
        name="dummy_schema_tool",
        description="dummy",
        fn=lambda target, passive_mode=False: {"target": target, "passive_mode": passive_mode},
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "passive_mode": {"type": "boolean"},
            },
            "required": ["target"],
        },
    )
    assert _get_valid_params(tool) == {"target", "passive_mode"}
    agent = object.__new__(BaseExecuterAgent)
    agent._role = "recon"
    agent._tools = {"dummy_schema_tool": tool}
    agent._tool_valid_params = {"dummy_schema_tool": {"target", "passive_mode"}}
    agent._execution_tool_timeout_cap_seconds = None

    filtered = agent._filter_tool_args(
        "dummy_schema_tool",
        {"target": "http://example.com", "passive_mode": True, "tool": "junk"},
    )

    assert filtered == {"target": "http://example.com", "passive_mode": True}


def test_base_executer_recovers_malformed_tool_name_payload():
    tool = Tool(
        name="web_crawler",
        description="dummy",
        fn=lambda tool, target, args=None, timeout=120: {"tool": tool, "target": target},
        parameters={
            "type": "object",
            "properties": {
                "tool": {"type": "string"},
                "target": {"type": "string"},
                "args": {"type": "array"},
                "timeout": {"type": "integer"},
            },
            "required": ["tool", "target"],
        },
    )
    agent = object.__new__(BaseExecuterAgent)
    agent._role = "recon"
    agent._tools = {"web_crawler": tool}
    agent._tool_valid_params = {"web_crawler": {"tool", "target", "args", "timeout"}}
    agent._execution_tool_timeout_cap_seconds = None

    name, args, scenario_id = agent._recover_tool_invocation(
        'web_crawler**********************************_scenario_id="s1,s2" {"tool": "katana", "target": "http://scanme.nmap.org", "args": ["-jc"], "timeout": 120}',
        "{}",
    )

    assert name == "web_crawler"
    assert scenario_id == "s1,s2"
    assert args["tool"] == "katana"
    assert args["target"] == "http://scanme.nmap.org"
    assert args["args"] == ["-jc"]


def test_scenario_status_preserves_failed_and_blocked_when_done():
    assert _normalize_scenario_status("failed", done=True) == "failed"
    assert _normalize_scenario_status("blocked", done=True) == "blocked"
    assert _normalize_scenario_status("complete", done=True) == "completed"


def test_parse_executer_output_normalizes_recon_partial_statuses():
    result = _parse_executer_output(
        json.dumps(
            {
                "status": "partial",
                "findings": [],
                "summary": "Partial evidence gathered.",
                "scenario_summaries": [
                    {
                        "scenario_id": "s1",
                        "task": "Local Perimeter Mapping",
                        "status": "partial",
                        "summary": "Blocked by localhost restrictions.",
                        "findings": [],
                        "tools": ["run_custom"],
                    },
                    {
                        "scenario_id": "s2",
                        "task": "API Extraction",
                        "status": "complete",
                        "summary": "Endpoints discovered.",
                        "findings": [],
                        "tools": ["api_endpoint_discovery"],
                    },
                ],
            }
        ),
        role="recon",
    )

    assert result.status == "blocked"
    assert [item["status"] for item in result.scenario_summaries] == ["blocked", "complete"]


def test_parse_executer_output_derives_recon_status_from_scenario_summaries():
    result = _parse_executer_output(
        json.dumps(
            {
                "status": "unknown",
                "findings": [],
                "summary": "Warmup batch summary.",
                "scenario_summaries": [
                    {
                        "scenario_id": "s1",
                        "task": "Scenario A",
                        "status": "complete",
                        "summary": "A done",
                        "findings": [],
                        "tools": [],
                    },
                    {
                        "scenario_id": "s2",
                        "task": "Scenario B",
                        "status": "blocked",
                        "summary": "B blocked",
                        "findings": [],
                        "tools": [],
                    },
                ],
            }
        ),
        role="recon",
    )

    assert result.status == "blocked"


def test_parse_executer_output_downgrades_failed_recon_summary_with_evidence():
    result = _parse_executer_output(
        json.dumps(
            {
                "status": "failed",
                "findings": [],
                "summary": "Discovered several endpoints but localhost restrictions limited rate-limit validation.",
                "scenario_summaries": [
                    {
                        "scenario_id": "s2",
                        "task": "Operational Synthesis",
                        "status": "failed",
                        "summary": "Discovered backup paths and rate-limit clues, but localhost restrictions limited validation.",
                        "findings": [
                            {
                                "title": "Artifact clue",
                                "severity": "info",
                                "details": "Observed backup path indicators.",
                                "tools": ["web_fuzz"],
                            }
                        ],
                        "tools": ["http_header_analysis", "web_fuzz"],
                    }
                ],
            }
        ),
        role="recon",
    )

    assert result.status == "blocked"
    assert result.scenario_summaries[0]["status"] == "blocked"


def test_execution_history_is_added_to_prompt_for_same_agent_role():
    class DummyProjectsStore:
        def get_project(self, project_id: str) -> dict:
            return {"id": project_id}

        def upsert_project(self, project: dict) -> dict:
            return project

        def append_scan_event_cache(self, project_id: str, payload: dict) -> None:
            return None

    service = ScanOrchestratorService(projects_store=DummyProjectsStore())
    scenario = {
        "task": "Structural Content Discovery",
        "agent": "recon",
        "priority": 1,
        "details": "Find exposed files",
        "methods": ["crawl"],
    }
    other = {
        "task": "Defensive & Tech Fingerprinting",
        "agent": "recon",
        "priority": 2,
        "details": "Fingerprint stack",
        "methods": ["headers"],
    }
    plan_data = _build_warmup_recon_plan(
        target="http://example.com",
        scope="scope",
        target_type="web_app",
        seed_scenarios=[scenario, other],
    )

    tracked_scenario = plan_data["phases"][0]["steps"][0]["scenarios"][0]
    tracked_other = plan_data["phases"][0]["steps"][0]["scenarios"][1]
    _append_scenario_execution_history(
        plan_data,
        tracked_scenario,
        cycle_number=1,
        row_result={
            "status": "complete",
            "summary": "Found /.git and /robots.txt.",
            "tool_results": [
                {
                    "name": "web_fuzz",
                    "args": {"target": "http://example.com"},
                    "result": "{}",
                }
            ],
            "round_labels": ["r1", "r2"],
        },
    )
    _append_scenario_execution_history(
        plan_data,
        tracked_other,
        cycle_number=1,
        row_result={
            "status": "blocked",
            "summary": "Fingerprinting blocked by local target policy.",
            "tool_results": [
                {
                    "name": "detect_tech",
                    "args": {"target": "http://example.com"},
                    "result": "{}",
                }
            ],
            "round_labels": ["r1"],
        },
    )

    history = _format_agent_execution_history_for_prompt(
        plan_data,
        agent_role="recon",
        active_scenarios=[tracked_scenario],
    )
    message = service._build_executer_message(
        plan_data=plan_data,
        scenario=tracked_scenario,
        target="http://example.com",
        target_type="web_app",
        scope="scope",
        info="info",
    )

    assert "Previous runs for the currently assigned scenario(s):" in history
    assert "Other prior recon cycle activity:" in history
    assert "web_fuzz" in history
    assert "detect_tech" in history
    assert "Prior execution history:" in message
    assert "Found /.git and /robots.txt." in message


def test_target_execution_guidance_marks_loopback_targets_and_discourages_external_enumeration():
    guidance = _build_target_execution_guidance(
        target="http://127.0.0.1:3001",
        scenario_tasks=["External Perimeter Mapping", "Operational Synthesis"],
    )

    assert "loopback/local target" in guidance
    assert "Do NOT spend rounds on internet-perimeter or external OSINT tooling" in guidance
    assert "Do NOT use run_python in warmup recon" in guidance
    assert "Operational Synthesis" in guidance


def test_execution_cycle_hands_info_findings_to_planner_without_cycle_number_crash():
    class DummyProjectsStore:
        def get_project(self, project_id: str) -> dict:
            return {"id": project_id}

        def upsert_project(self, project: dict) -> dict:
            return project

        def append_scan_event_cache(self, project_id: str, payload: dict) -> None:
            return None

    class DummyResult:
        status = "complete"
        summary = "Discovered websocket and API routes."
        findings = [{"title": "WebSocket route", "severity": "info"}]
        evidence = []
        needs = []
        tool_results = [
            {
                "name": "websocket_recon",
                "args": {"target": "http://127.0.0.1:3001"},
                "result": '{"socket_io": true}',
            }
        ]
        discovered_target_types = []
        rounds_executed = 3
        round_labels = ["r1", "r2", "r3"]

    class DummyReconAgent:
        async def run(self, message: str) -> DummyResult:
            return DummyResult()

    class DummyExploitAgent:
        async def run(self, message: str) -> DummyResult:
            return DummyResult()

    class DummyVerifyAgent:
        def reset_context_window_for_cycle(self) -> None:
            return None

    class DummyPerceptorAgent:
        async def assess_tool_results(self, *, scenario: dict, tool_results: list, asset_context: dict) -> dict:
            return {
                "finding_type": "info",
                "compact_summary": "Socket.IO endpoint and client-side API hints discovered.",
                "overall": {"ssvc": "TRACK"},
            }

    class DummyPlanner:
        def __init__(self) -> None:
            self.messages: list[str] = []
            self.summary = "Planner integrated recon info and moved forward."

        async def run(self, message: str, **kwargs: object) -> object:
            self.messages.append(message)
            return self

    service = ScanOrchestratorService(projects_store=DummyProjectsStore())
    emitted_events: list[dict] = []
    service._emit_event = lambda *args, **kwargs: emitted_events.append(kwargs)  # type: ignore[method-assign]

    plan_data = {
        "target": "http://127.0.0.1:3001",
        "scope": "local web app",
        "target_types": ["web_app"],
        "phases": [
            {
                "name": "Reconnaissance",
                "priority": 1,
                "steps": [
                    {
                        "id": "recon-01",
                        "description": "Discover APIs",
                        "scenarios": [
                            {
                                "task": "Discover hidden APIs and WebSockets using client-side code and documentation.",
                                "agent": "recon",
                                "priority": 2,
                                "done": False,
                            }
                        ],
                    }
                ],
            }
        ],
    }
    planner = DummyPlanner()

    async def _run() -> tuple[bool, dict]:
        return await service._run_execution_cycle(
            project_id="p1",
            scan_id="s1",
            cycle_number=3,
            plan_data=plan_data,
            recon_agent=DummyReconAgent(),
            exploit_agent=DummyExploitAgent(),
            verify_agent=DummyVerifyAgent(),
            retest_agent=DummyVerifyAgent(),
            perceptor_agent=DummyPerceptorAgent(),
            loop_planner=planner,
            target="http://127.0.0.1:3001",
            target_type="web_app",
            scope="local web app",
            info="info",
            intel_checklist={},
        )

    should_continue, updated_plan = asyncio.run(_run())

    assert should_continue is True
    assert planner.messages
    assert "RECONNAISSANCE FINDINGS (informational only)" in planner.messages[0]
    assert "Socket.IO endpoint and client-side API hints discovered." in planner.messages[0]
    scenario = updated_plan["phases"][0]["steps"][0]["scenarios"][0]
    assert scenario["done"] is True
    assert scenario.get("execution_history", [{}])[-1]["cycle"] == 3
    assert any(event.get("event") == "plan_updated_by_planner" for event in emitted_events)


def test_warmup_batch_message_explicitly_allows_operational_synthesis_to_use_prior_evidence():
    class DummyProjectsStore:
        def get_project(self, project_id: str) -> dict:
            return {"id": project_id}

        def upsert_project(self, project: dict) -> dict:
            return project

        def append_scan_event_cache(self, project_id: str, payload: dict) -> None:
            return None

    service = ScanOrchestratorService(projects_store=DummyProjectsStore())
    scenarios = [
        {"task": "Data Handling & Trust Review", "agent": "recon", "priority": 3, "details": "Review trust", "methods": ["cors"]},
        {"task": "Operational Synthesis", "agent": "recon", "priority": 3, "details": "Synthesize artifacts", "methods": ["rate limit"]},
    ]
    plan_data = _build_warmup_recon_plan(
        target="http://example.com",
        scope="scope",
        target_type="web_app",
        seed_scenarios=scenarios,
    )

    message, _ = service._build_warmup_batch_executer_message(
        plan_data=plan_data,
        scenarios=scenarios,
        target="http://example.com",
        target_type="web_app",
        scope="scope",
        info="info",
    )

    assert "If a scenario is `Operational Synthesis`, it may synthesize earlier recon evidence" in message
    assert "Make sure every assigned scenario gets direct evidence by the end of Round 2." in message
    assert "loopback/local target" not in message


def test_warmup_batch_message_includes_loopback_guidance_when_target_is_local():
    class DummyProjectsStore:
        def get_project(self, project_id: str) -> dict:
            return {"id": project_id}

        def upsert_project(self, project: dict) -> dict:
            return project

        def append_scan_event_cache(self, project_id: str, payload: dict) -> None:
            return None

    service = ScanOrchestratorService(projects_store=DummyProjectsStore())
    scenarios = [
        {"task": "External Perimeter Mapping", "agent": "recon", "priority": 1, "details": "Map perimeter", "methods": ["OSINT"]},
        {"task": "Identity & Access Analysis", "agent": "recon", "priority": 2, "details": "Analyze auth", "methods": ["session review"]},
    ]
    plan_data = _build_warmup_recon_plan(
        target="http://127.0.0.1:3001",
        scope="scope",
        target_type="web_app",
        seed_scenarios=scenarios,
    )

    message, _ = service._build_warmup_batch_executer_message(
        plan_data=plan_data,
        scenarios=scenarios,
        target="http://127.0.0.1:3001",
        target_type="web_app",
        scope="scope",
        info="info",
    )

    assert "loopback/local target" in message
    assert "Do NOT spend rounds on internet-perimeter or external OSINT tooling" in message
    assert "Identity & Access Analysis" in message
    assert "Do NOT use run_python in warmup recon" in message


def test_single_scenario_message_includes_loopback_target_guidance():
    class DummyProjectsStore:
        def get_project(self, project_id: str) -> dict:
            return {"id": project_id}

        def upsert_project(self, project: dict) -> dict:
            return project

        def append_scan_event_cache(self, project_id: str, payload: dict) -> None:
            return None

    service = ScanOrchestratorService(projects_store=DummyProjectsStore())
    plan_data = _build_warmup_recon_plan(
        target="http://127.0.0.1:3001",
        scope="scope",
        target_type="web_app",
        seed_scenarios=[
            {"task": "Identity & Access Analysis", "agent": "recon", "priority": 2, "details": "auth", "methods": ["session review"]},
        ],
    )
    scenario = plan_data["phases"][1]["steps"][0]["scenarios"][0]
    message = service._build_executer_message(
        plan_data=plan_data,
        scenario=scenario,
        target="http://127.0.0.1:3001",
        target_type="web_app",
        scope="scope",
        info="info",
    )

    assert "loopback/local target" in message
    assert "Do NOT use run_python in warmup recon" in message
    assert "Identity & Access Analysis" in message


def test_run_warmup_recon_worker_returns_one_result_per_scenario():
    class DummyReconResult:
        def __init__(self) -> None:
            self.status = "complete"
            self.summary = "Combined warmup batch completed."
            self.findings = []
            self.evidence = []
            self.needs = []
            self.tool_results = [
                {"name": "dummy_tool_a", "scenario_id": "s1", "result": "summary a"},
                {"name": "dummy_tool_b", "scenario_id": "s2", "result": "summary b"},
            ]
            self.discovered_target_types = []
            self.rounds_executed = 1
            self.round_labels = ["round-1"]
            self.scenario_summaries = [
                {
                    "scenario_id": "s1",
                    "task": "Scenario A",
                    "status": "complete",
                    "summary": "Scenario A summary",
                    "findings": [],
                    "tools": ["dummy_tool_a"],
                },
                {
                    "scenario_id": "s2",
                    "task": "Scenario B",
                    "status": "complete",
                    "summary": "Scenario B summary",
                    "findings": [],
                    "tools": ["dummy_tool_b"],
                },
            ]

    class DummyReconAgent:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def reset_context_window_for_cycle(self) -> None:
            return None

        async def run(self, message: str) -> DummyReconResult:
            self.calls.append(message)
            return DummyReconResult()

    class DummyProjectsStore:
        def get_project(self, project_id: str) -> dict:
            return {"id": project_id}

        def upsert_project(self, project: dict) -> dict:
            return project

        def append_scan_event_cache(self, project_id: str, payload: dict) -> None:
            return None

    service = ScanOrchestratorService(projects_store=DummyProjectsStore())
    recon_agent = DummyReconAgent()
    scenarios = [
        {"task": "Scenario A", "agent": "recon", "priority": 1, "details": "A", "methods": ["m1"]},
        {"task": "Scenario B", "agent": "recon", "priority": 2, "details": "B", "methods": ["m2"]},
    ]
    plan_data = _build_warmup_recon_plan(
        target="http://example.com",
        scope="scope",
        target_type="web_app",
        seed_scenarios=scenarios,
    )

    async def _run() -> list[tuple[dict, dict]]:
        return await service._run_warmup_recon_worker(
            project_id="p1",
            scan_id="s1",
            plan_data=plan_data,
            recon_agent=recon_agent,
            perceptor_agent=None,
            perceptor_lock=asyncio.Lock(),
            scenarios=scenarios,
            target="http://example.com",
            target_type="web_app",
            scope="scope",
            info="info",
            cycle_number=1,
            worker_number=1,
            display_cycle_number=1,
        )

    results = asyncio.run(_run())

    assert len(results) == 2
    assert [scenario["task"] for scenario, _ in results] == ["Scenario A", "Scenario B"]
    assert [row["summary"] for _, row in results] == ["Scenario A summary", "Scenario B summary"]
    assert [len(row["tool_results"]) for _, row in results] == [1, 1]
    assert len(recon_agent.calls) == 1


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        (
            {
                "verdict": "real_vulnerability",
                "verify_confidence": 0.91,
                "verify_summary": "Time-based SQL injection confirmed with 5 second delay.",
            },
            True,
        ),
        (
            {
                "verdict": "real_vulnerability",
                "verify_confidence": 0.95,
                "verify_summary": "The target discloses Apache/2.4.7 in HTTP headers.",
            },
            False,
        ),
        (
            {
                "verdict": "real_vulnerability",
                "verify_confidence": 0.52,
                "verify_summary": "Weak evidence only.",
            },
            False,
        ),
    ],
)
def test_should_trigger_retest_uses_confidence_and_filters_version_disclosure(item: dict, expected: bool):
    assert _should_trigger_retest(item) is expected
