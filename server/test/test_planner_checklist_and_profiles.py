from __future__ import annotations

import asyncio
import json
from pathlib import Path

from server.agents.planner.prompts import trim_brain
from server.agents.planner.tools.pentest_plan import _apply_scenario_evidence_gating
from server.app.scan.grounding import (
    _build_target_memory_evidence_text,
    _validate_grounded_verified_finding_entry,
)
from server.app.scan.warmup import (
    _display_cycle_number,
    _scenario_max_rounds,
    _select_warmup_recon_batches,
)
from server.app.scan.utils import (
    _extract_prioritized_exec_scenarios,
    _scenario_missing_prerequisites,
)
from server.agents.executer.recon.tools import ALL_RECON_TOOLS
from server.agents.executer.run_custom_guard import current_execution_context
from server.agents.planner.agent import PlannerAgent
from server.core.llm import LLMResponse
from server.core.tool import tool
from server.app._full_orchestrator_impl import _build_info_gathering_report_entry
from server.app._full_orchestrator_impl import _should_refresh_target_info_profile_from_defaults as _orchestrator_profile_should_refresh
from server.app.scan.utils import _should_refresh_target_info_profile_from_defaults as _scan_utils_profile_should_refresh
from server.nodes.information_gathering.node import InformationGatheringNode, _summarize_tool_result
from server.nodes.system_memory import SystemMemoryNode
from server.nodes.system_memory.schema import Brain
from unittest.mock import AsyncMock, patch


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
            for raw_tool in block.get("tools", []):
                if isinstance(raw_tool, str):
                    tool_name = raw_tool
                elif isinstance(raw_tool, dict):
                    tool_name = str(raw_tool.get("name") or raw_tool.get("tool") or "").strip()
                    if tool_name == "run_custom":
                        command = str(raw_tool.get("command", "")).strip()
                        args = raw_tool.get("args", [])
                        assert command or (
                            isinstance(args, list)
                            and len(args) > 0
                            and isinstance(args[0], str)
                            and str(args[0]).strip()
                        ), f"Malformed run_custom target-info entry in {target_type}:{block.get('id', '')}: {raw_tool}"
                    else:
                        assert tool_name, f"Missing tool name in {target_type}:{block.get('id', '')}: {raw_tool}"
                else:
                    missing.append((target_type, str(block.get("id", "")), str(raw_tool)))
                    continue
                if tool_name not in known_tools:
                    missing.append((target_type, str(block.get("id", "")), tool_name))

    assert not missing, f"Missing target-info recon tools: {missing}"


def test_information_gathering_executes_object_style_builtin_tools() -> None:
    recorded: list[dict[str, object]] = []

    class FakeTool:
        async def execute(self, **kwargs):
            recorded.append(kwargs)
            return "ok"

    node = InformationGatheringNode()

    result = asyncio.run(
        node._execute_block(
            project_id="proj-1",
            scan_id="scan-1",
            project_cache_dir="/tmp/pf-test",
            prepared_block={
                "id": "fingerprinting",
                "status": "keep",
                "tools": [{"name": "http_probe"}],
            },
            memory={},
            target="https://example.com",
            target_type="web_app",
            info="",
            tool_map={"http_probe": FakeTool()},
            tool_arg_builder=lambda tool_name, target, target_type, info, memory: (
                {"target": target, "args": ["-follow-redirects"], "timeout": 120},
                None,
            ),
        )
    )

    assert recorded == [{"target": "https://example.com", "args": ["-follow-redirects"], "timeout": 120}]
    assert result[0]["tool"] == "http_probe"
    assert result[0]["status"] == "completed"


def test_information_gathering_uses_profile_args_and_target_placeholders() -> None:
    recorded: list[dict[str, object]] = []

    class FakeTool:
        parameters = {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "timeout": {"type": "integer"},
                "threads": {"type": "integer"},
                "max_urls": {"type": "integer"},
            },
        }

        async def execute(self, **kwargs):
            recorded.append(kwargs)
            return "ok"

    node = InformationGatheringNode()

    result = asyncio.run(
        node._execute_block(
            project_id="proj-1",
            scan_id="scan-1",
            project_cache_dir="/tmp/pf-test",
            prepared_block={
                "id": "passive_context",
                "status": "keep",
                "tools": [
                    {
                        "name": "passive_web_recon",
                        "args": [
                            "target",
                            "trgt",
                            "timeout",
                            40,
                            "threads",
                            "4",
                            "--max-urls",
                            150,
                            "json-only",
                        ],
                    }
                ],
            },
            memory={},
            target="https://scanme.nmap.org/api/data",
            target_type="web_app",
            info="",
            tool_map={"passive_web_recon": FakeTool()},
            tool_arg_builder=lambda tool_name, target, target_type, info, memory: (
                {"target": "builder-should-not-run"},
                None,
            ),
        )
    )

    assert recorded == [{
        "target": "scanme.nmap.org",
        "timeout": 40,
        "threads": 4,
        "max_urls": 150,
    }]
    assert result[0]["tool"] == "passive_web_recon"
    assert result[0]["status"] == "completed"


def test_information_gathering_resolves_full_target_for_profile_run_custom() -> None:
    recorded: list[dict[str, object]] = []

    class FakeTool:
        async def execute(self, **kwargs):
            recorded.append(kwargs)
            return "ok"

    node = InformationGatheringNode()

    result = asyncio.run(
        node._execute_block(
            project_id="proj-1",
            scan_id="scan-1",
            project_cache_dir="/tmp/pf-test",
            prepared_block={
                "id": "fingerprinting",
                "status": "keep",
                "tools": [
                    {
                        "name": "run_custom",
                        "args": ["wafw00f", "-a", "full_trgt"],
                    }
                ],
            },
            memory={},
            target="scanme.nmap.org",
            target_type="web_app",
            info="",
            tool_map={"run_custom": FakeTool()},
            tool_arg_builder=lambda tool_name, target, target_type, info, memory: (
                None,
                "builder-should-not-run",
            ),
        )
    )

    assert recorded == [{
        "command": "wafw00f",
        "args": ["-a", "https://scanme.nmap.org"],
        "reason": "Profile-defined information gathering step for wafw00f against scanme.nmap.org.",
    }]
    assert result[0]["tool"] == "run_custom"
    assert result[0]["status"] == "completed"


def test_information_gathering_normalizes_wappalyzer_input_to_full_target() -> None:
    recorded: list[dict[str, object]] = []

    class FakeTool:
        async def execute(self, **kwargs):
            recorded.append(kwargs)
            return "ok"

    node = InformationGatheringNode()

    result = asyncio.run(
        node._execute_block(
            project_id="proj-1",
            scan_id="scan-1",
            project_cache_dir="/tmp/pf-test",
            prepared_block={
                "id": "fingerprinting",
                "status": "keep",
                "tools": [
                    {
                        "name": "run_custom",
                        "args": ["wappalyzer", "-i", "trgt", "-t", "4", "--scan-type", "full"],
                    }
                ],
            },
            memory={},
            target="scanme.nmap.org",
            target_type="web_app",
            info="",
            tool_map={"run_custom": FakeTool()},
            tool_arg_builder=lambda tool_name, target, target_type, info, memory: (
                None,
                "builder-should-not-run",
            ),
        )
    )

    assert recorded == [{
        "command": "wappalyzer",
        "args": ["-i", "https://scanme.nmap.org", "-t", "4", "--scan-type", "full"],
        "reason": "Profile-defined information gathering step for wappalyzer against scanme.nmap.org.",
    }]
    assert result[0]["tool"] == "run_custom"
    assert result[0]["status"] == "completed"


def test_information_gathering_summarizes_run_custom_failure_from_actual_output() -> None:
    class FakeTool:
        async def execute(self, **kwargs):
            return {
                "success": False,
                "command": "httpx",
                "full_command": "httpx -u pentest-ground.com -silent -json",
                "stderr": (
                    "runtime/cgo: pthread_create failed: Resource temporarily unavailable\n"
                    "SIGABRT: abort\n"
                ),
                "return_code": 2,
                "error": "Exited with code 2",
            }

    node = InformationGatheringNode()

    result = asyncio.run(
        node._execute_block(
            project_id="proj-1",
            scan_id="scan-1",
            project_cache_dir="/tmp/pf-test",
            prepared_block={
                "id": "fingerprinting",
                "status": "keep",
                "tools": [
                    {
                        "name": "run_custom",
                        "args": ["httpx", "-u", "trgt", "-silent", "-json"],
                    }
                ],
            },
            memory={},
            target="pentest-ground.com",
            target_type="web_app",
            info="",
            tool_map={"run_custom": FakeTool()},
            tool_arg_builder=lambda tool_name, target, target_type, info, memory: (
                None,
                "builder-should-not-run",
            ),
        )
    )

    assert result[0]["tool"] == "run_custom"
    assert result[0]["status"] == "error"
    assert result[0]["summary"] == (
        "Custom command `httpx -u pentest-ground.com -silent -json` failed: "
        "Process crashed with pthread_create resource error and SIGABRT."
    )


def test_information_gathering_summarizes_json_string_run_custom_failure() -> None:
    class FakeTool:
        async def execute(self, **kwargs):
            return json.dumps(
                {
                    "success": False,
                    "command": "gau",
                    "args": ["pentest-ground.com", "|", "sort", "-u"],
                    "reason": "Profile-defined information gathering step for gau against pentest-ground.com.",
                    "full_command": "gau pentest-ground.com '|' sort -u",
                    "error": "Validation error: Dangerous shell token '|' detected in arg: '|'",
                }
            )

    node = InformationGatheringNode()

    result = asyncio.run(
        node._execute_block(
            project_id="proj-1",
            scan_id="scan-1",
            project_cache_dir="/tmp/pf-test",
            prepared_block={
                "id": "surface_mapping",
                "status": "keep",
                "tools": [
                    {
                        "name": "run_custom",
                        "args": ["gau", "trgt", "|", "sort", "-u"],
                    }
                ],
            },
            memory={},
            target="pentest-ground.com",
            target_type="web_app",
            info="",
            tool_map={"run_custom": FakeTool()},
            tool_arg_builder=lambda tool_name, target, target_type, info, memory: (
                None,
                "builder-should-not-run",
            ),
        )
    )

    assert result[0]["tool"] == "run_custom"
    assert result[0]["status"] == "error"
    assert result[0]["summary"] == (
        "Validation error: Dangerous shell token '|' detected in arg: '|'"
    )


def test_information_gathering_summarizes_sandbox_executor_blocker() -> None:
    summary = _summarize_tool_result(
        "run_custom",
        {
            "success": False,
            "command": "curl http://scanme.nmap.org",
            "return_code": -1,
            "error": "Sandbox executor unavailable: run_custom may only execute through the tool sandbox. Configure SANDBOX_EXECUTOR_URL for backend-side callers.",
        },
    )

    assert "Execution environment blocked" in summary
    assert "sandbox executor was unavailable" in summary


def test_information_gathering_does_not_render_literal_none_for_failed_command() -> None:
    summary = _summarize_tool_result(
        "run_custom",
        {
            "success": False,
            "command": "wafw00f",
            "full_command": "wafw00f -a http://scanme.nmap.org",
            "stderr": None,
            "stdout": "",
            "return_code": 1,
            "error": None,
        },
    )

    assert summary == "Custom command `wafw00f -a http://scanme.nmap.org` failed: Exited with code 1."


def test_information_gathering_sets_shared_execution_context_for_tools() -> None:
    recorded: list[dict[str, object]] = []

    class FakeTool:
        async def execute(self, **kwargs):
            recorded.append({
                "kwargs": kwargs,
                "context": current_execution_context(),
            })
            return "ok"

    node = InformationGatheringNode()

    result = asyncio.run(
        node._execute_block(
            project_id="proj-ctx",
            scan_id="scan-ctx",
            project_cache_dir="/tmp/pf-info-gathering",
            prepared_block={
                "id": "fingerprinting",
                "status": "keep",
                "tools": [{
                    "name": "run_custom",
                    "command": "curl",
                    "args": ["-I", "full_trgt"],
                    "reason": "check headers",
                }],
            },
            memory={},
            target="http://scanme.nmap.org",
            target_type="web_app",
            info="",
            tool_map={"run_custom": FakeTool()},
            tool_arg_builder=lambda tool_name, target, target_type, info, memory: (None, "builder-should-not-run"),
        )
    )

    assert result[0]["status"] == "completed"
    assert recorded == [{
        "kwargs": {"command": "curl", "args": ["-I", "http://scanme.nmap.org"], "reason": "check headers"},
        "context": {
            "project_id": "proj-ctx",
            "project_cache_dir": "/tmp/pf-info-gathering",
            "scan_id": "scan-ctx",
            "role": "information_gathering",
            "tool": "run_custom",
            "target_url": "http://scanme.nmap.org",
        },
    }]


def test_system_memory_sanitize_preserves_fallback_tool_result_summary() -> None:
    helper = SystemMemoryNode()
    fallback = {
        "id": "fingerprinting",
        "name": "Fingerprinting",
        "goal": "Identify live web behavior, headers, and technology fingerprints.",
        "interaction": "active_safe",
        "planned_tools": ["run_custom"],
        "selection_rationale": "",
        "skipped_tools": [],
        "status": "partial",
        "objective": "Identify live web behavior, headers, and technology fingerprints.",
        "summary": "Fingerprinting produced mixed results.",
        "confirmed_facts": [],
        "security_signals": [],
        "unknowns": [],
        "why_it_matters": "",
        "next_actions": [],
        "artifacts": [],
        "results": [
            {
                "tool": "run_custom",
                "status": "error",
                "summary": (
                    "Custom command `httpx -u pentest-ground.com -silent -json` failed: "
                    "Process crashed with pthread_create resource error and SIGABRT."
                ),
                "command": "httpx -u pentest-ground.com -silent -json",
                "artifacts": [],
                "structured": {},
            }
        ],
    }
    organized = {
        **fallback,
        "results": [
            {
                "tool": "run_custom",
                "status": "failed",
                "summary": "CLI error: invalid option '-u'",
                "command": "httpx -u pentest-ground.com -silent -json",
                "artifacts": [],
                "structured": {},
            }
        ],
    }

    cleaned = helper.llm._sanitize_organized_block(organized, fallback)

    assert cleaned["results"][0]["summary"] == fallback["results"][0]["summary"]
    assert cleaned["results"][0]["command"] == "httpx -u pentest-ground.com -silent -json"


def test_system_memory_sanitize_matches_results_by_command_not_position() -> None:
    helper = SystemMemoryNode()
    fallback = {
        "id": "fingerprinting",
        "name": "Fingerprinting",
        "goal": "Identify live web behavior, headers, and technology fingerprints.",
        "interaction": "active_safe",
        "planned_tools": ["run_custom"],
        "selection_rationale": "",
        "skipped_tools": [],
        "status": "partial",
        "objective": "Identify live web behavior, headers, and technology fingerprints.",
        "summary": "Fingerprinting produced mixed results.",
        "confirmed_facts": [],
        "security_signals": [],
        "unknowns": [],
        "why_it_matters": "",
        "next_actions": [],
        "artifacts": [],
        "results": [
            {
                "tool": "run_custom",
                "status": "error",
                "summary": "Custom command `wappalyzer -i http://scanme.nmap.org -t 4 --scan-type full` failed: Process failed with a Python traceback.",
                "command": "wappalyzer -i http://scanme.nmap.org -t 4 --scan-type full",
                "artifacts": [],
                "structured": {},
            },
            {
                "tool": "run_custom",
                "status": "completed",
                "summary": "Custom command `wafw00f -a http://scanme.nmap.org` completed successfully.",
                "command": "wafw00f -a http://scanme.nmap.org",
                "artifacts": [],
                "structured": {},
            },
            {
                "tool": "run_custom",
                "status": "completed",
                "summary": "Custom command `curl --connect-timeout 10 -m 30 -s -I -L http://scanme.nmap.org` completed successfully.",
                "command": "curl --connect-timeout 10 -m 30 -s -I -L http://scanme.nmap.org",
                "artifacts": [],
                "structured": {},
            },
        ],
    }
    organized = {
        **fallback,
        "results": [
            {
                "tool": "run_custom",
                "status": "completed",
                "summary": "Custom command `curl --connect-timeout 10 -m 30 -s -I -L http://scanme.nmap.org` completed successfully.",
                "command": "curl --connect-timeout 10 -m 30 -s -I -L http://scanme.nmap.org",
                "artifacts": [],
                "structured": {},
            },
            {
                "tool": "run_custom",
                "status": "error",
                "summary": "Custom command `wappalyzer -i http://scanme.nmap.org -t 4 --scan-type full` failed: Process failed with a Python traceback.",
                "command": "wappalyzer -i http://scanme.nmap.org -t 4 --scan-type full",
                "artifacts": [],
                "structured": {},
            },
            {
                "tool": "run_custom",
                "status": "completed",
                "summary": "Custom command `wafw00f -a http://scanme.nmap.org` completed successfully.",
                "command": "wafw00f -a http://scanme.nmap.org",
                "artifacts": [],
                "structured": {},
            },
        ],
    }

    cleaned = helper.llm._sanitize_organized_block(organized, fallback)

    assert cleaned["results"][0]["command"] == "curl --connect-timeout 10 -m 30 -s -I -L http://scanme.nmap.org"
    assert cleaned["results"][0]["status"] == "completed"
    assert cleaned["results"][0]["summary"] == "Custom command `curl --connect-timeout 10 -m 30 -s -I -L http://scanme.nmap.org` completed successfully."
    assert cleaned["results"][1]["command"] == "wappalyzer -i http://scanme.nmap.org -t 4 --scan-type full"
    assert cleaned["results"][1]["status"] == "error"


def test_information_gathering_preserves_static_tool_objects_and_block_metadata() -> None:
    node = InformationGatheringNode()
    original_block = {
        "id": "fingerprinting",
        "block_name": "Fingerprinting",
        "goal": "Identify live web behavior, headers, and technology fingerprints with low-noise wrappers.",
        "interaction": "active_safe",
        "tools": [
            {
                "name": "run_custom",
                "args": ["wappalyzer", "-i", "trgt", "-t", "4", "--scan-type", "full"],
            },
            {
                "name": "run_custom",
                "args": ["wafw00f", "-a", "full_trgt"],
            },
        ],
    }

    prepared = node._normalize_prepared_block(
        original_block=original_block,
        payload_block={
            "name": "Changed Name",
            "goal": "Changed goal",
            "interaction": "passive",
            "tools": ["run_custom"],
            "rationale": "Keep the static fingerprinting commands as-is.",
        },
        available_tools=["run_custom", "passive_web_recon"],
    )

    assert prepared["block_name"] == original_block["block_name"]
    assert prepared["goal"] == original_block["goal"]
    assert prepared["interaction"] == original_block["interaction"]
    assert prepared["tools"] == original_block["tools"]


def test_info_gathering_report_entry_includes_command_status_details() -> None:
    entry = _build_info_gathering_report_entry(
        scan_id="scan-1",
        payload={
            "index": 4,
            "total": 4,
            "name": "Trust And Auth",
            "goal": "Check for trust-boundary and session-handling exposure using safe wrappers.",
            "status": "completed",
            "summary": "CORS check failed but session sampling succeeded.",
            "confirmed_facts": [
                "Custom command `python3 server/tools/Corsy/corsy.py -u https://pentest-ground.com:5013` failed.",
                "Session analysis collected 20 token samples.",
            ],
            "results": [
                {
                    "tool": "run_custom",
                    "status": "error",
                    "command": "python3 server/tools/Corsy/corsy.py -u https://pentest-ground.com:5013",
                    "summary": "Connection refused",
                },
                {
                    "tool": "session_token_analysis",
                    "status": "completed",
                    "command": "session_token_analysis(target=\"https://pentest-ground.com:5013\")",
                    "summary": "Collected 20 token samples.",
                },
            ],
        },
    )

    report = entry["scenario_report"][0]
    assert report["tool_results"] == [
        {
            "tool": "run_custom",
            "command": "python3 server/tools/Corsy/corsy.py -u https://pentest-ground.com:5013",
            "status": "failed",
            "raw_status": "error",
            "summary": "Connection refused",
        },
        {
            "tool": "session_token_analysis",
            "command": "session_token_analysis(target=\"https://pentest-ground.com:5013\")",
            "status": "passed",
            "raw_status": "completed",
            "summary": "Collected 20 token samples.",
        },
    ]
    assert "## Full Tool History" in entry["markdown"]
    assert "## What We Find" in entry["markdown"]
    assert "## What We Should Do" in entry["markdown"]
    assert "## Unknowns / Gaps" in entry["markdown"]
    assert "`failed` `python3 server/tools/Corsy/corsy.py -u https://pentest-ground.com:5013`" in entry["markdown"]
    assert "`passed` `session_token_analysis(target=\"https://pentest-ground.com:5013\")`" in entry["markdown"]


def test_info_gathering_report_entry_surfaces_concrete_passive_recon_artifacts() -> None:
    entry = _build_info_gathering_report_entry(
        scan_id="scan-2",
        payload={
            "index": 1,
            "total": 4,
            "name": "Passive Context",
            "goal": "Collect passive hostname, DNS, and archive context for the target domain before active probing.",
            "status": "partial",
            "summary": "Passive recon found subdomains and historical URLs.",
            "confirmed_facts": [
                "2 subdomains observed via crt.sh",
            ],
            "results": [
                {
                    "tool": "passive_web_recon",
                    "status": "partial",
                    "command": "passive_web_recon(pentest-ground.com, timeout=40, threads=4, max_urls=150)",
                    "summary": "2 subdomains from crt.sh; Wayback returned historical URLs.",
                    "structured": {
                        "tool": "passive_web_recon",
                        "normalized_domain": "pentest-ground.com",
                        "subdomains": ["api.pentest-ground.com", "dev.pentest-ground.com"],
                        "historical_urls": [
                            "https://pentest-ground.com/admin",
                            "https://pentest-ground.com/debug",
                        ],
                    },
                }
            ],
        },
    )

    markdown = entry["markdown"]
    assert "Observed subdomains: api.pentest-ground.com, dev.pentest-ground.com" in markdown
    assert "Historical URLs: https://pentest-ground.com/admin, https://pentest-ground.com/debug" in markdown


def test_target_info_profile_refresh_detects_block_content_changes() -> None:
    stored_profile = {
        "generated_from": "database",
        "blocks": [
            {
                "id": "fingerprinting",
                "block_name": "Fingerprinting",
                "tools": [
                    {"name": "run_custom", "args": ["wappalyzer", "-u", "full_trgt"]},
                ],
            }
        ],
    }
    built_in_profile = {
        "generated_from": "static_target_info_profile",
        "blocks": [
            {
                "id": "fingerprinting",
                "block_name": "Fingerprinting",
                "tools": [
                    {"name": "run_custom", "args": ["wappalyzer", "-i", "trgt", "-t", "4", "--scan-type", "full"]},
                ],
            }
        ],
    }

    assert _orchestrator_profile_should_refresh(stored_profile, built_in_profile) is True
    assert _scan_utils_profile_should_refresh(stored_profile, built_in_profile) is True


def test_information_gathering_forces_keep_for_web_fingerprinting_block() -> None:
    node = InformationGatheringNode()
    valid_blocks = [
        {
            "id": "fingerprinting",
            "block_name": "Fingerprinting",
            "goal": "Identify live web behavior, headers, and technology fingerprints with low-noise wrappers.",
            "interaction": "active_safe",
            "tools": [
                {"name": "run_custom", "args": ["wappalyzer", "-i", "trgt", "-t", "4", "--scan-type", "full"]},
                {"name": "run_custom", "args": ["wafw00f", "-a", "full_trgt"]},
                {"name": "run_custom", "args": ["httpx", "-u", "trgt", "-silent", "-json"]},
            ],
        }
    ]
    fake_payload = {
        "blocks": [
            {
                "status": "skip",
                "tools": [],
                "rationale": "Too active for this stage.",
                "skipped_tools": ["run_custom"],
            }
        ]
    }

    with patch("server.nodes.information_gathering.node.get_llm") as mock_get_llm:
        llm_ctx = AsyncMock()
        llm_ctx.__aenter__.return_value.chat = AsyncMock(
            return_value=LLMResponse(
                content=json.dumps(fake_payload),
                tool_calls=[],
                finish_reason="stop",
                usage={},
            )
        )
        llm_ctx.__aexit__.return_value = False
        mock_get_llm.return_value = llm_ctx

        prepared_blocks = asyncio.run(
            node._prepare_blocks(
                target="https://pentest-ground.com:5013",
                target_type="web_app",
                scope="public web",
                info="",
                profile={"blocks": valid_blocks},
                valid_blocks=valid_blocks,
                available_tools=["run_custom", "passive_web_recon", "cors_misconfig_check"],
            )
        )

    assert len(prepared_blocks) == 1
    prepared = prepared_blocks[0]
    assert prepared["status"] == "keep"
    assert prepared["tools"] == valid_blocks[0]["tools"]


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


def test_trim_brain_demotes_unsupported_verified_findings_to_hypotheses() -> None:
    payload = {
        "verified_findings": [
            {
                "title": "Confirmed SQL injection on /login",
                "target": "/login",
                "status": "real_vulnerability",
                "severity": "high",
                "claim_status": "observed",
                "cited_tool_output_ids": ["sqlmap#1"],
            },
            {
                "title": "Possible SSRF on /proxy",
                "target": "/proxy",
                "status": "real_vulnerability",
                "severity": "medium",
                "claim_status": "assumed",
            },
        ]
    }

    rendered = trim_brain(payload)

    assert "Confirmed SQL injection on /login" in rendered
    assert "\"testing_hypotheses\": [{\"name\": \"Possible SSRF on /proxy\"" in rendered
    assert "\"claim_status\": \"assumed\"" in rendered


def test_brain_for_planner_only_exposes_grounded_findings_as_confirmed() -> None:
    memory = {
        "verified_findings": [
            {
                "id": "f-1",
                "title": "Observed IDOR on /user/1",
                "status": "real_vulnerability",
                "severity": "high",
                "claim_status": "observed",
                "source_lineage": ["tool:run_custom"],
                "cited_tool_output_ids": ["run_custom#1"],
            },
            {
                "id": "f-2",
                "title": "Assumed SSRF on /proxy",
                "status": "real_vulnerability",
                "severity": "medium",
                "claim_status": "assumed",
            },
        ]
    }

    planner_brain = Brain.from_system_memory(memory).for_planner()

    assert [item["name"] for item in planner_brain["confirmed_vulns"]] == ["Observed IDOR on /user/1"]
    assert planner_brain["testing_hypotheses"] == [
        {"name": "Assumed SSRF on /proxy", "endpoint": None, "claim_status": "assumed"}
    ]


def test_grounding_validation_rejects_unsupported_or_uncited_findings() -> None:
    unsupported = {
        "claim_status": "unsupported",
        "evidence": {
            "claim_status": "unsupported",
            "cited_tool_output_ids": [],
        },
    }
    inferred_without_citation = {
        "claim_status": "inferred",
        "evidence": {
            "claim_status": "inferred",
            "cited_tool_output_ids": [],
        },
    }
    observed_with_citation = {
        "claim_status": "observed",
        "evidence": {
            "claim_status": "observed",
            "cited_tool_output_ids": ["run_custom#4"],
        },
    }

    assert _validate_grounded_verified_finding_entry(unsupported) == (False, "claim_status=unsupported")
    assert _validate_grounded_verified_finding_entry(inferred_without_citation) == (
        False,
        "missing_cited_tool_output_ids",
    )
    assert _validate_grounded_verified_finding_entry(observed_with_citation) == (True, "")


def test_target_memory_evidence_text_keeps_grounding_metadata() -> None:
    rendered = _build_target_memory_evidence_text(
        {
            "verified_findings": [
                {
                    "title": "Observed SQL injection",
                    "summary": "Confirmed with deterministic validation.",
                    "status": "real_vulnerability",
                    "claim_status": "observed",
                    "source_lineage": ["tool:run_custom", "citation:run_custom:run_custom#1"],
                    "cited_tool_output_ids": ["run_custom#1"],
                }
            ]
        }
    )

    assert "\"claim_status\": \"observed\"" in rendered
    assert "\"cited_tool_output_ids\": [\"run_custom#1\"]" in rendered


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


def test_select_warmup_recon_batches_limits_work_by_worker_capacity() -> None:
    plan = {
        "phases": [
            {
                "steps": [
                    {
                        "scenarios": [
                            {"task": "one", "agent": "recon", "done": False},
                            {"task": "two", "agent": "recon", "done": False},
                            {"task": "three", "agent": "recon", "done": False},
                            {"task": "four", "agent": "recon", "done": False},
                            {"task": "skip-exploit", "agent": "exploit", "done": False},
                        ]
                    }
                ]
            }
        ]
    }

    batches = _select_warmup_recon_batches(plan, worker_count=2, scenarios_per_worker=2)

    assert len(batches) == 2
    assert [item["task"] for item in batches[0]] == ["one", "two"]
    assert [item["task"] for item in batches[1]] == ["three", "four"]


def test_scenario_max_rounds_stays_clamped_to_safe_bounds() -> None:
    assert _scenario_max_rounds({}, default=1) == 1
    assert _scenario_max_rounds({"max_rounds": 0}, default=1) == 1
    assert _scenario_max_rounds({"max_rounds": 5}, default=1) == 3
