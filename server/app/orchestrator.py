"""App-level scan orchestrator service.

This service is the API entrypoint for scan execution:
1. Resolve project details from storage
2. Run Intel Agent to produce pentest checklist intelligence
3. Run Planner Agent to build/store the initial pentest plan
4. Persist scan lifecycle/status back to the project record
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

import structlog

from server.db.projects import ProjectsStore
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore

logger = structlog.get_logger(__name__)

_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web": "web_app",
    "web3": "web_app",
    "infrastructure": "infra",
    "infra": "infra",
    "binary": "desktop",
    "identity": "linux_server",
    "supply_chain": "repository",
    "recon": "shared",
    "red_team": "shared",
    "cve_exploit": "shared",
}

_TARGET_CONFIG_KEYS = (
    "url",
    "base_url",
    "host",
    "target_ip",
    "gateway",
    "cidr",
    "repo_url",
    "targets.ip_address",
)

_STATIC_RECON_FILE_MAP: dict[str, str] = {
    "web_app": "common_web.json",
    "api": "common_api.json",
    "mobile": "common_mobile.json",
    "infra": "common_infra.json",
    "network": "common_network.json",
    "iot": "common_iot.json",
    "linux_server": "common_server.json",
    "desktop": "common_desktop.json",
    "cloud": "common_cloud.json",
    "container": "common_container.json",
    "repository": "common_repository.json",
}

WARMUP_RECON_SCENARIO_COUNT = 8
WARMUP_RECON_WORKERS = 2
WARMUP_RECON_SCENARIOS_PER_WORKER = 2
WARMUP_RECON_CYCLES = 2
MAX_SYNTH_INTEL_CHECKLIST_ITEMS = 20
RETEST_MIN_CONFIDENCE = 0.75
SCENARIO_EXECUTION_HISTORY_LIMIT = 4
PROMPT_HISTORY_SCENARIO_LIMIT = 3
PROMPT_HISTORY_ROLE_LIMIT = 6
PROMPT_HISTORY_TOOL_LIMIT = 4
_FINDING_CWE_MAP: dict[str, str] = {
    "command injection": "CWE-78",
    "sql injection": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "open redirect": "CWE-601",
    "csrf": "CWE-352",
    "cross-site request forgery": "CWE-352",
    "idor": "CWE-639",
    "insecure direct object reference": "CWE-639",
    "ssti": "CWE-1336",
    "server-side template injection": "CWE-1336",
    "xxe": "CWE-611",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_finding_severity(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"critical", "high", "medium", "low", "info"}:
        return raw
    if raw in {"1", "p1", "s1"}:
        return "critical"
    if raw in {"2", "p2", "s2"}:
        return "high"
    if raw in {"3", "p3", "s3"}:
        return "medium"
    if raw in {"4", "p4", "s4"}:
        return "low"
    if raw in {"5", "p5", "s5"}:
        return "info"
    return "medium"


def _safe_json_loads(value: Any) -> dict[str, Any]:
    if not isinstance(value, str):
        return {}
    text = value.strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        clean = value.strip()
        return [clean] if clean else []
    return [] 


def _extract_target_host(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = parsed.hostname or ""
    if host:
        return str(host).strip().lower()
    return raw.strip().lower().split("/")[0].split(":")[0]


def _is_loopback_or_local_target(target: str) -> bool:
    host = _extract_target_host(target)
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.endswith(".local")


def _build_target_execution_guidance(
    *,
    target: str,
    scenario_tasks: list[str] | None = None,
) -> str:
    host = _extract_target_host(target)
    tasks = [str(item).strip() for item in (scenario_tasks or []) if str(item).strip()]
    if not _is_loopback_or_local_target(target):
        return "Target execution guidance: standard target. Use scenario-appropriate tools and avoid unnecessary duplicates."

    guidance_lines = [
        "Target execution guidance: this is a loopback/local target.",
        f"Resolved host: {host or 'localhost'}",
        "Treat public-internet enumeration as inapplicable here.",
        "Do NOT spend rounds on internet-perimeter or external OSINT tooling such as amass/subdomain/cloud/CDN discovery for this target.",
        "Prefer local web evidence: detect_tech, http_probe, http_header_analysis, web_crawler, web_fuzz, directory_file_fuzzing, api_endpoint_discovery, api_passive_enum, js_source_code_analyzer, param_discovery, websocket_recon, cors_misconfig_check, session_token_analysis.",
        "Use run_custom only for tightly scoped localhost HTTP/service checks when that adds direct evidence.",
        "Do NOT use run_python in warmup recon unless there is no built-in tool that can summarize already collected evidence.",
        "If the assigned scenario is inherently public-internet oriented, gather the minimal local evidence that still applies, then mark it blocked instead of retrying unrelated tools.",
        "For Identity & Access Analysis, focus on discovered auth routes, cookies, headers, login/session artifacts, and access-control clues; if none exist, mark blocked after a minimal focused attempt.",
        "For Operational Synthesis, synthesize already discovered endpoints, headers, trust-boundary clues, rate-limit behavior, and artifact paths; do not restart broad discovery from scratch.",
    ]
    if tasks:
        guidance_lines.append(f"Current assigned scenarios: {', '.join(tasks)}")
    return "\n".join(guidance_lines)


def _compact_preview(value: Any, limit: int = 220) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3].rstrip()}..."


def _guess_cwe(vulnerability_type: Any, summary: Any = "") -> str | None:
    haystack = f"{vulnerability_type or ''} {summary or ''}".strip().lower()
    if not haystack:
        return None
    for marker, cwe in _FINDING_CWE_MAP.items():
        if marker in haystack:
            return cwe
    return None


def _render_tool_command(tool_name: str, args: dict[str, Any], result: Any = "") -> str:
    if tool_name == "run_custom":
        parsed = _safe_json_loads(result)
        full_command = str(parsed.get("full_command", "")).strip()
        if full_command:
            return full_command
        base_command = str(args.get("command", "")).strip()
        arg_list = args.get("args", [])
        if base_command:
            if isinstance(arg_list, list) and arg_list:
                return f"{base_command} {' '.join(str(item) for item in arg_list)}".strip()
            return base_command

    if tool_name == "capture_screenshot":
        parsed = _safe_json_loads(result)
        redacted_url = str(parsed.get("redacted_url", "")).strip() or str(args.get("url", "")).strip()
        if redacted_url:
            return f"capture_screenshot {redacted_url}"
        return "capture_screenshot"

    if tool_name:
        compact_args = []
        for key, value in (args or {}).items():
            if value in ("", None, [], {}):
                continue
            compact_args.append(f"{key}={_compact_preview(value, 80)}")
        if compact_args:
            return f"{tool_name}({', '.join(compact_args[:4])})"
    return tool_name or "unknown"


def _extract_tool_execution_entries(tool_results: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not isinstance(tool_results, list):
        return entries

    for item in tool_results:
        if not isinstance(item, dict):
            continue
        tool_name = str(item.get("name", "")).strip()
        args = item.get("args", {})
        result = item.get("result", "")
        entries.append(
            {
                "tool": tool_name,
                "command": _render_tool_command(tool_name, args if isinstance(args, dict) else {}, result),
                "args": args if isinstance(args, dict) else {},
                "result_preview": _compact_preview(result, 280),
            }
        )
    return entries


def _extract_commands_from_tool_results(tool_results: Any) -> list[str]:
    commands: list[str] = []
    for item in _extract_tool_execution_entries(tool_results):
        command = str(item.get("command", "")).strip()
        if command and command not in commands:
            commands.append(command)
    return commands


def _extract_tool_names(tool_results: Any) -> list[str]:
    names: list[str] = []
    if not isinstance(tool_results, list):
        return names
    for item in tool_results:
        if not isinstance(item, dict):
            continue
        tool_name = str(item.get("name", "")).strip()
        if tool_name and tool_name not in names:
            names.append(tool_name)
    return names


def _normalize_recon_result_status(
    value: Any,
    *,
    summary: Any = "",
    findings: Any = None,
    tools: Any = None,
    tool_results: Any = None,
    default: str = "failed",
) -> str:
    raw = str(value or "").strip().lower()
    summary_text = str(summary or "").strip().lower()
    findings_list = findings if isinstance(findings, list) else []
    tools_list = tools if isinstance(tools, list) else []
    tool_results_list = tool_results if isinstance(tool_results, list) else []
    has_findings = any(isinstance(item, dict) for item in findings_list)
    has_tools = any(str(item).strip() for item in tools_list)
    has_tool_results = any(isinstance(item, dict) for item in tool_results_list)
    useful_summary_markers = (
        "discovered",
        "identified",
        "found",
        "revealed",
        "mapped",
        "enumerated",
        "fingerprinted",
        "observed",
        "detected",
        "collected",
        "exposed",
        "located",
    )
    blocked_summary_markers = (
        "blocked",
        "restriction",
        "restricted",
        "prevented",
        "policy",
        "localhost",
        "127.0.0.1",
        "insufficient",
        "limited",
    )
    if raw in {"complete", "completed", "done", "success", "succeeded"}:
        return "complete"
    if raw in {
        "blocked",
        "partial",
        "partially_complete",
        "partially completed",
        "partial_success",
        "partially_successful",
        "incomplete",
        "limited",
    }:
        return "blocked"
    if raw in {"failed", "failure", "error"}:
        if (
            has_findings
            or has_tools
            or has_tool_results
            or any(marker in summary_text for marker in useful_summary_markers)
            or any(marker in summary_text for marker in blocked_summary_markers)
        ):
            return "blocked"
        return "failed"
    if any(marker in summary_text for marker in blocked_summary_markers):
        return "blocked"
    if has_findings or has_tools or has_tool_results or any(marker in summary_text for marker in useful_summary_markers):
        return "blocked"
    return default


def _build_scenario_execution_history_entry(
    *,
    cycle_number: int,
    agent_role: str,
    row_result: dict[str, Any],
) -> dict[str, Any]:
    tool_results = row_result.get("tool_results", []) if isinstance(row_result, dict) else []
    tool_entries = _extract_tool_execution_entries(tool_results)
    commands = _extract_commands_from_tool_results(tool_results)
    tools = _extract_tool_names(tool_results)
    round_labels = row_result.get("round_labels", []) if isinstance(row_result, dict) else []
    raw_status = str(row_result.get("status", "")).strip().lower()
    if str(agent_role or "").strip().lower() == "recon":
        normalized_status = _normalize_recon_result_status(
            raw_status,
            summary=row_result.get("summary", ""),
            findings=row_result.get("findings", []),
            tools=tools,
            tool_results=tool_results,
            default="unknown",
        )
    else:
        normalized_status = raw_status or "unknown"

    return {
        "cycle": int(cycle_number or 0),
        "status": normalized_status,
        "summary": _compact_preview(row_result.get("summary", ""), 240),
        "rounds_seen": [
            str(item).strip().lower()
            for item in round_labels
            if str(item).strip()
        ] if isinstance(round_labels, list) else [],
        "tools": tools[:PROMPT_HISTORY_TOOL_LIMIT],
        "commands": commands[:PROMPT_HISTORY_TOOL_LIMIT],
        "tool_executions": [
            {
                "tool": str(item.get("tool", "")).strip(),
                "command": str(item.get("command", "")).strip(),
            }
            for item in tool_entries[:PROMPT_HISTORY_TOOL_LIMIT]
            if str(item.get("tool", "")).strip()
        ],
    }


def _append_scenario_execution_history(
    plan_data: dict[str, Any],
    scenario: dict[str, Any],
    *,
    cycle_number: int,
    row_result: dict[str, Any],
) -> bool:
    target = _locate_scenario_in_plan(plan_data, scenario)
    if not isinstance(target, dict):
        return False

    history = target.get("execution_history", [])
    if not isinstance(history, list):
        history = []

    entry = _build_scenario_execution_history_entry(
        cycle_number=cycle_number,
        agent_role=str(target.get("agent", "")).strip().lower(),
        row_result=row_result,
    )
    cycle_value = int(entry.get("cycle", 0) or 0)
    filtered = [
        item for item in history
        if isinstance(item, dict) and int(item.get("cycle", 0) or 0) != cycle_value
    ]
    filtered.append(entry)
    target["execution_history"] = filtered[-SCENARIO_EXECUTION_HISTORY_LIMIT:]
    return True


def _iter_plan_scenarios(plan_data: dict[str, Any]) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    phases = plan_data.get("phases", [])
    if not isinstance(phases, list):
        return scenarios
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        for step in phase.get("steps", []):
            if not isinstance(step, dict):
                continue
            for scenario in step.get("scenarios", []):
                if isinstance(scenario, dict):
                    scenarios.append(scenario)
    return scenarios


def _format_history_entry_for_prompt(
    entry: dict[str, Any],
    *,
    task: str,
) -> str:
    cycle = int(entry.get("cycle", 0) or 0)
    status = str(entry.get("status", "")).strip().lower() or "unknown"
    summary = str(entry.get("summary", "")).strip() or "(no summary recorded)"
    rounds_seen = entry.get("rounds_seen", [])
    rounds_text = ", ".join(
        str(item).strip().lower() for item in rounds_seen if str(item).strip()
    ) if isinstance(rounds_seen, list) else ""
    tool_executions = entry.get("tool_executions", [])
    tool_chunks: list[str] = []
    if isinstance(tool_executions, list):
        for item in tool_executions[:PROMPT_HISTORY_TOOL_LIMIT]:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("tool", "")).strip()
            command = str(item.get("command", "")).strip()
            if tool_name and command:
                tool_chunks.append(f"{tool_name} => {command}")
            elif tool_name:
                tool_chunks.append(tool_name)
    if not tool_chunks:
        tool_chunks = [
            str(item).strip()
            for item in entry.get("tools", [])
            if str(item).strip()
        ][:PROMPT_HISTORY_TOOL_LIMIT]
    tools_text = "; ".join(tool_chunks) if tool_chunks else "no tool executions recorded"
    rounds_suffix = f"; rounds={rounds_text}" if rounds_text else ""
    return (
        f"- Cycle {cycle} | {task} | status={status}{rounds_suffix}\n"
        f"  Tools/commands: {tools_text}\n"
        f"  Summary: {summary}"
    )


def _format_agent_execution_history_for_prompt(
    plan_data: dict[str, Any],
    *,
    agent_role: str,
    active_scenarios: list[dict[str, Any]] | None = None,
) -> str:
    normalized_role = str(agent_role or "").strip().lower()
    active_scenarios = [
        item for item in (active_scenarios or [])
        if isinstance(item, dict)
    ]
    if not normalized_role:
        return "No prior execution history for this agent."

    lines: list[str] = []
    active_keys = {
        (
            str(item.get("task", "")).strip().lower(),
            _normalize_priority(item.get("priority", 3)),
        )
        for item in active_scenarios
    }

    current_scenario_lines: list[str] = []
    for scenario in active_scenarios:
        history = scenario.get("execution_history", [])
        if not isinstance(history, list) or not history:
            continue
        task = str(scenario.get("task", "")).strip() or "scenario"
        for entry in history[-PROMPT_HISTORY_SCENARIO_LIMIT:]:
            if isinstance(entry, dict):
                current_scenario_lines.append(
                    _format_history_entry_for_prompt(entry, task=task)
                )

    if current_scenario_lines:
        lines.append("Previous runs for the currently assigned scenario(s):")
        lines.extend(current_scenario_lines)

    role_entries: list[tuple[int, str]] = []
    for scenario in _iter_plan_scenarios(plan_data):
        if str(scenario.get("agent", "")).strip().lower() != normalized_role:
            continue
        scenario_key = (
            str(scenario.get("task", "")).strip().lower(),
            _normalize_priority(scenario.get("priority", 3)),
        )
        if scenario_key in active_keys:
            continue
        history = scenario.get("execution_history", [])
        if not isinstance(history, list):
            continue
        task = str(scenario.get("task", "")).strip() or "scenario"
        for entry in history:
            if not isinstance(entry, dict):
                continue
            role_entries.append(
                (
                    int(entry.get("cycle", 0) or 0),
                    _format_history_entry_for_prompt(entry, task=task),
                )
            )

    role_entries.sort(key=lambda item: item[0], reverse=True)
    if role_entries:
        lines.append(f"Other prior {normalized_role} cycle activity:")
        lines.extend(text for _, text in role_entries[:PROMPT_HISTORY_ROLE_LIMIT])

    if not lines:
        return "No prior execution history for this agent."
    return "\n".join(lines)


def _extract_screenshots_from_tool_results(tool_results: Any) -> list[dict[str, Any]]:
    screenshots: list[dict[str, Any]] = []
    if not isinstance(tool_results, list):
        return screenshots
    for item in tool_results:
        if not isinstance(item, dict):
            continue
        if str(item.get("name", "")).strip() != "capture_screenshot":
            continue
        parsed = _safe_json_loads(item.get("result", ""))
        path = str(parsed.get("path", "")).strip()
        if not path:
            continue
        screenshots.append(
            {
                "path": path,
                "hash": str(parsed.get("hash", "")).strip(),
                "redacted_url": str(parsed.get("redacted_url", "")).strip(),
                "timestamp": str(parsed.get("timestamp", "")).strip(),
                "label": str(item.get("args", {}).get("label", "screenshot")).strip(),
            }
        )
    return screenshots


def _extract_retest_evidence_bundle(retest_data: dict[str, Any]) -> dict[str, Any]:
    evidence_items = retest_data.get("evidence", [])
    manual_steps: list[str] = []
    proof_points: list[str] = []
    commands = _extract_commands_from_tool_results(retest_data.get("tool_results", []))
    tools_used = _extract_tool_names(retest_data.get("tool_results", []))
    screenshots = _extract_screenshots_from_tool_results(retest_data.get("tool_results", []))
    cve_candidates: list[str] = []
    endpoint = ""
    description = ""

    if isinstance(evidence_items, list):
        for item in evidence_items:
            if not isinstance(item, dict):
                continue
            if not endpoint:
                endpoint = str(item.get("endpoint", "") or item.get("affected_endpoint", "")).strip()
            if not description:
                description = str(item.get("description", "") or item.get("proof_statement", "")).strip()
            for field in ("manual_validation_steps", "steps", "reproduction_steps"):
                for step in _coerce_string_list(item.get(field)):
                    if step not in manual_steps:
                        manual_steps.append(step)
            for field in ("proof_points", "proof", "observations"):
                for proof in _coerce_string_list(item.get(field)):
                    if proof not in proof_points:
                        proof_points.append(proof)
            for candidate in _coerce_string_list(item.get("cve_candidates")):
                if candidate not in cve_candidates:
                    cve_candidates.append(candidate)
            for command in _coerce_string_list(item.get("commands")):
                if command not in commands:
                    commands.append(command)
            for tool_name in _coerce_string_list(item.get("tools_used")):
                if tool_name not in tools_used:
                    tools_used.append(tool_name)
            screenshot_paths = _coerce_string_list(item.get("screenshot_paths"))
            for path in screenshot_paths:
                if not any(existing.get("path") == path for existing in screenshots):
                    screenshots.append({"path": path})

    if not manual_steps and commands:
        manual_steps = [
            "Replay the proof-of-concept request against the affected endpoint.",
            "Confirm that command output or other unauthorized execution appears in the response.",
        ]

    return {
        "summary": str(retest_data.get("summary", "")).strip(),
        "status": str(retest_data.get("status", "")).strip().lower() or "captured",
        "endpoint": endpoint,
        "description": description,
        "manual_steps": manual_steps,
        "commands": commands,
        "tools_used": tools_used,
        "tool_executions": _extract_tool_execution_entries(retest_data.get("tool_results", [])),
        "screenshots": screenshots,
        "proof_points": proof_points,
        "cve_candidates": cve_candidates,
        "raw_evidence": evidence_items if isinstance(evidence_items, list) else [],
    }


def _extract_cve_candidates_from_text(*values: Any) -> list[str]:
    pattern = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    matches: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        for match in pattern.findall(text):
            normalized = match.upper()
            if normalized in seen:
                continue
            seen.add(normalized)
            matches.append(normalized)
    return matches


def _build_verified_finding_entry(
    *,
    target: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    scenario = item.get("scenario", {}) if isinstance(item.get("scenario", {}), dict) else {}
    verify_data = item.get("verify_data", {}) if isinstance(item.get("verify_data", {}), dict) else {}
    verify_summary = str(item.get("verify_summary", "")).strip()
    verify_confidence = _coerce_confidence(item.get("verify_confidence"))
    severity = _normalize_finding_severity(scenario.get("priority", "medium"))
    vuln_type = str(scenario.get("vulnerability_type", "")).strip() or "Security Issue"
    endpoint = str(scenario.get("endpoint", "")).strip() or "N/A"
    scenario_task = str(scenario.get("task", "")).strip()
    scenario_details = str(scenario.get("details", "")).strip()
    commands = _extract_commands_from_tool_results(verify_data.get("tool_results", []))
    tool_executions = _extract_tool_execution_entries(verify_data.get("tool_results", []))
    tools_used = _extract_tool_names(verify_data.get("tool_results", []))
    cve_candidates = _extract_cve_candidates_from_text(
        scenario.get("cve"),
        verify_summary,
        verify_data.get("summary", ""),
        verify_data.get("result", ""),
    )

    description_parts = [
        f"Vulnerability Type: {vuln_type}",
        f"Target Endpoint: {endpoint}",
        "",
        "Finding Summary:",
        verify_summary or "Verified vulnerability confirmed by the Verify agent.",
        "",
        "Verification Status: CONFIRMED",
        f"Severity Level: {severity.upper()}",
    ]
    if verify_confidence is not None:
        description_parts.append(f"Verification Confidence: {verify_confidence:.2f}")
    if scenario_task:
        description_parts.extend(["", "Scenario:", scenario_task])
    if scenario_details:
        description_parts.extend(["", "How It Was Tested:", scenario_details])
    if commands:
        description_parts.extend(["", "Confirmation Commands:"])
        description_parts.extend(f"  - {command}" for command in commands[:8])
    if tools_used:
        description_parts.extend(["", "Tools Used:"])
        description_parts.append(f"  - {', '.join(tools_used[:8])}")
    if cve_candidates:
        description_parts.extend(["", "CVE Candidates:"])
        description_parts.extend(f"  - {candidate}" for candidate in cve_candidates)

    evidence_payload = verify_data.get("evidence", {})
    evidence_map = dict(evidence_payload) if isinstance(evidence_payload, dict) else {}
    evidence_map.setdefault("verification_summary", verify_summary)
    evidence_map.setdefault("verification_confidence", verify_confidence)
    evidence_map.setdefault("commands", commands)
    evidence_map.setdefault("tools_used", tools_used)
    evidence_map.setdefault("tool_executions", tool_executions)
    if cve_candidates:
        evidence_map.setdefault("cve_candidates", cve_candidates)

    remediation = str(scenario.get("remediation", "")).strip()
    if not remediation:
        remediation = "Retest/PoC generation pending. Review the confirmation commands and remove or patch the affected service/version."

    return {
        "id": str(uuid.uuid4()),
        "title": verify_summary or scenario_task or "Verified vulnerability",
        "severity": severity,
        "category": vuln_type,
        "target": target,
        "status": "verified",
        "cvss": scenario.get("cvss"),
        "cve": cve_candidates[0] if cve_candidates else scenario.get("cve"),
        "description": "\n".join(description_parts),
        "evidence": evidence_map,
        "remediation": remediation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _upsert_project_finding(
    *,
    findings: list[dict[str, Any]],
    finding_entry: dict[str, Any],
) -> dict[str, Any]:
    title = str(finding_entry.get("title", "")).strip().lower()
    target = str(finding_entry.get("target", "")).strip().lower()
    category = str(finding_entry.get("category", "")).strip().lower()

    for idx, existing in enumerate(findings):
        if not isinstance(existing, dict):
            continue
        if (
            str(existing.get("title", "")).strip().lower() == title
            and str(existing.get("target", "")).strip().lower() == target
            and str(existing.get("category", "")).strip().lower() == category
        ):
            merged = dict(existing)
            merged.update(finding_entry)
            merged["id"] = str(existing.get("id", merged.get("id", "")) or merged.get("id", ""))
            findings[idx] = merged
            return merged

    findings.append(finding_entry)
    return finding_entry


def _write_project_findings_cache(
    *,
    project_id: str,
    findings: list[dict[str, Any]],
    cache_dir: str | None = None,
) -> str:
    base_dir = cache_dir or os.path.join(os.path.dirname(__file__), "..", "cache", "project_findings")
    os.makedirs(base_dir, exist_ok=True)
    cache_path = os.path.join(base_dir, f"{str(project_id).strip()}.json")
    payload = {
        "project_id": str(project_id).strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    with open(cache_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
    return cache_path


def _normalize_target_type(value: Any) -> str:
    clean = str(value or "").strip().lower().replace("-", "_")
    if not clean:
        return "web_app"
    return _TARGET_TYPE_ALIASES.get(clean, clean)


def _nested_get(data: dict[str, Any], dotted_key: str) -> str:
    current: Any = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return ""
        current = current.get(part)
    return str(current).strip() if isinstance(current, str) else ""


def _extract_target(project: dict[str, Any]) -> str:
    primary = project.get("target")
    if isinstance(primary, str) and primary.strip():
        return primary.strip()

    target_config = project.get("targetConfig")
    if not isinstance(target_config, dict):
        return ""

    for key in _TARGET_CONFIG_KEYS:
        value = _nested_get(target_config, key)
        if value:
            return value
    return ""


def _ensure_intel_agent_importable() -> None:
    """Raise a clear runtime error when Intel Agent deps are missing."""
    try:
        from server.agents.intel.agent import IntelAgent as _IntelAgent  # noqa: F401
    except ModuleNotFoundError as exc:
        missing = str(exc.name or "").strip() or "unknown"
        raise RuntimeError(
            "intel dependency is missing: "
            f"{missing}. Install full backend dependencies with "
            "`python -m pip install -r server/requirements.txt`.",
        ) from exc


def _ensure_planner_agent_importable() -> None:
    """Raise a clear runtime error when Planner Agent deps are missing."""
    try:
        from server.agents.planner.agent import PlannerAgent as _PlannerAgent  # noqa: F401
    except ModuleNotFoundError as exc:
        missing = str(exc.name or "").strip() or "unknown"
        raise RuntimeError(
            "planner dependency is missing: "
            f"{missing}. Install full backend dependencies with "
            "`python -m pip install -r server/requirements.txt`.",
        ) from exc


def _is_truthy_env(name: str, default: str = "") -> bool:
    value = os.getenv(name, default).strip().lower()
    return value in {"1", "true", "yes", "on"}


def _count_checklist_items(payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    blocks = payload.get("checklist")
    if not isinstance(blocks, list):
        return 0
    total = 0
    for block in blocks:
        if not isinstance(block, dict):
            continue
        items = block.get("items")
        if isinstance(items, list):
            total += len(items)
    return total


def _coerce_priority(value: Any) -> int | None:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= p <= 5:
        return p
    return None


def _normalize_priority(value: Any) -> int:
    parsed = _coerce_priority(value)
    return parsed if parsed is not None else 3


def _extract_prioritized_exec_scenarios(
    plan_data: dict[str, Any],
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    phases = plan_data.get("phases", [])
    if not isinstance(phases, list):
        return []

    indexed: list[tuple[int, int, int, int, dict[str, Any]]] = []
    for phase_idx, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue
        phase_name = str(phase.get("name", "")).strip()
        steps = phase.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            step_id = str(step.get("id", "")).strip()
            scenarios = step.get("scenarios", [])
            if not isinstance(scenarios, list):
                continue
            for scen_idx, scenario in enumerate(scenarios):
                if not isinstance(scenario, dict):
                    continue
                if bool(scenario.get("done", False)):
                    continue
                agent = str(scenario.get("agent", "")).strip().lower()
                if agent not in {"recon", "exploit"}:
                    continue
                priority = _normalize_priority(scenario.get("priority", 3))
                enriched = dict(scenario)
                enriched["priority"] = priority
                enriched["agent"] = agent
                enriched["_phase"] = phase_name
                enriched["_step_id"] = step_id
                enriched["_phase_index"] = phase_idx
                enriched["_step_index"] = step_idx
                enriched["_scenario_index"] = scen_idx
                indexed.append((priority, phase_idx, step_idx, scen_idx, enriched))

    indexed.sort(key=lambda row: (row[0], row[1], row[2], row[3]))
    return [row[4] for row in indexed[: max(0, int(limit))]]


def _select_recon_exploit_parallel_scenarios(plan_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Pick at most one recon and one exploit scenario (highest priority each)."""
    candidates = _extract_prioritized_exec_scenarios(plan_data, limit=50)
    best_recon: dict[str, Any] | None = None
    best_exploit: dict[str, Any] | None = None

    for scenario in candidates:
        role = str(scenario.get("agent", "")).strip().lower()
        if role == "recon" and best_recon is None:
            best_recon = scenario
        elif role == "exploit" and best_exploit is None:
            best_exploit = scenario
        if best_recon is not None and best_exploit is not None:
            break

    selected = [s for s in [best_recon, best_exploit] if isinstance(s, dict)]
    selected.sort(key=lambda s: _normalize_priority(s.get("priority", 3)))
    return selected


def _normalize_perceptor_classification(
    *,
    agent_role: str,
    row_status: str,
    finding_type: str,
    compact_summary: str,
    row_result: dict[str, Any] | None,
    scenario: dict[str, Any] | None,
) -> tuple[str, str]:
    normalized_role = str(agent_role or "").strip().lower()
    normalized_status = str(row_status or "").strip().lower()
    normalized_type = str(finding_type or "info").strip().lower() or "info"
    row_result = row_result if isinstance(row_result, dict) else {}
    scenario = scenario if isinstance(scenario, dict) else {}

    task = (
        str(scenario.get("task", "")).strip()
        or str(scenario.get("description", "")).strip()
        or "scenario"
    )
    summary = (
        str(row_result.get("summary", "")).strip()
        or str(row_result.get("error", "")).strip()
        or str(compact_summary or "").strip()
        or "No execution summary available."
    )

    if normalized_status in {"failed", "error", "blocked", "incomplete", "awaiting_user_approval"}:
        return "info", f"[{normalized_status.upper()}] {task} - {summary}"

    if normalized_role == "exploit" and normalized_status in {"not_vulnerable", "inconclusive"}:
        return "info", f"[{normalized_status.upper()}] {task} - {summary}"

    if normalized_role == "recon" and normalized_status != "complete":
        return "info", f"[{normalized_status.upper() or 'INFO'}] {task} - {summary}"

    return normalized_type, str(compact_summary or summary).strip()


def _select_recon_only_scenarios(
    plan_data: dict[str, Any],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for scenario in _extract_prioritized_exec_scenarios(plan_data, limit=100):
        if str(scenario.get("agent", "")).strip().lower() != "recon":
            continue
        selected.append(scenario)
        if len(selected) >= max(0, int(limit)):
            break
    return selected


def _default_static_recon_scenarios(target_type: str) -> list[dict[str, Any]]:
    normalized = _normalize_target_type(target_type)

    base_dir = os.path.dirname(__file__)
    static_data_dir = os.path.join(base_dir, "..", "db", "static_data")
    file_name = _STATIC_RECON_FILE_MAP.get(normalized, "common_web.json")
    file_path = os.path.join(static_data_dir, file_name)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            base = json.load(f)
    except Exception as e:
        logger.error("Failed to load static recon file", file=file_name, error=str(e))
        base = {}

    raw_scenarios = base.get("scenarios", []) if isinstance(base, dict) else base
    scenarios: list[dict[str, Any]] = []
    if not isinstance(raw_scenarios, list):
        return scenarios

    for item in raw_scenarios:
        if not isinstance(item, dict):
            continue
        task = str(item.get("task") or item.get("scenario") or "").strip()
        if not task:
            continue
        scenario = {
            "id": str(item.get("id", "")).strip(),
            "task": task,
            "details": str(item.get("details") or item.get("objective") or "").strip(),
            "methods": item.get("methods", []) if isinstance(item.get("methods"), list) else [],
            "priority": _normalize_priority(item.get("priority", 3)),
            "agent": "recon",
            "done": False,
            "status": "not yet",
        }
        scenarios.append(scenario)
    return scenarios[:20]


def _default_warmup_recon_scenarios(target_type: str) -> list[dict[str, Any]]:
    return _default_static_recon_scenarios(target_type)[:WARMUP_RECON_SCENARIO_COUNT]


def _build_static_recon_plan(target_type: str) -> dict[str, Any]:
    normalized = _normalize_target_type(target_type)
    scenarios = _default_static_recon_scenarios(normalized)
    return {
        "target_type": normalized,
        "max_items": 20,
        "generated_from": "static_data_file",
        "scenarios": scenarios,
    }


def _is_user_managed_static_recon_plan(plan: dict[str, Any]) -> bool:
    generated_from = str(plan.get("generated_from", "")).strip().lower()
    return generated_from in {"ui", "ui_settings", "user", "manual"}


def _should_refresh_static_recon_plan_from_files(
    stored_plan: dict[str, Any],
    built_in_plan: dict[str, Any],
) -> bool:
    if _is_user_managed_static_recon_plan(stored_plan):
        return False

    stored_scenarios = stored_plan.get("scenarios", [])
    built_in_scenarios = built_in_plan.get("scenarios", [])
    if not isinstance(stored_scenarios, list) or not stored_scenarios:
        return True
    if not isinstance(built_in_scenarios, list) or not built_in_scenarios:
        return False

    stored_tasks = [
        str(item.get("task", "")).strip()
        for item in stored_scenarios
        if isinstance(item, dict)
    ]
    built_in_tasks = [
        str(item.get("task", "")).strip()
        for item in built_in_scenarios
        if isinstance(item, dict)
    ]
    return stored_tasks[: len(built_in_tasks)] != built_in_tasks


def _resolve_static_recon_plan(projects_store: Any, target_type: str) -> dict[str, Any]:
    normalized = _normalize_target_type(target_type)
    built_in = _build_static_recon_plan(normalized)
    try:
        stored = projects_store.get_static_recon_plan(normalized)
    except Exception:
        stored = None
    if isinstance(stored, dict):
        if _should_refresh_static_recon_plan_from_files(stored, built_in):
            try:
                return projects_store.upsert_static_recon_plan(
                    target_type=normalized,
                    payload=built_in,
                )
            except Exception:
                return built_in

        stored.setdefault("target_type", normalized)
        stored.setdefault("max_items", 20)
        stored.setdefault("generated_from", "database")
        scenarios = stored.get("scenarios", [])
        if isinstance(scenarios, list):
            stored["scenarios"] = scenarios[:20]
        else:
            stored["scenarios"] = list(built_in.get("scenarios", []))
        return stored
    try:
        return projects_store.upsert_static_recon_plan(
            target_type=normalized,
            payload=built_in,
        )
    except Exception:
        return built_in


def _format_static_recon_plan_for_prompt(static_plan: dict[str, Any]) -> str:
    scenarios = static_plan.get("scenarios", []) if isinstance(static_plan, dict) else []
    if not isinstance(scenarios, list) or not scenarios:
        return "(no static recon template available)"
    lines: list[str] = []
    for idx, item in enumerate(scenarios[:20], start=1):
        if not isinstance(item, dict):
            continue
        task = str(item.get("task", "")).strip()
        details = str(item.get("details", "")).strip()
        priority = _normalize_priority(item.get("priority", 3))
        if task:
            lines.append(f"{idx}. P{priority} {task} :: {details}")
    return "\n".join(lines) if lines else "(no static recon template available)"


def _split_prompt_clauses(value: str) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    normalized = re.sub(r"[\r\n]+", "\n", text)
    parts = re.split(r"\n|;\s*", normalized)
    clauses: list[str] = []
    seen: set[str] = set()
    for part in parts:
        clean = re.sub(r"\s+", " ", str(part or "").strip(" -\t\r\n"))
        if not clean:
            continue
        key = clean.lower()
        if key in seen:
            continue
        seen.add(key)
        clauses.append(clean)
    return clauses


def _extract_scope_clauses(
    *texts: str,
    keywords: tuple[str, ...],
    limit: int = 4,
) -> list[str]:
    matches: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for clause in _split_prompt_clauses(text):
            lowered = clause.lower()
            if not any(keyword in lowered for keyword in keywords):
                continue
            if lowered in seen:
                continue
            seen.add(lowered)
            matches.append(clause)
            if len(matches) >= limit:
                return matches
    return matches


def _format_prompt_bullets(items: list[str], empty_text: str) -> str:
    if not items:
        return f"- {empty_text}"
    return "\n".join(f"- {item}" for item in items)


def _infer_target_value_line(info: str, scope: str) -> str:
    value_clauses = _extract_scope_clauses(
        info,
        scope,
        keywords=(
            "value",
            "critical",
            "criticality",
            "production",
            "prod",
            "sensitive",
            "customer",
            "payment",
            "finance",
            "internal",
            "crown jewel",
            "high impact",
        ),
        limit=2,
    )
    if value_clauses:
        return "; ".join(value_clauses)
    lowered = f"{info}\n{scope}".lower()
    if any(token in lowered for token in ("prod", "production", "critical", "sensitive")):
        return "High-value or production-like asset context inferred from operator notes."
    return "(not explicitly provided)"


def _format_warmup_recon_tooling(target_type: str, limit: int = 12) -> str:
    try:
        from server.agents.executer.target_tool_routing import RECON_TOOL_TARGET_TYPES
    except Exception:
        return "(recon tool inventory unavailable)"

    normalized = _normalize_target_type(target_type)
    tool_names = sorted(
        tool_name
        for tool_name, target_types in RECON_TOOL_TARGET_TYPES.items()
        if normalized in target_types
    )
    if not tool_names:
        return "(no target-specific recon tools registered)"
    selected = tool_names[:limit]
    suffix = " ..." if len(tool_names) > limit else ""
    return ", ".join(selected) + suffix


def _build_warmup_recon_plan(
    *,
    target: str,
    scope: str,
    target_type: str,
    seed_scenarios: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized_target_type = _normalize_target_type(target_type)
    wanted = WARMUP_RECON_SCENARIO_COUNT
    candidates: list[dict[str, Any]] = []
    seen_tasks: set[str] = set()

    def _push(scenario: dict[str, Any]) -> None:
        if len(candidates) >= wanted:
            return
        task = str(scenario.get("task", "")).strip()
        if not task:
            return
        key = task.lower()
        if key in seen_tasks:
            return
        seen_tasks.add(key)
        normalized = {
            "task": task,
            "agent": "recon",
            "priority": _normalize_priority(scenario.get("priority", 3)),
            "details": str(scenario.get("details", "")).strip(),
            "methods": scenario.get("methods", []) if isinstance(scenario.get("methods", []), list) else [],
            "done": bool(scenario.get("done", False)),
            "status": str(scenario.get("status", "not yet")).strip() or "not yet",
        }
        candidates.append(normalized)

    for scenario in seed_scenarios:
        if str(scenario.get("agent", "")).strip().lower() != "recon":
            continue
        _push(scenario)

    for scenario in _default_warmup_recon_scenarios(normalized_target_type):
        _push(scenario)

    candidates = candidates[:wanted]
    recon_first = candidates[:4]
    enum_second = candidates[4:wanted]

    return {
        "target": target,
        "scope": scope,
        "target_types": [normalized_target_type],
        "notes": "Warmup recon-only plan generated before full checklist synthesis.",
        "phases": [
            {
                "name": "Reconnaissance",
                "priority": 1,
                "steps": [
                    {"id": "warmup-recon-01", "description": "Initial surface profiling", "scenarios": recon_first[:2]},
                    {"id": "warmup-recon-02", "description": "Expanded surface discovery", "scenarios": recon_first[2:4]},
                ],
            },
            {
                "name": "Enumeration",
                "priority": 2,
                "steps": [
                    {"id": "warmup-enum-01", "description": "Input and hidden surface discovery", "scenarios": enum_second[:2]},
                    {"id": "warmup-enum-02", "description": "Session, API, and alternate surface discovery", "scenarios": enum_second[2:4]},
                ],
            },
            {
                "name": "Exploitation",
                "priority": 3,
                "steps": [],
            },
            {
                "name": "Reporting",
                "priority": 4,
                "steps": [],
            },
        ],
    }


def _build_warmup_planner_message(
    *,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    static_recon_plan: dict[str, Any],
) -> str:
    normalized_target_type = _normalize_target_type(target_type)
    allowed_actions = _extract_scope_clauses(
        scope,
        info,
        keywords=(
            "allowed",
            "permit",
            "permitted",
            "authorized",
            "safe to test",
            "in scope",
            "within scope",
            "recon",
            "enumeration",
        ),
    )
    disallowed_actions = _extract_scope_clauses(
        scope,
        info,
        keywords=(
            "not allowed",
            "out of scope",
            "forbidden",
            "do not",
            "don't",
            "dont",
            "avoid",
            "exclude",
            "excluded",
            "denied",
            "no brute",
            "no dos",
            "no exploit",
        ),
    )
    info_text = str(info or "").strip() or "(not provided)"
    scope_text = str(scope or "").strip() or "(not provided)"
    return (
        f"Target: {target}\n"
        f"Target type: {normalized_target_type}\n"
        f"Scope: {scope_text}\n"
        f"Info: {info_text}\n\n"
        "## Target Profile\n"
        f"- Asset: {target}\n"
        f"- Target type: {normalized_target_type}\n"
        f"- Asset value / criticality: {_infer_target_value_line(info_text, scope_text)}\n"
        "Description / operator notes:\n"
        f"{info_text}\n\n"
        "## Scope Rules\n"
        "Allowed / in-scope actions:\n"
        f"{_format_prompt_bullets(allowed_actions, 'Use scope + operator notes as hard constraints and stay recon-only.')}\n"
        "Not allowed / out-of-scope actions:\n"
        f"{_format_prompt_bullets(disallowed_actions, 'Do not infer exploit or destructive work unless it is explicitly allowed later.')}\n\n"
        "## Static Recon Template\n"
        f"{_format_static_recon_plan_for_prompt(static_recon_plan)}\n\n"
        "## Available Recon Tooling\n"
        f"{_format_warmup_recon_tooling(normalized_target_type)}\n"
        "Use tool availability only as capability context. Do NOT mention tool names in methods[] and do NOT call tools in this planner pass.\n\n"
        "## Warmup Planner Task\n"
        "This is a recon-only warmup stage before the main pentest plan.\n"
        "Return a plan containing EXACTLY 8 reconnaissance scenarios and NO exploit/report work.\n"
        "Start from the stored static recon template for this target type.\n"
        "Use the target profile, scope rules, static recon template, and available recon tooling to maximize information gain while staying in scope.\n"
        "Using only the target description and scope rules, keep the plan as-is or adapt priorities/details/order so it better matches the target.\n"
        "Preserve the original static scenario task names unless the target description clearly requires a small adjustment.\n"
        "Preserve the original static methods unless the target description clearly justifies a small edit.\n"
        "Do NOT use tools in this planner pass.\n"
        "The 8 scenarios must maximize early reconnaissance coverage and information gain for this target type.\n"
        "Every scenario must use agent=recon, include priority, and stay evidence-seeking rather than exploitative.\n"
        "Return strict JSON with keys: summary, needs, plan, action_plan.\n"
    )


def _build_post_warmup_intel_info(
    *,
    info: str,
    warmup_summaries: list[dict[str, Any]],
    recon_plan_data: dict[str, Any] | None = None,
) -> str:
    lines: list[str] = []
    base_info = str(info or "").strip()
    if base_info:
        lines.append("Target description / info:")
        lines.append(base_info)

    recon_plan_lines: list[str] = []
    if isinstance(recon_plan_data, dict):
        phases = recon_plan_data.get("phases", [])
        if isinstance(phases, list):
            for phase in phases:
                if not isinstance(phase, dict):
                    continue
                for step in phase.get("steps", []):
                    if not isinstance(step, dict):
                        continue
                    for scenario in step.get("scenarios", []):
                        if not isinstance(scenario, dict):
                            continue
                        if str(scenario.get("agent", "")).strip().lower() != "recon":
                            continue
                        task = str(scenario.get("task", "")).strip()
                        if not task:
                            continue
                        details = str(scenario.get("details", "")).strip()
                        priority = _normalize_priority(scenario.get("priority", 3))
                        status = str(scenario.get("status", "not yet")).strip().lower() or "not yet"
                        detail_suffix = f" :: {details}" if details else ""
                        recon_plan_lines.append(
                            f"- [P{priority}] [{status}] {task}{detail_suffix}"
                        )
    if recon_plan_lines:
        lines.append("This is the recon plan to find max reconnaissance:")
        lines.extend(recon_plan_lines[:10])

    latest_cycle = 0
    for item in warmup_summaries:
        if not isinstance(item, dict):
            continue
        try:
            latest_cycle = max(latest_cycle, int(item.get("cycle", 0) or 0))
        except Exception:
            continue

    cache_lines: list[str] = []
    cycle_filtered = []
    if latest_cycle > 0:
        cycle_filtered = [
            item for item in warmup_summaries
            if isinstance(item, dict) and int(item.get("cycle", 0) or 0) == latest_cycle
        ]
    else:
        cycle_filtered = [item for item in warmup_summaries if isinstance(item, dict)]

    for idx, item in enumerate(cycle_filtered, start=1):
        task = str(item.get("task", "")).strip()
        finding_type = str(item.get("finding_type", "info")).strip().lower() or "info"
        compact_summary = str(item.get("compact_summary", "")).strip()
        recon_summary = str(item.get("recon_summary", "")).strip()
        summary = compact_summary or recon_summary
        if not summary:
            continue
        priority = _normalize_priority(item.get("priority", 3))
        cache_lines.append(
            f"- [{idx}] [P{priority}] ({finding_type}) {task}: {summary}"
        )

    if cache_lines:
        cycle_label = latest_cycle if latest_cycle > 0 else "latest"
        lines.append(f"This is the result (Perceptor cache) from cycle {cycle_label}:")
        lines.extend(cache_lines[:8])

    lines.append(
        "Use the recon plan and cache as the source of truth for a target-specific checklist. Stay strictly in scope."
    )
    return "\n".join(line for line in lines if line).strip()


def _format_structured_checklist_for_prompt(checklist: dict[str, Any]) -> str:
    if not isinstance(checklist, dict):
        return "(no synthesized checklist available)"

    blocks = checklist.get("checklist", [])
    if not isinstance(blocks, list) or not blocks:
        return "(no synthesized checklist available)"

    lines: list[str] = []
    total_items = 0
    for block_idx, block in enumerate(blocks, start=1):
        if not isinstance(block, dict):
            continue
        phase = str(block.get("phase", "")).strip()
        title = str(block.get("title", "")).strip() or f"Checklist Block {block_idx}"
        items = block.get("items", [])
        if phase:
            lines.append(f"{block_idx}. Phase {phase} - {title}")
        else:
            lines.append(f"{block_idx}. {title}")

        if not isinstance(items, list) or not items:
            lines.append("   - (no items)")
            continue

        for item_idx, item in enumerate(items, start=1):
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                priority = _normalize_priority(item.get("priority", 3))
            else:
                name = str(item).strip()
                priority = 3
            if name:
                lines.append(f"   - P{priority} {name}")
                total_items += 1

    if total_items:
        lines.append(f"Total checklist items: {total_items}")

    return "\n".join(lines) if lines else "(no synthesized checklist available)"


def _select_warmup_recon_batches(
    plan_data: dict[str, Any],
    *,
    worker_count: int = WARMUP_RECON_WORKERS,
    scenarios_per_worker: int = WARMUP_RECON_SCENARIOS_PER_WORKER,
) -> list[list[dict[str, Any]]]:
    selected = _select_recon_only_scenarios(
        plan_data,
        limit=worker_count * scenarios_per_worker,
    )
    batches: list[list[dict[str, Any]]] = []
    cursor = 0
    for _ in range(worker_count):
        batch = selected[cursor : cursor + scenarios_per_worker]
        cursor += scenarios_per_worker
        if batch:
            batches.append(batch)
    return batches


def _is_version_disclosure_summary(summary: str) -> bool:
    lowered = str(summary or "").strip().lower()
    if not lowered:
        return False
    version_markers = ("discloses", "server header", "banner", "version", "x-powered-by", "apache/", "nginx/", "php/")
    exploit_markers = ("shell", "dump", "retrieved", "executed", "unauthorized", "time-based", "blind injection", "internal metadata")
    return any(marker in lowered for marker in version_markers) and not any(
        marker in lowered for marker in exploit_markers
    )


def _coerce_confidence(value: Any) -> float | None:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    if confidence < 0:
        return 0.0
    if confidence > 1:
        return 1.0
    return confidence


def _should_trigger_retest(item: dict[str, Any]) -> bool:
    if str(item.get("verdict", "")).strip().lower() != "real_vulnerability":
        return False
    summary = str(item.get("verify_summary", "")).strip()
    if _is_version_disclosure_summary(summary):
        return False
    confidence = _coerce_confidence(item.get("verify_confidence"))
    if confidence is None:
        return False
    return confidence >= RETEST_MIN_CONFIDENCE


def _mark_scenario_done_in_plan(plan_data: dict[str, Any], scenario: dict[str, Any]) -> bool:
    """Mark a scenario as done in plan_data using stored indexes (fallback to matching)."""
    phases = plan_data.get("phases")
    if not isinstance(phases, list):
        return False

    phase_idx = scenario.get("_phase_index")
    step_idx = scenario.get("_step_index")
    scen_idx = scenario.get("_scenario_index")
    if isinstance(phase_idx, int) and isinstance(step_idx, int) and isinstance(scen_idx, int):
        try:
            target = phases[phase_idx]["steps"][step_idx]["scenarios"][scen_idx]
            if isinstance(target, dict):
                target["done"] = True
                target["status"] = _normalize_scenario_status(
                    target.get("status"),
                    done=True,
                )
                return True
        except (IndexError, KeyError, TypeError):
            pass

    target_task = str(scenario.get("task", "")).strip().lower()
    target_agent = str(scenario.get("agent", "")).strip().lower()
    target_priority = _normalize_priority(scenario.get("priority", 3))
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios")
            if not isinstance(scenarios, list):
                continue
            for item in scenarios:
                if not isinstance(item, dict):
                    continue
                if bool(item.get("done", False)):
                    continue
                task = str(item.get("task", "")).strip().lower()
                agent = str(item.get("agent", "")).strip().lower()
                priority = _normalize_priority(item.get("priority", 3))
                if task == target_task and agent == target_agent and priority == target_priority:
                    item["done"] = True
                    item["status"] = _normalize_scenario_status(
                        item.get("status"),
                        done=True,
                    )
                    return True
    return False


def _normalize_scenario_status(value: Any, *, done: bool = False) -> str:
    if done:
        normalized_done = str(value or "").strip().lower()
        if normalized_done in {"failed", "error"}:
            return "failed"
        if normalized_done in {"blocked", "vulnerable", "not_vulnerable", "inconclusive"}:
            return normalized_done
        return "completed"
    normalized = str(value or "").strip().lower()
    if normalized in {"completed", "complete", "done"}:
        return "completed"
    if normalized in {"working", "running", "in_progress", "in progress"}:
        return "working"
    if normalized in {"blocked", "failed", "error", "vulnerable", "not_vulnerable", "inconclusive"}:
        return "failed" if normalized == "error" else normalized
    return "not yet"


def _normalize_round_label(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("r") and raw[1:].isdigit():
        return raw
    if raw.isdigit():
        return f"r{raw}"
    return ""


def _locate_scenario_in_plan(plan_data: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any] | None:
    phases = plan_data.get("phases")
    if not isinstance(phases, list):
        return None

    phase_idx = scenario.get("_phase_index")
    step_idx = scenario.get("_step_index")
    scen_idx = scenario.get("_scenario_index")
    if isinstance(phase_idx, int) and isinstance(step_idx, int) and isinstance(scen_idx, int):
        try:
            target = phases[phase_idx]["steps"][step_idx]["scenarios"][scen_idx]
            if isinstance(target, dict):
                return target
        except (IndexError, KeyError, TypeError):
            pass

    target_task = str(scenario.get("task", "")).strip().lower()
    target_agent = str(scenario.get("agent", "")).strip().lower()
    target_priority = _normalize_priority(scenario.get("priority", 3))
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios")
            if not isinstance(scenarios, list):
                continue
            for item in scenarios:
                if not isinstance(item, dict):
                    continue
                task = str(item.get("task", "")).strip().lower()
                agent = str(item.get("agent", "")).strip().lower()
                priority = _normalize_priority(item.get("priority", 3))
                if task == target_task and agent == target_agent and priority == target_priority:
                    return item
    return None


def _update_scenario_runtime_state(
    plan_data: dict[str, Any],
    scenario: dict[str, Any],
    *,
    status: str | None = None,
    done: bool | None = None,
    round_label: str | None = None,
    round_labels: list[str] | None = None,
    route: str | None = None,
) -> bool:
    target = _locate_scenario_in_plan(plan_data, scenario)
    if not isinstance(target, dict):
        return False

    effective_done = bool(done) if done is not None else bool(target.get("done", False))
    if status is not None:
        target["status"] = _normalize_scenario_status(status, done=effective_done)
    elif "status" not in target:
        target["status"] = _normalize_scenario_status(target.get("status"), done=effective_done)

    if done is not None:
        target["done"] = bool(done)
        if bool(done):
            target["status"] = "completed"

    normalized_round_label = _normalize_round_label(round_label)
    if normalized_round_label:
        target["last_round"] = normalized_round_label

    if isinstance(round_labels, list) and round_labels:
        normalized_rounds = [
            label
            for label in (_normalize_round_label(item) for item in round_labels)
            if label
        ]
        if normalized_rounds:
            target["rounds_seen"] = normalized_rounds
            target["last_round"] = normalized_rounds[-1]

    if route:
        target["last_route"] = str(route).strip().lower()

    return True


def _count_done_scenarios(plan_data: dict[str, Any]) -> int:
    phases = plan_data.get("phases")
    if not isinstance(phases, list):
        return 0

    total = 0
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios")
            if not isinstance(scenarios, list):
                continue
            for scenario in scenarios:
                if not isinstance(scenario, dict):
                    continue
                done = bool(scenario.get("done", False))
                status = str(scenario.get("status", "")).strip().lower()
                if done or status in {"completed", "complete", "done"}:
                    total += 1
    return total


def _sync_plan_data_into_planner_state(plan_data: dict[str, Any]) -> bool:
    if not isinstance(plan_data, dict):
        return False
    try:
        from server.agents.planner.tools.pentest_plan import _current_plan as current_plan
    except Exception:
        return False
    if not isinstance(current_plan, dict):
        return False
    current_plan.clear()
    current_plan.update(deepcopy(plan_data))
    return True


def _sanitize_plan_remove_forbidden_agents(plan_data: dict[str, Any]) -> dict[str, Any]:
    """Remove any scenarios with forbidden agents (verify, retest, perceptor) from plan.

    Returns cleaned plan_data with only recon/exploit/report scenarios.
    """
    if not isinstance(plan_data, dict):
        return plan_data

    FORBIDDEN_AGENTS = {"verify", "retest", "perceptor"}
    cleaned_plan = dict(plan_data)
    phases = cleaned_plan.get("phases", [])

    if not isinstance(phases, list):
        return cleaned_plan

    for phase in phases:
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios", [])
            if not isinstance(scenarios, list):
                continue

            # Filter out forbidden agents
            cleaned_scenarios = [
                s for s in scenarios
                if isinstance(s, dict) and s.get("agent", "").strip().lower() not in FORBIDDEN_AGENTS
            ]

            if len(cleaned_scenarios) != len(scenarios):
                step["scenarios"] = cleaned_scenarios

    return cleaned_plan


async def _batch_verify_findings(
    findings: list[dict[str, Any]],
    verify_agent: Any,
    target: str,
    target_type: str,
    scope: str,
) -> list[dict[str, Any]]:
    """Verify all findings in parallel (not sequential per-finding).

    Returns list of dicts with verdict, verify_data, compact_summary for each finding.
    """
    verified = []

    # Build all verify tasks
    verify_tasks = []
    for finding in findings:
        scenario = finding.get("scenario", {})
        compact_summary = str(finding.get("compact_summary", "")).strip()
        row = finding.get("execution_row", {})

        verify_message = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"Original scenario: {json.dumps(scenario, ensure_ascii=True)}\n\n"
            "Finding to verify:\n"
            f"{compact_summary}\n\n"
            "Execution row:\n"
            f"{json.dumps(row, ensure_ascii=True)}"
        )
        verify_tasks.append((finding, verify_agent.run(verify_message)))

    # Run all verify agents in parallel
    if verify_tasks:
        results = await asyncio.gather(
            *[task for _, task in verify_tasks],
            return_exceptions=True
        )

        for (finding, _), result in zip(verify_tasks, results):
            if isinstance(result, Exception):
                verdict = "inconclusive"
                verify_data = {"error": str(result), "verdict": "inconclusive"}
            else:
                # Convert ExecuterResult to dict
                verify_data = asdict(result) if hasattr(result, '__dataclass_fields__') else result
                verdict = str(verify_data.get("verdict", verify_data.get("summary", "inconclusive"))).strip().lower()

            verified.append({
                "finding": finding,
                "verdict": verdict,
                "verify_data": verify_data,
                "compact_summary": str(finding.get("compact_summary", "")).strip(),
            })

    return verified


def _route_followup_from_assessment(assessment: dict[str, Any]) -> str:
    """Route perceptor assessment to appropriate next phase: verify, planner, or skip.

    Args:
        assessment: Perceptor assessment with finding_type and overall.ssvc fields

    Returns:
        str: "verify" (gate findings), "planner" (info/recon), or "skip"
    """
    finding_type = assessment.get("finding_type", "").strip().lower()

    # Vulnerabilities go to verify (gate to filter false positives)
    if "vulnerability" in finding_type or finding_type in {"vuln", "vulnerability"}:
        return "verify"

    # Info-only findings go to planner (update plan with evidence)
    if "info" in finding_type or finding_type in {"recon", "info_only", "information", "enumeration"}:
        return "planner"

    # Unknown types default to planner
    return "planner"


def _organize_findings_by_verdict(
    verified_findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Organize findings by verdict type for routing.

    Returns: {"real_vulnerability": [...], "false_positive": [...], "inconclusive": [...], "info_only": [...]}
    """
    organized = {
        "real_vulnerability": [],
        "false_positive": [],
        "inconclusive": [],
        "info_only": [],
    }

    for verified in verified_findings:
        finding = verified.get("finding", {})
        finding_type = str(finding.get("finding_type", "info")).strip().lower()
        verdict = verified.get("verdict", "inconclusive")

        # Route based on finding_type + verdict
        if finding_type == "vulnerability":
            if verdict == "real_vulnerability":
                organized["real_vulnerability"].append(verified)
            elif verdict == "false_positive":
                organized["false_positive"].append(verified)
            else:
                organized["inconclusive"].append(verified)
        else:
            # Info findings don't go to verify, just to planner
            organized["info_only"].append(verified)

    return organized
    overall = assessment.get("overall", {}) if isinstance(assessment, dict) else {}
    if not isinstance(overall, dict):
        return "planner"
    ssvc = str(overall.get("ssvc", "TRACK")).strip().upper()
    confidence = str(overall.get("confidence", "low")).strip().lower()

    if ssvc == "ACT":
        return "verify"
    if ssvc == "ATTEND" and confidence in {"medium", "high"}:
        return "retest"
    return "planner"


def _extract_failed_execution_rows(
    execution_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    failed: list[dict[str, Any]] = []
    for row in execution_rows:
        if not isinstance(row, dict):
            continue
        result = row.get("result")
        if not isinstance(result, dict):
            continue
        status = str(result.get("status", "")).strip().lower()
        if status in {"failed", "error"}:
            failed.append(row)
    return failed


def _classify_intel_log_kind(message: str) -> str:
    raw = str(message or "").strip()
    lowered = raw.lower()

    if "intel agent starting" in lowered:
        return "start"
    if "intel agent complete" in lowered:
        return "completed"
    if "rag is fresh" in lowered or "skipping update" in lowered:
        return "skip_rag_update"

    if "calling tools" in lowered or re.match(r"^[a-z0-9_]+\(", lowered):
        return "run_tool"

    if "final answer" in lowered or lowered.startswith("formatter done") or lowered.startswith("→"):
        return "result"

    if (
        "rag update needed" in lowered
        or lowered.startswith("update:")
        or "collecting rag snapshot" in lowered
        or lowered.startswith("rag snapshot:")
        or "prefetching formatter context" in lowered
        or lowered.startswith("prefetch:")
    ):
        return "updating_resources"

    if lowered.startswith("llm formatter starting") or lowered.startswith("llm round"):
        return "thinking"

    return "thinking"


def _classify_planner_log_kind(message: str) -> str:
    raw = str(message or "").strip()
    lowered = raw.lower()

    if "planner agent starting" in lowered:
        return "start"
    if "planner agent complete" in lowered:
        return "completed"
    if "calling tools" in lowered or re.match(r"^[a-z0-9_]+\(", lowered):
        return "run_tool"
    if lowered.startswith("llm round"):
        return "thinking"
    if lowered.startswith("executed ") or lowered.startswith("final answer"):
        return "result"
    if "error" in lowered or "failed" in lowered:
        return "warn"
    return "thinking"


def _build_planner_kickoff_message(
    *,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    intel_status: str,
    intel_vulnerabilities: list[str],
    intel_stats: dict[str, Any],
    intel_checklist: dict[str, Any],
    checklist_overview: dict[str, Any],
    static_recon_plan: dict[str, Any],
    warmup_summaries: list[dict[str, Any]],
) -> str:
    warmup_lines = []
    for idx, item in enumerate(warmup_summaries[:8], start=1):
        if not isinstance(item, dict):
            continue
        task = str(item.get("task", "")).strip()
        finding_type = str(item.get("finding_type", "info")).strip().lower() or "info"
        compact_summary = str(item.get("compact_summary", "")).strip()
        if task:
            warmup_lines.append(f"- [{idx}] ({finding_type}) {task}: {compact_summary}")
    checklist_text = _format_structured_checklist_for_prompt(intel_checklist)
    return (
        f"Target: {target}\n"
        f"Target type: {target_type}\n"
        f"Scope: {scope}\n"
        f"Info: {info}\n\n"
        "## Target Data\n"
        "Use the target, target type, scope, and info as hard planning constraints.\n\n"
        "## Static Recon Template\n"
        f"{_format_static_recon_plan_for_prompt(static_recon_plan)}\n\n"
        "## Intel Input\n"
        f"Intel status: {intel_status}\n"
        f"Vulnerabilities: {intel_vulnerabilities}\n"
        f"Checklist overview: {checklist_overview}\n"
        f"Intel stats: {intel_stats}\n\n"
        "## Synthesized Checklist\n"
        f"{checklist_text}\n\n"
        "## Warmup Recon Results\n"
        f"{chr(10).join(warmup_lines) if warmup_lines else '(no warmup summaries available)'}\n\n"
        "## Planner Task\n"
        "1. FIRST STEP: create a great pentest plan for this target.\n"
        "2. Start from target data + static recon template + warmup results, then use the synthesized checklist to refine the full plan.\n"
        "3. Treat warmup recon results as the source of truth for what the target actually exposes.\n"
        "4. Use the synthesized checklist as prioritized coverage guidance, not as abstract theory.\n"
        "5. The initial full plan should keep recon evidence-first and only add exploit scenarios when recon artifacts justify them.\n"
        "6. Every scenario should map back to either warmup evidence, target description, or a concrete checklist item.\n"
        "7. Return strict JSON with keys: summary, needs, plan, action_plan.\n"
        "8. action_plan must include: checklist_updates, checklist_additions, "
        "plan_modifications, dispatch, phase_advance, phase_advance_blocked_by, rationale.\n"
    )


class PrintCallback:
    """Print step-by-step output in the same style as test_intel_agent."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        on_log: Callable[[str, str], None] | None = None,
    ) -> None:
        self._start = time.perf_counter()
        self._enabled = enabled
        self._on_log = on_log

    def _ts(self) -> str:
        return f"[{time.perf_counter() - self._start:.1f}s]"

    def on_step(self, message: str) -> None:
        if self._enabled:
            print(f"  → {message} {self._ts()}", flush=True)
        if self._on_log is not None:
            self._on_log("info", message)

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  ✓ {message}", flush=True)
        if self._on_log is not None:
            self._on_log("success", message)

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ⚠ {message}", flush=True)
        if self._on_log is not None:
            self._on_log("warn", message)

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        if self._enabled:
            print(
                f"  ⚠ approval required: role={role} tool={tool_name} call_id={call_id}",
                flush=True,
            )
        if self._on_log is not None:
            self._on_log(
                "warn",
                (
                    f"Tool approval required: role={role} "
                    f"tool={tool_name} call_id={call_id} args={args}"
                ),
            )
        # Secure default: deny unless orchestration layer explicitly approves.
        return False


class ExecuterScanCallback:
    """Executer callback bridged to scan event bus + approval workflow."""

    def __init__(
        self,
        *,
        service: "ScanOrchestratorService",
        project_id: str,
        scan_id: str,
        enabled: bool = True,
    ) -> None:
        self._service = service
        self._project_id = project_id
        self._scan_id = scan_id
        self._enabled = enabled
        self._start = time.perf_counter()

    def _ts(self) -> str:
        return f"[{time.perf_counter() - self._start:.1f}s]"

    def on_step(self, message: str) -> None:
        if self._enabled:
            print(f"  → {message} {self._ts()}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_step",
            scan_id=self._scan_id,
            level="info",
            message=f"Executer [step] {message}",
            data={"stage": "executer", "kind": "step", "raw_message": message},
        )

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  ✓ {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_done",
            scan_id=self._scan_id,
            level="success",
            message=f"Executer [done] {message}",
            data={"stage": "executer", "kind": "done", "raw_message": message},
        )

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ⚠ {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_warn",
            scan_id=self._scan_id,
            level="warn",
            message=f"Executer [warn] {message}",
            data={"stage": "executer", "kind": "warn", "raw_message": message},
        )

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        return await self._service.request_executer_tool_approval(
            project_id=self._project_id,
            scan_id=self._scan_id,
            role=role,
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )

    async def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        return await self._service.request_executer_password(
            project_id=self._project_id,
            scan_id=self._scan_id,
            tool_name="ssh",  # Default to ssh, can be extracted from prompt
            prompt=prompt,
            reason=reason,
            call_id=call_id,
        )


@dataclass
class _PendingToolApproval:
    scan_id: str
    role: str
    tool_name: str
    args: dict[str, Any]
    call_id: str
    event: asyncio.Event
    decision: str | None = None


@dataclass
class _PendingPasswordRequest:
    scan_id: str
    tool_name: str
    prompt: str
    reason: str
    call_id: str
    event: asyncio.Event
    password: str | None = None
    approved: bool = False


class ScanOrchestratorService:
    """Runs and tracks orchestrated scan executions per project."""

    def __init__(self, projects_store: ProjectsStore) -> None:
        self._projects_store = projects_store
        self._vector_store = QdrantVectorStore()
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._runs: dict[str, dict[str, Any]] = {}
        self._planner_approval_events: dict[str, asyncio.Event] = {}
        self._tool_approval_events: dict[str, dict[str, _PendingToolApproval]] = {}
        self._password_request_events: dict[str, dict[str, _PendingPasswordRequest]] = {}
        self._event_subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}
        self._lock = asyncio.Lock()

    async def start_scan(
        self,
        project_id: str,
        *,
        target: str = "",
        target_config: dict[str, Any] | None = None,
        scope: str = "",
        info: str = "",
        resume: bool = False,
        force: bool = False,
    ) -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        current_status = str(project.get("status", "") or "").strip().lower()
        last_scan = project.get("lastScan")
        last_scan_id = str(last_scan.get("scanId", "")).strip() if isinstance(last_scan, dict) else ""

        if current_status == "completed" and not force:
            return {
                "scan_id": last_scan_id,
                "project_id": project_key,
                "status": "completed",
                "started_at": last_scan.get("startedAt") if isinstance(last_scan, dict) else None,
                "updated_at": project.get("updatedAt"),
                "finished_at": last_scan.get("finishedAt") if isinstance(last_scan, dict) else None,
                "error": "",
                "already_running": True,
            }
        if current_status == "paused" and not resume:
            return {
                "scan_id": last_scan_id,
                "project_id": project_key,
                "status": "paused",
                "started_at": last_scan.get("startedAt") if isinstance(last_scan, dict) else None,
                "updated_at": project.get("updatedAt"),
                "finished_at": last_scan.get("finishedAt") if isinstance(last_scan, dict) else None,
                "error": "",
                "already_running": True,
            }

        provided_target = str(target or "").strip()
        provided_target_config = target_config if isinstance(target_config, dict) else None
        if not provided_target and provided_target_config is not None:
            provided_target = _extract_target({"targetConfig": provided_target_config})

        project_target = _extract_target(project)
        effective_target = provided_target or project_target
        if not effective_target:
            raise ValueError("project target is missing")

        if provided_target:
            project["target"] = provided_target
        if provided_target_config is not None:
            project["targetConfig"] = provided_target_config
        if provided_target or provided_target_config is not None:
            project["updatedAt"] = _utc_now_iso()
            self._projects_store.upsert_project(project)

        effective_target_type = _normalize_target_type(project.get("targetType"))
        scope_payload = str(scope or "").strip()
        project_description = str(project.get("description", "")).strip()
        custom_info = str(info or "").strip() or project_description
        info_parts = [
            f"Target: {effective_target}",
            f"Scope: {scope_payload}" if scope_payload else "",
            custom_info,
        ]
        info_payload = "\n".join(part for part in info_parts if part).strip()
        _ensure_intel_agent_importable()
        _ensure_planner_agent_importable()

        async with self._lock:
            active_task = self._tasks.get(project_key)
            if active_task is not None and not active_task.done():
                current = dict(self._runs.get(project_key, {}))
                current["already_running"] = True
                return current

            if not resume:
                try:
                    self._projects_store.clear_scan_event_cache(project_key)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "scan_event_cache_clear_failed",
                        project_id=project_key,
                        error=str(exc),
                    )
                try:
                    self._projects_store.clear_project_context_windows(project_key)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "project_context_windows_clear_failed",
                        project_id=project_key,
                        error=str(exc),
                    )

            scan_id = str(uuid.uuid4())
            started_at = _utc_now_iso()
            run_state = {
                "scan_id": scan_id,
                "project_id": project_key,
                "status": "running",
                "started_at": started_at,
                "updated_at": started_at,
                "finished_at": None,
                "error": "",
                "awaiting_planner_approval": False,
                "awaiting_tool_approval": False,
                "pending_tool_approval": None,
                "already_running": False,
            }
            self._runs[project_key] = run_state
            self._persist_project_status(
                project_key,
                status="running",
                scan_progress=5,
                scan_meta={
                    "scanId": scan_id,
                    "status": "running",
                    "startedAt": started_at,
                },
            )
            self._emit_event(
                project_key,
                event="scan_started",
                scan_id=scan_id,
                level="info",
                message=f"Scan started for {effective_target}.",
                data={
                    "target": effective_target,
                    "target_type": effective_target_type,
                    "status": "running",
                    "scan_progress": 5,
                },
            )

            task = asyncio.create_task(
                self._run_scan(
                    project_id=project_key,
                    scan_id=scan_id,
                    target=effective_target,
                    target_type=effective_target_type,
                    started_at=started_at,
                    info=info_payload,
                ),
                name=f"scan_orchestrator_{project_key}",
            )
            task.add_done_callback(
                lambda done_task, pid=project_key: self._on_task_done(pid, done_task),
            )
            self._tasks[project_key] = task

            return dict(run_state)

    def subscribe_events(self, project_id: str) -> asyncio.Queue[dict[str, Any]]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        self._event_subscribers.setdefault(project_key, set()).add(queue)

        try:
            cached = self._projects_store.list_scan_event_cache(project_key, limit=180)
        except Exception as exc:  # pragma: no cover - defensive
            cached = []
            logger.warning(
                "scan_event_cache_load_failed",
                project_id=project_key,
                error=str(exc),
            )
        for payload in cached:
            self._push_event(queue, payload)

        status_snapshot = self.get_scan_status(project_key)
        self._push_event(
            queue,
            {
                "event": "scan_status_snapshot",
                "project_id": project_key,
                "scan_id": str(status_snapshot.get("scan_id", "")),
                "level": "info",
                "message": f"Current scan status: {status_snapshot.get('status', 'idle')}.",
                "timestamp": _utc_now_iso(),
                "data": {
                    "status": status_snapshot.get("status", "idle"),
                    "scan_progress": int(project.get("scanProgress", 0) or 0),
                    "scan": status_snapshot,
                },
            },
        )
        return queue

    def unsubscribe_events(self, project_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        project_key = str(project_id or "").strip()
        if not project_key:
            return
        subscribers = self._event_subscribers.get(project_key)
        if not subscribers:
            return
        subscribers.discard(queue)
        if not subscribers:
            self._event_subscribers.pop(project_key, None)

    def _push_event(
        self,
        queue: asyncio.Queue[dict[str, Any]],
        payload: dict[str, Any],
    ) -> None:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            pass

    def _emit_event(
        self,
        project_id: str,
        *,
        event: str,
        message: str,
        level: str = "info",
        scan_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "event": event,
            "project_id": project_id,
            "scan_id": scan_id or "",
            "level": level,
            "message": message,
            "timestamp": _utc_now_iso(),
            "data": data or {},
        }

        try:
            self._projects_store.append_scan_event_cache(project_id, payload)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "scan_event_cache_append_failed",
                project_id=project_id,
                event=event,
                error=str(exc),
            )

        subscribers = tuple(self._event_subscribers.get(project_id, set()))
        if not subscribers:
            return

        for queue in subscribers:
            self._push_event(queue, payload)

    def clear_event_cache(self, project_id: str) -> int:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")
        return self._projects_store.clear_scan_event_cache(project_key)

    def list_event_cache(self, project_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")
        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")
        return self._projects_store.list_scan_event_cache(project_key, limit=limit)

    def _reset_project_runtime_state(self, project: dict[str, Any]) -> None:
        agents = project.get("agents")
        if isinstance(agents, list):
            for agent in agents:
                if not isinstance(agent, dict):
                    continue
                agent["state"] = "idle"
                agent["progress"] = 0
                agent["currentTask"] = ""
                agent["lastUpdate"] = ""

        phases = project.get("phases")
        if isinstance(phases, list):
            for phase in phases:
                if not isinstance(phase, dict):
                    continue
                phase["status"] = "pending"
                phase["progress"] = 0
                phase["startedAt"] = ""
                phase["completedAt"] = ""

    def stop_scan(self, project_id: str, *, mode: str = "pause") -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        mode_clean = str(mode or "").strip().lower()
        if mode_clean not in {"pause", "cancel"}:
            raise ValueError("mode must be 'pause' or 'cancel'")

        task = self._tasks.get(project_key)
        if task is not None and not task.done():
            task.cancel()
        gate = self._planner_approval_events.get(project_key)
        if gate is not None:
            gate.set()

        now_iso = _utc_now_iso()
        run_state = self._runs.get(project_key, {})
        scan_id = str(run_state.get("scan_id") or project.get("lastScan", {}).get("scanId", "") or "")

        if mode_clean == "pause":
            self._runs[project_key] = {
                "scan_id": scan_id,
                "project_id": project_key,
                "status": "paused",
                "started_at": run_state.get("started_at"),
                "updated_at": now_iso,
                "finished_at": now_iso,
                "error": "",
                "awaiting_planner_approval": False,
                "awaiting_tool_approval": False,
                "pending_tool_approval": None,
                "already_running": False,
            }
            last_scan = project.get("lastScan")
            if isinstance(last_scan, dict):
                last_scan["status"] = "paused"
                last_scan["finishedAt"] = last_scan.get("finishedAt") or now_iso
                project["lastScan"] = last_scan
            project["status"] = "paused"
            project["updatedAt"] = now_iso
            self._projects_store.upsert_project(project)
            self._emit_event(
                project_key,
                event="scan_paused",
                scan_id=scan_id,
                level="warn",
                message="Scan paused by user.",
                data={"status": "paused"},
            )
            return {
                "ok": True,
                "project_id": project_key,
                "scan_id": scan_id,
                "status": "paused",
            }

        # cancel
        self._runs[project_key] = {
            "scan_id": scan_id,
            "project_id": project_key,
            "status": "idle",
            "started_at": run_state.get("started_at"),
            "updated_at": now_iso,
            "finished_at": now_iso,
            "error": "",
            "awaiting_planner_approval": False,
            "awaiting_tool_approval": False,
            "pending_tool_approval": None,
            "already_running": False,
        }
        project["status"] = "idle"
        project["scanProgress"] = 0
        project["updatedAt"] = now_iso
        project.pop("lastScan", None)
        project.pop("contextWindows", None)
        self._reset_project_runtime_state(project)
        self._projects_store.upsert_project(project)
        try:
            self._projects_store.clear_scan_event_cache(project_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "scan_event_cache_clear_failed",
                project_id=project_key,
                error=str(exc),
            )
        try:
            self._projects_store.clear_project_context_windows(project_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "project_context_windows_clear_failed",
                project_id=project_key,
                error=str(exc),
            )
        self._emit_event(
            project_key,
            event="scan_cancelled",
            scan_id=scan_id,
            level="warn",
            message="Scan cancelled by user.",
            data={"status": "idle"},
        )
        return {
            "ok": True,
            "project_id": project_key,
            "scan_id": scan_id,
            "status": "idle",
        }

    async def approve_planner(self, project_id: str) -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        async with self._lock:
            run_state = self._runs.get(project_key)
            if not isinstance(run_state, dict):
                raise ValueError("no active scan for project")

            scan_id = str(run_state.get("scan_id", "")).strip()
            status = str(run_state.get("status", "")).strip().lower()
            waiting = bool(run_state.get("awaiting_planner_approval"))

            if status != "running":
                raise ValueError("scan is not running")

            if waiting:
                gate = self._planner_approval_events.get(project_key)
                if gate is not None:
                    gate.set()
                now_iso = _utc_now_iso()
                run_state["awaiting_planner_approval"] = False
                run_state["updated_at"] = now_iso
                self._runs[project_key] = run_state

                self._emit_event(
                    project_key,
                    event="planner_approval_received",
                    scan_id=scan_id,
                    level="success",
                    message="Planner [approved] Checklist approved by pentester. Starting planner now.",
                    data={
                        "stage": "planner",
                        "kind": "approved",
                        "status": "running",
                        "awaiting_user_approval": False,
                    },
                )

            return {
                "ok": True,
                "project_id": project_key,
                "scan_id": scan_id,
                "status": "running",
                "awaiting_planner_approval": False,
                "already_approved": not waiting,
            }

    async def request_executer_tool_approval(
        self,
        *,
        project_id: str,
        scan_id: str,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        project_key = str(project_id or "").strip()
        if not project_key:
            return False

        approval_id = str(uuid.uuid4())
        pending = _PendingToolApproval(
            scan_id=str(scan_id or ""),
            role=str(role or ""),
            tool_name=str(tool_name or ""),
            args=dict(args or {}),
            call_id=str(call_id or ""),
            event=asyncio.Event(),
        )
        project_pending = self._tool_approval_events.setdefault(project_key, {})
        project_pending[approval_id] = pending

        run_state = self._runs.get(project_key)
        if isinstance(run_state, dict):
            run_state["awaiting_tool_approval"] = True
            run_state["pending_tool_approval"] = {
                "approval_id": approval_id,
                "scan_id": pending.scan_id,
                "role": pending.role,
                "tool_name": pending.tool_name,
                "call_id": pending.call_id,
            }
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_key] = run_state

        self._emit_event(
            project_key,
            event="executer_tool_waiting_approval",
            scan_id=pending.scan_id,
            level="warn",
            message=(
                f"Executer [waiting approval] {pending.role} requested "
                f"tool '{pending.tool_name}'. Approve or skip."
            ),
            data={
                "stage": "executer",
                "kind": "waiting_tool_approval",
                "awaiting_user_approval": True,
                "approval_id": approval_id,
                "role": pending.role,
                "tool_name": pending.tool_name,
                "call_id": pending.call_id,
                "args": pending.args,
            },
        )

        # Tools with long execution times need longer approval timeouts
        # Tool-specific timeouts: hydra/nuclei/sqlmap can take 10-20+ minutes
        TOOL_TIMEOUTS = {
            "hydra_bruteforce": 1800,      # 30 minutes - brute force takes time
            "nuclei_vuln_scan": 1200,      # 20 minutes - template scanning
            "sqlmap": 1200,                # 20 minutes - SQL injection testing
            "run_custom": 900,             # 15 minutes - generic CLI commands
            "run_python": 600,             # 10 minutes - Python scripts
        }
        # OPTIMIZATION: Default to 60 seconds for approval timeout (was 1800s/30min)
        # This prevents artificial delays while keeping tool-specific longer timeouts
        APPROVAL_TIMEOUT = TOOL_TIMEOUTS.get(pending.tool_name, 60)

        try:
            # Wait with heartbeat messages every 60 seconds to keep connection alive
            start_time = time.time()
            HEARTBEAT_INTERVAL = 60  # Send keepalive every 60 seconds
            next_heartbeat = start_time + HEARTBEAT_INTERVAL

            while not pending.event.is_set():
                remaining = APPROVAL_TIMEOUT - (time.time() - start_time)
                if remaining <= 0:
                    raise asyncio.TimeoutError()

                # Wait for event or heartbeat interval, whichever is shorter
                wait_time = min(HEARTBEAT_INTERVAL, remaining)
                try:
                    await asyncio.wait_for(pending.event.wait(), timeout=wait_time)
                    break  # Event was set, exit loop
                except asyncio.TimeoutError:
                    # Check if total timeout exceeded
                    if time.time() - start_time >= APPROVAL_TIMEOUT:
                        raise
                    # Send keepalive message
                    elapsed = int(time.time() - start_time)
                    self._emit_event(
                        project_key,
                        event="executer_tool_approval_waiting",
                        scan_id=pending.scan_id,
                        level="info",
                        message=(
                            f"Executer [approval waiting] {pending.role} tool '{pending.tool_name}' "
                            f"waiting for approval... ({elapsed}s/{APPROVAL_TIMEOUT}s)"
                        ),
                        data={
                            "stage": "executer",
                            "kind": "tool_approval_waiting",
                            "approval_id": approval_id,
                            "role": pending.role,
                            "tool_name": pending.tool_name,
                            "elapsed_seconds": elapsed,
                            "timeout_seconds": APPROVAL_TIMEOUT,
                        },
                    )
                    continue

        except asyncio.TimeoutError:
            # Timeout - auto-skip the tool
            pending.decision = "skip"
            logger.warning(
                "tool_approval_timeout",
                project_id=project_key,
                approval_id=approval_id,
                tool_name=pending.tool_name,
                timeout_seconds=APPROVAL_TIMEOUT,
            )
            self._emit_event(
                project_key,
                event="executer_tool_approval_timeout",
                scan_id=pending.scan_id,
                level="warn",
                message=(
                    f"Executer [approval timeout] {pending.role} tool '{pending.tool_name}' "
                    f"timeout after {APPROVAL_TIMEOUT}s - skipping tool"
                ),
                data={
                    "stage": "executer",
                    "kind": "tool_approval_timeout",
                    "approval_id": approval_id,
                    "role": pending.role,
                    "tool_name": pending.tool_name,
                    "call_id": pending.call_id,
                    "timeout_seconds": APPROVAL_TIMEOUT,
                },
            )

        approved = pending.decision == "approve"

        project_pending = self._tool_approval_events.get(project_key, {})
        project_pending.pop(approval_id, None)
        if not project_pending:
            self._tool_approval_events.pop(project_key, None)

        run_state = self._runs.get(project_key)
        if isinstance(run_state, dict):
            if project_pending:
                next_id, next_pending = next(iter(project_pending.items()))
                run_state["awaiting_tool_approval"] = True
                run_state["pending_tool_approval"] = {
                    "approval_id": next_id,
                    "scan_id": next_pending.scan_id,
                    "role": next_pending.role,
                    "tool_name": next_pending.tool_name,
                    "call_id": next_pending.call_id,
                }
            else:
                run_state["awaiting_tool_approval"] = False
                run_state["pending_tool_approval"] = None
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_key] = run_state

        self._emit_event(
            project_key,
            event="executer_tool_approval_decision",
            scan_id=pending.scan_id,
            level="success" if approved else "warn",
            message=(
                f"Executer [approval {'approved' if approved else 'skipped'}] "
                f"{pending.role} tool '{pending.tool_name}'."
            ),
            data={
                "stage": "executer",
                "kind": "tool_approval_decision",
                "approved": approved,
                "decision": pending.decision,
                "role": pending.role,
                "tool_name": pending.tool_name,
                "call_id": pending.call_id,
            },
        )
        return approved

    async def approve_executer_tool(
        self,
        project_id: str,
        *,
        approval_id: str,
        action: str,
    ) -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")
        action_clean = str(action or "").strip().lower()
        if action_clean not in {"approve", "skip"}:
            raise ValueError("action must be 'approve' or 'skip'")

        pending_by_id = self._tool_approval_events.get(project_key, {})
        pending = pending_by_id.get(str(approval_id or "").strip())
        if pending is None:
            raise ValueError("tool approval request not found")

        pending.decision = action_clean
        pending.event.set()

        return {
            "ok": True,
            "project_id": project_key,
            "approval_id": approval_id,
            "action": action_clean,
            "role": pending.role,
            "tool_name": pending.tool_name,
            "scan_id": pending.scan_id,
        }

    async def request_executer_password(
        self,
        *,
        project_id: str,
        scan_id: str,
        tool_name: str,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        """Request password from user for tools like SSH/sudo."""
        project_key = str(project_id or "").strip()
        if not project_key:
            return None

        password_id = str(uuid.uuid4())
        pending = _PendingPasswordRequest(
            scan_id=str(scan_id or ""),
            tool_name=str(tool_name or ""),
            prompt=str(prompt or ""),
            reason=str(reason or ""),
            call_id=str(call_id or ""),
            event=asyncio.Event(),
        )
        project_pending = self._password_request_events.setdefault(project_key, {})
        project_pending[password_id] = pending

        # Emit password request event to frontend
        self._emit_event(
            project_key,
            event="executer_password_request",
            scan_id=pending.scan_id,
            level="info",
            message=f"Executer [password required] {pending.tool_name} needs authentication",
            data={
                "stage": "executer",
                "kind": "password_request",
                "tool_name": pending.tool_name,
                "prompt": pending.prompt,
                "reason": pending.reason,
                "call_id": pending.call_id,
                "password_id": password_id,
            },
        )

        # Wait for password response with generous timeout and heartbeat
        PASSWORD_TIMEOUT = 600  # 10 minutes - user needs time to enter password
        try:
            start_time = time.time()
            HEARTBEAT_INTERVAL = 30  # Send keepalive every 30 seconds

            while not pending.event.is_set():
                remaining = PASSWORD_TIMEOUT - (time.time() - start_time)
                if remaining <= 0:
                    raise asyncio.TimeoutError()

                wait_time = min(HEARTBEAT_INTERVAL, remaining)
                try:
                    await asyncio.wait_for(pending.event.wait(), timeout=wait_time)
                    break  # Event was set, exit loop
                except asyncio.TimeoutError:
                    # Check if total timeout exceeded
                    if time.time() - start_time >= PASSWORD_TIMEOUT:
                        raise
                    # Send keepalive message
                    elapsed = int(time.time() - start_time)
                    self._emit_event(
                        project_key,
                        event="executer_password_waiting",
                        scan_id=pending.scan_id,
                        level="info",
                        message=(
                            f"Executer [password waiting] {pending.tool_name} "
                            f"waiting for password input... ({elapsed}s/{PASSWORD_TIMEOUT}s)"
                        ),
                        data={
                            "stage": "executer",
                            "kind": "password_waiting",
                            "password_id": password_id,
                            "tool_name": pending.tool_name,
                            "elapsed_seconds": elapsed,
                            "timeout_seconds": PASSWORD_TIMEOUT,
                        },
                    )
                    continue

        except asyncio.TimeoutError:
            logger.warning(
                "password_request_timeout",
                project_id=project_key,
                password_id=password_id,
                tool_name=pending.tool_name,
                timeout_seconds=PASSWORD_TIMEOUT,
            )
            self._emit_event(
                project_key,
                event="executer_password_timeout",
                scan_id=pending.scan_id,
                level="warn",
                message=f"Password request timed out after {PASSWORD_TIMEOUT}s",
                data={
                    "stage": "executer",
                    "kind": "password_timeout",
                    "tool_name": pending.tool_name,
                    "timeout_seconds": PASSWORD_TIMEOUT,
                },
            )
            project_pending = self._password_request_events.get(project_key, {})
            project_pending.pop(password_id, None)
            return None

        # Clean up
        project_pending = self._password_request_events.get(project_key, {})
        project_pending.pop(password_id, None)
        if not project_pending:
            self._password_request_events.pop(project_key, None)

        return pending.password if pending.approved else None

    async def approve_executer_password(
        self,
        project_id: str,
        *,
        password_id: str,
        password: str,
        approved: bool = True,
    ) -> dict[str, Any]:
        """Handle password response from frontend."""
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        pending_by_id = self._password_request_events.get(project_key, {})
        pending = pending_by_id.get(str(password_id or "").strip())
        if pending is None:
            raise ValueError("password request not found")

        pending.approved = approved
        pending.password = password if approved else None
        pending.event.set()

        return {
            "ok": True,
            "project_id": project_key,
            "password_id": password_id,
            "approved": approved,
            "tool_name": pending.tool_name,
            "scan_id": pending.scan_id,
        }

    def _emit_intel_callback_event(
        self,
        *,
        project_id: str,
        scan_id: str,
        level: str,
        raw_message: str,
    ) -> None:
        kind = _classify_intel_log_kind(raw_message)
        # Start/completed/crashed have dedicated top-level events.
        if kind in {"start", "completed", "crashed"}:
            return
        safe_message = str(raw_message or "").strip()
        if not safe_message:
            safe_message = kind.replace("_", " ")
        display_kind = kind.replace("_", " ")
        self._emit_event(
            project_id,
            event=f"intel_{kind}",
            scan_id=scan_id,
            level=level,
            message=f"Intel [{display_kind}] {safe_message}",
            data={
                "stage": "intel",
                "kind": kind,
                "raw_message": raw_message,
            },
        )

    def _emit_planner_callback_event(
        self,
        *,
        project_id: str,
        scan_id: str,
        level: str,
        raw_message: str,
    ) -> None:
        kind = _classify_planner_log_kind(raw_message)
        if kind in {"start", "completed", "crashed"}:
            return
        safe_message = str(raw_message or "").strip() or kind.replace("_", " ")
        display_kind = kind.replace("_", " ")
        self._emit_event(
            project_id,
            event=f"planner_{kind}",
            scan_id=scan_id,
            level=level,
            message=f"Planner [{display_kind}] {safe_message}",
            data={
                "stage": "planner",
                "kind": kind,
                "raw_message": raw_message,
            },
        )

    def get_scan_status(self, project_id: str) -> dict[str, Any]:
        project_key = str(project_id or "").strip()
        if not project_key:
            raise ValueError("project_id is required")

        run = self._runs.get(project_key)
        if run is not None:
            return dict(run)

        project = self._projects_store.get_project(project_key)
        if project is None:
            raise LookupError("project not found")

        last_scan = project.get("lastScan")
        if not isinstance(last_scan, dict):
            last_scan = {}

        return {
            "scan_id": str(last_scan.get("scanId", "")),
            "project_id": project_key,
            "status": str(project.get("status", "idle")),
            "started_at": last_scan.get("startedAt"),
            "updated_at": str(project.get("updatedAt", "")) or None,
            "finished_at": last_scan.get("finishedAt"),
            "error": str(last_scan.get("error", "")),
            "awaiting_planner_approval": bool(last_scan.get("awaitingPlannerApproval")),
            "awaiting_tool_approval": bool(last_scan.get("awaitingToolApproval")),
            "pending_tool_approval": last_scan.get("pendingToolApproval"),
            "already_running": False,
        }

    def _on_task_done(self, project_id: str, task: asyncio.Task[None]) -> None:
        self._tasks.pop(project_id, None)
        self._planner_approval_events.pop(project_id, None)
        self._tool_approval_events.pop(project_id, None)
        try:
            task.result()
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("scan_orchestrator_task_crashed", project_id=project_id, error=repr(exc))

    def _build_executer_message(
        self,
        *,
        plan_data: dict[str, Any],
        scenario: dict[str, Any],
        target: str,
        target_type: str,
        scope: str,
        info: str,
    ) -> str:
        history_block = _format_agent_execution_history_for_prompt(
            plan_data,
            agent_role=str(scenario.get("agent", "")).strip().lower() or "recon",
            active_scenarios=[scenario],
        )
        target_guidance = _build_target_execution_guidance(
            target=target,
            scenario_tasks=[str(scenario.get("task", "")).strip()],
        )
        return (
            f"Scenario: {str(scenario.get('task', '')).strip()}\n"
            f"Agent: {str(scenario.get('agent', '')).strip()}\n"
            f"Priority: {_normalize_priority(scenario.get('priority', 3))}\n"
            f"Details: {str(scenario.get('details', '')).strip()}\n"
            f"Methods: {json.dumps(scenario.get('methods', []), ensure_ascii=True)}\n"
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"Extra info: {info}\n"
            f"{target_guidance}\n"
            f"Prior execution history:\n{history_block}\n"
        )

    def _build_warmup_batch_executer_message(
        self,
        *,
        plan_data: dict[str, Any],
        scenarios: list[dict[str, Any]],
        target: str,
        target_type: str,
        scope: str,
        info: str,
    ) -> tuple[str, list[dict[str, Any]]]:
        labeled_scenarios: list[dict[str, Any]] = []
        blocks: list[str] = []
        for idx, scenario in enumerate(scenarios, start=1):
            scenario_id = f"s{idx}"
            task = str(scenario.get("task", "")).strip()
            details = str(scenario.get("details", "")).strip()
            methods = scenario.get("methods", []) if isinstance(scenario.get("methods"), list) else []
            labeled_scenarios.append(
                {
                    "scenario_id": scenario_id,
                    "scenario": scenario,
                }
            )
            blocks.append(
                f"Scenario ID: {scenario_id}\n"
                f"Task: {task}\n"
                f"Priority: {_normalize_priority(scenario.get('priority', 3))}\n"
                f"Details: {details}\n"
                f"Methods: {json.dumps(methods, ensure_ascii=True)}"
            )

        history_block = _format_agent_execution_history_for_prompt(
            plan_data,
            agent_role="recon",
            active_scenarios=scenarios,
        )
        target_guidance = _build_target_execution_guidance(
            target=target,
            scenario_tasks=[str(item.get("task", "")).strip() for item in scenarios if isinstance(item, dict)],
        )
        message = (
            "Warmup scenario batch:\n"
            "You have multiple recon scenarios assigned to the same worker for this warmup cycle.\n"
            "Stay strictly inside these listed scenarios.\n"
            "Treat each scenario as a separate lane of work.\n"
            "If you call a tool, include `_scenario_id` in the tool arguments with the matching scenario id.\n"
            "Across rounds 1 and 2, use at most 3 tools per round total, ideally covering both scenarios.\n"
            "Use prior execution history as valid evidence when it directly helps the assigned scenario.\n"
            "If a scenario is `Operational Synthesis`, it may synthesize earlier recon evidence from prior cycles and the current batch.\n"
            "Make sure every assigned scenario gets direct evidence by the end of Round 2.\n"
            "In the final JSON, include `scenario_summaries` with one entry per scenario.\n\n"
            "Target info:\n"
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"Extra info: {info}\n\n"
            f"{target_guidance}\n\n"
            "Prior recon execution history:\n"
            f"{history_block}\n\n"
            "Assigned scenarios:\n\n"
            + "\n\n".join(blocks)
        )
        return message, labeled_scenarios

    async def _cache_warmup_recon_summary(
        self,
        *,
        project_id: str,
        scan_id: str,
        plan_data: dict[str, Any],
        perceptor_agent: Any,
        scenario: dict[str, Any],
        row_result: dict[str, Any],
        cycle_number: int,
        worker_number: int,
    ) -> dict[str, Any]:
        # Run Perceptor analysis on tool results
        tool_results = row_result.get("tool_results", []) if isinstance(row_result, dict) else []
        if isinstance(tool_results, list) and tool_results:
            assessment = await perceptor_agent.assess_tool_results(
                scenario=scenario if isinstance(scenario, dict) else {},
                tool_results=tool_results,
                asset_context={
                    "criticality": "medium",
                    "internet_exposed": True,
                },
            )
        else:
            assessment = await perceptor_agent.assess_text(
                str(row_result.get("summary", "")).strip(),
                scenario=scenario if isinstance(scenario, dict) else {},
                tool_name="warmup_summary",
                asset_context={
                    "criticality": "medium",
                    "internet_exposed": True,
                },
            )

        scenario_task = str(scenario.get("task", "")).strip()
        recon_summary = str(row_result.get("summary", "")).strip()
        compact_summary = str(assessment.get("compact_summary", "")).strip()
        finding_type = str(assessment.get("finding_type", "info")).strip().lower() or "info"

        cached_payload = {
            "task": scenario_task,
            "priority": _normalize_priority(scenario.get("priority", 3)),
            "finding_type": finding_type,
            "compact_summary": compact_summary,
            "assessment": assessment,
            "recon_summary": recon_summary,
            "cycle": cycle_number,
            "worker": worker_number,
            "status": str(row_result.get("status", "")).strip().lower() or "complete",
        }

        # Log: show scenario name + what was found (not vuln classification)
        self._emit_event(
            project_id,
            event="perceptor_cached",
            scan_id=scan_id,
            level="info",
            message=(
                f"Perceptor [cached] cycle {cycle_number} worker {worker_number} "
                f"→ scenario: {scenario_task[:60]} → {recon_summary[:100]}"
            ),
            data={
                "stage": "perceptor",
                "kind": "warmup_cached",
                "iteration": cycle_number,
                "worker": worker_number,
                "scenario_task": scenario_task,
                "recon_summary": recon_summary[:200],
                "compact_summary": compact_summary,
            },
        )

        return cached_payload

    async def _run_warmup_recon_worker(
        self,
        *,
        project_id: str,
        scan_id: str,
        plan_data: dict[str, Any],
        recon_agent: Any,
        perceptor_agent: Any,
        perceptor_lock: asyncio.Lock,
        scenarios: list[dict[str, Any]],
        target: str,
        target_type: str,
        scope: str,
        info: str,
        cycle_number: int,
        worker_number: int,
        display_cycle_number: int,
    ) -> list[dict[str, Any]]:
        if not scenarios:
            return []

        completed_rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
        warmup_info = (
            str(info or "").strip()
            + "\nWarmup mode: recon-only surface discovery before full checklist synthesis."
        ).strip()

        recon_agent.reset_context_window_for_cycle()

        for s in scenarios:
            _update_scenario_runtime_state(plan_data, s, status="working", done=False)

        self._emit_event(
            project_id,
            event="scenario_state_change",
            scan_id=scan_id,
            level="info",
            message=(
                f"Worker [{worker_number - 1}] Executer [cycle {display_cycle_number}] warmup batch started: "
                f"{len(scenarios)} recon scenarios queued."
            ),
            data={
                "stage": "executer",
                "kind": "scenario_working",
                "scenario_task": ", ".join(
                    str(item.get("task", "")).strip() for item in scenarios if isinstance(item, dict)
                )[:200],
                "agent": "recon",
                "worker": worker_number - 1,
                "cycle": display_cycle_number,
                "warmup": True,
                "state": "working",
                "plan_data": plan_data,
            },
        )

        if len(scenarios) == 1:
            message = self._build_executer_message(
                plan_data=plan_data,
                scenario=scenarios[0],
                target=target,
                target_type=target_type,
                scope=scope,
                info=warmup_info,
            )
            result = await recon_agent.run(message)
            row_result = {
                "status": result.status,
                "summary": result.summary,
                "findings": result.findings,
                "evidence": result.evidence,
                "needs": result.needs,
                "tool_results": result.tool_results,
                "discovered_target_types": result.discovered_target_types,
                "rounds_executed": result.rounds_executed,
                "round_labels": result.round_labels,
            }
            scenario = scenarios[0]
            _append_scenario_execution_history(
                plan_data,
                scenario,
                cycle_number=cycle_number,
                row_result=row_result,
            )
            row_status = _normalize_recon_result_status(
                row_result.get("status"),
                summary=row_result.get("summary", ""),
                findings=row_result.get("findings", []),
                tool_results=row_result.get("tool_results", []),
                default="complete",
            )
            row_result["status"] = row_status
            _update_scenario_runtime_state(plan_data, scenario, status=row_status, done=True)
            _mark_scenario_done_in_plan(plan_data, scenario)
            self._emit_event(
                project_id,
                event="scenario_state_change",
                scan_id=scan_id,
                level="success" if row_status == "complete" else "warn",
                message=(
                    f"Worker [{worker_number - 1}] Executer [cycle {display_cycle_number}] "
                    f"warmup scenario finished with status={row_status}: "
                    f"{str(scenario.get('task', '')).strip()[:120]}"
                ),
                data={
                    "stage": "executer",
                    "kind": "scenario_finished",
                    "scenario_task": str(scenario.get("task", "")).strip(),
                    "agent": "recon",
                    "worker": worker_number - 1,
                    "cycle": display_cycle_number,
                    "warmup": True,
                    "state": row_status,
                    "plan_data": plan_data,
                },
            )
            completed_rows.append((scenario, row_result))
            return completed_rows

        batch_message, labeled_scenarios = self._build_warmup_batch_executer_message(
            plan_data=plan_data,
            scenarios=scenarios,
            target=target,
            target_type=target_type,
            scope=scope,
            info=warmup_info,
        )
        result = await recon_agent.run(batch_message)
        scenario_summaries = (
            result.scenario_summaries if isinstance(result.scenario_summaries, list) else []
        )
        summary_by_id: dict[str, dict[str, Any]] = {}
        for item in scenario_summaries:
            if not isinstance(item, dict):
                continue
            scenario_id = str(item.get("scenario_id", "")).strip().lower()
            if scenario_id:
                summary_by_id[scenario_id] = item

        for item in labeled_scenarios:
            scenario_id = str(item.get("scenario_id", "")).strip().lower()
            scenario = item.get("scenario")
            if not isinstance(scenario, dict):
                continue
            per_scenario = summary_by_id.get(scenario_id, {})
            scenario_tool_results = [
                tr for tr in result.tool_results
                if isinstance(tr, dict)
                and str(tr.get("scenario_id", "")).strip().lower() == scenario_id
            ]
            row_result = {
                "status": _normalize_recon_result_status(
                    per_scenario.get("status", result.status),
                    summary=per_scenario.get("summary", result.summary),
                    findings=per_scenario.get("findings", []) if isinstance(per_scenario.get("findings"), list) else result.findings,
                    tools=per_scenario.get("tools", []) if isinstance(per_scenario.get("tools"), list) else [],
                    tool_results=scenario_tool_results,
                    default=str(result.status or "").strip().lower() or "failed",
                ),
                "summary": str(per_scenario.get("summary", result.summary)).strip() or result.summary,
                "findings": per_scenario.get("findings", []) if isinstance(per_scenario.get("findings"), list) else result.findings,
                "evidence": [],
                "needs": per_scenario.get("needs", []) if isinstance(per_scenario.get("needs"), list) else result.needs,
                "tool_results": scenario_tool_results,
                "discovered_target_types": result.discovered_target_types,
                "rounds_executed": result.rounds_executed,
                "round_labels": result.round_labels,
            }
            _append_scenario_execution_history(
                plan_data,
                scenario,
                cycle_number=cycle_number,
                row_result=row_result,
            )
            row_status = _normalize_recon_result_status(
                row_result.get("status"),
                summary=row_result.get("summary", ""),
                findings=row_result.get("findings", []),
                tools=per_scenario.get("tools", []) if isinstance(per_scenario.get("tools"), list) else [],
                tool_results=row_result.get("tool_results", []),
                default="complete",
            )
            row_result["status"] = row_status
            _update_scenario_runtime_state(plan_data, scenario, status=row_status, done=True)
            _mark_scenario_done_in_plan(plan_data, scenario)
            self._emit_event(
                project_id,
                event="scenario_state_change",
                scan_id=scan_id,
                level="success" if row_status == "complete" else "warn",
                message=(
                    f"Worker [{worker_number - 1}] Executer [cycle {display_cycle_number}] "
                    f"warmup scenario finished with status={row_status}: "
                    f"{str(scenario.get('task', '')).strip()[:120]}"
                ),
                data={
                    "stage": "executer",
                    "kind": "scenario_finished",
                    "scenario_task": str(scenario.get("task", "")).strip(),
                    "agent": "recon",
                    "worker": worker_number - 1,
                    "cycle": display_cycle_number,
                    "warmup": True,
                    "state": row_status,
                    "plan_data": plan_data,
                },
            )
            completed_rows.append((scenario, row_result))

        # Return per-scenario results; caching happens only after all parallel workers finish.
        return completed_rows

    async def _run_warmup_recon_cycles(
        self,
        *,
        project_id: str,
        scan_id: str,
        plan_data: dict[str, Any],
        target: str,
        target_type: str,
        scope: str,
        info: str,
        callback: Any,
        cycle_offset: int = 0,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        from server.agents.executer.recon.agent import ReconExecuterAgent
        from server.agents.perceptor.agent import PerceptorAgent
        from server.config.agent import get_public_agent_config

        import re as _re

        class WorkerPrefixCallback:
            """Emit warmup worker events directly, producing clean [worker][N] logs."""

            _ROLE_RE = _re.compile(r"^\[(?:recon|exploit)\]\s*")

            def __init__(self, service: Any, project_id: str, scan_id: str, worker_index: int, parent_cb: Any):
                self._svc = service
                self._pid = project_id
                self._sid = scan_id
                self._prefix = f"[worker][{worker_index}]"
                self._parent = parent_cb  # for request_tool_approval only

            def _clean(self, message: str) -> str:
                """Strip [recon] role tag, return clean message."""
                return self._ROLE_RE.sub("", message)

            def on_step(self, message: str) -> None:
                clean = self._clean(message)
                self._svc._emit_event(
                    self._pid,
                    event="executer_step",
                    scan_id=self._sid,
                    level="info",
                    message=f"{self._prefix} {clean}",
                    data={"stage": "recon", "kind": "step", "raw_message": message},
                )

            def on_done(self, message: str) -> None:
                clean = self._clean(message)
                self._svc._emit_event(
                    self._pid,
                    event="executer_done",
                    scan_id=self._sid,
                    level="success",
                    message=f"{self._prefix} {clean}",
                    data={"stage": "recon", "kind": "done", "raw_message": message},
                )

            def on_warn(self, message: str) -> None:
                clean = self._clean(message)
                self._svc._emit_event(
                    self._pid,
                    event="executer_warn",
                    scan_id=self._sid,
                    level="warn",
                    message=f"{self._prefix} {clean}",
                    data={"stage": "recon", "kind": "warn", "raw_message": message},
                )

            def request_tool_approval(self, *, role: str, tool_name: str, args: dict[str, Any], call_id: str) -> Any:
                if hasattr(self._parent, "request_tool_approval"):
                    return self._parent.request_tool_approval(role=role, tool_name=tool_name, args=args, call_id=call_id)
                return False

        warmup_recon_agents = []
        for i in range(WARMUP_RECON_WORKERS):
            # Load-balance public LLM models: use exploit config for odd workers
            override_config = None
            if i % 2 == 1:
                try:
                    override_config = get_public_agent_config("exploit")
                except Exception:
                    pass

            worker_cb = WorkerPrefixCallback(self, project_id, scan_id, i, callback)
            warmup_recon_agents.append(
                ReconExecuterAgent(
                    callback=worker_cb,
                    target_types=[target_type],
                    project_id=None,
                    config=override_config,
                )
            )
        # Warmup caching is deterministic and per-scenario; avoid persisted perceptor
        # context/compression here so the loop moves directly into cached summaries.
        perceptor_agent = PerceptorAgent()
        perceptor_lock = asyncio.Lock()
        cached_summaries: list[dict[str, Any]] = []

        try:
            for cycle_number in range(1, WARMUP_RECON_CYCLES + 1):
                display_cycle_number = cycle_offset + cycle_number
                batches = _select_warmup_recon_batches(plan_data)
                if not batches:
                    break

                self._emit_event(
                    project_id,
                    event="executer_cycle_start",
                    scan_id=scan_id,
                    level="info",
                    message=(
                        f"Executer [cycle {display_cycle_number}] starting warmup scenario selection "
                        f"(executed={_count_done_scenarios(plan_data)})."
                    ),
                    data={
                        "stage": "executer",
                        "kind": "cycle_start",
                        "cycle": display_cycle_number,
                        "warmup": True,
                        "scenarios_executed_total": _count_done_scenarios(plan_data),
                    },
                )
                self._emit_event(
                    project_id,
                    event="warmup_cycle_started",
                    scan_id=scan_id,
                    level="info",
                    message=(
                        f"Warmup [cycle {display_cycle_number}] starting recon-only execution "
                        f"with {len(batches)} parallel recon workers."
                    ),
                    data={
                        "stage": "executer",
                        "kind": "cycle_start",
                        "cycle": display_cycle_number,
                        "warmup_cycle": cycle_number,
                        "warmup": True,
                        "batch_count": len(batches),
                    },
                )

                worker_tasks = []
                for worker_idx, batch in enumerate(batches, start=1):
                    if worker_idx - 1 < len(warmup_recon_agents):
                        warmup_recon_agents[worker_idx - 1].reset_context_window_for_cycle()
                    worker_tasks.append(
                        self._run_warmup_recon_worker(
                            project_id=project_id,
                            scan_id=scan_id,
                            plan_data=plan_data,
                            recon_agent=warmup_recon_agents[worker_idx - 1],
                            perceptor_agent=perceptor_agent,
                            perceptor_lock=perceptor_lock,
                            scenarios=batch,
                            target=target,
                            target_type=target_type,
                            scope=scope,
                            info=info,
                            cycle_number=cycle_number,
                            worker_number=worker_idx,
                            display_cycle_number=display_cycle_number,
                        )
                    )

                batch_results = await asyncio.gather(*worker_tasks)
                
                # Now that ALL parallel recon workers are complete, cache their results sequentially
                for worker_idx, worker_output in enumerate(batch_results):
                    for scenario, row_result in worker_output:
                        cached_payload = await self._cache_warmup_recon_summary(
                            project_id=project_id,
                            scan_id=scan_id,
                            plan_data=plan_data,
                            perceptor_agent=perceptor_agent,
                            scenario=scenario,
                            row_result=row_result,
                            cycle_number=cycle_number,
                            worker_number=worker_idx,
                        )
                        cached_summaries.append(cached_payload)

                self._emit_event(
                    project_id,
                    event="warmup_cycle_caching_started",
                    scan_id=scan_id,
                    level="info",
                    message=(
                        f"Warmup [cycle {display_cycle_number}] recon workers finished. "
                        f"Caching {sum(len(rows) for rows in batch_results)} per-scenario summaries."
                    ),
                    data={
                        "stage": "warmup",
                        "kind": "cache_start",
                        "cycle": display_cycle_number,
                        "warmup_cycle": cycle_number,
                        "warmup": True,
                        "result_count": sum(len(rows) for rows in batch_results),
                    },
                )

                self._emit_event(
                    project_id,
                    event="warmup_cycle_completed",
                    scan_id=scan_id,
                    level="success",
                    message=(
                        f"---------------------"
                        f"(cycle {display_cycle_number} finish)---------------------"
                    ),
                    data={
                        "stage": "warmup",
                        "kind": "cycle_completed",
                        "cycle": display_cycle_number,
                        "warmup_cycle": cycle_number,
                        "warmup": True,
                        "cached_summaries": sum(len(rows) for rows in batch_results),
                        "plan_data": plan_data,
                    },
                )
        finally:
            for agent in warmup_recon_agents:
                await agent.clear_context_window()
            await perceptor_agent.clear_context_window()
            for agent in warmup_recon_agents:
                await agent.close()
            await perceptor_agent.close()

        return plan_data, cached_summaries

    async def _run_retest_background(
        self,
        *,
        item: dict[str, Any],
        retest_agent: Any,
        retest_message: str,
        project_id: str,
        scan_id: str,
        target: str,
        target_type: str,
    ) -> None:
        """Run Retest agent in background to build PoC/report entries.

        This method runs independently and does NOT block other operations.
        - Takes verified vulnerability description
        - Executes PoC to gather evidence
        - Emits event for UI (tracking purpose only)
        - Does NOT save findings (Verify already saved them)
        """
        try:
            # Run retest agent (takes screenshot + detailed PoC)
            retest_result = await retest_agent.run(retest_message)

            # Build report entry from retest result
            retest_summary = str(retest_result.summary or "").strip()
            retest_data = (
                asdict(retest_result)
                if hasattr(retest_result, '__dataclass_fields__')
                else retest_result
            )

            # Emit event for UI tracking (informational only)
            # Do NOT save to findings - Verify already saved the finding
            self._emit_event(
                project_id,
                event="retest_poc_generated",
                scan_id=scan_id,
                level="info",
                message=f"Generated PoC for verified finding: {item['verify_summary'][:80]}",
                data={
                    "stage": "retest",
                    "kind": "poc_generated",
                    "verify_summary": item["verify_summary"],
                    "retest_summary": retest_summary,
                    "severity": _normalize_finding_severity(item["scenario"].get("priority", "medium")),
                    "vulnerability_type": item["scenario"].get("vulnerability_type", "unknown"),
                    "endpoint": item["scenario"].get("endpoint", ""),
                    "evidence_available": bool(retest_data.get("evidence")),
                    "tools_executed": len(retest_data.get("tool_results", [])),
                },
            )

            logger.info(
                "retest_background_poc_generated",
                project_id=project_id,
                scan_id=scan_id,
                vulnerability_type=item["scenario"].get("vulnerability_type", "unknown"),
                retest_summary_length=len(retest_summary),
            )

        except Exception as e:
            logger.error(
                "retest_background_error",
                project_id=project_id,
                error=str(e),
            )
            self._emit_event(
                project_id,
                event="retest_poc_error",
                scan_id=scan_id,
                level="warn",
                message=f"PoC generation failed: {str(e)[:100]}",
                data={
                    "stage": "retest",
                    "kind": "error",
                    "error": str(e),
                },
            )

    async def _execute_scenario_with_agent(
        self,
        *,
        plan_data: dict[str, Any],
        scenario: dict[str, Any],
        recon_agent: Any,
        exploit_agent: Any,
        target: str,
        target_type: str,
        scope: str,
        info: str,
    ) -> dict[str, Any]:
        message = self._build_executer_message(
            plan_data=plan_data,
            scenario=scenario,
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
        )
        role = str(scenario.get("agent", "recon")).strip().lower()
        if role == "exploit":
            result = await exploit_agent.run(message)
        else:
            role = "recon"
            result = await recon_agent.run(message)
        return {
            "scenario": dict(scenario),
            "executor_agent": role,
            "result": {
                "status": result.status,
                "summary": result.summary,
                "findings": result.findings,
                "evidence": result.evidence,
                "needs": result.needs,
                "tool_results": result.tool_results,
                "discovered_target_types": result.discovered_target_types,
                "rounds_executed": result.rounds_executed,
                "round_labels": result.round_labels,
            },
        }

    async def _run_execution_cycle(
        self,
        *,
        project_id: str,
        scan_id: str,
        cycle_number: int,
        plan_data: dict[str, Any],
        recon_agent: Any,
        exploit_agent: Any,
        verify_agent: Any,
        retest_agent: Any,
        perceptor_agent: Any,
        loop_planner: Any,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        intel_checklist: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """
        Execute one full cycle: select scenarios → run parallel → perceptor decides → verify/retest/plan.

        Returns: (should_continue, updated_plan_data)
            should_continue=False means Planner said "done"
        """
        # Select at most 1 recon + 1 exploit from pending scenarios
        selected = _select_recon_exploit_parallel_scenarios(plan_data)

        # Log what scenarios were selected for debugging
        available_scenarios = _extract_prioritized_exec_scenarios(plan_data, limit=20)

        # Count total scenarios in plan
        total_scenarios = 0
        done_scenarios = 0
        phases = plan_data.get("phases", [])
        for phase in phases:
            if isinstance(phase, dict):
                for step in phase.get("steps", []):
                    if isinstance(step, dict):
                        for scenario in step.get("scenarios", []):
                            if isinstance(scenario, dict):
                                total_scenarios += 1
                                if scenario.get("done"):
                                    done_scenarios += 1

        logger.info(
            "execution_cycle_selection",
            total_scenarios_in_plan=total_scenarios,
            done_scenarios=done_scenarios,
            pending_scenarios=total_scenarios - done_scenarios,
            available_count=len(available_scenarios),
            selected_count=len(selected),
            selected_agents=[s.get("agent") for s in selected] if selected else [],
            available_agents=[s.get("agent") for s in available_scenarios] if available_scenarios else [],
        )

        if not selected:
            # No more scenarios - ask planner if done
            return await self._check_planner_completion(
                project_id=project_id,
                scan_id=scan_id,
                loop_planner=loop_planner,
                plan_data=plan_data,
                target=target,
                target_type=target_type,
                scope=scope,
                info=info,
                intel_checklist=intel_checklist,
            )

        # Mark selected scenarios as working and emit state change
        for scenario in selected:
            _update_scenario_runtime_state(
                plan_data,
                scenario,
                status="working",
                done=False,
            )
            self._emit_event(
                project_id,
                event="scenario_state_change",
                scan_id=scan_id,
                level="info",
                message=f"Scenario started execution: {scenario.get('task', 'unknown')}",
                data={
                    "stage": "executer",
                    "kind": "scenario_working",
                    "scenario_task": scenario.get("task", ""),
                    "agent": scenario.get("agent", ""),
                    "state": "working",
                    "plan_data": plan_data,
                },
            )

        # Run selected scenarios in parallel (true async with asyncio.gather)
        execution_rows: list[dict[str, Any]] = []
        if selected:
            results = await asyncio.gather(*[
                self._execute_scenario_with_agent(
                    plan_data=plan_data,
                    scenario=scenario,
                    recon_agent=recon_agent,
                    exploit_agent=exploit_agent,
                    target=target,
                    target_type=target_type,
                    scope=scope,
                    info=info,
                )
                for scenario in selected
            ])
            execution_rows.extend(results)

        # ============================================================================
        # PHASE 1: Perceptor analyzes findings (SEQUENTIAL - Verify depends on this)
        # ============================================================================
        perceptor_rows: list[dict[str, Any]] = []
        planner_loop_rows: list[dict[str, Any]] = []

        # Organize findings by assessment type as we process them
        assessments_organized: dict[str, list[dict[str, Any]]] = {
            "vulnerabilities": [],  # Will be verified in Phase 2
            "info_only": [],        # Direct to planner in Phase 3
        }

        for idx, row in enumerate(execution_rows, start=1):
            row_result = row.get("result", {}) if isinstance(row, dict) else {}
            row_status = str(row_result.get("status", "")).strip().lower() if isinstance(row_result, dict) else ""

            # FIX: Process ALL rows including failed ones (classify failed as INFO)
            # Previously skipped failed rows entirely, causing Perceptor to never run
            # when both agents failed. This prevented proper assessment.

            scenario = row.get("scenario", {})
            tool_results = (
                row.get("result", {}).get("tool_results", [])
                if isinstance(row.get("result"), dict)
                else []
            )

            # Perceptor analyzes findings (sequential - required for Verify)
            assessment = await perceptor_agent.assess_tool_results(
                scenario=scenario if isinstance(scenario, dict) else {},
                tool_results=tool_results if isinstance(tool_results, list) else [],
                asset_context={
                    "criticality": (
                        "high"
                        if _normalize_priority((scenario or {}).get("priority", 3)) <= 2
                        else "medium"
                    ),
                    "internet_exposed": target_type in {"web_app", "api"},
                },
            )
            perceptor_rows.append(assessment)

            compact_summary = str(assessment.get("compact_summary", "")).strip()
            finding_type = str(assessment.get("finding_type", "info")).strip().lower()
            agent_role = str(scenario.get("agent", "")).strip().lower() if isinstance(scenario, dict) else ""
            finding_type, compact_summary = _normalize_perceptor_classification(
                agent_role=agent_role,
                row_status=row_status,
                finding_type=finding_type,
                compact_summary=compact_summary,
                row_result=row_result if isinstance(row_result, dict) else {},
                scenario=scenario if isinstance(scenario, dict) else {},
            )

            # Emit perceptor_classified event
            self._emit_event(
                project_id,
                event="perceptor_classified",
                scan_id=scan_id,
                level="info",
                message=(
                    f"Perceptor [classified] scenario #{idx} → "
                    f"{assessment.get('overall', {}).get('ssvc', 'TRACK')} "
                    f"(type={finding_type})"
                ),
                data={
                    "stage": "perceptor",
                    "kind": "classified",
                    "iteration": idx,
                    "assessment": assessment,
                },
            )

            # Organize by type for batch processing
            if finding_type == "vulnerability":
                assessments_organized["vulnerabilities"].append({
                    "idx": idx,
                    "assessment": assessment,
                    "row": row,
                    "scenario": scenario,
                    "row_result": row_result,
                    "compact_summary": compact_summary,
                })
            else:
                assessments_organized["info_only"].append({
                    "idx": idx,
                    "assessment": assessment,
                    "row": row,
                    "scenario": scenario,
                    "row_result": row_result,
                    "compact_summary": compact_summary,
                })

        # ============================================================================
        # PHASE 2-3: Verify → Planner → Retest (WRAPPED IN EXCEPTION HANDLER)
        # ============================================================================
        verify_results_organized: dict[str, list[dict[str, Any]]] = {
            "real_vulnerabilities": [],
            "false_positives": [],
            "inconclusives": [],
        }

        try:
            logger.info(
                "phase2_verify_start",
                vulnerabilities_count=len(assessments_organized["vulnerabilities"]),
            )

            if assessments_organized["vulnerabilities"]:
                for verify_index, item in enumerate(
                    assessments_organized["vulnerabilities"],
                    start=1,
                ):
                    verify_agent.reset_context_window_for_cycle()
                    self._emit_event(
                        project_id,
                        event="verify_batch_progress",
                        scan_id=scan_id,
                        level="info",
                        message=(
                            f"Verify [batch] processing finding {verify_index}/"
                            f"{len(assessments_organized['vulnerabilities'])}."
                        ),
                        data={
                            "stage": "verify",
                            "kind": "batch_progress",
                            "current": verify_index,
                            "total": len(assessments_organized["vulnerabilities"]),
                            "scenario_task": str(item.get("scenario", {}).get("task", "")),
                        },
                    )

                    # EMIT: Show finding as "working" in UI during verification
                    severity = _normalize_finding_severity(
                        item.get("scenario", {}).get("priority", "medium")
                    )
                    self._emit_event(
                        project_id,
                        event="verify_finding_working",
                        scan_id=scan_id,
                        level="info",
                        message=f"Verifying finding: {item.get('compact_summary', 'Unknown')[:100]}",
                        data={
                            "stage": "verify",
                            "kind": "finding_working",
                            "title": item.get('compact_summary', 'Finding'),
                            "severity": severity,
                            "endpoint": str(item.get("scenario", {}).get("endpoint", "")).strip(),
                            "vulnerability_type": str(item.get("scenario", {}).get("vulnerability_type", "")).strip(),
                            "status": "working",  # UI badge shows "working" during verification
                            "index": verify_index,
                        },
                    )

                    verify_message = (
                        f"Target: {target}\n"
                        f"Target type: {target_type}\n"
                        f"Scope: {scope}\n"
                        f"Original scenario: {json.dumps(item['scenario'], ensure_ascii=True)}\n\n"
                        "Finding to verify:\n"
                        f"{item['compact_summary']}\n\n"
                        "Execution row:\n"
                        f"{json.dumps(item['row'], ensure_ascii=True)}"
                    )

                    try:
                        verify_result = await verify_agent.run(verify_message)
                    except Exception as verify_exc:
                        logger.error(
                            "verify_task_exception",
                            task_index=verify_index - 1,
                            error=str(verify_exc),
                            error_type=type(verify_exc).__name__,
                        )
                        self._emit_event(
                            project_id,
                            event="verify_task_failed",
                            scan_id=scan_id,
                            level="warn",
                            message=f"Verify task {verify_index} failed: {str(verify_exc)[:100]}",
                            data={"task_index": verify_index - 1, "error": str(verify_exc)},
                        )
                        continue

                    try:
                        verify_data = asdict(verify_result) if hasattr(verify_result, '__dataclass_fields__') else verify_result

                        # CRITICAL FIX: Defensive verdict extraction with fallback mapping
                        # Handles: status=incomplete, verdict=..., summary=..., unknown fields
                        verdict = str(verify_data.get("verdict", "")).strip().lower()
                        status = str(verify_data.get("status", "")).strip().lower()
                        summary = str(verify_data.get("summary", "")).strip()

                        logger.warning(
                            "verify_result_raw",
                            item_idx=item["idx"],
                            verdict_field=verdict,
                            status_field=status,
                            summary_field=summary,
                            all_keys=list(verify_data.keys()) if isinstance(verify_data, dict) else [],
                        )

                        if not verdict:
                            if status in {"real_vulnerability", "false_positive", "inconclusive"}:
                                verdict = status
                            elif status in {"incomplete", "not_vulnerable", "unknown", "error"}:
                                verdict = "inconclusive"
                            else:
                                verdict = "inconclusive"

                        if not verdict:
                            verdict = "inconclusive"

                        if verdict not in {"real_vulnerability", "false_positive", "inconclusive"}:
                            logger.warning(
                                "verify_invalid_verdict",
                                item_idx=item["idx"],
                                original_verdict=verdict,
                                status=status,
                            )
                            self._emit_event(
                                project_id,
                                event="verify_warning",
                                scan_id=scan_id,
                                level="warn",
                                message=f"Verify returned unexpected verdict: {verdict} → inconclusive",
                                data={"original_verdict": verdict, "status": status},
                            )
                            verdict = "inconclusive"

                        logger.info(
                            "verify_verdict_assigned",
                            item_idx=item["idx"],
                            final_verdict=verdict,
                            from_status=status,
                        )

                        verify_summary = summary if summary else f"[{status}] Verification incomplete - treating as inconclusive"
                        verify_confidence = _coerce_confidence(verify_data.get("confidence"))
                        severity = _normalize_finding_severity(
                            item.get("scenario", {}).get("priority", "medium")
                        )

                        organized_item = {
                            "idx": item["idx"],
                            "assessment": item["assessment"],
                            "row": item["row"],
                            "scenario": item["scenario"],
                            "row_result": item["row_result"],
                            "compact_summary": item["compact_summary"],
                            "verdict": verdict,
                            "verify_summary": verify_summary,
                            "verify_confidence": verify_confidence,
                            "verify_data": verify_data,
                        }

                        if verdict == "real_vulnerability":
                            verify_results_organized["real_vulnerabilities"].append(organized_item)
                            self._emit_event(
                                project_id,
                                event="verify_real_vulnerability_confirmed",
                                scan_id=scan_id,
                                level="warn",
                                message=f"Verify confirmed real vulnerability: {verify_summary[:120]}",
                                data={
                                    "stage": "verify",
                                    "kind": "real_vulnerability_confirmed",
                                    "title": verify_summary,
                                    "summary": verify_summary,
                                    "severity": severity,
                                    "endpoint": str(item.get("scenario", {}).get("endpoint", "")).strip(),
                                    "scenario_task": str(item.get("scenario", {}).get("task", "")).strip(),
                                    "vulnerability_type": str(item.get("scenario", {}).get("vulnerability_type", "")).strip(),
                                    "status": "real_vulnerability",  # UI updates badge to confirmed
                                },
                            )
                        elif verdict == "false_positive":
                            verify_results_organized["false_positives"].append(organized_item)
                            self._emit_event(
                                project_id,
                                event="verify_finding_verdict",
                                scan_id=scan_id,
                                level="info",
                                message=f"Verify determined false positive: {verify_summary[:120]}",
                                data={
                                    "stage": "verify",
                                    "kind": "false_positive_confirmed",
                                    "title": verify_summary,
                                    "severity": severity,
                                    "endpoint": str(item.get("scenario", {}).get("endpoint", "")).strip(),
                                    "status": "false_positive",  # UI updates badge to dismissed
                                    "verdict": "false_positive",
                                },
                            )
                        else:  # inconclusive
                            verify_results_organized["inconclusives"].append(organized_item)
                            self._emit_event(
                                project_id,
                                event="verify_finding_verdict",
                                scan_id=scan_id,
                                level="info",
                                message=f"Verify inconclusive: {verify_summary[:120]}",
                                data={
                                    "stage": "verify",
                                    "kind": "inconclusive_confirmed",
                                    "title": verify_summary,
                                    "severity": severity,
                                    "endpoint": str(item.get("scenario", {}).get("endpoint", "")).strip(),
                                    "status": "inconclusive",  # UI updates badge to inconclusive
                                    "verdict": "inconclusive",
                                },
                            )

                    except Exception as item_error:
                        logger.error(
                            "verify_result_processing_error",
                            item_idx=item.get("idx", "unknown"),
                            error=str(item_error),
                        )
                        verify_results_organized["inconclusives"].append({
                            "idx": item.get("idx", -1),
                            "verdict": "inconclusive",
                            "verify_summary": f"[ERROR] Verification processing failed: {str(item_error)[:100]}",
                            "verify_data": {},
                            "compact_summary": item.get("compact_summary", "Unknown"),
                        })

            # Log final verdict organization
            logger.info(
                "verify_batch_complete",
                real_vulns=len(verify_results_organized["real_vulnerabilities"]),
                false_positives=len(verify_results_organized["false_positives"]),
                inconclusives=len(verify_results_organized["inconclusives"]),
            )

            # CRITICAL: Save real vulnerabilities to project database (Verify's responsibility)
            # Only real vulnerabilities are added to findings
            if verify_results_organized["real_vulnerabilities"]:
                project_key = str(project_id or "").strip()
                current_project = self._projects_store.get_project(project_key)

                if "findings" not in current_project:
                    current_project["findings"] = []
                findings_list = (
                    current_project["findings"]
                    if isinstance(current_project.get("findings"), list)
                    else []
                )
                current_project["findings"] = findings_list
                saved_finding_entries: list[dict[str, Any]] = []

                for item in verify_results_organized["real_vulnerabilities"]:
                    finding_entry = _build_verified_finding_entry(
                        target=target,
                        item=item,
                    )
                    saved_finding = _upsert_project_finding(
                        findings=findings_list,
                        finding_entry=finding_entry,
                    )
                    saved_finding_entries.append(saved_finding)

                current_project["findings_count"] = len(current_project.get("findings", []))
                current_project["last_findings_updated"] = datetime.now(timezone.utc).isoformat()
                self._projects_store.upsert_project(current_project)
                cache_path = _write_project_findings_cache(
                    project_id=project_key,
                    findings=[
                        finding
                        for finding in current_project.get("findings", [])
                        if isinstance(finding, dict)
                    ],
                )

                for saved_finding in saved_finding_entries:
                    self._emit_event(
                        project_id,
                        event="verify_finding_saved",
                        scan_id=scan_id,
                        level="success",
                        message=f"Verify [saved] confirmed finding persisted: {saved_finding.get('title', '')[:120]}",
                        data={
                            "stage": "verify",
                            "kind": "finding_saved",
                            "finding": saved_finding,
                            "cache_path": cache_path,
                        },
                    )

                logger.info(
                    "verify_findings_saved_to_db",
                    project_id=project_id,
                    scan_id=scan_id,
                    findings_count=len(verify_results_organized["real_vulnerabilities"]),
                    cache_path=cache_path,
                )

        except Exception as phase2_exc:
            logger.error(
                "phase2_verify_batch_failed",
                error=str(phase2_exc),
                error_type=type(phase2_exc).__name__,
            )
            self._emit_event(
                project_id,
                event="verify_batch_error",
                scan_id=scan_id,
                level="warn",
                message=f"Verify batch processing failed: {str(phase2_exc)[:100]}",
                data={"error": str(phase2_exc)},
            )
            # Continue with empty results

        retest_candidates = [
            item
            for item in verify_results_organized["real_vulnerabilities"]
            if _should_trigger_retest(item)
        ]

        # Mark completed scenarios before handing the current plan back to Planner.
        for row in execution_rows:
            row_result = row.get("result", {}) if isinstance(row, dict) else {}
            row_status = str(row_result.get("status", "")).strip().lower() if isinstance(row_result, dict) else ""

            scenario = row.get("scenario", {})
            if isinstance(scenario, dict):
                _append_scenario_execution_history(
                    plan_data,
                    scenario,
                    cycle_number=cycle_number,
                    row_result=row_result,
                )

            if row_status in {"failed", "error"}:
                continue

            if isinstance(scenario, dict):
                rounds_executed = int(row_result.get("rounds_executed", 0) or 0)
                round_labels = row_result.get("round_labels", [])

                route = "batch_processed"
                for item in verify_results_organized["real_vulnerabilities"]:
                    if item["scenario"] == scenario:
                        route = (
                            "verify->planner+retest(batch)"
                            if any(candidate["scenario"] == scenario for candidate in retest_candidates)
                            else "verify->planner(real_vulnerability,batch)"
                        )
                        break
                for item in verify_results_organized["false_positives"]:
                    if item["scenario"] == scenario:
                        route = "verify->planner(false_positive,batch)"
                        break
                if route == "batch_processed":
                    for item in verify_results_organized["inconclusives"]:
                        if item["scenario"] == scenario:
                            route = "verify->planner(inconclusive,batch)"
                            break
                if route == "batch_processed":
                    for item in assessments_organized["info_only"]:
                        if item["scenario"] == scenario:
                            route = "perceptor->planner(info_only,batch)"
                            break

                _update_scenario_runtime_state(
                    plan_data,
                    scenario,
                    status="completed",
                    done=True,
                    round_label=f"r{rounds_executed}" if rounds_executed > 0 else None,
                    round_labels=round_labels if isinstance(round_labels, list) else None,
                    route=route,
                )
                _mark_scenario_done_in_plan(plan_data, scenario)
                self._emit_event(
                    project_id,
                    event="scenario_state_change",
                    scan_id=scan_id,
                    level="info",
                    message=f"Scenario completed: {scenario.get('task', 'unknown')}",
                    data={
                        "stage": "executer",
                        "kind": "scenario_done",
                        "scenario_task": scenario.get("task", ""),
                        "agent": scenario.get("agent", ""),
                        "state": "completed",
                        "route": route,
                        "round_label": f"r{rounds_executed}" if rounds_executed > 0 else "",
                        "rounds_seen": round_labels if isinstance(round_labels, list) else [],
                        "plan_data": plan_data,
                    },
                )

        _sync_plan_data_into_planner_state(plan_data)

        # ============================================================================
        # PHASE 3A: Launch Retest (PARALLEL - fire and forget)
        # PHASE 3B: Launch Planner (PARALLEL - immediate)
        # ============================================================================
        # Both run independently and concurrently

        # Create Retest tasks (fire-and-forget, non-blocking)
        retest_background_tasks = []
        if retest_candidates:
            for item in retest_candidates:
                retest_message = (
                    f"Target: {target}\n"
                    f"Target type: {target_type}\n"
                    f"Scope: {scope}\n\n"
                    "VERIFIED VULNERABILITY - Build Report Entry:\n"
                    f"{item['verify_summary']}\n\n"
                    f"Verify confidence: {item.get('verify_confidence', 'n/a')}\n\n"
                    "Verify Evidence:\n"
                    f"{json.dumps(item['verify_data'].get('evidence', {}), ensure_ascii=True)}\n\n"
                    "Instructions:\n"
                    "1. Take screenshot of vulnerability\n"
                    "2. Capture detailed PoC proof (request/response/output)\n"
                    "3. Build report entry with all details\n"
                    "4. Return structured JSON for database storage"
                )

                # Create task but don't await it yet
                retest_task = asyncio.create_task(
                    self._run_retest_background(
                        item=item,
                        retest_agent=retest_agent,
                        retest_message=retest_message,
                        project_id=project_id,
                        scan_id=scan_id,
                        target=target,
                        target_type=target_type,
                    )
                )
                retest_background_tasks.append(retest_task)

        # Build aggregated planner message with all findings
        planner_sections = []

        # Add real vulnerabilities section
        if verify_results_organized["real_vulnerabilities"]:
            real_vuln_section = "VERIFIED REAL VULNERABILITIES (confirmed by Verify agent):\n"
            for item in verify_results_organized["real_vulnerabilities"]:
                real_vuln_section += f"\n- [{item['idx']}] {item['verify_summary']}"
            planner_sections.append(real_vuln_section)

        # Add false positives section
        if verify_results_organized["false_positives"]:
            false_pos_section = "FALSE POSITIVES (filtered out):\n"
            for item in verify_results_organized["false_positives"]:
                false_pos_section += f"\n- [{item['idx']}] {item['verify_summary']}"
            planner_sections.append(false_pos_section)

        # Add inconclusives section
        if verify_results_organized["inconclusives"]:
            inconc_section = "INCONCLUSIVE FINDINGS (need manual review):\n"
            for item in verify_results_organized["inconclusives"]:
                inconc_section += f"\n- [{item['idx']}] {item['compact_summary']}"
            planner_sections.append(inconc_section)

        # Add info-only section
        if assessments_organized["info_only"]:
            info_section = "RECONNAISSANCE FINDINGS (informational only):\n"
            for item in assessments_organized["info_only"]:
                info_section += f"\n- [{item['idx']}] {item['compact_summary']}"
            planner_sections.append(info_section)

        # Build single aggregated message
        aggregated_planner_message = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n\n"
            "BATCH FINDINGS SUMMARY:\n"
            + ("\n\n".join(planner_sections) if planner_sections else "No findings classified in this cycle. Continue enumeration.")
            + "\n\n"
            "Review all findings above. Update plan accordingly:\n"
            "- For real vulnerabilities: mark as discovered and continue testing\n"
            "- For false positives: acknowledge and move forward\n"
            "- For inconclusives: add to review queue or continue testing\n"
            "- For recon info: integrate into plan and continue enumeration"
        )

        # Log Phase 3 start
        logger.info(
            "phase3_planner_retest_start",
            real_vulns=len(verify_results_organized["real_vulnerabilities"]),
            retest_candidates=len(retest_candidates),
            false_positives=len(verify_results_organized["false_positives"]),
            inconclusives=len(verify_results_organized["inconclusives"]),
            info_only=len(assessments_organized["info_only"]),
        )
        self._emit_event(
            project_id,
            event="planner_batch_handoff",
            scan_id=scan_id,
            level="info",
            message="Planner [thinking] Aggregating batch findings for replanning.",
            data={
                "stage": "planner",
                "kind": "batch_handoff",
                "real_vulnerabilities_count": len(verify_results_organized["real_vulnerabilities"]),
                "retest_candidates_count": len(retest_candidates),
                "false_positives_count": len(verify_results_organized["false_positives"]),
                "inconclusives_count": len(verify_results_organized["inconclusives"]),
                "info_only_count": len(assessments_organized["info_only"]),
            },
        )

        # Call planner IMMEDIATELY (while Retest runs in background)
        # Wrapped in try/except to ensure loop continues even if planner fails
        planner_loop_result = None
        try:
            logger.info("planner_calling", phase="3_aggregation")
            planner_loop_result = await loop_planner.run(
                aggregated_planner_message,
                is_loop=True,
                intel_checklist=intel_checklist,
                plan_mode="loop",
            )
        except Exception as planner_exc:
            self._emit_event(
                project_id,
                event="planner_error",
                scan_id=scan_id,
                level="warn",
                message=f"Planner error (continuing): {str(planner_exc)[:200]}",
                data={"error": str(planner_exc)},
            )
            # Create minimal planner result to continue loop
            planner_loop_result = type('obj', (object,), {
                'summary': 'Planner encountered error; continuing with next cycle',
                'plan': {}
            })()

        # Capture updated plan immediately after planner runs
        from server.agents.planner.tools.pentest_plan import _current_plan as current
        plan_data = dict(current) if isinstance(current, dict) else plan_data
        plan_data = _sanitize_plan_remove_forbidden_agents(plan_data)

        # Log single planner update
        logger.info(
            "planner_batch_findings_processed",
            real_vulns_count=len(verify_results_organized["real_vulnerabilities"]),
            false_positives_count=len(verify_results_organized["false_positives"]),
            inconclusives_count=len(verify_results_organized["inconclusives"]),
            info_only_count=len(assessments_organized["info_only"]),
            planner_summary=str(planner_loop_result.summary or "")[:100],
        )

        # Emit single plan update event for UI
        self._emit_event(
            project_id,
            event="plan_updated_by_planner",
            scan_id=scan_id,
            level="success",
            message=f"Planner processed batch: {len(verify_results_organized['real_vulnerabilities'])} real, "
                    f"{len(verify_results_organized['false_positives'])} false pos, "
                    f"{len(verify_results_organized['inconclusives'])} inconc, "
                    f"{len(assessments_organized['info_only'])} info",
            data={
                "stage": "planner",
                "kind": "batch_findings_processed",
                "real_vulnerabilities_count": len(verify_results_organized["real_vulnerabilities"]),
                "false_positives_count": len(verify_results_organized["false_positives"]),
                "inconclusives_count": len(verify_results_organized["inconclusives"]),
                "info_only_count": len(assessments_organized["info_only"]),
                "summary": str(planner_loop_result.summary or "").strip(),
                "plan_data": plan_data,
            },
        )

        # ============================================================================
        # PHASE 3C: Retest continues in background (already running)
        # ============================================================================
        # Retest tasks are already executing while Planner updates plan
        # No need to wait for them here - they save to database independently

        # Add real vulnerabilities to log
        for item in verify_results_organized["real_vulnerabilities"]:
            planner_loop_rows.append({
                "iteration": item["idx"],
                "route": (
                    "verify->planner+retest(batch)"
                    if item in retest_candidates
                    else "verify->planner(real_vulnerability,batch)"
                ),
                "verdict": "real_vulnerability",
                "confidence": item.get("verify_confidence"),
                "planner_summary": str(planner_loop_result.summary or "").strip(),
                "compact_bridge": item["compact_summary"],
            })

        # Add false positives to log
        for item in verify_results_organized["false_positives"]:
            planner_loop_rows.append({
                "iteration": item["idx"],
                "route": "verify->planner(false_positive,batch)",
                "verdict": "false_positive",
                "false_positive_reason": item["verify_summary"],
                "planner_summary": str(planner_loop_result.summary or "").strip(),
                "compact_bridge": item["compact_summary"],
            })

        # Add inconclusives to log
        for item in verify_results_organized["inconclusives"]:
            planner_loop_rows.append({
                "iteration": item["idx"],
                "route": "verify->planner(inconclusive,batch)",
                "verdict": "inconclusive",
                "planner_summary": str(planner_loop_result.summary or "").strip(),
                "compact_bridge": item["compact_summary"],
            })

        # Add info-only findings to log
        for item in assessments_organized["info_only"]:
            planner_loop_rows.append({
                "iteration": item["idx"],
                "route": "perceptor->planner(info_only,batch)",
                "summary": str(planner_loop_result.summary or "").strip(),
                "compact_bridge": item["compact_summary"],
            })

        # Capture updated plan from planner (scenarios may have been modified/added)
        from server.agents.planner.tools.pentest_plan import _current_plan
        updated_plan = dict(_current_plan) if isinstance(_current_plan, dict) else plan_data
        updated_plan = _sanitize_plan_remove_forbidden_agents(updated_plan)

        # CRITICAL FIX: Check if Planner indicated completion during batch processing
        # If any planner result says "done" or "complete", return False to stop looping
        should_stop = False
        for row in planner_loop_rows:
            summary = str(row.get("planner_summary") or row.get("summary", "")).strip().lower()
            if summary.startswith("pentest complete") or summary == "complete":
                should_stop = True
                logger.info("planner_batch_stop_signal", reason="planner_said_done", summary=summary)
                break

        # Continue to next cycle, or stop if Planner indicated completion
        # Safety: Always return True by default (continue loop) unless Planner explicitly says stop
        logger.info(
            "execution_cycle_complete",
            cycle_should_stop=should_stop,
            planner_summary=str(planner_loop_result.summary if planner_loop_result else "")[:100],
        )
        try:
            return not should_stop, updated_plan
        except Exception as return_exc:
            logger.error("execution_cycle_return_error", error=str(return_exc))
            # Safety fallback: Continue loop on any error
            return True, plan_data

    async def _check_planner_completion(
        self,
        *,
        project_id: str,
        scan_id: str,
        loop_planner: Any,
        plan_data: dict[str, Any],
        target: str,
        target_type: str,
        scope: str,
        info: str,
        intel_checklist: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Ask planner if pentest is complete."""
        completion_message = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n\n"
            "No more pending scenarios. Review plan:\n"
            "- If any critical P1-P2 items remain untested, return updated plan with new scenarios\n"
            "- If all critical items tested, return summary: 'Pentest complete.'"
        )

        _sync_plan_data_into_planner_state(plan_data)

        plan_result = await loop_planner.run(
            completion_message,
            is_loop=True,
            intel_checklist=intel_checklist,
            plan_mode="loop",
        )

        from server.agents.planner.tools.pentest_plan import _current_plan as current

        updated_plan = dict(current) if isinstance(current, dict) else plan_data
        updated_plan = _sanitize_plan_remove_forbidden_agents(updated_plan)
        summary = str(plan_result.summary or "").strip()
        normalized_summary = re.sub(r"\s+", " ", summary.lower()).strip()
        is_done = normalized_summary.startswith("pentest complete") or normalized_summary == "complete"

        if not is_done:
            self._emit_event(
                project_id,
                event="plan_updated_by_planner",
                scan_id=scan_id,
                level="info",
                message="Planner refreshed plan after empty-scenario completion check.",
                data={
                    "stage": "planner",
                    "kind": "plan_updated_after_completion_check",
                    "summary": summary,
                    "plan_data": updated_plan,
                },
            )

        return not is_done, updated_plan

    async def _run_scan(
        self,
        *,
        project_id: str,
        scan_id: str,
        target: str,
        target_type: str,
        started_at: str,
        info: str,
    ) -> None:
        logger.info(
            "scan_orchestrator_start",
            project_id=project_id,
            scan_id=scan_id,
            target_type=target_type,
            target=target,
        )
        self._emit_event(
            project_id,
            event="intel_started",
            scan_id=scan_id,
            level="info",
            message=f"Intel [start] agent started for target type '{target_type}'.",
            data={"stage": "intel", "status": "running", "kind": "start"},
        )

        scope_text = ""
        for raw_line in info.splitlines():
            if raw_line.lower().startswith("scope:"):
                scope_text = raw_line.split(":", 1)[1].strip()
                break

        warmup_summaries: list[dict[str, Any]] = []
        warmup_plan_data: dict[str, Any] = {}
        static_recon_plan: dict[str, Any] = _resolve_static_recon_plan(
            self._projects_store,
            target_type,
        )
        custom_checklist_text = ""
        print_steps = _is_truthy_env("INTEL_PRINT_STEPS", "1")
        intel_stats: dict[str, Any] = {}

        try:
            project = self._projects_store.get_project(project_id) or {}
            custom_checklist_text = (
                str(project.get("customChecklistText", "")).strip()
                if isinstance(project, dict)
                else ""
            )
            if isinstance(project, dict):
                project["plannerStaticPlan"] = static_recon_plan
                self._projects_store.upsert_project(project)

            # Lazy import avoids loading heavy agent modules at app boot.
            from server.agents.intel.agent import IntelAgent
            from server.agents.planner.agent import PlannerAgent
            from server.agents.planner.tools.pentest_plan import _current_plan

            callback = PrintCallback(
                enabled=print_steps,
                on_log=lambda level, message: self._emit_intel_callback_event(
                    project_id=project_id,
                    scan_id=scan_id,
                    level=level,
                    raw_message=message,
                ),
            )
            intel_agent = IntelAgent(callback=callback, project_id=project_id)

            self._emit_event(
                project_id,
                event="intel_update_started",
                scan_id=scan_id,
                level="info",
                message="Intel [start] refreshing RAG state before warmup reconnaissance.",
                data={"stage": "intel", "kind": "update_only_start"},
            )
            intel_update_result = await intel_agent.run(
                target_type=target_type,
                info=info,
                update_only=True,
            )
            intel_stats = intel_update_result.stats if isinstance(intel_update_result.stats, dict) else {}
            self._emit_event(
                project_id,
                event="intel_update_complete",
                scan_id=scan_id,
                level="success",
                message="Intel [completed] RAG refresh/update pass completed.",
                data={
                    "stage": "intel",
                    "kind": "update_only_complete",
                    "stats": intel_stats,
                },
            )

            planner_callback = PrintCallback(
                enabled=print_steps,
                on_log=lambda level, message: self._emit_planner_callback_event(
                    project_id=project_id,
                    scan_id=scan_id,
                    level=level,
                    raw_message=message,
                ),
            )
            warmup_planner_input = _build_warmup_planner_message(
                target=target,
                target_type=target_type,
                scope=scope_text,
                info=info,
                static_recon_plan=static_recon_plan,
            )
            self._emit_event(
                project_id,
                event="warmup_planner_started",
                scan_id=scan_id,
                level="info",
                message="Planner [start] building warmup recon-only plan.",
                data={"stage": "warmup", "kind": "planner_start"},
            )
            async with PlannerAgent(
                callback=planner_callback,
                project_id=project_id,
                projects_store=self._projects_store,
                vector_store=self._vector_store,
            ) as warmup_planner:
                await warmup_planner.run(
                    warmup_planner_input,
                    is_loop=False,
                    intel_checklist={},
                    plan_mode="warmup",
                )
                warmup_seed_plan = dict(_current_plan) if isinstance(_current_plan, dict) else {}
            warmup_plan_data = _build_warmup_recon_plan(
                target=target,
                scope=scope_text,
                target_type=target_type,
                seed_scenarios=_select_recon_only_scenarios(
                    warmup_seed_plan,
                    limit=WARMUP_RECON_SCENARIO_COUNT,
                ),
            )
            self._emit_event(
                project_id,
                event="warmup_plan_ready",
                scan_id=scan_id,
                level="success",
                message="Planner [completed] warmup recon plan normalized to 8 prioritized scenarios.",
                data={
                    "stage": "warmup",
                    "kind": "planner_completed",
                    "scenario_count": len(
                        _select_recon_only_scenarios(
                            warmup_plan_data,
                            limit=WARMUP_RECON_SCENARIO_COUNT,
                        )
                    ),
                    "plan_data": warmup_plan_data,
                },
            )

            self._persist_project_status(
                project_id,
                status="running",
                scan_progress=30,
                scan_meta={
                    "scanId": scan_id,
                    "status": "running",
                    "startedAt": started_at,
                    "finishedAt": None,
                    "error": "",
                    "awaitingPlannerApproval": False,
                    "result": {
                        "target": target,
                        "targetType": target_type,
                        "intel": {
                            "status": "complete",
                            "summary": "Update-only Intel pass complete.",
                            "stats": intel_stats,
                            "checklist": {},
                        },
                        "plannerStaticPlan": static_recon_plan,
                        "warmup": {
                            "status": "running",
                            "plan": warmup_plan_data,
                            "summaries": [],
                        },
                    },
                },
            )

            executer_callback = ExecuterScanCallback(
                service=self,
                project_id=project_id,
                scan_id=scan_id,
                enabled=print_steps,
            )
            warmup_plan_data, warmup_summaries = await self._run_warmup_recon_cycles(
                project_id=project_id,
                scan_id=scan_id,
                plan_data=warmup_plan_data,
                target=target,
                target_type=target_type,
                scope=scope_text,
                info=info,
                callback=executer_callback,
                cycle_offset=0,
            )

            self._persist_project_status(
                project_id,
                status="running",
                scan_progress=45,
                scan_meta={
                    "scanId": scan_id,
                    "status": "running",
                    "startedAt": started_at,
                    "finishedAt": None,
                    "error": "",
                    "awaitingPlannerApproval": False,
                    "result": {
                        "target": target,
                        "targetType": target_type,
                        "intel": {
                            "status": "complete",
                            "summary": "Update-only Intel pass complete.",
                            "stats": intel_stats,
                            "checklist": {},
                        },
                        "plannerStaticPlan": static_recon_plan,
                        "warmup": {
                            "status": "completed",
                            "plan": warmup_plan_data,
                            "summaries": warmup_summaries,
                        },
                    },
                },
            )

            synthesis_info = _build_post_warmup_intel_info(
                info=info,
                warmup_summaries=warmup_summaries,
                recon_plan_data=warmup_plan_data,
            )
            self._emit_event(
                project_id,
                event="intel_synthesis_started",
                scan_id=scan_id,
                level="info",
                message="Intel [start] synthesizing prioritized checklist from warmup recon, current recon plan, perceptor cache, resources, and user checklist.",
                data={
                    "stage": "intel",
                    "kind": "synthesis_start",
                    "warmup_summary_count": len(warmup_summaries),
                },
            )
            intel_result = await intel_agent.run(
                target_type=target_type,
                info=synthesis_info,
                custom_checklist_text=custom_checklist_text,
                merge_custom_checklist=True,
                max_checklist_items=MAX_SYNTH_INTEL_CHECKLIST_ITEMS,
                skip_rag_check=True,
            )
            info = synthesis_info
        except asyncio.CancelledError:
            current = self._runs.get(project_id, {})
            if str(current.get("status")) in {"paused", "idle"}:
                logger.info("scan_orchestrator_cancelled", project_id=project_id, scan_id=scan_id)
                return
            self._mark_failed(project_id, scan_id, "scan cancelled")
            return
        except Exception as exc:
            self._emit_event(
                project_id,
                event="intel_crashed",
                scan_id=scan_id,
                level="error",
                message=f"Intel/Warmup [crashed] {exc}",
                data={
                    "stage": "intel",
                    "kind": "crashed",
                    "error": str(exc),
                },
            )
            self._mark_failed(project_id, scan_id, f"intel warmup runtime error: {exc}")
            return

        intel_summary = intel_result.summary
        intel_status = intel_result.status
        if isinstance(intel_result.stats, dict) and intel_result.stats:
            intel_stats = intel_result.stats
        intel_checklist = intel_result.checklist if isinstance(intel_result.checklist, dict) else {}
        checklist_items_count = _count_checklist_items(intel_checklist)
        self._emit_event(
            project_id,
            event="intel_complete",
            scan_id=scan_id,
            level="success",
            message="Intel [completed] synthesized checklist ready after warmup reconnaissance.",
            data={
                "stage": "intel",
                "kind": "completed",
                "intel_status": intel_status,
                "summary_length": len(intel_summary),
                "summary": intel_summary,
                "checklist": intel_checklist,
                "checklist_items_count": checklist_items_count,
                "warmup_summary_count": len(warmup_summaries),
            },
        )

        partial_intel_scan_meta = {
            "scanId": scan_id,
            "status": "awaiting_planner_approval",
            "startedAt": started_at,
            "finishedAt": None,
            "error": "",
            "awaitingPlannerApproval": True,
            "result": {
                "target": target,
                "targetType": target_type,
                "intel": {
                    "status": intel_status,
                    "summary": intel_summary,
                    "stats": intel_stats,
                    "checklist": intel_checklist,
                },
                "plannerStaticPlan": static_recon_plan,
                "warmup": {
                    "status": "completed",
                    "plan": warmup_plan_data,
                    "summaries": warmup_summaries,
                },
            },
        }
        self._persist_project_status(
            project_id,
            status="running",
            scan_progress=60,
            scan_meta=partial_intel_scan_meta,
        )

        run_state = self._runs.get(project_id)
        if isinstance(run_state, dict):
            run_state["awaiting_planner_approval"] = True
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_id] = run_state

        gate = asyncio.Event()
        self._planner_approval_events[project_id] = gate
        self._emit_event(
            project_id,
            event="planner_waiting_approval",
            scan_id=scan_id,
            level="warn",
            message=(
                "Planner [waiting approval] Intel checklist is ready. "
                "Review/edit checklist, then click Continue to Planner."
            ),
            data={
                "stage": "planner",
                "kind": "waiting_approval",
                "status": "running",
                "awaiting_user_approval": True,
                "checklist_items_count": checklist_items_count,
                "warmup_summary_count": len(warmup_summaries),
            },
        )
        logger.info(
            "scan_orchestrator_waiting_planner_approval",
            project_id=project_id,
            scan_id=scan_id,
            checklist_items_count=checklist_items_count,
        )

        try:
            await gate.wait()
        except asyncio.CancelledError:
            current = self._runs.get(project_id, {})
            if str(current.get("status")) in {"paused", "idle"}:
                logger.info("scan_orchestrator_cancelled", project_id=project_id, scan_id=scan_id)
                return
            self._mark_failed(project_id, scan_id, "scan cancelled")
            return
        finally:
            self._planner_approval_events.pop(project_id, None)

        run_state = self._runs.get(project_id)
        if isinstance(run_state, dict):
            run_state["awaiting_planner_approval"] = False
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_id] = run_state

        latest_project = self._projects_store.get_project(project_id)
        if isinstance(latest_project, dict):
            latest_last_scan = latest_project.get("lastScan")
            if isinstance(latest_last_scan, dict):
                latest_result = latest_last_scan.get("result")
                if isinstance(latest_result, dict):
                    latest_intel = latest_result.get("intel")
                    if isinstance(latest_intel, dict):
                        latest_checklist = latest_intel.get("checklist")
                        if isinstance(latest_checklist, dict):
                            intel_checklist = latest_checklist
                            checklist_items_count = _count_checklist_items(intel_checklist)

        self._persist_project_status(
            project_id,
            status="running",
            scan_progress=70,
            scan_meta={
                "scanId": scan_id,
                "status": "running",
                "startedAt": started_at,
                "finishedAt": None,
                "error": "",
                "awaitingPlannerApproval": False,
                "result": {
                    "target": target,
                    "targetType": target_type,
                    "intel": {
                        "status": intel_status,
                        "summary": intel_summary,
                        "stats": intel_stats,
                        "checklist": intel_checklist,
                    },
                    "plannerStaticPlan": static_recon_plan,
                    "warmup": {
                        "status": "completed",
                        "plan": warmup_plan_data,
                        "summaries": warmup_summaries,
                    },
                },
            },
        )

        planner_input = _build_planner_kickoff_message(
            target=target,
            target_type=target_type,
            scope=scope_text,
            info=info,
            intel_status=intel_status,
            intel_vulnerabilities=list(intel_result.vulnerabilities),
            intel_stats=intel_stats,
            intel_checklist=intel_checklist,
            checklist_overview={
                "target_type": str(intel_checklist.get("target_type", "") or target_type),
                "available_total": int(intel_checklist.get("available_total", 0) or 0),
                "items_count": checklist_items_count,
            },
            static_recon_plan=static_recon_plan,
            warmup_summaries=warmup_summaries,
        )
        self._emit_event(
            project_id,
            event="planner_started",
            scan_id=scan_id,
            level="info",
            message="Planner [start] agent started to build pentest plan.",
            data={"stage": "planner", "status": "running", "kind": "start"},
        )

        try:
            from server.agents.planner.agent import PlannerAgent

            planner_callback = PrintCallback(
                enabled=print_steps,
                on_log=lambda level, message: self._emit_planner_callback_event(
                    project_id=project_id,
                    scan_id=scan_id,
                    level=level,
                    raw_message=message,
                ),
            )
            async with PlannerAgent(
                callback=planner_callback,
                project_id=project_id,
                projects_store=self._projects_store,
                vector_store=self._vector_store,
            ) as planner_agent:
                planner_result = await planner_agent.run(
                    planner_input,
                    is_loop=False,
                    intel_checklist=intel_checklist,
                    plan_mode="full",
                )
                # Plan data is maintained in pentest_plan module and retrieved via import
                from server.agents.planner.tools.pentest_plan import _current_plan
                plan_data = dict(_current_plan) if isinstance(_current_plan, dict) else {}
                # Sanitize plan: remove any forbidden agents (verify, retest, perceptor)
                plan_data = _sanitize_plan_remove_forbidden_agents(plan_data)

                # Log plan structure for debugging (why 0 scenarios?)
                phases = plan_data.get("phases", [])
                scenario_counts = {}
                for phase_idx, phase in enumerate(phases):
                    if isinstance(phase, dict):
                        steps = phase.get("steps", [])
                        if isinstance(steps, list):
                            for step_idx, step in enumerate(steps):
                                if isinstance(step, dict):
                                    scenarios = step.get("scenarios", [])
                                    agent_counts = {}
                                    for scen in scenarios:
                                        if isinstance(scen, dict):
                                            agent = scen.get("agent", "unknown")
                                            agent_counts[agent] = agent_counts.get(agent, 0) + 1
                                    if agent_counts:
                                        key = f"{phase.get('name', 'Phase')}:step{step_idx}"
                                        scenario_counts[key] = agent_counts

                logger.info(
                    "plan_loaded_from_planner",
                    target=plan_data.get("target", ""),
                    phases_count=len(phases),
                    scenario_breakdown=scenario_counts if scenario_counts else "NO SCENARIOS FOUND",
                )
        except asyncio.CancelledError:
            current = self._runs.get(project_id, {})
            if str(current.get("status")) in {"paused", "idle"}:
                logger.info("scan_orchestrator_cancelled", project_id=project_id, scan_id=scan_id)
                return
            self._mark_failed(project_id, scan_id, "scan cancelled")
            return
        except Exception as exc:
            self._emit_event(
                project_id,
                event="planner_crashed",
                scan_id=scan_id,
                level="error",
                message=f"Planner [crashed] {exc}",
                data={
                    "stage": "planner",
                    "kind": "crashed",
                    "error": str(exc),
                },
            )
            self._mark_failed(project_id, scan_id, f"planner runtime error: {exc}")
            return

        planner_summary = str(planner_result.summary or "").strip()
        planner_summary_lower = planner_summary.lower()
        plan_phases = plan_data.get("phases", [])
        plan_phase_count = len(plan_phases) if isinstance(plan_phases, list) else 0
        planner_failed = planner_summary_lower.startswith("planning failed:")
        if planner_failed:
            failure_reason = planner_summary or "planner did not persist a valid plan"
            self._emit_event(
                project_id,
                event="planner_failed",
                scan_id=scan_id,
                level="warn",
                message=f"Planner [failed] {failure_reason}",
                data={
                    "stage": "planner",
                    "kind": "failed",
                    "summary": planner_summary,
                    "plan_phase_count": plan_phase_count,
                },
            )
            self._mark_failed(project_id, scan_id, f"planner failed: {failure_reason}")
            return

        if plan_phase_count <= 0:
            self._emit_event(
                project_id,
                event="planner_incomplete",
                scan_id=scan_id,
                level="warn",
                message=(
                    "Planner [warn] No persisted plan phases; "
                    "continuing with checklist-only summary."
                ),
                data={
                    "stage": "planner",
                    "kind": "incomplete",
                    "summary": planner_summary,
                    "plan_phase_count": 0,
                },
            )

        self._emit_event(
            project_id,
            event="planner_complete",
            scan_id=scan_id,
            level="success",
            message="Planner [completed] agent completed successfully.",
            data={
                "stage": "planner",
                "kind": "completed",
                "summary_length": len(planner_summary),
                "scenario_count": len(planner_result.scenarios),
                "needs_count": len(planner_result.needs),
                "checklist_updates_count": len(
                    planner_result.action_plan.get("checklist_updates", [])
                    if isinstance(planner_result.action_plan, dict)
                    else []
                ),
                "checklist_additions_count": len(
                    planner_result.action_plan.get("checklist_additions", [])
                    if isinstance(planner_result.action_plan, dict)
                    else []
                ),
                "plan_phase_count": plan_phase_count,
                "summary": planner_result.summary,
                "scenarios": planner_result.scenarios,
                "needs": planner_result.needs,
                "action_plan": planner_result.action_plan,
                "plan_data": plan_data,
            },
        )

        execution_rows: list[dict[str, Any]] = []
        perceptor_rows: list[dict[str, Any]] = []
        planner_loop_rows: list[dict[str, Any]] = []
        exec_scope = scope_text
        executer_error: str = ""

        self._emit_event(
            project_id,
            event="executer_started",
            scan_id=scan_id,
            level="info",
            message="Executer [start] starting first prioritized scenario wave.",
            data={"stage": "executer", "kind": "start"},
        )

        try:
            from server.agents.executer.recon.agent import ReconExecuterAgent
            from server.agents.executer.exploit.agent import ExploitExecuterAgent
            from server.agents.executer.verify.agent import VerifyExecuterAgent
            from server.agents.executer.retest.agent import RetestExecuterAgent
            from server.agents.perceptor.agent import PerceptorAgent
            from server.agents.planner.agent import PlannerAgent

            executer_callback = ExecuterScanCallback(
                service=self,
                project_id=project_id,
                scan_id=scan_id,
                enabled=print_steps,
            )

            recon_agent = ReconExecuterAgent(
                callback=executer_callback,
                target_types=[target_type],
                project_id=project_id,
            )
            exploit_agent = ExploitExecuterAgent(
                callback=executer_callback,
                target_types=[target_type],
                project_id=project_id,
            )
            verify_agent = VerifyExecuterAgent(
                callback=executer_callback,
                project_id=project_id,
            )
            retest_agent = RetestExecuterAgent(
                callback=executer_callback,
                project_id=project_id,
            )
            perceptor_agent = PerceptorAgent(project_id=project_id)
            loop_planner_callback = PrintCallback(
                enabled=print_steps,
                on_log=lambda level, message: self._emit_planner_callback_event(
                    project_id=project_id,
                    scan_id=scan_id,
                    level=level,
                    raw_message=message,
                ),
            )
            loop_planner = PlannerAgent(
                callback=loop_planner_callback,
                project_id=project_id,
                projects_store=self._projects_store,
                vector_store=self._vector_store,
            )
            await recon_agent.clear_context_window()
            await exploit_agent.clear_context_window()
            await verify_agent.clear_context_window()
            await retest_agent.clear_context_window()
            await perceptor_agent.clear_context_window()

            try:
                execution_rows: list[dict[str, Any]] = []
                perceptor_rows: list[dict[str, Any]] = []
                planner_loop_rows: list[dict[str, Any]] = []
                exec_scope = scope_text

                self._emit_event(
                    project_id,
                    event="executer_started",
                    scan_id=scan_id,
                    level="info",
                    message="Executer [start] entering cyclic execution loop.",
                    data={"stage": "executer", "kind": "start"},
                )

                # CYCLIC EXECUTION LOOP with explicit state tracking
                cycle_count = 0
                max_cycles = 20  # Safety limit

                while cycle_count < max_cycles:
                    cycle_count += 1
                    display_cycle_count = cycle_count + WARMUP_RECON_CYCLES

                    # FRESH CONTEXT PER CYCLE: Reset context windows for executer agents
                    # (only Planner keeps context across cycles)
                    recon_agent.reset_context_window_for_cycle()
                    exploit_agent.reset_context_window_for_cycle()
                    verify_agent.reset_context_window_for_cycle()
                    retest_agent.reset_context_window_for_cycle()
                    perceptor_agent.reset_context_window_for_cycle()
                    executed_scenarios = _count_done_scenarios(plan_data)

                    self._emit_event(
                        project_id,
                        event="executer_cycle_start",
                        scan_id=scan_id,
                        level="info",
                        message=f"Executer [cycle {display_cycle_count}] starting scenario selection (executed={executed_scenarios}).",
                        data={
                            "stage": "executer",
                            "kind": "cycle_start",
                            "cycle": display_cycle_count,
                            "scenarios_executed_total": executed_scenarios,
                        },
                    )

                    try:
                        should_continue, updated_plan = await self._run_execution_cycle(
                            project_id=project_id,
                            scan_id=scan_id,
                            cycle_number=display_cycle_count,
                            plan_data=plan_data,
                            recon_agent=recon_agent,
                            exploit_agent=exploit_agent,
                            verify_agent=verify_agent,
                            retest_agent=retest_agent,
                            perceptor_agent=perceptor_agent,
                            loop_planner=loop_planner,
                            target=target,
                            target_type=target_type,
                            scope=exec_scope,
                            info=info,
                            intel_checklist=intel_checklist,
                        )
                    except Exception as cycle_exc:
                        # Safety: If execution cycle fails, emit warning and continue loop
                        logger.error(
                            "executer_cycle_exception",
                            cycle=cycle_count,
                            error=str(cycle_exc)[:200],
                        )
                        self._emit_event(
                            project_id,
                            event="executer_cycle_error",
                            scan_id=scan_id,
                            level="warn",
                            message=f"Executer cycle error (continuing): {str(cycle_exc)[:200]}",
                            data={"error": str(cycle_exc)},
                        )
                        should_continue = True  # Always continue on error
                        updated_plan = plan_data

                    plan_data = updated_plan

                    # OPTIMIZATION: Compress Planner context window between cycles (after cycle 1)
                    # to prevent token bloat while keeping critical plan history
                    if cycle_count > 1 and loop_planner._context_window is not None:
                        from server.agents.planner.context_compression import (
                            compress_planner_context_window,
                        )

                        try:
                            await compress_planner_context_window(
                                loop_planner._context_window, cycle_count
                            )
                        except Exception as compression_exc:
                            logger.warning(
                                "planner_context_compression_skipped",
                                cycle=cycle_count,
                                error=str(compression_exc),
                            )

                    self._emit_event(
                        project_id,
                        event="executer_cycle_completed",
                        scan_id=scan_id,
                        level="success",
                        message=(
                            f"---------------------"
                            f"(cycle {display_cycle_count} finish)---------------------"
                        ),
                        data={
                            "stage": "executer",
                            "kind": "cycle_completed",
                            "cycle": display_cycle_count,
                            "warmup": False,
                            "should_continue": bool(should_continue),
                            "scenarios_executed_total": _count_done_scenarios(plan_data),
                            "plan_data": plan_data,
                        },
                    )

                    if not should_continue:
                        self._emit_event(
                            project_id,
                            event="executer_planner_says_done",
                            scan_id=scan_id,
                            level="success",
                            message="Executer [done signal] Planner returned completion.",
                            data={
                                "stage": "executer",
                                "kind": "planner_done",
                                "cycle": cycle_count + WARMUP_RECON_CYCLES,
                            },
                        )
                        break

                self._emit_event(
                    project_id,
                    event="executer_complete",
                    scan_id=scan_id,
                    level="success",
                    message=(
                        f"Executer [completed] finished after "
                        f"{cycle_count + WARMUP_RECON_CYCLES} total cycle(s) "
                        f"including {WARMUP_RECON_CYCLES} warmup cycle(s)."
                    ),
                    data={
                        "stage": "executer",
                        "kind": "completed",
                        "cycle_count": cycle_count + WARMUP_RECON_CYCLES,
                        "warmup_cycle_count": WARMUP_RECON_CYCLES,
                        "main_cycle_count": cycle_count,
                        "execution_count": len(execution_rows),
                        "perceptor_count": len(perceptor_rows),
                        "planner_loop_count": len(planner_loop_rows),
                    },
                )
            finally:
                await recon_agent.close()
                await exploit_agent.close()
                await verify_agent.close()
                await retest_agent.close()
                await perceptor_agent.close()
                await loop_planner.close()
        except Exception as exc:
            executer_error = str(exc)
            self._emit_event(
                project_id,
                event="executer_crashed",
                scan_id=scan_id,
                level="warn",
                message=f"Executer [crashed] {exc}",
                data={
                    "stage": "executer",
                    "kind": "crashed",
                    "error": str(exc),
                },
            )
        if executer_error:
            self._mark_failed(
                project_id,
                scan_id,
                f"executer runtime error: {executer_error}",
            )
            return

        finished_at = _utc_now_iso()

        scan_meta = {
            "scanId": scan_id,
            "status": "completed",
            "startedAt": started_at,
            "finishedAt": finished_at,
            "error": "",
            "result": {
                "target": target,
                "targetType": target_type,
                "intel": {
                    "status": intel_status,
                    "summary": intel_summary,
                    "stats": intel_stats,
                    "checklist": intel_checklist,
                },
                "plannerStaticPlan": static_recon_plan,
                "warmup": {
                    "status": "completed",
                    "plan": warmup_plan_data,
                    "summaries": warmup_summaries,
                },
                "planner": {
                    "summary": str(planner_result.summary),
                    "scenarios": list(planner_result.scenarios),
                    "needs": list(planner_result.needs),
                    "action_plan": (
                        dict(planner_result.action_plan)
                        if isinstance(planner_result.action_plan, dict)
                        else {}
                    ),
                    "plan_data": plan_data,
                },
                "execution": execution_rows,
                "perceptor": perceptor_rows,
                "plannerLoops": planner_loop_rows,
            },
        }

        self._runs[project_id] = {
            "scan_id": scan_id,
            "project_id": project_id,
            "status": "completed",
            "started_at": started_at,
            "updated_at": finished_at,
            "finished_at": finished_at,
            "error": "",
            "awaiting_planner_approval": False,
            "awaiting_tool_approval": False,
            "pending_tool_approval": None,
            "already_running": False,
        }
        self._persist_project_status(
            project_id,
            status="completed",
            scan_progress=100,
            scan_meta=scan_meta,
        )
        self._emit_event(
            project_id,
            event="scan_completed",
            scan_id=scan_id,
            level="success",
            message="Scan completed successfully.",
            data={"status": "completed", "scan_progress": 100},
        )
        logger.info("scan_orchestrator_complete", project_id=project_id, scan_id=scan_id)

    def _mark_failed(
        self,
        project_id: str,
        scan_id: str,
        error_message: str,
        *,
        finished_at: str | None = None,
    ) -> None:
        finish_time = finished_at or _utc_now_iso()
        logger.warning(
            "scan_orchestrator_failed",
            project_id=project_id,
            scan_id=scan_id,
            error=error_message,
        )
        self._runs[project_id] = {
            "scan_id": scan_id,
            "project_id": project_id,
            "status": "error",
            "started_at": self._runs.get(project_id, {}).get("started_at", finish_time),
            "updated_at": finish_time,
            "finished_at": finish_time,
            "error": error_message,
            "awaiting_planner_approval": False,
            "awaiting_tool_approval": False,
            "pending_tool_approval": None,
            "already_running": False,
        }
        self._persist_project_status(
            project_id,
            status="error",
            scan_progress=0,
            scan_meta={
                "scanId": scan_id,
                "status": "error",
                "finishedAt": finish_time,
                "error": error_message,
            },
        )
        self._emit_event(
            project_id,
            event="scan_failed",
            scan_id=scan_id,
            level="warn",
            message=f"Scan failed: {error_message}",
            data={"status": "error", "scan_progress": 0, "error": error_message},
        )

    def _persist_project_status(
        self,
        project_id: str,
        *,
        status: str,
        scan_progress: int,
        scan_meta: dict[str, Any],
    ) -> None:
        project = self._projects_store.get_project(project_id)
        if project is None:
            return

        project["status"] = status
        project["scanProgress"] = scan_progress
        project["updatedAt"] = _utc_now_iso()
        if isinstance(scan_meta, dict):
            result = scan_meta.get("result", {})
            if not isinstance(result, dict):
                result = {}
            context_windows = project.get("contextWindows", {})
            if isinstance(context_windows, dict) and context_windows:
                result["contextWindows"] = dict(context_windows)
            scan_meta["result"] = result
        project["lastScan"] = scan_meta
        self._projects_store.upsert_project(project)
        self._emit_event(
            project_id,
            event="project_status",
            scan_id=str(scan_meta.get("scanId", "")),
            level="warn" if status == "error" else "success" if status == "completed" else "info",
            message=f"Project status updated to {status}.",
            data={
                "status": status,
                "scan_progress": scan_progress,
            },
        )
