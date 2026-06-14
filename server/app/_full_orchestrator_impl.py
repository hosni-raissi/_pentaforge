"""App-level scan orchestrator service.

This service is the API entrypoint for scan execution:
1. Resolve project details from storage
2. Run Intel Agent to produce pentest checklist intelligence
3. Run Planner Agent to build/store the initial pentest plan
4. Persist scan lifecycle/status back to the project record
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import os
import re
import shutil
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import structlog

from server.db.projects import ProjectsStore
from server.db.projects.config import projects_db_config
from server.db.projects.project_rag import index_verified_finding
from server.db.projects.runtime_cache import get_project_runtime_cache
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore
from server.agents.executer.sandbox import delete_project_workspace
from server.agents.executer.payload_filter import get_payloads as _get_filtered_payloads
from server.agents.executer.base import _executer_callback_context
from server.nodes.information_gathering import load_target_info_profile_defaults
from server.nodes.intel import IntelNode
from server.nodes.system_memory import (
    Brain,
    BrainBuilderNode,
    SystemMemoryNode,
    SystemMemoryLLM,
    append_system_memory_updates as _append_system_memory_updates_external,
    build_system_memory_prompt_block as _build_target_memory_prompt_block_external,
    compute_tool_efficiency_snapshot as _compute_tool_efficiency_snapshot,
    initialize_system_memory as _initialize_system_memory,
    load_system_memory as _load_target_memory_external,
    merge_system_memory_artifacts as _merge_target_memory_artifacts_external,
    save_system_memory as _save_target_memory_external,
    store_system_memory_checklist as _store_system_memory_checklist_external,
    system_memory_dir as _system_memory_dir_external,
    system_memory_paths as _system_memory_paths_external,
)
from server.nodes.architect.agent import ArchitectAgent
from server.tools.session.session_manager import SessionContext, SessionManager
from server.utils.target_scope import normalize_target_scope

logger = structlog.get_logger(__name__)

_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web": "web_app",
    "web3": "web_app",
    "infrastructure": "infra",
    "infra": "infra",
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
PROJECT_FINDINGS_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
WARMUP_PERCEPTOR_CACHE_TTL_SECONDS = 2 * 60 * 60
ANALYZER_AGENT_REPORT_HISTORY_LIMIT = 12
ANALYZER_AGENT_REPORT_MAX_RESULT_CHARS = 12000
ANALYZER_AGENT_REPORT_MAX_MARKDOWN_CHARS = 60000
FINDINGS_HISTORY_KEY = "findings_history"
LEGACY_FINDINGS_HISTORY_KEY = "analyzer_agent_reports"
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


def _unique_strings(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        unique.append(text)
    return unique


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
    tasks = [str(item).strip() for item in (scenario_tasks or []) if str(item).strip()]
    guidance_lines = [
        "Target execution guidance: standard target. Use scenario-appropriate tools and avoid unnecessary duplicates.",
    ]
    if tasks:
        guidance_lines.append(f"Current assigned scenarios: {', '.join(tasks)}")
    return "\n".join(guidance_lines)


def _build_warmup_scenario_tool_guidance(task: str) -> str:
    task_name = str(task or "").strip().lower()
    if not task_name:
        return ""

    guidance_map: list[tuple[str, str]] = [
        (
            "local web app perimeter mapping",
            "Preferred tools: http_probe, web_crawler, directory_file_fuzzing, api_endpoint_discovery. Avoid repeating broad discovery once core routes are confirmed.",
        ),
        (
            "defensive & tech fingerprinting",
            "Preferred tools: detect_tech, http_header_analysis, waf_detection. Avoid spending extra rounds on generic crawling unless it adds direct fingerprint evidence.",
        ),
        (
            "structural content discovery",
            "Preferred tools: web_crawler, directory_file_fuzzing, js_source_code_analyzer. Focus on hidden paths, metadata, and client-side route clues.",
        ),
        (
            "api & endpoint extraction",
            "Preferred tools: api_passive_enum, api_endpoint_discovery, js_source_code_analyzer, websocket_recon. Avoid generic header checks unless they reveal API-specific behavior.",
        ),
        (
            "input & parameter profiling",
            "Preferred tools: web_crawler, js_source_code_analyzer, api_endpoint_discovery, then param_discovery only once against confirmed dynamic endpoints. Avoid repeating param_discovery or session_token_analysis when no forms, params, or cookies were found.",
        ),
        (
            "identity & access analysis",
            "Preferred tools: web_crawler on auth routes, http_header_analysis, session_token_analysis on real cookie-bearing responses, js_source_code_analyzer for auth flows. Avoid repeating session_token_analysis if no cookies or login/session artifacts exist; summarize the negative result instead.",
        ),
        (
            "data handling & trust review",
            "Preferred tools: cors_misconfig_check, http_header_analysis, api_response_analyzer, directory_file_fuzzing on upload or file-processing routes. Avoid restarting perimeter discovery.",
        ),
        (
            "operational synthesis",
            "Preferred approach: synthesize prior evidence first. At most one small validation call on an already discovered endpoint if needed. Do not restart broad crawling, fuzzing, or fingerprinting from scratch.",
        ),
    ]

    for marker, guidance in guidance_map:
        if marker in task_name:
            return guidance
    return ""


def _build_target_type_followup_hypotheses(
    *,
    target_type: str,
    warmup_summaries: list[dict[str, Any]],
    intel_vulnerabilities: list[str],
) -> list[str]:
    evidence_parts: list[str] = []
    for item in warmup_summaries:
        if not isinstance(item, dict):
            continue
        evidence_parts.append(str(item.get("task", "")).strip())
        evidence_parts.append(str(item.get("compact_summary", "")).strip())
    evidence_parts.extend(str(item).strip() for item in intel_vulnerabilities if str(item).strip())
    evidence_text = " ".join(part for part in evidence_parts if part).lower()

    def has_any(*markers: str) -> bool:
        return any(marker in evidence_text for marker in markers)

    grouped_rules: dict[str, list[tuple[tuple[str, ...], str]]] = {
        "web": [
            (
                ("cors", "access-control-allow-origin", "origin", "websocket", "socket.io"),
                "Trust-boundary misuse is plausible: convert discovered cross-origin or WebSocket clues into focused CORS/CSWSH validation against already observed routes or sockets.",
            ),
            (
                ("protected", "admin", "debug", "swagger", "openapi", "api-docs", "graphql", "endpoint"),
                "Access-control weaknesses are plausible: promote authorization, IDOR, or BOLA testing for already discovered protected, admin, debug, or documented API surfaces.",
            ),
            (
                ("upload", "file processing", "file-processing", "multipart", "attachment", "import"),
                "File-handling abuse is plausible: schedule upload or file-processing testing only where the warmup evidence already exposed concrete file-related routes or handlers.",
            ),
            (
                ("500", "error", "stack trace", "exception", "verbose"),
                "Error-handling weaknesses are plausible: validate stack traces, debug leakage, and unsafe error paths around the exact endpoints that already returned verbose failures.",
            ),
            (
                ("login", "auth", "session", "token", "cookie", "jwt"),
                "Authentication or session abuse is plausible: follow up with targeted session, token, and auth-flow testing on concrete login or protected flows already seen in recon.",
            ),
            (
                ("form", "parameter", "query", "input", "search", "filter"),
                "Injection or input-validation issues are plausible: promote focused injection testing only on confirmed forms, parameters, or dynamic endpoints already found in warmup.",
            ),
        ],
        "service": [
            (
                ("tls", "ssl", "certificate", "cipher"),
                "Transport or crypto weaknesses are plausible: convert the observed TLS/certificate evidence into targeted protocol and configuration validation.",
            ),
            (
                ("admin", "management", "dashboard", "console", "debug"),
                "Administrative exposure is plausible: promote access-control and hardening checks against already observed management surfaces.",
            ),
            (
                ("auth", "login", "session", "token", "credential"),
                "Authentication weaknesses are plausible: follow up on concrete auth surfaces with credential, session, or privilege-abuse scenarios.",
            ),
        ],
        "repo": [
            (
                ("secret", "token", "key", "credential", "env", ".npmrc", ".pypirc"),
                "Secret exposure is plausible: promote targeted verification of discovered credentials, tokens, or configuration material before broad new exploration.",
            ),
            (
                ("workflow", "action", "ci", "pipeline", "hook"),
                "Pipeline abuse is plausible: convert discovered CI/CD or automation clues into workflow, token-scope, or trigger-abuse scenarios.",
            ),
            (
                ("dependency", "package", "manifest", "lockfile"),
                "Supply-chain risk is plausible: schedule dependency-trust, package-source, or unsafe build-chain follow-up where manifests or lockfiles were already exposed.",
            ),
        ],
        "runtime": [
            (
                ("service", "port", "exposed", "open", "listener"),
                "Service exposure is plausible: convert confirmed exposed services into version-specific hardening, auth, and privilege-boundary testing.",
            ),
            (
                ("config", "metadata", "iam", "role", "policy", "secret"),
                "Configuration abuse is plausible: prioritize privilege, policy, and secret-handling validation around the exact artifacts already uncovered.",
            ),
            (
                ("container", "image", "registry", "docker", "kubernetes", "pod"),
                "Runtime isolation weaknesses are plausible: promote image, registry, or container-boundary testing only where those artifacts were actually observed.",
            ),
        ],
    }

    target_group_map = {
        "web_app": "web",
        "api": "web",
        "mobile": "web",
        "linux_server": "service",
        "network": "service",
        "iot": "service",
        "infra": "runtime",
        "cloud": "runtime",
        "container": "runtime",
        "repository": "repo",
    }
    group = target_group_map.get(str(target_type or "").strip().lower(), "web")
    hypotheses = [
        hypothesis
        for markers, hypothesis in grouped_rules.get(group, [])
        if has_any(*markers)
    ]
    if has_any("cors", "access-control-allow-origin", "wildcard cors") and has_any("login", "auth", "cookie", "session", "jwt", "protected"):
        hypotheses.append(
            "Chain recognition applies: validate cross-origin data exposure or CSRF-adjacent impact only against authenticated or sensitive endpoints already observed in evidence."
        )
    if has_any("xss", "cross-site scripting") and has_any("httponly missing", "without httponly", "cookie", "session token"):
        hypotheses.append(
            "Chain recognition applies: if XSS is confirmed and cookies lack HttpOnly, validate session theft or account-hijack impact on the concrete affected route."
        )
    if has_any("path traversal", "directory traversal", "/etc/passwd", ".env", "sensitive file"):
        hypotheses.append(
            "Chain recognition applies: escalate the confirmed traversal path to concrete sensitive-file reads such as app config, `.env`, or `/etc/passwd` only where the file path is already evidenced."
        )
    if has_any("sqli", "sql injection") and has_any("mysql", "postgres", "mssql", "oracle", "mongodb"):
        hypotheses.append(
            "Chain recognition applies: use the observed database fingerprint to schedule DB-specific extraction or RCE validation rather than generic SQLi retests."
        )
    if has_any("open redirect", "redirect_uri", "redirect url") and has_any("oauth", "oidc", "authorize", "callback"):
        hypotheses.append(
            "Chain recognition applies: validate OAuth or token-theft impact through the observed open redirect and authorization flow rather than treating it as a standalone low-signal issue."
        )
    if has_any("2fa", "mfa", "otp") and has_any("no rate limit", "missing rate limit", "rate limiting absent"):
        hypotheses.append(
            "Chain recognition applies: prioritize bounded 2FA brute-force validation only on the observed 2FA flow when rate limiting evidence is absent."
        )
    if has_any("form", "parameter", "query", "api", "graphql", "search", "filter"):
        hypotheses.append(
            "Hidden parameter discovery is high-value here: schedule `param_discovery` once against the confirmed dynamic endpoints instead of repeating broad crawls."
        )
    if not hypotheses and evidence_text:
        hypotheses.append(
            "Use the strongest concrete warmup evidence to create one deeper follow-up scenario that validates the observed weakness before restarting broad discovery."
        )
    return hypotheses[:8]


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

    if tool_name == "run_python":
        code = str(args.get("code", "")).strip()
        if code:
            # Show the first few lines or a snippet
            snippet = _compact_preview(code, 180).replace("\n", " ")
            return f"python: {snippet}"
        return "run_python"

    if tool_name == "search_web":
        query = str(args.get("query", "")).strip()
        if query:
            return f"search_web: {query}"
        return "search_web"

    if tool_name == "fetch_url_content" or tool_name == "get_page":
        url = str(args.get("Url", args.get("url", ""))).strip()
        if url:
            return f"fetch: {url}"
        return "fetch_url_content"

    if tool_name:
        compact_args = []
        for key, value in (args or {}).items():
            if value in ("", None, [], {}):
                continue
            # Skip code/payload fields if we already handled them or they are too large
            if key in {"code", "args", "payload"}:
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


def _stringify_markdown_value(value: Any, *, max_chars: int | None = None) -> str:
    if isinstance(value, str):
        text = value.strip()
    else:
        try:
            text = json.dumps(value, ensure_ascii=True, indent=2)
        except TypeError:
            text = str(value)
        text = text.strip()
    text = text.replace("```", "'''")
    if max_chars and max_chars > 0 and len(text) > max_chars:
        return text[:max_chars] + "\n...[truncated]"
    return text


def _build_analyzer_agent_report_markdown(
    *,
    scan_id: str,
    entry_id: str,
    generated_at: str,
    scenario: dict[str, Any],
    row_result: dict[str, Any],
    assessment: dict[str, Any],
    compact_summary: str,
    verdict: str,
    detail_summary: str,
    verify_data: dict[str, Any] | None = None,
) -> str:
    safe_scenario = scenario if isinstance(scenario, dict) else {}
    safe_row_result = row_result if isinstance(row_result, dict) else {}
    safe_assessment = assessment if isinstance(assessment, dict) else {}
    safe_verify = verify_data if isinstance(verify_data, dict) else {}

    agent_role = str(safe_scenario.get("agent", "")).strip().lower() or "unknown"
    overall = safe_assessment.get("overall", {}) if isinstance(safe_assessment.get("overall"), dict) else {}
    confidence = safe_verify.get("confidence", overall.get("confidence"))
    normalized_summary = str(safe_assessment.get("normalized_summary", "")).strip()
    reasoning = str(safe_verify.get("reasoning", "")).strip()
    base_markdown = str(safe_assessment.get("agent_markdown", "")).strip()
    if not base_markdown:
        scenario_task = str(safe_scenario.get("task", "")).strip() or "Untitled scenario"
        tool_names = _extract_tool_names(safe_row_result.get("tool_results", []))
        row_summary = str(safe_row_result.get("summary", "")).strip()
        base_lines = [
            f"# {agent_role.upper()} Analyzer Report",
            "",
            "## Scenario Run",
            "",
            f"- Scenario Ran: {scenario_task}",
            f"- Tools Run: {', '.join(f'`{tool}`' for tool in tool_names) or 'No tools recorded'}",
        ]
        if row_summary:
            base_lines.append(f"- Execution Summary: {row_summary}")
        if normalized_summary:
            base_lines.extend(["", "## What The Tools Found", ""])
            for summary_line in normalized_summary.splitlines()[:8]:
                clean_line = str(summary_line).strip()
                if clean_line:
                    base_lines.append(f"- {clean_line}")
        base_markdown = "\n".join(base_lines).strip()

    lines = [
        base_markdown,
        "",
        "## Analyzer Decision",
        "",
        f"- Scan ID: `{scan_id}`",
        f"- Entry ID: `{entry_id}`",
        f"- Generated At: `{generated_at}`",
        f"- Verdict: `{verdict}`",
        f"- Finding Type: `{str(safe_assessment.get('finding_type', 'info')).strip() or 'info'}`",
        f"- Confidence: `{confidence}`" if confidence not in ("", None) else "- Confidence: `unknown`",
        f"- SSVC: `{str(overall.get('ssvc', '')).strip() or 'TRACK'}`",
        f"- Deep Description: {detail_summary or compact_summary or 'No analyzer summary available.'}",
    ]
    if reasoning:
        lines.extend(["", "### Reasoning", "", reasoning])

    markdown = "\n".join(lines).strip()
    if len(markdown) > ANALYZER_AGENT_REPORT_MAX_MARKDOWN_CHARS:
        return markdown[:ANALYZER_AGENT_REPORT_MAX_MARKDOWN_CHARS] + "\n\n...[truncated]"
    return markdown


def _build_info_gathering_report_entry(
    *,
    scan_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    def _extra_findings_from_structured(rows: list[dict[str, Any]]) -> list[str]:
        derived: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            structured = row.get("structured", {})
            if not isinstance(structured, dict):
                continue
            tool_name = str(structured.get("tool", "")).strip().lower()
            if tool_name == "passive_web_recon":
                domain = str(structured.get("normalized_domain", "")).strip()
                subdomains = [
                    str(value).strip()
                    for value in structured.get("subdomains", [])
                    if str(value).strip()
                ] if isinstance(structured.get("subdomains"), list) else []
                urls = [
                    str(value).strip()
                    for value in structured.get("historical_urls", [])
                    if str(value).strip()
                ] if isinstance(structured.get("historical_urls"), list) else []
                if domain:
                    derived.append(f"Domain: {domain}")
                if subdomains:
                    rendered = ", ".join(subdomains[:5])
                    suffix = " ..." if len(subdomains) > 5 else ""
                    derived.append(f"Observed subdomains: {rendered}{suffix}")
                if urls:
                    rendered = ", ".join(urls[:5])
                    suffix = " ..." if len(urls) > 5 else ""
                    derived.append(f"Historical URLs: {rendered}{suffix}")
        return _unique_strings(derived)

    safe_payload = payload if isinstance(payload, dict) else {}
    block_index = int(safe_payload.get("index", 0) or 0)
    total_blocks = int(safe_payload.get("total", 0) or 0)
    block_name = str(safe_payload.get("name", "")).strip() or "Unnamed Gathering Block"
    block_goal = str(safe_payload.get("goal", "")).strip()
    block_summary = str(safe_payload.get("summary", "")).strip()
    block_status = str(safe_payload.get("status", "")).strip().lower() or "completed"
    objective = str(safe_payload.get("objective", "")).strip() or block_goal or block_name
    confirmed_facts = _unique_strings([
        str(item).strip()
        for item in (safe_payload.get("confirmed_facts", []) if isinstance(safe_payload.get("confirmed_facts"), list) else [])
        if str(item).strip()
    ])
    security_signals = _unique_strings([
        str(item).strip()
        for item in (safe_payload.get("security_signals", []) if isinstance(safe_payload.get("security_signals"), list) else [])
        if str(item).strip()
    ])
    unknowns = _unique_strings([
        str(item).strip()
        for item in (safe_payload.get("unknowns", []) if isinstance(safe_payload.get("unknowns"), list) else [])
        if str(item).strip()
    ])
    next_actions = _unique_strings([
        str(item).strip()
        for item in (safe_payload.get("next_actions", []) if isinstance(safe_payload.get("next_actions"), list) else [])
        if str(item).strip()
    ])
    why_it_matters = str(safe_payload.get("why_it_matters", "")).strip()
    result_rows = [
        item
        for item in (safe_payload.get("results", []) if isinstance(safe_payload.get("results"), list) else [])
        if isinstance(item, dict)
    ]
    command_results: list[dict[str, str]] = []
    for item in result_rows:
        command_text = str(item.get("command", "")).strip() or str(item.get("tool", "")).strip()
        raw_status = str(item.get("status", "")).strip().lower() or "unknown"
        status_label = (
            "passed"
            if raw_status == "completed"
            else "failed"
            if raw_status == "error"
            else raw_status
        )
        if not command_text:
            continue
        command_results.append(
            {
                "tool": str(item.get("tool", "")).strip() or "tool",
                "command": command_text,
                "status": status_label,
                "raw_status": raw_status,
                "summary": str(item.get("summary", "")).strip(),
            }
        )
    tools_ran = [
        str(item.get("command", "")).strip() or str(item.get("tool", "")).strip()
        for item in result_rows
        if str(item.get("command", "")).strip() or str(item.get("tool", "")).strip()
    ]
    findings_summary = _unique_strings([
        f"{str(item.get('tool', '')).strip() or 'tool'}: {str(item.get('summary', '')).strip()}"
        for item in result_rows
        if str(item.get("summary", "")).strip()
    ])
    raw_tool_evidence = findings_summary
    if not findings_summary:
        findings_summary = confirmed_facts[:]
    derived_findings = _extra_findings_from_structured(result_rows)
    scenario_text = objective
    execution_summary = (
        f"Completed information-gathering block {block_index}/{total_blocks} with "
        f"{len(result_rows)} tool result(s). Status: {block_status}."
        if total_blocks > 0 and block_index > 0
        else f"Completed information-gathering block with {len(result_rows)} tool result(s). Status: {block_status}."
    )
    sequence_label = f"g{block_index}" if block_index > 0 else "g?"
    entry_id = f"{scan_id}:information_gathering:{sequence_label}:classified"
    scenario_report = [
        {
            "scenario_ran": scenario_text,
            "agent": "information_gathering",
            "status": block_status,
            "tools_ran": _unique_strings(tools_ran),
            "tool_results": command_results,
            "findings_summary": _unique_strings(confirmed_facts + security_signals + derived_findings) or findings_summary,
            "execution_summary": execution_summary,
        }
    ]
    markdown_lines = [
        "# INFORMATION GATHERING Report",
        "",
        f"- Agent / Node: information_gathering",
        f"- Block: {sequence_label} ({block_name})",
        f"- Scenario: {scenario_text}",
        f"- Status: {block_status}",
        "",
        "## Full Tool History",
        "",
    ]
    if command_results:
        for item in command_results:
            status = str(item.get("status", "")).strip() or "unknown"
            command_text = str(item.get("command", "")).strip() or str(item.get("tool", "")).strip() or "tool"
            line = f"- `{status}` `{command_text}`"
            summary_text = str(item.get("summary", "")).strip()
            if summary_text:
                line = f"{line} -> {summary_text}"
            markdown_lines.append(line)
    else:
        markdown_lines.append("- No tool history recorded.")

    markdown_lines.extend(["", "## What We Find", ""])
    combined_findings = _unique_strings(confirmed_facts + security_signals + derived_findings)
    if combined_findings:
        markdown_lines.extend(f"- {line}" for line in combined_findings)
    elif block_summary:
        markdown_lines.append(f"- {block_summary}")
    else:
        markdown_lines.append("- No grounded confirmed facts were produced.")

    markdown_lines.extend(["", "## What We Should Do", ""])
    if next_actions:
        markdown_lines.extend(f"- {line}" for line in next_actions)
    else:
        markdown_lines.append("- No next action was recorded.")

    markdown_lines.extend(["", "## Unknowns / Gaps", ""])
    if unknowns:
        markdown_lines.extend(f"- {line}" for line in unknowns)
    else:
        markdown_lines.append("- No unresolved unknowns were recorded.")
    markdown_lines.extend([
        "",
        "## Metadata",
        "",
        f"- Scan ID: `{scan_id}`",
        f"- Entry ID: `{entry_id}`",
        f"- Verdict: `info`",
        f"- Deep Description: {block_summary or scenario_text}",
    ])
    return {
        "id": entry_id,
        "scan_id": scan_id,
        "agent": "information_gathering",
        "phase": "classified",
        "cycle_number": 0,
        "scenario_index": block_index,
        "sequence_label": sequence_label,
        "scenario_task": scenario_text,
        "execution_status": block_status,
        "verdict": "info",
        "summary": (block_summary or scenario_text)[:400],
        "objective": objective,
        "confirmed_facts": _unique_strings(confirmed_facts + derived_findings),
        "security_signals": security_signals[:12],
        "unknowns": unknowns,
        "why_it_matters": why_it_matters,
        "next_actions": next_actions,
        "raw_tool_evidence": raw_tool_evidence,
        "scenario_report": scenario_report,
        "markdown": "\n".join(markdown_lines).strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _persist_information_gathering_report(
    *,
    project_store: ProjectsStore,
    project_id: str,
    scan_id: str,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    project = project_store.get_project(project_id)
    if not isinstance(project, dict):
        return None

    project_payload = project.get("payload")
    if not isinstance(project_payload, dict):
        project_payload = {}
        project["payload"] = project_payload

    existing_root = project_payload.get(FINDINGS_HISTORY_KEY)
    if not isinstance(existing_root, dict):
        existing_root = project_payload.get(LEGACY_FINDINGS_HISTORY_KEY)
    reports_root = dict(existing_root) if isinstance(existing_root, dict) else {}
    entry = _build_info_gathering_report_entry(scan_id=scan_id, payload=payload)
    existing_bucket = reports_root.get("information_gathering")
    bucket_entries = (
        list(existing_bucket.get("entries", []))
        if isinstance(existing_bucket, dict) and isinstance(existing_bucket.get("entries", []), list)
        else []
    )
    bucket_entries = [
        item for item in bucket_entries
        if isinstance(item, dict) and str(item.get("id", "")).strip() != str(entry.get("id", "")).strip()
    ]
    bucket_entries.append(entry)
    bucket_entries.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    reports_root["information_gathering"] = {
        "updated_at": str(entry.get("updated_at", "")).strip(),
        "entries": bucket_entries,
    }
    project_payload[FINDINGS_HISTORY_KEY] = reports_root
    project["updatedAt"] = str(entry.get("updated_at", "")).strip() or datetime.now(timezone.utc).isoformat()
    project_store.upsert_project(project)
    return entry


def _persist_analyzer_agent_reports(
    *,
    project_store: ProjectsStore,
    project_id: str,
    scan_id: str,
    info_only_items: list[dict[str, Any]],
    verify_results: dict[str, list[dict[str, Any]]],
) -> None:
    project = project_store.get_project(project_id)
    if not isinstance(project, dict):
        return

    payload = project.get("payload")
    if not isinstance(payload, dict):
        payload = {}
        project["payload"] = payload

    existing_root = payload.get(FINDINGS_HISTORY_KEY)
    if not isinstance(existing_root, dict):
        existing_root = payload.get(LEGACY_FINDINGS_HISTORY_KEY)
    reports_root = dict(existing_root) if isinstance(existing_root, dict) else {}

    def _append_report(
        *,
        role: str,
        idx: Any,
        scenario: dict[str, Any],
        row_result: dict[str, Any],
        assessment: dict[str, Any],
        compact_summary: str,
        verdict: str,
        detail_summary: str,
        verify_data: dict[str, Any] | None = None,
    ) -> None:
        safe_role = str(role or "").strip().lower()
        if safe_role not in {"recon", "exploit"}:
            return

        generated_at = datetime.now(timezone.utc).isoformat()
        entry_id = f"{scan_id}:{safe_role}:{str(idx or '0').strip() or '0'}:{verdict}"
        markdown = _build_analyzer_agent_report_markdown(
            scan_id=scan_id,
            entry_id=entry_id,
            generated_at=generated_at,
            scenario=scenario if isinstance(scenario, dict) else {},
            row_result=row_result if isinstance(row_result, dict) else {},
            assessment=assessment if isinstance(assessment, dict) else {},
            compact_summary=compact_summary,
            verdict=verdict,
            detail_summary=detail_summary,
            verify_data=verify_data if isinstance(verify_data, dict) else None,
        )

        existing_bucket = reports_root.get(safe_role)
        bucket_entries = (
            list(existing_bucket.get("entries", []))
            if isinstance(existing_bucket, dict) and isinstance(existing_bucket.get("entries", []), list)
            else []
        )
        bucket_entries = [
            item for item in bucket_entries
            if isinstance(item, dict) and str(item.get("id", "")).strip() != entry_id
        ]
        bucket_entries.append(
            {
                "id": entry_id,
                "scan_id": scan_id,
                "agent": safe_role,
                "phase": "verified",
                "scenario_index": idx,
                "scenario_task": str((scenario or {}).get("task", "")).strip(),
                "verdict": verdict,
                "summary": detail_summary[:400],
                "markdown": markdown,
                "updated_at": generated_at,
            }
        )
        bucket_entries.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
        reports_root[safe_role] = {
            "updated_at": generated_at,
            "entries": bucket_entries,
        }

    for item in info_only_items:
        if not isinstance(item, dict):
            continue
        scenario = item.get("scenario", {}) if isinstance(item.get("scenario"), dict) else {}
        row_result = item.get("row_result", {}) if isinstance(item.get("row_result"), dict) else {}
        assessment = item.get("assessment", {}) if isinstance(item.get("assessment"), dict) else {}
        compact_summary = str(item.get("compact_summary", "")).strip()
        detail_summary = (
            compact_summary
            or str(assessment.get("overall", {}).get("summary", "")).strip()
            if isinstance(assessment.get("overall"), dict)
            else compact_summary
        )
        _append_report(
            role=str(scenario.get("agent", "")).strip().lower(),
            idx=item.get("idx"),
            scenario=scenario,
            row_result=row_result,
            assessment=assessment,
            compact_summary=compact_summary,
            verdict="info",
            detail_summary=detail_summary or str(row_result.get("summary", "")).strip(),
        )

    for bucket_name, bucket_items in verify_results.items():
        if not isinstance(bucket_items, list):
            continue
        for item in bucket_items:
            if not isinstance(item, dict):
                continue
            scenario = item.get("scenario", {}) if isinstance(item.get("scenario"), dict) else {}
            row_result = item.get("row_result", {}) if isinstance(item.get("row_result"), dict) else {}
            assessment = item.get("assessment", {}) if isinstance(item.get("assessment"), dict) else {}
            compact_summary = str(item.get("compact_summary", "")).strip()
            verify_summary = str(item.get("verify_summary", "")).strip()
            _append_report(
                role=str(scenario.get("agent", "")).strip().lower(),
                idx=item.get("idx"),
                scenario=scenario,
                row_result=row_result,
                assessment=assessment,
                compact_summary=compact_summary,
                verdict=str(item.get("verdict", bucket_name)).strip().lower() or bucket_name,
                detail_summary=verify_summary or compact_summary or str(row_result.get("summary", "")).strip(),
                verify_data=item.get("verify_data", {}) if isinstance(item.get("verify_data"), dict) else {},
            )

    payload[FINDINGS_HISTORY_KEY] = reports_root
    project["updatedAt"] = datetime.now(timezone.utc).isoformat()
    project_store.upsert_project(project)


def _persist_single_analyzer_agent_report(
    *,
    project_store: ProjectsStore,
    project_id: str,
    scan_id: str,
    cycle_number: int,
    role: str,
    idx: Any,
    scenario: dict[str, Any],
    row_result: dict[str, Any],
    assessment: dict[str, Any],
    compact_summary: str,
    verdict: str,
    detail_summary: str,
    verify_data: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    safe_role = str(role or "").strip().lower()
    if safe_role not in {"recon", "exploit"}:
        return None

    project = project_store.get_project(project_id)
    if not isinstance(project, dict):
        return None

    payload = project.get("payload")
    if not isinstance(payload, dict):
        payload = {}
        project["payload"] = payload

    existing_root = payload.get(FINDINGS_HISTORY_KEY)
    if not isinstance(existing_root, dict):
        existing_root = payload.get(LEGACY_FINDINGS_HISTORY_KEY)
    reports_root = dict(existing_root) if isinstance(existing_root, dict) else {}
    generated_at = datetime.now(timezone.utc).isoformat()
    scenario_index = int(idx or 0)
    normalized_cycle = int(cycle_number or 0)
    sequence_label = f"c{normalized_cycle}s{scenario_index}"
    entry_id = f"{scan_id}:{safe_role}:{sequence_label}:classified"
    markdown = _build_analyzer_agent_report_markdown(
        scan_id=scan_id,
        entry_id=entry_id,
        generated_at=generated_at,
        scenario=scenario if isinstance(scenario, dict) else {},
        row_result=row_result if isinstance(row_result, dict) else {},
        assessment=assessment if isinstance(assessment, dict) else {},
        compact_summary=compact_summary,
        verdict=verdict,
        detail_summary=detail_summary,
        verify_data=verify_data if isinstance(verify_data, dict) else None,
    )

    scenario_report = (
        assessment.get("scenario_reports", [])
        if isinstance(assessment.get("scenario_reports", []), list)
        else (
            verify_data.get("scenario_report", [])
            if isinstance(verify_data, dict) and isinstance(verify_data.get("scenario_report", []), list)
            else []
        )
    )
    entry = {
        "id": entry_id,
        "scan_id": scan_id,
        "agent": safe_role,
        "phase": "classified",
        "cycle_number": normalized_cycle,
        "scenario_index": scenario_index,
        "sequence_label": sequence_label,
        "scenario_task": str((scenario or {}).get("task", "")).strip(),
        "verdict": verdict,
        "summary": detail_summary[:400],
        "scenario_report": scenario_report,
        "markdown": markdown,
        "updated_at": generated_at,
    }

    existing_bucket = reports_root.get(safe_role)
    bucket_entries = (
        list(existing_bucket.get("entries", []))
        if isinstance(existing_bucket, dict) and isinstance(existing_bucket.get("entries", []), list)
        else []
    )
    bucket_entries = [
        item for item in bucket_entries
        if isinstance(item, dict) and str(item.get("id", "")).strip() != entry_id
    ]
    bucket_entries.append(entry)
    bucket_entries.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    reports_root[safe_role] = {
        "updated_at": generated_at,
        "entries": bucket_entries,
    }

    payload[FINDINGS_HISTORY_KEY] = reports_root
    project["updatedAt"] = generated_at
    project_store.upsert_project(project)
    return entry


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
    scan_id: str = "",
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
    analyzer_chain = (
        verify_data.get("analysis_chain", [])
        if isinstance(verify_data.get("analysis_chain"), list)
        else []
    )
    normalized_outputs = (
        verify_data.get("normalized_outputs", [])
        if isinstance(verify_data.get("normalized_outputs"), list)
        else []
    )
    normalized_summary = str(
        (
            verify_data.get("evidence", {}).get("normalized_summary", "")
            if isinstance(verify_data.get("evidence"), dict)
            else ""
        )
        or verify_data.get("normalized_summary", "")
        or ""
    ).strip()
    evidence_status = str(
        (
            verify_data.get("evidence", {}).get("evidence_status", "")
            if isinstance(verify_data.get("evidence"), dict)
            else ""
        )
        or verify_data.get("evidence_status", "")
        or ""
    ).strip().lower() or "evidence_backed"
    proof_quality = str(
        (
            verify_data.get("evidence", {}).get("proof_quality", "")
            if isinstance(verify_data.get("evidence"), dict)
            else ""
        )
        or verify_data.get("proof_quality", "")
        or ""
    ).strip().lower() or "moderate"
    deterministic_validation = bool(
        (
            verify_data.get("evidence", {}).get("deterministic_validation")
            if isinstance(verify_data.get("evidence"), dict)
            else None
        )
        if (
            isinstance(verify_data.get("evidence"), dict)
            and "deterministic_validation" in verify_data.get("evidence", {})
        )
        else verify_data.get("deterministic_validation", False)
    )
    verification_methods = _coerce_string_list(
        (
            verify_data.get("evidence", {}).get("verification_methods")
            if isinstance(verify_data.get("evidence"), dict)
            else None
        )
        or verify_data.get("verification_methods")
    )
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
        f"Evidence Tier: {evidence_status.replace('_', ' ').upper()}",
        f"Proof Quality: {proof_quality.upper()}",
        f"Deterministic Validation: {'YES' if deterministic_validation else 'NO'}",
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
    if verification_methods:
        description_parts.extend(["", "Verification Methods:"])
        description_parts.append(f"  - {', '.join(verification_methods[:8])}")
    if analyzer_chain:
        description_parts.extend(["", "Analyzer Chain:"])
        description_parts.append(f"  - {' -> '.join(str(step) for step in analyzer_chain[:8])}")
    if normalized_summary:
        description_parts.extend(["", "Normalized Evidence Summary:", normalized_summary])
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
    evidence_map.setdefault("analyzer_chain", analyzer_chain)
    evidence_map.setdefault("normalized_outputs", normalized_outputs)
    evidence_map.setdefault("normalized_summary", normalized_summary)
    evidence_map.setdefault("ssvc", verify_data.get("ssvc"))
    evidence_map.setdefault("ssvc_action", verify_data.get("ssvc_action"))
    evidence_map.setdefault("hitl_required", verify_data.get("hitl_required"))
    evidence_map.setdefault("vulnerability_type", verify_data.get("vulnerability_type"))
    evidence_map.setdefault("expected_indicator", verify_data.get("expected_indicator"))
    evidence_map.setdefault("evidence_status", evidence_status)
    evidence_map.setdefault("proof_quality", proof_quality)
    evidence_map.setdefault("deterministic_validation", deterministic_validation)
    evidence_map.setdefault("verification_methods", verification_methods)
    evidence_map.setdefault("artifact_quality", verify_data.get("artifact_quality"))
    if cve_candidates:
        evidence_map.setdefault("cve_candidates", cve_candidates)

    remediation = str(scenario.get("remediation", "")).strip()
    if not remediation:
        remediation = "Retest/PoC generation pending. Review the confirmation commands and remove or patch the affected service/version."

    return {
        "id": str(uuid.uuid4()),
        "scan_id": str(scan_id or "").strip(),
        "title": verify_summary or scenario_task or "Verified vulnerability",
        "severity": severity,
        "category": vuln_type,
        "target": target,
        "status": "verified",
        "cvss": scenario.get("cvss"),
        "cve": cve_candidates[0] if cve_candidates else scenario.get("cve"),
        "ssvc": verify_data.get("ssvc"),
        "evidence_status": evidence_status,
        "proof_quality": proof_quality,
        "deterministic_validation": deterministic_validation,
        "verification_methods": verification_methods,
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
    use_redis: bool = True,
) -> str:
    payload = {
        "project_id": str(project_id).strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    if use_redis and not cache_dir:
        cache_key = f"project_findings:{str(project_id).strip()}"
        get_project_runtime_cache().set_json(
            cache_key,
            payload,
            ttl_seconds=PROJECT_FINDINGS_CACHE_TTL_SECONDS,
        )
        return f"redis://{cache_key}"

    base_dir = cache_dir or os.path.join(os.path.dirname(__file__), "..", "cache", "project_findings")
    os.makedirs(base_dir, exist_ok=True)
    cache_path = os.path.join(base_dir, f"{str(project_id).strip()}.json")
    with open(cache_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
    return cache_path


def _cache_root() -> Path:
    return (Path(__file__).resolve().parents[1] / "cache").resolve()


def _projects_artifacts_root() -> Path:
    db_path = Path(projects_db_config.projects_db_path).expanduser().resolve()
    return db_path.parent / "artifacts"


def _delete_project_uploaded_artifacts(project_id: str) -> int:
    safe_project_id = str(project_id or "").strip()
    if not safe_project_id:
        return 0
    project_root = _projects_artifacts_root() / safe_project_id
    if not project_root.exists():
        return 0
    count = sum(1 for path in project_root.rglob("*") if path.is_file())
    shutil.rmtree(project_root, ignore_errors=True)
    return count


def _delete_project_cache_artifacts(project_id: str) -> dict[str, int]:
    safe_project_id = str(project_id or "").strip()
    if not safe_project_id:
        return {"project_runs_removed": 0, "project_findings_removed": 0}

    get_project_runtime_cache().pop_json(f"project_findings:{safe_project_id}")

    cache_root = _cache_root()
    project_runs_root = cache_root / "project_runs"
    project_findings_root = cache_root / "project_findings"
    project_runs_removed = 0
    project_findings_removed = 0

    findings_path = project_findings_root / f"{safe_project_id}.json"
    if findings_path.exists():
        findings_path.unlink(missing_ok=True)
        project_findings_removed += 1

    if project_runs_root.exists():
        for run_dir in project_runs_root.iterdir():
            if not run_dir.is_dir():
                continue
            memory_json = run_dir / "system_memory" / "memory.json"
            if not memory_json.exists():
                continue
            try:
                payload = json.loads(memory_json.read_text(encoding="utf-8"))
            except Exception:
                continue
            overview = payload.get("overview", {}) if isinstance(payload, dict) else {}
            if str(overview.get("project_id", "")).strip() != safe_project_id:
                continue
            shutil.rmtree(run_dir, ignore_errors=True)
            project_runs_removed += 1

    return {
        "project_runs_removed": project_runs_removed,
        "project_findings_removed": project_findings_removed,
    }


def _purge_project_runtime_artifacts(project_id: str, *, project_payload: dict[str, Any] | None = None) -> dict[str, int]:
    deleted_cache = _delete_project_cache_artifacts(project_id)
    deleted_sandbox = delete_project_workspace(project_id, project_payload=project_payload)
    uploaded_artifacts_removed = _delete_project_uploaded_artifacts(project_id)
    return {
        **deleted_cache,
        **deleted_sandbox,
        "uploaded_artifacts_removed": uploaded_artifacts_removed,
    }


def _slugify_cache_part(value: Any, *, max_len: int = 80) -> str:
    clean = str(value or "").strip().lower()
    clean = re.sub(r"^[a-z][a-z0-9+.-]*://", "", clean)
    clean = clean.strip().strip("/")
    clean = re.sub(r"[^a-z0-9._-]+", "-", clean)
    clean = re.sub(r"-{2,}", "-", clean).strip("-._")
    if not clean:
        return ""
    return clean[:max_len].strip("-._")


def _project_cache_timestamp(value: Any = None) -> str:
    raw = str(value or "").strip()
    dt: datetime
    if raw:
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _extract_project_display_name(project: dict[str, Any] | None) -> str:
    if not isinstance(project, dict):
        return ""
    for key in ("name", "title", "projectName", "displayName"):
        value = str(project.get(key, "") or "").strip()
        if value:
            return value
    return ""


def _build_project_run_cache_dir(
    *,
    project_id: str,
    target: str,
    project_name: str = "",
    created_at: str | None = None,
    cache_root: str | None = None,
) -> str:
    root = cache_root or os.path.join(os.path.dirname(__file__), "..", "cache", "project_runs")
    project_part = _slugify_cache_part(project_name) or _slugify_cache_part(project_id, max_len=48) or "project"
    target_raw = str(target or "").strip()
    parsed_target = urlparse(target_raw if "://" in target_raw else f"//{target_raw}")
    target_identity = parsed_target.netloc or _extract_target_host(target_raw) or target_raw
    target_part = _slugify_cache_part(target_identity, max_len=80) or "target"
    timestamp = _project_cache_timestamp(created_at)
    folder_name = f"{project_part}__{target_part}__{timestamp}"
    path = os.path.abspath(os.path.join(root, folder_name))
    os.makedirs(path, exist_ok=True)
    return path


def _write_warmup_perceptor_cache(
    *,
    project_id: str,
    target: str,
    project_name: str,
    created_at: str,
    warmup_summaries: list[dict[str, Any]],
    recon_plan_data: dict[str, Any],
    project_cache_dir: str,
    use_redis: bool = True,
) -> str:
    payload = {
        "project_id": str(project_id).strip(),
        "target": str(target or "").strip(),
        "project_name": str(project_name or "").strip(),
        "created_at": created_at,
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "recon_plan": recon_plan_data if isinstance(recon_plan_data, dict) else {},
        "summaries": warmup_summaries,
    }
    if use_redis:
        cache_key = (
            f"warmup_perceptor:{str(project_id).strip()}:"
            f"{_project_cache_timestamp(created_at)}"
        )
        get_project_runtime_cache().set_json(
            cache_key,
            payload,
            ttl_seconds=WARMUP_PERCEPTOR_CACHE_TTL_SECONDS,
        )
        return f"redis://{cache_key}"

    cache_dir = os.path.join(project_cache_dir, "warmup_perceptor")
    os.makedirs(cache_dir, exist_ok=True)
    cache_path = os.path.join(cache_dir, "summaries.json")
    with open(cache_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
    return cache_path


def _consume_warmup_perceptor_cache(
    cache_path: str,
    *,
    use_redis: bool = True,
) -> list[dict[str, Any]]:
    if use_redis and str(cache_path or "").startswith("redis://"):
        cache_key = str(cache_path).removeprefix("redis://").strip()
        payload = get_project_runtime_cache().pop_json(cache_key) or {}
        summaries = payload.get("summaries") if isinstance(payload, dict) else None
        return [item for item in summaries if isinstance(item, dict)] if isinstance(summaries, list) else []

    try:
        with open(cache_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []

    summaries = payload.get("summaries") if isinstance(payload, dict) else None
    if not isinstance(summaries, list):
        summaries = []

    cache_dir = os.path.dirname(cache_path)
    try:
        shutil.rmtree(cache_dir)
    except OSError as exc:  # pragma: no cover - defensive cleanup
        logger.warning(
            "warmup_perceptor_cache_delete_failed",
            cache_path=cache_path,
            error=str(exc),
        )
    return [item for item in summaries if isinstance(item, dict)]


def _target_memory_dir(project_cache_dir: str) -> str:
    return _system_memory_dir_external(project_cache_dir)


def _target_memory_paths(project_cache_dir: str) -> tuple[str, str]:
    return _system_memory_paths_external(project_cache_dir)


def _compact_tool_output(raw: Any, *, limit: int = 1400) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        parsed = None
    if isinstance(parsed, dict):
        for key in ("llm_brief", "summary", "result", "status"):
            value = str(parsed.get(key, "")).strip()
            if value:
                text = value
                break
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def _extract_artifact_candidates(*values: Any, limit: int = 20) -> list[str]:
    pattern = re.compile(
        r"(?:(?:https?://|wss?://)[^\s'\"<>]+|/[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{2,}|[A-Za-z0-9._-]+\.(?:js|json|txt|xml|yaml|yml|env|bak|old|zip))"
    )
    found: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        for match in pattern.findall(text):
            clean = str(match).strip().rstrip(".,;)")
            if len(clean) < 3:
                continue
            if clean.lower() in seen:
                continue
            seen.add(clean.lower())
            found.append(clean)
            if len(found) >= limit:
                return found
    return found


def _load_target_memory(project_cache_dir: str) -> dict[str, Any]:
    return _load_target_memory_external(project_cache_dir)


async def _save_target_memory(
    project_cache_dir: str,
    memory: dict[str, Any],
    *,
    memory_llm: SystemMemoryLLM | None = None,
) -> dict[str, Any]:
    return await _save_target_memory_external(
        project_cache_dir,
        memory,
        memory_llm=memory_llm,
    )


async def _store_target_memory_checklist(
    project_cache_dir: str,
    *,
    checklist: dict[str, Any],
    memory_llm: SystemMemoryLLM | None = None,
) -> dict[str, Any]:
    return await _store_system_memory_checklist_external(
        project_cache_dir,
        checklist=checklist,
        memory_llm=memory_llm,
    )


def _merge_target_memory_artifacts(memory: dict[str, Any], *values: Any) -> None:
    _merge_target_memory_artifacts_external(memory, *values)


async def _append_target_memory_updates(
    project_cache_dir: str,
    *,
    stage: str,
    updates: list[dict[str, Any]],
    verified_findings: list[dict[str, Any]] | None = None,
    tool_observations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return await _append_system_memory_updates_external(
        project_cache_dir,
        stage=stage,
        updates=updates,
        verified_findings=verified_findings,
        tool_observations=tool_observations,
    )


def _build_target_memory_prompt_block(memory: dict[str, Any]) -> str:
    return _build_target_memory_prompt_block_external(memory)


def _coerce_string_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    cleaned: dict[str, str] = {}
    for key, raw_value in value.items():
        clean_key = str(key or "").strip()
        clean_value = str(raw_value or "").strip()
        if clean_key and clean_value:
            cleaned[clean_key] = clean_value
    return cleaned


def _parse_cookie_header(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in str(value or "").split(";"):
        if "=" not in part:
            continue
        name, cookie_value = part.split("=", 1)
        clean_name = str(name or "").strip()
        clean_value = str(cookie_value or "").strip()
        if clean_name and clean_value:
            cookies[clean_name] = clean_value
    return cookies


def _build_auth_runtime_context(
    *,
    target_type: str,
    target_config: dict[str, Any] | None,
    target: str,
) -> tuple[SessionManager, dict[str, str], dict[str, str]]:
    manager = SessionManager()
    if not isinstance(target_config, dict):
        return manager, {}, {}

    headers = _coerce_string_dict(target_config.get("headers"))
    cookies = _coerce_string_dict(target_config.get("cookies"))
    normalized_type = _normalize_target_type(target_type)

    if normalized_type == "api":
        auth = target_config.get("auth", {}) if isinstance(target_config.get("auth"), dict) else {}
        auth_type = str(auth.get("type", "")).strip().lower()
        token = str(auth.get("token", "")).strip()
        if auth_type == "bearer" and token:
            headers.setdefault("Authorization", f"Bearer {token}")
        elif auth_type == "api_key":
            header_name = str(auth.get("api_key_header", "")).strip() or "X-API-Key"
            api_key = str(auth.get("api_key", "")).strip()
            if api_key:
                headers.setdefault(header_name, api_key)
        elif auth_type == "cookie" and token:
            cookies.update(_parse_cookie_header(token))

    if headers or cookies:
        manager.register(
            SessionContext(
                label="authenticated_primary",
                cookies=cookies,
                headers=headers,
                base_url=str(target or "").strip(),
            )
        )

    credentials = target_config.get("credentials")
    if isinstance(credentials, list):
        for idx, item in enumerate(credentials[:3], start=1):
            if not isinstance(item, dict):
                continue
            username = str(item.get("username", item.get("email", ""))).strip()
            if username:
                manager.register(
                    SessionContext(
                        label=f"credential_{idx}:{username}",
                        base_url=str(target or "").strip(),
                    )
                )

    return manager, headers, cookies


def _iter_memory_text_fragments(memory: dict[str, Any]) -> list[str]:
    fragments: list[str] = []
    if not isinstance(memory, dict):
        return fragments

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for value in node.values():
                visit(value)
            return
        if isinstance(node, list):
            for value in node:
                visit(value)
            return
        text = str(node or "").strip()
        if text:
            fragments.append(text)

    visit(memory.get("gathering", {}))
    visit(memory.get("artifacts", []))
    visit(memory.get("updates", []))
    return fragments


def _extract_backticked_paths(*values: Any) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for value in values:
        for match in re.findall(r"`([^`]+)`", str(value or "")):
            clean = str(match or "").strip()
            if not clean.startswith("/"):
                continue
            if clean.lower() in seen:
                continue
            seen.add(clean.lower())
            paths.append(clean)
    return paths


def _extract_routes_from_memory(memory: dict[str, Any]) -> list[str]:
    routes: list[str] = []
    seen: set[str] = set()
    fragments = _iter_memory_text_fragments(memory)
    for fragment in fragments:
        for match in re.findall(r"https?://[^\s\"'<>`]+", fragment):
            clean = match.rstrip(".,);]")
            if clean.lower() in seen:
                continue
            seen.add(clean.lower())
            routes.append(clean)
        for path in _extract_backticked_paths(fragment):
            if path.lower() in seen:
                continue
            seen.add(path.lower())
            routes.append(path)
    return routes[:250]


def _normalize_route_token(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("http://") or text.startswith("https://"):
        text = re.sub(r"^[a-z][a-z0-9+.-]*://[^/]+", "", text, flags=re.IGNORECASE)
    text = text.strip()
    if not text.startswith("/"):
        return ""
    text = re.split(r"[?#]", text, maxsplit=1)[0].strip()
    text = text.rstrip(".,);]>\"'")
    if not text.startswith("/"):
        return ""
    text = re.sub(r"/{2,}", "/", text)
    if len(text) > 1:
        text = text.rstrip("/")
    return text or "/"


def _extract_route_tokens(*values: Any) -> list[str]:
    routes: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        candidates = re.findall(r"https?://[^\s\"'<>`]+|/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?)+", text)
        candidates.extend(_extract_backticked_paths(text))
        for candidate in candidates:
            route = _normalize_route_token(candidate)
            if not route:
                continue
            lowered = route.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            routes.append(route)
    return routes


def _route_family_prefixes(route: str) -> list[str]:
    normalized = _normalize_route_token(route)
    if not normalized or normalized == "/":
        return []
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return []
    families: list[str] = []
    if len(parts) >= 2:
        prefix = "/" + "/".join(parts[:2])
        if prefix != normalized:
            families.append(prefix)
    return families


def _verify_summary_indicates_blocked_route(summary: str) -> bool:
    lowered = str(summary or "").strip().lower()
    if not lowered:
        return False
    blocked_markers = (
        "404 not found",
        "403 forbidden",
        "405 method not allowed",
        "does not exist",
        "is inaccessible",
        "returned 404",
        "returned 403",
        "not exposed",
        "no sensitive data exposure exists at",
        "endpoint returned http 404",
        "route is forbidden",
        "base path is forbidden",
    )
    return any(marker in lowered for marker in blocked_markers)


def _extract_blocked_route_memory_updates(
    items: list[dict[str, Any]],
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    blocked_routes: list[str] = []
    blocked_prefixes: list[str] = []
    updates: list[dict[str, Any]] = []
    route_seen: set[str] = set()
    prefix_seen: set[str] = set()
    root_prefix_counts: dict[str, int] = {}

    for item in items:
        if not isinstance(item, dict):
            continue
        verify_summary = str(item.get("verify_summary", "")).strip()
        scenario = item.get("scenario", {}) if isinstance(item.get("scenario"), dict) else {}
        if not _verify_summary_indicates_blocked_route(verify_summary):
            continue
        routes = _extract_route_tokens(
            scenario.get("endpoint", ""),
            scenario.get("task", ""),
            scenario.get("details", ""),
            verify_summary,
        )
        if not routes:
            continue
        for route in routes:
            lowered = route.lower()
            if lowered not in route_seen:
                route_seen.add(lowered)
                blocked_routes.append(route)
            root_parts = [part for part in route.split("/") if part]
            if root_parts:
                root_prefix = "/" + root_parts[0]
                root_prefix_counts[root_prefix] = root_prefix_counts.get(root_prefix, 0) + 1
            for prefix in _route_family_prefixes(route):
                prefix_lower = prefix.lower()
                if prefix_lower not in prefix_seen:
                    prefix_seen.add(prefix_lower)
                    blocked_prefixes.append(prefix)
    for prefix, count in root_prefix_counts.items():
        if count >= 2 and prefix.lower() not in prefix_seen:
            prefix_seen.add(prefix.lower())
            blocked_prefixes.append(prefix)

    for item in items:
        if not isinstance(item, dict):
            continue
        verify_summary = str(item.get("verify_summary", "")).strip()
        scenario = item.get("scenario", {}) if isinstance(item.get("scenario"), dict) else {}
        if not _verify_summary_indicates_blocked_route(verify_summary):
            continue
        routes = _extract_route_tokens(
            scenario.get("endpoint", ""),
            scenario.get("task", ""),
            scenario.get("details", ""),
            verify_summary,
        )
        if not routes:
            continue
        updates.append(
            {
                "title": "Blocked route family recorded",
                "summary": (
                    f"Verification disproved route(s) {', '.join(routes[:4])}. "
                    f"Do not schedule follow-up scenarios against this path family without new evidence."
                ),
                "routes": routes[:8],
                "route_prefixes": [prefix for prefix in blocked_prefixes[:8]],
                "kind": "blocked_route",
            }
        )

    return blocked_routes, blocked_prefixes, updates


def _scenario_references_blocked_route(
    scenario: dict[str, Any],
    *,
    blocked_routes: list[str],
    blocked_route_prefixes: list[str],
) -> bool:
    routes = _extract_route_tokens(
        scenario.get("endpoint", ""),
        scenario.get("task", ""),
        scenario.get("details", ""),
        scenario.get("notes", ""),
    )
    if not routes:
        return False
    blocked_exact = {item.lower() for item in blocked_routes if str(item).strip()}
    blocked_prefix = {item.lower() for item in blocked_route_prefixes if str(item).strip()}
    for route in routes:
        lowered = route.lower()
        if lowered in blocked_exact:
            return True
        if any(lowered == prefix or lowered.startswith(prefix + "/") for prefix in blocked_prefix):
            return True
    return False


def _scenario_requires_evidence_gate(scenario: dict[str, Any]) -> bool:
    text = " ".join(
        str(part or "")
        for part in (
            scenario.get("task", ""),
            scenario.get("details", ""),
            " ".join(str(item or "") for item in scenario.get("methods", []) if isinstance(item, str))
            if isinstance(scenario.get("methods"), list)
            else "",
        )
    ).lower()
    cues = (
        "sql injection",
        "sqli",
        "xss",
        "cross-site scripting",
        "csrf",
        "command injection",
        "ssti",
        "ssrf",
        "rce",
        "default credential",
        "session fixation",
        "file upload",
        "method tampering",
        "authentication bypass",
        "exploit",
    )
    return any(cue in text for cue in cues)


def _memory_prerequisite_evidence(target_memory: dict[str, Any]) -> set[str]:
    if not isinstance(target_memory, dict):
        return set()
    memory_text = _build_target_memory_evidence_text(target_memory)
    evidence: set[str] = set()
    observed_routes = {
        _normalize_route_token(item)
        for item in (
            (target_memory.get("anonymous_routes", []) if isinstance(target_memory.get("anonymous_routes"), list) else [])
            + (target_memory.get("authenticated_routes", []) if isinstance(target_memory.get("authenticated_routes"), list) else [])
            + _extract_routes_from_memory(target_memory)
        )
    }
    observed_routes = {item for item in observed_routes if item}
    if observed_routes:
        evidence.add("route_observed")
    parameter_hints = (
        target_memory.get("parameter_hints", [])
        if isinstance(target_memory.get("parameter_hints"), list)
        else []
    )
    if parameter_hints:
        evidence.add("parameter_observed")
        evidence.add("file_parameter_observed")
    if any(marker in memory_text for marker in ("reflect", "reflected", "echoed", "sink", "xss")):
        evidence.add("input_or_reflection_observed")
    if any(marker in memory_text for marker in ("phpsessid", "set-cookie", "cookie", "jwt", "bearer", "authorization")):
        evidence.add("session_cookie_observed")
        evidence.add("auth_surface_observed")
    if any(marker in memory_text for marker in ("login", "signin", "sign-in", "register", "signup", "username", "password", "session")):
        evidence.add("auth_surface_observed")
    if any(marker in memory_text for marker in ("content-security-policy", "csp", "missing csp")):
        evidence.add("missing_csp_observed")
    if any(marker in memory_text for marker in ("sql", "database", "mysql", "postgres", "oracle", "sqlite", "syntax error", "union select")):
        evidence.add("sql_signal_observed")
    if any(marker in memory_text for marker in ("command injection", "shell", "rce", "ping", "exec")):
        evidence.add("command_surface_observed")
    if any(marker in memory_text for marker in ("upload", "multipart", "filename", "attachment")):
        evidence.add("upload_surface_observed")
    if any(marker in memory_text for marker in ("cors", "access-control-allow-origin")):
        evidence.add("cors_signal_observed")
    return evidence


def _scenario_missing_prerequisites(
    scenario: dict[str, Any],
    *,
    target_memory: dict[str, Any],
) -> list[str]:
    prerequisites = scenario.get("prerequisites", [])
    if not isinstance(prerequisites, list):
        return []
    required = [
        str(item or "").strip().lower()
        for item in prerequisites
        if str(item or "").strip()
    ]
    if not required:
        return []
    available = _memory_prerequisite_evidence(target_memory)
    return [item for item in required if item not in available]


def _build_target_memory_evidence_text(target_memory: dict[str, Any]) -> str:
    if not isinstance(target_memory, dict):
        return ""

    evidence_fragments: list[str] = []

    for key in (
        "overview",
        "tech_stack",
        "target_info",
        "profile",
        "checklist",
        "parameter_hints",
        "anonymous_routes",
        "authenticated_routes",
        "auth_surface_delta",
        "session_contexts",
        "blocked_routes",
        "blocked_route_prefixes",
    ):
        value = target_memory.get(key)
        if value is not None:
            evidence_fragments.append(json.dumps(value, ensure_ascii=True))

    verified_findings = target_memory.get("verified_findings", [])
    if isinstance(verified_findings, list):
        compact_findings: list[dict[str, Any]] = []
        for item in verified_findings[:40]:
            if not isinstance(item, dict):
                continue
            compact_findings.append(
                {
                    "title": str(item.get("title", "")).strip(),
                    "summary": str(item.get("summary", "")).strip(),
                    "status": str(item.get("status", "")).strip(),
                }
            )
        if compact_findings:
            evidence_fragments.append(json.dumps(compact_findings, ensure_ascii=True))

    tool_observations = target_memory.get("tool_observations", [])
    if isinstance(tool_observations, list):
        compact_observations: list[dict[str, Any]] = []
        for item in tool_observations[-80:]:
            if not isinstance(item, dict):
                continue
            compact_observations.append(
                {
                    "tool": str(item.get("tool", "")).strip(),
                    "scenario_task": str(item.get("scenario_task", "")).strip(),
                    "status": str(item.get("status", "")).strip(),
                }
            )
        if compact_observations:
            evidence_fragments.append(json.dumps(compact_observations, ensure_ascii=True))

    return "\n".join(fragment for fragment in evidence_fragments if fragment).lower()


def _scenario_has_unbacked_assumption(
    scenario: dict[str, Any],
    *,
    target_memory: dict[str, Any],
) -> bool:
    if not _scenario_requires_evidence_gate(scenario):
        return False

    evidence_tier = str(scenario.get("evidence_tier", "")).strip().lower()
    confidence_label = str(scenario.get("confidence_label", "")).strip().lower()
    missing_prereqs = _scenario_missing_prerequisites(
        scenario,
        target_memory=target_memory,
    )
    if evidence_tier == "confirmed" and missing_prereqs:
        return True
    if confidence_label == "low" and str(scenario.get("agent", "")).strip().lower() == "exploit":
        return True

    scenario_text = " ".join(
        str(part or "")
        for part in (
            scenario.get("task", ""),
            scenario.get("details", ""),
            " ".join(str(item or "") for item in scenario.get("methods", []) if isinstance(item, str))
            if isinstance(scenario.get("methods"), list)
            else "",
        )
    ).lower()
    memory_text = _build_target_memory_evidence_text(target_memory)
    observed_routes = {
        _normalize_route_token(item)
        for item in (
            (target_memory.get("anonymous_routes", []) if isinstance(target_memory.get("anonymous_routes"), list) else [])
            + (target_memory.get("authenticated_routes", []) if isinstance(target_memory.get("authenticated_routes"), list) else [])
            + _extract_routes_from_memory(target_memory)
        )
    }
    observed_routes = {item for item in observed_routes if item}

    route_tokens = _extract_route_tokens(
        scenario.get("endpoint", ""),
        scenario.get("task", ""),
        scenario.get("details", ""),
    )
    if route_tokens:
        route_matches = 0
        for route in route_tokens:
            lowered = route.lower()
            candidate_parts = [part for part in lowered.split("/") if part]
            for observed in observed_routes:
                observed_lower = observed.lower()
                observed_parts = [part for part in observed_lower.split("/") if part]
                if lowered == observed_lower:
                    route_matches += 1
                    break
                if lowered.startswith(observed_lower + "/") and len(observed_parts) >= min(2, len(candidate_parts)):
                    route_matches += 1
                    break
                if observed_lower.startswith(lowered + "/") and len(candidate_parts) >= min(2, len(observed_parts)):
                    route_matches += 1
                    break
            if route_matches > 0:
                continue
        if route_matches == 0 and (
            "login.php" in scenario_text
            or "vulnerabilities/" in scenario_text
            or "/graphql" in scenario_text
            or "/api/" in scenario_text
            or "/admin" in scenario_text
            or "/dvwa/" in scenario_text
        ):
            return True

        if (
            any("vulnerabilities/" in route.lower() for route in route_tokens)
            and not any(
                route.lower() in {observed.lower() for observed in observed_routes}
                for route in route_tokens
            )
        ):
            return True

    if ("security=low" in scenario_text or "security low" in scenario_text) and "security=low" not in memory_text and "security low" not in memory_text:
        return True

    if "phpsessid" in scenario_text and "phpsessid" not in memory_text:
        return True

    if ("default credential" in scenario_text or "login form" in scenario_text or "registration form" in scenario_text or "signup" in scenario_text or "register" in scenario_text) and not any(
        marker in memory_text
        for marker in ("login", "signin", "sign-in", "register", "signup", "sign-up", "/login", "/register", "username", "password")
    ):
        return True

    if ("missing csp" in scenario_text or "without csp" in scenario_text or "no csp" in scenario_text) and not any(
        marker in memory_text
        for marker in ("content-security-policy", "csp", "missing csp")
    ):
        return True

    return False


def _prune_plan_blocked_route_scenarios(
    plan_data: dict[str, Any],
    *,
    target_memory: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    if not isinstance(plan_data, dict) or not isinstance(target_memory, dict):
        return plan_data, 0
    blocked_routes = (
        target_memory.get("blocked_routes", [])
        if isinstance(target_memory.get("blocked_routes"), list)
        else []
    )
    blocked_route_prefixes = (
        target_memory.get("blocked_route_prefixes", [])
        if isinstance(target_memory.get("blocked_route_prefixes"), list)
        else []
    )
    if not blocked_routes and not blocked_route_prefixes:
        return plan_data, 0

    removed = 0
    phases = plan_data.get("phases", [])
    if not isinstance(phases, list):
        return plan_data, 0
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
            kept: list[dict[str, Any]] = []
            for scenario in scenarios:
                if not isinstance(scenario, dict):
                    continue
                if _scenario_references_blocked_route(
                    scenario,
                    blocked_routes=blocked_routes,
                    blocked_route_prefixes=blocked_route_prefixes,
                ):
                    removed += 1
                    continue
                kept.append(scenario)
            step["scenarios"] = kept
        phase["steps"] = [
            step for step in steps
            if isinstance(step, dict) and isinstance(step.get("scenarios"), list) and step.get("scenarios")
        ]
    plan_data["phases"] = [
        phase for phase in phases
        if isinstance(phase, dict) and isinstance(phase.get("steps"), list) and phase.get("steps")
    ]
    return plan_data, removed


def _prune_plan_unbacked_assumption_scenarios(
    plan_data: dict[str, Any],
    *,
    target_memory: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    if not isinstance(plan_data, dict) or not isinstance(target_memory, dict):
        return plan_data, 0
    phases = plan_data.get("phases", [])
    if not isinstance(phases, list):
        return plan_data, 0
    removed = 0
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
            kept: list[dict[str, Any]] = []
            for scenario in scenarios:
                if not isinstance(scenario, dict):
                    continue
                if _scenario_has_unbacked_assumption(scenario, target_memory=target_memory):
                    removed += 1
                    continue
                kept.append(scenario)
            step["scenarios"] = kept
        phase["steps"] = [
            step for step in steps
            if isinstance(step, dict) and isinstance(step.get("scenarios"), list) and step.get("scenarios")
        ]
    plan_data["phases"] = [
        phase for phase in phases
        if isinstance(phase, dict) and isinstance(phase.get("steps"), list) and phase.get("steps")
    ]
    return plan_data, removed


def _extract_parameter_hints_from_routes(routes: list[str]) -> list[str]:
    hints: list[str] = []
    seen: set[str] = set()
    for route in routes:
        parsed = urlparse(route if route.startswith("http") else f"https://example.invalid{route}")
        if parsed.query:
            for key in parsed.query.split("&"):
                name = str(key.split("=", 1)[0] or "").strip()
                if not name:
                    continue
                lowered = name.lower()
                if lowered in seen:
                    continue
                seen.add(lowered)
                hints.append(name)
    return hints[:40]


def _derive_tech_stack_from_memory(memory: dict[str, Any]) -> dict[str, str]:
    text = " ".join(_iter_memory_text_fragments(memory)).lower()
    tech_stack: dict[str, str] = {}

    framework_markers = {
        "django": "django",
        "flask": "flask",
        "fastapi": "fastapi",
        "spring": "spring",
        "express": "express",
        "next.js": "next.js",
        "nextjs": "next.js",
        "laravel": "laravel",
        "rails": "rails",
        "wordpress": "wordpress",
        "drupal": "drupal",
    }
    database_markers = {
        "postgresql": "postgresql",
        "postgres": "postgresql",
        "mysql": "mysql",
        "mariadb": "mysql",
        "mssql": "mssql",
        "sql server": "mssql",
        "mongodb": "mongodb",
        "sqlite": "sqlite",
        "oracle": "oracle",
    }
    frontend_markers = {
        "react": "react",
        "angular": "angular",
        "vue": "vue",
        "svelte": "svelte",
        "html5": "html5",
    }
    waf_markers = {
        "cloudflare": "cloudflare",
        "modsecurity": "modsecurity",
        "akamai": "akamai",
        "aws waf": "aws waf",
    }

    for marker, value in framework_markers.items():
        if marker in text:
            tech_stack["framework"] = value
            break
    for marker, value in database_markers.items():
        if marker in text:
            tech_stack["database"] = value
            break
    for marker, value in frontend_markers.items():
        if marker in text:
            tech_stack["frontend"] = value
            break
    for marker, value in waf_markers.items():
        if marker in text:
            tech_stack["waf"] = value
            break

    framework = tech_stack.get("framework", "")
    if framework in {"django", "flask", "fastapi"}:
        tech_stack["backend_language"] = "python"
    elif framework in {"spring"}:
        tech_stack["backend_language"] = "java"
    elif framework in {"express", "next.js"}:
        tech_stack["backend_language"] = "node"
    elif framework in {"laravel", "wordpress", "drupal"}:
        tech_stack["backend_language"] = "php"
    elif framework == "rails":
        tech_stack["backend_language"] = "ruby"

    server_match = re.search(r"\b(nginx(?:/[0-9.]+)?|apache(?:/[0-9.]+)?|iis(?:/[0-9.]+)?|caddy(?:/[0-9.]+)?)\b", text)
    if server_match:
        tech_stack["server"] = server_match.group(1)

    return tech_stack


def _apply_memory_enrichment(memory: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(memory, dict):
        return {}
    enriched = dict(memory)
    anonymous_routes = _extract_routes_from_memory(enriched)
    parameter_hints = _extract_parameter_hints_from_routes(anonymous_routes)
    tech_stack = _derive_tech_stack_from_memory(enriched)

    if anonymous_routes:
        enriched["anonymous_routes"] = anonymous_routes
    if parameter_hints:
        enriched["parameter_hints"] = parameter_hints
    if tech_stack:
        current = enriched.get("tech_stack", {})
        current_map = dict(current) if isinstance(current, dict) else {}
        current_map.update({key: value for key, value in tech_stack.items() if value})
        enriched["tech_stack"] = current_map
    return enriched


def _infer_payload_family_from_scenario(scenario: dict[str, Any]) -> str:
    text = " ".join(
        [
            str(scenario.get("task", "")).strip(),
            str(scenario.get("details", "")).strip(),
            " ".join(str(item) for item in scenario.get("methods", []) if str(item).strip())
            if isinstance(scenario.get("methods"), list)
            else "",
        ]
    ).lower()
    if "sql" in text or "sqli" in text:
        return "sqli"
    if "template" in text or "ssti" in text:
        return "ssti"
    if "xss" in text or "cross-site scripting" in text:
        return "xss"
    if "ssrf" in text or "server-side request forgery" in text:
        return "ssrf"
    return ""


async def _run_authenticated_surface_enrichment(
    *,
    project_cache_dir: str,
    target_memory: dict[str, Any],
    target: str,
    target_type: str,
    target_config: dict[str, Any] | None,
    tool_map: dict[str, Any],
) -> dict[str, Any]:
    manager, headers, cookies = _build_auth_runtime_context(
        target_type=target_type,
        target_config=target_config,
        target=target,
    )
    memory = dict(target_memory) if isinstance(target_memory, dict) else {}
    session_labels = manager.all_labels()
    if session_labels:
        memory["session_contexts"] = session_labels
    if not (headers or cookies):
        return memory

    crawler = tool_map.get("web_crawler")
    if crawler is None:
        return memory

    try:
        raw = await crawler.execute(
            tool="katana",
            target=target,
            args=["-jc"],
            headers=headers,
            cookies=cookies,
            max_results=200,
            timeout=60,
        )
        payload = json.loads(raw)
    except Exception:
        logger.warning("authenticated_crawl_failed", target=target, exc_info=True)
        return memory

    if not isinstance(payload, dict) or payload.get("success") is not True:
        return memory

    routes = [
        str(item).strip()
        for item in payload.get("urls", [])
        if str(item).strip()
    ] if isinstance(payload.get("urls"), list) else []
    if not routes:
        return memory

    anonymous_routes = memory.get("anonymous_routes", []) if isinstance(memory.get("anonymous_routes"), list) else []
    anonymous_seen = {str(item).strip().lower() for item in anonymous_routes if str(item).strip()}
    auth_delta = [route for route in routes if route.lower() not in anonymous_seen]
    memory["authenticated_routes"] = routes[:250]
    memory["auth_surface_delta"] = auth_delta[:120]
    parameter_hints = _extract_parameter_hints_from_routes(routes)
    if parameter_hints:
        combined_hints = list(dict.fromkeys((memory.get("parameter_hints", []) if isinstance(memory.get("parameter_hints"), list) else []) + parameter_hints))
        memory["parameter_hints"] = combined_hints[:40]
    return memory


def _build_tool_observation_entries(
    *,
    scenario: dict[str, Any],
    row_result: dict[str, Any],
    status: str,
    confidence: Any,
    false_positive_count: int = 0,
) -> list[dict[str, Any]]:
    tool_names = _extract_tool_names(row_result.get("tool_results", []))
    if not tool_names:
        return []
    observations: list[dict[str, Any]] = []
    normalized_confidence = _coerce_confidence(confidence)
    for tool_name in tool_names:
        observations.append(
            {
                "tool": tool_name,
                "scenario_task": str(scenario.get("task", "")).strip(),
                "status": status,
                "confidence": normalized_confidence if normalized_confidence is not None else 0.0,
                "false_positive_count": int(false_positive_count or 0),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    return observations


def _infer_cloud_provider(*values: Any) -> str:
    text = " ".join(str(value or "") for value in values).lower()
    if any(marker in text for marker in ("aws", "amazon", "s3://", "cloudfront", ".amazonaws.com")):
        return "aws"
    if any(marker in text for marker in ("azure", "blob.core.windows.net", "azurecr.io")):
        return "azure"
    if any(marker in text for marker in ("gcp", "google cloud", "gs://", "gcr.io")):
        return "gcp"
    return ""


def _build_target_info_tool_kwargs(
    tool_name: str,
    target: str,
    target_type: str,
    info: str,
    memory: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    normalized_type = _normalize_target_type(target_type)
    host = _extract_target_host(target)
    runtime_state = memory.get("target_runtime", {}) if isinstance(memory, dict) else {}
    repo_checkout_path = (
        str(runtime_state.get("repository_checkout_path", "")).strip()
        if isinstance(runtime_state, dict)
        else ""
    )
    target_text = repo_checkout_path if normalized_type == "repository" and repo_checkout_path else str(target or "").strip()
    repo_like = normalized_type == "repository" or os.path.exists(target_text)
    mobile_artifact = target_text.lower().endswith((".apk", ".ipa", ".aab"))
    container_artifact = bool(re.search(r"(dockerfile|\.tar$|:[A-Za-z0-9._-]+$|/)", target_text, re.IGNORECASE))
    firmware_artifact = target_text.lower().endswith((".bin", ".img", ".fw", ".firmware"))

    if tool_name == "passive_web_recon":
        if not host:
            return None, "skipped: passive recon requires a hostname or domain"
        return {
            "target": host,
            "include_subdomains": True,
            "include_historical_urls": True,
            "max_urls": 120,
            "threads": 4,
        }, None
    if tool_name == "dns_recon":
        if not host:
            return None, "skipped: DNS recon requires a hostname or domain"
        return {"target": host, "mode": "records", "output_format": "text", "timeout": 90}, None
    if tool_name == "http_probe":
        return {"target": target_text, "args": ["-follow-redirects"], "use_cache": True, "timeout": 120}, None
    if tool_name == "detect_tech":
        return {"tool": "whatweb", "target": target_text, "use_cache": True}, None
    if tool_name == "known_vuln_lookup":
        raw_inventory = memory.get("tech_inventory", []) if isinstance(memory, dict) and isinstance(memory.get("tech_inventory"), list) else []
        products: list[dict[str, Any]] = []
        for item in raw_inventory:
            if not isinstance(item, dict):
                continue
            product = str(item.get("product", "")).strip()
            confidence = str(item.get("confidence_label", "")).strip().lower()
            version = str(item.get("version_normalized", item.get("version", ""))).strip()
            source_count = int(item.get("source_count", 0) or 0)
            if not product:
                continue
            if confidence == "low" and not version and source_count < 2:
                continue
            products.append(
                {
                    "product": product,
                    "version": version,
                    "confidence_label": confidence or "medium",
                    "source_count": source_count,
                    "kb_query": str(item.get("kb_query", "")).strip(),
                }
            )
        if not products:
            return None, "skipped: no corroborated product/version fingerprints available for known-vulnerability lookup"
        return {
            "products": products[:8],
            "target_type": normalized_type or target_type,
            "severity": "HIGH",
            "max_results_per_product": 4,
        }, None
    if tool_name == "http_header_analysis":
        return {"tool": "manual", "target": target_text, "methods": ["GET"]}, None
    if tool_name == "web_crawler":
        return {"tool": "katana", "target": target_text, "args": ["-jc"], "max_results": 150, "timeout": 60}, None
    if tool_name == "api_endpoint_discovery":
        return {"tool": "manual", "target": target_text, "compact_output": True}, None
    if tool_name == "api_passive_enum":
        return {"target": target_text}, None
    if tool_name == "js_source_code_analyzer":
        return {"tool": "getjs", "target": target_text}, None
    if tool_name == "cors_misconfig_check":
        return {
            "tool": "manual",
            "target": target_text,
            "origins": ["https://example.com", "https://evil.example"],
            "use_cache": True,
            "timeout": 60,
        }, None
    if tool_name == "session_token_analysis":
        return {"target": target_text, "sample_count": 5, "verify_tls": True, "timeout": 20}, None
    if tool_name == "mobile_static_analysis":
        if not mobile_artifact:
            return None, "skipped: mobile static analysis requires an APK/IPA/AAB target artifact"
        return {"tool": "manual", "target": target_text, "platform": "auto"}, None
    if tool_name == "mobile_storage_check":
        if not mobile_artifact:
            return None, "skipped: mobile storage checks require an extracted mobile artifact or app context"
        platform = "ios" if target_text.lower().endswith(".ipa") else "android"
        return {"platform": platform, "checks": ["shared_prefs", "sqlite"]}, None
    if tool_name == "nmap_scan":
        if not host:
            return None, "skipped: service inventory requires a host or IP target"
        return {"target": host, "scan_mode": "tcp", "top_ports": 100, "output_format": "text", "timeout": 120}, None
    if tool_name == "route_topology":
        if not host:
            return None, "skipped: route topology requires a host target"
        return {"target": host, "output_format": "text"}, None
    if tool_name == "arp_scan":
        return None, "skipped: arp scan requires a local broadcast-domain execution context"
    if tool_name == "iot_protocol_scan":
        if not host:
            return None, "skipped: IoT protocol scan requires a host target"
        return {"target": host, "protocols": ["mqtt", "coap", "modbus"]}, None
    if tool_name == "firmware_analysis":
        if not firmware_artifact:
            return None, "skipped: firmware analysis requires a firmware image target"
        return {"firmware_path": target_text, "tools": ["strings"]}, None
    if tool_name == "linux_config_audit":
        if host:
            return {"target": host, "mode": "quick", "timeout": 120}, None
        return None, "skipped: linux audit requires a host target"
    if tool_name == "db_enum_and_audit":
        if not host:
            return None, "skipped: database exposure checks require a host target"
        return {"target": host, "timeout": 20, "max_workers": 10}, None
    if tool_name == "binary_analysis":
        if not os.path.exists(target_text):
            return None, "skipped: binary analysis requires a local desktop artifact"
        return {"target": target_text}, None
    if tool_name == "cloud_storage_enum":
        if not target_text:
            return None, "skipped: cloud storage enumeration requires a keyword or target identifier"
        return {"target": host or target_text}, None
    if tool_name == "cloud_misconfig_scan":
        provider = _infer_cloud_provider(target_text, info)
        if not provider:
            return None, "skipped: cloud provider could not be inferred from target info"
        return {"tool": "scoutsuite", "provider": provider}, None
    if tool_name == "container_image_scan":
        if not container_artifact:
            return None, "skipped: container image scan requires an image ref, tarball, or Dockerfile"
        return {"tool": "syft", "target": target_text, "scan_type": "sbom"}, None
    if tool_name == "container_layer_analysis":
        if not container_artifact:
            return None, "skipped: container layer analysis requires an image ref or tarball"
        return {"target": target_text, "include_secrets": True, "timeout": 120}, None
    if tool_name == "container_runtime_audit":
        return {"tool": "custom", "target": "local"}, None
    if tool_name == "container_registry_enum":
        if not target_text:
            return None, "skipped: registry enumeration requires a registry-like target"
        return {"target": target_text, "registry_type": "auto", "timeout": 60}, None
    if tool_name == "secret_scan":
        if not repo_like:
            return None, "skipped: secret scanning requires a repository path or URL"
        return {"tool": "gitleaks", "target": target_text, "scan_scope": "repo"}, None
    if tool_name == "git_history_audit":
        if not repo_like:
            return None, "skipped: git history audit requires a repository path"
        return {"target": target_text, "analysis_depth": "quick", "include_deleted": True, "timeout": 120}, None
    if tool_name == "sensitive_files_scan":
        if not repo_like:
            return None, "skipped: sensitive file scanning requires a repository or directory target"
        return {"target": target_text, "include_backups": True, "include_ide_config": True, "timeout": 120}, None
    if tool_name == "sast_scan":
        if not repo_like:
            return None, "skipped: SAST requires a repository or source path"
        return {"tool": "semgrep", "target": target_text, "language": "auto", "scan_type": "security"}, None
    if tool_name == "dependency_scan":
        if not repo_like:
            return None, "skipped: dependency scanning requires a repository or manifest path"
        return {"tool": "safety", "target": target_text, "ecosystem": "auto", "scan_type": "vuln"}, None
    if tool_name == "ci_cd_pipeline_audit":
        if not repo_like:
            return None, "skipped: CI/CD audit requires a repository or config path"
        return {"target": target_text, "platform": "auto", "include_secrets": True, "timeout": 120}, None
    if tool_name == "iac_security_scan":
        if not repo_like:
            return None, "skipped: IaC audit requires a repository or manifest path"
        return {"tool": "checkov", "target": target_text, "include_secrets": True, "timeout": 120}, None
    return None, f"skipped: no deterministic target-info runner configured for {tool_name}"


async def _run_target_info_gathering(
    *,
    project_id: str,
    scan_id: str,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    profile: dict[str, Any],
    project_cache_dir: str,
    progress_callback: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    from server.agents.executer.recon.tools import ALL_RECON_TOOLS
    from server.agents.executer.target_tool_routing import filter_tools_for_target_types

    normalized_type = _normalize_target_type(target_type)
    scoped_tools = filter_tools_for_target_types(
        role="recon",
        tools=ALL_RECON_TOOLS,
        target_types=[normalized_type],
    )
    tool_map = {tool.name: tool for tool in scoped_tools}
    blocks = profile.get("blocks", []) if isinstance(profile, dict) else []
    memory_llm = SystemMemoryLLM()
    memory = _initialize_system_memory(
        project_id=project_id,
        scan_id=scan_id,
        target=target,
        target_type=normalized_type,
        scope=scope,
        info=info,
        profile=profile,
    )
    memory = await _save_target_memory(
        project_cache_dir,
        memory,
        memory_llm=memory_llm,
    )

    valid_blocks = [block for block in blocks if isinstance(block, dict)]

    for index, block in enumerate(valid_blocks, start=1):
        if not isinstance(block, dict):
            continue
        block_name = str(block.get("name", "")).strip()
        prepared_block = await memory_llm.prepare_block(
            target=target,
            target_type=normalized_type,
            scope=scope,
            info=info,
            block=block,
        )
        prepared_name = str(prepared_block.get("name", block_name)).strip() or block_name
        if progress_callback:
            progress_callback(
                "block_started",
                {
                    "id": str(prepared_block.get("id", block.get("id", ""))).strip(),
                    "name": prepared_name,
                    "goal": str(prepared_block.get("goal", block.get("goal", ""))).strip(),
                    "index": index,
                    "total": len(valid_blocks),
                    "planned_tools": [
                        str(item).strip()
                        for item in prepared_block.get("tools", [])
                        if str(item).strip()
                    ],
                },
            )
        tool_names = [str(item).strip() for item in prepared_block.get("tools", []) if str(item).strip()]
        result_rows: list[dict[str, Any]] = []
        for tool_name in tool_names:
            kwargs, skip_reason = _build_target_info_tool_kwargs(
                tool_name=tool_name,
                target=target,
                target_type=normalized_type,
                info=info,
                memory=memory,
            )
            if skip_reason:
                result_rows.append({
                    "tool": tool_name,
                    "status": "skipped",
                    "summary": skip_reason,
                    "args": kwargs or {},
                })
                continue
            tool = tool_map.get(tool_name)
            if tool is None or kwargs is None:
                result_rows.append({
                    "tool": tool_name,
                    "status": "skipped",
                    "summary": "skipped: tool is not registered for this target type",
                    "args": kwargs or {},
                })
                continue
            try:
                raw_result = await tool.execute(**kwargs)
                summary = _compact_tool_output(raw_result)
                result_rows.append({
                    "tool": tool_name,
                    "status": "completed",
                    "summary": summary,
                    "args": kwargs,
                })
            except Exception as exc:
                result_rows.append({
                    "tool": tool_name,
                    "status": "error",
                    "summary": f"error: {str(exc)[:240]}",
                    "args": kwargs,
                })
        organized_block = await memory_llm.organize_block(
            target=target,
            target_type=normalized_type,
            scope=scope,
            info=info,
            block=prepared_block,
            raw_results=result_rows,
        )
        gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
        block_rows = gathering.get("blocks", []) if isinstance(gathering.get("blocks"), list) else []
        block_rows.append(organized_block)
        gathering["blocks"] = block_rows
        gathering["status"] = "running"
        memory["gathering"] = gathering
        _merge_target_memory_artifacts(
            memory,
            organized_block.get("name"),
            organized_block.get("goal"),
            organized_block.get("summary"),
            *(organized_block.get("artifacts", []) if isinstance(organized_block.get("artifacts"), list) else []),
        )
        for result in organized_block.get("results", []) if isinstance(organized_block.get("results"), list) else []:
            if not isinstance(result, dict):
                continue
            _merge_target_memory_artifacts(memory, result.get("summary"), *(result.get("artifacts", []) or []))
        memory = await _save_target_memory(
            project_cache_dir,
            memory,
            memory_llm=memory_llm,
        )
        if progress_callback:
            progress_callback(
                "block_completed",
                {
                    "id": str(organized_block.get("id", "")).strip(),
                    "name": str(organized_block.get("name", "")).strip(),
                    "status": str(organized_block.get("status", "")).strip(),
                    "summary": str(organized_block.get("summary", "")).strip(),
                    "index": index,
                    "total": len(valid_blocks),
                },
            )

    gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
    gathering["status"] = "completed"
    memory["gathering"] = gathering
    return await _save_target_memory(
        project_cache_dir,
        memory,
        memory_llm=memory_llm,
    )


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


def _merge_nested_records(
    base: dict[str, Any] | None,
    override: dict[str, Any] | None,
) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base) if isinstance(base, dict) else {}
    if not isinstance(override, dict):
        return merged
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_nested_records(
                merged.get(key) if isinstance(merged.get(key), dict) else {},
                value,
            )
        else:
            merged[key] = value
    return merged


def _merge_scan_metadata(
    existing_last_scan: dict[str, Any] | None,
    scan_meta: dict[str, Any] | None,
) -> dict[str, Any]:
    existing = existing_last_scan if isinstance(existing_last_scan, dict) else {}
    incoming = scan_meta if isinstance(scan_meta, dict) else {}
    incoming_scan_id = str(incoming.get("scanId", "")).strip()
    existing_scan_id = str(existing.get("scanId", "")).strip()

    # A fresh scan must not inherit planner/checklist/result payloads from a
    # previous scan on the same project record.
    if incoming_scan_id and incoming_scan_id != existing_scan_id:
        merged = deepcopy(incoming)
    else:
        existing_started = existing.get("startedAt")
        incoming_started = incoming.get("startedAt")
        
        merged = _merge_nested_records(existing, incoming)
        
        if existing_started and incoming_started:
            try:
                from datetime import datetime
                existing_dt = datetime.fromisoformat(existing_started.replace("Z", "+00:00"))
                incoming_dt = datetime.fromisoformat(incoming_started.replace("Z", "+00:00"))
                if existing_dt > incoming_dt:
                    merged["startedAt"] = existing_started
            except Exception:
                pass

    result = merged.get("result", {})
    if not isinstance(result, dict):
        result = {}
    merged["result"] = result
    return merged


def _compute_scan_elapsed_seconds(scan_meta: dict[str, Any]) -> int:
    if not isinstance(scan_meta, dict):
        return 0

    started_at_raw = str(scan_meta.get("startedAt", "") or "").strip()
    if not started_at_raw:
        return max(0, int(scan_meta.get("elapsedSeconds", 0) or 0))

    try:
        started_at = datetime.fromisoformat(started_at_raw.replace("Z", "+00:00"))
    except ValueError:
        return max(0, int(scan_meta.get("elapsedSeconds", 0) or 0))

    finished_at_raw = str(
        scan_meta.get("finishedAt", "") or scan_meta.get("completedAt", "") or ""
    ).strip()
    if finished_at_raw:
        try:
            finished_at = datetime.fromisoformat(finished_at_raw.replace("Z", "+00:00"))
        except ValueError:
            finished_at = datetime.now(timezone.utc)
    else:
        finished_at = datetime.now(timezone.utc)

    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    if finished_at.tzinfo is None:
        finished_at = finished_at.replace(tzinfo=timezone.utc)

    elapsed_seconds = int(max(0.0, (finished_at - started_at).total_seconds()))
    return elapsed_seconds


def _started_at_for_elapsed(now_iso: str, elapsed_seconds: int) -> str:
    """Return a start timestamp that preserves accumulated scan runtime on resume."""
    elapsed = max(0, int(elapsed_seconds or 0))
    if elapsed <= 0:
        return now_iso
    try:
        now = datetime.fromisoformat(str(now_iso).replace("Z", "+00:00"))
    except ValueError:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return (now - timedelta(seconds=elapsed)).isoformat()


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


def _ensure_intel_node_importable() -> None:
    """Raise a clear runtime error when Intel node deps are missing."""
    try:
        from server.nodes.intel.node import IntelNode as _IntelNode  # noqa: F401
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
    if 1 <= p <= 6:
        return p
    return None


def _normalize_priority(value: Any) -> int:
    parsed = _coerce_priority(value)
    return parsed if parsed is not None else 3


def _priority_sort_key(priority: int) -> tuple[int, int]:
    normalized = _normalize_priority(priority)
    return (1, normalized)


def _evidence_tier_sort_value(value: Any) -> int:
    normalized = str(value or "").strip().lower()
    return {
        "confirmed": 3,
        "observed": 2,
        "hypothesized": 1,
    }.get(normalized, 1)


def _confidence_label_sort_value(value: Any) -> int:
    normalized = str(value or "").strip().lower()
    return {
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(normalized, 1)


def _display_cycle_number(cycle_number: int, *, prior_cycles: int = 0) -> int:
    try:
        normalized_cycle = int(cycle_number)
    except (TypeError, ValueError):
        normalized_cycle = 1
    try:
        normalized_prior = int(prior_cycles)
    except (TypeError, ValueError):
        normalized_prior = 0
    return max(1, normalized_cycle + max(0, normalized_prior))


_SCENARIO_FAMILY_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqli", ("sql injection", "sqli", "union select", "boolean-based", "time-based", "sql error")),
    ("command_injection", ("command injection", "os command", "rce", "remote code execution", "commix", "shell payload")),
    ("code_injection", ("code injection", "eval(", "/eval", "template injection", "ssti", "deserialization", "php object injection")),
    ("xxe", ("xxe", "xml external entity", "<!doctype", "xml parser", "svg upload", "soap xml")),
    ("ssrf", ("ssrf", "server-side request forgery", "169.254.169.254", "metadata endpoint", "internal ip", "localhost fetch")),
    ("file_inclusion", ("lfi", "rfi", "file inclusion", "path traversal", "directory traversal", "/etc/passwd", "php://input", ".env")),
    ("auth_bypass", ("auth bypass", "authentication bypass", "login bypass", "default credential", "password reset bypass")),
    ("idor", ("idor", "insecure direct object reference", "mass assignment", "access control bypass", "forced browsing")),
    ("upload_abuse", ("file upload", "upload bypass", "multipart", "polyglot upload", "web shell upload")),
    ("xss", ("xss", "cross-site scripting", "dom xss", "reflected xss", "stored xss")),
    ("session_abuse", ("session fixation", "session hijacking", "cookie theft", "jwt", "phpsessid")),
    ("csrf", ("csrf", "cross-site request forgery", "origin bypass", "same-site request")),
    ("header_injection", ("header injection", "x-forwarded-for", "host header", "referer", "user-agent", "injected_header")),
    ("dependency_cve", ("dependency", "third-party", "javascript library", "tailwind", "popper", "alpine", "fathom", "known cve", "cve scan")),
    ("info_disclosure", ("readme", "documentation", "phpinfo", "config file", "backup file", "directory listing")),
)

_SCENARIO_FAMILY_STRENGTH: dict[str, int] = {
    "sqli": 10,
    "command_injection": 10,
    "code_injection": 9,
    "xxe": 9,
    "ssrf": 9,
    "file_inclusion": 8,
    "auth_bypass": 8,
    "idor": 8,
    "upload_abuse": 8,
    "xss": 7,
    "session_abuse": 6,
    "info_disclosure": 5,
    "csrf": 4,
    "header_injection": 3,
    "dependency_cve": 2,
    "generic_recon": 5,
}

_LOW_SIGNAL_SCENARIO_FAMILIES = {"header_injection", "csrf", "dependency_cve"}
_REPEAT_FAILURE_STATUSES = {
    "blocked",
    "failed",
    "unknown",
    "inconclusive",
    "not_vulnerable",
    "false_positive",
}
_SUCCESSFUL_SCENARIO_STATUSES = {
    "complete",
    "completed",
    "success",
    "succeeded",
    "vulnerable",
    "real_vulnerability",
    "confirmed",
    "verified",
}


def _scenario_text_blob(scenario: dict[str, Any]) -> str:
    return " ".join(
        str(part or "")
        for part in (
            scenario.get("task", ""),
            scenario.get("details", ""),
            scenario.get("endpoint", ""),
            " ".join(str(item or "") for item in scenario.get("methods", []) if isinstance(item, str))
            if isinstance(scenario.get("methods"), list)
            else "",
        )
    ).lower()


def _scenario_family_tags(scenario: dict[str, Any]) -> list[str]:
    text = _scenario_text_blob(scenario)
    tags: list[str] = []
    for family, markers in _SCENARIO_FAMILY_PATTERNS:
        if any(marker in text for marker in markers):
            tags.append(family)
    if not tags:
        return ["generic_recon"]
    return tags


def _scenario_primary_family(scenario: dict[str, Any]) -> str:
    tags = _scenario_family_tags(scenario)
    return tags[0] if tags else "generic_recon"


def _scenario_family_strength(scenario: dict[str, Any]) -> int:
    return max(
        (_SCENARIO_FAMILY_STRENGTH.get(tag, _SCENARIO_FAMILY_STRENGTH["generic_recon"]) for tag in _scenario_family_tags(scenario)),
        default=_SCENARIO_FAMILY_STRENGTH["generic_recon"],
    )


def _build_family_history_stats(plan_data: dict[str, Any]) -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = {}
    for scenario in _iter_plan_scenarios(plan_data):
        if not isinstance(scenario, dict):
            continue
        family = _scenario_primary_family(scenario)
        bucket = stats.setdefault(
            family,
            {"attempts": 0, "failures": 0, "successes": 0},
        )
        history = scenario.get("execution_history", [])
        if not isinstance(history, list):
            history = []
        for entry in history:
            if not isinstance(entry, dict):
                continue
            bucket["attempts"] += 1
            status = str(entry.get("status", "")).strip().lower()
            if status in _SUCCESSFUL_SCENARIO_STATUSES:
                bucket["successes"] += 1
            elif status in _REPEAT_FAILURE_STATUSES:
                bucket["failures"] += 1
    return stats


def _scenario_repeat_penalty(
    scenario: dict[str, Any],
    *,
    family_stats: dict[str, dict[str, int]],
) -> int:
    history = scenario.get("execution_history", [])
    if not isinstance(history, list):
        history = []

    failures = 0
    successes = 0
    for entry in history:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status", "")).strip().lower()
        if status in _SUCCESSFUL_SCENARIO_STATUSES:
            successes += 1
        elif status in _REPEAT_FAILURE_STATUSES:
            failures += 1

    family = _scenario_primary_family(scenario)
    family_bucket = family_stats.get(family, {})
    family_failures = int(family_bucket.get("failures", 0) or 0)
    family_successes = int(family_bucket.get("successes", 0) or 0)
    scenario_text = _scenario_text_blob(scenario)

    penalty = 0
    if failures >= 1 and successes == 0:
        penalty += 1
    if failures >= 2 and successes == 0:
        penalty += 1
    if family_failures >= 3 and family_successes == 0:
        penalty += 1
    if (
        any(marker in scenario_text for marker in ("re-test", "retest", "refined payload", "alternative payload"))
        and failures >= 1
        and successes == 0
    ):
        penalty += 1
    return penalty


def _scenario_effective_priority(
    scenario: dict[str, Any],
    *,
    family_stats: dict[str, dict[str, int]],
) -> int:
    priority = _normalize_priority(scenario.get("priority", 3))
    family = _scenario_primary_family(scenario)
    strength = _scenario_family_strength(scenario)
    evidence_tier = str(scenario.get("evidence_tier", "")).strip().lower()
    confidence_label = str(scenario.get("confidence_label", "")).strip().lower()
    repeat_penalty = _scenario_repeat_penalty(scenario, family_stats=family_stats)

    adjusted = priority
    if strength >= 9 and evidence_tier in {"observed", "confirmed"}:
        adjusted -= 1
    elif strength >= 8 and confidence_label == "high":
        adjusted -= 1

    if family in _LOW_SIGNAL_SCENARIO_FAMILIES and evidence_tier == "hypothesized":
        adjusted += 1
    if family in {"dependency_cve", "header_injection"} and confidence_label != "high":
        adjusted += 1

    adjusted += repeat_penalty
    return max(1, min(6, adjusted))


def _normalize_execution_slot(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed in {1, 2} else None


def _extract_prioritized_exec_scenarios(
    plan_data: dict[str, Any],
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    phases = plan_data.get("phases", [])
    if not isinstance(phases, list):
        return []

    family_stats = _build_family_history_stats(plan_data)
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
                enriched["active_slot"] = _normalize_execution_slot(enriched.get("active_slot"))
                enriched["_family_tags"] = _scenario_family_tags(enriched)
                enriched["_primary_family"] = _scenario_primary_family(enriched)
                enriched["_family_strength"] = _scenario_family_strength(enriched)
                enriched["_repeat_penalty"] = _scenario_repeat_penalty(
                    enriched,
                    family_stats=family_stats,
                )
                enriched["_effective_priority"] = _scenario_effective_priority(
                    enriched,
                    family_stats=family_stats,
                )
                indexed.append((priority, phase_idx, step_idx, scen_idx, enriched))

    indexed.sort(
        key=lambda row: (
            _priority_sort_key(row[4].get("_effective_priority", row[0])),
            row[4].get("_repeat_penalty", 0),
            -int(row[4].get("_family_strength", 0) or 0),
            -_evidence_tier_sort_value(row[4].get("evidence_tier")),
            -_confidence_label_sort_value(row[4].get("confidence_label")),
            row[1],
            row[2],
            row[3],
        )
    )
    return [row[4] for row in indexed[: max(0, int(limit))]]


def _ensure_execution_slots(plan_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize the plan so at most two pending recon/exploit scenarios hold active slots."""

    phases = plan_data.get("phases", [])
    if not isinstance(phases, list):
        return plan_data

    pending: list[dict[str, Any]] = []
    slotted: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    used_slots: set[int] = set()

    for phase in phases:
        if not isinstance(phase, dict):
            continue
        for step in phase.get("steps", []):
            if not isinstance(step, dict):
                continue
            for scenario in step.get("scenarios", []):
                if not isinstance(scenario, dict):
                    continue
                agent = str(scenario.get("agent", "")).strip().lower()
                scenario["active_slot"] = _normalize_execution_slot(scenario.get("active_slot"))
                if agent not in {"recon", "exploit"}:
                    scenario["active_slot"] = None
                    continue
                if bool(scenario.get("done", False)):
                    scenario["active_slot"] = None
                    continue
                pending.append(scenario)
                slot = _normalize_execution_slot(scenario.get("active_slot"))
                key = (
                    agent,
                    str(scenario.get("task", "")).strip().lower(),
                )
                if slot is None or not key[1]:
                    continue
                if slot in used_slots or key in seen_keys:
                    scenario["active_slot"] = None
                    continue
                used_slots.add(slot)
                seen_keys.add(key)
                slotted.append(scenario)

    if len(slotted) < 2:
        for scenario in pending:
            key = (
                str(scenario.get("agent", "")).strip().lower(),
                str(scenario.get("task", "")).strip().lower(),
            )
            if not key[1] or key in seen_keys:
                continue
            next_slot = 1 if 1 not in used_slots else 2
            scenario["active_slot"] = next_slot
            used_slots.add(next_slot)
            seen_keys.add(key)
            slotted.append(scenario)
            if len(slotted) >= 2:
                break

    slotted_ids = {id(item) for item in slotted}
    for scenario in pending:
        key = (
            str(scenario.get("agent", "")).strip().lower(),
            str(scenario.get("task", "")).strip().lower(),
        )
        slot = _normalize_execution_slot(scenario.get("active_slot"))
        if slot is None:
            continue
        if key not in seen_keys or id(scenario) not in slotted_ids:
            scenario["active_slot"] = None

    return plan_data


def _select_recon_exploit_parallel_scenarios(plan_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Pick up to two runnable-now scenarios, preferring explicit active slots."""

    plan_data = _ensure_execution_slots(plan_data)
    candidates = _extract_prioritized_exec_scenarios(plan_data, limit=50)
    seen_keys: set[tuple[str, str]] = set()
    runnable_now: list[dict[str, Any]] = []
    for scenario in candidates:
        if _normalize_execution_slot(scenario.get("active_slot")) is None:
            continue
        scenario_key = (
            str(scenario.get("agent", "")).strip().lower(),
            str(scenario.get("task", "")).strip().lower(),
        )
        if not scenario_key[1] or scenario_key in seen_keys:
            continue
        seen_keys.add(scenario_key)
        runnable_now.append(scenario)
        if len(runnable_now) >= 2:
            break
    if runnable_now:
        runnable_now.sort(
            key=lambda s: (
                _normalize_execution_slot(s.get("active_slot")) or 99,
                _priority_sort_key(int(s.get("_effective_priority", _normalize_priority(s.get("priority", 3))))),
            )
        )
        return runnable_now

    fallback: list[dict[str, Any]] = []
    seen_keys.clear()
    for scenario in candidates:
        if not isinstance(scenario, dict):
            continue
        scenario_key = (
            str(scenario.get("agent", "")).strip().lower(),
            str(scenario.get("task", "")).strip().lower(),
        )
        if not scenario_key[1] or scenario_key in seen_keys:
            continue
        seen_keys.add(scenario_key)
        fallback.append(scenario)
        if len(fallback) >= 2:
            break
    fallback.sort(
        key=lambda s: (
            _priority_sort_key(int(s.get("_effective_priority", _normalize_priority(s.get("priority", 3))))),
            int(s.get("_repeat_penalty", 0) or 0),
            -int(s.get("_family_strength", 0) or 0),
            -_evidence_tier_sort_value(s.get("evidence_tier")),
            -_confidence_label_sort_value(s.get("confidence_label")),
        )
    )
    return fallback


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

    if not os.path.exists(file_path):
        logger.info(
            "Legacy static recon file unavailable; skipping file-backed warmup scenarios",
            file=file_name,
            target_type=normalized,
        )
        return []

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


_LOCAL_WARMUP_EXTERNAL_TERMS = (
    "external perimeter",
    "public perimeter",
    "organizational footprint",
    "subdomain",
    "cloud asset",
    "cdn",
    "asn",
    "osint",
)


def _adapt_warmup_scenario_for_target(
    scenario: dict[str, Any],
    *,
    target: str,
) -> dict[str, Any]:
    del target
    return dict(scenario)


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


def _build_default_target_info_profile(target_type: str) -> dict[str, Any]:
    normalized = _normalize_target_type(target_type)
    defaults = load_target_info_profile_defaults()
    blocks = deepcopy(defaults.get(normalized, defaults["web_app"]))
    return {
        "target_type": normalized,
        "version": "1.0",
        "generated_from": "static_target_info_profile",
        "max_blocks": len(blocks),
        "blocks": blocks,
    }


def _is_user_managed_target_info_profile(profile: dict[str, Any]) -> bool:
    generated_from = str(profile.get("generated_from", "")).strip().lower()
    return generated_from in {"ui", "ui_settings", "user", "manual"}


def _canonical_target_info_blocks(profile: dict[str, Any]) -> str:
    blocks = profile.get("blocks", []) if isinstance(profile, dict) else []
    if not isinstance(blocks, list):
        blocks = []
    return json.dumps(blocks, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _should_refresh_target_info_profile_from_defaults(
    stored_profile: dict[str, Any],
    built_in_profile: dict[str, Any],
) -> bool:
    if _is_user_managed_target_info_profile(stored_profile):
        return False

    stored_blocks = stored_profile.get("blocks", [])
    built_in_blocks = built_in_profile.get("blocks", [])
    if not isinstance(stored_blocks, list) or not stored_blocks:
        return True
    if not isinstance(built_in_blocks, list) or not built_in_blocks:
        return False

    return _canonical_target_info_blocks(stored_profile) != _canonical_target_info_blocks(built_in_profile)


def _resolve_target_info_profile(projects_store: Any, target_type: str) -> dict[str, Any]:
    normalized = _normalize_target_type(target_type)
    built_in = _build_default_target_info_profile(normalized)
    try:
        stored = projects_store.get_target_info_profile(normalized)
    except Exception:
        stored = None
    if isinstance(stored, dict):
        if _should_refresh_target_info_profile_from_defaults(stored, built_in):
            try:
                return projects_store.upsert_target_info_profile(
                    target_type=normalized,
                    payload=built_in,
                )
            except Exception:
                return built_in

        stored.setdefault("target_type", normalized)
        stored.setdefault("version", "1.0")
        stored.setdefault("generated_from", "database")
        blocks = stored.get("blocks", [])
        stored["blocks"] = blocks if isinstance(blocks, list) else list(built_in.get("blocks", []))
        return stored
    try:
        return projects_store.upsert_target_info_profile(
            target_type=normalized,
            payload=built_in,
        )
    except Exception:
        return built_in


def _format_target_info_profile_for_prompt(profile: dict[str, Any]) -> str:
    blocks = profile.get("blocks", []) if isinstance(profile, dict) else []
    if not isinstance(blocks, list) or not blocks:
        return "(no target-info gathering profile available)"
    lines: list[str] = []
    for idx, block in enumerate(blocks, start=1):
        if not isinstance(block, dict):
            continue
        name = str(block.get("block_name") or block.get("name") or "").strip()
        goal = str(block.get("goal", "")).strip()
        interaction = str(block.get("interaction", "")).strip()
        
        tools_list = []
        for item in block.get("tools", []):
            if isinstance(item, dict):
                # Format object like run_custom(binary, arg1, arg2)
                t_name = str(item.get("name") or item.get("tool") or "custom").strip()
                t_args = item.get("args", [])
                if not isinstance(t_args, list):
                    t_args = [t_args]
                args_str = ", ".join(map(str, t_args))
                tools_list.append(f"{t_name}({args_str})")
            else:
                tools_list.append(str(item).strip())
        
        tools = ", ".join(t for t in tools_list if t)
        if name:
            lines.append(
                f"{idx}. {name} [{interaction or 'unspecified'}] :: {goal or '(no goal)'}"
                + (f" | tools: {tools}" if tools else "")
            )
    return "\n".join(lines) if lines else "(no target-info gathering profile available)"


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
        scenario = _adapt_warmup_scenario_for_target(scenario, target=target)
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
    target_info_profile: dict[str, Any],
    target_memory: dict[str, Any] | None = None,
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
        "## Structured Target-Info Gathering Profile\n"
        f"{_format_target_info_profile_for_prompt(target_info_profile)}\n\n"
        "## Target Memory From Deterministic Gathering\n"
        f"{_build_target_memory_prompt_block(target_memory or {})}\n\n"
        "## Available Recon Tooling\n"
        f"{_format_warmup_recon_tooling(normalized_target_type)}\n"
        "Use tool availability only as capability context. Do NOT mention tool names in methods[] and do NOT call tools in this planner pass.\n\n"
        "## Warmup Planner Task\n"
        "This is a recon-only warmup stage before the main pentest plan.\n"
        "Return a plan containing EXACTLY 8 reconnaissance scenarios and NO exploit work.\n"
        + "Start from the structured target-info profile and the deterministic target-memory findings for this target type.\n"
        "Use the target profile, scope rules, target-info profile, deterministic target memory, and available recon tooling to maximize information gain while staying in scope.\n"
        "Using only the target description, target memory, and scope rules, keep the plan as-is or adapt priorities/details/order so it better matches the target.\n"
        "Preserve the high-value intent of the structured gathering profile unless the target description clearly requires a small adjustment.\n"
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
    target_memory: dict[str, Any] | None = None,
) -> str:
    lines: list[str] = []
    base_info = str(info or "").strip()
    if base_info:
        lines.append("Target description / info:")
        lines.append(base_info)

    target_memory_block = _build_target_memory_prompt_block(target_memory or {})
    if target_memory_block.strip() and target_memory_block.strip() != "(no target memory available)":
        lines.extend(["", "Deterministic target memory:", target_memory_block])

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


def _build_post_gathering_intel_info(
    *,
    info: str,
    target_memory: dict[str, Any] | None = None,
) -> str:
    lines: list[str] = []
    base_info = str(info or "").strip()
    if base_info:
        lines.append("Target description / info:")
        lines.append(base_info)

    target_memory_block = _build_target_memory_prompt_block(target_memory or {})
    if target_memory_block.strip() and target_memory_block.strip() != "(no target memory available)":
        lines.extend(["", "System memory from grouped information gathering:", target_memory_block])

    lines.append(
        "Use the grouped information-gathering results above as the primary evidence baseline for the target-specific checklist."
    )
    return "\n".join(line for line in lines if line).strip()


def _build_planner_checklist_message(
    *,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    target_info_profile: dict[str, Any],
    target_memory: dict[str, Any],
    custom_checklist_text: str = "",
    current_checklist: dict[str, Any] | None = None,
) -> str:
    lines = [
        f"Target: {target}",
        f"Target type: {target_type}",
        f"Scope: {scope or '(not provided)'}",
        f"Info: {info or '(not provided)'}",
        "",
        "Structured target-info gathering profile:",
        _format_target_info_profile_for_prompt(target_info_profile),
        "",
        "System memory from grouped information gathering:",
        _build_target_memory_prompt_block(target_memory or {}),
    ]
    if isinstance(current_checklist, dict) and current_checklist:
        lines.extend(
            [
                "",
                "Current checklist state:",
                _format_structured_checklist_for_prompt(current_checklist),
            ]
        )
    custom_text = str(custom_checklist_text or "").strip()
    if custom_text:
        lines.extend(
            [
                "",
                "Operator-supplied custom checklist text:",
                custom_text,
            ]
        )
    lines.extend(
        [
            "",
            "Checklist generation task:",
            "Generate or update the target-specific checklist using the grouped information-gathering results as the primary evidence baseline.",
            "Preserve relevant current items, remove mismatched items, and merge custom checklist guidance only when it fits the observed surface.",
        ]
    )
    return "\n".join(lines)


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
    text = str(value or "").strip().lower()
    if text in {"low", "medium", "high"}:
        mapping = {
            "low": 0.25,
            "medium": 0.6,
            "high": 0.9,
        }
        return mapping[text]
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


def _count_total_scenarios(plan_data: dict[str, Any]) -> int:
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
            total += len([scenario for scenario in scenarios if isinstance(scenario, dict)])
    return total


def _extract_saved_plan_from_last_scan(last_scan: Any) -> dict[str, Any]:
    if not isinstance(last_scan, dict):
        return {}

    result = last_scan.get("result")
    if isinstance(result, dict):
        planner = result.get("planner")
        if isinstance(planner, dict):
            plan_data = planner.get("plan_data")
            if isinstance(plan_data, dict) and _count_total_scenarios(plan_data) > 0:
                return deepcopy(plan_data)

    # Legacy compatibility: older planner code also reads/writes lastScan.plan.
    legacy_plan = last_scan.get("plan")
    if isinstance(legacy_plan, dict) and _count_total_scenarios(legacy_plan) > 0:
        return deepcopy(legacy_plan)

    return {}


def _prepare_plan_for_resume(plan_data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
    """Use the saved plan as resume source but rerun ALL scenarios by resetting them."""

    resumed_plan = deepcopy(plan_data) if isinstance(plan_data, dict) else {}
    stats = {
        "total": _count_total_scenarios(resumed_plan),
        "completed": 0,
        "reset_to_pending": 0,
        "pending": 0,
    }
    for scenario in _iter_plan_scenarios(resumed_plan):
        status = str(scenario.get("status", "")).strip().lower()
        is_completed = bool(scenario.get("done", False)) or status in {
            "completed",
            "complete",
            "done",
        }
        scenario["active_slot"] = None
        
        scenario["done"] = False
        if is_completed or status in {"working", "running", "in_progress", "in progress", "active", "executing"}:
            stats["reset_to_pending"] += 1
        scenario["status"] = "not yet"
        stats["pending"] += 1

    return _ensure_execution_slots(resumed_plan), stats


def _fallback_methods_for_checklist_item(
    phase_name: str,
    item_name: str,
) -> list[str]:
    base = str(item_name or "").strip()
    normalized_phase = str(phase_name or "").strip().lower()
    if normalized_phase == "post-exploitation":
        return [
            "use only confirmed access paths and capture exact evidence",
            "validate impact without repeating broad discovery",
        ]
    if normalized_phase == "exploitation":
        return [
            "confirm the exact endpoint, input, or artifact from observed evidence",
            "execute the minimum scoped validation needed to prove exploitability",
        ]
    if normalized_phase == "enumeration":
        return [
            "map the exact endpoint, parameter, or route involved",
            "collect request and response evidence that confirms the weakness hypothesis",
        ]
    return [
        "gather concrete evidence from the identified route, asset, or response",
        f"validate this objective directly: {base}",
    ]


def _phase_name_for_checklist_title(title: str, phase_number: str) -> str:
    normalized_title = str(title or "").strip().lower()
    if "report" in normalized_title or "cleanup" in normalized_title:
        return "Reporting"
    if "post" in normalized_title or "flag" in normalized_title:
        return "Post-Exploitation"
    if "exploit" in normalized_title:
        return "Exploitation"
    if "vulnerability" in normalized_title or "discovery" in normalized_title or "enum" in normalized_title:
        return "Enumeration"
    if str(phase_number).strip() == "1":
        return "Reconnaissance"
    if str(phase_number).strip() == "2":
        return "Enumeration"
    if str(phase_number).strip() == "3":
        return "Exploitation"
    if str(phase_number).strip() == "4":
        return "Post-Exploitation"
    if str(phase_number).strip() == "5":
        return "Reporting"
    return "Enumeration"


def _build_fallback_plan_from_checklist(
    *,
    target: str,
    scope: str,
    target_type: str,
    checklist: dict[str, Any],
) -> dict[str, Any]:
    phase_order = [
        "Reconnaissance",
        "Enumeration",
        "Exploitation",
        "Post-Exploitation",
        "Reporting",
    ]
    phases: list[dict[str, Any]] = [
        {"name": name, "priority": idx + 1, "steps": []}
        for idx, name in enumerate(phase_order)
    ]
    phase_lookup = {phase["name"]: phase for phase in phases}

    raw_blocks = checklist.get("checklist", []) if isinstance(checklist, dict) else []
    step_counter = 0
    for block in raw_blocks:
        if not isinstance(block, dict):
            continue
        phase_number = str(block.get("phase", "")).strip()
        title = str(block.get("title", "")).strip()
        phase_name = _phase_name_for_checklist_title(title, phase_number)
        target_phase = phase_lookup.get(phase_name)
        if not target_phase:
            continue
        items = block.get("items", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            if phase_name == "Reporting":
                continue
            step_counter += 1
            priority = _normalize_priority(item.get("priority", 3))
            agent = "exploit" if phase_name in {"Exploitation", "Post-Exploitation"} else "recon"
            scenario_max_rounds = 2 if agent == "exploit" else 1
            scenario = {
                "task": name,
                "agent": agent,
                "priority": priority,
                "max_rounds": scenario_max_rounds,
                "details": f"Checklist-derived fallback scenario for {phase_name.lower()} based on approved checklist evidence.",
                "methods": _fallback_methods_for_checklist_item(phase_name, name),
                "done": False,
                "status": "not yet",
            }
            target_phase["steps"].append(
                {
                    "id": f"{phase_name.lower().replace(' ', '-')}-step-{step_counter:02d}",
                    "description": name,
                    "scenarios": [scenario],
                }
            )

    phases = [phase for phase in phases if isinstance(phase.get("steps"), list) and phase["steps"]]

    return {
        "target": target,
        "scope": scope,
        "target_types": [_normalize_target_type(target_type)],
        "notes": "Fallback plan generated deterministically from the approved checklist because the planner did not persist runnable scenarios.",
        "phases": phases,
    }


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


def _scenario_max_rounds(scenario: dict[str, Any], *, default: int) -> int:
    try:
        parsed = int(scenario.get("max_rounds", default))
    except (TypeError, ValueError):
        parsed = default
    return min(3, max(1, parsed))


def _sanitize_plan_remove_forbidden_agents(plan_data: dict[str, Any]) -> dict[str, Any]:
    """Remove any scenarios with forbidden agents and speculative exploit examples from plan.

    Returns cleaned plan_data with only recon/exploit scenarios.
    """
    if not isinstance(plan_data, dict):
        return plan_data

    FORBIDDEN_AGENTS = {"verify", "retest", "perceptor", "report"}

    def _strip_speculative_examples(text: str) -> tuple[str, bool]:
        raw = str(text or "").strip()
        if not raw:
            return "", False

        updated = raw
        changed = False
        patterns = [
            r"\s*\((?:e\.g\.|eg\.|for example|such as)[^)]*\)",
            r"\s*[-,:]?\s*(?:e\.g\.|eg\.|for example|such as)\s+[^.;\n]*(?:/|https?://|wss?://|s3://|gs://)[^.;\n]*",
        ]
        for pattern in patterns:
            next_value = re.sub(pattern, "", updated, flags=re.IGNORECASE)
            if next_value != updated:
                changed = True
                updated = next_value

        updated = re.sub(r"\s{2,}", " ", updated).strip(" ,;-")
        return updated, changed

    def _has_concrete_artifact_reference(text: str) -> bool:
        haystack = str(text or "")
        patterns = (
            r"https?://\S+",
            r"wss?://\S+",
            r"s3://\S+",
            r"gs://\S+",
            r"/[A-Za-z0-9._~{}:-]{2,}(?:/[A-Za-z0-9._~{}:{}-]*)*",
            r"\bport\s+\d+\b",
            r"\bCVE-\d{4}-\d+\b",
            r"`[^`]{1,64}`",
        )
        return any(re.search(pattern, haystack, flags=re.IGNORECASE) for pattern in patterns)

    def _sanitize_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(scenario, dict):
            return scenario

        cleaned = dict(scenario)
        changed = False
        speculative = False

        for field_name in ("task", "details"):
            value = str(cleaned.get(field_name, "") or "")
            updated, was_changed = _strip_speculative_examples(value)
            if was_changed:
                speculative = True
                changed = True
                cleaned[field_name] = updated

        methods = cleaned.get("methods", [])
        if isinstance(methods, list):
            cleaned_methods: list[str] = []
            for method in methods:
                updated, was_changed = _strip_speculative_examples(str(method or ""))
                speculative = speculative or was_changed
                changed = changed or was_changed
                if updated:
                    cleaned_methods.append(updated)
            cleaned["methods"] = cleaned_methods

        agent_name = str(cleaned.get("agent", "") or "").strip().lower()
        evidence_blob = " ".join(
            [
                str(cleaned.get("task", "") or ""),
                str(cleaned.get("details", "") or ""),
                " ".join(str(item or "") for item in cleaned.get("methods", []) if str(item or "").strip()),
            ]
        )
        if agent_name == "exploit" and speculative and not _has_concrete_artifact_reference(evidence_blob):
            cleaned["details"] = (
                "Confirm the exact target artifact for this hypothesis before active exploitation. "
                + str(cleaned.get("details", "") or "").strip()
            ).strip()
            methods = cleaned.get("methods", [])
            if isinstance(methods, list):
                prefix = "confirm the exact endpoint, parameter, asset, or input vector from observed evidence"
                if prefix not in methods:
                    cleaned["methods"] = [prefix, *methods]
            changed = True

        return cleaned if changed else scenario

    cleaned_plan = dict(plan_data)
    phases = cleaned_plan.get("phases", [])

    if not isinstance(phases, list):
        return cleaned_plan

    for phase in phases:
        if not isinstance(phase, dict):
            continue
        phase_name = str(phase.get("name", "") or "").strip().lower()
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
            cleaned_scenarios = []
            for scenario in scenarios:
                if not isinstance(scenario, dict):
                    continue
                if scenario.get("agent", "").strip().lower() in FORBIDDEN_AGENTS:
                    continue

                cleaned_scenario = _sanitize_scenario(scenario)
                if not isinstance(cleaned_scenario, dict):
                    continue

                current_agent = str(cleaned_scenario.get("agent", "") or "").strip().lower()
                if phase_name in {"reconnaissance", "enumeration"} and current_agent == "exploit":
                    cleaned_scenario = dict(cleaned_scenario)
                    cleaned_scenario["agent"] = "recon"
                elif phase_name == "exploitation" and current_agent == "recon":
                    cleaned_scenario = dict(cleaned_scenario)
                    cleaned_scenario["agent"] = "exploit"

                cleaned_scenarios.append(cleaned_scenario)

            if len(cleaned_scenarios) != len(scenarios):
                step["scenarios"] = cleaned_scenarios
            elif cleaned_scenarios != scenarios:
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
    target_info_profile: dict[str, Any],
    target_memory: dict[str, Any],
    warmup_summaries: list[dict[str, Any]],
) -> str:
    warmup_lines = []
    completed_warmup_tasks: list[str] = []
    for idx, item in enumerate(warmup_summaries[:8], start=1):
        if not isinstance(item, dict):
            continue
        task = str(item.get("task", "")).strip()
        finding_type = str(item.get("finding_type", "info")).strip().lower() or "info"
        compact_summary = str(item.get("compact_summary", "")).strip()
        if task:
            warmup_lines.append(f"- [{idx}] ({finding_type}) {task}: {compact_summary}")
            if task not in completed_warmup_tasks:
                completed_warmup_tasks.append(task)
    checklist_text = _format_structured_checklist_for_prompt(intel_checklist)
    followup_hypotheses = _build_target_type_followup_hypotheses(
        target_type=target_type,
        warmup_summaries=warmup_summaries,
        intel_vulnerabilities=intel_vulnerabilities,
    )
    completed_warmup_text = (
        ", ".join(completed_warmup_tasks)
        if completed_warmup_tasks
        else "(no completed warmup tasks recorded)"
    )
    return (
        f"Target: {target}\n"
        f"Target type: {target_type}\n"
        f"Scope: {scope}\n"
        f"Info: {info}\n\n"
        "## Target Data\n"
        "Use the target, target type, scope, and info as hard planning constraints.\n\n"
        "## Structured Target-Info Gathering Profile\n"
        f"{_format_target_info_profile_for_prompt(target_info_profile)}\n\n"
        "## Target Memory\n"
        f"{_build_target_memory_prompt_block(target_memory)}\n\n"
        "## Intel Input\n"
        f"Intel status: {intel_status}\n"
        f"Vulnerabilities: {intel_vulnerabilities}\n"
        f"Checklist overview: {checklist_overview}\n"
        f"Intel stats: {intel_stats}\n\n"
        "## Synthesized Checklist\n"
        f"{checklist_text}\n\n"
        "## Warmup Recon Results\n"
        f"{chr(10).join(warmup_lines) if warmup_lines else '(no warmup summaries available)'}\n\n"
        "## Evidence-Backed Follow-Up Hypotheses\n"
        f"{chr(10).join(f'- {item}' for item in followup_hypotheses) if followup_hypotheses else '(no follow-up hypotheses generated yet)'}\n\n"
        "## Completed Warmup Baseline\n"
        f"Completed warmup recon tasks already covered: {completed_warmup_text}\n"
        "Do NOT recreate these as fresh scenarios unless a warmup summary clearly shows an unresolved gap or a justified deeper follow-up.\n\n"
        "## Planner Task\n"
        "1. FIRST STEP: create a great pentest plan for this target.\n"
        "2. Start from target data + structured target-info profile + deterministic target memory, then use the synthesized checklist to refine the full plan.\n"
        "3. If warmup recon results are present, treat them as the strongest source of truth for what the target actually exposes. If no warmup results are present, use deterministic target memory as the primary evidence baseline.\n"
        "4. Treat deterministic target memory and evidence-backed follow-up hypotheses as candidate scenario seeds whenever they map to concrete observed artifacts.\n"
        "5. Use the synthesized checklist as prioritized coverage guidance, not as abstract theory.\n"
        "6. The initial full plan should be dense enough to cover the synthesized checklist in one plan, not a thin starter plan.\n"
        "7. Keep total scenarios across Phases 1-3 at 20 or fewer.\n"
        "8. Do not leave Reconnaissance empty. Do not leave Exploitation empty when P1-P2 checklist items or warmup evidence justify active testing.\n"
        "9. Every scenario should map back to either warmup evidence, target description, or a concrete checklist item.\n"
        "10. Do NOT invent endpoints, routes, parameters, repos, services, cloud assets, or credentials for exploit scenarios. If the checklist suggests a vulnerability but no concrete target artifact exists yet, schedule recon/enumeration to close that gap first.\n"
        "11. Cover modern attack paths only when they fit the observed target surface: API authz, IDOR/BOLA, GraphQL, WebSocket, upload abuse, SSRF, SSTI, deserialization, session/token abuse, CORS/trust misuse, CI/CD abuse, exposed secrets, cloud/IAM misconfigurations, container escape paths, and admin-surface weaknesses.\n"
        "12. Return strict JSON with keys: summary, needs, plan, action_plan.\n"
        "13. action_plan must include: checklist_updates, checklist_additions, "
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


def _approval_prefix_for_role(role: str) -> str:
    normalized = str(role or "").strip().lower().replace("-", "_")
    if "intel" in normalized:
        return "Intel"
    if "planner" in normalized:
        return "Planner"
    if "information_gathering" in normalized or "information gathering" in normalized:
        return "Information Gathering"
    if "analyzer" in normalized or "verify" in normalized or "retest" in normalized:
        return "Analyzer"
    return "Executer"


class ExecuterScanCallback:
    """Executer callback bridged to scan event bus + approval workflow."""

    def __init__(
        self,
        *,
        service: "ScanOrchestratorService",
        project_id: str,
        scan_id: str,
        enabled: bool = True,
        stage: str = "executer",
    ) -> None:
        self._service = service
        self._project_id = project_id
        self._scan_id = scan_id
        self._enabled = enabled
        self._stage = stage
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
            message=f"{self._stage.replace('_', ' ').title()} [step] {message}",
            data={"stage": self._stage, "kind": "step", "raw_message": message},
        )

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  ✓ {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_done",
            scan_id=self._scan_id,
            level="success",
            message=f"{self._stage.replace('_', ' ').title()} [done] {message}",
            data={"stage": self._stage, "kind": "done", "raw_message": message},
        )

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ⚠ {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_warn",
            scan_id=self._scan_id,
            level="warn",
            message=f"{self._stage.replace('_', ' ').title()} [warn] {message}",
            data={"stage": self._stage, "kind": "warn", "raw_message": message},
        )

    def get_approval_mode(self) -> str:
        project = self._service._projects_store.get_project(self._project_id)  # noqa: SLF001
        return str(project.get("approval_mode") or "custom").lower().strip() if project else "custom"

    def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
        ) -> Any:
        # Detection: are we running in the main orchestrator loop?
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        service_loop = getattr(self._service, "_loop", None)
        if current_loop is not None and current_loop is service_loop:
            # We are in the main loop — return a coroutine for the async tool to await.
            return self._service.request_executer_tool_approval(
                project_id=self._project_id,
                scan_id=self._scan_id,
                role=role,
                tool_name=tool_name,
                args=args,
                call_id=call_id,
            )

        # We are in a thread (or a different loop) — use the thread-safe bridge.
        return self._service.request_tool_approval_threadsafe(
            project_id=self._project_id,
            scan_id=self._scan_id,
            role=role,
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )

    def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> Any:
        prompt_text = str(prompt or "").strip()
        reason_text = str(reason or "").strip()
        tool_name = "authentication"
        for token_source in (prompt_text, reason_text):
            first_token = token_source.split(" ", 1)[0].strip(" :").lower()
            if first_token in {"ssh", "sudo", "mysql", "psql", "sqlite3", "ftp", "sshpass"}:
                tool_name = first_token
                break

        # Detection: are we running in the main orchestrator loop?
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        service_loop = getattr(self._service, "_loop", None)
        if current_loop is not None and current_loop is service_loop:
            # We are in the main loop — return a coroutine for the async tool to await.
            return self._service.request_executer_password(
                project_id=self._project_id,
                scan_id=self._scan_id,
                tool_name=tool_name,
                prompt=prompt_text,
                reason=reason_text,
                call_id=call_id,
                stage=self._stage,
            )

        # We are in a thread (or a different loop) — use the thread-safe bridge.
        return self._service.request_password_threadsafe(
            project_id=self._project_id,
            scan_id=self._scan_id,
            tool_name=tool_name,
            prompt=prompt_text,
            reason=reason_text,
            call_id=call_id,
            stage=self._stage,
        )


class InformationGatheringScanCallback(ExecuterScanCallback):
    """Information Gathering callback bridged to scan event bus."""

    def __init__(
        self,
        *,
        service: "ScanOrchestratorService",
        project_id: str,
        scan_id: str,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            service=service,
            project_id=project_id,
            scan_id=scan_id,
            enabled=enabled,
            stage="information_gathering",
        )

    def request_tool_approval_threadsafe(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        return True

    def request_password_threadsafe(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
        stage: str = "information_gathering",
    ) -> str | None:
        return ""

    def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> Any:
        try:
            import asyncio
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        service_loop = getattr(self._service, "_loop", None)
        if current_loop is not None and current_loop is service_loop:
            async def _auto_approve() -> bool:
                return True
            return _auto_approve()
        return True

    def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> Any:
        try:
            import asyncio
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        service_loop = getattr(self._service, "_loop", None)
        if current_loop is not None and current_loop is service_loop:
            async def _auto_password() -> str | None:
                return ""
            return _auto_password()
        return ""


class AnalyzerScanCallback(ExecuterScanCallback):
    """Analyzer callback bridged to scan event bus + approval workflow."""

    def on_step(self, message: str) -> None:
        if self._enabled:
            print(f"  → {message} {self._ts()}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="analyzer_step",
            scan_id=self._scan_id,
            level="info",
            message=f"Analyzer [step] {message}",
            data={"stage": "analyzer", "kind": "step", "raw_message": message},
        )

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  ✓ {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="analyzer_done",
            scan_id=self._scan_id,
            level="success",
            message=f"Analyzer [done] {message}",
            data={"stage": "analyzer", "kind": "done", "raw_message": message},
        )

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ⚠ {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="analyzer_warn",
            scan_id=self._scan_id,
            level="warn",
            message=f"Analyzer [warn] {message}",
            data={"stage": "analyzer", "kind": "warn", "raw_message": message},
        )


class WorkerExecuterCallback:
    """Prefixes executer callback logs with a stable worker label."""

    def __init__(self, *, parent: ExecuterScanCallback, worker_index: int) -> None:
        self._parent = parent
        self._worker_index = worker_index
        self._prefix = f"[worker {worker_index}]"

    def _prefix_message(self, message: str) -> str:
        text = str(message or "").strip()
        if not text:
            return self._prefix
        if text.startswith(self._prefix):
            return text
        return f"{self._prefix} {text}"

    def on_step(self, message: str) -> None:
        self._parent.on_step(self._prefix_message(message))

    def on_done(self, message: str) -> None:
        self._parent.on_done(self._prefix_message(message))

    def on_warn(self, message: str) -> None:
        self._parent.on_warn(self._prefix_message(message))

    def get_approval_mode(self) -> str:
        return self._parent.get_approval_mode()

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        result = self._parent.request_tool_approval(
            role=f"{self._prefix} {role}",
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )
        if asyncio.iscoroutine(result) or asyncio.isfuture(result) or inspect.isawaitable(result):
            return await result
        return bool(result)

    async def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        result = self._parent.request_password(
            prompt=prompt,
            reason=reason,
            call_id=call_id,
        )
        if asyncio.iscoroutine(result) or asyncio.isfuture(result) or inspect.isawaitable(result):
            return await result
        return str(result) if result is not None else None


@dataclass
class _PendingToolApproval:
    scan_id: str
    role: str
    tool_name: str
    args: dict[str, Any]
    call_id: str
    event: asyncio.Event
    decision: str | None = None
    loop: asyncio.AbstractEventLoop | None = None


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
    loop: asyncio.AbstractEventLoop | None = None


class ScanOrchestratorService:
    """Runs and tracks orchestrated scan executions per project."""

    def __init__(self, projects_store: ProjectsStore) -> None:
        self._projects_store = projects_store
        self._vector_store = QdrantVectorStore()
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._runs: dict[str, dict[str, Any]] = {}
        self._info_gathering_approval_events: dict[str, asyncio.Event] = {}
        self._planner_approval_events: dict[str, asyncio.Event] = {}
        self._tool_approval_events: dict[str, dict[str, _PendingToolApproval]] = {}
        self._password_request_events: dict[str, dict[str, _PendingPasswordRequest]] = {}
        self._event_subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}
        self._lock = asyncio.Lock()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

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
        # Ensure event loop is captured for threadsafe approval callbacks (may be
        # None when the orchestrator was constructed before uvicorn started).
        if self._loop is None:
            self._loop = asyncio.get_running_loop()

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
        _ensure_intel_node_importable()
        _ensure_planner_agent_importable()

        # If a task is currently running but marked as shutting down,
        # wait briefly for it to exit so we can cleanly restart without flip-flopping.
        existing_task = self._tasks.get(project_key)
        if existing_task is not None and not existing_task.done():
            run_state = self._runs.get(project_key, {})
            if run_state.get("status") in ("paused", "error", "completed", "cancelled"):
                try:
                    await asyncio.wait_for(asyncio.shield(existing_task), timeout=170.0)
                except BaseException:
                    pass

        async with self._lock:
            active_task = self._tasks.get(project_key)
            if active_task is not None and not active_task.done():
                current = dict(self._runs.get(project_key, {}))
                current["already_running"] = True
                return current

            resume_result: dict[str, Any] = {}
            resume_plan_data: dict[str, Any] = {}
            resume_plan_stats: dict[str, int] = {}
            resume_elapsed_seconds = 0

            # SAFE RESUME LOGIC
            # The saved plan is the first stable checkpoint. If no plan exists,
            # discard incomplete runtime data and start from scratch.
            if resume:
                last_scan = project.get("lastScan")
                saved_plan = _extract_saved_plan_from_last_scan(last_scan)
                if saved_plan:
                    resume_plan_data, resume_plan_stats = _prepare_plan_for_resume(saved_plan)
                    resume_result = deepcopy(last_scan.get("result", {})) if isinstance(last_scan, dict) else {}
                    resume_elapsed_seconds = _compute_scan_elapsed_seconds(
                        last_scan if isinstance(last_scan, dict) else {}
                    )
                    planner_payload = resume_result.get("planner")
                    if not isinstance(planner_payload, dict):
                        planner_payload = {}
                    planner_payload["plan_data"] = resume_plan_data
                    planner_payload["resume"] = {
                        "source": "saved_plan",
                        "stats": resume_plan_stats,
                    }
                    resume_result["planner"] = planner_payload
                else:
                    resume = False
                    resume_result = {}

            if not resume:
                from server.agents.planner.tools.pentest_plan import reset_pentest_plan_state

                reset_pentest_plan_state()
                self._reset_project_runtime_state(project, clear_scan_artifacts=True)
                project["scanProgress"] = 0
                project["updatedAt"] = _utc_now_iso()
                write_payload = getattr(self._projects_store, "_write_project_payload", None)
                if callable(write_payload):
                    write_payload(project)
                else:  # pragma: no cover - compatibility with alternate stores
                    self._projects_store.upsert_project(project)
                
                try:
                    from server.api.routes.projects import _delete_project_runtime_artifacts
                    _delete_project_runtime_artifacts(project_key, project_payload=project)
                except Exception as exc:  # pragma: no cover
                    logger.warning(
                        "runtime_artifacts_clear_failed",
                        project_id=project_key,
                        error=str(exc),
                    )
                
                try:
                    self._projects_store.clear_scan_event_cache(project_key)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "scan_event_cache_clear_failed",
                        project_id=project_key,
                        error=str(exc),
                    )
                for report_format in ("markdown", "html", "pdf"):
                    try:
                        self._projects_store.delete_report(project_key, report_format)
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "project_report_clear_failed",
                            project_id=project_key,
                            report_format=report_format,
                            error=str(exc),
                        )
            scan_id = str(uuid.uuid4())
            now_iso = _utc_now_iso()
            started_at = _started_at_for_elapsed(now_iso, resume_elapsed_seconds) if resume else now_iso
            
            if resume and isinstance(project.get("lastScan"), dict):
                original_started_at = project["lastScan"].get("originalStartedAt") or project["lastScan"].get("startedAt") or now_iso
            else:
                original_started_at = now_iso
                
            approval_mode = str(project.get("approval_mode") or "custom").lower().strip()
            run_state = {
                "scan_id": scan_id,
                "project_id": project_key,
                "status": "running",
                "started_at": started_at,
                "updated_at": now_iso,
                "finished_at": None,
                "error": "",
                "elapsed_seconds": resume_elapsed_seconds,
                "approval_mode": approval_mode,
                "awaiting_information_gathering_approval": False,
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
                    "originalStartedAt": original_started_at,
                    "elapsedSeconds": resume_elapsed_seconds,
                    # Preserve the previous stable checkpoint for _run_scan().
                    # _merge_scan_metadata intentionally drops old result data
                    # when a new scan id is written, so resume must carry the saved
                    # plan forward explicitly.
                    **({"plan": resume_plan_data} if resume_plan_data else {}),
                    **({"result": resume_result} if resume_result else {}),
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
                    "elapsed_seconds": resume_elapsed_seconds,
                    "started_at": started_at,
                    **({"resume_plan": resume_plan_stats} if resume_plan_stats else {}),
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
                    resume=resume,
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
            payload_copy = dict(payload)
            payload_copy["is_cached"] = True
            self._push_event(queue, payload_copy)

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

    def _reset_project_runtime_state(
        self,
        project: dict[str, Any],
        *,
        clear_scan_artifacts: bool = False,
    ) -> None:
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

        if clear_scan_artifacts:
            project["findings"] = []
            project["findings_count"] = 0
            project.pop("last_findings_updated", None)
            project.pop("checklist", None)
            project.pop("plannerStaticPlan", None)
            payload = project.get("payload")
            if isinstance(payload, dict):
                for key in (
                    FINDINGS_HISTORY_KEY,
                    LEGACY_FINDINGS_HISTORY_KEY,
                    "targetInfoGathering",
                    "target_info_gathering",
                    "information_gathering",
                    "planner",
                    "warmup",
                ):
                    payload.pop(key, None)
                if payload:
                    project["payload"] = payload
                else:
                    project.pop("payload", None)

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
        info_gate = self._info_gathering_approval_events.get(project_key)
        if info_gate is not None:
            loop = getattr(info_gate, "_loop", None)
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(info_gate.set)
            else:
                info_gate.set()
        
        gate = self._planner_approval_events.get(project_key)
        if gate is not None:
            loop = getattr(gate, "_loop", None)
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(gate.set)
            else:
                gate.set()
                
        pending_tool_approvals = list(self._tool_approval_events.get(project_key, {}).items())
        for _approval_id, pending in pending_tool_approvals:
            pending.decision = "skip"
            loop = getattr(pending, "loop", None)
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(pending.event.set)
            else:
                pending.event.set()
        self._tool_approval_events.pop(project_key, None)

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
                "awaiting_information_gathering_approval": False,
                "awaiting_planner_approval": False,
                "awaiting_tool_approval": False,
                "pending_tool_approval": None,
                "already_running": False,
            }
            last_scan = project.get("lastScan")
            last_scan_meta = dict(last_scan) if isinstance(last_scan, dict) else {}
            last_scan_meta["awaitingToolApproval"] = False
            last_scan_meta["pendingToolApproval"] = None
            paused_scan_meta = {
                **last_scan_meta,
                "scanId": scan_id,
                "status": "paused",
                "finishedAt": last_scan_meta.get("finishedAt") or now_iso,
            }
            paused_elapsed_seconds = _compute_scan_elapsed_seconds(paused_scan_meta)
            self._persist_project_status(
                project_key,
                status="paused",
                scan_progress=int(project.get("scanProgress", 0) or 0),
                scan_meta=paused_scan_meta,
            )
            self._emit_event(
                project_key,
                event="scan_paused",
                scan_id=scan_id,
                level="warn",
                message="Scan paused by user.",
                data={
                    "status": "paused",
                    "elapsed_seconds": paused_elapsed_seconds,
                    "started_at": paused_scan_meta.get("startedAt"),
                    "finished_at": paused_scan_meta.get("finishedAt"),
                },
            )
            self._emit_event(
                project_key,
                event="executer_tool_approval_cleared",
                scan_id=scan_id,
                level="info",
                message="Executer [approval cleared] Cleared pending tool approvals because the scan was paused.",
                data={
                    "stage": "executer",
                    "kind": "tool_approval_cleared",
                    "awaiting_user_approval": False,
                    "status": "paused",
                },
            )
            return {
                "ok": True,
                "project_id": project_key,
                "scan_id": scan_id,
                "status": "paused",
                "finished_at": now_iso,
                "elapsed_seconds": paused_elapsed_seconds,
                "started_at": paused_scan_meta.get("startedAt"),
            }

        # cancel
        self._tasks.pop(project_key, None)
        self._runs.pop(project_key, None)
        reset_project = self._projects_store.reset_project_runtime_state(project_key)
        cleanup_project = reset_project if isinstance(reset_project, dict) else project
        project.pop("contextWindows", None)
        cleanup_project.pop("contextWindows", None)
        self._projects_store.upsert_project(cleanup_project)
        _purge_project_runtime_artifacts(project_key, project_payload=cleanup_project)
        self._emit_event(
            project_key,
            event="scan_cancelled",
            scan_id=scan_id,
            level="warn",
            message="Scan cancelled by user.",
            data={"status": "idle"},
        )
        self._emit_event(
            project_key,
            event="executer_tool_approval_cleared",
            scan_id=scan_id,
            level="info",
            message="Executer [approval cleared] Cleared pending tool approvals because the scan was cancelled.",
            data={
                "stage": "executer",
                "kind": "tool_approval_cleared",
                "awaiting_user_approval": False,
                "status": "idle",
            },
        )
        try:
            self._projects_store.clear_scan_event_cache(project_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "scan_event_cache_clear_failed",
                project_id=project_key,
                error=str(exc),
            )
        return {
            "ok": True,
            "project_id": project_key,
            "scan_id": scan_id,
            "status": "idle",
        }

    async def approve_information_gathering(
        self, 
        project_id: str, 
        modified_program: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
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
            waiting = bool(run_state.get("awaiting_information_gathering_approval"))

            if status != "running":
                raise ValueError("scan is not running")

            if waiting:
                # Apply modified program if provided
                if modified_program is not None:
                    memory = run_state.get("active_memory")
                    if isinstance(memory, dict):
                        gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
                        gathering["program"] = modified_program
                        memory["gathering"] = gathering
                        logger.info("orchestrator_gathering_plan_updated", project_id=project_key)

                gate = self._info_gathering_approval_events.get(project_key)
                if gate is not None:
                    loop = getattr(gate, "_loop", None)
                    if loop is not None and not loop.is_closed():
                        loop.call_soon_threadsafe(gate.set)
                    else:
                        gate.set()
                now_iso = _utc_now_iso()
                run_state["awaiting_information_gathering_approval"] = False
                run_state.pop("active_memory", None)  # Clean up reference
                run_state["updated_at"] = now_iso
                self._runs[project_key] = run_state

                self._emit_event(
                    project_key,
                    event="target_info_gathering_approval_received",
                    scan_id=scan_id,
                    level="success",
                    message="Information Gathering [approved] Static gathering program approved. Starting block execution now.",
                    data={
                        "stage": "information_gathering",
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
                "awaiting_information_gathering_approval": False,
                "already_approved": not waiting,
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
                    loop = getattr(gate, "_loop", None)
                    if loop is not None and not loop.is_closed():
                        loop.call_soon_threadsafe(gate.set)
                    else:
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

        project = self._projects_store.get_project(project_key)
        approval_mode = str(project.get("approval_mode") or "custom").lower().strip() if project else "custom"
        require_manual = bool(args.get("_require_manual_approval")) if isinstance(args, dict) else False
        display_prefix = _approval_prefix_for_role(role)
        
        run_state = self._runs.get(project_key)
        if isinstance(run_state, dict):
            # Sync run_state for consistency
            run_state["approval_mode"] = approval_mode
            self._runs[project_key] = run_state

        if approval_mode == "auto":
            logger.info(
                "executer_tool_auto_approved",
                project_id=project_key,
                role=role,
                tool_name=tool_name,
            )
            return True

        approval_id = str(uuid.uuid4())
        pending = _PendingToolApproval(
            scan_id=str(scan_id or ""),
            role=str(role or ""),
            tool_name=str(tool_name or ""),
            args=dict(args or {}),
            call_id=str(call_id or ""),
            event=asyncio.Event(),
            loop=asyncio.get_running_loop(),
        )
        project_pending = self._tool_approval_events.setdefault(project_key, {})
        is_first = len(project_pending) == 0
        project_pending[approval_id] = pending

        if is_first:
            run_state = self._runs.get(project_key)
            if isinstance(run_state, dict):
                run_state["awaiting_tool_approval"] = True
                run_state["pending_tool_approval"] = {
                    "approval_id": approval_id,
                    "scan_id": pending.scan_id,
                    "role": pending.role,
                    "tool_name": pending.tool_name,
                    "call_id": pending.call_id,
                    "args": pending.args,
                }
                run_state["updated_at"] = _utc_now_iso()
                self._runs[project_key] = run_state

            self._persist_project_status(
                project_key,
                status="running",
                scan_progress=run_state.get("progress", 50) if isinstance(run_state, dict) else 50,
                scan_meta={
                    "status": "awaiting_tool_approval",
                    "awaitingToolApproval": True,
                    "pendingToolApproval": run_state.get("pending_tool_approval") if isinstance(run_state, dict) else None,
                }
            )

            self._emit_event(
                project_key,
                event="executer_tool_waiting_approval",
                scan_id=pending.scan_id,
                level="warn",
                message=(
                    f"{display_prefix} [waiting approval] {pending.role} requested "
                    f"tool '{pending.tool_name}': {_render_tool_command(pending.tool_name, pending.args)}. Approve or skip."
                ),
                data={
                    "stage": "executer",
                    "kind": "waiting_tool_approval",
                    "status": "awaiting_tool_approval",
                    "awaiting_user_approval": True,
                    "approval_id": approval_id,
                    "role": pending.role,
                    "tool_name": pending.tool_name,
                    "call_id": pending.call_id,
                    "args": pending.args,
                    "rendered_command": _render_tool_command(pending.tool_name, pending.args),
                    "preview": str(pending.args.get("code", pending.args.get("command", ""))).strip()[:2000],
                },
            )

        wait_start = time.time()
        try:
            # Wait with heartbeat messages every 60 seconds to keep connection alive
            start_time = time.time()
            HEARTBEAT_INTERVAL = 60  # Send keepalive every 60 seconds

            while not pending.event.is_set():
                # Pause timeout if we are waiting in queue (not the active approval)
                if project_pending:
                    active_id = next(iter(project_pending.keys()))
                    if active_id != approval_id:
                        await asyncio.sleep(0.1)
                        wait_start = time.time()
                        start_time = time.time()
                        continue
                
                # Re-evaluate approval mode inside the loop
                current_project = self._projects_store.get_project(project_key)
                if current_project:
                    approval_mode = str(current_project.get("approval_mode") or "custom").lower().strip()
                
                if approval_mode == "auto":
                    pending.decision = "approve"
                    logger.info("tool_approval_bypassed_by_mode_switch", project_id=project_key, tool_name=pending.tool_name)
                    break

                try:
                    await asyncio.wait_for(pending.event.wait(), timeout=HEARTBEAT_INTERVAL)
                    break  # Event was set, exit loop
                except asyncio.TimeoutError:
                    # Send keepalive message
                    elapsed = int(time.time() - start_time)
                    self._emit_event(
                        project_key,
                        event="executer_tool_approval_waiting",
                        scan_id=pending.scan_id,
                        level="info",
                        message=(
                            f"{display_prefix} [approval waiting] {pending.role} tool '{pending.tool_name}' "
                            f"waiting for approval... ({elapsed}s)"
                        ),
                        data={
                            "stage": "executer",
                            "kind": "tool_approval_waiting",
                            "approval_id": approval_id,
                            "role": pending.role,
                            "tool_name": pending.tool_name,
                            "wait_seconds": elapsed,
                        },
                    )
                    continue

        except Exception as exc:
            logger.error("tool_approval_error", project_id=project_key, error=str(exc))
            pending.decision = "skip"

        approved = pending.decision == "approve"

        wait_duration = time.time() - wait_start
        if wait_duration > 0.1:
            self._shift_project_scan_start_time(project_key, wait_duration)

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
                    "args": next_pending.args,
                }
            else:
                run_state["awaiting_tool_approval"] = False
                run_state["pending_tool_approval"] = None
            run_state["updated_at"] = _utc_now_iso()
            self._runs[project_key] = run_state

        self._persist_project_status(
            project_key,
            status="running",
            scan_progress=run_state.get("progress", 50) if isinstance(run_state, dict) else 50,
            scan_meta={
                "status": "awaiting_tool_approval" if project_pending else "running",
                "awaitingToolApproval": bool(project_pending),
                "pendingToolApproval": run_state.get("pending_tool_approval") if isinstance(run_state, dict) else None,
            }
        )

        self._emit_event(
            project_key,
            event="executer_tool_approval_decision",
            scan_id=pending.scan_id,
            level="success" if approved else "warn",
            message=(
                f"{display_prefix} [approval {'approved' if approved else 'skipped'}] "
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

        if project_pending:
            next_id, next_pending = next(iter(project_pending.items()))
            self._emit_event(
                project_key,
                event="executer_tool_waiting_approval",
                scan_id=next_pending.scan_id,
                level="warn",
                message=(
                    f"{display_prefix} [waiting approval] {next_pending.role} requested "
                    f"tool '{next_pending.tool_name}': {_render_tool_command(next_pending.tool_name, next_pending.args)}. Approve or skip."
                ),
                data={
                    "stage": "executer",
                    "kind": "waiting_tool_approval",
                    "status": "awaiting_tool_approval",
                    "awaiting_user_approval": True,
                    "approval_id": next_id,
                    "role": next_pending.role,
                    "tool_name": next_pending.tool_name,
                    "call_id": next_pending.call_id,
                    "args": next_pending.args,
                    "rendered_command": _render_tool_command(next_pending.tool_name, next_pending.args),
                    "preview": str(next_pending.args.get("code", next_pending.args.get("command", ""))).strip()[:2000],
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
            run_state = self._runs.get(project_key, {})
            status = str(run_state.get("status", "")).strip().lower()
            return {
                "ok": False,
                "project_id": project_key,
                "approval_id": approval_id,
                "action": action_clean,
                "status": status or "unknown",
                "stale": True,
                "message": "tool approval request not found",
            }

        pending.decision = action_clean
        
        loop = getattr(pending, "loop", None)
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(pending.event.set)
        else:
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
        stage: str = "executer",
    ) -> str | None:
        """Request password from user for tools like SSH/sudo."""
        project_key = str(project_id or "").strip()
        if not project_key:
            return None

        current_project = self._projects_store.get_project(project_key)
        approval_mode = "custom"
        if current_project:
            approval_mode = str(current_project.get("approval_mode") or "custom").lower().strip()
            
        if approval_mode == "auto":
            import os
            if os.geteuid() == 0:
                return ""  # Auto-approve silently when running as root

        password_id = str(uuid.uuid4())
        pending = _PendingPasswordRequest(
            scan_id=str(scan_id or ""),
            tool_name=str(tool_name or ""),
            prompt=str(prompt or ""),
            reason=str(reason or ""),
            call_id=str(call_id or ""),
            event=asyncio.Event(),
            loop=asyncio.get_running_loop(),
        )
        project_pending = self._password_request_events.setdefault(project_key, {})
        project_pending[password_id] = pending

        # Emit password request event to frontend
        display_stage = stage.replace("_", " ").title()
        self._emit_event(
            project_key,
            event="executer_password_request",
            scan_id=pending.scan_id,
            level="info",
            message=f"{display_stage} [password required] {pending.tool_name} needs authentication",
            data={
                "stage": stage,
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
        wait_start = time.time()
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

        # Shift startedAt if we waited
        wait_duration = time.time() - wait_start
        if wait_duration > 0.1:
            self._shift_project_scan_start_time(project_key, wait_duration)

        # Clean up
        project_pending = self._password_request_events.get(project_key, {})
        project_pending.pop(password_id, None)
        if not project_pending:
            self._password_request_events.pop(project_key, None)

        return pending.password if pending.approved else None

    def request_tool_approval_threadsafe(
        self,
        *,
        project_id: str,
        scan_id: str,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        """Thread-safe wrapper for requesting tool approval from a tool thread."""
        if self._loop is None:
            logger.warning("request_tool_approval_threadsafe_no_loop")
            return True # Default to approve if loop missing? Or safe skip?
        
        future = asyncio.run_coroutine_threadsafe(
            self.request_executer_tool_approval(
                project_id=project_id,
                scan_id=scan_id,
                role=role,
                tool_name=tool_name,
                args=args,
                call_id=call_id,
            ),
            self._loop
        )
        try:
            return future.result()
        except Exception:
            logger.error("request_tool_approval_threadsafe_failed", exc_info=True)
            return False

    
    def request_password_threadsafe(
        self,
        *,
        project_id: str,
        scan_id: str,
        tool_name: str,
        prompt: str,
        reason: str,
        call_id: str,
        stage: str = "executer",
    ) -> str | None:
        """Thread-safe wrapper for requesting password from a tool thread."""
        if self._loop is None:
            logger.warning("request_password_threadsafe_no_loop")
            return None
        
        future = asyncio.run_coroutine_threadsafe(
            self.request_executer_password(
                project_id=project_id,
                scan_id=scan_id,
                tool_name=tool_name,
                prompt=prompt,
                reason=reason,
                call_id=call_id,
                stage=stage,
            ),
            self._loop
        )
        try:
            return future.result()
        except Exception:
            logger.error("request_password_threadsafe_failed", exc_info=True)
            return None


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
        
        loop = getattr(pending, "loop", None)
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(pending.event.set)
        else:
            pending.event.set()

        self._emit_event(
            project_key,
            event="executer_password_response",
            scan_id=pending.scan_id,
            level="success" if approved else "warn",
            message=(
                f"Executer [password {'approved' if approved else 'denied'}] "
                f"{pending.tool_name} authentication response received."
            ),
            data={
                "stage": "executer",
                "kind": "password_response",
                "password_id": password_id,
                "tool_name": pending.tool_name,
                "approved": approved,
                "call_id": pending.call_id,
            },
        )

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
            "awaiting_information_gathering_approval": bool(last_scan.get("awaitingInformationGatheringApproval")),
            "awaiting_planner_approval": bool(last_scan.get("awaitingPlannerApproval")),
            "awaiting_tool_approval": bool(last_scan.get("awaitingToolApproval")),
            "pending_tool_approval": last_scan.get("pendingToolApproval"),
            "already_running": False,
        }

    def _on_task_done(self, project_id: str, task: asyncio.Task[None]) -> None:
        if self._tasks.get(project_id) is task:
            self._tasks.pop(project_id, None)
        self._info_gathering_approval_events.pop(project_id, None)
        self._planner_approval_events.pop(project_id, None)
        self._tool_approval_events.pop(project_id, None)
        try:
            task.result()
        except asyncio.CancelledError:
            pass  # Expected when a scan is manually stopped
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
        target_memory: dict[str, Any] | None = None,
    ) -> str:
        from server.agents.executer.target_tool_routing import recommend_product_tooling

        history_block = _format_agent_execution_history_for_prompt(
            plan_data,
            agent_role=str(scenario.get("agent", "")).strip().lower() or "recon",
            active_scenarios=[scenario],
        )
        target_guidance = _build_target_execution_guidance(
            target=target,
            scenario_tasks=[str(scenario.get("task", "")).strip()],
        )
        brain = Brain.from_system_memory(target_memory or {})
        executor_projection = brain.for_executor()
        product_tooling = recommend_product_tooling(
            role=str(scenario.get("agent", "")).strip().lower() or "recon",
            target_type=target_type,
            tech_inventory=executor_projection.get("tech_inventory", []),
        )
        payload_family = _infer_payload_family_from_scenario(scenario if isinstance(scenario, dict) else {})
        suggested_payloads = (
            _get_filtered_payloads(payload_family, executor_projection.get("tech_stack"), max_payloads=5)
            if payload_family
            else []
        )
        tool_efficiency = _compute_tool_efficiency_snapshot(target_memory or {})
        return (
            f"Scenario: {str(scenario.get('task', '')).strip()}\n"
            f"Agent: {str(scenario.get('agent', '')).strip()}\n"
            f"Priority: {_normalize_priority(scenario.get('priority', 3))}\n"
            f"Evidence tier: {str(scenario.get('evidence_tier', 'observed')).strip()}\n"
            f"Confidence label: {str(scenario.get('confidence_label', 'medium')).strip()}\n"
            f"Prerequisites: {json.dumps(scenario.get('prerequisites', []), ensure_ascii=True)}\n"
            f"Evidence basis: {json.dumps(scenario.get('evidence_basis', []), ensure_ascii=True)}\n"
            f"Details: {str(scenario.get('details', '')).strip()}\n"
            f"Methods: {json.dumps(scenario.get('methods', []), ensure_ascii=True)}\n"
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"Extra info: {info}\n"
            f"{target_guidance}\n"
            f"Executor brain projection: {json.dumps(executor_projection, ensure_ascii=True)}\n"
            f"Recommended product tooling: {json.dumps(product_tooling, ensure_ascii=True)}\n"
            f"Suggested payload family: {payload_family or 'generic'}\n"
            f"Suggested payloads: {json.dumps(suggested_payloads, ensure_ascii=True)}\n"
            f"Observed tool efficiency: {json.dumps(tool_efficiency, ensure_ascii=True)}\n"
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
            tool_guidance = _build_warmup_scenario_tool_guidance(task)
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
                f"Methods: {json.dumps(methods, ensure_ascii=True)}\n"
                f"Tool guidance: {tool_guidance or 'Use the smallest complementary tools that directly fit this scenario. Avoid near-duplicate repeats.'}"
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
            "Round 1 must call at least one focused recon tool unless every assigned scenario is impossible for this target.\n"
            "Do not repeat the same expensive tool for the same scenario unless earlier evidence exposed a new concrete endpoint, cookie, route, or behavior that justifies the retry.\n"
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
        analyzer_agent: Any,
        scenario: dict[str, Any],
        row_result: dict[str, Any],
        cycle_number: int,
        worker_number: int,
    ) -> dict[str, Any]:
        # Run Analyzer classification on tool results
        tool_results = row_result.get("tool_results", []) if isinstance(row_result, dict) else []
        if isinstance(tool_results, list) and tool_results:
            assessment = await analyzer_agent.assess_tool_results(
                scenario=scenario if isinstance(scenario, dict) else {},
                tool_results=tool_results,
                asset_context={
                    "criticality": "medium",
                    "internet_exposed": True,
                },
            )
        else:
            assessment = await analyzer_agent.assess_text(
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
                f"Analyzer [cached] cycle {cycle_number} worker {worker_number} "
                f"→ scenario: {scenario_task[:60]} → {recon_summary[:100]}"
            ),
            data={
                "stage": "analyzer",
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
        analyzer_agent: Any,
        analyzer_lock: asyncio.Lock,
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
                target_memory=None,
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
        project_cache_dir: str = "",
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        from server.agents.analyzer import AnalyzerAgent
        from server.agents.executer.recon.agent import ReconExecuterAgent
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

            def get_approval_mode(self) -> str:
                project = self._svc._projects_store.get_project(self._pid)  # noqa: SLF001
                return str(project.get("approval_mode") or "custom").lower().strip() if project else "custom"

            def request_tool_approval(self, *, role: str, tool_name: str, args: dict[str, Any], call_id: str) -> Any:
                if hasattr(self._parent, "request_tool_approval"):
                    return self._parent.request_tool_approval(role=role, tool_name=tool_name, args=args, call_id=call_id)
                return False

        project = self._projects_store.get_project(project_id)
        approval_mode = str(project.get("approval_mode") or "custom").lower().strip() if project else "custom"

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
                    project_cache_dir=project_cache_dir,
                    config=override_config,
                    approval_mode=approval_mode,
                )
            )
        analyzer_agent = None
        analyzer_lock = asyncio.Lock()
        cached_summaries: list[dict[str, Any]] = []
        try:
            analyzer_agent = AnalyzerAgent()
            for cycle_number in range(1, WARMUP_RECON_CYCLES + 1):
                display_cycle_number = _display_cycle_number(
                    cycle_number,
                    prior_cycles=cycle_offset,
                )
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
                            analyzer_agent=analyzer_agent,
                            analyzer_lock=analyzer_lock,
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
                            analyzer_agent=analyzer_agent,
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
            if analyzer_agent:
                await analyzer_agent.clear_context_window()
            for agent in warmup_recon_agents:
                await agent.close()
            if analyzer_agent:
                await analyzer_agent.close()

        return plan_data, cached_summaries

    async def _run_poc_background(
        self,
        *,
        item: dict[str, Any],
        analyzer_agent: Any,
        project_id: str,
        scan_id: str,
        target: str,
        target_type: str,
        project_cache_dir: str,
    ) -> None:
        """Run Analyzer PoC generation in background.

        This method runs independently and does NOT block other operations.
        """
        try:
            poc_data = await analyzer_agent.build_poc(
                target=target,
                target_type=target_type,
                scope="",
                item=item,
            )
            poc_summary = str(poc_data.get("poc") or poc_data.get("summary") or "").strip()

            self._emit_event(
                project_id,
                event="analyzer_poc_generated",
                scan_id=scan_id,
                level="info",
                message=f"Generated PoC for verified finding: {item['verify_summary'][:80]}",
                data={
                    "stage": "analyzer",
                    "kind": "poc_generated",
                    "verify_summary": item["verify_summary"],
                    "poc_summary": poc_summary,
                    "severity": _normalize_finding_severity(item["scenario"].get("priority", "medium")),
                    "vulnerability_type": item["scenario"].get("vulnerability_type", "unknown"),
                    "endpoint": item["scenario"].get("endpoint", ""),
                    "evidence_available": bool(poc_data.get("evidence")),
                    "tools_executed": len(poc_data.get("tool_results", [])) if isinstance(poc_data.get("tool_results"), list) else 0,
                },
            )

            logger.info(
                "analyzer_background_poc_generated",
                project_id=project_id,
                scan_id=scan_id,
                vulnerability_type=item["scenario"].get("vulnerability_type", "unknown"),
                poc_summary_length=len(poc_summary),
            )

            await _append_target_memory_updates(
                project_cache_dir,
                stage="analyzer",
                updates=[
                    {
                        "title": str(item.get("scenario", {}).get("task", "")).strip()
                        or str(item.get("verify_summary", "")).strip()
                        or "verified-vulnerability-poc",
                        "summary": poc_summary
                        or f"PoC/report evidence generated for verified finding: {str(item.get('verify_summary', '')).strip()}",
                        "agent": "analyzer",
                        "status": "poc_generated",
                    }
                ],
                verified_findings=[
                    {
                        "id": f"vuln-{item['idx']}",
                        "cwe_id": poc_data.get("cwe_id"),
                        "cve_id": poc_data.get("cve_id"),
                        "steps_to_reproduce": poc_data.get("steps_to_reproduce", []),
                        "exploit_script": poc_data.get("exploit_script"),
                        "verification_commands": poc_data.get("verification_commands", []),
                        "visual_evidence_paths": poc_data.get("visual_evidence_paths", []),
                        "impact_assessment": poc_data.get("impact_assessment", {}),
                        "remediation_steps": poc_data.get("remediation_steps", []),
                        "poc_path": poc_summary, # Still keep the text summary here
                    }
                ],
            )

        except Exception as e:
            logger.error(
                "analyzer_background_poc_error",
                project_id=project_id,
                error=str(e),
            )
            self._emit_event(
                project_id,
                event="analyzer_poc_error",
                scan_id=scan_id,
                level="warn",
                message=f"PoC generation failed: {str(e)[:100]}",
                data={
                    "stage": "analyzer",
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
        recon_agent_worker_1: Any | None,
        exploit_agent: Any,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        target_memory: dict[str, Any] | None = None,
        recon_worker_index: int | None = None,
    ) -> dict[str, Any]:
        message = self._build_executer_message(
            plan_data=plan_data,
            scenario=scenario,
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
            target_memory=target_memory,
        )
        role = str(scenario.get("agent", "recon")).strip().lower()
        if role == "exploit":
            result = await exploit_agent.run(
                message,
                max_tool_rounds_override=_scenario_max_rounds(scenario, default=2),
            )
        else:
            role = "recon"
            selected_recon_agent = (
                recon_agent_worker_1
                if recon_worker_index == 1 and recon_agent_worker_1 is not None
                else recon_agent
            )
            result = await selected_recon_agent.run(
                message,
                max_tool_rounds_override=_scenario_max_rounds(scenario, default=1),
            )
        return {
            "scenario": dict(scenario),
            "executor_agent": role,
            "worker_index": recon_worker_index if role == "recon" else None,
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
        recon_agent_worker_1: Any | None,
        exploit_agent: Any,
        analyzer_agent: Any,
        loop_planner: Any,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        intel_checklist: dict[str, Any],
        project_cache_dir: str,
        target_memory: dict[str, Any] | None = None,
    ) -> tuple[bool, dict[str, Any]]:
        """
        Execute one full cycle: select scenarios -> run parallel -> analyze -> plan.

        Returns: (should_continue, updated_plan_data)
            should_continue=False means Planner said "done"
        """
        plan_data, pre_cycle_pruned = _prune_plan_blocked_route_scenarios(
            plan_data,
            target_memory=target_memory,
        )
        plan_data, pre_cycle_unbacked_pruned = _prune_plan_unbacked_assumption_scenarios(
            plan_data,
            target_memory=target_memory,
        )
        if pre_cycle_pruned > 0 or pre_cycle_unbacked_pruned > 0:
            _sync_plan_data_into_planner_state(plan_data)
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
            self._emit_event(
                project_id,
                event="executer_cycle_idle",
                scan_id=scan_id,
                level="info",
                message="Executer [idle] no runnable scenarios remain in the current plan. Asking Planner whether the pentest is complete or the plan needs refilling.",
                data={
                    "stage": "executer",
                    "kind": "idle_no_selected_scenarios",
                    "cycle": cycle_number,
                    "total_scenarios_in_plan": total_scenarios,
                    "done_scenarios": done_scenarios,
                    "pending_scenarios": total_scenarios - done_scenarios,
                },
            )
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
        selected_with_workers: list[tuple[dict[str, Any], int | None]] = []
        next_recon_worker = 0
        for scenario in selected:
            worker_index: int | None = None
            if str(scenario.get("agent", "recon")).strip().lower() == "recon":
                worker_index = min(next_recon_worker, 1)
                next_recon_worker += 1
            selected_with_workers.append((scenario, worker_index))

        for scenario, worker_index in selected_with_workers:
            _update_scenario_runtime_state(
                plan_data,
                scenario,
                status="working",
                done=False,
            )
            scenario_task = str(scenario.get("task", "unknown")).strip() or "unknown"
            if worker_index is not None:
                scenario_message = f"[worker {worker_index}] Scenario started execution: {scenario_task}"
            else:
                scenario_message = f"Scenario started execution: {scenario_task}"
            self._emit_event(
                project_id,
                event="scenario_state_change",
                scan_id=scan_id,
                level="info",
                message=scenario_message,
                data={
                    "stage": "executer",
                    "kind": "scenario_working",
                    "scenario_task": scenario.get("task", ""),
                    "agent": scenario.get("agent", ""),
                    "worker_index": worker_index,
                    "state": "working",
                    "plan_data": plan_data,
                },
            )

        # Run selected scenarios in parallel (true async with asyncio.gather)
        execution_rows: list[dict[str, Any]] = []
        if selected_with_workers:
            results = await asyncio.gather(*[
                self._execute_scenario_with_agent(
                    plan_data=plan_data,
                    scenario=scenario,
                    recon_agent=recon_agent,
                    recon_agent_worker_1=recon_agent_worker_1,
                    exploit_agent=exploit_agent,
                    target=target,
                    target_type=target_type,
                    scope=scope,
                    info=info,
                    target_memory=target_memory,
                    recon_worker_index=worker_index,
                )
                for scenario, worker_index in selected_with_workers
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
            analyzed = await analyzer_agent.classify(
                idx=idx,
                row=row if isinstance(row, dict) else {},
                target_type=target_type,
            )
            assessment = analyzed.assessment
            scenario = analyzed.scenario
            row_result = analyzed.row_result
            compact_summary = analyzed.compact_summary
            perceptor_rows.append(assessment)

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

            # Emit analyzer_classified event
            self._emit_event(
                project_id,
                event="analyzer_classified",
                scan_id=scan_id,
                level="info",
                message=(
                    f"Analyzer [classified] scenario #{idx} → "
                    f"{assessment.get('overall', {}).get('ssvc', 'TRACK')} "
                    f"(type={finding_type})"
                ),
                data={
                    "stage": "analyzer",
                    "kind": "classified",
                    "iteration": idx,
                    "assessment": assessment,
                },
            )

            try:
                classification_detail = (
                    str(assessment.get("overall", {}).get("summary", "")).strip()
                    if isinstance(assessment.get("overall"), dict)
                    else ""
                ) or compact_summary or str(row_result.get("summary", "")).strip()
                saved_report = _persist_single_analyzer_agent_report(
                    project_store=self._projects_store,
                    project_id=project_id,
                    scan_id=scan_id,
                    cycle_number=cycle_number,
                    role=agent_role,
                    idx=idx,
                    scenario=scenario if isinstance(scenario, dict) else {},
                    row_result=row_result if isinstance(row_result, dict) else {},
                    assessment=assessment if isinstance(assessment, dict) else {},
                    compact_summary=compact_summary,
                    verdict=finding_type,
                    detail_summary=classification_detail,
                )
                if saved_report:
                    self._emit_event(
                        project_id,
                        event="analyzer_report_saved",
                        scan_id=scan_id,
                        level="info",
                        message=(
                            f"Analyzer [saved] {agent_role or 'unknown'} "
                            f"scenario #{idx} classified as {finding_type}."
                        ),
                        data={
                            "stage": "analyzer",
                            "kind": "report_saved",
                            "iteration": idx,
                            "agent_role": agent_role,
                            "report": saved_report,
                        },
                    )
            except Exception as report_exc:
                logger.warning(
                    "analyzer_report_save_failed",
                    project_id=project_id,
                    scan_id=scan_id,
                    item_idx=idx,
                    error=str(report_exc),
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

        info_only_memory_updates: list[dict[str, Any]] = []
        for item in assessments_organized["info_only"]:
            row_result = item.get("row_result", {}) if isinstance(item.get("row_result"), dict) else {}
            info_summary = (
                str(item.get("compact_summary", "")).strip()
                or str(row_result.get("summary", "")).strip()
            )
            info_only_memory_updates.append({
                "title": str(item.get("scenario", {}).get("task", "")).strip() or f"info-{item.get('idx', '')}",
                "summary": info_summary,
                "agent": str(item.get("scenario", {}).get("agent", "")).strip(),
                "status": "info_only",
            })
        if info_only_memory_updates:
            await _append_target_memory_updates(
                project_cache_dir,
                stage="analyzer",
                updates=info_only_memory_updates,
            )

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
                    self._emit_event(
                        project_id,
                        event="analyzer_batch_progress",
                        scan_id=scan_id,
                        level="info",
                        message=(
                            f"Analyzer [verify] processing finding {verify_index}/"
                            f"{len(assessments_organized['vulnerabilities'])}."
                        ),
                        data={
                            "stage": "analyzer",
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
                        event="analyzer_finding_working",
                        scan_id=scan_id,
                        level="info",
                        message=f"Verifying finding: {item.get('compact_summary', 'Unknown')[:100]}",
                        data={
                            "stage": "analyzer",
                            "kind": "finding_working",
                            "title": item.get('compact_summary', 'Finding'),
                            "severity": severity,
                            "endpoint": str(item.get("scenario", {}).get("endpoint", "")).strip(),
                            "vulnerability_type": str(item.get("scenario", {}).get("vulnerability_type", "")).strip(),
                            "status": "working",  # UI badge shows "working" during verification
                            "index": verify_index,
                        },
                    )

                    try:
                        verify_data = await analyzer_agent.verify(
                            target=target,
                            target_type=target_type,
                            scope=scope,
                            candidate=item,
                        )
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

            # CRITICAL: Save real vulnerabilities and inconclusive findings to project database
            # This ensures WAF-blocked (inconclusive) findings are persisted and reported properly.
            items_to_save = verify_results_organized["real_vulnerabilities"] + verify_results_organized["inconclusives"]
            if items_to_save:
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

                for item in items_to_save:
                    finding_entry = _build_verified_finding_entry(
                        target=target,
                        scan_id=scan_id,
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
                    # Only index verified vulnerabilities to avoid polluting RAG context with inconclusives
                    if saved_finding.get("status") == "verified":
                        try:
                            await index_verified_finding(
                                project_id=project_key,
                                target=target,
                                target_type=target_type,
                                finding=saved_finding,
                                project_store=self._projects_store,
                            )
                        except Exception:
                            logger.warning(
                                "verify_finding_project_rag_index_failed",
                                project_id=project_key,
                                finding_id=saved_finding.get("id"),
                                exc_info=True,
                            )
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
                    findings_count=len(items_to_save),
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

        try:
            _persist_analyzer_agent_reports(
                project_store=self._projects_store,
                project_id=project_id,
                scan_id=scan_id,
                info_only_items=assessments_organized["info_only"],
                verify_results=verify_results_organized,
            )
        except Exception as report_exc:
            logger.warning(
                "analyzer_agent_reports_persist_failed",
                project_id=project_id,
                scan_id=scan_id,
                error=str(report_exc),
                error_type=type(report_exc).__name__,
            )

        retest_candidates = [
            item
            for item in verify_results_organized["real_vulnerabilities"]
            if _should_trigger_retest(item)
        ]

        # Mark completed scenarios before handing the current plan back to Planner.
        for row in execution_rows:
            row_result = row.get("result", {}) if isinstance(row, dict) else {}
            row_status = str(row_result.get("status", "")).strip().lower() if isinstance(row_result, dict) else ""
            worker_index = row.get("worker_index") if isinstance(row, dict) else None

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
                completed_task = str(scenario.get("task", "unknown")).strip() or "unknown"
                self._emit_event(
                    project_id,
                    event="scenario_state_change",
                    scan_id=scan_id,
                    level="info",
                    message=(
                        f"[worker {worker_index}] Analyzer closed scenario: {completed_task}"
                        if isinstance(worker_index, int)
                        else f"Analyzer closed scenario: {completed_task}"
                    ),
                    data={
                        "stage": "analyzer",
                        "kind": "scenario_done",
                        "phase": "verify",
                        "scenario_task": scenario.get("task", ""),
                        "agent": scenario.get("agent", ""),
                        "worker_index": worker_index,
                        "state": "completed",
                        "route": route,
                        "round_label": f"r{rounds_executed}" if rounds_executed > 0 else "",
                        "rounds_seen": round_labels if isinstance(round_labels, list) else [],
                        "plan_data": plan_data,
                    },
                )

        _sync_plan_data_into_planner_state(plan_data)

        # ============================================================================
        # PHASE 3A: Launch Analyzer PoC generation (background)
        # PHASE 3B: Launch Planner immediately
        # ============================================================================
        poc_background_tasks = []
        if retest_candidates:
            for item in retest_candidates:
                poc_task = asyncio.create_task(
                    self._run_poc_background(
                        item=item,
                        analyzer_agent=analyzer_agent,
                        project_id=project_id,
                        scan_id=scan_id,
                        target=target,
                        target_type=target_type,
                        project_cache_dir=project_cache_dir,
                    )
                )
                poc_background_tasks.append(poc_task)

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

        target_memory_updates: list[dict[str, Any]] = []
        tool_observations: list[dict[str, Any]] = []
        for item in assessments_organized["info_only"]:
            scenario = item.get("scenario", {}) if isinstance(item.get("scenario"), dict) else {}
            row_result = item.get("row_result", {}) if isinstance(item.get("row_result"), dict) else {}
            confidence = (
                item.get("assessment", {}).get("overall", {}).get("confidence", 0.0)
                if isinstance(item.get("assessment"), dict)
                else 0.0
            )
            tool_observations.extend(
                _build_tool_observation_entries(
                    scenario=scenario,
                    row_result=row_result,
                    status="info",
                    confidence=confidence,
                )
            )
        for bucket_name in ("false_positives", "inconclusives", "real_vulnerabilities"):
            for item in verify_results_organized[bucket_name]:
                scenario = item.get("scenario", {}) if isinstance(item.get("scenario"), dict) else {}
                row_result = item.get("row_result", {}) if isinstance(item.get("row_result"), dict) else {}
                target_memory_updates.append({
                    "title": str(scenario.get("task", "")).strip() or bucket_name,
                    "summary": str(item.get("verify_summary", "")).strip() or str(item.get("compact_summary", "")).strip(),
                    "agent": str(scenario.get("agent", "")).strip(),
                    "status": bucket_name,
                })
                observation_status = "success" if bucket_name == "real_vulnerabilities" else "failed"
                false_positive_count = 1 if bucket_name == "false_positives" else 0
                tool_observations.extend(
                    _build_tool_observation_entries(
                        scenario=scenario,
                        row_result=row_result,
                        status=observation_status,
                        confidence=item.get("verify_confidence", 0.0),
                        false_positive_count=false_positive_count,
                    )
                )
        blocked_routes, blocked_route_prefixes, blocked_route_updates = _extract_blocked_route_memory_updates(
            verify_results_organized["false_positives"]
        )
        if blocked_route_updates:
            target_memory_updates.extend(blocked_route_updates)
        target_memory = await _append_target_memory_updates(
            project_cache_dir,
            stage="execution_cycle",
            updates=target_memory_updates,
            tool_observations=tool_observations,
            verified_findings=[
                {
                    "id": f"vuln-{item['idx']}",
                    "title": str(item.get("verify_summary", "")).strip() or str(item.get("compact_summary", "")).strip(),
                    "summary": str(item.get("scenario", {}).get("task", "")).strip(),
                    "status": "real_vulnerability",
                    "cwe_id": None,
                    "cve_id": None,
                    "steps_to_reproduce": [],
                    "exploit_script": None,
                    "visual_evidence_paths": [],
                    "impact_assessment": {},
                    "remediation_steps": [],
                }
                for item in verify_results_organized["real_vulnerabilities"]
            ],
        )
        if blocked_routes:
            logger.info(
                "blocked_routes_recorded",
                blocked_routes=blocked_routes[:8],
                blocked_route_prefixes=blocked_route_prefixes[:8],
            )

        # ============================================================================
        # PHASE 2.5: Architect Agent (background synthesis of target map)
        # ============================================================================
        try:
            architect = ArchitectAgent(project_id=project_id, project_cache_dir=project_cache_dir)
            current_project = self._projects_store.get_project(project_id)
            previous_architecture = current_project.get("payload", {}).get("architecture_draft")
            scope_key = normalize_target_scope(target, target_type)
            
            # Build memory and vulnerability context for synthesis
            arch_memory_parts = [_build_target_memory_prompt_block(target_memory)]
            if str(current_project.get("copilotContextScope", "")).strip() == scope_key:
                assistant_memory = str(current_project.get("copilotContext", "") or "").strip()
                if assistant_memory:
                    arch_memory_parts.extend(["### ASSISTANT WORKING MEMORY", assistant_memory[:6000]])
            arch_memory_block = "\n\n".join(part for part in arch_memory_parts if str(part).strip())
            arch_vulnerabilities_block = ""
            for item in verify_results_organized["real_vulnerabilities"]:
                arch_vulnerabilities_block += f"- {item['verify_summary']}\n"

            # Run architect synthesis
            architecture_draft = await architect.synthesize(
                target=target,
                target_type=target_type,
                scope=scope,
                memory_block=arch_memory_block,
                vulnerabilities_block=arch_vulnerabilities_block,
                previous_draft=previous_architecture
            )
            
            if architecture_draft and isinstance(architecture_draft, dict) and architecture_draft.get("hosts"):
                if "payload" not in current_project:
                    current_project["payload"] = {}
                current_project["payload"]["architecture_draft"] = architecture_draft
                self._projects_store.upsert_project(current_project)
                
                self._emit_event(
                    project_id,
                    event="architect_updated",
                    scan_id=scan_id,
                    level="info",
                    message="Architect [updated] Refined target architecture draft based on latest findings.",
                    data={
                        "stage": "architect",
                        "kind": "updated",
                        "architecture_draft": architecture_draft,
                        "cycle": cycle_number
                    },
                )
        except Exception as arch_exc:
            logger.warning("architect_synthesis_failed", error=str(arch_exc))
            # Non-critical failure, continue to planner

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
        plan_data, replanner_pruned = _prune_plan_blocked_route_scenarios(
            plan_data,
            target_memory=target_memory,
        )
        plan_data, replanner_unbacked_pruned = _prune_plan_unbacked_assumption_scenarios(
            plan_data,
            target_memory=target_memory,
        )
        if replanner_pruned > 0 or replanner_unbacked_pruned > 0:
            _sync_plan_data_into_planner_state(plan_data)

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
        # PHASE 3C: Analyzer PoC generation continues in background
        # ============================================================================
        # PoC tasks are already executing while Planner updates plan.

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
                "route": "analyzer->planner(info_only,batch)",
                "summary": str(planner_loop_result.summary or "").strip(),
                "compact_bridge": item["compact_summary"],
            })

        # Capture updated plan from planner (scenarios may have been modified/added)
        from server.agents.planner.tools.pentest_plan import _current_plan
        updated_plan = dict(_current_plan) if isinstance(_current_plan, dict) else plan_data
        updated_plan = _sanitize_plan_remove_forbidden_agents(updated_plan)
        updated_plan, updated_pruned = _prune_plan_blocked_route_scenarios(
            updated_plan,
            target_memory=target_memory,
        )
        updated_plan, updated_unbacked_pruned = _prune_plan_unbacked_assumption_scenarios(
            updated_plan,
            target_memory=target_memory,
        )
        if updated_pruned > 0 or updated_unbacked_pruned > 0:
            _sync_plan_data_into_planner_state(updated_plan)

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
        self._emit_event(
            project_id,
            event="planner_completion_check_started",
            scan_id=scan_id,
            level="info",
            message="Planner [check] no runnable scenarios remain. Reviewing whether the pentest is complete or the plan should be refreshed.",
            data={
                "stage": "planner",
                "kind": "completion_check_start",
            },
        )
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
                message="Planner refreshed plan after the no-runnable-scenarios completion check.",
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
        resume: bool = False,
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
        target_info_profile: dict[str, Any] = _resolve_target_info_profile(
            self._projects_store,
            target_type,
        )
        target_memory: dict[str, Any] = {}
        project_cache_dir = ""
        custom_checklist_text = ""
        print_steps = _is_truthy_env("INTEL_PRINT_STEPS", "1")
        intel_stats: dict[str, Any] = {}

        try:
            project = self._projects_store.get_project(project_id) or {}
            project_name = _extract_project_display_name(project if isinstance(project, dict) else {})
            
            last_scan = project.get("lastScan") if isinstance(project, dict) else {}
            original_started_at = last_scan.get("originalStartedAt") if isinstance(last_scan, dict) else None
            
            project_cache_dir = _build_project_run_cache_dir(
                project_id=project_id,
                target=target,
                project_name=project_name,
                created_at=original_started_at or started_at,
            )
            custom_checklist_text = (
                str(project.get("customChecklistText", "")).strip()
                if isinstance(project, dict)
                else ""
            )
            if isinstance(project, dict):
                project["plannerStaticPlan"] = static_recon_plan
                project["targetInfoProfile"] = target_info_profile
                self._projects_store.upsert_project(project)

            # Lazy import avoids loading heavy agent modules at app boot.
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
            async def _request_intel_refresh_approval(
                *,
                role: str,
                tool_name: str,
                args: dict[str, Any],
                call_id: str,
            ) -> bool:
                return await self.request_executer_tool_approval(
                    project_id=project_id,
                    scan_id=scan_id,
                    role=role,
                    tool_name=tool_name,
                    args=args,
                    call_id=call_id,
                )

            callback.request_tool_approval = _request_intel_refresh_approval
            intel_agent = IntelNode(callback=callback, project_id=project_id)
            brain_builder = BrainBuilderNode(memory_node=SystemMemoryNode())

            self._emit_event(
                project_id,
                event="intel_update_started",
                scan_id=scan_id,
                level="info",
                message="Intel [start] refreshing RAG state before grouped information gathering.",
                data={"stage": "intel", "kind": "update_only_start"},
            )
            intel_update_result = await intel_agent.refresh_rag(
                target_type=target_type,
                info=info,
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

            self._emit_event(
                project_id,
                event="target_info_gathering_started",
                scan_id=scan_id,
                level="info",
                message="Information Gathering [start] running grouped static target-info gathering before checklist generation and planning.",
                data={"stage": "information_gathering", "kind": "target_info_gathering_start"},
            )

            def _emit_system_memory_progress(stage: str, payload: dict[str, Any]) -> None:
                block_name = str(payload.get("name", "")).strip() or "Unnamed Block"
                if stage == "program_organized":
                    self._emit_event(
                        project_id,
                        event="target_info_gathering_program_organized",
                        scan_id=scan_id,
                        level="info",
                        message=(
                            f"Information Gathering [group] organized the full static gathering program "
                            f"with target info ({payload.get('total', '?')} blocks) before sequential block execution."
                        ),
                        data={
                            "stage": "information_gathering",
                            "kind": "target_info_gathering_program_organized",
                            "program": payload,
                        },
                    )
                elif stage == "block_started":
                    self._emit_event(
                        project_id,
                        event="target_info_gathering_block_started",
                        scan_id=scan_id,
                        level="info",
                        message=f"Information Gathering [group] gathering block {payload.get('index', '?')}/{payload.get('total', '?')}: {block_name}.",
                        data={
                            "stage": "information_gathering",
                            "kind": "target_info_gathering_block_started",
                            "block": payload,
                        },
                    )
                elif stage == "block_completed":
                    try:
                        saved_report = _persist_information_gathering_report(
                            project_store=self._projects_store,
                            project_id=project_id,
                            scan_id=scan_id,
                            payload=payload,
                        )
                        if saved_report:
                            self._emit_event(
                                project_id,
                                event="analyzer_report_saved",
                                scan_id=scan_id,
                                level="info",
                                message=(
                                    "Information Gathering [saved] organized block findings "
                                    f"stored for {block_name}."
                                ),
                                data={
                                    "stage": "information_gathering",
                                    "kind": "report_saved",
                                    "agent_role": "information_gathering",
                                    "report": saved_report,
                                },
                            )
                    except Exception as report_exc:
                        logger.warning(
                            "information_gathering_report_save_failed",
                            project_id=project_id,
                            scan_id=scan_id,
                            block_name=block_name,
                            error=str(report_exc),
                        )
                    self._emit_event(
                        project_id,
                        event="target_info_gathering_block_completed",
                        scan_id=scan_id,
                        level="success",
                        message=f"Information Gathering [group] completed block {payload.get('index', '?')}/{payload.get('total', '?')}: {block_name}.",
                        data={
                            "stage": "information_gathering",
                            "kind": "target_info_gathering_block_completed",
                            "block": payload,
                        },
                    )
                elif stage == "memory_compacting":
                    self._emit_event(
                        project_id,
                        event="system_memory_compacting",
                        scan_id=scan_id,
                        level="info",
                        message="System Memory [working] Automatically compacting context.",
                        data={
                            "stage": "system_memory",
                            "kind": "system_memory_compacting",
                            "memory": payload,
                        },
                    )
                elif stage == "memory_compacted":
                    self._emit_event(
                        project_id,
                        event="system_memory_compacted",
                        scan_id=scan_id,
                        level="success",
                        message="System Memory [completed] Context compaction complete.",
                        data={
                            "stage": "system_memory",
                            "kind": "system_memory_compacted",
                            "memory": payload,
                        },
                    )

            from server.agents.executer.recon.tools import ALL_RECON_TOOLS
            from server.agents.executer.target_tool_routing import filter_tools_for_target_types

            scoped_tools = filter_tools_for_target_types(
                role="recon",
                tools=ALL_RECON_TOOLS,
                target_types=[_normalize_target_type(target_type)],
            )
            tool_map = {tool.name: tool for tool in scoped_tools}

            def _build_target_info_gathering_result(memory: dict[str, Any]) -> dict[str, Any]:
                return brain_builder.build_structured_brain(memory)

            async def _await_information_gathering_plan_approval(memory: dict[str, Any]) -> None:
                target_info_gathering_result = _build_target_info_gathering_result(memory)
                self._persist_project_status(
                    project_id,
                    status="running",
                    scan_progress=18,
                    scan_meta={
                        "scanId": scan_id,
                        "status": "running",
                        "startedAt": started_at,
                        "finishedAt": None,
                        "error": "",
                        "awaitingInformationGatheringApproval": True,
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
                            "targetInfoProfile": target_info_profile,
                            "targetMemory": memory.get("paths", {}),
                            "targetInfoGathering": target_info_gathering_result,
                            "warmup": {
                                "status": "skipped",
                                "plan": {},
                                "summaries": [],
                            },
                        },
                    },
                )


            # Setup callback context for tools to request passwords/approvals
            info_gathering_cb = InformationGatheringScanCallback(
                service=self,
                project_id=project_id,
                scan_id=scan_id,
                enabled=print_steps,
            )
            
            target_memory = _load_target_memory(project_cache_dir)
            gathering_state = target_memory.get("gathering", {}) if isinstance(target_memory.get("gathering"), dict) else {}
            if str(gathering_state.get("status", "")).strip().lower() != "completed":
                callback_token = _executer_callback_context.set(info_gathering_cb)
                try:
                    target_memory = await brain_builder.run(
                        project_id=project_id,
                        scan_id=scan_id,
                        target=target,
                        target_type=_normalize_target_type(target_type),
                        scope=scope_text,
                        info=info,
                        profile=target_info_profile,
                        project_cache_dir=project_cache_dir,
                        tool_map=tool_map,
                        tool_arg_builder=_build_target_info_tool_kwargs,
                        progress_callback=_emit_system_memory_progress,
                        pre_execution_gate=None,
                    )
                    target_memory = _apply_memory_enrichment(target_memory)
                    target_memory = await _run_authenticated_surface_enrichment(
                        project_cache_dir=project_cache_dir,
                        target_memory=target_memory,
                        target=target,
                        target_type=target_type,
                        target_config=project.get("targetConfig") if isinstance(project.get("targetConfig"), dict) else None,
                        tool_map=tool_map,
                    )
                finally:
                    _executer_callback_context.reset(callback_token)
                target_memory = _apply_memory_enrichment(target_memory)
                target_memory = await _save_target_memory(
                    project_cache_dir,
                    target_memory,
                    memory_llm=SystemMemoryLLM(),
                )
                
            target_info_gathering_result = _build_target_info_gathering_result(target_memory)
            detected_tech = [
                str(value).strip()
                for value in (target_memory.get("tech_stack", {}) or {}).values()
                if str(value).strip()
            ] if isinstance(target_memory.get("tech_stack"), dict) else []
            self._emit_event(
                project_id,
                event="target_info_gathering_complete",
                scan_id=scan_id,
                level="success",
                message="Information Gathering [completed] grouped static target-info gathering saved to system memory.",
                data={
                    "stage": "information_gathering",
                    "kind": "target_info_gathering_complete",
                    "gathering": target_memory.get("gathering", {}),
                    "target_memory": target_memory.get("paths", {}),
                    "block_count": len(target_memory.get("gathering", {}).get("blocks", []))
                    if isinstance(target_memory.get("gathering", {}), dict)
                    else 0,
                },
            )

            self._persist_project_status(
                project_id,
                status="running",
                scan_progress=35,
                scan_meta={
                    "scanId": scan_id,
                    "status": "running",
                    "startedAt": started_at,
                    "finishedAt": None,
                    "error": "",
                    "awaitingInformationGatheringApproval": False,
                    "awaitingPlannerApproval": False,
                    "detectedTech": detected_tech[:10],
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
                        "targetInfoProfile": target_info_profile,
                        "targetMemory": target_memory.get("paths", {}),
                        "targetInfoGathering": target_info_gathering_result,
                        "warmup": {
                            "status": "skipped",
                            "plan": {},
                            "summaries": [],
                        },
                    },
                },
            )

            synthesis_info = _build_post_gathering_intel_info(
                info=info,
                target_memory=target_memory,
            )
            
            existing_checklist = {}
            existing_summary = ""
            existing_plan_data: dict[str, Any] = {}
            if resume and isinstance(project, dict):
                last_scan = project.get("lastScan", {}) or {}
                existing_plan_data = _extract_saved_plan_from_last_scan(last_scan)
                last_result = last_scan.get("result", {}) or {}
                last_intel = last_result.get("intel", {}) or {}
                existing_checklist = last_intel.get("checklist", {}) or {}
                existing_summary = last_intel.get("summary", "") or ""

            if resume and existing_plan_data:
                intel_checklist = existing_checklist
                intel_summary = existing_summary
                intel_status = "complete"
                info = synthesis_info
                self._emit_event(
                    project_id,
                    event="planner_checklist_started",
                    scan_id=scan_id,
                    level="info",
                    message="Planner [start] Rebuilding checklist from saved plan checkpoint.",
                    data={
                        "stage": "planner",
                        "kind": "checklist_start",
                        "resume_source": "saved_plan",
                        "scenario_count": _count_total_scenarios(existing_plan_data),
                        "warmup_summary_count": 0,
                        "project_cache_dir": project_cache_dir,
                    },
                )
            else:
                self._emit_event(
                    project_id,
                    event="planner_checklist_started",
                    scan_id=scan_id,
                    level="info",
                    message="Planner [start] generating prioritized checklist from grouped information gathering, target info, and any user checklist input.",
                    data={
                        "stage": "planner",
                        "kind": "checklist_start",
                        "warmup_summary_count": 0,
                        "warmup_cache_path": "",
                        "project_cache_dir": project_cache_dir,
                    },
                )
                from server.agents.planner.agent import PlannerAgent
    
                checklist_callback = PrintCallback(
                    enabled=print_steps,
                    on_log=lambda level, message: self._emit_planner_callback_event(
                        project_id=project_id,
                        scan_id=scan_id,
                        level=level,
                        raw_message=message,
                    ),
                )
                checklist_input = _build_planner_checklist_message(
                    target=target,
                    target_type=target_type,
                    scope=scope_text,
                    info=synthesis_info,
                    target_info_profile=target_info_profile,
                    target_memory=target_memory,
                    custom_checklist_text=custom_checklist_text,
                    current_checklist={},
                )
                async with PlannerAgent(
                    callback=checklist_callback,
                    project_id=project_id,
                    projects_store=self._projects_store,
                    vector_store=self._vector_store,
                ) as checklist_planner:
                    planner_checklist_result = await checklist_planner.generate_checklist(
                        checklist_input,
                        current_checklist={},
                        target_type=target_type,
                    )
                intel_summary = planner_checklist_result.summary
                intel_status = planner_checklist_result.status
                intel_checklist = (
                    planner_checklist_result.checklist
                    if isinstance(planner_checklist_result.checklist, dict)
                    else {}
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
                event="planner_checklist_crashed",
                scan_id=scan_id,
                level="error",
                message=f"Planner checklist generation [crashed] {exc}",
                data={
                    "stage": "planner",
                    "kind": "crashed",
                    "error": str(exc),
                },
            )
            self._mark_failed(project_id, scan_id, f"planner checklist runtime error: {exc}")
            return

        checklist_items_count = _count_checklist_items(intel_checklist)
        self._emit_event(
            project_id,
            event="planner_checklist_complete",
            scan_id=scan_id,
            level="success",
            message="Planner [completed] synthesized checklist ready after grouped information gathering.",
            data={
                "stage": "planner",
                "kind": "checklist_completed",
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
            "awaitingInformationGatheringApproval": False,
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
                "targetInfoProfile": target_info_profile,
                "targetMemory": target_memory.get("paths", {}),
                "targetInfoGathering": target_info_gathering_result,
                "warmup": {
                    "status": "skipped",
                    "plan": {},
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

        project = self._projects_store.get_project(project_id)
        approval_mode = str(project.get("approval_mode") or "custom").lower().strip() if project else "custom"
        
        gate = None
        run_state = self._runs.get(project_id)
        if isinstance(run_state, dict):
            # Sync run_state
            run_state["approval_mode"] = approval_mode
            
            if approval_mode == "auto" or resume:
                logger.info("planner_auto_approved_or_resumed", project_id=project_id)
                gate = None
            else:
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
                        "Planner [waiting approval] Planner-generated checklist is ready. "
                        "Review/edit checklist, then click Continue to Planner."
                    ),
                    data={
                        "stage": "planner",
                        "kind": "waiting_approval",
                        "status": "awaiting_planner_approval",
                        "awaiting_user_approval": True,
                        "checklist_items_count": checklist_items_count,
                        "warmup_summary_count": len(warmup_summaries),
                        "checklist": intel_checklist,
                        "summary": intel_summary,
                        "intel_status": intel_status,
                    },
                )
                logger.info(
                    "scan_orchestrator_waiting_planner_approval",
                    project_id=project_id,
                    scan_id=scan_id,
                    checklist_items_count=checklist_items_count,
                )

        if gate:
            wait_start = time.time()
            try:
                await gate.wait()
                wait_duration = time.time() - wait_start
                if wait_duration > 0.1:
                    self._shift_project_scan_start_time(project_id, wait_duration)
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

        target_memory = await brain_builder.memory_node.store_checklist(
            project_cache_dir,
            checklist=intel_checklist,
        )

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
                    "targetInfoProfile": target_info_profile,
                    "targetMemory": target_memory.get("paths", {}),
                    "targetInfoGathering": target_info_gathering_result,
                    "warmup": {
                        "status": "skipped",
                        "plan": {},
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
            intel_vulnerabilities=[],
            intel_stats=intel_stats,
            intel_checklist=intel_checklist,
            checklist_overview={
                "target_type": str(intel_checklist.get("target_type", "") or target_type),
                "available_total": int(intel_checklist.get("available_total", 0) or 0),
                "items_count": checklist_items_count,
            },
            target_info_profile=target_info_profile,
            target_memory=target_memory,
            warmup_summaries=warmup_summaries,
        )
        existing_plan = {}
        if resume and isinstance(project, dict):
            last_scan = project.get("lastScan", {}) or {}
            existing_plan = _extract_saved_plan_from_last_scan(last_scan)

        try:
            from server.agents.planner.agent import PlannerAgent, PlannerResult

            if resume and existing_plan and existing_plan.get("phases"):
                self._emit_event(
                    project_id,
                    event="planner_started",
                    scan_id=scan_id,
                    level="info",
                    message="Planner [start] agent started to rebuild pentest plan from resumed checkpoint.",
                    data={"stage": "planner", "status": "running", "kind": "start"},
                )
                plan_data, resume_plan_stats = _prepare_plan_for_resume(existing_plan)
                _sync_plan_data_into_planner_state(plan_data)
                
                # We do NOT return a fake PlannerResult here anymore.
                # We inject the resumed plan_data into the planner's input so it runs
                # a full planning cycle over the explicitly reset scenarios.
                planner_callback = PrintCallback(
                    enabled=print_steps,
                    on_log=lambda level, message: self._emit_planner_callback_event(
                        project_id=project_id,
                        scan_id=scan_id,
                        level=level,
                        raw_message=message,
                    ),
                )
                
                # Append context to inform the LLM it's resuming and needs to re-evaluate
                resume_context = f"\n\nRESUME CONTEXT: We are resuming a previous scan. Previous scenarios have been reset to 'not yet'. Re-evaluate the plan, validate prerequisites, and select exactly two scenarios to execute next.\n\n"
                
                async with PlannerAgent(
                    callback=planner_callback,
                    project_id=project_id,
                    projects_store=self._projects_store,
                    vector_store=self._vector_store,
                ) as planner_agent:
                    planner_result = await planner_agent.run(
                        planner_input + resume_context,
                        is_loop=False,
                        intel_checklist=intel_checklist,
                        plan_mode="full",
                    )
                    from server.agents.planner.tools.pentest_plan import _current_plan
                    plan_data = dict(_current_plan) if isinstance(_current_plan, dict) else {}
            else:
                self._emit_event(
                    project_id,
                    event="planner_started",
                    scan_id=scan_id,
                    level="info",
                    message="Planner [start] agent started to build pentest plan.",
                    data={"stage": "planner", "status": "running", "kind": "start"},
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
                plan_data, pruned_blocked_count = _prune_plan_blocked_route_scenarios(
                    plan_data,
                    target_memory=target_memory,
                )
                plan_data, pruned_unbacked_count = _prune_plan_unbacked_assumption_scenarios(
                    plan_data,
                    target_memory=target_memory,
                )
                if pruned_blocked_count > 0 or pruned_unbacked_count > 0:
                    _sync_plan_data_into_planner_state(plan_data)
                    logger.info(
                        "planner_initial_scenario_guardrail_prune",
                        removed_scenarios=pruned_blocked_count,
                        removed_unbacked_scenarios=pruned_unbacked_count,
                    )
                    self._emit_event(
                        project_id,
                        event="planner_scenario_guardrail_prune",
                        scan_id=scan_id,
                        level="info",
                        message=(
                            "Planner [guardrail] Removed "
                            f"{pruned_blocked_count + pruned_unbacked_count} scenario(s) "
                            "that targeted disproven routes or relied on unobserved assumptions."
                        ),
                        data={
                            "stage": "planner",
                            "kind": "scenario_guardrail_prune",
                            "removed_blocked_route_scenarios": pruned_blocked_count,
                            "removed_unbacked_scenarios": pruned_unbacked_count,
                        },
                    )

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

                if _count_total_scenarios(plan_data) <= 0:
                    fallback_plan_data = _build_fallback_plan_from_checklist(
                        target=target,
                        scope=scope_text,
                        target_type=target_type,
                        checklist=intel_checklist,
                    )
                    plan_data = _sanitize_plan_remove_forbidden_agents(fallback_plan_data)
                    plan_data, fallback_pruned_count = _prune_plan_blocked_route_scenarios(
                        plan_data,
                        target_memory=target_memory,
                    )
                    plan_data, fallback_unbacked_pruned_count = _prune_plan_unbacked_assumption_scenarios(
                        plan_data,
                        target_memory=target_memory,
                    )
                    _sync_plan_data_into_planner_state(plan_data)
                    logger.warning(
                        "planner_fallback_plan_applied",
                        project_id=project_id,
                        scan_id=scan_id,
                        checklist_items=_count_checklist_items(intel_checklist),
                        fallback_scenarios=_count_total_scenarios(plan_data),
                        pruned_blocked_routes=fallback_pruned_count,
                        pruned_unbacked_scenarios=fallback_unbacked_pruned_count,
                    )
                    self._emit_event(
                        project_id,
                        event="planner_fallback_plan_applied",
                        scan_id=scan_id,
                        level="warn",
                        message="Planner [fallback] No runnable scenarios were persisted. Built a fallback plan from the approved checklist.",
                        data={
                            "stage": "planner",
                            "kind": "fallback_plan",
                            "plan_data": plan_data,
                            "scenario_count": _count_total_scenarios(plan_data),
                        },
                    )
                    planner_result.summary = "Built fallback plan from approved checklist due to planner failure."
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

        self._persist_project_status(
            project_id,
            status="running",
            scan_progress=75,
            scan_meta={
                "scanId": scan_id,
                "status": "running",
                "startedAt": started_at,
                "finishedAt": None,
                "error": "",
                "awaitingPlannerApproval": False,
                "plan": plan_data,
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
                    "targetInfoProfile": target_info_profile,
                    "targetMemory": target_memory.get("paths", {}),
                    "targetInfoGathering": target_info_gathering_result,
                    "warmup": {
                        "status": "skipped",
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
                },
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

        recon_agent = None
        recon_agent_worker_1 = None
        exploit_agent = None
        analyzer_agent = None
        loop_planner = None

        try:
            from server.agents.analyzer import AnalyzerAgent
            from server.agents.executer.recon.agent import ReconExecuterAgent
            from server.agents.executer.exploit.agent import ExploitExecuterAgent
            from server.agents.planner.agent import PlannerAgent
            from server.config.agent import get_public_agent_config

            executer_callback = ExecuterScanCallback(
                service=self,
                project_id=project_id,
                scan_id=scan_id,
                enabled=print_steps,
            )
            analyzer_callback = AnalyzerScanCallback(
                service=self,
                project_id=project_id,
                scan_id=scan_id,
                enabled=print_steps,
            )
            recon_worker_0_callback = WorkerExecuterCallback(parent=executer_callback, worker_index=0)
            recon_worker_1_callback = WorkerExecuterCallback(parent=executer_callback, worker_index=1)

            recon_agent = ReconExecuterAgent(
                callback=recon_worker_0_callback,
                target_types=[target_type],
                project_id=project_id,
                project_cache_dir=project_cache_dir,
                approval_mode=run_state.get("approval_mode", "custom"),
            )
            recon_agent_worker_1 = ReconExecuterAgent(
                callback=recon_worker_1_callback,
                target_types=[target_type],
                project_id=project_id,
                project_cache_dir=project_cache_dir,
                config=get_public_agent_config("exploit"),
                approval_mode=run_state.get("approval_mode", "custom"),
            )
            exploit_agent = ExploitExecuterAgent(
                callback=executer_callback,
                target_types=[target_type],
                project_id=project_id,
                project_cache_dir=project_cache_dir,
                approval_mode=run_state.get("approval_mode", "custom"),
            )
            analyzer_agent = AnalyzerAgent(
                callback=analyzer_callback,
                project_id=project_id,
                project_cache_dir=project_cache_dir,
            )
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
            await recon_agent_worker_1.clear_context_window()
            await exploit_agent.clear_context_window()
            await analyzer_agent.clear_context_window()

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
                    display_cycle_count = _display_cycle_number(cycle_count)

                    # FRESH CONTEXT PER CYCLE: Reset context windows for executer agents
                    # (only Planner keeps context across cycles)
                    recon_agent.reset_context_window_for_cycle()
                    recon_agent_worker_1.reset_context_window_for_cycle()
                    exploit_agent.reset_context_window_for_cycle()
                    analyzer_agent.reset_context_window_for_cycle()
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
                            recon_agent_worker_1=recon_agent_worker_1,
                            exploit_agent=exploit_agent,
                            analyzer_agent=analyzer_agent,
                            loop_planner=loop_planner,
                            target=target,
                            target_type=target_type,
                            scope=exec_scope,
                            info=info,
                            intel_checklist=intel_checklist,
                            project_cache_dir=project_cache_dir,
                            target_memory=target_memory,
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

                    self._emit_event(
                        project_id,
                        event="executer_cycle_completed",
                        scan_id=scan_id,
                        level="success",
                        message=(
                            f"Planner [loop] cycle {display_cycle_count} handoff ready."
                        ),
                        data={
                            "stage": "planner",
                            "kind": "cycle_completed",
                            "source_stage": "executer",
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
                            message="Planner [done signal] returned completion.",
                            data={
                                "stage": "planner",
                                "kind": "planner_done",
                                "source_stage": "executer",
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
            finally:
                if recon_agent:
                    await recon_agent.close()
                if recon_agent_worker_1:
                    await recon_agent_worker_1.close()
                if exploit_agent:
                    await exploit_agent.close()
                if analyzer_agent:
                    await analyzer_agent.close()
                if loop_planner:
                    await loop_planner.close()

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
                "plan": plan_data,
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
                    "targetInfoProfile": target_info_profile,
                    "targetMemory": target_memory.get("paths", {}),
                    "targetInfoGathering": target_info_gathering_result,
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
                "awaiting_information_gathering_approval": False,
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

        except Exception as exc:
            logger.exception(
                "scan_orchestrator_fatal_error",
                project_id=project_id,
                scan_id=scan_id,
                error=str(exc),
            )
            self._mark_failed(project_id, scan_id, f"fatal orchestrator error: {exc}")
        finally:
            current_run = self._runs.get(project_id)
            if isinstance(current_run, dict) and str(current_run.get("scan_id")) == str(scan_id):
                self._runs.pop(project_id, None)
                self._planner_approval_events.pop(project_id, None)
                self._info_gathering_approval_events.pop(project_id, None)

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
            "awaiting_information_gathering_approval": False,
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

    def _shift_project_scan_start_time(self, project_id: str, shift_seconds: float) -> None:
        try:
            from datetime import datetime, timedelta
            project = self._projects_store.get_project(project_id)
            if not project or not isinstance(project, dict):
                return
            last_scan = project.get("lastScan")
            if not isinstance(last_scan, dict):
                return
            started_at_raw = last_scan.get("startedAt")
            if not started_at_raw:
                return
            
            try:
                started_dt = datetime.fromisoformat(started_at_raw.replace("Z", "+00:00"))
            except ValueError:
                return
                
            shifted_dt = started_dt + timedelta(seconds=shift_seconds)
            new_started_at = shifted_dt.isoformat()
            if started_at_raw.endswith("Z"):
                new_started_at = new_started_at.replace("+00:00", "Z")
            
            last_scan["startedAt"] = new_started_at
            
            elapsed_seconds = _compute_scan_elapsed_seconds(last_scan)
            last_scan["elapsedSeconds"] = elapsed_seconds
            
            project["lastScan"] = last_scan
            self._projects_store.upsert_project(project)
            
            self._emit_event(
                project_id,
                event="project_status",
                scan_id=str(last_scan.get("scanId", "")),
                level="info",
                message="Adjusting scan timer for wait period.",
                data={
                    "status": project.get("status", "running"),
                    "scan_progress": project.get("scanProgress", 50),
                    "elapsed_seconds": elapsed_seconds,
                    "started_at": new_started_at,
                    "finished_at": last_scan.get("finishedAt"),
                },
            )
            logger.info("shifted_scan_started_at_for_gate_wait", project_id=project_id, shift_seconds=shift_seconds, new_started_at=new_started_at)
        except Exception as exc:
            logger.warning("failed_to_shift_project_scan_start_time", project_id=project_id, error=str(exc))

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
        existing_last_scan = project.get("lastScan", {})
        merged_scan_meta = _merge_scan_metadata(
            existing_last_scan if isinstance(existing_last_scan, dict) else {},
            scan_meta if isinstance(scan_meta, dict) else {},
        )
        elapsed_seconds = _compute_scan_elapsed_seconds(merged_scan_meta)
        merged_scan_meta["elapsedSeconds"] = elapsed_seconds
        if status in {"completed", "paused", "error"}:
            merged_scan_meta["durationSeconds"] = elapsed_seconds
        project["lastScan"] = merged_scan_meta
        self._projects_store.upsert_project(project)
        self._emit_event(
            project_id,
            event="project_status",
            scan_id=str(merged_scan_meta.get("scanId", "")),
            level="warn" if status == "error" else "success" if status == "completed" else "info",
            message=f"Project status updated to {status}.",
            data={
                "status": status,
                "scan_progress": scan_progress,
                "elapsed_seconds": elapsed_seconds,
                "started_at": merged_scan_meta.get("startedAt"),
                "finished_at": merged_scan_meta.get("finishedAt"),
            },
        )
