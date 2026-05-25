"""Scan utilities for PentaForge orchestrator and agents."""

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shutil
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Optional, Sequence, Union, cast
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)

from .grounding import (
    _build_target_memory_evidence_text,
    _validate_grounded_verified_finding_entry,
)
from .verification import VerificationTier, classify_evidence
from server.nodes.information_gathering.profiles import load_target_info_profile_defaults
from server.nodes.system_memory import (
    Brain,
    SystemMemoryLLM,
    append_system_memory_updates as _append_system_memory_updates_external,
    build_system_memory_prompt_block as _build_target_memory_prompt_block_external,
    compute_tool_efficiency_snapshot as _compute_tool_efficiency_snapshot,
    load_system_memory as _load_target_memory_external,
    merge_system_memory_artifacts as _merge_target_memory_artifacts_external,
    save_system_memory as _save_target_memory_external,
    system_memory_dir as _system_memory_dir_external,
    system_memory_paths as _system_memory_paths_external,
)
from server.tools.session.session_manager import SessionContext, SessionManager
from server.db.projects.runtime_cache import get_project_runtime_cache
from server.utils.cvss import enrich_payload_with_cvss

WARMUP_RECON_SCENARIO_COUNT = 8

MAX_SYNTH_INTEL_CHECKLIST_ITEMS = 20

RETEST_MIN_CONFIDENCE = 0.75

SCENARIO_EXECUTION_HISTORY_LIMIT = 4

PROMPT_HISTORY_SCENARIO_LIMIT = 3

PROMPT_HISTORY_ROLE_LIMIT = 6

PROMPT_HISTORY_TOOL_LIMIT = 4

PROJECT_FINDINGS_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60

WARMUP_PERCEPTOR_CACHE_TTL_SECONDS = 2 * 60 * 60

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

_SCENARIO_FAMILY_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("sql_injection", ("sql injection", "sqli", "union select", "boolean-based", "time-based")),
    ("xss", ("xss", "cross-site scripting", "script injection", "dom-based")),
    ("ssrf", ("ssrf", "server-side request forgery", "metadata endpoints", "url parameter")),
    ("code_injection", ("code injection", "command injection", "header injection", "/eval", "rce")),
    ("authz", ("idor", "bola", "authorization", "access control", "admin panel")),
    ("generic_recon", ()),
]

_SCENARIO_FAMILY_STRENGTH: dict[str, int] = {
    "generic_recon": 10,
    "xss": 60,
    "authz": 75,
    "code_injection": 85,
    "ssrf": 95,
    "sql_injection": 100,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()



def _normalize_target_type(value: Any) -> str:
    clean = str(value or "").strip().lower().replace("-", "_")
    if not clean:
        return "web_app"
    return _TARGET_TYPE_ALIASES.get(clean, clean)



def _normalize_priority(value: Any) -> int:
    parsed = _coerce_priority(value)
    return parsed if parsed is not None else 3



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



def _build_target_memory_prompt_block(memory: dict[str, Any]) -> str:
    return _build_target_memory_prompt_block_external(memory)



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



def _infer_cloud_provider(*values: Any) -> str:
    text = " ".join(str(value or "") for value in values).lower()
    if any(marker in text for marker in ("aws", "amazon", "s3://", "cloudfront", ".amazonaws.com")):
        return "aws"
    if any(marker in text for marker in ("azure", "blob.core.windows.net", "azurecr.io")):
        return "azure"
    if any(marker in text for marker in ("gcp", "google cloud", "gs://", "gcr.io")):
        return "gcp"
    return ""



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


def _build_executer_message(
    *,
    plan_data: dict[str, Any],
    scenario: dict[str, Any],
    target: str,
    target_type: str,
    scope: str,
    info: str,
    target_memory: dict[str, Any] | None = None,
) -> str:
    from server.agents.executer.payload_filter import get_payloads as _get_filtered_payloads_local
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
        _get_filtered_payloads_local(payload_family, executor_projection.get("tech_stack"), max_payloads=5)
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
        labeled_scenarios.append({"scenario_id": scenario_id, "scenario": scenario})
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
    *,
    project_id: str,
    scan_id: str,
    plan_data: dict[str, Any],
    analyzer_agent: Any,
    scenario: dict[str, Any],
    row_result: dict[str, Any],
    cycle_number: int,
    worker_number: int,
    emit_event: Callable[..., None] | None = None,
) -> dict[str, Any]:
    tool_results = row_result.get("tool_results", []) if isinstance(row_result, dict) else []
    if isinstance(tool_results, list) and tool_results:
        assessment = await analyzer_agent.assess_tool_results(
            scenario=scenario if isinstance(scenario, dict) else {},
            tool_results=tool_results,
            asset_context={"criticality": "medium", "internet_exposed": True},
        )
    else:
        assessment = await analyzer_agent.assess_text(
            str(row_result.get("summary", "")).strip(),
            scenario=scenario if isinstance(scenario, dict) else {},
            tool_name="warmup_summary",
            asset_context={"criticality": "medium", "internet_exposed": True},
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

    if emit_event is not None:
        emit_event(
            project_id,
            event="perceptor_cached",
            scan_id=scan_id,
            level="info",
            message=(
                f"Analyzer [cached] cycle {cycle_number} worker {worker_number} "
                f"-> scenario: {scenario_task[:60]} -> {recon_summary[:100]}"
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


async def _run_poc_background(
    *,
    item: dict[str, Any],
    analyzer_agent: Any,
    project_id: str,
    scan_id: str,
    target: str,
    target_type: str,
    project_cache_dir: str,
    emit_event: Callable[..., None] | None = None,
) -> None:
    try:
        poc_data = await analyzer_agent.build_poc(
            target=target,
            target_type=target_type,
            scope="",
            item=item,
        )
        poc_summary = str(poc_data.get("poc") or poc_data.get("summary") or "").strip()
        if emit_event is not None:
            emit_event(
                project_id,
                event="analyzer_poc_generated",
                scan_id=scan_id,
                level="info",
                message=f"Generated PoC for verified finding: {str(item.get('verify_summary', ''))[:80]}",
                data={
                    "stage": "analyzer",
                    "kind": "poc_generated",
                    "verify_summary": item.get("verify_summary", ""),
                    "poc_summary": poc_summary,
                    "severity": _normalize_finding_severity(item.get("scenario", {}).get("priority", "medium")),
                    "vulnerability_type": item.get("scenario", {}).get("vulnerability_type", "unknown"),
                    "endpoint": item.get("scenario", {}).get("endpoint", ""),
                    "evidence_available": bool(poc_data.get("evidence")),
                    "tools_executed": len(poc_data.get("tool_results", [])) if isinstance(poc_data.get("tool_results"), list) else 0,
                },
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
                enrich_payload_with_cvss(
                    {
                        "id": f"vuln-{item['idx']}",
                        "severity": poc_data.get("severity"),
                        "cwe_id": poc_data.get("cwe_id"),
                        "cve_id": poc_data.get("cve_id"),
                        "steps_to_reproduce": poc_data.get("steps_to_reproduce", []),
                        "exploit_script": poc_data.get("exploit_script"),
                        "verification_commands": poc_data.get("verification_commands", []),
                        "visual_evidence_paths": poc_data.get("visual_evidence_paths", []),
                        "impact_assessment": poc_data.get("impact_assessment", {}),
                        "remediation_steps": poc_data.get("remediation_steps", []),
                        "poc_path": poc_summary,
                        "cvss_vector": poc_data.get("cvss_vector"),
                    }
                )
            ],
        )
    except Exception as exc:
        if emit_event is not None:
            emit_event(
                project_id,
                event="analyzer_poc_error",
                scan_id=scan_id,
                level="warn",
                message=f"PoC generation failed: {str(exc)[:100]}",
                data={"stage": "analyzer", "kind": "error", "error": str(exc)},
            )


def _build_verified_finding_memory_entry(entry: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    entry = enrich_payload_with_cvss(dict(entry))
    now_iso = _utc_now_iso()
    return {
        "id": str(entry.get("id", "")).strip() or str(uuid.uuid4()),
        "title": str(entry.get("title", "")).strip() or "Verified finding",
        "summary": str(entry.get("summary", "")).strip() or str(entry.get("verify_summary", "")).strip(),
        "status": str(entry.get("status", "confirmed")).strip() or "confirmed",
        "severity": _normalize_finding_severity(entry.get("severity", "medium")),
        "target": str(entry.get("target", "")).strip(),
        "endpoint": str(entry.get("endpoint", entry.get("target", ""))).strip(),
        "timestamp": str(entry.get("timestamp", "")).strip() or now_iso,
        "updated_at": str(entry.get("updated_at", "")).strip() or now_iso,
        "cwe": str(entry.get("cwe", "")).strip(),
        "cve": str(entry.get("cve", "")).strip(),
        "proof_quality": str(entry.get("proof_quality", "")).strip(),
        "evidence_status": str(entry.get("evidence_status", "")).strip(),
        "cvss_score": entry.get("cvss_score"),
        "cvss_vector": str(entry.get("cvss_vector", "")).strip(),
        "verification_methods": _coerce_string_list(entry.get("verification_methods", [])),
        "commands": _coerce_string_list(entry.get("commands", [])),
        "tools_used": _coerce_string_list(entry.get("tools_used", [])),
    }



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



def _build_verified_finding_entry(
    *,
    target: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    scenario = item.get("scenario", {}) if isinstance(item.get("scenario", {}), dict) else {}
    verify_data = item.get("verify_data", {}) if isinstance(item.get("verify_data", {}), dict) else {}
    verify_summary = str(item.get("verify_summary", "")).strip()
    verify_confidence = _coerce_confidence(item.get("verify_confidence"))
    verify_data = enrich_payload_with_cvss(dict(verify_data), scenario)
    cvss_score = verify_data.get("cvss_score")
    cvss_vector = str(verify_data.get("cvss_vector", "")).strip()
    cvss_severity = str(verify_data.get("cvss_severity", "")).strip().lower()
    severity = _normalize_finding_severity(cvss_severity or scenario.get("priority", "medium"))
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

    verification_tier = classify_evidence(vuln_type, {
        "summary": verify_summary,
        "raw_output": str(verify_data.get("result", "")),
        "deterministic_validation": deterministic_validation,
    })

    description_parts = [
        f"Vulnerability Type: {vuln_type}",
        f"Target Endpoint: {endpoint}",
        "",
        "Finding Summary:",
        verify_summary or "Verified vulnerability confirmed by the Verify agent.",
        "",
        f"Verification Tier: {verification_tier.value.replace('_', ' ').upper()}",
        f"Evidence Status: {evidence_status.replace('_', ' ').upper()}",
        f"Proof Quality: {proof_quality.upper()}",
        f"Deterministic Validation: {'YES' if deterministic_validation else 'NO'}",
        f"Severity Level: {severity.upper()}",
    ]
    if isinstance(cvss_score, (int, float)):
        description_parts.append(f"CVSS Base Score: {float(cvss_score):.1f} ({severity.upper()})")
    if cvss_vector:
        description_parts.append(f"CVSS Vector: {cvss_vector}")
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
    if isinstance(cvss_score, (int, float)):
        evidence_map.setdefault("cvss_score", float(cvss_score))
    if cvss_vector:
        evidence_map.setdefault("cvss_vector", cvss_vector)
    if cvss_severity:
        evidence_map.setdefault("cvss_severity", cvss_severity)
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
        "cvss": float(cvss_score) if isinstance(cvss_score, (int, float)) else scenario.get("cvss"),
        "cvss_score": float(cvss_score) if isinstance(cvss_score, (int, float)) else None,
        "cvss_vector": cvss_vector or None,
        "cvss_severity": cvss_severity or None,
        "cve": cve_candidates[0] if cve_candidates else scenario.get("cve"),
        "ssvc": verify_data.get("ssvc"),
        "evidence_status": evidence_status,
        "proof_quality": proof_quality,
        "deterministic_validation": deterministic_validation,
        "verification_methods": verification_methods,
        "description": "\n".join(description_parts),
        "verification_tier": verification_tier.value,
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



def _is_truthy_env(name: str, default: str = "") -> bool:
    value = os.getenv(name, default).strip().lower()
    return value in {"1", "true", "yes", "on"}



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



def _is_version_disclosure_summary(summary: str) -> bool:
    lowered = str(summary or "").strip().lower()
    if not lowered:
        return False
    version_markers = ("discloses", "server header", "banner", "version", "x-powered-by", "apache/", "nginx/", "php/")
    exploit_markers = ("shell", "dump", "retrieved", "executed", "unauthorized", "time-based", "blind injection", "internal metadata")
    return any(marker in lowered for marker in version_markers) and not any(
        marker in lowered for marker in exploit_markers
    )



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



def _merge_target_memory_artifacts(memory: dict[str, Any], *values: Any) -> None:
    _merge_target_memory_artifacts_external(memory, *values)



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


def _merge_scan_metadata(existing: Any, new_values: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(existing) if isinstance(existing, dict) else {}
    if isinstance(new_values, dict):
        for key, value in new_values.items():
            if value is None:
                continue
            merged[key] = value
    return merged



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



def _coerce_priority(value: Any) -> int | None:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= p <= 6:
        return p
    return None



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



def _route_followup_from_assessment(assessment: dict[str, Any]) -> str:
    """Route perceptor assessment to appropriate next phase: verify, planner, or skip.

    Args:
        assessment: Perceptor assessment with finding_type and overall.ssvc fields

    Returns:
        str: "verify" (gate findings), "planner" (info/recon), or "retest"
    """
    finding_type = assessment.get("finding_type", "").strip().lower()
    overall = assessment.get("overall", {}) if isinstance(assessment, dict) else {}

    # Vulnerabilities go to verify (gate to filter false positives)
    if "vulnerability" in finding_type or finding_type in {"vuln", "vulnerability"}:
        if not isinstance(overall, dict):
            return "verify"

        ssvc = str(overall.get("ssvc", "TRACK")).strip().upper()
        confidence = str(overall.get("confidence", "low")).strip().lower()

        if ssvc == "ACT":
            return "verify"
        if ssvc == "ATTEND" and confidence in {"medium", "high"}:
            return "retest"
        return "planner"

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




def _classify_intel_log_kind(message: str) -> str:
    msg = str(message or "").lower()
    if "starting" in msg or "start" in msg: return "start"
    if "completed" in msg or "finish" in msg or "completed" in msg: return "completed"
    if "crashed" in msg or "failed" in msg or "error" in msg: return "crashed"
    if "finding" in msg or "vulnerability" in msg: return "finding"
    if "progress" in msg or "step" in msg: return "progress"
    return "info"

def _classify_planner_log_kind(message: str) -> str:
    msg = str(message or "").lower()
    if "starting" in msg or "start" in msg: return "start"
    if "completed" in msg or "finish" in msg or "completed" in msg: return "completed"
    if "crashed" in msg or "failed" in msg or "error" in msg: return "crashed"
    if "finding" in msg or "vulnerability" in msg: return "finding"
    if "progress" in msg or "step" in msg: return "progress"
    return "info"
