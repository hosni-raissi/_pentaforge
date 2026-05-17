"""Target-type aware tool routing for executer agents."""

from __future__ import annotations

import json
import re
from typing import Any

from server.core.tool import Tool
from server.agents.executer.recon.tools.index import load_recon_tool_scope_index
from server.utils.known_vuln_intelligence import (
    recommend_nuclei_hints,
    recommend_run_custom_tools,
)

_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web": "web_app",
    "webapp": "web_app",
    "web_app": "web_app",
    "api": "api",
    "network": "network",
    "infra": "infra",
    "infrastructure": "infra",
    "linux": "linux_server",
    "server": "linux_server",
    "linux_server": "linux_server",
    "mobile": "mobile",
    "desktop": "desktop",
    "binary": "desktop",
    "cloud": "cloud",
    "container": "container",
    "db": "infra",
    "database": "infra",
    "repo": "repository",
    "repository": "repository",
    "supply_chain": "repository",
    "iot": "iot",
    "shared": "shared",
}

_VALID_TARGET_TYPES: set[str] = {
    "web_app",
    "api",
    "network",
    "infra",
    "linux_server",
    "mobile",
    "desktop",
    "cloud",
    "container",
    "repository",
    "iot",
    "shared",
}

_RECON_TOOL_SCOPE_INDEX = load_recon_tool_scope_index()
_WEB_SCOPE_RECON_TOOL_TARGET_TYPES: dict[str, set[str]] = {
    tool_name: {"web_app", "api"}
    for tool_name in _RECON_TOOL_SCOPE_INDEX.get("web", [])
}

RECON_TOOL_TARGET_TYPES: dict[str, set[str]] = {
    "api_endpoint_discovery": {"api", "web_app"},
    "api_service_recon": {"api", "web_app"},
    "api_passive_enum": {"api", "web_app"},
    "api_response_analyzer": {"api", "web_app"},
    "arp_scan": {"network", "infra", "iot"},
    "ci_cd_pipeline_audit": {"repository"},
    "cloud_misconfig_scan": {"cloud"},
    "cloud_storage_enum": {"cloud"},
    "container_image_scan": {"container"},
    "container_layer_analysis": {"container"},
    "container_registry_enum": {"cloud", "container"},
    "container_runtime_audit": {"container"},
    "dependency_scan": {"repository"},
    "dns_recon": {"network", "infra", "web_app"},
    "firmware_analysis": {"iot"},
    "git_history_audit": {"repository"},
    "iac_security_scan": {"repository", "infra"},
    "iot_protocol_scan": {"iot", "network"},
    "mobile_dynamic_analysis": {"mobile"},
    "mobile_static_analysis": {"mobile"},
    "mobile_storage_check": {"mobile"},
    "known_vuln_lookup": {"web_app", "api", "linux_server", "infra", "network", "cloud"},
    "run_custom": {"shared"},
    "run_python": {"shared"},
    "sast_scan": {"repository"},
    "secret_scan": {"repository", "cloud"},
    "sensitive_files_scan": {"repository"},
    "traffic_analyze": {"network", "infra"},
    "wireless_scan": {"network", "iot"},
    **_WEB_SCOPE_RECON_TOOL_TARGET_TYPES,
}

EXPLOIT_TOOL_TARGET_TYPES: dict[str, set[str]] = {
    "api_payload_injection": {"api", "web_app"},
    "api_abuse_test": {"api", "web_app"},
    "api_authz_matrix": {"api", "web_app"},
    "api_auth_test": {"api", "web_app"},
    "api_fuzzing": {"api", "web_app"},
    "db_injection_test": {
        "web_app",
        "api",
        "network",
        "infra",
        "linux_server",
        "mobile",
        "desktop",
        "cloud",
        "container",
        "repository",
        "iot",
    },
    "encode_payload": {"shared"},
    "file_upload_api_abuse": {"api", "web_app"},
    "generate_payload": {"shared"},
    "generate_oob_payload": {"web_app", "api"},
    "generate_waf_bypass_variants": {"shared"},
    "graphql_attack": {"api", "web_app"},
    "hydra_bruteforce": {"network", "infra", "linux_server", "iot", "web_app", "api"},
    "http_smuggling": {"web_app", "api"},
    "john_the_ripper_bruteforce": {"linux_server", "infra", "repository", "desktop"},
    "jwt_attack": {"api", "web_app"},
    "metasploit_exploit": {
        "web_app",
        "api",
        "network",
        "infra",
        "linux_server",
        "cloud",
        "container",
        "iot",
    },
    "nuclei_vuln_scan": {"web_app", "api", "network", "infra", "cloud"},
    "nosql_injection_test": {"api", "web_app"},
    "open_redirect_scan": {"web_app", "api"},
    "prompt_injection_test": {"api", "web_app"},
    "race_condition_test": {"api", "web_app"},
    "run_custom": {"shared"},
    "run_python": {"shared"},
    "script_injection_test": {"web_app", "api"},
    "sqlmap_injection": {
        "web_app",
        "api",
        "network",
        "infra",
        "linux_server",
        "mobile",
        "desktop",
        "cloud",
        "container",
        "repository",
        "iot",
    },
    "ssrf_detect": {"web_app", "api"},
    "ssti_detect": {"web_app", "api"},
    "check_oob_callbacks": {"web_app", "api"},
    "web_payload_injection": {"web_app", "api"},
    "web_auth_brute": {"web_app", "api"},
    "webhook_security_test": {"api", "web_app"},
    "websocket_attack": {"web_app", "api"},
    "xss_scan": {"web_app", "api"},
}

_TARGET_TYPE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("mobile", re.compile(r"\b(apk|ipa|android|ios|mobile app)\b", re.IGNORECASE)),
    ("repository", re.compile(r"\b(github|gitlab|bitbucket|repository|repo)\b", re.IGNORECASE)),
    ("cloud", re.compile(r"\b(s3://|gs://|azure blob|cloudfront|bucket)\b", re.IGNORECASE)),
    ("container", re.compile(r"\b(docker|kubernetes|k8s|container image|pod)\b", re.IGNORECASE)),
    ("infra", re.compile(r"\b(mysql|postgres|mssql|mongodb|redis|database)\b", re.IGNORECASE)),
    ("iot", re.compile(r"\b(iot|mqtt|coap|modbus|firmware)\b", re.IGNORECASE)),
    ("api", re.compile(r"\b(api|swagger|openapi|graphql)\b", re.IGNORECASE)),
    ("web_app", re.compile(r"\b(http|https|web|vhost|subdomain)\b", re.IGNORECASE)),
    ("network", re.compile(r"\b(cidr|open port|snmp|smb|rdp|ssh|nmap|network)\b", re.IGNORECASE)),
]


def normalize_target_type(value: Any) -> str:
    cleaned = str(value or "").strip().lower().replace("-", "_")
    if not cleaned:
        return ""
    normalized = _TARGET_TYPE_ALIASES.get(cleaned, cleaned)
    return normalized if normalized in _VALID_TARGET_TYPES else ""


def normalize_target_types(values: list[Any] | tuple[Any, ...] | set[Any] | None) -> list[str]:
    if not values:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = normalize_target_type(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def _mapping_for_role(role: str) -> dict[str, set[str]]:
    clean_role = str(role or "").strip().lower()
    if clean_role == "exploit":
        return EXPLOIT_TOOL_TARGET_TYPES
    return RECON_TOOL_TARGET_TYPES


def filter_tools_for_target_types(
    *,
    role: str,
    tools: list[Tool],
    target_types: list[str] | None,
) -> list[Tool]:
    normalized_types = set(normalize_target_types(target_types))
    if not normalized_types:
        return tools

    mapping = _mapping_for_role(role)
    filtered: list[Tool] = []
    for tool in tools:
        allowed_for_tool = mapping.get(tool.name)
        if not allowed_for_tool:
            # Keep unmapped tools available by default to avoid accidental outages.
            filtered.append(tool)
            continue
        if "shared" in allowed_for_tool or allowed_for_tool.intersection(normalized_types):
            filtered.append(tool)
    return filtered


def tools_by_target_type(*, role: str, target_type: str, tools: list[Tool]) -> list[str]:
    normalized_target = normalize_target_type(target_type)
    if not normalized_target:
        return []
    selected = filter_tools_for_target_types(
        role=role,
        tools=tools,
        target_types=[normalized_target],
    )
    return [tool.name for tool in selected]


def mapped_tool_names_for_target_type(*, role: str, target_type: str) -> list[str]:
    normalized_target = normalize_target_type(target_type)
    if not normalized_target:
        return []
    mapping = _mapping_for_role(role)
    names: list[str] = []
    for name, allowed in mapping.items():
        if "shared" in allowed or normalized_target in allowed:
            names.append(name)
    names.sort()
    return names


def recommend_product_tooling(
    *,
    role: str,
    target_type: str,
    tech_inventory: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    del role
    normalized_target = normalize_target_type(target_type)
    if not normalized_target:
        return {
            "target_type": "",
            "recommended_run_custom_tools": [],
            "nuclei_hints": {},
        }
    return {
        "target_type": normalized_target,
        "recommended_run_custom_tools": recommend_run_custom_tools(tech_inventory),
        "nuclei_hints": recommend_nuclei_hints(tech_inventory),
    }


def _collect_target_types_from_obj(obj: Any, out: set[str]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).strip().lower()
            if key_lower in {
                "target_type",
                "target_types",
                "surface",
                "surfaces",
                "discovered_target_type",
                "discovered_target_types",
                "detected_target_types",
            }:
                if isinstance(value, list):
                    for entry in value:
                        normalized = normalize_target_type(entry)
                        if normalized:
                            out.add(normalized)
                else:
                    normalized = normalize_target_type(value)
                    if normalized:
                        out.add(normalized)
            _collect_target_types_from_obj(value, out)
        return

    if isinstance(obj, list):
        for item in obj:
            _collect_target_types_from_obj(item, out)
        return

    if isinstance(obj, str):
        text = obj.strip()
        if not text:
            return
        direct = normalize_target_type(text)
        if direct:
            out.add(direct)
        for target_type, pattern in _TARGET_TYPE_PATTERNS:
            if pattern.search(text):
                out.add(target_type)


def extract_discovered_target_types(raw_output: Any) -> list[str]:
    discovered: set[str] = set()

    if isinstance(raw_output, dict):
        _collect_target_types_from_obj(raw_output, discovered)
        return sorted(discovered)

    if isinstance(raw_output, str):
        text = raw_output.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            _collect_target_types_from_obj(parsed, discovered)
        except Exception:
            pass
        _collect_target_types_from_obj(text, discovered)
        return sorted(discovered)

    _collect_target_types_from_obj(raw_output, discovered)
    return sorted(discovered)


def merge_target_types(base: list[str] | None, discovered: list[str] | None) -> list[str]:
    merged = normalize_target_types(base or [])
    seen = set(merged)
    for target_type in normalize_target_types(discovered or []):
        if target_type not in seen:
            merged.append(target_type)
            seen.add(target_type)
    return merged
