from __future__ import annotations

import importlib
from collections import defaultdict

from server.agents.executer.target_tool_routing import RECON_TOOL_TARGET_TYPES


def _current_recon_tool_names() -> set[str]:
    recon_tools = importlib.import_module("server.agents.executer.recon.tools").ALL_RECON_TOOLS
    return {tool.name for tool in recon_tools}


def _coverage_by_target_type(names: set[str]) -> dict[str, list[str]]:
    by_type: dict[str, list[str]] = defaultdict(list)
    for tool_name, target_types in RECON_TOOL_TARGET_TYPES.items():
        if tool_name not in names:
            continue
        for target_type in target_types:
            by_type[target_type].append(tool_name)
    return dict(by_type)


def test_recon_tools_are_all_mapped():
    names = _current_recon_tool_names()
    unmapped = sorted(name for name in names if name not in RECON_TOOL_TARGET_TYPES)
    assert not unmapped, f"Recon tools missing target-type mapping: {unmapped}"


def test_recon_target_type_coverage_minimums():
    names = _current_recon_tool_names()
    by_type = _coverage_by_target_type(names)

    # Core target types that must always be covered by recon.
    required_types = {
        "web_app",
        "api",
        "network",
        "cloud",
        "container",
        "mobile",
        "iot",
        "repository",
        "infra",
        "linux_server",
        "desktop",
    }

    missing_types = sorted(t for t in required_types if t not in by_type or not by_type[t])
    assert not missing_types, f"Missing recon coverage for target types: {missing_types}"

    # Depth checks for major surfaces.
    assert len(by_type.get("web_app", [])) >= 10, "web_app recon coverage is too shallow"
    assert len(by_type.get("api", [])) >= 8, "api recon coverage is too shallow"
    assert len(by_type.get("network", [])) >= 6, "network recon coverage is too shallow"


def test_recon_has_critical_capabilities_per_surface():
    names = _current_recon_tool_names()

    must_have = {
        "web_app": {"web_crawler", "directory_file_fuzzing", "waf_detection"},
        "api": {"api_endpoint_discovery", "param_discovery"},
        "network": {"port_scan_service_enum", "network_enum", "network_vuln_scan"},
        "cloud": {"cloud_storage_enum", "cloud_misconfig_scan"},
        "mobile": {"mobile_static_analysis", "mobile_dynamic_analysis"},
        "iot": {"iot_protocol_scan", "firmware_analysis"},
        "repository": {"secret_scan", "dependency_scan"},
        "infra": {"db_enum_and_audit"},
    }

    missing: dict[str, list[str]] = {}
    for target_type, required_tools in must_have.items():
        missing_tools = sorted(tool for tool in required_tools if tool not in names)
        if missing_tools:
            missing[target_type] = missing_tools

    assert not missing, f"Missing critical recon tools by target type: {missing}"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__]))
