from __future__ import annotations

import json

from server.agents.executer.exploit.agent import (
    build_exploit_callable_tools,
    build_exploit_scoped_prompt,
    build_run_custom_catalog_for_target_types,
)
from server.agents.executer.exploit.tools import ALL_EXPLOIT_TOOLS
from server.agents.executer.recon.agent import (
    build_recon_callable_tool_guide_for_target_types,
    build_recon_scenario_packet,
    build_recon_run_custom_catalog_for_target_types,
    build_recon_scoped_prompt,
)
from server.agents.executer.recon.tools import ALL_RECON_TOOLS, _load_recon_registry
from server.agents.executer.recon.tools.web.runtime_policy import (
    WEB_ALIAS_BACKED_TOOL_NAMES,
    WEB_SMART_PYTHON_TOOL_NAMES,
    load_web_recon_runtime_policy,
)
from server.agents.executer.target_tool_routing import (
    filter_tools_for_target_types,
    normalize_target_types,
)

TARGET_TYPES = [
    "web_app",
   
]

""" "api",
    "network",
    "infra",
    "linux_server",
    "mobile",
    "desktop",
    "cloud",
    "container",
    "repository",
    "iot","""

ALL_RECON_SCOPE_TARGET_TYPES = [
    "web_app",
    "api",
    "network",
    "infra",
    "linux_server",
    "mobile",
    "cloud",
    "container",
    "repository",
    "iot",
]

def _tool_names(tools: list) -> list[str]:
    return sorted(tool.name for tool in tools)


def _recon_preview(target_type: str) -> dict[str, object]:
    normalized = normalize_target_types([target_type])
    scoped_tools = filter_tools_for_target_types(
        role="recon",
        tools=ALL_RECON_TOOLS,
        target_types=normalized,
    )
    run_custom_catalog = build_recon_run_custom_catalog_for_target_types(normalized)
    return {
        "role": "recon",
        "target_type": target_type,
        "normalized_target_types": normalized,
        "callable_tools": _tool_names(scoped_tools),
        "run_custom_catalog_tools": sorted(run_custom_catalog.keys()),
        "prompt": build_recon_scoped_prompt(normalized),
    }


def _exploit_preview(target_type: str) -> dict[str, object]:
    normalized = normalize_target_types([target_type])
    scoped_tools = build_exploit_callable_tools(normalized)
    run_custom_catalog = build_run_custom_catalog_for_target_types(normalized)
    return {
        "role": "exploit",
        "target_type": target_type,
        "normalized_target_types": normalized,
        "callable_tools": _tool_names(scoped_tools),
        "run_custom_catalog_tools": sorted(run_custom_catalog.keys()),
        "all_exploit_tools_loaded": _tool_names(ALL_EXPLOIT_TOOLS),
        "prompt": build_exploit_scoped_prompt(normalized),
    }


def _format_preview_block(preview: dict[str, object]) -> str:
    header = (
        f"{'=' * 100}\n"
        f"ROLE={preview['role']} TARGET_TYPE={preview['target_type']}\n"
        f"{'=' * 100}"
    )
    metadata = json.dumps(
        {
            "normalized_target_types": preview["normalized_target_types"],
            "callable_tools": preview["callable_tools"],
            "run_custom_catalog_tools": preview["run_custom_catalog_tools"],
        },
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    )
    return (
        f"{header}\n"
        "TOOLS AND ROUTING\n"
        f"{metadata}\n\n"
        "PROMPT\n"
        f"{preview['prompt']}\n"
    )


def build_agent_prompt_matrix() -> dict[str, list[dict[str, object]]]:
    return {
        "recon": [_recon_preview(target_type) for target_type in TARGET_TYPES],
        "exploit": [_exploit_preview(target_type) for target_type in TARGET_TYPES],
    }


def test_print_recon_prompt_matrix() -> None:
    previews = [_recon_preview(target_type) for target_type in TARGET_TYPES]

    for preview in previews:
        print(_format_preview_block(preview))
        assert preview["callable_tools"]
        assert isinstance(preview["prompt"], str)
        assert preview["prompt"]


def test_web_recon_surface_restores_security_tool_aliases() -> None:
    tool_names = _tool_names(ALL_RECON_TOOLS)
    catalog = build_recon_run_custom_catalog_for_target_types(["web_app"])

    assert "http_probe" in tool_names
    assert "cms_detect_and_scan" in tool_names
    assert "directory_file_fuzzing" in tool_names
    assert "web_fuzz" not in tool_names
    assert "ffuf" in catalog
    assert "httpx" in catalog


def test_web_recon_prompt_and_packet_include_run_custom_catalog_guidance() -> None:
    catalog = build_recon_run_custom_catalog_for_target_types(["web_app"])
    callable_guide = build_recon_callable_tool_guide_for_target_types(["web_app"])
    prompt = build_recon_scoped_prompt(["web_app"])
    packet = build_recon_scenario_packet(
        scenario_and_target="Check the web target safely.",
        context_block="No prior findings.",
        available_tools=["run_custom", "http_probe", "js_source_code_analyzer"],
        target_types=["web_app"],
        run_custom_catalog=catalog,
        callable_tool_guide=callable_guide,
        local_resource_catalog="wordlists/web/folders.txt",
        max_tool_calls_per_round=4,
        max_rounds_per_scenario=3,
    )

    assert callable_guide
    assert "run_custom command catalog for this target scope:" in prompt
    assert "Scoped built-in recon tools for this target type:" in prompt
    assert '"httpx"' in prompt
    assert '"ffuf"' in prompt
    assert "passive_web_recon" in prompt
    assert "For external security CLIs from this catalog, use run_custom" in prompt
    assert "prefer it before falling back to run_custom" in prompt

    assert "run_custom catalog security tools for this scope:" in packet
    assert "Scoped run_custom catalog details:" in packet
    assert "Scoped built-in recon tools for this run:" in packet
    assert '"httpx"' in packet
    assert '"ffuf"' in packet
    assert "passive_web_recon" in packet
    assert "prefer that agent-native tool first" in packet
    assert "prefer executing it via run_custom(command=..., args=[...], reason=...)" in packet


def test_network_recon_prompt_stays_scoped_to_network_catalog_and_tools() -> None:
    catalog = build_recon_run_custom_catalog_for_target_types(["network"])
    callable_guide = build_recon_callable_tool_guide_for_target_types(["network"])
    prompt = build_recon_scoped_prompt(["network"])
    packet = build_recon_scenario_packet(
        scenario_and_target="Enumerate the network target safely.",
        context_block="No prior findings.",
        available_tools=["run_custom", "arp_scan", "traffic_analyze"],
        target_types=["network"],
        run_custom_catalog=catalog,
        callable_tool_guide=callable_guide,
        local_resource_catalog="wordlists/network/common.txt",
        max_tool_calls_per_round=4,
        max_rounds_per_scenario=3,
    )

    assert catalog
    assert callable_guide
    assert '"nmap"' in prompt
    assert '"masscan"' in prompt
    assert "Scoped built-in recon tools for this target type:" in prompt
    assert "run_custom command catalog for this target scope:" in prompt
    assert "Scoped built-in recon tools for this run:" in packet
    assert "Use run_custom for external CLIs that are appropriate in this scoped catalog." in packet


def test_api_recon_scope_exposes_service_recon_built_in() -> None:
    normalized = normalize_target_types(["api"])
    scoped_tools = filter_tools_for_target_types(
        role="recon",
        tools=ALL_RECON_TOOLS,
        target_types=normalized,
    )
    tool_names = _tool_names(scoped_tools)
    callable_guide = build_recon_callable_tool_guide_for_target_types(["api"])
    prompt = build_recon_scoped_prompt(["api"])

    assert "api_service_recon" in tool_names
    assert "api_endpoint_discovery" in tool_names
    assert "graphql_recon" not in tool_names
    assert "grpc_recon" not in tool_names
    assert "soap_wsdl_recon" not in tool_names
    assert any(item.get("name") == "api_service_recon" for item in callable_guide)
    assert "api_service_recon" in prompt


def test_web_recon_runtime_policy_keeps_smart_tools_and_alias_wrappers() -> None:
    tool_names = set(_tool_names(ALL_RECON_TOOLS))
    policy = load_web_recon_runtime_policy()

    assert policy["migration_mode"] == "incremental"

    for tool_name in WEB_ALIAS_BACKED_TOOL_NAMES:
        assert tool_name in tool_names

    for tool_name in WEB_SMART_PYTHON_TOOL_NAMES:
        assert tool_name in tool_names

    assert "web_fuzz" not in tool_names


def test_recon_registry_skips_removed_modules_and_loads_current_api_tools() -> None:
    _, errors = _load_recon_registry()

    assert "server.agents.executer.recon.tools.api.api_endpoint_discovery" not in errors
    assert "server.agents.executer.recon.tools.api.api_passive_enum" not in errors

    removed_modules = {
        "server.agents.executer.recon.tools.api.oauth_oidc_check",
        "server.agents.executer.recon.tools.api.zap_daemon_scan",
        "server.agents.executer.recon.tools.infra.binary_analysis",
        "server.agents.executer.recon.tools.network.name_service_surface",
        "server.agents.executer.recon.tools.network.remote_access_recon",
        "server.agents.executer.recon.tools.network.route_topology",
        "server.agents.executer.recon.tools.network.voip_recon",
        "server.agents.executer.recon.tools.server.db_enum_and_audit",
        "server.agents.executer.recon.tools.server.smb_deep_enum",
        "server.agents.executer.recon.tools.server.snmp_fast_enum",
        "server.agents.executer.recon.tools.web.cdn_origin_detect",
        "server.agents.executer.recon.tools.web.cors_misconfig_check",
        "server.agents.executer.recon.tools.web.web_proxy_capture",
    }
    assert not (removed_modules & set(errors))


def test_all_recon_run_custom_catalogs_use_normalized_security_tool_shape() -> None:
    required_keys = {"phase", "type", "when", "targets", "cmd", "pipe_into"}
    legacy_keys = {"t", "c", "u", "d", "tgt"}

    for target_type in ALL_RECON_SCOPE_TARGET_TYPES:
        catalog = build_recon_run_custom_catalog_for_target_types([target_type])
        assert catalog, f"expected non-empty catalog for {target_type}"
        for tool_name, meta in catalog.items():
            assert required_keys.issubset(meta.keys()), f"{target_type}:{tool_name} missing keys"
            assert not (legacy_keys & set(meta.keys())), f"{target_type}:{tool_name} still exposes legacy keys"


def test_print_exploit_prompt_matrix() -> None:
    previews = [_exploit_preview(target_type) for target_type in TARGET_TYPES]

    for preview in previews:
        print(_format_preview_block(preview))
        assert preview["callable_tools"]
        assert isinstance(preview["prompt"], str)
        assert preview["prompt"]


if __name__ == "__main__":
    matrix = build_agent_prompt_matrix()
    for preview in matrix["recon"]:
        print(_format_preview_block(preview))
    #for preview in matrix["exploit"]:
        #print(_format_preview_block(preview))
