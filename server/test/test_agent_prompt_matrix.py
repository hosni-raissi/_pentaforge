from __future__ import annotations

import json

from server.agents.executer.exploit.agent import (
    build_exploit_callable_tools,
    build_exploit_scoped_prompt,
    build_run_custom_catalog_for_target_types,
)
from server.agents.executer.exploit.tools import ALL_EXPLOIT_TOOLS
from server.agents.executer.recon.agent import (
    build_recon_run_custom_catalog_for_target_types,
    build_recon_scoped_prompt,
)
from server.agents.executer.recon.tools import ALL_RECON_TOOLS
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


def test_web_recon_runtime_policy_keeps_smart_tools_and_alias_wrappers() -> None:
    tool_names = set(_tool_names(ALL_RECON_TOOLS))
    policy = load_web_recon_runtime_policy()

    assert policy["migration_mode"] == "incremental"

    for tool_name in WEB_ALIAS_BACKED_TOOL_NAMES:
        assert tool_name in tool_names

    for tool_name in WEB_SMART_PYTHON_TOOL_NAMES:
        assert tool_name in tool_names

    assert "web_fuzz" not in tool_names


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
