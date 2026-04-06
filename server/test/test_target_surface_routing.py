from __future__ import annotations

import asyncio
import importlib
import json

from server.agents.executer.target_tool_routing import (
    extract_discovered_target_types,
    filter_tools_for_target_types,
    normalize_target_types,
)
from server.agents.planner.tools.pentest_plan import _current_plan, _reset_plan
from server.agents.planner.tools.target_types import add_target_type


def test_normalize_target_types_aliases():
    values = normalize_target_types(["web", "db", "infra", "mobile", "unknown"])
    assert "web_app" in values
    assert "database" in values
    assert "infra" in values
    assert "mobile" in values
    assert "unknown" not in values


def test_filter_recon_tools_by_target_type():
    recon_tools = importlib.import_module("server.agents.executer.recon.tools").ALL_RECON_TOOLS
    scoped = filter_tools_for_target_types(
        role="recon",
        tools=recon_tools,
        target_types=["network"],
    )
    names = {tool.name for tool in scoped}
    assert "port_scan_service_enum" in names
    assert "network_enum" in names
    assert "web_fuzz" not in names


def test_extract_discovered_target_types_from_output():
    payload = {
        "success": True,
        "summary": "Found Android APK endpoint and S3 bucket",
        "discovered_target_types": ["mobile", "cloud"],
    }
    discovered = extract_discovered_target_types(json.dumps(payload))
    assert "mobile" in discovered
    assert "cloud" in discovered


def test_add_target_type_accepts_alias_and_normalizes():
    _reset_plan()
    result = asyncio.run(add_target_type.execute(target_type="web"))
    assert "Added 'web_app'" in result
    assert "web_app" in _current_plan.get("target_types", [])
