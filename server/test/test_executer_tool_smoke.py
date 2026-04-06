from __future__ import annotations

import asyncio
import sys
import importlib
import json
from typing import Any

from server.core.tool import Tool


def _find_tool(tools: list[Tool], name: str) -> Tool:
    for tool in tools:
        if tool.name == name:
            return tool
    raise AssertionError(f"Tool '{name}' not found in registry")


async def _execute(invocation: Tool, **kwargs):
    raw = await invocation.execute(**kwargs)
    return json.loads(raw)


def test_tool_packages_importable():
    recon_tools = importlib.import_module("server.agents.executer.recon.tools")
    exploit_tools = importlib.import_module("server.agents.executer.exploit.tools")

    assert hasattr(recon_tools, "ALL_RECON_TOOLS")
    assert hasattr(exploit_tools, "ALL_EXPLOIT_TOOLS")


def test_registry_entries_are_tool_objects():
    recon_tools = importlib.import_module("server.agents.executer.recon.tools")
    exploit_tools = importlib.import_module("server.agents.executer.exploit.tools")

    assert recon_tools.ALL_RECON_TOOLS
    assert exploit_tools.ALL_EXPLOIT_TOOLS
    assert all(isinstance(t, Tool) for t in recon_tools.ALL_RECON_TOOLS)
    assert all(isinstance(t, Tool) for t in exploit_tools.ALL_EXPLOIT_TOOLS)

    recon_names = [t.name for t in recon_tools.ALL_RECON_TOOLS]
    exploit_names = [t.name for t in exploit_tools.ALL_EXPLOIT_TOOLS]
    assert len(recon_names) == len(set(recon_names))
    assert len(exploit_names) == len(set(exploit_names))


def test_intrusive_tools_moved_to_exploit():
    recon_tools = importlib.import_module("server.agents.executer.recon.tools")
    exploit_tools = importlib.import_module("server.agents.executer.exploit.tools")

    recon_names = {t.name for t in recon_tools.ALL_RECON_TOOLS}
    exploit_names = {t.name for t in exploit_tools.ALL_EXPLOIT_TOOLS}

    assert "db_injection_test" not in recon_names
    assert "api_fuzzing" not in recon_names
    assert "api_auth_test" not in recon_names

    assert "db_injection_test" in exploit_names
    assert "api_fuzzing" in exploit_names
    assert "api_auth_test" in exploit_names


def test_list_type_schema_uses_user_ia():
    recon_tools = importlib.import_module("server.agents.executer.recon.tools")
    exploit_tools = importlib.import_module("server.agents.executer.exploit.tools")

    for tool in recon_tools.ALL_RECON_TOOLS + exploit_tools.ALL_EXPLOIT_TOOLS:
        props = tool.parameters.get("properties", {}) if isinstance(tool.parameters, dict) else {}
        list_type = props.get("list_type")
        if not isinstance(list_type, dict):
            continue
        enum = list_type.get("enum")
        if not isinstance(enum, list):
            continue
        lowered = {str(v).lower() for v in enum}
        assert "mine" not in lowered
        assert "yours" not in lowered


def test_execution_smoke_per_target_type():
    recon_tools = importlib.import_module("server.agents.executer.recon.tools").ALL_RECON_TOOLS
    exploit_tools = importlib.import_module("server.agents.executer.exploit.tools").ALL_EXPLOIT_TOOLS

    cases = [
        ("web", recon_tools, "directory_file_fuzzing", {"tool": "ffuf", "target": "invalid-url"}),
        ("api", recon_tools, "api_endpoint_discovery", {"tool": "kiterunner", "target": "localhost"}),
        ("network", recon_tools, "port_scan_service_enum", {"tool": "nmap", "target": "localhost"}),
        ("cloud", recon_tools, "cloud_misconfig_scan", {"tool": "prowler", "provider": "aws", "args": [";"]}),
        ("container", recon_tools, "container_image_scan", {"tool": "trivy", "target": ""}),
        ("db", exploit_tools, "db_injection_test", {"url": "bad"}),
        ("mobile", recon_tools, "mobile_static_analysis", {"tool": "invalid", "target": "/nope.apk"}),
        ("iot", recon_tools, "iot_protocol_scan", {"target": "192.0.2.1", "protocols": ["invalid"]}),
        ("repo", recon_tools, "secret_scan", {"tool": "gitleaks", "target": ""}),
    ]

    for _, pool, tool_name, kwargs in cases:
        tool = _find_tool(pool, tool_name)
        result = asyncio.run(_execute(tool, **kwargs))
        assert isinstance(result, dict)
        assert "success" in result
        assert "error" in result
        assert "execution_time" in result
        assert "raw_output" in result


def _shorten(value: Any, limit: int = 120) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


async def _run_debug_trace() -> None:
    recon_tools = importlib.import_module("server.agents.executer.recon.tools").ALL_RECON_TOOLS
    exploit_tools = importlib.import_module("server.agents.executer.exploit.tools").ALL_EXPLOIT_TOOLS

    validation_cases = [
        ("web", recon_tools, "directory_file_fuzzing", {"tool": "ffuf", "target": "invalid-url"}),
        ("api", recon_tools, "api_endpoint_discovery", {"tool": "kiterunner", "target": "localhost"}),
        ("network", recon_tools, "port_scan_service_enum", {"tool": "nmap", "target": "localhost"}),
        ("cloud", recon_tools, "cloud_misconfig_scan", {"tool": "prowler", "provider": "aws", "args": [";"]}),
        ("container", recon_tools, "container_image_scan", {"tool": "trivy", "target": ""}),
        ("db", exploit_tools, "db_injection_test", {"url": "bad"}),
        ("mobile", recon_tools, "mobile_static_analysis", {"tool": "invalid", "target": "/nope.apk"}),
        ("iot", recon_tools, "iot_protocol_scan", {"target": "192.0.2.1", "protocols": ["invalid"]}),
        ("repo", recon_tools, "secret_scan", {"tool": "gitleaks", "target": ""}),
    ]
    live_cases = [
        ("web", recon_tools, "directory_file_fuzzing", {"tool": "ffuf", "target": "https://example.com"}),
        ("api", recon_tools, "api_endpoint_discovery", {"tool": "kiterunner", "target": "https://example.com/api"}),
        ("network", recon_tools, "port_scan_service_enum", {"tool": "nmap", "target": "192.0.2.1", "args": ["-Pn", "-p", "22"]}),
        ("cloud", recon_tools, "cloud_misconfig_scan", {"tool": "prowler", "provider": "aws", "args": []}),
        ("container", recon_tools, "container_image_scan", {"tool": "trivy", "target": "alpine:latest"}),
        ("db", exploit_tools, "db_injection_test", {"url": "https://nonexistent.invalid/?id=1"}),
        ("mobile", recon_tools, "mobile_static_analysis", {"tool": "manual", "target": "/tmp/fake.apk"}),
        ("iot", recon_tools, "iot_protocol_scan", {"target": "192.0.2.1", "protocols": ["mqtt"]}),
        ("repo", recon_tools, "secret_scan", {"tool": "gitleaks", "target": "."}),
    ]

    mode = "validation"
    if len(sys.argv) > 1:
        selected = str(sys.argv[1]).strip().lower()
        if selected in {"validation", "live"}:
            mode = selected
    cases = live_cases if mode == "live" else validation_cases

    print("=" * 80)
    print(f"EXECUTER AGENT TOOL TRACE ({mode.upper()})")
    print("=" * 80)

    for surface, _, tool_name, kwargs in cases:
        agent = "exploit" if any(t.name == tool_name for t in exploit_tools) else "recon"
        tool = _find_tool(exploit_tools if agent == "exploit" else recon_tools, tool_name)
        raw = await tool.execute(**kwargs)
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"success": False, "error": f"Non-JSON output: {_shorten(raw)}"}

        success = parsed.get("success")
        error = _shorten(parsed.get("error"), limit=180)
        execution_time = parsed.get("execution_time")

        print(f"\n[{surface}] agent={agent} tool={tool_name}")
        print(f"  args={kwargs}")
        print(
            "  result:"
            f" success={success} | execution_time={execution_time} | error={error or 'None'}"
        )


if __name__ == "__main__":
    asyncio.run(_run_debug_trace())
