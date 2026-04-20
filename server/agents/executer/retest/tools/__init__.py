"""Retest tool registry - Report entry building tools."""

from server.core.tool import Tool

from server.agents.executer.exploit.tools.all.run_custom import (
    RUN_CUSTOM_TOOL_DEFINITION,
    run_custom,
)
from server.agents.executer.exploit.tools.all.run_python import (
    RUN_PYTHON_TOOL_DEFINITION,
    run_python,
)

from .screenshot import capture_screenshot

run_custom_tool = Tool(
    name=RUN_CUSTOM_TOOL_DEFINITION["name"],
    description=RUN_CUSTOM_TOOL_DEFINITION["description"],
    fn=run_custom,
    parameters=RUN_CUSTOM_TOOL_DEFINITION["parameters"],
)

run_python_tool = Tool(
    name=RUN_PYTHON_TOOL_DEFINITION["name"],
    description=RUN_PYTHON_TOOL_DEFINITION["description"],
    fn=run_python,
    parameters=RUN_PYTHON_TOOL_DEFINITION["parameters"],
)

screenshot_tool = capture_screenshot

ALL_RETEST_TOOLS: list[Tool] = [
    # Execution primitives for PoC
    run_custom_tool,      # Execute HTTP requests, CLI commands
    run_python_tool,      # Execute custom PoC Python scripts
    # Evidence capture
    screenshot_tool,      # Take visual proof of vulnerability
]

__all__ = [
    "ALL_RETEST_TOOLS",
    "run_custom_tool",
    "run_python_tool",
    "screenshot_tool",
    "capture_screenshot",
]
