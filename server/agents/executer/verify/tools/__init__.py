"""Verify tool registry."""

from server.core.tool import Tool

from server.agents.executer.exploit.tools.all.run_custom import (
    RUN_CUSTOM_TOOL_DEFINITION,
    run_custom,
)
from server.agents.executer.exploit.tools.all.run_python import (
    RUN_PYTHON_TOOL_DEFINITION,
    run_python,
)

# Screenshot capture tools
from ...retest.tools.screenshot import (
    capture_screenshot,
    annotate_screenshot,
    capture_before_after,
    create_evidence_chain,
)

# Vision model validation tools
from .vision import (
    analyze_screenshot_with_vision,
    compare_before_after_screenshots,
    detect_false_positive,
)

# Legacy tool
from ...retest.record_verification_result import record_verification_result
from ..catalog import VERIFY_TOOLS

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


ALL_VERIFY_TOOLS: list[Tool] = [
    # Shared execution primitives
    run_custom_tool,
    run_python_tool,
    # Screenshot
    capture_screenshot,
    annotate_screenshot,
    capture_before_after,
    create_evidence_chain,
    # Vision
    analyze_screenshot_with_vision,
    compare_before_after_screenshots,
    detect_false_positive,
    # Legacy
    record_verification_result,
]

__all__ = [
    "ALL_VERIFY_TOOLS",
    # Screenshot
    "capture_screenshot",
    "annotate_screenshot",
    "capture_before_after",
    "create_evidence_chain",
    # Vision
    "analyze_screenshot_with_vision",
    "compare_before_after_screenshots",
    "detect_false_positive",
    # Legacy
    "record_verification_result",
    "run_custom_tool",
    "run_python_tool",
    "VERIFY_TOOLS",
]
