"""Retest tool registry."""

from server.core.tool import Tool

from server.agents.executer.exploit.tools.all.run_custom import (
    RUN_CUSTOM_TOOL_DEFINITION,
    run_custom,
)
from server.agents.executer.exploit.tools.all.run_python import (
    RUN_PYTHON_TOOL_DEFINITION,
    run_python,
)

from .record_retest_result import record_retest_result
from .payload_replay import replay_payload, replay_finding, compare_responses
from .bypass_mutations import (
    generate_mutations,
    llm_generate_mutations,
    apply_encoding_chain,
)
from .patch_confidence import (
    calculate_patch_confidence,
    analyze_retest_results,
    detect_regression,
)
from ..catalog import RETEST_TOOLS

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

ALL_RETEST_TOOLS: list[Tool] = [
    # Shared execution primitives
    run_custom_tool,
    run_python_tool,
    # Result recording
    record_retest_result,
    # Payload replay
    replay_payload,
    replay_finding,
    compare_responses,
    # Bypass mutations
    generate_mutations,
    llm_generate_mutations,
    apply_encoding_chain,
    # Patch confidence scoring
    calculate_patch_confidence,
    analyze_retest_results,
    detect_regression,
]

__all__ = [
    "ALL_RETEST_TOOLS",
    "record_retest_result",
    "replay_payload",
    "replay_finding",
    "compare_responses",
    "generate_mutations",
    "llm_generate_mutations",
    "apply_encoding_chain",
    "calculate_patch_confidence",
    "analyze_retest_results",
    "detect_regression",
    "run_custom_tool",
    "run_python_tool",
    "RETEST_TOOLS",
]
