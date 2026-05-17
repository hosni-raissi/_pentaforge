"""Tool registry for Analyzer."""

from server.core.tool import Tool

from server.agents.tools.run_custom import (
    RUN_CUSTOM_TOOL_DEFINITION,
    run_custom,
)
from server.agents.tools.run_python import (
    RUN_PYTHON_TOOL_DEFINITION,
    run_python,
)
from server.agents.tools.search_web import (
    SEARCH_WEB_TOOL_DEFINITION,
    search_web,
)
from server.agents.tools.fetch_url_content import (
    FETCH_URL_CONTENT_TOOL_DEFINITION,
    fetch_url_content,
)

from .record_verification_result import record_verification_result
from .screenshot import (
    annotate_screenshot,
    capture_before_after,
    capture_screenshot,
    create_evidence_chain,
)
from .vision import (
    analyze_screenshot_with_vision,
    compare_before_after_screenshots,
    detect_false_positive,
)

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

search_web_tool = Tool(
    name=SEARCH_WEB_TOOL_DEFINITION["name"],
    description=SEARCH_WEB_TOOL_DEFINITION["description"],
    fn=search_web,
    parameters=SEARCH_WEB_TOOL_DEFINITION["parameters"],
)

fetch_url_content_tool = Tool(
    name=FETCH_URL_CONTENT_TOOL_DEFINITION["name"],
    description=FETCH_URL_CONTENT_TOOL_DEFINITION["description"],
    fn=fetch_url_content,
    parameters=FETCH_URL_CONTENT_TOOL_DEFINITION["parameters"],
)

VERIFY_ANALYZER_TOOLS: list[Tool] = [
    run_custom_tool,
    run_python_tool,
    search_web_tool,
    fetch_url_content_tool,
    record_verification_result,
]

POC_ANALYZER_TOOLS: list[Tool] = [
    run_custom_tool,
    run_python_tool,
    search_web_tool,
    fetch_url_content_tool,
    capture_screenshot,
    annotate_screenshot,
    capture_before_after,
    create_evidence_chain,
    analyze_screenshot_with_vision,
    compare_before_after_screenshots,
    detect_false_positive,
    record_verification_result,
]

__all__ = [
    "POC_ANALYZER_TOOLS",
    "VERIFY_ANALYZER_TOOLS",
    "analyze_screenshot_with_vision",
    "annotate_screenshot",
    "capture_before_after",
    "capture_screenshot",
    "compare_before_after_screenshots",
    "create_evidence_chain",
    "detect_false_positive",
    "record_verification_result",
    "run_custom_tool",
    "run_python_tool",
    "search_web_tool",
    "fetch_url_content_tool",
]
