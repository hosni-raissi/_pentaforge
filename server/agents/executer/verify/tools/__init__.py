"""Verify tool registry."""

from server.core.tool import Tool

# Screenshot capture tools
from .screenshot import (
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
from .record_verification_result import record_verification_result


ALL_VERIFY_TOOLS: list[Tool] = [
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
]
