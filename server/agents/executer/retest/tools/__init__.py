"""Retest tool registry."""

from server.core.tool import Tool

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

ALL_RETEST_TOOLS: list[Tool] = [
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
]
