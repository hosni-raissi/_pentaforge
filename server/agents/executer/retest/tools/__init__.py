"""Retest tool registry."""

from server.core.tool import Tool

from .record_retest_result import record_retest_result

ALL_RETEST_TOOLS: list[Tool] = [record_retest_result]

__all__ = ["ALL_RETEST_TOOLS", "record_retest_result"]
