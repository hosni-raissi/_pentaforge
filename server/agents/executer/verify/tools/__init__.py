"""Verify tool registry."""

from server.core.tool import Tool

from .record_verification_result import record_verification_result

ALL_VERIFY_TOOLS: list[Tool] = [record_verification_result]

__all__ = ["ALL_VERIFY_TOOLS", "record_verification_result"]
