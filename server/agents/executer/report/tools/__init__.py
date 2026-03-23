"""Report tool registry."""

from server.core.tool import Tool

from .record_report_section import record_report_section

ALL_REPORT_TOOLS: list[Tool] = [record_report_section]

__all__ = ["ALL_REPORT_TOOLS", "record_report_section"]
