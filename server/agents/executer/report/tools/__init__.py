"""Report tool registry."""

from server.core.tool import Tool

from .record_report_section import record_report_section
from .cvss import calculate_cvss, cvss_from_vulnerability, parse_cvss_vector
from .mapping import map_to_owasp, map_to_mitre, map_to_cwe, get_full_mapping
from .report_generator import (
    generate_json_report,
    generate_html_report,
    generate_sarif_report,
    generate_pdf_report,
)

ALL_REPORT_TOOLS: list[Tool] = [
    # Report section recording
    record_report_section,
    # CVSS calculation
    calculate_cvss,
    cvss_from_vulnerability,
    parse_cvss_vector,
    # Security framework mapping
    map_to_owasp,
    map_to_mitre,
    map_to_cwe,
    get_full_mapping,
    # Report generation
    generate_json_report,
    generate_html_report,
    generate_sarif_report,
    generate_pdf_report,
]

__all__ = [
    "ALL_REPORT_TOOLS",
    "record_report_section",
    "calculate_cvss",
    "cvss_from_vulnerability",
    "parse_cvss_vector",
    "map_to_owasp",
    "map_to_mitre",
    "map_to_cwe",
    "get_full_mapping",
    "generate_json_report",
    "generate_html_report",
    "generate_sarif_report",
    "generate_pdf_report",
]
