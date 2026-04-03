"""Report generation tools for Report agent."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from server.core.tool import tool
from ..config import (
    REPORT_OUTPUT_PATH,
    SARIF_VERSION,
    PDF_TEMPLATE,
    HTML_TEMPLATE,
)

log = structlog.get_logger(__name__)


def _ensure_output_dir() -> Path:
    """Ensure report output directory exists."""
    path = Path(REPORT_OUTPUT_PATH)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _hash_content(content: str) -> str:
    """Generate SHA-256 hash of content."""
    return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"


@tool(
    name="generate_json_report",
    description="Generate a structured JSON report from findings.",
)
async def generate_json_report(
    target: str,
    findings: str,
    executive_summary: str = "",
    scan_id: str = "",
) -> str:
    """
    Generate JSON report.

    Args:
        target: Target of the assessment
        findings: JSON string of findings array
        executive_summary: Executive summary text
        scan_id: Unique scan identifier
    """
    output_dir = _ensure_output_dir()
    timestamp = datetime.now(timezone.utc)
    filename = f"report_{scan_id or timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    filepath = output_dir / filename

    try:
        findings_list = json.loads(findings) if isinstance(findings, str) else findings
    except json.JSONDecodeError:
        findings_list = []

    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings_list:
        sev = finding.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    report = {
        "report_metadata": {
            "title": f"Security Assessment Report - {target}",
            "target": target,
            "generated_at": timestamp.isoformat(),
            "scan_id": scan_id,
            "format": "json",
            "version": "1.0",
        },
        "executive_summary": executive_summary,
        "findings_summary": severity_counts,
        "total_findings": len(findings_list),
        "risk_rating": _calculate_risk_rating(severity_counts),
        "findings": findings_list,
    }

    content = json.dumps(report, indent=2)
    filepath.write_text(content)
    content_hash = _hash_content(content)

    return json.dumps({
        "ok": True,
        "format": "json",
        "path": str(filepath),
        "hash": content_hash,
        "findings_count": len(findings_list),
        "generated_at": timestamp.isoformat(),
    })


@tool(
    name="generate_html_report",
    description="Generate an HTML report with interactive elements.",
)
async def generate_html_report(
    target: str,
    findings: str,
    executive_summary: str = "",
    scan_id: str = "",
    include_charts: bool = True,
) -> str:
    """
    Generate HTML report.

    Args:
        target: Target of the assessment
        findings: JSON string of findings array
        executive_summary: Executive summary text
        scan_id: Unique scan identifier
        include_charts: Include interactive charts
    """
    output_dir = _ensure_output_dir()
    timestamp = datetime.now(timezone.utc)
    filename = f"report_{scan_id or timestamp.strftime('%Y%m%d_%H%M%S')}.html"
    filepath = output_dir / filename

    try:
        findings_list = json.loads(findings) if isinstance(findings, str) else findings
    except json.JSONDecodeError:
        findings_list = []

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings_list:
        sev = finding.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Generate HTML content
    html_content = _generate_html_content(
        target=target,
        findings=findings_list,
        executive_summary=executive_summary,
        severity_counts=severity_counts,
        timestamp=timestamp,
        include_charts=include_charts,
    )

    filepath.write_text(html_content)
    content_hash = _hash_content(html_content)

    return json.dumps({
        "ok": True,
        "format": "html",
        "path": str(filepath),
        "hash": content_hash,
        "findings_count": len(findings_list),
        "template": HTML_TEMPLATE,
        "generated_at": timestamp.isoformat(),
    })


@tool(
    name="generate_sarif_report",
    description="Generate a SARIF (Static Analysis Results Interchange Format) report.",
)
async def generate_sarif_report(
    target: str,
    findings: str,
    tool_name: str = "PentaForge",
    scan_id: str = "",
) -> str:
    """
    Generate SARIF report for integration with CI/CD and IDEs.

    Args:
        target: Target of the assessment
        findings: JSON string of findings array
        tool_name: Name of the scanning tool
        scan_id: Unique scan identifier
    """
    output_dir = _ensure_output_dir()
    timestamp = datetime.now(timezone.utc)
    filename = f"report_{scan_id or timestamp.strftime('%Y%m%d_%H%M%S')}.sarif"
    filepath = output_dir / filename

    try:
        findings_list = json.loads(findings) if isinstance(findings, str) else findings
    except json.JSONDecodeError:
        findings_list = []

    # Convert findings to SARIF format
    sarif_results = []
    sarif_rules = []
    rule_ids = set()

    for finding in findings_list:
        rule_id = finding.get("id", f"PF-{len(sarif_rules)+1:04d}")

        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            sarif_rules.append({
                "id": rule_id,
                "name": finding.get("title", "Unknown"),
                "shortDescription": {
                    "text": finding.get("title", "Unknown")
                },
                "fullDescription": {
                    "text": finding.get("description", "")
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(finding.get("severity", "info"))
                },
                "properties": {
                    "security-severity": str(finding.get("cvss", {}).get("score", 0.0)),
                    "tags": [
                        finding.get("owasp", {}).get("id", ""),
                        finding.get("cwe", {}).get("id", ""),
                    ]
                }
            })

        sarif_results.append({
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(finding.get("severity", "info")),
            "message": {
                "text": finding.get("description", finding.get("title", ""))
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("affected_url", target)
                        }
                    }
                }
            ],
            "properties": {
                "cvss": finding.get("cvss", {}),
                "owasp": finding.get("owasp", {}),
                "mitre": finding.get("mitre", []),
                "remediation": finding.get("remediation", {}),
            }
        })

    sarif_report = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "informationUri": "https://pentaforge.io",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": timestamp.isoformat(),
                    }
                ],
            }
        ]
    }

    content = json.dumps(sarif_report, indent=2)
    filepath.write_text(content)
    content_hash = _hash_content(content)

    return json.dumps({
        "ok": True,
        "format": "sarif",
        "version": SARIF_VERSION,
        "path": str(filepath),
        "hash": content_hash,
        "findings_count": len(sarif_results),
        "rules_count": len(sarif_rules),
        "generated_at": timestamp.isoformat(),
    })


@tool(
    name="generate_pdf_report",
    description="Generate a professional PDF report.",
)
async def generate_pdf_report(
    target: str,
    findings: str,
    executive_summary: str = "",
    scan_id: str = "",
    include_screenshots: bool = True,
) -> str:
    """
    Generate PDF report (returns HTML for conversion).

    Args:
        target: Target of the assessment
        findings: JSON string of findings array
        executive_summary: Executive summary text
        scan_id: Unique scan identifier
        include_screenshots: Include evidence screenshots
    """
    output_dir = _ensure_output_dir()
    timestamp = datetime.now(timezone.utc)

    try:
        findings_list = json.loads(findings) if isinstance(findings, str) else findings
    except json.JSONDecodeError:
        findings_list = []

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings_list:
        sev = finding.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Generate PDF-ready HTML
    html_filename = f"report_{scan_id or timestamp.strftime('%Y%m%d_%H%M%S')}_print.html"
    html_filepath = output_dir / html_filename

    html_content = _generate_pdf_html(
        target=target,
        findings=findings_list,
        executive_summary=executive_summary,
        severity_counts=severity_counts,
        timestamp=timestamp,
        include_screenshots=include_screenshots,
    )

    html_filepath.write_text(html_content)

    # PDF would be generated by external tool (weasyprint, puppeteer, etc.)
    pdf_filename = f"report_{scan_id or timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_filepath = output_dir / pdf_filename

    return json.dumps({
        "ok": True,
        "format": "pdf",
        "html_source": str(html_filepath),
        "pdf_path": str(pdf_filepath),
        "template": PDF_TEMPLATE,
        "findings_count": len(findings_list),
        "generated_at": timestamp.isoformat(),
        "note": "PDF conversion requires external renderer (weasyprint/puppeteer)",
    })


def _calculate_risk_rating(severity_counts: dict[str, int]) -> str:
    """Calculate overall risk rating from severity counts."""
    if severity_counts["critical"] > 0:
        return "critical"
    elif severity_counts["high"] > 2:
        return "critical"
    elif severity_counts["high"] > 0:
        return "high"
    elif severity_counts["medium"] > 3:
        return "high"
    elif severity_counts["medium"] > 0:
        return "medium"
    elif severity_counts["low"] > 0:
        return "low"
    return "info"


def _severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }
    return mapping.get(severity.lower(), "warning")


def _generate_html_content(
    target: str,
    findings: list[dict],
    executive_summary: str,
    severity_counts: dict[str, int],
    timestamp: datetime,
    include_charts: bool,
) -> str:
    """Generate interactive HTML report content."""
    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    findings_html = ""
    for i, finding in enumerate(findings):
        sev = finding.get("severity", "info").lower()
        color = severity_colors.get(sev, "#6b7280")
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color};">
            <h3>{i+1}. {finding.get("title", "Unknown")}</h3>
            <span class="severity" style="background: {color};">{sev.upper()}</span>
            <p><strong>CVSS:</strong> {finding.get("cvss", {}).get("score", "N/A")}</p>
            <p>{finding.get("description", "")}</p>
            <h4>Remediation</h4>
            <p>{finding.get("remediation", {}).get("summary", "No remediation provided")}</p>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f8fafc; }}
        .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); color: white; padding: 30px; border-radius: 8px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin: 24px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .finding {{ background: white; padding: 20px; margin: 16px 0; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .severity {{ color: white; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
        h1, h2, h3, h4 {{ margin-top: 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Date:</strong> {timestamp.strftime('%Y-%m-%d %H:%M UTC')}</p>
    </div>

    <div class="summary">
        <div class="summary-card" style="border-top: 4px solid #dc2626;"><h2>{severity_counts['critical']}</h2><p>Critical</p></div>
        <div class="summary-card" style="border-top: 4px solid #ea580c;"><h2>{severity_counts['high']}</h2><p>High</p></div>
        <div class="summary-card" style="border-top: 4px solid #ca8a04;"><h2>{severity_counts['medium']}</h2><p>Medium</p></div>
        <div class="summary-card" style="border-top: 4px solid #2563eb;"><h2>{severity_counts['low']}</h2><p>Low</p></div>
        <div class="summary-card" style="border-top: 4px solid #6b7280;"><h2>{severity_counts['info']}</h2><p>Info</p></div>
    </div>

    <section>
        <h2>Executive Summary</h2>
        <p>{executive_summary or "No executive summary provided."}</p>
    </section>

    <section>
        <h2>Findings</h2>
        {findings_html or "<p>No findings to report.</p>"}
    </section>
</body>
</html>"""


def _generate_pdf_html(
    target: str,
    findings: list[dict],
    executive_summary: str,
    severity_counts: dict[str, int],
    timestamp: datetime,
    include_screenshots: bool,
) -> str:
    """Generate print-optimized HTML for PDF conversion."""
    # Similar to HTML but with print-optimized styles
    base_html = _generate_html_content(
        target=target,
        findings=findings,
        executive_summary=executive_summary,
        severity_counts=severity_counts,
        timestamp=timestamp,
        include_charts=False,
    )

    # Add print styles
    print_styles = """
    <style>
        @media print {
            body { margin: 0; }
            .finding { page-break-inside: avoid; }
            @page { size: A4; margin: 2cm; }
        }
    </style>
    """

    return base_html.replace("</head>", f"{print_styles}</head>")
