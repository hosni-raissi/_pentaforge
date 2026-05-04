"""Report generator — builds a pentest report from project scan data using an LLM."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from server.config.agent import get_public_agent_config
from server.core.llm import ChatMessage, LLMClient
from server.agents.rate_limiter import get_global_llm_queue

from .prompts import REPORT_SYSTEM_PROMPT, REPORT_USER_PROMPT_TEMPLATE

logger = structlog.get_logger(__name__)

_REPORT_MAX_TOKENS = 8000
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_BADGE = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🔵 Low",
    "info": "⚪ Info",
}


def _format_finding(finding: dict[str, Any], index: int) -> str:
    """Format a single finding for the prompt."""
    severity = str(finding.get("severity", "info")).strip().lower()
    badge = _SEVERITY_BADGE.get(severity, severity)
    title = str(finding.get("title", "Untitled Finding")).strip()
    category = str(finding.get("category", "")).strip()
    status = str(finding.get("status", "open")).strip()
    description = str(finding.get("description", "")).strip()
    remediation = str(finding.get("remediation", "")).strip()
    cvss = finding.get("cvss")
    cve = str(finding.get("cve", "")).strip()
    target = str(finding.get("target", "")).strip()
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    evidence_status = str(
        finding.get("evidenceStatus", evidence.get("evidence_status", ""))
    ).strip()
    proof_quality = str(
        finding.get("proofQuality", evidence.get("proof_quality", ""))
    ).strip()
    verification_summary = str(evidence.get("verification_summary", "")).strip()
    commands = evidence.get("commands", [])
    if not isinstance(commands, list):
        commands = []
    tools_used = evidence.get("tools_used", [])
    if not isinstance(tools_used, list):
        tools_used = []

    lines = [
        f"### Finding {index}: {title}",
        f"- **Severity**: {badge}",
        f"- **Status**: {status}",
    ]
    if category:
        lines.append(f"- **Category**: {category}")
    if cvss is not None:
        lines.append(f"- **CVSS**: {cvss}")
    if cve:
        lines.append(f"- **CVE**: {cve}")
    if target:
        lines.append(f"- **Target**: {target}")
    if evidence_status:
        lines.append(f"- **Evidence Status**: {evidence_status}")
    if proof_quality:
        lines.append(f"- **Proof Quality**: {proof_quality}")
    if description:
        lines.append(f"\n**Description**: {description}")
    if verification_summary:
        lines.append(f"\n**Verification**: {verification_summary}")
    if commands:
        lines.append("\n**Commands Used**:")
        for cmd in commands[:10]:
            lines.append(f"  - `{cmd}`")
    if tools_used:
        lines.append(f"\n**Tools**: {', '.join(str(t) for t in tools_used[:10])}")
    if remediation:
        lines.append(f"\n**Remediation**: {remediation}")

    return "\n".join(lines)


def _format_findings_section(findings: list[dict[str, Any]]) -> str:
    """Format all findings grouped by severity."""
    if not findings:
        return "No findings were recorded during this scan."

    # Separate by status.
    verified = [f for f in findings if str(f.get("status", "")).lower() == "verified"]
    open_findings = [f for f in findings if str(f.get("status", "")).lower() == "open"]
    false_positives = [
        f for f in findings if str(f.get("status", "")).lower() == "false_positive"
    ]

    sections: list[str] = []

    # Verified findings grouped by severity.
    if verified:
        sorted_verified = sorted(
            verified,
            key=lambda f: _SEVERITY_ORDER.index(
                str(f.get("severity", "info")).strip().lower()
            )
            if str(f.get("severity", "info")).strip().lower() in _SEVERITY_ORDER
            else 99,
        )
        sections.append(f"### Verified Findings ({len(sorted_verified)})\n")
        for i, finding in enumerate(sorted_verified, 1):
            sections.append(_format_finding(finding, i))
            sections.append("")

    # Open (unverified).
    if open_findings:
        sections.append(f"\n### Open / Unverified Findings ({len(open_findings)})\n")
        for i, finding in enumerate(open_findings, 1):
            severity = str(finding.get("severity", "info")).strip().lower()
            title = str(finding.get("title", "Untitled")).strip()
            badge = _SEVERITY_BADGE.get(severity, severity)
            sections.append(f"- {badge} — {title}")

    # False positives.
    if false_positives:
        sections.append(
            f"\n### False Positives / Dismissed ({len(false_positives)})\n"
        )
        for finding in false_positives:
            title = str(finding.get("title", "Untitled")).strip()
            desc = str(finding.get("description", "")).strip()[:200]
            sections.append(f"- **{title}**: {desc}")

    # Summary stats.
    stats: dict[str, int] = {}
    for finding in verified:
        sev = str(finding.get("severity", "info")).strip().lower()
        stats[sev] = stats.get(sev, 0) + 1
    stats_line = ", ".join(
        f"{_SEVERITY_BADGE.get(s, s)}: {c}" for s, c in sorted(stats.items(), key=lambda x: _SEVERITY_ORDER.index(x[0]) if x[0] in _SEVERITY_ORDER else 99)
    )
    if stats_line:
        sections.insert(0, f"**Summary**: {stats_line}\n")

    return "\n".join(sections)


def _format_checklist_section(project: dict[str, Any]) -> str:
    """Extract checklist state from project data."""
    last_scan = project.get("lastScan", {})
    if not isinstance(last_scan, dict):
        return "No checklist data available."
    result = last_scan.get("result", {})
    if not isinstance(result, dict):
        return "No checklist data available."
    intel = result.get("intel", {})
    if not isinstance(intel, dict):
        return "No checklist data available."
    checklist = intel.get("checklist", {})
    if not isinstance(checklist, dict):
        return "No checklist data available."

    items = checklist.get("items", [])
    if not isinstance(items, list) or not items:
        return "No checklist items available."

    lines: list[str] = []
    for item in items[:40]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        status = str(item.get("status", "pending")).strip()
        priority = str(item.get("priority", "")).strip()
        if name:
            marker = "✅" if status in ("done", "completed") else "⬜"
            prio = f" [{priority}]" if priority else ""
            lines.append(f"- {marker} {name}{prio}")

    return "\n".join(lines) if lines else "No checklist items available."


def _format_memory_section(project: dict[str, Any]) -> str:
    """Extract system memory summary."""
    last_scan = project.get("lastScan", {})
    if not isinstance(last_scan, dict):
        return "No system memory available."
    result = last_scan.get("result", {})
    if not isinstance(result, dict):
        return "No system memory available."
    memory = result.get("targetMemory", result.get("system_memory", {}))
    if not isinstance(memory, dict):
        return "No system memory available."

    parts: list[str] = []

    # Target overview.
    overview = memory.get("target_overview", "")
    if isinstance(overview, str) and overview.strip():
        parts.append(f"**Target Overview**:\n{overview.strip()[:1500]}")

    # Routes.
    routes = memory.get("observed_routes", [])
    if isinstance(routes, list) and routes:
        parts.append(f"\n**Observed Routes** ({len(routes)}):")
        for route in routes[:20]:
            parts.append(f"  - {route}")

    # Tech stack.
    tech = memory.get("tech_stack", "")
    if isinstance(tech, str) and tech.strip():
        parts.append(f"\n**Tech Stack**: {tech.strip()}")
    elif isinstance(tech, list) and tech:
        parts.append(f"\n**Tech Stack**: {', '.join(str(t) for t in tech[:15])}")

    # Findings summary from memory.
    findings_mem = memory.get("verified_findings", [])
    if isinstance(findings_mem, list) and findings_mem:
        parts.append(f"\n**Memory Findings**: {len(findings_mem)} verified")

    return "\n".join(parts) if parts else "No system memory available."


def _format_tech_section(project: dict[str, Any]) -> str:
    """Extract technology stack information."""
    last_scan = project.get("lastScan", {})
    if not isinstance(last_scan, dict):
        return "No technology data available."
    result = last_scan.get("result", {})
    if not isinstance(result, dict):
        return "No technology data available."
    memory = result.get("targetMemory", result.get("system_memory", {}))
    if not isinstance(memory, dict):
        return "No technology data available."

    parts: list[str] = []

    tech_inventory = memory.get("tech_inventory", [])
    if isinstance(tech_inventory, list) and tech_inventory:
        parts.append("**Detected Technologies**:")
        for item in tech_inventory[:20]:
            if isinstance(item, dict):
                product = str(item.get("product", "")).strip()
                version = str(item.get("version", "")).strip()
                confidence = str(item.get("confidence", "")).strip()
                if product:
                    line = f"  - {product}"
                    if version:
                        line += f" {version}"
                    if confidence:
                        line += f" (confidence: {confidence})"
                    parts.append(line)
            elif isinstance(item, str):
                parts.append(f"  - {item}")

    tech_stack = memory.get("tech_stack", "")
    if not parts:
        if isinstance(tech_stack, str) and tech_stack.strip():
            parts.append(f"**Tech Stack**: {tech_stack.strip()}")
        elif isinstance(tech_stack, list):
            parts.append(f"**Tech Stack**: {', '.join(str(t) for t in tech_stack[:15])}")

    vuln_signals = memory.get("known_vulnerability_signals", [])
    if isinstance(vuln_signals, list) and vuln_signals:
        parts.append(f"\n**Known Vulnerability Signals** ({len(vuln_signals)}):")
        for signal in vuln_signals[:10]:
            if isinstance(signal, dict):
                desc = str(signal.get("description", str(signal))).strip()[:200]
                parts.append(f"  - {desc}")
            elif isinstance(signal, str):
                parts.append(f"  - {signal[:200]}")

    return "\n".join(parts) if parts else "No technology data available."


def _format_plan_section(project: dict[str, Any]) -> str:
    """Extract plan summary."""
    last_scan = project.get("lastScan", {})
    if not isinstance(last_scan, dict):
        return "No plan data available."
    result = last_scan.get("result", {})
    if not isinstance(result, dict):
        return "No plan data available."
    planner = result.get("planner", {})
    if not isinstance(planner, dict):
        return "No plan data available."

    summary = str(planner.get("summary", "")).strip()
    scenarios = planner.get("scenarios", [])
    if not isinstance(scenarios, list):
        scenarios = []

    parts: list[str] = []
    if summary:
        parts.append(f"**Summary**: {summary[:500]}")

    if scenarios:
        done = sum(1 for s in scenarios if isinstance(s, dict) and s.get("done"))
        total = len(scenarios)
        parts.append(f"\n**Scenarios**: {done}/{total} completed")

    return "\n".join(parts) if parts else "No plan data available."


async def generate_report(
    project_id: str,
    projects_store: Any,
) -> dict[str, Any]:
    """Generate a comprehensive pentest report for a project.

    Args:
        project_id: The project to generate a report for.
        projects_store: ProjectsStore instance.

    Returns:
        Dict with keys: report_id, content (markdown), created_at, metadata.
    """
    project = projects_store.get_project(project_id)
    if not isinstance(project, dict):
        raise ValueError(f"Project not found: {project_id}")

    target = str(project.get("target", "")).strip() or "Unknown"
    target_type = str(project.get("targetType", "")).strip() or "unknown"
    scope = str(project.get("description", "")).strip() or "Not specified"
    engagement_type = str(project.get("engagement_type", "pentest")).strip()
    status = str(project.get("status", "")).strip()

    last_scan = project.get("lastScan", {})
    if not isinstance(last_scan, dict):
        last_scan = {}
    scan_status = str(last_scan.get("status", status)).strip()

    findings = project.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    # Build prompt sections.
    findings_section = _format_findings_section(findings)
    checklist_section = _format_checklist_section(project)
    memory_section = _format_memory_section(project)
    tech_section = _format_tech_section(project)
    plan_section = _format_plan_section(project)

    user_message = REPORT_USER_PROMPT_TEMPLATE.format(
        target=target,
        target_type=target_type,
        scope=scope,
        engagement_type=engagement_type,
        scan_status=scan_status,
        total_findings=len(findings),
        findings_section=findings_section,
        checklist_section=checklist_section,
        memory_section=memory_section,
        tech_section=tech_section,
        plan_section=plan_section,
    )

    # Call LLM.
    config = get_public_agent_config("assistant")
    llm = LLMClient(config, client_name="report_generator")
    queue = get_global_llm_queue()

    try:
        messages = [
            ChatMessage(role="system", content=REPORT_SYSTEM_PROMPT),
            ChatMessage(role="user", content=user_message),
        ]

        async def _call():
            return await llm.chat(
                messages,
                tools=None,
                temperature=0.1,
                max_tokens=_REPORT_MAX_TOKENS,
            )

        response = await queue.call_with_queue("report_generator", _call())
        content = str(response.content or "").strip()
        if not content:
            raise RuntimeError("LLM returned empty report content")

    finally:
        await llm.close()

    report_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    verified_count = sum(
        1 for f in findings if str(f.get("status", "")).lower() == "verified"
    )
    severity_counts: dict[str, int] = {}
    for f in findings:
        if str(f.get("status", "")).lower() == "verified":
            sev = str(f.get("severity", "info")).lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    metadata = {
        "target": target,
        "target_type": target_type,
        "total_findings": len(findings),
        "verified_findings": verified_count,
        "severity_counts": severity_counts,
        "scan_status": scan_status,
        "generated_at": now_iso,
    }

    return {
        "report_id": report_id,
        "content": content,
        "created_at": now_iso,
        "metadata": metadata,
    }
