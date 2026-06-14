"""LLM-backed report generator with strict project/scan scoping."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from server.agents.rate_limiter import get_global_llm_queue
from server.config.agent import get_public_agent_config
from server.core.llm import ChatMessage, LLMClient
from server.utils.cvss import enrich_payload_with_cvss

from .prompts import REPORT_SYSTEM_PROMPT, REPORT_USER_PROMPT_TEMPLATE

logger = structlog.get_logger(__name__)

_REPORT_MAX_TOKENS = 8000
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}
_FINDINGS_HISTORY_KEY = "findings_history"
_LEGACY_FINDINGS_HISTORY_KEY = "analyzer_agent_reports"
_TOOL_LABEL_MAP = {
    "cors_misconfig_check": "CORS configuration review",
    "session_token_analysis": "Session handling review",
    "passive_web_recon": "Passive reconnaissance",
    "api_passive_enum": "Passive API enumeration",
    "api_endpoint_discovery": "API endpoint discovery",
    "api_response_analyzer": "API response review",
    "js_source_code_analyzer": "Client-side JavaScript review",
    "fetch_url_content": "Target content retrieval",
    "wappalyzer": "Technology fingerprinting",
    "wafw00f": "WAF detection",
    "whatweb": "Web fingerprinting",
    "curl": "HTTP request review",
    "katana": "Web crawling",
    "gospider": "Web crawling",
    "gau": "Historical URL collection",
    "ffuf": "Content and parameter fuzzing",
    "nuclei": "Template-based security checks",
    "nmap": "Network service enumeration",
    "httpx": "HTTP service probing",
    "paramspider": "Parameter discovery",
    "dns_recon": "DNS reconnaissance",
    "run_custom": "Custom command execution",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_report_date(project: dict[str, Any]) -> str:
    raw = str(project.get("createdAt", project.get("created_at", "")) or "").strip()
    if not raw:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if "T" in raw:
        return raw.split("T", 1)[0]
    return raw


def _current_scan_id(project: dict[str, Any]) -> str:
    last_scan = project.get("lastScan", {})
    if not isinstance(last_scan, dict):
        return ""
    return str(last_scan.get("scanId", "")).strip()


def _severity_rank(value: Any) -> int:
    severity = str(value or "info").strip().lower()
    if severity in _SEVERITY_ORDER:
        return _SEVERITY_ORDER.index(severity)
    return len(_SEVERITY_ORDER)


def _overall_risk_label(findings: list[dict[str, Any]]) -> str:
    severities = [
        str(item.get("severity", "")).strip().lower()
        for item in findings
        if isinstance(item, dict)
    ]
    if "critical" in severities:
        return "Critical"
    if "high" in severities:
        return "High"
    if "medium" in severities:
        return "Medium"
    if "low" in severities:
        return "Low"
    return "Informational"


def _clean_text(value: Any, *, max_chars: int | None = None) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    if max_chars is not None and len(text) > max_chars:
        return text[:max_chars].rstrip() + "..."
    return text


def _friendly_tool_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    for prefix, label in _TOOL_LABEL_MAP.items():
        if lowered.startswith(prefix):
            return label
    first = text.split()[0].split("(")[0].strip()
    return _TOOL_LABEL_MAP.get(first.lower(), first.replace("_", " ").strip().title())


def _prepare_report_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        if str(row.get("status", "")).strip().lower() == "verified":
            row = enrich_payload_with_cvss(row, set_severity=False)
        prepared.append(row)
    return prepared


def _scope_findings_to_current_scan(
    findings: list[dict[str, Any]],
    *,
    scan_id: str,
) -> list[dict[str, Any]]:
    if not scan_id:
        return findings
    has_tagged_findings = any(str(item.get("scan_id", "")).strip() for item in findings)
    if not has_tagged_findings:
        return findings
    return [
        item for item in findings
        if str(item.get("scan_id", "")).strip() == scan_id
    ]


def _history_root(project: dict[str, Any]) -> dict[str, Any]:
    payload = project.get("payload")
    if not isinstance(payload, dict):
        return {}
    root = payload.get(_FINDINGS_HISTORY_KEY)
    if isinstance(root, dict):
        return root
    legacy = payload.get(_LEGACY_FINDINGS_HISTORY_KEY)
    return legacy if isinstance(legacy, dict) else {}


def _history_entries(project: dict[str, Any], *, scan_id: str) -> list[dict[str, Any]]:
    root = _history_root(project)
    entries: list[dict[str, Any]] = []
    for bucket in root.values():
        if not isinstance(bucket, dict):
            continue
        bucket_entries = bucket.get("entries", [])
        if not isinstance(bucket_entries, list):
            continue
        for item in bucket_entries:
            if isinstance(item, dict):
                entries.append(dict(item))

    if scan_id:
        matching = [
            item for item in entries
            if str(item.get("scan_id", "")).strip() == scan_id
        ]
        if matching:
            entries = matching

    entries.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    return entries


def _parse_bullets_from_section(markdown: str, heading: str) -> list[str]:
    lines = str(markdown or "").splitlines()
    target_heading = heading.strip().lower()
    collecting = False
    bullets: list[str] = []
    for raw_line in lines:
        line = raw_line.rstrip()
        normalized = line.strip().lower()
        if normalized.startswith("## "):
            collecting = normalized == f"## {target_heading}"
            continue
        if not collecting:
            continue
        stripped = line.strip()
        if stripped.startswith("- "):
            bullets.append(_clean_text(stripped[2:], max_chars=220))
    return bullets


def _parse_tool_history(markdown: str) -> list[str]:
    bullets = _parse_bullets_from_section(markdown, "Full Tool History")
    tools: list[str] = []
    for bullet in bullets:
        match = re.search(r"`([^`]+)`", bullet)
        if match:
            friendly = _friendly_tool_name(match.group(1))
            if friendly:
                tools.append(friendly)
    return tools


def _summarize_history_entry(entry: dict[str, Any]) -> dict[str, Any]:
    markdown = str(entry.get("markdown", "")).strip()
    return {
        "recorded_at": str(entry.get("updated_at", "")).strip() or "N/A",
        "summary": _clean_text(entry.get("summary", ""), max_chars=280) or "No summary recorded.",
        "observations": _parse_bullets_from_section(markdown, "What We Find"),
        "next_steps": _parse_bullets_from_section(markdown, "What We Should Do"),
        "gaps": _parse_bullets_from_section(markdown, "Unknowns / Gaps"),
        "tools_used": _parse_tool_history(markdown),
    }


def _extract_commands(findings: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for finding in findings:
        evidence = finding.get("evidence", {})
        if not isinstance(evidence, dict):
            continue
        commands = evidence.get("commands", [])
        if not isinstance(commands, list):
            continue
        for command in commands:
            text = str(command or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            ordered.append(text)
    return ordered


def _extract_references(findings: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for finding in findings:
        cve = str(finding.get("cve", "") or "").strip()
        if cve and cve.lower() not in seen:
            seen.add(cve.lower())
            ordered.append(cve)
        cwe = str(finding.get("cwe_id", "") or "").strip()
        if cwe and cwe.lower() not in seen:
            seen.add(cwe.lower())
            ordered.append(cwe)
    return ordered


def _cvss_table_value(finding: dict[str, Any]) -> str:
    candidates = [
        finding.get("cvss_score"),
        finding.get("cvss"),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        text = str(candidate).strip()
        if not text:
            continue
        match = re.search(r"\d+(?:\.\d+)?", text)
        if match:
            return match.group(0)
    return "N/A"


def _status_label(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "Open"
    return text.replace("_", " ").title()


def _extract_tools(findings: list[dict[str, Any]], history_entries: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []

    def _add(value: Any) -> None:
        label = _friendly_tool_name(value)
        key = label.lower()
        if not label or key in seen:
            return
        seen.add(key)
        ordered.append(label)

    for finding in findings:
        evidence = finding.get("evidence", {})
        if not isinstance(evidence, dict):
            continue
        tools_used = evidence.get("tools_used", [])
        if isinstance(tools_used, list):
            for tool in tools_used:
                _add(tool)

    for entry in history_entries:
        for tool in _summarize_history_entry(entry).get("tools_used", []):
            _add(tool)

    if ordered:
        return ordered
    return ["Passive reconnaissance", "Web crawling", "HTTP inspection", "Session and trust review"]


def _extract_verification_summary(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        summary = _clean_text(evidence.get("verification_summary", ""), max_chars=320)
        if summary:
            return summary

    description = str(finding.get("description", "")).strip()
    if "Finding Summary:" in description:
        fragment = description.split("Finding Summary:", 1)[1]
        fragment = fragment.split("Verification Status:", 1)[0]
        summary = _clean_text(fragment, max_chars=320)
        if summary:
            return summary

    return _clean_text(finding.get("title", ""), max_chars=320) or "N/A"


def _extract_finding_description(finding: dict[str, Any]) -> str:
    raw = str(finding.get("description", "") or "").strip()
    if not raw:
        return ""

    markers = [
        "Verification Status:",
        "Evidence Tier:",
        "Proof Quality:",
        "Deterministic Validation:",
        "Severity Level:",
        "Scenario:",
        "How It Was Tested:",
        "Confirmation Commands:",
        "Tools Used:",
        "Verification Methods:",
        "Analyzer Chain:",
        "Normalized Evidence Summary:",
        "CVE Candidates:",
    ]
    for marker in markers:
        if marker in raw:
            raw = raw.split(marker, 1)[0]

    if "Finding Summary:" in raw:
        raw = raw.split("Finding Summary:", 1)[1]
    if "Vulnerability Type:" in raw and "Target Endpoint:" in raw and "Finding Summary:" not in str(finding.get("description", "")):
        raw = ""

    return _clean_text(raw, max_chars=800)


def _extract_finding_evidence_points(finding: dict[str, Any]) -> list[str]:
    points: list[str] = []
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        summary = _clean_text(evidence.get("verification_summary", ""), max_chars=220)
        if summary:
            points.append(summary)
        details = evidence.get("details", [])
        if isinstance(details, list):
            for item in details:
                text = _clean_text(item, max_chars=220)
                if text and text not in points:
                    points.append(text)
                if len(points) >= 3:
                    break

    for command in finding.get("evidence", {}).get("commands", []) if isinstance(finding.get("evidence", {}), dict) else []:
        text = _clean_text(command, max_chars=180)
        if text and text not in points:
            points.append(text)
        if len(points) >= 3:
            break

    if not points:
        summary = _extract_verification_summary(finding)
        if summary and summary != "N/A":
            points.append(summary)
    return points[:3]


def _finding_confidence_label(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}
    confidence = evidence.get("verification_confidence")
    if isinstance(confidence, (int, float)):
        value = float(confidence)
        if value >= 0.85:
            return "High"
        if value >= 0.6:
            return "Medium"
        return "Low"
    status = str(finding.get("status", "")).strip().lower()
    return "High" if status == "verified" else "Pending"


def _sanitize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}
    commands = evidence.get("commands", [])
    if not isinstance(commands, list):
        commands = []
    tools_used = evidence.get("tools_used", [])
    if not isinstance(tools_used, list):
        tools_used = []

    severity = str(finding.get("severity", "info")).strip().lower()
    return {
        "title": _clean_text(finding.get("title", ""), max_chars=220) or "Untitled Finding",
        "severity": _SEVERITY_LABEL.get(severity, "Info"),
        "status": _status_label(finding.get("status", "open")),
        "cvss": finding.get("cvss", finding.get("cvss_score")) or "N/A",
        "cvss_score_display": _cvss_table_value(finding),
        "cvss_vector": str(finding.get("cvss_vector", "")).strip() or "N/A",
        "confidence": _finding_confidence_label(finding),
        "affected_asset": _clean_text(finding.get("target", ""), max_chars=220) or "N/A",
        "category": _clean_text(finding.get("category", ""), max_chars=120) or "Security Issue",
        "summary": _extract_verification_summary(finding),
        "description": _extract_finding_description(finding) or _extract_verification_summary(finding),
        "remediation": _clean_text(finding.get("remediation", ""), max_chars=320) or "N/A",
        "impact": _clean_text(finding.get("impact", ""), max_chars=320) or "",
        "tools_used": [_friendly_tool_name(tool) for tool in tools_used if _friendly_tool_name(tool)],
        "evidence_commands": [str(item).strip() for item in commands[:4] if str(item).strip()],
        "evidence_points": _extract_finding_evidence_points(finding),
        "references": [
            ref for ref in [
                str(finding.get("cve", "")).strip(),
                str(finding.get("cwe_id", "")).strip(),
            ] if ref
        ],
    }


def _sanitize_false_positive(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": _clean_text(finding.get("title", ""), max_chars=220) or "Untitled Finding",
        "reason": _clean_text(finding.get("description", ""), max_chars=320) or "Dismissed by analyzer workflow.",
    }


def _build_report_payload(
    *,
    project: dict[str, Any],
    findings: list[dict[str, Any]],
    history_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    target = str(project.get("target", "")).strip() or "Unknown"
    target_type = str(project.get("targetType", "")).strip() or "unknown"
    description = _clean_text(project.get("description", ""), max_chars=500) or "Not specified"
    scan_status = str(
        (
            project.get("lastScan", {}).get("status", "")
            if isinstance(project.get("lastScan"), dict)
            else ""
        )
        or project.get("status", "")
        or "unknown"
    ).strip()

    verified_findings = [
        _sanitize_finding(item)
        for item in sorted(
            [row for row in findings if str(row.get("status", "")).strip().lower() == "verified"],
            key=lambda row: (_severity_rank(row.get("severity")), str(row.get("title", "")).lower()),
        )
    ]
    open_findings = [
        _sanitize_finding(item)
        for item in sorted(
            [row for row in findings if str(row.get("status", "")).strip().lower() in ("open", "inconclusive")],
            key=lambda row: (_severity_rank(row.get("severity")), str(row.get("title", "")).lower()),
        )
    ]
    false_positives = [
        _sanitize_false_positive(item)
        for item in findings
        if str(item.get("status", "")).strip().lower() == "false_positive"
    ]
    activity = [_summarize_history_entry(item) for item in history_entries]
    severity_counts: dict[str, int] = {}
    for item in verified_findings:
        key = str(item.get("severity", "")).strip().lower()
        severity_counts[key] = severity_counts.get(key, 0) + 1

    risk_summary_rows = [
        {
            "#": index,
            "finding": item["title"],
            "severity": item["severity"],
            "cvss": item["cvss_score_display"],
            "confidence": item["confidence"],
            "status": item["status"],
        }
        for index, item in enumerate([*verified_findings, *open_findings], start=1)
    ]

    return {
        "project_name": _clean_text(project.get("name", ""), max_chars=160) or "Untitled Project",
        "target": target,
        "target_type": target_type,
        "scope": description,
        "engagement_type": _clean_text(project.get("engagement_type", "pentest"), max_chars=80) or "pentest",
        "report_date": _normalize_report_date(project),
        "scan_status": scan_status,
        "overall_risk": _overall_risk_label(verified_findings or open_findings),
        "highest_severity": _overall_risk_label(verified_findings),
        "tools_used": _extract_tools(findings, history_entries),
        "risk_summary_rows": risk_summary_rows,
        "verified_findings": verified_findings,
        "open_findings": open_findings,
        "false_positives": false_positives,
        "assessment_activity": activity,
        "appendix": {
            "tool_commands_used": _extract_commands(findings),
            "references": _extract_references(findings),
            "limitations": [
                f"Scan status at report generation: {scan_status or 'unknown'}.",
                "This is a point-in-time assessment of the in-scope project data and is not a warranty that all possible security issues were identified.",
                "Absence of verified findings does not prove absence of risk; it means no verified vulnerabilities were saved for this project at report time.",
            ],
        },
        "summary": {
            "verified_count": len(verified_findings),
            "open_count": len(open_findings),
            "false_positive_count": len(false_positives),
            "activity_record_count": len(activity),
            "severity_counts": severity_counts,
        },
    }


async def generate_report(
    project_id: str,
    projects_store: Any,
) -> dict[str, Any]:
    project = projects_store.get_project(project_id)
    if not isinstance(project, dict):
        raise ValueError(f"Project not found: {project_id}")

    scan_id = _current_scan_id(project)
    findings = project.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    scoped_findings = _scope_findings_to_current_scan(
        _prepare_report_findings(findings),
        scan_id=scan_id,
    )
    history_entries = _history_entries(project, scan_id=scan_id)
    report_payload = _build_report_payload(
        project=project,
        findings=scoped_findings,
        history_entries=history_entries,
    )

    user_message = REPORT_USER_PROMPT_TEMPLATE.format(
        report_payload_json=json.dumps(report_payload, ensure_ascii=True, indent=2),
    )

    config = get_public_agent_config("report")
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

    now_iso = _utc_now_iso()
    verified_count = report_payload["summary"]["verified_count"]
    metadata = {
        "target": report_payload["target"],
        "target_type": report_payload["target_type"],
        "scan_status": report_payload["scan_status"],
        "scan_id": scan_id,
        "generated_at": now_iso,
        "report_date": report_payload["report_date"],
        "total_findings": len(scoped_findings),
        "verified_findings": verified_count,
        "severity_counts": report_payload["summary"]["severity_counts"],
        "history_entry_count": report_payload["summary"]["activity_record_count"],
        "report_mode": "llm_project_scoped",
    }

    logger.info(
        "report_generated_prompt_scope",
        project_id=project_id,
        scan_id=scan_id,
        verified_findings=verified_count,
        open_findings=report_payload["summary"]["open_count"],
        history_records=report_payload["summary"]["activity_record_count"],
    )

    return {
        "report_id": str(uuid.uuid4()),
        "content": content,
        "created_at": now_iso,
        "metadata": metadata,
    }
