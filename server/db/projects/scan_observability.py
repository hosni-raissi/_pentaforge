from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any


_WORKER_RE = re.compile(r"\[worker[^\]]*?(\d+)\]", re.IGNORECASE)
_SCENARIO_QUOTED_RE = re.compile(r"scenario='([^']+)'", re.IGNORECASE)
_SCENARIO_PLAIN_RE = re.compile(r"scenario(?: started execution| completed)?:\s*(.+)$", re.IGNORECASE)
_TOOL_CALL_RE = re.compile(r"tool call:\s*([a-z0-9_./-]+)", re.IGNORECASE)
_TOOL_COMPLETED_RE = re.compile(r"\b([a-z0-9_./-]+)\s+completed(?:\s*\(|:)", re.IGNORECASE)
_CYCLE_RE = re.compile(r"cycle\s+(\d+)", re.IGNORECASE)


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(_normalize_text(part) for part in parts if _normalize_text(part))
    digest = hashlib.sha1(material.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _parse_iso(value: Any) -> datetime | None:
    text = _normalize_text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _extract_cycle(payload: dict[str, Any], data: dict[str, Any]) -> int | None:
    for candidate in (data.get("cycle"), payload.get("cycle")):
        if isinstance(candidate, int):
            return max(0, candidate)
        if isinstance(candidate, float) and candidate.is_integer():
            return max(0, int(candidate))
    text = f"{_normalize_text(payload.get('event'))} {_normalize_text(payload.get('message'))}"
    match = _CYCLE_RE.search(text)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def _extract_tool(payload: dict[str, Any], data: dict[str, Any]) -> str:
    for candidate in (
        data.get("tool_name"),
        data.get("tool"),
        data.get("command_name"),
        data.get("safety_profile", {}).get("tool_name") if isinstance(data.get("safety_profile"), dict) else None,
    ):
        text = _normalize_text(candidate).lower()
        if text:
            return text
    message = _normalize_text(payload.get("message"))
    match = _TOOL_CALL_RE.search(message)
    if match:
        return match.group(1).strip().lower()
    match = _TOOL_COMPLETED_RE.search(message)
    if match:
        return match.group(1).strip().lower()
    return ""


def _is_tool_start_event(event: dict[str, Any]) -> bool:
    return bool(_TOOL_CALL_RE.search(_normalize_text(event.get("message"))))


def _is_tool_failure_event(event: dict[str, Any]) -> bool:
    message = _normalize_text(event.get("message")).lower()
    event_name = _normalize_text(event.get("event")).lower()
    level = _normalize_text(event.get("level")).lower()
    return (
        "tool error:" in message
        or message.startswith("error executing ")
        or (level == "error" and "tool" in event_name)
    )


def _is_resume_terminal_event(event_name: str, event: dict[str, Any]) -> bool:
    if event_name in {"scan_completed", "scan_failed", "scan_paused"}:
        return True
    if event_name == "project_status":
        status = _normalize_text(event.get("data", {}).get("status") if isinstance(event.get("data"), dict) else "").lower()
        return status in {"completed", "failed", "stopped", "paused", "cancelled", "error"}
    return False


def _extract_phase(payload: dict[str, Any], data: dict[str, Any]) -> str:
    for candidate in (data.get("stage"), data.get("phase")):
        text = _normalize_text(candidate).lower().replace(" ", "_")
        if text:
            return text
    event_name = _normalize_text(payload.get("event")).lower()
    message = _normalize_text(payload.get("message")).lower()
    for text in (event_name, message):
        if "information_gathering" in text or "target_info_gathering" in text:
            return "information_gathering"
        if "planner" in text or "checklist" in text:
            return "planner"
        if "executer" in text or "recon" in text or "exploit" in text:
            return "executer"
        if "analyzer" in text or "verify" in text or "retest" in text or "perceptor" in text:
            return "analyzer"
        if "intel" in text:
            return "intel"
        if "memory" in text or "brain" in text:
            return "brain"
        if "report" in text:
            return "reporting"
    return "system"


def _extract_agent(data: dict[str, Any], phase: str) -> str:
    agent = _normalize_text(data.get("agent")).lower()
    if agent:
        if agent in {"recon", "exploit"}:
            return "executer"
        if agent in {"verify", "report", "retest", "perceptor"}:
            return "analyzer"
        return agent
    if phase in {"recon", "exploit", "executer"}:
        return "executer"
    if phase in {"verify", "retest", "perceptor", "analyzer"}:
        return "analyzer"
    if phase == "planner":
        return "planner"
    if phase == "intel":
        return "intel"
    return "system"


def _extract_scenario_title(payload: dict[str, Any], data: dict[str, Any]) -> str:
    for candidate in (
        data.get("scenario_id"),
        data.get("scenario_title"),
        data.get("scenario"),
        data.get("task"),
    ):
        text = _normalize_text(candidate)
        if text:
            return text
    scenario = data.get("scenario")
    if isinstance(scenario, dict):
        for key in ("id", "title", "task", "details", "name"):
            text = _normalize_text(scenario.get(key))
            if text:
                return text
    assessment = data.get("assessment")
    if isinstance(assessment, dict):
        for key in ("scenario_id", "compact_summary", "task"):
            text = _normalize_text(assessment.get(key))
            if text:
                return text
    message = _normalize_text(payload.get("message"))
    for regex in (_SCENARIO_QUOTED_RE, _SCENARIO_PLAIN_RE):
        match = regex.search(message)
        if match:
            return match.group(1).strip()
    return ""


def _extract_approval_id(payload: dict[str, Any], data: dict[str, Any], phase: str) -> str:
    for key in ("approval_id", "password_id"):
        text = _normalize_text(data.get(key))
        if text:
            return text
    event_name = _normalize_text(payload.get("event")).lower()
    if event_name in {"planner_waiting_approval", "planner_approval_received"}:
        return _stable_id("approval", payload.get("scan_id"), "planner")
    if event_name in {
        "target_info_gathering_waiting_approval",
        "target_info_gathering_approval_received",
    }:
        return _stable_id("approval", payload.get("scan_id"), "information_gathering")
    if "approval" in event_name and phase:
        return _stable_id("approval", payload.get("scan_id"), phase, payload.get("event"))
    return ""


def _extract_finding_id(payload: dict[str, Any], data: dict[str, Any]) -> str:
    for candidate in (
        data.get("finding_id"),
        data.get("record_id"),
    ):
        text = _normalize_text(candidate)
        if text:
            return text
    finding = data.get("finding")
    if isinstance(finding, dict):
        text = _normalize_text(finding.get("id"))
        if text:
            return text
    assessment = data.get("assessment")
    if isinstance(assessment, dict):
        text = _normalize_text(assessment.get("finding_id"))
        if text:
            return text
    summary = _normalize_text(payload.get("message"))
    if not summary:
        return ""
    return _stable_id("finding", payload.get("scan_id"), summary[:120])


def _extract_reason_code(payload: dict[str, Any], data: dict[str, Any], phase: str) -> str:
    direct = _normalize_text(data.get("reason_code")).lower()
    if direct:
        return direct
    event_name = _normalize_text(payload.get("event")).lower()
    message = _normalize_text(payload.get("message")).lower()
    kind = _normalize_text(data.get("kind")).lower()
    status = _normalize_text(data.get("status")).lower()

    if event_name == "scan_started":
        return "resume_restored" if data.get("resume_restored") else "scan_started"
    if event_name == "scan_completed":
        return "scan_completed"
    if event_name == "scan_failed":
        return "scan_failed"
    if "false_positive" in event_name or status == "false_positive" or "false positive" in message:
        return "false_positive_confirmed" if phase == "analyzer" else "manual_false_positive_marked"
    if "inconclusive" in event_name or status == "inconclusive":
        return "verification_inconclusive"
    if "grounding_rejected" in kind or "grounding_rejected" in event_name:
        return "verification_grounding_rejected"
    if "fallback" in event_name or kind == "fallback_plan":
        return "planner_fallback_plan"
    if event_name == "finding_updated":
        return "finding_status_changed"
    if "approval_received" in event_name:
        return "approval_granted"
    if "tool_approval_decision" in event_name:
        action = _normalize_text(data.get("action")).lower() or "unknown"
        return f"tool_approval_{action}"
    if "password_response" in event_name:
        return "password_response_submitted"
    if "tool_approval_cleared" in event_name:
        return "approval_cleared"
    if "waiting_approval" in event_name or "password_request" in event_name:
        return "approval_waiting"
    return ""


def enrich_scan_event_payload(project_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    safe_payload = dict(payload)
    data = safe_payload.get("data", {})
    if not isinstance(data, dict):
        data = {}
    data = dict(data)

    phase = _extract_phase(safe_payload, data)
    cycle = _extract_cycle(safe_payload, data)
    agent = _extract_agent(data, phase)
    scenario_title = _extract_scenario_title(safe_payload, data)
    approval_id = _extract_approval_id(safe_payload, data, phase)
    finding_id = _extract_finding_id(safe_payload, data)
    tool = _extract_tool(safe_payload, data)
    reason_code = _extract_reason_code(safe_payload, data, phase)
    scan_id = _normalize_text(safe_payload.get("scan_id"))
    timestamp = _normalize_text(safe_payload.get("timestamp"))
    message = _normalize_text(safe_payload.get("message"))
    event_name = _normalize_text(safe_payload.get("event")).lower()
    worker_match = _WORKER_RE.search(message)
    worker_id = worker_match.group(1) if worker_match else ""
    scenario_id = _normalize_text(data.get("scenario_id"))
    if not scenario_id and scenario_title:
        scenario_id = _stable_id("scenario", scan_id or project_id, scenario_title)
    phase_id = _normalize_text(data.get("phase_id")) or (
        f"{scan_id}:{phase}" if scan_id and phase else ""
    )
    event_id = _normalize_text(safe_payload.get("event_id")) or _stable_id(
        "evt",
        project_id,
        scan_id,
        timestamp,
        event_name,
        message,
    )

    observability = {
        "event_id": event_id,
        "phase": phase,
        "phase_id": phase_id,
        "cycle": cycle,
        "scenario_id": scenario_id,
        "scenario_title": scenario_title,
        "approval_id": approval_id,
        "finding_id": finding_id,
        "agent": agent,
        "tool": tool,
        "worker_id": worker_id,
        "reason_code": reason_code,
    }
    data["observability"] = observability
    safe_payload["project_id"] = _normalize_text(project_id)
    safe_payload["event_id"] = event_id
    safe_payload["phase"] = phase
    safe_payload["phase_id"] = phase_id
    safe_payload["cycle"] = cycle
    safe_payload["scenario_id"] = scenario_id
    safe_payload["approval_id"] = approval_id
    safe_payload["finding_id"] = finding_id
    safe_payload["agent"] = agent
    safe_payload["tool"] = tool
    safe_payload["worker_id"] = worker_id
    safe_payload["reason_code"] = reason_code
    safe_payload["data"] = data
    return safe_payload


def build_debug_timeline(
    events: list[dict[str, Any]],
    tool_audits: list[dict[str, Any]],
    *,
    limit: int = 200,
) -> list[dict[str, Any]]:
    min_dt = datetime.min.replace(tzinfo=timezone.utc)
    items: list[dict[str, Any]] = []
    for event in events:
        enriched = enrich_scan_event_payload(_normalize_text(event.get("project_id")), event)
        items.append(
            {
                "id": _normalize_text(enriched.get("event_id")),
                "kind": "scan_event",
                "at": _normalize_text(enriched.get("timestamp")),
                "event": _normalize_text(enriched.get("event")),
                "level": _normalize_text(enriched.get("level")) or "info",
                "message": _normalize_text(enriched.get("message")),
                "project_id": _normalize_text(enriched.get("project_id")),
                "scan_id": _normalize_text(enriched.get("scan_id")),
                "cycle": enriched.get("cycle"),
                "phase": _normalize_text(enriched.get("phase")),
                "phase_id": _normalize_text(enriched.get("phase_id")),
                "scenario_id": _normalize_text(enriched.get("scenario_id")),
                "approval_id": _normalize_text(enriched.get("approval_id")),
                "finding_id": _normalize_text(enriched.get("finding_id")),
                "agent": _normalize_text(enriched.get("agent")),
                "tool": _normalize_text(enriched.get("tool")),
                "reason_code": _normalize_text(enriched.get("reason_code")),
                "worker_id": _normalize_text(enriched.get("worker_id")),
            }
        )

    for audit in tool_audits:
        status = _normalize_text(audit.get("status")).lower() or "unknown"
        items.append(
            {
                "id": _stable_id("audit", audit.get("id"), audit.get("project_id"), audit.get("scan_id"), audit.get("tool_name"), audit.get("full_command")),
                "kind": "tool_audit",
                "at": _normalize_text(audit.get("created_at")),
                "event": "tool_audit",
                "level": "error" if status in {"failed", "blocked"} else "info",
                "message": _normalize_text(audit.get("full_command")) or _normalize_text(audit.get("tool_name")),
                "project_id": _normalize_text(audit.get("project_id")),
                "scan_id": _normalize_text(audit.get("scan_id")),
                "cycle": None,
                "phase": _normalize_text(audit.get("role")) or "executer",
                "phase_id": "",
                "scenario_id": "",
                "approval_id": "",
                "finding_id": "",
                "agent": _normalize_text(audit.get("role")) or "executer",
                "tool": _normalize_text(audit.get("tool_name")),
                "reason_code": f"tool_audit_{status}",
                "worker_id": "",
            }
        )

    items.sort(
        key=lambda item: _parse_iso(item.get("at")) or min_dt,
        reverse=True,
    )
    return items[: max(1, min(limit, 500))]


def compute_observability_metrics(
    events: list[dict[str, Any]],
    tool_audits: list[dict[str, Any]],
) -> dict[str, Any]:
    min_dt = datetime.min.replace(tzinfo=timezone.utc)
    enriched_events = [
        enrich_scan_event_payload(_normalize_text(event.get("project_id")), event)
        for event in events
    ]
    enriched_events.sort(key=lambda item: _parse_iso(item.get("timestamp")) or min_dt)

    cycle_starts: dict[str, datetime] = {}
    cycle_durations: list[float] = []
    approval_starts: dict[str, datetime] = {}
    approval_durations: list[float] = []
    resume_started: set[str] = set()
    resume_completed: set[str] = set()
    false_positive_ids: set[str] = set()
    verified_vulnerability_ids: set[str] = set()
    non_audited_tool_starts = 0
    non_audited_tool_failures = 0

    for event in enriched_events:
        event_name = _normalize_text(event.get("event")).lower()
        reason_code = _normalize_text(event.get("reason_code")).lower()
        timestamp = _parse_iso(event.get("timestamp"))
        scan_id = _normalize_text(event.get("scan_id"))
        approval_id = _normalize_text(event.get("approval_id"))
        cycle = event.get("cycle")
        tool_name = _normalize_text(event.get("tool")).lower()
        finding_id = _normalize_text(event.get("finding_id"))
        message = _normalize_text(event.get("message"))

        if timestamp and isinstance(cycle, int):
            cycle_key = f"{scan_id}:{cycle}"
            if event_name == "executer_cycle_start":
                cycle_starts[cycle_key] = timestamp
            elif event_name in {"executer_cycle_completed", "warmup_cycle_completed"}:
                started_at = cycle_starts.pop(cycle_key, None)
                if started_at:
                    cycle_durations.append((timestamp - started_at).total_seconds())

        if timestamp and approval_id:
            if "waiting" in event_name or event_name == "executer_password_request":
                approval_starts.setdefault(approval_id, timestamp)
            elif (
                "approval_received" in event_name
                or "tool_approval_decision" in event_name
                or "password_response" in event_name
                or "approval_cleared" in event_name
            ):
                started_at = approval_starts.pop(approval_id, None)
                if started_at:
                    approval_durations.append((timestamp - started_at).total_seconds())

        if reason_code == "resume_restored" and scan_id:
            resume_started.add(scan_id)
        if scan_id and scan_id in resume_started and _is_resume_terminal_event(event_name, event):
            resume_completed.add(scan_id)

        if reason_code in {"false_positive_confirmed", "manual_false_positive_marked"}:
            false_positive_ids.add(finding_id or _stable_id("fp", scan_id, message[:160]))
        if (
            "real_vulnerability" in message.lower()
            or event_name == "verified_finding_saved"
        ):
            verified_vulnerability_ids.add(finding_id or _stable_id("rv", scan_id, message[:160]))

        if _is_tool_start_event(event) and tool_name and tool_name != "run_custom":
            non_audited_tool_starts += 1
        if _is_tool_failure_event(event):
            non_audited_tool_failures += 1

    audited_tool_logs = len(tool_audits)
    failed_tool_logs = sum(
        1
        for item in tool_audits
        if _normalize_text(item.get("status")).lower() in {"failed", "blocked", "error"}
    )
    total_tool_logs = audited_tool_logs + non_audited_tool_starts
    failed_tool_logs += non_audited_tool_failures
    tool_failure_rate = (failed_tool_logs / total_tool_logs) if total_tool_logs else 0.0
    false_positive_count = len(false_positive_ids)
    verified_vulnerability_count = len(verified_vulnerability_ids)
    verification_total = false_positive_count + verified_vulnerability_count
    false_positive_rate = (false_positive_count / verification_total) if verification_total else 0.0
    resume_total = len(resume_started)
    resume_success_rate = (len(resume_completed) / resume_total) if resume_total else 0.0

    return {
        "average_cycle_time_seconds": round(sum(cycle_durations) / len(cycle_durations), 2) if cycle_durations else 0.0,
        "average_approval_delay_seconds": round(sum(approval_durations) / len(approval_durations), 2) if approval_durations else 0.0,
        "tool_failure_rate": round(tool_failure_rate, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "resume_success_rate": round(resume_success_rate, 4),
        "cycle_count": len(cycle_durations),
        "approval_count": len(approval_durations),
        "tool_log_count": total_tool_logs,
        "failed_tool_log_count": failed_tool_logs,
        "false_positive_count": false_positive_count,
        "verified_vulnerability_count": verified_vulnerability_count,
        "resume_attempt_count": resume_total,
        "resume_success_count": len(resume_completed),
    }
