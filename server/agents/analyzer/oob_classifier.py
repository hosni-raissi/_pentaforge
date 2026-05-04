"""Deterministic analyzer helpers for confirmed OOB callback results."""

from __future__ import annotations

import json
from typing import Any

from .parsers import normalize_tool_output, summarize_normalized_outputs

_SEVERITY_MAP = {
    "http": "high",
    "dns": "high",
    "ldap": "critical",
    "smtp": "medium",
}

_SCORE_MAP = {
    "critical": 0.99,
    "high": 0.97,
    "medium": 0.84,
}

_SSVC_MAP = {
    "critical": "ACT",
    "high": "ACT",
    "medium": "ATTEND",
}


def _candidate_scenario(candidate: Any) -> dict[str, Any]:
    if isinstance(candidate, dict):
        scenario = candidate.get("scenario", {})
        return scenario if isinstance(scenario, dict) else {}
    scenario = getattr(candidate, "scenario", {})
    return scenario if isinstance(scenario, dict) else {}


def _vuln_name(raw_result: dict[str, Any]) -> str:
    hint = str(raw_result.get("vuln_hint", "SSRF")).strip() or "SSRF"
    lowered = hint.lower()
    if lowered.startswith("blind "):
        return hint[6:].strip() or "SSRF"
    return hint


def _protocol(raw_result: dict[str, Any]) -> str:
    callbacks = raw_result.get("callbacks", [])
    if isinstance(callbacks, list) and callbacks and isinstance(callbacks[0], dict):
        return str(callbacks[0].get("protocol", "unknown")).strip().lower() or "unknown"
    return "unknown"


def _severity(protocol: str) -> str:
    return _SEVERITY_MAP.get(protocol, "high")


def _normalized_output(tool_name: str, raw_result: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_tool_output(tool_name, raw_result)
    callbacks = raw_result.get("callbacks", [])
    callback_excerpt = json.dumps(callbacks, indent=2, ensure_ascii=True)[:1200]
    markers = list(normalized.get("evidence_markers", []))
    for marker in ("oob_confirmed", "callback", str(raw_result.get("vuln_hint", "SSRF")).lower()):
        clean = str(marker).strip().lower()
        if clean and clean not in markers:
            markers.append(clean)
    normalized["parser"] = "oob_callback"
    normalized["format"] = "json"
    normalized["evidence_markers"] = markers
    normalized["raw_excerpt"] = callback_excerpt
    snippets = list(normalized.get("snippets", []))
    snippets.insert(0, f"oob_confirmed={raw_result.get('oob_confirmed', False)}")
    if raw_result.get("remote_address"):
        snippets.insert(1, f"remote_address={raw_result.get('remote_address')}")
    normalized["snippets"] = snippets[:12]
    return normalized


def build_oob_assessment(tool_name: str, raw_result: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    protocol = _protocol(raw_result)
    severity = _severity(protocol)
    score = _SCORE_MAP[severity]
    ssvc = _SSVC_MAP[severity]
    vuln_name = _vuln_name(raw_result)
    summary_name = f"Blind {vuln_name} confirmed via {protocol} callback"
    normalized = _normalized_output(tool_name, raw_result)
    normalized_summary = summarize_normalized_outputs([normalized])
    per_tool = {
        "ssvc": ssvc,
        "score": score,
        "confidence": "high",
        "finding_type": "vulnerability",
        "summary": summary_name,
        "reason": f"confirmed {protocol} OOB callback evidence",
        "signals": {
            "oob_confirmed": True,
            "protocol": protocol,
            "severity_hint": severity,
            "callback_count": len(raw_result.get("callbacks", []) if isinstance(raw_result.get("callbacks", []), list) else []),
        },
        "tool": tool_name,
        "normalized": normalized,
    }
    overall = {
        "ssvc": ssvc,
        "score": score,
        "confidence": "high",
        "finding_type": "vulnerability",
        "summary": summary_name,
        "reason": per_tool["reason"],
    }
    safe_scenario = scenario if isinstance(scenario, dict) else {}
    compact_summary = (
        f"scenario={str(safe_scenario.get('task', '')).strip()!r} "
        f"agent={str(safe_scenario.get('agent', ''))} "
        f"priority={int(safe_scenario.get('priority', 3) or 3)} "
        f"{summary_name}"
    )[:500]
    return {
        "scenario": {
            "task": str(safe_scenario.get("task", "")),
            "agent": str(safe_scenario.get("agent", "")),
            "priority": int(safe_scenario.get("priority", 3) or 3),
        },
        "finding_type": "vulnerability",
        "overall": overall,
        "per_tool": [per_tool],
        "normalized_outputs": [normalized],
        "normalized_summary": normalized_summary,
        "compact_summary": compact_summary,
    }


def build_oob_verification_payload(candidate: Any, raw_result: dict[str, Any]) -> dict[str, Any]:
    scenario = _candidate_scenario(candidate)
    protocol = _protocol(raw_result)
    vuln_name = _vuln_name(raw_result)
    summary_name = f"Blind {vuln_name} confirmed via {protocol} callback"
    tool_name = str(raw_result.get("tool_name", "check_oob_callbacks")).strip() or "check_oob_callbacks"
    normalized = _normalized_output(tool_name, raw_result)
    normalized_summary = summarize_normalized_outputs([normalized])
    callbacks = raw_result.get("callbacks", []) if isinstance(raw_result.get("callbacks"), list) else []
    return {
        "verdict": "real_vulnerability",
        "status": "real_vulnerability",
        "summary": summary_name,
        "confidence": 0.95,
        "evidence_status": "confirmed",
        "proof_quality": "strong",
        "deterministic_validation": True,
        "verification_methods": ["oob_callback"],
        "artifact_quality": {
            "callback_count": len(callbacks),
            "normalized_output_count": 1,
            "oob_confirmed": True,
        },
        "poc": json.dumps(callbacks, indent=2, ensure_ascii=True),
        "analysis_chain": ["parse", "classify", "oob_confirmed", "confirm"],
        "evidence": {
            "oob_confirmed": True,
            "callbacks": callbacks,
            "remote_address": raw_result.get("remote_address"),
            "protocol": protocol,
            "evidence_status": "confirmed",
            "proof_quality": "strong",
            "deterministic_validation": True,
            "verification_methods": ["oob_callback"],
            "artifact_quality": {
                "callback_count": len(callbacks),
                "normalized_output_count": 1,
                "oob_confirmed": True,
            },
            "normalized_outputs": [normalized],
            "normalized_summary": normalized_summary,
            "verification_summary": summary_name,
            "verification_confidence": 0.95,
            "scenario": scenario,
        },
        "normalized_outputs": [normalized],
        "normalized_summary": normalized_summary,
        "ssvc": "ACT" if _severity(protocol) in {"critical", "high"} else "ATTEND",
        "ssvc_action": "ACT" if _severity(protocol) in {"critical", "high"} else "ATTEND",
        "hitl_required": False,
        "finding_type": "vulnerability",
        "vulnerability_type": str(raw_result.get("vuln_hint", "SSRF")).strip() or "SSRF",
        "expected_indicator": f"{protocol} callback",
        "tool_results": [],
    }
