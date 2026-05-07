from __future__ import annotations

import json
from typing import Any


def _validate_grounded_verified_finding_entry(entry: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(entry, dict):
        return False, "invalid_type"

    claim_status = str(entry.get("claim_status") or "").strip().lower()
    if claim_status == "unsupported":
        return False, "claim_status=unsupported"

    evidence = entry.get("evidence") or entry
    if not isinstance(evidence, dict):
        evidence = {}

    evidence_status = str(evidence.get("claim_status") or "").strip().lower()
    if evidence_status == "unsupported":
        return False, "claim_status=unsupported"

    citations = evidence.get("cited_tool_output_ids")
    if (claim_status == "observed" or evidence_status == "observed") and not citations:
        return False, "missing_cited_tool_output_ids"

    if (claim_status == "inferred" or evidence_status == "inferred") and not citations:
        return False, "missing_cited_tool_output_ids"

    return True, ""


def _build_target_memory_evidence_text(target_memory: dict[str, Any]) -> str:
    if not isinstance(target_memory, dict):
        return ""

    evidence_fragments: list[str] = []

    for key in (
        "overview",
        "tech_stack",
        "target_info",
        "profile",
        "checklist",
        "parameter_hints",
        "anonymous_routes",
        "authenticated_routes",
        "auth_surface_delta",
        "session_contexts",
        "blocked_routes",
        "blocked_route_prefixes",
    ):
        value = target_memory.get(key)
        if value is not None:
            evidence_fragments.append(json.dumps(value, ensure_ascii=True))

    verified_findings = target_memory.get("verified_findings", [])
    if isinstance(verified_findings, list):
        compact_findings: list[dict[str, Any]] = []
        for item in verified_findings[:40]:
            if not isinstance(item, dict):
                continue
            compact_findings.append(
                {
                    "title": str(item.get("title", "")).strip(),
                    "summary": str(item.get("summary", "")).strip(),
                    "status": str(item.get("status", "")).strip(),
                    "claim_status": str(item.get("claim_status", "")).strip(),
                    "source_lineage": item.get("source_lineage", []),
                    "cited_tool_output_ids": item.get("cited_tool_output_ids", []),
                }
            )
        if compact_findings:
            evidence_fragments.append(json.dumps(compact_findings, ensure_ascii=True))

    tool_observations = target_memory.get("tool_observations", [])
    if isinstance(tool_observations, list):
        compact_observations: list[dict[str, Any]] = []
        for item in tool_observations[-80:]:
            if not isinstance(item, dict):
                continue
            compact_observations.append(
                {
                    "tool": str(item.get("tool", "")).strip(),
                    "scenario_task": str(item.get("scenario_task", "")).strip(),
                    "status": str(item.get("status", "")).strip(),
                }
            )
        if compact_observations:
            evidence_fragments.append(json.dumps(compact_observations, ensure_ascii=True))

    return "\n".join(fragment for fragment in evidence_fragments if fragment).lower()
