"""Planner Context Helpers — Data retrieval for context building.

Provides functions to query SQLite projects store, Qdrant vector store,
and maintain the context window lifecycle.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone
import json

import structlog

logger = structlog.get_logger(__name__)


async def get_engagement_snapshot(
    project_id: str,
    projects_store: Any,
) -> dict[str, Any]:
    """Query current engagement state from projects store.

    Returns dict with keys: current_phase, round_num, detected_tech,
    checklist_coverage, world_state.
    """
    try:
        project = projects_store.get_project(project_id)
        if not isinstance(project, dict):
            return _empty_snapshot()

        # Extract detection results if available
        last_scan = project.get("lastScan", {})
        detected_tech = []
        if isinstance(last_scan, dict):
            detected_tech = last_scan.get("detectedTech", [])

        # Extract checklist data
        checklist_data = project.get("checklist", {})
        if isinstance(checklist_data, dict):
            checklist_items = checklist_data.get("items", [])
            total = len(checklist_items)
            completed = sum(1 for item in checklist_items if isinstance(item, dict) and item.get("done"))

            # Find critical gaps (high priority, not done)
            critical_gaps = []
            for item in checklist_items:
                if isinstance(item, dict):
                    priority = item.get("priority", 3)
                    done = item.get("done", False)
                    if priority <= 2 and not done:
                        critical_gaps.append(str(item.get("name", "unknown"))[:40])

            checklist_coverage = {
                "total": total,
                "completed": completed,
                "critical_gaps": critical_gaps[:5],  # Limit to 5 items
                "blocked_by_prereqs": [],  # TODO: Parse prereqs from checklist
            }
        else:
            checklist_coverage = {
                "total": 0,
                "completed": 0,
                "critical_gaps": [],
                "blocked_by_prereqs": [],
            }

        # Get world state from scan events
        world_state = _extract_world_state_from_events(
            projects_store.list_scan_event_cache(project_id, limit=200)
        )

        return {
            "current_phase": last_scan.get("phase", "reconnaissance"),
            "round_num": last_scan.get("round", 1),
            "detected_tech": detected_tech[:10],  # Limit to 10
            "checklist_coverage": checklist_coverage,
            "world_state": world_state,
        }
    except Exception as exc:
        logger.warning("engagement_snapshot_failed", error=str(exc))
        return _empty_snapshot()


def _empty_snapshot() -> dict[str, Any]:
    """Return empty snapshot defaults."""
    return {
        "current_phase": "reconnaissance",
        "round_num": 1,
        "detected_tech": [],
        "checklist_coverage": {
            "total": 0,
            "completed": 0,
            "critical_gaps": [],
            "blocked_by_prereqs": [],
        },
        "world_state": {
            "open_tasks": 0,
            "blocked_tasks": 0,
            "act_findings": 0,
            "attend_findings": 0,
            "track_findings": 0,
        },
    }


def _extract_world_state_from_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Count findings by SSVC level from events cache."""
    act_count = 0
    attend_count = 0
    track_count = 0

    for event in events:
        if not isinstance(event, dict):
            continue
        data = event.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                continue
        if not isinstance(data, dict):
            continue

        assessment = data.get("assessment", {})
        if isinstance(assessment, dict):
            overall = assessment.get("overall", {})
            if isinstance(overall, dict):
                ssvc = str(overall.get("ssvc", "")).strip().upper()
                if ssvc == "ACT":
                    act_count += 1
                elif ssvc == "ATTEND":
                    attend_count += 1
                elif ssvc == "TRACK":
                    track_count += 1

    return {
        "open_tasks": 5,  # TODO: Parse from plan scenarios
        "blocked_tasks": 0,  # TODO: Parse from plan scenarios
        "act_findings": act_count,
        "attend_findings": attend_count,
        "track_findings": track_count,
    }


async def get_new_findings_delta(
    project_id: str,
    last_round_timestamp: str | None,
    projects_store: Any,
) -> list[dict[str, Any]]:
    """Query NEW findings since last round (pure delta).

    Only findings created after last_round_timestamp are returned.
    Each finding is extracted from perceptor_classified events.
    """
    try:
        # Get all events from the cache
        all_events = projects_store.list_scan_event_cache(project_id, limit=500)

        # Filter to only perceptor_classified events with findings
        findings = []
        cutoff_time = (
            datetime.fromisoformat(last_round_timestamp)
            if last_round_timestamp
            else datetime.fromtimestamp(0, tz=timezone.utc)
        )

        for event in all_events:
            if not isinstance(event, dict):
                continue

            # Check timestamp
            event_time_str = event.get("timestamp")
            if event_time_str:
                try:
                    event_time = datetime.fromisoformat(event_time_str)
                    if event_time <= cutoff_time:
                        continue
                except (ValueError, TypeError):
                    pass

            # Only process perceptor_classified events
            if event.get("event") != "perceptor_classified":
                continue

            data = event.get("data", {})
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except (json.JSONDecodeError, TypeError):
                    continue
            if not isinstance(data, dict):
                continue

            assessment = data.get("assessment", {})
            if not isinstance(assessment, dict):
                continue

            # Extract key fields
            overall = assessment.get("overall", {})
            if isinstance(overall, dict):
                finding = {
                    "ref_id": f"fin_{len(findings):03d}",
                    "tool": assessment.get("tool_name", "unknown"),
                    "target": assessment.get("target", "unknown"),
                    "summary": assessment.get("compact_summary", "finding"),
                    "ssvc": str(overall.get("ssvc", "TRACK")).strip().upper(),
                    "cvss_score": overall.get("cvss_score", "N/A"),
                    "epss_score": overall.get("epss_score", "N/A"),
                    "cisa_kev": bool(overall.get("cisa_kev", False)),
                    "confirmed": assessment.get("finding_type") == "vulnerability",
                    "recommended_action": assessment.get("recommended_action", "evaluate"),
                }
                findings.append(finding)

        return findings[:10]  # Limit to 10 most recent findings
    except Exception as exc:
        logger.warning("new_findings_delta_failed", error=str(exc))
        return []


async def retrieve_rag_context(
    query: str,
    domain: str,
    vector_store: Any,
    max_chunks: int = 5,
) -> list[dict[str, Any]]:
    """Query Qdrant for relevant knowledge chunks.

    Args:
        query: Combined signal (finding summary + detected tech + phase)
        domain: Knowledge domain ("web", "api", "network", etc.)
        vector_store: QdrantVectorStore instance
        max_chunks: Maximum chunks to return (hard cap 5)

    Returns:
        List of {source, content, similarity_score, metadata}
    """
    try:
        # Map domain to content types to search
        content_types = ["strategies", "exploits", "tools", "standards", "attack_types"]

        # Search across multiple content types
        results = vector_store.search_multi(
            query_text=query,
            content_types=content_types,
            domain_filter=domain if domain != "general" else None,
            limit=max_chunks,
            min_score=0.72,  # Hard cutoff
        )

        # Format results
        formatted = []
        for result in results[:max_chunks]:
            chunk = result.get("chunk")  # KnowledgeChunk object
            if chunk is None:
                continue

            formatted.append({
                "source": chunk.source if hasattr(chunk, "source") else "unknown",
                "content": chunk.text[:400] if hasattr(chunk, "text") else "",
                "similarity_score": result.get("score", 0.0),
                "metadata": {
                    "domain": chunk.domain if hasattr(chunk, "domain") else domain,
                    "tags": chunk.tags if hasattr(chunk, "tags") else [],
                },
            })

        return formatted
    except Exception as exc:
        logger.warning("rag_context_retrieval_failed", error=str(exc))
        return []


def build_rag_query_signal(
    new_finding_summary: str | None,
    detected_tech: list[str],
    current_phase: str,
) -> str:
    """Combine multiple signals into a single RAG query.

    The query should describe the current problem space to Qdrant.
    """
    parts = []
    if new_finding_summary:
        # Take first 100 chars of finding
        parts.append(new_finding_summary[:100])
    if detected_tech:
        parts.append(f"Technology: {', '.join(detected_tech[:5])}")
    if current_phase:
        parts.append(f"Phase: {current_phase}")
    return " | ".join(parts) if parts else "general methodology"


def extract_domain_from_targets(targets: list[str]) -> str:
    """Infer knowledge domain from target list.

    Examples:
        ["10.0.0.0/24", "192.168.1.1"] → "network"
        ["example.com", "api.example.com"] → "web"
    """
    if not targets:
        return "general"

    # Heuristic: check first target
    first = targets[0].lower() if targets else ""
    if ":" in first:  # Port number
        return "web"
    if first.startswith("10.") or first.startswith("192.168") or first.startswith("172."):
        return "network"
    if "/" in first:  # CIDR
        return "network"
    if "." in first:  # Domain
        return "web"
    return "general"


async def record_planner_round(
    project_id: str,
    round_num: int,
    input_message: str,
    output_json: dict[str, Any],
    projects_store: Any,
) -> None:
    """Record this Planner round to event cache for audit trail."""
    try:
        # Store as a special event for future retrieval
        event_data = {
            "stage": "planner",
            "kind": "round_record",
            "round_num": round_num,
            "input_length": len(input_message),
            "output": output_json,
        }

        projects_store.append_scan_event_cache(
            project_id=project_id,
            event="planner_round_recorded",
            level="info",
            message=f"Planner round {round_num} recorded",
            data=event_data,
        )
        logger.info(
            "planner_round_recorded",
            project_id=project_id,
            round_num=round_num,
        )
    except Exception as exc:
        logger.warning("planner_round_recording_failed", error=str(exc))

