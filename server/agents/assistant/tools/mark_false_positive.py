"""Assistant tool to mark a finding as a false positive."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from server.db.projects.project_rag import (
    _artifact_doc_identity,
    _get_vector_store,
)

logger = structlog.get_logger(__name__)


def mark_false_positive(
    project_id: str,
    finding_id: str,
    reason: str,
    *,
    project_store: Any,
) -> dict[str, Any]:
    """
    Mark a finding as a false positive in the project store and remove it from RAG.
    """
    safe_project_id = str(project_id or "").strip()
    safe_finding_id = str(finding_id or "").strip()
    safe_reason = str(reason or "Operator marked as false positive").strip()

    if not safe_project_id or not safe_finding_id:
        return {"success": False, "error": "project_id and finding_id are required"}

    project = project_store.get_project(safe_project_id)
    if not isinstance(project, dict):
        return {"success": False, "error": f"Project {safe_project_id} not found"}

    findings = project.get("findings", [])
    if not isinstance(findings, list):
        return {"success": False, "error": "Project has no findings list"}

    target_finding = None
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("id")).strip() == safe_finding_id:
            target_finding = finding
            break

    if not target_finding:
        return {"success": False, "error": f"Finding {safe_finding_id} not found in project"}

    # Update finding status
    old_status = target_finding.get("status")
    target_finding["status"] = "false_positive"
    target_finding["false_positive_reason"] = safe_reason
    target_finding["updated_at"] = datetime.now(timezone.utc).isoformat()

    # Remove from RAG (verified_vulnerability kind)
    try:
        doc_identity = _artifact_doc_identity(safe_project_id, "verified_vulnerability", safe_finding_id)
        vector_store = _get_vector_store()
        # Finding is usually in 'exploits' content type in Qdrant for verified vulnerabilities
        vector_store.delete_by_doc_identity("project_verified_vulnerability", doc_identity, "exploits")
        
        # Also clean up from metadata if it exists
        rag_artifacts = project.get("ragArtifacts", [])
        if isinstance(rag_artifacts, list):
            project["ragArtifacts"] = [
                art for art in rag_artifacts 
                if isinstance(art, dict) and str(art.get("id")) != doc_identity
            ]
    except Exception as exc:
        logger.warning("false_positive_rag_cleanup_failed", finding_id=safe_finding_id, error=str(exc))

    # Log scan event for UI
    try:
        project_store.append_scan_event_cache(
            safe_project_id,
            {
                "scan_id": "assistant-action",
                "event": "finding_updated",
                "level": "info",
                "message": f"Finding '{target_finding.get('title')}' marked as false positive by assistant.",
                "data": {
                    "finding_id": safe_finding_id,
                    "status": "false_positive",
                    "reason": safe_reason,
                },
            }
        )
    except Exception:
        pass

    # Save project
    project["updatedAt"] = datetime.now(timezone.utc).isoformat()
    project_store.upsert_project(project)

    return {
        "success": True,
        "finding_id": safe_finding_id,
        "old_status": old_status,
        "new_status": "false_positive",
    }


ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION = {
    "name": "mark_false_positive",
    "description": (
        "Mark a specific vulnerability finding as a false positive. "
        "This will remove it from the assistant's long-term memory (RAG), "
        "update its status in the project database, and notify the dashboard."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "finding_id": {
                "type": "string",
                "description": "The unique ID of the finding to mark as false positive.",
            },
            "reason": {
                "type": "string",
                "description": "Brief explanation of why this finding is considered a false positive.",
            },
        },
        "required": ["finding_id", "reason"],
    },
}
