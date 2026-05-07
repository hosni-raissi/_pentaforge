"""Assistant tool to add a finding or intelligence to the planner's 'brain'."""

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


def add_finding_to_brain(
    project_id: str,
    title: str,
    description: str,
    severity: str = "info",
    status: str = "not_done",
    *,
    project_store: Any,
) -> dict[str, Any]:
    """
    Add a finding, vulnerability, or intelligence note to the project store.
    """
    safe_project_id = str(project_id or "").strip()
    safe_title = str(title or "").strip()
    safe_description = str(description or "").strip()
    safe_severity = str(severity or "info").lower().strip()
    # status 'done' maps to project finding 'confirmed' or similar, 
    # but we'll use a specific field for user-added status.
    is_done = str(status or "").lower().strip() == "done"

    if not safe_project_id or not safe_title:
        return {"success": False, "error": "project_id and title are required"}

    project = project_store.get_project(safe_project_id)
    if not isinstance(project, dict):
        return {"success": False, "error": f"Project {safe_project_id} not found"}

    findings = project.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    # Check for duplicates by title
    normalized_title = safe_title.lower().replace(" ", "").replace("_", "").replace("-", "")
    for f in findings:
        if not isinstance(f, dict):
            continue
        existing_title = str(f.get("title", "")).lower().replace(" ", "").replace("_", "").replace("-", "")
        if existing_title == normalized_title:
            return {
                "success": False, 
                "error": f"A finding with title '{safe_title}' already exists.",
                "finding_id": f.get("id")
            }

    finding_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    new_finding = {
        "id": finding_id,
        "title": safe_title,
        "description": safe_description,
        "severity": safe_severity,
        "status": "confirmed" if is_done else "pending",
        "source": "user_contribution",
        "user_contribution_status": "done" if is_done else "not_done",
        "timestamp": now_iso,
        "updated_at": now_iso,
        "tags": ["assistant_injected", "user_help"],
    }

    findings.append(new_finding)
    project["findings"] = findings
    project["updatedAt"] = now_iso

    # Add to RAG if it's a significant finding
    if safe_severity not in ("info", "low") or is_done:
        try:
            vector_store = _get_vector_store()
            doc_identity = _artifact_doc_identity(safe_project_id, "verified_vulnerability", finding_id)
            
            # Metadata for RAG
            metadata = {
                "project_id": safe_project_id,
                "kind": "verified_vulnerability",
                "recordId": finding_id,
                "title": safe_title,
                "severity": safe_severity,
                "source": "assistant_finding",
                "timestamp": now_iso,
            }
            
            # Simple text content for embedding
            content = f"Title: {safe_title}\nDescription: {safe_description}\nSeverity: {safe_severity}\nSource: User Contribution via Assistant"
            
            vector_store.upsert_document(
                collection_name="project_verified_vulnerability",
                doc_identity=doc_identity,
                content=content,
                metadata=metadata,
                content_type="exploits"
            )
        except Exception as exc:
            logger.warning("add_finding_to_rag_failed", title=safe_title, error=str(exc))

    # Log scan event for UI and Planner sync
    try:
        project_store.append_scan_event_cache(
            safe_project_id,
            {
                "scan_id": "assistant-contribution",
                "event": "perceptor_classified", # Planner specifically looks for this
                "level": "info",
                "message": f"New finding added via assistant: {safe_title}",
                "data": {
                    "reason_code": "assistant_finding_added",
                    "assessment": {
                        "compact_summary": f"[User Contributed] {safe_title}: {safe_description[:50]}...",
                        "severity": safe_severity,
                        "finding_id": finding_id,
                    }
                },
            }
        )
    except Exception:
        pass

    # Save project
    project_store.upsert_project(project)

    return {
        "success": True,
        "finding_id": finding_id,
        "title": safe_title,
        "status": "done" if is_done else "not_done",
    }


ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION = {
    "name": "add_finding_to_brain",
    "description": (
        "Add a new finding, vulnerability, or intelligence note to the project's 'brain'. "
        "Use this when the user provides valuable information or when you discover something manually "
        "that should be tracked and verified by the automated agents."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Short, descriptive title of the finding.",
            },
            "description": {
                "type": "string",
                "description": "Detailed explanation of the finding, including potential impact or location.",
            },
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "The estimated severity level.",
                "default": "info",
            },
            "status": {
                "type": "string",
                "enum": ["done", "not_done"],
                "description": "Whether the finding is already confirmed ('done') or needs verification ('not_done').",
                "default": "not_done",
            },
        },
        "required": ["title", "description"],
    },
}
