"""Assistant tool to mark a finding as a false positive."""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from server.db.projects.project_rag import (
    _artifact_doc_identity,
    _get_vector_store,
)
from server.nodes.system_memory import load_system_memory, save_system_memory

logger = structlog.get_logger(__name__)


def _normalize_match_text(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = text.replace("_", " ").replace("-", " ")
    text = re.sub(r"\s+", " ", text)
    return text


def _extract_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _collect_finding_texts(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []

    texts: list[str] = []
    for key in (
        "id",
        "title",
        "description",
        "summary",
        "category",
        "target",
        "endpoint",
        "parameter",
        "tool",
        "severity",
        "status",
        "remediation",
        "cve",
        "cwe",
        "false_positive_reason",
        "verify_summary",
        "compact_summary",
    ):
        text = str(value.get(key, "")).strip()
        if text:
            texts.append(text)

    evidence = value.get("evidence", {})
    if isinstance(evidence, dict):
        for key in (
            "verification_summary",
            "evidence_status",
            "proof_quality",
            "protocol",
            "remote_address",
        ):
            text = str(evidence.get(key, "")).strip()
            if text:
                texts.append(text)
        for key in ("verification_methods", "commands", "tools_used"):
            texts.extend(_extract_string_list(evidence.get(key)))

    for key in ("verification_methods", "commands", "tools_used"):
        texts.extend(_extract_string_list(value.get(key)))

    deduped: list[str] = []
    seen: set[str] = set()
    for text in texts:
        norm = _normalize_match_text(text)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        deduped.append(text)
    return deduped


def _candidate_score(query: str, candidate: str) -> int:
    if not query or not candidate:
        return 0
    if query == candidate:
        return 5000
    if len(query) >= 16 and query in candidate:
        return 3200 + min(len(query), 400)
    if len(candidate) >= 16 and candidate in query:
        return 2800 + min(len(candidate), 400)

    query_tokens = {token for token in query.split() if len(token) >= 4}
    candidate_tokens = {token for token in candidate.split() if len(token) >= 4}
    if not query_tokens or not candidate_tokens:
        return 0

    overlap = query_tokens & candidate_tokens
    if not overlap:
        return 0

    coverage = len(overlap) / max(len(query_tokens), 1)
    score = int(len(overlap) * 90 + coverage * 1000)
    if coverage >= 0.8:
        score += 1200
    elif coverage >= 0.6:
        score += 700
    elif coverage >= 0.4:
        score += 300
    return score


def _match_entry(entries: list[dict[str, Any]], reference: str) -> dict[str, Any] | None:
    safe_reference = str(reference or "").strip()
    if not safe_reference:
        return None

    for entry in entries:
        if entry.get("id") == safe_reference:
            return entry

    for entry in entries:
        if entry.get("title") == safe_reference:
            return entry

    query_norm = _normalize_match_text(safe_reference)
    if not query_norm:
        return None

    best_entry: dict[str, Any] | None = None
    best_score = 0
    for entry in entries:
        best_candidate_score = 0
        for text in entry.get("texts", []):
            candidate_score = _candidate_score(query_norm, _normalize_match_text(text))
            if candidate_score > best_candidate_score:
                best_candidate_score = candidate_score
        if best_candidate_score > best_score:
            best_score = best_candidate_score
            best_entry = entry

    return best_entry if best_score >= 900 else None


def _resolve_project_cache_dir(project: dict[str, Any]) -> str:
    last_scan = project.get("lastScan", {})
    if not isinstance(last_scan, dict):
        return ""
    result = last_scan.get("result", {})
    if not isinstance(result, dict):
        return ""
    target_memory = result.get("targetMemory", {})
    if not isinstance(target_memory, dict):
        return ""

    for key in ("json", "markdown"):
        raw_path = str(target_memory.get(key, "")).strip()
        if not raw_path:
            continue
        memory_dir = os.path.dirname(raw_path)
        project_cache_dir = os.path.dirname(memory_dir)
        if project_cache_dir:
            return project_cache_dir
    return ""


async def _sync_false_positive_to_system_memory(
    *,
    project: dict[str, Any],
    target_finding: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    project_cache_dir = _resolve_project_cache_dir(project)
    if not project_cache_dir:
        return {"updated": False, "appended": False, "available": False}

    try:
        memory = load_system_memory(project_cache_dir)
        verified_findings = (
            memory.get("verified_findings", [])
            if isinstance(memory.get("verified_findings"), list)
            else []
        )

        actual_id = str(target_finding.get("id", "")).strip()
        actual_title = str(target_finding.get("title", "")).strip()
        actual_description = str(target_finding.get("description", "")).strip()
        now_iso = datetime.now(timezone.utc).isoformat()

        matched = False
        for item in verified_findings:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id", "")).strip()
            item_title = str(item.get("title", "")).strip()
            if actual_id and item_id == actual_id:
                matched = True
            elif actual_title and item_title == actual_title:
                matched = True
            else:
                entry = {
                    "id": item_id,
                    "title": item_title,
                    "texts": _collect_finding_texts(item),
                }
                matched = _match_entry([entry], actual_description or actual_title) is not None

            if not matched:
                continue

            if actual_id:
                item["id"] = actual_id
            if actual_title:
                item["title"] = actual_title
            if actual_description:
                item["summary"] = actual_description
            item["status"] = "false_positive"
            item["verdict"] = "false_positive"
            item["severity"] = str(target_finding.get("severity", item.get("severity", "info"))).strip() or "info"
            item["target"] = str(target_finding.get("target", item.get("target", ""))).strip()
            item["endpoint"] = str(target_finding.get("target", item.get("endpoint", ""))).strip()
            item["false_positive_reason"] = reason
            item["updated_at"] = now_iso
            item.setdefault("timestamp", now_iso)
            break

        appended = False
        if not matched:
            verified_findings.append(
                {
                    "id": actual_id or uuid.uuid4().hex,
                    "title": actual_title or "False positive finding",
                    "summary": actual_description or actual_title,
                    "status": "false_positive",
                    "verdict": "false_positive",
                    "severity": str(target_finding.get("severity", "info")).strip() or "info",
                    "target": str(target_finding.get("target", "")).strip(),
                    "endpoint": str(target_finding.get("target", "")).strip(),
                    "false_positive_reason": reason,
                    "timestamp": now_iso,
                    "updated_at": now_iso,
                }
            )
            appended = True

        memory["verified_findings"] = verified_findings[-200:]
        await save_system_memory(project_cache_dir, memory)
        return {"updated": matched, "appended": appended, "available": True}
    except Exception as exc:
        logger.warning(
            "false_positive_system_memory_sync_failed",
            finding_id=str(target_finding.get("id", "")).strip(),
            error=str(exc),
        )
        return {"updated": False, "appended": False, "available": True, "error": str(exc)}


async def mark_false_positive(
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

    potential_findings = []
    for f in findings:
        if isinstance(f, dict):
            potential_findings.append(
                {
                    "id": str(f.get("id", "")).strip(),
                    "title": str(f.get("title", "")).strip(),
                    "ref": f,
                    "source": "findings",
                    "texts": _collect_finding_texts(f),
                }
            )

    rag_artifacts = project.get("ragArtifacts", [])
    if isinstance(rag_artifacts, list):
        for art in rag_artifacts:
            if isinstance(art, dict):
                potential_findings.append(
                    {
                        "id": str(art.get("recordId") or art.get("id", "")).strip(),
                        "title": str(art.get("title", "")).strip(),
                        "ref": art,
                        "source": "rag",
                        "texts": _collect_finding_texts(art),
                    }
                )

    target_finding_entry = _match_entry(potential_findings, safe_finding_id)
    if not target_finding_entry:
        return {
            "success": False,
            "error": (
                f"Finding '{safe_finding_id}' not found in the project findings or saved evidence. "
                "Try referencing the finding title or a more specific excerpt from the saved description."
            ),
        }

    if target_finding_entry["source"] == "rag":
        new_finding = {
            "id": target_finding_entry["id"],
            "title": target_finding_entry["title"],
            "status": "false_positive",
            "severity": "info",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        findings.append(new_finding)
        project["findings"] = findings
        target_finding = new_finding
    else:
        target_finding = target_finding_entry["ref"]

    actual_finding_id = str(target_finding.get("id", safe_finding_id)).strip()

    # Update finding status
    old_status = target_finding.get("status")
    target_finding["status"] = "false_positive"
    target_finding["false_positive_reason"] = safe_reason
    target_finding["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        doc_identity = _artifact_doc_identity(safe_project_id, "verified_vulnerability", actual_finding_id)
        vector_store = _get_vector_store()
        vector_store.delete_by_doc_identity("project_verified_vulnerability", doc_identity, "exploits")

        rag_artifacts = project.get("ragArtifacts", [])
        if isinstance(rag_artifacts, list):
            project["ragArtifacts"] = [
                art for art in rag_artifacts
                if isinstance(art, dict) and str(art.get("id")) != doc_identity
            ]
    except Exception as exc:
        logger.warning("false_positive_rag_cleanup_failed", finding_id=safe_finding_id, error=str(exc))

    memory_sync = await _sync_false_positive_to_system_memory(
        project=project,
        target_finding=target_finding,
        reason=safe_reason,
    )

    try:
        project_store.append_scan_event_cache(
            safe_project_id,
            {
                "scan_id": "assistant-action",
                "event": "finding_updated",
                "level": "info",
                "message": f"Finding '{target_finding.get('title')}' marked as false positive by assistant.",
                "data": {
                    "finding_id": actual_finding_id,
                    "status": "false_positive",
                    "reason": safe_reason,
                    "finding": {
                        "id": actual_finding_id,
                        "title": str(target_finding.get("title", "")).strip(),
                        "status": "false_positive",
                        "severity": str(target_finding.get("severity", "info")).strip() or "info",
                        "description": str(target_finding.get("description", "")).strip(),
                        "target": str(target_finding.get("target", "")).strip(),
                    },
                },
            }
        )
    except Exception:
        pass

    project["updatedAt"] = datetime.now(timezone.utc).isoformat()
    project_store.upsert_project(project)

    return {
        "success": True,
        "finding_id": safe_finding_id,
        "matched_finding_id": actual_finding_id,
        "matched_finding_title": str(target_finding.get("title", "")).strip(),
        "old_status": old_status,
        "new_status": "false_positive",
        "reason": safe_reason,
        "system_memory": memory_sync,
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
                "description": "The finding UUID, title, or descriptive excerpt to mark as false positive.",
            },
            "reason": {
                "type": "string",
                "description": "Brief explanation of why this finding is considered a false positive.",
            },
        },
        "required": ["finding_id", "reason"],
    },
}
