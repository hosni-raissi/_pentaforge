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


def _entry_matches_any_reference(
    entry: dict[str, Any],
    references: list[str],
) -> bool:
    valid_references = [str(item or "").strip() for item in references if str(item or "").strip()]
    if not isinstance(entry, dict) or not valid_references:
        return False

    entry_id = str(entry.get("id", "")).strip()
    entry_title = str(entry.get("title", "")).strip()
    texts = _collect_finding_texts(entry)

    for reference in valid_references:
        if entry_id and reference == entry_id:
            return True
        if entry_title and reference == entry_title:
            return True
        matcher = _match_entry(
            [
                {
                    "id": entry_id,
                    "title": entry_title,
                    "texts": texts,
                }
            ],
            reference,
        )
        if matcher is not None:
            return True
    return False


def _entry_matches_canonical_finding(
    entry: dict[str, Any],
    *,
    finding_id: str,
    finding_title: str,
) -> bool:
    if not isinstance(entry, dict):
        return False
    safe_id = str(finding_id or "").strip()
    safe_title = str(finding_title or "").strip()

    entry_id = str(entry.get("id", "")).strip()
    if safe_id and entry_id == safe_id:
        return True

    if safe_id:
        return False

    entry_title = str(entry.get("title", "")).strip()
    return bool(safe_title and entry_title == safe_title)


def _mark_entry_false_positive(
    entry: dict[str, Any],
    *,
    reason: str,
    now_iso: str,
    fallback_id: str,
    fallback_title: str,
    fallback_description: str,
    fallback_target: str,
    fallback_severity: str,
) -> None:
    if not isinstance(entry, dict):
        return
    if fallback_id and not str(entry.get("id", "")).strip():
        entry["id"] = fallback_id
    if fallback_title and not str(entry.get("title", "")).strip():
        entry["title"] = fallback_title
    if fallback_description and not str(entry.get("summary", "")).strip():
        entry["summary"] = fallback_description
    if fallback_target and not str(entry.get("target", "")).strip():
        entry["target"] = fallback_target
    entry["status"] = "false_positive"
    entry["verdict"] = "false_positive"
    entry["false_positive_reason"] = reason
    entry["updated_at"] = now_iso
    if fallback_severity and not str(entry.get("severity", "")).strip():
        entry["severity"] = fallback_severity


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
            matched = _entry_matches_canonical_finding(
                item,
                finding_id=actual_id,
                finding_title=actual_title,
            )

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

    target_finding = target_finding_entry["ref"]
    actual_finding_id = str(target_finding.get("id", safe_finding_id)).strip()
    actual_title = str(target_finding.get("title", "")).strip()
    actual_description = str(target_finding.get("description", "")).strip()
    actual_target = str(target_finding.get("target", "")).strip()
    actual_severity = str(target_finding.get("severity", "info")).strip() or "info"
    now_iso = datetime.now(timezone.utc).isoformat()
    match_references = [
        safe_finding_id,
        actual_finding_id,
        actual_title,
        actual_description,
        str(target_finding_entry.get("title", "")).strip(),
    ]

    old_status = target_finding.get("status")
    matched_project_findings = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if not _entry_matches_canonical_finding(
            finding,
            finding_id=actual_finding_id,
            finding_title=actual_title,
        ):
            continue
        matched_project_findings += 1
        _mark_entry_false_positive(
            finding,
            reason=safe_reason,
            now_iso=now_iso,
            fallback_id=actual_finding_id,
            fallback_title=actual_title,
            fallback_description=actual_description,
            fallback_target=actual_target,
            fallback_severity=actual_severity,
        )

    if matched_project_findings == 0:
        new_finding = {
            "id": actual_finding_id or str(target_finding_entry.get("id", "")).strip() or uuid.uuid4().hex,
            "title": actual_title or str(target_finding_entry.get("title", "")).strip() or "False positive finding",
            "description": actual_description,
            "target": actual_target,
            "status": "false_positive",
            "severity": actual_severity,
            "false_positive_reason": safe_reason,
            "timestamp": now_iso,
            "updated_at": now_iso,
        }
        findings.append(new_finding)
        target_finding = new_finding
    else:
        project["findings"] = findings
        for finding in findings:
            if isinstance(finding, dict) and _entry_matches_canonical_finding(
                finding,
                finding_id=actual_finding_id,
                finding_title=actual_title,
            ):
                target_finding = finding
                break

    last_scan = project.get("lastScan")
    if isinstance(last_scan, dict):
        result = last_scan.get("result")
        if isinstance(result, dict):
            target_memory = result.get("targetMemory")
            if isinstance(target_memory, dict):
                verified_findings = target_memory.get("verified_findings")
                if isinstance(verified_findings, list):
                    for item in verified_findings:
                        if not isinstance(item, dict):
                            continue
                        if not _entry_matches_canonical_finding(
                            item,
                            finding_id=actual_finding_id,
                            finding_title=actual_title,
                        ):
                            continue
                        _mark_entry_false_positive(
                            item,
                            reason=safe_reason,
                            now_iso=now_iso,
                            fallback_id=actual_finding_id,
                            fallback_title=actual_title,
                            fallback_description=actual_description,
                            fallback_target=actual_target,
                            fallback_severity=actual_severity,
                        )

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
    if not (memory_sync.get("updated") or memory_sync.get("appended")):
        project_cache_dir = _resolve_project_cache_dir(project)
        if project_cache_dir:
            try:
                memory = load_system_memory(project_cache_dir)
                verified_findings = (
                    memory.get("verified_findings", [])
                    if isinstance(memory.get("verified_findings"), list)
                    else []
                )
                now_iso = datetime.now(timezone.utc).isoformat()
                verified_findings.append(
                    {
                        "id": actual_finding_id or uuid.uuid4().hex,
                        "title": str(target_finding.get("title", "")).strip() or "False positive finding",
                        "summary": str(target_finding.get("description", "")).strip()
                        or str(target_finding.get("title", "")).strip(),
                        "status": "false_positive",
                        "verdict": "false_positive",
                        "severity": str(target_finding.get("severity", "info")).strip() or "info",
                        "target": str(target_finding.get("target", "")).strip(),
                        "endpoint": str(target_finding.get("target", "")).strip(),
                        "false_positive_reason": safe_reason,
                        "timestamp": now_iso,
                        "updated_at": now_iso,
                    }
                )
                memory["verified_findings"] = verified_findings[-200:]
                await save_system_memory(project_cache_dir, memory)
                memory_sync = {
                    **memory_sync,
                    "available": True,
                    "updated": bool(memory_sync.get("updated")),
                    "appended": True,
                    "fallback": True,
                }
            except Exception as exc:
                logger.warning(
                    "false_positive_system_memory_fallback_failed",
                    finding_id=actual_finding_id,
                    error=str(exc),
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
                    "reason_code": "manual_false_positive_marked",
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
