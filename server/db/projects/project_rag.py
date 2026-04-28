"""Project-scoped vector persistence for assistant-searchable knowledge."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from server.db.knowledge.models.chunk import KnowledgeChunk
from server.db.knowledge.storage.embedding import EmbeddingGenerator
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore

logger = structlog.get_logger(__name__)

_ARTIFACT_KIND_TO_CONTENT_TYPE = {
    "verified_vulnerability": "exploits",
    "system_memory_markdown": "strategies",
}

_EMBEDDER: EmbeddingGenerator | None = None
_VECTOR_STORE: QdrantVectorStore | None = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_text(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _sanitize_excerpt(text: str, *, limit: int = 240) -> str:
    clean = " ".join(str(text or "").split())
    if len(clean) <= limit:
        return clean
    return clean[: max(0, limit - 3)].rstrip() + "..."


def _artifact_source_name(kind: str) -> str:
    return f"project_{kind}"


def _artifact_doc_identity(project_id: str, kind: str, record_id: str) -> str:
    return f"project:{project_id}:{kind}:{record_id}"


def _content_hash(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8", errors="ignore")).hexdigest()


def _get_embedder() -> EmbeddingGenerator:
    global _EMBEDDER
    if _EMBEDDER is None:
        _EMBEDDER = EmbeddingGenerator()
    return _EMBEDDER


def _get_vector_store() -> QdrantVectorStore:
    global _VECTOR_STORE
    if _VECTOR_STORE is None:
        _VECTOR_STORE = QdrantVectorStore()
    return _VECTOR_STORE


def _upsert_project_rag_artifact_metadata(
    *,
    project_store: Any | None,
    project_id: str,
    artifact_entry: dict[str, Any],
    max_entries: int = 200,
) -> None:
    if project_store is None:
        return

    try:
        project = project_store.get_project(project_id)
    except Exception:
        logger.warning("project_rag_metadata_lookup_failed", project_id=project_id, exc_info=True)
        return
    if not isinstance(project, dict):
        return

    raw_entries = project.get("ragArtifacts", [])
    entries: list[dict[str, Any]] = raw_entries if isinstance(raw_entries, list) else []
    artifact_id = _coerce_text(artifact_entry.get("id"))
    if not artifact_id:
        return

    replaced = False
    for idx, existing in enumerate(entries):
        if not isinstance(existing, dict):
            continue
        if _coerce_text(existing.get("id")) == artifact_id:
            merged = dict(existing)
            merged.update(artifact_entry)
            entries[idx] = merged
            replaced = True
            break

    if not replaced:
        entries.append(dict(artifact_entry))

    if len(entries) > max_entries:
        entries = entries[-max_entries:]

    project["ragArtifacts"] = entries
    project["updatedAt"] = _utc_now_iso()
    try:
        project_store.upsert_project(project)
    except Exception:
        logger.warning("project_rag_metadata_upsert_failed", project_id=project_id, artifact_id=artifact_id, exc_info=True)


def _build_verified_finding_document(
    *,
    target: str,
    target_type: str,
    finding: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    finding_id = _coerce_text(finding.get("id"), str(uuid.uuid4()))
    title = _coerce_text(finding.get("title"), "Verified vulnerability")
    severity = _coerce_text(finding.get("severity"), "unknown")
    category = _coerce_text(finding.get("category"), "security_issue")
    description = _coerce_text(finding.get("description"))
    remediation = _coerce_text(finding.get("remediation"))
    cve = _coerce_text(finding.get("cve"))
    status = _coerce_text(finding.get("status"), "verified")
    timestamp = _coerce_text(finding.get("timestamp"), _utc_now_iso())
    evidence = finding.get("evidence", {})
    evidence_text = ""
    if isinstance(evidence, dict):
        commands = evidence.get("commands", [])
        tools_used = evidence.get("tools_used", [])
        verification_summary = _coerce_text(evidence.get("verification_summary"))
        lines: list[str] = []
        if verification_summary:
            lines.extend(["Verification Summary:", verification_summary, ""])
        if isinstance(commands, list) and commands:
            lines.append("Commands:")
            lines.extend(f"- {str(command).strip()}" for command in commands[:8] if str(command).strip())
            lines.append("")
        if isinstance(tools_used, list) and tools_used:
            lines.append("Tools Used:")
            lines.append("- " + ", ".join(str(tool).strip() for tool in tools_used[:8] if str(tool).strip()))
            lines.append("")
        evidence_text = "\n".join(lines).strip()

    parts = [
        f"Verified Vulnerability: {title}",
        f"Target: {target}",
        f"Target Type: {target_type}",
        f"Severity: {severity}",
        f"Category: {category}",
        f"Status: {status}",
    ]
    if cve:
        parts.append(f"CVE: {cve}")
    parts.extend(
        [
            f"Timestamp: {timestamp}",
            "",
            "Description:",
            description or "No description captured.",
        ]
    )
    if evidence_text:
        parts.extend(["", evidence_text])
    if remediation:
        parts.extend(["", "Remediation:", remediation])

    return "\n".join(parts).strip(), {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "target": target,
        "target_type": target_type,
        "cve": cve,
        "status": status,
        "timestamp": timestamp,
    }


def _build_system_memory_document(
    *,
    target: str,
    target_type: str,
    markdown_content: str,
) -> tuple[str, dict[str, Any]]:
    title = "System Memory"
    body = _coerce_text(markdown_content)
    if not body:
        body = "# System Memory\n\nNo content available."
    content = "\n".join(
        [
            f"Project System Memory for {target or 'target'}",
            f"Target Type: {target_type}",
            "",
            body,
        ]
    ).strip()
    return content, {
        "id": "system-memory-markdown",
        "title": title,
        "target": target,
        "target_type": target_type,
        "timestamp": _utc_now_iso(),
    }


async def _upsert_project_artifact(
    *,
    project_id: str,
    kind: str,
    record_id: str,
    title: str,
    content: str,
    target: str,
    target_type: str,
    metadata: dict[str, Any],
    project_store: Any | None = None,
) -> dict[str, Any]:
    safe_project_id = _coerce_text(project_id)
    safe_kind = _coerce_text(kind)
    safe_record_id = _coerce_text(record_id)
    safe_title = _coerce_text(title, "Project knowledge artifact")
    safe_content = _coerce_text(content)
    if not safe_project_id or not safe_kind or not safe_record_id or not safe_content:
        return {"success": False, "error": "Missing project knowledge artifact fields."}

    content_type = _ARTIFACT_KIND_TO_CONTENT_TYPE.get(safe_kind, "strategies")
    source_name = _artifact_source_name(safe_kind)
    doc_identity = _artifact_doc_identity(safe_project_id, safe_kind, safe_record_id)
    content_hash = _content_hash(safe_content)

    if project_store is not None:
        try:
            project = project_store.get_project(safe_project_id)
        except Exception:
            project = None
        if isinstance(project, dict):
            raw_entries = project.get("ragArtifacts", [])
            if isinstance(raw_entries, list):
                for existing in raw_entries:
                    if not isinstance(existing, dict):
                        continue
                    if _coerce_text(existing.get("id")) != doc_identity:
                        continue
                    if _coerce_text(existing.get("contentHash")) == content_hash:
                        return {
                            "success": True,
                            "skipped": True,
                            "reason": "unchanged_content",
                            "artifact": existing,
                        }
                    break

    chunk = KnowledgeChunk(
        document_id=uuid.uuid4(),
        content=safe_content,
        chunk_index=0,
        heading=safe_title,
        source_name=source_name,
        source_url="",
        file_path=doc_identity,
        domain=_coerce_text(target_type, "project"),
        category=safe_kind,
        target=_coerce_text(target_type, "project"),
        severity=_coerce_text(metadata.get("severity")),
        tags=[safe_kind, "project", safe_project_id],
        extra={
            "project_id": safe_project_id,
            "artifact_kind": safe_kind,
            "record_id": safe_record_id,
            "title": safe_title,
            "target": _coerce_text(target),
            "target_type": _coerce_text(target_type),
            "updated_at": _utc_now_iso(),
            "content_hash": content_hash,
        },
    )

    embedder = _get_embedder()
    vector_store = _get_vector_store()
    embedding = await embedder.embed_single(safe_content)
    vector_store.delete_by_doc_identity(source_name, doc_identity, content_type)
    vector_store.upsert_chunks([chunk], [embedding], content_type=content_type)

    artifact_entry = {
        "id": doc_identity,
        "recordId": safe_record_id,
        "kind": safe_kind,
        "contentType": content_type,
        "title": safe_title,
        "target": _coerce_text(target),
        "targetType": _coerce_text(target_type),
        "timestamp": _utc_now_iso(),
        "excerpt": _sanitize_excerpt(safe_content),
        "contentHash": content_hash,
    }
    _upsert_project_rag_artifact_metadata(
        project_store=project_store,
        project_id=safe_project_id,
        artifact_entry=artifact_entry,
    )

    return {
        "success": True,
        "artifact": artifact_entry,
    }


async def index_verified_finding(
    *,
    project_id: str,
    target: str,
    target_type: str,
    finding: dict[str, Any],
    project_store: Any | None = None,
) -> dict[str, Any]:
    content, metadata = _build_verified_finding_document(
        target=target,
        target_type=target_type,
        finding=finding if isinstance(finding, dict) else {},
    )
    return await _upsert_project_artifact(
        project_id=project_id,
        kind="verified_vulnerability",
        record_id=_coerce_text(metadata.get("id"), str(uuid.uuid4())),
        title=_coerce_text(metadata.get("title"), "Verified vulnerability"),
        content=content,
        target=target,
        target_type=target_type,
        metadata=metadata,
        project_store=project_store,
    )


async def index_system_memory_markdown(
    *,
    project_id: str,
    target: str,
    target_type: str,
    markdown_content: str,
    project_store: Any | None = None,
) -> dict[str, Any]:
    content, metadata = _build_system_memory_document(
        target=target,
        target_type=target_type,
        markdown_content=markdown_content,
    )
    return await _upsert_project_artifact(
        project_id=project_id,
        kind="system_memory_markdown",
        record_id="memory-md",
        title=_coerce_text(metadata.get("title"), "System Memory"),
        content=content,
        target=target,
        target_type=target_type,
        metadata=metadata,
        project_store=project_store,
    )


async def search_project_vectors(
    *,
    project_id: str,
    query: str,
    limit: int = 5,
    kinds: list[str] | None = None,
) -> dict[str, Any]:
    safe_project_id = _coerce_text(project_id)
    safe_query = _coerce_text(query)
    safe_limit = max(1, min(int(limit or 5), 8))
    normalized_kinds = [
        _coerce_text(kind).lower()
        for kind in (kinds or [])
        if _coerce_text(kind)
    ]
    if not safe_project_id:
        return {"success": False, "error": "project_id is required", "matches": []}
    if not safe_query:
        return {"success": False, "error": "query is required", "matches": []}

    content_types = sorted(
        {
            _ARTIFACT_KIND_TO_CONTENT_TYPE.get(kind, "")
            for kind in normalized_kinds
            if _ARTIFACT_KIND_TO_CONTENT_TYPE.get(kind, "")
        }
    )
    if not content_types:
        content_types = sorted(set(_ARTIFACT_KIND_TO_CONTENT_TYPE.values()))

    embedder = _get_embedder()
    vector_store = _get_vector_store()
    query_embedding = await embedder.embed_single(safe_query, is_query=True)

    hits = vector_store.search_multi(
        query_embedding=query_embedding,
        content_types=content_types,
        n_results=safe_limit,
        where={"project_id": safe_project_id},
    )

    matches: list[dict[str, Any]] = []
    for hit in hits:
        metadata = hit.get("metadata", {}) if isinstance(hit.get("metadata"), dict) else {}
        kind = _coerce_text(metadata.get("artifact_kind")).lower()
        if normalized_kinds and kind not in normalized_kinds:
            continue
        content = _coerce_text(hit.get("content"))
        matches.append(
            {
                "id": _coerce_text(hit.get("id")),
                "score": float(hit.get("score", 0.0) or 0.0),
                "kind": kind or "project_artifact",
                "title": _coerce_text(metadata.get("title"), "Project knowledge artifact"),
                "excerpt": _sanitize_excerpt(content, limit=420),
                "content": content[:4000],
                "metadata": metadata,
            }
        )

    return {
        "success": True,
        "project_id": safe_project_id,
        "query": safe_query,
        "matches": matches[:safe_limit],
        "count": min(len(matches), safe_limit),
    }
