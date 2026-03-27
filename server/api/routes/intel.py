"""Intel/RAG resource and update-status routes."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import structlog

from server.agents.intel.config import (
    DEFAULT_VERIFY_SOURCES,
    RAG_REFRESH_DAYS,
    UPDATE_DAYS_BACK,
    UPDATE_MAX_RESULTS,
    VERIFY_SOURCES,
)
from server.api.dependencies import intel_state_store, projects_store
from server.db.knowledge.config.sources import (
    INTEL_UPDATABLE_SOURCES,
    PAYLOAD_SOURCES,
    get_all_domains,
    get_enabled_sources,
    get_source_by_name,
)

router = APIRouter(tags=["intel"])
logger = structlog.get_logger(__name__)

_INTEL_UPDATABLE_SET = {name.lower() for name in INTEL_UPDATABLE_SOURCES}
_FORCE_UPDATE_LOCK = threading.Lock()
_FORCE_UPDATE_RUNNING: dict[str, dict[str, Any]] = {}


class _ForceUpdateCancelled(Exception):
    """Raised when a user cancels an in-progress force update."""

_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web_app": "web",
    "linux_server": "infrastructure",
    "desktop": "binary",
    "repository": "supply_chain",
    "container": "cloud",
    "database": "infrastructure",
}

_CONTENT_TYPE_ALIASES: dict[str, str] = {
    "payloads": "payload",
}

_ALLOWED_CONTENT_TYPES = {
    "strategies",
    "exploits",
    "tools",
    "standards",
    "attack_types",
    "payload",
}

_UPDATE_MODE_ALIASES: dict[str, str] = {
    "every3days": "every_3_days",
    "refresh_3_days": "every_3_days",
    "dynamic": "every_3_days",
}

_ALLOWED_UPDATE_MODES = {
    "every_3_days",
    "static",
}


class IntelResourceCreatePayload(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    url: str = Field(min_length=8, max_length=2048)
    target_type: str = Field(default="all", min_length=2, max_length=64)
    content_type: str = Field(default="strategies", min_length=4, max_length=32)
    update_mode: str = Field(default="every_3_days", min_length=6, max_length=32)
    enabled: bool = True


class IntelUpdateSchedulePayload(BaseModel):
    target_type: str = Field(default="all", min_length=2, max_length=64)
    refresh_days: int = Field(default=3, ge=1, le=3650)


class IntelForceUpdatePayload(BaseModel):
    target_type: str = Field(default="all", min_length=2, max_length=64)
    info: str = Field(default="", max_length=500)


class IntelForceUpdateCancelPayload(BaseModel):
    target_type: str = Field(default="all", min_length=2, max_length=64)


class IntelResourceUpdatePayload(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    url: str | None = Field(default=None, min_length=8, max_length=2048)
    target_type: str | None = Field(default=None, min_length=2, max_length=64)
    content_type: str | None = Field(default=None, min_length=4, max_length=32)
    update_mode: str | None = Field(default=None, min_length=6, max_length=32)
    enabled: bool | None = None


def _label_target_type(value: str) -> str:
    if value == "all":
        return "All Targets"
    return value.replace("_", " ").title()


def _normalize_target_type(value: str | None) -> str:
    clean = (value or "").strip().lower().replace("-", "_")
    if not clean:
        return "all"
    return _TARGET_TYPE_ALIASES.get(clean, clean)


def _target_type_options() -> list[dict[str, str]]:
    values = set(get_all_domains())
    values.update(VERIFY_SOURCES.keys())
    values.update(_TARGET_TYPE_ALIASES.values())
    values.discard("")
    ordered = sorted(values)
    return [{"value": "all", "label": _label_target_type("all")}] + [
        {"value": value, "label": _label_target_type(value)}
        for value in ordered
    ]


def _refresh_days_for_target(target_type: str) -> int:
    configured = projects_store.get_intel_refresh_days(target_type)
    if configured is None:
        return RAG_REFRESH_DAYS
    return configured


def _resource_update_target(target_type: str | None) -> str:
    normalized = _normalize_target_type(target_type)
    if normalized in {"", "shared"}:
        return "all"
    return normalized


def _attach_resource_update_metadata(resource: dict[str, Any]) -> dict[str, Any]:
    update_target = _resource_update_target(str(resource.get("target_type", "all")))
    refresh_days = _refresh_days_for_target(update_target)
    last_update = intel_state_store.get_last_update(update_target)
    next_update = (
        last_update + timedelta(days=refresh_days)
        if last_update is not None
        else None
    )
    resource["intel_last_update"] = last_update.isoformat() if last_update else None
    resource["intel_next_update"] = next_update.isoformat() if next_update else None
    resource["intel_refresh_days"] = refresh_days
    return resource


def _purge_resource_data(*, source_name: str, content_type: str) -> dict[str, Any]:
    from server.db.knowledge.storage.payload_store import PayloadStore
    from server.db.knowledge.storage.qdrant_store import QdrantVectorStore

    safe_source = str(source_name or "").strip()
    safe_content_type = str(content_type or "").strip().lower()
    if not safe_source:
        return {"vectors_purged": False, "payload_rows_deleted": 0}

    vector_store = QdrantVectorStore()
    vector_store.delete_by_source(
        safe_source,
        content_type=(safe_content_type if safe_content_type and safe_content_type != "payload" else None),
    )

    payload_rows_deleted = 0
    payload_store = PayloadStore()
    try:
        payload_rows_deleted = payload_store.delete_by_source(safe_source)
    finally:
        payload_store.close()

    return {
        "vectors_purged": True,
        "payload_rows_deleted": payload_rows_deleted,
    }


def _update_progress_from_message(message: str) -> int:
    lowered = str(message or "").lower()
    if "starting for target_type" in lowered:
        return 5
    if "force update requested" in lowered:
        return 10
    if "rag update needed" in lowered:
        return 18
    if "update: verifying sources" in lowered:
        return 28
    if "update: syncing payload store" in lowered:
        return 36
    if "payload store synced" in lowered:
        return 44
    if "update: fetching payloads" in lowered:
        return 52
    if "update: found" in lowered:
        return 62
    if "update: embedded" in lowered:
        return 72
    if "collecting rag snapshot" in lowered:
        return 82
    if "prefetching formatter context" in lowered:
        return 88
    if "llm round" in lowered:
        return 92
    if "intel agent complete" in lowered:
        return 100
    return 40


def _normalize_content_type(value: str | None) -> str:
    clean = (value or "").strip().lower().replace("-", "_")
    if not clean:
        return "strategies"
    clean = _CONTENT_TYPE_ALIASES.get(clean, clean)
    if clean not in _ALLOWED_CONTENT_TYPES:
        raise ValueError(
            "content_type must be one of: "
            + ", ".join(sorted(_ALLOWED_CONTENT_TYPES))
        )
    return clean


def _normalize_update_mode(value: str | None) -> str:
    clean = (value or "").strip().lower().replace("-", "_")
    if not clean:
        return "every_3_days"
    clean = _UPDATE_MODE_ALIASES.get(clean, clean)
    if clean not in _ALLOWED_UPDATE_MODES:
        raise ValueError(
            "update_mode must be one of: "
            + ", ".join(sorted(_ALLOWED_UPDATE_MODES))
        )
    return clean


def _serialize_builtin_source(source: Any, *, target_type: str | None = None) -> dict[str, Any]:
    source_name = str(source.name)
    updatable = source_name.lower() in _INTEL_UPDATABLE_SET
    source_kind = "custom" if _is_user_manageable_builtin_source(source) else "builtin"
    return {
        "id": f"builtin::{source_name}",
        "name": source_name,
        "url": str(source.url),
        "target_type": str(source.domain or target_type or "shared"),
        "enabled": bool(source.enabled),
        "source_kind": source_kind,
        "updatable": updatable,
        "description": str(source.description or ""),
        "category": str(source.category or ""),
        "content_type": str(source.content_type),
        "update_mode": "every_3_days" if updatable else "static",
        "created_at": None,
        "updated_at": None,
    }


def _serialize_custom_source(row: dict[str, Any]) -> dict[str, Any]:
    source_name = str(row.get("name", "")).strip()
    update_mode = str(row.get("update_mode", "every_3_days") or "every_3_days")
    content_type = str(row.get("content_type", "strategies") or "strategies")
    return {
        "id": str(row.get("id", "")),
        "name": source_name,
        "url": str(row.get("url", "")),
        "target_type": str(row.get("target_type", "all")),
        "enabled": bool(row.get("enabled", False)),
        "source_kind": "custom",
        "updatable": update_mode == "every_3_days",
        "description": "User-added source",
        "category": "custom",
        "content_type": content_type,
        "update_mode": update_mode,
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def _serialize_builtin_payload_source(source: Any) -> dict[str, Any]:
    source_name = str(getattr(source, "name", "") or "").strip()
    return {
        "id": f"builtin::{source_name}",
        "name": source_name,
        "url": str(getattr(source, "url", "") or ""),
        "target_type": str(getattr(source, "domain", "") or "shared"),
        "enabled": True,
        # Payload resources are intentionally user-manageable in settings.
        "source_kind": "custom",
        "updatable": True,
        "description": str(getattr(source, "description", "") or ""),
        "category": str(getattr(source, "category", "") or ""),
        "content_type": "payload",
        "update_mode": "every_3_days",
        "created_at": None,
        "updated_at": None,
    }


def _get_payload_source_by_name(name: str) -> Any | None:
    clean_name = name.strip().lower()
    if not clean_name:
        return None
    for source in PAYLOAD_SOURCES:
        source_name = str(getattr(source, "name", "") or "").strip().lower()
        if source_name == clean_name:
            return source
    return None


def _resolve_builtin_resource(source_name: str) -> tuple[str, Any] | None:
    source_cfg = get_source_by_name(source_name)
    if source_cfg is not None:
        return ("vector", source_cfg)
    payload_cfg = _get_payload_source_by_name(source_name)
    if payload_cfg is not None:
        return ("payload", payload_cfg)
    return None


def _is_user_manageable_builtin_source(source: Any) -> bool:
    source_name = str(getattr(source, "name", "") or "").strip().lower()
    category = str(getattr(source, "category", "") or "").strip().lower()
    content_type = str(getattr(source, "content_type", "") or "").strip().lower()
    is_payload = (
        "payload" in source_name
        or "payload" in category
        or content_type == "payload"
    )
    is_intel_mutable = source_name in _INTEL_UPDATABLE_SET
    return (
        is_payload
        or is_intel_mutable
    )


def _extract_builtin_name(resource_id: str) -> str:
    clean_id = resource_id.strip()
    if not clean_id.startswith("builtin::"):
        return ""
    return clean_id.split("builtin::", 1)[1].strip()


def _list_combined_intel_resources(target_type: str | None = None) -> list[dict[str, Any]]:
    normalized = _normalize_target_type(target_type) if target_type else ""
    domain_filter = "" if normalized in {"", "all"} else normalized
    hidden_builtin_names = projects_store.list_hidden_builtin_intel_resources()

    builtin_resources: list[dict[str, Any]] = []
    for source in get_enabled_sources():
        if domain_filter and source.domain != domain_filter:
            continue
        if str(source.name).strip().lower() in hidden_builtin_names:
            continue
        builtin_resources.append(_serialize_builtin_source(source))
    for payload_source in PAYLOAD_SOURCES:
        source_domain = str(getattr(payload_source, "domain", "") or "shared")
        source_name = str(getattr(payload_source, "name", "") or "").strip()
        if domain_filter and source_domain != domain_filter:
            continue
        if source_name.lower() in hidden_builtin_names:
            continue
        builtin_resources.append(_serialize_builtin_payload_source(payload_source))

    custom_filter = None if not domain_filter else domain_filter
    custom_rows = projects_store.list_intel_resources(target_type=custom_filter, enabled_only=False)
    custom_resources = [_serialize_custom_source(row) for row in custom_rows]

    combined = builtin_resources + custom_resources
    combined.sort(
        key=lambda item: (
            str(item.get("target_type", "")),
            str(item.get("source_kind", "")),
            str(item.get("name", "")).lower(),
        )
    )
    return [_attach_resource_update_metadata(item) for item in combined]


def _build_update_sources(
    target_type: str,
    custom_by_target: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    configured_names = VERIFY_SOURCES.get(target_type, DEFAULT_VERIFY_SOURCES)
    hidden_builtin_names = projects_store.list_hidden_builtin_intel_resources()

    rows: list[dict[str, Any]] = []
    for source_name in configured_names:
        if source_name.strip().lower() in hidden_builtin_names:
            continue
        source_cfg = get_source_by_name(source_name)
        if source_cfg is not None:
            rows.append(_serialize_builtin_source(source_cfg, target_type=target_type))
        else:
            rows.append(
                {
                    "id": f"builtin::{source_name}",
                    "name": source_name,
                    "url": "",
                    "target_type": target_type,
                    "enabled": True,
                    "source_kind": "builtin",
                    "updatable": source_name.lower() in _INTEL_UPDATABLE_SET,
                    "description": "Configured Intel source",
                    "category": "configured",
                    "content_type": "mixed",
                    "update_mode": "every_3_days",
                    "created_at": None,
                    "updated_at": None,
                }
            )

    if target_type == "all":
        for custom_rows in custom_by_target.values():
            for custom in custom_rows:
                if str(custom.get("update_mode", "every_3_days")) != "every_3_days":
                    continue
                rows.append(_serialize_custom_source(custom))
    else:
        for custom in custom_by_target.get(target_type, []):
            if str(custom.get("update_mode", "every_3_days")) != "every_3_days":
                continue
            rows.append(_serialize_custom_source(custom))
        for custom in custom_by_target.get("all", []):
            if str(custom.get("update_mode", "every_3_days")) != "every_3_days":
                continue
            rows.append(_serialize_custom_source(custom))

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (
            str(row.get("name", "")).strip().lower(),
            str(row.get("url", "")).strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


@router.get("/api/intel/resources")
def list_intel_resources(target_type: str | None = None) -> dict[str, Any]:
    try:
        resources = _list_combined_intel_resources(target_type=target_type)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list intel resources: {exc}") from exc
    return {
        "resources": resources,
        "target_type_options": _target_type_options(),
    }


@router.post("/api/intel/resources")
def add_intel_resource(payload: IntelResourceCreatePayload) -> dict[str, Any]:
    try:
        target_type = _normalize_target_type(payload.target_type)
        content_type = _normalize_content_type(payload.content_type)
        update_mode = _normalize_update_mode(payload.update_mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        saved = projects_store.add_intel_resource(
            name=payload.name,
            url=payload.url,
            target_type=target_type,
            content_type=content_type,
            update_mode=update_mode,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save intel resource: {exc}") from exc

    return {
        "ok": True,
        "resource": _attach_resource_update_metadata(_serialize_custom_source(saved)),
    }


@router.patch("/api/intel/resources/{resource_id}")
def update_intel_resource(resource_id: str, payload: IntelResourceUpdatePayload) -> dict[str, Any]:
    clean_id = resource_id.strip()
    if clean_id.startswith("builtin::"):
        source_name = _extract_builtin_name(clean_id)
        resolved = _resolve_builtin_resource(source_name)
        if resolved is None:
            raise HTTPException(status_code=404, detail="builtin resource not found")
        source_kind, source_cfg = resolved
        if source_kind == "payload":
            try:
                target_type = _normalize_target_type(payload.target_type) if payload.target_type is not None else _normalize_target_type(str(getattr(source_cfg, "domain", "all")))
                content_type = _normalize_content_type(payload.content_type) if payload.content_type is not None else "payload"
                update_mode = _normalize_update_mode(payload.update_mode) if payload.update_mode is not None else "every_3_days"
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            try:
                saved = projects_store.add_intel_resource(
                    name=payload.name or str(getattr(source_cfg, "name", "") or source_name),
                    url=payload.url or str(getattr(source_cfg, "url", "")),
                    target_type=target_type,
                    content_type=content_type,
                    update_mode=update_mode,
                    enabled=payload.enabled if payload.enabled is not None else True,
                )
                projects_store.hide_builtin_intel_resource(str(getattr(source_cfg, "name", "") or source_name))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Failed to update builtin payload resource: {exc}") from exc
            try:
                _purge_resource_data(
                    source_name=str(getattr(source_cfg, "name", "") or source_name),
                    content_type="payload",
                )
            except Exception as exc:
                logger.warning("intel_builtin_payload_edit_purge_failed", source_name=str(getattr(source_cfg, "name", "") or source_name), error=str(exc))
            return {
                "ok": True,
                "resource": _attach_resource_update_metadata(_serialize_custom_source(saved)),
            }
        if not _is_user_manageable_builtin_source(source_cfg):
            raise HTTPException(status_code=400, detail="builtin resources cannot be changed")
        try:
            target_type = _normalize_target_type(payload.target_type) if payload.target_type is not None else _normalize_target_type(str(source_cfg.domain or "all"))
            content_type = _normalize_content_type(payload.content_type) if payload.content_type is not None else _normalize_content_type(str(source_cfg.content_type))
            update_mode = _normalize_update_mode(payload.update_mode) if payload.update_mode is not None else ("every_3_days" if str(source_name).lower() in _INTEL_UPDATABLE_SET else "static")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            saved = projects_store.add_intel_resource(
                name=payload.name or str(source_cfg.name),
                url=payload.url or str(source_cfg.url),
                target_type=target_type,
                content_type=content_type,
                update_mode=update_mode,
                enabled=payload.enabled if payload.enabled is not None else bool(source_cfg.enabled),
            )
            projects_store.hide_builtin_intel_resource(str(source_cfg.name))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to update builtin payload resource: {exc}") from exc
        try:
            _purge_resource_data(
                source_name=str(source_cfg.name),
                content_type=str(source_cfg.content_type),
            )
        except Exception as exc:
            logger.warning("intel_builtin_payload_edit_purge_failed", source_name=str(source_cfg.name), error=str(exc))
        return {
            "ok": True,
            "resource": _attach_resource_update_metadata(_serialize_custom_source(saved)),
        }

    try:
        target_type = _normalize_target_type(payload.target_type) if payload.target_type is not None else None
        content_type = _normalize_content_type(payload.content_type) if payload.content_type is not None else None
        update_mode = _normalize_update_mode(payload.update_mode) if payload.update_mode is not None else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        saved = projects_store.update_intel_resource(
            clean_id,
            name=payload.name,
            url=payload.url,
            target_type=target_type,
            content_type=content_type,
            update_mode=update_mode,
            enabled=payload.enabled,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update intel resource: {exc}") from exc

    return {
        "ok": True,
        "resource": _attach_resource_update_metadata(_serialize_custom_source(saved)),
    }


@router.delete("/api/intel/resources/{resource_id}")
def delete_intel_resource(resource_id: str) -> dict[str, Any]:
    clean_id = resource_id.strip()
    if clean_id.startswith("builtin::"):
        source_name = _extract_builtin_name(clean_id)
        resolved = _resolve_builtin_resource(source_name)
        if resolved is None:
            raise HTTPException(status_code=404, detail="builtin resource not found")
        source_kind, source_cfg = resolved
        if source_kind == "payload":
            try:
                projects_store.hide_builtin_intel_resource(str(getattr(source_cfg, "name", "") or source_name))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Failed to hide builtin payload resource: {exc}") from exc
            purge_result: dict[str, Any] = {}
            try:
                purge_result = _purge_resource_data(
                    source_name=str(getattr(source_cfg, "name", "") or source_name),
                    content_type="payload",
                )
            except Exception as exc:
                logger.warning("intel_builtin_payload_purge_failed", resource_id=clean_id, error=str(exc))
                purge_result = {
                    "vectors_purged": False,
                    "payload_rows_deleted": 0,
                    "purge_error": str(exc),
                }
            return {
                "ok": True,
                "deleted": True,
                "hidden_builtin": True,
                **purge_result,
            }
        if not _is_user_manageable_builtin_source(source_cfg):
            raise HTTPException(status_code=400, detail="builtin resources cannot be removed")
        try:
            projects_store.hide_builtin_intel_resource(str(source_cfg.name))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to hide builtin payload resource: {exc}") from exc
        purge_result: dict[str, Any] = {}
        try:
            purge_result = _purge_resource_data(
                source_name=str(source_cfg.name),
                content_type=str(source_cfg.content_type),
            )
        except Exception as exc:
            logger.warning("intel_builtin_payload_purge_failed", resource_id=clean_id, error=str(exc))
            purge_result = {
                "vectors_purged": False,
                "payload_rows_deleted": 0,
                "purge_error": str(exc),
            }
        return {
            "ok": True,
            "deleted": True,
            "hidden_builtin": True,
            **purge_result,
        }
    row = projects_store.get_intel_resource(clean_id)
    if row is None:
        raise HTTPException(status_code=404, detail="resource not found")
    try:
        deleted = projects_store.delete_intel_resource(clean_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete intel resource: {exc}") from exc
    if not deleted:
        raise HTTPException(status_code=404, detail="resource not found")
    purge_result: dict[str, Any] = {}
    try:
        purge_result = _purge_resource_data(
            source_name=str(row.get("name", "")),
            content_type=str(row.get("content_type", "")),
        )
    except Exception as exc:
        logger.warning("intel_resource_purge_failed", resource_id=clean_id, error=str(exc))
        purge_result = {
            "vectors_purged": False,
            "payload_rows_deleted": 0,
            "purge_error": str(exc),
        }
    return {"ok": True, "deleted": True, **purge_result}


@router.get("/api/intel/update-status")
def intel_update_status(target_type: str | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    normalized_target = _normalize_target_type(target_type) if target_type else ""

    try:
        custom_enabled = projects_store.list_intel_resources(enabled_only=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read intel resources: {exc}") from exc

    custom_by_target: dict[str, list[dict[str, Any]]] = {}
    for row in custom_enabled:
        row_target = str(row.get("target_type", "all")).strip().lower() or "all"
        custom_by_target.setdefault(row_target, []).append(row)

    if normalized_target:
        if normalized_target == "all":
            target_types = ["all"]
        else:
            target_types = [normalized_target]
    else:
        target_set = set(VERIFY_SOURCES.keys())
        target_set.update(
            target_name
            for target_name in custom_by_target
            if target_name and target_name != "all"
        )
        target_types = ["all"] + sorted(target_set)

    statuses: list[dict[str, Any]] = []
    for entry_target in target_types:
        refresh_days = _refresh_days_for_target(entry_target)
        last_update = intel_state_store.get_last_update(entry_target)
        next_update = (
            last_update + timedelta(days=refresh_days)
            if last_update is not None
            else None
        )
        due_now = next_update is None or now >= next_update
        seconds_until = 0
        if next_update is not None and not due_now:
            seconds_until = max(0, int((next_update - now).total_seconds()))

        sources = _build_update_sources(entry_target, custom_by_target)
        statuses.append(
            {
                "target_type": entry_target,
                "last_update": last_update.isoformat() if last_update else None,
                "next_update": next_update.isoformat() if next_update else None,
                "due_now": due_now,
                "refresh_days": refresh_days,
                "seconds_until_next_update": seconds_until,
                "uses_default_sources": entry_target not in VERIFY_SOURCES,
                "sources": sources,
                "will_update": {
                    "verify_sources": [source.get("name", "") for source in sources],
                    "fetch_streams": [
                        (
                            "payload_store(all_domains)"
                            if entry_target == "all"
                            else f"payload_store({entry_target}+shared)"
                        ),
                        f"payloads(last_{UPDATE_DAYS_BACK}_days)",
                        f"exploits(last_{UPDATE_DAYS_BACK}_days)",
                    ],
                    "embed_content_types": ["attack_types", "exploits"],
                },
            }
        )

    return {
        "checked_at": now.isoformat(),
        "refresh_days": _refresh_days_for_target(
            normalized_target if normalized_target else "all"
        ),
        "update_days_back": UPDATE_DAYS_BACK,
        "update_max_results": UPDATE_MAX_RESULTS,
        "pipeline_outputs": ["attack_types", "exploits"],
        "statuses": statuses,
    }


@router.post("/api/intel/update-schedule")
def set_intel_update_schedule(payload: IntelUpdateSchedulePayload) -> dict[str, Any]:
    target_type = _normalize_target_type(payload.target_type)
    try:
        saved = projects_store.set_intel_refresh_days(
            target_type=target_type,
            refresh_days=int(payload.refresh_days),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save intel update schedule: {exc}") from exc
    return {
        "ok": True,
        "schedule": saved,
    }


async def _run_force_update(target_type: str, info: str) -> None:
    from server.agents.intel.agent import IntelAgent

    def _cancel_requested() -> bool:
        with _FORCE_UPDATE_LOCK:
            current = _FORCE_UPDATE_RUNNING.get(target_type, {})
            status = str(current.get("status", "")).lower()
            return bool(current.get("cancel_requested")) or status == "cancelling"

    class _ProgressCallback:
        def __init__(self, target: str) -> None:
            self._target = target

        def _update(self, status: str, message: str) -> None:
            if _cancel_requested():
                raise _ForceUpdateCancelled("Force update cancelled by user.")
            progress = _update_progress_from_message(message)
            now_iso = datetime.now(timezone.utc).isoformat()
            with _FORCE_UPDATE_LOCK:
                current = _FORCE_UPDATE_RUNNING.get(self._target, {})
                existing_progress = int(current.get("progress", 0) or 0)
                _FORCE_UPDATE_RUNNING[self._target] = {
                    **current,
                    "target_type": self._target,
                    "status": status,
                    "progress": max(existing_progress, progress),
                    "message": message,
                    "updated_at": now_iso,
                }

        def on_step(self, message: str) -> None:
            self._update("running", message)

        def on_done(self, message: str) -> None:
            self._update("running", message)

        def on_warn(self, message: str) -> None:
            self._update("running", message)

    agent = IntelAgent(callback=_ProgressCallback(target_type))
    await agent.run(
        target_type=target_type,
        info=info,
        force_update=True,
        update_only=True,
    )


def _force_update_worker(target_type: str, info: str) -> None:
    try:
        asyncio.run(_run_force_update(target_type, info))
        now_iso = datetime.now(timezone.utc).isoformat()
        with _FORCE_UPDATE_LOCK:
            current = _FORCE_UPDATE_RUNNING.get(target_type, {})
            _FORCE_UPDATE_RUNNING[target_type] = {
                **current,
                "target_type": target_type,
                "status": "completed",
                "progress": 100,
                "message": str(current.get("message", "Force update completed.")) or "Force update completed.",
                "updated_at": now_iso,
                "finished_at": now_iso,
            }
        logger.info("intel_force_update_complete", target_type=target_type)
    except _ForceUpdateCancelled as exc:
        now_iso = datetime.now(timezone.utc).isoformat()
        with _FORCE_UPDATE_LOCK:
            current = _FORCE_UPDATE_RUNNING.get(target_type, {})
            _FORCE_UPDATE_RUNNING[target_type] = {
                **current,
                "target_type": target_type,
                "status": "cancelled",
                "message": str(exc),
                "updated_at": now_iso,
                "finished_at": now_iso,
                "cancel_requested": False,
            }
        logger.info("intel_force_update_cancelled", target_type=target_type)
    except Exception as exc:
        now_iso = datetime.now(timezone.utc).isoformat()
        with _FORCE_UPDATE_LOCK:
            current = _FORCE_UPDATE_RUNNING.get(target_type, {})
            _FORCE_UPDATE_RUNNING[target_type] = {
                **current,
                "target_type": target_type,
                "status": "error",
                "progress": int(current.get("progress", 0) or 0),
                "message": str(exc),
                "error": str(exc),
                "updated_at": now_iso,
                "finished_at": now_iso,
            }
        logger.warning("intel_force_update_failed", target_type=target_type, error=str(exc))


@router.post("/api/intel/force-update")
def force_intel_update(payload: IntelForceUpdatePayload) -> dict[str, Any]:
    target_type = _normalize_target_type(payload.target_type)
    with _FORCE_UPDATE_LOCK:
        current = _FORCE_UPDATE_RUNNING.get(target_type)
        current_status = str(current.get("status", "")).lower() if isinstance(current, dict) else ""
        if current_status in {"running", "cancelling"}:
            return {
                "ok": True,
                "started": False,
                "target_type": target_type,
                "reason": "already_running",
            }
        now_iso = datetime.now(timezone.utc).isoformat()
        _FORCE_UPDATE_RUNNING[target_type] = {
            "target_type": target_type,
            "status": "running",
            "progress": 1,
            "message": "Force update queued.",
            "updated_at": now_iso,
            "started_at": now_iso,
            "finished_at": None,
            "error": "",
            "cancel_requested": False,
        }

    thread = threading.Thread(
        target=_force_update_worker,
        kwargs={"target_type": target_type, "info": payload.info.strip()},
        daemon=True,
        name=f"intel_force_update_{target_type}",
    )
    thread.start()

    logger.info("intel_force_update_started", target_type=target_type)
    return {
        "ok": True,
        "started": True,
        "target_type": target_type,
    }


@router.post("/api/intel/force-update/cancel")
def cancel_force_intel_update(payload: IntelForceUpdateCancelPayload) -> dict[str, Any]:
    target_type = _normalize_target_type(payload.target_type)
    with _FORCE_UPDATE_LOCK:
        current = _FORCE_UPDATE_RUNNING.get(target_type)
        if not isinstance(current, dict):
            return {
                "ok": True,
                "cancelled": False,
                "target_type": target_type,
                "reason": "not_running",
            }
        current_status = str(current.get("status", "")).lower()
        if current_status != "running":
            return {
                "ok": True,
                "cancelled": False,
                "target_type": target_type,
                "reason": f"status_{current_status or 'idle'}",
            }
        now_iso = datetime.now(timezone.utc).isoformat()
        _FORCE_UPDATE_RUNNING[target_type] = {
            **current,
            "target_type": target_type,
            "status": "cancelling",
            "cancel_requested": True,
            "message": "Cancellation requested by user.",
            "updated_at": now_iso,
        }
    return {
        "ok": True,
        "cancelled": True,
        "target_type": target_type,
    }


@router.get("/api/intel/force-update-status")
def force_intel_update_status(target_type: str | None = None) -> dict[str, Any]:
    if target_type:
        normalized = _normalize_target_type(target_type)
        with _FORCE_UPDATE_LOCK:
            row = dict(_FORCE_UPDATE_RUNNING.get(normalized, {}))
        if not row:
            row = {
                "target_type": normalized,
                "status": "idle",
                "progress": 0,
                "message": "",
                "updated_at": None,
                "started_at": None,
                "finished_at": None,
                "error": "",
            }
        return row
    with _FORCE_UPDATE_LOCK:
        rows = [dict(item) for item in _FORCE_UPDATE_RUNNING.values()]
    rows.sort(key=lambda item: str(item.get("target_type", "")))
    return {"statuses": rows}
