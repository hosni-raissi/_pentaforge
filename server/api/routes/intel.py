"""Intel/RAG resource and update-status routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

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
    get_all_domains,
    get_enabled_sources,
    get_source_by_name,
)

router = APIRouter(tags=["intel"])

_INTEL_UPDATABLE_SET = {name.lower() for name in INTEL_UPDATABLE_SOURCES}

_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web_app": "web",
    "linux_server": "infrastructure",
    "desktop": "binary",
    "repository": "supply_chain",
    "container": "cloud",
    "database": "infrastructure",
}


class IntelResourceCreatePayload(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    url: str = Field(min_length=8, max_length=2048)
    target_type: str = Field(default="all", min_length=2, max_length=64)
    enabled: bool = True


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


def _serialize_builtin_source(source: Any, *, target_type: str | None = None) -> dict[str, Any]:
    source_name = str(source.name)
    return {
        "id": f"builtin::{source_name}",
        "name": source_name,
        "url": str(source.url),
        "target_type": str(source.domain or target_type or "shared"),
        "enabled": bool(source.enabled),
        "source_kind": "builtin",
        "updatable": source_name.lower() in _INTEL_UPDATABLE_SET,
        "description": str(source.description or ""),
        "category": str(source.category or ""),
        "content_type": str(source.content_type),
        "created_at": None,
        "updated_at": None,
    }


def _serialize_custom_source(row: dict[str, Any]) -> dict[str, Any]:
    source_name = str(row.get("name", "")).strip()
    return {
        "id": str(row.get("id", "")),
        "name": source_name,
        "url": str(row.get("url", "")),
        "target_type": str(row.get("target_type", "all")),
        "enabled": bool(row.get("enabled", False)),
        "source_kind": "custom",
        "updatable": True,
        "description": "User-added source",
        "category": "custom",
        "content_type": "strategies",
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def _list_combined_intel_resources(target_type: str | None = None) -> list[dict[str, Any]]:
    normalized = _normalize_target_type(target_type) if target_type else ""
    domain_filter = "" if normalized in {"", "all"} else normalized

    builtin_resources: list[dict[str, Any]] = []
    for source in get_enabled_sources():
        if domain_filter and source.domain != domain_filter:
            continue
        builtin_resources.append(_serialize_builtin_source(source))

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
    return combined


def _build_update_sources(
    target_type: str,
    custom_by_target: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    configured_names = VERIFY_SOURCES.get(target_type, DEFAULT_VERIFY_SOURCES)

    rows: list[dict[str, Any]] = []
    for source_name in configured_names:
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
                    "created_at": None,
                    "updated_at": None,
                }
            )

    if target_type == "all":
        for custom_rows in custom_by_target.values():
            for custom in custom_rows:
                rows.append(_serialize_custom_source(custom))
    else:
        for custom in custom_by_target.get(target_type, []):
            rows.append(_serialize_custom_source(custom))
        for custom in custom_by_target.get("all", []):
            rows.append(_serialize_custom_source(custom))

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (
            str(row.get("source_kind", "")),
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
    target_type = _normalize_target_type(payload.target_type)
    try:
        saved = projects_store.add_intel_resource(
            name=payload.name,
            url=payload.url,
            target_type=target_type,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save intel resource: {exc}") from exc

    return {
        "ok": True,
        "resource": _serialize_custom_source(saved),
    }


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
        last_update = intel_state_store.get_last_update(entry_target)
        next_update = (
            last_update + timedelta(days=RAG_REFRESH_DAYS)
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
                "seconds_until_next_update": seconds_until,
                "uses_default_sources": entry_target not in VERIFY_SOURCES,
                "sources": sources,
                "will_update": {
                    "verify_sources": [source.get("name", "") for source in sources],
                    "fetch_streams": [
                        f"payloads(last_{UPDATE_DAYS_BACK}_days)",
                        f"exploits(last_{UPDATE_DAYS_BACK}_days)",
                    ],
                    "embed_content_types": ["attack_types", "exploits"],
                },
            }
        )

    return {
        "checked_at": now.isoformat(),
        "refresh_days": RAG_REFRESH_DAYS,
        "update_days_back": UPDATE_DAYS_BACK,
        "update_max_results": UPDATE_MAX_RESULTS,
        "pipeline_outputs": ["attack_types", "exploits"],
        "statuses": statuses,
    }

