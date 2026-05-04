"""Helper functions for Intel node RAG refresh and deterministic checklist fallback."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from server.agents.planner.tools.get_checklists import (
    _default_priority_for_item,
    build_deterministic_checklist_payload,
    get_checklists,
)
from server.db.knowledge.config.sources import ContentType, SourceConfig, get_source_by_name
from server.db.knowledge.models.document import SourceType
from server.db.knowledge.orchestrator import KnowledgeOrchestrator
from server.db.knowledge.storage.intel_state_store import IntelStateStore
from server.db.projects import ProjectsStore

from .config import DEFAULT_VERIFY_SOURCES, RAG_REFRESH_DAYS, VERIFY_SOURCES

logger = structlog.get_logger(__name__)

_TARGET_TYPE_ALIASES: dict[str, str] = {
    "web": "web_app",
    "web3": "web_app",
    "infrastructure": "infra",
    "infra": "infra",
    "database": "infra",
    "db": "infra",
    "binary": "desktop",
    "identity": "linux_server",
    "supply_chain": "repository",
    "recon": "shared",
    "red_team": "shared",
    "cve_exploit": "shared",
}

_TARGET_TO_RAG_DOMAIN: dict[str, str] = {
    "infra": "linux_server",
    "container": "cloud",
}

_CONTENT_TYPE_MAP: dict[str, ContentType] = {
    "strategies": ContentType.STRATEGIES,
    "exploits": ContentType.EXPLOITS,
    "tools": ContentType.TOOLS,
    "standards": ContentType.STANDARDS,
    "attack_types": ContentType.ATTACK_TYPES,
}


@dataclass
class IntelResult:
    status: str = "complete"
    summary: str = ""
    stats: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[str] = field(default_factory=list)
    checklist: dict[str, Any] = field(default_factory=dict)


def _default_stats() -> dict[str, Any]:
    return {
        "new_payloads": 0,
        "new_exploits": 0,
        "total_embedded": 0,
        "payload_store_added": 0,
        "content_types_updated": [],
        "domains_updated": [],
        "update_status": "no_new_data",
        "rate_limited": False,
        "source_errors": [],
        "sources_selected": 0,
        "sources_verified": 0,
        "sources_updated": 0,
    }


def _notify(callback: Any, method: str, message: str) -> None:
    handler = getattr(callback, method, None)
    if callable(handler):
        handler(message)


def _normalize_target_type(value: str) -> str:
    clean = str(value or "").strip().lower().replace("-", "_")
    if not clean:
        return "all"
    return _TARGET_TYPE_ALIASES.get(clean, clean)


def _resolve_rag_domain(target_type: str) -> str:
    normalized = _normalize_target_type(target_type)
    if normalized in {"", "all"}:
        return "shared"
    return _TARGET_TO_RAG_DOMAIN.get(normalized, normalized)


def _source_type_from_url(url: str) -> SourceType:
    clean = str(url or "").strip().lower()
    if "github.com/" in clean:
        return SourceType.GITHUB_REPO
    return SourceType.WEBSITE


def _content_type_from_text(value: str) -> ContentType:
    return _CONTENT_TYPE_MAP.get(str(value or "").strip().lower(), ContentType.STRATEGIES)


def _resolve_check_url(
    url: str,
    builtin: SourceConfig | None,
    custom: dict[str, Any] | None,
) -> str:
    if url:
        return url
    if builtin is not None and str(builtin.url).strip():
        return str(builtin.url).strip()
    if custom and str(custom.get("url", "")).strip():
        return str(custom.get("url", "")).strip()
    return ""


async def _check_url_reachability(check_url: str) -> tuple[int, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    score = 0
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.head(check_url)
            reachable = resp.status_code < 500
            if reachable:
                score += 15
            checks.append(
                {
                    "check": "reachable",
                    "passed": reachable,
                    "detail": f"HTTP {resp.status_code}",
                }
            )
    except Exception as exc:
        checks.append(
            {
                "check": "reachable",
                "passed": False,
                "detail": str(exc)[:100],
            }
        )

    uses_tls = check_url.startswith("https://")
    if uses_tls:
        score += 15
    checks.append(
        {
            "check": "tls",
            "passed": uses_tls,
            "detail": "HTTPS" if uses_tls else "No HTTPS",
        }
    )
    return score, checks


async def verify_source(
    source_name: str,
    *,
    url: str = "",
    target_type: str = "all",
    projects_store: ProjectsStore | None = None,
) -> dict[str, Any]:
    trust_score = 0
    checks: list[dict[str, Any]] = []
    projects = projects_store or ProjectsStore()

    builtin = get_source_by_name(source_name)
    if builtin is not None:
        trust_score += 70
        checks.append(
            {
                "check": "pentaforge_config",
                "passed": True,
                "detail": f"Domain: {builtin.domain}",
            }
        )
    else:
        checks.append(
            {
                "check": "pentaforge_config",
                "passed": False,
                "detail": "Not in source config",
            }
        )

    custom = projects.get_intel_resource_by_name(
        source_name,
        target_type=target_type,
        enabled_only=True,
    )
    if custom is not None:
        trust_score += 30
        checks.append(
            {
                "check": "custom_registry",
                "passed": True,
                "detail": f"Target type: {custom.get('target_type', 'all')}",
            }
        )
    else:
        checks.append(
            {
                "check": "custom_registry",
                "passed": False,
                "detail": "Not in custom sources",
            }
        )

    check_url = _resolve_check_url(url, builtin, custom)
    if check_url:
        url_score, url_checks = await _check_url_reachability(check_url)
        trust_score += url_score
        checks.extend(url_checks)
    else:
        checks.append(
            {
                "check": "reachable",
                "passed": False,
                "detail": "No URL to check",
            }
        )

    result = {
        "source_name": source_name,
        "url": check_url,
        "trust_score": min(trust_score, 100),
        "verified": trust_score >= 50,
        "checks": checks,
    }
    logger.info("intel_verify_source_done", source=source_name, score=result["trust_score"])
    return result


def _collect_source_entries(
    target_type: str,
    *,
    projects_store: ProjectsStore,
) -> list[dict[str, Any]]:
    configured_names = VERIFY_SOURCES.get(target_type, DEFAULT_VERIFY_SOURCES)
    rows: list[dict[str, Any]] = []

    for source_name in configured_names:
        builtin = get_source_by_name(source_name)
        rows.append(
            {
                "name": source_name,
                "url": str(getattr(builtin, "url", "") or ""),
                "target_type": target_type,
                "content_type": str(getattr(builtin, "content_type", "strategies")),
                "update_mode": "every_3_days",
                "source_kind": "builtin",
                "updatable": True,
            }
        )

    for row in projects_store.list_intel_resources(enabled_only=True):
        row_target = _normalize_target_type(str(row.get("target_type", "all")))
        if row_target not in {"all", target_type}:
            continue
        if str(row.get("update_mode", "every_3_days")) != "every_3_days":
            continue
        rows.append(
            {
                "name": str(row.get("name", "")).strip(),
                "url": str(row.get("url", "")).strip(),
                "target_type": row_target,
                "content_type": str(row.get("content_type", "strategies") or "strategies"),
                "update_mode": str(row.get("update_mode", "every_3_days") or "every_3_days"),
                "source_kind": "custom",
                "updatable": True,
            }
        )

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        name = str(row.get("name", "")).strip()
        if not name:
            continue
        key = (name.lower(), str(row.get("url", "")).strip().lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _custom_source_to_config(entry: dict[str, Any]) -> SourceConfig:
    target_type = _normalize_target_type(str(entry.get("target_type", "all")))
    domain = _resolve_rag_domain(target_type)
    return SourceConfig(
        name=str(entry.get("name", "")).strip(),
        url=str(entry.get("url", "")).strip(),
        source_type=_source_type_from_url(str(entry.get("url", ""))),
        domain=domain,
        category="custom",
        content_type=_content_type_from_text(str(entry.get("content_type", "strategies"))),
        enabled=True,
        is_runtime=True,
        is_fixed=False,
        priority=2,
        tags=["custom", target_type],
        description="User-managed Intel resource",
    )


def _domains_for_payload_sync(target_type: str) -> list[str | None]:
    normalized = _normalize_target_type(target_type)
    if normalized == "all":
        return [None]
    domain = _resolve_rag_domain(normalized)
    if domain == "shared":
        return ["shared"]
    return [domain, "shared"]


async def _sync_payload_store(target_type: str) -> tuple[int, list[str]]:
    orchestrator = KnowledgeOrchestrator(payload_only=True)
    added_total = 0
    errors: list[str] = []
    try:
        for domain in _domains_for_payload_sync(target_type):
            try:
                rows = await orchestrator.ingest_payloads(domain=domain)
            except Exception as exc:
                errors.append(f"payload_store_sync({domain or 'all'}): {exc}")
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                added_total += int(row.get("payloads_added", 0) or 0)
                if row.get("error"):
                    errors.append(str(row["error"]))
    finally:
        await orchestrator.close()
    return added_total, errors


async def refresh_rag(
    *,
    target_type: str,
    info: str,
    force_update: bool = False,
    callback: Any = None,
    projects_store: ProjectsStore | None = None,
    state_store: IntelStateStore | None = None,
) -> IntelResult:
    normalized_target = _normalize_target_type(target_type)
    projects = projects_store or ProjectsStore()
    intel_state = state_store or IntelStateStore()
    stats = _default_stats()

    _notify(callback, "on_step", f"Intel Agent starting for target_type='{normalized_target}'")

    now = datetime.now(timezone.utc)
    refresh_days = RAG_REFRESH_DAYS
    custom_days = projects.get_intel_refresh_days(normalized_target)
    if custom_days and custom_days > 0:
        refresh_days = int(custom_days)

    last_update = intel_state.get_last_update(normalized_target)
    next_update = (
        last_update + timedelta(days=refresh_days)
        if last_update is not None
        else None
    )
    needs_update = (
        force_update
        or last_update is None
        or (next_update is not None and now >= next_update)
    )
    if not needs_update:
        days_ago = (now - last_update).total_seconds() / 86400 if last_update else 0.0
        message = (
            f"RAG is fresh (updated {days_ago:.1f} days ago, interval={refresh_days}d) "
            f"— next update at {next_update.isoformat() if next_update else 'unknown'} — skipping update"
        )
        _notify(callback, "on_done", message)
        stats["update_status"] = "fresh"
        stats["last_update"] = last_update.isoformat() if last_update else None
        stats["next_update"] = next_update.isoformat() if next_update else None
        return IntelResult(
            status="complete",
            summary=message,
            stats=stats,
        )

    if force_update:
        _notify(callback, "on_step", f"Force update requested — bypassing cooldown ({refresh_days} day window)")

    if last_update is None:
        _notify(callback, "on_step", "RAG update needed — no previous update found, updating knowledge base")
    else:
        _notify(
            callback,
            "on_step",
            "RAG update needed — "
            f"last update {last_update.isoformat()}, "
            f"cooldown ended at {next_update.isoformat() if next_update else 'unknown'}",
        )
    _notify(callback, "on_step", f"Update: Verifying sources for '{normalized_target}'")

    source_entries = _collect_source_entries(normalized_target, projects_store=projects)
    stats["sources_selected"] = len(source_entries)

    verified_entries: list[dict[str, Any]] = []
    for entry in source_entries:
        verified = await verify_source(
            str(entry.get("name", "")),
            url=str(entry.get("url", "")),
            target_type=normalized_target,
            projects_store=projects,
        )
        if verified.get("verified"):
            merged = dict(entry)
            merged.update(verified)
            verified_entries.append(merged)
        else:
            stats["source_errors"].append(
                f"{entry.get('name', '')}: verification failed"
            )
    stats["sources_verified"] = len(verified_entries)
    _notify(
        callback,
        "on_done",
        f"Update: {len(verified_entries)}/{len(source_entries)} sources verified",
    )

    if verified_entries:
        orchestrator = KnowledgeOrchestrator()
        try:
            for entry in verified_entries:
                source_name = str(entry.get("source_name", entry.get("name", ""))).strip()
                builtin = get_source_by_name(source_name)
                source_cfg: SourceConfig
                if builtin is not None:
                    result = await orchestrator.ingest_source(source_name)
                    source_cfg = builtin
                else:
                    source_cfg = _custom_source_to_config(entry)
                    result = await orchestrator._ingest(source_cfg)

                if result.errors:
                    stats["source_errors"].extend(
                        f"{source_name}: {error}" for error in result.errors
                    )
                    _notify(
                        callback,
                        "on_warn",
                        f"Source {source_name}: {len(result.errors)} error(s) while ingesting.",
                    )
                    continue

                stats["sources_updated"] += 1
                stats["total_embedded"] += int(result.chunks_embedded or 0)
                content_type = str(source_cfg.content_type.value)
                domain = str(source_cfg.domain)
                if content_type not in stats["content_types_updated"]:
                    stats["content_types_updated"].append(content_type)
                if domain not in stats["domains_updated"]:
                    stats["domains_updated"].append(domain)
                _notify(
                    callback,
                    "on_done",
                    f"Updated source {source_name}: docs={result.documents_extracted}, chunks={result.chunks_created}",
                )
        finally:
            await orchestrator.close()

    _notify(callback, "on_step", f"Update: Syncing payload store for '{normalized_target}'")
    payload_store_added, payload_errors = await _sync_payload_store(normalized_target)
    stats["payload_store_added"] = payload_store_added
    if payload_errors:
        stats["source_errors"].extend(payload_errors)
    _notify(callback, "on_done", f"Payload store synced (+{payload_store_added})")

    if stats["sources_updated"] > 0 or payload_store_added > 0:
        stats["update_status"] = "updated"
    elif verified_entries:
        stats["update_status"] = "verified_only"
    else:
        stats["update_status"] = "source_unavailable"

    summary = (
        f"RAG refresh complete for {normalized_target}: "
        f"verified={stats['sources_verified']}/{stats['sources_selected']}, "
        f"sources_updated={stats['sources_updated']}, "
        f"embedded={stats['total_embedded']}, "
        f"payload_store_added={payload_store_added}, "
        f"status={stats['update_status']}."
    )
    stats["last_update"] = last_update.isoformat() if last_update else None
    stats["next_update"] = (
        (datetime.now(timezone.utc) + timedelta(days=refresh_days)).isoformat()
    )
    intel_state.set_last_update(
        normalized_target,
        datetime.now(timezone.utc),
        update_status=str(stats["update_status"]),
    )
    _notify(callback, "on_done", f"Update: embedded={stats['total_embedded']}, payload_store_added={payload_store_added}, status={stats['update_status']}")
    _notify(callback, "on_done", f"Intel Agent complete — status=complete ({info[:80]})" if info else "Intel Agent complete — status=complete")

    return IntelResult(
        status="complete",
        summary=summary,
        stats=stats,
    )


def _priorityize_checklist_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized_blocks: list[dict[str, Any]] = []
    for block in payload.get("checklist", []):
        if not isinstance(block, dict):
            continue
        phase = str(block.get("phase", "")).strip()
        title = str(block.get("title", "")).strip()
        items = block.get("items", [])
        if not phase or not title or not isinstance(items, list):
            continue
        normalized_items: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in items:
            name = str(item if isinstance(item, str) else item.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized_items.append(
                {
                    "name": name,
                    "priority": _default_priority_for_item(name, phase),
                }
            )
        if normalized_items:
            normalized_blocks.append(
                {
                    "phase": phase,
                    "title": title,
                    "items": normalized_items,
                }
            )
    return {
        "target_type": str(payload.get("target_type", "")).strip(),
        "available_total": int(payload.get("available_total", 0) or 0),
        "checklist": normalized_blocks,
    }


def _parse_custom_checklist_text(raw_text: str, *, target_type: str) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    current_title = "Imported Custom Checklist"
    current_phase = "4"
    current_items: list[str] = []

    def flush() -> None:
        nonlocal current_items
        names: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw_name in current_items:
            name = str(raw_name or "").strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(
                {
                    "name": name,
                    "priority": _default_priority_for_item(name, current_phase),
                }
            )
        if names:
            blocks.append(
                {
                    "phase": current_phase,
                    "title": current_title,
                    "items": names,
                }
            )
        current_items = []

    for raw_line in str(raw_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("phase "):
            flush()
            _, _, remainder = line.partition(" ")
            phase_text, _, title = remainder.partition("-")
            current_phase = phase_text.strip().split()[0] or "4"
            current_title = title.strip() or "Imported Custom Checklist"
            continue
        if line.startswith(("#", "##", "###")):
            flush()
            current_title = line.lstrip("#").strip() or "Imported Custom Checklist"
            continue
        if line.startswith(("- ", "* ", "• ")):
            current_items.append(line[2:].strip())
            continue
        current_items.append(line)
    flush()

    return {
        "target_type": target_type,
        "available_total": sum(len(block.get("items", [])) for block in blocks),
        "checklist": blocks,
    }


def _merge_checklist_payloads(
    base_payload: dict[str, Any],
    custom_payload: dict[str, Any],
) -> dict[str, Any]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for payload in (base_payload, custom_payload):
        for block in payload.get("checklist", []):
            if not isinstance(block, dict):
                continue
            phase = str(block.get("phase", "")).strip()
            title = str(block.get("title", "")).strip()
            items = block.get("items", [])
            if not phase or not title or not isinstance(items, list):
                continue
            key = (phase, title)
            target = merged.setdefault(
                key,
                {"phase": phase, "title": title, "items": []},
            )
            existing: dict[str, int] = {
                str(item.get("name", "")).strip().lower(): int(item.get("priority", 3) or 3)
                for item in target["items"]
                if isinstance(item, dict)
            }
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).strip()
                if not name:
                    continue
                priority = int(item.get("priority", 3) or 3)
                key_name = name.lower()
                if key_name in existing:
                    if priority > existing[key_name]:
                        for existing_item in target["items"]:
                            if str(existing_item.get("name", "")).strip().lower() == key_name:
                                existing_item["priority"] = priority
                                existing[key_name] = priority
                                break
                    continue
                target["items"].append({"name": name, "priority": priority})
                existing[key_name] = priority

    ordered = [
        merged[key]
        for key in sorted(merged.keys(), key=lambda row: (int(row[0]) if row[0].isdigit() else 99, row[1].lower()))
    ]
    return {
        "target_type": str(base_payload.get("target_type") or custom_payload.get("target_type") or ""),
        "available_total": sum(len(block.get("items", [])) for block in ordered),
        "checklist": ordered,
    }


def _limit_checklist_items(payload: dict[str, Any], max_items: int | None) -> dict[str, Any]:
    if not max_items or max_items <= 0:
        return payload
    remaining = int(max_items)
    limited_blocks: list[dict[str, Any]] = []
    for block in payload.get("checklist", []):
        if remaining <= 0 or not isinstance(block, dict):
            break
        items = block.get("items", [])
        if not isinstance(items, list) or not items:
            continue
        selected = items[:remaining]
        remaining -= len(selected)
        limited_blocks.append(
            {
                "phase": block.get("phase", ""),
                "title": block.get("title", ""),
                "items": selected,
            }
        )
    return {
        "target_type": str(payload.get("target_type", "")).strip(),
        "available_total": sum(len(block.get("items", [])) for block in limited_blocks),
        "checklist": limited_blocks,
    }


async def synthesize_checklist(
    *,
    target_type: str,
    info: str,
    custom_checklist_text: str = "",
    merge_custom_checklist: bool = False,
    max_checklist_items: int | None = None,
    callback: Any = None,
) -> IntelResult:
    normalized_target = _normalize_target_type(target_type)
    _notify(
        callback,
        "on_step",
        "Intel checklist synthesis now runs in deterministic mode without LLM.",
    )

    raw = await get_checklists(target_type=normalized_target, info=info)
    try:
        checklist_data = json.loads(raw)
    except json.JSONDecodeError:
        checklist_data = {}

    base_payload = _priorityize_checklist_payload(
        build_deterministic_checklist_payload(checklist_data, info)
        if isinstance(checklist_data, dict)
        else {"target_type": normalized_target, "available_total": 0, "checklist": []}
    )

    final_payload = base_payload
    custom_text = str(custom_checklist_text or "").strip()
    if custom_text:
        custom_payload = _parse_custom_checklist_text(
            custom_text,
            target_type=normalized_target,
        )
        final_payload = (
            _merge_checklist_payloads(base_payload, custom_payload)
            if merge_custom_checklist
            else custom_payload
        )

    final_payload = _limit_checklist_items(final_payload, max_checklist_items)
    summary = (
        f"Deterministic checklist ready for {normalized_target}: "
        f"{final_payload.get('available_total', 0)} items."
    )
    _notify(callback, "on_done", summary)
    return IntelResult(
        status="complete",
        summary=summary,
        stats=_default_stats(),
        checklist=final_payload,
    )
