from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from server.core.tool import tool
from server.db.knowledge.config.sources import get_source_by_name
from server.db.projects import ProjectsStore

from .constants import TRUSTED_SOURCES

logger = structlog.get_logger(__name__)
_projects_store = ProjectsStore()
_projects_store.init_schema()


async def _check_url_reachability(check_url: str) -> tuple[int, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    score = 0
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.head(check_url)
            reachable = resp.status_code < 500
            if reachable:
                score += 15
            checks.append({"check": "reachable", "passed": reachable, "detail": f"HTTP {resp.status_code}"})
    except Exception as exc:
        checks.append({"check": "reachable", "passed": False, "detail": str(exc)[:100]})

    uses_tls = check_url.startswith("https://")
    if uses_tls:
        score += 15
    checks.append({"check": "tls", "passed": uses_tls, "detail": "HTTPS" if uses_tls else "No HTTPS"})

    return score, checks


def _resolve_check_url(
    url: str,
    trusted: dict | None,
    config: Any,
    custom: dict[str, Any] | None,
) -> str:
    if url:
        return url
    if trusted:
        return trusted["url"]
    if config:
        return config.url
    if custom and custom.get("url"):
        return str(custom["url"])
    return ""


@tool(
    name="verify_source",
    description=(
        "Validate the integrity and trust score of a source. "
        "Checks URL reachability, matches against trusted source registry, "
        "and computes a trust score (0-100). Use before embedding external data."
    ),
)
async def verify_source(source_name: str, url: str = "") -> str:
    trust_score = 0
    checks: list[dict[str, Any]] = []

    trusted = TRUSTED_SOURCES.get(source_name)
    if trusted:
        trust_score += 40
        checks.append({"check": "trusted_registry", "passed": True, "detail": f"Type: {trusted['type']}"})
    else:
        checks.append({"check": "trusted_registry", "passed": False, "detail": "Not in trusted registry"})

    config = get_source_by_name(source_name)
    if config:
        trust_score += 30
        checks.append({"check": "pentaforge_config", "passed": True, "detail": f"Domain: {config.domain}"})
    else:
        checks.append({"check": "pentaforge_config", "passed": False, "detail": "Not in source config"})

    custom = _projects_store.get_intel_resource_by_name(source_name, enabled_only=True)
    if custom:
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

    check_url = _resolve_check_url(url, trusted, config, custom)
    if check_url:
        url_score, url_checks = await _check_url_reachability(check_url)
        trust_score += url_score
        checks.extend(url_checks)
    else:
        checks.append({"check": "reachable", "passed": False, "detail": "No URL to check"})

    result = {
        "source_name": source_name,
        "trust_score": min(trust_score, 100),
        "verified": trust_score >= 50,
        "checks": checks,
    }
    logger.info("verify_source_done", source=source_name, score=trust_score)
    return json.dumps(result)
