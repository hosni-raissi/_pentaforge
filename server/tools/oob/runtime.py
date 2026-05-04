"""Runtime helpers for per-engagement OOB client access."""

from __future__ import annotations

import os
import uuid
from typing import Any

import structlog

from .interactsh_client import InteractshClient

logger = structlog.get_logger(__name__)

_PROCESS_ENGAGEMENT_KEY = uuid.uuid4().hex
_CLIENT_CACHE: dict[str, InteractshClient] = {}
_MISSING_CONFIG_WARNED = False
_CONTEXT_IMPORT_WARNED = False


def _tool_context() -> dict[str, Any]:
    global _CONTEXT_IMPORT_WARNED
    try:
        from server.agents.executer.base import _executer_tool_context
    except Exception:
        if not _CONTEXT_IMPORT_WARNED:
            logger.warning("oob_tool_context_unavailable", fallback="process_uuid")
            _CONTEXT_IMPORT_WARNED = True
        return {}

    try:
        context = _executer_tool_context.get({})
    except LookupError:
        return {}
    return context if isinstance(context, dict) else {}


def build_engagement_key() -> str:
    context = _tool_context()
    project_id = str(context.get("project_id", "")).strip()
    if project_id:
        return project_id
    project_cache_dir = str(context.get("project_cache_dir", "")).strip()
    if project_cache_dir:
        return uuid.uuid5(uuid.NAMESPACE_URL, project_cache_dir).hex
    return _PROCESS_ENGAGEMENT_KEY


def get_default_wait_seconds() -> int:
    raw_value = str(os.getenv("OOB_WAIT_SECONDS", "15")).strip()
    try:
        return max(0, int(raw_value))
    except ValueError:
        return 15


def get_oob_client() -> InteractshClient | None:
    global _MISSING_CONFIG_WARNED

    server_url = str(os.getenv("INTERACTSH_SERVER_URL", "")).strip()
    token = str(os.getenv("INTERACTSH_TOKEN", "")).strip()
    if not server_url or not token:
        if not _MISSING_CONFIG_WARNED:
            logger.warning(
                "oob_disabled_missing_config",
                has_server_url=bool(server_url),
                has_token=bool(token),
            )
            _MISSING_CONFIG_WARNED = True
        return None

    engagement_key = build_engagement_key()
    client = _CLIENT_CACHE.get(engagement_key)
    if client is not None:
        return client

    client = InteractshClient(
        server_url=server_url,
        token=token,
        engagement_id=engagement_key,
    )
    _CLIENT_CACHE[engagement_key] = client
    return client
