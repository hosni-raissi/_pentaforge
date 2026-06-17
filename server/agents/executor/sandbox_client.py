"""Client helpers for delegating tool execution to a dedicated sandbox service."""

from __future__ import annotations

import os
from typing import Any

import httpx

from server.agents.executor.run_custom_guard import current_execution_context


def sandbox_executor_url() -> str:
    return str(os.getenv("SANDBOX_EXECUTOR_URL", "")).strip().rstrip("/")


def sandbox_remote_enabled() -> bool:
    if str(os.getenv("PENTAFORGE_SANDBOX_SERVICE", "")).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return bool(sandbox_executor_url())


def _execution_context_payload() -> dict[str, str]:
    context = current_execution_context()
    if not isinstance(context, dict):
        return {}
    return {
        "role": str(context.get("role", "")).strip().lower(),
        "target_url": str(context.get("target_url", "")).strip(),
        "project_id": str(context.get("project_id", "")).strip(),
        "scan_id": str(context.get("scan_id", "")).strip(),
        "project_cache_dir": str(context.get("project_cache_dir", "")).strip(),
    }


def _post_json(path: str, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    base_url = sandbox_executor_url()
    if not base_url:
        raise RuntimeError("SANDBOX_EXECUTOR_URL is not configured")
    with httpx.Client(timeout=max(timeout_seconds, 10.0)) as client:
        response = client.post(f"{base_url}{path}", json=payload)
        response.raise_for_status()
        data = response.json()
    return data if isinstance(data, dict) else {"success": False, "error": "Sandbox returned a non-object response"}


def execute_run_custom_remotely(
    *,
    command: str,
    args: list[str],
    timeout: int,
    env: dict[str, str] | None,
    cwd: str | None,
    password: str | None,
) -> dict[str, Any]:
    payload = {
        "command": command,
        "args": list(args),
        "timeout": int(timeout),
        "env": dict(env or {}),
        "cwd": cwd,
        "password": password,
        "execution_context": _execution_context_payload(),
    }
    return _post_json("/execute/run-custom", payload, timeout_seconds=float(timeout) + 30.0)


def execute_run_python_remotely(payload: dict[str, Any], *, timeout: int) -> dict[str, Any]:
    request_payload = dict(payload)
    request_payload["execution_context"] = _execution_context_payload()
    return _post_json("/execute/run-python", request_payload, timeout_seconds=float(timeout) + 60.0)
