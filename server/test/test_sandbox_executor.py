from __future__ import annotations

import pytest
from fastapi import HTTPException

from server.agents.executer.sandbox_client import sandbox_remote_enabled
from server.sandbox_service.app import (
    RunCustomRemoteRequest,
    SandboxExecutionContext,
    execute_run_custom,
    health,
)


def test_sandbox_remote_disabled_inside_service(monkeypatch):
    monkeypatch.setenv("SANDBOX_EXECUTOR_URL", "http://tool-sandbox:8010")
    monkeypatch.setenv("PENTAFORGE_SANDBOX_SERVICE", "1")
    assert sandbox_remote_enabled() is False


def test_sandbox_service_health():
    assert health() == {"status": "ok"}


def test_sandbox_service_blocks_out_of_scope_run_custom():
    with pytest.raises(HTTPException) as exc:
        execute_run_custom(
            RunCustomRemoteRequest(
                command="curl",
                args=["-I", "https://example.com"],
                timeout=30,
                env={},
                execution_context=SandboxExecutionContext(
                    role="recon",
                    target_url="https://pentest-ground.com:9000",
                ),
            )
        )
    assert exc.value.status_code == 403
    assert "scope" in str(exc.value.detail).lower()
