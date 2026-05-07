from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any

from server.app.orchestrator import ScanOrchestratorService
from server.app.scan.approval import ApprovalGateService
from server.app.scan.events import ScanEventService
from server.app.scan.lifecycle import ScanLifecycleService
from server.app.scan.persistence import ScanPersistenceService
from server.app.scan.runner import PhaseRunnerService
from server.db.projects.store import ProjectsStore


def test_operator_workflow_smoke(tmp_path) -> None:
    store = ProjectsStore(db_path=str(tmp_path / "smoke.db"))
    store.init_schema()
    store.upsert_project(
        {
            "id": "smoke-1",
            "name": "Smoke Project",
            "target": "https://example.com",
            "targetType": "web_app",
            "status": "idle",
            "scanProgress": 0,
            "updatedAt": "2026-05-06T10:00:00+00:00",
            "approval_mode": "custom",
            "phases": [],
            "agents": [],
            "findings": [],
            "lastScan": {},
        }
    )

    persistence = ScanPersistenceService(store)
    events = ScanEventService(persistence, store)
    approval = ApprovalGateService(persistence, events)
    runner = PhaseRunnerService(persistence, events, approval)
    lifecycle = ScanLifecycleService(persistence, events, runner, approval)
    orchestrator = ScanOrchestratorService(
        store,
        persistence_service=persistence,
        event_service=events,
        approval_service=approval,
        runner_service=runner,
        lifecycle_service=lifecycle,
    )

    async def _success_phase(*_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(success=True, error="")

    runner.run_intel_phase = _success_phase  # type: ignore[method-assign]
    runner.run_warmup_recon_phase = _success_phase  # type: ignore[method-assign]

    async def _run() -> None:
        started = await orchestrator.start_scan(
            "smoke-1",
            target="https://example.com",
            resume=False,
            force=True,
        )
        assert started["status"] == "running"

        deadline = time.time() + 2.0
        latest_status = {}
        while time.time() < deadline:
            latest_status = orchestrator.get_scan_status("smoke-1")
            if latest_status.get("status") == "completed":
                break
            await asyncio.sleep(0.05)

        assert latest_status.get("status") == "completed"

        events_cache = orchestrator.list_event_cache("smoke-1", limit=50)
        assert any(event["event"] == "scan_started" for event in events_cache)
        assert any(event["event"] == "scan_completed" for event in events_cache)

        observability = orchestrator.get_scan_observability("smoke-1", limit=50)
        assert observability["timeline"]
        assert "metrics" in observability

    asyncio.run(_run())
