from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from server.app._full_orchestrator_impl import ScanOrchestratorService
from server.db.projects.store import ProjectsStore


def _make_store(tmp_path) -> ProjectsStore:
    store = ProjectsStore(db_path=str(tmp_path / "projects.db"))
    store.init_schema()
    store.upsert_project(
        {
            "id": "proj-1",
            "name": "Resume Project",
            "target": "https://example.com",
            "targetType": "web_app",
            "status": "idle",
            "scanProgress": 0,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "approval_mode": "custom",
            "phases": [],
            "agents": [],
            "findings": [],
            "ragArtifacts": [],
            "lastScan": {},
            "copilotHistory": [],
            "copilotContext": "",
        }
    )
    return store


def test_resume_start_preserves_saved_plan_checkpoint(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    assert project is not None
    saved_plan = {
        "target": "https://example.com",
        "phases": [
            {
                "name": "Validation",
                "steps": [
                    {
                        "id": "step-1",
                        "scenarios": [
                            {
                                "agent": "recon",
                                "task": "Map application routes",
                                "priority": 2,
                                "done": True,
                                "status": "completed",
                            },
                            {
                                "agent": "exploit",
                                "task": "Validate reflected XSS",
                                "priority": 3,
                                "done": False,
                                "status": "working",
                                "active_slot": 1,
                            },
                        ],
                    }
                ],
            }
        ],
    }
    project["status"] = "paused"
    project["lastScan"] = {
        "scanId": "old-scan",
        "status": "executing",
        "startedAt": "2026-01-01T00:00:00+00:00",
        "finishedAt": "2026-01-01T00:02:00+00:00",
        "result": {
            "target": "https://example.com",
            "targetType": "web_app",
            "intel": {
                "status": "complete",
                "summary": "Saved plan ready.",
                "stats": {},
                "checklist": {},
            },
            "planner": {"plan_data": saved_plan},
            "targetMemory": {},
        },
    }
    store.upsert_project(project)

    async def _noop_run_scan(self, **kwargs) -> None:
        return None

    monkeypatch.setattr(ScanOrchestratorService, "_run_scan", _noop_run_scan)
    orchestrator = ScanOrchestratorService(store)

    async def _run() -> None:
        started = await orchestrator.start_scan("proj-1", resume=True)
        assert started["status"] == "running"
        assert started["elapsed_seconds"] == 120
        await asyncio.sleep(0)

    asyncio.run(_run())

    updated = store.get_project("proj-1")
    assert updated is not None
    last_scan = updated["lastScan"]
    result = last_scan["result"]
    resumed_plan = result["planner"]["plan_data"]
    scenarios = resumed_plan["phases"][0]["steps"][0]["scenarios"]
    assert scenarios[0]["done"] is True
    assert scenarios[0]["status"] == "completed"
    assert scenarios[1]["done"] is False
    assert scenarios[1]["status"] == "not yet"
    assert scenarios[1]["active_slot"] in {1, 2}
    assert last_scan["plan"] == resumed_plan
    assert updated["lastScan"]["scanId"] != "old-scan"
    assert 120 <= updated["lastScan"]["elapsedSeconds"] <= 125


def test_resume_without_saved_plan_starts_clean(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    assert project is not None
    project["status"] = "paused"
    project["findings"] = [{"id": "old-finding", "title": "Old finding"}]
    project["findings_count"] = 1
    project["checklist"] = {"checklist": [{"title": "Old project checklist"}]}
    project["plannerStaticPlan"] = {"scenarios": [{"task": "old static scenario"}]}
    project["payload"] = {
        "findings_history": {"recon": {"entries": [{"id": "old-history"}]}},
        "analyzer_agent_reports": {"recon": {"entries": [{"id": "legacy-history"}]}},
        "architecture_refresh": {"status": "completed"},
    }
    project["lastScan"] = {
        "scanId": "old-scan",
        "status": "awaiting_planner_approval",
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "result": {
            "intel": {
                "status": "complete",
                "summary": "Checklist exists, but plan does not.",
                "checklist": {"checklist": [{"title": "Old unstable checklist"}]},
            },
        },
    }
    store.upsert_project(project)

    async def _noop_run_scan(self, **kwargs) -> None:
        return None

    monkeypatch.setattr(ScanOrchestratorService, "_run_scan", _noop_run_scan)
    orchestrator = ScanOrchestratorService(store)

    async def _run() -> None:
        started = await orchestrator.start_scan("proj-1", resume=True)
        assert started["status"] == "running"
        await asyncio.sleep(0)

    asyncio.run(_run())

    updated = store.get_project("proj-1")
    assert updated is not None
    last_scan = updated["lastScan"]
    assert last_scan["scanId"] != "old-scan"
    assert last_scan.get("result") == {}
    assert "plan" not in last_scan
    assert updated.get("findings") == []
    assert updated.get("findings_count") == 0
    assert "checklist" not in updated
    assert "plannerStaticPlan" not in updated
    assert updated.get("payload") == {"architecture_refresh": {"status": "completed"}}
