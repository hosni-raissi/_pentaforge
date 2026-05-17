from __future__ import annotations

import asyncio

from server.app.scan.approval import ApprovalGateService
from server.app.scan.events import ScanEventService
from server.app.scan.persistence import ScanPersistenceService
from server.db.projects.store import ProjectsStore


def _seed_project(store: ProjectsStore, project_id: str = "proj-1") -> None:
    project = {
        "id": project_id,
        "name": "Approval Test Project",
        "target": "https://example.com",
        "targetType": "web_app",
        "status": "idle",
        "scanProgress": 0,
        "updatedAt": "2026-05-15T00:00:00Z",
        "approval_mode": "auto",
        "phases": [],
        "agents": [],
        "findings": [],
        "ragArtifacts": [],
        "lastScan": {},
        "copilotHistory": [],
        "copilotContext": "",
    }
    store.upsert_project(project)


def test_intel_refresh_approval_can_force_manual_gate_even_when_project_is_auto(tmp_path) -> None:
    store = ProjectsStore(db_path=str(tmp_path / "projects.db"))
    store.init_schema()
    _seed_project(store)

    persistence = ScanPersistenceService(store)
    events = ScanEventService(persistence, store)
    approval = ApprovalGateService(persistence, events)

    persistence.set_run_state(
        "proj-1",
        {
            "scan_id": "scan-1",
            "project_id": "proj-1",
            "status": "running",
        },
    )

    async def _run() -> None:
        request_task = asyncio.create_task(
            approval.request_tool_approval(
                project_id="proj-1",
                scan_id="scan-1",
                role="intel",
                tool_name="refresh RAG knowledge source HackTricks",
                args={
                    "source_name": "HackTricks",
                    "_require_manual_approval": True,
                },
                call_id="intel-rag-refresh:HackTricks",
            )
        )
        await asyncio.sleep(0.05)

        run_state = persistence.get_run_state("proj-1")
        assert run_state is not None
        assert run_state["awaiting_tool_approval"] is True
        pending = run_state["pending_tool_approval"]
        assert pending["args"]["source_name"] == "HackTricks"
        approval_id = str(pending["approval_id"])

        assert approval.approve_tool("proj-1", approval_id, "skip") is True
        approved = await request_task
        assert approved is False

    asyncio.run(_run())
