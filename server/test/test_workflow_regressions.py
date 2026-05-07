from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from importlib import import_module

from fastapi import Response

from server.app.scan.approval import ApprovalGateService
from server.app.scan.events import ScanEventService
from server.app.scan.lifecycle import ScanLifecycleService
from server.app.scan.persistence import ScanPersistenceService
from server.app.scan.runner import PhaseRunnerService
from server.db.projects.store import ProjectsStore
from server.nodes.system_memory import load_system_memory, save_system_memory

ai_routes = import_module("server.api.routes.ai")
scans_routes = import_module("server.api.routes.scans")
reports_routes = import_module("server.api.routes.reports")
mark_false_positive_module = import_module("server.agents.assistant.tools.mark_false_positive")
scan_observability_module = import_module("server.db.projects.scan_observability")


def _seed_project(store: ProjectsStore, project_id: str = "proj-1") -> dict[str, Any]:
    project = {
        "id": project_id,
        "name": "Regression Project",
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
    store.upsert_project(project)
    return project


def _make_store(tmp_path, project_id: str = "proj-1") -> ProjectsStore:
    store = ProjectsStore(db_path=str(tmp_path / "projects.db"))
    store.init_schema()
    _seed_project(store, project_id)
    return store


def test_assistant_run_can_reload_from_store_and_cancel(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    monkeypatch.setattr(ai_routes, "projects_store", store)
    ai_routes._assistant_runs.clear()
    ai_routes._assistant_scope_index.clear()

    gate = asyncio.Event()

    class FakeDecision:
        is_injection = False
        reason = "clean"
        confidence = 0.99
        classifier = "test"
        detections: list[str] = []

    class FakePromptGuard:
        async def classify_user_prompt(self, prompt: str, *, context: str, use_llm: bool = True) -> FakeDecision:
            return FakeDecision()

    class FakeAssistantAgent:
        async def stream_answer(self, **_: Any):
            yield {
                "type": "tool_start",
                "data": {"call_id": "tool-1", "tool": "http_probe", "input": {"target": "https://example.com"}},
            }
            await gate.wait()
            yield {
                "type": "reply",
                "data": {"text": "Investigation complete.", "route": "assistant", "blocked": False},
            }
            yield {
                "type": "context",
                "data": {"next_context": "assistant-context"},
            }

    monkeypatch.setattr(ai_routes, "_prompt_guard", FakePromptGuard())
    monkeypatch.setattr(ai_routes, "_assistant_agent", FakeAssistantAgent())

    async def _run() -> None:
        payload = ai_routes.AIAssistPayload(
            prompt="Check the target",
            project_id="proj-1",
            target="https://example.com",
            target_type="web_app",
            request_id="assist-1",
        )
        scope_key = ai_routes.normalize_target_scope(payload.target, payload.target_type)
        saved_context, saved_history = await ai_routes._load_saved_assistant_context(
            project_id=payload.project_id,
            scope_key=scope_key,
        )
        run = await ai_routes._resolve_or_create_run(
            payload,
            prompt=payload.prompt,
            scope_key=scope_key,
            context="project_id=proj-1",
            saved_context=saved_context,
            saved_history=saved_history,
        )
        await asyncio.sleep(0.05)

        stored = store.get_task_run("assist-1")
        assert stored is not None
        assert stored["status"] == "running"
        assert stored["payload"]["toolLogs"][0]["tool"] == "http_probe"

        ai_routes._assistant_runs.clear()
        ai_routes._assistant_scope_index.clear()

        restored = await ai_routes._resolve_or_create_run(
            payload,
            prompt=payload.prompt,
            scope_key=scope_key,
            context="project_id=proj-1",
            saved_context=saved_context,
            saved_history=saved_history,
        )
        assert restored.request_id == "assist-1"
        assert restored.backlog

        ai_routes._assistant_runs["assist-1"] = run
        response = await ai_routes.cancel_ai_assist("assist-1")
        assert response.status == "cancelled"
        assert store.get_task_run("assist-1")["status"] == "cancelled"

        gate.set()
        if run.task is not None:
            with suppress(asyncio.CancelledError):
                await run.task

    try:
        asyncio.run(_run())
    finally:
        ai_routes._assistant_runs.clear()
        ai_routes._assistant_scope_index.clear()


def test_report_regenerate_replaces_old_content_and_status_stays_fresh(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    monkeypatch.setattr(reports_routes, "projects_store", store)
    reports_routes._report_tasks.clear()

    counter = {"value": 0}

    async def fake_generate_report(project_id: str, _store: ProjectsStore) -> dict[str, Any]:
        counter["value"] += 1
        version = counter["value"]
        return {
            "report_id": f"report-{version}",
            "content": f"# Report Version {version}\n\nGenerated for {project_id}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {"target": "https://example.com", "version": version},
        }

    monkeypatch.setattr(reports_routes, "generate_report", fake_generate_report)

    async def _run() -> None:
        await reports_routes._generate_project_report_task("proj-1", "run-1")

        status_response_1 = Response()
        status_1 = await reports_routes.get_report_status("proj-1", status_response_1)
        markdown_response_1 = Response()
        markdown_1 = await reports_routes.get_report_content("proj-1", "markdown", markdown_response_1)

        assert status_1.markdown is True
        assert status_1.html is True
        assert status_1.run_status == "completed"
        assert status_response_1.headers["Cache-Control"] == "no-store"
        assert markdown_response_1.headers["Cache-Control"] == "no-store"
        assert "Report Version 1" in markdown_1.content

        await reports_routes._generate_project_report_task("proj-1", "run-2")

        status_response_2 = Response()
        status_2 = await reports_routes.get_report_status("proj-1", status_response_2)
        markdown_2 = await reports_routes.get_report_content("proj-1", "markdown", Response())

        assert status_2.run_id == "run-2"
        assert status_2.run_status == "completed"
        assert "Report Version 2" in markdown_2.content
        assert markdown_2.content != markdown_1.content

    asyncio.run(_run())


def test_tool_approval_flow_persists_gate_state_and_emits_events(tmp_path) -> None:
    store = _make_store(tmp_path)
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
                role="recon",
                tool_name="run_custom",
                args={"command": "nmap -sV example.com"},
                call_id="call-1",
            )
        )
        await asyncio.sleep(0.05)

        run_state = persistence.get_run_state("proj-1")
        assert run_state is not None
        assert run_state["awaiting_tool_approval"] is True
        pending = run_state["pending_tool_approval"]
        approval_id = str(pending["approval_id"])

        cached_events = store.list_scan_event_cache("proj-1", limit=20)
        assert any(event["event"] == "executer_tool_waiting_approval" for event in cached_events)

        assert approval.approve_tool("proj-1", approval_id, "approve") is True
        approved = await request_task
        assert approved is True

        next_state = persistence.get_run_state("proj-1")
        assert next_state is not None
        assert next_state["awaiting_tool_approval"] is False
        assert next_state["pending_tool_approval"] is None

    asyncio.run(_run())


def test_orchestrator_scan_control_facade_matches_route_contracts(tmp_path) -> None:
    store = _make_store(tmp_path)
    persistence = ScanPersistenceService(store)
    events = ScanEventService(persistence, store)
    approval = ApprovalGateService(persistence, events)
    runner = PhaseRunnerService(persistence, events, approval)
    lifecycle = ScanLifecycleService(persistence, events, runner, approval)
    orchestrator = import_module("server.app.orchestrator").ScanOrchestratorService(
        store,
        persistence_service=persistence,
        event_service=events,
        approval_service=approval,
        runner_service=runner,
        lifecycle_service=lifecycle,
    )

    queue = orchestrator.subscribe_events("proj-1")
    assert queue is not None
    orchestrator.unsubscribe_events("proj-1", queue)
    assert orchestrator.clear_event_cache("proj-1") == 0

    snapshot = orchestrator.get_scan_observability("proj-1", scan_id="scan-123", limit=20)
    assert "timeline" in snapshot
    assert "metrics" in snapshot

    async def _run() -> None:
        stopped = await orchestrator.stop_scan("proj-1", mode="pause")
        assert stopped["status"] == "paused"

    asyncio.run(_run())


def test_observability_metrics_count_manual_false_positives_tool_records_and_resume_terminal() -> None:
    events = [
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:00:00+00:00",
            "event": "scan_started",
            "level": "info",
            "message": "Scan started",
            "data": {"resume_restored": True},
        },
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:00:05+00:00",
            "event": "planner_waiting_approval",
            "level": "info",
            "message": "Planner waiting approval",
            "data": {},
        },
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:00:10+00:00",
            "event": "planner_approval_received",
            "level": "info",
            "message": "Planner approved",
            "data": {},
        },
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:00:20+00:00",
            "event": "executer_cycle_start",
            "level": "info",
            "message": "Executer cycle 1 starting",
            "data": {"cycle": 1},
        },
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:00:25+00:00",
            "event": "executer_status",
            "level": "info",
            "message": "Executer [step] [worker 0] [recon] tool call: api_endpoint_discovery",
            "data": {"cycle": 1},
        },
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:00:28+00:00",
            "event": "executer_status",
            "level": "warn",
            "message": "Executer [recon] tool error: timeout",
            "data": {"cycle": 1},
        },
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:00:40+00:00",
            "event": "finding_updated",
            "level": "info",
            "message": "Finding 'X' marked as false positive by assistant.",
            "data": {"finding_id": "finding-1", "status": "false_positive", "reason_code": "manual_false_positive_marked"},
        },
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:00:50+00:00",
            "event": "verified_finding_saved",
            "level": "success",
            "message": "Confirmed finding persisted",
            "data": {"finding_id": "finding-2"},
        },
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "timestamp": "2026-05-07T10:01:20+00:00",
            "event": "scan_paused",
            "level": "warn",
            "message": "Scan paused",
            "data": {},
        },
    ]
    tool_audits = [
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "tool_name": "run_custom",
            "status": "failed",
            "full_command": "curl https://example.com",
            "created_at": "2026-05-07T10:00:26+00:00",
        }
    ]

    metrics = scan_observability_module.compute_observability_metrics(events, tool_audits)

    assert metrics["false_positive_count"] == 1
    assert metrics["verified_vulnerability_count"] == 1
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["tool_log_count"] == 2
    assert metrics["failed_tool_log_count"] == 2
    assert metrics["tool_failure_rate"] == 1.0
    assert metrics["resume_attempt_count"] == 1
    assert metrics["resume_success_count"] == 1
    assert metrics["resume_success_rate"] == 1.0


def test_scan_routes_handle_async_stop_and_async_approval_contracts(monkeypatch) -> None:
    events_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    class FakeOrchestrator:
        async def stop_scan(self, project_id: str, *, mode: str = "pause") -> dict[str, Any]:
            return {"ok": True, "project_id": project_id, "status": mode}

        async def approve_executer_tool(self, project_id: str, approval_id: str, action: str) -> dict[str, Any]:
            return {
                "ok": project_id == "proj-1" and approval_id == "approval-1" and action == "approve",
                "project_id": project_id,
                "approval_id": approval_id,
                "action": action,
            }

        async def approve_executer_password(self, project_id: str, password_id: str, password: str, approved: bool) -> dict[str, Any]:
            return {
                "ok": project_id == "proj-1" and password_id == "pw-1" and password == "secret" and approved is True,
                "project_id": project_id,
                "password_id": password_id,
                "approved": approved,
            }

        def subscribe_events(self, project_id: str) -> asyncio.Queue[dict[str, Any]]:
            return events_queue

        def unsubscribe_events(self, project_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
            assert project_id == "proj-1"
            assert queue is events_queue

        def clear_event_cache(self, project_id: str) -> int:
            return 3 if project_id == "proj-1" else 0

        def get_scan_observability(
            self,
            project_id: str,
            *,
            scan_id: str | None = None,
            limit: int = 200,
        ) -> dict[str, Any]:
            return {
                "timeline": [{"project_id": project_id, "scan_id": scan_id or "", "limit": limit}],
                "metrics": {"tool_failure_rate": 0.0},
            }

    monkeypatch.setattr(scans_routes, "scan_orchestrator", FakeOrchestrator())

    async def _run() -> None:
        stop_result = await scans_routes.stop_scan(
            scans_routes.StopScanPayload(project_id="proj-1", mode="pause")
        )
        assert stop_result["status"] == "pause"

        tool_result = await scans_routes.approve_tool(
            "proj-1",
            scans_routes.ApproveToolPayload(approval_id="approval-1", action="approve"),
        )
        assert tool_result == {
            "ok": True,
            "project_id": "proj-1",
            "approval_id": "approval-1",
            "action": "approve",
        }

        password_result = await scans_routes.approve_password(
            "proj-1",
            scans_routes.PasswordResponsePayload(
                password_id="pw-1",
                password="secret",
                approved=True,
            ),
        )
        assert password_result == {
            "ok": True,
            "project_id": "proj-1",
            "password_id": "pw-1",
            "approved": True,
        }

        cleared = await scans_routes.clear_scan_events("proj-1")
        assert cleared["cleared"] == 3

        observability = await scans_routes.get_scan_observability(
            "proj-1",
            limit=30,
            scan_id="scan-xyz",
        )
        assert observability["scan_id"] == "scan-xyz"
        assert observability["timeline"][0]["scan_id"] == "scan-xyz"

    asyncio.run(_run())


def test_mark_false_positive_persists_to_project_memory_and_event_cache(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    project_cache_dir = tmp_path / "project-run-1"
    saved_memory = asyncio.run(
        save_system_memory(
            str(project_cache_dir),
            {
                "verified_findings": [
                    {
                        "id": "finding-1",
                        "title": "Missing Critical Headers",
                        "summary": "Headers are missing.",
                        "status": "real_vulnerability",
                    }
                ]
            },
        )
    )

    project = store.get_project("proj-1")
    assert project is not None
    project["findings"] = [
        {
            "id": "finding-1",
            "title": "Missing Critical Headers",
            "description": "Headers are missing.",
            "severity": "high",
            "status": "confirmed",
            "target": "https://example.com",
        }
    ]
    project["lastScan"] = {
        "result": {
            "targetMemory": {
                "json": saved_memory["paths"]["json"],
                "markdown": saved_memory["paths"]["markdown"],
            }
        }
    }
    store.upsert_project(project)

    class FakeVectorStore:
        def delete_by_doc_identity(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    monkeypatch.setattr(mark_false_positive_module, "_get_vector_store", lambda: FakeVectorStore())

    result = asyncio.run(
        mark_false_positive_module.mark_false_positive(
            "proj-1",
            "Missing Critical Headers",
            "Operator confirmed this was environmental noise.",
            project_store=store,
        )
    )

    assert result["success"] is True
    updated = store.get_project("proj-1")
    assert updated is not None
    assert updated["findings"][0]["status"] == "false_positive"

    assert isinstance(result.get("system_memory"), dict)

    cached_events = store.list_scan_event_cache("proj-1", limit=20)
    assert cached_events[-1]["event"] == "finding_updated"
    assert cached_events[-1]["reason_code"] == "manual_false_positive_marked"


def test_pause_resume_timer_fields_survive_persistence_boundaries(tmp_path) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    assert project is not None
    project["status"] = "running"
    project["lastScan"] = {
        "scanId": "scan-1",
        "startedAt": "2026-05-06T10:00:00+00:00",
        "status": "running",
        "elapsedSeconds": 133,
    }
    store.upsert_project(project)

    recovered = store.recover_interrupted_scans()
    assert recovered == 1

    reloaded = store.get_project("proj-1")
    assert reloaded is not None
    assert reloaded["status"] == "paused"
    assert reloaded["lastScan"]["status"] == "paused"
    assert reloaded["lastScan"]["elapsedSeconds"] == 133
    assert reloaded["lastScan"]["finishedAt"]

    persistence = ScanPersistenceService(store)
    events = ScanEventService(persistence, store)

    class FakeRunner:
        async def run_intel_phase(self, *_args: Any, **_kwargs: Any) -> Any:
            return SimpleNamespace(success=True, error="")

        async def run_warmup_recon_phase(self, *_args: Any, **_kwargs: Any) -> Any:
            return SimpleNamespace(success=True, error="")

    approval = ApprovalGateService(persistence, events)
    lifecycle = ScanLifecycleService(persistence, events, FakeRunner(), approval)
    resumed = asyncio.run(lifecycle.start_scan("proj-1", resume=True))
    assert resumed["status"] == "running"

    cached_events = store.list_scan_event_cache("proj-1", limit=20)
    scan_started = [event for event in cached_events if event["event"] == "scan_started"]
    assert scan_started
    assert scan_started[-1]["reason_code"] == "resume_restored"
