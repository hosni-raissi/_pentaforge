from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from server.agents.report import report_generator as report_generator_module
from server.app import _full_orchestrator_impl as full_orchestrator_module
from server.app._full_orchestrator_impl import ScanOrchestratorService
from server.db.projects.store import ProjectsStore


def _seed_project(store: ProjectsStore, project_id: str = "proj-1") -> None:
    store.upsert_project(
        {
            "id": project_id,
            "name": "Guard Test Project",
            "target": "https://example.com",
            "targetType": "web_app",
            "status": "idle",
            "scanProgress": 0,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "approval_mode": "custom",
            "phases": [],
            "agents": [],
            "findings": [],
            "lastScan": {},
        }
    )


def _make_store(tmp_path) -> ProjectsStore:
    store = ProjectsStore(db_path=str(tmp_path / "projects.db"))
    store.init_schema()
    _seed_project(store)
    return store


class _FakeQueue:
    async def call_with_queue(self, _name: str, coro):
        return await coro


class _CapturingLLM:
    captured_messages = None

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    async def chat(self, messages, **_kwargs: Any):
        type(self).captured_messages = messages
        return SimpleNamespace(
            content=(
                "# Penetration Test Report\n\n"
                "## 1. Executive Summary\n"
                "Structured LLM report.\n\n"
                "## 2. Scope\n"
                "- Hosts/URLs tested\n"
                "- Tools used\n\n"
                "## 3. Risk Summary Table\n"
                "| # | Finding | Severity | CVSS | Confidence | Status |\n"
                "|---|---------|----------|------|------------|--------|\n\n"
                "## 4. Findings\n"
                "None.\n\n"
                "## 5. False Positives\n"
                "| Finding | Reason Dismissed |\n"
                "|---------|------------------|\n\n"
                "## 6. Attack Path\n"
                "N/A\n\n"
                "## 7. Appendix\n"
                "- N/A\n"
            )
        )

    async def close(self) -> None:
        return None


def test_report_generation_without_verified_findings_uses_project_history_only(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    assert project is not None
    project["status"] = "running"
    project["lastScan"] = {
        "scanId": "scan-1",
        "status": "running",
            "startedAt": datetime.now(timezone.utc).isoformat(),
    }
    project["payload"] = {
        "findings_history": {
            "recon": {
                "updated_at": "2026-05-25T18:00:00+00:00",
                "entries": [
                    {
                        "id": "scan-1:recon:c1s1:classified",
                        "scan_id": "scan-1",
                        "agent": "recon",
                        "verdict": "info",
                        "summary": "Observed upload and login surfaces.",
                        "markdown": "## Recon Notes\n\n- Observed `/upload`\n- Observed `/login`",
                        "updated_at": "2026-05-25T18:00:00+00:00",
                    },
                    {
                        "id": "scan-old:recon:c1s1:classified",
                        "scan_id": "scan-old",
                        "agent": "recon",
                        "verdict": "info",
                        "summary": "Old scan should not appear.",
                        "markdown": "old-history-should-not-appear",
                        "updated_at": "2026-05-24T18:00:00+00:00",
                    },
                ],
            },
        },
    }
    store.upsert_project(project)

    monkeypatch.setattr(report_generator_module, "LLMClient", _CapturingLLM)
    monkeypatch.setattr(report_generator_module, "get_global_llm_queue", lambda: _FakeQueue())

    result = asyncio.run(report_generator_module.generate_report("proj-1", store))
    prompt = _CapturingLLM.captured_messages[1].content

    assert result["metadata"]["verified_findings"] == 0
    assert result["metadata"]["report_mode"] == "llm_project_scoped"
    assert result["metadata"]["history_entry_count"] == 1
    assert result["content"].startswith("# Penetration Test Report")
    assert '"risk_summary_rows": []' in prompt
    assert "Observed upload and login surfaces." in prompt
    assert "old-history-should-not-appear" not in prompt
    assert "information_gathering" not in prompt
    assert "Full Tool History" not in prompt
    assert "cors_misconfig_check" not in prompt


def test_fresh_scan_start_clears_old_findings_and_reports(tmp_path) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    assert project is not None
    project["findings"] = [{"id": "finding-1", "title": "Old finding", "status": "verified"}]
    project["findings_count"] = 1
    store.upsert_project(project)
    store.save_report("proj-1", report_id="report-1", format="markdown", content="# Old report")

    service = ScanOrchestratorService(store)
    gate = asyncio.Event()

    async def _blocked_run_scan(self, **_kwargs: Any) -> None:
        await gate.wait()

    service._run_scan = _blocked_run_scan.__get__(service, type(service))

    async def _run() -> None:
        started = await service.start_scan("proj-1", target="https://example.com", resume=False, force=True)
        assert started["status"] == "running"

        refreshed = store.get_project("proj-1")
        assert refreshed is not None
        assert refreshed["findings"] == []
        assert refreshed["findings_count"] == 0
        assert store.list_report_status("proj-1") == {
            "markdown": False,
            "html": False,
            "pdf": False,
            "generated_at": None,
        }

        task = service._tasks.get("proj-1")
        assert task is not None
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    asyncio.run(_run())


def test_cancel_scan_cleans_project_runtime_state(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    assert project is not None
    project.update(
        {
            "status": "running",
            "scanProgress": 77,
            "findings": [{"id": "finding-1", "title": "Old finding", "status": "verified"}],
            "copilotHistory": [{"id": "msg-1", "role": "assistant", "text": "hello"}],
            "copilotContext": "saved context",
            "payload": {"architecture_draft": {"hosts": [{"id": "host-1"}]}},
            "lastScan": {"scanId": "scan-1", "status": "running"},
        }
    )
    store.upsert_project(project)
    store.save_report("proj-1", report_id="report-1", format="markdown", content="# Old report")
    store.add_client_message("proj-1", "client", "hello")
    store.create_share_link("proj-1")
    store.append_scan_event_cache(
        "proj-1",
        {
            "scan_id": "scan-1",
            "event": "scan_started",
            "level": "info",
            "message": "Scan started",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {},
        },
    )

    monkeypatch.setattr(
        full_orchestrator_module,
        "_purge_project_runtime_artifacts",
        lambda *_args, **_kwargs: {
            "project_runs_removed": 0,
            "project_findings_removed": 0,
            "sandbox_paths_removed": 0,
            "uploaded_artifacts_removed": 0,
        },
    )

    service = ScanOrchestratorService(store)

    stopped = service.stop_scan("proj-1", mode="cancel")
    assert stopped["status"] == "idle"

    refreshed = store.get_project("proj-1")
    assert refreshed is not None
    assert refreshed["status"] == "idle"
    assert refreshed["findings"] == []
    assert refreshed["copilotHistory"] == []
    assert refreshed["copilotContext"] == ""
    assert refreshed["payload"] is None
    assert refreshed["lastScan"] is None
    assert store.list_report_status("proj-1") == {
        "markdown": False,
        "html": False,
        "pdf": False,
        "generated_at": None,
    }
    assert store.list_client_messages("proj-1") == []
    assert store.list_scan_event_cache("proj-1", limit=20) == []


def test_report_generation_is_scoped_to_current_project_and_current_scan(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    _seed_project(store, "proj-2")

    project_one = store.get_project("proj-1")
    project_two = store.get_project("proj-2")
    assert project_one is not None
    assert project_two is not None

    project_one["target"] = "https://pentest-ground.com:9000"
    project_one["lastScan"] = {"scanId": "scan-1", "status": "completed"}
    project_one["findings"] = [
        {
            "id": "finding-1",
            "scan_id": "scan-1",
            "title": "Current project finding one",
            "severity": "critical",
            "status": "verified",
            "target": "https://pentest-ground.com:9000/a",
            "description": "Current project finding one description.",
            "evidence": {"verification_summary": "Confirmed one."},
        },
        {
            "id": "finding-2",
            "scan_id": "scan-1",
            "title": "Current project finding two",
            "severity": "high",
            "status": "verified",
            "target": "https://pentest-ground.com:9000/b",
            "description": "Current project finding two description.",
            "evidence": {"verification_summary": "Confirmed two."},
        },
        {
            "id": "finding-3",
            "scan_id": "scan-old",
            "title": "Old scan finding should not appear",
            "severity": "medium",
            "status": "verified",
            "target": "https://pentest-ground.com:9000/old",
            "description": "Old scan finding.",
            "evidence": {"verification_summary": "Old finding."},
        },
    ]
    store.upsert_project(project_one)

    project_two["target"] = "https://pentest-ground.com:9000"
    project_two["lastScan"] = {"scanId": "scan-2", "status": "completed"}
    project_two["findings"] = [
        {
            "id": "finding-x",
            "scan_id": "scan-2",
            "title": "Other project finding should not appear",
            "severity": "critical",
            "status": "verified",
            "target": "https://pentest-ground.com:9000/x",
            "description": "Other project finding.",
            "evidence": {"verification_summary": "Other project only."},
        },
    ]
    store.upsert_project(project_two)

    monkeypatch.setattr(report_generator_module, "LLMClient", _CapturingLLM)
    monkeypatch.setattr(report_generator_module, "get_global_llm_queue", lambda: _FakeQueue())

    result = asyncio.run(report_generator_module.generate_report("proj-1", store))
    prompt = _CapturingLLM.captured_messages[1].content

    assert result["metadata"]["total_findings"] == 2
    assert result["metadata"]["verified_findings"] == 2
    assert '"risk_summary_rows": [' in prompt
    assert '"#": 1' in prompt
    assert '"status": "Verified"' in prompt
    assert "Current project finding one" in prompt
    assert "Current project finding two" in prompt
    assert "Old scan finding should not appear" not in prompt
    assert "Other project finding should not appear" not in prompt
