from __future__ import annotations

import asyncio
from importlib import import_module
from types import SimpleNamespace


intel_routes = import_module("server.api.routes.intel")
intel_helpers = import_module("server.nodes.intel.helpers")


class _CallbackRecorder:
    def __init__(self) -> None:
        self.steps: list[str] = []
        self.done: list[str] = []
        self.warn: list[str] = []

    def on_step(self, message: str) -> None:
        self.steps.append(message)

    def on_done(self, message: str) -> None:
        self.done.append(message)

    def on_warn(self, message: str) -> None:
        self.warn.append(message)


class _ApprovalCallbackRecorder(_CallbackRecorder):
    def __init__(self, decision: bool) -> None:
        super().__init__()
        self.decision = decision
        self.requests: list[dict[str, object]] = []

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, object],
        call_id: str,
    ) -> bool:
        self.requests.append(
            {
                "role": role,
                "tool_name": tool_name,
                "args": args,
                "call_id": call_id,
            }
        )
        return self.decision


def test_intel_progress_maps_source_ingest_step() -> None:
    assert intel_routes._update_progress_from_message(
        "Update: ingesting source 2/4: PayloadsAllTheThings"
    ) == 32


def test_refresh_rag_emits_source_step_and_duration(monkeypatch) -> None:
    callback = _CallbackRecorder()

    class _ProjectsStore:
        def get_intel_refresh_days(self, target_type: str) -> int | None:
            return None

    class _StateStore:
        def get_last_update(self, target_type: str):
            return None

        def set_last_update(self, target_type: str, when, *, update_status: str) -> None:
            return None

    async def _verify_source(*args, **kwargs):
        return {
            "source_name": "PayloadsAllTheThings",
            "verified": True,
            "trust_score": 100,
            "checks": [],
        }

    class _FakeOrchestrator:
        async def ingest_source(self, source_name: str):
            return SimpleNamespace(
                errors=[],
                documents_extracted=34,
                chunks_created=0,
                chunks_embedded=0,
                duration_seconds=61.5,
            )

        async def close(self) -> None:
            return None

    async def _sync_payload_store(target_type: str) -> tuple[int, list[str]]:
        return (0, [])

    monkeypatch.setattr(
        intel_helpers,
        "_collect_source_entries",
        lambda target_type, *, projects_store: [
            {
                "name": "PayloadsAllTheThings",
                "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
                "target_type": target_type,
                "content_type": "strategies",
                "update_mode": "every_3_days",
            }
        ],
    )
    monkeypatch.setattr(intel_helpers, "verify_source", _verify_source)
    monkeypatch.setattr(intel_helpers, "KnowledgeOrchestrator", _FakeOrchestrator)
    monkeypatch.setattr(intel_helpers, "_sync_payload_store", _sync_payload_store)
    monkeypatch.setattr(
        intel_helpers,
        "get_source_by_name",
        lambda name: SimpleNamespace(
            name=name,
            content_type=SimpleNamespace(value="strategies"),
            domain="shared",
        ),
    )

    result = asyncio.run(
        intel_helpers.refresh_rag(
            target_type="web_app",
            info="",
            force_update=False,
            callback=callback,
            projects_store=_ProjectsStore(),
            state_store=_StateStore(),
        )
    )

    assert any(
        msg == "Update: ingesting source 1/1: PayloadsAllTheThings"
        for msg in callback.steps
    )
    assert any(
        "Updated source PayloadsAllTheThings: docs=34, chunks=0, embedded=0, duration=61.5s"
        in msg
        for msg in callback.done
    )
    assert result.stats["sources_updated"] == 1


def test_refresh_rag_defers_large_sources_during_routine_refresh(monkeypatch) -> None:
    callback = _CallbackRecorder()
    ingest_calls: list[str] = []

    class _ProjectsStore:
        def get_intel_refresh_days(self, target_type: str) -> int | None:
            return None

    class _StateStore:
        def get_last_update(self, target_type: str):
            return None

        def set_last_update(self, target_type: str, when, *, update_status: str) -> None:
            return None

    async def _verify_source(*args, **kwargs):
        return {
            "source_name": "HackTricks",
            "verified": True,
            "trust_score": 100,
            "checks": [],
        }

    class _FakeOrchestrator:
        async def ingest_source(self, source_name: str):
            ingest_calls.append(source_name)
            return SimpleNamespace(
                errors=[],
                documents_extracted=10,
                chunks_created=20,
                chunks_embedded=20,
                duration_seconds=5.0,
            )

        async def close(self) -> None:
            return None

    async def _sync_payload_store(target_type: str) -> tuple[int, list[str]]:
        return (0, [])

    monkeypatch.setattr(
        intel_helpers,
        "_collect_source_entries",
        lambda target_type, *, projects_store: [
            {
                "name": "HackTricks",
                "url": "https://github.com/HackTricks-wiki/hacktricks",
                "target_type": target_type,
                "content_type": "strategies",
                "update_mode": "every_3_days",
            }
        ],
    )
    monkeypatch.setattr(intel_helpers, "verify_source", _verify_source)
    monkeypatch.setattr(intel_helpers, "KnowledgeOrchestrator", _FakeOrchestrator)
    monkeypatch.setattr(intel_helpers, "_sync_payload_store", _sync_payload_store)
    monkeypatch.setattr(
        intel_helpers,
        "get_source_by_name",
        lambda name: SimpleNamespace(
            name=name,
            content_type=SimpleNamespace(value="strategies"),
            domain="shared",
            intel_inline_refresh=False,
        ),
    )

    result = asyncio.run(
        intel_helpers.refresh_rag(
            target_type="web_app",
            info="",
            force_update=False,
            callback=callback,
            projects_store=_ProjectsStore(),
            state_store=_StateStore(),
        )
    )

    assert ingest_calls == []
    assert result.stats["sources_deferred"] == 1
    assert any("Deferred source HackTricks" in msg for msg in callback.done)


def test_refresh_rag_requests_manual_approval_for_deferred_source_and_skips_when_denied(monkeypatch) -> None:
    callback = _ApprovalCallbackRecorder(decision=False)
    ingest_calls: list[str] = []

    class _ProjectsStore:
        def get_intel_refresh_days(self, target_type: str) -> int | None:
            return None

    class _StateStore:
        def get_last_update(self, target_type: str):
            return None

        def set_last_update(self, target_type: str, when, *, update_status: str) -> None:
            return None

    async def _verify_source(*args, **kwargs):
        return {
            "source_name": "HackTricks",
            "verified": True,
            "trust_score": 100,
            "checks": [],
        }

    class _FakeOrchestrator:
        async def ingest_source(self, source_name: str):
            ingest_calls.append(source_name)
            return SimpleNamespace(
                errors=[],
                documents_extracted=10,
                chunks_created=20,
                chunks_embedded=20,
                duration_seconds=5.0,
            )

        async def close(self) -> None:
            return None

    async def _sync_payload_store(target_type: str) -> tuple[int, list[str]]:
        return (0, [])

    monkeypatch.setattr(
        intel_helpers,
        "_collect_source_entries",
        lambda target_type, *, projects_store: [
            {
                "name": "HackTricks",
                "url": "https://github.com/HackTricks-wiki/hacktricks",
                "target_type": target_type,
                "content_type": "strategies",
                "update_mode": "every_3_days",
            }
        ],
    )
    monkeypatch.setattr(intel_helpers, "verify_source", _verify_source)
    monkeypatch.setattr(intel_helpers, "KnowledgeOrchestrator", _FakeOrchestrator)
    monkeypatch.setattr(intel_helpers, "_sync_payload_store", _sync_payload_store)
    monkeypatch.setattr(
        intel_helpers,
        "get_source_by_name",
        lambda name: SimpleNamespace(
            name=name,
            url="https://github.com/HackTricks-wiki/hacktricks",
            content_type=SimpleNamespace(value="strategies"),
            domain="shared",
            intel_inline_refresh=False,
        ),
    )

    result = asyncio.run(
        intel_helpers.refresh_rag(
            target_type="web_app",
            info="",
            force_update=False,
            callback=callback,
            projects_store=_ProjectsStore(),
            state_store=_StateStore(),
        )
    )

    assert ingest_calls == []
    assert result.stats["sources_deferred"] == 1
    assert len(callback.requests) == 1
    request = callback.requests[0]
    assert request["role"] == "intel"
    assert request["tool_name"] == "refresh RAG knowledge source HackTricks"
    assert request["call_id"] == "intel-rag-refresh:HackTricks"
    request_args = request["args"]
    assert isinstance(request_args, dict)
    assert request_args["source_name"] == "HackTricks"
    assert request_args["_require_manual_approval"] is True
    assert any("skipped by operator" in msg for msg in callback.done)


def test_refresh_rag_ingests_deferred_source_when_operator_approves(monkeypatch) -> None:
    callback = _ApprovalCallbackRecorder(decision=True)
    ingest_calls: list[str] = []

    class _ProjectsStore:
        def get_intel_refresh_days(self, target_type: str) -> int | None:
            return None

    class _StateStore:
        def get_last_update(self, target_type: str):
            return None

        def set_last_update(self, target_type: str, when, *, update_status: str) -> None:
            return None

    async def _verify_source(*args, **kwargs):
        return {
            "source_name": "HackTricks",
            "verified": True,
            "trust_score": 100,
            "checks": [],
        }

    class _FakeOrchestrator:
        async def ingest_source(self, source_name: str):
            ingest_calls.append(source_name)
            return SimpleNamespace(
                errors=[],
                documents_extracted=12,
                chunks_created=24,
                chunks_embedded=24,
                duration_seconds=6.0,
            )

        async def close(self) -> None:
            return None

    async def _sync_payload_store(target_type: str) -> tuple[int, list[str]]:
        return (0, [])

    monkeypatch.setattr(
        intel_helpers,
        "_collect_source_entries",
        lambda target_type, *, projects_store: [
            {
                "name": "HackTricks",
                "url": "https://github.com/HackTricks-wiki/hacktricks",
                "target_type": target_type,
                "content_type": "strategies",
                "update_mode": "every_3_days",
            }
        ],
    )
    monkeypatch.setattr(intel_helpers, "verify_source", _verify_source)
    monkeypatch.setattr(intel_helpers, "KnowledgeOrchestrator", _FakeOrchestrator)
    monkeypatch.setattr(intel_helpers, "_sync_payload_store", _sync_payload_store)
    monkeypatch.setattr(
        intel_helpers,
        "get_source_by_name",
        lambda name: SimpleNamespace(
            name=name,
            url="https://github.com/HackTricks-wiki/hacktricks",
            content_type=SimpleNamespace(value="strategies"),
            domain="shared",
            intel_inline_refresh=False,
        ),
    )

    result = asyncio.run(
        intel_helpers.refresh_rag(
            target_type="web_app",
            info="",
            force_update=False,
            callback=callback,
            projects_store=_ProjectsStore(),
            state_store=_StateStore(),
        )
    )

    assert ingest_calls == ["HackTricks"]
    assert result.stats["sources_deferred"] == 0
    assert result.stats["sources_updated"] == 1
    assert any(msg == "Update: ingesting source 1/1: HackTricks" for msg in callback.steps)
