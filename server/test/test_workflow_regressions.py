from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
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
projects_routes = import_module("server.api.routes.projects")
mark_false_positive_module = import_module("server.agents.assistant.tools.mark_false_positive")
scan_observability_module = import_module("server.db.projects.scan_observability")
assistant_agent_module = import_module("server.agents.assistant.agent")
architect_agent_module = import_module("server.agents.architect.agent")
llm_module = import_module("server.core.llm")
rate_limiter_module = import_module("server.agents.rate_limiter")
privacy_gate_node_module = import_module("server.layers.PrivacyGate.node")
prompt_guard_module = import_module("server.layers.safety.prompt_guard")
target_validation_module = import_module("server.layers.safety.target_validation")
config_agent_module = import_module("server.config.agent")
route_topology_module = import_module("server.agents.executer.recon.tools.network.route_topology")
executer_base_module = import_module("server.agents.executer.base")


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
            guard_context="project_id=proj-1",
            live_context="Findings: none",
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
            guard_context="project_id=proj-1",
            live_context="Findings: none",
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


def test_assistant_stream_persists_stable_turn_ids_for_history_merge(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    monkeypatch.setattr(ai_routes, "projects_store", store)
    ai_routes._assistant_runs.clear()
    ai_routes._assistant_scope_index.clear()

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
                "type": "reply",
                "data": {"text": "Port 3031 is closed.", "route": "assistant", "blocked": False},
            }
            yield {
                "type": "context",
                "data": {"next_context": '{"verified_evidence":["3031/tcp closed"]}'},
            }

    monkeypatch.setattr(ai_routes, "_prompt_guard", FakePromptGuard())
    monkeypatch.setattr(ai_routes, "_assistant_agent", FakeAssistantAgent())

    async def _run() -> None:
        payload = ai_routes.AIAssistPayload(
            prompt="Check if port 3031 is open",
            project_id="proj-1",
            target="192.168.100.81",
            target_type="linux_server",
            request_id="assist-3031",
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
            guard_context="project_id=proj-1",
            live_context="Findings: none",
            saved_context=saved_context,
            saved_history=saved_history,
        )
        if run.task is not None:
            await run.task

        project = store.get_project("proj-1")
        history = project.get("copilotHistory", [])
        assert history[0]["id"] == "u-assist-3031"
        assert history[0]["requestId"] == "assist-3031"
        assert history[1]["id"] == "a-assist-3031"
        assert history[1]["requestId"] == "assist-3031"

    try:
        asyncio.run(_run())
    finally:
        ai_routes._assistant_runs.clear()
        ai_routes._assistant_scope_index.clear()


def test_assistant_external_research_is_explicit_and_schema_is_gated() -> None:
    agent = assistant_agent_module.AssistantAgent()

    assert agent._allows_external_research("Please look it up online and check the latest CVE details.") is True
    assert agent._allows_external_research("Explain this saved finding from the current project.") is False

    gated = agent._tool_schemas_for_turn(allow_external_research=False)
    allowed = agent._tool_schemas_for_turn(allow_external_research=True)
    gated_names = [row["function"]["name"] for row in gated]
    allowed_names = [row["function"]["name"] for row in allowed]

    assert "search_web" not in gated_names
    assert "search_web" in allowed_names


def test_assistant_project_vector_payload_adds_citations() -> None:
    payload = {
        "success": True,
        "matches": [
            {
                "id": "doc-1",
                "kind": "verified_vulnerability",
                "title": "Open Redirect",
                "excerpt": "Confirmed redirect through next parameter.",
                "metadata": {
                    "record_id": "finding-123",
                    "title": "Open Redirect",
                },
            }
        ],
    }

    enriched = assistant_agent_module.AssistantAgent._normalize_vector_search_payload(payload)
    assert enriched["matches"][0]["citation"] == "[project:verified_vulnerability:finding-123]"
    assert enriched["citations"] == ["[project:verified_vulnerability:finding-123]"]


def test_architect_compacts_large_input_without_second_llm_round(monkeypatch) -> None:
    call_count = {"value": 0}

    class FakeLLMClient:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def chat(self, _messages: list[Any]):
            call_count["value"] += 1
            return SimpleNamespace(
                content=json.dumps(
                    {
                        "title": "Observed Target Surface",
                        "hosts": [
                            {
                                "id": "web-frontend",
                                "name": "Web Frontend",
                                "role": "Edge",
                                "ports": ["80/tcp"],
                                "note": "HTTP surface observed.",
                                "x": 12,
                                "y": 30,
                            }
                        ],
                        "flows": [],
                    }
                )
            )

    class FakeQueue:
        async def call_with_queue(self, _agent_name: str, coro):
            return await coro

    monkeypatch.setattr(architect_agent_module, "LLMClient", FakeLLMClient)
    monkeypatch.setattr(architect_agent_module, "get_public_agent_config", lambda _role: SimpleNamespace())
    monkeypatch.setattr(architect_agent_module, "get_global_llm_queue", lambda: FakeQueue())
    monkeypatch.setattr(architect_agent_module, "ARCHITECT_HISTORY_THRESHOLD", 200)

    agent = architect_agent_module.ArchitectAgent()
    result = asyncio.run(
        agent.synthesize(
            target="192.168.100.81",
            target_type="linux_server",
            scope="single host",
            memory_block=("observed route /admin\nopen port 80/tcp\n" * 80),
            vulnerabilities_block=("confirmed finding: telnet default creds\n" * 40),
            previous_draft=None,
        )
    )

    assert call_count["value"] == 1
    assert result["hosts"][0]["name"] == "Web Frontend"


def test_assistant_build_context_block_keeps_short_recent_turn_window_with_working_memory() -> None:
    agent = assistant_agent_module.AssistantAgent()
    saved_context = json.dumps(
        {
            "operator_mode": "Investigate",
            "execution_lane": "investigation",
            "response_style": "natural",
            "verified_evidence": ["FTP reachable on port 21."],
            "recent_checks": ["nmap -sV -p21 192.168.100.81"],
        }
    )

    block = agent._build_context_block(
        project_id="proj-1",
        target="192.168.100.81",
        target_type="linux_server",
        prompt="summarize ftp state",
        context="project_id=proj-1",
        saved_context=saved_context,
        external_research_allowed=False,
        operator_mode="Investigate",
        execution_lane="investigation",
        response_style="natural",
        history=[
            {
                "role": "assistant",
                "text": "Recent live scan output that should stay out of the prompt once working memory exists.",
                "toolLogs": [
                    {"tool": "run_custom", "input": "nmap -p21 192.168.100.81", "status": "done"}
                ],
            }
        ],
    )

    assert "- working_memory:" in block
    assert "- recent_completed_checks:" not in block
    assert "- recent_conversation_turns:" in block
    assert "Recent live scan output that should stay out of the prompt once working memory exists." in block


def test_assistant_recent_turn_recall_uses_lightweight_lane() -> None:
    agent = assistant_agent_module.AssistantAgent()

    assert (
        agent._resolve_execution_lane(
            prompt="what i asked you about in the last three message",
            operator_mode="Ask",
        )
        == "lightweight"
    )


def test_assistant_local_context_memory_preserves_latest_dialogue_pair() -> None:
    payload = json.loads(
        assistant_agent_module.AssistantAgent._build_local_context_memory(
            operator_mode="Ask",
            execution_lane="investigation",
            response_style="natural",
            prompt="What did I ask you about in the last three messages?",
            reply="You asked me to test anonymous FTP access and summarize the result.",
            target="192.168.100.81",
            target_type="linux_server",
            project_state_summary="findings: ftp anonymous denied",
            investigation_brief="Answer from recent conversation and saved evidence.",
            tool_summaries=["command=curl ftp://192.168.100.81/"],
            learning_signals={},
            tool_results=[],
        )
    )

    assert payload["recent_dialogue"][0].startswith("user: What did I ask you about")
    assert payload["recent_dialogue"][1].startswith("assistant: You asked me to test anonymous FTP")


def test_architect_manual_refresh_uses_planner_memory_assistant_brain_and_confirmed_findings(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    project.update(
        {
            "target": "192.168.100.81",
            "targetType": "linux_server",
            "info": "Scope: single target",
            "copilotContextScope": "linux_server|192.168.100.81",
            "copilotContext": '{"verified_evidence":["ftp 21 open","telnet default creds confirmed"]}',
            "copilotHistoryScope": "linux_server|192.168.100.81",
            "copilotHistory": [
                {"role": "user", "text": "check ftp"},
                {"role": "assistant", "text": "Anonymous FTP denied; telnet creds confirmed."},
            ],
            "findings": [
                {
                    "id": "finding-1",
                    "title": "Telnet Default Credentials",
                    "description": "msfadmin:msfadmin works on port 23",
                    "severity": "critical",
                    "status": "confirmed",
                    "target": "192.168.100.81",
                }
            ],
            "payload": {},
        }
    )
    store.upsert_project(project)
    monkeypatch.setattr(ai_routes, "projects_store", store)
    cache_root = Path(ai_routes.__file__).resolve().parents[2] / "cache" / "project_runs"
    cache_root.mkdir(parents=True, exist_ok=True)
    (cache_root / "proj-1-test-run").mkdir(exist_ok=True)
    monkeypatch.setattr(ai_routes, "load_system_memory", lambda _run_dir: {"overview": "Planner observed HTTP and Telnet services."})
    monkeypatch.setattr(
        ai_routes,
        "build_target_memory_prompt_block",
        lambda memory: f"PLANNER MEMORY\n{memory.get('overview', '')}",
    )

    captured: dict[str, Any] = {}

    class FakeArchitectAgent:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        async def synthesize(self, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {
                "title": "Observed Target Surface",
                "hosts": [
                    {
                        "id": "edge",
                        "name": "Observed Edge",
                        "role": "Edge",
                        "ports": ["21/tcp", "23/tcp"],
                        "note": "FTP and Telnet exposed.",
                        "x": 20,
                        "y": 40,
                    }
                ],
                "flows": [],
            }

    monkeypatch.setattr(ai_routes, "ArchitectAgent", FakeArchitectAgent)

    result = asyncio.run(
        ai_routes.ai_architect_synthesize(
            ai_routes.ArchitectSynthesizePayload(project_id="proj-1")
        )
    )

    assert result["ok"] is True
    assert "PLANNER MEMORY" in captured["memory_block"]
    assert "ASSISTANT WORKING MEMORY" in captured["memory_block"]
    assert "RECENT ASSISTANT DISCUSSION" in captured["memory_block"]
    assert "Telnet Default Credentials" in captured["vulnerabilities_block"]
    assert "severity=critical" in captured["vulnerabilities_block"]


def test_architect_manual_refresh_emits_no_update_when_draft_empty(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    project.update(
        {
            "target": "192.168.100.81",
            "targetType": "linux_server",
            "payload": {},
        }
    )
    store.upsert_project(project)
    monkeypatch.setattr(ai_routes, "projects_store", store)
    monkeypatch.setattr(ai_routes, "load_system_memory", lambda _run_dir: {})
    monkeypatch.setattr(ai_routes, "build_target_memory_prompt_block", lambda _memory: "")

    emitted: list[tuple[str, dict[str, Any]]] = []

    class FakeArchitectAgent:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        async def synthesize(self, **_kwargs: Any) -> dict[str, Any]:
            return {}

    class FakeOrchestrator:
        def emit_event(self, project_id: str, *, event: str, data: dict[str, Any], **_kwargs: Any) -> None:
            emitted.append((event, data))

    monkeypatch.setattr(ai_routes, "ArchitectAgent", FakeArchitectAgent)
    monkeypatch.setattr(ai_routes, "scan_orchestrator", FakeOrchestrator())

    result = asyncio.run(
        ai_routes.ai_architect_synthesize(
            ai_routes.ArchitectSynthesizePayload(project_id="proj-1")
        )
    )

    assert result["ok"] is True
    assert result["architecture_draft"] == {}
    assert any(event == "architect_no_update" for event, _data in emitted)


def test_architect_sanitize_draft_preserves_llm_board_layout() -> None:
    agent = architect_agent_module.ArchitectAgent(project_id="proj-1")

    draft = agent._sanitize_draft(
        {
            "title": "Observed Target Surface",
            "hosts": [
                {
                    "id": "edge-node",
                    "name": "Linux Server",
                    "role": "Edge",
                    "ports": ["21/tcp", "22/tcp", "23/tcp", "80/tcp"],
                    "note": "Single externally exposed Linux server.",
                    "x": 18,
                    "y": 28,
                }
            ],
            "flows": [],
            "board": {
                "theme": "mono-grid",
                "canvas": {"width": 1280, "height": 720},
                "boxes": [
                    {
                        "id": "entry-box",
                        "title": "ENTRY BOX",
                        "subtitle": "Linux Server",
                        "kind": "host",
                        "x": 120,
                        "y": 140,
                        "w": 240,
                        "h": 160,
                        "lines": ["Primary ingress node", "Telnet exposed"],
                        "tags": ["21/tcp", "23/tcp"],
                        "hostIds": ["edge-node"],
                        "emphasis": "primary",
                    },
                    {
                        "id": "notes-box",
                        "title": "OBSERVED NOTES",
                        "kind": "notes",
                        "x": 420,
                        "y": 320,
                        "w": 320,
                        "h": 180,
                        "lines": ["Confirmed default credentials on Telnet."],
                        "hostIds": ["edge-node"],
                    },
                ],
                "links": [
                    {
                        "fromId": "entry-box",
                        "toId": "notes-box",
                        "label": "notes",
                    }
                ],
            },
        }
    )

    assert draft["board"]["theme"] == "mono-grid"
    assert draft["board"]["canvas"]["width"] == 1280
    assert draft["board"]["boxes"][0]["id"] == "entry-box"
    assert draft["board"]["boxes"][0]["hostIds"] == ["edge-node"]
    assert draft["board"]["links"][0]["fromId"] == "entry-box"
    assert draft["board"]["links"][0]["toId"] == "notes-box"


def test_store_copilot_context_cap_accepts_large_working_memory(tmp_path) -> None:
    store = _make_store(tmp_path)
    large_context = "A" * 31000

    store.update_project_copilot_context("proj-1", large_context)
    project = store.get_project("proj-1")

    assert project["copilotContext"] == large_context


def test_assistant_structured_reply_includes_sections_and_citations() -> None:
    tool_results = [
        {
            "success": True,
            "matches": [
                {
                    "title": "Open Redirect",
                    "excerpt": "Confirmed redirect through next parameter.",
                    "citation": "[project:verified_vulnerability:finding-123]",
                }
            ],
        }
    ]

    reply = assistant_agent_module.AssistantAgent._ensure_structured_reply(
        "Open redirect appears to be confirmed on the active target.",
        tool_results=tool_results,
        prompt="Verify this finding",
        target="https://example.com",
    )

    assert "**Summary**" in reply
    assert "**Verdict**" in reply
    assert "**Evidence**" in reply
    assert "**Unknowns**" in reply
    assert "**Next Step**" in reply
    assert "**Confidence**" in reply
    assert "[project:verified_vulnerability:finding-123]" in reply


def test_assistant_structured_reply_assigns_false_positive_verdict() -> None:
    reply = assistant_agent_module.AssistantAgent._ensure_structured_reply(
        "This looks like a false positive after review.",
        tool_results=[
            {
                "success": True,
                "status": "false_positive",
                "title": "Open Redirect",
            }
        ],
        prompt="Mark this as a false positive",
        target="https://example.com",
    )

    assert "**Verdict**\nfalse_positive" in reply


def test_assistant_detects_operator_modes() -> None:
    assert assistant_agent_module.AssistantAgent._detect_operator_mode("Generate the report for this project") == "Report"
    assert assistant_agent_module.AssistantAgent._detect_operator_mode("Retest this finding and check again") == "Retest"
    assert assistant_agent_module.AssistantAgent._detect_operator_mode("Investigate why this endpoint is exposed") == "Investigate"
    assert assistant_agent_module.AssistantAgent._detect_operator_mode("What does this finding mean?") == "Ask"


def test_assistant_capability_question_handles_identity_prompt() -> None:
    assert assistant_agent_module.AssistantAgent._is_capability_question("who are you?") is True


def test_assistant_lightweight_meta_prompt_uses_llm_reply(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()

    async def fake_chat(*_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(content="I am Echo. I help with pentest workflow for the active target.")

    monkeypatch.setattr(agent, "_chat_with_fallback", fake_chat)

    reply = asyncio.run(
        agent._answer_lightweight_lane_prompt(
            prompt="who are you?",
            target="https://example.com",
            target_type="web_app",
            project_id="proj-1",
            saved_context="",
            history=[],
        )
    )

    assert "I am Echo" in reply
    assert assistant_agent_module.AssistantAgent._resolve_execution_lane(prompt="who are you?", operator_mode="Ask") == "lightweight"
    assert assistant_agent_module.AssistantAgent._resolve_response_style(
        operator_mode="Ask",
        execution_lane="lightweight",
        prompt="who are you?",
    ) == "natural"


def test_assistant_summary_prompt_prefers_natural_style() -> None:
    assert assistant_agent_module.AssistantAgent._resolve_response_style(
        operator_mode="Ask",
        execution_lane="investigation",
        prompt="summary what we find",
    ) == "natural"


def test_assistant_lightweight_meta_prompt_omits_findings_context_when_not_requested(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()
    captured: dict[str, str] = {}

    async def fake_chat(messages: list[Any], **_kwargs: Any) -> Any:
        captured["content"] = str(messages[1].content)
        return SimpleNamespace(content="Hi! I'm Echo.")

    monkeypatch.setattr(agent, "_chat_with_fallback", fake_chat)

    reply = asyncio.run(
        agent._answer_lightweight_lane_prompt(
            prompt="hi",
            target="https://example.com",
            target_type="web_app",
            project_id="proj-1",
            saved_context='{"verified_evidence":["finding present"]}',
            history=[{"role": "assistant", "text": "Previous finding summary"}],
        )
    )

    assert "Hi! I'm Echo." in reply
    assert "Findings context requested: no" in captured["content"]
    assert "Minimal project state:" not in captured["content"]
    assert "Working memory:" not in captured["content"]


def test_assistant_masks_credentials_in_run_custom_preview_and_display_payload() -> None:
    preview = assistant_agent_module.AssistantAgent._render_run_custom_preview(
        "curl",
        ["-u", "msfadmin:msfadmin", "ftp://192.168.100.81/"],
    )
    payload = assistant_agent_module.AssistantAgent._sanitize_run_custom_result_for_display(
        {
            "success": True,
            "command": "curl",
            "args": ["-u", "msfadmin:msfadmin", "ftp://192.168.100.81/"],
            "full_command": "curl -u msfadmin:msfadmin ftp://192.168.100.81/",
            "stdout": "listing",
        }
    )

    assert "msfadmin:msfadmin" not in preview
    assert "msfadmin:****" in preview
    assert payload["args"] == ["-u", "msfadmin:****", "ftp://192.168.100.81/"]
    assert "msfadmin:msfadmin" not in payload["full_command"]
    assert "msfadmin:****" in payload["full_command"]


def test_assistant_stream_answer_does_not_use_static_ftp_auth_shortcut(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()
    calls = {"count": 0}

    async def fake_chat(*_args: Any, **_kwargs: Any) -> Any:
        calls["count"] += 1
        return SimpleNamespace(content="I can test those credentials, but I will decide the right tool from the current context.", tool_calls=[])

    async def fake_build_next_context(**_kwargs: Any) -> str:
        return '{"execution_lane": "investigation"}'

    async def fail_execute_run_custom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("Static prompt shortcuts should not execute run_custom before the LLM decides.")

    monkeypatch.setattr(agent, "_chat_with_fallback", fake_chat)
    monkeypatch.setattr(agent, "_execute_run_custom", fail_execute_run_custom)
    monkeypatch.setattr(agent, "_build_next_context", fake_build_next_context)

    async def _collect() -> list[dict[str, Any]]:
        return [
            event
            async for event in agent.stream_answer(
                prompt="try login msfadmin and password msfadmin",
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                context="",
                saved_context="",
                history=[
                    {
                        "role": "assistant",
                        "text": "FTP on port 21 is reachable.",
                        "toolLogs": [
                            {"tool": "run_custom", "input": "nmap -sV -p21 192.168.100.81", "status": "done"}
                        ],
                    }
                ],
            )
        ]

    events = asyncio.run(_collect())
    reply_event = next(event for event in events if event["type"] == "reply")

    assert calls["count"] >= 1
    assert all(event["type"] != "tool_start" for event in events)
    assert "current context" in reply_event["data"]["text"]


def test_assistant_stream_answer_does_not_use_static_followup_shortcut(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()
    calls = {"count": 0}

    async def fake_chat(*_args: Any, **_kwargs: Any) -> Any:
        calls["count"] += 1
        return SimpleNamespace(content="Please confirm which command you want me to run.", tool_calls=[])

    async def fail_execute_run_custom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("Static follow-up shortcut should not execute without LLM choice.")

    async def fake_build_next_context(**_kwargs: Any) -> str:
        return '{"execution_lane": "investigation"}'

    monkeypatch.setattr(agent, "_chat_with_fallback", fake_chat)
    monkeypatch.setattr(agent, "_execute_run_custom", fail_execute_run_custom)
    monkeypatch.setattr(agent, "_build_next_context", fake_build_next_context)

    async def _collect() -> list[dict[str, Any]]:
        return [
            event
            async for event in agent.stream_answer(
                prompt="run it",
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                context="",
                saved_context="",
                history=[
                    {
                        "role": "assistant",
                        "text": 'Recommended command: `nmap -sV -p23 192.168.100.81`',
                    }
                ],
            )
        ]

    events = asyncio.run(_collect())
    reply_event = next(event for event in events if event["type"] == "reply")

    assert calls["count"] >= 1
    assert all(event["type"] != "tool_start" for event in events)
    assert "confirm" in reply_event["data"]["text"].lower()


def test_assistant_stream_answer_blocks_near_duplicate_hydra_attempts(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()
    calls = {"count": 0}
    executions: list[dict[str, Any]] = []

    async def fake_chat(*_args: Any, **_kwargs: Any) -> Any:
        calls["count"] += 1
        if calls["count"] == 1:
            return SimpleNamespace(
                content="",
                tool_calls=[
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "run_custom",
                            "arguments": json.dumps({
                                "command": "hydra",
                                "args": ["-l", "msfadmin", "-p", "msfadmin", "192.168.100.81", "telnet"],
                                "reason": "Test telnet credentials.",
                            }),
                        },
                    },
                    {
                        "id": "call-2",
                        "type": "function",
                        "function": {
                            "name": "run_custom",
                            "arguments": json.dumps({
                                "command": "hydra",
                                "args": ["-vV", "-l", "msfadmin", "-p", "msfadmin", "192.168.100.81", "telnet"],
                                "reason": "Re-run the same telnet credential check with verbose output.",
                            }),
                        },
                    },
                ],
            )
        return SimpleNamespace(content="The credentials were confirmed with the first hydra run.", tool_calls=[])

    async def fake_execute_run_custom(args: dict[str, Any], *, target: str, project_id: str | None = None) -> dict[str, Any]:
        executions.append(args)
        return {
            "success": True,
            "command": "hydra",
            "args": list(args.get("args", [])),
            "reason": args.get("reason", ""),
            "full_command": "hydra -l msfadmin -p msfadmin 192.168.100.81 telnet",
            "stdout": "[23][telnet] host: 192.168.100.81 login: msfadmin password: msfadmin",
            "stderr": "",
            "return_code": 0,
            "execution_time": 1.0,
            "logged": True,
        }

    async def fake_build_next_context(**_kwargs: Any) -> str:
        return '{"execution_lane":"investigation"}'

    monkeypatch.setattr(agent, "_chat_with_fallback", fake_chat)
    monkeypatch.setattr(agent, "_execute_run_custom", fake_execute_run_custom)
    monkeypatch.setattr(agent, "_build_next_context", fake_build_next_context)

    async def _collect() -> list[dict[str, Any]]:
        return [
            event
            async for event in agent.stream_answer(
                prompt="now with hydra try to access to telnet with login msfadmin and password msfadmin",
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                context="",
                saved_context="",
                history=[],
            )
        ]

    events = asyncio.run(_collect())
    tool_outputs = [event for event in events if event["type"] == "tool_output"]
    blocked_outputs = [
        event for event in tool_outputs
        if "Near-duplicate tool call blocked" in str(event["data"]["output"].get("error", ""))
    ]

    assert len(executions) == 1
    assert len(tool_outputs) == 2
    assert len(blocked_outputs) == 1


def test_assistant_stream_answer_blocks_exact_duplicate_run_custom_with_different_reasons(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()
    calls = {"count": 0}
    executions: list[dict[str, Any]] = []

    async def fake_chat(*_args: Any, **_kwargs: Any) -> Any:
        calls["count"] += 1
        if calls["count"] == 1:
            return SimpleNamespace(
                content="",
                tool_calls=[
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "run_custom",
                            "arguments": json.dumps({
                                "command": "nmap",
                                "args": ["-p-", "--open", "-T4", "-n", "192.168.100.81"],
                                "reason": "List all open TCP ports.",
                            }),
                        },
                    },
                    {
                        "id": "call-2",
                        "type": "function",
                        "function": {
                            "name": "run_custom",
                            "arguments": json.dumps({
                                "command": "nmap",
                                "args": ["-p-", "--open", "-T4", "-n", "192.168.100.81"],
                                "reason": "Repeat the full TCP scan to confirm open ports.",
                            }),
                        },
                    },
                ],
            )
        return SimpleNamespace(content="The open-port scan already completed once.", tool_calls=[])

    async def fake_execute_run_custom(args: dict[str, Any], *, target: str, project_id: str | None = None) -> dict[str, Any]:
        executions.append(args)
        return {
            "success": True,
            "command": "nmap",
            "args": list(args.get("args", [])),
            "reason": args.get("reason", ""),
            "full_command": "nmap -p- --open -T4 -n 192.168.100.81",
            "stdout": "21/tcp open ftp\n23/tcp open telnet\n",
            "stderr": "",
            "return_code": 0,
            "execution_time": 0.9,
            "logged": True,
        }

    async def fake_build_next_context(**_kwargs: Any) -> str:
        return '{"execution_lane":"investigation"}'

    monkeypatch.setattr(agent, "_chat_with_fallback", fake_chat)
    monkeypatch.setattr(agent, "_execute_run_custom", fake_execute_run_custom)
    monkeypatch.setattr(agent, "_build_next_context", fake_build_next_context)

    async def _collect() -> list[dict[str, Any]]:
        return [
            event
            async for event in agent.stream_answer(
                prompt="scan all open ports",
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                context="",
                saved_context="",
                history=[],
            )
        ]

    events = asyncio.run(_collect())
    tool_outputs = [event for event in events if event["type"] == "tool_output"]
    blocked_outputs = [
        event for event in tool_outputs
        if "Near-duplicate tool call blocked" in str(event["data"]["output"].get("error", ""))
    ]

    assert len(executions) == 1
    assert len(tool_outputs) == 2
    assert len(blocked_outputs) == 1


def test_assistant_stream_answer_falls_back_to_local_tool_summary_when_llm_round_fails(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()
    calls = {"count": 0}

    async def fake_chat(*_args: Any, **_kwargs: Any) -> Any:
        calls["count"] += 1
        if calls["count"] == 1:
            return SimpleNamespace(
                content="",
                tool_calls=[
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "run_custom",
                            "arguments": (
                                '{"command":"ftp","args":["192.168.100.81"],'
                                '"reason":"Directly connect to FTP for verification."}'
                            ),
                        },
                    }
                ],
            )
        raise RuntimeError("provider unavailable during follow-up synthesis")

    async def fake_execute_run_custom(args: dict[str, Any], *, target: str, project_id: str | None = None) -> dict[str, Any]:
        assert args["command"] == "ftp"
        assert target == "192.168.100.81"
        return {
            "success": True,
            "command": "ftp",
            "args": ["192.168.100.81"],
            "reason": args["reason"],
            "full_command": "ftp 192.168.100.81",
            "stdout": "Name (192.168.100.81:test): Login incorrect.\n",
            "stderr": "Password:Login failed.\n",
            "return_code": 0,
            "execution_time": 1.0,
            "logged": True,
        }

    async def fake_build_next_context(**_kwargs: Any) -> str:
        return '{"execution_lane": "investigation"}'

    monkeypatch.setattr(agent, "_chat_with_fallback", fake_chat)
    monkeypatch.setattr(agent, "_execute_run_custom", fake_execute_run_custom)
    monkeypatch.setattr(agent, "_build_next_context", fake_build_next_context)

    async def _collect() -> list[dict[str, Any]]:
        return [
            event
            async for event in agent.stream_answer(
                prompt="connect with ftp",
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                context="",
                saved_context="",
                history=[],
            )
        ]

    events = asyncio.run(_collect())
    reply_event = next(event for event in events if event["type"] == "reply")

    assert "ftp 192.168.100.81" in reply_event["data"]["text"]
    assert "Login incorrect" in reply_event["data"]["text"]
    assert any(event["type"] == "context" for event in events)


def test_ai_compress_route_supports_backend_working_context(monkeypatch) -> None:
    class FakeAssistantAgent:
        async def compress_working_memory(self, context: str) -> str:
            assert '"verified_evidence"' in context
            return '{"operator_mode":"Ask","execution_lane":"investigation","response_style":"natural"}'

        async def compress_history(self, history: list[dict[str, Any]]) -> str:
            raise AssertionError("history compression should not be used for working-context refresh")

    monkeypatch.setattr(ai_routes, "_assistant_agent", FakeAssistantAgent())

    result = asyncio.run(
        ai_routes.ai_compress_history(
            ai_routes.AICompressPayload(
                context='{"verified_evidence":["FTP reachable and banner collected"]}',
            )
        )
    )

    assert result == {
        "context": '{"operator_mode":"Ask","execution_lane":"investigation","response_style":"natural"}'
    }


def test_ai_context_metrics_route_uses_backend_effective_context_estimate(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    store.update_project_copilot_context(
        "proj-1",
        json.dumps(
            {
                "operator_mode": "Investigate",
                "execution_lane": "investigation",
                "response_style": "natural",
                "verified_evidence": ["FTP reachable"],
            }
        ),
        scope_key="linux_server|192.168.100.81",
    )
    monkeypatch.setattr(ai_routes, "projects_store", store)

    result = asyncio.run(
        ai_routes.ai_assist_context_metrics(
            ai_routes.AIAssistContextMetricsPayload(
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                prompt="check whether ftp is still open",
                context="Findings: [info] FTP reachable",
            )
        )
    )

    assert result["display_tokens"] > 0
    assert result["effective_tokens"] > 0
    assert result["limit_tokens"] == 8000
    assert result["threshold_tokens"] == 7600
    assert result["has_working_memory"] is True
    assert result["uses_recent_history_fallback"] is False


def test_assistant_stream_answer_precompresses_large_saved_context_before_llm(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()
    huge_context = json.dumps(
        {
            "operator_mode": "Investigate",
            "execution_lane": "investigation",
            "response_style": "natural",
            "verified_evidence": ["A" * 33000],
        }
    )
    compressed_context = json.dumps(
        {
            "operator_mode": "Investigate",
            "execution_lane": "investigation",
            "response_style": "natural",
            "verified_evidence": ["FTP reachable on port 21."],
            "next_steps": ["Try a narrow anonymous login check."],
        }
    )
    captured: dict[str, Any] = {}

    async def fake_compress_working_memory(saved_context: str) -> str:
        captured["compressed_from"] = saved_context
        return compressed_context

    def fake_build_context_block(*, saved_context: str, **_kwargs: Any) -> str:
        captured["saved_context_in_block"] = saved_context
        return "Frontend assistant context:\n- working_memory: compressed"

    async def fake_chat(messages: list[Any], **_kwargs: Any) -> Any:
        captured["llm_user_content"] = messages[-1].content
        return SimpleNamespace(content="Grounded FTP summary.", tool_calls=[])

    async def fake_build_next_context(**_kwargs: Any) -> str:
        return compressed_context

    def fake_estimate_effective_context_metrics(**_kwargs: Any) -> dict[str, Any]:
        return {
            "display_tokens": 1200,
            "effective_tokens": 7900,
            "limit_tokens": 8000,
            "threshold_tokens": 7600,
            "should_compress_before_send": True,
            "operator_mode": "Investigate",
            "execution_lane": "investigation",
            "response_style": "natural",
            "has_working_memory": True,
            "uses_recent_history_fallback": False,
        }

    monkeypatch.setattr(agent, "compress_working_memory", fake_compress_working_memory)
    monkeypatch.setattr(agent, "estimate_effective_context_metrics", fake_estimate_effective_context_metrics)
    monkeypatch.setattr(agent, "_build_context_block", fake_build_context_block)
    monkeypatch.setattr(agent, "_chat_with_fallback", fake_chat)
    monkeypatch.setattr(agent, "_build_next_context", fake_build_next_context)

    async def _collect() -> list[dict[str, Any]]:
        return [
            event
            async for event in agent.stream_answer(
                prompt="summarize the ftp evidence",
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                context="",
                saved_context=huge_context,
                history=[],
            )
        ]

    events = asyncio.run(_collect())
    context_events = [event for event in events if event["type"] == "context"]
    reply_event = next(event for event in events if event["type"] == "reply")

    assert captured["compressed_from"] == huge_context
    assert captured["saved_context_in_block"] == compressed_context
    assert context_events[0]["data"]["next_context"] == compressed_context
    assert "working_memory: compressed" in captured["llm_user_content"]
    assert reply_event["data"]["text"] == "Grounded FTP summary."


def test_assistant_context_metrics_saved_context_override_wins(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    store.update_project_copilot_context(
        "proj-1",
        json.dumps({"verified_evidence": ["tiny"]}),
        scope_key="linux_server|192.168.100.81",
    )
    monkeypatch.setattr(ai_routes, "projects_store", store)

    base = asyncio.run(
        ai_routes.ai_assist_context_metrics(
            ai_routes.AIAssistContextMetricsPayload(
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                context="Findings: none",
            )
        )
    )
    overridden = asyncio.run(
        ai_routes.ai_assist_context_metrics(
            ai_routes.AIAssistContextMetricsPayload(
                project_id="proj-1",
                target="192.168.100.81",
                target_type="linux_server",
                context="Findings: none",
                saved_context_override=json.dumps({"verified_evidence": ["A" * 2000]}),
            )
        )
    )

    assert overridden["display_tokens"] > base["display_tokens"]


def test_url_normalizer_can_skip_reachability_probe(monkeypatch) -> None:
    async def forbidden_probe(self, _url: str) -> bool:
        raise AssertionError("reachability probe should not run")

    monkeypatch.setattr(target_validation_module.UrlNormalizer, "_probe", forbidden_probe)

    result = asyncio.run(
        target_validation_module.UrlNormalizer(
            "https://pentest-ground.com:9000",
            probe_reachability=False,
        ).normalize()
    )

    assert result["valid"] is True
    assert result["normalized_url"] == "https://pentest-ground.com:9000"
    assert result["reachable"] is False


def test_lightweight_lane_returns_soft_failure_when_llm_unavailable(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()

    async def broken_chat(*_args: Any, **_kwargs: Any):
        raise RuntimeError("backup provider unavailable")

    monkeypatch.setattr(agent, "_chat_with_fallback", broken_chat)

    reply = asyncio.run(
        agent._answer_lightweight_lane_prompt(
            prompt="hi",
            target="https://example.com",
            target_type="web_app",
            project_id="proj-1",
            saved_context="",
            history=[],
        )
    )

    assert "trouble reaching the model" in reply.lower()


def test_assistant_chat_falls_back_to_backup_on_primary_503(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()

    class FakeQueue:
        async def call_with_queue(self, _agent_name: str, coro):
            return await coro

    class FakeBackupLLM:
        async def chat(self, *_args: Any, **_kwargs: Any):
            return llm_module.LLMResponse(
                content="Recovered through backup provider.",
                tool_calls=[],
                finish_reason="stop",
                usage={},
            )

    class FakeBackupManager:
        async def get_backup_llm(self):
            return FakeBackupLLM()

    async def primary_503(*_args: Any, **_kwargs: Any):
        request = httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")
        response = httpx.Response(503, request=request, text="Service Unavailable")
        raise httpx.HTTPStatusError("503 Service Unavailable", request=request, response=response)

    monkeypatch.setattr(agent, "_queue", FakeQueue())
    monkeypatch.setattr(agent, "_backup", FakeBackupManager())
    monkeypatch.setattr(agent._llm, "chat", primary_503)

    response = asyncio.run(
        agent._chat_with_fallback(
            [llm_module.ChatMessage(role="user", content="verify if is it correct or false positif")],
            allow_tools=False,
        )
    )

    assert response.content == "Recovered through backup provider."


def test_privacy_gate_verbose_output_ignores_blocking_stdout(monkeypatch) -> None:
    class BrokenStdout:
        def write(self, _text: str) -> int:
            raise BlockingIOError(11, "write could not complete without blocking", 0)

        def flush(self) -> None:
            raise AssertionError("flush should not be reached after write failure")

    monkeypatch.setattr(privacy_gate_node_module.sys, "stdout", BrokenStdout())

    privacy_gate_node_module._print_verbose(
        "sanitized prompt",
        {"__IP_001__": "192.168.100.81"},
    )


def test_assistant_connectivity_failure_forces_needs_retest_even_with_saved_matches() -> None:
    verdict = assistant_agent_module.AssistantAgent._estimate_verdict(
        [
            {
                "success": True,
                "matches": [
                    {
                        "kind": "verified_vulnerability",
                        "title": "Exposed WSDL",
                        "citation": "[project:finding:abc]",
                    }
                ],
            },
            {
                "success": False,
                "command": "curl",
                "return_code": 6,
                "stderr": "curl: (6) Could not resolve host: pentest-ground.com",
                "error": "Exited with code 6",
            },
        ],
        [],
        prompt="Retest the WSDL finding",
    )

    assert verdict == "needs_retest"


def test_assistant_blocks_false_positive_marking_after_connectivity_failure() -> None:
    issue = assistant_agent_module.AssistantAgent._mark_false_positive_safety_issue(
        tool_results=[
            {
                "success": False,
                "command": "curl",
                "return_code": 28,
                "stderr": "curl: (28) Operation timed out after 5000 milliseconds",
                "error": "Exited with code 28",
            }
        ]
    )

    assert "automatic false-positive marking is blocked" in issue.lower()


def test_assistant_search_web_tool_only_reply_summarizes_results() -> None:
    reply = assistant_agent_module.AssistantAgent._format_tool_only_reply(
        [
            {
                "query": "latest SOAP XXE guidance",
                "engine": "google",
                "results": [
                    {
                        "title": "OWASP XXE Prevention",
                        "url": "https://owasp.org/example",
                        "snippet": "Guidance for preventing XML external entity attacks.",
                    }
                ],
            }
        ]
    )

    assert 'latest SOAP XXE guidance' in reply
    assert "OWASP XXE Prevention" in reply
    assert "https://owasp.org/example" in reply
    assert "[search_web]" not in reply


def test_assistant_formats_command_failures_with_likely_cause() -> None:
    payload = assistant_agent_module.AssistantAgent._augment_command_failure_payload(
        "ffuf",
        [
            "-u",
            "https://pentest-ground.com:9000/FUZZ",
            "-e",
            ".wsdl,.xml,.svc,.asmx,?wsdl",
        ],
        {
            "success": False,
            "command": "ffuf",
            "args": [
                "-u",
                "https://pentest-ground.com:9000/FUZZ",
                "-e",
                ".wsdl,.xml,.svc,.asmx,?wsdl",
            ],
            "return_code": 2,
            "error": "Exited with code 2",
        },
    )

    reply = assistant_agent_module.AssistantAgent._format_direct_command_reply(payload)

    assert "Likely cause:" in reply
    assert "FFUF" in reply or "ffuf" in reply


def test_assistant_identifies_getaddrinfo_thread_failure_as_environment_issue() -> None:
    payload = assistant_agent_module.AssistantAgent._augment_command_failure_payload(
        "curl",
        ["--connect-timeout", "10", "https://pentest-ground.com:9000/eval?input=test"],
        {
            "success": False,
            "command": "curl",
            "return_code": 6,
            "error": "Exited with code 6",
            "stderr": "* getaddrinfo() thread failed to start",
        },
    )

    assert "resolver failure" in str(payload.get("likely_cause", "")).lower()


def test_assistant_structured_reply_preserves_llm_text_without_backend_repair() -> None:
    preserved = assistant_agent_module.AssistantAgent._normalize_reply_for_style(
        """**Summary**
The finding "missing CSP header" means the site does not send a Content Security Policy header.

**Verdict**
likely

**Evidence**
- No direct evidence was collected in this turn.

**Unknowns**
- None.

**Next Step**
Run one narrow verification step.

**Confidence**
Low
""",
        response_style="structured",
        prompt="Investigate whether the exposed WSDL endpoint is actually reachable on the current target.",
        target="https://pentest-ground.com:9000",
        tool_results=[],
    )

    assert "missing CSP header" in preserved
    assert "WSDL" not in preserved and "wsdl" not in preserved


def test_assistant_structured_reply_sanitizes_raw_web_trace_but_preserves_llm_text() -> None:
    preserved = assistant_agent_module.AssistantAgent._normalize_reply_for_style(
        """[search_web]
"latest SOAP XXE vulnerabilities and exploitation guidance 2024"

**Summary**
Command: ``

**Verdict**
likely

**Evidence**
- No direct evidence was collected in this turn.

**Unknowns**
- No major unresolved blockers surfaced in this turn.

**Next Step**
Use the web-backed results to narrow the investigation.

**Confidence**
Low
""",
        response_style="structured",
        prompt="Search the web for the latest SOAP XXE guidance.",
        target="https://pentest-ground.com:9000",
        tool_results=[
            {
                "query": "latest SOAP XXE guidance",
                "engine": "google",
                "results": [
                    {
                        "title": "OWASP XXE Prevention Cheat Sheet",
                        "url": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                        "snippet": "Prevention guidance for XML external entity processing flaws.",
                    }
                ],
            }
        ],
    )

    assert "[search_web]" not in preserved
    assert "No direct evidence was collected in this turn." in preserved
    assert "OWASP XXE Prevention Cheat Sheet" not in preserved


def test_assistant_structured_reply_preserves_nonempty_llm_output_even_if_it_is_weak() -> None:
    preserved = assistant_agent_module.AssistantAgent._normalize_reply_for_style(
        """Summary:
You asked two things—first, the difference between observed and confirmed verdicts, and second, whether there are SOAP-related paths beyond /wsdl.

Verdict:
observed

Evidence:
- Live Check:
  - /wsdl: HTTP 404
  - /soap: HTTP 404

Unknowns:
- Are there non-standard SOAP paths?

Next Step:
Run ffuf.

Confidence:
Medium
""",
        response_style="structured",
        prompt="Check whether there are SOAP-related paths beyond /wsdl on the current target.",
        target="https://pentest-ground.com:9000",
        tool_results=[],
    )

    assert "You asked two things" in preserved
    assert "HTTP 404" in preserved


def test_assistant_blocked_payload_recommends_safe_next_command() -> None:
    payload = assistant_agent_module.AssistantAgent._blocked_tool_payload(
        tool_name="run_custom",
        parsed_args={"command": "python3", "args": ["-c", "print(1)"]},
        target="https://example.com",
        operator_mode="Investigate",
        error="Policy violation: local interpreter blocked",
    )

    assert payload["blocked"] is True
    assert "recommendation" in payload
    assert "curl -I https://example.com" == payload["recommendation"]["suggested_command"]


def test_assistant_scope_check_allows_ffuf_extension_lists_on_current_target() -> None:
    agent = assistant_agent_module.AssistantAgent()

    issue = agent._assistant_scope_issue_for_command(
        command="ffuf",
        args=[
            "-u",
            "https://pentest-ground.com:4280/FUZZ",
            "-w",
            "/server/share/wordlists/short.txt",
            "-e",
            ".wsdl,.xml,.svc,.asmx,?wsdl",
            "-k",
            "-s",
            "-t",
            "50",
        ],
        target="https://pentest-ground.com:4280",
    )

    assert issue is None


def test_assistant_normalizes_curl_write_out_args() -> None:
    normalized = assistant_agent_module.AssistantAgent._normalize_run_custom_args(
        "curl",
        [
            "-I",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "%{content_type}\\n",
            "https://pentest-ground.com:9000/?wsdl",
        ],
    )

    assert normalized == [
        "-I",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{content_type}",
        "https://pentest-ground.com:9000/?wsdl",
    ]


def test_assistant_normalizes_curl_write_out_args_with_embedded_newline_url() -> None:
    normalized = assistant_agent_module.AssistantAgent._normalize_run_custom_args(
        "curl",
        [
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}\n https://pentest-ground.com:9000/eval?input=test",
        ],
    )

    assert normalized == [
        "-sk",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "https://pentest-ground.com:9000/eval?input=test",
    ]


def test_assistant_normalizes_curl_write_out_args_with_literal_backslash_n() -> None:
    normalized = assistant_agent_module.AssistantAgent._normalize_run_custom_args(
        "curl",
        [
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}\\n",
            "https://pentest-ground.com:9000/eval?input=test",
        ],
    )

    assert normalized == [
        "-sk",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "https://pentest-ground.com:9000/eval?input=test",
    ]


def test_assistant_normalizes_curl_write_out_args_with_embedded_newline_flags_and_url() -> None:
    normalized = assistant_agent_module.AssistantAgent._normalize_run_custom_args(
        "curl",
        [
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}\n --connect-timeout 10 -m 30 -g https://pentest-ground.com:9000/eval?input=test",
        ],
    )

    assert normalized == [
        "-sk",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--connect-timeout",
        "10",
        "-m",
        "30",
        "-g",
        "https://pentest-ground.com:9000/eval?input=test",
    ]


def test_assistant_renders_run_custom_preview_without_literal_backslash_n() -> None:
    preview = assistant_agent_module.AssistantAgent._render_run_custom_preview(
        "curl",
        [
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}\\n",
            "https://pentest-ground.com:9000/eval?input=test",
        ],
    )

    assert "\\n" not in preview
    assert "https://pentest-ground.com:9000/eval?input=test" in preview


def test_assistant_scope_check_blocks_external_target_even_with_safe_binary() -> None:
    agent = assistant_agent_module.AssistantAgent()

    issue = agent._assistant_scope_issue_for_command(
        command="curl",
        args=["https://example.org/admin"],
        target="https://pentest-ground.com:4280",
    )

    assert issue is not None
    assert "current target" in issue.lower()


def test_assistant_scope_check_allows_ping_on_current_target() -> None:
    agent = assistant_agent_module.AssistantAgent()

    issue = agent._assistant_scope_issue_for_command(
        command="ping",
        args=["-c", "1", "pentest-ground.com"],
        target="https://pentest-ground.com:9000",
    )

    assert issue is None


def test_assistant_learning_signals_capture_corrections_and_false_positives() -> None:
    learning = assistant_agent_module.AssistantAgent._extract_learning_signals(
        prompt="That finding is a false positive, and that's wrong because the redirect is internal only.",
        tool_results=[
            {
                "success": True,
                "status": "false_positive",
                "title": "Open Redirect",
            }
        ],
    )

    assert learning["operator_corrections"]
    assert any("false positive" in row.lower() for row in learning["lessons_learned"])


def test_assistant_context_block_unifies_project_state_and_investigation_brief(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    dependencies_module = import_module("server.api.dependencies")
    monkeypatch.setattr(dependencies_module, "projects_store", store)

    memory_payload = asyncio.run(
        save_system_memory(
            str(tmp_path / "assistant-memory"),
            {
                "overview": "Login flow exposes a legacy admin surface.",
                "tech_stack": ["nginx", "php"],
                "verified_findings": [
                    {
                        "title": "Missing CSP",
                        "status": "real_vulnerability",
                        "claim_status": "confirmed",
                        "cited_tool_output_ids": ["tool-1"],
                    }
                ],
                "tool_observations": [
                    {"tool": "nmap", "status": "success"},
                ],
            },
        )
    )

    project = store.get_project("proj-1")
    assert project is not None
    project["findings"] = [
        {
            "id": "finding-1",
            "title": "Missing CSP",
            "description": "Content-Security-Policy header is absent.",
            "severity": "high",
            "status": "confirmed",
            "target": "https://example.com",
        }
    ]
    project["lastScan"] = {
        "scanId": "scan-1",
        "status": "completed",
        "result": {
            "targetMemory": {
                "json": memory_payload["paths"]["json"],
            }
        },
    }
    store.upsert_project(project)
    store.save_report(
        "proj-1",
        report_id="report-1",
        format="markdown",
        content="# Pentest Report\n\nConfirmed header issues.",
        metadata={"verified_findings": 1, "total_findings": 1},
    )
    store.append_scan_event_cache(
        "proj-1",
        {
            "scan_id": "scan-1",
            "event": "verified_finding_saved",
            "level": "success",
            "message": "Confirmed finding persisted",
            "timestamp": "2026-05-08T10:00:00+00:00",
            "data": {"finding_id": "finding-1"},
        },
    )

    agent = assistant_agent_module.AssistantAgent()
    context_block = agent._build_context_block(
        project_id="proj-1",
        target="https://example.com",
        target_type="web_app",
        prompt="Investigate why the header issue keeps appearing",
        context="operator_selected_tab=assistant",
        saved_context='{"hypotheses":["header issue may be global"],"unresolved_questions":["is the admin path separate?"],"verdicts":["missing csp: observed"]}',
        external_research_allowed=False,
        operator_mode="Investigate",
        execution_lane="investigation",
        response_style="structured",
        history=[],
    )

    assert "unified_project_state" in context_block
    assert "[project:finding:finding-1]" in context_block
    assert "latest_report_heading: Pentest Report" in context_block
    assert "metrics:" in context_block
    assert "investigation_brief" in context_block
    assert "step_1:" in context_block


def test_assistant_build_next_context_skips_llm_for_lightweight_meta_prompt(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()

    async def fail_chat(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("LLM compression should not run for lightweight meta prompts")

    monkeypatch.setattr(agent, "_chat_with_fallback", fail_chat)

    next_context = asyncio.run(
        agent._build_next_context(
            project_id="proj-1",
            saved_context="",
            history=[],
            prompt="who are you?",
            reply="I am Echo.",
            tool_results=[],
            target="https://example.com",
            target_type="web_app",
            execution_lane="lightweight",
            response_style="natural",
            operator_mode="Ask",
        )
    )

    assert '"operator_mode": "Ask"' in next_context
    assert '"execution_lane": "lightweight"' in next_context
    assert '"response_style": "natural"' in next_context
    assert "I am Echo." in next_context


def test_assistant_build_next_context_uses_local_first_for_simple_investigation(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()

    async def fail_chat(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Simple investigation context should stay local-first")

    monkeypatch.setattr(agent, "_chat_with_fallback", fail_chat)

    next_context = asyncio.run(
        agent._build_next_context(
            project_id="proj-1",
            saved_context="",
            history=[],
            prompt="Explain this finding",
            reply="This finding suggests a missing CSP header.",
            tool_results=[],
            target="https://example.com",
            target_type="web_app",
            execution_lane="lightweight",
            response_style="natural",
            operator_mode="Ask",
        )
    )

    assert '"response_style": "natural"' in next_context


def test_assistant_context_block_uses_minimal_grounding_for_lightweight_lane(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    dependencies_module = import_module("server.api.dependencies")
    monkeypatch.setattr(dependencies_module, "projects_store", store)

    project = store.get_project("proj-1")
    assert project is not None
    project["findings"] = [
        {"id": "finding-1", "title": "Missing CSP", "description": "Header absent.", "severity": "high", "status": "confirmed", "target": "https://example.com"}
    ]
    store.upsert_project(project)

    agent = assistant_agent_module.AssistantAgent()
    context_block = agent._build_context_block(
        project_id="proj-1",
        target="https://example.com",
        target_type="web_app",
        prompt="What can you do?",
        context="",
        saved_context="",
        external_research_allowed=False,
        operator_mode="Ask",
        execution_lane="lightweight",
        response_style="natural",
        history=[],
    )

    assert "execution_lane: lightweight" in context_block
    assert "response_style: natural" in context_block
    assert "task_runs:" not in context_block
    assert "observability:" not in context_block


def test_gemini_queue_defaults_are_retuned(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_LLM_ASSISTANT_API_PROVIDER", "gemini")
    monkeypatch.delenv("GLOBAL_LLM_QUEUE_MAX_CONCURRENT", raising=False)
    monkeypatch.delenv("GLOBAL_LLM_QUEUE_MAX_CALLS_PER_MINUTE", raising=False)

    max_concurrent, max_calls = rate_limiter_module._default_queue_limits()

    assert max_concurrent == 4
    assert max_calls == 8


def test_gemini_queue_defaults_can_use_role_resolved_provider(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_LLM_ASSISTANT_API_PROVIDER", raising=False)
    monkeypatch.delenv("GLOBAL_LLM_QUEUE_MAX_CONCURRENT", raising=False)
    monkeypatch.delenv("GLOBAL_LLM_QUEUE_MAX_CALLS_PER_MINUTE", raising=False)
    monkeypatch.setattr(
        config_agent_module,
        "get_public_agent_config",
        lambda _role: SimpleNamespace(provider="gemini"),
    )

    max_concurrent, max_calls = rate_limiter_module._default_queue_limits()

    assert max_concurrent == 4
    assert max_calls == 8


def test_global_llm_queue_singleton_uses_dynamic_defaults(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_LLM_ASSISTANT_API_PROVIDER", "gemini")
    monkeypatch.delenv("GLOBAL_LLM_QUEUE_MAX_CONCURRENT", raising=False)
    monkeypatch.delenv("GLOBAL_LLM_QUEUE_MAX_CALLS_PER_MINUTE", raising=False)
    monkeypatch.setattr(rate_limiter_module, "_global_llm_queue", None)

    queue = rate_limiter_module.get_global_llm_queue()

    assert queue._max_concurrent == 4
    assert queue._max_calls_per_minute == 8


def test_assistant_llm_config_can_target_gemini(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_LLM_ASSISTANT_API_PROVIDER", "gemini")
    monkeypatch.setenv("AGENT_LLM_ASSISTANT_MODEL", "gemini-2.5-flash")
    monkeypatch.setenv("AGENT_LLM_ASSISTANT_API_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
    monkeypatch.setenv("AGENT_LLM_ASSISTANT_API_KEY", "test-gemini-key")

    cfg = llm_module.get_public_agent_config("assistant")

    assert cfg.provider == "gemini"
    assert cfg.model == "gemini-2.5-flash"
    assert cfg.api_url == "https://generativelanguage.googleapis.com/v1beta/openai/"
    assert cfg.api_key == "test-gemini-key"


def test_prompt_guard_uses_assistant_role_config_when_global_public_config_lacks_key(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class FakeLLMClient:
        def __init__(self, config, mode="public", client_name=None):
            captured["config"] = config
            captured["mode"] = mode

        async def chat(self, *_args, **_kwargs):
            return SimpleNamespace(
                content='{"is_injection": false, "intent": "reporting", "confidence": 0.91, "reason": "ok"}'
            )

        async def close(self):
            return None

    monkeypatch.setenv("AGENT_LLM_MODE", "public")
    monkeypatch.setattr(config_agent_module, "public_llm_config", SimpleNamespace(api_key=""))
    monkeypatch.setattr(
        config_agent_module,
        "get_public_agent_config",
        lambda _role: SimpleNamespace(
            provider="gemini",
            model="gemini-2.5-flash",
            api_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            api_key="assistant-key",
            temperature=0.0,
            max_tokens=1024,
        ),
    )
    monkeypatch.setattr(llm_module, "LLMClient", FakeLLMClient)

    guard = prompt_guard_module.PromptInjectionGuard()
    result = asyncio.run(guard._classify_with_llm("Summarize the current target status."))

    assert result is not None
    assert result.classifier == "llm"
    assert captured["mode"] == "public"
    assert captured["config"].provider == "gemini"
    assert captured["config"].api_key == "assistant-key"


def test_prompt_guard_extracts_fenced_json_response() -> None:
    parsed = prompt_guard_module.PromptInjectionGuard._extract_llm_json(
        "```json\n"
        '{"is_injection": false, "intent": "reporting", "confidence": 0.93, "reason": "ok"}\n'
        "```"
    )

    assert parsed is not None
    assert parsed["is_injection"] is False
    assert parsed["intent"] == "reporting"


def test_llm_env_loader_allows_later_env_entries_to_override_earlier_ones(tmp_path) -> None:
    root_env = tmp_path / ".env"
    server_env = tmp_path / "server.env"
    root_env.write_text(
        "\n".join(
            [
                "AGENT_LLM_ASSISTANT_API_PROVIDER=groq",
                "AGENT_LLM_ASSISTANT_MODEL=llama-3.3-70b-versatile",
            ]
        ),
        encoding="utf-8",
    )
    server_env.write_text(
        "\n".join(
            [
                "AGENT_LLM_ASSISTANT_API_PROVIDER=groq",
                "AGENT_LLM_ASSISTANT_API_PROVIDER=gemini",
                "AGENT_LLM_ASSISTANT_MODEL=gemini-2.5-flash",
            ]
        ),
        encoding="utf-8",
    )

    fake_env = {"UNCHANGED": "1"}
    llm_module._load_env_file((root_env, server_env), environ=fake_env)

    assert fake_env["AGENT_LLM_ASSISTANT_API_PROVIDER"] == "gemini"
    assert fake_env["AGENT_LLM_ASSISTANT_MODEL"] == "gemini-2.5-flash"


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


def test_reset_project_runtime_state_clears_generated_project_artifacts(tmp_path) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    assert project is not None
    project.update(
        {
            "status": "running",
            "scanProgress": 82,
            "findings": [{"id": "finding-1", "title": "XSS"}],
            "copilotHistory": [{"id": "msg-1", "role": "assistant", "text": "hello"}],
            "copilotContext": "saved context",
            "copilotHistoryScope": "web_app|https://example.com",
            "copilotContextScope": "web_app|https://example.com",
            "lastScan": {"scanId": "scan-1", "status": "running"},
            "payload": {"architecture_draft": {"hosts": [{"id": "host-1"}]}},
            "agents": [{"name": "planner", "state": "running", "progress": 44, "currentTask": "plan", "lastUpdate": "now"}],
            "phases": [{"name": "Reconnaissance", "status": "active", "progress": 55, "startedAt": "now", "completedAt": ""}],
        }
    )
    store.upsert_project(project)
    store.save_report("proj-1", report_id="report-1", format="markdown", content="# Report")
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
    store.append_tool_audit_log(
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "role": "executer",
            "tool_name": "nmap",
            "full_command": "nmap -sV example.com",
        }
    )
    store.upsert_task_run(
        run_id="run-1",
        project_id="proj-1",
        task_type="report",
        scope_key="",
        status="completed",
        payload={"report_id": "report-1"},
    )
    store.add_client_message("proj-1", "client", "hello")
    share = store.create_share_link("proj-1")
    assert share["token"]

    reset = store.reset_project_runtime_state("proj-1")

    assert reset["status"] == "idle"
    assert reset["scanProgress"] == 0
    assert reset["findings"] == []
    assert reset["copilotHistory"] == []
    assert reset["copilotContext"] == ""
    assert reset["copilotHistoryScope"] == ""
    assert reset["copilotContextScope"] == ""
    assert reset["lastScan"] is None
    assert reset["payload"] is None
    assert reset["agents"][0]["state"] == "idle"
    assert reset["phases"][0]["status"] == "pending"

    reloaded = store.get_project("proj-1")
    assert reloaded is not None
    assert reloaded["status"] == "idle"
    assert reloaded["findings"] == []
    assert reloaded["payload"] is None
    assert store.list_report_status("proj-1") == {
        "markdown": False,
        "html": False,
        "pdf": False,
        "generated_at": None,
    }
    assert store.list_scan_event_cache("proj-1", limit=20) == []
    assert store.list_tool_audit_logs("proj-1", limit=20) == []
    assert store.list_task_runs("proj-1", limit=20) == []
    assert store.list_client_messages("proj-1") == []
    assert store.get_active_share_link("proj-1") is None


def test_reset_project_runtime_route_returns_clean_project(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    project = store.get_project("proj-1")
    assert project is not None
    project["status"] = "running"
    project["copilotContext"] = "saved context"
    project["payload"] = {"architecture_draft": {"hosts": [{"id": "host-1"}]}}
    store.upsert_project(project)

    monkeypatch.setattr(projects_routes, "projects_store", store)
    monkeypatch.setattr(
        projects_routes,
        "_delete_project_cache_artifacts",
        lambda project_id: {
            "project_runs_removed": 1 if project_id == "proj-1" else 0,
            "project_findings_removed": 1 if project_id == "proj-1" else 0,
        },
    )

    response = projects_routes.reset_project_runtime("proj-1")

    assert response["ok"] is True
    assert response["id"] == "proj-1"
    assert response["project"]["status"] == "idle"
    assert response["project"]["copilotContext"] == ""
    assert response["project"]["payload"] is None
    assert response["project_runs_removed"] == 1
    assert response["project_findings_removed"] == 1


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


def test_scan_observability_timeline_handles_mixed_naive_and_aware_timestamps() -> None:
    events = [
        {
            "project_id": "proj-1",
            "scan_id": "assistant-contribution",
            "timestamp": "2026-05-10T11:25:47.733042+00:00",
            "event": "perceptor_classified",
            "level": "info",
            "message": "Assistant finding added",
            "data": {},
        }
    ]
    tool_audits = [
        {
            "id": 1,
            "project_id": "proj-1",
            "scan_id": "",
            "role": "assistant",
            "tool_name": "run_custom",
            "status": "completed",
            "full_command": "nmap -p- --open -T4 -n 192.168.100.81",
            "created_at": "2026-05-10 12:14:17",
        }
    ]

    timeline = scan_observability_module.build_debug_timeline(events, tool_audits, limit=20)

    assert len(timeline) == 2
    assert timeline[0]["kind"] == "tool_audit"
    assert timeline[1]["kind"] == "scan_event"


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
    assert reloaded["status"] == "stopped"
    assert reloaded["lastScan"]["status"] == "cancelled"
    assert reloaded["lastScan"]["elapsedSeconds"] == 133
    assert reloaded["lastScan"]["finishedAt"]
    assert reloaded["lastScan"]["error"] == "Scan cancelled because the server stopped."

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


def test_route_topology_uses_password_callback_for_sudo(monkeypatch) -> None:
    recorded: list[tuple[list[str], str | None]] = []

    class FakeCallback:
        async def request_password(self, *, prompt: str, reason: str, call_id: str) -> str | None:
            assert prompt == "sudo password: "
            assert "sudo mtr" in reason
            assert "sudo nmap" in reason
            assert call_id == "route_topology_sudo"
            return "secret"

    monkeypatch.setattr(route_topology_module, "_validate_target", lambda target: (False, ""))
    monkeypatch.setattr(route_topology_module, "_parse_mtr", lambda stdout: ([], []))
    monkeypatch.setattr(route_topology_module, "_parse_nmap", lambda stdout: ([], [], [], False, []))
    monkeypatch.setattr(
        route_topology_module,
        "_analyze_path",
        lambda path_hops, boundary_threshold_ms: {
            "avg_latency": None,
            "max_latency": None,
            "worst_loss": None,
            "possible_firewalls": [],
            "boundaries": [],
        },
    )

    def fake_execute(cmd: list[str], timeout: int = 120, password: str | None = None) -> tuple[str, str, int]:
        recorded.append((cmd, password))
        return "", "permission denied", 1

    monkeypatch.setattr(route_topology_module, "_execute", fake_execute)

    token = executer_base_module._executer_callback_context.set(FakeCallback())
    try:
        route_topology_module.route_topology(target="192.168.100.81")
    finally:
        executer_base_module._executer_callback_context.reset(token)

    assert len(recorded) == 2
    for cmd, password in recorded:
        assert cmd[:5] == ["sudo", "-S", "-k", "-p", ""]
        assert password == "secret\n"
