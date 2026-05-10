from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import json
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
assistant_agent_module = import_module("server.agents.assistant.agent")
llm_module = import_module("server.core.llm")
rate_limiter_module = import_module("server.agents.rate_limiter")
privacy_gate_node_module = import_module("server.layers.PrivacyGate.node")


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
            context="project_id=proj-1",
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


def test_assistant_resolves_direct_ftp_auth_attempt_from_recent_ftp_context() -> None:
    resolved = assistant_agent_module.AssistantAgent._resolve_direct_ftp_auth_attempt(
        "try login msfadmin and password msfadmin",
        target="192.168.100.81",
        history=[
            {
                "role": "assistant",
                "text": "Earlier we checked FTP on port 21.",
                "toolLogs": [
                    {"tool": "run_custom", "input": "nmap -sV -p21 192.168.100.81", "status": "done"}
                ],
            }
        ],
    )

    assert resolved is not None
    assert resolved["command"] == "curl"
    assert resolved["args"] == ["-u", "msfadmin:msfadmin", "ftp://192.168.100.81/"]


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


def test_assistant_stream_answer_uses_direct_ftp_auth_path_for_exact_login_prompt(monkeypatch) -> None:
    agent = assistant_agent_module.AssistantAgent()

    async def fail_chat(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("LLM should not run for the direct FTP auth shortcut")

    async def fake_execute_run_custom(args: dict[str, Any], *, target: str, project_id: str | None = None) -> dict[str, Any]:
        assert args["command"] == "curl"
        assert args["args"] == ["-u", "msfadmin:msfadmin", "ftp://192.168.100.81/"]
        raw_payload = {
            "success": True,
            "command": "curl",
            "args": list(args["args"]),
            "reason": args["reason"],
            "full_command": "curl -u msfadmin:msfadmin ftp://192.168.100.81/",
            "stdout": "drwxr-xr-x 2 root root 4096 Jan 01 00:00 pub\n",
            "stderr": "",
            "return_code": 0,
            "execution_time": 0.42,
            "logged": True,
        }
        return agent._sanitize_run_custom_result_for_display(raw_payload)

    async def fake_build_next_context(**_kwargs: Any) -> str:
        return '{"execution_lane": "investigation"}'

    monkeypatch.setattr(agent, "_chat_with_fallback", fail_chat)
    monkeypatch.setattr(agent, "_execute_run_custom", fake_execute_run_custom)
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
    tool_start = next(event for event in events if event["type"] == "tool_start")
    tool_output = next(event for event in events if event["type"] == "tool_output")
    reply_event = next(event for event in events if event["type"] == "reply")

    assert "curl -u 'msfadmin:****' ftp://192.168.100.81/" == tool_start["data"]["input"]
    assert "msfadmin:msfadmin" not in str(tool_output["data"]["output"])
    assert "msfadmin:****" in str(tool_output["data"]["output"])
    assert "msfadmin:msfadmin" not in reply_event["data"]["text"]
    assert "msfadmin:****" in reply_event["data"]["text"]
    assert "pub" in reply_event["data"]["text"]


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

    monkeypatch.setattr(agent, "compress_working_memory", fake_compress_working_memory)
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
