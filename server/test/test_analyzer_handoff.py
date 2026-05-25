from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

from server.agents.analyzer.agent import AnalyzerAgent
from server.agents.analyzer.parsers import normalize_tool_output
from server.agents.executer.base import ExecuterResult
from server.utils.cvss import calculate_cvss, enrich_payload_with_cvss


@dataclass
class _FakeVerifyResult:
    verdict: str = "false_positive"
    summary: str = "No issue reproduced."
    confidence: float = 0.25
    poc: str = ""
    tool_results: list[dict] = field(default_factory=list)


class _CaptureVerifyRunner:
    def __init__(self) -> None:
        self.last_message = ""

    async def run(self, user_message: str):
        self.last_message = user_message
        return _FakeVerifyResult()


class _CaptureStructuredVerifyRunner:
    def __init__(self) -> None:
        self.last_message = ""

    async def run(self, user_message: str):
        self.last_message = user_message
        return ExecuterResult(
            status="real_vulnerability",
            summary="Unauthenticated SSRF reached internal metadata.",
            confidence=0.95,
            raw_payload={
                "verdict": "real_vulnerability",
                "summary": "Unauthenticated SSRF reached internal metadata.",
                "confidence": 0.95,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            },
        )


def test_analyzer_verify_packet_includes_executor_command_history() -> None:
    analyzer = AnalyzerAgent()
    capture = _CaptureVerifyRunner()
    analyzer._verify = capture  # type: ignore[assignment]

    candidate = {
        "idx": 1,
        "assessment": {"finding_type": "vulnerability", "overall": {"ssvc": "ATTEND"}},
        "row": {
            "scenario": {"task": "Review accessible static documentation"},
            "result": {
                "tool_results": [
                    {
                        "name": "run_custom",
                        "args": {"command": "curl -i -sS https://pentest-ground.com:4280/compose.yml"},
                        "result": "HTTP/1.1 404 Not Found",
                    },
                    {
                        "name": "run_custom",
                        "args": {
                            "command": "feroxbuster --url https://pentest-ground.com:4280 --wordlist files.txt --json"
                        },
                        "result": '{"type":"response","status":404}',
                    },
                ]
            },
        },
        "scenario": {
            "task": "Review accessible static documentation",
            "agent": "recon",
            "priority": 2,
            "evidence_tier": "observed",
            "confidence_label": "medium",
            "prerequisites": ["route_observed"],
            "evidence_basis": ["/compose.yml"],
        },
        "row_result": {
            "tool_results": [
                {
                    "name": "run_custom",
                    "args": {"command": "curl -i -sS https://pentest-ground.com:4280/compose.yml"},
                    "result": "HTTP/1.1 404 Not Found",
                },
                {
                    "name": "run_custom",
                    "args": {
                        "command": "feroxbuster --url https://pentest-ground.com:4280 --wordlist files.txt --json"
                    },
                    "result": '{"type":"response","status":404}',
                },
            ]
        },
        "compact_summary": "Potential exposed static documentation or config file.",
        "normalized_outputs": [],
    }

    result = asyncio.run(
        analyzer.verify(
            target="https://pentest-ground.com:4280",
            target_type="web_app",
            scope="web app",
            candidate=candidate,
        )
    )

    assert "Executor command history:" in capture.last_message
    assert "Scenario evidence metadata:" in capture.last_message
    assert "evidence_tier=observed" in capture.last_message
    assert "confidence_label=medium" in capture.last_message
    assert "curl -i -sS https://pentest-ground.com:4280/compose.yml" in capture.last_message
    assert "feroxbuster --url https://pentest-ground.com:4280 --wordlist files.txt --json" in capture.last_message
    assert result["evidence"]["executor_commands"] == [
        "curl -i -sS https://pentest-ground.com:4280/compose.yml",
        "feroxbuster --url https://pentest-ground.com:4280 --wordlist files.txt --json",
    ]


def test_analyzer_tool_split_keeps_screenshots_for_retest_only() -> None:
    analyzer = AnalyzerAgent()

    verify_tools = set(analyzer._verify._tools.keys())  # type: ignore[attr-defined]
    poc_tools = set(analyzer._poc._tools.keys())  # type: ignore[attr-defined]

    assert "capture_screenshot" not in verify_tools
    assert "annotate_screenshot" not in verify_tools
    assert "analyze_screenshot_with_vision" not in verify_tools

    assert "capture_screenshot" in poc_tools
    assert "annotate_screenshot" in poc_tools
    assert "analyze_screenshot_with_vision" in poc_tools


def test_analyzer_run_custom_summary_prefers_generic_observations() -> None:
    analyzer = AnalyzerAgent()
    raw_result = json.dumps(
        {
            "command": "nmap",
            "observations": [
                "Open port 80/tcp on target",
                "Service banner: Apache/2.4.7",
            ],
            "stdout": "80/tcp open http Apache 2.4.7",
        }
    )

    summary = analyzer._tool_findings_summary(  # type: ignore[attr-defined]
        tool_name="run_custom",
        raw_result=raw_result,
        normalized=normalize_tool_output("run_custom", raw_result),
        tool_args={"command": "nmap", "reason": "Port scan"},
    )

    assert "Open port 80/tcp on target" in summary
    assert "Service banner: Apache/2.4.7" in summary
    assert "Port scan" not in summary


def test_calculate_cvss_matches_expected_score_and_severity() -> None:
    result = calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")

    assert result == {
        "score": 10.0,
        "severity": "Critical",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    }


def test_analyzer_verify_preserves_cvss_vector_from_llm_payload() -> None:
    analyzer = AnalyzerAgent()
    capture = _CaptureStructuredVerifyRunner()
    analyzer._verify = capture  # type: ignore[assignment]

    candidate = {
        "idx": 7,
        "assessment": {"finding_type": "vulnerability", "overall": {"ssvc": "ACT"}},
        "row": {
            "scenario": {"task": "Confirm SSRF against metadata endpoint"},
            "result": {"tool_results": []},
        },
        "scenario": {
            "task": "Confirm SSRF against metadata endpoint",
            "agent": "exploit",
            "priority": 2,
            "endpoint": "https://example.com/fetch?url=",
            "vulnerability_type": "ssrf",
            "evidence_tier": "observed",
            "confidence_label": "high",
            "prerequisites": [],
            "evidence_basis": ["metadata response"],
        },
        "row_result": {"tool_results": []},
        "compact_summary": "Potential SSRF against metadata endpoint.",
        "normalized_outputs": [],
    }

    result = asyncio.run(
        analyzer.verify(
            target="https://example.com",
            target_type="web_app",
            scope="web app",
            candidate=candidate,
        )
    )

    assert result["cvss_score"] == 10.0
    assert result["cvss_severity"] == "critical"
    assert result["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert result["evidence"]["cvss_score"] == 10.0
    assert result["evidence"]["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def test_enrich_payload_with_cvss_infers_debugger_vector_when_missing() -> None:
    payload = enrich_payload_with_cvss(
        {
            "title": "Unauthenticated Werkzeug Debugger Enabling Arbitrary Code Execution",
            "status": "verified",
            "severity": "high",
        }
    )

    assert payload["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert payload["cvss_score"] == 10.0
    assert payload["cvss_severity"] == "critical"


def test_enrich_payload_with_cvss_infers_session_fixation_vector_when_missing() -> None:
    payload = enrich_payload_with_cvss(
        {
            "title": "Session Fixation with Weak Cookie Flags",
            "status": "verified",
            "severity": "high",
        }
    )

    assert payload["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
    assert payload["cvss_score"] == 8.1
    assert payload["cvss_severity"] == "high"
