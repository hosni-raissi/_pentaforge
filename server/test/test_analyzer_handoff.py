from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from server.agents.analyzer.agent import AnalyzerAgent


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
