"""Report executer agent."""

from __future__ import annotations

from server.agents.executer.base import BaseExecuterAgent, ExecuterCallback
from server.config.agent import LocalLLMConfig, PublicLLMConfig

from .config import (
    LLM_CALL_TIMEOUT_SECONDS,
    MAX_TOOL_ROUNDS,
    REPORT_CONTEXT_WINDOW_MAX_TOKENS,
)
from .context_window import REPORT_CONTEXT_WINDOW_KEY
from .prompts import SYSTEM_PROMPT
from .tools import ALL_REPORT_TOOLS


class ReportExecuterAgent(BaseExecuterAgent):
    """
    Transforms verified findings into professional, audit-ready security reports.

    Capabilities:
    - Calculate CVSS 3.1 scores with full vector strings
    - Map findings to OWASP Top 10 2021, MITRE ATT&CK, and CWE
    - Generate LLM-authored remediation guidance with code examples
    - Produce PDF, HTML, SARIF, and JSON report outputs
    - Create executive summaries with risk heat maps

    Report outputs include:
    - JSON: Structured data for programmatic access
    - HTML: Interactive web reports with charts
    - SARIF: CI/CD and IDE integration format
    - PDF: Professional print-ready documents
    """

    def __init__(
        self,
        *,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        project_id: str | None = None,
    ) -> None:
        super().__init__(
            role="report",
            system_prompt=SYSTEM_PROMPT,
            tools=ALL_REPORT_TOOLS,
            max_tool_rounds=MAX_TOOL_ROUNDS,
            call_timeout_seconds=LLM_CALL_TIMEOUT_SECONDS,
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
            project_id=project_id,
            context_window_key=REPORT_CONTEXT_WINDOW_KEY,
            context_window_max_tokens=REPORT_CONTEXT_WINDOW_MAX_TOKENS,
        )
