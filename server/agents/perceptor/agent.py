"""Perceptor Agent — SSVC classification and compact risk bridge generation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from server.agents.context_window_manager import ContextWindowManager
from server.core.llm import LLMClient
from .config import (
    ACT_MIN_CVSS,
    ACT_MIN_EPSS,
    ACT_MIN_SCORE,
    ATTEND_MIN_CVSS,
    ATTEND_MIN_EPSS,
    ATTEND_MIN_SCORE,
    PERCEPTOR_CONTEXT_WINDOW_KEY,
    PERCEPTOR_CONTEXT_WINDOW_MAX_TOKENS,
    PERCEPTOR_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS,
    PERCEPTOR_MAX_INPUT_CHARS,
    PERCEPTOR_MAX_SUMMARY_CHARS,
)
from .prompts import MINIMAL_PERCEPTOR_SUMMARY_FORMAT

logger = structlog.get_logger(__name__)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)
_CVSS_RE = re.compile(r"\bcvss(?:\s*(?:v3(?:\.1)?|score|base)?)?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b", re.IGNORECASE)
_EPSS_RE = re.compile(r"\bepss\s*[:=]?\s*([0-9]*\.?[0-9]+)\s*%?", re.IGNORECASE)
_KEV_RE = re.compile(r"\b(cisa\s*kev|known\s+exploited\s+vulnerabilities?|\bkev\b)\b", re.IGNORECASE)

_EXPLOIT_SIGNAL_TERMS = (
    "remote code execution",
    "rce",
    "shell",
    "auth bypass",
    "privilege escalation",
    "sql injection",
    "sqli",
    "ssrf",
    "deserialization",
    "critical",
    "confirmed",
    "exploitable",
)


@dataclass
class PerceptorAssessment:
    """Single SSVC assessment payload."""

    ssvc: str
    score: float
    confidence: str
    summary: str
    reason: str
    signals: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ssvc": self.ssvc,
            "score": round(float(self.score), 3),
            "confidence": self.confidence,
            "summary": self.summary,
            "reason": self.reason,
            "signals": dict(self.signals),
        }


class PerceptorAgent:
    """Deterministic SSVC engine for planner/executer bridge compression."""

    def __init__(
        self,
        *,
        project_id: str | None = None,
        llm: LLMClient | None = None,
    ) -> None:
        self._context_window: ContextWindowManager | None = None
        if str(project_id or "").strip():
            self._context_window = ContextWindowManager(
                project_id=str(project_id),
                agent_key=PERCEPTOR_CONTEXT_WINDOW_KEY,
                max_tokens=PERCEPTOR_CONTEXT_WINDOW_MAX_TOKENS,
                llm=llm,
            )

    def reset_context_window_for_cycle(self) -> None:
        """Clear context window entries to start fresh for this cycle."""
        if self._context_window is not None:
            self._context_window._entries = []
            self._context_window._compression_count = 0
            logger.info(
                "perceptor_context_reset",
                reason="cycle_start_fresh_context",
            )

    async def clear_context_window(self) -> None:
        """Clear persisted and in-memory context window state for this agent."""
        if self._context_window is None:
            return
        await self._context_window.clear()
        self._context_window._entries = []
        self._context_window._compression_count = 0
        logger.info(
            "perceptor_context_cleared",
            reason="phase_transition_fresh_context",
        )

    async def assess_text(
        self,
        text: str,
        *,
        scenario: dict[str, Any] | None = None,
        tool_name: str = "",
        asset_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        raw = str(text or "")[:PERCEPTOR_MAX_INPUT_CHARS]
        if self._context_window is not None:
            await self._context_window.ensure_token_budget(
                threshold_tokens=PERCEPTOR_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS
            )
            await self._context_window.record(
                kind="run_input",
                role="user",
                content=raw,
                metadata={
                    "agent": "perceptor",
                    "tool": tool_name,
                    "scenario_task": str((scenario or {}).get("task", ""))[:120],
                },
            )

        parsed = self._parse_signals(raw)
        asset_score = self._asset_score(asset_context)
        decision, score, reason = self._ssvc_decision(parsed, asset_score)
        confidence = self._confidence(parsed)
        finding_type = "vulnerability" if decision in {"ACT", "ATTEND"} else "info"

        summary = MINIMAL_PERCEPTOR_SUMMARY_FORMAT.format(
            finding_type=finding_type,
            ssvc=decision,
            score=score,
            confidence=confidence,
            cvss=(f"{parsed['cvss']:.1f}" if parsed["cvss"] is not None else "na"),
            epss=(f"{parsed['epss']:.3f}" if parsed["epss"] is not None else "na"),
            kev=("yes" if parsed["kev"] else "no"),
            cve_count=len(parsed["cves"]),
            summary=(
                f"ssvc={decision} score={float(score):.2f} "
                f"cvss={(f'{parsed['cvss']:.1f}' if parsed['cvss'] is not None else 'na')} "
                f"epss={(f'{parsed['epss']:.3f}' if parsed['epss'] is not None else 'na')} "
                f"kev={'yes' if parsed['kev'] else 'no'} cves={len(parsed['cves'])} "
                f"reason={reason}"
            ),
            reason=reason,
        )
        summary = summary[:PERCEPTOR_MAX_SUMMARY_CHARS]

        assessment = PerceptorAssessment(
            ssvc=decision,
            score=score,
            confidence=confidence,
            summary=summary,
            reason=reason,
            signals=parsed,
        )

        if self._context_window is not None:
            await self._context_window.record(
                kind="run_result",
                role="assistant",
                content=summary,
                metadata={
                    "agent": "perceptor",
                    "finding_type": finding_type,
                    "ssvc": decision,
                    "score": round(score, 3),
                    "tool": tool_name,
                },
            )

        payload = assessment.to_dict()
        payload["finding_type"] = finding_type
        return payload

    async def assess_tool_results(
        self,
        *,
        scenario: dict[str, Any],
        tool_results: list[dict[str, Any]],
        asset_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        evaluations: list[dict[str, Any]] = []
        for item in tool_results:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("name", ""))
            raw_result = item.get("result", "")
            if not isinstance(raw_result, str):
                raw_result = json.dumps(raw_result, ensure_ascii=True)
            per_tool = await self.assess_text(
                raw_result,
                scenario=scenario,
                tool_name=tool_name,
                asset_context=asset_context,
            )
            per_tool["tool"] = tool_name
            evaluations.append(per_tool)

        overall = self._overall_assessment(evaluations)
        return {
            "scenario": {
                "task": str(scenario.get("task", "")),
                "agent": str(scenario.get("agent", "")),
                "priority": int(scenario.get("priority", 3) or 3),
            },
            "finding_type": str(overall.get("finding_type", "info")),
            "overall": overall,
            "per_tool": evaluations,
            "compact_summary": self._compact_bridge_line(scenario=scenario, overall=overall),
        }

    def _parse_signals(self, text: str) -> dict[str, Any]:
        lowered = text.lower()

        cves = sorted({m.upper() for m in _CVE_RE.findall(text)})
        cwes = sorted({m.upper() for m in _CWE_RE.findall(text)})

        cvss: float | None = None
        for m in _CVSS_RE.findall(text):
            try:
                val = float(m)
            except ValueError:
                continue
            if 0.0 <= val <= 10.0:
                cvss = max(cvss or 0.0, val)

        epss: float | None = None
        for m in _EPSS_RE.findall(text):
            try:
                val = float(m)
            except ValueError:
                continue
            if val > 1.0:
                val = val / 100.0
            if 0.0 <= val <= 1.0:
                epss = max(epss or 0.0, val)

        kev = bool(_KEV_RE.search(text))
        exploit_signal = any(term in lowered for term in _EXPLOIT_SIGNAL_TERMS)

        return {
            "cves": cves,
            "cwes": cwes,
            "cvss": cvss,
            "epss": epss,
            "kev": kev,
            "exploit_signal": exploit_signal,
        }

    def _asset_score(self, asset_context: dict[str, Any] | None) -> float:
        if not isinstance(asset_context, dict):
            return 0.0
        criticality = str(asset_context.get("criticality", "")).strip().lower()
        mapping = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "info": 0.0,
        }
        score = mapping.get(criticality, 0.0)
        if bool(asset_context.get("internet_exposed", False)):
            score = max(score, 0.7)
        return min(1.0, score)

    def _ssvc_decision(self, parsed: dict[str, Any], asset_score: float) -> tuple[str, float, str]:
        cvss = parsed.get("cvss")
        epss = parsed.get("epss")
        kev = bool(parsed.get("kev"))
        exploit_signal = bool(parsed.get("exploit_signal"))

        cvss_norm = (float(cvss) / 10.0) if isinstance(cvss, (int, float)) else 0.0
        epss_norm = float(epss) if isinstance(epss, (int, float)) else 0.0
        kev_norm = 1.0 if kev else 0.0
        exploit_norm = 1.0 if exploit_signal else 0.0

        score = (
            0.42 * cvss_norm
            + 0.25 * epss_norm
            + 0.20 * kev_norm
            + 0.08 * asset_score
            + 0.05 * exploit_norm
        )

        if kev:
            return "ACT", min(1.0, score + 0.2), "KEV evidence present"

        if isinstance(cvss, (int, float)) and float(cvss) >= ACT_MIN_CVSS:
            return "ACT", min(1.0, score + 0.1), "CVSS critical"

        if (
            isinstance(cvss, (int, float))
            and isinstance(epss, (int, float))
            and float(cvss) >= 8.0
            and float(epss) >= ACT_MIN_EPSS
        ):
            return "ACT", min(1.0, score + 0.08), "High CVSS + elevated EPSS"

        if score >= ACT_MIN_SCORE:
            return "ACT", score, "Composite risk score high"

        if (
            (isinstance(cvss, (int, float)) and float(cvss) >= ATTEND_MIN_CVSS)
            or (isinstance(epss, (int, float)) and float(epss) >= ATTEND_MIN_EPSS)
            or exploit_signal
            or asset_score >= 0.8
            or score >= ATTEND_MIN_SCORE
        ):
            return "ATTEND", score, "Requires analyst attention"

        return "TRACK", score, "Track for trend/correlation"

    def _confidence(self, parsed: dict[str, Any]) -> str:
        indicators = 0
        if parsed.get("cves"):
            indicators += 1
        if parsed.get("cwes"):
            indicators += 1
        if parsed.get("cvss") is not None:
            indicators += 1
        if parsed.get("epss") is not None:
            indicators += 1
        if parsed.get("kev"):
            indicators += 1
        if indicators >= 4:
            return "high"
        if indicators >= 2:
            return "medium"
        return "low"

    def _overall_assessment(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        if not entries:
            return {
                "ssvc": "TRACK",
                "score": 0.0,
                "confidence": "low",
                "finding_type": "info",
                "summary": "ssvc=TRACK score=0.00 confidence=low cvss=na epss=na kev=no cves=0 reason=no tool evidence",
                "reason": "no tool evidence",
            }

        rank = {"ACT": 3, "ATTEND": 2, "TRACK": 1}
        best = sorted(
            entries,
            key=lambda item: (
                rank.get(str(item.get("ssvc", "TRACK")), 0),
                float(item.get("score", 0.0) or 0.0),
            ),
            reverse=True,
        )[0]
        return {
            "ssvc": str(best.get("ssvc", "TRACK")),
            "score": float(best.get("score", 0.0) or 0.0),
            "confidence": str(best.get("confidence", "low")),
            "finding_type": str(best.get("finding_type", "info")),
            "summary": str(best.get("summary", "")),
            "reason": str(best.get("reason", "")),
        }

    def _compact_bridge_line(self, *, scenario: dict[str, Any], overall: dict[str, Any]) -> str:
        task = str(scenario.get("task", "")).strip()
        if len(task) > 110:
            task = task[:107] + "..."
        return (
            f"scenario={task!r} "
            f"agent={str(scenario.get('agent', ''))} "
            f"priority={int(scenario.get('priority', 3) or 3)} "
            f"{str(overall.get('summary', ''))}"
        )[:PERCEPTOR_MAX_SUMMARY_CHARS]

    async def close(self) -> None:
        return None

    async def __aenter__(self) -> PerceptorAgent:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
