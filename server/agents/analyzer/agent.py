"""Analyzer agent: classify -> verify -> PoC."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from server.agents.executer.base import (
    BaseExecuterAgent,
    ExecuterCallback,
    ExecuterResult,
)
from server.app.scan.verification import VerificationTier, VERIFICATION_PLAYBOOKS, classify_evidence
from server.config.agent import LocalLLMConfig, PublicLLMConfig
from server.utils.cvss import enrich_payload_with_cvss

from .config import (
    ACT_MIN_CVSS,
    ACT_MIN_EPSS,
    ACT_MIN_SCORE,
    ANALYZER_DEFAULT_VERDICT,
    ANALYZER_HITL_DECISIONS,
    ANALYZER_LLM_CALL_TIMEOUT_SECONDS,
    ANALYZER_MAX_INPUT_CHARS,
    ANALYZER_MAX_NORMALIZED_EVIDENCE_ITEMS,
    ANALYZER_MAX_SUMMARY_CHARS,
    ANALYZER_MAX_TOOL_CALLS_PER_ROUND,
    ANALYZER_MAX_TOOL_ROUNDS,
    ATTEND_MIN_CVSS,
    ATTEND_MIN_EPSS,
    ATTEND_MIN_SCORE,
)
from .oob_classifier import build_oob_assessment, build_oob_verification_payload
from .parsers import normalize_tool_output, summarize_normalized_outputs
from .policy import build_analyzer_packet
from .prompts import ANALYZER_POC_PROMPT, ANALYZER_SYSTEM_PROMPT, MINIMAL_ANALYZER_SUMMARY_FORMAT
from .tools import POC_ANALYZER_TOOLS, VERIFY_ANALYZER_TOOLS

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


class _AnalyzerVerifyRunner(BaseExecuterAgent):
    def __init__(
        self,
        *,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        project_id: str | None = None,
        project_cache_dir: str | None = None,
    ) -> None:
        super().__init__(
            role="verify",
            system_prompt=ANALYZER_SYSTEM_PROMPT,
            tools=VERIFY_ANALYZER_TOOLS,
            max_tool_rounds=ANALYZER_MAX_TOOL_ROUNDS,
            max_tool_calls_per_round=ANALYZER_MAX_TOOL_CALLS_PER_ROUND,
            call_timeout_seconds=ANALYZER_LLM_CALL_TIMEOUT_SECONDS,
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
            project_id=project_id,
            project_cache_dir=project_cache_dir,
        )

    async def run(self, user_message: str) -> ExecuterResult:
        context_block = "Project memory system is authoritative for prior findings; no legacy context window is used."
        packet = build_analyzer_packet(
            scenario_and_target=user_message,
            context_block=context_block,
            available_tools=sorted(self._tools.keys()),
            mode="verification",
        )
        return await super().run(packet)


class _AnalyzerPocRunner(BaseExecuterAgent):
    def __init__(
        self,
        *,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        project_id: str | None = None,
        project_cache_dir: str | None = None,
    ) -> None:
        super().__init__(
            role="retest",
            system_prompt=ANALYZER_POC_PROMPT,
            tools=POC_ANALYZER_TOOLS,
            max_tool_rounds=ANALYZER_MAX_TOOL_ROUNDS,
            max_tool_calls_per_round=ANALYZER_MAX_TOOL_CALLS_PER_ROUND,
            call_timeout_seconds=ANALYZER_LLM_CALL_TIMEOUT_SECONDS,
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
            project_id=project_id,
            project_cache_dir=project_cache_dir,
        )

    async def run(self, user_message: str) -> ExecuterResult:
        context_block = "Project memory system is authoritative for prior findings; no legacy context window is used."
        packet = build_analyzer_packet(
            scenario_and_target=user_message,
            context_block=context_block,
            available_tools=sorted(self._tools.keys()),
            mode="poc",
        )
        return await super().run(packet)


@dataclass
class AnalyzerAssessment:
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


@dataclass
class AnalyzerCandidate:
    idx: int
    assessment: dict[str, Any]
    row: dict[str, Any]
    scenario: dict[str, Any]
    row_result: dict[str, Any]
    compact_summary: str
    normalized_outputs: list[dict[str, Any]] = field(default_factory=list)


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        clean = str(value or "").strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        ordered.append(clean)
    return ordered


class AnalyzerAgent:
    """Self-contained classification, verification, and PoC agent."""

    def __init__(
        self,
        *,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        project_id: str | None = None,
        project_cache_dir: str | None = None,
    ) -> None:
        self._verify = _AnalyzerVerifyRunner(
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
            project_id=project_id,
            project_cache_dir=project_cache_dir,
        )
        self._poc = _AnalyzerPocRunner(
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
            project_id=project_id,
            project_cache_dir=project_cache_dir,
        )

    def reset_context_window_for_cycle(self) -> None:
        self._verify.reset_context_window_for_cycle()
        self._poc.reset_context_window_for_cycle()

    async def clear_context_window(self) -> None:
        await self._verify.clear_context_window()
        await self._poc.clear_context_window()

    async def close(self) -> None:
        await self._verify.close()
        await self._poc.close()

    async def assess_text(
        self,
        text: str,
        *,
        scenario: dict[str, Any] | None = None,
        tool_name: str = "",
        asset_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        raw = str(text or "")[:ANALYZER_MAX_INPUT_CHARS]
        parsed = self._parse_signals(raw)
        asset_score = self._asset_score(asset_context)
        decision, score, reason = self._ssvc_decision(parsed, asset_score)
        confidence = self._confidence(parsed)
        finding_type = "vulnerability" if decision in {"ACT", "ATTEND"} else "info"
        cvss_val = f"{parsed['cvss']:.1f}" if parsed.get('cvss') is not None else "na"
        epss_val = f"{parsed['epss']:.3f}" if parsed.get('epss') is not None else "na"
        summary = MINIMAL_ANALYZER_SUMMARY_FORMAT.format(
            finding_type=finding_type,
            confidence=confidence,
            summary=(
                f"ssvc={decision} score={float(score):.2f} "
                f"cvss={cvss_val} epss={epss_val} "
                f"kev={'yes' if parsed['kev'] else 'no'} cves={len(parsed['cves'])} "
                f"reason={reason}"
            ),
        )[:ANALYZER_MAX_SUMMARY_CHARS]
        assessment = AnalyzerAssessment(
            ssvc=decision,
            score=score,
            confidence=confidence,
            summary=summary,
            reason=reason,
            signals=parsed,
        ).to_dict()
        assessment["finding_type"] = finding_type
        return assessment

    async def assess_tool_results(
        self,
        *,
        scenario: dict[str, Any],
        tool_results: list[dict[str, Any]],
        asset_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        evaluations: list[dict[str, Any]] = []
        normalized_outputs: list[dict[str, Any]] = []
        for item in tool_results:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("name", ""))
            raw_result = item.get("result", "")
            parsed_raw_result = self._parse_tool_result_payload(raw_result)
            if self._is_confirmed_oob_result(parsed_raw_result):
                parsed_raw_result.setdefault("tool_name", tool_name)
                return build_oob_assessment(
                    tool_name=tool_name,
                    raw_result=parsed_raw_result,
                    scenario=scenario if isinstance(scenario, dict) else {},
                )
            if not isinstance(raw_result, str):
                raw_result = json.dumps(raw_result, ensure_ascii=True)
            normalized = normalize_tool_output(tool_name, raw_result)
            normalized_outputs.append(normalized)
            normalized_summary_text = self._normalized_entry_text(normalized)
            per_tool = await self.assess_text(
                f"{normalized_summary_text}\n\n{raw_result[:2400]}",
                scenario=scenario,
                tool_name=tool_name,
                asset_context=asset_context,
            )
            per_tool["tool"] = tool_name
            per_tool["normalized"] = normalized
            evaluations.append(per_tool)

        overall = self._overall_assessment(evaluations)
        scenario_reports = self._build_scenario_reports(
            scenario=scenario if isinstance(scenario, dict) else {},
            tool_results=tool_results if isinstance(tool_results, list) else [],
            normalized_outputs=normalized_outputs,
            row_summary="",
        )
        return {
            "scenario": {
                "task": str(scenario.get("task", "")),
                "agent": str(scenario.get("agent", "")),
                "priority": int(scenario.get("priority", 3) or 3),
            },
            "finding_type": str(overall.get("finding_type", "info")),
            "overall": overall,
            "per_tool": evaluations,
            "normalized_outputs": normalized_outputs[:ANALYZER_MAX_NORMALIZED_EVIDENCE_ITEMS],
            "normalized_summary": summarize_normalized_outputs(normalized_outputs),
            "compact_summary": self._compact_bridge_line(scenario=scenario, overall=overall),
            "scenario_reports": scenario_reports,
            "agent_markdown": self._build_agent_markdown(
                scenario=scenario if isinstance(scenario, dict) else {},
                scenario_reports=scenario_reports,
                row_summary="",
            ),
        }

    async def classify(
        self,
        *,
        idx: int,
        row: dict[str, Any],
        target_type: str,
    ) -> AnalyzerCandidate:
        row_result = row.get("result", {}) if isinstance(row, dict) else {}
        scenario = row.get("scenario", {}) if isinstance(row, dict) else {}
        tool_results = (
            row_result.get("tool_results", [])
            if isinstance(row_result, dict)
            else []
        )
        assessment = await self.assess_tool_results(
            scenario=scenario if isinstance(scenario, dict) else {},
            tool_results=tool_results if isinstance(tool_results, list) else [],
            asset_context={
                "criticality": (
                    "high"
                    if int((scenario or {}).get("priority", 3) or 3) <= 2
                    else "medium"
                ),
                "internet_exposed": target_type in {"web_app", "api"},
            },
        )
        execution_summary = (
            str(row_result.get("summary", "")).strip()
            if isinstance(row_result, dict)
            else ""
        )
        scenario_reports = self._build_scenario_reports(
            scenario=scenario if isinstance(scenario, dict) else {},
            tool_results=tool_results if isinstance(tool_results, list) else [],
            normalized_outputs=(
                assessment.get("normalized_outputs", [])
                if isinstance(assessment.get("normalized_outputs"), list)
                else []
            ),
            row_summary=execution_summary,
        )
        assessment["scenario_reports"] = scenario_reports
        assessment["agent_markdown"] = self._build_agent_markdown(
            scenario=scenario if isinstance(scenario, dict) else {},
            scenario_reports=scenario_reports,
            row_summary=execution_summary,
        )
        return AnalyzerCandidate(
            idx=idx,
            assessment=assessment,
            row=row,
            scenario=scenario if isinstance(scenario, dict) else {},
            row_result=row_result if isinstance(row_result, dict) else {},
            compact_summary=str(assessment.get("compact_summary", "")).strip(),
            normalized_outputs=(
                assessment.get("normalized_outputs", [])
                if isinstance(assessment.get("normalized_outputs"), list)
                else []
            ),
        )

    async def verify(
        self,
        *,
        target: str,
        target_type: str,
        scope: str,
        candidate: Any,
    ) -> dict[str, Any]:
        prepared = self._normalize_candidate(candidate)
        confirmed_oob_result = self._find_confirmed_oob_result(prepared.row_result.get("tool_results", []))
        if confirmed_oob_result is not None:
            return build_oob_verification_payload(prepared, confirmed_oob_result)
        executor_history = self._executor_history_block(prepared.row_result.get("tool_results", []))
        verify_message = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n"
            f"Original scenario: {json.dumps(prepared.scenario, ensure_ascii=True)}\n\n"
            "Scenario evidence metadata:\n"
            f"evidence_tier={str(prepared.scenario.get('evidence_tier', '')).strip() or 'unknown'}\n"
            f"confidence_label={str(prepared.scenario.get('confidence_label', '')).strip() or 'unknown'}\n"
            f"prerequisites={json.dumps(prepared.scenario.get('prerequisites', []), ensure_ascii=True)}\n"
            f"evidence_basis={json.dumps(prepared.scenario.get('evidence_basis', []), ensure_ascii=True)}\n\n"
            "Normalized parser output:\n"
            f"{self._normalized_outputs_block(prepared.normalized_outputs)}\n\n"
            "Executor command history:\n"
            f"{executor_history}\n\n"
            "Finding to verify:\n"
            f"{prepared.compact_summary}\n\n"
            "Execution row:\n"
            f"{json.dumps(prepared.row, ensure_ascii=True)}"
        )
        verify_result = await self._verify.run(verify_message)
        data = asdict(verify_result) if hasattr(verify_result, "__dataclass_fields__") else verify_result
        if isinstance(data, dict):
            raw_payload = data.get("raw_payload", {})
            if isinstance(raw_payload, dict) and raw_payload:
                merged = dict(raw_payload)
                merged.update(data)
                data = merged
            data = enrich_payload_with_cvss(data, prepared.scenario, prepared.row_result)
        return self._finalize_verification_payload(
            candidate=prepared,
            verify_data=data if isinstance(data, dict) else {},
        )

    async def build_poc(
        self,
        *,
        target: str,
        target_type: str,
        scope: str,
        item: dict[str, Any],
    ) -> dict[str, Any]:
        scenario = item.get("scenario", {}) if isinstance(item.get("scenario"), dict) else {}
        verify_summary = str(item.get("verify_summary", "")).strip()
        verify_data = item.get("verify_data", {}) if isinstance(item.get("verify_data"), dict) else {}
        poc_message = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"Scope: {scope}\n\n"
            "VERIFIED VULNERABILITY - Build detailed PoC:\n"
            f"{verify_summary}\n\n"
            f"Original scenario: {json.dumps(scenario, ensure_ascii=True)}\n\n"
            "Verification evidence:\n"
            f"{json.dumps(verify_data.get('evidence', {}), ensure_ascii=True)}\n\n"
            "PoC Requirements:\n"
            "1. Types of Evidence to Capture:\n"
            "   - Visual Evidence: Screenshots (Initial, Malicious input, Exploitation), UI State, Error Messages, URL Bar, Network Traffic, Console Output.\n"
            "   - Programmatic Evidence: Request/Response Pairs, Payloads, System State, Timing.\n"
            "2. Best Practices:\n"
            "   - Capture BEFORE and AFTER exploitation.\n"
            "   - Include precise timestamps.\n"
            "   - Annotate screenshots with highlights or arrows.\n"
            "3. Format:\n"
            "   - Return a structured JSON object matching the Finding schema requirements specified in the system prompt."
        )
        poc_result = await self._poc.run(poc_message)
        data = asdict(poc_result) if hasattr(poc_result, "__dataclass_fields__") else poc_result
        if isinstance(data, dict):
            raw_payload = data.get("raw_payload", {})
            if isinstance(raw_payload, dict) and raw_payload:
                merged = dict(raw_payload)
                merged.update(data)
                data = merged

            # Ensure mandatory fields for orchestrator/memory
            data.setdefault("verdict", "real_vulnerability")
            data.setdefault("summary", str(data.get("summary", "PoC generated")).strip())
            data.setdefault("analysis_chain", ["poc_capture"])
            
            # Ensure structured PoC fields are present (default to empty if LLM missed any)
            data.setdefault("title", str(item.get("verify_summary", "Finding")).strip())
            data.setdefault("steps_to_reproduce", data.get("steps_to_reproduce", []))
            data.setdefault("exploit_script", data.get("exploit_script", ""))
            data.setdefault("verification_commands", data.get("verification_commands", []))
            data.setdefault("visual_evidence_paths", data.get("visual_evidence_paths", []))
            data.setdefault("impact_assessment", data.get("impact_assessment", {}))
            data.setdefault("remediation_steps", data.get("remediation_steps", []))
            data = enrich_payload_with_cvss(data, scenario, verify_data)
            
            # Map 'poc' for legacy compatibility if needed
            if "poc" not in data:
                data["poc"] = data.get("description", "")
                
        return data

    def _normalize_candidate(self, candidate: Any) -> AnalyzerCandidate:
        if isinstance(candidate, AnalyzerCandidate):
            return candidate
        if isinstance(candidate, dict):
            return AnalyzerCandidate(
                idx=int(candidate.get("idx", 0) or 0),
                assessment=candidate.get("assessment", {}) if isinstance(candidate.get("assessment"), dict) else {},
                row=candidate.get("row", {}) if isinstance(candidate.get("row"), dict) else {},
                scenario=candidate.get("scenario", {}) if isinstance(candidate.get("scenario"), dict) else {},
                row_result=candidate.get("row_result", {}) if isinstance(candidate.get("row_result"), dict) else {},
                compact_summary=str(candidate.get("compact_summary", "")).strip(),
                normalized_outputs=(
                    candidate.get("normalized_outputs", [])
                    if isinstance(candidate.get("normalized_outputs"), list)
                    else []
                ),
            )
        raise TypeError("candidate must be AnalyzerCandidate or dict")

    def _parse_tool_result_payload(self, raw_result: Any) -> dict[str, Any]:
        if isinstance(raw_result, dict):
            return dict(raw_result)
        if not isinstance(raw_result, str):
            return {}
        text = raw_result.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _is_confirmed_oob_result(self, raw_result: dict[str, Any]) -> bool:
        return (
            isinstance(raw_result, dict)
            and raw_result.get("oob_enabled") is True
            and raw_result.get("oob_confirmed") is True
        )

    def _find_confirmed_oob_result(self, tool_results: Any) -> dict[str, Any] | None:
        if not isinstance(tool_results, list):
            return None
        for item in tool_results:
            if not isinstance(item, dict):
                continue
            parsed = self._parse_tool_result_payload(item.get("result", ""))
            if self._is_confirmed_oob_result(parsed):
                parsed.setdefault("tool_name", str(item.get("name", "")).strip())
                return parsed
        return None

    def _normalized_entry_text(self, normalized: dict[str, Any]) -> str:
        if not isinstance(normalized, dict):
            return ""
        parts = [
            f"tool={normalized.get('tool', '')}",
            f"parser={normalized.get('parser', '')}",
        ]
        snippets = normalized.get("snippets", [])
        if isinstance(snippets, list) and snippets:
            parts.append("snippets=" + " || ".join(str(item) for item in snippets[:4]))
        markers = normalized.get("evidence_markers", [])
        if isinstance(markers, list) and markers:
            parts.append("markers=" + ", ".join(str(item) for item in markers[:6]))
        codes = normalized.get("status_codes", [])
        if isinstance(codes, list) and codes:
            parts.append("status_codes=" + ", ".join(str(item) for item in codes[:6]))
        observations = normalized.get("observations", [])
        if isinstance(observations, list) and observations:
            parts.append("observations=" + " || ".join(str(item) for item in observations[:4]))
        routes = normalized.get("routes", [])
        if isinstance(routes, list) and routes:
            parts.append("routes=" + ", ".join(str(item) for item in routes[:6]))
        cves = normalized.get("cves", [])
        if isinstance(cves, list) and cves:
            parts.append("cves=" + ", ".join(str(item) for item in cves[:6]))
        return "\n".join(parts)

    def _normalized_outputs_block(self, outputs: list[dict[str, Any]]) -> str:
        if not isinstance(outputs, list) or not outputs:
            return "No normalized parser output available."
        return summarize_normalized_outputs(outputs[:ANALYZER_MAX_NORMALIZED_EVIDENCE_ITEMS])

    def _short_text(self, value: Any, *, limit: int | None = 220) -> str:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        if isinstance(limit, int) and limit > 0 and len(text) > limit:
            return text[:limit].rstrip() + "..."
        return text

    def _tool_findings_summary(
        self,
        *,
        tool_name: str,
        raw_result: Any,
        normalized: dict[str, Any] | None,
        tool_args: dict[str, Any] | None = None,
    ) -> str:
        parsed = self._parse_tool_result_payload(raw_result)
        normalized_map = normalized if isinstance(normalized, dict) else {}
        args_map = tool_args if isinstance(tool_args, dict) else {}

        if tool_name == "dns_recon":
            warnings = parsed.get("warnings", []) if isinstance(parsed.get("warnings"), list) else []
            interesting = parsed.get("interesting_findings", []) if isinstance(parsed.get("interesting_findings"), list) else []
            subdomains = parsed.get("subdomains", []) if isinstance(parsed.get("subdomains"), list) else []
            nameservers = parsed.get("nameservers", []) if isinstance(parsed.get("nameservers"), list) else []
            wildcard_warning = next(
                (
                    self._short_text(item, limit=None)
                    for item in warnings
                    if "wildcard" in str(item).lower()
                ),
                "",
            )
            if wildcard_warning:
                return wildcard_warning
            if interesting:
                labels = []
                for item in interesting[:3]:
                    if isinstance(item, dict):
                        labels.append(str(item.get("type", "")).replace("_", " ").strip() or "finding")
                if labels:
                    return f"Interesting DNS findings: {', '.join(labels)}."
            if subdomains:
                return f"Discovered {len(subdomains)} subdomain(s) from DNS recon."
            if nameservers:
                return f"Enumerated {len(nameservers)} nameserver(s); no hidden subdomains confirmed."
            if parsed.get("success") is False:
                return "DNS recon did not identify additional hidden subdomains or records."

        if tool_name == "passive_web_recon":
            insights = parsed.get("insights", []) if isinstance(parsed.get("insights"), list) else []
            warnings = parsed.get("warnings", []) if isinstance(parsed.get("warnings"), list) else []
            totals: list[str] = []
            if parsed.get("total_subdomains") not in (None, ""):
                totals.append(f"{parsed.get('total_subdomains')} passive subdomain(s)")
            if parsed.get("total_historical_urls") not in (None, ""):
                totals.append(f"{parsed.get('total_historical_urls')} historical URL(s)")
            if parsed.get("total_ip_history") not in (None, ""):
                totals.append(f"{parsed.get('total_ip_history')} historical IP(s)")
            if insights:
                return self._short_text("; ".join(str(item) for item in insights[:3]), limit=None)
            if totals:
                return "Collected " + ", ".join(totals) + "."
            if warnings:
                return self._short_text("; ".join(str(item) for item in warnings[:2]), limit=None)

        if tool_name == "run_custom":
            parsed_observations = (
                parsed.get("observations", [])
                if isinstance(parsed.get("observations"), list)
                else normalized_map.get("observations", [])
            )
            if isinstance(parsed_observations, list) and parsed_observations:
                return self._short_text("; ".join(str(item) for item in parsed_observations[:3]), limit=None)
            error_text = self._short_text(parsed.get("error", ""), limit=None)
            reason_text = self._short_text(args_map.get("reason", ""), limit=None)
            if error_text and reason_text:
                return f"{reason_text} Failed: {error_text}"
            if error_text:
                return f"Failed: {error_text}"
            if reason_text:
                return reason_text
            command_args = args_map.get("args", [])
            if isinstance(command_args, list) and command_args:
                return "Ran custom command: " + self._short_text(" ".join(str(item) for item in command_args[:6]), limit=None)

        if parsed:
            success = parsed.get("success")
            error_text = self._short_text(parsed.get("error", ""), limit=None)
            if success is False and error_text:
                return f"Failed: {error_text}"

            phrases: list[str] = []
            summary_keys = (
                "summary",
                "reason",
                "info_disclosure_risk",
                "average_grade",
                "severity",
            )
            for key in summary_keys:
                value = parsed.get(key)
                if str(value or "").strip():
                    phrases.append(f"{key.replace('_', ' ')}={self._short_text(value, limit=None)}")

            if isinstance(parsed.get("unique_parameters"), list) and parsed.get("unique_parameters"):
                params = ", ".join(str(item) for item in parsed.get("unique_parameters", [])[:5])
                phrases.append(f"parameters={params}")
            if isinstance(parsed.get("detected_fields"), list) and parsed.get("detected_fields"):
                fields = ", ".join(str(item) for item in parsed.get("detected_fields", [])[:5])
                phrases.append(f"fields={fields}")
            if isinstance(parsed.get("missing_headers"), list) and parsed.get("missing_headers"):
                headers = ", ".join(str(item) for item in parsed.get("missing_headers", [])[:5])
                phrases.append(f"missing_headers={headers}")
            if isinstance(parsed.get("observations"), list) and parsed.get("observations"):
                obs = ", ".join(self._short_text(item, limit=None) for item in parsed.get("observations", [])[:3])
                phrases.append(f"observations={obs}")
            if isinstance(parsed.get("findings"), list) and parsed.get("findings"):
                findings = ", ".join(self._short_text(item, limit=None) for item in parsed.get("findings", [])[:3])
                phrases.append(f"findings={findings}")
            if isinstance(parsed.get("status_summary"), dict) and parsed.get("status_summary"):
                statuses = ", ".join(
                    f"{str(key)}={str(value)}"
                    for key, value in list(parsed.get("status_summary", {}).items())[:4]
                )
                phrases.append(f"status_summary={statuses}")
            if parsed.get("total_parameters_found") not in (None, ""):
                phrases.append(f"parameters_found={parsed.get('total_parameters_found')}")
            if parsed.get("total_vulnerable") not in (None, ""):
                phrases.append(f"vulnerable_endpoints={parsed.get('total_vulnerable')}")

            if phrases:
                return self._short_text("; ".join(phrases[:4]), limit=None)

        markers = normalized_map.get("evidence_markers", [])
        routes = normalized_map.get("routes", [])
        codes = normalized_map.get("status_codes", [])
        snippets = normalized_map.get("snippets", [])
        fallback_parts: list[str] = []
        if isinstance(markers, list) and markers:
            fallback_parts.append("markers=" + ", ".join(str(item) for item in markers[:4]))
        if isinstance(routes, list) and routes:
            fallback_parts.append("routes=" + ", ".join(str(item) for item in routes[:4]))
        if isinstance(codes, list) and codes:
            fallback_parts.append("status=" + ", ".join(str(item) for item in codes[:4]))
        if isinstance(snippets, list) and snippets:
            fallback_parts.append("snippets=" + " | ".join(self._short_text(item, limit=None) for item in snippets[:2]))
        if fallback_parts:
            return self._short_text("; ".join(fallback_parts), limit=None)

        raw_text = self._short_text(raw_result, limit=None)
        return raw_text or f"No concise findings were extracted for {tool_name}."

    def _execution_summary_for_report(
        self,
        *,
        tool_results: list[dict[str, Any]],
        row_summary: str,
    ) -> str:
        summary_text = self._short_text(row_summary, limit=None)
        if summary_text:
            summary_text = re.sub(r"\s*Observed evidence:.*$", "", summary_text, flags=re.IGNORECASE).strip()
            summary_text = re.sub(r"\s*Forwarding raw evidence.*$", "", summary_text, flags=re.IGNORECASE).strip()
        rounds_match = re.search(r"across\s+(\d+)\s+tool round", row_summary, re.IGNORECASE)
        rounds_value = rounds_match.group(1) if rounds_match else ""
        tool_calls = sum(1 for item in tool_results if isinstance(item, dict))
        if rounds_value and tool_calls > 0:
            return f"Completed {rounds_value} round(s) with {tool_calls} tool call(s)."
        if tool_calls > 0:
            return f"Completed this scenario with {tool_calls} tool call(s)."
        return summary_text or "Execution summary not available."

    def _tool_command_text(self, *, tool_name: str, tool_args: dict[str, Any] | None) -> str:
        args_map = tool_args if isinstance(tool_args, dict) else {}
        for key in ("command", "cmd", "raw_command", "script", "code", "url"):
            value = args_map.get(key)
            if str(value or "").strip():
                command = str(value).strip()
                arg_list = args_map.get("args", [])
                if key == "command" and isinstance(arg_list, list) and arg_list:
                    return self._short_text(
                        " ".join([command, *[str(item) for item in arg_list[:10]]]),
                        limit=None,
                    )
                return self._short_text(command, limit=None)

        compact_args: list[str] = []
        for key, value in list(args_map.items())[:6]:
            if value in ("", None, [], {}):
                continue
            if isinstance(value, list):
                rendered = "[" + ", ".join(self._short_text(item, limit=None) for item in value[:5]) + "]"
            else:
                rendered = self._short_text(value, limit=None)
            compact_args.append(f"{key}={rendered}")
        if compact_args:
            return self._short_text(f"{tool_name}({', '.join(compact_args)})", limit=None)
        return tool_name

    def _build_scenario_reports(
        self,
        *,
        scenario: dict[str, Any],
        tool_results: list[dict[str, Any]],
        normalized_outputs: list[dict[str, Any]],
        row_summary: str,
    ) -> list[dict[str, Any]]:
        safe_scenario = scenario if isinstance(scenario, dict) else {}
        safe_tool_results = tool_results if isinstance(tool_results, list) else []
        safe_normalized = normalized_outputs if isinstance(normalized_outputs, list) else []
        tools_ran: list[str] = []
        findings_summary: list[str] = []
        tool_details: list[dict[str, str]] = []

        for index, item in enumerate(safe_tool_results):
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("name", "")).strip() or f"tool_{index + 1}"
            command_text = self._tool_command_text(
                tool_name=tool_name,
                tool_args=item.get("args", {}) if isinstance(item.get("args", {}), dict) else {},
            )
            tools_ran.append(command_text)
            normalized = safe_normalized[index] if index < len(safe_normalized) and isinstance(safe_normalized[index], dict) else {}
            tool_summary = self._tool_findings_summary(
                tool_name=tool_name,
                raw_result=item.get('result', ''),
                normalized=normalized,
                tool_args=item.get('args', {}) if isinstance(item.get('args', {}), dict) else {},
            )
            findings_summary.append(f"{tool_name}: {tool_summary}")
            raw_status = str(item.get("status", "")).strip().lower()
            status_label = (
                "passed"
                if raw_status in {"completed", "success", "passed"}
                else "failed"
                if raw_status in {"error", "failed"}
                else raw_status or "observed"
            )
            tool_details.append(
                {
                    "tool": tool_name,
                    "command": command_text,
                    "status": status_label,
                    "raw_status": raw_status or "observed",
                    "summary": tool_summary,
                }
            )

        return [
            {
                "scenario_ran": str(safe_scenario.get("task", "")).strip() or "Untitled scenario",
                "agent": str(safe_scenario.get("agent", "")).strip().lower() or "unknown",
                "tools_ran": _unique_strings(tools_ran),
                "tool_results": tool_details,
                "findings_summary": findings_summary,
                "execution_summary": self._execution_summary_for_report(
                    tool_results=safe_tool_results,
                    row_summary=row_summary,
                ),
            }
        ]

    def _build_agent_markdown(
        self,
        *,
        scenario: dict[str, Any],
        scenario_reports: list[dict[str, Any]],
        row_summary: str,
    ) -> str:
        safe_scenario = scenario if isinstance(scenario, dict) else {}
        safe_reports = scenario_reports if isinstance(scenario_reports, list) else []
        agent_role = str(safe_scenario.get("agent", "")).strip().lower() or "unknown"
        title = f"# {agent_role.upper()} Analyzer Report"
        lines: list[str] = [title]

        for report in safe_reports:
            if not isinstance(report, dict):
                continue
            tool_results = report.get("tool_results", [])
            lines.extend([
                "",
                "## Scenario Run",
                "",
                f"- Scenario Ran: {str(report.get('scenario_ran', '')).strip() or 'Untitled scenario'}",
                f"- Tools Run: {', '.join(f'`{str(item).strip()}`' for item in report.get('tools_ran', []) if str(item).strip()) or 'No tools recorded'}",
            ])
            execution_summary = str(report.get("execution_summary", "")).strip() or self._short_text(row_summary, limit=None)
            if execution_summary:
                lines.append(f"- Execution Summary: {execution_summary}")

            lines.extend(["", "## Full Tool History", ""])
            if isinstance(tool_results, list) and tool_results:
                for item in tool_results:
                    if not isinstance(item, dict):
                        continue
                    status = str(item.get("status", "")).strip() or "observed"
                    command = str(item.get("command", "")).strip() or str(item.get("tool", "")).strip() or "tool"
                    summary = str(item.get("summary", "")).strip()
                    line = f"- `{status}` `{command}`"
                    if summary:
                        line += f" -> {summary}"
                    lines.append(line)
            else:
                lines.append("- No tool history recorded.")

            findings_summary = report.get("findings_summary", [])
            lines.extend(["", "## What The Tools Found", ""])
            if isinstance(findings_summary, list) and findings_summary:
                for item in findings_summary:
                    lines.append(f"- {self._short_text(item, limit=None)}")
            else:
                lines.append("- No concise findings summary was produced.")

        return "\n".join(lines).strip()

    def _executor_history_block(self, tool_results: Any) -> str:
        if not isinstance(tool_results, list) or not tool_results:
            return "No executor command history available."

        lines: list[str] = []
        step_count = 0
        for item in tool_results:
            if not isinstance(item, dict):
                continue
            step_count += 1
            tool_name = str(item.get("name", "")).strip() or "unknown_tool"
            args = item.get("args", {})
            args_map = args if isinstance(args, dict) else {}

            command = ""
            for key in ("command", "cmd", "raw_command", "script", "code", "url"):
                value = args_map.get(key)
                if str(value or "").strip():
                    command = str(value).strip()
                    break
            if not command:
                command = tool_name

            result_preview = str(item.get("result", "")).strip()
            if len(result_preview) > 500:
                result_preview = result_preview[:500] + " ...[truncated]"

            lines.append(f"[{step_count}] tool={tool_name}")
            lines.append(f"command={command}")
            if result_preview:
                lines.append(f"result={result_preview}")
            lines.append("")

        return "\n".join(lines).strip() or "No executor command history available."

    def _derive_vulnerability_type(self, candidate: AnalyzerCandidate) -> str:
        scenario_type = str(candidate.scenario.get("vulnerability_type", "")).strip()
        if scenario_type:
            return scenario_type
        text = " ".join(
            [
                str(candidate.compact_summary or ""),
                str(candidate.scenario.get("task", "") or ""),
                json.dumps(candidate.assessment, ensure_ascii=True),
            ]
        ).lower()
        if "xss" in text or "cross-site scripting" in text:
            return "Cross-Site Scripting"
        if "sqli" in text or "sql injection" in text:
            return "SQL Injection"
        if "idor" in text or "broken access control" in text:
            return "Broken Access Control"
        if "cors" in text:
            return "CORS Misconfiguration"
        if "csrf" in text:
            return "CSRF"
        return "Security Issue"

    def _derive_expected_indicator(self, candidate: AnalyzerCandidate) -> str:
        routes: list[str] = []
        markers: list[str] = []
        for entry in (candidate.normalized_outputs or [])[:5]:
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("routes"), list):
                routes.extend(str(route) for route in entry.get("routes", [])[:3])
            if isinstance(entry.get("evidence_markers"), list):
                markers.extend(str(marker) for marker in entry.get("evidence_markers", [])[:3])
        route_hint = ", ".join(list(dict.fromkeys(routes))[:3])
        marker_hint = ", ".join(list(dict.fromkeys(markers))[:4])
        pieces = [piece for piece in (route_hint, marker_hint, candidate.compact_summary[:120]) if piece]
        return " | ".join(pieces)[:240]

    def _extract_verification_artifacts(
        self,
        *,
        candidate: AnalyzerCandidate,
        verify_data: dict[str, Any],
    ) -> dict[str, Any]:
        evidence = verify_data.get("evidence", {})
        evidence_map = evidence if isinstance(evidence, dict) else {}
        tool_results = verify_data.get("tool_results") or []
        commands: list[str] = []
        tool_names: list[str] = []
        screenshots = 0
        replay_count = 0
        result_previews = 0

        if isinstance(tool_results, list):
            for item in tool_results:
                if not isinstance(item, dict):
                    continue
                tool_name = str(item.get("name", "")).strip()
                if tool_name:
                    tool_names.append(tool_name)
                args = item.get("args", {})
                args_map = args if isinstance(args, dict) else {}
                command = ""
                for key in ("command", "cmd", "raw_command", "script", "code", "url"):
                    value = args_map.get(key)
                    if str(value or "").strip():
                        command = str(value).strip()
                        break
                if not command and tool_name:
                    command = tool_name
                if command:
                    commands.append(command)
                if tool_name == "capture_screenshot":
                    screenshots += 1
                if tool_name in {"run_custom", "run_python", "record_verification_result", "capture_screenshot"}:
                    replay_count += 1
                if str(item.get("result", "")).strip():
                    result_previews += 1

        commands = _unique_strings(commands)
        tool_names = _unique_strings(tool_names)
        evidence_commands = evidence_map.get("commands")
        if isinstance(evidence_commands, list):
            commands = _unique_strings(commands + [str(item) for item in evidence_commands])
        evidence_tools = evidence_map.get("tools_used")
        if isinstance(evidence_tools, list):
            tool_names = _unique_strings(tool_names + [str(item) for item in evidence_tools])

        normalized_outputs = (
            candidate.normalized_outputs
            if isinstance(candidate.normalized_outputs, list)
            else []
        )
        oob_confirmed = bool(evidence_map.get("oob_confirmed"))
        has_visual_capture = screenshots > 0
        has_command_replay = bool(commands) and result_previews > 0
        deterministic_validation = oob_confirmed or has_command_replay

        verification_methods: list[str] = []
        if oob_confirmed:
            verification_methods.append("oob_callback")
        if has_command_replay:
            verification_methods.append("command_replay")
        if has_visual_capture:
            verification_methods.append("visual_capture")
        if normalized_outputs:
            verification_methods.append("normalized_output_analysis")
        if not verification_methods:
            verification_methods.append("llm_reasoning")

        verdict = self._extract_verdict(verify_data)
        vuln_type = self._derive_vulnerability_type(candidate)
        
        # Use new deterministic classification
        verification_tier = classify_evidence(vuln_type, {
            "summary": str(verify_data.get("summary", "")),
            "raw_output": str(verify_data.get("result", "")),
            "deterministic_validation": deterministic_validation,
        })

        if verdict == "real_vulnerability":
            evidence_status = verification_tier.value
            if verification_tier == VerificationTier.CONFIRMED:
                proof_quality = "strong"
            elif verification_tier == VerificationTier.REPRODUCED:
                proof_quality = "high"
            else:
                proof_quality = "moderate"
        else:
            evidence_status = "suspicion"
            proof_quality = "weak"

        return {
            "evidence_status": evidence_status,
            "proof_quality": proof_quality,
            "verification_tier": verification_tier.value,
            "deterministic_validation": deterministic_validation,
            "verification_methods": verification_methods,
            "artifact_quality": {
                "command_count": len(commands),
                "tool_count": len(tool_names),
                "screenshot_count": screenshots,
                "replay_count": replay_count,
                "normalized_output_count": len(normalized_outputs),
                "result_preview_count": result_previews,
                "oob_confirmed": oob_confirmed,
            },
            "commands": commands,
            "tools_used": tool_names,
        }

    def _finalize_verification_payload(
        self,
        *,
        candidate: AnalyzerCandidate,
        verify_data: dict[str, Any],
    ) -> dict[str, Any]:
        data = dict(verify_data) if isinstance(verify_data, dict) else {}
        if not data.get("verdict"):
            data["verdict"] = self._extract_verdict(data)

        waf_interference = False
        tool_results = candidate.row_result.get("tool_results", [])
        if isinstance(tool_results, list):
            for cmd_res in tool_results:
                if not isinstance(cmd_res, dict):
                    continue
                text = str(cmd_res.get("result", "")).lower()
                if "429 too many requests" in text or "cloudflare waf" in text or "attention required! | cloudflare" in text or "rate limit" in text or "rate-limit" in text:
                    waf_interference = True
                    break
                    
        if waf_interference and data.get("verdict") == "real_vulnerability":
            data["verdict"] = "inconclusive"
            data["reasoning"] = "WAF interference or rate-limiting detected in the tool results. The finding cannot be conclusively verified."
        data = enrich_payload_with_cvss(data, candidate.scenario, candidate.row_result)
        data.setdefault("poc", "")
        data.setdefault(
            "analysis_chain",
            ["parse", "classify", "false_positive_filter", "confirm" if data.get("verdict") == "real_vulnerability" else "reject_or_inconclusive"],
        )
        evidence = data.get("evidence", {})
        evidence_map = dict(evidence) if isinstance(evidence, dict) else {}
        evidence_map.setdefault("normalized_outputs", candidate.normalized_outputs)
        evidence_map.setdefault("normalized_summary", self._normalized_outputs_block(candidate.normalized_outputs))
        evidence_map.setdefault("assessment", candidate.assessment)
        evidence_map.setdefault(
            "scenario_evidence_metadata",
            {
                "evidence_tier": str(candidate.scenario.get("evidence_tier", "")).strip(),
                "confidence_label": str(candidate.scenario.get("confidence_label", "")).strip(),
                "prerequisites": candidate.scenario.get("prerequisites", [])
                if isinstance(candidate.scenario.get("prerequisites"), list)
                else [],
                "evidence_basis": candidate.scenario.get("evidence_basis", [])
                if isinstance(candidate.scenario.get("evidence_basis"), list)
                else [],
            },
        )
        evidence_map.setdefault(
            "executor_tool_results",
            candidate.row_result.get("tool_results", [])
            if isinstance(candidate.row_result.get("tool_results", []), list)
            else [],
        )
        evidence_map.setdefault(
            "executor_commands",
            self._extract_executor_commands(candidate.row_result.get("tool_results", [])),
        )
        verification_artifacts = self._extract_verification_artifacts(
            candidate=candidate,
            verify_data=data,
        )
        evidence_map.setdefault("evidence_status", verification_artifacts["evidence_status"])
        evidence_map.setdefault("proof_quality", verification_artifacts["proof_quality"])
        evidence_map.setdefault("deterministic_validation", verification_artifacts["deterministic_validation"])
        evidence_map.setdefault("verification_methods", verification_artifacts["verification_methods"])
        evidence_map.setdefault("artifact_quality", verification_artifacts["artifact_quality"])
        evidence_map.setdefault("commands", verification_artifacts["commands"])
        evidence_map.setdefault("tools_used", verification_artifacts["tools_used"])
        data.setdefault("tier", verification_artifacts.get("verification_tier", "needs_manual_review"))
        data.setdefault("reasoning", data.get("reasoning", "LLM-based analysis of verification evidence."))
        data["evidence"] = evidence_map
        data.setdefault("normalized_outputs", candidate.normalized_outputs)
        data.setdefault("scenario_report", candidate.assessment.get("scenario_reports", []))
        data.setdefault("analysis_markdown", str(candidate.assessment.get("agent_markdown", "")).strip())
        data.setdefault("ssvc", candidate.assessment.get("overall", {}).get("ssvc", "TRACK"))
        data.setdefault("ssvc_action", candidate.assessment.get("overall", {}).get("ssvc", "TRACK"))
        data.setdefault("hitl_required", str(data.get("ssvc", "")).upper() in set(ANALYZER_HITL_DECISIONS))
        data.setdefault("finding_type", candidate.assessment.get("finding_type", "info"))
        data.setdefault("vulnerability_type", self._derive_vulnerability_type(candidate))
        data.setdefault("expected_indicator", self._derive_expected_indicator(candidate))
        data.setdefault("evidence_status", verification_artifacts["evidence_status"])
        data.setdefault("proof_quality", verification_artifacts["proof_quality"])
        data.setdefault("deterministic_validation", verification_artifacts["deterministic_validation"])
        data.setdefault("verification_methods", verification_artifacts["verification_methods"])
        data.setdefault("artifact_quality", verification_artifacts["artifact_quality"])
        if data.get("cvss_score") is not None:
            evidence_map.setdefault("cvss_score", data.get("cvss_score"))
        if data.get("cvss_vector"):
            evidence_map.setdefault("cvss_vector", data.get("cvss_vector"))
        if data.get("cvss_severity"):
            evidence_map.setdefault("cvss_severity", data.get("cvss_severity"))
        return data

    def _extract_executor_commands(self, tool_results: Any) -> list[str]:
        commands: list[str] = []
        if not isinstance(tool_results, list):
            return commands
        for item in tool_results:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("name", "")).strip()
            args = item.get("args", {})
            args_map = args if isinstance(args, dict) else {}
            command = ""
            for key in ("command", "cmd", "raw_command", "script", "code", "url"):
                value = args_map.get(key)
                if str(value or "").strip():
                    command = str(value).strip()
                    break
            if not command and tool_name:
                command = tool_name
            if command:
                commands.append(command)
        return _unique_strings(commands)

    def _extract_verdict(self, data: dict[str, Any]) -> str:
        verdict = str(data.get("verdict", "")).strip().lower()
        if verdict in {"real_vulnerability", "false_positive", "inconclusive"}:
            return verdict
        status = str(data.get("status", "")).strip().lower()
        if status in {"real_vulnerability", "false_positive", "inconclusive"}:
            return status
        return ANALYZER_DEFAULT_VERDICT

    def _parse_signals(self, text: str) -> dict[str, Any]:
        lowered = text.lower()
        cves = sorted({m.upper() for m in _CVE_RE.findall(text)})
        cwes = sorted({m.upper() for m in _CWE_RE.findall(text)})
        cvss: float | None = None
        for match in _CVSS_RE.findall(text):
            try:
                value = float(match)
            except ValueError:
                continue
            if 0.0 <= value <= 10.0:
                cvss = max(cvss or 0.0, value)
        epss: float | None = None
        for match in _EPSS_RE.findall(text):
            try:
                value = float(match)
            except ValueError:
                continue
            if value > 1.0:
                value = value / 100.0
            if 0.0 <= value <= 1.0:
                epss = max(epss or 0.0, value)
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
        )[:ANALYZER_MAX_SUMMARY_CHARS]
