from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_confidence(value: Any) -> float:
    text = str(value or "").strip().lower()
    if text in {"low", "medium", "high"}:
        mapping = {
            "low": 0.25,
            "medium": 0.6,
            "high": 0.9,
        }
        return mapping[text]
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    if confidence < 0:
        return 0.0
    if confidence > 1:
        return 1.0
    return confidence


@dataclass
class TechStack:
    backend_language: Optional[str] = None
    framework: Optional[str] = None
    database: Optional[str] = None
    waf: Optional[str] = None
    server: Optional[str] = None
    frontend: Optional[str] = None


@dataclass
class TechFingerprint:
    product: str
    display_name: Optional[str] = None
    category: Optional[str] = None
    version: Optional[str] = None
    version_normalized: Optional[str] = None
    confidence_score: float = 0.0
    confidence_label: Optional[str] = None
    corroborated: bool = False
    source_count: int = 0
    sources: list[str] = field(default_factory=list)
    recommended_run_custom_tools: list[str] = field(default_factory=list)
    nuclei_tags: list[str] = field(default_factory=list)
    nuclei_templates: list[str] = field(default_factory=list)
    kb_query: Optional[str] = None


@dataclass
class KnownVulnerabilitySignal:
    product: str
    version: Optional[str] = None
    cve: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    cisa_kev: bool = False
    exploit_source: Optional[str] = None
    summary: Optional[str] = None
    confidence_label: Optional[str] = None


@dataclass
class Finding:
    id: str
    type: Literal["vulnerability", "info", "false_positive"]
    name: str
    severity: Optional[Literal["critical", "high", "medium", "low", "info"]] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    tool: Optional[str] = None
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    poc_path: Optional[str] = None
    oob_confirmed: bool = False
    confidence: float = 0.0
    claim_status: Literal["observed", "inferred", "assumed", "unsupported"] = "unsupported"
    source_lineage: list[str] = field(default_factory=list)
    cited_tool_output_ids: list[str] = field(default_factory=list)
    ssvc_decision: Optional[Literal["ACT", "ATTEND", "TRACK"]] = None
    related_findings: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utc_now_iso)


@dataclass
class ToolResult:
    tool: str
    scenario_task: str
    status: Literal["success", "failed", "blocked", "timeout", "info"]
    confidence: float
    finding_ids: list[str] = field(default_factory=list)
    false_positive_count: int = field(default=0)
    timestamp: str = field(default_factory=_utc_now_iso)


@dataclass
class Brain:
    target_info: dict[str, Any] = field(default_factory=dict)
    tech_stack: TechStack = field(default_factory=TechStack)
    tech_inventory: list[TechFingerprint] = field(default_factory=list)
    known_vulnerability_signals: list[KnownVulnerabilitySignal] = field(default_factory=list)
    recommended_run_custom_tools: list[str] = field(default_factory=list)
    nuclei_scan_hints: dict[str, Any] = field(default_factory=dict)
    anonymous_routes: list[str] = field(default_factory=list)
    authenticated_routes: list[str] = field(default_factory=list)
    auth_surface_delta: list[str] = field(default_factory=list)
    blocked_routes: list[str] = field(default_factory=list)
    blocked_route_prefixes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    session_contexts: list[str] = field(default_factory=list)
    parameter_hints: list[str] = field(default_factory=list)

    @classmethod
    def from_system_memory(cls, memory: dict[str, Any]) -> "Brain":
        overview = memory.get("overview", {}) if isinstance(memory.get("overview"), dict) else {}
        raw_tech = memory.get("tech_stack", {}) if isinstance(memory.get("tech_stack"), dict) else {}
        raw_tech_inventory = memory.get("tech_inventory", []) if isinstance(memory.get("tech_inventory"), list) else []
        raw_known_signals = memory.get("known_vulnerability_signals", []) if isinstance(memory.get("known_vulnerability_signals"), list) else []
        raw_findings = memory.get("verified_findings", []) if isinstance(memory.get("verified_findings"), list) else []
        raw_tool_results = memory.get("tool_observations", []) if isinstance(memory.get("tool_observations"), list) else []

        findings: list[Finding] = []
        for idx, item in enumerate(raw_findings, start=1):
            if not isinstance(item, dict):
                continue
            findings.append(
                Finding(
                    id=str(item.get("id", f"memory-finding-{idx}")).strip() or f"memory-finding-{idx}",
                    type=_normalize_finding_type(item.get("status")),
                    name=str(item.get("title", item.get("summary", "Finding"))).strip() or "Finding",
                    severity=_normalize_severity(item.get("severity")),
                    endpoint=str(item.get("endpoint", item.get("target", ""))).strip() or None,
                    parameter=str(item.get("parameter", "")).strip() or None,
                    tool=str(item.get("tool", "")).strip() or None,
                    oob_confirmed=bool(item.get("oob_confirmed")),
                    confidence=_coerce_confidence(item.get("confidence", 0.0)),
                    claim_status=_normalize_claim_status(item.get("claim_status")),
                    source_lineage=_clean_string_list(item.get("source_lineage", []), limit=20),
                    cited_tool_output_ids=_clean_string_list(item.get("cited_tool_output_ids", []), limit=20),
                    ssvc_decision=_normalize_ssvc(item.get("ssvc")),
                    timestamp=str(item.get("timestamp", _utc_now_iso())).strip() or _utc_now_iso(),
                )
            )

        tool_results: list[ToolResult] = []
        for item in raw_tool_results:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("tool", "")).strip()
            if not tool_name:
                continue
            tool_results.append(
                ToolResult(
                    tool=tool_name,
                    scenario_task=str(item.get("scenario_task", "")).strip(),
                    status=_normalize_tool_status(item.get("status")),
                    confidence=_coerce_confidence(item.get("confidence", 0.0)),
                    finding_ids=[
                        str(value).strip()
                        for value in item.get("finding_ids", [])
                        if str(value).strip()
                    ]
                    if isinstance(item.get("finding_ids"), list)
                    else [],
                    false_positive_count=int(item.get("false_positive_count", 0) or 0),
                    timestamp=str(item.get("timestamp", _utc_now_iso())).strip() or _utc_now_iso(),
                )
            )

        tech_inventory: list[TechFingerprint] = []
        for item in raw_tech_inventory:
            if not isinstance(item, dict):
                continue
            product = str(item.get("product", "")).strip()
            if not product:
                continue
            tech_inventory.append(
                TechFingerprint(
                    product=product,
                    display_name=str(item.get("display_name", "")).strip() or None,
                    category=str(item.get("category", "")).strip() or None,
                    version=str(item.get("version", "")).strip() or None,
                    version_normalized=str(item.get("version_normalized", "")).strip() or None,
                    confidence_score=_coerce_confidence(item.get("confidence_score", 0.0)),
                    confidence_label=str(item.get("confidence_label", "")).strip() or None,
                    corroborated=bool(item.get("corroborated")),
                    source_count=int(item.get("source_count", 0) or 0),
                    sources=_clean_string_list(item.get("sources", [])),
                    recommended_run_custom_tools=_clean_string_list(item.get("recommended_run_custom_tools", [])),
                    nuclei_tags=_clean_string_list(item.get("nuclei_tags", [])),
                    nuclei_templates=_clean_string_list(item.get("nuclei_templates", [])),
                    kb_query=str(item.get("kb_query", "")).strip() or None,
                )
            )

        known_signals: list[KnownVulnerabilitySignal] = []
        for item in raw_known_signals:
            if not isinstance(item, dict):
                continue
            product = str(item.get("product", "")).strip()
            if not product:
                continue
            known_signals.append(
                KnownVulnerabilitySignal(
                    product=product,
                    version=str(item.get("version", "")).strip() or None,
                    cve=str(item.get("cve", "")).strip() or None,
                    title=str(item.get("title", "")).strip() or None,
                    severity=str(item.get("severity", "")).strip() or None,
                    cisa_kev=bool(item.get("cisa_kev")),
                    exploit_source=str(item.get("exploit_source", item.get("source", ""))).strip() or None,
                    summary=str(item.get("summary", "")).strip() or None,
                    confidence_label=str(item.get("confidence_label", "")).strip() or None,
                )
            )

        return cls(
            target_info={
                "target": str(overview.get("target", "")).strip(),
                "target_type": str(overview.get("target_type", "")).strip(),
                "scope": str(overview.get("scope", "")).strip(),
                "info": str(overview.get("info", "")).strip(),
            },
            tech_stack=TechStack(**{key: raw_tech.get(key) for key in asdict(TechStack()).keys()}),
            tech_inventory=tech_inventory,
            known_vulnerability_signals=known_signals,
            recommended_run_custom_tools=_clean_string_list(memory.get("recommended_run_custom_tools", [])),
            nuclei_scan_hints=memory.get("nuclei_scan_hints", {}) if isinstance(memory.get("nuclei_scan_hints"), dict) else {},
            anonymous_routes=_clean_string_list(memory.get("anonymous_routes", [])),
            authenticated_routes=_clean_string_list(memory.get("authenticated_routes", [])),
            auth_surface_delta=_clean_string_list(memory.get("auth_surface_delta", [])),
            blocked_routes=_clean_string_list(memory.get("blocked_routes", [])),
            blocked_route_prefixes=_clean_string_list(memory.get("blocked_route_prefixes", [])),
            findings=findings,
            tool_results=tool_results,
            session_contexts=_clean_string_list(memory.get("session_contexts", [])),
            parameter_hints=_clean_string_list(memory.get("parameter_hints", [])),
        )

    def for_planner(self) -> dict[str, Any]:
        confirmed = [
            f for f in self.findings
            if f.type == "vulnerability" and f.claim_status in {"observed", "inferred"}
        ]
        hypotheses = [
            f for f in self.findings
            if f.type == "vulnerability" and f.claim_status in {"assumed", "unsupported"}
        ]
        false_positives = [f for f in self.findings if f.type == "false_positive"]
        info_items = [f for f in self.findings if f.type == "info"]
        tool_efficiency = _compute_tool_efficiency(self.tool_results)
        return {
            "tech_stack": asdict(self.tech_stack),
            "tech_inventory": [asdict(item) for item in self.tech_inventory],
            "known_vulnerability_signals": [asdict(item) for item in self.known_vulnerability_signals],
            "recommended_run_custom_tools": self.recommended_run_custom_tools[:10],
            "nuclei_scan_hints": self.nuclei_scan_hints,
            "confirmed_vulns": [
                {
                    "name": f.name,
                    "endpoint": f.endpoint,
                    "severity": f.severity,
                    "ssvc": f.ssvc_decision,
                    "claim_status": f.claim_status,
                    "source_lineage": f.source_lineage[:6],
                    "cited_tool_output_ids": f.cited_tool_output_ids[:6],
                }
                for f in confirmed
            ],
            "testing_hypotheses": [
                {
                    "name": f.name,
                    "endpoint": f.endpoint,
                    "claim_status": f.claim_status,
                }
                for f in hypotheses[-10:]
            ],
            "false_positives": [f.name for f in false_positives],
            "tool_efficiency": tool_efficiency,
            "auth_surface_delta_count": len(self.auth_surface_delta),
            "auth_surface_delta": self.auth_surface_delta[:20],
            "blocked_routes": self.blocked_routes[:20],
            "blocked_route_prefixes": self.blocked_route_prefixes[:20],
            "parameter_hints": self.parameter_hints[:20],
            "recent_info": [
                {"name": f.name, "endpoint": f.endpoint}
                for f in info_items[-10:]
            ],
        }

    def for_executor(self) -> dict[str, Any]:
        return {
            "tech_stack": asdict(self.tech_stack),
            "tech_inventory": [asdict(item) for item in self.tech_inventory],
            "known_vulnerability_signals": [asdict(item) for item in self.known_vulnerability_signals],
            "recommended_run_custom_tools": self.recommended_run_custom_tools[:10],
            "nuclei_scan_hints": self.nuclei_scan_hints,
            "confirmed_endpoints": list(
                {
                    f.endpoint
                    for f in self.findings
                    if f.type == "vulnerability" and f.endpoint
                }
            ),
            "false_positive_patterns": [f.name for f in self.findings if f.type == "false_positive"][-10:],
            "active_sessions": self.session_contexts,
            "parameter_hints": self.parameter_hints[:20],
            "auth_surface_delta": self.auth_surface_delta[:20],
            "blocked_routes": self.blocked_routes[:20],
            "blocked_route_prefixes": self.blocked_route_prefixes[:20],
        }

    def for_analyzer(self) -> dict[str, Any]:
        return {
            "tech_inventory": [asdict(item) for item in self.tech_inventory],
            "known_vulnerability_signals": [asdict(item) for item in self.known_vulnerability_signals],
            "false_positive_history": [
                {"name": f.name, "endpoint": f.endpoint, "tool": f.tool}
                for f in self.findings
                if f.type == "false_positive"
            ],
            "confirmed_vuln_names": [f.name for f in self.findings if f.type == "vulnerability"],
            "tool_false_positive_rates": _compute_tool_false_positive_rates(self.tool_results),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_info": self.target_info,
            "tech_stack": asdict(self.tech_stack),
            "tech_inventory": [asdict(item) for item in self.tech_inventory],
            "known_vulnerability_signals": [asdict(item) for item in self.known_vulnerability_signals],
            "recommended_run_custom_tools": self.recommended_run_custom_tools,
            "nuclei_scan_hints": self.nuclei_scan_hints,
            "anonymous_routes": self.anonymous_routes,
            "authenticated_routes": self.authenticated_routes,
            "auth_surface_delta": self.auth_surface_delta,
            "blocked_routes": self.blocked_routes,
            "blocked_route_prefixes": self.blocked_route_prefixes,
            "findings": [asdict(item) for item in self.findings],
            "tool_results": [asdict(item) for item in self.tool_results],
            "session_contexts": self.session_contexts,
            "parameter_hints": self.parameter_hints,
        }


def _clean_string_list(value: Any, *, limit: int | None = None) -> list[str]:
    if isinstance(value, list):
        raw_items = value
    elif isinstance(value, str):
        raw_items = [value]
    else:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        text = str(item or "").strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(text)
        if limit is not None and len(out) >= limit:
            break
    return out


def _normalize_finding_type(value: Any) -> Literal["vulnerability", "info", "false_positive"]:
    text = str(value or "").strip().lower()
    if text in {"real_vulnerability", "verified", "vulnerability"}:
        return "vulnerability"
    if text == "false_positive":
        return "false_positive"
    return "info"


def _normalize_claim_status(value: Any) -> Literal["observed", "inferred", "assumed", "unsupported"]:
    normalized = str(value or "").strip().lower()
    if normalized in {"observed", "inferred", "assumed", "unsupported"}:
        return normalized
    return "unsupported"


def _normalize_tool_status(value: Any) -> Literal["success", "failed", "blocked", "timeout", "info"]:
    text = str(value or "").strip().lower()
    if text in {"success", "failed", "blocked", "timeout", "info"}:
        return text  # type: ignore[return-value]
    return "info"


def _normalize_severity(value: Any) -> Optional[Literal["critical", "high", "medium", "low", "info"]]:
    text = str(value or "").strip().lower()
    if text in {"critical", "high", "medium", "low", "info"}:
        return text  # type: ignore[return-value]
    return None


def _normalize_ssvc(value: Any) -> Optional[Literal["ACT", "ATTEND", "TRACK"]]:
    text = str(value or "").strip().upper()
    if text in {"ACT", "ATTEND", "TRACK"}:
        return text  # type: ignore[return-value]
    return None


def _compute_tool_efficiency(tool_results: list[ToolResult]) -> dict[str, float]:
    stats: dict[str, dict[str, int]] = {}
    for item in tool_results:
        bucket = stats.setdefault(item.tool, {"total": 0, "success": 0})
        bucket["total"] += 1
        if item.status == "success":
            bucket["success"] += 1
    return {
        tool: round(values["success"] / max(values["total"], 1), 2)
        for tool, values in stats.items()
    }


def _compute_tool_false_positive_rates(tool_results: list[ToolResult]) -> dict[str, float]:
    stats: dict[str, dict[str, int]] = {}
    for item in tool_results:
        bucket = stats.setdefault(item.tool, {"total": 0, "false_positives": 0})
        bucket["total"] += 1
        bucket["false_positives"] += max(0, int(item.false_positive_count))
    return {
        tool: round(values["false_positives"] / max(values["total"], 1), 2)
        for tool, values in stats.items()
    }
