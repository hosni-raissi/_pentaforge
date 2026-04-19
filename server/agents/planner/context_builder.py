"""Planner Context Builder — 6-Part Context Window Construction.

Builds the complete prompt for each Planner round using a fixed 6-part structure,
always within ~10,000 tokens. Each part has a different lifecycle.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger(__name__)


class PlannerContextBuilder:
    """Builds and manages the 6-part context window for Planner rounds."""

    def __init__(
        self,
        projects_store: Any,
        vector_store: Any,
        system_prompt: str,
    ):
        self.projects_store = projects_store
        self.vector_store = vector_store
        self.system_prompt = system_prompt
        self.last_round_timestamp: str | None = None
        self.round_count = 0

    async def build_context(
        self,
        project_id: str,
        engagement_data: dict[str, Any],
        user_message: str | None = None,
    ) -> str:
        """Build complete 6-part context for this round."""
        self.round_count += 1
        parts = []

        # PART 1 — System Core (frozen)
        parts.append(self.system_prompt)

        # PART 2 — Engagement Snapshot (rebuilt every round)
        project = self.projects_store.get_project(project_id)
        if isinstance(project, dict):
            parts.append(self._build_engagement_snapshot(project))
        else:
            parts.append("ENGAGEMENT SNAPSHOT: Not yet available")

        # PART 3 — Compressed Plan
        parts.append(self._build_compressed_plan(project))

        # PART 4 — New Findings
        parts.append(self._build_new_findings(project))

        # PART 5 — RAG Context
        parts.append(self._build_rag_context(project))

        # PART 6 — User Directive
        parts.append(self._build_user_directive(user_message))

        # Update timestamp for next round
        self.last_round_timestamp = datetime.now(tz=timezone.utc).isoformat()

        complete_prompt = "\n\n".join(parts)

        logger.info(
            "planner_context_built",
            project_id=project_id,
            round_count=self.round_count,
            total_tokens_approx=len(complete_prompt) // 4,
        )

        return complete_prompt

    def _build_engagement_snapshot(self, project: dict[str, Any]) -> str:
        """PART 2 — Engagement Snapshot (rebuilt every round)."""
        last_scan = project.get("lastScan", {})
        if not isinstance(last_scan, dict):
            last_scan = {}

        detected_tech = last_scan.get("detectedTech", [])
        phase = last_scan.get("phase", "reconnaissance")

        checklist = project.get("checklist", {})
        if isinstance(checklist, dict):
            total_items = len(checklist.get("checklist", []))
            completed = sum(
                1 for item in checklist.get("checklist", [])
                if isinstance(item, dict) and item.get("done")
            )
        else:
            total_items = 0
            completed = 0

        coverage_pct = (100 * completed // total_items) if total_items > 0 else 0

        tech_list = "\n  - ".join(detected_tech[:8]) if detected_tech else "(none detected yet)"

        return f"""ENGAGEMENT SNAPSHOT (Round {self.round_count}):
Current Phase: {phase}
Checklist Coverage: {coverage_pct}% ({completed}/{total_items})
Detected Technologies:
  - {tech_list}"""

    def _build_compressed_plan(self, project: dict[str, Any]) -> str:
        """PART 3 — Compressed Plan (incremental)."""
        last_scan = project.get("lastScan", {}) if isinstance(project, dict) else {}
        plan = last_scan.get("plan", {}) if isinstance(last_scan, dict) else {}

        if not isinstance(plan, dict) or not plan.get("phases"):
            return "COMPRESSED PLAN: (not yet initialized)"

        phases = plan.get("phases", [])
        if not isinstance(phases, list):
            return "COMPRESSED PLAN: (empty)"

        plan_summary = []
        for phase in phases[:4]:  # Limit to first 4 phases
            if not isinstance(phase, dict):
                continue
            phase_name = phase.get("name", "Unknown")
            steps = phase.get("steps", [])
            if isinstance(steps, list):
                step_count = len(steps)
                scenario_count = sum(
                    len(step.get("scenarios", []))
                    for step in steps
                    if isinstance(step, dict)
                )
                plan_summary.append(
                    f"  {phase_name}: {step_count} steps, {scenario_count} scenarios"
                )

        return "COMPRESSED PLAN:\n" + "\n".join(plan_summary) if plan_summary else "COMPRESSED PLAN: (empty)"

    def _build_new_findings(self, project: dict[str, Any]) -> str:
        """PART 4 — New Findings (pure delta)."""
        if not isinstance(project, dict):
            return "NEW FINDINGS: (no project data)"

        # Query scan events for recent findings
        try:
            events = self.projects_store.list_scan_event_cache(
                project.get("_id", ""),
                limit=100
            )
        except Exception:
            return "NEW FINDINGS: (query failed)"

        findings = []
        for event in events:
            if not isinstance(event, dict):
                continue
            if event.get("event") == "perceptor_classified":
                data = event.get("data", {})
                if isinstance(data, str):
                    import json
                    try:
                        data = json.loads(data)
                    except (json.JSONDecodeError, TypeError):
                        continue
                if isinstance(data, dict):
                    assessment = data.get("assessment", {})
                    if isinstance(assessment, dict):
                        findings.append(
                            f"  - {assessment.get('compact_summary', 'finding')[:60]}"
                        )

        if not findings:
            return "NEW FINDINGS: None this round."

        return "NEW FINDINGS:\n" + "\n".join(findings[:10])

    def _build_rag_context(self, project: dict[str, Any]) -> str:
        """PART 5 — RAG Context (dynamic per this round's signals)."""
        # For now, return placeholder
        # In production: query Qdrant with signals from findings + detected tech
        return "RAG CONTEXT: (Qdrant retrieval not yet enabled)"

    def _build_user_directive(self, user_message: str | None) -> str:
        """PART 6 — User Directive (per-round)."""
        if user_message:
            return f"USER DIRECTIVE THIS ROUND:\n{user_message}"
        else:
            return "USER DIRECTIVE: No directive. Continue executing plan autonomously."

    def should_re_anchor(self) -> bool:
        """Check if this round should trigger a re-anchor (every 10 rounds)."""
        return self.round_count > 0 and self.round_count % 10 == 0



def build_system_core_part() -> str:
    """Build PART 1 — System Core (frozen, ~1,500 tokens).

    This part contains the Planner's identity, rules, output schema,
    and SSVC decision logic. Written once at deployment, never changes.
    """
    return """\
You are PentaForge Planner — the strategic orchestrator of a multi-phase penetration test.

YOUR ROLE:
- Synthesize findings from reconnai​ssance, exploitation, and verification sub-agents
- Decide which scenarios to execute next (recon/exploit in parallel)
- Manage risk: defer untested high-priority items, escalate SSVC=ACT findings
- Adapt plan in real time based on evidence — incomplete data is not excuse for inaction
- Output ONLY valid JSON; no explanation, no markdown, no apology

═══════════════════════════════════════════════════════════════
OUTPUT FORMAT (strict JSON, always 4 keys):
{
  "summary": "(<50 chars) your decision: e.g., 'Exploit SQLi on login, continue enum'",
  "needs": ["..."],                    # Items you need to know before next round
  "plan": {                            # Optional — only if updating plan
    "phases": [
      {
        "name": "...",
        "priority": 1,
        "steps": [
          {
            "id": "...",
            "description": "...",
            "scenarios": [
              { "task": "...", "agent": "recon|exploit", "priority": 1-5, "done": false }
            ]
          }
        ]
      }
    ]
  },
  "action_plan": {                      # Strategic guidance
    "dispatch": [                       # What agent-scenario pairs to execute next
      { "phase": "Phase1", "agent": "recon", "count": 1, "priority_filter": "p1+p2" }
    ],
    "ssvc_escalations": [               # Critical findings requiring human decision
      { "finding_ref": "fin_001", "verdict": "ACT", "rationale": "..." }
    ],
    "rationale": "Why this plan makes sense"
  }
}

═══════════════════════════════════════════════════════════════
SSVC DECISION RULES (embedded in your decision-making):

ACT (immediate escalation):
  - CVSS >= 9.0 AND exploitable AND exposed
  - Any RCE/Auth bypass/SQLi confirmed
  - → Send to Verify + human approval before exploit

ATTEND (escalate after verification):
  - CVSS 7-8.9 AND exploitable
  - Multiple correlated findings pointing to attack chain
  - → Send to Verify, proceed if confirmed

TRACK (log and continue):
  - CVSS < 7.0 or low confidence
  - Information-only findings (missing headers, version banners)
  - → Log in report, continue scanning

═══════════════════════════════════════════════════════════════
AGENT ROLES (what agent does NEXT per priority):

RECON: Information gathering, enumeration, passive verification
  - Subdomain discovery, port scanning, service enumeration
  - Technology stack detection, vulnerability research
  - Firewall/WAF detection, rate limit testing

EXPLOIT: Active vulnerability testing & proof-of-concept
  - SQL injection, XSS, authentication bypass
  - Known CVE exploitation, privilege escalation
  - File upload, RCE, deserialization attacks

REPORT: Documentation & final deliverable (happens LAST)
"""


def build_engagement_snapshot_part(
    engagement_id: str | None,
    round_num: int,
    current_phase: str,
    targets: list[str],
    detected_tech: list[str],
    checklist_coverage: dict[str, Any],
    world_state: dict[str, Any],
) -> str:
    """Build PART 2 — Engagement Snapshot (~1,000 tokens).

    A high-level status dashboard rebuilt from scratch every round.
    Answers: "where are we right now?"
    """
    tech_str = ", ".join(detected_tech) if detected_tech else "unknown"
    targets_str = ", ".join(targets) if targets else "undefined"

    total_items = checklist_coverage.get("total", 0)
    completed = checklist_coverage.get("completed", 0)
    coverage_pct = int((completed / total_items * 100) if total_items > 0 else 0)
    critical_gaps = checklist_coverage.get("critical_gaps", [])
    blocked = checklist_coverage.get("blocked_by_prereqs", [])

    open_tasks = world_state.get("open_tasks", 0)
    blocked_tasks = world_state.get("blocked_tasks", 0)
    act_findings = world_state.get("act_findings", 0)
    attend_findings = world_state.get("attend_findings", 0)
    track_findings = world_state.get("track_findings", 0)

    return f"""\
─── ENGAGEMENT SNAPSHOT ───
Engagement ID : {engagement_id or 'unknown'}
Round         : {round_num}
Phase         : {current_phase}
Targets       : {targets_str}
Tech Stack    : {tech_str}

Checklist Coverage:
  Total      : {total_items} items
  Completed  : {completed} ({coverage_pct}%)
  Critical gaps ({len(critical_gaps)}): {', '.join(critical_gaps[:3]) if critical_gaps else 'none'}
  Blocked by prereqs ({len(blocked)}): {', '.join(blocked[:2]) if blocked else 'none'}

World State:
  Open tasks    : {open_tasks}
  Blocked tasks : {blocked_tasks}
  ACT findings  : {act_findings} — awaiting human approval
  ATTEND        : {attend_findings}
  TRACK         : {track_findings}
"""


def build_compressed_plan_part(
    plan_data: dict[str, Any],
) -> str:
    """Build PART 3 — Compressed Plan (~2,000 tokens).

    The full ActionPlan but with intelligent compression:
    - Completed tasks → single line with ref_id
    - Active/pending/blocked → full detail
    """
    completed_lines = []
    active_lines = []
    pending_lines = []
    blocked_lines = []

    phases = plan_data.get("phases", [])
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        phase_name = phase.get("name", "Unknown")
        steps = phase.get("steps", [])

        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios", [])

            for scenario in scenarios:
                if not isinstance(scenario, dict):
                    continue

                task = scenario.get("task", "unknown")
                status = scenario.get("status", "pending")
                priority = scenario.get("priority", 3)
                done = scenario.get("done", False)
                ref_id = scenario.get("_ref_id", "unknown")

                line = f"[{phase_name}] {task} — priority:{priority}"

                if done or status == "completed":
                    summary = scenario.get("result_summary", "completed")
                    completed_lines.append(f"✓ {line} | {summary} | ref:{ref_id}")
                elif status == "active":
                    active_lines.append(f"→ {line} | status:{status} | ref:{ref_id}")
                elif status == "blocked":
                    reason = scenario.get("blocked_reason", "unknown")
                    blocked_lines.append(f"✗ {line} | reason:{reason} | ref:{ref_id}")
                else:
                    pending_lines.append(f"◯ {line} | priority:{priority} | ref:{ref_id}")

    result = "─── COMPRESSED PLAN ───\n"

    if completed_lines:
        result += f"\nCOMPLETED ({len(completed_lines)}):\n"
        result += "\n".join(completed_lines[:20])  # Limit output
        if len(completed_lines) > 20:
            result += f"\n... and {len(completed_lines) - 20} more completed tasks\n"

    if active_lines:
        result += f"\nACTIVE ({len(active_lines)}):\n"
        result += "\n".join(active_lines)

    if pending_lines:
        result += f"\nPENDING ({len(pending_lines)}):\n"
        result += "\n".join(pending_lines[:10])  # Limit to top 10
        if len(pending_lines) > 10:
            result += f"\n... and {len(pending_lines) - 10} more pending tasks\n"

    if blocked_lines:
        result += f"\nBLOCKED ({len(blocked_lines)}):\n"
        result += "\n".join(blocked_lines)

    if not (completed_lines or active_lines or pending_lines or blocked_lines):
        result += "(No tasks recorded yet)\n"

    return result


def build_new_findings_part(
    findings: list[dict[str, Any]],
) -> str:
    """Build PART 4 — New Findings (~3,000 tokens).

    Only findings that arrived since last round (pure delta).
    If nothing new, explicit placeholder.
    """
    if not findings:
        return "─── NEW FINDINGS THIS ROUND ───\nNo new findings this round. Continue executing current plan.\n"

    result = f"─── NEW FINDINGS THIS ROUND ({len(findings)}) ───\n"

    for idx, finding in enumerate(findings[:10], start=1):  # Limit to 10 per round
        ref_id = finding.get("ref_id", f"fin_{idx}")
        tool = finding.get("tool", "unknown")
        target = finding.get("target", "unknown")
        summary = finding.get("summary", "no summary")
        ssvc = finding.get("ssvc", "TRACK")
        cvss = finding.get("cvss_score", "N/A")
        epss = finding.get("epss_score", "N/A")
        cisa_kev = finding.get("cisa_kev", False)
        confirmed = finding.get("confirmed", False)
        action = finding.get("recommended_action", "evaluate")

        cisa_label = "YES" if cisa_kev else "NO"
        confirmed_label = "true" if confirmed else "false"

        result += f"""
[F-{idx:03d}] ref:{ref_id}
Tool      : {tool}
Target    : {target}
Summary   : {summary}
SSVC      : {ssvc}
CVSS      : {cvss} | EPSS: {epss} | CISA KEV: {cisa_label}
Confirmed : {confirmed_label}
Action    : {action}"""

    if len(findings) > 10:
        result += f"\n\n... and {len(findings) - 10} more findings (available via get_finding_detail)\n"

    return result


def build_rag_context_part(
    rag_chunks: list[dict[str, Any]],
) -> str:
    """Build PART 5 — RAG Context (~2,000 tokens).

    Dynamically retrieved knowledge chunks selected for this round's signals.
    """
    if not rag_chunks:
        return "─── RAG CONTEXT ───\n(No relevant knowledge base matches for this round)\n"

    result = f"─── RAG CONTEXT (from vector database) ───\nRetrieved {len(rag_chunks)} chunks:\n"

    for idx, chunk in enumerate(rag_chunks, start=1):
        source = chunk.get("source", "unknown")
        content = chunk.get("content", "")
        score = chunk.get("similarity_score", 0.0)

        # Truncate if too long
        if len(content) > 400:
            content = content[:397] + "..."

        result += f"""
[Chunk {idx} — {source}] (score: {score:.2f})
{content}
"""

    return result


def build_user_directive_part(user_message: str | None) -> str:
    """Build PART 6 — User Directive (~500 tokens).

    Raw user message verbatim, or explicit placeholder if none.
    """
    if not user_message or not user_message.strip():
        return "─── USER DIRECTIVE ───\nNo directive this round. Continue executing current plan autonomously.\n"

    return f"""─── USER DIRECTIVE ───
{user_message}
"""


def build_complete_context_message(
    *,
    engagement_id: str | None,
    round_num: int,
    current_phase: str,
    targets: list[str],
    detected_tech: list[str],
    checklist_coverage: dict[str, Any],
    world_state: dict[str, Any],
    plan_data: dict[str, Any],
    new_findings: list[dict[str, Any]],
    rag_chunks: list[dict[str, Any]],
    user_message: str | None,
) -> str:
    """Construct the complete 6-part context message for the Planner LLM.

    Returns the full message string ready to send to the LLM.
    """
    parts = [
        ("PART 1 — System Core", build_system_core_part()),
        ("PART 2 — Engagement Snapshot", build_engagement_snapshot_part(
            engagement_id=engagement_id,
            round_num=round_num,
            current_phase=current_phase,
            targets=targets,
            detected_tech=detected_tech,
            checklist_coverage=checklist_coverage,
            world_state=world_state,
        )),
        ("PART 3 — Compressed Plan", build_compressed_plan_part(plan_data)),
        ("PART 4 — New Findings", build_new_findings_part(new_findings)),
        ("PART 5 — RAG Context", build_rag_context_part(rag_chunks)),
        ("PART 6 — User Directive", build_user_directive_part(user_message)),
    ]

    # Log token estimates
    total_estimated_tokens = 0
    for part_name, part_content in parts:
        estimated = len(part_content.split()) * 1.3  # Rough estimate
        total_estimated_tokens += estimated
        logger.info(
            "context_part_size",
            part=part_name,
            estimated_tokens=int(estimated),
        )

    logger.info(
        "context_message_complete",
        total_estimated_tokens=int(total_estimated_tokens),
        parts_count=len(parts),
    )

    # Concatenate all parts
    full_message = "\n\n".join(content for _, content in parts)
    return full_message
