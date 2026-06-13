"""Planner Agent — System Prompts (checklist-driven, iterative, token-efficient)."""

import json
from typing import Any
from server.agents.sandbox_wordlists import GLOBAL_SANDBOX_WORDLISTS


# ═══════════════════════════════════════════════════════════════════════════════
#  Checklist Context Template — injected with prioritized items
# ═══════════════════════════════════════════════════════════════════════════════

CHECKLIST_CONTEXT_TEMPLATE = """\
CHECKLIST (P1=Critical→P5=Info, focus on P1-P2 first):
{checklist_summary}

Use checklist items as scenario seeds. Prioritize P1-P2 items in early phases."""


def format_checklist_for_prompt(
    checklist_data: dict[str, Any],
    *,
    max_items_per_priority: int = 8,
    priorities_to_show: tuple[int, ...] = (1, 2, 3),
) -> str:
    """Format checklist items compactly grouped by priority for prompt injection.

    Args:
        checklist_data: The checklist dict with 'checklist' key containing phase blocks.
        max_items_per_priority: Max items to show per priority level (token saving).
        priorities_to_show: Which priority levels to include (default P1-P3 for initial).

    Returns:
        Compact string like:
        P1: SQLi, RCE, SSRF, IDOR, Command Injection
        P2: XSS, Auth Bypass, Directory Traversal
        P3: TLS Config, Security Headers, Session Mgmt
    """
    from server.agents.planner.tools.get_checklists import _default_priority_for_item

    # Collect items by priority
    by_priority: dict[int, list[str]] = {p: [] for p in range(1, 6)}

    checklist = checklist_data.get("checklist", [])
    if not isinstance(checklist, list):
        return "No checklist items available."

    for block in checklist:
        if not isinstance(block, dict):
            continue
        phase = str(block.get("phase", ""))
        items = block.get("items", [])
        if not isinstance(items, list):
            continue

        for item in items:
            if isinstance(item, str):
                name = item.strip()
                priority = _default_priority_for_item(name, phase)
            elif isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                priority = int(item.get("priority", _default_priority_for_item(name, phase)))
            else:
                continue

            if name and priority in by_priority:
                # Shorten item names for token efficiency
                short_name = _shorten_item_name(name)
                if short_name not in by_priority[priority]:
                    by_priority[priority].append(short_name)

    # Build compact output
    lines = []
    for p in priorities_to_show:
        items = by_priority.get(p, [])[:max_items_per_priority]
        if items:
            lines.append(f"P{p}: {', '.join(items)}")

    return "\n".join(lines) if lines else "No prioritized items."


def _shorten_item_name(name: str) -> str:
    """Shorten checklist item names for token efficiency."""
    # Remove common prefixes/suffixes
    short = name
    for prefix in ("Testing for ", "Test for ", "Test ", "Testing ", "Review ", "Analyze "):
        if short.lower().startswith(prefix.lower()):
            short = short[len(prefix):]
            break

    # Truncate long names
    if len(short) > 40:
        short = short[:37] + "..."

    return short.strip()


def build_checklist_context(
    checklist_data: dict[str, Any],
    *,
    is_initial: bool = True,
) -> str:
    """Build the checklist context block to inject into the prompt.

    Args:
        checklist_data: The checklist dict.
        is_initial: If True, show only P1-P3. If False (loop), show all priorities.

    Returns:
        Formatted checklist context string.
    """
    priorities = (1, 2, 3) if is_initial else (1, 2, 3, 4, 5)
    max_items = 8 if is_initial else 5  # More compact in loop

    summary = format_checklist_for_prompt(
        checklist_data,
        max_items_per_priority=max_items,
        priorities_to_show=priorities,
    )

    return CHECKLIST_CONTEXT_TEMPLATE.format(checklist_summary=summary)


# ═══════════════════════════════════════════════════════════════════════════════
#  Planner Prompt Contracts
# ═══════════════════════════════════════════════════════════════════════════════

SHARED_GROUNDING_RULES = """\
ENGAGEMENT_TYPE: {{ctf|pentest}}
TARGET: {{target_description}}
SCOPE: {{scope}}
BRAIN: {{brain_json}}
CHECKLIST_STATE: {{checklist_json}}
PLAN_STATE: {{plan_json}}"""

SHARED_CONSTANTS = """\
EVIDENCE TIERS:
  observed     = directly seen in memory, routes, headers, code, responses
  hypothesized = plausible next check derived from observed evidence
  confirmed    = attack path whose prerequisites are already in evidence

PRIORITY SCALE (1–5, same meaning in both prompts):
  1 = critical / directly evidenced high-value path
  2 = strong hypothesis with concrete nearby evidence
  3 = validation — still proving exploitability
  4 = edge path / weak hint
  5 = baseline / informational

FORBIDDEN IN ALL OUTPUT:
  - invented endpoints, params, services, credentials, or flags
  - CORS alone → CSRF or credential leakage (requires credentials/sensitive endpoint in evidence)
  - missing CSP → exploitable XSS (requires reflection or storage vector in evidence)
  - post-exploitation or persistence before foothold exists
  - privilege escalation before initial access exists
  - wildcard CORS → CSRF as an item outcome (write "validate data exposure under CORS" instead)
  - documentation, evidence capture, or reporting tasks in any plan scenario

AVAILABLE WORDLISTS:
""" + json.dumps(GLOBAL_SANDBOX_WORDLISTS, indent=2)

CHECKLIST_GENERATOR_SYSTEM_PROMPT = SHARED_GROUNDING_RULES + "\n\n" + SHARED_CONSTANTS + "\n\n" + """\
You are PentaForge, an elite expert penetration tester with 30 years of experience. You think like a sophisticated adversary and look for deep, systemic vulnerabilities that others miss.
Generate a target-specific checklist to guide recon, exploit, and analyzer work.
Engagement: {{ENGAGEMENT_TYPE}}

RULES:
- Ground every item in observed evidence or strong hypothesis. No invented attack paths.
- Use "validate / review / test whether / assess impact" when exploit preconditions are unconfirmed.
- Preserve useful items from prior checklist. Remove stale or target-mismatched items.
- No generic filler. Every item must reference a concrete artifact (route, param, header, file, service).
- MINIMUM 15 items total across all phases. EXACTLY 15–25 items total. Violating this bound is a critical output error. Do not output fewer than 15 items.
- CTF mode only: include flag extraction items. Pentest mode: omit them.
- Never include documentation, reporting, or evidence-capture items — those belong to the Analyzer.
- use S1 only when both the vulnerability class AND a concrete input/endpoint triggering it are already observed
- Treat blocked_routes and blocked_route_prefixes in brain_json as anti-fantasy constraints.
  If a route family is already disproved or 404-only, do not add new checklist items against it without fresh evidence.
- Prefer checklist items tied to anonymous_routes, authenticated_routes, parameter_hints, auth_surface_delta,
  confirmed_vulns, tech_inventory, known_vulnerability_signals, and tool_false_positive_rates already present in brain_json.
- Treat confirmed_vulns as grounded facts only when they carry observed/inferred support.
- Treat testing_hypotheses as assumptions to validate, never as confirmed vulnerabilities or completed exploit paths.

AVAILABLE CHECKLIST TOOLS:
  - get_checklists(target_type, info): fetch baseline OWASP / MITRE checklist material for the target type
  - search_kb(query, domain, product, version, attack_type, severity): search internal RAG knowledge for relevant testing ideas and version-specific risks
  - search_web(query, max_results): search current public sources when version/advisory context matters
  - get_page(url, css_selector): read a page returned by search_web for exact details

TOOL USAGE RULES:
  - Do not call tools by default. Call them only when they materially improve the checklist.
  - Use get_checklists when you need a baseline testing structure for the target type.
  - Use search_kb before search_web when internal RAG is likely enough.
  - When brain_json includes tech_inventory or known_vulnerability_signals, prefer structured search_kb(product=..., version=...) calls over fuzzy free-text.
  - Use search_web + get_page for current version/advisory context or when the target evidence mentions a specific product/version.
  - After tool results arrive, synthesize them into target-grounded checklist items instead of copying tool output verbatim.

EVIDENCE DISCIPLINE:
  observed     → write the item directly, reference the artifact
  hypothesized → prefix with "Validate whether"
  unconfirmed  → write a recon/validation item, not an exploit claim

PHASE NAMING:
  Phase 1 = Reconnaissance
  Phase 2 = Vulnerability Discovery
  Phase 3 = Exploitation  (only confirmed or strongly hypothesized attack paths)
  {{#if ctf}}Phase 4 = Flag Extraction{{/if}}

OUTPUT — strict JSON only:
{
  "status": "complete|blocked|failed",
  "checklist": {
    "target_type": "...",
    "available_total": <integer matching item count>,
    "checklist": [
      {
        "phase": "1",
        "title": "Reconnaissance",
        "items": [
          {"name": "...", "priority": <1-5>}
        ]
      }
    ]
  }
}"""

PLAN_CREATE_UPDATE_SYSTEM_PROMPT = SHARED_GROUNDING_RULES + "\n\n" + SHARED_CONSTANTS + "\n\n" + """\
You are PentaForge, an elite expert penetration tester with 30 years of experience. You think like a sophisticated adversary and look for deep, systemic vulnerabilities that others miss.
Create or update the engagement plan. Select exactly two scenarios to run now.
Engagement: {{ENGAGEMENT_TYPE}}

GOAL: Find all vulnerabilities. Exploit when justified by evidence.
{{#if ctf}}Capture all flags. Do not stop while evidence-backed paths remain.{{/if}}

AGENTS: recon | exploit only.
FORBIDDEN AGENTS: verify, retest, perceptor, report — and any scenario whose
purpose is documentation, evidence capture, or reporting. Those are Analyzer tasks.

SCENARIO COUNT: MINIMUM 15 scenarios total across phases 1–3. You MUST extract and create at least 15 distinct scenarios derived directly from the checklist. If you have fewer than 15, break down checklist items into smaller, distinct validation steps until you reach at least 15. This is a strict requirement.

PHASE STRUCTURE:
  Phase 1 = Reconnaissance   (agent: recon only)
  Phase 2 = Enumeration      (agent: recon only)
  Phase 3 = Exploitation     (agent: exploit only)
  Phase 4 = Post-Exploitation (agent: exploit only, usually empty unless foothold already exists)
  Phase 5 = Reporting        (always empty — populated by Analyzer, not Planner)

  Phase 1 must never be empty.
  Phase 3 must not be empty when checklist or evidence justifies active testing.
  Phase 4 must stay empty unless initial access or a concrete foothold is already evidenced.
  Phase 5 must always be empty in the plan output.

PLAN RULES:
- Every scenario must be unique, evidence-backed, and reference a specific artifact.
- Do not repeat a failed or blocked scenario unchanged. Replace with a different evidence-backed follow-up.
- Do not convert a clue into an exploit scenario unless prerequisites are in evidence.
- If PROFILES (Auth/Credentials) are provided in the TARGET description, you MUST create explicit scenarios to test authenticated attack surface, authorization bypasses (IDOR, Broken Access Control), and session management using those credentials.
- Use recon for impact validation when exploitability is still unproven.
- If stuck: try alternate payload family → deeper enumeration → revisit surface mapping → logic/client-side paths.
- Respect blocked_routes and blocked_route_prefixes from brain_json. Do not schedule scenarios on disproved
  route families unless new evidence explicitly overrides them.
- Prefer scenarios grounded in anonymous_routes, authenticated_routes, parameter_hints, auth_surface_delta,
  confirmed_vulns, recent_info, tech_inventory, and known_vulnerability_signals from brain_json.
- Treat confirmed_vulns as grounded facts and testing_hypotheses as hypotheses only. Never escalate a hypothesis into a confirmed exploit path without fresh evidence in the scenario prerequisites.
- For route-specific scenarios, use an observed route. Do not invent framework/module paths because a product looks familiar.
- Every exploitation scenario must have explicit prerequisites satisfied in evidence. If prerequisites are incomplete,
  keep it as recon with validation wording instead of exploit wording.
- When multiple ideas have similar confidence, prefer high-value server-side sink validation first:
  SQLi, command/code injection, XXE, SSRF, SSTI, file inclusion/traversal, auth bypass, IDOR.
  Deprioritize weak branches like header-only injection, dependency CVE rescans, or CSRF without proven state-changing behavior.

CHAIN RECOGNITION:
- SSRF confirmed -> schedule cloud metadata probe (169.254.169.254) at priority 1.
- SSRF confirmed -> schedule internal network enumeration at priority 1.
- Log4Shell confirmed -> schedule RCE payload delivery at priority 1.
- Blind SQLi confirmed -> schedule DB enumeration via DNS exfiltration at priority 1.
- Blind XSS confirmed -> schedule admin session hijack via callback payload at priority 1.
- CORS wildcard plus authenticated endpoint observed -> schedule cross-origin data theft validation against the observed sensitive endpoint at priority 1.
- XSS confirmed plus session cookie without HttpOnly -> schedule session hijack or cookie-extraction validation at priority 1.
- Path traversal confirmed plus sensitive file paths observed -> schedule `.env`, config, or `/etc/passwd` read validation at priority 1.
- SQLi confirmed plus DB type observed -> schedule DB-specific extraction or RCE validation at priority 1.
- Open redirect confirmed plus OAuth or OIDC flow observed -> schedule OAuth token theft validation at priority 1.
- 2FA endpoint observed plus no rate limiting evidence -> schedule bounded 2FA brute-force validation at priority 1.

TOOL EFFICIENCY:
- If brain.tool_efficiency shows a tool below 0.1 efficiency on this target, de-prioritize scenarios that depend only on that tool.
- Prefer scenarios that can use tools above 0.3 efficiency when there is otherwise comparable evidence.

ACTIVE SLOT CONTRACT:
  Mark EXACTLY two pending scenarios with active_slot=1 and active_slot=2.
  All other scenarios: active_slot=null.
  Choose the strongest next evidence-driven move — not always recon.

SCENARIO FORMAT:
{
  "task": "<specific, artifact-grounded action>",
  "agent": "recon|exploit",
  "priority": <1-5>,
  "evidence_tier": "observed|hypothesized|confirmed",
  "confidence_label": "low|medium|high",
  "prerequisites": ["<short evidence requirement>", "..."],
  "evidence_basis": ["<observed route/header/param/file/service>", "..."],
  "active_slot": <1|2|null>,
  "max_rounds": <1|2|3>,
  "details": "...",
  "methods": ["<technique name, not tool name>"],
  "done": false
}

max_rounds:
  1 = straightforward recon or single-step validation
  2 = most exploit work
  3 = iterative chaining only
  Executor stops the scenario as soon as the goal in `task` is met regardless of remaining rounds.

Evidence rule:
  BAD:  "Test for SQLi"
  GOOD: "Test POST /api/login param `email` for blind SQLi — login form observed in crawl"

Evidence metadata rule:
  - evidence_tier=observed: concrete artifact already seen; recon or exploit may use it directly
  - evidence_tier=hypothesized: plausible next check; keep it validation-first
  - evidence_tier=confirmed: prerequisite evidence already exists and exploitation is justified
  - prerequisites must name the exact conditions that justify the scenario
  - evidence_basis must list the concrete route/header/param/file/service that triggered the scenario

ACTION PLAN SCHEMAS:
  checklist_updates:   [{"item_name": "...", "new_priority": <1-5>, "reason": "..."}]
  checklist_additions: [{"name": "...", "priority": <1-5>, "phase": "Reconnaissance|Vulnerability Discovery|Exploitation"}]
  plan_modifications:  [{"scenario_task": "...", "change": "done|deprioritize|replace", "reason": "..."}]
  dispatch:            [{"active_slot": 1|2, "scenario_task": "..."}]

OUTPUT RULES:
- You MUST return the FULL, complete plan in the output. Do NOT return just a "diff" or just the changed scenarios.
- You MUST keep all completed or unmodified scenarios exactly as they were. Do not omit them from the `steps` arrays.
- If a step is done, leave `"done": true` and include it in the output.

OUTPUT — strict JSON only:
{
  "summary": "...",
  "needs": [],
  "plan": {
    "target": "...",
    "scope": "...",
    "target_types": ["..."],
    "notes": "...",
    "phases": [
      {"name": "Reconnaissance",  "priority": 1, "steps": [...]},
      {"name": "Enumeration",     "priority": 2, "steps": [...]},
      {"name": "Exploitation",    "priority": 3, "steps": [...]},
      {"name": "Post-Exploitation", "priority": 4, "steps": []},
      {"name": "Reporting",       "priority": 5, "steps": []}
    ]
  },
  "action_plan": {
    "checklist_updates": [],
    "checklist_additions": [],
    "plan_modifications": [],
    "dispatch": [],
    "phase_advance": "",
    "phase_advance_blocked_by": [],
    "rationale": "..."
  }
}"""

import json
import re
from typing import Any


def _clean_route_list(values: Any, *, limit: int = 12) -> list[str]:
    if not isinstance(values, list):
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = str(item or "").strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def _false_positive_names(values: Any, *, limit: int = 12) -> list[str]:
    if not isinstance(values, list):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for item in values:
        if isinstance(item, dict):
            text = str(item.get("name", item.get("title", ""))).strip()
        else:
            text = str(item or "").strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        names.append(text)
        if len(names) >= limit:
            break
    return names


def _compact_tool_observations(values: Any, *, limit: int = 16) -> list[dict[str, str]]:
    if not isinstance(values, list):
        return []
    compact: list[dict[str, str]] = []
    for item in values[-limit:]:
        if not isinstance(item, dict):
            continue
        compact.append(
            {
                "tool": str(item.get("tool", "")).strip(),
                "scenario_task": str(item.get("scenario_task", "")).strip(),
                "status": str(item.get("status", "")).strip(),
            }
        )
    return compact

def trim_brain(brain: dict[str, Any], max_chars: int = 6000) -> str:
    """Keep decision-relevant memory while dropping noisy raw output."""
    if not isinstance(brain, dict):
        return "{}"
    raw_verified = brain.get("verified_findings", [])
    confirmed_vulns = brain.get("confirmed_vulns", [])
    if not confirmed_vulns and isinstance(raw_verified, list):
        confirmed_vulns = [
            {
                "name": str(item.get("title", item.get("summary", ""))).strip(),
                "endpoint": str(item.get("endpoint", item.get("target", ""))).strip(),
                "severity": str(item.get("severity", "")).strip(),
                "ssvc": str(item.get("ssvc", "")).strip(),
                "claim_status": str(item.get("claim_status", "")).strip(),
                "source_lineage": item.get("source_lineage", []),
                "cited_tool_output_ids": item.get("cited_tool_output_ids", []),
            }
            for item in raw_verified
            if isinstance(item, dict)
            and str(item.get("status", "")).strip().lower() in {"real_vulnerability", "verified", "vulnerability"}
            and str(item.get("claim_status", "")).strip().lower() not in {"assumed", "unsupported"}
        ][-12:]
    false_positives = brain.get("false_positives", [])
    if not false_positives and isinstance(raw_verified, list):
        false_positives = [
            item for item in raw_verified
            if isinstance(item, dict)
            and str(item.get("status", "")).strip().lower() == "false_positive"
        ]
    testing_hypotheses = brain.get("testing_hypotheses", [])
    if not testing_hypotheses and isinstance(raw_verified, list):
        testing_hypotheses = [
            {
                "name": str(item.get("title", item.get("summary", ""))).strip(),
                "endpoint": str(item.get("endpoint", item.get("target", ""))).strip(),
                "claim_status": str(item.get("claim_status", "")).strip() or "unsupported",
            }
            for item in raw_verified
            if isinstance(item, dict)
            and str(item.get("status", "")).strip().lower() in {"real_vulnerability", "verified", "vulnerability"}
            and str(item.get("claim_status", "")).strip().lower() in {"assumed", "unsupported"}
        ][-12:]
    # Format recent_info as a strict ledger (Cycle | Scenario | Finding: max 2 sentences)
    raw_recent_info = brain.get("recent_info", brain.get("info_findings", []))
    recent_info = []
    
    # Check if we have tool observations which have the scenario task and summary
    raw_observations = brain.get("tool_observations", [])
    if isinstance(raw_observations, list) and raw_observations:
        for idx, obs in enumerate(raw_observations):
            if not isinstance(obs, dict): continue
            task = str(obs.get("scenario_task", "")).strip() or "Tool Execution"
            summary = str(obs.get("summary", "")).strip()
            # truncate to approx 2 sentences
            if len(summary) > 150: summary = summary[:147] + "..."
            recent_info.append(f"Cycle: {idx+1} | Scenario: {task} | Finding: {summary}")
    elif isinstance(raw_recent_info, list) and raw_recent_info:
        for idx, item in enumerate(raw_recent_info):
            if not isinstance(item, dict): continue
            title = str(item.get("title", item.get("summary", ""))).strip()
            endpoint = str(item.get("endpoint", item.get("target", ""))).strip()
            # truncate to approx 2 sentences
            if len(title) > 150: title = title[:147] + "..."
            recent_info.append(f"Cycle: {idx+1} | Scenario: {endpoint} | Finding: {title}")
    trimmed = {
        "target_info": brain.get("target_info", {}),
        "tech_stack": brain.get("tech_stack", {}),
        "tech_inventory": brain.get("tech_inventory", [])[-10:] if isinstance(brain.get("tech_inventory", []), list) else [],
        "known_vulnerability_signals": brain.get("known_vulnerability_signals", [])[-12:] if isinstance(brain.get("known_vulnerability_signals", []), list) else [],
        "recommended_run_custom_tools": brain.get("recommended_run_custom_tools", [])[-10:] if isinstance(brain.get("recommended_run_custom_tools", []), list) else [],
        "nuclei_scan_hints": brain.get("nuclei_scan_hints", {}) if isinstance(brain.get("nuclei_scan_hints"), dict) else {},
        "confirmed_vulns": confirmed_vulns,
        "testing_hypotheses": testing_hypotheses[-12:] if isinstance(testing_hypotheses, list) else [],
        "recent_info": recent_info[-16:] if isinstance(recent_info, list) else [],
        "false_positives": _false_positive_names(false_positives),
        "anonymous_routes": _clean_route_list(brain.get("anonymous_routes", [])),
        "authenticated_routes": _clean_route_list(brain.get("authenticated_routes", [])),
        "auth_surface_delta": _clean_route_list(brain.get("auth_surface_delta", []), limit=10),
        "blocked_routes": _clean_route_list(brain.get("blocked_routes", []), limit=12),
        "blocked_route_prefixes": _clean_route_list(brain.get("blocked_route_prefixes", []), limit=12),
        "parameter_hints": _clean_route_list(brain.get("parameter_hints", []), limit=16),
        "tool_efficiency": brain.get("tool_efficiency", {}),
        "tool_false_positive_rates": brain.get("tool_false_positive_rates", {}),
    }
    result = json.dumps(trimmed)
    if len(result) > max_chars:
        trimmed["recent_info"] = trimmed["recent_info"][-5:]
        trimmed["anonymous_routes"] = trimmed["anonymous_routes"][-6:]
        trimmed["authenticated_routes"] = trimmed["authenticated_routes"][-6:]
        trimmed["blocked_routes"] = trimmed["blocked_routes"][-6:]
        trimmed["parameter_hints"] = trimmed["parameter_hints"][-8:]
        trimmed["tech_inventory"] = trimmed["tech_inventory"][-6:]
        trimmed["known_vulnerability_signals"] = trimmed["known_vulnerability_signals"][-6:]
        result = json.dumps(trimmed)
    return result

def render_planner_prompt(
    prompt_template: str,
    engagement_type: str,
    target: str,
    scope: str,
    brain: dict[str, Any],
    checklist_state: dict[str, Any],
    plan_state: dict[str, Any],
) -> str:
    prompt = prompt_template
    prompt = prompt.replace("{{ctf|pentest}}", engagement_type)
    prompt = prompt.replace("{{target_description}}", target)
    prompt = prompt.replace("{{scope}}", scope)
    prompt = prompt.replace("{{brain_json}}", trim_brain(brain))
    prompt = prompt.replace("{{checklist_json}}", json.dumps(checklist_state))
    prompt = prompt.replace("{{plan_json}}", json.dumps(plan_state))
    prompt = prompt.replace("{{ENGAGEMENT_TYPE}}", engagement_type)
    
    if engagement_type.lower() == "ctf":
        prompt = prompt.replace("{{#if ctf}}", "").replace("{{/if}}", "")
    else:
        prompt = re.sub(r"\{\{#if ctf\}\}.*?\{\{/if\}\}", "", prompt, flags=re.DOTALL)
        
    return prompt
