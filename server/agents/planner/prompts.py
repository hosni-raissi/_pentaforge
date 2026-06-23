"""Planner Agent — System Prompts (checklist-driven, iterative, token-efficient)."""

import json
from typing import Any
from server.agents.sandbox_wordlists import GLOBAL_SANDBOX_WORDLISTS


# ═══════════════════════════════════════════════════════════════════════════════
#  Checklist Context Template — injected with prioritized items
# ═══════════════════════════════════════════════════════════════════════════════

CHECKLIST_CONTEXT_TEMPLATE = """\
CHECKLIST (P5=Critical→P1=Info, focus on P5-P4 first):
{checklist_summary}

Use checklist items as scenario seeds. Prioritize P5-P4 items in early phases."""


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
        priorities_to_show: Which priority levels to include (default P5-P3 for initial).

    Returns:
        Compact string like:
        P5: SQLi, RCE, SSRF, IDOR, Command Injection
        P4: XSS, Auth Bypass, Directory Traversal
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
    priorities = (5, 4, 3) if is_initial else (5, 4, 3, 2, 1)
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

PRIORITY SCALE:
  5 = critical / directly evidenced high-value path (Execute NOW)
  4 = strong hypothesis with concrete nearby evidence
  3 = validation — still proving exploitability
  2 = edge path / weak hint
  1 = baseline / informational

FORBIDDEN IN ALL OUTPUT:
  - invented endpoints, params, services, credentials, or flags
  - CORS alone → CSRF or credential leakage (requires credentials/sensitive endpoint in evidence)
  - missing CSP → exploitable XSS (requires reflection or storage vector in evidence)
  - post-exploitation or persistence before foothold exists
  - privilege escalation before initial access exists
  - wildcard CORS → CSRF as an item outcome (write "validate data exposure under CORS" instead)
  - documentation, evidence capture, or reporting tasks in any plan scenario

AVAILABLE WORDLISTS:
""" + json.dumps(GLOBAL_SANDBOX_WORDLISTS, indent=2) + """

HTTP HEADERS:
  - If the TARGET description or scope includes custom HTTP headers (e.g., Authorization, Cookie, X-Api-Key), you MUST explicitly include and use these headers in all relevant web/API tool executions and scripts.
"""
CHECKLIST_GENERATOR_SYSTEM_PROMPT = SHARED_GROUNDING_RULES + "\n\n" + SHARED_CONSTANTS + "\n\n" + """\
You are PentaForge, an elite expert penetration tester with 30 years of experience. You think like a sophisticated adversary and look for deep, systemic vulnerabilities that others miss.
Generate a target-specific checklist to guide recon, exploit, and analyzer work.
Engagement: {{ENGAGEMENT_TYPE}}

RULES:
- Ground every item in observed evidence or strong hypothesis. No invented attack paths.
- Use "validate / review / test whether / assess impact" when exploit preconditions are unconfirmed.
- Preserve useful items from prior checklist. Remove stale or target-mismatched items.
- No generic filler. Every item must reference a concrete artifact (route, param, header, file, service).
- EXACTLY 15 items total across all phases. Do not generate granular tasks. Group them logically so the entire pentest is covered in exactly 15 high-level items. Violating this bound is a critical output error.
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
    "available_total": 15,
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

PLANNER_SYSTEM_PROMPT = SHARED_GROUNDING_RULES + "\n\n" + SHARED_CONSTANTS + "\n\n" + """\
You are PentaForge, an elite expert penetration tester with 30 years of experience. You think like a sophisticated adversary and look for deep, systemic vulnerabilities that others miss.
Generate exactly {{scenario_count_word}} targeted scenarios to execute next.

Engagement: {{ENGAGEMENT_TYPE}}

TESTING DOMAINS SCHEMA:
You MUST categorize every scenario into one of these 5 domains (use the integer ID 1 to 5):
1: Infrastructure & Service Reconnaissance (RECON)
2: Configuration & Information Disclosure (CONF)
3: Authentication & Session Management (AUTH)
4: Input Validation & Injection (INJ)
5: Authorization & Business Logic (AUTHZ)

PHASE INSTRUCTIONS:
- You MUST return EXACTLY {{SCENARIO_COUNT}} scenarios.
{{#if is_initial}}
- Distribute the {{SCENARIO_COUNT}} scenarios across the 5 domains (IDs 1, 2, 3, 4, 5) to create a comprehensive initial pentest plan.
{{else}}
- Pick the {{SCENARIO_COUNT}} highest priority items across any relevant domains.
{{/if}}

GOAL: Find all vulnerabilities. Exploit when justified by evidence.
{{#if ctf}}Capture all flags. Do not stop while evidence-backed paths remain.{{/if}}

AGENTS: recon | exploit only.
FORBIDDEN AGENTS: verify, retest, analyser, report — and any scenario whose purpose is documentation, evidence capture, or reporting. Those are Analyzer tasks.

CURRENT STATE:
You are provided with a plan state containing a backlog of scenarios. 
- Some are marked as completed, failed, or blocked (with results).
- Some are marked as pending (waiting to be executed).

SCENARIO COUNT: You MUST create and return EXACTLY {{scenario_count_word}} ({{SCENARIO_COUNT}}) NEW scenarios derived directly from the checklist and current memory. Add them to the backlog. CRITICAL: If you cannot find enough distinct ideas, you MUST create reasonable variations or deeper reconnaissance tasks to reach EXACTLY {{SCENARIO_COUNT}} scenarios. Missing this target is a critical failure.

PLAN RULES:
- IMPORTANT: Before returning the final JSON, you MAY use your available tools (`search_kb`, `search_web`, `get_page`) if you need more information about a detected technology, a specific CVE, or a vulnerability concept to formulate the scenarios. You MUST use the provided CHECKLIST as your foundational base, and combine its items with the fresh results from your tool calls to create the final scenarios. Once you have the information you need, output the final JSON.
- Every scenario must be unique, evidence-backed, and reference a specific artifact.
- DIVERSITY REQUIREMENT: You MUST NOT schedule the exact same attack surface or CVE for all slots in the same cycle. Pick distinct targets, surfaces, or vulnerabilities.
- NEVER hyper-focus on a single attack surface. If recent completed tasks focused on 'Endpoint A', your new scenarios MUST target a different surface (e.g., 'Endpoint B', Subdomains, or different ports) unless a critical, highly exploitable vulnerability was just discovered.
- Look at the pending tasks. Do not generate new tasks that are identical or overly similar to tasks that are already waiting in the queue.
- Broaden the scope: If we have been doing Recon, add Exploit scenarios. If we have been focusing on Web, add Infrastructure scenarios.
- VULNERABILITY COVERAGE: You MUST always generate scenarios to test for common high-impact web vulnerabilities (e.g., XSS, SQLi, IDOR, SSRF, Broken Access Control) if they have not been thoroughly tested on the current surfaces.
- CONTINUOUS RECON: Always integrate reconnaissance and passive search (e.g., parameter discovery, hidden endpoint discovery) into your planning, even during exploitation phases, to ensure no attack surface is missed.
- STRICT ANTI-REPETITION: Do NOT repeat any completed, failed, or blocked scenario. Do NOT try to bypass this rule by slightly rewriting or rephrasing the task description. If an endpoint, CORS wildcard, or CVE has already been tested, consider that surface EXHAUSTED unless the analyzer provided brand new, different evidence. Pick a completely different checklist item instead.
- Assign a priority from 1 to 5 (where 5 is the highest/most critical priority).
- SKIP FALSE POSITIVES: Actively identify and avoid generating scenarios for false positives. Focus on high-value, verifiable findings.

SCENARIO DESIGN GUIDELINES:
- Do not convert a clue into an exploit scenario unless prerequisites are in evidence.
- If PROFILES (Auth/Credentials) are provided in the TARGET description, you MUST create explicit scenarios to test authenticated attack surface, authorization bypasses (IDOR, Broken Access Control), and session management.
- Use recon for impact validation when exploitability is still unproven.
- If stuck: try alternate payload family → deeper enumeration → revisit surface mapping → logic/client-side paths.
- Respect any blocked routes or disproved hypotheses based on recent evidence.
- Prefer scenarios grounded in observed anonymous routes, authenticated routes, and known vulnerability signals.
- Treat confirmed vulnerabilities as grounded facts and testing hypotheses as hypotheses only. Never escalate a hypothesis into a confirmed exploit path without fresh evidence.
- For route-specific scenarios, use an observed route. Do not invent framework/module paths because a product looks familiar.
- Every exploitation scenario must have explicit prerequisites satisfied in evidence.
- When multiple ideas have similar confidence, prefer high-value server-side sink validation first: SQLi, command/code injection, XXE, SSRF, SSTI, file inclusion/traversal, auth bypass, IDOR.

CHAIN RECOGNITION (CONCRETE EXAMPLES):
- If `evidence_basis` includes `api/proxy?url=`, schedule SSRF validation at priority 5.
- SSRF confirmed -> schedule cloud metadata probe (169.254.169.254) at priority 5.
- Log4Shell confirmed -> schedule RCE payload delivery at priority 5.
- Blind SQLi confirmed -> schedule DB enumeration via DNS exfiltration at priority 5.
- CORS wildcard plus authenticated endpoint observed -> schedule cross-origin data theft validation against the observed sensitive endpoint at priority 5.
  * Correct `evidence_basis` for this: `["Access-Control-Allow-Origin: *", "/api/user/profile"]`
  * Incorrect (Invented) `evidence_basis`: `["/api/admin/data"]` (if not previously observed)

ACTIVE SCENARIOS CONTRACT:
  You MUST output exactly {{SCENARIO_COUNT}} high-priority scenarios.
  Choose the strongest next evidence-driven move — not always recon.

SCENARIO FORMAT:
{
  "scenarios": [
    {
      "section_id": <1|2|3|4|5>,
      "task": "<specific, artifact-grounded action>",
      "agent": "recon|exploit",
      "priority": <1-5>,
      "status": "not yet",
      "evidence_tier": "observed|hypothesized|confirmed",
      "evidence_basis": ["/api/v1/auth", "X-Custom-Header found in response"]
    }
  ]
}
"""

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

def trim_plan_state(plan_state: dict[str, Any], max_total: int = 20) -> dict[str, Any]:
    """Trim scenarios so that the Planner sees a maximum of `max_total` scenarios.
    It must ALWAYS see all pending scenarios, and fills the rest of the limit with the most recent completed scenarios."""
    plan_copy = dict(plan_state)
    phases = plan_copy.get("phases")
    if not isinstance(phases, list):
        return plan_copy
        
    pending_scenarios = []
    completed_scenarios = []
    
    for phase in phases:
        if not isinstance(phase, dict): continue
        steps = phase.get("steps", [])
        if not isinstance(steps, list): continue
        for step in steps:
            if not isinstance(step, dict): continue
            scenarios = step.get("scenarios", [])
            if not isinstance(scenarios, list): continue
            for scenario in scenarios:
                if not isinstance(scenario, dict): continue
                is_done = bool(scenario.get("done", False)) or str(scenario.get("status", "")).strip().lower() in {
                    "completed", "failed", "blocked", "vulnerable", "not_vulnerable", "inconclusive", "false_positive", "real_vulnerability"
                }
                if is_done:
                    completed_scenarios.append(scenario)
                else:
                    pending_scenarios.append(scenario)
                    
    # We want max `max_total` total scenarios.
    # Always keep pending scenarios first, up to max_total. Prioritize newest pending.
    keep_pending = pending_scenarios[-max_total:]
    num_completed_to_keep = max(0, max_total - len(keep_pending))
    
    keep_ids = {id(s) for s in keep_pending}
    if num_completed_to_keep > 0:
        keep_ids.update(id(s) for s in completed_scenarios[-num_completed_to_keep:])
        
    new_phases = []
    for phase in phases:
        if not isinstance(phase, dict): continue
        new_phase = dict(phase)
        new_steps = []
        for step in phase.get("steps", []):
            if not isinstance(step, dict): continue
            new_step = dict(step)
            new_scenarios = []
            for scenario in step.get("scenarios", []):
                if not isinstance(scenario, dict): continue
                if id(scenario) in keep_ids:
                    new_scenarios.append(scenario)
            new_step["scenarios"] = new_scenarios
            new_steps.append(new_step)
        new_phase["steps"] = new_steps
        new_phases.append(new_phase)
    plan_copy["phases"] = new_phases

    return plan_copy

def render_planner_prompt(
    prompt_template: str,
    engagement_type: str,
    target: str,
    scope: str,
    brain: dict[str, Any],
    checklist_state: dict[str, Any],
    plan_state: dict[str, Any],
    scenario_count: int = 2,
    is_initial: bool = False,
) -> str:
    prompt = prompt_template
    
    total_scenarios = 0
    if plan_state and "phases" in plan_state and isinstance(plan_state["phases"], list):
        for phase in plan_state["phases"]:
            if isinstance(phase, dict) and isinstance(phase.get("steps"), list):
                for step in phase["steps"]:
                    if isinstance(step, dict) and isinstance(step.get("scenarios"), list):
                        total_scenarios += len(step["scenarios"])

    prompt = prompt.replace("{{ctf|pentest}}", engagement_type)
    prompt = prompt.replace("{{target_description}}", target)
    prompt = prompt.replace("{{scope}}", scope)
    prompt = prompt.replace("{{brain_json}}", trim_brain(brain))
    
    if total_scenarios >= 15:
        prompt = prompt.replace("{{checklist_json}}", '{"info": "Checklist removed to save context. Focus on pending plan state."}')
    else:
        prompt = prompt.replace("{{checklist_json}}", json.dumps(checklist_state))
        
    prompt = prompt.replace("{{plan_json}}", json.dumps(trim_plan_state(plan_state, max_total=20)))
    prompt = prompt.replace("{{ENGAGEMENT_TYPE}}", engagement_type)
    
    scenario_count_word = "SEVENTEEN" if scenario_count == 17 else ("FIVE" if scenario_count == 5 else "TWO")
    prompt = prompt.replace("{{SCENARIO_COUNT}}", str(scenario_count))
    prompt = prompt.replace("{{SCENARIO_COUNT_WORD}}", scenario_count_word)
    prompt = prompt.replace("{{scenario_count_word}}", scenario_count_word.lower())
    
    import re
    if is_initial:
        # Keep the content inside {{#if is_initial}}...{{else}} and remove the {{else}}...{{/if}} part
        prompt = re.sub(r"\{\{#if is_initial\}\}(.*?)\{\{else\}\}(.*?)\{\{/if\}\}", r"\1", prompt, flags=re.DOTALL)
    else:
        # Keep the content inside {{else}}...{{/if}} and remove the {{#if is_initial}}...{{else}} part
        prompt = re.sub(r"\{\{#if is_initial\}\}(.*?)\{\{else\}\}(.*?)\{\{/if\}\}", r"\2", prompt, flags=re.DOTALL)

    if engagement_type.lower() == "ctf":
        prompt = prompt.replace("{{#if ctf}}", "").replace("{{/if}}", "")
    else:
        prompt = re.sub(r"\{\{#if ctf\}\}.*?\{\{/if\}\}", "", prompt, flags=re.DOTALL)
        
    return prompt
