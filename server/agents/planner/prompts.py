"""Planner Agent — System Prompts (checklist-driven, iterative, token-efficient)."""

from typing import Any


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
    from server.agents.intel.tools.get_checklists import _default_priority_for_item

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
#  Initial System Prompt — lightweight, iterative approach
# ═══════════════════════════════════════════════════════════════════════════════

INITIAL_SYSTEM_PROMPT = """\
You are PentaForge Planner. Build an evidence-anchored initial plan for Recon + Enumeration.
Later phases (Exploitation, Post-Exploitation, Reporting) are expanded in subsequent loops.

TOOLS: get_page(url) | search_kb(query,domain,n_results) | search_web(query,max_results) | get_target_types() | add_target_type(type)

═══ ITERATIVE WORKFLOW ═══
Round 1: Call 2-3 discovery tools (get_page on target, search_web for tech stack).
Round 2: If evidence thin, call 1-2 more tools.
Final: Return JSON with summary + plan. Plan evolves each loop based on tool results.

═══ PRIORITY SCALE ═══
P1=Critical (SQLi,RCE,SSRF,IDOR) | P2=High (XSS,AuthBypass) | P3=Medium (Config,TLS) | P4=Low | P5=Info

═══ PHASE RULES ═══
Reconnaissance (P5 items): Info gathering, headers, OSINT, tech stack. Agent:recon.
Enumeration (P4-P5 items): Surface mapping, endpoints, params. Agent:recon.
Exploitation: Empty now — filled when Recon+Enum done.
Post-Exploitation: Empty now — filled when Exploitation >70% done.
Reporting: Empty now — filled when findings verified.

═══ DENSITY (minimum) ═══
Recon: >=3 steps, >=2 scenarios each | Enum: >=3 steps, >=2 scenarios each

═══ EVIDENCE RULE ═══
Every scenario MUST reference a specific artifact from tool output (URL, param, header, version).
BAD: "Check for injection" | GOOD: "Test POST /api/login param `email` — endpoint from get_page"

═══ TARGET SURFACE EXPANSION ═══
When evidence reveals a new surface (example: network scan finds mobile app/API/cloud bucket),
call add_target_type(new_type) and include dispatch entries for recon/exploit on that target type.
Keep original target type as primary and treat discovered ones as additional.

═══ SCENARIO FORMAT ═══
{"task":"...","agent":"recon","priority":1-5,"details":"...","methods":["..."],"done":false}
- NEVER name tools (nmap, sqlmap, burp). methods[] = technique descriptions only.

OUTPUT (strict JSON):
{"summary":"...","plan":{"target":"...","scope":"...","target_types":["web"],"notes":"...","phases":[
{"name":"Reconnaissance","priority":1,"steps":[{"id":"recon-01","description":"...","scenarios":[...]}]},
{"name":"Enumeration","priority":2,"steps":[{"id":"enum-01","description":"...","scenarios":[...]}]},
{"name":"Exploitation","priority":3,"steps":[]},
{"name":"Post-Exploitation","priority":4,"steps":[]},
{"name":"Reporting","priority":5,"steps":[]}
]}}"""


LOOP_SYSTEM_PROMPT = """\
You are PentaForge Planner (loop). Advance the plan using executor results and checklist priorities.

TOOLS: get_page(url) | search_kb(query,domain,n_results) | search_web(query,max_results) | get_target_types() | add_target_type(type)

═══ ITERATIVE WORKFLOW ═══
1. Read current plan + executor results from context.
2. Mark executed scenarios done:true.
3. Apply PHASE GATE to expand the right phase.
4. Add scenarios for P1-P2 checklist items first, then P3-P5.
5. Return JSON with summary + full updated plan. Max 1 tool call/round.

═══ PRIORITY SCALE ═══
P1=Critical (SQLi,RCE,SSRF,IDOR) | P2=High (XSS,AuthBypass) | P3=Medium | P4=Low | P5=Info

═══ PHASE GATE (strict order) ═══
STATE 1 — Recon/Enum has pending (done:false):
  → Expand only Recon/Enum. Add new steps if surfaces discovered.

STATE 2 — Recon+Enum all done:
  → Expand Exploitation (>=3 steps, >=2 scenarios). Agent:exploit.
  → Focus on P1-P2 items: SQLi, RCE, SSRF, XSS, AuthBypass.

STATE 3 — Exploitation >70% done:
  → Expand Post-Exploitation (>=3 steps). Agent:exploit/verify.
  → Focus: privesc, persistence, lateral movement.

STATE 4 — Post-Exploitation >70% done:
  → Fill remaining gaps in Exploitation/Post-Exploitation.

STATE 5 — Verify scenarios mostly done:
  → Expand Reporting (>=3 steps). Agent:report.

STATE 6 — All done:
  → Return summary:"Pentest complete.", plan unchanged.

═══ DENSITY ═══
Every expanded phase: >=3 steps, >=2 scenarios each. Never reduce existing counts.

═══ EVIDENCE RULE ═══
Every scenario MUST reference a specific artifact from executor results (path, param, header, version).
BAD: "Test SQLi" | GOOD: "Test POST /api/auth `username` for blind SQLi — endpoint confirmed"

═══ TARGET SURFACE EXPANSION ═══
If executor evidence introduces a new surface type, add it via add_target_type(type)
and update action_plan.dispatch with entries per target_type + agent (recon/exploit).
Example: main=network, discovered=mobile -> keep network, add mobile as secondary stream.

═══ SCENARIO FORMAT ═══
{"task":"...","agent":"recon|exploit|verify|report","priority":1-5,"details":"...","methods":["..."],"done":false}
NEVER name tools. methods[] = technique descriptions only. Nothing left → "Pentest complete.\""""
