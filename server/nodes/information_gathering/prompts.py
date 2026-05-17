"""Prompts for the information-gathering node."""

from __future__ import annotations

import json
from typing import Any


PREPARE_INFORMATION_BLOCK_SYSTEM_PROMPT = (
    "Role: information-gathering planner for a pentest orchestrator.\n"
    "Goal: review the entire static gathering program first, then return the adjusted execution plan for all blocks.\n"
    "Rules:\n"
    "1. Use the full static gathering program, target info, and scope to decide whether each block is authorized, compatible, and useful.\n"
    "2. Evaluate all blocks together before deciding what to keep, skip, or refine.\n"
    "3. Keep blocks grouped and simple. Do not explode one block into many sub-blocks.\n"
    "4. Remove tools that clearly do not fit the target type, target description, scope, local/private context, or available evidence.\n"
    "5. Keep built-in tools only if they appear in the provided allowed built-in tool inventory.\n"
    "6. This first grouped static gathering stage must stay non-bruteforce: no wordlist attacks, no fuzzing, no password guessing, no spray attempts, and no broad exploit scanners.\n"
    "7. CRITICAL: Never include any actions that could cause bad effects, instability, or service disruption. Stay passive or extremely low-impact.\n"
    "8. You may add a tool only as a run_custom object if there is a very clear, scoped, non-destructive command that improves a block.\n"
    "   For run_custom, `command` must be the binary name only (example: `curl`), and all flags/targets must go in `args`.\n"
    "9. Never invent findings, endpoints, vulnerabilities, assets, or credentials.\n"
    "10. Never add more than one run_custom object per block.\n"
    "11. If a block should not run for this target, set status to skip and return tools as an empty list for that block.\n"
    "12. Preserve execution order unless there is a strong target-specific reason to change it.\n"
    "13. Return strict JSON only with shape:\n"
    '   {"blocks":[{"status":"keep|refine|skip","name":"...","goal":"...","interaction":"...","tools":[...],"rationale":"...","skipped_tools":[...]}]}\n'
    "14. tools may contain strings for built-in tools or an object with keys:\n"
    "   tool, command, args, reason.\n"
    "15. Never place a full shell command inside run_custom.command. Split it into command + args.\n"
    "16. Do not rewrite or reconfigure existing profile tools. Existing tool objects and args are static.\n"
    "17. For existing tools, use the tools list only to indicate keep/remove decisions by name. Do not change flags, targets, goals, block names, or interaction text.\n"
    "18. Preserve each original block name, goal, and interaction. Only remove unneeded tools, skip whole blocks, or add at most one extra run_custom entry when clearly justified.\n"
)


def build_information_block_preparation_prompt(
    *,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    profile: dict[str, Any],
    available_tools: list[str],
) -> str:
    return (
        f"Target: {target}\n"
        f"Target type: {target_type}\n"
        f"Scope: {scope or '(not provided)'}\n"
        f"Info: {info or '(not provided)'}\n\n"
        "Allowed built-in tools for this target:\n"
        f"{json.dumps(available_tools, ensure_ascii=True, indent=2)}\n\n"
        "Full static gathering program:\n"
        f"{json.dumps(profile, ensure_ascii=True, indent=2)}\n\n"
        "Return the adjusted full block list for this exact target. "
        "Review all blocks together first, then return the full ordered set to run one by one. "
        "Remove unauthorized or incompatible tools, skip blocks if needed, "
        "and add at most one scoped run_custom entry per block only when it clearly improves coverage. "
        "Do not introduce any brute-force, fuzzing, or wordlist-driven actions in this static stage. "
        "Stay strictly non-destructive and avoid anything that could cause bad effects or instability."
    )
