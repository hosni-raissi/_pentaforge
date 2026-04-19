"""Planner context window compression between cycles.

Compresses findings from previous cycles into summaries to prevent
context window bloat while retaining critical history for the Planner.
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def compress_planner_findings_between_cycles(
    current_entries: list[dict[str, Any]],
    cycle_number: int,
) -> list[dict[str, Any]]:
    """Compress findings from previous cycles into summaries.

    Keeps:
    - System prompt entries (role="system")
    - Current/active plan entries
    - Tool execution results from current cycle

    Compresses:
    - Findings from cycle N-1 and earlier (→ summary count)
    - Task completion records (→ count)

    Args:
        current_entries: All context window entries
        cycle_number: Current cycle number (1-based)

    Returns:
        Optimized entries with previous cycles compressed
    """
    if cycle_number <= 1:
        return current_entries  # No compression needed for first cycle

    system_entries = []
    plan_entries = []
    current_cycle_entries = []
    old_findings = {
        "vulnerabilities": 0,
        "false_positives": 0,
        "inconclusives": 0,
        "info_findings": 0,
    }
    old_tasks = 0

    for entry in current_entries:
        if not isinstance(entry, dict):
            continue

        kind = str(entry.get("kind", "")).strip().lower()
        content = str(entry.get("content", "")).strip()
        metadata = entry.get("metadata", {})
        cycle = metadata.get("cycle", 0) if isinstance(metadata, dict) else 0

        # Keep system prompt and instructions
        if kind == "system_instruction" or "system" in kind.lower():
            system_entries.append(entry)
            continue

        # Keep current cycle's plan
        if kind in ("plan", "plan_update") and cycle >= cycle_number:
            plan_entries.append(entry)
            continue

        # Keep current cycle's execution results
        if cycle == cycle_number:
            current_cycle_entries.append(entry)
            continue

        # Count and compress old findings
        if "vulnerability" in content.lower() or "real_vulnerability" in content.lower():
            old_findings["vulnerabilities"] += 1
        elif "false_positive" in content.lower():
            old_findings["false_positives"] += 1
        elif "inconclusive" in content.lower():
            old_findings["inconclusives"] += 1
        elif "info" in content.lower() or kind == "info":
            old_findings["info_findings"] += 1
        else:
            old_tasks += 1

    # Build compressed summary if there are old findings
    result = list(system_entries)
    result.extend(plan_entries)

    if any(old_findings.values()) or old_tasks > 0:
        summary_content = (
            f"[COMPRESSED from cycles 1-{cycle_number - 1}] "
            f"Verified: {old_findings['vulnerabilities']} real vulnerabilities, "
            f"{old_findings['false_positives']} false positives. "
            f"Inconclusive: {old_findings['inconclusives']}, "
            f"Info findings: {old_findings['info_findings']}, "
            f"Completed tasks: {old_tasks}."
        )
        result.append(
            {
                "kind": "compressed_summary",
                "role": "assistant",
                "content": summary_content,
                "tokens": max(100, len(summary_content) // 4),
                "metadata": {
                    "cycle": cycle_number,
                    "compression_reason": "between_cycle_optimization",
                    "old_findings_count": sum(old_findings.values()) + old_tasks,
                },
            }
        )
        logger.info(
            "planner_context_compressed",
            cycle=cycle_number,
            old_findings_count=sum(old_findings.values()) + old_tasks,
            new_entry_count=len(result),
        )

    result.extend(current_cycle_entries)
    return result


def compress_planner_context_window(
    context_window: "ContextWindowManager",
    cycle_number: int,
) -> None:
    """Compress Planner's context window between execution cycles.

    Called after cycle N completes, before cycle N+1 starts.
    Reduces stored entries by compressing old findings into summaries.

    Args:
        context_window: Planner's context window manager
        cycle_number: Current cycle number (1-based)
    """
    if context_window is None or cycle_number <= 1:
        return

    # Ensure we've loaded the current entries
    import asyncio

    try:
        asyncio.run(context_window.ensure_loaded())
    except RuntimeError:
        # Already in async context, likely
        pass

    # Get current entries
    snapshot = context_window.snapshot()
    current_entries = snapshot.entries if isinstance(snapshot.entries, list) else []

    # Compress
    compressed_entries = compress_planner_findings_between_cycles(
        current_entries, cycle_number
    )

    # Update context window with compressed entries
    if compressed_entries != current_entries:
        context_window._entries = compressed_entries
        logger.info(
            "planner_context_window_updated",
            cycle=cycle_number,
            original_count=len(current_entries),
            compressed_count=len(compressed_entries),
        )
