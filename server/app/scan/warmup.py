from __future__ import annotations

from typing import Any

from .utils import _select_recon_only_scenarios

WARMUP_RECON_WORKERS = 2
WARMUP_RECON_SCENARIOS_PER_WORKER = 2
WARMUP_RECON_CYCLES = 2


def _select_warmup_recon_batches(
    plan_data: dict[str, Any],
    *,
    worker_count: int = WARMUP_RECON_WORKERS,
    scenarios_per_worker: int = WARMUP_RECON_SCENARIOS_PER_WORKER,
) -> list[list[dict[str, Any]]]:
    selected = _select_recon_only_scenarios(
        plan_data,
        limit=worker_count * scenarios_per_worker,
    )
    batches: list[list[dict[str, Any]]] = []
    cursor = 0
    for _ in range(worker_count):
        batch = selected[cursor : cursor + scenarios_per_worker]
        cursor += scenarios_per_worker
        if batch:
            batches.append(batch)
    return batches


def _count_done_scenarios(plan_data: dict[str, Any]) -> int:
    phases = plan_data.get("phases")
    if not isinstance(phases, list):
        return 0

    total = 0
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            scenarios = step.get("scenarios")
            if not isinstance(scenarios, list):
                continue
            for scenario in scenarios:
                if not isinstance(scenario, dict):
                    continue
                done = bool(scenario.get("done", False))
                status = str(scenario.get("status", "")).strip().lower()
                if done or status in {"completed", "complete", "done"}:
                    total += 1
    return total


def _display_cycle_number(cycle_number: int, *, prior_cycles: int = 0) -> int:
    try:
        normalized_cycle = int(cycle_number)
    except (TypeError, ValueError):
        normalized_cycle = 1
    try:
        normalized_prior = int(prior_cycles)
    except (TypeError, ValueError):
        normalized_prior = 0
    return max(1, normalized_cycle + max(0, normalized_prior))


def _scenario_max_rounds(scenario: dict[str, Any], *, default: int) -> int:
    try:
        parsed = int(scenario.get("max_rounds", default))
    except (TypeError, ValueError):
        parsed = default
    return min(3, max(1, parsed))
