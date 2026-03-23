"""Fault isolation logic for the compensator layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FaultIsolationResult:
    isolated_agent: str
    reason: str
    impacted_agents: list[str] = field(default_factory=list)
    severity: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)


class FaultIsolator:
    """Identifies the failing agent and estimates blast radius."""

    def isolate(
        self,
        *,
        failed_agent: str,
        reason: str,
        dependency_order: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> FaultIsolationResult:
        order = dependency_order or []
        impacted_agents: list[str] = []

        if failed_agent in order:
            idx = order.index(failed_agent)
            impacted_agents = order[idx + 1 :]

        severity = "high" if impacted_agents else "medium"
        return FaultIsolationResult(
            isolated_agent=failed_agent,
            reason=reason,
            impacted_agents=impacted_agents,
            severity=severity,
            metadata=metadata or {},
        )

