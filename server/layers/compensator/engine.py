"""Compensator / Rollback Engine orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .agent_recovery import AgentRecoveryManager, RecoveryAction
from .audit_log import AuditLog
from .dependency_graph import DependencyGraph
from .fault_isolation import FaultIsolationResult, FaultIsolator
from .state_restore import StateRestoreManager


@dataclass
class CompensationResult:
    fault: FaultIsolationResult
    restored_state: dict[str, Any]
    recovery_action: RecoveryAction
    impacted_agents: list[str]


class CompensatorRollbackEngine:
    """Coordinates rollback and recovery for failed agent execution."""

    def __init__(
        self,
        *,
        fault_isolator: FaultIsolator | None = None,
        state_restore: StateRestoreManager | None = None,
        agent_recovery: AgentRecoveryManager | None = None,
        dependency_graph: DependencyGraph | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.fault_isolator = fault_isolator or FaultIsolator()
        self.state_restore = state_restore or StateRestoreManager()
        self.agent_recovery = agent_recovery or AgentRecoveryManager()
        self.dependency_graph = dependency_graph or DependencyGraph()
        self.audit_log = audit_log or AuditLog()

    def compensate(
        self,
        *,
        failed_agent: str,
        reason: str,
        snapshot_id: str,
        retry_count: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> CompensationResult:
        dependency_order = self.dependency_graph.topological_like_order()
        fault = self.fault_isolator.isolate(
            failed_agent=failed_agent,
            reason=reason,
            dependency_order=dependency_order,
            metadata=metadata or {},
        )

        restored_state = self.state_restore.restore(snapshot_id)
        recovery_action = self.agent_recovery.build_recovery_action(
            agent=failed_agent,
            reason=reason,
            retry_count=retry_count,
        )

        self.audit_log.add(
            "fault_isolated",
            f"Fault isolated for agent '{failed_agent}'",
            {
                "reason": reason,
                "impacted_agents": fault.impacted_agents,
                "severity": fault.severity,
            },
        )
        self.audit_log.add(
            "state_restored",
            f"State restored from snapshot '{snapshot_id}'",
            {"snapshot_id": snapshot_id},
        )
        self.audit_log.add(
            "agent_recovery",
            f"Recovery action for '{failed_agent}' is '{recovery_action.action}'",
            {
                "retry_count": retry_count,
                "payload": recovery_action.payload,
            },
        )

        return CompensationResult(
            fault=fault,
            restored_state=restored_state,
            recovery_action=recovery_action,
            impacted_agents=fault.impacted_agents,
        )

