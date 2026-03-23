"""Agent recovery actions for failed workflow steps."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RecoveryAction:
    agent: str
    action: str
    reason: str
    payload: dict[str, Any]


class AgentRecoveryManager:
    """Builds deterministic recovery actions for agents."""

    def build_recovery_action(
        self,
        *,
        agent: str,
        reason: str,
        retry_count: int = 0,
    ) -> RecoveryAction:
        if retry_count < 1:
            action = "retry"
        elif retry_count < 3:
            action = "restart"
        else:
            action = "escalate"

        return RecoveryAction(
            agent=agent,
            action=action,
            reason=reason,
            payload={"retry_count": retry_count},
        )

