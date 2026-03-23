"""Audit log for compensator decisions and actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AuditEvent:
    timestamp: str
    event_type: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    """In-memory audit log for rollback/recovery decisions."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def add(self, event_type: str, message: str, details: dict[str, Any] | None = None) -> None:
        self._events.append(
            AuditEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=event_type,
                message=message,
                details=details or {},
            ),
        )

    def all_events(self) -> list[AuditEvent]:
        return list(self._events)

