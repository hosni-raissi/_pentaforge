from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SessionContext:
    label: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    jwt: Optional[str] = None
    base_url: str = ""

    def to_headers(self) -> dict[str, str]:
        headers = dict(self.headers)
        if self.jwt:
            headers.setdefault("Authorization", f"Bearer {self.jwt}")
        return headers


class SessionManager:
    """Store lightweight authenticated session contexts for multi-user testing."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionContext] = {}

    def register(self, context: SessionContext) -> None:
        self._sessions[context.label] = context

    def get(self, label: str) -> Optional[SessionContext]:
        return self._sessions.get(label)

    def all_labels(self) -> list[str]:
        return list(self._sessions.keys())

    def has_multiple_users(self) -> bool:
        return len(self._sessions) >= 2
