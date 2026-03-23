"""Scope & Safety Engine — Shared data models."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(Enum):
    """Result of a safety check."""
    ALLOW = "allow"
    DENY = "deny"
    PENDING = "pending"  # Awaiting human approval.


@dataclass(frozen=True)
class CheckResult:
    """Immutable result from any safety component."""
    verdict: Verdict
    component: str          # Which component produced this.
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def __str__(self) -> str:
        symbol = "✓" if self.allowed else "✗"
        return f"[{symbol} {self.component}] {self.reason}"


@dataclass
class ActionRequest:
    """Describes an action an agent wants to perform.

    Every tool call, every network request, every payload execution
    gets wrapped in this before passing through the safety engine.
    """
    agent: str                          # recon, exploit, verify, report, retest
    tool: str                           # nmap, sqlmap, get_page, etc.
    target: str                         # IP, URL, hostname, CIDR
    args: dict[str, Any] = field(default_factory=dict)
    phase: str = ""                     # reconnaissance, exploitation, etc.
    ssvc_level: str = ""                # ACT, ATTEND, TRACK (if known)
    engagement_id: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class EngagementScope:
    """Defines the legal boundaries of an engagement.

    Set once at engagement start. Immutable during execution.
    """
    # Allowed targets — at least one must be set.
    allowed_cidrs: list[str] = field(default_factory=list)     # ["10.0.0.0/24", "192.168.1.0/24"]
    allowed_domains: list[str] = field(default_factory=list)   # ["example.com", "*.example.com"]
    allowed_urls: list[str] = field(default_factory=list)      # ["http://target.local/app"]

    # Explicit exclusions (override allows).
    excluded_cidrs: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)

    # Restrictions.
    allowed_ports: list[int] = field(default_factory=list)     # Empty = all ports allowed.
    max_concurrent_scans: int = 5
    testing_window_start: str = ""     # "08:00" — empty = 24/7
    testing_window_end: str = ""       # "18:00"

    # Engagement metadata.
    engagement_id: str = ""
    client_name: str = ""
    rules_of_engagement: str = ""

    # Auto-approve recon tools (skip approval gate for low-impact actions).
    auto_approve_recon: bool = True