from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScanStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass
class PendingToolApproval:
    approval_id: str
    scan_id: str
    role: str
    tool_name: str
    args: dict[str, Any]
    call_id: str
    event: asyncio.Event = field(default_factory=asyncio.Event)
    decision: str | None = None


@dataclass
class PendingPasswordRequest:
    password_id: str
    scan_id: str
    tool_name: str
    prompt: str
    reason: str
    call_id: str
    event: asyncio.Event = field(default_factory=asyncio.Event)
    password: str | None = None
    approved: bool = False


@dataclass
class PhaseResult:
    phase: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
