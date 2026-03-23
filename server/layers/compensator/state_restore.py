"""State snapshot and restore primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class StateSnapshot:
    snapshot_id: str
    created_at: str
    state: dict[str, Any]
    source: str = "runtime"


class StateRestoreManager:
    """Stores and restores in-memory state snapshots."""

    def __init__(self) -> None:
        self._snapshots: dict[str, StateSnapshot] = {}

    def create_snapshot(self, snapshot_id: str, state: dict[str, Any]) -> StateSnapshot:
        snapshot = StateSnapshot(
            snapshot_id=snapshot_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            state=dict(state),
        )
        self._snapshots[snapshot_id] = snapshot
        return snapshot

    def restore(self, snapshot_id: str) -> dict[str, Any]:
        snapshot = self._snapshots.get(snapshot_id)
        if snapshot is None:
            raise KeyError(f"Snapshot not found: {snapshot_id}")
        return dict(snapshot.state)

    def latest(self) -> StateSnapshot | None:
        if not self._snapshots:
            return None
        newest_key = sorted(self._snapshots.keys())[-1]
        return self._snapshots[newest_key]

