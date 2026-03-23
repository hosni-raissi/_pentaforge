"""Recon tools."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from server.core.tool import tool


@tool(
    name="record_recon_signal",
    description="Record a reconnaissance signal or observation with source attribution.",
)
async def record_recon_signal(
    observation: str,
    source: str = "",
    confidence: str = "medium",
) -> str:
    return json.dumps(
        {
            "ok": True,
            "observation": observation,
            "source": source,
            "confidence": confidence,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        },
    )
