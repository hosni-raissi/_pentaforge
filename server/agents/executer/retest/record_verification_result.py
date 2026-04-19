"""Verify tools."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from server.core.tool import tool


@tool(
    name="record_verification_result",
    description="Record verification outcome for a finding and whether it was reproducible.",
)
async def record_verification_result(
    finding_title: str,
    verdict: str,
    rationale: str = "",
) -> str:
    return json.dumps(
        {
            "ok": True,
            "finding_title": finding_title,
            "verdict": verdict,
            "rationale": rationale,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        },
    )
