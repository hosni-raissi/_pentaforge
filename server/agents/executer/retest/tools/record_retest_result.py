"""Retest tools."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from server.core.tool import tool


@tool(
    name="record_retest_result",
    description="Record post-fix retest result for a previously reported finding.",
)
async def record_retest_result(
    finding_id: str,
    retest_verdict: str,
    notes: str = "",
) -> str:
    return json.dumps(
        {
            "ok": True,
            "finding_id": finding_id,
            "retest_verdict": retest_verdict,
            "notes": notes,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        },
    )
