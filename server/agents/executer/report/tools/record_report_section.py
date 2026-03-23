"""Report tools."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from server.core.tool import tool


@tool(
    name="record_report_section",
    description="Record generated report section text and traceability metadata.",
)
async def record_report_section(
    section_name: str,
    section_text: str,
    trace_source: str = "",
) -> str:
    return json.dumps(
        {
            "ok": True,
            "section_name": section_name,
            "section_text": section_text,
            "trace_source": trace_source,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        },
    )
