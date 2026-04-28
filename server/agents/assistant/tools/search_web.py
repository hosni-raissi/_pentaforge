"""Assistant tool wrapper for public web search."""

from __future__ import annotations

import json
from typing import Any

from server.agents.planner.tools.search_web import search_web as planner_search_web


async def search_web(
    *,
    query: str,
    max_results: int = 5,
) -> dict[str, Any]:
    raw = await planner_search_web.execute(query=query, max_results=max_results)
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return {
        "query": str(query or "").strip(),
        "engine": "unknown",
        "results": [],
        "error": str(raw or "").strip() or "search_web returned no structured result",
    }


ASSISTANT_SEARCH_WEB_TOOL_DEFINITION = {
    "name": "search_web",
    "description": (
        "Search the public web for current external information and return compact results "
        "with titles, URLs, and snippets."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The external topic or question to search for.",
            },
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 8,
                "default": 5,
                "description": "Maximum number of web results to return.",
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}
