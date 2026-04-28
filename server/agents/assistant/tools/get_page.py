"""Assistant tool wrapper for page fetching."""

from __future__ import annotations

from typing import Any

from server.agents.planner.tools.get_page import get_page as planner_get_page


async def get_page(
    *,
    url: str,
    css_selector: str = "",
) -> dict[str, Any]:
    text = await planner_get_page.execute(url=url, css_selector=css_selector)
    return {
        "success": not str(text or "").strip().lower().startswith("error fetching"),
        "url": str(url or "").strip(),
        "css_selector": str(css_selector or "").strip(),
        "text": str(text or "").strip(),
    }


ASSISTANT_GET_PAGE_TOOL_DEFINITION = {
    "name": "get_page",
    "description": (
        "Fetch a specific web page and return cleaned visible text content. "
        "Optionally focus on a CSS selector."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to fetch and read.",
            },
            "css_selector": {
                "type": "string",
                "description": "Optional CSS selector to extract a specific section from the page.",
            },
        },
        "required": ["url"],
        "additionalProperties": False,
    },
}
