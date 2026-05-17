"""Shared tool for general URL fetching."""

from __future__ import annotations

from typing import Any

import httpx
import structlog
from bs4 import BeautifulSoup

from server.core.tool import tool

logger = structlog.get_logger(__name__)

_USER_AGENT = "PentaForge-Shared/0.1"


@tool(
    name="fetch_url_content",
    description=(
        "Fetch a public web page and return cleaned visible text content. "
        "Use this for external research, documentation reading, or CVE lookups."
    ),
)
async def fetch_url_content(url: str, css_selector: str = "") -> dict[str, Any]:
    """Fetch a URL and return cleaned text content as a structured dict."""
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0),
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        return {
            "success": False,
            "url": url,
            "error": f"Error fetching {url}: {exc}",
            "text": "",
        }

    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()

    if css_selector:
        selected = soup.select_one(css_selector)
        if selected:
            text = selected.get_text(separator="\n", strip=True)
        else:
            text = f"Selector '{css_selector}' not found. Full page text:\n"
            text += soup.get_text(separator="\n", strip=True)
    else:
        text = soup.get_text(separator="\n", strip=True)

    if len(text) > 4_000:
        text = text[:4_000] + "\n\n... [truncated]"

    return {
        "success": True,
        "url": url,
        "css_selector": css_selector,
        "text": text,
    }


FETCH_URL_CONTENT_TOOL_DEFINITION = {
    "name": "fetch_url_content",
    "description": (
        "Fetch a public web page and return cleaned visible text content. "
        "Use this for external research, documentation reading, or CVE lookups."
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
