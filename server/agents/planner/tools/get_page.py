"""get_page — Fetch a web page and return its text content."""

from __future__ import annotations

import httpx
import structlog
from bs4 import BeautifulSoup

from server.core.tool import tool

logger = structlog.get_logger(__name__)

_USER_AGENT = "PentaForge-Planner/0.1"


@tool(
    name="get_page",
    description="Fetch a URL and return its text content (HTML stripped).",
)
async def get_page(url: str, css_selector: str = "") -> str:
    """Fetch a URL and return cleaned text content.

    Args:
        url: The URL to fetch.
        css_selector: Optional CSS selector to extract a specific section.
    """
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0),
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        return f"Error fetching {url}: {exc}"

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

    if len(text) > 2_500:
        text = text[:2_500] + "\n\n... [truncated]"

    return text
