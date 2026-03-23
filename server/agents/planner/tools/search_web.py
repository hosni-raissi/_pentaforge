"""search_web — Search public web (Google-first, fallback DuckDuckGo)."""

from __future__ import annotations

import json
from urllib.parse import quote_plus

import httpx
import structlog
from bs4 import BeautifulSoup

from server.core.tool import tool
from server.db.knowledge.config.settings import settings

logger = structlog.get_logger(__name__)


def _extract_google_results(html: str, max_results: int) -> list[dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    rows: list[dict[str, str]] = []
    for block in soup.select("div.g"):
        link = block.select_one("a[href]")
        title = block.select_one("h3")
        if link is None or title is None:
            continue
        href = link.get("href", "")
        if not href.startswith("http"):
            continue
        snippet = block.select_one("div.VwiC3b, span.aCOpRe, div.IsZvec")
        rows.append(
            {
                "title": title.get_text(" ", strip=True),
                "url": href,
                "snippet": snippet.get_text(" ", strip=True) if snippet else "",
            },
        )
        if len(rows) >= max_results:
            break
    return rows


def _extract_duckduckgo_results(html: str, max_results: int) -> list[dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    rows: list[dict[str, str]] = []
    for item in soup.select(".result"):
        link = item.select_one(".result__title a")
        if link is None:
            continue
        snippet = item.select_one(".result__snippet")
        rows.append(
            {
                "title": link.get_text(" ", strip=True),
                "url": link.get("href", ""),
                "snippet": snippet.get_text(" ", strip=True) if snippet else "",
            },
        )
        if len(rows) >= max_results:
            break
    return rows


@tool(
    name="search_web",
    description=(
        "Search the public web for recent information. "
        "Uses Google-style search results (with fallback if blocked). "
        "Returns title/url/snippet entries."
    ),
)
async def search_web(query: str, max_results: int = 5) -> str:
    """Search the public web and return compact search results as JSON."""
    limit = max(1, min(10, int(max_results)))
    headers = {"User-Agent": settings.user_agent}
    google_url = f"https://www.google.com/search?q={quote_plus(query)}&num={limit}&hl=en"
    ddg_url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(8.0, connect=3.0),
        follow_redirects=True,
        headers=headers,
    ) as client:
        # Google-first.
        try:
            resp = await client.get(google_url)
            resp.raise_for_status()
            google_hits = _extract_google_results(resp.text, limit)
            if google_hits:
                return json.dumps(
                    {"query": query, "engine": "google", "results": google_hits},
                    ensure_ascii=True,
                )
        except Exception as exc:
            logger.warning("planner_search_web_google_failed", error=str(exc))

        # Fallback to DuckDuckGo if Google blocks/changes markup.
        try:
            resp = await client.get(ddg_url)
            resp.raise_for_status()
            ddg_hits = _extract_duckduckgo_results(resp.text, limit)
            return json.dumps(
                {"query": query, "engine": "duckduckgo", "results": ddg_hits},
                ensure_ascii=True,
            )
        except Exception as exc:
            logger.error("planner_search_web_failed", error=str(exc))
            return json.dumps(
                {"query": query, "engine": "none", "results": [], "error": str(exc)},
                ensure_ascii=True,
            )
