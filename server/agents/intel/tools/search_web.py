from __future__ import annotations

import json
from urllib.parse import quote_plus

import httpx
from bs4 import BeautifulSoup

from server.core.tool import tool
from server.db.knowledge.config.settings import settings


@tool(
    name="search_web",
    description=(
        "Search the public web for up-to-date context using a lightweight search engine query. "
        "Use this only during final formatting when RAG context needs external confirmation or enrichment."
    ),
)
async def search_web(query: str, max_results: int = 5) -> str:
    max_results = max(1, min(10, int(max_results)))
    url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"

    try:
        async with httpx.AsyncClient(
            timeout=20,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
    except Exception as exc:
        return json.dumps({"query": query, "results": [], "error": str(exc)})

    soup = BeautifulSoup(response.text, "html.parser")
    results: list[dict[str, str]] = []

    for item in soup.select(".result"):
        link = item.select_one(".result__title a")
        snippet = item.select_one(".result__snippet")
        if link is None:
            continue
        results.append(
            {
                "title": link.get_text(" ", strip=True),
                "url": link.get("href", ""),
                "snippet": snippet.get_text(" ", strip=True) if snippet else "",
            }
        )
        if len(results) >= max_results:
            break

    return json.dumps({"query": query, "results": results}, ensure_ascii=True)