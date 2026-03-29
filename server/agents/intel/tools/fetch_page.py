"""fetch_page - fetch a URL, extract body text, and return target-focused essentials."""

from __future__ import annotations

import json
import re

import httpx
import structlog
from bs4 import BeautifulSoup

from server.core.llm_clean_data import clean_essential_content
from server.core.tool import tool

logger = structlog.get_logger(__name__)

_USER_AGENT = "PentaForge-Intel/0.1"


def _normalize_text(text: str) -> str:
    text = re.sub(r"\r\n?", "\n", str(text or ""))
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_text(html: str, css_selector: str = "") -> tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.get_text(" ", strip=True) if soup.title else "").strip()

    for tag in soup(["script", "style", "noscript", "nav", "header", "footer", "aside", "svg"]):
        tag.decompose()

    if css_selector:
        selected = soup.select_one(css_selector)
        if selected is not None:
            return _normalize_text(selected.get_text("\n", strip=True)), title

    return _normalize_text(soup.get_text("\n", strip=True)), title


@tool(
    name="fetch_page",
    description=(
        "Fetch a URL and return LLM-cleaned essential content focused on the target type. "
        "Useful when raw page text is too noisy."
    ),
)
async def fetch_page(
    url: str,
    target_type: str = "shared",
    focus: str = "",
    css_selector: str = "",
    max_chars: int = 4000,
) -> str:
    max_chars = max(400, min(int(max_chars), 12000))
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0),
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except Exception as exc:
        logger.warning("intel_fetch_page_failed", url=url, error=str(exc))
        return json.dumps(
            {
                "ok": False,
                "url": url,
                "error": str(exc),
                "content": "",
            },
            ensure_ascii=True,
        )

    raw_text, title = _extract_text(resp.text, css_selector=css_selector)
    cleaned = await clean_essential_content(
        raw_text=raw_text,
        target_type=target_type,
        focus=focus,
        source_url=url,
        title=title,
        max_output_chars=max_chars,
    )

    return json.dumps(
        {
            "ok": True,
            "url": url,
            "target_type": target_type,
            "title": title,
            "focus": focus,
            "selector_used": css_selector or "",
            "status_code": resp.status_code,
            "input_chars": len(raw_text),
            "content_chars": len(cleaned),
            "content": cleaned,
        },
        ensure_ascii=True,
    )
