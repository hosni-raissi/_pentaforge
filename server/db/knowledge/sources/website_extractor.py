"""
WebsiteExtractor — Scrapes websites to extract cybersecurity knowledge.

Handles:
  - GTFOBins (https://gtfobins.github.io/) — static Jekyll site, each binary is a page
  - LOLBAS (https://lolbas-project.github.io/) — static site, each binary is a page
  - exploit.education — educational content
  - social-engineer.org/framework — SE tools page
"""

from __future__ import annotations

import asyncio
import fnmatch
import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx
import structlog

from server.db.knowledge.config.settings import settings
from server.db.knowledge.config.sources import SourceConfig
from server.db.knowledge.models.document import (
    KnowledgeDocument,
    SourceMetadata,
    SourceType,
)
from server.db.knowledge.sources.base import BaseExtractor
from server.db.knowledge.storage.page_cache_store import PageCacheStore

logger = structlog.get_logger(__name__)


class WebsiteExtractor(BaseExtractor):
    """
    Crawls a website and extracts page content as KnowledgeDocuments.

    Strategy:
      1. Fetch the index / sitemap page
      2. Discover internal links matching include_patterns
      3. Fetch each page, extract text via HTML→Markdown conversion
      4. Yield KnowledgeDocuments
    """

    def __init__(self, config: SourceConfig) -> None:
        super().__init__(config)
        self._visited: set[str] = set()
        self._page_cache = PageCacheStore()

    async def extract(self) -> AsyncIterator[KnowledgeDocument]:
        async with httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            # Discover pages from the entry URL
            pages = await self._discover_pages(client)
            logger.info("pages_discovered", source=self.source_name, count=len(pages))

            doc_count = 0
            for page_url in pages[:self.config.max_pages]:
                if page_url in self._visited:
                    continue
                self._visited.add(page_url)

                try:
                    content = await self._fetch_page(client, page_url)
                    if not content:
                        continue

                    title = self._extract_title_from_html(content, page_url)
                    md_content = self._html_to_markdown(content)

                    doc = KnowledgeDocument(
                        title=title,
                        content=md_content,
                        content_type="markdown",
                        domain=self.config.domain,
                        category=self.config.category,
                        tags=list(self.config.tags),
                        metadata=SourceMetadata(
                            source_name=self.config.name,
                            source_type=SourceType.WEBSITE,
                            source_url=page_url,
                            license=self.config.license,
                        ),
                    )

                    if doc.is_meaningful():
                        doc_count += 1
                        yield doc

                    # Polite delay
                    await asyncio.sleep(settings.scrape_delay)

                except Exception as exc:
                    logger.warning("page_fetch_error", url=page_url, error=str(exc))

            logger.info("extraction_complete", source=self.source_name, documents=doc_count)

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.head(self.config.url)
                return resp.status_code < 400
        except Exception:
            return False

    # ── Private helpers ───────────────────────────────────────────────────

    async def _discover_pages(self, client: httpx.AsyncClient) -> list[str]:
        """
        Discover all pages to scrape by:
          1. Trying /sitemap.xml
          2. Falling back to crawling the index for internal links
        """
        pages: list[str] = []

        # Try sitemap first
        sitemap_url = urljoin(self.config.url, "/sitemap.xml")
        try:
            resp = await client.get(sitemap_url)
            if resp.status_code == 200 and "<loc>" in resp.text:
                locs = re.findall(r"<loc>(.*?)</loc>", resp.text)
                pages.extend(locs)
                logger.info("sitemap_found", source=self.source_name, urls=len(locs))
        except Exception:
            pass

        # Also crawl index page for links
        try:
            resp = await client.get(self.config.url)
            if resp.status_code == 200:
                links = self._extract_links(resp.text, self.config.url)
                pages.extend(links)
        except Exception as exc:
            logger.warning("index_crawl_error", source=self.source_name, error=str(exc))

        # Filter by include_patterns and skip non-HTML resources
        _SKIP_EXTS = {
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar",
            ".xml", ".json", ".rss", ".atom", ".mp4", ".webm", ".mp3",
        }
        base_domain = urlparse(self.config.url).netloc

        # Build URL glob patterns from include_patterns (those starting with http)
        url_patterns = [p for p in self.config.include_patterns if p.startswith("http")]

        filtered: list[str] = []
        seen: set[str] = set()
        for url in pages:
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != base_domain:
                continue
            # Skip non-HTML resource URLs
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in _SKIP_EXTS):
                continue
            # Apply URL include_patterns filter
            if url_patterns and not any(fnmatch.fnmatch(url, pat) for pat in url_patterns):
                continue
            # Normalize
            normalized = url.rstrip("/")
            if normalized in seen:
                continue
            seen.add(normalized)
            filtered.append(url)

        return filtered

    async def _fetch_page(self, client: httpx.AsyncClient, url: str) -> str | None:
        """Fetch page HTML, using cache if available."""
        cached = self._page_cache.get(self.source_name, url)
        if cached is not None:
            return cached

        resp = await client.get(url)
        if resp.status_code != 200:
            return None

        html = resp.text
        self._page_cache.set(self.source_name, url, html)
        return html

    @staticmethod
    def _extract_links(html: str, base_url: str) -> list[str]:
        """Extract all internal href links from HTML."""
        links: list[str] = []
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html):
            href = match.group(1)
            if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
                continue
            full = urljoin(base_url, href)
            links.append(full)
        return links

    @staticmethod
    def _extract_title_from_html(html: str, url: str) -> str:
        """Extract <title> or first <h1> from HTML."""
        # <title>
        match = re.search(r"<title>(.*?)</title>", html, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        # <h1>
        match = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.DOTALL | re.IGNORECASE)
        if match:
            return re.sub(r"<[^>]+>", "", match.group(1)).strip()
        # Fallback to URL path
        return urlparse(url).path.strip("/").split("/")[-1].replace("-", " ").title()

    @staticmethod
    def _html_to_markdown(html: str) -> str:
        """
        Lightweight HTML → text/markdown conversion.

        For a production system, use a library like markdownify or html2text.
        This handles the common cases we encounter in security documentation.
        """
        text = html

        # Remove script & style blocks
        text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<nav[^>]*>.*?</nav>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<footer[^>]*>.*?</footer>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<header[^>]*>.*?</header>", "", text, flags=re.DOTALL | re.IGNORECASE)

        # Convert headings
        for i in range(1, 7):
            text = re.sub(
                rf"<h{i}[^>]*>(.*?)</h{i}>",
                lambda m, lvl=i: f"\n{'#' * lvl} {m.group(1).strip()}\n",
                text,
                flags=re.DOTALL | re.IGNORECASE,
            )

        # Convert code blocks
        text = re.sub(
            r"<pre[^>]*><code[^>]*>(.*?)</code></pre>",
            lambda m: f"\n```\n{m.group(1)}\n```\n",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )
        text = re.sub(
            r"<pre[^>]*>(.*?)</pre>",
            lambda m: f"\n```\n{m.group(1)}\n```\n",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )
        text = re.sub(
            r"<code[^>]*>(.*?)</code>",
            lambda m: f"`{m.group(1)}`",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Convert paragraphs and line breaks
        text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"<p[^>]*>", "\n\n", text, flags=re.IGNORECASE)
        text = re.sub(r"</p>", "", text, flags=re.IGNORECASE)

        # Convert lists
        text = re.sub(r"<li[^>]*>", "- ", text, flags=re.IGNORECASE)
        text = re.sub(r"</li>", "\n", text, flags=re.IGNORECASE)

        # Convert links
        text = re.sub(
            r'<a[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>',
            lambda m: f"[{m.group(2)}]({m.group(1)})",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Convert bold/italic
        text = re.sub(r"<(strong|b)[^>]*>(.*?)</\1>", r"**\2**", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<(em|i)[^>]*>(.*?)</\1>", r"*\2*", text, flags=re.DOTALL | re.IGNORECASE)

        # Strip remaining HTML tags
        text = re.sub(r"<[^>]+>", "", text)

        # Decode common HTML entities
        text = text.replace("&amp;", "&")
        text = text.replace("&lt;", "<")
        text = text.replace("&gt;", ">")
        text = text.replace("&quot;", '"')
        text = text.replace("&#39;", "'")
        text = text.replace("&nbsp;", " ")

        # Clean up whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]+", " ", text)

        return text.strip()
