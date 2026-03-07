"""
GitBookExtractor — Extracts content from GitBook-hosted documentation.

Handles:
  - ir0nstone.gitbook.io/notes (binary exploitation notes)
  - book.hacktricks.xyz/mobile-pentesting

GitBook sites expose content as HTML pages. We crawl the sidebar navigation
to discover all pages, then extract content from each.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import AsyncIterator
from pathlib import Path
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
from server.db.knowledge.sources.website_extractor import WebsiteExtractor

logger = structlog.get_logger(__name__)


class GitBookExtractor(BaseExtractor):
    """
    Crawls GitBook sites by following sidebar/table-of-contents navigation.
    """

    def __init__(self, config: SourceConfig) -> None:
        super().__init__(config)
        self._visited: set[str] = set()
        self._cache_dir = settings.cache_dir / self.config.name

    async def extract(self) -> AsyncIterator[KnowledgeDocument]:
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        async with httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            # Get table of contents from the main page
            pages = await self._discover_toc(client)
            logger.info("gitbook_pages_discovered", source=self.source_name, count=len(pages))

            doc_count = 0
            for page_url in pages[:self.config.max_pages]:
                if page_url in self._visited:
                    continue
                self._visited.add(page_url)

                try:
                    html = await self._fetch_cached(client, page_url)
                    if not html:
                        continue

                    title = self._extract_title(html, page_url)
                    md = WebsiteExtractor._html_to_markdown(html)

                    # Additional GitBook cleanup
                    md = self._clean_gitbook_content(md)

                    doc = KnowledgeDocument(
                        title=title,
                        content=md,
                        content_type="markdown",
                        domain=self.config.domain,
                        category=self.config.category,
                        tags=list(self.config.tags),
                        metadata=SourceMetadata(
                            source_name=self.config.name,
                            source_type=SourceType.GITBOOK,
                            source_url=page_url,
                            license=self.config.license,
                        ),
                    )

                    if doc.is_meaningful():
                        doc_count += 1
                        yield doc

                    await asyncio.sleep(settings.scrape_delay)

                except Exception as exc:
                    logger.warning("gitbook_page_error", url=page_url, error=str(exc))

            logger.info("extraction_complete", source=self.source_name, documents=doc_count)

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.head(self.config.url)
                return resp.status_code < 400
        except Exception:
            return False

    # ── Private ───────────────────────────────────────────────────────────

    async def _discover_toc(self, client: httpx.AsyncClient) -> list[str]:
        """
        GitBook exposes a table-of-contents in the sidebar.
        Extract all internal links from the main page.
        """
        pages: list[str] = []
        base_domain = urlparse(self.config.url).netloc

        try:
            resp = await client.get(self.config.url)
            if resp.status_code != 200:
                return [self.config.url]

            html = resp.text
            links = re.findall(r'href=["\']([^"\']+)["\']', html)

            seen: set[str] = set()
            for href in links:
                full = urljoin(self.config.url, href)
                parsed = urlparse(full)
                if parsed.netloc != base_domain:
                    continue
                # Skip anchors, images, etc.
                if any(full.endswith(ext) for ext in [".png", ".jpg", ".gif", ".svg", ".css", ".js"]):
                    continue
                normalized = full.split("#")[0].rstrip("/")
                if normalized not in seen:
                    seen.add(normalized)
                    pages.append(full)
        except Exception as exc:
            logger.warning("toc_discovery_error", source=self.source_name, error=str(exc))

        if not pages:
            pages.append(self.config.url)
        return pages

    async def _fetch_cached(self, client: httpx.AsyncClient, url: str) -> str | None:
        cache_key = hashlib.sha256(url.encode()).hexdigest()[:16]
        cache_file = self._cache_dir / f"{cache_key}.html"

        if cache_file.exists():
            return cache_file.read_text(encoding="utf-8")

        resp = await client.get(url)
        if resp.status_code != 200:
            return None
        cache_file.write_text(resp.text, encoding="utf-8")
        return resp.text

    @staticmethod
    def _extract_title(html: str, url: str) -> str:
        match = re.search(r"<title>(.*?)</title>", html, re.DOTALL | re.IGNORECASE)
        if match:
            title = re.sub(r"<[^>]+>", "", match.group(1)).strip()
            # GitBook titles often have " | SiteName" suffix
            if " | " in title:
                title = title.split(" | ")[0].strip()
            return title
        return urlparse(url).path.strip("/").split("/")[-1].replace("-", " ").title()

    @staticmethod
    def _clean_gitbook_content(md: str) -> str:
        """Remove GitBook-specific boilerplate."""
        # Remove "Powered by GitBook" footers
        md = re.sub(r"Powered by GitBook.*$", "", md, flags=re.MULTILINE | re.IGNORECASE)
        # Remove navigation prompts
        md = re.sub(r"Previous\s*\n.*?\n", "", md, flags=re.IGNORECASE)
        md = re.sub(r"Next\s*\n.*?\n", "", md, flags=re.IGNORECASE)
        md = re.sub(r"Last updated.*$", "", md, flags=re.MULTILINE | re.IGNORECASE)
        return md.strip()
