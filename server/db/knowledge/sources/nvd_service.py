"""
NVDService — On-demand CVE lookup with local caching & optional bulk seeding.

Architecture Decision:
  NVD has ~260k+ CVEs. Bulk-ingesting all of them is impractical:
    - Rate-limited (5 req/30s without key, 50 req/30s with key)
    - Storage waste: most CVEs are irrelevant to a given engagement
    - Data goes stale within days

  Instead, PentaForge uses:
    1. ON-DEMAND — lookup specific CVEs or products during active pentests
    2. CACHING   — store fetched CVEs locally so repeat lookups are instant
    3. SEED MODE — optionally pre-populate CRITICAL/HIGH CVEs from last 90 days
                   for common pentest targets (Apache, nginx, SSH, etc.)

Usage:
    nvd = NVDService(orchestrator)
    await nvd.initialize()

    # Lookup a specific CVE
    doc = await nvd.lookup_cve("CVE-2024-3094")  # xz-utils backdoor

    # Search by product  
    docs = await nvd.search_product("Apache Tomcat 9.0", severity="CRITICAL")

    # Pre-seed common pentest targets (optional, one-time)
    result = await nvd.seed_common_targets()
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from server.db.knowledge.config.settings import settings
from server.db.knowledge.models.document import (
    KnowledgeDocument,
    SourceMetadata,
    SourceType,
)
from server.db.knowledge.processing.chunker import MarkdownChunker
from server.db.knowledge.processing.cleaner import ContentCleaner
from server.db.knowledge.storage.embedding import EmbeddingGenerator
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore

logger = structlog.get_logger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Common pentest-target products for seeding
SEED_KEYWORDS = [
    "Apache HTTP Server",
    "nginx",
    "OpenSSH",
    "Microsoft Exchange",
    "WordPress",
    "Apache Tomcat",
    "Microsoft IIS",
    "ProFTPD",
    "vsftpd",
    "Samba",
    "ActiveDirectory",
    "OpenSSL",
    "Log4j",
    "Spring Framework",
    "Jenkins",
    "GitLab",
    "Jira",
    "Confluence",
    "Redis",
    "PostgreSQL",
    "MySQL",
    "MongoDB",
    "Elasticsearch",
    "Docker",
    "Kubernetes",
    "VMware ESXi",
    "Citrix NetScaler",
    "Fortinet FortiOS",
    "Palo Alto PAN-OS",
    "SonicWall",
]


@dataclass
class NVDLookupResult:
    """Result of a single NVD lookup/search."""

    query: str
    documents: list[KnowledgeDocument] = field(default_factory=list)
    cached: int = 0
    fetched: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.documents)


class NVDService:
    """
    On-demand NVD CVE service with transparent local caching.

    Every CVE fetched from the API is:
      1. Cleaned & chunked
      2. Embedded & stored in Qdrant (exploits collection)
      3. Deduplicated via content_hash in Qdrant
    So the second lookup is instant (served from local vector store).
    """

    SOURCE_NAME = "NVD-CVE"
    CONTENT_TYPE = "exploits"  # CVEs go to the exploits collection

    def __init__(
        self,
        embedder: EmbeddingGenerator | None = None,
        vector_store: QdrantVectorStore | None = None,
        chunker: MarkdownChunker | None = None,
    ) -> None:
        self.embedder = embedder or EmbeddingGenerator()
        self.vector_store = vector_store or QdrantVectorStore()
        self.chunker = chunker or MarkdownChunker()

    async def initialize(self) -> None:
        """Ensure storage is ready."""
        self.vector_store.ensure_all_collections()

    # ── On-Demand Lookups ─────────────────────────────────────────────────

    async def lookup_cve(self, cve_id: str) -> KnowledgeDocument | None:
        """
        Fetch a single CVE by ID (e.g. "CVE-2024-3094").
        Returns from cache if already ingested, otherwise fetches from NVD API.
        """
        cve_id = cve_id.upper().strip()
        logger.info("nvd_lookup_cve", cve_id=cve_id)

        # Check local cache first
        cached = await self._search_local(cve_id, n_results=1)
        if cached:
            logger.debug("nvd_cache_hit", cve_id=cve_id)
            return cached[0]

        # Fetch from API
        doc = await self._fetch_single_cve(cve_id)
        if doc:
            await self._ingest_documents([doc])
        return doc

    async def search_product(
        self,
        keyword: str,
        severity: str | None = "CRITICAL",
        days_back: int = 365,
        max_results: int = 50,
    ) -> NVDLookupResult:
        """
        Search NVD for CVEs affecting a specific product/keyword.
        Results are cached locally for future queries.

        Args:
            keyword: Product name, e.g. "Apache Tomcat 9.0"
            severity: CVSS severity filter (CRITICAL, HIGH, MEDIUM, LOW, or None for all)
            days_back: Only fetch CVEs published within this many days
            max_results: Limit on number of CVEs to fetch

        Returns:
            NVDLookupResult with fetched documents.
        """
        logger.info("nvd_search_product", keyword=keyword, severity=severity)

        result = NVDLookupResult(query=keyword)

        # Check if we have cached results for this keyword
        cached = await self._search_local(keyword, n_results=max_results)
        if cached:
            result.documents = cached
            result.cached = len(cached)
            logger.debug("nvd_cache_partial", keyword=keyword, cached=len(cached))
            # Still fetch fresh results to supplement, but with shorter lookback
            days_back = min(days_back, 90)

        # Fetch from API
        docs = await self._fetch_by_keyword(
            keyword=keyword,
            severity=severity,
            days_back=days_back,
            max_results=max_results,
        )

        # Deduplicate against cache
        cached_hashes = {d.content_hash for d in cached} if cached else set()
        new_docs = [d for d in docs if d.content_hash not in cached_hashes]

        if new_docs:
            await self._ingest_documents(new_docs)
            result.documents.extend(new_docs)
            result.fetched = len(new_docs)

        logger.info(
            "nvd_search_complete",
            keyword=keyword,
            cached=result.cached,
            fetched=result.fetched,
            total=result.total,
        )
        return result

    async def search_cpe(
        self,
        cpe_string: str,
        severity: str | None = None,
        max_results: int = 50,
    ) -> NVDLookupResult:
        """
        Search NVD by CPE (Common Platform Enumeration) string.
        Useful after Nmap/service detection identifies exact product versions.

        Example CPE: "cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*"
        """
        logger.info("nvd_search_cpe", cpe=cpe_string)
        result = NVDLookupResult(query=cpe_string)

        docs = await self._fetch_paginated(
            extra_params={"cpeName": cpe_string},
            severity=severity,
            max_results=max_results,
        )

        if docs:
            await self._ingest_documents(docs)
            result.documents = docs
            result.fetched = len(docs)

        return result

    # ── Seed Mode ─────────────────────────────────────────────────────────

    async def seed_common_targets(
        self,
        keywords: list[str] | None = None,
        severity: str = "CRITICAL",
        days_back: int = 90,
        max_per_keyword: int = 20,
    ) -> dict[str, NVDLookupResult]:
        """
        Pre-populate the knowledge base with CRITICAL CVEs for common pentest targets.
        Run once (or periodically) to have baseline coverage.

        Returns: dict of keyword → result.
        """
        keywords = keywords or SEED_KEYWORDS
        logger.info("nvd_seed_start", keywords=len(keywords), severity=severity)

        results: dict[str, NVDLookupResult] = {}
        for kw in keywords:
            result = await self.search_product(
                keyword=kw,
                severity=severity,
                days_back=days_back,
                max_results=max_per_keyword,
            )
            results[kw] = result
            logger.info(
                "nvd_seed_keyword_done",
                keyword=kw,
                fetched=result.fetched,
                cached=result.cached,
            )

        total_fetched = sum(r.fetched for r in results.values())
        total_cached = sum(r.cached for r in results.values())
        logger.info(
            "nvd_seed_complete",
            keywords=len(keywords),
            total_fetched=total_fetched,
            total_cached=total_cached,
        )
        return results

    # ── Internals ─────────────────────────────────────────────────────────

    async def _search_local(
        self, query: str, n_results: int = 10
    ) -> list[KnowledgeDocument]:
        """Search the local vector store for cached CVE data."""
        try:
            query_embedding = await self.embedder.embed_single(query, is_query=True)
            hits = self.vector_store.search(
                query_embedding=query_embedding,
                content_type=self.CONTENT_TYPE,
                n_results=n_results,
                where={"source_name": self.SOURCE_NAME},
            )
            if not hits:
                return []

            # Reconstruct minimal KnowledgeDocuments from search results
            docs = []
            for hit in hits:
                meta = hit.get("metadata", {})
                doc = KnowledgeDocument(
                    title=meta.get("title", hit.get("id", "")),
                    content=hit.get("content", ""),
                    domain="cve_exploit",
                    category="intelligence",
                    tags=meta.get("tags", "").split(",") if meta.get("tags") else [],
                    metadata=SourceMetadata(
                        source_name=self.SOURCE_NAME,
                        source_type=SourceType.API,
                        source_url=meta.get("source_url", ""),
                    ),
                )
                docs.append(doc)
            return docs
        except Exception as exc:
            logger.debug("nvd_local_search_failed", error=str(exc))
            return []

    async def _fetch_single_cve(self, cve_id: str) -> KnowledgeDocument | None:
        """Fetch a single CVE by ID from the NVD API."""
        headers = self._build_headers()

        async with httpx.AsyncClient(
            timeout=settings.request_timeout, headers=headers
        ) as client:
            try:
                resp = await client.get(
                    NVD_BASE_URL, params={"cveId": cve_id}
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                logger.error("nvd_fetch_cve_error", cve_id=cve_id, error=str(exc))
                return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        return self._cve_to_document(vulns[0])

    async def _fetch_by_keyword(
        self,
        keyword: str,
        severity: str | None = None,
        days_back: int = 365,
        max_results: int = 50,
    ) -> list[KnowledgeDocument]:
        """Fetch CVEs by keyword search."""
        extra_params = {"keywordSearch": keyword}
        return await self._fetch_paginated(
            extra_params=extra_params,
            severity=severity,
            days_back=days_back,
            max_results=max_results,
        )

    async def _fetch_paginated(
        self,
        extra_params: dict[str, str] | None = None,
        severity: str | None = None,
        days_back: int = 365,
        max_results: int = 50,
    ) -> list[KnowledgeDocument]:
        """Paginated NVD API fetch with rate limiting."""
        headers = self._build_headers()
        documents: list[KnowledgeDocument] = []
        start_index = 0
        results_per_page = min(50, max_results)

        async with httpx.AsyncClient(
            timeout=settings.request_timeout, headers=headers
        ) as client:
            while len(documents) < max_results:
                params: dict[str, str] = {
                    "startIndex": str(start_index),
                    "resultsPerPage": str(results_per_page),
                }

                if severity:
                    params["cvssV3Severity"] = severity.upper()

                if days_back:
                    end = datetime.now(timezone.utc)
                    start = end - timedelta(days=days_back)
                    params["pubStartDate"] = start.strftime("%Y-%m-%dT00:00:00.000")
                    params["pubEndDate"] = end.strftime("%Y-%m-%dT23:59:59.999")

                if extra_params:
                    params.update(extra_params)

                try:
                    resp = await client.get(NVD_BASE_URL, params=params)

                    if resp.status_code == 403:
                        logger.warning("nvd_rate_limited")
                        await asyncio.sleep(30)
                        continue

                    resp.raise_for_status()
                    data = resp.json()
                except Exception as exc:
                    logger.error("nvd_paginated_error", error=str(exc))
                    break

                vulns = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                if not vulns:
                    break

                for vuln in vulns:
                    doc = self._cve_to_document(vuln)
                    if doc and doc.is_meaningful():
                        documents.append(doc)
                        if len(documents) >= max_results:
                            break

                start_index += results_per_page
                if start_index >= total_results:
                    break

                await asyncio.sleep(settings.nvd_rate_limit_delay)

        return documents

    async def _ingest_documents(self, docs: list[KnowledgeDocument]) -> None:
        """Process and store documents: clean → chunk → embed → store."""
        # Clean
        for doc in docs:
            doc.content = ContentCleaner.clean(doc.content, self.SOURCE_NAME)

        # Deduplicate against existing (via Qdrant content_hash)
        new_docs = []
        for doc in docs:
            if not self.vector_store.exists_by_hash(doc.content_hash, self.CONTENT_TYPE):
                new_docs.append(doc)

        if not new_docs:
            return

        # Chunk
        all_chunks = self.chunker.chunk_documents(new_docs)
        if not all_chunks:
            return

        # Embed
        texts = [c.content for c in all_chunks]
        embeddings = await self.embedder.embed_texts(texts)

        # Store vectors in the exploits collection
        self.vector_store.upsert_chunks(all_chunks, embeddings, content_type=self.CONTENT_TYPE)

        logger.info(
            "nvd_docs_ingested",
            docs=len(new_docs),
            chunks=len(all_chunks),
        )

    def _build_headers(self) -> dict[str, str]:
        headers = {"User-Agent": settings.user_agent}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        return headers

    def _cve_to_document(self, vuln: dict[str, Any]) -> KnowledgeDocument | None:
        """Convert NVD CVE JSON to a KnowledgeDocument."""
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        # Description (prefer English)
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS v3
        cvss3 = self._extract_cvss3(cve)
        severity = cvss3.get("baseSeverity", "UNKNOWN")
        score = cvss3.get("baseScore", 0.0)
        vector = cvss3.get("vectorString", "")

        # CWE weaknesses
        weaknesses = self._extract_cwes(cve)

        # Affected products
        affected = self._extract_affected(cve)

        # References
        references = [
            ref.get("url", "")
            for ref in cve.get("references", [])
            if ref.get("url")
        ]

        # Build content
        content_parts = [
            f"# {cve_id}",
            f"\n**Severity:** {severity} (CVSS {score})",
            f"**CVSS Vector:** {vector}" if vector else "",
            f"\n## Description\n{description}",
        ]

        if weaknesses:
            content_parts.append(
                "\n## Weaknesses (CWE)\n" + "\n".join(f"- {w}" for w in weaknesses)
            )

        if affected:
            content_parts.append(
                "\n## Affected Products\n"
                + "\n".join(f"- {a}" for a in affected[:20])
            )

        if references:
            content_parts.append(
                "\n## References\n" + "\n".join(f"- {r}" for r in references[:10])
            )

        exploit_score = cvss3.get("exploitabilityScore")
        impact_score = cvss3.get("impactScore")
        if exploit_score is not None:
            content_parts.append(
                f"\n## Exploitability\n- Exploitability Score: {exploit_score}\n- Impact Score: {impact_score}"
            )

        content = "\n".join(p for p in content_parts if p)

        tags = [cve_id, severity.lower()]
        tags.extend(weaknesses[:5])
        tags.extend(["cve", "nvd", "vulnerability", "cvss"])

        return KnowledgeDocument(
            title=f"{cve_id} — {severity} ({score})",
            content=content,
            content_type="markdown",
            domain="cve_exploit",
            category="intelligence",
            tags=tags,
            metadata=SourceMetadata(
                source_name=self.SOURCE_NAME,
                source_type=SourceType.API,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                license="Public Domain (NVD)",
            ),
            extra={
                "cve_id": cve_id,
                "cvss_score": score,
                "cvss_severity": severity,
                "cvss_vector": vector,
                "cwes": weaknesses,
                "affected_products": affected[:20],
            },
        )

    @staticmethod
    def _extract_cvss3(cve: dict[str, Any]) -> dict[str, Any]:
        metrics = cve.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                return {
                    "baseScore": cvss_data.get("baseScore", 0.0),
                    "baseSeverity": cvss_data.get("baseSeverity", "UNKNOWN"),
                    "vectorString": cvss_data.get("vectorString", ""),
                    "exploitabilityScore": entries[0].get("exploitabilityScore"),
                    "impactScore": entries[0].get("impactScore"),
                }
        return {}

    @staticmethod
    def _extract_cwes(cve: dict[str, Any]) -> list[str]:
        cwes: list[str] = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwes.append(desc.get("value", ""))
        return cwes

    @staticmethod
    def _extract_affected(cve: dict[str, Any]) -> list[str]:
        products: list[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        parts = criteria.split(":")
                        if len(parts) >= 6:
                            products.append(
                                f"{parts[3]} {parts[4]} {parts[5]}".replace("*", "").strip()
                            )
        return list(set(products))
