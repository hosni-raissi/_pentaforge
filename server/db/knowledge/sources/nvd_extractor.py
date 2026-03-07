"""
NVDCVEExtractor — Fetches vulnerabilities from the NIST NVD CVE 2.0 API.

API docs: https://nvd.nist.gov/developers/vulnerabilities
Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0

Rate limits:
  - Without API key: 5 requests per 30 seconds
  - With API key:    50 requests per 30 seconds

Each CVE becomes a KnowledgeDocument with structured metadata:
  - CVE ID, CVSS v3 score, severity, description, affected products (CPE)
  - References, weaknesses (CWE), exploitability metrics
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

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

logger = structlog.get_logger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDCVEExtractor(BaseExtractor):
    """
    Fetches CVEs from the NVD API and yields one KnowledgeDocument per CVE.

    Supports:
      - Keyword search (e.g. "Apache Tomcat 9.0.30")
      - Severity filter (CRITICAL, HIGH, MEDIUM, LOW)
      - Date range (pubStartDate / pubEndDate)
      - Pagination (resultsPerPage + startIndex)
    """

    def __init__(
        self,
        config: SourceConfig,
        keyword: str | None = None,
        severity: str | None = "CRITICAL",
        days_back: int = 365,
        max_results: int = 500,
    ) -> None:
        super().__init__(config)
        self.keyword = keyword
        self.severity = severity
        self.days_back = days_back
        self.max_results = max_results

    async def extract(self) -> AsyncIterator[KnowledgeDocument]:
        """Paginated fetch of CVEs from NVD."""
        headers = {"User-Agent": settings.user_agent}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        start_index = 0
        results_per_page = 50
        total_fetched = 0

        async with httpx.AsyncClient(
            timeout=settings.request_timeout,
            headers=headers,
        ) as client:
            while total_fetched < self.max_results:
                params = self._build_params(start_index, results_per_page)
                logger.info(
                    "nvd_fetch",
                    start_index=start_index,
                    keyword=self.keyword,
                    severity=self.severity,
                )

                try:
                    resp = await client.get(NVD_BASE_URL, params=params)

                    if resp.status_code == 403:
                        logger.warning("nvd_rate_limited, waiting...")
                        await asyncio.sleep(30)
                        continue

                    resp.raise_for_status()
                    data = resp.json()

                except httpx.HTTPStatusError as exc:
                    logger.error("nvd_api_error", status=exc.response.status_code)
                    break
                except Exception as exc:
                    logger.error("nvd_fetch_error", error=str(exc))
                    break

                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    doc = self._cve_to_document(vuln)
                    if doc and doc.is_meaningful():
                        total_fetched += 1
                        yield doc

                start_index += results_per_page
                if start_index >= total_results:
                    break

                # Rate limiting
                delay = settings.nvd_rate_limit_delay
                await asyncio.sleep(delay)

        logger.info("nvd_extraction_complete", total=total_fetched)

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    NVD_BASE_URL,
                    params={"resultsPerPage": "1", "startIndex": "0"},
                )
                return resp.status_code == 200
        except Exception:
            return False

    # ── Private ───────────────────────────────────────────────────────────

    def _build_params(self, start_index: int, results_per_page: int) -> dict[str, str]:
        params: dict[str, str] = {
            "startIndex": str(start_index),
            "resultsPerPage": str(results_per_page),
        }

        if self.keyword:
            params["keywordSearch"] = self.keyword

        if self.severity:
            params["cvssV3Severity"] = self.severity.upper()

        if self.days_back:
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=self.days_back)
            params["pubStartDate"] = start.strftime("%Y-%m-%dT00:00:00.000")
            params["pubEndDate"] = end.strftime("%Y-%m-%dT23:59:59.999")

        # Merge any extra params from config
        params.update(self.config.api_params)
        return params

    def _cve_to_document(self, vuln: dict[str, Any]) -> KnowledgeDocument | None:
        """Convert a single NVD CVE response object to a KnowledgeDocument."""
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

        # CVSS v3 metrics
        cvss3 = self._extract_cvss3(cve)
        severity = cvss3.get("baseSeverity", "UNKNOWN")
        score = cvss3.get("baseScore", 0.0)
        vector = cvss3.get("vectorString", "")

        # Weaknesses (CWE)
        weaknesses = self._extract_cwes(cve)

        # Affected products (CPE)
        affected = self._extract_affected(cve)

        # References
        references = [
            ref.get("url", "")
            for ref in cve.get("references", [])
            if ref.get("url")
        ]

        # Build rich content for RAG
        content_parts = [
            f"# {cve_id}",
            f"\n**Severity:** {severity} (CVSS {score})",
            f"**CVSS Vector:** {vector}" if vector else "",
            f"\n## Description\n{description}",
        ]

        if weaknesses:
            content_parts.append(f"\n## Weaknesses (CWE)\n" + "\n".join(f"- {w}" for w in weaknesses))

        if affected:
            content_parts.append(f"\n## Affected Products\n" + "\n".join(f"- {a}" for a in affected[:20]))

        if references:
            content_parts.append(f"\n## References\n" + "\n".join(f"- {r}" for r in references[:10]))

        # Exploitability info
        exploit_score = cvss3.get("exploitabilityScore")
        impact_score = cvss3.get("impactScore")
        if exploit_score is not None:
            content_parts.append(f"\n## Exploitability\n- Exploitability Score: {exploit_score}")
            content_parts.append(f"- Impact Score: {impact_score}")

        content = "\n".join(p for p in content_parts if p)

        tags = [cve_id, severity.lower()]
        tags.extend(weaknesses[:5])
        tags.extend(self.config.tags)

        return KnowledgeDocument(
            title=f"{cve_id} — {severity} ({score})",
            content=content,
            content_type="markdown",
            domain="cve_exploit",
            category="intelligence",
            tags=tags,
            metadata=SourceMetadata(
                source_name=self.config.name,
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
        """Extract CVSS v3.x metrics."""
        metrics = cve.get("metrics", {})

        # Try v3.1 first, then v3.0
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
                        # cpe:2.3:a:vendor:product:version:... → vendor product version
                        parts = criteria.split(":")
                        if len(parts) >= 6:
                            products.append(f"{parts[3]} {parts[4]} {parts[5]}".replace("*", "").strip())
        return list(set(products))
