"""
KnowledgeOrchestrator — Domain-aware pipeline: extraction → cleaning → chunking → embedding → storage.

Each source is routed to the correct vector index based on its domain.
Shared sources go to vector_shared (queried by all agents).

Usage:
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.ingest_source("HackTricks")
    await orchestrator.ingest_domain("web")
    await orchestrator.ingest_all()
    results = await orchestrator.search("SQL injection bypass WAF", domain="web")
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from server.db.knowledge.config.settings import settings
from server.db.knowledge.config.sources import (
    ALL_SOURCES,
    SourceConfig,
    get_enabled_sources,
    get_source_by_name,
    get_sources_by_domain,
    get_all_domains,
)
from server.db.knowledge.models.document import KnowledgeDocument, SourceType
from server.db.knowledge.processing.chunker import MarkdownChunker
from server.db.knowledge.processing.cleaner import ContentCleaner
from server.db.knowledge.sources.base import BaseExtractor
from server.db.knowledge.sources.github_extractor import GitHubRepoExtractor
from server.db.knowledge.sources.gitbook_extractor import GitBookExtractor
from server.db.knowledge.sources.nvd_extractor import NVDCVEExtractor
from server.db.knowledge.sources.nvd_service import NVDService
from server.db.knowledge.sources.website_extractor import WebsiteExtractor
from server.db.knowledge.storage.embedding import EmbeddingGenerator
from server.db.knowledge.storage.pg_store import NullPgStore, PgDocumentStore
from server.db.knowledge.storage.qdrant_store import QdrantVectorStore
from server.db.knowledge.storage.redis_cache import NullRedisCache, RedisCache

logger = structlog.get_logger(__name__)


@dataclass
class IngestionResult:
    """Result of ingesting a single source."""

    source_name: str
    domain: str = "shared"
    documents_extracted: int = 0
    chunks_created: int = 0
    chunks_embedded: int = 0
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    skipped_existing: int = 0

    @property
    def success(self) -> bool:
        return self.documents_extracted > 0 and len(self.errors) == 0


class KnowledgeOrchestrator:
    """
    Domain-aware pipeline: source → extract → clean → chunk → embed → store.

    Sources are routed to the correct vector_<domain> index.
    Supports single source, domain-level, or full ingestion.
    """

    def __init__(
        self,
        embedding_generator: EmbeddingGenerator | None = None,
        vector_store: QdrantVectorStore | None = None,
        pg_store: PgDocumentStore | None = None,
        chunker: MarkdownChunker | None = None,
        cache: RedisCache | None = None,
    ) -> None:
        self.embedder = embedding_generator or EmbeddingGenerator()
        self.vector_store = vector_store or QdrantVectorStore()
        self.pg_store = pg_store or PgDocumentStore()
        self.chunker = chunker or MarkdownChunker()
        self.cache = cache
        self.nvd = NVDService(
            embedder=self.embedder,
            vector_store=self.vector_store,
            pg_store=self.pg_store,
            chunker=self.chunker,
        )

    async def initialize(self) -> None:
        """Ensure storage backends are ready."""
        try:
            await self.pg_store.ensure_schema()
        except Exception as exc:
            logger.warning(
                "pg_unavailable",
                error=str(exc),
                hint="Running without PostgreSQL — no dedup or metadata tracking",
            )
            self.pg_store = NullPgStore()
            await self.pg_store.ensure_schema()

        # Initialize Qdrant (lazy — first collection created on upsert)
        self.vector_store._get_client()

        # Initialize Redis cache (fallback to no-op if unavailable)
        if self.cache is None:
            try:
                self.cache = RedisCache()
                logger.info("redis_cache_enabled")
            except Exception:
                self.cache = NullRedisCache()
                logger.warning("redis_unavailable", hint="Running without cache")

        logger.info("orchestrator_initialized")

    # ── Ingestion ─────────────────────────────────────────────────────────

    async def ingest_source(self, source_name: str) -> IngestionResult:
        """Ingest a single source by name."""
        config = get_source_by_name(source_name)
        if config is None:
            return IngestionResult(
                source_name=source_name,
                errors=[f"Unknown source: {source_name}"],
            )
        return await self._ingest(config)

    async def ingest_domain(
        self, domain: str, concurrency: int = 1
    ) -> list[IngestionResult]:
        """Ingest all enabled sources for a specific domain."""
        sources = get_sources_by_domain(domain)
        if not sources:
            return [IngestionResult(source_name=f"[{domain}]", domain=domain,
                                    errors=[f"No sources for domain: {domain}"])]

        logger.info("ingest_domain_start", domain=domain, source_count=len(sources))
        return await self._ingest_batch(sources, concurrency)

    async def ingest_all(self, concurrency: int = 1) -> list[IngestionResult]:
        """Ingest all enabled sources across all domains."""
        sources = get_enabled_sources()
        logger.info("ingest_all_start", source_count=len(sources))
        return await self._ingest_batch(sources, concurrency)

    async def _ingest_batch(
        self, sources: list[SourceConfig], concurrency: int = 1
    ) -> list[IngestionResult]:
        """Run ingestion for a batch of sources.

        Pre-clones shared repos (identified by clone_id) once before
        individual source ingestion so duplicated git clones are avoided.
        """
        await self._pre_clone_shared_repos(sources)

        results: list[IngestionResult] = []
        if concurrency <= 1:
            for config in sources:
                result = await self._ingest(config)
                results.append(result)
        else:
            sem = asyncio.Semaphore(concurrency)

            async def _limited(cfg: SourceConfig) -> IngestionResult:
                async with sem:
                    return await self._ingest(cfg)

            results = list(await asyncio.gather(
                *[_limited(cfg) for cfg in sources]
            ))

        total_docs = sum(r.documents_extracted for r in results)
        total_chunks = sum(r.chunks_created for r in results)
        logger.info(
            "ingest_batch_complete",
            sources=len(results),
            total_docs=total_docs,
            total_chunks=total_chunks,
        )
        return results

    async def _ingest(self, config: SourceConfig) -> IngestionResult:
        """Run the full pipeline for a single source config."""
        start = datetime.now(timezone.utc)
        result = IngestionResult(source_name=config.name, domain=config.domain)

        logger.info("ingest_start", source=config.name, domain=config.domain,
                     type=config.source_type.value)

        try:
            # 1. Extract documents
            extractor = self._create_extractor(config)
            documents: list[KnowledgeDocument] = []

            async for doc in extractor.extract():
                doc.content = ContentCleaner.clean(doc.content, config.name)

                if not doc.is_meaningful():
                    continue

                if await self.pg_store.exists(config.name, doc.content_hash):
                    result.skipped_existing += 1
                    continue

                # Stamp domain + category from source config
                doc.domain = config.domain
                doc.category = config.category
                documents.append(doc)

            result.documents_extracted = len(documents)

            if not documents:
                logger.info("ingest_no_new_docs", source=config.name,
                            skipped=result.skipped_existing)
                result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            # 2. Chunk documents
            all_chunks = self.chunker.chunk_documents(documents)
            # Stamp domain + source-level default metadata on chunks
            for chunk in all_chunks:
                chunk.domain = config.domain
                if config.default_metadata:
                    for key, val in config.default_metadata.items():
                        if hasattr(chunk, key) and not getattr(chunk, key):
                            setattr(chunk, key, val)
            result.chunks_created = len(all_chunks)

            if not all_chunks:
                result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            # 3. Generate embeddings
            texts = [chunk.content for chunk in all_chunks]
            embeddings = await self.embedder.embed_texts(texts)
            result.chunks_embedded = len(embeddings)

            # 4. Store vectors in the domain's collection
            self.vector_store.upsert_chunks(all_chunks, embeddings, domain=config.domain)

            # 5. Persist document metadata in PostgreSQL
            for doc in documents:
                doc_chunks = [c for c in all_chunks if c.document_id == doc.id]
                await self.pg_store.upsert_document(doc, chunk_count=len(doc_chunks))

            logger.info(
                "ingest_complete",
                source=config.name,
                domain=config.domain,
                docs=result.documents_extracted,
                chunks=result.chunks_created,
                skipped=result.skipped_existing,
            )

        except Exception as exc:
            result.errors.append(str(exc))
            logger.error("ingest_error", source=config.name, error=str(exc), exc_info=True)

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    async def _pre_clone_shared_repos(
        self, sources: list[SourceConfig]
    ) -> None:
        """Clone each unique clone_id repo once so shared sources skip re-cloning."""
        seen: dict[str, SourceConfig] = {}
        for cfg in sources:
            if cfg.clone_id and cfg.source_type == SourceType.GITHUB_REPO and cfg.clone_id not in seen:
                seen[cfg.clone_id] = cfg

        if not seen:
            return

        logger.info("pre_cloning_shared_repos", count=len(seen),
                     repos=list(seen.keys()))

        for clone_id, cfg in seen.items():
            extractor = GitHubRepoExtractor(cfg)
            await extractor._ensure_repo()

    def _create_extractor(self, config: SourceConfig) -> BaseExtractor:
        """Factory: pick the right extractor for a source type."""
        match config.source_type:
            case SourceType.GITHUB_REPO:
                return GitHubRepoExtractor(config)
            case SourceType.WEBSITE:
                return WebsiteExtractor(config)
            case SourceType.GITBOOK:
                return GitBookExtractor(config)
            case SourceType.API:
                return NVDCVEExtractor(config)
            case _:
                raise ValueError(f"No extractor for type: {config.source_type}")

    # ── Search ────────────────────────────────────────────────────────────

    async def search(
        self,
        query: str,
        domain: str | None = None,
        source_name: str | None = None,
        n_results: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Semantic search across the knowledge base.

        If domain is specified, searches that domain + shared.
        If domain is None, searches all collections.
        Results are cached in Redis for fast repeat queries.
        """
        search_domain = domain or "shared"

        # Check cache (skip if source_name filter is used)
        if not source_name and self.cache:
            cached = await self.cache.get(query, search_domain, n_results)
            if cached is not None:
                logger.debug("search_cache_hit", query=query[:50], domain=search_domain)
                return cached

        query_embedding = await self.embedder.embed_single(query)

        where: dict[str, Any] | None = None
        if source_name:
            where = {"source_name": source_name}

        if domain:
            results = self.vector_store.search_with_shared(
                query_embedding=query_embedding,
                domain=domain,
                n_results=n_results,
                where=where,
            )
        else:
            # Search all domains
            domains = get_all_domains()
            results = self.vector_store.search_multi(
                query_embedding=query_embedding,
                domains=domains,
                n_results=n_results,
                where=where,
            )

        # Cache results
        if not source_name and self.cache:
            await self.cache.set(query, search_domain, n_results, results)

        return results

    # ── NVD On-Demand ─────────────────────────────────────────────────────

    async def lookup_cve(self, cve_id: str) -> KnowledgeDocument | None:
        return await self.nvd.lookup_cve(cve_id)

    async def search_cves(
        self,
        keyword: str,
        severity: str | None = "CRITICAL",
        max_results: int = 50,
    ) -> list[KnowledgeDocument]:
        result = await self.nvd.search_product(
            keyword=keyword, severity=severity, max_results=max_results
        )
        return result.documents

    async def seed_nvd(self, keywords: list[str] | None = None) -> dict:
        results = await self.nvd.seed_common_targets(keywords=keywords)
        return {
            kw: {"fetched": r.fetched, "cached": r.cached, "total": r.total}
            for kw, r in results.items()
        }

    # ── Management ────────────────────────────────────────────────────────

    async def get_stats(self) -> dict[str, Any]:
        vector_stats = self.vector_store.get_stats()
        pg_stats = await self.pg_store.get_source_stats()

        return {
            "vector_store": vector_stats,
            "document_store": {
                "sources": pg_stats,
                "total_sources": len(pg_stats),
            },
            "domains": get_all_domains(),
        }

    async def delete_source(self, source_name: str) -> None:
        config = get_source_by_name(source_name)
        domain = config.domain if config else None
        self.vector_store.delete_by_source(source_name, domain=domain)
        await self.pg_store.delete_by_source(source_name)
        logger.info("source_deleted", source_name=source_name, domain=domain)

    async def close(self) -> None:
        await self.pg_store.close()
        if self.cache:
            await self.cache.close()
