"""
KnowledgeOrchestrator — Content-type-aware pipeline: extraction → cleaning → chunking → embedding → storage.

Each source is routed to the correct Qdrant collection based on its content_type.
Domain is stored as metadata for filtering.

Usage:
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.ingest_source("HackTricks")
    await orchestrator.ingest_domain("web")
    await orchestrator.ingest_all()
    results = await orchestrator.search("SQL injection bypass WAF", domain="web")
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from server.db.knowledge.config.settings import settings
from server.db.knowledge.config.sources import (
    ALL_SOURCES,
    ContentType,
    PayloadSourceConfig,
    PAYLOAD_SOURCES,
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
    replaced_existing: int = 0

    @property
    def success(self) -> bool:
        return len(self.errors) == 0 and (
            self.documents_extracted > 0 or self.skipped_existing > 0 or self.replaced_existing > 0
        )


class KnowledgeOrchestrator:
    """
    Content-type-aware pipeline: source → extract → clean → chunk → embed → store.

    Sources are routed to the correct Qdrant collection by content_type.
    Domain is stored as metadata for filtering.
    """

    def __init__(
        self,
        embedding_generator: EmbeddingGenerator | None = None,
        vector_store: QdrantVectorStore | None = None,
        chunker: MarkdownChunker | None = None,
        cache: RedisCache | None = None,
    ) -> None:
        self.embedder = embedding_generator or EmbeddingGenerator()
        self.vector_store = vector_store or QdrantVectorStore()
        self.chunker = chunker or MarkdownChunker()
        self.cache = cache
        self.nvd = NVDService(
            embedder=self.embedder,
            vector_store=self.vector_store,
            chunker=self.chunker,
        )

    async def initialize(self) -> None:
        """Ensure storage backends are ready."""
        # Pre-create all 5 content-type collections
        self.vector_store.ensure_all_collections()

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
        """Run the full pipeline for a single source config.

        Document-level dedup:
          1. Bulk-fetch existing {doc_identity → content_hash} from Qdrant for this source.
          2. For each extracted doc, compute its stable identity (file_path or source_url).
          3. If identity exists AND hash matches → skip (unchanged).
          4. If identity exists AND hash differs → delete old chunks, re-ingest.
          5. If identity is new → ingest fresh.
        """
        start = datetime.now(timezone.utc)
        result = IngestionResult(source_name=config.name, domain=config.domain)

        logger.info("ingest_start", source=config.name, domain=config.domain,
                     type=config.source_type.value, content_type=config.content_type)

        try:
            # Pre-fetch existing doc hashes for this source from Qdrant
            existing_hashes = self.vector_store.get_source_doc_hashes(
                config.name, config.content_type.value,
            )

            # 1. Extract & dedup documents
            extractor = self._create_extractor(config)
            documents = await self._extract_with_dedup(extractor, config, existing_hashes, result)

            result.documents_extracted = len(documents)

            if not documents:
                logger.info("ingest_no_new_docs", source=config.name,
                            skipped=result.skipped_existing,
                            replaced=result.replaced_existing)
                result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            # 2. Chunk documents — stamp doc-level content_hash on every chunk
            all_chunks = self._chunk_and_stamp(documents, config)
            result.chunks_created = len(all_chunks)

            if not all_chunks:
                result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            # 3. Generate embeddings
            texts = [chunk.content for chunk in all_chunks]
            embeddings = await self.embedder.embed_texts(texts)
            result.chunks_embedded = len(embeddings)

            # 4. Store vectors in the content-type collection (domain in metadata)
            self.vector_store.upsert_chunks(all_chunks, embeddings, content_type=config.content_type.value)

            logger.info(
                "ingest_complete",
                source=config.name,
                domain=config.domain,
                content_type=config.content_type.value,
                docs=result.documents_extracted,
                chunks=result.chunks_created,
                skipped=result.skipped_existing,
                replaced=result.replaced_existing,
            )

        except Exception as exc:
            result.errors.append(str(exc))
            logger.error("ingest_error", source=config.name, error=str(exc), exc_info=True)

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    async def _extract_with_dedup(
        self,
        extractor: BaseExtractor,
        config: SourceConfig,
        existing_hashes: dict[str, dict[str, int | str | None]],
        result: IngestionResult,
    ) -> list[KnowledgeDocument]:
        """Extract docs, skip unchanged, delete-then-queue changed ones."""
        documents: list[KnowledgeDocument] = []
        seen_in_run: dict[str, str] = {}

        async for doc in extractor.extract():
            doc.content = ContentCleaner.clean(doc.content, config.name)

            if not doc.is_meaningful():
                continue

            doc_identity = self._build_doc_identity(doc, config.name)

            # Collapse duplicate identities emitted within the same ingestion run.
            # This prevents repeated embedding of identical documents when extractors
            # surface aliases or duplicated paths/URLs.
            seen_hash = seen_in_run.get(doc_identity)
            if seen_hash is not None and seen_hash == doc.content_hash:
                result.skipped_existing += 1
                continue
            seen_in_run[doc_identity] = doc.content_hash

            old_state = existing_hashes.pop(doc_identity, None)
            old_hash = (old_state or {}).get("doc_content_hash") if old_state else None
            old_chunk_count = int((old_state or {}).get("chunk_count", 0)) if old_state else 0
            old_chunk_total_raw = (old_state or {}).get("doc_chunk_total") if old_state else None
            old_chunk_total = int(old_chunk_total_raw) if old_chunk_total_raw is not None else None
            is_incomplete = old_chunk_total is not None and old_chunk_count < old_chunk_total

            if old_hash is not None:
                if old_hash == doc.content_hash and not is_incomplete:
                    result.skipped_existing += 1
                    continue
                # Changed — delete old chunks so new ones replace them
                self.vector_store.delete_by_doc_identity(
                    config.name, doc_identity, config.content_type.value,
                )
                result.replaced_existing += 1
                if is_incomplete:
                    logger.debug(
                        "doc_replaced_incomplete",
                        source=config.name,
                        identity=doc_identity,
                        chunk_count=old_chunk_count,
                        chunk_total=old_chunk_total,
                    )
                else:
                    logger.debug("doc_replaced", source=config.name, identity=doc_identity)

            doc.domain = config.domain
            doc.category = config.category
            documents.append(doc)

        return documents

    @staticmethod
    def _slugify(value: str) -> str:
        lowered = value.lower().strip()
        lowered = re.sub(r"[^a-z0-9]+", "-", lowered)
        return lowered.strip("-") or "untitled"

    def _build_doc_identity(self, doc: KnowledgeDocument, source_name: str) -> str:
        """Return a stable identity used for dedup and replacement semantics.

        Priority:
          1. file_path
          2. source_url
          3. synthetic URL based on source + title
        """
        if doc.metadata.file_path:
            return doc.metadata.file_path
        if doc.metadata.source_url:
            return doc.metadata.source_url

        synthetic = f"kb://{self._slugify(source_name)}/{self._slugify(doc.title)}"
        doc.metadata.source_url = synthetic
        return synthetic

    def _chunk_and_stamp(
        self,
        documents: list[KnowledgeDocument],
        config: SourceConfig,
    ) -> list["KnowledgeChunk"]:
        """Chunk documents and stamp domain + doc-level content_hash on every chunk."""
        all_chunks = self.chunker.chunk_documents(documents)
        doc_hash_map = {str(d.id): d.content_hash for d in documents}
        doc_chunk_total_map: dict[str, int] = {}
        for chunk in all_chunks:
            key = str(chunk.document_id)
            doc_chunk_total_map[key] = doc_chunk_total_map.get(key, 0) + 1

        for chunk in all_chunks:
            chunk.domain = config.domain
            chunk.extra["doc_content_hash"] = doc_hash_map.get(str(chunk.document_id), "")
            chunk.extra["doc_chunk_total"] = doc_chunk_total_map.get(str(chunk.document_id), 0)
            if config.default_metadata:
                for key, val in config.default_metadata.items():
                    if hasattr(chunk, key) and not getattr(chunk, key):
                        setattr(chunk, key, val)
        return all_chunks

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

    @staticmethod
    def _merge_results(
        primary: list[dict[str, Any]],
        secondary: list[dict[str, Any]],
        n_results: int,
    ) -> list[dict[str, Any]]:
        """Merge two result sets, de-duplicate by id, and keep top-N by score."""
        seen_ids: set[str] = set()
        merged: list[dict[str, Any]] = []
        for hit in sorted(primary + secondary, key=lambda h: h.get("score", 0), reverse=True):
            hit_id = str(hit.get("id", ""))
            if hit_id and hit_id in seen_ids:
                continue
            if hit_id:
                seen_ids.add(hit_id)
            merged.append(hit)
            if len(merged) >= n_results:
                break
        return merged

    # ── Search ────────────────────────────────────────────────────────────

    async def search(
        self,
        query: str,
        domain: str | None = None,
        content_type: str | None = None,
        source_name: str | None = None,
        n_results: int = 10,
        include_shared: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Semantic search across the knowledge base.

        Searches by content_type collection(s), optionally filtered by domain.
        Results are cached in Redis for fast repeat queries.
        """
        cache_key = content_type or domain or "all"

        # Check cache (skip if source_name filter is used)
        if not source_name and self.cache:
            cached = await self.cache.get(query, cache_key, n_results)
            if cached is not None:
                logger.debug("search_cache_hit", query=query[:50], key=cache_key)
                return cached

        query_embedding = await self.embedder.embed_single(query, is_query=True)

        where: dict[str, Any] | None = None
        if source_name:
            where = {"source_name": source_name}

        include_shared = include_shared and bool(domain and domain != "shared")

        if content_type:
            primary = self.vector_store.search(
                query_embedding=query_embedding,
                content_type=content_type,
                domain=domain,
                n_results=n_results,
                where=where,
            )
            if include_shared:
                shared = self.vector_store.search(
                    query_embedding=query_embedding,
                    content_type=content_type,
                    domain="shared",
                    n_results=n_results,
                    where=where,
                )
                results = self._merge_results(primary, shared, n_results)
            else:
                results = primary
        else:
            # Search across all content-type collections.
            primary = self.vector_store.search_multi(
                query_embedding=query_embedding,
                content_types=[ct.value for ct in ContentType],
                domain=domain,
                n_results=n_results,
                where=where,
            )
            if include_shared:
                shared = self.vector_store.search_multi(
                    query_embedding=query_embedding,
                    content_types=[ct.value for ct in ContentType],
                    domain="shared",
                    n_results=n_results,
                    where=where,
                )
                results = self._merge_results(primary, shared, n_results)
            else:
                results = primary

        # Cache results
        if not source_name and self.cache:
            await self.cache.set(query, cache_key, n_results, results)

        return results

    async def search_payloads(
        self,
        query: str,
        domain: str | None = None,
        source_name: str | None = None,
        n_results: int = 10,
    ) -> list[dict[str, Any]]:
        """Exact/substring payload search from SQLite payload store."""
        from server.db.knowledge.storage.payload_store import PayloadStore

        store = PayloadStore()
        try:
            results = store.search_payloads(keyword=query, domain=domain)
            if source_name:
                results = [r for r in results if r.get("source") == source_name]
            return results[:n_results]
        finally:
            store.close()

    async def search_hybrid(
        self,
        query: str,
        domain: str | None = None,
        content_type: str | None = None,
        source_name: str | None = None,
        semantic_results: int = 10,
        payload_results: int = 10,
        include_shared: bool = True,
    ) -> dict[str, list[dict[str, Any]]]:
        """Run semantic vector search + payload text search in one call."""
        semantic_task = self.search(
            query=query,
            domain=domain,
            content_type=content_type,
            source_name=source_name,
            n_results=semantic_results,
            include_shared=include_shared,
        )
        payload_task = self.search_payloads(
            query=query,
            domain=domain,
            source_name=source_name,
            n_results=payload_results,
        )

        semantic, payloads = await asyncio.gather(semantic_task, payload_task)
        return {
            "semantic": semantic,
            "payloads": payloads,
        }

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

        return {
            "vector_store": vector_stats,
            "domains": get_all_domains(),
        }

    async def delete_source(self, source_name: str) -> None:
        config = get_source_by_name(source_name)
        content_type = config.content_type.value if config else None
        self.vector_store.delete_by_source(source_name, content_type=content_type)
        logger.info("source_deleted", source_name=source_name, content_type=content_type)

    # ── Payload Ingestion ─────────────────────────────────────────────────

    async def ingest_payloads(
        self, domain: str | None = None
    ) -> list[dict[str, Any]]:
        """Ingest raw payload files into the JSON PayloadStore.

        Clones repos (reusing clone_id), reads .txt/.md files line-by-line,
        and adds each non-empty line as a payload string.
        """
        from fnmatch import fnmatch
        from pathlib import Path

        from server.db.knowledge.storage.payload_store import PayloadStore

        store = PayloadStore()
        sources = PAYLOAD_SOURCES
        if domain:
            sources = [s for s in sources if s.domain == domain]

        if not sources:
            configured_domains = sorted({s.domain for s in PAYLOAD_SOURCES})
            logger.warning(
                "no_payload_sources",
                domain=domain,
                configured_domains=configured_domains,
            )
            return [{
                "name": "[no-payload-sources]",
                "domain": domain or "all",
                "category": "-",
                "payloads_added": 0,
                "error": (
                    f"No payload sources configured for domain '{domain}'. "
                    f"Configured payload domains: {', '.join(configured_domains) or 'none'}."
                ),
            }]

        # Pre-clone shared repos
        await self._pre_clone_payload_repos(sources)

        results: list[dict[str, Any]] = []
        for src in sources:
            try:
                count = await self._ingest_single_payload(src, store)
                results.append({
                    "name": src.name, "domain": src.domain,
                    "category": src.category, "payloads_added": count,
                })
            except Exception as exc:
                logger.error("payload_ingest_error", source=src.name, error=str(exc))
                results.append({
                    "name": src.name, "domain": src.domain,
                    "category": src.category, "payloads_added": 0,
                    "error": str(exc),
                })

        total = sum(r["payloads_added"] for r in results)
        logger.info("payload_ingestion_complete", sources=len(results), total_payloads=total)
        return results

    async def _pre_clone_payload_repos(
        self, sources: list[PayloadSourceConfig]
    ) -> None:
        """Clone each unique payload repo once."""
        seen: dict[str, PayloadSourceConfig] = {}
        for s in sources:
            key = s.clone_id or s.name
            if key not in seen:
                seen[key] = s

        for key, src in seen.items():
            # Build a minimal SourceConfig to reuse GitHubRepoExtractor._ensure_repo
            proxy = SourceConfig(
                name=src.name, url=src.url,
                source_type=SourceType.GITHUB_REPO,
                branch=src.branch,
                clone_id=src.clone_id,
            )
            extractor = GitHubRepoExtractor(proxy)
            await extractor._ensure_repo()

    async def _ingest_single_payload(
        self,
        src: PayloadSourceConfig,
        store: "PayloadStore",
    ) -> int:
        """Read .txt/.md payload files and feed lines into PayloadStore."""
        from fnmatch import fnmatch
        from pathlib import Path

        key = src.clone_id or src.name
        repo_dir = settings.clone_dir / key
        root = repo_dir / src.subdirectory if src.subdirectory else repo_dir

        if not root.exists():
            logger.error("payload_dir_missing", source=src.name, path=str(root))
            return 0

        total_added = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = str(path.relative_to(repo_dir))
            if not any(fnmatch(rel, pat) for pat in src.include_patterns):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # Each non-empty line is a payload
            lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
            # Skip comment-only or metadata lines (lines starting with # in .txt)
            payloads = [ln for ln in lines if not ln.startswith("#")]

            if payloads:
                added = store.add_payloads(
                    domain=src.domain,
                    category=src.category,
                    payloads=payloads,
                    source=src.name,
                    tags=src.tags,
                )
                total_added += added

        logger.info("payload_source_done", source=src.name, added=total_added)
        return total_added

    async def close(self) -> None:
        if self.cache:
            await self.cache.close()
