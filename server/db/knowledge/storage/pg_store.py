"""
PostgreSQL metadata store for KnowledgeDocuments.

Tracks which documents/sources have been ingested, their content hashes for
deduplication, and last-fetched timestamps for incremental updates.
Uses asyncpg via SQLAlchemy async for non-blocking writes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog

from server.config.database import db_config
from server.db.knowledge.models.document import KnowledgeDocument

logger = structlog.get_logger(__name__)


# ── SQL Schema (idempotent create) ────────────────────────────────────────

CREATE_DOCUMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS knowledge_documents (
    id              UUID PRIMARY KEY,
    title           TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    content_type    TEXT NOT NULL DEFAULT 'text',
    domain          TEXT NOT NULL DEFAULT 'shared',
    category        TEXT NOT NULL DEFAULT 'general',
    source_name     TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    source_url      TEXT NOT NULL DEFAULT '',
    file_path       TEXT NOT NULL DEFAULT '',
    branch          TEXT,
    commit_sha      TEXT,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    chunk_count     INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_doc_hash UNIQUE (source_name, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_docs_source ON knowledge_documents(source_name);
CREATE INDEX IF NOT EXISTS idx_docs_domain ON knowledge_documents(domain);
CREATE INDEX IF NOT EXISTS idx_docs_category ON knowledge_documents(category);
CREATE INDEX IF NOT EXISTS idx_docs_hash ON knowledge_documents(content_hash);
"""

ADD_DOMAIN_COLUMN = """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'knowledge_documents' AND column_name = 'domain'
    ) THEN
        ALTER TABLE knowledge_documents ADD COLUMN domain TEXT NOT NULL DEFAULT 'shared';
        CREATE INDEX IF NOT EXISTS idx_docs_domain ON knowledge_documents(domain);
    END IF;
END $$;
"""

UPSERT_DOCUMENT = """
INSERT INTO knowledge_documents (
    id, title, content_hash, content_type, domain, category,
    source_name, source_type, source_url, file_path,
    branch, commit_sha, tags, chunk_count, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12, $13, $14, $15, $15
)
ON CONFLICT (source_name, content_hash)
DO UPDATE SET
    title       = EXCLUDED.title,
    domain      = EXCLUDED.domain,
    chunk_count = EXCLUDED.chunk_count,
    updated_at  = EXCLUDED.updated_at
RETURNING id;
"""

GET_DOC_BY_HASH = """
SELECT id FROM knowledge_documents
WHERE source_name = $1 AND content_hash = $2;
"""

DELETE_BY_SOURCE = """
DELETE FROM knowledge_documents WHERE source_name = $1;
"""

GET_SOURCE_STATS = """
SELECT source_name, domain, COUNT(*) AS doc_count, MAX(updated_at) AS last_update
FROM knowledge_documents
GROUP BY source_name, domain
ORDER BY domain, source_name;
"""

GET_DOMAIN_STATS = """
SELECT domain, COUNT(*) AS doc_count, SUM(chunk_count) AS total_chunks,
       MAX(updated_at) AS last_update
FROM knowledge_documents
GROUP BY domain
ORDER BY domain;
"""


class NullPgStore:
    """No-op fallback when PostgreSQL is unavailable. Skips dedup/metadata."""

    async def ensure_schema(self) -> None:
        logger.warning("pg_disabled", reason="No PostgreSQL configured — running without dedup/metadata")

    async def upsert_document(self, doc: KnowledgeDocument, chunk_count: int = 0) -> uuid.UUID:
        return doc.id

    async def exists(self, source_name: str, content_hash: str) -> bool:
        return False

    async def delete_by_source(self, source_name: str) -> int:
        return 0

    async def get_source_stats(self) -> list[dict]:
        return []

    async def get_domain_stats(self) -> list[dict]:
        return []

    async def close(self) -> None:
        pass


class PgDocumentStore:
    """PostgreSQL adapter for document metadata persistence."""

    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn or db_config.database_url
        self._pool = None

    async def _get_pool(self):
        """Lazy-init asyncpg connection pool."""
        if self._pool is None:
            try:
                import asyncpg
            except ImportError:
                raise RuntimeError("asyncpg package required — pip install asyncpg")

            self._pool = await asyncpg.create_pool(
                dsn=self.dsn,
                min_size=2,
                max_size=10,
            )
            logger.info("pg_pool_initialized", dsn=self.dsn[:30] + "...")
        return self._pool

    async def ensure_schema(self) -> None:
        """Create tables/indexes if they don't exist."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(CREATE_DOCUMENTS_TABLE)
            await conn.execute(ADD_DOMAIN_COLUMN)
        logger.info("pg_schema_ensured")

    async def upsert_document(
        self,
        doc: KnowledgeDocument,
        chunk_count: int = 0,
    ) -> uuid.UUID:
        """
        Insert or update a document record.
        Deduplication is based on (source_name, content_hash).

        Returns the document UUID.
        """
        pool = await self._get_pool()
        now = datetime.now(timezone.utc)

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                UPSERT_DOCUMENT,
                doc.id,
                doc.title,
                doc.content_hash,
                doc.content_type,
                doc.domain,
                doc.category,
                doc.metadata.source_name,
                doc.metadata.source_type.value,
                doc.metadata.source_url,
                doc.metadata.file_path or "",
                doc.metadata.branch,
                doc.metadata.commit_sha,
                doc.tags,
                chunk_count,
                now,
            )
            return row["id"]

    async def exists(self, source_name: str, content_hash: str) -> bool:
        """Check if a document with this hash already exists for the source."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(GET_DOC_BY_HASH, source_name, content_hash)
            return row is not None

    async def delete_by_source(self, source_name: str) -> int:
        """Delete all documents for a source. Returns count deleted."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute(DELETE_BY_SOURCE, source_name)
            count = int(result.split()[-1])
            logger.info("pg_docs_deleted", source_name=source_name, count=count)
            return count

    async def get_source_stats(self) -> list[dict]:
        """Get ingestion stats per source."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(GET_SOURCE_STATS)
            return [
                {
                    "source_name": r["source_name"],
                    "domain": r["domain"],
                    "doc_count": r["doc_count"],
                    "last_update": r["last_update"].isoformat() if r["last_update"] else None,
                }
                for r in rows
            ]

    async def get_domain_stats(self) -> list[dict]:
        """Get ingestion stats per domain."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(GET_DOMAIN_STATS)
            return [
                {
                    "domain": r["domain"],
                    "doc_count": r["doc_count"],
                    "total_chunks": r["total_chunks"],
                    "last_update": r["last_update"].isoformat() if r["last_update"] else None,
                }
                for r in rows
            ]

    async def close(self) -> None:
        """Close connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None
