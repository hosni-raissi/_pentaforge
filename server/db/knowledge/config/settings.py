"""
Global settings for the Knowledge Base RAG pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class KnowledgeSettings(BaseSettings):
    """Environment-driven configuration for the knowledge pipeline."""

    # ── Paths ─────────────────────────────────────────────────────────────
    data_dir: Path = Field(
        default=Path(__file__).resolve().parent.parent / "data",
        description="Root directory for cloned repos and cached data",
    )
    clone_dir: Optional[Path] = Field(default=None, description="Where to clone repos")
    cache_dir: Optional[Path] = Field(default=None, description="Scraped page cache")

    # ── Embedding ─────────────────────────────────────────────────────────
    embedding_provider: str = "local"   # "local" (sentence-transformers) or "openai"
    embedding_model: str = "all-MiniLM-L6-v2"  # local default; use "text-embedding-3-small" for openai
    embedding_dimensions: int = 384      # 384 for MiniLM, 1536 for text-embedding-3-small
    embedding_batch_size: int = 100
    openai_api_key: str = ""

    # ── Chunking ──────────────────────────────────────────────────────────
    chunk_size: int = 1000          # tokens
    chunk_overlap: int = 150        # tokens
    min_chunk_words: int = 20       # skip tiny chunks

    # ── Vector DB (legacy — use server.config.database.db_config instead) ──
    # Kept for backward compat; unused by QdrantVectorStore.
    chroma_persist_dir: Optional[Path] = Field(default=None, description="Deprecated — ChromaDB removed")

    # ── PostgreSQL (document metadata) ────────────────────────────────────
    pg_dsn: str = "postgresql://pentaforge:pentaforge@localhost:5432/pentaforge"

    # ── NVD API ───────────────────────────────────────────────────────────
    nvd_api_key: str = ""
    nvd_rate_limit_delay: float = 6.0  # seconds between requests (NVD default)

    # ── Scraping ──────────────────────────────────────────────────────────
    scrape_concurrency: int = 3
    scrape_delay: float = 1.5
    request_timeout: int = 30
    user_agent: str = "PentaForge-KnowledgeBot/0.1 (+https://github.com/pentaforge)"

    # ── Git ────────────────────────────────────────────────────────────────
    git_depth: int = 5              # shallow clone
    git_clone_timeout: int = 600    # seconds (10 min max per git operation)

    model_config = {
        "env_prefix": "KNOWLEDGE_",
        "env_file": ".env",
        "extra": "ignore",
    }

    def model_post_init(self, __context: object) -> None:
        """Derive paths from data_dir if not explicitly set."""
        if self.clone_dir is None:
            self.clone_dir = self.data_dir / "repos"
        if self.cache_dir is None:
            self.cache_dir = self.data_dir / "cache"
        if self.chroma_persist_dir is None:
            self.chroma_persist_dir = self.data_dir / "chroma"

        # Ensure directories exist
        for d in [self.data_dir, self.clone_dir, self.cache_dir, self.chroma_persist_dir]:
            d.mkdir(parents=True, exist_ok=True)


# Singleton (import once)
settings = KnowledgeSettings()
