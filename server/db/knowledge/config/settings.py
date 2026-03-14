"""
Global settings for the Knowledge Base RAG pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings


_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


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
    embedding_model: str = "nomic-ai/nomic-embed-text-v2-moe"  # local default; use "text-embedding-3-small" for openai
    embedding_dimensions: int = 768      # 768 for nomic-embed-text-v2-moe, 1536 for text-embedding-3-small
    embedding_batch_size: int = 100
    openai_api_key: str = ""

    # ── Chunking ──────────────────────────────────────────────────────────
    chunk_size: int = 512           # tokens (matches bge-small-en-v1.5 max sequence length)
    chunk_overlap: int = 100        # tokens
    min_chunk_words: int = 20       # skip tiny chunks

    # ── RAG refresh throttling ────────────────────────────────────────────
    rag_refresh_days: int = 3  # minimum days between RAG refreshes for the same document

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
    github_token: str = Field(
        default="",
        validation_alias=AliasChoices("KNOWLEDGE_GITHUB_TOKEN", "GITHUB_TOKEN"),
        description="Optional PAT to avoid GitHub API rate limits",
    )

    model_config = {
        "env_prefix": "KNOWLEDGE_",
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }

    def model_post_init(self, __context: object) -> None:
        """Derive paths from data_dir if not explicitly set."""
        if self.clone_dir is None:
            self.clone_dir = self.data_dir / "repos"
        if self.cache_dir is None:
            self.cache_dir = self.data_dir / "cache"

        # Ensure directories exist
        for d in [self.data_dir, self.clone_dir, self.cache_dir]:
            d.mkdir(parents=True, exist_ok=True)


# Singleton (import once)
settings = KnowledgeSettings()
