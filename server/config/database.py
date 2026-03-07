"""
Database & Storage Configuration — Neon PostgreSQL, Qdrant, Redis.

┌─────────────────────────────────────────────────────┐
│                  RAG Storage Layer                   │
├──────────────────┬──────────────────┬────────────────┤
│   Vector DB      │   Document DB    │   Cache        │
│   (Qdrant)       │   (PostgreSQL)   │   (Redis)      │
│                  │                  │                │
│ embeddings +     │ raw chunks +     │ hot queries +  │
│ metadata index   │ source registry  │ recent results │
└──────────────────┴──────────────────┴────────────────┘

All values are read from environment variables (no prefix).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class DatabaseConfig(BaseSettings):
    """Unified config for all storage backends."""

    # ── Neon PostgreSQL (document store + source registry) ────────────────
    database_url: str  # e.g. postgresql://...@neon.tech/neondb?sslmode=require

    # ── Qdrant (vector embeddings + metadata index) ───────────────────────
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = ""
    qdrant_collection_prefix: str = "pentaforge"  # collections: pentaforge_shared, pentaforge_web, etc.

    # ── Redis (cache — hot queries + recent results) ──────────────────────
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = Field(default=3600, description="Cache TTL in seconds (1 hour)")

    # ── Embedding settings ────────────────────────────────────────────────
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_dimensions: int = 384
    embedding_batch_size: int = 100

    model_config = {
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }

    def qdrant_collection(self, domain: str) -> str:
        """Derive Qdrant collection name: 'pentaforge_web', 'pentaforge_shared', etc."""
        return f"{self.qdrant_collection_prefix}_{domain}"


# Singleton
db_config = DatabaseConfig()
