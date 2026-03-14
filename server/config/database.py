"""
Database & Storage Configuration — Qdrant, Redis.

┌─────────────────────────────────────────┐
│            RAG Storage Layer            │
├──────────────────┬──────────────────────┤
│   Vector DB      │   Cache             │
│   (Qdrant)       │   (Redis)           │
│                  │                     │
│ embeddings +     │ hot queries +       │
│ metadata index   │ recent results      │
└──────────────────┴──────────────────────┘

All values are read from environment variables (no prefix).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class DatabaseConfig(BaseSettings):
    """Unified config for all storage backends."""

    # ── Qdrant (vector embeddings + metadata index) ───────────────────────
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = ""
    qdrant_collection_prefix: str = "pentaforge"  # collections: pentaforge_strategies, _exploits, _tools, _standards, _attack_types

    # ── Redis (cache — hot queries + recent results) ──────────────────────
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = Field(default=3600, description="Cache TTL in seconds (1 hour)")

    # ── Embedding settings ────────────────────────────────────────────────
    embedding_model: str = "nomic-ai/nomic-embed-text-v2-moe"
    embedding_dimensions: int = 768
    embedding_batch_size: int = 100

    model_config = {
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }


# Singleton
db_config = DatabaseConfig()
