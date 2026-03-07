"""
KnowledgeDocument — Represents a single extracted document from a cybersecurity source.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


class SourceType(StrEnum):
    """Taxonomy of knowledge source types."""
    GITHUB_REPO = "github_repo"
    WEBSITE = "website"
    API = "api"
    GITBOOK = "gitbook"


class SourceMetadata(BaseModel):
    """Provenance and lineage tracking for a document."""
    source_name: str = Field(..., description="Human-readable source name, e.g. 'HackTricks'")
    source_type: SourceType
    source_url: str = Field(..., description="Origin URL (repo URL, page URL, API endpoint)")
    file_path: Optional[str] = Field(default=None, description="Relative path within repo, e.g. 'src/web/sqli.md'")
    branch: str = "main"
    commit_sha: Optional[str] = None
    last_fetched: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    license: Optional[str] = None


class KnowledgeDocument(BaseModel):
    """
    A single document extracted from a cybersecurity knowledge source.

    This is the raw extracted content before chunking. Each document maps to
    one file (from a repo), one page (from a website), or one API response.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    title: str = ""
    content: str = Field(..., description="Raw text/markdown content")
    content_type: str = Field(default="markdown", description="markdown | text | json | yaml")
    domain: str = Field(default="shared", description="Target domain (web, api, mobile, cloud, ...)")
    category: str = Field(default="general", description="Sub-category within the domain")
    tags: list[str] = Field(default_factory=list, description="e.g. ['sqli', 'mysql', 'bypass']")
    metadata: SourceMetadata
    language: str = "en"
    extra: dict[str, Any] = Field(default_factory=dict, description="Source-specific extra fields")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field  # type: ignore[misc]
    @property
    def content_hash(self) -> str:
        """SHA-256 hash of the content, used for deduplication."""
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def word_count(self) -> int:
        return len(self.content.split())

    def is_meaningful(self, min_words: int = 20) -> bool:
        """Filter out near-empty or boilerplate docs."""
        return self.word_count >= min_words
