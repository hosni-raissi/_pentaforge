"""
KnowledgeChunk — A chunked segment of a KnowledgeDocument, ready for embedding.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


class KnowledgeChunk(BaseModel):
    """
    A discrete chunk of text derived from a KnowledgeDocument.

    Chunks are the unit stored in the vector database and retrieved during RAG.
    Each chunk preserves a reference to its parent document for lineage.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    document_id: uuid.UUID = Field(..., description="FK to parent KnowledgeDocument")
    content: str = Field(..., description="The chunk text")
    chunk_index: int = Field(default=0, description="Position within the parent doc")
    heading: str = Field(default="", description="Section heading this chunk belongs to")
    token_count: int = 0
    embedding: Optional[list[float]] = Field(default=None, exclude=True)

    # ── Provenance ────────────────────────────────────────────────────────
    source_name: str = ""
    source_url: str = ""
    file_path: str = ""
    domain: str = "shared"
    category: str = "general"
    tags: list[str] = Field(default_factory=list)

    # ── Rich security metadata ────────────────────────────────────────────
    target: str = ""                     # e.g. "web", "api", "mobile"
    attack_phase: str = ""               # MITRE kill-chain phase
    mitre_technique_id: str = ""         # e.g. "T1190"
    attack_tactic: str = ""              # e.g. "initial-access"
    cwe: str = ""                        # e.g. "CWE-89"
    cvss: float | None = None
    severity: str = ""                   # info, low, medium, high, critical
    platform: list[str] = Field(default_factory=list)
    exploit_maturity: str = ""           # theoretical, poc, functional, weaponized
    tooling: list[str] = Field(default_factory=list)
    detection_method: str = ""
    evasion_technique: str = ""

    extra: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field  # type: ignore[misc]
    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    def to_vector_metadata(self) -> dict[str, Any]:
        """Flatten metadata for vector DB storage (Qdrant payload)."""
        meta: dict[str, Any] = {
            "document_id": str(self.document_id),
            "chunk_index": self.chunk_index,
            "source_name": self.source_name,
            "source_url": self.source_url,
            "file_path": self.file_path,
            "domain": self.domain,
            "category": self.category,
            "tags": ",".join(self.tags),
            "heading": self.heading,
            "content_hash": self.content_hash,
        }
        # Only include non-empty security metadata
        if self.target:
            meta["target"] = self.target
        if self.attack_phase:
            meta["attack_phase"] = self.attack_phase
        if self.mitre_technique_id:
            meta["mitre_technique_id"] = self.mitre_technique_id
        if self.attack_tactic:
            meta["attack_tactic"] = self.attack_tactic
        if self.cwe:
            meta["cwe"] = self.cwe
        if self.cvss is not None:
            meta["cvss"] = self.cvss
        if self.severity:
            meta["severity"] = self.severity
        if self.platform:
            meta["platform"] = ",".join(self.platform)
        if self.exploit_maturity:
            meta["exploit_maturity"] = self.exploit_maturity
        if self.tooling:
            meta["tooling"] = ",".join(self.tooling)
        if self.detection_method:
            meta["detection_method"] = self.detection_method
        if self.evasion_technique:
            meta["evasion_technique"] = self.evasion_technique
        return meta
