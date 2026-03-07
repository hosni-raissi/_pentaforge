"""
Knowledge Base domain models.

  KnowledgeDocument  — a full extracted document from any source
  KnowledgeChunk     — a chunked piece of a document, ready for embedding
  SourceMetadata     — provenance + lineage info for a document
  SourceType         — extraction type enum (GITHUB_REPO, WEBSITE, API, GITBOOK)
"""

from .document import KnowledgeDocument, SourceMetadata, SourceType
from .chunk import KnowledgeChunk

__all__ = ["KnowledgeDocument", "SourceMetadata", "SourceType", "KnowledgeChunk"]
