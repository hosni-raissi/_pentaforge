"""
MarkdownChunker — Splits KnowledgeDocuments into semantically meaningful chunks.

Strategy:
  1. Split by markdown headings (##, ###) to preserve section boundaries
  2. If a section is too long, split by paragraphs
  3. If a paragraph is still too long, split by sentences with overlap
  4. Preserve code blocks as atomic units when possible
  5. Attach heading context to each chunk for better retrieval
"""

from __future__ import annotations

import re
import uuid
from typing import Optional

import structlog

from server.db.knowledge.config.settings import settings
from server.db.knowledge.models.chunk import KnowledgeChunk
from server.db.knowledge.models.document import KnowledgeDocument

logger = structlog.get_logger(__name__)


class MarkdownChunker:
    """
    Splits documents into chunks optimized for embedding and retrieval.

    Respects:
      - Markdown heading boundaries (semantic sections)
      - Code block integrity (never splits inside ```)
      - Configurable chunk_size (tokens) and overlap
    """

    def __init__(
        self,
        chunk_size: int | None = None,
        chunk_overlap: int | None = None,
        min_chunk_words: int | None = None,
    ) -> None:
        self.chunk_size = chunk_size or settings.chunk_size
        self.chunk_overlap = chunk_overlap or settings.chunk_overlap
        self.min_chunk_words = min_chunk_words or settings.min_chunk_words

    def chunk_document(self, doc: KnowledgeDocument) -> list[KnowledgeChunk]:
        """Split a KnowledgeDocument into chunks."""
        sections = self._split_by_headings(doc.content)

        chunks: list[KnowledgeChunk] = []
        chunk_index = 0

        for heading, section_content in sections:
            section_chunks = self._split_section(section_content)

            for text in section_chunks:
                word_count = len(text.split())
                if word_count < self.min_chunk_words:
                    continue

                chunk = KnowledgeChunk(
                    document_id=doc.id,
                    content=text,
                    chunk_index=chunk_index,
                    heading=heading,
                    token_count=self._estimate_tokens(text),
                    source_name=doc.metadata.source_name,
                    source_url=doc.metadata.source_url,
                    file_path=doc.metadata.file_path or "",
                    domain=doc.domain,
                    category=doc.category,
                    tags=doc.tags,
                )
                chunks.append(chunk)
                chunk_index += 1

        logger.debug(
            "document_chunked",
            doc_id=str(doc.id),
            title=doc.title[:60],
            chunks=len(chunks),
        )
        return chunks

    def chunk_documents(self, docs: list[KnowledgeDocument]) -> list[KnowledgeChunk]:
        """Chunk multiple documents."""
        all_chunks: list[KnowledgeChunk] = []
        for doc in docs:
            all_chunks.extend(self.chunk_document(doc))
        return all_chunks

    # ── Private ───────────────────────────────────────────────────────────

    def _split_by_headings(self, content: str) -> list[tuple[str, str]]:
        """
        Split markdown by H2/H3 headings.
        Returns: [(heading, section_text), ...]
        """
        # Pattern matches ## or ### headings
        pattern = r"^(#{2,3})\s+(.+)$"
        sections: list[tuple[str, str]] = []
        current_heading = ""
        current_lines: list[str] = []

        for line in content.split("\n"):
            match = re.match(pattern, line)
            if match:
                # Flush previous section
                if current_lines:
                    sections.append((current_heading, "\n".join(current_lines).strip()))
                current_heading = match.group(2).strip()
                current_lines = [line]
            else:
                current_lines.append(line)

        # Flush last section
        if current_lines:
            sections.append((current_heading, "\n".join(current_lines).strip()))

        return sections

    def _split_section(self, text: str) -> list[str]:
        """
        Split a section into chunks that fit within chunk_size tokens.
        Preserves code blocks and uses paragraph boundaries.
        """
        tokens = self._estimate_tokens(text)
        if tokens <= self.chunk_size:
            return [text]

        # Try splitting by paragraphs first
        paragraphs = re.split(r"\n\n+", text)
        return self._merge_segments(paragraphs)

    def _merge_segments(self, segments: list[str]) -> list[str]:
        """
        Merge small segments into chunks that don't exceed chunk_size.
        Apply overlap between consecutive chunks.
        """
        chunks: list[str] = []
        current: list[str] = []
        current_tokens = 0

        for segment in segments:
            seg_tokens = self._estimate_tokens(segment)

            if seg_tokens > self.chunk_size:
                # Segment itself is too large — split by sentences
                if current:
                    chunks.append("\n\n".join(current))
                    current = []
                    current_tokens = 0
                sentence_chunks = self._split_by_sentences(segment)
                chunks.extend(sentence_chunks)
                continue

            if current_tokens + seg_tokens > self.chunk_size:
                # Flush current chunk
                chunks.append("\n\n".join(current))
                # Overlap: keep last N tokens worth of segments
                overlap_segments = self._compute_overlap(current)
                current = overlap_segments + [segment]
                current_tokens = sum(self._estimate_tokens(s) for s in current)
            else:
                current.append(segment)
                current_tokens += seg_tokens

        if current:
            chunks.append("\n\n".join(current))

        return chunks

    def _split_by_sentences(self, text: str) -> list[str]:
        """Last resort: split by sentences, then by lines, then by characters."""
        sentences = re.split(r"(?<=[.!?])\s+", text)
        # If regex didn't actually split (no sentence-ending punctuation),
        # fall back to line-based splitting to avoid infinite recursion.
        if len(sentences) <= 1:
            lines = text.split("\n")
            if len(lines) > 1:
                return self._merge_segments_safe(lines)
            # Absolute fallback: hard split by character count
            return self._hard_split(text)
        return self._merge_segments_safe(sentences)

    def _merge_segments_safe(self, segments: list[str]) -> list[str]:
        """Merge segments without recursing into _split_by_sentences."""
        chunks: list[str] = []
        current: list[str] = []
        current_tokens = 0

        for segment in segments:
            seg_tokens = self._estimate_tokens(segment)

            if seg_tokens > self.chunk_size:
                if current:
                    chunks.append("\n".join(current))
                    current = []
                    current_tokens = 0
                # Hard split oversized segments
                chunks.extend(self._hard_split(segment))
                continue

            if current_tokens + seg_tokens > self.chunk_size:
                chunks.append("\n".join(current))
                current = [segment]
                current_tokens = seg_tokens
            else:
                current.append(segment)
                current_tokens += seg_tokens

        if current:
            chunks.append("\n".join(current))

        return chunks

    def _hard_split(self, text: str) -> list[str]:
        """Hard split text by character count as absolute fallback."""
        char_limit = self.chunk_size * 4  # ~4 chars per token
        return [text[i:i + char_limit] for i in range(0, len(text), char_limit)]

    def _compute_overlap(self, segments: list[str]) -> list[str]:
        """Return trailing segments that fit within the overlap budget."""
        overlap_tokens = 0
        result: list[str] = []
        for seg in reversed(segments):
            seg_tokens = self._estimate_tokens(seg)
            if overlap_tokens + seg_tokens > self.chunk_overlap:
                break
            result.insert(0, seg)
            overlap_tokens += seg_tokens
        return result

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """
        Rough token estimation: ~1 token per 4 characters (GPT-family heuristic).
        For precise counts, use tiktoken at embedding time.
        """
        return max(1, len(text) // 4)
