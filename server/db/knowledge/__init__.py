# ─────────────────────────────────────────────────────────────────────────────
# PentaForge Knowledge Base — RAG Pipeline for Cybersecurity Intelligence
# ─────────────────────────────────────────────────────────────────────────────
#
# Extracts, chunks, embeds, and stores cybersecurity knowledge from:
#   - GitHub repositories (HackTricks, PayloadsAllTheThings, OWASP WSTG, etc.)
#   - Websites (GTFOBins, LOLBAS, exploit.education, etc.)
#   - APIs (NVD CVE 2.0)
#   - GitBook-hosted content
#
# Architecture:
#   sources/       → Extractors / scrapers per source type
#   processing/    → Chunking, cleaning, metadata enrichment
#   models/        → Domain models (KnowledgeDocument, Chunk, etc.)
#   storage/       → Persistence adapters (Qdrant, Redis, SQLite payload/cache)
#   config/        → Settings, source registry
#
"""PentaForge RAG Knowledge Base."""

__version__ = "0.1.0"
