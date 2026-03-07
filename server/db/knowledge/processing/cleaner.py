"""
ContentCleaner — Pre-processing pipeline to clean extracted content before chunking.

Handles:
  - Removing sponsor/banner sections from HackTricks, PayloadsAllTheThings
  - Stripping navigation boilerplate
  - Normalizing whitespace and line endings
  - Removing HTML artifacts that survived scraping
  - Cleaning up broken reference links
"""

from __future__ import annotations

import re

import structlog

logger = structlog.get_logger(__name__)


class ContentCleaner:
    """Pipeline of cleaning passes applied to raw document content."""

    @classmethod
    def clean(cls, content: str, source_name: str = "") -> str:
        """Apply all cleaning passes."""
        content = cls.normalize_whitespace(content)
        content = cls.remove_html_artifacts(content)
        content = cls.remove_banner_sections(content, source_name)
        content = cls.remove_empty_links(content)
        content = cls.normalize_code_blocks(content)
        content = cls.collapse_blank_lines(content)
        return content.strip()

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        """Normalize tabs, trailing spaces, CRLF."""
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        # Remove trailing whitespace per line
        text = re.sub(r"[ \t]+$", "", text, flags=re.MULTILINE)
        return text

    @staticmethod
    def remove_html_artifacts(text: str) -> str:
        """Remove leftover HTML tags that survived markdown conversion."""
        # Common leftovers
        text = re.sub(r"</?div[^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"</?span[^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"</?table[^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"</?tr[^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"</?td[^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"</?th[^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"</?tbody[^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"</?thead[^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
        return text

    @staticmethod
    def remove_banner_sections(text: str, source_name: str) -> str:
        """Remove known sponsor/banner boilerplate per source."""
        # HackTricks banners
        if "hacktricks" in source_name.lower():
            # Remove {% hint %} blocks
            text = re.sub(r"\{%\s*hint.*?%\}.*?\{%\s*endhint\s*%\}", "", text, flags=re.DOTALL)
            # Remove {{#ref}} blocks
            text = re.sub(r"\{\{#ref\}\}.*?\{\{#endref\}\}", "", text, flags=re.DOTALL)
            # Remove include statements 
            text = re.sub(r"\{\{#include.*?\}\}", "", text, flags=re.DOTALL)
            # Remove sponsor sections
            text = re.sub(
                r"(?:^|\n).*?(?:STM Cyber|RootedCON|Intigriti|Trickest|HACKENPROOF|WebSec|SerpApi|8kSec).*?(?:\n|$)",
                "\n",
                text,
                flags=re.IGNORECASE,
            )

        # PayloadsAllTheThings sponsors
        if "payload" in source_name.lower():
            text = re.sub(r"## 🍻 Sponsors.*?(?=\n## |\Z)", "", text, flags=re.DOTALL)

        # Generic: remove "Powered by" footers
        text = re.sub(r"Powered by .*?$", "", text, flags=re.MULTILINE | re.IGNORECASE)

        return text

    @staticmethod
    def remove_empty_links(text: str) -> str:
        """Remove broken or empty markdown links."""
        # [](empty) or [text]()
        text = re.sub(r"\[([^\]]*)\]\(\s*\)", r"\1", text)
        text = re.sub(r"\[\s*\]\([^\)]+\)", "", text)
        return text

    @staticmethod
    def normalize_code_blocks(text: str) -> str:
        """Ensure code blocks are properly fenced."""
        # Fix unclosed code blocks
        open_count = text.count("```")
        if open_count % 2 != 0:
            text += "\n```"
        return text

    @staticmethod
    def collapse_blank_lines(text: str) -> str:
        """Collapse 3+ consecutive blank lines to 2."""
        return re.sub(r"\n{3,}", "\n\n", text)
