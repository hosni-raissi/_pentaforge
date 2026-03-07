"""
Source extractors — one adapter per source type.

Each extractor implements BaseExtractor and yields KnowledgeDocuments.
"""

from .base import BaseExtractor
from .github_extractor import GitHubRepoExtractor
from .website_extractor import WebsiteExtractor
from .nvd_extractor import NVDCVEExtractor
from .gitbook_extractor import GitBookExtractor

__all__ = [
    "BaseExtractor",
    "GitHubRepoExtractor",
    "WebsiteExtractor",
    "NVDCVEExtractor",
    "GitBookExtractor",
]
