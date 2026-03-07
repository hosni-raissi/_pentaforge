"""
BaseExtractor — Abstract interface all source extractors must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from server.db.knowledge.config.sources import SourceConfig
from server.db.knowledge.models.document import KnowledgeDocument


class BaseExtractor(ABC):
    """
    Abstract base for all knowledge source extractors.

    Children must implement `extract()` which yields KnowledgeDocuments.
    """

    def __init__(self, config: SourceConfig) -> None:
        self.config = config

    @abstractmethod
    async def extract(self) -> AsyncIterator[KnowledgeDocument]:
        """Yield extracted documents from the source."""
        ...  # pragma: no cover

    @abstractmethod
    async def health_check(self) -> bool:
        """Quick connectivity / availability check."""
        ...  # pragma: no cover

    @property
    def source_name(self) -> str:
        return self.config.name
