"""Sensitive data detector — scans text and returns match spans."""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from .config import DataCategory
from .patterns import SensitivePattern, get_patterns_sorted

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class Detection:
    """A single detected sensitive data occurrence."""
    category: DataCategory
    value: str             # The matched text.
    start: int             # Start index in original text.
    end: int               # End index in original text.
    pattern_desc: str      # Which pattern matched (for audit).


class SensitiveDataDetector:
    """Scans text for sensitive data patterns.

    Uses priority-ordered patterns to avoid overlapping matches.
    Higher-priority patterns (credentials, keys) are checked first;
    their spans are excluded from lower-priority pattern matching.
    """

    def __init__(
        self,
        patterns: list[SensitivePattern] | None = None,
        extra_values: list[tuple[str, DataCategory]] | None = None,
    ) -> None:
        """
        Args:
            patterns: Custom pattern list (default: all built-in patterns).
            extra_values: Exact string values to always detect.
                          E.g., [("prod-db.internal", DataCategory.HOSTNAME)]
        """
        self._patterns = patterns or get_patterns_sorted()
        self._extra_literals: list[tuple[re.Pattern, DataCategory, str]] = []

        if extra_values:
            for value, category in extra_values:
                escaped = re.escape(value)
                compiled = re.compile(rf"\b{escaped}\b", re.IGNORECASE)
                self._extra_literals.append(
                    (compiled, category, f"exact:{value}")
                )

    def detect(self, text: str) -> list[Detection]:
        """Scan text and return all detections, non-overlapping.

        Returns detections sorted by start position.
        """
        if not text:
            return []

        detections: list[Detection] = []
        # Track claimed character ranges to prevent overlaps.
        claimed: list[tuple[int, int]] = []

        # 1. Check exact literals first (highest specificity).
        for pattern, category, desc in self._extra_literals:
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()
                if self._overlaps(start, end, claimed):
                    continue
                detections.append(Detection(
                    category=category,
                    value=match.group(0),
                    start=start,
                    end=end,
                    pattern_desc=desc,
                ))
                claimed.append((start, end))

        # 2. Check regex patterns in priority order.
        for sp in self._patterns:
            for match in sp.pattern.finditer(text):
                start, end = match.start(), match.end()
                if self._overlaps(start, end, claimed):
                    continue

                # Use the first capture group if present, otherwise full match.
                value = match.group(1) if match.lastindex else match.group(0)

                detections.append(Detection(
                    category=sp.category,
                    value=value,
                    start=start,
                    end=end,
                    pattern_desc=sp.description,
                ))
                claimed.append((start, end))

        # Sort by position for consistent processing.
        detections.sort(key=lambda d: d.start)
        return detections

    @staticmethod
    def _overlaps(start: int, end: int, claimed: list[tuple[int, int]]) -> bool:
        """Check if a span overlaps with any already-claimed range."""
        for cs, ce in claimed:
            if start < ce and end > cs:
                return True
        return False