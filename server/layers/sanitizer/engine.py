"""Sanitization engine — sanitize outbound text, restore inbound text.

This is the core logic that the LLM proxy calls.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from .config import (
    CLOUD_POLICY,
    LOCAL_POLICY,
    DataCategory,
    SensitivityLevel,
    TOKEN_PREFIX,
    TOKEN_SUFFIX,
)
from .detector import Detection, SensitiveDataDetector
from .vault import SanitizationVault

logger = structlog.get_logger(__name__)

# Regex to find redaction tokens in LLM responses for restoration.
_TOKEN_PATTERN = re.compile(
    re.escape(TOKEN_PREFIX) + r"_[A-Z0-9_]+_\d{3}" + re.escape(TOKEN_SUFFIX)
)


class SanitizationEngine:
    """Bidirectional text sanitization for LLM proxy.

    Outbound (agent → LLM):
        Detects sensitive data, encrypts it in the vault,
        replaces with deterministic tokens.

    Inbound (LLM → agent):
        Finds redaction tokens in LLM response, decrypts
        from vault, restores original values.

    Usage:
        engine = SanitizationEngine(mode="cloud")
        sanitized = engine.sanitize("Connect to 192.168.1.50:5432")
        # sanitized == "Connect to <REDACTED_IP_001>:5432"

        restored = engine.restore("Scan <REDACTED_IP_001> for open ports")
        # restored == "Scan 192.168.1.50 for open ports"
    """

    def __init__(
        self,
        mode: str = "cloud",
        vault: SanitizationVault | None = None,
        detector: SensitiveDataDetector | None = None,
        extra_sensitive_values: list[tuple[str, DataCategory]] | None = None,
    ) -> None:
        """
        Args:
            mode: "cloud" (sanitize everything) or "local" (passthrough).
            vault: Shared vault instance (one per engagement).
            detector: Custom detector (default: built-in patterns).
            extra_sensitive_values: Additional exact values to always redact.
                E.g., client hostnames not caught by generic patterns.
        """
        self._mode = mode
        self._policy = CLOUD_POLICY if mode == "cloud" else LOCAL_POLICY
        self._vault = vault or SanitizationVault()
        self._detector = detector or SensitiveDataDetector(
            extra_values=extra_sensitive_values,
        )

    @property
    def vault(self) -> SanitizationVault:
        return self._vault

    @property
    def mode(self) -> str:
        return self._mode

    def sanitize(self, text: str, context: str = "") -> str:
        """Sanitize outbound text (agent → LLM).

        Replaces sensitive data with encrypted redaction tokens.
        Returns sanitized text safe for cloud LLM.
        """
        if not text:
            return text

        if self._mode == "local":
            return text

        detections = self._detector.detect(text)
        if not detections:
            return text

        # Process detections from end to start (so indices stay valid).
        result = text
        for detection in reversed(detections):
            sensitivity = self._policy.get(
                detection.category, SensitivityLevel.REDACT
            )
            if sensitivity == SensitivityLevel.PASSTHROUGH:
                continue

            token = self._vault.add(
                value=detection.value,
                category=detection.category,
                sensitivity=sensitivity,
                context=context,
            )

            # Replace the detected span with the token.
            result = result[: detection.start] + token + result[detection.end :]

        if detections:
            categories = set(d.category.value for d in detections)
            logger.info(
                "sanitizer_outbound",
                detections=len(detections),
                categories=sorted(categories),
                context=context[:50],
            )

        return result

    def restore(self, text: str) -> str:
        """Restore inbound text (LLM → agent).

        Finds redaction tokens in the LLM response and replaces
        them with decrypted original values.

        MASK-level tokens are left as-is (credentials/keys never restored).
        """
        if not text:
            return text

        if self._mode == "local":
            return text

        def _replace_token(match: re.Match) -> str:
            token = match.group(0)
            original = self._vault.decrypt(token)
            if original is not None:
                return original
            # Token not found or MASK-level: leave as-is.
            return token

        restored = _TOKEN_PATTERN.sub(_replace_token, text)

        return restored

    def sanitize_messages(
        self, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Sanitize all message contents in a conversation history.

        Processes user messages, tool results, and assistant content.
        System messages are left unchanged (they contain prompts, not data).
        """
        sanitized: list[dict[str, Any]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                sanitized.append(msg)
                continue

            role = msg.get("role", "")
            new_msg = dict(msg)

            if role == "system":
                # System prompts don't contain client data.
                sanitized.append(new_msg)
                continue

            # Sanitize content.
            content = msg.get("content")
            if isinstance(content, str) and content:
                ctx = f"{role}:{msg.get('name', '')}" if role == "tool" else role
                new_msg["content"] = self.sanitize(content, context=ctx)

            sanitized.append(new_msg)
        return sanitized

    def restore_content(self, content: str | None) -> str:
        """Restore a single content string (convenience wrapper)."""
        if not content:
            return content or ""
        return self.restore(content)

    def get_stats(self) -> dict[str, Any]:
        """Return sanitization statistics."""
        return {
            "mode": self._mode,
            **self._vault.stats(),
        }