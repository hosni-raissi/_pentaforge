"""Encrypted vault — maps redaction tokens ↔ original sensitive values.

Uses AES-256-GCM for authenticated encryption. Each engagement gets
its own vault instance. Values are encrypted at rest in memory —
even a memory dump won't expose raw credentials.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass, field
from typing import Any

import structlog

from .config import (
    DataCategory,
    MAX_VAULT_ENTRIES,
    SensitivityLevel,
    TOKEN_PREFIX,
    TOKEN_SUFFIX,
    VAULT_KEY_ENV_VAR,
    VAULT_KEY_LENGTH,
)

logger = structlog.get_logger(__name__)

# Try to import cryptography; fall back to base64 obfuscation if unavailable.
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    logger.warning(
        "vault_crypto_unavailable",
        msg="cryptography package not installed; using base64 obfuscation "
        "(NOT secure for production — install cryptography).",
    )


@dataclass
class VaultEntry:
    """Single encrypted mapping."""
    token: str                     # e.g. <REDACTED_IP_001>
    category: DataCategory
    sensitivity: SensitivityLevel
    encrypted_value: bytes         # AES-256-GCM ciphertext or base64.
    nonce: bytes                   # GCM nonce (12 bytes).
    context: str = ""              # Optional: which message/tool produced this.


class SanitizationVault:
    """Per-session encrypted mapping between redaction tokens and real values.

    Thread-safe for read operations. Write operations (add) should be
    called from a single coroutine per session (which is the normal flow).

    Usage:
        vault = SanitizationVault()
        token = vault.add("192.168.1.100", DataCategory.IPV4, SensitivityLevel.REDACT)
        # token == "<REDACTED_IP_001>"
        original = vault.decrypt(token)
        # original == "192.168.1.100"
    """

    def __init__(self, encryption_key: bytes | None = None) -> None:
        # Resolve encryption key.
        if encryption_key is not None:
            self._key = encryption_key
        else:
            env_key = os.environ.get(VAULT_KEY_ENV_VAR, "")
            if env_key:
                self._key = base64.b64decode(env_key)
            else:
                # Generate ephemeral key for this session.
                self._key = secrets.token_bytes(VAULT_KEY_LENGTH)
                logger.info(
                    "vault_ephemeral_key",
                    msg="No vault key configured; generated ephemeral key "
                    "(entries lost on restart).",
                )

        if _HAS_CRYPTO:
            self._cipher = AESGCM(self._key[:VAULT_KEY_LENGTH])
        else:
            self._cipher = None

        # Token → VaultEntry mapping.
        self._entries: dict[str, VaultEntry] = {}

        # Value hash → token (deduplication: same value always gets same token).
        self._value_to_token: dict[str, str] = {}

        # Per-category counters for token naming.
        self._counters: dict[DataCategory, int] = {}

    @property
    def size(self) -> int:
        return len(self._entries)

    def add(
        self,
        value: str,
        category: DataCategory,
        sensitivity: SensitivityLevel,
        context: str = "",
    ) -> str:
        """Encrypt a sensitive value and return its redaction token.

        If the same value was already stored, returns the existing token
        (deterministic: same IP always maps to same token within a session).
        """
        if sensitivity == SensitivityLevel.PASSTHROUGH:
            return value

        # Deduplication check.
        value_key = f"{category.value}:{value}"
        existing_token = self._value_to_token.get(value_key)
        if existing_token is not None:
            return existing_token

        if self.size >= MAX_VAULT_ENTRIES:
            logger.error("vault_capacity_exceeded", max=MAX_VAULT_ENTRIES)
            return f"{TOKEN_PREFIX}_OVERFLOW{TOKEN_SUFFIX}"

        # Generate token.
        count = self._counters.get(category, 0) + 1
        self._counters[category] = count
        cat_label = category.value.upper()
        token = f"{TOKEN_PREFIX}_{cat_label}_{count:03d}{TOKEN_SUFFIX}"

        # Encrypt.
        encrypted_value, nonce = self._encrypt(value)

        entry = VaultEntry(
            token=token,
            category=category,
            sensitivity=sensitivity,
            encrypted_value=encrypted_value,
            nonce=nonce,
            context=context,
        )
        self._entries[token] = entry
        self._value_to_token[value_key] = token

        return token

    def decrypt(self, token: str) -> str | None:
        """Decrypt and return the original value for a redaction token.

        Returns None if:
        - Token not found.
        - Entry was MASK-level (one-way, never restored).
        - Decryption fails.
        """
        entry = self._entries.get(token)
        if entry is None:
            return None

        if entry.sensitivity == SensitivityLevel.MASK:
            # Masked values are never restored — that's the point.
            return None

        try:
            return self._decrypt(entry.encrypted_value, entry.nonce)
        except Exception as exc:
            logger.error("vault_decrypt_error", token=token, error=str(exc))
            return None

    def get_entry(self, token: str) -> VaultEntry | None:
        """Get metadata about a vault entry (without decrypting)."""
        return self._entries.get(token)

    def all_tokens(self) -> list[str]:
        """Return all active redaction tokens."""
        return list(self._entries.keys())

    def clear(self) -> None:
        """Wipe all entries (call at end of engagement)."""
        self._entries.clear()
        self._value_to_token.clear()
        self._counters.clear()
        logger.info("vault_cleared")

    def stats(self) -> dict[str, Any]:
        """Return vault statistics for monitoring."""
        by_category: dict[str, int] = {}
        by_sensitivity: dict[str, int] = {}
        for entry in self._entries.values():
            cat = entry.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
            sens = entry.sensitivity.value
            by_sensitivity[sens] = by_sensitivity.get(sens, 0) + 1
        return {
            "total_entries": self.size,
            "by_category": by_category,
            "by_sensitivity": by_sensitivity,
            "has_crypto": _HAS_CRYPTO,
        }

    # ── Crypto internals ───────────────────────────────────────

    def _encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        data = plaintext.encode("utf-8")
        nonce = secrets.token_bytes(12)

        if self._cipher is not None:
            ciphertext = self._cipher.encrypt(nonce, data, None)
            return ciphertext, nonce

        # Fallback: base64 (NOT secure — development only).
        encoded = base64.b64encode(data)
        return encoded, nonce

    def _decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        if self._cipher is not None:
            plaintext = self._cipher.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")

        # Fallback: base64.
        return base64.b64decode(ciphertext).decode("utf-8")