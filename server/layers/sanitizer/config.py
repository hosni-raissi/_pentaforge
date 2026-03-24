"""Sanitizer configuration — what to detect, crypto settings."""

from __future__ import annotations

from enum import Enum


class SensitivityLevel(Enum):
    """How to handle detected sensitive data."""
    REDACT = "redact"       # Replace with token, store encrypted for restore.
    MASK = "mask"           # Replace with token, do NOT restore (one-way).
    PASSTHROUGH = "pass"    # Allow through unchanged (local LLM only).


class DataCategory(Enum):
    """Categories of sensitive data detected by the proxy."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    INTERNAL_URL = "internal_url"
    EMAIL = "email"
    CREDENTIAL = "credential"
    API_KEY = "api_key"
    JWT = "jwt"
    PRIVATE_KEY = "private_key"
    PATH = "path"
    MAC_ADDRESS = "mac"
    AWS_ARN = "aws_arn"
    CONNECTION_STRING = "connstr"


# Default handling per category when using cloud LLM.
CLOUD_POLICY: dict[DataCategory, SensitivityLevel] = {
    DataCategory.IPV4: SensitivityLevel.REDACT,
    DataCategory.IPV6: SensitivityLevel.REDACT,
    DataCategory.CIDR: SensitivityLevel.REDACT,
    DataCategory.HOSTNAME: SensitivityLevel.REDACT,
    DataCategory.INTERNAL_URL: SensitivityLevel.REDACT,
    DataCategory.EMAIL: SensitivityLevel.REDACT,
    DataCategory.CREDENTIAL: SensitivityLevel.MASK,      # Never restore passwords.
    DataCategory.API_KEY: SensitivityLevel.MASK,
    DataCategory.JWT: SensitivityLevel.MASK,
    DataCategory.PRIVATE_KEY: SensitivityLevel.MASK,
    DataCategory.PATH: SensitivityLevel.REDACT,
    DataCategory.MAC_ADDRESS: SensitivityLevel.REDACT,
    DataCategory.AWS_ARN: SensitivityLevel.REDACT,
    DataCategory.CONNECTION_STRING: SensitivityLevel.MASK,
}

# Local LLM policy — everything passes through unmodified.
LOCAL_POLICY: dict[DataCategory, SensitivityLevel] = {
    cat: SensitivityLevel.PASSTHROUGH for cat in DataCategory
}

# Encryption settings for the vault.
VAULT_KEY_ENV_VAR: str = "PENTAFORGE_VAULT_KEY"
VAULT_KEY_LENGTH: int = 32  # AES-256

# Token format used in sanitized text.
# Must be unique enough that the LLM won't accidentally generate it,
# and structured enough for reliable regex restoration.
TOKEN_PREFIX: str = "<REDACTED"
TOKEN_SUFFIX: str = ">"
# Example: <REDACTED_IP_001>

# Maximum tokens tracked per session before forced rotation.
MAX_VAULT_ENTRIES: int = 10_000