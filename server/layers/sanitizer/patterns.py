"""Regex patterns for detecting sensitive data in text."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import DataCategory


@dataclass(frozen=True)
class SensitivePattern:
    """A compiled regex with its data category and priority.

    Higher priority patterns are checked first. When patterns overlap
    (e.g., an IP inside a URL), the higher-priority match wins.
    """
    category: DataCategory
    pattern: re.Pattern
    priority: int = 10  # Higher = checked first.
    description: str = ""


# ── Pattern definitions ────────────────────────────────────────────
# Order matters: more specific patterns should have higher priority
# so they match before generic ones consume their text.

SENSITIVE_PATTERNS: list[SensitivePattern] = [
    # ── Credentials (highest priority — most dangerous) ────────
    SensitivePattern(
        category=DataCategory.PRIVATE_KEY,
        pattern=re.compile(
            r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----"
            r"[\s\S]*?"
            r"-----END\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----",
            re.MULTILINE,
        ),
        priority=100,
        description="PEM private key block",
    ),
    SensitivePattern(
        category=DataCategory.CONNECTION_STRING,
        pattern=re.compile(
            r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)"
            r"://[^\s\"'<>]+",
            re.IGNORECASE,
        ),
        priority=95,
        description="Database/service connection string",
    ),
    SensitivePattern(
        category=DataCategory.JWT,
        pattern=re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        ),
        priority=90,
        description="JSON Web Token",
    ),
    SensitivePattern(
        category=DataCategory.API_KEY,
        pattern=re.compile(
            r"(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|access[_-]?token"
            r"|secret[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*[\"']?([A-Za-z0-9_\-/.+=]{16,})[\"']?",
            re.IGNORECASE,
        ),
        priority=85,
        description="API key/token assignment",
    ),
    SensitivePattern(
        category=DataCategory.CREDENTIAL,
        pattern=re.compile(
            r"(?:password|passwd|pwd|pass|secret|token|credential)"
            r"\s*[:=]\s*[\"']?(\S{4,})[\"']?",
            re.IGNORECASE,
        ),
        priority=80,
        description="Password/secret assignment",
    ),

    # ── AWS ────────────────────────────────────────────────────
    SensitivePattern(
        category=DataCategory.API_KEY,
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        priority=88,
        description="AWS Access Key ID",
    ),
    SensitivePattern(
        category=DataCategory.AWS_ARN,
        pattern=re.compile(
            r"arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"'<>]+",
        ),
        priority=75,
        description="AWS ARN",
    ),

    # ── Network identifiers ───────────────────────────────────
    SensitivePattern(
        category=DataCategory.CIDR,
        pattern=re.compile(
            r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)"
            r"(?:\.\d{1,3}){2}/\d{1,2}\b",
        ),
        priority=70,
        description="Private CIDR range (RFC 1918)",
    ),
    SensitivePattern(
        category=DataCategory.INTERNAL_URL,
        pattern=re.compile(
            r"https?://(?:"
            r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)(?:\.\d{1,3}){2}"
            r"|localhost"
            r"|[a-zA-Z0-9._-]+\.(?:local|internal|corp|lan|intranet|private)"
            r")(?::\d+)?(?:/[^\s\"'<>]*)?",
            re.IGNORECASE,
        ),
        priority=65,
        description="Internal URL (private IP or internal domain)",
    ),
    SensitivePattern(
        category=DataCategory.IPV4,
        pattern=re.compile(
            r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)"
            r"(?:\.\d{1,3}){2}\b",
        ),
        priority=60,
        description="Private IPv4 address (RFC 1918)",
    ),
    SensitivePattern(
        category=DataCategory.IPV6,
        pattern=re.compile(
            r"\b(?:fd[0-9a-f]{2}:)[0-9a-f:]{4,}\b",
            re.IGNORECASE,
        ),
        priority=55,
        description="Private IPv6 address (ULA fd00::/8)",
    ),
    SensitivePattern(
        category=DataCategory.MAC_ADDRESS,
        pattern=re.compile(
            r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b",
        ),
        priority=50,
        description="MAC address",
    ),
    SensitivePattern(
        category=DataCategory.HOSTNAME,
        pattern=re.compile(
            r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            r"\.(?:local|internal|corp|lan|intranet|private|home|localdomain)\b",
            re.IGNORECASE,
        ),
        priority=45,
        description="Internal hostname",
    ),

    # ── Emails ─────────────────────────────────────────────────
    SensitivePattern(
        category=DataCategory.EMAIL,
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        ),
        priority=40,
        description="Email address",
    ),

    # ── File paths (Linux/Windows internal) ────────────────────
    SensitivePattern(
        category=DataCategory.PATH,
        pattern=re.compile(
            r"(?:/(?:etc|home|var|opt|root|tmp|srv|usr/local)"
            r"(?:/[^\s\"'<>:*?|]+)+)",
        ),
        priority=35,
        description="Sensitive Unix path",
    ),
    SensitivePattern(
        category=DataCategory.PATH,
        pattern=re.compile(
            r"(?:[A-Z]:\\(?:Users|Windows|Program Files|ProgramData|AppData)"
            r"(?:\\[^\s\"'<>:*?|]+)+)",
            re.IGNORECASE,
        ),
        priority=35,
        description="Sensitive Windows path",
    ),
]


def get_patterns_sorted() -> list[SensitivePattern]:
    """Return patterns sorted by priority (highest first)."""
    return sorted(SENSITIVE_PATTERNS, key=lambda p: p.priority, reverse=True)