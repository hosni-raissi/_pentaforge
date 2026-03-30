import re
from enum import Enum
from typing import List, Tuple, Pattern

class SensitiveDataType(Enum):
    URL = "URL"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    IP_ADDRESS = "IP"
    PHONE = "PHONE"
    CREDIT_CARD = "CC"
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    SSN = "SSN"
    CUSTOM = "CUSTOM"

class PatternRegistry:
    """Registry of sensitive data patterns"""
    
    PATTERNS: List[Tuple[SensitiveDataType, Pattern]] = [
        # URLs (http, https, ftp)
        (
            SensitiveDataType.URL,
            re.compile(
                r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
                re.IGNORECASE
            )
        ),
        # Domains
        (
            SensitiveDataType.DOMAIN,
            re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
                re.IGNORECASE
            )
        ),
        # Email addresses
        (
            SensitiveDataType.EMAIL,
            re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            )
        ),
        # IP Addresses (IPv4)
        (
            SensitiveDataType.IP_ADDRESS,
            re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            )
        ),
        # Phone numbers
        (
            SensitiveDataType.PHONE,
            re.compile(
                r'\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b'
            )
        ),
        # Credit card numbers
        (
            SensitiveDataType.CREDIT_CARD,
            re.compile(
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
            )
        ),
        # API Keys (generic pattern)
        (
            SensitiveDataType.API_KEY,
            re.compile(
                r'\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
                re.IGNORECASE
            )
        ),
    ]
    
    @classmethod
    def get_all_patterns(cls) -> List[Tuple[SensitiveDataType, Pattern]]:
        return cls.PATTERNS
    
    @classmethod
    def add_custom_pattern(cls, pattern: str, data_type: SensitiveDataType = SensitiveDataType.CUSTOM):
        cls.PATTERNS.append((data_type, re.compile(pattern)))