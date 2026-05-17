from __future__ import annotations

from urllib.parse import urlparse


def extract_host(target: str) -> str:
    """Return the hostname portion of a bare host or URL-like target."""
    value = str(target or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"http://{value}")
    return (parsed.hostname or value).strip().lower()
