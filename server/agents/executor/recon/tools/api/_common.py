from __future__ import annotations

import os
from urllib.parse import urlparse
from urllib.parse import urlunparse


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def extract_host(target: str) -> str:
    """Return the hostname portion of a bare host or URL-like target."""
    value = str(target or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"http://{value}")
    return (parsed.hostname or value).strip().lower()


def is_loopback_target_host(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    return normalized in _LOOPBACK_HOSTS


def is_valid_http_target(target: str) -> bool:
    value = str(target or "").strip()
    if not value:
        return False
    parsed = urlparse(value if "://" in value else f"http://{value}")
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return False
    return bool(parsed.hostname)


def normalize_http_target(target: str, *, default_scheme: str = "https") -> str:
    value = str(target or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    return value.rstrip("/")


def is_containerized_runtime() -> bool:
    flag = str(os.getenv("PENTAFORGE_CONTAINER_RUNTIME", "")).strip().lower()
    if flag in {"1", "true", "yes", "on"}:
        return True
    return os.path.exists("/.dockerenv")


def prepare_runtime_http_target(
    target: str,
    *,
    container_loopback_host: str = "host.docker.internal",
) -> str:
    normalized = normalize_http_target(target)
    parsed = urlparse(normalized)
    if not parsed.hostname or not is_containerized_runtime():
        return normalized
    if not is_loopback_target_host(parsed.hostname):
        return normalized

    port = f":{parsed.port}" if parsed.port is not None else ""
    netloc = f"{container_loopback_host}{port}"
    return urlunparse(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def remap_origin_url(url: str, *, from_base: str, to_base: str) -> str:
    source = urlparse(str(from_base or "").strip())
    target = urlparse(str(to_base or "").strip())
    candidate = urlparse(str(url or "").strip())
    if not source.netloc or not target.netloc or not candidate.netloc:
        return str(url or "").strip()
    if (candidate.scheme, candidate.netloc) != (source.scheme, source.netloc):
        return str(url or "").strip()
    return urlunparse(
        (
            target.scheme,
            target.netloc,
            candidate.path,
            candidate.params,
            candidate.query,
            candidate.fragment,
        )
    )
