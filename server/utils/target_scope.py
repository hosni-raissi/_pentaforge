"""Helpers for normalizing and enforcing assistant target scope."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def _split_target(value: str) -> tuple[str, str, int | None, str]:
    raw = str(value or "").strip()
    if not raw:
        return "", "", None, ""

    has_scheme = "://" in raw
    if has_scheme:
        parsed = urlsplit(raw)
        scheme = (parsed.scheme or "").strip().lower()
        host = (parsed.hostname or "").strip().lower()
        try:
            port = parsed.port
        except ValueError:
            port = None
        path = (parsed.path or "").strip()
    else:
        # No scheme, handle host[:port][/path]
        scheme = ""
        host_part = raw.split("/", 1)[0]
        path = "/" + raw.split("/", 1)[1] if "/" in raw else ""
        
        if ":" in host_part:
            host_str, port_str = host_part.rsplit(":", 1)
            host = host_str.lower()
            try:
                port = int(port_str)
            except ValueError:
                port = None
                host = host_part.lower()
        else:
            host = host_part.lower()
            port = None

    if port is None:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443

    if path == "/":
        path = ""
    elif path.endswith("/"):
        path = path.rstrip("/")

    return scheme, host, port, path


def normalize_target_scope(target: str, target_type: str = "") -> str:
    """Return a stable assistant scope key for a target."""
    scheme, host, port, path = _split_target(target)
    scope_type = str(target_type or "").strip().lower()
    if not host:
        return scope_type
    authority = host if port is None else f"{host}:{port}"
    location = f"{scheme}://{authority}{path}" if scheme else f"{authority}{path}"
    return f"{scope_type}|{location}" if scope_type else location


def extract_target_host_port(target: str) -> tuple[str, int | None]:
    _, host, port, _ = _split_target(target)
    return host, port


def is_loopback_host(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    return normalized in {"localhost", "127.0.0.1", "::1"}


def _is_host_in_target_scope(value_host: str, target_host: str, target_path: str) -> bool:
    if value_host == target_host or value_host.endswith(f".{target_host}"):
        return True
        
    if target_host.startswith("www."):
        base_domain = target_host[4:]
        if value_host == base_domain or value_host.endswith(f".{base_domain}"):
            return True
        
    same_loopback_family = is_loopback_host(value_host) and is_loopback_host(target_host)
    if same_loopback_family:
        return True
        
    # Check if target is a CIDR network (e.g. 192.168.1.0/24 split into host=192.168.1.0 and path=/24)
    if target_path and target_path.startswith("/") and target_path[1:].isdigit():
        try:
            target_cidr = ipaddress.ip_network(f"{target_host}{target_path}", strict=False)
            val_ip = ipaddress.ip_address(value_host)
            if val_ip in target_cidr:
                return True
        except ValueError:
            pass
            
    return False


def describe_url_scope_issue(url: str, active_target: str) -> str | None:
    """Return a human-readable scope mismatch for a URL, or None if allowed."""
    _, target_host, target_port, target_path = _split_target(active_target)
    if not target_host:
        return None

    _, url_host, url_port, _ = _split_target(url)
    if not url_host or url.isdigit() or ("__IP_" in url) or ("__HOST_" in url) or " " in url:
        return None

    # Ignore tokens that don't look like hostnames or IPs.
    # Must have a dot (domain/IP), a scheme, be 'localhost', or be a valid IPv6 (has multiple colons).
    is_localhost = url_host == "localhost"
    has_dot = "." in url_host
    has_scheme = "://" in url
    is_ipv6 = url_host.count(":") >= 2
    
    if not (has_dot or has_scheme or is_localhost or is_ipv6):
        return None

    # Ignore common local file extensions to avoid false-positive scope violations
    ignored_extensions = (
        ".txt", ".json", ".log", ".xml", ".csv", ".bak", ".html", ".js", ".dic",
        ".zip", ".tar.gz", ".gz", ".pdf", ".png", ".jpg", ".jpeg", ".sqlite", ".db",
        ".yaml", ".yml", ".sh", ".php", ".asp", ".aspx", ".jsp", ".exe", ".dll",
        ".bin", ".py", ".md", ".conf", ".ini", ".apk", ".ipa", ".aab",
    )
    if url.lower().endswith(ignored_extensions):
        return None

    if not _is_host_in_target_scope(url_host, target_host, target_path):
        # Determine actual target string to print
        target_display = f"{target_host}{target_path}" if target_path and target_path.startswith("/") and target_path[1:].isdigit() else target_host
        return f"{url} is outside target host {target_display}"
    return None


def describe_network_target_scope_issue(value: str, active_target: str) -> str | None:
    """Validate a URL or host[:port] token against the active target."""
    text = str(value or "").strip().strip("'\"")
    if not text or " " in text:
        return None
    if "://" in text:
        return describe_url_scope_issue(text, active_target)

    _, target_host, target_port, target_path = _split_target(active_target)
    if not target_host:
        return None

    _, value_host, value_port, _ = _split_target(text)
    if not value_host:
        return None

    try:
        ipaddress.ip_address(value_host)
        host_like = True
    except ValueError:
        host_like = value_host == "localhost" or "." in value_host or value_host.count(":") >= 2
    if not host_like:
        return None

    if not _is_host_in_target_scope(value_host, target_host, target_path):
        target_display = f"{target_host}{target_path}" if target_path and target_path.startswith("/") and target_path[1:].isdigit() else target_host
        return f"{text} is outside target host {target_display}"
    return None
