"""Shared helpers for recon run_custom security tool catalogs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

_LEGACY_KEYS = frozenset({"t", "c", "u", "d", "tgt"})
_NORMALIZED_KEYS = frozenset({"phase", "type", "when", "targets", "cmd", "pipe_into", "category"})

_PHASE_BY_CATEGORY: dict[str, int] = {
    "passive": 1,
    "discovery": 1,
    "osint": 1,
    "github": 1,
    "gitlab": 1,
    "bitbucket": 1,
    "gitea": 1,
    "forgejo": 1,
    "dns": 2,
    "enum": 2,
    "auth": 2,
    "aws": 2,
    "azure": 2,
    "gcp": 2,
    "k8s": 2,
    "docker": 2,
    "analysis": 3,
    "http": 3,
    "protocol": 3,
    "scan": 3,
    "topology": 3,
    "mobile": 3,
    "firmware": 3,
    "fuzz": 4,
    "crawler": 4,
    "secret_scan": 5,
    "supply_chain": 5,
    "misconfig": 5,
    "automation": 6,
}


def _as_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        cleaned = value.strip()
        return [cleaned] if cleaned else []
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        items: list[str] = []
        for item in value:
            cleaned = str(item or "").strip()
            if cleaned:
                items.append(cleaned)
        return items
    cleaned = str(value).strip()
    return [cleaned] if cleaned else []


def _default_phase(entry: Mapping[str, object], *, fallback: int) -> int:
    explicit = entry.get("phase")
    if explicit is not None:
        try:
            return int(explicit)
        except (TypeError, ValueError):
            return fallback
    category = str(entry.get("category") or entry.get("t") or "").strip().lower()
    return _PHASE_BY_CATEGORY.get(category, fallback)


def normalize_security_catalog(
    raw_catalog: Mapping[str, Mapping[str, object]],
    *,
    default_phase: int = 1,
) -> dict[str, dict[str, object]]:
    """Normalize legacy recon security catalogs to the web-style metadata shape."""
    normalized: dict[str, dict[str, object]] = {}
    for tool_name, entry in raw_catalog.items():
        phase = _default_phase(entry, fallback=default_phase)
        category = str(entry.get("category") or entry.get("t") or "").strip()
        tool_type = str(entry.get("type") or entry.get("c") or category or "").strip()
        meta: dict[str, object] = {
            "phase": phase,
            "type": tool_type,
            "when": _as_str_list(entry.get("when", entry.get("d"))),
            "targets": _as_str_list(entry.get("targets", entry.get("tgt"))),
            "cmd": str(entry.get("cmd") or entry.get("u") or "").strip(),
            "pipe_into": _as_str_list(entry.get("pipe_into")),
        }
        if category:
            meta["category"] = category
        for key, value in entry.items():
            if key in _LEGACY_KEYS or key in _NORMALIZED_KEYS:
                continue
            meta[key] = value
        normalized[tool_name] = meta
    return normalized
