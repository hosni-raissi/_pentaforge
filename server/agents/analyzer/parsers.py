"""Normalization helpers for Analyzer tool output."""

from __future__ import annotations

import json
import re
from typing import Any

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ROUTE_RE = re.compile(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,160})")
_STATUS_RE = re.compile(r"\b(?:status|code|http(?:/1\.[01])?)\s*[:=]?\s*(\d{3})\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _safe_json_loads(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _first_lines(text: str, limit: int = 12) -> list[str]:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    return lines[:limit]


def _extract_routes(text: str) -> list[str]:
    routes = sorted({match.group(1) for match in _ROUTE_RE.finditer(text or "") if match.group(1).startswith("/")})
    return routes[:20]


def _extract_status_codes(text: str) -> list[int]:
    values: list[int] = []
    for raw in _STATUS_RE.findall(text or ""):
        try:
            code = int(raw)
        except ValueError:
            continue
        if 100 <= code <= 599 and code not in values:
            values.append(code)
    return values[:12]


def _extract_urls(text: str) -> list[str]:
    return sorted(set(_URL_RE.findall(text or "")))[:20]


def _extract_cves(text: str) -> list[str]:
    return sorted({match.upper() for match in _CVE_RE.findall(text or "")})[:20]


def _flatten_json_summary(value: Any) -> tuple[list[str], list[str], list[int], list[str]]:
    snippets: list[str] = []
    routes: list[str] = []
    status_codes: list[int] = []
    cves: list[str] = []

    def walk(node: Any, *, depth: int = 0) -> None:
        if depth > 3:
            return
        if isinstance(node, dict):
            for key, item in list(node.items())[:25]:
                if isinstance(item, (str, int, float, bool)) and len(snippets) < 20:
                    snippets.append(f"{key}={item}")
                walk(item, depth=depth + 1)
            return
        if isinstance(node, list):
            for item in node[:20]:
                walk(item, depth=depth + 1)
            return
        if isinstance(node, str):
            routes.extend(_extract_routes(node))
            status_codes.extend(_extract_status_codes(node))
            cves.extend(_extract_cves(node))

    walk(value)
    dedup_routes = list(dict.fromkeys(routes))[:20]
    dedup_codes = list(dict.fromkeys(status_codes))[:12]
    dedup_cves = list(dict.fromkeys(cves))[:20]
    return snippets[:20], dedup_routes, dedup_codes, dedup_cves


def normalize_tool_output(tool_name: str, raw_result: Any) -> dict[str, Any]:
    """Convert tool-specific output into a uniform structure for Analyzer reasoning."""
    text = raw_result if isinstance(raw_result, str) else json.dumps(raw_result, ensure_ascii=True)
    parsed_json = _safe_json_loads(text)
    tool = str(tool_name or "").strip().lower()

    parser_name = "plain_text"
    snippets = _first_lines(text)
    routes = _extract_routes(text)
    status_codes = _extract_status_codes(text)
    urls = _extract_urls(text)
    cves = _extract_cves(text)

    if parsed_json is not None:
        parser_name = "json"
        json_snippets, json_routes, json_codes, json_cves = _flatten_json_summary(parsed_json)
        snippets = json_snippets or snippets
        routes = json_routes or routes
        status_codes = json_codes or status_codes
        cves = json_cves or cves

    if tool == "http_header_analysis":
        parser_name = "http_headers"
    elif tool == "http_probe":
        parser_name = "http_probe"
    elif tool == "js_source_code_analyzer":
        parser_name = "js_analysis"
    elif tool == "nuclei" or "template-id" in text.lower():
        parser_name = "nuclei"
    elif tool == "sqlmap" or "parameter '" in text.lower():
        parser_name = "sqlmap"
    elif tool == "nmap" or "<nmaprun" in text.lower():
        parser_name = "nmap"

    evidence_markers: list[str] = []
    lowered = text.lower()
    for marker in (
        "vulnerable",
        "exploitable",
        "unauthorized",
        "forbidden",
        "access-control-allow-origin",
        "set-cookie",
        "sql injection",
        "cross-site scripting",
        "dom xss",
        "directory listing",
        "login",
        "admin",
    ):
        if marker in lowered:
            evidence_markers.append(marker)

    return {
        "tool": tool_name,
        "parser": parser_name,
        "format": "json" if parsed_json is not None else "text",
        "snippets": snippets[:12],
        "routes": routes[:20],
        "status_codes": status_codes[:12],
        "urls": urls[:20],
        "cves": cves[:20],
        "evidence_markers": evidence_markers[:16],
        "raw_excerpt": (text[:1200] + ("... [truncated]" if len(text) > 1200 else "")),
    }


def summarize_normalized_outputs(entries: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for entry in entries[:10]:
        if not isinstance(entry, dict):
            continue
        parts = [
            f"tool={entry.get('tool', '')}",
            f"parser={entry.get('parser', '')}",
        ]
        routes = entry.get("routes", [])
        if isinstance(routes, list) and routes:
            parts.append(f"routes={','.join(str(route) for route in routes[:5])}")
        codes = entry.get("status_codes", [])
        if isinstance(codes, list) and codes:
            parts.append(f"status={','.join(str(code) for code in codes[:5])}")
        markers = entry.get("evidence_markers", [])
        if isinstance(markers, list) and markers:
            parts.append(f"markers={','.join(str(marker) for marker in markers[:5])}")
        lines.append(" | ".join(parts))
    return "\n".join(lines)
