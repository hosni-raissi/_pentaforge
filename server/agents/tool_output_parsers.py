"""Shared parsers for common CLI tool outputs."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import urlparse

_ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_FFUF_TEXT_RESULT_RE = re.compile(
    r"(?:^|(?<=\]\s))(?P<path>[^\[\r\n][^\[\r\n]*?)\s*\[Status:\s*(?P<status>\d{3})\s*,\s*Size:\s*(?P<size>\d+)\s*,\s*Words:\s*(?P<words>\d+)\s*,\s*Lines:\s*(?P<lines>\d+)",
    flags=re.IGNORECASE,
)
_STATUS_RE = re.compile(r"\b(?:status|code|http(?:/1\.[01])?)\s*[:=]?\s*(\d{3})\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def strip_ansi_sequences(text: str) -> str:
    return _ANSI_ESCAPE_RE.sub("", str(text or ""))


def _normalize_ffuf_finding(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    path = str(item.get("path", "") or "").strip()
    if not path or path.startswith("#") or path.startswith("|"):
        return None
    try:
        status = int(item.get("status"))
    except (TypeError, ValueError):
        return None
    finding: dict[str, Any] = {
        "path": path,
        "status": status,
    }
    for field in ("size", "words", "lines"):
        value = item.get(field)
        try:
            if value is not None:
                finding[field] = int(value)
        except (TypeError, ValueError):
            continue
    for field in ("url", "redirectlocation"):
        value = str(item.get(field, "") or "").strip()
        if value:
            finding[field] = value
    return finding


def _dedupe_ffuf_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for item in items:
        normalized = _normalize_ffuf_finding(item)
        if normalized is None:
            continue
        key = (str(normalized.get("path", "")), int(normalized.get("status", 0)))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(normalized)
    return deduped[:12]


def _iter_json_values(text: str) -> list[Any]:
    values: list[Any] = []
    decoder = json.JSONDecoder()
    idx = 0
    limit = len(text)
    while idx < limit:
        while idx < limit and text[idx].isspace():
            idx += 1
        if idx >= limit:
            break
        try:
            value, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            next_object = text.find("{", idx + 1)
            next_array = text.find("[", idx + 1)
            candidates = [pos for pos in (next_object, next_array) if pos != -1]
            if not candidates:
                break
            idx = min(candidates)
            continue
        values.append(value)
        idx = end
    return values


def _decode_ffuf_input_value(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="ignore").strip()
    except Exception:
        decoded = ""
    return decoded or text


def _path_from_ffuf_json_entry(entry: dict[str, Any]) -> str:
    inputs = entry.get("input")
    if isinstance(inputs, dict):
        fuzz_value = _decode_ffuf_input_value(inputs.get("FUZZ"))
        if fuzz_value:
            return fuzz_value
    url_value = str(entry.get("url", "") or "").strip()
    if url_value:
        parsed = urlparse(url_value)
        path = (parsed.path or "").lstrip("/")
        if path:
            return path
    return ""


def _parse_ffuf_json_stream(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for value in _iter_json_values(text):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    path = _path_from_ffuf_json_entry(item)
                    findings.append(
                        {
                            "path": path,
                            "status": item.get("status"),
                            "size": item.get("length"),
                            "words": item.get("words"),
                            "lines": item.get("lines"),
                            "url": item.get("url"),
                            "redirectlocation": item.get("redirectlocation"),
                        }
                    )
            continue
        if not isinstance(value, dict):
            continue
        path = _path_from_ffuf_json_entry(value)
        findings.append(
            {
                "path": path,
                "status": value.get("status"),
                "size": value.get("length"),
                "words": value.get("words"),
                "lines": value.get("lines"),
                "url": value.get("url"),
                "redirectlocation": value.get("redirectlocation"),
            }
        )
    return _dedupe_ffuf_findings(findings)


def _parse_ffuf_text_results(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in _FFUF_TEXT_RESULT_RE.finditer(text):
        path = " ".join(str(match.group("path") or "").split()).strip()
        findings.append(
            {
                "path": path,
                "status": match.group("status"),
                "size": match.group("size"),
                "words": match.group("words"),
                "lines": match.group("lines"),
            }
        )
    return _dedupe_ffuf_findings(findings)


def parse_ffuf_findings(payload: Any) -> list[dict[str, Any]]:
    """Extract deterministic ffuf findings from raw stdout or a run_custom payload."""
    if isinstance(payload, dict):
        existing = payload.get("parsed_findings")
        if isinstance(existing, list) and existing:
            return _dedupe_ffuf_findings(existing)
        stdout = str(payload.get("stdout", "") or "")
    else:
        stdout = str(payload or "")

    cleaned = strip_ansi_sequences(stdout)
    if not cleaned.strip():
        return []

    findings = _parse_ffuf_json_stream(cleaned)
    if findings:
        return findings
    return _parse_ffuf_text_results(cleaned)


def summarize_ffuf_findings(findings: list[dict[str, Any]], *, limit: int = 3) -> str:
    parts: list[str] = []
    extra = 0
    for item in findings:
        if len(parts) >= limit:
            extra += 1
            continue
        normalized = _normalize_ffuf_finding(item)
        if normalized is None:
            continue
        parts.append(f"{normalized['path']} (HTTP {normalized['status']})")
    if extra > 0:
        parts.append(f"+{extra} more")
    return ", ".join(parts)


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


def _first_lines(text: str, limit: int = 8) -> list[str]:
    return [line.strip() for line in str(text or "").splitlines() if line.strip()][:limit]


def _short_text(value: Any, limit: int = 160) -> str:
    text = " ".join(str(value or "").split()).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _normalize_observations(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    observations: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = _short_text(item)
        lowered = text.lower()
        if not text or lowered in seen:
            continue
        seen.add(lowered)
        observations.append(text)
        if len(observations) >= 8:
            break
    return observations


def summarize_tool_output(payload: Any) -> dict[str, Any]:
    """Return generic structured observations for any tool output.

    The returned shape is intentionally generic so agents can consume one
    consistent evidence lane across all security CLIs:
      - output_parser: plugin/fallback name
      - observations: concise human-readable facts
      - status_codes / urls: low-level extracted signals
      - parsed_findings: optional structured matches for richer parsers
    """
    if isinstance(payload, dict):
        existing_observations = _normalize_observations(payload.get("observations"))
        command = str(payload.get("command", "") or "").strip().lower()
        stdout = str(payload.get("stdout", "") or "")
        stderr = str(payload.get("stderr", "") or "")
        if command == "ffuf":
            findings = parse_ffuf_findings(payload)
            ffuf_observations = [
                _short_text(
                    f"Matched {item['path']} with HTTP {item['status']}"
                    + (
                        f" (size={item.get('size')}, words={item.get('words')})"
                        if item.get("size") is not None and item.get("words") is not None
                        else ""
                    ),
                    limit=200,
                )
                for item in findings[:6]
                if str(item.get("path", "")).strip()
            ]
            return {
                "output_parser": "ffuf",
                "observations": ffuf_observations or existing_observations,
                "status_codes": list(dict.fromkeys([int(item["status"]) for item in findings if item.get("status") is not None]))[:12],
                "urls": _extract_urls(stdout),
                "parsed_findings": findings,
            }

        if existing_observations:
            return {
                "output_parser": str(payload.get("output_parser", "") or "structured"),
                "observations": existing_observations,
                "status_codes": _extract_status_codes(f"{stdout}\n{stderr}"),
                "urls": _extract_urls(stdout),
                "parsed_findings": [],
            }

        parsed_observations: list[str] = []
        for key in ("summary", "reason", "error"):
            value = str(payload.get(key, "") or "").strip()
            if value:
                parsed_observations.append(_short_text(value, limit=200))
        findings_value = payload.get("findings")
        if isinstance(findings_value, list):
            for item in findings_value[:4]:
                if isinstance(item, dict):
                    detail = str(item.get("details") or item.get("title") or "").strip()
                else:
                    detail = str(item or "").strip()
                if detail:
                    parsed_observations.append(_short_text(detail, limit=200))
        parser_name = "structured_json"
        if not parsed_observations:
            body = stdout or stderr
            parsed_observations = [_short_text(line, limit=200) for line in _first_lines(strip_ansi_sequences(body), limit=4)]
            parser_name = "generic_text"
        return {
            "output_parser": parser_name,
            "observations": _normalize_observations(parsed_observations),
            "status_codes": _extract_status_codes(f"{stdout}\n{stderr}"),
            "urls": _extract_urls(stdout),
            "parsed_findings": [],
        }

    text = strip_ansi_sequences(str(payload or ""))
    return {
        "output_parser": "generic_text",
        "observations": _normalize_observations([_short_text(line, limit=200) for line in _first_lines(text, limit=4)]),
        "status_codes": _extract_status_codes(text),
        "urls": _extract_urls(text),
        "parsed_findings": [],
    }
