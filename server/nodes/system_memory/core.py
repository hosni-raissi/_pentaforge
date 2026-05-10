"""Runtime system memory helpers."""

from __future__ import annotations

import json
import os
import re
import ast
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable

import structlog
from server.config.agent import get_public_agent_config
from server.core.llm import ChatMessage, get_llm
from server.db.projects.project_rag import index_system_memory_markdown
from server.db.projects.store import ProjectsStore
from server.utils.known_vuln_intelligence import (
    build_known_vuln_query,
    canonicalize_product_name,
    confidence_label,
    get_product_profile,
    normalize_version_text,
    project_legacy_tech_stack,
    recommend_nuclei_hints,
    recommend_run_custom_tools,
)

from .config import SystemMemoryConfig, get_system_memory_config
from .prompts import (
    COMPRESS_MEMORY_SYSTEM_PROMPT,
    ORGANIZE_BLOCK_SYSTEM_PROMPT,
    PREPARE_BLOCK_SYSTEM_PROMPT,
    build_compress_memory_prompt,
    build_organize_block_prompt,
    build_prepare_block_prompt,
)

logger = structlog.get_logger(__name__)


def estimate_tokens(value: Any) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    return max(1, len(text) // 4)


def _loads_json_loose(raw: str) -> dict[str, Any] | None:
    text = str(raw or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _normalize_string_list(value: Any, *, limit: int = 12) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def _truncate_text(value: Any, limit: int = 240) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _apply_memory_confidence_guards(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    replacements = [
        (
            re.compile(
                r"potential for cross-site request forgery \(csrf\) attacks due to cors misconfiguration",
                flags=re.IGNORECASE,
            ),
            "Potential cross-origin data exposure due to wildcard CORS; CSRF impact is unconfirmed and depends on credential handling.",
        ),
        (
            re.compile(
                r"cors misconfiguration was identified, while no session tokens were collected for analysis",
                flags=re.IGNORECASE,
            ),
            "Wildcard CORS behavior was observed, while no session tokens were observed during this block, leaving token security impact unassessed.",
        ),
        (
            re.compile(
                r"no session tokens were collected(?: for analysis)?",
                flags=re.IGNORECASE,
            ),
            "No session tokens were observed during this block, so token security impact remains unassessed.",
        ),
        (
            re.compile(
                r"exposed javascript files could contain hardcoded secrets, api keys, or sensitive logic",
                flags=re.IGNORECASE,
            ),
            "Exposed JavaScript files warrant review for hardcoded secrets, API keys, or sensitive logic.",
        ),
        (
            re.compile(
                r"potential unauthorized cross-origin data access due to wildcard cors policy",
                flags=re.IGNORECASE,
            ),
            "Wildcard CORS may permit cross-origin reads where responses are readable to the browser; sensitive-data impact remains to be validated.",
        ),
    ]
    for pattern, replacement in replacements:
        text = pattern.sub(replacement, text)
    return text


def _parse_structured_text(raw: Any) -> Any | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        return ast.literal_eval(text)
    except Exception:
        return None


def _summarize_structured_value(value: Any) -> str:
    if isinstance(value, dict):
        if "error" in value and value.get("error"):
            return _truncate_text(value.get("error"), 180)
        if "summary" in value and str(value.get("summary", "")).strip():
            return _truncate_text(value.get("summary"), 180)
        if "success" in value and "total_endpoints" in value:
            total_endpoints = int(value.get("total_endpoints", 0) or 0)
            total_vulnerable = int(value.get("total_vulnerable", 0) or 0)
            if total_vulnerable > 0:
                return f"CORS analysis checked {total_endpoints} endpoints and found {total_vulnerable} vulnerable endpoints."
            return f"CORS analysis checked {total_endpoints} endpoints and found no vulnerable endpoints."
        if "success" in value and "tokens_collected" in value:
            tokens = int(value.get("tokens_collected", 0) or 0)
            error = str(value.get("error", "")).strip()
            if tokens > 0:
                return f"Session analysis collected {tokens} token samples."
            if error:
                return _truncate_text(error, 180)
            return "Session analysis collected no session tokens."
        if "return_code" in value and "command" in value:
            command = str(value.get("command", "")).strip() or "command"
            rc = value.get("return_code")
            stderr = str(value.get("stderr", "")).strip()
            stdout = str(value.get("stdout", "")).strip()
            if int(rc or 0) == 0:
                return f"Custom command `{command}` completed successfully."
            detail = stderr or stdout or str(value.get("error", "")).strip()
            if detail:
                return f"Custom command `{command}` failed: {_truncate_text(detail, 140)}"
            return f"Custom command `{command}` failed."
        if "success" in value and "tool" in value:
            tool = str(value.get("tool", "")).strip() or "tool"
            if bool(value.get("success")):
                return f"{tool} completed successfully."
            error = str(value.get("error", "")).strip()
            if error:
                return f"{tool} failed: {_truncate_text(error, 140)}"
            return f"{tool} did not return a useful result."
        parts: list[str] = []
        for key in ("title", "name", "finding", "severity", "status", "value"):
            text = str(value.get(key, "")).strip()
            if text:
                parts.append(f"{key}={_truncate_text(text, 80)}")
        if parts:
            return "; ".join(parts[:4])
    if isinstance(value, list):
        if not value:
            return ""
        head = _summarize_structured_value(value[0])
        if head:
            return _truncate_text(f"{head} (+{max(0, len(value) - 1)} more)" if len(value) > 1 else head, 180)
    return ""


def _summarize_blob_text(text: str) -> str:
    lowered = text.lower()
    if "manual_cors_check(" in text or "acao_header" in lowered or "origin_sent" in lowered:
        if "httpconnectionpool" in lowered or "connection refused" in lowered:
            return "CORS validation attempted requests to the target, but connectivity failed and no vulnerable endpoints were confirmed."
        if '"total_vulnerable": 0' in text or '"vulnerable": false' in lowered:
            return "CORS validation found no vulnerable endpoints."
        if '"total_vulnerable":' in text:
            vuln_match = re.search(r'"total_vulnerable"\s*:\s*(\d+)', text)
            vulnerable = int(vuln_match.group(1)) if vuln_match else 0
            return f"CORS validation found {vulnerable} vulnerable endpoints."
        return "CORS validation ran, but the saved tool output was truncated before detailed findings could be normalized."
    if "total_endpoints" in lowered and "total_vulnerable" in lowered:
        endpoints_match = re.search(r'"total_endpoints"\s*:\s*(\d+)', text)
        vuln_match = re.search(r'"total_vulnerable"\s*:\s*(\d+)', text)
        endpoints = int(endpoints_match.group(1)) if endpoints_match else 0
        vulnerable = int(vuln_match.group(1)) if vuln_match else 0
        if vulnerable > 0:
            return f"CORS analysis checked {endpoints} endpoints and found {vulnerable} vulnerable endpoints."
        if "httpconnectionpool" in lowered or "connection refused" in lowered:
            return f"CORS analysis checked {endpoints} endpoints; requests to the target failed during validation and no vulnerable endpoints were confirmed."
        return f"CORS analysis checked {endpoints} endpoints and found no vulnerable endpoints."
    if "tokens_collected" in lowered:
        tokens_match = re.search(r'"tokens_collected"\s*:\s*(\d+)', text)
        tokens = int(tokens_match.group(1)) if tokens_match else 0
        error_match = re.search(r'"error"\s*:\s*"([^"]+)"', text)
        if tokens > 0:
            return f"Session analysis collected {tokens} token samples."
        if error_match:
            return _truncate_text(error_match.group(1), 180)
        return "Session analysis collected no session tokens."
    if "return_code" in lowered and "command" in lowered:
        command_match = re.search(r'"command"\s*:\s*"([^"]+)"', text)
        stderr_match = re.search(r'"stderr"\s*:\s*"([^"]+)"', text)
        command = command_match.group(1) if command_match else "command"
        if stderr_match:
            return f"Custom command `{command}` failed: {_truncate_text(stderr_match.group(1), 140)}"
        return f"Custom command `{command}` failed."
    return ""


def _sanitize_memory_text(value: Any, *, limit: int = 220) -> str:
    text = _apply_memory_confidence_guards(value)
    if not text:
        return ""
    blob_summary = _summarize_blob_text(text)
    if blob_summary:
        return _truncate_text(blob_summary, limit)
    structured = _parse_structured_text(text)
    if structured is not None:
        summary = _summarize_structured_value(structured)
        if summary:
            return _truncate_text(summary, limit)
    if text.startswith(("{", "[")) or text.startswith(("{'", '["')):
        return _truncate_text(text, min(limit, 120))
    return _truncate_text(text, limit)


def _sanitize_memory_list(value: Any, *, limit: int, text_limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _sanitize_memory_text(item, limit=text_limit)
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def _sanitize_artifact_values(values: list[Any], *, limit: int = 12) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = _sanitize_memory_text(item, limit=180)
        if (
            not text
            or text.lower() in {"true", "false", "manual"}
            or text.isdigit()
            or text.startswith("[")
        ):
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def _sanitize_structured_snapshot(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    def _clean(item: Any, *, depth: int = 0) -> Any:
        if depth >= 3:
            return None
        if isinstance(item, dict):
            cleaned_dict: dict[str, Any] = {}
            for key, sub_value in list(item.items())[:20]:
                cleaned_value = _clean(sub_value, depth=depth + 1)
                if cleaned_value in (None, "", [], {}):
                    continue
                cleaned_dict[str(key)] = cleaned_value
            return cleaned_dict
        if isinstance(item, list):
            cleaned_list = []
            for sub_value in item[:20]:
                cleaned_value = _clean(sub_value, depth=depth + 1)
                if cleaned_value in (None, "", [], {}):
                    continue
                cleaned_list.append(cleaned_value)
            return cleaned_list
        if isinstance(item, str):
            return _sanitize_memory_text(item, limit=180)
        return item

    cleaned = _clean(value, depth=0)
    return cleaned if isinstance(cleaned, dict) else {}


def system_memory_dir(project_cache_dir: str) -> str:
    return os.path.join(project_cache_dir, "system_memory")


def system_memory_paths(project_cache_dir: str) -> tuple[str, str]:
    base = system_memory_dir(project_cache_dir)
    return (
        os.path.join(base, "memory.json"),
        os.path.join(base, "memory.md"),
    )


def initialize_system_memory(
    *,
    project_id: str,
    scan_id: str,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    profile: dict[str, Any],
) -> dict[str, Any]:
    return {
        "overview": {
            "project_id": project_id,
            "scan_id": scan_id,
            "target": target,
            "target_type": target_type,
            "scope": scope,
            "info": info,
        },
        "profile": deepcopy(profile) if isinstance(profile, dict) else {},
        "gathering": {
            "status": "initialized",
            "blocks": [],
        },
        "updates": [],
        "checklist": {},
        "artifacts": [],
        "tech_stack": {},
        "tech_inventory": [],
        "known_vulnerability_signals": [],
        "recommended_run_custom_tools": [],
        "nuclei_scan_hints": {},
        "anonymous_routes": [],
        "authenticated_routes": [],
        "auth_surface_delta": [],
        "blocked_routes": [],
        "blocked_route_prefixes": [],
        "session_contexts": [],
        "parameter_hints": [],
        "tool_observations": [],
        "compression": {},
        "paths": {},
    }


def load_system_memory(project_cache_dir: str) -> dict[str, Any]:
    json_path, md_path = system_memory_paths(project_cache_dir)
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                paths = data.get("paths", {})
                if not isinstance(paths, dict):
                    paths = {}
                paths["json"] = json_path
                paths["markdown"] = md_path
                data["paths"] = paths
                return data
        except Exception:
            pass
    memory = initialize_system_memory(
        project_id="",
        scan_id="",
        target="",
        target_type="",
        scope="",
        info="",
        profile={},
    )
    memory["paths"] = {"json": json_path, "markdown": md_path}
    return memory


def merge_system_memory_artifacts(memory: dict[str, Any], *values: Any) -> None:
    artifacts = memory.get("artifacts", [])
    if not isinstance(artifacts, list):
        artifacts = []
    seen = {str(item).strip().lower() for item in artifacts if str(item).strip()}
    for value in values:
        if isinstance(value, list):
            for inner in value:
                merge_system_memory_artifacts(memory, inner)
            continue
        text = str(value or "").strip()
        if len(text) < 3:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        artifacts.append(text)
    memory["artifacts"] = artifacts[:200]


def _merge_memory_string_list(memory: dict[str, Any], key: str, values: Any, *, limit: int = 200) -> None:
    existing = memory.get(key, [])
    if not isinstance(existing, list):
        existing = []
    merged: list[str] = []
    seen: set[str] = set()
    for item in list(existing) + (values if isinstance(values, list) else [values]):
        text = str(item or "").strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        merged.append(text)
    memory[key] = merged[:limit]


def _render_checklist_lines(checklist: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    blocks = checklist.get("checklist", []) if isinstance(checklist, dict) else []
    for block in blocks[:4]:
        if not isinstance(block, dict):
            continue
        phase = str(block.get("phase", "")).strip()
        title = str(block.get("title", "")).strip()
        if phase or title:
            lines.append(f"- Phase {phase} {title}".strip())
        items = block.get("items", [])
        if not isinstance(items, list):
            continue
        for item in items[:4]:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                priority = item.get("priority")
                if name:
                    suffix = f" (P{priority})" if isinstance(priority, int) else ""
                    lines.append(f"  - {name}{suffix}")
            else:
                name = str(item).strip()
                if name:
                    lines.append(f"  - {name}")
    return lines


def _normalize_memory_update_summary(title: Any, summary: Any) -> str:
    title_text = str(title or "").strip()
    text = str(summary or "").strip()
    if not text:
        return ""

    text = re.sub(r"\s+", " ", text).strip()

    transport_prefixes = (
        "Collected reconnaissance evidence across",
        "Collected exploit evidence across",
        "Collected verification evidence across",
        "Collected retest evidence across",
    )
    if any(text.startswith(prefix) for prefix in transport_prefixes):
        round_match = re.search(r"across\s+(\d+)\s+tool round", text, re.IGNORECASE)
        if round_match:
            text = f"Evidence collected across {round_match.group(1)} tool round(s)."
        else:
            text = "Evidence collected for this scenario."

    text = re.sub(
        r"\bForwarding raw evidence and per-round summaries for (analysis|verdicting)\.?$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()

    text = re.sub(
        r"Round\s+\d+\s+executed\s+\d+\s+tool\(s\).*",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()

    text = re.sub(r"\s+", " ", text).strip(" -:")

    if title_text and text:
        normalized_title = re.sub(r"\s+", " ", title_text).strip().lower()
        normalized_text = re.sub(r"\s+", " ", text).strip().lower()
        if normalized_text == normalized_title:
            return text

    return text


def _memory_is_effectively_empty(memory: dict[str, Any]) -> bool:
    overview = memory.get("overview", {}) if isinstance(memory.get("overview"), dict) else {}
    gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
    checklist = memory.get("checklist", {}) if isinstance(memory.get("checklist"), dict) else {}
    updates = memory.get("updates", []) if isinstance(memory.get("updates"), list) else []
    artifacts = memory.get("artifacts", []) if isinstance(memory.get("artifacts"), list) else []
    return (
        not str(overview.get("target", "")).strip()
        and not str(overview.get("scan_id", "")).strip()
        and not (gathering.get("blocks", []) if isinstance(gathering.get("blocks"), list) else [])
        and not updates
        and not artifacts
        and not (checklist.get("checklist", []) if isinstance(checklist.get("checklist"), list) else [])
    )


def _iter_structured_gathering_results(memory: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
    blocks = gathering.get("blocks", []) if isinstance(gathering.get("blocks"), list) else []
    rows: list[tuple[str, dict[str, Any]]] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for result in block.get("results", []) if isinstance(block.get("results"), list) else []:
            if not isinstance(result, dict):
                continue
            tool_name = str(result.get("tool", "")).strip().lower()
            structured = result.get("structured", {})
            if tool_name and isinstance(structured, dict):
                rows.append((tool_name, structured))
    return rows


def _parse_banner_claim(value: Any, source: str, *, category: str) -> dict[str, Any] | None:
    text = str(value or "").strip()
    if not text:
        return None
    product_part = text
    version_part = ""
    if "/" in text:
        product_part, version_part = text.split("/", 1)
    elif " " in text:
        product_part, version_part = text.split(" ", 1)
    product = canonicalize_product_name(product_part)
    normalized_version = normalize_version_text(version_part)
    return {
        "product": product or product_part.strip(),
        "display_name": product_part.strip() or product,
        "category": category,
        "version": version_part.strip(),
        "version_normalized": normalized_version,
        "source": source,
        "source_detail": source,
        "confidence_score": 0.68 if normalized_version else 0.55,
        "confidence_label": confidence_label(0.68 if normalized_version else 0.55),
    }


def _append_claim(claims: dict[tuple[str, str], list[dict[str, Any]]], claim: dict[str, Any] | None) -> None:
    if not isinstance(claim, dict):
        return
    product = canonicalize_product_name(claim.get("product", claim.get("display_name", "")))
    if not product:
        return
    version = normalize_version_text(claim.get("version_normalized") or claim.get("version"))
    key = (product, version)
    claim["product"] = product
    claim["version_normalized"] = version
    claims.setdefault(key, []).append(claim)


def _build_tech_inventory(memory: dict[str, Any]) -> list[dict[str, Any]]:
    claims: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for tool_name, structured in _iter_structured_gathering_results(memory):
        if tool_name == "detect_tech":
            for item in structured.get("technologies", []) if isinstance(structured.get("technologies"), list) else []:
                if not isinstance(item, dict):
                    continue
                score = float(item.get("confidence", 0) or 0) / 100.0
                claim = {
                    "product": item.get("name", ""),
                    "display_name": str(item.get("name", "")).strip(),
                    "category": str(item.get("category", "")).strip().lower(),
                    "version": str(item.get("version", "")).strip(),
                    "version_normalized": str(item.get("version_normalized", "")).strip(),
                    "source": "detect_tech",
                    "source_detail": "detect_tech",
                    "confidence_score": max(0.35, min(score or 0.0, 1.0)),
                    "confidence_label": confidence_label(score),
                }
                _append_claim(claims, claim)
        elif tool_name == "http_probe":
            for host in structured.get("hosts", []) if isinstance(structured.get("hosts"), list) else []:
                if not isinstance(host, dict):
                    continue
                _append_claim(claims, _parse_banner_claim(host.get("webserver"), "http_probe:webserver", category="web server"))
                for tech_name in host.get("tech", []) if isinstance(host.get("tech"), list) else []:
                    _append_claim(
                        claims,
                        {
                            "product": tech_name,
                            "display_name": str(tech_name).strip(),
                            "category": "technology",
                            "version": "",
                            "version_normalized": "",
                            "source": "http_probe",
                            "source_detail": "http_probe:tech",
                            "confidence_score": 0.58,
                            "confidence_label": "medium",
                        },
                    )
        elif tool_name == "http_header_analysis":
            for endpoint in structured.get("endpoints", []) if isinstance(structured.get("endpoints"), list) else []:
                if not isinstance(endpoint, dict):
                    continue
                _append_claim(claims, _parse_banner_claim(endpoint.get("server"), "http_header_analysis:server", category="web server"))
                _append_claim(claims, _parse_banner_claim(endpoint.get("x_powered_by"), "http_header_analysis:x_powered_by", category="backend"))

    inventory: list[dict[str, Any]] = []
    for (product, version), grouped_claims in claims.items():
        if not grouped_claims:
            continue
        sources = sorted(
            {
                str(item.get("source_detail", item.get("source", ""))).strip()
                for item in grouped_claims
                if str(item.get("source_detail", item.get("source", ""))).strip()
            }
        )
        best = max(grouped_claims, key=lambda item: float(item.get("confidence_score", 0.0) or 0.0))
        version_sources = {
            str(item.get("source", "")).strip()
            for item in grouped_claims
            if normalize_version_text(item.get("version_normalized") or item.get("version")) == version
            and version
        }
        corroborated = bool(version and len(version_sources) >= 2)
        confidence_score = max(float(best.get("confidence_score", 0.0) or 0.0), 0.55 if corroborated else 0.0)
        if corroborated:
            confidence_score = max(confidence_score, 0.9)
        profile = get_product_profile(product)
        kb_query = build_known_vuln_query(
            product=product,
            version=version,
            target_type=memory.get("overview", {}).get("target_type", "") if isinstance(memory.get("overview"), dict) else "",
        )
        inventory.append(
            {
                "product": product,
                "display_name": str(best.get("display_name", product)).strip() or product,
                "category": str(best.get("category", "")).strip() or "technology",
                "version": str(best.get("version", "")).strip(),
                "version_normalized": version,
                "confidence_score": round(confidence_score, 2),
                "confidence_label": "high" if corroborated else confidence_label(confidence_score),
                "corroborated": corroborated,
                "source_count": len(sources),
                "sources": sources,
                "legacy_field": str(profile.get("legacy_field", "")).strip(),
                "recommended_run_custom_tools": profile.get("run_custom_tools", [])[:5],
                "nuclei_tags": profile.get("nuclei_tags", [])[:6],
                "nuclei_templates": profile.get("nuclei_templates", [])[:4],
                "kb_query": kb_query,
            }
        )

    inventory.sort(
        key=lambda item: (
            float(item.get("confidence_score", 0.0) or 0.0),
            int(item.get("source_count", 0) or 0),
            len(str(item.get("version_normalized", "")).strip()),
        ),
        reverse=True,
    )
    return inventory[:20]


def _build_known_vulnerability_signals(memory: dict[str, Any]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    seen: set[str] = set()
    for tool_name, structured in _iter_structured_gathering_results(memory):
        if tool_name != "known_vuln_lookup":
            continue
        for item in structured.get("signals", []) if isinstance(structured.get("signals"), list) else []:
            if not isinstance(item, dict):
                continue
            product = canonicalize_product_name(item.get("product", ""))
            version = normalize_version_text(item.get("version"))
            key = "|".join(
                [
                    product,
                    version,
                    str(item.get("cve", "")).strip().upper(),
                    str(item.get("title", "")).strip().lower(),
                ]
            )
            if key in seen:
                continue
            seen.add(key)
            signals.append(
                {
                    "product": product,
                    "version": version,
                    "cve": str(item.get("cve", "")).strip().upper(),
                    "title": str(item.get("title", "")).strip(),
                    "severity": str(item.get("severity", "")).strip().upper(),
                    "cisa_kev": bool(item.get("cisa_kev")),
                    "exploit_source": str(item.get("source", "")).strip(),
                    "summary": str(item.get("summary", "")).strip(),
                    "confidence_label": str(item.get("confidence_label", "")).strip() or "medium",
                }
            )
    return signals[:30]


def _apply_memory_enrichment(memory: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(memory, dict):
        return {}
    enriched = dict(memory)
    inventory = _build_tech_inventory(enriched)
    if inventory:
        enriched["tech_inventory"] = inventory
        current_stack = enriched.get("tech_stack", {})
        stack = dict(current_stack) if isinstance(current_stack, dict) else {}
        stack.update(project_legacy_tech_stack(inventory))
        enriched["tech_stack"] = stack
        enriched["recommended_run_custom_tools"] = recommend_run_custom_tools(inventory)
        enriched["nuclei_scan_hints"] = recommend_nuclei_hints(inventory)
    else:
        enriched.setdefault("tech_inventory", [])
        enriched.setdefault("recommended_run_custom_tools", [])
        enriched.setdefault("nuclei_scan_hints", {})

    known_signals = _build_known_vulnerability_signals(enriched)
    if known_signals:
        enriched["known_vulnerability_signals"] = known_signals
    else:
        enriched.setdefault("known_vulnerability_signals", [])
    return enriched


def compute_tool_efficiency_snapshot(memory: dict[str, Any]) -> dict[str, dict[str, float | int]]:
    observations = memory.get("tool_observations", []) if isinstance(memory.get("tool_observations"), list) else []
    stats: dict[str, dict[str, float | int]] = {}
    for row in observations:
        if not isinstance(row, dict):
            continue
        tool_name = str(row.get("tool", "")).strip()
        if not tool_name:
            continue
        bucket = stats.setdefault(
            tool_name,
            {
                "total": 0,
                "successes": 0,
                "false_positives": 0,
                "avg_confidence": 0.0,
            },
        )
        bucket["total"] = int(bucket["total"]) + 1
        if str(row.get("status", "")).strip().lower() == "success":
            bucket["successes"] = int(bucket["successes"]) + 1
        bucket["false_positives"] = int(bucket["false_positives"]) + int(row.get("false_positive_count", 0) or 0)
        confidence = float(row.get("confidence", 0.0) or 0.0)
        bucket["avg_confidence"] = float(bucket["avg_confidence"]) + confidence

    for bucket in stats.values():
        total = max(int(bucket["total"]), 1)
        bucket["efficiency"] = round(int(bucket["successes"]) / total, 2)
        bucket["false_positive_rate"] = round(int(bucket["false_positives"]) / total, 2)
        bucket["avg_confidence"] = round(float(bucket["avg_confidence"]) / total, 2)
    return stats


def build_system_memory_prompt_block(memory: dict[str, Any]) -> str:
    overview = memory.get("overview", {}) if isinstance(memory.get("overview"), dict) else {}
    gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
    compression = memory.get("compression", {}) if isinstance(memory.get("compression"), dict) else {}
    updates = memory.get("updates", []) if isinstance(memory.get("updates"), list) else []
    checklist = memory.get("checklist", {}) if isinstance(memory.get("checklist"), dict) else {}
    tech_stack = memory.get("tech_stack", {}) if isinstance(memory.get("tech_stack"), dict) else {}
    tech_inventory = memory.get("tech_inventory", []) if isinstance(memory.get("tech_inventory"), list) else []
    known_vuln_signals = memory.get("known_vulnerability_signals", []) if isinstance(memory.get("known_vulnerability_signals"), list) else []
    nuclei_scan_hints = memory.get("nuclei_scan_hints", {}) if isinstance(memory.get("nuclei_scan_hints"), dict) else {}
    recommended_run_custom_tools = memory.get("recommended_run_custom_tools", []) if isinstance(memory.get("recommended_run_custom_tools"), list) else []
    anonymous_routes = memory.get("anonymous_routes", []) if isinstance(memory.get("anonymous_routes"), list) else []
    authenticated_routes = memory.get("authenticated_routes", []) if isinstance(memory.get("authenticated_routes"), list) else []
    auth_surface_delta = memory.get("auth_surface_delta", []) if isinstance(memory.get("auth_surface_delta"), list) else []
    blocked_routes = memory.get("blocked_routes", []) if isinstance(memory.get("blocked_routes"), list) else []
    blocked_route_prefixes = memory.get("blocked_route_prefixes", []) if isinstance(memory.get("blocked_route_prefixes"), list) else []
    session_contexts = memory.get("session_contexts", []) if isinstance(memory.get("session_contexts"), list) else []
    parameter_hints = memory.get("parameter_hints", []) if isinstance(memory.get("parameter_hints"), list) else []
    tool_efficiency = compute_tool_efficiency_snapshot(memory)

    lines = [
        "# System Memory",
        "",
        "## Overview",
        f"- Target: {overview.get('target', '')}",
        f"- Target type: {overview.get('target_type', '')}",
        f"- Scope: {overview.get('scope', '')}",
    ]

    blocks = gathering.get("blocks", []) if isinstance(gathering.get("blocks"), list) else []
    lines.extend(["", "## Grouped Static Gathering"])
    if blocks:
        for block in blocks[:6]:
            if not isinstance(block, dict):
                continue
            block_name = str(block.get("name", "")).strip() or "Unnamed block"
            block_status = str(block.get("status", "")).strip() or "unknown"
            block_summary = str(block.get("summary", "")).strip() or block_status
            lines.extend(
                [
                    f"### {block_name}",
                    f"- Status: {block_status}",
                    f"- Summary: {block_summary}",
                ]
            )
            key_findings = block.get("key_findings", [])
            if isinstance(key_findings, list) and key_findings:
                lines.append("- Key findings:")
                for item in key_findings[:4]:
                    text = str(item or "").strip()
                    if text:
                        lines.append(f"  - {text}")
            risk_signals = block.get("risk_signals", [])
            if isinstance(risk_signals, list) and risk_signals:
                lines.append("- Risk signals:")
                for item in risk_signals[:3]:
                    text = str(item or "").strip()
                    if text:
                        lines.append(f"  - {text}")
            open_questions = block.get("open_questions", [])
            if isinstance(open_questions, list) and open_questions:
                lines.append("- Open questions:")
                for item in open_questions[:3]:
                    text = str(item or "").strip()
                    if text:
                        lines.append(f"  - {text}")
            results = block.get("results", [])
            if isinstance(results, list) and results:
                lines.append("- Tool outcomes:")
                for row in results[:4]:
                    if not isinstance(row, dict):
                        continue
                    tool_name = str(row.get("tool", "")).strip() or "tool"
                    tool_summary = str(row.get("summary", "")).strip()
                    if tool_summary:
                        lines.append(f"  - {tool_name}: {tool_summary}")
            lines.append("")
    else:
        lines.append("- (no grouped gathering blocks stored)")

    tech_lines = [
        f"{key.replace('_', ' ').title()}: {value}"
        for key, value in tech_stack.items()
        if str(value or "").strip()
    ]
    if tech_lines:
        lines.extend(["", "## Tech Stack"])
        lines.extend(f"- {item}" for item in tech_lines[:8])
    if tech_inventory:
        lines.extend(["", "## Tech Inventory"])
        for row in tech_inventory[:10]:
            if not isinstance(row, dict):
                continue
            product = str(row.get("product", "")).strip()
            version = str(row.get("version_normalized", row.get("version", ""))).strip()
            confidence = str(row.get("confidence_label", "")).strip()
            sources = ", ".join(str(item).strip() for item in row.get("sources", [])[:3]) if isinstance(row.get("sources"), list) else ""
            line = product
            if version:
                line = f"{line} {version}"
            if confidence:
                line = f"{line} [{confidence}]"
            if sources:
                line = f"{line} via {sources}"
            if line.strip():
                lines.append(f"- {line.strip()}")
    if recommended_run_custom_tools or nuclei_scan_hints:
        lines.extend(["", "## Known-Vuln Fast Lane Hints"])
        if recommended_run_custom_tools:
            lines.append(
                f"- Preferred scoped tools: {', '.join(str(item) for item in recommended_run_custom_tools[:8])}"
            )
        tags = nuclei_scan_hints.get("tags", []) if isinstance(nuclei_scan_hints.get("tags"), list) else []
        templates = nuclei_scan_hints.get("templates", []) if isinstance(nuclei_scan_hints.get("templates"), list) else []
        if tags:
            lines.append(f"- Nuclei tags: {', '.join(str(item) for item in tags[:8])}")
        if templates:
            lines.append(f"- Nuclei templates: {', '.join(str(item) for item in templates[:6])}")
    if known_vuln_signals:
        lines.extend(["", "## Known Vulnerability Signals"])
        for row in known_vuln_signals[:10]:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve", "")).strip()
            title = str(row.get("title", "")).strip()
            product = str(row.get("product", "")).strip()
            version = str(row.get("version", "")).strip()
            severity = str(row.get("severity", "")).strip()
            kev = " KEV" if bool(row.get("cisa_kev")) else ""
            summary_text = str(row.get("summary", "")).strip()
            label = " ".join(part for part in [product, version, cve, severity] if part).strip()
            if not label:
                label = title or "known vulnerability signal"
            lines.append(f"- {label}{kev}: {summary_text or title}")

    if anonymous_routes or authenticated_routes or auth_surface_delta or blocked_routes or blocked_route_prefixes or session_contexts:
        lines.extend(["", "## Session And Surface Context"])
        if session_contexts:
            lines.append(f"- Session contexts: {', '.join(str(item) for item in session_contexts[:8])}")
        if anonymous_routes:
            lines.append(f"- Anonymous routes discovered: {len(anonymous_routes)}")
        if authenticated_routes:
            lines.append(f"- Authenticated routes discovered: {len(authenticated_routes)}")
        if auth_surface_delta:
            lines.append("- Auth-only surface delta:")
            for route in auth_surface_delta[:8]:
                lines.append(f"  - {route}")
        if blocked_routes:
            lines.append("- Blocked or disproven routes:")
            for route in blocked_routes[:10]:
                lines.append(f"  - {route}")
        if blocked_route_prefixes:
            lines.append("- Blocked route families:")
            for route in blocked_route_prefixes[:8]:
                lines.append(f"  - {route}")

    if parameter_hints:
        lines.extend(["", "## Parameter Hints"])
        for hint in parameter_hints[:12]:
            text = str(hint or "").strip()
            if text:
                lines.append(f"- {text}")

    if tool_efficiency:
        lines.extend(["", "## Tool Efficiency"])
        for tool_name, stats in list(tool_efficiency.items())[:10]:
            lines.append(
                "- "
                + f"{tool_name}: efficiency={stats.get('efficiency', 0.0)} "
                + f"avg_confidence={stats.get('avg_confidence', 0.0)} "
                + f"false_positive_rate={stats.get('false_positive_rate', 0.0)} "
                + f"total={stats.get('total', 0)}"
            )

    summary = str(compression.get("summary", "")).strip()
    if summary:
        lines.extend(["", "## Compressed Memory Snapshot", summary])

    if updates:
        lines.extend(["", "## Recent Updates"])
        for update in updates[-6:]:
            if not isinstance(update, dict):
                continue
            title = str(update.get("title", update.get("stage", "update"))).strip()
            update_summary = str(update.get("summary", "")).strip()
            lines.append(f"- {title}: {update_summary}")

    checklist_lines = _render_checklist_lines(checklist)
    if checklist_lines:
        lines.extend(["", "## Stored Checklist"])
        lines.extend(checklist_lines)

    return "\n".join(lines).strip()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _render_memory_markdown(memory: dict[str, Any], config: SystemMemoryConfig) -> str:
    content = build_system_memory_prompt_block(memory)
    if len(content) <= config.max_markdown_chars:
        return content
    summary = content[: config.compression_summary_chars].rstrip()
    memory["compression"] = {"summary": summary}
    return build_system_memory_prompt_block(memory)


def _fallback_compress_markdown(
    memory: dict[str, Any],
    *,
    content: str,
    current_tokens: int,
    config: SystemMemoryConfig,
) -> str:
    overview = memory.get("overview", {}) if isinstance(memory.get("overview"), dict) else {}
    gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
    checklist = memory.get("checklist", {}) if isinstance(memory.get("checklist"), dict) else {}
    updates = memory.get("updates", []) if isinstance(memory.get("updates"), list) else []
    artifacts = memory.get("artifacts", []) if isinstance(memory.get("artifacts"), list) else []

    lines = [
        "# Compressed System Memory",
        "",
        "## Overview",
        f"- Target: {overview.get('target', '')}",
        f"- Target type: {overview.get('target_type', '')}",
        f"- Scope: {overview.get('scope', '')}",
    ]

    blocks = gathering.get("blocks", []) if isinstance(gathering.get("blocks"), list) else []
    lines.extend(["", "## Key Gathering Findings"])
    if blocks:
        for block in blocks[-6:]:
            if not isinstance(block, dict):
                continue
            name = str(block.get("name", "")).strip() or "Unnamed block"
            summary = str(block.get("summary", "")).strip() or str(block.get("status", "")).strip()
            if summary:
                lines.append(f"- {name}: {summary}")
    else:
        lines.append("- No grouped gathering blocks stored yet.")

    checklist_lines = _render_checklist_lines(checklist)[:12]
    if checklist_lines:
        lines.extend(["", "## Checklist Snapshot"])
        lines.extend(checklist_lines)

    if updates:
        lines.extend(["", "## Recent Updates"])
        for update in updates[-5:]:
            if not isinstance(update, dict):
                continue
            title = str(update.get("title", update.get("stage", "update"))).strip() or "update"
            summary = str(update.get("summary", "")).strip()
            if summary:
                lines.append(f"- {title}: {summary}")

    if artifacts:
        lines.extend(["", "## Artifacts"])
        for artifact in artifacts[-12:]:
            text = str(artifact or "").strip()
            if text:
                lines.append(f"- {text}")

    compressed = "\n".join(lines).strip()
    compression = memory.get("compression", {}) if isinstance(memory.get("compression"), dict) else {}
    compression.update(
        {
            "summary": compressed[: config.compression_summary_chars].rstrip(),
            "mode": "fallback",
            "trigger": "token_limit",
            "input_tokens": int(current_tokens),
            "output_tokens": int(estimate_tokens(compressed)),
            "target_tokens": int(config.compression_target_tokens),
            "compressed_at": _utc_now_iso(),
        }
    )
    memory["compression"] = compression
    return compressed


def _normalize_saved_memory(memory: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(memory) if isinstance(memory, dict) else {}
    normalized = _apply_memory_enrichment(normalized)

    gathering = normalized.get("gathering", {}) if isinstance(normalized.get("gathering"), dict) else {}
    raw_blocks = gathering.get("blocks", [])
    if isinstance(raw_blocks, list):
        cleaned_blocks: list[dict[str, Any]] = []
        helper = SystemMemoryLLM()
        for block in raw_blocks:
            if not isinstance(block, dict):
                continue
            cleaned_blocks.append(helper._sanitize_organized_block(block, block))
        gathering["blocks"] = cleaned_blocks
    program = gathering.get("program", [])
    if isinstance(program, list):
        cleaned_program: list[dict[str, Any]] = []
        for block in program:
            if not isinstance(block, dict):
                continue
            cleaned = deepcopy(block)
            cleaned["selection_rationale"] = _sanitize_memory_text(cleaned.get("selection_rationale", ""), limit=220)
            cleaned["skipped_tools"] = _normalize_string_list(cleaned.get("skipped_tools", []), limit=12)
            cleaned_program.append(cleaned)
        gathering["program"] = cleaned_program
    normalized["gathering"] = gathering

    raw_updates = normalized.get("updates", [])
    if isinstance(raw_updates, list):
        cleaned_updates: list[dict[str, Any]] = []
        for row in raw_updates:
            if not isinstance(row, dict):
                continue
            cleaned = dict(row)
            cleaned["title"] = _sanitize_memory_text(cleaned.get("title", ""), limit=140)
            cleaned["summary"] = _sanitize_memory_text(
                _normalize_memory_update_summary(
                    cleaned.get("title", ""),
                    cleaned.get("summary", ""),
                ),
                limit=240,
            )
            cleaned_updates.append(cleaned)
        normalized["updates"] = cleaned_updates[-100:]

    normalized["artifacts"] = _sanitize_artifact_values(
        normalized.get("artifacts", []) if isinstance(normalized.get("artifacts"), list) else [],
        limit=200,
    )
    normalized["tech_inventory"] = [
        row for row in normalized.get("tech_inventory", [])
        if isinstance(row, dict)
    ][:20] if isinstance(normalized.get("tech_inventory"), list) else []
    normalized["known_vulnerability_signals"] = [
        row for row in normalized.get("known_vulnerability_signals", [])
        if isinstance(row, dict)
    ][:30] if isinstance(normalized.get("known_vulnerability_signals"), list) else []
    normalized["recommended_run_custom_tools"] = _normalize_string_list(
        normalized.get("recommended_run_custom_tools", []),
        limit=12,
    )
    normalized["nuclei_scan_hints"] = _sanitize_structured_snapshot(
        normalized.get("nuclei_scan_hints", {})
    )
    return normalized


async def save_system_memory(
    project_cache_dir: str,
    memory: dict[str, Any],
    *,
    memory_llm: Any | None = None,
    config: SystemMemoryConfig | None = None,
    progress_callback: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    cfg = config or get_system_memory_config()
    json_path, md_path = system_memory_paths(project_cache_dir)
    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    saved = _normalize_saved_memory(memory)
    saved["paths"] = {"json": json_path, "markdown": md_path}

    if os.path.exists(json_path) and _memory_is_effectively_empty(saved):
        return saved

    markdown_content = _render_memory_markdown(saved, cfg)
    estimated_tokens = int(estimate_tokens(markdown_content))
    compression = saved.get("compression", {}) if isinstance(saved.get("compression"), dict) else {}
    compression["last_markdown_tokens"] = estimated_tokens
    compression["max_markdown_tokens"] = int(cfg.max_markdown_tokens)
    saved["compression"] = compression

    if estimated_tokens > cfg.max_markdown_tokens:
        if progress_callback:
            progress_callback(
                "memory_compacting",
                {
                    "message": "Automatically compacting context",
                    "estimated_tokens": estimated_tokens,
                    "max_tokens": int(cfg.max_markdown_tokens),
                    "target_tokens": int(cfg.compression_target_tokens),
                    "markdown_path": md_path,
                },
            )
        if memory_llm is not None and hasattr(memory_llm, "compress_memory_markdown"):
            markdown_content = await memory_llm.compress_memory_markdown(
                memory=saved,
                content=markdown_content,
                current_tokens=estimated_tokens,
            )
        else:
            markdown_content = _fallback_compress_markdown(
                saved,
                content=markdown_content,
                current_tokens=estimated_tokens,
                config=cfg,
            )
        compacted_tokens = int(estimate_tokens(markdown_content))
        compression = saved.get("compression", {}) if isinstance(saved.get("compression"), dict) else {}
        compression["last_markdown_tokens"] = compacted_tokens
        saved["compression"] = compression
        if progress_callback:
            progress_callback(
                "memory_compacted",
                {
                    "message": "Context compaction complete",
                    "estimated_tokens": compacted_tokens,
                    "max_tokens": int(cfg.max_markdown_tokens),
                    "target_tokens": int(cfg.compression_target_tokens),
                    "markdown_path": md_path,
                },
            )

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(saved, fh, indent=2, ensure_ascii=True)

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown_content.rstrip() + "\n")

    overview = saved.get("overview", {}) if isinstance(saved.get("overview"), dict) else {}
    project_id = str(overview.get("project_id", "")).strip()
    if project_id:
        try:
            await index_system_memory_markdown(
                project_id=project_id,
                target=str(overview.get("target", "")).strip(),
                target_type=str(overview.get("target_type", "")).strip(),
                markdown_content=markdown_content,
                project_store=ProjectsStore(),
            )
        except Exception:
            logger.warning("system_memory_project_rag_index_failed", project_id=project_id, exc_info=True)

    return saved


async def append_system_memory_updates(
    project_cache_dir: str,
    *,
    stage: str,
    updates: list[dict[str, Any]],
    verified_findings: list[dict[str, Any]] | None = None,
    tool_observations: list[dict[str, Any]] | None = None,
    memory_llm: Any | None = None,
    config: SystemMemoryConfig | None = None,
) -> dict[str, Any]:
    del memory_llm
    memory = load_system_memory(project_cache_dir)
    update_rows = memory.get("updates", [])
    if not isinstance(update_rows, list):
        update_rows = []
    for update in updates:
        if not isinstance(update, dict):
            continue
        row = dict(update)
        row.setdefault("stage", stage)
        update_rows.append(row)
        merge_system_memory_artifacts(memory, row.get("title"), row.get("summary"))
        if row.get("kind") == "blocked_route":
            _merge_memory_string_list(memory, "blocked_routes", row.get("routes", []), limit=200)
            _merge_memory_string_list(memory, "blocked_route_prefixes", row.get("route_prefixes", []), limit=80)
    if verified_findings:
        existing_findings = memory.get("verified_findings", [])
        if not isinstance(existing_findings, list):
            existing_findings = []
        
        # Merge by ID
        findings_map = {str(f.get("id", "")): f for f in existing_findings if f.get("id")}
        for new_f in verified_findings:
            f_id = str(new_f.get("id", ""))
            if f_id and f_id in findings_map:
                # Merge fields: new_f overwrites existing non-null fields
                existing_f = findings_map[f_id]
                for k, v in new_f.items():
                    if v is not None or k not in existing_f:
                        existing_f[k] = v
            else:
                existing_findings.append(new_f)
        memory["verified_findings"] = existing_findings
    if tool_observations:
        observation_rows = memory.get("tool_observations", [])
        if not isinstance(observation_rows, list):
            observation_rows = []
        for item in tool_observations:
            if isinstance(item, dict):
                observation_rows.append(dict(item))
        memory["tool_observations"] = observation_rows[-200:]
    memory["updates"] = update_rows[-100:]
    return await save_system_memory(project_cache_dir, memory, config=config)


async def store_system_memory_checklist(
    project_cache_dir: str,
    *,
    checklist: dict[str, Any],
    memory_llm: Any | None = None,
    config: SystemMemoryConfig | None = None,
) -> dict[str, Any]:
    del memory_llm
    memory = load_system_memory(project_cache_dir)
    memory["checklist"] = checklist if isinstance(checklist, dict) else {}
    return await save_system_memory(project_cache_dir, memory, config=config)


class SystemMemoryLLM:
    """Adaptive system-memory helper with deterministic fallback."""

    def __init__(self, config: SystemMemoryConfig | None = None) -> None:
        self._config = config or get_system_memory_config()
        self._llm_config = get_public_agent_config("system_memory")

    def _prepare_block_fallback(self, block: dict[str, Any]) -> dict[str, Any]:
        prepared = deepcopy(block) if isinstance(block, dict) else {}
        prepared.setdefault("selection_rationale", "")
        prepared.setdefault("skipped_tools", [])
        prepared["skipped_tools"] = _normalize_string_list(prepared.get("skipped_tools"), limit=12)
        return prepared

    def _organize_block_fallback(
        self,
        *,
        block: dict[str, Any],
        raw_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        block_id = str(block.get("id", "")).strip()
        block_name = str(block.get("name", block_id or "Unnamed Block")).strip()
        goal = str(block.get("goal", "")).strip()
        interaction = str(block.get("interaction", "")).strip()
        planned_tools = []
        for item in block.get("tools", []) if isinstance(block.get("tools"), list) else []:
            if isinstance(item, str):
                planned_tools.append(item.strip())
            elif isinstance(item, dict):
                tool_name = str(item.get("tool", "")).strip()
                if tool_name:
                    planned_tools.append(tool_name)

        summaries = [
            _sanitize_memory_text(row.get("summary", ""), limit=220)
            for row in raw_results
            if isinstance(row, dict) and _sanitize_memory_text(row.get("summary", ""), limit=220)
        ]
        artifact_values: list[Any] = []
        for row in raw_results:
            if not isinstance(row, dict):
                continue
            merge_values = [row.get("summary")]
            args = row.get("args", {})
            if isinstance(args, dict):
                merge_values.extend(args.values())
            artifact_values.extend(merge_values)
        artifacts = _sanitize_artifact_values(artifact_values, limit=20)

        status_values = {
            str(row.get("status", "")).strip().lower()
            for row in raw_results
            if isinstance(row, dict)
        }
        if "completed" in status_values:
            status = "completed"
        elif "error" in status_values:
            status = "partial"
        else:
            status = "skipped"

        results = []
        for row in raw_results:
            if not isinstance(row, dict):
                continue
            results.append(
                {
                    "tool": str(row.get("tool", "")).strip(),
                    "status": str(row.get("status", "")).strip(),
                    "summary": _sanitize_memory_text(row.get("summary", ""), limit=220),
                    "command": _sanitize_memory_text(row.get("command", ""), limit=420),
                    "artifacts": [],
                    "structured": _sanitize_structured_snapshot(row.get("structured")),
                }
            )

        summary = summaries[0] if summaries else f"{block_name} produced no detailed result summaries."
        return {
            "id": block_id or block_name.lower().replace(" ", "_"),
            "name": block_name,
            "goal": goal,
            "interaction": interaction,
            "planned_tools": planned_tools,
            "selection_rationale": str(block.get("selection_rationale", "")).strip(),
            "skipped_tools": _normalize_string_list(block.get("skipped_tools"), limit=12),
            "status": status,
            "summary": summary,
            "key_findings": summaries[:5],
            "risk_signals": [],
            "open_questions": [],
            "artifacts": artifacts[:20],
            "results": results,
        }

    async def prepare_block(
        self,
        *,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        block: dict[str, Any],
    ) -> dict[str, Any]:
        fallback = self._prepare_block_fallback(block)
        prompt = build_prepare_block_prompt(
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
            block=block,
        )
        try:
            async with get_llm(self._llm_config) as llm:
                response = await llm.chat(
                    [
                        ChatMessage(role="system", content=PREPARE_BLOCK_SYSTEM_PROMPT),
                        ChatMessage(role="user", content=prompt),
                    ],
                    temperature=self._config.llm_temperature,
                    max_tokens=self._config.llm_prepare_max_tokens,
                )
            payload = _loads_json_loose(response.content or "")
            if not isinstance(payload, dict):
                return fallback
            prepared = deepcopy(fallback)
            for key in ("name", "goal", "interaction", "selection_rationale"):
                value = str(payload.get(key, "")).strip()
                if value:
                    prepared[key] = value
            prepared["skipped_tools"] = _normalize_string_list(
                payload.get("skipped_tools"),
                limit=12,
            ) or prepared.get("skipped_tools", [])
            return prepared
        except Exception:
            return fallback

    def _sanitize_organized_block(self, organized: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
        cleaned = deepcopy(fallback)
        cleaned.update(
            {
                "id": str(organized.get("id", fallback.get("id", ""))).strip() or fallback.get("id", ""),
                "name": str(organized.get("name", fallback.get("name", ""))).strip() or fallback.get("name", ""),
                "goal": str(organized.get("goal", fallback.get("goal", ""))).strip() or fallback.get("goal", ""),
                "interaction": str(organized.get("interaction", fallback.get("interaction", ""))).strip() or fallback.get("interaction", ""),
                "planned_tools": organized.get("planned_tools", fallback.get("planned_tools", [])),
                "selection_rationale": _sanitize_memory_text(
                    organized.get("selection_rationale", fallback.get("selection_rationale", "")),
                    limit=220,
                ),
                "skipped_tools": _normalize_string_list(
                    organized.get("skipped_tools", fallback.get("skipped_tools", [])),
                    limit=12,
                ),
            }
        )

        status = str(organized.get("status", fallback.get("status", ""))).strip().lower()
        cleaned["status"] = status if status in {"completed", "partial", "skipped"} else fallback.get("status", "partial")

        summary = _sanitize_memory_text(organized.get("summary", fallback.get("summary", "")), limit=520)
        if not summary:
            summary = _sanitize_memory_text(fallback.get("summary", ""), limit=520)
        cleaned["summary"] = summary

        for key in ("key_findings", "risk_signals", "open_questions"):
            cleaned[key] = _sanitize_memory_list(
                organized.get(key, fallback.get(key, [])),
                limit=8,
                text_limit=260,
            )
        cleaned["artifacts"] = _sanitize_artifact_values(
            organized.get("artifacts", fallback.get("artifacts", [])),
            limit=20,
        )

        raw_results = organized.get("results", fallback.get("results", []))
        results: list[dict[str, Any]] = []
        fallback_results = fallback.get("results", []) if isinstance(fallback.get("results", []), list) else []
        if isinstance(raw_results, list):
            for index, row in enumerate(raw_results[:12]):
                if not isinstance(row, dict):
                    continue
                tool_name = str(row.get("tool", "")).strip()
                status_text = str(row.get("status", "")).strip().lower()
                fallback_row = fallback_results[index] if index < len(fallback_results) and isinstance(fallback_results[index], dict) else {}
                results.append(
                    {
                        "tool": tool_name,
                        "status": status_text if status_text else "completed",
                        "summary": _sanitize_memory_text(row.get("summary", ""), limit=320),
                        "command": _sanitize_memory_text(
                            row.get("command", fallback_row.get("command", "")),
                            limit=420,
                        ),
                        "artifacts": _sanitize_artifact_values(row.get("artifacts", []), limit=8),
                        "structured": _sanitize_structured_snapshot(
                            row.get("structured", fallback_row.get("structured", {}))
                        ),
                    }
                )
        if results:
            cleaned["results"] = results

        if not cleaned["key_findings"] and cleaned["summary"]:
            cleaned["key_findings"] = [cleaned["summary"]]
        return cleaned

    async def organize_block(
        self,
        *,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        block: dict[str, Any],
        raw_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        fallback = self._organize_block_fallback(block=block, raw_results=raw_results)
        prompt = build_organize_block_prompt(
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
            block=block,
            raw_results=raw_results,
        )
        try:
            async with get_llm(self._llm_config) as llm:
                response = await llm.chat(
                    [
                        ChatMessage(role="system", content=ORGANIZE_BLOCK_SYSTEM_PROMPT),
                        ChatMessage(role="user", content=prompt),
                    ],
                    temperature=self._config.llm_temperature,
                    max_tokens=self._config.llm_organize_max_tokens,
                )
            payload = _loads_json_loose(response.content or "")
            if not isinstance(payload, dict):
                return fallback
            organized = deepcopy(fallback)
            status = str(payload.get("status", "")).strip().lower()
            if status in {"completed", "partial", "skipped"}:
                organized["status"] = status
            summary = str(payload.get("summary", "")).strip()
            if summary:
                organized["summary"] = summary
            for key in ("key_findings", "risk_signals", "open_questions", "artifacts"):
                organized[key] = _normalize_string_list(
                    payload.get(key),
                    limit=20 if key == "artifacts" else 8,
                )
            raw_structured_results = payload.get("results", [])
            if isinstance(raw_structured_results, list):
                results: list[dict[str, Any]] = []
                for row in raw_structured_results[:12]:
                    if not isinstance(row, dict):
                        continue
                    results.append(
                        {
                            "tool": str(row.get("tool", "")).strip(),
                            "status": str(row.get("status", "")).strip(),
                            "summary": str(row.get("summary", "")).strip(),
                            "artifacts": _normalize_string_list(row.get("artifacts"), limit=8),
                        }
                    )
                if results:
                    organized["results"] = results
            return self._sanitize_organized_block(organized, fallback)
        except Exception:
            return self._sanitize_organized_block(fallback, fallback)

    async def compress_memory_markdown(
        self,
        *,
        memory: dict[str, Any],
        content: str,
        current_tokens: int,
    ) -> str:
        prompt = build_compress_memory_prompt(
            token_budget=self._config.compression_target_tokens,
            current_tokens=current_tokens,
            memory_markdown=content,
        )
        try:
            async with get_llm(self._llm_config) as llm:
                response = await llm.chat(
                    [
                        ChatMessage(role="system", content=COMPRESS_MEMORY_SYSTEM_PROMPT),
                        ChatMessage(role="user", content=prompt),
                    ],
                    temperature=self._config.llm_temperature,
                    max_tokens=self._config.llm_compress_max_tokens,
                )
            compressed = str(response.content or "").strip()
            if not compressed:
                raise ValueError("empty compression response")
            compressed_tokens = int(estimate_tokens(compressed))
            if compressed_tokens > self._config.max_markdown_tokens:
                raise ValueError("compression response still exceeds token budget")
            compression = memory.get("compression", {}) if isinstance(memory.get("compression"), dict) else {}
            compression.update(
                {
                    "summary": compressed[: self._config.compression_summary_chars].rstrip(),
                    "mode": "llm",
                    "trigger": "token_limit",
                    "input_tokens": int(current_tokens),
                    "output_tokens": compressed_tokens,
                    "target_tokens": int(self._config.compression_target_tokens),
                    "compressed_at": _utc_now_iso(),
                }
            )
            memory["compression"] = compression
            return compressed
        except Exception:
            return _fallback_compress_markdown(
                memory,
                content=content,
                current_tokens=current_tokens,
                config=self._config,
            )
