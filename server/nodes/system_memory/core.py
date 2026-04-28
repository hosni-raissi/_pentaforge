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

from server.agents.context_window_manager import estimate_tokens
from server.config.agent import get_public_agent_config
from server.core.llm import ChatMessage, get_llm
from server.db.projects.project_rag import index_system_memory_markdown
from server.db.projects.store import ProjectsStore

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


def build_system_memory_prompt_block(memory: dict[str, Any]) -> str:
    overview = memory.get("overview", {}) if isinstance(memory.get("overview"), dict) else {}
    gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
    compression = memory.get("compression", {}) if isinstance(memory.get("compression"), dict) else {}
    updates = memory.get("updates", []) if isinstance(memory.get("updates"), list) else []
    checklist = memory.get("checklist", {}) if isinstance(memory.get("checklist"), dict) else {}

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
    memory_llm: Any | None = None,
    config: SystemMemoryConfig | None = None,
) -> dict[str, Any]:
    del memory_llm
    memory = load_system_memory(project_cache_dir)
    rows = memory.get("updates", [])
    if not isinstance(rows, list):
        rows = []
    for update in updates:
        if not isinstance(update, dict):
            continue
        row = dict(update)
        row.setdefault("stage", stage)
        rows.append(row)
        merge_system_memory_artifacts(memory, row.get("title"), row.get("summary"))
    if verified_findings:
        memory["verified_findings"] = verified_findings
    memory["updates"] = rows[-100:]
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
