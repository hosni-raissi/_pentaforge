"""Node that runs grouped information gathering and updates system memory."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

from server.agents.executor.sandbox import build_sandbox_env, get_project_workspace_dir
from server.core.llm import ChatMessage, get_llm, get_public_agent_config
from server.core.tool import coerce_args_from_schema
from server.nodes.system_memory import (
    SystemMemoryNode,
    _loads_json_loose,
    _normalize_string_list,
)

from .config import InformationGatheringConfig, get_information_gathering_config
from .prompts import (
    PREPARE_INFORMATION_BLOCK_SYSTEM_PROMPT,
    build_information_block_preparation_prompt,
)


def _repository_checkout_relative_path(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""

    local_candidate = Path(raw).expanduser()
    if local_candidate.exists():
        return str(local_candidate.resolve())

    parsed = urlsplit(raw)
    path_text = parsed.path.rstrip("/")
    parts = [part for part in path_text.split("/") if part]
    if not parts:
        return ""

    repo_name = parts[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    if not repo_name:
        return ""

    owner = parts[-2] if len(parts) >= 2 else ""
    if owner:
        return str(Path("repos") / owner / repo_name)
    return repo_name


def _repository_checkout_absolute_path(project_id: str, target: str) -> str:
    relative = _repository_checkout_relative_path(target)
    if not relative:
        return ""

    candidate = Path(relative).expanduser()
    if candidate.is_absolute():
        return str(candidate.resolve())

    workspace = get_project_workspace_dir(project_id)
    return str((workspace / candidate).resolve())


def _ensure_repository_checkout(project_id: str, target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""

    local_candidate = Path(raw).expanduser()
    if local_candidate.exists():
        return str(local_candidate.resolve())

    relative = _repository_checkout_relative_path(raw)
    absolute = _repository_checkout_absolute_path(project_id, raw)
    if not relative or not absolute:
        return absolute

    checkout_dir = Path(absolute)
    if (checkout_dir / ".git").exists():
        return str(checkout_dir)
    if checkout_dir.exists() and any(checkout_dir.iterdir()):
        return str(checkout_dir)

    # Repository cloning is now handled by the UI uploading/cloning 
    # to the artifacts folder before the scan begins.
    # The scan shouldn't attempt to perform network clones directly.
    return str(checkout_dir)


def _build_target_placeholders(
    target: str,
    *,
    target_type: str = "",
    project_id: str = "",
) -> dict[str, str]:
    raw = str(target or "").strip()
    if not raw:
        return {
            "target": "",
            "raw_target": "",
            "trgt": "",
            "tgt": "",
            "host": "",
            "hostname": "",
            "full_trgt": "",
            "full_target": "",
            "url": "",
            "repo_url": "",
            "repo_path": "",
            "repo_abs_path": "",
        }

    normalized_target_type = str(target_type or "").strip().lower()
    if normalized_target_type == "repository":
        parsed = urlsplit(raw)
        host = str(parsed.hostname or "").strip().lower()
        repo_path = _repository_checkout_relative_path(raw)
        repo_abs_path = _repository_checkout_absolute_path(project_id, raw) if project_id else repo_path
        if Path(raw).expanduser().exists():
            repo_path = repo_abs_path or str(Path(raw).expanduser().resolve())
            repo_abs_path = repo_path
        return {
            "target": raw,
            "raw_target": raw,
            "trgt": repo_path,
            "tgt": repo_path,
            "host": host,
            "hostname": host,
            "full_trgt": raw,
            "full_target": raw,
            "url": raw,
            "repo_url": raw,
            "repo_path": repo_path,
            "repo_abs_path": repo_abs_path,
        }

    if normalized_target_type == "network":
        host = raw
        full_target = raw
    elif normalized_target_type in {"mobile", "container_image"} or raw.startswith("/"):
        host = raw
        full_target = raw
    else:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = str(parsed.hostname or "").strip().lower()
        if not host:
            host = raw.split("/", 1)[0].split(":", 1)[0].strip().lower()

        if "://" in raw:
            full_target = raw
        else:
            full_target = f"https://{raw.lstrip('/')}"

    return {
        "target": raw,
        "raw_target": raw,
        "trgt": host,
        "tgt": host,
        "host": host,
        "hostname": host,
        "full_trgt": full_target,
        "full_target": full_target,
        "url": full_target,
        "repo_url": "",
        "repo_path": "",
        "repo_abs_path": "",
    }


def _resolve_profile_value(value: Any, placeholders: dict[str, str]) -> Any:
    if isinstance(value, str):
        clean = value.strip()
        return placeholders.get(clean, value)
    if isinstance(value, list):
        return [_resolve_profile_value(item, placeholders) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _resolve_profile_value(item, placeholders)
            for key, item in value.items()
        }
    return value


def _normalize_profile_key(value: Any) -> str:
    return str(value or "").strip().lstrip("-").replace("-", "_")


def _looks_like_profile_key(token: Any, known_keys: set[str]) -> bool:
    if not isinstance(token, str):
        return False
    normalized = _normalize_profile_key(token)
    return token.startswith("-") or normalized in known_keys


def _build_profile_kwargs_from_args(
    raw_args: Any,
    *,
    tool: Any,
    placeholders: dict[str, str],
) -> dict[str, Any]:
    parameters = getattr(tool, "parameters", {}) if tool is not None else {}
    properties = parameters.get("properties", {}) if isinstance(parameters, dict) else {}
    known_keys = {
        str(key).strip()
        for key in properties.keys()
        if str(key).strip()
    }

    if isinstance(raw_args, dict):
        resolved = {
            _normalize_profile_key(key): _resolve_profile_value(value, placeholders)
            for key, value in raw_args.items()
            if _normalize_profile_key(key)
        }
    elif isinstance(raw_args, list):
        resolved: dict[str, Any] = {}
        index = 0
        while index < len(raw_args):
            key_token = raw_args[index]
            if not isinstance(key_token, str):
                index += 1
                continue
            key_name = _normalize_profile_key(key_token)
            if not key_name:
                index += 1
                continue

            next_value = raw_args[index + 1] if index + 1 < len(raw_args) else None
            next_is_key = _looks_like_profile_key(next_value, known_keys)
            if index + 1 < len(raw_args) and not next_is_key:
                resolved[key_name] = _resolve_profile_value(next_value, placeholders)
                index += 2
                continue

            resolved[key_name] = True
            index += 1
    else:
        return {}

    if known_keys:
        resolved = {
            key: value
            for key, value in resolved.items()
            if key in known_keys
        }
    return coerce_args_from_schema(parameters, resolved)


def _looks_like_web_target(target: str) -> bool:
    raw = str(target or "").strip().lower()
    if not raw:
        return False
    if raw.startswith(("http://", "https://")):
        return True
    parsed = urlsplit(f"//{raw}")
    return bool(parsed.hostname or parsed.netloc)


def _normalize_run_custom_args(
    command: str,
    args: list[str],
    placeholders: dict[str, str],
) -> list[str]:
    clean_command = str(command or "").strip().lower()
    if not clean_command or not args:
        return args

    url_flags_by_command = {
        "wappalyzer": {"-i"},
    }
    url_flags = url_flags_by_command.get(clean_command, set())
    if not url_flags:
        return args

    bare_target = placeholders.get("trgt", "")
    full_target = placeholders.get("full_trgt", "")
    if not bare_target or not full_target:
        return args

    normalized = list(args)
    index = 0
    while index < len(normalized) - 1:
        if normalized[index] in url_flags:
            candidate = str(normalized[index + 1] or "").strip()
            if candidate == bare_target or candidate == placeholders.get("host", ""):
                normalized[index + 1] = full_target
        index += 1
    return normalized


def _truncate_result_text(value: Any, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", str(value or "").strip())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _coerce_json_result(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith(("{", "[")):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


def _clean_result_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in {"none", "null"}:
        return ""
    return text


def _summarize_command_failure(detail: Any, *, return_code: Any = None) -> str:
    text = _clean_result_text(detail)
    lowered = text.lower()
    if "sandbox executor unavailable" in lowered:
        return (
            "Execution environment blocked: the shared tool sandbox executor was unavailable, "
            "so the command never reached the target."
        )
    if "traceback (most recent call last):" in lowered:
        return "Process failed with a Python traceback."
    if "pthread_create failed" in lowered and "sigabrt" in lowered:
        return "Process crashed with pthread_create resource error and SIGABRT."
    if "pthread_create failed" in lowered:
        return "Process crashed with pthread_create resource error."
    if "sigsegv" in lowered or "segmentation fault" in lowered or "status 11" in lowered:
        return "Process crashed with a segmentation fault."
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines:
        return _truncate_result_text(lines[0], limit=180)
    if return_code not in (None, ""):
        return f"Exited with code {return_code}."
    return ""


def _summarize_tool_result(tool_name: str, raw_result: Any) -> str:
    raw_result = _coerce_json_result(raw_result)
    clean_tool_name = str(tool_name or "").strip()
    if isinstance(raw_result, dict):
        command = str(
            raw_result.get("full_command")
            or raw_result.get("command")
            or clean_tool_name
            or "command"
        ).strip()
        if "return_code" in raw_result and ("command" in raw_result or "full_command" in raw_result):
            return_code = raw_result.get("return_code")
            try:
                rc_value = int(return_code)
            except Exception:
                rc_value = -1
            stderr = _clean_result_text(raw_result.get("stderr", ""))
            stdout = _clean_result_text(raw_result.get("stdout", ""))
            error = _clean_result_text(raw_result.get("error", ""))
            fallback_summary = _clean_result_text(raw_result.get("summary", ""))
            if rc_value == 0 and not error:
                return f"Custom command `{command}` completed successfully."
            detail = _summarize_command_failure(
                stderr or error or stdout or fallback_summary,
                return_code=return_code,
            )
            if detail:
                return f"Custom command `{command}` failed: {detail}"
            return f"Custom command `{command}` failed."

        if "success" in raw_result and "total_endpoints" in raw_result:
            total_endpoints = int(raw_result.get("total_endpoints", 0) or 0)
            total_vulnerable = int(raw_result.get("total_vulnerable", 0) or 0)
            if total_vulnerable > 0:
                return (
                    f"CORS analysis checked {total_endpoints} endpoints and found "
                    f"{total_vulnerable} vulnerable endpoints."
                )
            return f"CORS analysis checked {total_endpoints} endpoints and found no vulnerable endpoints."

        if "success" in raw_result and "tokens_collected" in raw_result:
            tokens = int(raw_result.get("tokens_collected", 0) or 0)
            if tokens > 0:
                return f"Session analysis collected {tokens} token samples."
            error = str(raw_result.get("error", "")).strip()
            if error:
                return _truncate_result_text(error, limit=180)
            return "Session analysis collected no session tokens."

        for key in ("summary", "result", "error"):
            value = _clean_result_text(raw_result.get(key, ""))
            if value:
                return _truncate_result_text(value, limit=220)

        return _truncate_result_text(json.dumps(raw_result, ensure_ascii=True), limit=220)

    return _truncate_result_text(str(raw_result or "").strip(), limit=220)


def _tool_execution_status(raw_result: Any) -> str:
    raw_result = _coerce_json_result(raw_result)
    if isinstance(raw_result, dict):
        if "return_code" in raw_result:
            try:
                rc = raw_result.get("return_code")
                rc = 1 if rc is None else int(rc)
                return "completed" if rc == 0 else "error"
            except Exception:
                return "error"
        if "success" in raw_result:
            return "completed" if bool(raw_result.get("success")) else "error"
    return "completed"


def _structured_snapshot(tool_name: str, raw_result: Any) -> dict[str, Any] | None:
    if isinstance(raw_result, dict):
        payload = raw_result
    else:
        text = str(raw_result or "").strip()
        if not text or not text.startswith(("{", "[")):
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None

    if not isinstance(payload, dict):
        return None

    clean_tool_name = str(tool_name or "").strip().lower()
    if clean_tool_name == "detect_tech":
        rows = []
        for item in payload.get("technologies", []) if isinstance(payload.get("technologies"), list) else []:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "name": str(item.get("name", "")).strip(),
                    "version": str(item.get("version", "")).strip(),
                    "version_normalized": str(item.get("version_normalized", "")).strip(),
                    "category": str(item.get("category", "")).strip(),
                    "confidence": item.get("confidence"),
                }
            )
        return {
            "tool": clean_tool_name,
            "http_status": payload.get("http_status"),
            "technologies": rows[:24],
        }

    if clean_tool_name == "http_probe":
        hosts = []
        for item in payload.get("hosts", []) if isinstance(payload.get("hosts"), list) else []:
            if not isinstance(item, dict):
                continue
            hosts.append(
                {
                    "url": str(item.get("url", "")).strip(),
                    "status_code": item.get("status_code"),
                    "webserver": str(item.get("webserver", "")).strip(),
                    "tech": [
                        str(value).strip()
                        for value in item.get("tech", [])
                        if str(value).strip()
                    ][:10]
                    if isinstance(item.get("tech"), list)
                    else [],
                }
            )
        return {
            "tool": clean_tool_name,
            "hosts": hosts[:10],
            "total_alive": payload.get("total_alive"),
        }

    if clean_tool_name == "http_header_analysis":
        endpoints = []
        for item in payload.get("endpoints", []) if isinstance(payload.get("endpoints"), list) else []:
            if not isinstance(item, dict):
                continue
            endpoints.append(
                {
                    "url": str(item.get("url", "")).strip(),
                    "status_code": item.get("status_code"),
                    "server": str(item.get("server", "")).strip(),
                    "x_powered_by": str(item.get("x_powered_by", "")).strip(),
                    "grade": str(item.get("grade", "")).strip(),
                    "vulnerable": bool(item.get("vulnerable")),
                    "missing_headers": [
                        str(value).strip()
                        for value in item.get("missing_headers", [])
                        if str(value).strip()
                    ][:8]
                    if isinstance(item.get("missing_headers"), list)
                    else [],
                }
            )
        return {
            "tool": clean_tool_name,
            "average_grade": str(payload.get("average_grade", "")).strip(),
            "total_vulnerable": payload.get("total_vulnerable"),
            "endpoints": endpoints[:10],
        }

    if clean_tool_name == "js_source_code_analyzer":
        return {
            "tool": clean_tool_name,
            "js_urls": [
                str(value).strip()
                for value in payload.get("js_urls", [])
                if str(value).strip()
            ][:20]
            if isinstance(payload.get("js_urls"), list)
            else [],
            "endpoints": [
                str(value).strip()
                for value in payload.get("endpoints", [])
                if str(value).strip()
            ][:20]
            if isinstance(payload.get("endpoints"), list)
            else [],
        }

    if clean_tool_name == "known_vuln_lookup":
        return {
            "tool": clean_tool_name,
            "products": payload.get("products", []) if isinstance(payload.get("products"), list) else [],
            "signals": payload.get("signals", []) if isinstance(payload.get("signals"), list) else [],
            "nuclei_hints": payload.get("nuclei_hints", {}) if isinstance(payload.get("nuclei_hints"), dict) else {},
        }

    if clean_tool_name == "passive_web_recon":
        return {
            "tool": clean_tool_name,
            "normalized_domain": str(payload.get("normalized_domain", "")).strip(),
            "subdomains": [
                str(value).strip()
                for value in payload.get("subdomains", [])
                if str(value).strip()
            ][:20]
            if isinstance(payload.get("subdomains"), list)
            else [],
            "historical_urls": [
                str(value).strip()
                for value in payload.get("historical_urls", [])
                if str(value).strip()
            ][:20]
            if isinstance(payload.get("historical_urls"), list)
            else [],
            "ip_history": [
                str(value).strip()
                for value in payload.get("ip_history", [])
                if str(value).strip()
            ][:10]
            if isinstance(payload.get("ip_history"), list)
            else [],
            "api_candidates": [
                str(value).strip()
                for value in payload.get("api_candidates", [])
                if str(value).strip()
            ][:20]
            if isinstance(payload.get("api_candidates"), list)
            else [],
        }

    return None


@contextmanager
def _information_gathering_tool_context(
    *,
    project_id: str,
    scan_id: str,
    project_cache_dir: str,
    target: str,
    tool_name: str,
):
    try:
        from server.agents.executor.base import _executer_tool_context
    except Exception:
        yield
        return

    token = _executer_tool_context.set(
        {
            "project_id": str(project_id or "").strip(),
            "project_cache_dir": str(project_cache_dir or "").strip(),
            "scan_id": str(scan_id or "").strip(),
            "role": "information_gathering",
            "tool": str(tool_name or "").strip(),
            "target_url": str(target or "").strip(),
        }
    )
    try:
        yield
    finally:
        _executer_tool_context.reset(token)


class InformationGatheringNode:
    """Grouped deterministic gathering with LLM-guided block preparation."""

    def __init__(
        self,
        *,
        config: InformationGatheringConfig | None = None,
        memory_node: SystemMemoryNode | None = None,
    ) -> None:
        self._config = config or get_information_gathering_config()
        self._memory_node = memory_node or SystemMemoryNode()
        self._llm_config = get_public_agent_config("information_gathering")

    def _is_blocked_static_tool(self, tool_name: str) -> bool:
        return tool_name.strip().lower() in {
            item.strip().lower()
            for item in self._config.blocked_static_tools
            if item.strip()
        }

    def _is_blocked_static_command(self, command: str) -> bool:
        return command.strip().lower() in {
            item.strip().lower()
            for item in self._config.blocked_static_commands
            if item.strip()
        }

    def _format_tool_execution_command(self, tool_name: str, kwargs: dict[str, Any]) -> str:
        if tool_name == "run_custom":
            command = str(kwargs.get("command", "")).strip()
            args = kwargs.get("args", [])
            rendered_args = " ".join(shlex.quote(str(arg)) for arg in args if str(arg).strip())
            return f"{command} {rendered_args}".strip()
        rendered_parts: list[str] = []
        for key, value in kwargs.items():
            if value in ("", None, [], {}):
                continue
            rendered_parts.append(f"{key}={json.dumps(value, ensure_ascii=True)}")
        return f"{tool_name}({', '.join(rendered_parts)})"

    def _normalize_prepared_block(
        self,
        *,
        original_block: dict[str, Any],
        payload_block: dict[str, Any] | None,
        available_tools: list[str],
    ) -> dict[str, Any]:
        prepared = dict(original_block)
        payload = payload_block if isinstance(payload_block, dict) else {}
        original_tools = original_block.get("tools", [])
        original_names = []
        original_named_entries: list[tuple[str, Any]] = []
        for item in original_tools:
            if isinstance(item, str):
                clean_name = item.strip()
                original_names.append(clean_name)
                original_named_entries.append((clean_name, item))
            elif isinstance(item, dict):
                # For objects, use the tool/name or a placeholder
                clean_name = str(item.get("name") or item.get("tool") or "custom").strip()
                original_names.append(clean_name)
                original_named_entries.append((clean_name, item))
        
        allowed_tool_names = {str(item).strip() for item in available_tools if str(item).strip()}

        tools: list[Any] = []
        removed_builtins: list[str] = []
        requested_keep_names: set[str] = set()
        requested_keep_order: list[str] = []
        has_explicit_keep_selection = False
        raw_tools = payload.get("tools", [])
        if isinstance(raw_tools, list):
            run_custom_count = 0
            for item in raw_tools:
                if isinstance(item, str) and item.strip():
                    tool_name = item.strip()
                    has_explicit_keep_selection = True
                    if self._is_blocked_static_tool(tool_name):
                        removed_builtins.append(tool_name)
                    elif tool_name in allowed_tool_names:
                        requested_keep_names.add(tool_name)
                        if tool_name not in requested_keep_order:
                            requested_keep_order.append(tool_name)
                    else:
                        removed_builtins.append(tool_name)
                    continue
                if not isinstance(item, dict):
                    continue
                tool_name = str(item.get("name") or item.get("tool", "")).strip()
                if tool_name != "run_custom":
                    has_explicit_keep_selection = True
                    if self._is_blocked_static_tool(tool_name):
                        removed_builtins.append(tool_name)
                    elif tool_name in allowed_tool_names:
                        requested_keep_names.add(tool_name)
                        if tool_name not in requested_keep_order:
                            requested_keep_order.append(tool_name)
                    else:
                        removed_builtins.append(tool_name)
                    continue
                if run_custom_count >= self._config.max_run_custom_additions_per_block:
                    continue
                command = str(item.get("command", "")).strip()
                if not command:
                    continue
                args = item.get("args", [])
                args = [str(arg).strip() for arg in args if str(arg).strip()] if isinstance(args, list) else []
                if " " in command:
                    try:
                        parts = shlex.split(command)
                    except ValueError:
                        parts = []
                    if parts:
                        command = parts[0]
                        args = parts[1:] + args
                if self._is_blocked_static_command(command):
                    removed_builtins.append(f"run_custom:{command}")
                    continue
                reason = str(item.get("reason", "")).strip() or "Scoped addition from information-gathering block preparation."
                tools.append(
                    {
                        "name": "run_custom",
                        "command": command,
                        "args": args,
                        "reason": reason,
                    }
                )
                run_custom_count += 1

        base_tools: list[Any]
        if has_explicit_keep_selection:
            base_tools = [
                entry
                for tool_name, entry in original_named_entries
                if tool_name in requested_keep_names
            ]
            kept_names = {
                tool_name
                for tool_name, _entry in original_named_entries
                if tool_name in requested_keep_names
            }
            for tool_name in requested_keep_order:
                if tool_name not in kept_names:
                    base_tools.append(tool_name)
            for tool_name, _entry in original_named_entries:
                if tool_name not in requested_keep_names and tool_name not in removed_builtins:
                    removed_builtins.append(tool_name)
        else:
            base_tools = [entry for _tool_name, entry in original_named_entries]

        prepared["tools"] = base_tools + tools
        if str(payload.get("status", "")).strip():
            prepared["status"] = str(payload.get("status", "")).strip().lower()
        prepared["selection_rationale"] = str(payload.get("rationale", "")).strip()
        prepared["skipped_tools"] = _normalize_string_list(
            payload.get("skipped_tools"),
            limit=12,
        )
        for tool_name in removed_builtins:
            if tool_name not in prepared["skipped_tools"]:
                prepared["skipped_tools"].append(tool_name)

        skipped_names = {item.strip().lower() for item in prepared["skipped_tools"] if item.strip()}
        filtered_tools: list[Any] = []
        for item in prepared.get("tools", []):
            if isinstance(item, str):
                if item.strip().lower() in skipped_names:
                    continue
                filtered_tools.append(item)
                continue
            if isinstance(item, dict):
                tool_name = str(item.get("name") or item.get("tool", "")).strip().lower()
                command_name = str(item.get("command", "")).strip().lower()
                if tool_name in skipped_names or (tool_name == "run_custom" and command_name in skipped_names):
                    continue
                filtered_tools.append(item)
        prepared["tools"] = filtered_tools

        if "tools" not in prepared:
            prepared["tools"] = original_names
        prepared.setdefault("status", "keep")
        prepared.setdefault("selection_rationale", "")
        if not prepared.get("skipped_tools"):
            kept_names = set()
            for item in prepared.get("tools", []):
                if isinstance(item, str):
                    kept_names.add(item.strip().lower())
                elif isinstance(item, dict):
                    kept_names.add(str(item.get("name") or item.get("tool", "")).strip().lower())
            prepared["skipped_tools"] = [
                item for item in original_names if item.lower() not in kept_names
            ]
        if not prepared.get("tools"):
            prepared["status"] = "skip"
        elif str(prepared.get("status", "")).strip().lower() == "skip":
            prepared["status"] = "refine"
        if str(prepared.get("status", "")).strip().lower() == "skip":
            prepared["tools"] = []
        return prepared

    async def _prepare_blocks(
        self,
        *,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        profile: dict[str, Any],
        valid_blocks: list[dict[str, Any]],
        available_tools: list[str],
    ) -> list[dict[str, Any]]:
        prompt = build_information_block_preparation_prompt(
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
            profile=profile,
            available_tools=available_tools,
        )
        payload: dict[str, Any] | None = None
        try:
            async with get_llm(self._llm_config) as llm:
                response = await llm.chat(
                    [
                        ChatMessage(role="system", content=PREPARE_INFORMATION_BLOCK_SYSTEM_PROMPT),
                        ChatMessage(role="user", content=prompt),
                    ],
                    temperature=self._config.llm_temperature,
                    max_tokens=self._config.llm_max_tokens,
                )
            payload = _loads_json_loose(response.content or "")
        except Exception:
            payload = None

        raw_blocks = payload.get("blocks", []) if isinstance(payload, dict) else []
        prepared_blocks: list[dict[str, Any]] = []
        for index, original_block in enumerate(valid_blocks):
            payload_block = raw_blocks[index] if isinstance(raw_blocks, list) and index < len(raw_blocks) else None
            prepared_block = self._normalize_prepared_block(
                original_block=original_block,
                payload_block=payload_block,
                available_tools=available_tools,
            )
            block_id = str(original_block.get("id", "")).strip().lower()
            normalized_target_type = str(target_type or "").strip().lower()
            if (
                block_id in {"fingerprinting", "transport_and_headers"}
                and normalized_target_type in {"web_app", "api"}
                and _looks_like_web_target(target)
                and str(prepared_block.get("status", "")).strip().lower() == "skip"
            ):
                # Low-noise fingerprinting is a core web/API static gathering step.
                # Do not let the planner skip it on normal reachable web targets
                # unless the profile itself is incompatible.
                prepared_block["status"] = "keep"
                prepared_block["tools"] = list(original_block.get("tools", []))
                prepared_block["selection_rationale"] = (
                    str(prepared_block.get("selection_rationale", "")).strip()
                    or "Fingerprinting preserved as a required low-noise web/API profiling block."
                )
                skipped = prepared_block.get("skipped_tools", [])
                if isinstance(skipped, list):
                    prepared_block["skipped_tools"] = [
                        item for item in skipped if str(item).strip().lower() not in {"run_custom", "http_probe"}
                    ]
            if normalized_target_type == "repository":
                block_id = str(original_block.get("id", "")).strip().lower()
                repository_builtin_fallbacks = {
                    "code_security_review": ["sast_scan"],
                }
                fallback_tools = repository_builtin_fallbacks.get(block_id, [])
                if fallback_tools and all(tool_name in available_tools for tool_name in fallback_tools):
                    if (
                        str(prepared_block.get("status", "")).strip().lower() == "skip"
                        or not prepared_block.get("tools")
                    ):
                        prepared_block["status"] = "refine"
                        prepared_block["tools"] = list(fallback_tools)
                        prepared_block["selection_rationale"] = (
                            str(prepared_block.get("selection_rationale", "")).strip()
                            or "Repository static review converted to authorized built-in repository tools."
                        )
                        prepared_block["skipped_tools"] = [
                            item
                            for item in prepared_block.get("skipped_tools", [])
                            if str(item).strip().lower() not in {tool_name.lower() for tool_name in fallback_tools}
                        ]
            prepared_blocks.append(prepared_block)
        return prepared_blocks

    async def _execute_block(
        self,
        *,
        project_id: str,
        scan_id: str,
        project_cache_dir: str,
        prepared_block: dict[str, Any],
        memory: dict[str, Any],
        target: str,
        target_type: str,
        info: str,
        tool_map: dict[str, Any],
        tool_arg_builder: Callable[[str, str, str, str, dict[str, Any]], tuple[dict[str, Any] | None, str | None]],
    ) -> list[dict[str, Any]]:
        result_rows: list[dict[str, Any]] = []
        normalized_target_type = str(target_type or "").strip().lower()
        if normalized_target_type == "repository":
            checkout_path = _ensure_repository_checkout(project_id, target)
            runtime_state = memory.get("target_runtime")
            if not isinstance(runtime_state, dict):
                runtime_state = {}
            if checkout_path:
                runtime_state["repository_checkout_path"] = checkout_path
            memory["target_runtime"] = runtime_state
        target_placeholders = _build_target_placeholders(
            target,
            target_type=target_type,
            project_id=project_id,
        )
        if str(prepared_block.get("status", "")).strip().lower() == "skip":
            result_rows.append({
                "tool": "__block__",
                "status": "skipped",
                "summary": str(
                    prepared_block.get("selection_rationale", "")
                    or "skipped: block marked incompatible or unauthorized for this target"
                ).strip(),
                "args": {},
            })
            return result_rows

        for entry in prepared_block.get("tools", []):
            if isinstance(entry, dict):
                tool_name = str(entry.get("name") or entry.get("tool", "")).strip()
                if tool_name == "run_custom":
                    args_list = entry.get("args", [])
                    resolved_args = [
                        str(_resolve_profile_value(item, target_placeholders)).strip()
                        for item in args_list
                    ] if isinstance(args_list, list) else []
                    resolved_args = [item for item in resolved_args if item]

                    command = str(
                        _resolve_profile_value(entry.get("command", ""), target_placeholders)
                    ).strip()
                    final_args = resolved_args
                    if not command and resolved_args:
                        command = resolved_args[0]
                        final_args = resolved_args[1:]
                    final_args = _normalize_run_custom_args(command, final_args, target_placeholders)

                    default_reason = (
                        f"Profile-defined information gathering step for {command or 'custom command'} "
                        f"against {target_placeholders.get('trgt') or target}."
                    )
                    kwargs = {
                        "command": command,
                        "args": final_args,
                        "reason": str(entry.get("reason", "")).strip() or default_reason,
                    }
                    if "timeout" in entry:
                        kwargs["timeout"] = entry.get("timeout")
                    if isinstance(entry.get("env"), dict):
                        kwargs["env"] = entry.get("env")
                    if str(entry.get("cwd", "")).strip():
                        kwargs["cwd"] = str(entry.get("cwd", "")).strip()
                    skip_reason = None if kwargs["command"] else "skipped: run_custom command was empty"
                else:
                    tool = tool_map.get(tool_name)
                    explicit_kwargs = _build_profile_kwargs_from_args(
                        entry.get("args"),
                        tool=tool,
                        placeholders=target_placeholders,
                    )
                    if explicit_kwargs:
                        kwargs, skip_reason = explicit_kwargs, None
                    else:
                        kwargs, skip_reason = tool_arg_builder(tool_name, target, target_type, info, memory)
            else:
                tool_name = str(entry).strip()
                kwargs, skip_reason = tool_arg_builder(tool_name, target, target_type, info, memory)

            if skip_reason:
                result_rows.append({
                    "tool": tool_name,
                    "status": "skipped",
                    "summary": skip_reason,
                    "args": kwargs or {},
                })
                continue
            tool = tool_map.get(tool_name)
            if tool is None or kwargs is None:
                result_rows.append({
                    "tool": tool_name,
                    "status": "skipped",
                    "summary": "skipped: tool is not registered for this target type",
                    "args": kwargs or {},
                })
                continue
            try:
                with _information_gathering_tool_context(
                    project_id=project_id,
                    scan_id=scan_id,
                    project_cache_dir=project_cache_dir,
                    target=target,
                    tool_name=tool_name,
                ):
                    raw_result = await tool.execute(**kwargs)
                summary = _summarize_tool_result(tool_name, raw_result)
                structured = _structured_snapshot(tool_name, raw_result)
                result_rows.append({
                    "tool": tool_name,
                    "status": _tool_execution_status(raw_result),
                    "summary": summary,
                    "args": kwargs,
                    "command": self._format_tool_execution_command(tool_name, kwargs),
                    "structured": structured,
                })
            except Exception as exc:
                result_rows.append({
                    "tool": tool_name,
                    "status": "error",
                    "summary": f"error: {str(exc)[:240]}",
                    "args": kwargs,
                    "command": self._format_tool_execution_command(tool_name, kwargs),
                })
        return result_rows

    async def _organize_block_result(
        self,
        *,
        prepared_block: dict[str, Any],
        target: str,
        target_type: str,
        scope: str,
        info: str,
        raw_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return await self._memory_node.llm.organize_block(
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
            block=prepared_block,
            raw_results=raw_results,
        )

    async def _store_organized_block(
        self,
        *,
        memory: dict[str, Any],
        project_cache_dir: str,
        organized_block: dict[str, Any],
        progress_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
        block_rows = gathering.get("blocks", []) if isinstance(gathering.get("blocks"), list) else []
        block_rows.append(organized_block)
        gathering["blocks"] = block_rows
        gathering["status"] = "running"
        memory["gathering"] = gathering
        self._memory_node.merge_artifacts(
            memory,
            organized_block.get("name"),
            organized_block.get("goal"),
            organized_block.get("summary"),
            *(organized_block.get("artifacts", []) if isinstance(organized_block.get("artifacts"), list) else []),
        )
        for result in organized_block.get("results", []) if isinstance(organized_block.get("results"), list) else []:
            if not isinstance(result, dict):
                continue
            self._memory_node.merge_artifacts(
                memory,
                result.get("summary"),
                *(result.get("artifacts", []) or []),
            )
        return await self._memory_node.save(
            project_cache_dir,
            memory,
            progress_callback=progress_callback,
        )

    async def run(
        self,
        *,
        project_id: str,
        scan_id: str,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        profile: dict[str, Any],
        project_cache_dir: str,
        tool_map: dict[str, Any],
        tool_arg_builder: Callable[[str, str, str, str, dict[str, Any]], tuple[dict[str, Any] | None, str | None]],
        progress_callback: Callable[[str, dict[str, Any]], None] | None = None,
        pre_execution_gate: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> dict[str, Any]:
        memory = self._memory_node.load(project_cache_dir)
        gathering_state = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
        if str(gathering_state.get("status", "")).strip().lower() == "completed":
            return memory

        overview = memory.get("overview", {}) if isinstance(memory.get("overview"), dict) else {}
        if not str(overview.get("target", "")).strip():
            memory = self._memory_node.initialize(
                project_id=project_id,
                scan_id=scan_id,
                target=target,
                target_type=target_type,
                scope=scope,
                info=info,
                profile=profile,
            )
        else:
            overview["scan_id"] = scan_id
            memory["overview"] = overview
            
        memory = await self._memory_node.save(
            project_cache_dir,
            memory,
            progress_callback=progress_callback,
        )

        blocks = profile.get("blocks", []) if isinstance(profile, dict) else []
        valid_blocks = [block for block in blocks if isinstance(block, dict)]
        available_tools = sorted(
            str(tool_name).strip()
            for tool_name in tool_map.keys()
            if str(tool_name).strip()
        )

        if gathering_state.get("program"):
            prepared_blocks = gathering_state.get("program")
        else:
            prepared_blocks = await self._prepare_blocks(
                target=target,
                target_type=target_type,
                scope=scope,
                info=info,
                profile=profile,
                valid_blocks=valid_blocks,
                available_tools=available_tools,
            )

            if progress_callback:
                progress_callback(
                    "program_organized",
                    {
                        "total": len(prepared_blocks),
                        "paths": memory.get("paths", {}),
                        "blocks": [
                            {
                                "id": str(block.get("id", "")).strip(),
                                "name": str(block.get("name", "")).strip(),
                                "status": str(block.get("status", "keep")).strip().lower() or "keep",
                                "planned_tools": block.get("tools", []),
                                "selection_rationale": str(block.get("selection_rationale", "")).strip(),
                                "skipped_tools": block.get("skipped_tools", []),
                            }
                            for block in prepared_blocks
                            if isinstance(block, dict)
                        ],
                    },
                )

            gathering_state["program"] = prepared_blocks
            gathering_state["status"] = "organized"
            memory["gathering"] = gathering_state
            memory = await self._memory_node.save(
                project_cache_dir,
                memory,
                progress_callback=progress_callback,
            )
            if pre_execution_gate is not None:
                await pre_execution_gate(memory)
                # Re-read organized program from memory after approval gate
                # in case the user edited the blocks/tools in the UI.
                gathering_state = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
                prepared_blocks = gathering_state.get("program", prepared_blocks)
                if not isinstance(prepared_blocks, list):
                    prepared_blocks = []

        completed_block_ids = {
            str(b.get("id", "")).strip() 
            for b in gathering_state.get("blocks", []) 
            if isinstance(b, dict) and str(b.get("id", "")).strip()
        }

        pending_organized_task: asyncio.Task[dict[str, Any]] | None = None
        pending_meta: dict[str, Any] | None = None

        for index, prepared_block in enumerate(prepared_blocks, start=1):
            block_id = str(prepared_block.get("id", "")).strip()
            if block_id and block_id in completed_block_ids:
                continue

            original_block = valid_blocks[index - 1] if index - 1 < len(valid_blocks) else {}
            if progress_callback:
                progress_callback(
                    "block_started",
                    {
                        "id": str(prepared_block.get("id", original_block.get("id", ""))).strip(),
                        "name": str(prepared_block.get("name", original_block.get("name", ""))).strip(),
                        "goal": str(prepared_block.get("goal", original_block.get("goal", ""))).strip(),
                        "index": index,
                        "total": len(prepared_blocks),
                        "planned_tools": prepared_block.get("tools", []),
                        "selection_rationale": str(prepared_block.get("selection_rationale", "")).strip(),
                        "skipped_tools": prepared_block.get("skipped_tools", []),
                    },
                )

            result_rows = await self._execute_block(
                project_id=project_id,
                scan_id=scan_id,
                project_cache_dir=project_cache_dir,
                prepared_block=prepared_block,
                memory=memory,
                target=target,
                target_type=target_type,
                info=info,
                tool_map=tool_map,
                tool_arg_builder=tool_arg_builder,
            )

            current_task = asyncio.create_task(
                self._organize_block_result(
                    prepared_block=prepared_block,
                    target=target,
                    target_type=target_type,
                    scope=scope,
                    info=info,
                    raw_results=result_rows,
                )
            )

            if pending_organized_task is not None and pending_meta is not None:
                organized_block = await pending_organized_task
                memory = await self._store_organized_block(
                    memory=memory,
                    project_cache_dir=project_cache_dir,
                    organized_block=organized_block,
                    progress_callback=progress_callback,
                )
                if progress_callback:
                    progress_callback(
                        "block_completed",
                        {
                            "index": pending_meta.get("index", "?"),
                            "total": len(prepared_blocks),
                            **organized_block,
                        },
                    )

            pending_organized_task = current_task
            pending_meta = {"index": index}

        if pending_organized_task is not None and pending_meta is not None:
            organized_block = await pending_organized_task
            memory = await self._store_organized_block(
                memory=memory,
                project_cache_dir=project_cache_dir,
                organized_block=organized_block,
                progress_callback=progress_callback,
            )
            if progress_callback:
                progress_callback(
                    "block_completed",
                    {
                        "index": pending_meta.get("index", "?"),
                        "total": len(prepared_blocks),
                        **organized_block,
                    },
                )

        gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
        gathering["status"] = "completed"
        memory["gathering"] = gathering
        return await self._memory_node.save(
            project_cache_dir,
            memory,
            progress_callback=progress_callback,
        )
