"""Node that runs grouped information gathering and updates system memory."""

from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any, Awaitable, Callable

from server.core.llm import ChatMessage, get_llm, get_public_agent_config
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

    return None


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
        for item in original_tools:
            if isinstance(item, str):
                original_names.append(item.strip())
            elif isinstance(item, dict):
                # For objects, use the tool/name or a placeholder
                original_names.append(str(item.get("name") or item.get("tool") or "custom").strip())
        
        allowed_tool_names = {str(item).strip() for item in available_tools if str(item).strip()}

        tools: list[Any] = []
        removed_builtins: list[str] = []
        raw_tools = payload.get("tools", [])
        if isinstance(raw_tools, list):
            run_custom_count = 0
            for item in raw_tools:
                if isinstance(item, str) and item.strip():
                    tool_name = item.strip()
                    if self._is_blocked_static_tool(tool_name):
                        removed_builtins.append(tool_name)
                    elif tool_name in allowed_tool_names:
                        tools.append(tool_name)
                    else:
                        removed_builtins.append(tool_name)
                    continue
                if not isinstance(item, dict):
                    continue
                tool_name = str(item.get("name") or item.get("tool", "")).strip()
                if tool_name != "run_custom":
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

        if tools:
            prepared["tools"] = tools
        if str(payload.get("block_name") or payload.get("name", "")).strip():
            prepared["name"] = str(payload.get("block_name") or payload.get("name", "")).strip()
        if str(payload.get("goal", "")).strip():
            prepared["goal"] = str(payload.get("goal", "")).strip()
        if str(payload.get("interaction", "")).strip():
            prepared["interaction"] = str(payload.get("interaction", "")).strip()
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
            prepared_blocks.append(
                self._normalize_prepared_block(
                    original_block=original_block,
                    payload_block=payload_block,
                    available_tools=available_tools,
                )
            )
        return prepared_blocks

    async def _execute_block(
        self,
        *,
        prepared_block: dict[str, Any],
        memory: dict[str, Any],
        target: str,
        target_type: str,
        info: str,
        tool_map: dict[str, Any],
        tool_arg_builder: Callable[[str, str, str, str, dict[str, Any]], tuple[dict[str, Any] | None, str | None]],
    ) -> list[dict[str, Any]]:
        result_rows: list[dict[str, Any]] = []
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
                    # If it's the new style from the profile, 'args' contains the full command as a list
                    args_list = entry.get("args", [])
                    if not isinstance(args_list, list):
                        args_list = []

                    if "command" in entry:
                        # Old style: command + args
                        command = str(entry.get("command", "")).strip()
                        final_args = args_list
                    else:
                        # New style: args[0] is command, rest are args
                        if args_list:
                            command = args_list[0]
                            final_args = args_list[1:]
                        else:
                            command = ""
                            final_args = []

                    kwargs = {
                        "command": command,
                        "args": final_args,
                        "reason": str(entry.get("reason", "")).strip(),
                    }
                    skip_reason = None if kwargs["command"] else "skipped: run_custom command was empty"
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
                raw_result = await tool.execute(**kwargs)
                summary = str(raw_result or "").strip()
                if len(summary) > 600:
                    summary = summary[:597].rstrip() + "..."
                structured = _structured_snapshot(tool_name, raw_result)
                result_rows.append({
                    "tool": tool_name,
                    "status": "completed",
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
        memory = self._memory_node.initialize(
            project_id=project_id,
            scan_id=scan_id,
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
            profile=profile,
        )
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

        gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
        gathering["program"] = prepared_blocks
        gathering["status"] = "organized"
        memory["gathering"] = gathering
        memory = await self._memory_node.save(
            project_cache_dir,
            memory,
            progress_callback=progress_callback,
        )
        if pre_execution_gate is not None:
            await pre_execution_gate(memory)
            # Re-read organized program from memory after approval gate
            # in case the user edited the blocks/tools in the UI.
            gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
            prepared_blocks = gathering.get("program", prepared_blocks)
            if not isinstance(prepared_blocks, list):
                prepared_blocks = []

        pending_organized_task: asyncio.Task[dict[str, Any]] | None = None
        pending_meta: dict[str, Any] | None = None

        for index, prepared_block in enumerate(prepared_blocks, start=1):
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
