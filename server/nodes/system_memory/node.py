"""Node wrapper around runtime system-memory services."""

from __future__ import annotations

from typing import Any, Callable

from . import (
    SystemMemoryLLM,
    append_system_memory_updates,
    build_system_memory_prompt_block,
    get_system_memory_config,
    initialize_system_memory,
    load_system_memory,
    merge_system_memory_artifacts,
    save_system_memory,
    store_system_memory_checklist,
    system_memory_dir,
    system_memory_paths,
)


class SystemMemoryNode:
    """Stable node contract for runtime memory management."""

    def __init__(self) -> None:
        self._config = get_system_memory_config()
        self._llm = SystemMemoryLLM(self._config)

    @property
    def llm(self) -> SystemMemoryLLM:
        return self._llm

    @property
    def config(self) -> Any:
        return self._config

    def initialize(
        self,
        *,
        project_id: str,
        scan_id: str,
        target: str,
        target_type: str,
        scope: str,
        info: str,
        profile: dict[str, Any],
    ) -> dict[str, Any]:
        return initialize_system_memory(
            project_id=project_id,
            scan_id=scan_id,
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
            profile=profile,
        )

    def load(self, project_cache_dir: str) -> dict[str, Any]:
        return load_system_memory(project_cache_dir)

    async def save(
        self,
        project_cache_dir: str,
        memory: dict[str, Any],
        *,
        progress_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        return await save_system_memory(
            project_cache_dir,
            memory,
            memory_llm=self._llm,
            config=self._config,
            progress_callback=progress_callback,
        )

    async def append_updates(
        self,
        project_cache_dir: str,
        *,
        stage: str,
        updates: list[dict[str, Any]],
        verified_findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return await append_system_memory_updates(
            project_cache_dir,
            stage=stage,
            updates=updates,
            verified_findings=verified_findings,
            memory_llm=self._llm,
            config=self._config,
        )

    async def store_checklist(
        self,
        project_cache_dir: str,
        *,
        checklist: dict[str, Any],
    ) -> dict[str, Any]:
        return await store_system_memory_checklist(
            project_cache_dir,
            checklist=checklist,
            memory_llm=self._llm,
            config=self._config,
        )

    def build_prompt_block(self, memory: dict[str, Any]) -> str:
        return build_system_memory_prompt_block(memory)

    def merge_artifacts(self, memory: dict[str, Any], *values: Any) -> None:
        merge_system_memory_artifacts(memory, *values)

    def directory(self, project_cache_dir: str) -> str:
        return system_memory_dir(project_cache_dir)

    def paths(self, project_cache_dir: str) -> tuple[str, str]:
        return system_memory_paths(project_cache_dir)
