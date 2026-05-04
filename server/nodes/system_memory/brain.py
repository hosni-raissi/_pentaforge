"""Brain-building lives inside system_memory because it is a projection of the same node."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from server.nodes.information_gathering import InformationGatheringNode
from .node import SystemMemoryNode
from .schema import Brain


class BrainBuilderNode:
    """Compatibility wrapper for building structured brain projections from system memory."""

    def __init__(
        self,
        *,
        memory_node: SystemMemoryNode | None = None,
        gathering_node: InformationGatheringNode | None = None,
    ) -> None:
        self._memory_node = memory_node or SystemMemoryNode()
        self._gathering_node = gathering_node or InformationGatheringNode(
            memory_node=self._memory_node,
        )

    @property
    def memory_node(self) -> SystemMemoryNode:
        return self._memory_node

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
        return await self._gathering_node.run(
            project_id=project_id,
            scan_id=scan_id,
            target=target,
            target_type=target_type,
            scope=scope,
            info=info,
            profile=profile,
            project_cache_dir=project_cache_dir,
            tool_map=tool_map,
            tool_arg_builder=tool_arg_builder,
            progress_callback=progress_callback,
            pre_execution_gate=pre_execution_gate,
        )

    def build_structured_brain(self, memory: dict[str, Any]) -> dict[str, Any]:
        gathering = memory.get("gathering", {}) if isinstance(memory.get("gathering"), dict) else {}
        brain = Brain.from_system_memory(memory if isinstance(memory, dict) else {})
        return {
            "status": str(gathering.get("status", "")).strip(),
            "program": gathering.get("program", []) if isinstance(gathering.get("program"), list) else [],
            "blocks": gathering.get("blocks", []) if isinstance(gathering.get("blocks"), list) else [],
            "paths": memory.get("paths", {}) if isinstance(memory.get("paths"), dict) else {},
            "brain": brain.to_dict(),
            "projections": {
                "planner": brain.for_planner(),
                "executor": brain.for_executor(),
                "analyzer": brain.for_analyzer(),
            },
        }
