"""System-memory node wrappers and runtime helpers."""

from .config import SystemMemoryConfig, get_system_memory_config
from .core import (
    SystemMemoryLLM,
    _loads_json_loose,
    _normalize_string_list,
    append_system_memory_updates,
    build_system_memory_prompt_block,
    compute_tool_efficiency_snapshot,
    initialize_system_memory,
    load_system_memory,
    merge_system_memory_artifacts,
    save_system_memory,
    store_system_memory_checklist,
    system_memory_dir,
    system_memory_paths,
)
from .node import SystemMemoryNode
from .schema import Brain, Finding, TechStack, ToolResult

def __getattr__(name: str):
    if name == "BrainBuilderNode":
        from .brain import BrainBuilderNode
        return BrainBuilderNode
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Brain",
    "BrainBuilderNode",
    "Finding",
    "SystemMemoryConfig",
    "SystemMemoryLLM",
    "SystemMemoryNode",
    "TechStack",
    "ToolResult",
    "_loads_json_loose",
    "_normalize_string_list",
    "append_system_memory_updates",
    "build_system_memory_prompt_block",
    "compute_tool_efficiency_snapshot",
    "get_system_memory_config",
    "initialize_system_memory",
    "load_system_memory",
    "merge_system_memory_artifacts",
    "save_system_memory",
    "store_system_memory_checklist",
    "system_memory_dir",
    "system_memory_paths",
]
