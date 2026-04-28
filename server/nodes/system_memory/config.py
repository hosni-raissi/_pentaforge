"""Configuration for runtime system memory services."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SystemMemoryConfig:
    max_markdown_chars: int = 20000
    max_markdown_tokens: int = 4500
    compression_target_tokens: int = 1800
    compression_summary_chars: int = 1200
    llm_temperature: float = 0.0
    llm_prepare_max_tokens: int = 1000
    llm_organize_max_tokens: int = 1800
    llm_compress_max_tokens: int = 1600


def get_system_memory_config() -> SystemMemoryConfig:
    return SystemMemoryConfig()
