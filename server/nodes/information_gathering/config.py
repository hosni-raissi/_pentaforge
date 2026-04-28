"""Configuration for the information-gathering node."""

from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_BLOCKED_STATIC_TOOLS: tuple[str, ...] = (
    "api_endpoint_discovery",
    "directory_file_fuzzing",
    "dns_enum_fuzzing",
    "param_discovery",
    "web_fuzz",
)

DEFAULT_BLOCKED_STATIC_COMMANDS: tuple[str, ...] = (
    "dirb",
    "feroxbuster",
    "ffuf",
    "gobuster",
    "hydra",
    "kiterunner",
    "nuclei",
    "sqlmap",
    "wfuzz",
    "x8",
)


@dataclass(frozen=True)
class InformationGatheringConfig:
    """Runtime settings for block preparation before static gathering."""

    llm_temperature: float = 0.0
    llm_max_tokens: int = 2800
    max_run_custom_additions_per_block: int = 1
    blocked_static_tools: tuple[str, ...] = DEFAULT_BLOCKED_STATIC_TOOLS
    blocked_static_commands: tuple[str, ...] = DEFAULT_BLOCKED_STATIC_COMMANDS


def get_information_gathering_config() -> InformationGatheringConfig:
    def _int(name: str, default: int) -> int:
        value = os.getenv(name, "").strip()
        if not value:
            return default
        try:
            return int(value)
        except ValueError:
            return default

    def _float(name: str, default: float) -> float:
        value = os.getenv(name, "").strip()
        if not value:
            return default
        try:
            return float(value)
        except ValueError:
            return default

    return InformationGatheringConfig(
        llm_temperature=_float("INFO_GATHERING_LLM_TEMPERATURE", 0.0),
        llm_max_tokens=_int("INFO_GATHERING_LLM_MAX_TOKENS", 2800),
        max_run_custom_additions_per_block=_int(
            "INFO_GATHERING_MAX_RUN_CUSTOM_ADDITIONS_PER_BLOCK",
            1,
        ),
    )
