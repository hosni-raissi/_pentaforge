"""
Agent LLM Configuration — Backward compatibility wrapper.

All configuration is now centralized in server.core.llm.
This module re-exports the configuration for backward compatibility.
"""

from __future__ import annotations

# Re-export from the unified LLM module for backward compatibility
from server.core.llm import (
    LLMConfig as PublicLLMConfig,
    LLMConfig as LocalLLMConfig,
    public_llm_config,
    local_llm_config,
    llm_mode,
    get_llm_mode,
    get_config,
)

# Also export the LLMMode class for backward compat
class LLMMode:
    """Controls which LLM backend the planner uses: 'public' or 'local'."""

    @property
    def mode(self) -> str:
        return get_llm_mode()

__all__ = [
    "PublicLLMConfig",
    "LocalLLMConfig",
    "public_llm_config",
    "local_llm_config",
    "llm_mode",
    "LLMMode",
]
