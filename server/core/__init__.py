"""PentaForge Core — LLM client, tool abstractions, and shared agent utilities."""

from .llm import (
    LLMClient,
    LLMConfig,
    LLMResponse,
    ChatMessage,
    get_llm,
    get_config,
    get_llm_mode,
    # Backward compatibility
    PublicLLMConfig,
    LocalLLMConfig,
    public_llm_config,
    local_llm_config,
    llm_mode,
)
from .tool import Tool, tool

__all__ = [
    # LLM
    "LLMClient",
    "LLMConfig",
    "LLMResponse",
    "ChatMessage",
    "get_llm",
    "get_config",
    "get_llm_mode",
    # Backward compat
    "PublicLLMConfig",
    "LocalLLMConfig",
    "public_llm_config",
    "local_llm_config",
    "llm_mode",
    # Tools
    "Tool",
    "tool",
]
