"""
Agent LLM Configuration — Pydantic-settings models for agent LLM backends.

Reads from environment variables (or .env file).
  - PLANNER_AGENT_LLM_MODE controls whether the planner uses "public" or "local".
  - PLANNER_AGENT_LLM_* configures the public (cloud) provider.
  - LOCAL_LLM_* configures the local Ollama instance.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class PlannerLLMMode(BaseSettings):
    """Controls which LLM backend the planner uses: 'public' or 'local'."""

    mode: str = Field(default="local", description="'public' for cloud API, 'local' for Ollama")

    model_config = {
        "env_prefix": "PLANNER_AGENT_LLM_",
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }


class PlannerLLMConfig(BaseSettings):
    """Configuration for the planner agent's public (cloud) LLM backend.

    All values are read from environment variables prefixed with PLANNER_AGENT_LLM_.
    Required only when PLANNER_AGENT_LLM_MODE=public.
    """

    api_provider: str = ""   # e.g. "groq", "openai", "together"
    model: str = ""          # e.g. "llama-3.3-70b-versatile"
    api_url: str = ""        # e.g. "https://api.groq.com/openai/v1"
    api_key: str = ""
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2048, ge=1)

    model_config = {
        "env_prefix": "PLANNER_AGENT_LLM_",
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }


class LocalLLMConfig(BaseSettings):
    """Configuration for the local Ollama LLM backend.

    All values are read from environment variables prefixed with LOCAL_LLM_.
    """

    model: str = Field(default="qwen3:4b", description="Ollama model name")
    api_url: str = Field(default="http://localhost:11434/v1", description="Ollama OpenAI-compatible endpoint")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2048, ge=1)

    model_config = {
        "env_prefix": "LOCAL_LLM_",
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }


# Singletons — import and use directly.
planner_llm_mode = PlannerLLMMode()
planner_llm_config = PlannerLLMConfig()
local_llm_config = LocalLLMConfig()
