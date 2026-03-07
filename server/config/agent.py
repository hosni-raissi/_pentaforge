"""
Agent LLM Configuration — Pydantic-settings models for agent LLM backends.

Reads from environment variables (or .env file) with the prefix PLANNER_AGENT_LLM_.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class PlannerLLMConfig(BaseSettings):
    """Configuration for the planner agent's LLM backend.

    All values are read from environment variables prefixed with PLANNER_AGENT_LLM_.
    No hardcoded defaults for provider/model/url — they MUST be set in .env.
    """

    api_provider: str  # e.g. "groq", "openai", "together"
    model: str         # e.g. "llama-3.3-70b-versatile"
    api_url: str       # e.g. "https://api.groq.com/openai/v1"
    api_key: str
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2048, ge=1)

    model_config = {
        "env_prefix": "PLANNER_AGENT_LLM_",
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }


# Singleton — import and use directly.
planner_llm_config = PlannerLLMConfig()
