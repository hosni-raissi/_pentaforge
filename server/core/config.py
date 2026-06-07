"""Centralized configuration management for PentaForge LLMs."""

import os
from typing import List
from pydantic import BaseModel, Field

class LLMProfile(BaseModel):
    id: str = Field(alias="LLM_ID")
    provider: str = Field(alias="LLM_PROVIDER")
    model: str = Field(alias="LLM_MODEL")
    api_url: str = Field(alias="LLM_API_URL")
    api_key: str = Field(alias="LLM_API_KEY")
    roles: List[str] = Field(alias="LLM_SCOOP", default_factory=list)

    class Config:
        populate_by_name = True

class AppConfig(BaseModel):
    default_llms: List[LLMProfile] = Field(default_factory=list)
    privacy_gate_enabled: bool = True
    llm_mode: str = "public"

def load_initial_config() -> AppConfig:
    """Load non-secret defaults.

    LLM provider profiles are product/user configuration and must be added from
    Settings. We intentionally ship no API URLs, models, or keys here.
    """
    llms_data: list[dict[str, object]] = []
    
    llms = [LLMProfile(**data) for data in llms_data]
    
    return AppConfig(
        default_llms=llms,
        privacy_gate_enabled=os.getenv("PRIVACY_GATE_ENABLED", "true").lower() == "true",
        llm_mode=os.getenv("AGENT_LLM_MODE", "public")
    )

config = load_initial_config()
