"""Centralized configuration management for PentaForge LLMs."""

import os
from typing import List, Optional
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
    """Load initial configuration from the specified schema."""
    llms_data = [
        {
            "LLM_ID": "id4848516_1",
            "LLM_PROVIDER": "mistral",
            "LLM_MODEL": "mistral-large-latest",
            "LLM_API_URL": "https://api.mistral.ai/v1",
            "LLM_API_KEY": "7JWrPGqRzcnY6ApEXdGX9D52PqASthwt",
            "LLM_SCOOP": ["memory", "analyser"]
        },
        {
            "LLM_ID": "id4848516_2",
            "LLM_PROVIDER": "mistral",
            "LLM_MODEL": "mistral-large-latest",
            "LLM_API_URL": "https://api.mistral.ai/v1",
            "LLM_API_KEY": "HXsEDG7nwLe39PZgTGvLNqXfDwQ2y2FF",
            "LLM_SCOOP": ["planner", "reporting"]
        },
        {
            "LLM_ID": "id4848516_3",
            "LLM_PROVIDER": "mistral",
            "LLM_MODEL": "mistral-large-latest",
            "LLM_API_URL": "https://api.mistral.ai/v1",
            "LLM_API_KEY": "lqyZ940SFJmE0uWPWjiDHhQlEzR5MxAR",
            "LLM_SCOOP": ["recon"]
        },
        {
            "LLM_ID": "id4848516_4",
            "LLM_PROVIDER": "mistral",
            "LLM_MODEL": "mistral-large-latest",
            "LLM_API_URL": "https://api.mistral.ai/v1",
            "LLM_API_KEY": "oc3knHw5ft01r5vVt0uTHF2ymYte1ECd",
            "LLM_SCOOP": ["exploit"]
        },
        {
            "LLM_ID": "id4848516_5",
            "LLM_PROVIDER": "mistral",
            "LLM_MODEL": "mistral-large-latest",
            "LLM_API_URL": "https://api.mistral.ai/v1",
            "LLM_API_KEY": "8vXR7qUnOfCYmGccqSd0AHrZqYxutDx4",
            "LLM_SCOOP": ["backup"]
        },
        {
            "LLM_ID": "id4848516_6",
            "LLM_PROVIDER": "gemini",
            "LLM_MODEL": "gemini-2.5-flash",
            "LLM_API_URL": "https://generativelanguage.googleapis.com/v1beta/openai/",
            "LLM_API_KEY": "AIzaSyBI1KnWWJiLFv3hpoo-LaCuhjV0BQHtBb8",
            "LLM_SCOOP": ["assistant"]
        },
        {
            "LLM_ID": "id4848516_7",
            "LLM_PROVIDER": "gemini",
            "LLM_MODEL": "gemini-2.5-flash",
            "LLM_API_URL": "https://generativelanguage.googleapis.com/v1beta/openai/",
            "LLM_API_KEY": "AIzaSyA3DtqXPV1MBycRnulRC19ly5yPBCh4zFE",
            "LLM_SCOOP": ["architect"]
        }
    ]
    
    llms = [LLMProfile(**data) for data in llms_data]
    
    return AppConfig(
        default_llms=llms,
        privacy_gate_enabled=os.getenv("PRIVACY_GATE_ENABLED", "true").lower() == "true",
        llm_mode=os.getenv("AGENT_LLM_MODE", "public")
    )

config = load_initial_config()
