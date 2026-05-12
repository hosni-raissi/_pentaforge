"""Global application settings routes."""

from __future__ import annotations

import os
import time
from typing import Any, List
import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from server.api.dependencies import projects_store

router = APIRouter(prefix="/api/settings", tags=["settings"])
logger = structlog.get_logger(__name__)

SETTINGS_ID = "global_system_settings"


class LLMProfile(BaseModel):
    id: str = Field(default_factory=lambda: f"profile_{int(time.time() * 1000)}")
    name: str
    provider: str
    model: str
    api_url: str | None = None
    api_key: str | None = None
    is_active: bool = True
    roles: List[str] = Field(default_factory=list)

class SystemSettings(BaseModel):
    privacy_gate: bool = True
    llm_profiles: List[LLMProfile] = Field(default_factory=list)
    llm_mode: str = "public"
    fallback_profiles: List[LLMProfile] = Field(default_factory=list)


@router.get("")
def get_settings() -> SystemSettings:
    try:
        from server.core.config import config as server_config
        data = projects_store.get_project(SETTINGS_ID)
        
        # Bootstrap logic: If DB is empty, migrate from config.py
        if not data:
            initial_profiles = []
            for cfg in server_config.default_llms:
                initial_profiles.append(LLMProfile(
                    id=cfg.id,
                    name=cfg.name if hasattr(cfg, 'name') else f"{cfg.provider} - {cfg.roles[0] if cfg.roles else 'default'}",
                    provider=cfg.provider,
                    api_url=cfg.api_url,
                    model=cfg.model,
                    api_key=cfg.api_key,
                    roles=cfg.roles
                ))
            
            settings = SystemSettings(
                llm_profiles=initial_profiles,
                privacy_gate=server_config.privacy_gate_enabled,
                llm_mode=server_config.llm_mode
            )
            
            # Save to DB for future use
            payload = settings.model_dump()
            payload["id"] = SETTINGS_ID
            projects_store.upsert_project(payload)
            return settings
        
        settings = SystemSettings(**data)
        return settings
    except Exception as exc:
        logger.error("failed_to_get_settings", error=str(exc))
        return SystemSettings()


@router.post("")
def update_settings(settings: SystemSettings) -> dict[str, bool]:
    try:
        payload = settings.model_dump()
        payload["id"] = SETTINGS_ID
        projects_store.upsert_project(payload)
        return {"ok": True}
    except Exception as exc:
        logger.error("failed_to_update_settings", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {exc}")

@router.post("/reset")
def reset_settings_to_defaults() -> SystemSettings:
    """Wipe DB settings and re-bootstrap from server/core/config.py."""
    try:
        from server.core.config import config as server_config
        
        # Delete existing settings
        with projects_store._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM records WHERE id = ?", (SETTINGS_ID,))
            conn.commit()
            
        # Trigger re-bootstrap by calling get_settings
        return get_settings()
    except Exception as exc:
        logger.error("failed_to_reset_settings", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to reset settings: {exc}")

@router.post("/test-llm")
async def test_llm_config(profile: LLMProfile) -> dict[str, Any]:
    """Test if an LLM configuration is valid by attempting a simple chat completion."""
    from server.core.llm import LLMClient, LLMConfig, ChatMessage
    
    config = LLMConfig(
        provider=profile.provider,
        model=profile.model,
        api_url=profile.api_url or "",
        api_key=profile.api_key or "",
        max_tokens=10,
        temperature=0.0
    )
    
    try:
        async with LLMClient(config=config, client_name="config_test") as client:
            response = await client.chat([
                ChatMessage(role="user", content="Respond with only the word 'OK'.")
            ])
            if response.content and "OK" in response.content.upper():
                return {"ok": True, "message": "Connection successful"}
            return {"ok": False, "message": f"Unexpected response: {response.content}"}
    except Exception as exc:
        logger.error("llm_test_failed", error=str(exc))
        return {"ok": False, "message": str(exc)}
