"""Global application settings routes."""

from __future__ import annotations

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from server.api.dependencies import projects_store

router = APIRouter(tags=["settings"])
logger = structlog.get_logger(__name__)

SETTINGS_ID = "global_system_settings"


class SystemSettings(BaseModel):
    privacy_gate: bool = Field(default=True)


@router.get("/api/settings")
def get_settings() -> SystemSettings:
    try:
        data = projects_store.get_project(SETTINGS_ID)
        if not data:
            return SystemSettings()
        return SystemSettings(**data)
    except Exception as exc:
        logger.error("failed_to_get_settings", error=str(exc))
        return SystemSettings()


@router.post("/api/settings")
def update_settings(settings: SystemSettings) -> dict[str, bool]:
    try:
        payload = settings.model_dump()
        payload["id"] = SETTINGS_ID
        projects_store.upsert_project(payload)
        return {"ok": True}
    except Exception as exc:
        logger.error("failed_to_update_settings", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {exc}")
