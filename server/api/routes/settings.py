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
SETTINGS_PATH = "/settings"
LLM_REQUIRED_CODE = "llm_profile_required"
_SEEDED_PROFILE_ID_PREFIX = "id4848516_"


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
    sudo_password: str | None = Field(default=None, description="Global root/sudo password for tool automation")


def _profile_has_usable_config(profile: Any, llm_mode: str = "public") -> bool:
    if not isinstance(profile, dict):
        profile = profile.model_dump() if hasattr(profile, "model_dump") else {}
    if not bool(profile.get("is_active", True)):
        return False
    provider = str(profile.get("provider") or "").strip().lower()
    model = str(profile.get("model") or "").strip()
    if not provider or not model:
        return False
    if provider in {"ollama", "local"} or str(llm_mode or "").strip().lower() == "local":
        return True
    return bool(str(profile.get("api_key") or "").strip())


def has_saved_usable_llm_profile() -> bool:
    """Return True only when the DB contains a user-saved usable LLM profile."""
    data = projects_store.get_project(SETTINGS_ID)
    if not isinstance(data, dict):
        return False
    profiles = data.get("llm_profiles")
    if not isinstance(profiles, list):
        return False
    llm_mode = str(data.get("llm_mode") or "public")
    return any(_profile_has_usable_config(profile, llm_mode) for profile in profiles)


def llm_required_response() -> dict[str, str]:
    return {
        "code": LLM_REQUIRED_CODE,
        "message": "No active LLM profile is configured. Add an LLM profile in Settings before using AI-powered actions.",
        "settings_path": SETTINGS_PATH,
    }


def _remove_seeded_llm_profiles(settings: SystemSettings) -> tuple[SystemSettings, bool]:
    profiles = [
        profile for profile in settings.llm_profiles
        if not str(profile.id or "").startswith(_SEEDED_PROFILE_ID_PREFIX)
    ]
    changed = len(profiles) != len(settings.llm_profiles)
    if changed:
        settings.llm_profiles = profiles
    return settings, changed


def _save_settings(settings: SystemSettings) -> None:
    payload = settings.model_dump()
    payload["id"] = SETTINGS_ID
    projects_store.upsert_project(payload)


@router.get("")
def get_settings() -> SystemSettings:
    try:
        from server.core.config import config as server_config
        data = projects_store.get_project(SETTINGS_ID)
        
        # Product builds ship without LLM credentials. The pentester must add
        # profiles explicitly from Settings before scans can run.
        if not data:
            settings = SystemSettings(
                llm_profiles=[],
                privacy_gate=server_config.privacy_gate_enabled,
                llm_mode=server_config.llm_mode
            )
            _save_settings(settings)
            return settings
        
        settings = SystemSettings(**data)
        settings, changed = _remove_seeded_llm_profiles(settings)
        if changed:
            _save_settings(settings)
        return settings
    except Exception as exc:
        logger.error("failed_to_get_settings", error=str(exc))
        return SystemSettings()


@router.post("")
def update_settings(settings: SystemSettings) -> dict[str, bool]:
    for fallback in settings.fallback_profiles:
        if not fallback.is_active:
            continue
        fallback_provider = str(fallback.provider or "").strip().lower()
        fallback_key = str(fallback.api_key or "").strip()
        
        for main_p in settings.llm_profiles:
            if not main_p.is_active:
                continue
            main_provider = str(main_p.provider or "").strip().lower()
            main_key = str(main_p.api_key or "").strip()
            
            if fallback_provider and fallback_provider == main_provider:
                if fallback_key == main_key:
                    raise HTTPException(
                        status_code=400, 
                        detail="Backup LLM cannot use the exact same Provider and API Key as the Main LLM."
                    )

    try:
        _save_settings(settings)
        return {"ok": True}
    except Exception as exc:
        logger.error("failed_to_update_settings", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {exc}")

@router.post("/reset")
def reset_settings_to_defaults() -> SystemSettings:
    """Clear DB LLM profiles and return the non-secret product defaults."""
    try:
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
    from server.core.llm import LLMClient, LLMConfig, ChatMessage, _rewrite_local_url
    
    # Resolve API URL: use provider defaults if empty, then rewrite localhost for Docker
    api_url = profile.api_url or ""
    if not api_url.strip():
        from server.core.llm import _provider_defaults
        api_url = _provider_defaults(profile.provider.strip().lower()).get("api_url", "")
    api_url = _rewrite_local_url(api_url)
    
    config = LLMConfig(
        provider=profile.provider,
        model=profile.model,
        api_url=api_url,
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

class SudoValidationRequest(BaseModel):
    password: str

@router.post("/verify-sudo")
def verify_sudo_password(payload: SudoValidationRequest) -> dict[str, Any]:
    """Verify if the provided password is valid for root/sudo on the host system."""
    import subprocess
    pwd = payload.password
    
    # Method 1: Try sudo -S
    try:
        proc = subprocess.run(
            ["sudo", "-S", "-v"],
            input=f"{pwd}\n",
            capture_output=True,
            text=True,
            timeout=5
        )
        if proc.returncode == 0:
            return {"ok": True, "message": "Password verified via sudo"}
    except FileNotFoundError:
        pass # sudo not installed
    except subprocess.TimeoutExpired:
        pass

    # Method 2: Try su root
    try:
        import pexpect
        child = pexpect.spawn("su", ["-c", "echo OK", "root"], timeout=5)
        index = child.expect([r"(?i)password:", pexpect.EOF, pexpect.TIMEOUT])
        if index == 0:
            child.sendline(pwd)
            child.expect(pexpect.EOF)
            out = child.before.decode(errors="ignore").strip()
            if "OK" in out or "su: Authentication failure" not in out:
                return {"ok": True, "message": "Password verified via su"}
    except Exception:
        pass

    return {"ok": False, "message": "Authentication failed. Incorrect password or not supported on this system."}
