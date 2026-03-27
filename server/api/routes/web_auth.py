"""Browser-only web auth routes.

This provides a lightweight server-validated login cookie used by the
browser UI gate. Desktop (Tauri) bypasses this gate client-side.
"""

from __future__ import annotations

import hmac
import secrets
import time
from hashlib import sha256
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

router = APIRouter(tags=["web-auth"])

_AUTH_COOKIE = "pf_web_auth"

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class WebAuthSettings(BaseSettings):
    web_ui_password: str = ""
    web_ui_auth_secret: str = ""
    web_ui_auth_ttl_seconds: int = 28_800

    model_config = {
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }


_settings = WebAuthSettings()
_AUTH_TTL_SECONDS = max(300, _settings.web_ui_auth_ttl_seconds)
_AUTH_SECRET = _settings.web_ui_auth_secret.strip() or secrets.token_urlsafe(32)


class WebLoginPayload(BaseModel):
    password: str = Field(min_length=1, max_length=256)


def _configured_password() -> str:
    return _settings.web_ui_password.strip()


def _sign(value: str) -> str:
    return hmac.new(_AUTH_SECRET.encode("utf-8"), value.encode("utf-8"), sha256).hexdigest()


def _build_token() -> str:
    issued_at = int(time.time())
    nonce = secrets.token_hex(12)
    payload = f"{issued_at}.{nonce}"
    return f"{payload}.{_sign(payload)}"


def _verify_token(token: str) -> bool:
    raw = str(token or "").strip()
    parts = raw.split(".")
    if len(parts) != 3:
        return False
    issued_at_raw, nonce, signature = parts
    if not issued_at_raw.isdigit() or len(nonce) < 8:
        return False
    payload = f"{issued_at_raw}.{nonce}"
    expected = _sign(payload)
    if not hmac.compare_digest(expected, signature):
        return False
    issued_at = int(issued_at_raw)
    if issued_at + _AUTH_TTL_SECONDS < int(time.time()):
        return False
    return True


@router.get("/api/web-auth/status")
def web_auth_status(request: Request) -> dict[str, object]:
    configured = bool(_configured_password())
    token = request.cookies.get(_AUTH_COOKIE, "")
    authenticated = configured and _verify_token(token)
    return {
        "configured": configured,
        "authenticated": authenticated,
        "ttl_seconds": _AUTH_TTL_SECONDS,
    }


@router.post("/api/web-auth/login")
def web_auth_login(payload: WebLoginPayload, response: Response) -> dict[str, object]:
    expected = _configured_password()
    if not expected:
        raise HTTPException(status_code=503, detail="WEB_UI_PASSWORD is not configured")
    if not hmac.compare_digest(expected, payload.password):
        raise HTTPException(status_code=401, detail="invalid credentials")

    token = _build_token()
    response.set_cookie(
        key=_AUTH_COOKIE,
        value=token,
        max_age=_AUTH_TTL_SECONDS,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
    )
    return {"ok": True}


@router.post("/api/web-auth/logout")
def web_auth_logout(response: Response) -> dict[str, object]:
    response.delete_cookie(key=_AUTH_COOKIE, path="/")
    return {"ok": True}
