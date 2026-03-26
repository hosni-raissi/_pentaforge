"""Share-link routes for project reports."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from server.api.dependencies import projects_store

router = APIRouter(tags=["share"])


class ShareLinkCreatePayload(BaseModel):
    expires_hours: int = Field(default=24, ge=1, le=168)
    password: str | None = Field(default=None, max_length=128)
    one_time: bool = False


class ShareLinkAccessPayload(BaseModel):
    password: str | None = None


def _raise_share_access_http_error(exc: Exception) -> None:
    if isinstance(exc, LookupError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, PermissionError):
        detail = str(exc)
        if detail in {"password_required", "invalid_password"}:
            status = 401
        elif detail == "share link revoked":
            status = 410
        else:
            status = 403
        raise HTTPException(status_code=status, detail=detail) from exc
    if isinstance(exc, TimeoutError):
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail=f"Failed to access share link: {exc}") from exc


@router.post("/api/projects/{project_id}/share-links")
def create_project_share_link(
    project_id: str,
    payload: ShareLinkCreatePayload,
    request: Request,
) -> dict[str, Any]:
    password = (payload.password or "").strip() or None
    if password and len(password) < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")

    try:
        share = projects_store.create_share_link(
            project_id,
            expires_hours=payload.expires_hours,
            password=password,
            one_time=payload.one_time,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=f"Failed to create share link: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to create share link: {exc}") from exc

    access_url = f"{str(request.base_url).rstrip('/')}/share/{share['token']}"
    return {"ok": True, "access_url": access_url, **share}


@router.get("/share/{token}", response_class=HTMLResponse)
def shared_report_viewer(token: str) -> HTMLResponse:
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PentaForge Shared Report</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui; background:#0b1020; color:#e2e8f0; margin:0; }}
    .wrap {{ max-width: 920px; margin: 32px auto; padding: 0 16px; }}
    .card {{ background:#121a2f; border:1px solid #23314a; border-radius:12px; padding:16px; }}
    .row {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; }}
    input {{ background:#0f1729; color:#e2e8f0; border:1px solid #23314a; border-radius:8px; padding:10px; width:260px; }}
    button {{ background:#1d4ed8; color:white; border:none; border-radius:8px; padding:10px 14px; cursor:pointer; }}
    button:hover {{ background:#1e40af; }}
    pre {{ background:#0a1120; border:1px solid #23314a; border-radius:8px; padding:12px; overflow:auto; max-height:70vh; }}
    .muted {{ color:#94a3b8; font-size: 13px; }}
    .err {{ color:#fca5a5; margin-top:8px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h2 style="margin-top:0">Shared Scan Report</h2>
      <p class="muted">Token: {token}</p>
      <div class="row">
        <input id="password" type="password" placeholder="Password (if required)" />
        <button id="openBtn">Open Report</button>
      </div>
      <p id="status" class="muted">Click Open Report to load content.</p>
      <p id="error" class="err"></p>
      <pre id="output" style="display:none"></pre>
    </div>
  </div>
  <script>
    const token = {token!r};
    const statusEl = document.getElementById('status');
    const errorEl = document.getElementById('error');
    const outputEl = document.getElementById('output');
    const pwdEl = document.getElementById('password');

    async function openReport() {{
      statusEl.textContent = 'Loading...';
      errorEl.textContent = '';
      outputEl.style.display = 'none';

      const password = pwdEl.value.trim();
      const resp = await fetch(`/api/share/${{encodeURIComponent(token)}}/access`, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ password: password || null }})
      }});

      if (!resp.ok) {{
        let detail = `${{resp.status}}`;
        try {{
          const payload = await resp.json();
          if (payload && payload.detail) detail = payload.detail;
        }} catch {{}}
        statusEl.textContent = 'Failed to load report.';
        errorEl.textContent = detail;
        return;
      }}

      const payload = await resp.json();
      outputEl.textContent = JSON.stringify(payload, null, 2);
      outputEl.style.display = 'block';
      statusEl.textContent = 'Report loaded.';
    }}

    document.getElementById('openBtn').addEventListener('click', openReport);
  </script>
</body>
</html>"""
    return HTMLResponse(content=html)


@router.get("/api/share/{token}")
def access_shared_project_without_password(token: str) -> dict[str, Any]:
    try:
        return projects_store.access_share_link(token)
    except Exception as exc:
        _raise_share_access_http_error(exc)


@router.post("/api/share/{token}/access")
def access_shared_project(token: str, payload: ShareLinkAccessPayload) -> dict[str, Any]:
    try:
        return projects_store.access_share_link(token, password=(payload.password or "").strip() or None)
    except Exception as exc:
        _raise_share_access_http_error(exc)

