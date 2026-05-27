"""Share-link routes for project reports and client Q&A."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from server.api.dependencies import projects_store
from server.api.routes.reports import (
    _build_pdf_export_bytes,
    _build_protected_zip_bytes,
)

router = APIRouter(tags=["share"])


class ShareLinkCreatePayload(BaseModel):
    expires_hours: int = Field(default=24, ge=1, le=87600)
    password: str | None = Field(default=None, max_length=128)
    one_time: bool = False


class ShareLinkAccessPayload(BaseModel):
    password: str | None = None


class SharedExportRequest(BaseModel):
    format: str = Field(default="html")
    password: str = Field(min_length=1, max_length=256)
    access_password: str | None = None


class ClientMessagePayload(BaseModel):
    password: str | None = None
    content: str


import time

# Ephemeral in-memory store for typing indicators
# Format: { project_id: { "pentester": timestamp, "client": timestamp } }
_typing_status: dict[str, dict[str, float]] = {}
_refresh_status: dict[str, float] = {}


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


from server.core.tunnel import get_or_start_tunnel, get_tunnel_status, stop_tunnel

@router.post("/api/projects/{project_id}/share-links")
def create_project_share_link(
    project_id: str,
    payload: ShareLinkCreatePayload,
    request: Request,
) -> dict[str, Any]:
    password = (payload.password or "").strip() or None
    if password and len(password) < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")

    # Start the cloudflare tunnel automatically
    tunnel_url = None
    try:
        tunnel_url = get_or_start_tunnel(port=8000)
    except Exception as exc:
        print(f"Failed to start tunnel: {exc}")

    try:
        share = projects_store.create_share_link(
            project_id,
            expires_hours=9999, # Effectively remove expiry until closed manually
            password=password,
            one_time=payload.one_time,
            tunnel_url=tunnel_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=f"Failed to create share link: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to create share link: {exc}") from exc

    access_url = f"{str(request.base_url).rstrip('/')}/share/{share['token']}"
    
    return {
        **share,
        "ok": True, 
        "access_url": access_url, 
        "tunnel_url": f"{tunnel_url.rstrip('/')}/share/{share['token']}" if tunnel_url else None,
    }

@router.get("/api/projects/{project_id}/share-link")
def get_active_share_link(project_id: str, request: Request) -> dict[str, Any]:
    share = projects_store.get_active_share_link(project_id)
    if not share:
        return {"ok": False, "detail": "No active share link found"}
    
    # Self-healing: try to ensure tunnel is running if we have an active share
    tunnel_url = None
    try:
        tunnel_url = get_or_start_tunnel(port=8000)
    except Exception as e:
        print(f"[TUNNEL] Self-healing failed: {e}")
        tunnel_url = get_tunnel_status()

    access_url = f"{str(request.base_url).rstrip('/')}/share/{share['token']}"
    
    return {
        **share,
        "ok": True,
        "access_url": access_url,
        "tunnel_url": f"{tunnel_url.rstrip('/')}/share/{share['token']}" if tunnel_url else None,
    }

@router.post("/api/tunnel/stop")
def stop_active_tunnel() -> dict[str, Any]:
    stop_tunnel()
    return {"ok": True}

@router.post("/api/projects/{project_id}/share-links/revoke")
def revoke_project_share_links(project_id: str) -> dict[str, Any]:
    try:
        # We'll revoke all active links for this project
        with projects_store._connect() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE share_links SET revoked = 1 WHERE project_id = ? AND revoked = 0", (project_id,))
            conn.commit()
        return {"ok": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to revoke share links: {exc}") from exc
 
@router.post("/api/projects/{project_id}/share-refresh")
def request_share_refresh(project_id: str) -> dict[str, Any]:
    _refresh_status[project_id] = time.time()
    return {"ok": True}

@router.post("/api/share/{token}/markdown")
def get_shared_markdown_report(token: str, payload: ShareLinkAccessPayload):
    try:
        data = projects_store.access_share_link(token, password=(payload.password or "").strip() or None)
        content = projects_store.get_report(data["project"]["id"], "markdown")
        if not content:
            return Response("Markdown report not found", status_code=404, media_type="text/plain")
        return Response(content=content["content"], media_type="text/plain")
    except Exception as exc:
        _raise_share_access_http_error(exc)


@router.get("/share/{token}", response_class=HTMLResponse)
def shared_report_viewer(token: str) -> HTMLResponse:
    # Check if link exists and is not revoked
    is_protected = False
    try:
        with projects_store._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT password_hash, revoked FROM share_links WHERE token = ?", (token,))
            row = cur.fetchone()
            if not row:
                return HTMLResponse("<h1>Link Not Found</h1><p>The shared link does not exist.</p>", status_code=404)
            if row["revoked"]:
                return HTMLResponse(
                    "<h1>Access Revoked</h1><p>This delivery link has been revoked by the operator and is no longer active.</p>", 
                    status_code=410
                )
            if row["password_hash"]:
                is_protected = True
    except Exception as exc:
        print(f"Share link check error: {exc}")
        pass

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PentaForge Client Portal</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-light: #f1f5f9;
      --border: #e2e8f0;
      --text: #1e293b;
      --text-muted: #64748b;
      --primary: #4f46e5;
      --primary-hover: #4338ca;
    }}
    
    [data-theme="dark"] {{
      --bg: #0c1220;
      --surface: #111827;
      --surface-light: #1e293b;
      --border: #1e293b;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
    }}

    * {{ box-sizing: border-box; }}
    html,
    body {{ height: 100%; }}
    body {{ font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; display: flex; min-height: 100vh; height: 100vh; overflow: hidden; transition: background 0.2s, color 0.2s; }}
    .auth-overlay {{ position: fixed; inset: 0; background: var(--bg); display: flex; align-items: center; justify-content: center; z-index: 1000; padding: 16px; }}
    .auth-card {{ background: var(--surface); padding: 2rem; border-radius: 12px; border: 1px solid var(--border); width: 100%; max-width: 400px; text-align: center; }}
    .auth-card input {{ width: 100%; box-sizing: border-box; padding: 0.75rem; margin: 1rem 0; background: var(--surface-light); border: 1px solid var(--border); color: var(--text); border-radius: 6px; }}
    .auth-card button {{ width: 100%; padding: 0.75rem; background: var(--primary); border: none; color: white; border-radius: 6px; cursor: pointer; font-weight: 600; }}
    
    .layout {{ display: flex; width: 100%; min-height: 100vh; height: 100vh; align-items: stretch; flex: 1 1 auto; }}
    .report-pane {{ flex: 1 1 auto; min-width: 0; min-height: 0; padding: 1.25rem; overflow: hidden; background: var(--bg); display: flex; flex-direction: column; }}
    .report-toolbar {{ display: flex; gap: 0.5rem; margin-bottom: 0.5rem; flex-shrink: 0; align-items: center; }}
    .report-toolbar button,
    .report-toolbar select {{
      min-height: 40px;
    }}
    .report-toolbar-actions {{ margin-left: auto; display: flex; gap: 0.5rem; align-items: center; }}
    .report-frame {{ flex: 1 1 auto; min-height: 0; width: 100%; height: 100%; border-radius: 12px; border: 1px solid var(--border); }}
    .report-markdown {{ display: none; flex: 1 1 auto; min-height: 0; width: 100%; height: 100%; white-space: pre-wrap; font-family: monospace; font-size: 0.85rem; background: var(--surface); padding: 1.5rem; border-radius: 12px; margin: 0; border: 1px solid var(--border); overflow-y: auto; color: var(--text); }}
    
    .chat-pane {{ width: 450px; max-width: 42vw; background: var(--surface); border-left: 1px solid var(--border); display: flex; flex-direction: column; min-height: 0; }}
    .chat-header {{ padding: 1rem; border-bottom: 1px solid var(--border); font-weight: 600; background: var(--surface); display: flex; align-items: center; justify-content: space-between; }}
    .chat-messages {{ flex: 1; padding: 1rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }}
    .msg {{ padding: 0.75rem; border-radius: 8px; max-width: 85%; line-height: 1.4; font-size: 0.9rem; word-wrap: break-word; overflow-wrap: break-word; word-break: break-word; }}
    .msg.client {{ background: var(--primary); color: white; align-self: flex-end; border-bottom-right-radius: 0; }}
    .msg.pentester {{ background: var(--surface-light); color: var(--text); align-self: flex-start; border-bottom-left-radius: 0; border: 1px solid var(--border); }}
    .format-option[disabled] {{ opacity: 0.72; cursor: wait; }}
    .format-option.is-busy {{ border-color: var(--primary); background: color-mix(in srgb, var(--primary) 8%, var(--surface)); }}
    .format-option.is-success {{ border-color: #10b981; background: rgba(16, 185, 129, 0.12); }}
    .chat-input {{
      padding: 1rem;
      border-top: 1px solid var(--border);
      background: var(--surface-light);
    }}
    .unified-input-group {{
      display: flex;
      flex-direction: column;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.5rem;
      transition: all 0.3s ease;
    }}
    .unified-input-group:focus-within {{
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1);
    }}
    .chat-input textarea {{
      width: 100%;
      background: transparent;
      border: none;
      color: var(--text);
      padding: 0.5rem;
      resize: none;
      min-height: 80px;
      font-family: inherit;
      font-size: 0.95rem;
      outline: none;
    }}
    .input-actions {{
      display: flex;
      justify-content: flex-end;
      padding: 0.25rem;
    }}
    #send-btn {{
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 8px;
      width: 36px;
      height: 36px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.2s;
    }}
    #send-btn:hover {{
      transform: scale(1.05);
      filter: brightness(1.1);
    }}
    #send-btn:disabled {{
      opacity: 0.5;
      cursor: not-allowed;
    }}
    #error {{ color: #ef4444; margin-top: 1rem; font-size: 0.9rem; }}
    iframe {{ width: 100%; height: 100%; border: none; background: white; border-radius: 12px; display: block; }}
    .theme-toggle {{ background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px; border-radius: 4px; display: flex; align-items: center; }}
    .theme-toggle:hover {{ color: var(--text); background: var(--surface-light); }}
    
    .modal-overlay {{ position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px); display: none; align-items: center; justify-content: center; z-index: 2000; padding: 20px; }}
    .modal-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; width: 100%; max-width: 440px; padding: 2rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }}
    .modal-title {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 0.5rem; color: var(--text); }}
    .modal-desc {{ color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.5rem; }}
    .format-option {{ display: flex; align-items: center; gap: 1rem; padding: 1rem; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 0.75rem; cursor: pointer; transition: all 0.2s; background: var(--surface-light); text-align: left; width: 100%; }}
    .format-option:hover {{ border-color: var(--primary); background: var(--primary); color: white; }}
    .format-option:hover .format-icon {{ color: white; }}
    .format-option .format-icon {{ color: var(--primary); flex-shrink: 0; }}
    .format-option .format-info {{ flex: 1; }}
    .format-option .format-name {{ font-weight: 600; display: block; }}
    .format-option .format-ext {{ font-size: 0.75rem; opacity: 0.7; }}
    .modal-close {{ margin-top: 1rem; color: var(--text-muted); background: none; border: none; cursor: pointer; font-size: 0.85rem; text-decoration: underline; }}
    .modal-close:hover {{ color: var(--text); }}

    @media (max-width: 960px) {{
      body {{ display: block; overflow: auto; }}
      .layout {{ flex-direction: column; min-height: 100vh; height: auto; }}
      .report-pane {{ padding: 1rem; overflow: visible; }}
      .report-toolbar {{
        flex-wrap: wrap;
        align-items: stretch;
      }}
      .report-toolbar button,
      .report-toolbar select {{
        flex: 1 1 140px;
      }}
      .report-toolbar-actions {{
        margin-left: 0;
        width: 100%;
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      }}
      .report-frame,
      .report-markdown {{
        min-height: 58vh;
      }}
      .chat-pane {{
        width: 100%;
        max-width: none;
        border-left: none;
        border-top: 1px solid var(--border);
        min-height: 45vh;
      }}
    }}

    @media (max-width: 640px) {{
      .auth-card {{ padding: 1.25rem; border-radius: 10px; }}
      .report-pane {{ padding: 0.75rem; }}
      .report-toolbar-actions {{
        grid-template-columns: 1fr;
      }}
      .report-frame,
      .report-markdown {{
        min-height: 52vh;
      }}
      .chat-header,
      .chat-messages,
      .chat-input {{
        padding-left: 0.75rem;
        padding-right: 0.75rem;
      }}
      .chat-input {{
        flex-wrap: wrap;
      }}
      .chat-input input,
      .chat-input button {{
        width: 100%;
      }}
      .msg {{
        max-width: 92%;
      }}
    }}
  </style>
</head>
<body>
  <div id="auth-overlay" class="auth-overlay">
    <div class="auth-card">
      <h2>Secure Client Portal</h2>
      <p style="color: #94a3b8; font-size: 0.9rem;">Please enter the password to access your report.</p>
      <input type="password" id="password" placeholder="Password" />
      <button id="unlock-btn">Unlock Report</button>
      <div id="error"></div>
    </div>
  </div>

  <div id="download-modal" class="modal-overlay">
    <div class="modal-card">
      <div class="modal-title">Download Report</div>
      <p class="modal-desc">Choose your preferred format and set an export password for the protected report.</p>
      <div style="display: flex; flex-direction: column; gap: 0.5rem; margin: 1rem 0 1.25rem;">
        <label for="download-password" style="font-size: 0.78rem; font-weight: 700; color: var(--text); letter-spacing: 0.04em; text-transform: uppercase;">Export Password</label>
        <input
          type="password"
          id="download-password"
          placeholder="Enter password for the downloaded file"
          style="width: 100%; box-sizing: border-box; padding: 0.8rem 0.9rem; background: var(--surface-light); border: 1px solid var(--border); color: var(--text); border-radius: 8px;"
        />
        <div id="download-error" style="min-height: 1rem; font-size: 0.8rem; color: #ef4444;"></div>
      </div>
      
      <button id="download-html-btn" class="format-option" onclick="downloadAs('html')">
        <div class="format-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
        </div>
        <div class="format-info">
          <span class="format-name" data-default-name="Professional Report">Professional Report</span>
          <span class="format-ext" data-default-desc="Password-protected HTML package (.html.zip)">Password-protected HTML package (.html.zip)</span>
        </div>
      </button>
      
      <button id="download-pdf-btn" class="format-option" onclick="downloadAs('pdf')">
        <div class="format-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><path d="M16 13a2 2 0 0 0-2-2H8v6h2a2 2 0 0 0 2-2v-2z"></path></svg>
        </div>
        <div class="format-info">
          <span class="format-name" data-default-name="PDF Document">PDF Document</span>
          <span class="format-ext" data-default-desc="Password-protected PDF (.pdf)">Password-protected PDF (.pdf)</span>
        </div>
      </button>
      
      <button class="modal-close" onclick="closeDownloadModal()">Cancel</button>
    </div>
  </div>

  <div class="layout" id="portal-layout" style="display: none;">
    <div class="report-pane">
      <div class="report-toolbar">
        
        <div class="report-toolbar-actions">
          <button onclick="downloadActive()" style="padding: 0.5rem 1.25rem; background: var(--primary); border: none; color: white; border-radius: 6px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 8px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            Download Report
          </button>
        </div>
      </div>
      <iframe id="report-frame" class="report-frame"></iframe>
    </div>
    <div class="chat-pane">
      <div class="chat-header">
        <div style="display: flex; align-items: center; gap: 8px;">
          Q&A with Pentester
          <span id="typing-indicator" style="display: none; font-size: 0.8rem; font-style: italic; color: var(--text-muted); margin-left: 8px;">is typing...</span>
        </div>
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle Theme">
          <span id="theme-icon">☀️</span>
        </button>
      </div>
      <div class="chat-messages" id="messages"></div>
      <div class="chat-input">
        <div class="unified-input-group">
          <textarea id="msg-input" placeholder="Ask a question..." rows="2"></textarea>
          <div class="input-actions">
            <button id="send-btn" title="Send Message">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
              </svg>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    const token = {token!r};
    const isPasswordProtected = {"true" if is_protected else "false"};
    let currentPassword = null;
    let downloadInFlight = false;
    
    async function unlock() {{
      const pwdInput = document.getElementById('password');
      const pwd = pwdInput.value.trim() || null;
      console.log("[PORTAL] Attempting to unlock...");
      
      if (isPasswordProtected) {{
        document.getElementById('error').textContent = 'Unlocking...';
      }}
      
      try {{
        const res = await fetch(`/api/share/${{token}}/access`, {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{password: pwd}})
        }});
        
        if (!res.ok) {{
          console.warn("[PORTAL] Access denied");
          if (isPasswordProtected) {{
             let msg = 'Access denied';
             try {{ const j = await res.json(); if (j.detail) msg = j.detail; }} catch(e) {{}}
             document.getElementById('error').textContent = msg;
          }}
          return;
        }}
        
        console.log("[PORTAL] Access granted");
        currentPassword = pwd;
        document.getElementById('auth-overlay').style.display = 'none';
        document.getElementById('portal-layout').style.display = 'flex';
        
        setView('html');
        loadMessages();
        setInterval(loadMessages, 5000);
      }} catch (err) {{
        console.error("[PORTAL] Unlock error:", err);
        if (isPasswordProtected) {{
          document.getElementById('error').textContent = 'Error: ' + err.message;
        }}
      }}
    }}

    function closeDownloadModal() {{
      if (downloadInFlight) return;
      document.getElementById('download-modal').style.display = 'none';
      const errorNode = document.getElementById('download-error');
      if (errorNode) errorNode.textContent = '';
    }}

    function setDownloadButtonState(format, state) {{
      const buttons = {{
        html: document.getElementById('download-html-btn'),
        pdf: document.getElementById('download-pdf-btn'),
      }};
      Object.entries(buttons).forEach(([key, button]) => {{
        if (!button) return;
        const nameNode = button.querySelector('.format-name');
        const descNode = button.querySelector('.format-ext');
        const defaultName = nameNode?.dataset.defaultName || nameNode?.textContent || '';
        const defaultDesc = descNode?.dataset.defaultDesc || descNode?.textContent || '';

        button.disabled = state === 'busy';
        button.classList.remove('is-busy', 'is-success');

        if (state === 'busy' && key === format) {{
          button.classList.add('is-busy');
          if (nameNode) nameNode.textContent = 'Preparing...';
          if (descNode) descNode.textContent = 'Building protected download';
        }} else if (state === 'success' && key === format) {{
          button.classList.add('is-success');
          if (nameNode) nameNode.textContent = 'Saved';
          if (descNode) descNode.textContent = 'Protected file downloaded successfully';
        }} else {{
          if (nameNode) nameNode.textContent = defaultName;
          if (descNode) descNode.textContent = defaultDesc;
        }}
      }});
    }}

    // Auto-unlock or bind events
    document.addEventListener('DOMContentLoaded', () => {{
      console.log("[PORTAL] Portal loaded, isProtected:", isPasswordProtected);
      
      // Close modal on escape
      document.addEventListener('keydown', (e) => {{
        if (e.key === 'Escape') closeDownloadModal();
      }});
      
      if (isPasswordProtected === false) {{
        unlock();
      }}
      
      const btn = document.getElementById('unlock-btn');
      if (btn) btn.addEventListener('click', unlock);
      
      const pwd = document.getElementById('password');
      if (pwd) pwd.addEventListener('keypress', (e) => {{
        if (e.key === 'Enter') unlock();
      }});
    }});
      let htmlContent = null;
    let mdContent = null;
    let currentTheme = 'light';

    function toggleTheme() {{
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', currentTheme);
      document.getElementById('theme-icon').textContent = currentTheme === 'dark' ? '🌙' : '☀️';
      // Re-apply theme to iframe content if it's already loaded
      if (htmlContent) {{
        const frame = document.getElementById('report-frame');
        const doc = frame.contentWindow.document;
        doc.documentElement.setAttribute('data-theme', currentTheme);
      }}
    }}

    async function setView(format) {{
      const btn = document.getElementById('btn-view-html');
      if (btn) btn.style.background = format === 'html' ? 'var(--primary)' : 'var(--surface-light)';
      document.getElementById('report-frame').style.display = format === 'html' ? 'block' : 'none';
      
      if (format === 'html' && !htmlContent) {{
        const res = await fetch(`/api/share/${{token}}/html`, {{ method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{password: currentPassword}}) }});
        if (res.ok) {{
          htmlContent = await res.text();
          const doc = document.getElementById('report-frame').contentWindow.document;
          doc.open(); 
          doc.write(htmlContent); 
          doc.close();
          doc.documentElement.setAttribute('data-theme', currentTheme);
        }}
      }} else if (format === 'markdown' && !mdContent) {{
        document.getElementById('report-markdown').textContent = 'Loading markdown...';
        const res = await fetch(`/api/share/${{token}}/markdown?ts=${{Date.now()}}`, {{ 
          method: 'POST', 
          headers: {{'Content-Type': 'application/json'}}, 
          body: JSON.stringify({{password: currentPassword}}) 
        }});
        if (res.ok) {{
          mdContent = await res.text();
          document.getElementById('report-markdown').textContent = mdContent;
        }} else {{
          document.getElementById('report-markdown').textContent = 'Failed to load markdown report.';
        }}
      }}
    }}

    async function downloadActive() {{
      document.getElementById('download-modal').style.display = 'flex';
      const passwordInput = document.getElementById('download-password');
      const errorNode = document.getElementById('download-error');
      if (errorNode) errorNode.textContent = '';
      if (passwordInput) {{
        passwordInput.value = '';
        passwordInput.focus();
      }}
    }}

    async function downloadAs(format) {{
      if (downloadInFlight) return;
      const passwordInput = document.getElementById('download-password');
      const errorNode = document.getElementById('download-error');
      const cleanPassword = passwordInput && typeof passwordInput.value === 'string'
        ? passwordInput.value.trim()
        : '';
      if (!cleanPassword) {{
        if (errorNode) errorNode.textContent = 'Enter an export password before downloading.';
        if (passwordInput) passwordInput.focus();
        return;
      }}
      if (errorNode) errorNode.textContent = '';
      downloadInFlight = true;
      setDownloadButtonState(format, 'busy');

      try {{
        const res = await fetch(`/api/share/${{token}}/reports/export`, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            format,
            password: cleanPassword,
            access_password: currentPassword
          }})
        }});

        if (!res.ok) {{
          let message = 'Failed to download report.';
          try {{
            const payload = await res.json();
            if (payload && payload.detail) {{
              message = payload.detail;
            }}
          }} catch (_err) {{}}
          if (errorNode) errorNode.textContent = message;
          downloadInFlight = false;
          setDownloadButtonState(format, 'idle');
          return;
        }}

        const blob = await res.blob();
        const disposition = res.headers.get('Content-Disposition') || '';
        const filenameMatch = disposition.match(/filename="([^"]+)"/i);
        const filename = filenameMatch
          ? filenameMatch[1]
          : (format === 'pdf' ? 'report.pdf' : `report.${{format}}.zip`);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        setDownloadButtonState(format, 'success');
        window.setTimeout(() => {{
          downloadInFlight = false;
          setDownloadButtonState(format, 'idle');
          closeDownloadModal();
        }}, 1200);
      }} catch (err) {{
        if (errorNode) errorNode.textContent = `Download failed: ${{err?.message || 'unknown error'}}`;
        downloadInFlight = false;
        setDownloadButtonState(format, 'idle');
      }}
    }}

    let lastRefreshTrigger = null;
    
    async function loadMessages() {{
      const res = await fetch(`/api/share/${{token}}/messages`, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{password: currentPassword}})
      }});
      if (res.ok) {{
        const data = await res.json();
        
        // Handle Refresh Signal
        if (lastRefreshTrigger !== null && data.refresh_trigger !== lastRefreshTrigger) {{
           location.reload();
           return;
        }}
        lastRefreshTrigger = data.refresh_trigger;

        // Handle typing indicator
        const typingEl = document.getElementById('typing-indicator');
        if (data.pentester_typing) {{
          typingEl.style.display = 'inline';
        }} else {{
          typingEl.style.display = 'none';
        }}

        const container = document.getElementById('messages');
        container.innerHTML = '';
        data.messages.forEach(m => {{
          const div = document.createElement('div');
          div.className = 'msg ' + m.sender;
          div.textContent = m.content;
          container.appendChild(div);
        }});
        container.scrollTop = container.scrollHeight;
      }} else if (res.status === 410 || res.status === 401) {{
        // Link revoked or session expired - refresh to show appropriate overlay/error
        location.reload();
      }}
    }}
    
    async function sendMessage() {{
      const input = document.getElementById('msg-input');
      const text = input.value.trim();
      if (!text) return;
      
      input.value = '';
      await fetch(`/api/share/${{token}}/messages/send`, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{password: currentPassword, content: text}})
      }});
      loadMessages();
    }}

    let typingTimeout = null;
    document.getElementById('msg-input').addEventListener('input', () => {{
      if (!typingTimeout) {{
        fetch(`/api/share/${{token}}/typing`, {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{password: currentPassword}})
        }});
      }}
      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {{ typingTimeout = null; }}, 2000);
    }});
    
    document.getElementById('unlock-btn').onclick = unlock;
    document.getElementById('password').addEventListener('keypress', e => {{ if (e.key === 'Enter') unlock(); }});
    document.getElementById('send-btn').onclick = sendMessage;
    document.getElementById('msg-input').addEventListener('keypress', e => {{ if (e.key === 'Enter') sendMessage(); }});
    
    // Auto-try empty password first
    unlock();
  </script>
</body>
</html>"""
    response = HTMLResponse(content=html)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@router.post("/api/share/{token}/access")
def access_shared_project(token: str, payload: ShareLinkAccessPayload) -> dict[str, Any]:
    try:
        return projects_store.access_share_link(token, password=(payload.password or "").strip() or None)
    except Exception as exc:
        _raise_share_access_http_error(exc)


@router.post("/api/share/{token}/html")
def get_shared_html_report(token: str, payload: ShareLinkAccessPayload) -> HTMLResponse:
    try:
        data = projects_store.access_share_link(token, password=(payload.password or "").strip() or None)
        project_id = data["project"]["id"]
        report = projects_store.get_report(project_id, format="html")
        if not report:
            return HTMLResponse("<h1>Report not generated yet</h1>", status_code=404)
        return HTMLResponse(content=report["content"])
    except Exception as exc:
        _raise_share_access_http_error(exc)


@router.post("/api/share/{token}/reports/export")
def export_shared_report(token: str, request: SharedExportRequest) -> Response:
    safe_format = str(request.format or "html").strip().lower()
    if safe_format not in {"html", "markdown", "pdf"}:
        raise HTTPException(status_code=400, detail=f"Unsupported export format: {safe_format}")
    password = str(request.password or "").strip()
    if not password:
        raise HTTPException(status_code=400, detail="Export password is required.")

    try:
        data = projects_store.access_share_link(token, password=(request.access_password or "").strip() or None)
    except Exception as exc:
        _raise_share_access_http_error(exc)

    project_id = data["project"]["id"]
    html_report = projects_store.get_report(project_id, format="html")
    markdown_report = projects_store.get_report(project_id, format="markdown")
    source_report = html_report if safe_format == "html" else markdown_report
    if safe_format == "pdf":
        source_report = markdown_report or html_report
    if source_report is None:
        raise HTTPException(status_code=404, detail=f"No source report found for {safe_format} export")

    base_name = f"pentaforge-report-{project_id[:8]}"
    if safe_format == "markdown":
        inner_name = f"{base_name}.md"
        payload = str(source_report["content"]).encode("utf-8")
        archive_bytes = _build_protected_zip_bytes(
            inner_name=inner_name,
            payload=payload,
            password=password,
            encryption_method="ZipCrypto",
        )
        file_name = f"{inner_name}.zip"
        media_type = "application/zip"
        content = archive_bytes
    elif safe_format == "html":
        inner_name = f"{base_name}.html"
        payload = str(source_report["content"]).encode("utf-8")
        archive_bytes = _build_protected_zip_bytes(
            inner_name=inner_name,
            payload=payload,
            password=password,
            encryption_method="ZipCrypto",
        )
        file_name = f"{inner_name}.zip"
        media_type = "application/zip"
        content = archive_bytes
    else:
        pdf_bytes = _build_pdf_export_bytes(
            project_id=project_id,
            content=str(source_report["content"]),
            source_format=str(source_report["format"]),
        )
        try:
            from server.api.routes.reports import _encrypt_pdf_bytes
            content = _encrypt_pdf_bytes(pdf_bytes, password)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to protect PDF export: {exc}") from exc
        file_name = f"{base_name}.pdf"
        media_type = "application/octet-stream"

    headers = {
        "Content-Disposition": f'attachment; filename="{file_name}"',
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "X-Archive-Format": safe_format,
    }
    return Response(content=content, media_type=media_type, headers=headers)


@router.post("/api/share/{token}/messages")
def get_shared_messages(token: str, payload: ShareLinkAccessPayload) -> dict[str, Any]:
    try:
        data = projects_store.access_share_link(token, password=(payload.password or "").strip() or None)
        project_id = data["project"]["id"]
        messages = projects_store.list_client_messages(project_id)
        status = _typing_status.get(project_id, {})
        return {
            "messages": messages,
            "pentester_typing": (time.time() - status.get("pentester", 0)) < 3,
            "refresh_trigger": _refresh_status.get(project_id, 0)
        }
    except Exception as exc:
        _raise_share_access_http_error(exc)


@router.post("/api/share/{token}/messages/send")
def send_shared_message(token: str, payload: ClientMessagePayload) -> dict[str, Any]:
    try:
        data = projects_store.access_share_link(token, password=(payload.password or "").strip() or None)
        projects_store.add_client_message(data["project"]["id"], sender="client", content=payload.content.strip())
        return {"ok": True}
    except Exception as exc:
        _raise_share_access_http_error(exc)


@router.post("/api/share/{token}/typing")
def set_client_typing(token: str, payload: ShareLinkAccessPayload) -> dict[str, Any]:
    try:
        data = projects_store.access_share_link(token, password=(payload.password or "").strip() or None)
        _typing_status.setdefault(data["project"]["id"], {})["client"] = time.time()
        return {"ok": True}
    except Exception as exc:
        _raise_share_access_http_error(exc)

# Add routes for Pentester to manage messages from Dashboard

class PentesterMessagePayload(BaseModel):
    content: str
    sender: str = "pentester"

@router.get("/api/projects/{project_id}/messages")
def get_pentester_messages(project_id: str) -> dict[str, Any]:
    messages = projects_store.list_client_messages(project_id)
    status = _typing_status.get(project_id, {})
    return {
        "messages": messages,
        "client_typing": (time.time() - status.get("client", 0)) < 3
    }

@router.post("/api/projects/{project_id}/messages")
def send_pentester_message(project_id: str, payload: PentesterMessagePayload) -> dict[str, Any]:
    projects_store.add_client_message(project_id, sender=payload.sender, content=payload.content.strip())
    return {"ok": True}

@router.post("/api/projects/{project_id}/typing")
def set_pentester_typing(project_id: str) -> dict[str, Any]:
    _typing_status.setdefault(project_id, {})["pentester"] = time.time()
    return {"ok": True}
