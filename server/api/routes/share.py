"""Share-link routes for project reports and client Q&A."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from server.api.dependencies import projects_store

router = APIRouter(tags=["share"])


class ShareLinkCreatePayload(BaseModel):
    expires_hours: int = Field(default=24, ge=1, le=87600)
    password: str | None = Field(default=None, max_length=128)
    one_time: bool = False


class ShareLinkAccessPayload(BaseModel):
    password: str | None = None


class ClientMessagePayload(BaseModel):
    password: str | None = None
    content: str


import time

# Ephemeral in-memory store for typing indicators
# Format: { project_id: { "pentester": timestamp, "client": timestamp } }
_typing_status: dict[str, dict[str, float]] = {}


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
    # Check if password is required
    is_protected = False
    try:
        # We use a lower-level check to avoid 'accessing' the link (which might increment view counts or fail)
        with projects_store._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT password_hash FROM share_links WHERE token = ? AND revoked = 0", (token,))
            row = cur.fetchone()
            if row and row["password_hash"]:
                is_protected = True
    except Exception:
        pass

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PentaForge Client Portal</title>
  <style>
    :root {{
      --bg: #0c1220;
      --surface: #111827;
      --surface-light: #1e293b;
      --border: #1e293b;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
    }}
    
    [data-theme="light"] {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-light: #f1f5f9;
      --border: #e2e8f0;
      --text: #1e293b;
      --text-muted: #64748b;
      --primary: #4f46e5;
      --primary-hover: #4338ca;
    }}

    body {{ font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; display: flex; height: 100vh; overflow: hidden; transition: background 0.2s, color 0.2s; }}
    .auth-overlay {{ position: fixed; inset: 0; background: var(--bg); display: flex; align-items: center; justify-content: center; z-index: 1000; }}
    .auth-card {{ background: var(--surface); padding: 2rem; border-radius: 12px; border: 1px solid var(--border); width: 100%; max-width: 400px; text-align: center; }}
    .auth-card input {{ width: 100%; box-sizing: border-box; padding: 0.75rem; margin: 1rem 0; background: var(--surface-light); border: 1px solid var(--border); color: var(--text); border-radius: 6px; }}
    .auth-card button {{ width: 100%; padding: 0.75rem; background: var(--primary); border: none; color: white; border-radius: 6px; cursor: pointer; font-weight: 600; }}
    
    .layout {{ display: flex; width: 100%; height: 100%; }}
    .report-pane {{ flex: 1; padding: 2rem; overflow-y: auto; background: var(--bg); }}
    
    .chat-pane {{ width: 450px; background: var(--surface); border-left: 1px solid var(--border); display: flex; flex-direction: column; }}
    .chat-header {{ padding: 1rem; border-bottom: 1px solid var(--border); font-weight: 600; background: var(--surface); display: flex; align-items: center; justify-content: space-between; }}
    .chat-messages {{ flex: 1; padding: 1rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }}
    .msg {{ padding: 0.75rem; border-radius: 8px; max-width: 85%; line-height: 1.4; font-size: 0.9rem; word-wrap: break-word; overflow-wrap: break-word; word-break: break-word; }}
    .msg.client {{ background: var(--primary); color: white; align-self: flex-end; border-bottom-right-radius: 0; }}
    .msg.pentester {{ background: var(--surface-light); color: var(--text); align-self: flex-start; border-bottom-left-radius: 0; border: 1px solid var(--border); }}
    .chat-input {{ padding: 1rem; border-top: 1px solid var(--border); background: var(--surface); display: flex; gap: 0.5rem; }}
    .chat-input input {{ flex: 1; padding: 0.5rem; background: var(--surface-light); border: 1px solid var(--border); color: var(--text); border-radius: 6px; }}
    .chat-input button {{ padding: 0.5rem 1rem; background: var(--primary); border: none; color: white; border-radius: 6px; cursor: pointer; }}
    
    #error {{ color: #ef4444; margin-top: 1rem; font-size: 0.9rem; }}
    iframe {{ width: 100%; height: 100%; border: none; background: white; border-radius: 12px; }}
    .theme-toggle {{ background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px; border-radius: 4px; display: flex; align-items: center; }}
    .theme-toggle:hover {{ color: var(--text); background: var(--surface-light); }}
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

  <div class="layout" id="portal-layout" style="display: none;">
    <div class="report-pane" style="display: flex; flex-direction: column;">
      <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-shrink: 0;">
        <button id="btn-view-html" onclick="setView('html')" style="padding: 0.5rem 1rem; background: var(--primary); border: none; color: white; border-radius: 6px; cursor: pointer; font-weight: 500;">HTML View</button>
        <button id="btn-view-md" onclick="setView('markdown')" style="padding: 0.5rem 1rem; background: var(--surface-light); border: 1px solid var(--border); color: var(--text); border-radius: 6px; cursor: pointer; font-weight: 500;">Markdown View</button>
        
        <div style="margin-left: auto; display: flex; gap: 0.5rem;">
          <select id="download-format" style="padding: 0.5rem; background: var(--surface-light); border: 1px solid var(--border); color: var(--text); border-radius: 6px; font-size: 0.85rem; cursor: pointer;">
            <option value="html">HTML</option>
            <option value="markdown">Markdown</option>
          </select>
          <button onclick="downloadActive()" style="padding: 0.5rem 1rem; background: var(--surface-light); border: 1px solid var(--border); color: var(--text); border-radius: 6px; cursor: pointer; font-weight: 500;">Download</button>
        </div>
      </div>
      <iframe id="report-frame" style="flex: 1; border-radius: 12px; border: 1px solid var(--border);"></iframe>
      <pre id="report-markdown" style="display: none; flex: 1; white-space: pre-wrap; font-family: monospace; font-size: 0.85rem; background: var(--surface); padding: 1.5rem; border-radius: 12px; margin: 0; border: 1px solid var(--border); overflow-y: auto; color: var(--text);"></pre>
    </div>
    <div class="chat-pane">
      <div class="chat-header">
        <div style="display: flex; align-items: center; gap: 8px;">
          Q&A with Pentester
          <span id="typing-indicator" style="display: none; font-size: 0.8rem; font-style: italic; color: var(--text-muted); margin-left: 8px;">is typing...</span>
        </div>
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle Theme">
          <span id="theme-icon">🌙</span>
        </button>
      </div>
      <div class="chat-messages" id="messages"></div>
      <div class="chat-input">
        <input type="text" id="msg-input" placeholder="Ask a question..." />
        <button id="send-btn">Send</button>
      </div>
    </div>
  </div>

  <script>
    const token = {token!r};
    const isPasswordProtected = {"true" if is_protected else "false"};
    let currentPassword = null;
    
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

    // Auto-unlock or bind events
    document.addEventListener('DOMContentLoaded', () => {{
      console.log("[PORTAL] Portal loaded, isProtected:", isPasswordProtected);
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
    let currentTheme = 'dark';

    function toggleTheme() {{
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', currentTheme);
      document.getElementById('theme-icon').textContent = currentTheme === 'dark' ? '🌙' : '☀️';
    }}

    async function setView(format) {{
      document.getElementById('btn-view-html').style.background = format === 'html' ? 'var(--primary)' : 'var(--surface-light)';
      document.getElementById('btn-view-md').style.background = format === 'markdown' ? 'var(--primary)' : 'var(--surface-light)';
      document.getElementById('report-frame').style.display = format === 'html' ? 'block' : 'none';
      document.getElementById('report-markdown').style.display = format === 'markdown' ? 'block' : 'none';
      
      if (format === 'html' && !htmlContent) {{
        const res = await fetch(`/api/share/${{token}}/html`, {{ method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{password: currentPassword}}) }});
        if (res.ok) {{
          htmlContent = await res.text();
          const doc = document.getElementById('report-frame').contentWindow.document;
          doc.open(); doc.write(htmlContent); doc.close();
        }}
      }} else if (format === 'markdown' && !mdContent) {{
        document.getElementById('report-markdown').textContent = 'Loading markdown...';
        const res = await fetch(`/api/share/${{token}}/markdown`, {{ 
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
      const format = document.getElementById('download-format').value;
      const isHtml = format === 'html';
      let content = isHtml ? htmlContent : mdContent;
      if (!content) {{
        // Fetch if not available
        const res = await fetch(`/api/share/${{token}}/${{format}}`, {{ method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{password: currentPassword}}) }});
        if (res.ok) {{
          content = await res.text();
          if (isHtml) htmlContent = content; else mdContent = content;
        }}
      }}
      if (!content) return;
      const blob = new Blob([content], {{ type: isHtml ? 'text/html' : 'text/markdown' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report.${{isHtml ? 'html' : 'md'}}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }}
    
    async function loadMessages() {{
      const res = await fetch(`/api/share/${{token}}/messages`, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{password: currentPassword}})
      }});
      if (res.ok) {{
        const data = await res.json();
        
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


@router.post("/api/share/{token}/messages")
def get_shared_messages(token: str, payload: ShareLinkAccessPayload) -> dict[str, Any]:
    try:
        data = projects_store.access_share_link(token, password=(payload.password or "").strip() or None)
        project_id = data["project"]["id"]
        messages = projects_store.list_client_messages(project_id)
        status = _typing_status.get(project_id, {})
        return {
            "messages": messages,
            "pentester_typing": (time.time() - status.get("pentester", 0)) < 3
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
