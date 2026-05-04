"""PentaForge API app wiring."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.api.dependencies import init_api_state, rate_limiter
from server.api.middleware import APISafetyMiddleware
from server.api.routes import (
    ai_router,
    debug_router,
    health_router,
    intel_router,
    projects_router,
    reports_router,
    scans_router,
    share_router,
    target_types_router,
    web_auth_router,
    settings_router,
)

app = FastAPI(
    title="PentaForge Server API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    APISafetyMiddleware,
    limiter=rate_limiter,
    excluded_paths={
        "/api/health",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "tauri://localhost",
        "https://tauri.localhost",
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_api_state()


app.include_router(health_router)
app.include_router(ai_router)
app.include_router(debug_router)
app.include_router(projects_router)
app.include_router(reports_router)
app.include_router(scans_router)
app.include_router(target_types_router)
app.include_router(intel_router)
app.include_router(share_router)
app.include_router(web_auth_router)
app.include_router(settings_router)
