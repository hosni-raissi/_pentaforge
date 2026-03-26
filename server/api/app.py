"""PentaForge API app wiring."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.api.dependencies import init_api_state
from server.api.middleware import APIRateLimitMiddleware
from server.api.routes import (
    health_router,
    intel_router,
    projects_router,
    share_router,
    target_types_router,
)

app = FastAPI(
    title="PentaForge Server API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    APIRateLimitMiddleware,
    excluded_paths={
        "/api/health",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_api_state()


app.include_router(health_router)
app.include_router(projects_router)
app.include_router(target_types_router)
app.include_router(intel_router)
app.include_router(share_router)
