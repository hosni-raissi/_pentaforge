"""Shared API dependencies (stores and startup hooks)."""

from __future__ import annotations

from server.app.orchestrator import ScanOrchestratorService
from server.db.knowledge.storage.intel_state_store import IntelStateStore
from server.db.projects import ProjectsStore
from server.layers.safety.rate_limiter import RateLimiter

projects_store = ProjectsStore()
intel_state_store = IntelStateStore()
rate_limiter = RateLimiter()
scan_orchestrator = ScanOrchestratorService(projects_store)


def init_api_state() -> None:
    """Initialize database schema required by API routes."""
    projects_store.init_schema()
    projects_store.recover_interrupted_scans()
