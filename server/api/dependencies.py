"""Shared API dependencies (stores and startup hooks)."""

from __future__ import annotations

from server.db.knowledge.storage.intel_state_store import IntelStateStore
from server.db.projects import ProjectsStore

projects_store = ProjectsStore()
intel_state_store = IntelStateStore()


def init_api_state() -> None:
    """Initialize database schema required by API routes."""
    projects_store.init_schema()

