"""Configuration for project persistence (SQLite)."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
_DEFAULT_DB_PATH = Path(__file__).resolve().parent / "projects.db"


class ProjectsDBConfig(BaseSettings):
    """SQLite settings for project storage."""

    # Local sqlite file path for project persistence.
    projects_db_path: str = Field(
        default=str(_DEFAULT_DB_PATH),
        alias="PROJECTS_DB_PATH",
    )

    model_config = {
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
        "populate_by_name": True,
    }


projects_db_config = ProjectsDBConfig()
