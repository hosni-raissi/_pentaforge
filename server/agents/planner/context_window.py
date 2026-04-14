"""Planner agent context-window settings."""

from server.agents.context_window_manager import ContextWindowManager
from .config import PLANNER_CONTEXT_WINDOW_MAX_TOKENS

PLANNER_CONTEXT_WINDOW_KEY = "planner"


def build_planner_context_window(
    *,
    project_id: str | None,
    llm,
) -> ContextWindowManager | None:
    if not str(project_id or "").strip():
        return None
    return ContextWindowManager(
        project_id=str(project_id),
        agent_key=PLANNER_CONTEXT_WINDOW_KEY,
        max_tokens=PLANNER_CONTEXT_WINDOW_MAX_TOKENS,
        llm=llm,
    )
