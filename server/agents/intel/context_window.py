"""Intel agent context-window settings."""

from server.agents.context_window_manager import ContextWindowManager
from .config import INTEL_CONTEXT_WINDOW_MAX_TOKENS

INTEL_CONTEXT_WINDOW_KEY = "intel"


def build_intel_context_window(
    *,
    project_id: str | None,
    llm,
) -> ContextWindowManager | None:
    if not str(project_id or "").strip():
        return None
    return ContextWindowManager(
        project_id=str(project_id),
        agent_key=INTEL_CONTEXT_WINDOW_KEY,
        max_tokens=INTEL_CONTEXT_WINDOW_MAX_TOKENS,
        llm=llm,
    )
