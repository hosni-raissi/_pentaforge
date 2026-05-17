"""Planner Agent tools — auto-loaded like Intel Agent."""

from server.core.tool import Tool
from .get_checklists import get_checklists
from server.agents.tools.fetch_url_content import fetch_url_content as get_page
from .pentest_plan import (
    get_pentest_plan,
    update_pentest_plan,
)
from .search_kb import search_kb
from server.agents.tools.search_web import search_web
from .target_types import add_target_type, get_target_types, remove_target_type

ALL_PLANNER_TOOLS: list[Tool] = [
    get_checklists,
    get_page,
    search_kb,
    search_web,
    # Keep get_pentest_plan implemented/exported for reuse by other agents,
    # but do not expose it to PlannerAgent runtime tool list.
    update_pentest_plan,
    get_target_types,
    add_target_type,
    remove_target_type,
]
