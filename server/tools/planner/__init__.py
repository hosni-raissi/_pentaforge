"""
Planner Tools — All tools available to the planner agent.

Import this module to get the full list of Tool objects ready for the agent.
"""

from server.core.tool import Tool

from .clone_repo import clone_repo
from .get_page import get_page
from .pentest_plan import get_pentest_plan, update_pentest_plan
from .search_kb import search_kb

ALL_TOOLS: list[Tool] = [
    clone_repo,
    get_page,
    search_kb,
    get_pentest_plan,
    update_pentest_plan,
]

__all__ = ["ALL_TOOLS"]
