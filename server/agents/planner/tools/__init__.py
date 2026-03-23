"""Planner Agent tools — auto-loaded like Intel Agent."""

from server.core.tool import Tool
from .get_page import get_page
from .pentest_plan import (
    get_pentest_plan,
    update_pentest_plan,
)
from .search_kb import search_kb
from .search_web import search_web
from .target_types import add_target_type, get_target_types, remove_target_type

ALL_PLANNER_TOOLS: list[Tool] = [
    get_page,
    search_kb,
    search_web,
    get_pentest_plan,
    update_pentest_plan,
    get_target_types,
    add_target_type,
    remove_target_type,
]
