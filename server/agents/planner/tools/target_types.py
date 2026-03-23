"""Standalone tools for reading and mutating plan target types."""

from __future__ import annotations

import structlog

from server.core.tool import tool
from .pentest_plan import VALID_TARGET_TYPES, _current_plan

logger = structlog.get_logger(__name__)


@tool(
    name="get_target_types",
    description="Return active target types from current plan.",
)
async def get_target_types() -> str:
    return str(sorted(set(_current_plan.get("target_types", []))))


@tool(
    name="add_target_type",
    description="Add one target type to plan. Only for NEW surfaces.",
)
async def add_target_type(target_type: str) -> str:
    if target_type not in VALID_TARGET_TYPES:
        return f"Invalid: '{target_type}'."

    current = set(_current_plan.get("target_types", []))
    if target_type in current:
        return f"Already present: '{target_type}'. Types: {sorted(current)}"

    current.add(target_type)
    _current_plan["target_types"] = sorted(current)
    logger.info("target_type_added", target_type=target_type)
    return f"Added '{target_type}'. Types: {_current_plan['target_types']}"


@tool(
    name="remove_target_type",
    description="Remove one target type from plan.",
)
async def remove_target_type(target_type: str) -> str:
    current = set(_current_plan.get("target_types", []))
    if target_type not in current:
        return f"Not present: '{target_type}'. Types: {sorted(current)}"

    current.remove(target_type)
    _current_plan["target_types"] = sorted(current)
    logger.info("target_type_removed", target_type=target_type)
    return f"Removed '{target_type}'. Types: {_current_plan['target_types']}"