"""Assistant tool exports.

Optional knowledge/RAG-backed tools must not prevent the lightweight Zigg
assistant from starting when those subsystems are absent.
"""

from __future__ import annotations

from typing import Any

from server.agents.tools.run_custom import (
    RUN_CUSTOM_TOOL_DEFINITION as SHARED_RUN_CUSTOM_TOOL_DEFINITION,
    run_custom,
)
from server.agents.tools.fetch_url_content import (
    FETCH_URL_CONTENT_TOOL_DEFINITION as ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION,
    fetch_url_content,
)


def _make_unavailable_tool_definition(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{description} Currently unavailable in this Zigg runtime.",
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }


def _unavailable_sync_tool(tool_name: str):
    def _tool(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "success": False,
            "error": f"Tool '{tool_name}' is unavailable because optional knowledge/RAG dependencies are not installed.",
        }

    return _tool


def _unavailable_async_tool(tool_name: str):
    async def _tool(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "success": False,
            "error": f"Tool '{tool_name}' is unavailable because optional knowledge/RAG dependencies are not installed.",
        }

    return _tool


try:
    from .add_finding_to_brain import (
        ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION,
        add_finding_to_brain,
    )
except ModuleNotFoundError:
    ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION = _make_unavailable_tool_definition(
        "add_finding_to_brain",
        "Add a new finding, vulnerability, or intelligence note to the project's 'brain'.",
        {
            "title": {"type": "string", "description": "Short, descriptive title of the finding."},
            "description": {"type": "string", "description": "Detailed explanation of the finding."},
            "severity": {"type": "string", "description": "Estimated severity level."},
            "status": {"type": "string", "description": "Whether the finding is done or not_done."},
        },
        ["title", "description"],
    )
    add_finding_to_brain = _unavailable_sync_tool("add_finding_to_brain")


try:
    from .search_project_vectors import (
        ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION,
        search_project_vectors,
    )
except ModuleNotFoundError:
    ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION = _make_unavailable_tool_definition(
        "search_project_vectors",
        "Search assistant-available project knowledge vectors for the current project.",
        {
            "query": {"type": "string", "description": "Search phrase about saved project knowledge."},
            "limit": {"type": "integer", "description": "Maximum number of relevant matches to return."},
            "kinds": {"type": "array", "items": {"type": "string"}, "description": "Optional artifact kinds."},
        },
        ["query"],
    )
    search_project_vectors = _unavailable_async_tool("search_project_vectors")

try:
    from server.agents.tools.search_web import (
        SEARCH_WEB_TOOL_DEFINITION as ASSISTANT_SEARCH_WEB_TOOL_DEFINITION,
        search_web,
    )
except ModuleNotFoundError:
    ASSISTANT_SEARCH_WEB_TOOL_DEFINITION = _make_unavailable_tool_definition(
        "search_web",
        "Search the public web for current external information.",
        {
            "query": {"type": "string", "description": "The external topic or question to search for."},
            "max_results": {"type": "integer", "description": "Maximum number of web results to return."},
        },
        ["query"],
    )
    search_web = _unavailable_async_tool("search_web")

ASSISTANT_GET_PAGE_TOOL_DEFINITION = {
    "name": "get_page",
    "description": (
        "Retrieve the text content of a targeted web page. Useful to view specific "
        "remediation advice, project files, or specific referenced resources in local scope."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to fetch and read.",
            },
            "css_selector": {
                "type": "string",
                "description": "Optional CSS selector to extract a specific section from the page.",
            },
        },
        "required": ["url"],
        "additionalProperties": False,
    },
}
get_page = fetch_url_content


ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION = {
    **SHARED_RUN_CUSTOM_TOOL_DEFINITION,
    "description": (
        "Execute a read-only diagnostic or pentest support command safely for the assistant chat. "
        "Blocks destructive commands, local code interpreters, package managers, repo-mutating workflows, "
        "custom working directories, and local write-style operations."
    ),
}

__all__ = [
    "ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION",
    "ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION",
    "ASSISTANT_GET_PAGE_TOOL_DEFINITION",
    "ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION",
    "ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION",
    "ASSISTANT_SEARCH_WEB_TOOL_DEFINITION",
    "add_finding_to_brain",
    "fetch_url_content",
    "get_page",
    "run_custom",
    "search_project_vectors",
    "search_web",
]
