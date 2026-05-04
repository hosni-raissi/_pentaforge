"""Assistant tool for project-scoped vector search."""

from __future__ import annotations

from typing import Any

from server.db.projects.project_rag import search_project_vectors as search_project_rag


async def search_project_vectors(
    *,
    project_id: str,
    query: str,
    limit: int = 5,
    kinds: list[str] | None = None,
    target: str = "",
    target_type: str = "",
) -> dict[str, Any]:
    return await search_project_rag(
        project_id=project_id,
        query=query,
        limit=limit,
        kinds=kinds,
        target=target,
        target_type=target_type,
    )


ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION = {
    "name": "search_project_vectors",
    "description": (
        "Search assistant-available project knowledge vectors such as verified vulnerabilities "
        "and saved system memory markdown for the current project."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The specific question or search phrase about saved project vulnerabilities or memory for the active target only.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 8,
                "default": 5,
                "description": "Maximum number of relevant matches to return.",
            },
            "kinds": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["verified_vulnerability", "system_memory_markdown"],
                },
                "description": "Optional artifact kinds to narrow the search.",
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}
