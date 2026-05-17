"""Assistant tool exports."""

from server.agents.tools.run_custom import (
    RUN_CUSTOM_TOOL_DEFINITION as SHARED_RUN_CUSTOM_TOOL_DEFINITION,
    run_custom,
)

from .add_finding_to_brain import (
    ASSISTANT_ADD_FINDING_TO_BRAIN_TOOL_DEFINITION,
    add_finding_to_brain,
)
from server.agents.tools.fetch_url_content import (
    FETCH_URL_CONTENT_TOOL_DEFINITION as ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION,
    fetch_url_content,
)

from .mark_false_positive import (
    ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION,
    mark_false_positive,
)
from .search_project_vectors import (
    ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION,
    search_project_vectors,
)
from server.agents.tools.search_web import (
    SEARCH_WEB_TOOL_DEFINITION as ASSISTANT_SEARCH_WEB_TOOL_DEFINITION,
    search_web,
)

ASSISTANT_GET_PAGE_TOOL_DEFINITION = ASSISTANT_FETCH_URL_CONTENT_TOOL_DEFINITION
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
    "ASSISTANT_MARK_FALSE_POSITIVE_TOOL_DEFINITION",
    "ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION",
    "ASSISTANT_SEARCH_PROJECT_VECTORS_TOOL_DEFINITION",
    "ASSISTANT_SEARCH_WEB_TOOL_DEFINITION",
    "add_finding_to_brain",
    "fetch_url_content",
    "get_page",
    "mark_false_positive",
    "run_custom",
    "search_project_vectors",
    "search_web",
]
