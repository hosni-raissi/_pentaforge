"""Shared agent tool entrypoints.

Keep imports lazy so lightweight runtimes such as the sandbox service do not
fail on unrelated optional tool dependencies during package initialization.
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS = {
    "RUN_CUSTOM_TOOL_DEFINITION": (".run_custom", "RUN_CUSTOM_TOOL_DEFINITION"),
    "run_custom": (".run_custom", "run_custom"),
    "RUN_PYTHON_TOOL_DEFINITION": (".run_python", "RUN_PYTHON_TOOL_DEFINITION"),
    "run_python": (".run_python", "run_python"),
    "SEARCH_WEB_TOOL_DEFINITION": (".search_web", "SEARCH_WEB_TOOL_DEFINITION"),
    "search_web": (".search_web", "search_web"),
    "FETCH_URL_CONTENT_TOOL_DEFINITION": (".fetch_url_content", "FETCH_URL_CONTENT_TOOL_DEFINITION"),
    "fetch_url_content": (".fetch_url_content", "fetch_url_content"),
}

__all__ = list(_EXPORTS.keys())


def __getattr__(name: str):
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attr_name = target
    module = import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
