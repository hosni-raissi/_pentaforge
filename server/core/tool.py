"""
Tool — Base class and decorator for agent tools.

Tools are callable units that an LLM agent can invoke via function calling.
Each tool declares its name, description, and JSON-schema parameters so the
LLM knows how to call it.

Usage:

    @tool(name="search_kb", description="Search the knowledge base.")
    async def search_kb(query: str, domain: str = "shared") -> str:
        ...
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Callable, get_type_hints


# Python type → JSON schema type mapping
_TYPE_MAP: dict[type, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
}


@dataclass
class Tool:
    """A callable tool with an OpenAI-compatible function schema."""

    name: str
    description: str
    fn: Callable[..., Any]
    parameters: dict[str, Any] = field(default_factory=dict)

    def schema(self) -> dict[str, Any]:
        """Return the OpenAI tool schema for this tool."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    async def execute(self, **kwargs: Any) -> str:
        """Run the tool and return a string result."""
        result = self.fn(**kwargs)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, str):
            result = json.dumps(result, default=str)
        return result


def _build_parameters(fn: Callable[..., Any]) -> dict[str, Any]:
    """Infer JSON schema parameters from function signature + type hints."""
    sig = inspect.signature(fn)
    hints = get_type_hints(fn)
    properties: dict[str, Any] = {}
    required: list[str] = []

    for name, param in sig.parameters.items():
        if name == "self":
            continue
        hint = hints.get(name, str)
        # Unwrap Optional
        origin = getattr(hint, "__origin__", None)
        if origin is not None:
            args = getattr(hint, "__args__", ())
            if type(None) in args:
                hint = next((a for a in args if a is not type(None)), str)
        json_type = _TYPE_MAP.get(hint, "string")
        properties[name] = {"type": json_type}
        if param.default is inspect.Parameter.empty:
            required.append(name)

    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
    }
    if required:
        schema["required"] = required
    return schema


def tool(name: str, description: str) -> Callable[[Callable[..., Any]], Tool]:
    """Decorator that turns an async function into a Tool with auto-inferred schema."""

    def wrapper(fn: Callable[..., Any]) -> Tool:
        return Tool(
            name=name,
            description=description,
            fn=fn,
            parameters=_build_parameters(fn),
        )

    return wrapper
