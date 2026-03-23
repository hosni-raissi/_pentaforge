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
import re
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
        # Unwrap Optional and normalize generic origins (e.g., list[str] -> list)
        origin = getattr(hint, "__origin__", None)
        if origin is not None:
            args = getattr(hint, "__args__", ())
            if type(None) in args:
                hint = next((a for a in args if a is not type(None)), str)
                origin = getattr(hint, "__origin__", None)
            if origin in (list, dict):
                hint = origin
        json_type = _TYPE_MAP.get(hint, "string")
        if json_type == "integer":
            properties[name] = {
                "anyOf": [
                    {"type": "integer"},
                    {"type": "string", "pattern": r"^-?\d+$"},
                ],
            }
        elif json_type == "number":
            properties[name] = {
                "anyOf": [
                    {"type": "number"},
                    {"type": "string", "pattern": r"^-?\d+(\.\d+)?$"},
                ],
            }
        elif json_type == "boolean":
            properties[name] = {
                "anyOf": [
                    {"type": "boolean"},
                    {"type": "string", "enum": ["true", "false", "1", "0", "yes", "no"]},
                ],
            }
        else:
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


def _target_json_type(schema: dict[str, Any]) -> str | None:
    """Pick the most useful target type from a JSON schema property."""
    t = schema.get("type")
    if isinstance(t, str):
        return t
    if isinstance(t, list):
        for candidate in ("integer", "number", "boolean", "array", "object", "string"):
            if candidate in t:
                return candidate
    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        # Prefer non-string primitives so we coerce "5" -> 5 where useful.
        for candidate in ("integer", "number", "boolean", "array", "object", "string"):
            for item in any_of:
                if isinstance(item, dict) and item.get("type") == candidate:
                    return candidate
    return None


def coerce_args_from_schema(parameters: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    """Coerce incoming tool args to schema-compatible runtime types when safe."""
    if not isinstance(args, dict):
        return {}
    props = parameters.get("properties", {}) if isinstance(parameters, dict) else {}
    if not isinstance(props, dict):
        return args

    coerced: dict[str, Any] = {}
    for key, value in args.items():
        prop = props.get(key, {})
        target = _target_json_type(prop if isinstance(prop, dict) else {})
        if target is None:
            coerced[key] = value
            continue

        if target == "integer" and isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
            coerced[key] = int(value.strip())
            continue
        if target == "number" and isinstance(value, str) and re.fullmatch(r"-?\d+(\.\d+)?", value.strip()):
            coerced[key] = float(value.strip())
            continue
        if target == "boolean" and isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "yes"}:
                coerced[key] = True
                continue
            if lowered in {"false", "0", "no"}:
                coerced[key] = False
                continue
        if target in {"array", "object"} and isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    decoded = json.loads(stripped)
                    if target == "array" and isinstance(decoded, list):
                        coerced[key] = decoded
                        continue
                    if target == "object" and isinstance(decoded, dict):
                        coerced[key] = decoded
                        continue
                except json.JSONDecodeError:
                    pass
        coerced[key] = value

    return coerced


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
