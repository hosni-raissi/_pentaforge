"""Shared helpers to build runtime Tool registries from module definitions."""

from __future__ import annotations

import copy
import importlib
import inspect
from pathlib import Path
from typing import Any, Callable, Iterable

import structlog

from server.core.tool import Tool

log = structlog.get_logger(__name__)


def _is_tool_definition(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    return "name" in obj and "description" in obj and "parameters" in obj


def _normalize_tool_schema(parameters: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """
    Normalize schema for runtime consistency.
    Returns (normalized_schema, legacy_list_type_expected).
    """
    schema = copy.deepcopy(parameters) if isinstance(parameters, dict) else {}
    legacy_list_type = False

    props = schema.get("properties")
    if isinstance(props, dict):
        lt = props.get("list_type")
        if isinstance(lt, dict):
            enum = lt.get("enum")
            if isinstance(enum, list):
                lowered = {str(x).lower() for x in enum}
                if "mine" in lowered or "yours" in lowered:
                    legacy_list_type = True
                    lt["enum"] = ["user", "ia"]
                    desc = str(lt.get("description", "")).strip()
                    suffix = "Use 'user' for built-in lists and 'ia' for inline lists."
                    lt["description"] = f"{desc} {suffix}".strip()

    return schema, legacy_list_type


def _inject_mutable_defaults(fn: Callable[..., Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Avoid shared mutable default bugs without editing every module."""
    out = dict(kwargs)
    sig = inspect.signature(fn)
    for name, param in sig.parameters.items():
        if name in out:
            continue
        default = param.default
        if isinstance(default, (list, dict, set)):
            out[name] = copy.deepcopy(default)
    return out


def _normalize_result_shape(result: Any) -> Any:
    if not isinstance(result, dict):
        return result
    normalized = dict(result)
    normalized.setdefault("success", not bool(normalized.get("error")))
    normalized.setdefault("error", None)
    normalized.setdefault("execution_time", 0.0)
    normalized.setdefault("raw_output", None)
    return normalized


def _wrap_tool_function(
    fn: Callable[..., Any],
    *,
    legacy_list_type: bool,
) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(fn):
        async def _async_wrapped(**kwargs: Any) -> Any:
            safe_kwargs = _inject_mutable_defaults(fn, kwargs)
            if legacy_list_type and "list_type" in safe_kwargs:
                v = str(safe_kwargs["list_type"]).strip().lower()
                if v in {"user", "mine"}:
                    safe_kwargs["list_type"] = "mine"
                elif v in {"ia", "yours"}:
                    safe_kwargs["list_type"] = "yours"
            result = await fn(**safe_kwargs)
            return _normalize_result_shape(result)
        return _async_wrapped

    def _sync_wrapped(**kwargs: Any) -> Any:
        safe_kwargs = _inject_mutable_defaults(fn, kwargs)
        if legacy_list_type and "list_type" in safe_kwargs:
            v = str(safe_kwargs["list_type"]).strip().lower()
            if v in {"user", "mine"}:
                safe_kwargs["list_type"] = "mine"
            elif v in {"ia", "yours"}:
                safe_kwargs["list_type"] = "yours"
        result = fn(**safe_kwargs)
        return _normalize_result_shape(result)

    return _sync_wrapped


def _collect_module_tools(module: Any) -> list[Tool]:
    collected: list[Tool] = []
    by_name: dict[str, Tool] = {}

    # 1) Already decorated Tool objects
    for value in vars(module).values():
        if isinstance(value, Tool):
            normalized_schema, legacy = _normalize_tool_schema(value.parameters)
            wrapped = _wrap_tool_function(value.fn, legacy_list_type=legacy)
            by_name[value.name] = Tool(
                name=value.name,
                description=value.description,
                fn=wrapped,
                parameters=normalized_schema,
            )

    # 2) Legacy *_TOOL_DEFINITION dicts
    for attr_name, value in vars(module).items():
        if not _is_tool_definition(value):
            continue
        if not (attr_name.endswith("_TOOL_DEFINITION") or attr_name.endswith("_TOOL")):
            continue

        tool_name = str(value.get("name", "")).strip()
        if not tool_name:
            continue

        fn_obj = getattr(module, tool_name, None)
        if isinstance(fn_obj, Tool):
            base_fn = fn_obj.fn
        elif callable(fn_obj):
            base_fn = fn_obj
        else:
            log.warning(
                "tool_definition_missing_callable",
                module=getattr(module, "__name__", "unknown"),
                tool_name=tool_name,
            )
            continue

        parameters, legacy = _normalize_tool_schema(value.get("parameters", {}))
        wrapped = _wrap_tool_function(base_fn, legacy_list_type=legacy)
        by_name[tool_name] = Tool(
            name=tool_name,
            description=str(value.get("description", "")),
            fn=wrapped,
            parameters=parameters,
        )

    collected.extend(sorted(by_name.values(), key=lambda t: t.name))
    return collected


def load_tools_from_module_names(module_names: Iterable[str]) -> tuple[list[Tool], dict[str, str]]:
    """Import modules and collect Tool objects safely."""
    tools: list[Tool] = []
    errors: dict[str, str] = {}
    seen: set[str] = set()

    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover - depends on environment
            errors[module_name] = f"{type(exc).__name__}: {exc}"
            continue

        for tool_obj in _collect_module_tools(module):
            if tool_obj.name in seen:
                continue
            seen.add(tool_obj.name)
            tools.append(tool_obj)

    tools.sort(key=lambda t: t.name)
    return tools, errors


def discover_module_names(
    package_name: str,
    package_dir: Path,
    *,
    exclude: set[str] | None = None,
    recursive: bool = False,
) -> list[str]:
    """Discover module names from a directory of .py files."""
    excluded = set(exclude or set())
    names: list[str] = []
    pattern = "**/*.py" if recursive else "*.py"

    for file_path in sorted(package_dir.glob(pattern)):
        rel = file_path.relative_to(package_dir)
        module_path = rel.with_suffix("").as_posix().replace("/", ".")
        stem = file_path.stem
        if stem == "__init__":
            continue
        if (
            stem in excluded
            or module_path in excluded
            or f"{package_name}.{module_path}" in excluded
        ):
            continue
        names.append(f"{package_name}.{module_path}")

    return names
