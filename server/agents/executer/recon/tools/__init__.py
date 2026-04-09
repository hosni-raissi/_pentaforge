"""Recon tool registry."""

from __future__ import annotations

import __main__
import inspect
import sys
from pathlib import Path

import structlog

from server.core.tool import Tool
from server.agents.executer.tools_registry import (
    discover_module_names,
    load_tools_from_module_names,
)

log = structlog.get_logger(__name__)

# Intrusive checks moved to Exploit ownership.
_RECON_EXCLUDED_MODULES = {
    "api.api_auth_test",
    "api.api_fuzzing",
}

_PACKAGE_DIR = Path(__file__).resolve().parent


def _detect_active_submodule() -> str | None:
    # Case 1: __main__.__spec__ is already populated.
    main_spec = getattr(__main__, "__spec__", None)
    main_module_name = getattr(main_spec, "name", "") if main_spec else ""
    if main_module_name.startswith(f"{__name__}."):
        return main_module_name[len(f"{__name__}.") :]

    # Case 2: argv points to a module file in this package (after -m resolution).
    argv0 = sys.argv[0] if sys.argv else ""
    if argv0.endswith(".py"):
        candidate = Path(argv0).stem
        if (_PACKAGE_DIR / f"{candidate}.py").is_file():
            return candidate

    # Case 3: runpy is importing this package before executing target module.
    for frame in inspect.stack():
        if frame.function != "_get_module_details":
            continue
        mod_name = frame.frame.f_locals.get("mod_name")
        if isinstance(mod_name, str) and mod_name.startswith(f"{__name__}."):
            return mod_name[len(f"{__name__}.") :]

    return None


_ALL_RECON_TOOLS_CACHE: list[Tool] | None = None
_RECON_TOOL_NAMES_CACHE: list[str] | None = None
_LOAD_ERRORS_CACHE: dict[str, str] | None = None


def _load_recon_registry() -> tuple[list[Tool], dict[str, str]]:
    excluded_modules = set(_RECON_EXCLUDED_MODULES)
    active_submodule = _detect_active_submodule()
    if active_submodule:
        excluded_modules.add(active_submodule)

    module_names = discover_module_names(
        package_name=__name__,
        package_dir=_PACKAGE_DIR,
        exclude=excluded_modules,
        recursive=True,
    )

    tools, errors = load_tools_from_module_names(module_names)
    if errors:  # pragma: no cover - environment dependent imports
        for module_name, error in errors.items():
            log.warning("recon_tool_module_load_failed", module=module_name, error=error)

    return tools, errors


def _ensure_registry_loaded() -> None:
    global _ALL_RECON_TOOLS_CACHE, _RECON_TOOL_NAMES_CACHE, _LOAD_ERRORS_CACHE

    if _ALL_RECON_TOOLS_CACHE is not None and _RECON_TOOL_NAMES_CACHE is not None:
        return

    tools, errors = _load_recon_registry()
    _ALL_RECON_TOOLS_CACHE = tools
    _RECON_TOOL_NAMES_CACHE = [tool.name for tool in tools]
    _LOAD_ERRORS_CACHE = errors
    globals()["ALL_RECON_TOOLS"] = tools
    globals()["RECON_TOOL_NAMES"] = _RECON_TOOL_NAMES_CACHE


def __getattr__(name: str):
    if name in {"ALL_RECON_TOOLS", "RECON_TOOL_NAMES"}:
        _ensure_registry_loaded()
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"ALL_RECON_TOOLS", "RECON_TOOL_NAMES"})

__all__ = [
    "ALL_RECON_TOOLS",
    "RECON_TOOL_NAMES",
]
