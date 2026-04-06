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
    "api_auth_test",
    "api_fuzzing",
    "db_injection_test",
}

_PACKAGE_DIR = Path(__file__).resolve().parent


def _detect_active_submodule_leaf() -> str | None:
    # Case 1: __main__.__spec__ is already populated.
    main_spec = getattr(__main__, "__spec__", None)
    main_module_name = getattr(main_spec, "name", "") if main_spec else ""
    if main_module_name.startswith(f"{__name__}."):
        return main_module_name.rsplit(".", 1)[-1]

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
            return mod_name.rsplit(".", 1)[-1]

    return None


_ACTIVE_SUBMODULE = _detect_active_submodule_leaf()
if _ACTIVE_SUBMODULE:
    _RECON_EXCLUDED_MODULES.add(_ACTIVE_SUBMODULE)

_MODULE_NAMES = discover_module_names(
    package_name=__name__,
    package_dir=_PACKAGE_DIR,
    exclude=_RECON_EXCLUDED_MODULES,
)

ALL_RECON_TOOLS, _LOAD_ERRORS = load_tools_from_module_names(_MODULE_NAMES)

if _LOAD_ERRORS:  # pragma: no cover - environment dependent imports
    for module_name, error in _LOAD_ERRORS.items():
        log.warning("recon_tool_module_load_failed", module=module_name, error=error)

RECON_TOOL_NAMES = [tool.name for tool in ALL_RECON_TOOLS]

__all__ = [
    "ALL_RECON_TOOLS",
    "RECON_TOOL_NAMES",
]
