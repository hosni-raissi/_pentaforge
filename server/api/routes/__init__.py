"""API route modules."""

from __future__ import annotations

from importlib import import_module

_ROUTER_MODULES = {
    "ai_router": ".ai",
    "debug_router": ".debug",
    "health_router": ".health",
    "intel_router": ".intel",
    "projects_router": ".projects",
    "reports_router": ".reports",
    "scans_router": ".scans",
    "share_router": ".share",
    "target_types_router": ".target_types",
    "web_auth_router": ".web_auth",
    "settings_router": ".settings",
}

__all__ = list(_ROUTER_MODULES.keys())


def __getattr__(name: str):
    module_name = _ROUTER_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_name, __name__)
    router = getattr(module, "router")
    globals()[name] = router
    return router
