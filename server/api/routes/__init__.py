"""API route modules."""

from .ai import router as ai_router
from .debug import router as debug_router
from .health import router as health_router
from .intel import router as intel_router
from .projects import router as projects_router
from .scans import router as scans_router
from .share import router as share_router
from .target_types import router as target_types_router
from .web_auth import router as web_auth_router

__all__ = [
    "ai_router",
    "debug_router",
    "health_router",
    "intel_router",
    "projects_router",
    "scans_router",
    "share_router",
    "target_types_router",
    "web_auth_router",
]
