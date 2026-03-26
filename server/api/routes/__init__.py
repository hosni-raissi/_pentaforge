"""API route modules."""

from .health import router as health_router
from .intel import router as intel_router
from .projects import router as projects_router
from .share import router as share_router
from .target_types import router as target_types_router

__all__ = [
    "health_router",
    "intel_router",
    "projects_router",
    "share_router",
    "target_types_router",
]

