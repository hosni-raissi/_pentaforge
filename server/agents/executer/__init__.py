"""Executer agents package."""

from .base import ExecuterCallback, ExecuterResult
from .exploit.agent import ExploitExecuterAgent
from .recon.agent import ReconExecuterAgent
from .report.agent import ReportExecuterAgent
from .verify.agent import VerifyExecuterAgent

# Retest can have optional dependencies during refactors; keep package importable.
try:  # pragma: no cover
    from .retest.agent import RetestExecuterAgent
except Exception:  # pragma: no cover
    RetestExecuterAgent = None  # type: ignore[assignment]

__all__ = [
    "ExecuterCallback",
    "ExecuterResult",
    "ReconExecuterAgent",
    "ExploitExecuterAgent",
    "VerifyExecuterAgent",
    "ReportExecuterAgent",
]

if RetestExecuterAgent is not None:
    __all__.append("RetestExecuterAgent")
