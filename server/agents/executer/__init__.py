"""Executer agents package."""

from __future__ import annotations

__all__ = [
    "ExecuterCallback",
    "ExecuterResult",
    "ReconExecuterAgent",
    "ExploitExecuterAgent",
]

def __getattr__(name: str):
    if name in {"ExecuterCallback", "ExecuterResult"}:
        from .base import ExecuterCallback, ExecuterResult

        return {
            "ExecuterCallback": ExecuterCallback,
            "ExecuterResult": ExecuterResult,
        }[name]

    if name == "ReconExecuterAgent":
        from .recon.agent import ReconExecuterAgent

        return ReconExecuterAgent

    if name == "ExploitExecuterAgent":
        from .exploit.agent import ExploitExecuterAgent

        return ExploitExecuterAgent

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
