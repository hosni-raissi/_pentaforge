"""Recon executer agent."""

from __future__ import annotations

__all__ = ["ReconExecuterAgent"]


def __getattr__(name: str):
    if name == "ReconExecuterAgent":
        from .agent import ReconExecuterAgent

        return ReconExecuterAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
