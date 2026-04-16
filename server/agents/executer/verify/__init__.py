"""Verify executer agent."""

from __future__ import annotations

__all__ = ["VerifyExecuterAgent"]


def __getattr__(name: str):
    if name == "VerifyExecuterAgent":
        from .agent import VerifyExecuterAgent

        return VerifyExecuterAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
