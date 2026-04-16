"""Retest executer agent."""

from __future__ import annotations

__all__ = ["RetestExecuterAgent"]


def __getattr__(name: str):
    if name == "RetestExecuterAgent":
        from .agent import RetestExecuterAgent

        return RetestExecuterAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
