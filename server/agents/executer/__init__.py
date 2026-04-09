"""Executer agents package."""

from __future__ import annotations

__all__ = [
    "ExecuterCallback",
    "ExecuterResult",
    "ReconExecuterAgent",
    "ExploitExecuterAgent",
    "VerifyExecuterAgent",
    "ReportExecuterAgent",
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

    if name == "VerifyExecuterAgent":
        from .verify.agent import VerifyExecuterAgent

        return VerifyExecuterAgent

    if name == "ReportExecuterAgent":
        from .report.agent import ReportExecuterAgent

        return ReportExecuterAgent

    if name == "RetestExecuterAgent":
        try:  # pragma: no cover
            from .retest.agent import RetestExecuterAgent
        except Exception as exc:  # pragma: no cover
            raise AttributeError(name) from exc
        return RetestExecuterAgent

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
