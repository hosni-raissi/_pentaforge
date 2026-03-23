"""Recon tool registry."""

from server.core.tool import Tool

from .record_recon_signal import record_recon_signal

ALL_RECON_TOOLS: list[Tool] = [record_recon_signal]

__all__ = ["ALL_RECON_TOOLS", "record_recon_signal"]
