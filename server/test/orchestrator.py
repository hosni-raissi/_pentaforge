"""Compatibility runner for orchestrator test.

Usage:
    python -m server.test.orchestrator
"""

from __future__ import annotations

import asyncio

from .test_orchestrator import main


if __name__ == "__main__":
    asyncio.run(main())
