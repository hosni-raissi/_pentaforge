"""
LocalLLMClient — Async Ollama-compatible chat completion client.

Connects to a local Ollama instance via its OpenAI-compatible API
(http://localhost:11434/v1). No API key required.

Usage:
    from server.core.llm_local import LocalLLMClient
    from server.config.agent import local_llm_config

    client = LocalLLMClient(local_llm_config)
    response = await client.chat([ChatMessage(role="user", content="Hello")])
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import structlog

from server.config.agent import LocalLLMConfig
from server.core.llm import ChatMessage, LLMResponse

logger = structlog.get_logger(__name__)


class LocalLLMClient:
    """Async client for local Ollama LLM via its OpenAI-compatible endpoint."""

    def __init__(self, config: LocalLLMConfig) -> None:
        self._config = config
        self._http = httpx.AsyncClient(
            base_url=config.api_url,
            headers={"Content-Type": "application/json"},
            timeout=httpx.Timeout(180.0, connect=10.0),
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        use_config_max_tokens: bool = True,
    ) -> LLMResponse:
        """Send a chat completion request to the local Ollama instance."""
        payload: dict[str, Any] = {
            "model": self._config.model,
            "messages": [m.to_api() for m in messages],
            "temperature": temperature if temperature is not None else self._config.temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        elif use_config_max_tokens:
            payload["max_tokens"] = self._config.max_tokens
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        logger.debug(
            "local_llm_request",
            provider="ollama",
            model=self._config.model,
            messages=len(messages),
            tools=len(tools) if tools else 0,
        )

        resp = await self._http.post("/chat/completions", json=payload)

        if resp.status_code >= 400:
            logger.error("local_llm_api_error", status=resp.status_code, body=resp.text[:500])

        resp.raise_for_status()
        data = resp.json()

        choice = data["choices"][0]
        msg = choice["message"]

        content = msg.get("content") or ""
        # Never promote hidden/internal reasoning to user-facing content.
        if not content.strip() and msg.get("reasoning"):
            logger.warning("local_llm_content_empty_reasoning_dropped")
            content = ""

        return LLMResponse(
            content=content,
            tool_calls=msg.get("tool_calls", []),
            finish_reason=choice.get("finish_reason", "stop"),
            usage=data.get("usage", {}),
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> LocalLLMClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
