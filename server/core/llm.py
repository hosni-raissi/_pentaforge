"""
LLMClient — Async OpenAI-compatible chat completion client.

Works with any provider that exposes the OpenAI /chat/completions endpoint:
Groq, OpenAI, Together, Ollama, vLLM, LM Studio, etc.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from server.config.agent import PlannerLLMConfig

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ChatMessage:
    """A single message in a conversation."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def to_api(self) -> dict[str, Any]:
        """Serialize to the OpenAI API message format."""
        msg: dict[str, Any] = {"role": self.role}
        if self.content is not None:
            msg["content"] = self.content
        if self.tool_calls:
            msg["tool_calls"] = self.tool_calls
        if self.tool_call_id is not None:
            msg["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            msg["name"] = self.name
        return msg


@dataclass
class LLMResponse:
    """Parsed response from the LLM."""

    content: str | None
    tool_calls: list[dict[str, Any]]
    finish_reason: str
    usage: dict[str, int]


class LLMClient:
    """Async client for OpenAI-compatible chat completion APIs."""

    def __init__(self, config: PlannerLLMConfig) -> None:
        self._config = config
        self._http = httpx.AsyncClient(
            base_url=config.api_url,
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(120.0, connect=10.0),
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a chat completion request and return the parsed response."""
        payload: dict[str, Any] = {
            "model": self._config.model,
            "messages": [m.to_api() for m in messages],
            "temperature": temperature if temperature is not None else self._config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self._config.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        logger.debug(
            "llm_request",
            provider=self._config.api_provider,
            model=self._config.model,
            messages=len(messages),
            tools=len(tools) if tools else 0,
        )

        resp = await self._http.post("/chat/completions", json=payload)

        # Log error body for non-2xx responses (except 429 which is retried)
        if resp.status_code >= 400 and resp.status_code != 429:
            logger.error("llm_api_error", status=resp.status_code, body=resp.text[:500])

        # Retry on rate-limit (429) with exponential backoff
        retries = 0
        max_retries = 3
        while resp.status_code == 429 and retries < max_retries:
            retries += 1
            wait = float(resp.headers.get("retry-after", 2 ** retries))
            logger.warning("llm_rate_limited", retry=retries, wait=wait)
            await asyncio.sleep(wait)
            resp = await self._http.post("/chat/completions", json=payload)

        resp.raise_for_status()
        data = resp.json()

        choice = data["choices"][0]
        msg = choice["message"]

        return LLMResponse(
            content=msg.get("content"),
            tool_calls=msg.get("tool_calls", []),
            finish_reason=choice.get("finish_reason", "stop"),
            usage=data.get("usage", {}),
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> LLMClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
