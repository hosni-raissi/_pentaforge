"""LLM Proxy — sits between every agent and the LLM.

Sanitizes outbound messages (agent → LLM): encrypts sensitive data.
Restores inbound responses (LLM → agent): decrypts tokens back.

This is the ONLY LLM interface agents should use.

Usage:
    from server.core.llm_proxy import LLMProxy

    proxy = LLMProxy(mode="cloud", config=public_llm_config)
    response = await proxy.chat(messages, tools=tools)
    # response.content has original IPs/hostnames restored.
    # The cloud LLM never saw them.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from server.config.agent import (
    LocalLLMConfig,
    PublicLLMConfig,
    local_llm_config,
    public_llm_config,
    llm_mode,
)
from server.core.llm import ChatMessage, LLMClient
from server.layers.sanitizer import (
    DataCategory,
    SanitizationEngine,
    SanitizationVault,
)

logger = structlog.get_logger(__name__)


class LLMProxy:
    """Transparent proxy between agents and LLMs with data sanitization.

    Architecture:
        Agent
          ↓ chat(messages)
        LLMProxy
          ↓ sanitize outbound (messages, tool schemas)
        LLMClient
          ↓ raw API call
        LLMProxy
          ↓ restore inbound (response content, tool call args)
        Agent
          ↓ clean response with original values

    For local LLM mode, sanitization is bypassed (passthrough).
    For cloud LLM mode, all sensitive data is encrypted before sending.
    """

    def __init__(
        self,
        mode: str | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        vault: SanitizationVault | None = None,
        extra_sensitive_values: list[tuple[str, DataCategory]] | None = None,
    ) -> None:
        self._mode = mode or llm_mode.mode

        # Initialize LLM client.
        if self._mode == "local":
            self._local_config = local_config or local_llm_config
            self._llm = LLMClient(self._local_config, mode="local")
            self._model_name = self._local_config.model
        else:
            self._config = config or public_llm_config
            self._llm = LLMClient(self._config, mode="public")
            self._model_name = self._config.model

        # Initialize sanitization engine.
        sanitizer_mode = "local" if self._mode == "local" else "cloud"
        self._sanitizer = SanitizationEngine(
            mode=sanitizer_mode,
            vault=vault,
            extra_sensitive_values=extra_sensitive_values,
        )

        logger.info(
            "llm_proxy_initialized",
            mode=self._mode,
            model=self._model_name,
            sanitizer_mode=sanitizer_mode,
        )

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def sanitizer(self) -> SanitizationEngine:
        return self._sanitizer

    @property
    def vault(self) -> SanitizationVault:
        return self._sanitizer.vault

    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ChatMessage:
        """Send messages to LLM with automatic sanitization/restoration.

        1. Sanitize all message contents (outbound).
        2. Send to LLM.
        3. Restore all redaction tokens in response (inbound).

        Returns a ChatMessage with original sensitive values restored.
        """
        # ── 1. Sanitize outbound ───────────────────────────────
        sanitized_messages = self._sanitize_outbound(messages)

        # ── 2. Call LLM ────────────────────────────────────────
        llm_response = await self._llm.chat(
            sanitized_messages,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        response = ChatMessage(
            role="assistant",
            content=llm_response.content,
            tool_calls=llm_response.tool_calls,
        )

        # ── 3. Restore inbound ─────────────────────────────────
        restored_response = self._restore_inbound(response)

        return restored_response

    # ── Outbound sanitization ──────────────────────────────────

    def _sanitize_outbound(
        self, messages: list[ChatMessage]
    ) -> list[ChatMessage]:
        """Sanitize message contents before sending to LLM."""
        if self._mode == "local":
            return messages

        sanitized: list[ChatMessage] = []
        for msg in messages:
            new_content = msg.content
            new_tool_calls = msg.tool_calls

            # Sanitize text content.
            if msg.content:
                context = f"{msg.role}:{msg.name or ''}"
                new_content = self._sanitizer.sanitize(
                    msg.content, context=context
                )

            sanitized.append(ChatMessage(
                role=msg.role,
                content=new_content,
                tool_calls=new_tool_calls,
                tool_call_id=msg.tool_call_id,
                name=msg.name,
            ))

        return sanitized

    # ── Inbound restoration ────────────────────────────────────

    def _restore_inbound(self, response: ChatMessage) -> ChatMessage:
        """Restore redaction tokens in LLM response."""
        if self._mode == "local":
            return response

        restored_content = response.content
        restored_tool_calls = response.tool_calls

        # Restore content text.
        if response.content:
            restored_content = self._sanitizer.restore(response.content)

        # Restore tool call arguments (LLM may reference redacted tokens).
        if response.tool_calls:
            restored_tool_calls = self._restore_tool_calls(response.tool_calls)

        return ChatMessage(
            role=response.role,
            content=restored_content,
            tool_calls=restored_tool_calls,
            tool_call_id=response.tool_call_id,
            name=response.name,
        )

    def _restore_tool_calls(
        self, tool_calls: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Restore redaction tokens inside tool call arguments."""
        restored: list[dict[str, Any]] = []
        for tc in tool_calls:
            new_tc = dict(tc)
            fn = tc.get("function", {})
            if isinstance(fn, dict):
                new_fn = dict(fn)
                raw_args = fn.get("arguments", "")
                if isinstance(raw_args, str) and raw_args:
                    new_fn["arguments"] = self._sanitizer.restore(raw_args)
                new_tc["function"] = new_fn
            restored.append(new_tc)
        return restored

    # ── Direct sanitize/restore for non-chat usage ─────────────

    def sanitize_text(self, text: str, context: str = "") -> str:
        """Sanitize arbitrary text (e.g., tool output before logging)."""
        return self._sanitizer.sanitize(text, context=context)

    def restore_text(self, text: str) -> str:
        """Restore redaction tokens in arbitrary text."""
        return self._sanitizer.restore(text)

    # ── Lifecycle ──────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Return proxy and sanitization statistics."""
        return {
            "mode": self._mode,
            "model": self._model_name,
            **self._sanitizer.get_stats(),
        }

    async def close(self) -> None:
        """Close the underlying LLM client and wipe the vault."""
        self._sanitizer.vault.clear()
        await self._llm.close()

    async def __aenter__(self) -> LLMProxy:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
