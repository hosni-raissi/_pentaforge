"""Shared LLM content cleaner used by agent tools.

Given raw text, returns a compact, target-focused summary suitable for tool context.
Falls back to deterministic truncation if the LLM call fails.
"""

from __future__ import annotations

import re

import structlog

from server.config.agent import (
    llm_mode,
    local_llm_config,
    public_llm_config,
)
from server.core.llm import ChatMessage, LLMClient

logger = structlog.get_logger(__name__)

_MAX_INPUT_CHARS = 24_000
_MAX_OUTPUT_CHARS = 4_000
_MIN_OUTPUT_CHARS = 400

_SYSTEM_PROMPT = (
    "You clean web content for penetration-testing agents.\n"
    "Return only essential, target-relevant information.\n"
    "Drop boilerplate, navigation, legal text, ads, and repetition.\n"
    "Keep actionable technical details, attack surface hints, versions, auth flows, "
    "endpoints, security controls, and misconfiguration clues.\n"
    "Output plain text only. No markdown fences."
)


def _normalize_text(text: str) -> str:
    normalized = re.sub(r"\r\n?", "\n", str(text or ""))
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return normalized.strip()


def _deterministic_fallback(text: str, max_output_chars: int) -> str:
    clean = _normalize_text(text)
    if not clean:
        return ""
    lines = [ln.strip() for ln in clean.splitlines() if ln.strip()]
    # Keep top non-empty lines to preserve key context without an LLM dependency.
    compact = "\n".join(lines[:40])
    return compact[:max(_MIN_OUTPUT_CHARS, max_output_chars)].strip()


async def clean_essential_content(
    *,
    raw_text: str,
    target_type: str,
    focus: str = "",
    source_url: str = "",
    title: str = "",
    max_output_chars: int = _MAX_OUTPUT_CHARS,
) -> str:
    """Clean raw text with an LLM into target-relevant essential content."""
    text = _normalize_text(raw_text)
    if not text:
        return ""

    max_output_chars = max(_MIN_OUTPUT_CHARS, min(max_output_chars, 12_000))
    bounded_text = text[:_MAX_INPUT_CHARS]

    user_prompt = (
        f"Target type: {target_type or 'shared'}\n"
        f"Focus: {focus or 'General pentest-relevant essentials'}\n"
        f"Source URL: {source_url or 'unknown'}\n"
        f"Page title: {title or 'unknown'}\n"
        f"Max output chars: {max_output_chars}\n\n"
        "Task:\n"
        "1) Extract only essential content for this pentest target.\n"
        "2) Prefer concise bullet-like lines.\n"
        "3) Preserve useful concrete indicators (paths, parameters, technologies, auth details, known risks).\n"
        "4) Exclude generic prose and marketing.\n\n"
        "Page text:\n"
        f"{bounded_text}"
    )

    mode = (llm_mode.mode or "local").strip().lower()
    client_mode = "local" if mode == "local" else "public"
    config = local_llm_config if client_mode == "local" else public_llm_config

    try:
        async with LLMClient(config, mode=client_mode) as llm:
            response = await llm.chat(
                messages=[
                    ChatMessage(role="system", content=_SYSTEM_PROMPT),
                    ChatMessage(role="user", content=user_prompt),
                ],
                temperature=0.1,
                max_tokens=900,
                use_config_max_tokens=False,
            )
        content = _normalize_text(response.content or "")
        if not content:
            return _deterministic_fallback(bounded_text, max_output_chars=max_output_chars)
        return content[:max_output_chars].strip()
    except Exception as exc:
        logger.warning(
            "llm_clean_data_failed",
            error=str(exc),
            mode=client_mode,
            source_url=source_url,
            target_type=target_type,
        )
        return _deterministic_fallback(bounded_text, max_output_chars=max_output_chars)
