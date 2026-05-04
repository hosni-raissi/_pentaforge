"""Minimal async Interactsh client helpers for OOB callback workflows."""

from __future__ import annotations

import json
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger(__name__)


class InteractshClient:
    """Small OOB client with deterministic payload generation and polling."""

    def __init__(self, server_url: str, token: str, engagement_id: str) -> None:
        clean_url = str(server_url or "").strip().rstrip("/")
        parsed = urlparse(clean_url if "://" in clean_url else f"https://{clean_url}")
        self.server_url = clean_url
        self.token = str(token or "").strip()
        self.engagement_id = str(engagement_id or "").strip() or uuid.uuid4().hex
        self.session_id = self.engagement_id
        self.session_domain = str(parsed.hostname or clean_url).strip()
        self._payload_map: dict[str, str] = {}
        self._used_prefixes: set[str] = set()

    def _next_unique_prefix(self) -> str:
        while True:
            prefix = uuid.uuid4().hex[:8]
            if prefix not in self._used_prefixes:
                self._used_prefixes.add(prefix)
                return prefix

    def generate_payload(self, tag: str) -> dict[str, str]:
        clean_tag = str(tag or "").strip() or "oob"
        unique_prefix = self._next_unique_prefix()
        self._payload_map[unique_prefix] = clean_tag
        payload = f"{unique_prefix}-{clean_tag}.{self.session_domain}"
        return {
            "payload": payload,
            "http_url": f"https://{payload}",
            "dns_host": payload,
            "tag": clean_tag,
        }

    async def poll_callbacks(self, tag: str, timeout_seconds: int) -> list[dict[str, Any]]:
        clean_tag = str(tag or "").strip()
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_seconds)) as client:
                response = await client.get(
                    f"{self.server_url}/poll",
                    params={"id": self.session_id, "secret": self.token},
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "interactsh_poll_failed",
                server_url=self.server_url,
                engagement_id=self.engagement_id,
                tag=clean_tag,
                error=str(exc),
            )
            return []

        if response.status_code != 200:
            logger.warning(
                "interactsh_poll_non_200",
                server_url=self.server_url,
                engagement_id=self.engagement_id,
                tag=clean_tag,
                status_code=response.status_code,
            )
            return []

        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError):
            logger.warning(
                "interactsh_poll_malformed_json",
                server_url=self.server_url,
                engagement_id=self.engagement_id,
                tag=clean_tag,
                raw_response=response.text[:2000],
            )
            return []

        callbacks = self._extract_callbacks(payload)
        if not clean_tag:
            return callbacks

        filtered: list[dict[str, Any]] = []
        tag_lower = clean_tag.lower()
        for callback in callbacks:
            if not isinstance(callback, dict):
                continue
            raw_request = str(callback.get("raw-request", "")).lower()
            full_id = str(callback.get("full-id", "")).lower()
            if tag_lower in raw_request or tag_lower in full_id:
                filtered.append(callback)
        return filtered

    def _extract_callbacks(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        for key in ("data", "callbacks", "items", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []
