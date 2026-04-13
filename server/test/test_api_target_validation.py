from __future__ import annotations

import asyncio

from server.api.middleware.safety import _normalize_target_payload
from server.layers.safety.target_validation import UrlNormalizer


def test_bare_domain_is_normalized_for_target_fields(monkeypatch):
    async def _always_unreachable(self, url: str) -> bool:
        return False

    monkeypatch.setattr(UrlNormalizer, "_probe", _always_unreachable)

    payload = {
        "target": "orange.com",
        "target_config": {
            "url": "orange.com",
        },
    }

    normalized, errors = asyncio.run(_normalize_target_payload(payload))

    assert errors == []
    assert normalized["target"] == "https://orange.com"
    assert normalized["target_config"]["url"] == "https://orange.com"


def test_invalid_target_still_returns_validation_error(monkeypatch):
    async def _always_unreachable(self, url: str) -> bool:
        return False

    monkeypatch.setattr(UrlNormalizer, "_probe", _always_unreachable)

    payload = {"target": "not a valid url"}
    _, errors = asyncio.run(_normalize_target_payload(payload))

    assert errors
    assert errors[0]["field"] == "target"
    assert errors[0]["type"] == "url"
