"""File-backed target-info profile defaults for Information Gathering."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


_PROFILE_FILE = Path(__file__).with_name("target_info_profiles.json")


@lru_cache(maxsize=1)
def load_target_info_profile_defaults() -> dict[str, list[dict[str, Any]]]:
    with _PROFILE_FILE.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise ValueError("target_info_profiles.json must contain a top-level object")

    normalized: dict[str, list[dict[str, Any]]] = {}
    for target_type, blocks in payload.items():
        if not isinstance(target_type, str):
            continue
        if not isinstance(blocks, list):
            continue
        normalized[target_type] = [block for block in blocks if isinstance(block, dict)]

    if "web_app" not in normalized or not normalized["web_app"]:
        raise ValueError("target_info_profiles.json must define a non-empty web_app profile")
    return normalized
