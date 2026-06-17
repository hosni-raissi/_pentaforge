"""Local executer resource catalog helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def get_executer_resource_catalog_path() -> Path:
    return Path(__file__).resolve().parent / "resources" / "executer_resource_catalog.json"


def _resolve_catalog_entry_path(raw_path: str) -> str:
    text = str(raw_path or "").strip()
    if not text:
        return text
    path = Path(text)
    if path.is_absolute():
        return str(path)
    return str((_repo_root() / path).resolve())


def load_executer_resource_catalog() -> dict[str, Any]:
    data = json.loads(get_executer_resource_catalog_path().read_text(encoding="utf-8"))
    enriched: dict[str, Any] = {}

    for section_name, section_value in data.items():
        if isinstance(section_value, list):
            rows: list[Any] = []
            for item in section_value:
                if isinstance(item, dict) and "path" in item:
                    row = dict(item)
                    row["absolute_path"] = _resolve_catalog_entry_path(str(item["path"]))
                    rows.append(row)
                else:
                    rows.append(item)
            enriched[section_name] = rows
        else:
            enriched[section_name] = section_value

    return enriched


def format_executer_resource_catalog_for_prompt() -> str:
    return json.dumps(
        load_executer_resource_catalog(),
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    )
