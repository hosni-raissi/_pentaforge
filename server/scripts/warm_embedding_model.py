from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from server.db.knowledge.config.settings import settings
from server.db.knowledge.storage.embedding import EmbeddingGenerator


def _marker_path() -> Path:
    cache_root = os.getenv("HF_HOME", "/data/huggingface")
    return Path(cache_root) / ".pentaforge_embedding_ready.json"


def _marker_payload() -> dict[str, object]:
    return {
        "provider": settings.embedding_provider,
        "model": settings.embedding_model,
        "dimensions": settings.embedding_dimensions,
    }


def _marker_matches(path: Path, payload: dict[str, object]) -> bool:
    try:
        return json.loads(path.read_text()) == payload
    except Exception:
        return False


async def _warm_local_embedding_model() -> None:
    marker = _marker_path()
    payload = _marker_payload()

    if settings.embedding_provider != "local":
        print(
            f"Skipping embedding warm-up because provider is "
            f"{settings.embedding_provider!r}."
        )
        return

    if _marker_matches(marker, payload):
        print(f"Embedding model already warm: {settings.embedding_model}")
        return

    marker.parent.mkdir(parents=True, exist_ok=True)

    embedder = EmbeddingGenerator()
    await embedder.embed_single("PentaForge embedding bootstrap", is_query=True)

    marker.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"Embedding model ready: {settings.embedding_model}")


def main() -> None:
    asyncio.run(_warm_local_embedding_model())


if __name__ == "__main__":
    main()
