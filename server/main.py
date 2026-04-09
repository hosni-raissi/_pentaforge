"""Server entrypoint for running the FastAPI app with uvicorn."""

from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run(
        "server.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    main()
