# Infrastructure

PentaForge ships with a local Docker Compose stack for the web UI, API server, Redis, and Qdrant.

## Services

- `frontend`: builds the React web dashboard and serves it with Nginx
- `backend`: runs the FastAPI API on port `8000`
- `tool-sandbox`: isolated execution service for `run_custom` and `run_python`
- `redis`: ephemeral cache and coordination
- `qdrant`: vector store for knowledge and retrieval

## Start

From the repository root:

```bash
docker compose -f infra/docker/docker-compose.yml up --build
```

## Access

- Frontend: `http://localhost:8080`
- Backend API: `http://localhost:8000`
- Qdrant: `http://localhost:6333`

The frontend talks directly to the backend on `localhost:8000`, which matches the current UI defaults.

## Persistence

The compose stack keeps the following in named Docker volumes:

- SQLite project database
- Hugging Face / sentence-transformers model cache
- backend cache and logs
- sandbox workspace
- Redis data
- Qdrant storage

## Notes

- The first backend startup can take time because the embedding model may be downloaded into the model cache volume.
- The backend container disables code reload by default (`PENTAFORGE_RELOAD=0`) because this stack is meant for packaged local deployment, not live development.
- The backend image stays the control plane. The dangerous execution path for `run_custom` and `run_python` is delegated to the `tool-sandbox` container through `SANDBOX_EXECUTOR_URL`.
- The sandbox image includes the core runtime plus baseline tooling such as `curl` and `nmap`. If you want the full offensive tool surface inside Docker, extend `infra/docker/sandbox.Dockerfile` with the extra binaries your workflows require, such as `nuclei`, `ffuf`, `gobuster`, `sqlmap`, or `hydra`.
