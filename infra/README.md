# Infrastructure

PentaForge ships with a local Docker Compose stack for the web UI, API server, Redis, and Qdrant.

## Services

- `frontend`: builds the React web dashboard and serves it with Nginx
- `backend`: runs the FastAPI API on port `8000`
- `tool-sandbox`: isolated execution service for `run_custom` and `run_python`
- `redis`: ephemeral cache and coordination
- `qdrant`: vector store for knowledge and retrieval
- `mobile-android` (optional): Google Android Emulator container runtime for APK/mobile engagements

## Start

From the repository root:

```bash
docker compose -f infra/docker/docker-compose.yml up --build
```

Run detached:

```bash
docker compose -f infra/docker/docker-compose.yml up -d --build
```

Start the desktop stack with the optional Android mobile lab:

```bash
./scripts/run-desktop-with-docker.sh --build-backend --reinstall-sandbox-tools --build-sandbox
```

## Access

- Frontend: `http://localhost:8080`
- Backend API: `http://localhost:8000`
- Qdrant is internal-only by default and reachable from the backend at `http://qdrant:6333`
- Redis is internal-only by default and reachable from the backend at `redis://redis:6379/0`
- Mobile APK projects run through static analysis only in the default stack; no Android runtime sidecar is started.

The frontend talks directly to the backend on `localhost:8000`, which matches the current UI defaults.

## Persistence

The compose stack keeps the following in named Docker volumes:

- SQLite project database
- knowledge data, runtime caches, and SQLite knowledge-side stores
- Hugging Face / sentence-transformers model cache
- backend cache and logs
- sandbox workspace
- Redis data
- Qdrant storage

This is intentional:

- the Docker image does not ship your current local `projects.db`
- the Docker image does not ship your current fetched knowledge data
- the Docker image does not ship your current downloaded embedding models
- each machine creates and warms its own runtime state inside Docker volumes

## Health And Startup

- `backend` exposes `/api/health`
- `tool-sandbox` exposes `/health`
- `frontend` is checked over local Nginx HTTP
- `redis` is checked with `redis-cli ping`
- `backend` waits for `redis` and `tool-sandbox` health before starting work
- `qdrant` stays a separate service and collections are created lazily by the app when needed
- `mobile-android` is optional and only starts when the Compose `mobile-lab` profile is enabled

## Reset Everything

Stop the stack:

```bash
docker compose -f infra/docker/docker-compose.yml down
```

Stop and remove all Docker-managed project data:

```bash
docker compose -f infra/docker/docker-compose.yml down -v
```

That `-v` reset removes:

- Qdrant vector storage
- Redis data
- the backend SQLite project database
- knowledge data/cache created by the app
- downloaded embedding/model cache
- backend logs/cache
- sandbox workspace

## Notes

- The first backend startup can take time because the embedding model may be downloaded into the model cache volume.
- The backend container disables code reload by default (`PENTAFORGE_RELOAD=0`) because this stack is meant for packaged local deployment, not live development.
- The backend image stays the control plane. The dangerous execution path for `run_custom` and `run_python` is delegated to the `tool-sandbox` container through `SANDBOX_EXECUTOR_URL`.
- The sandbox image now builds a broad recon and analysis toolchain during Docker image build through [infra/docker/install-sandbox-tools.sh](/home/hosnizap/projects/PentaForge/infra/docker/install-sandbox-tools.sh). Rebuild the sandbox image with:
  `docker compose -f infra/docker/docker-compose.yml build tool-sandbox`
- The sandbox install now tracks the executer recon and exploit catalogs much more closely, including extra API/web/mobile/network/container helpers and CLI aliases like `kiterunner`, `jwt-tool`, `proxychains`, `aapt2`, and `retire_js`.
- The install report is written inside the image at `/opt/pentaforge-tools/INSTALL-REPORT.txt`.
- Bundled repo wordlists are exposed inside the container at `/usr/share/wordlists/pentaforge`, `/usr/share/wordlists/SecLists`, and `/opt/wordlists/pentaforge`.
- [scripts/run-desktop-with-docker.sh](/home/hosnizap/projects/PentaForge/scripts/run-desktop-with-docker.sh) now auto-rebuilds the backend/sandbox images when bootstrap files change, verifies the sandbox toolchain marker, and warms the local `nomic-ai/nomic-embed-text-v2-moe` cache before opening the desktop app.
- The launcher now separates rebuilds: backend changes still rebuild automatically, while sandbox/toolchain changes only print a reminder unless you run `./scripts/run-desktop-with-docker.sh --build-sandbox` or `--build`.
- `tool-sandbox` gets `NET_RAW` and `NET_ADMIN` so tools like `arp-scan`, `arping`, `mtr`, and raw-socket `nmap` modes can run.
- The Docker CLI is installed in the sandbox, but the host Docker socket is not mounted by default. That keeps the sandbox isolated; image-inspection workflows that need host Docker daemon access should be enabled separately and deliberately.
- Mobile APK projects currently use static artifact analysis by default, which avoids host-dependent emulator requirements and keeps the scan path stable across environments.
