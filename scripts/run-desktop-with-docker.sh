#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/infra/docker/docker-compose.yml"
UI_DIR="$ROOT_DIR/client/ui"
API_HEALTH_URL="http://127.0.0.1:8000/api/health"
STATE_DIR="$ROOT_DIR/.cache"
BACKEND_HASH_FILE="$STATE_DIR/backend-bootstrap.sha256"
SANDBOX_HASH_FILE="$STATE_DIR/sandbox-bootstrap.sha256"
SANDBOX_TOOLS_HASH_FILE="$STATE_DIR/sandbox-tools-bootstrap.sha256"
COMPOSE_ARGS=(up -d --remove-orphans)
FORCE_BUILD_BACKEND=0
FORCE_BUILD_SANDBOX=0
FORCE_BUILD_SANDBOX_TOOLS=0
STOP_STACK_ON_EXIT=0
COMPOSE_PROFILE_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --build)
      FORCE_BUILD_BACKEND=1
      FORCE_BUILD_SANDBOX=1
      ;;
    --build-backend)
      FORCE_BUILD_BACKEND=1
      ;;
    --build-sandbox)
      FORCE_BUILD_SANDBOX=1
      ;;
    --reinstall-sandbox-tools|--build-sandbox-tools)
      FORCE_BUILD_SANDBOX=1
      FORCE_BUILD_SANDBOX_TOOLS=1
      ;;
  esac
done

if [[ "${PENTAFORGE_DOCKER_BUILD:-0}" == "1" ]]; then
  FORCE_BUILD_BACKEND=1
  FORCE_BUILD_SANDBOX=1
  FORCE_BUILD_SANDBOX_TOOLS=1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required but not installed." >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required but not installed." >&2
  exit 1
fi

handle_interrupt() {
  STOP_STACK_ON_EXIT=1
}

cleanup_stack_if_needed() {
  if [[ "$STOP_STACK_ON_EXIT" == "1" ]]; then
    echo
    echo "[cleanup] Stopping Docker stack..."
    docker compose -f "$COMPOSE_FILE" down --remove-orphans || true
  fi
}

trap handle_interrupt INT TERM

compute_backend_hash() {
  sha256sum \
    "$ROOT_DIR/infra/docker/backend.Dockerfile" \
    "$ROOT_DIR/server/requirements.txt" \
    "$ROOT_DIR/server/scripts/warm_embedding_model.py" \
    "$ROOT_DIR/server/db/knowledge/storage/embedding.py" \
    "$ROOT_DIR/server/agents/assistant/agent.py" \
    "$ROOT_DIR/server/agents/assistant/prompts.py" \
    "$ROOT_DIR/server/agents/assistant/security_tools.py" \
    "$ROOT_DIR/server/agents/tools/run_custom.py" \
    "$ROOT_DIR/server/nodes/intel/config.py" \
    "$ROOT_DIR/server/nodes/intel/helpers.py" \
    "$ROOT_DIR/server/db/knowledge/config/sources.py" \
    "$ROOT_DIR/server/db/knowledge/sources/github_extractor.py" \
    "$ROOT_DIR/server/sandbox_service/app.py" | sha256sum | awk '{print $1}'
}

compute_sandbox_hash() {
  sha256sum \
    "$ROOT_DIR/infra/docker/sandbox.Dockerfile" \
    "$ROOT_DIR/server/requirements.txt" \
    "$ROOT_DIR/server/agents/tools/run_custom.py" \
    "$ROOT_DIR/server/agents/executer/sandbox.py" \
    "$ROOT_DIR/server/sandbox_service/app.py" \
    "$ROOT_DIR/server/sandbox/share/wordlists/short.txt" \
    "$ROOT_DIR/server/sandbox/share/wordlists/medium.txt" \
    "$ROOT_DIR/server/sandbox/share/wordlists/large.txt" \
    "$ROOT_DIR/server/sandbox/share/wordlists/dns-fuzz-common.txt" \
    "$ROOT_DIR/server/sandbox/share/wordlists/rockyou.txt" | sha256sum | awk '{print $1}'
}

compute_sandbox_tools_hash() {
  sha256sum \
    "$ROOT_DIR/infra/docker/sandbox-tools.Dockerfile" \
    "$ROOT_DIR/infra/docker/install-sandbox-tools.sh" | sha256sum | awk '{print $1}'
}

mkdir -p "$STATE_DIR"
CURRENT_BACKEND_HASH="$(compute_backend_hash)"
PREVIOUS_BACKEND_HASH=""
if [[ -f "$BACKEND_HASH_FILE" ]]; then
  PREVIOUS_BACKEND_HASH="$(<"$BACKEND_HASH_FILE")"
fi

CURRENT_SANDBOX_HASH="$(compute_sandbox_hash)"
PREVIOUS_SANDBOX_HASH=""
if [[ -f "$SANDBOX_HASH_FILE" ]]; then
  PREVIOUS_SANDBOX_HASH="$(<"$SANDBOX_HASH_FILE")"
fi

CURRENT_SANDBOX_TOOLS_HASH="$(compute_sandbox_tools_hash)"
PREVIOUS_SANDBOX_TOOLS_HASH=""
if [[ -f "$SANDBOX_TOOLS_HASH_FILE" ]]; then
  PREVIOUS_SANDBOX_TOOLS_HASH="$(<"$SANDBOX_TOOLS_HASH_FILE")"
fi

if [[ "$CURRENT_BACKEND_HASH" != "$PREVIOUS_BACKEND_HASH" ]]; then
  FORCE_BUILD_BACKEND=1
fi

SANDBOX_CHANGED=0
if [[ "$CURRENT_SANDBOX_HASH" != "$PREVIOUS_SANDBOX_HASH" ]]; then
  SANDBOX_CHANGED=1
fi

SANDBOX_TOOLS_CHANGED=0
if [[ "$CURRENT_SANDBOX_TOOLS_HASH" != "$PREVIOUS_SANDBOX_TOOLS_HASH" ]]; then
  SANDBOX_TOOLS_CHANGED=1
fi

if [[ "$FORCE_BUILD_SANDBOX_TOOLS" == "1" ]]; then
  FORCE_BUILD_SANDBOX=1
fi

if [[ "$FORCE_BUILD_BACKEND" == "1" ]]; then
  echo "[1/5] Rebuilding backend image..."
  docker compose "${COMPOSE_PROFILE_ARGS[@]}" -f "$COMPOSE_FILE" build backend
  printf '%s\n' "$CURRENT_BACKEND_HASH" > "$BACKEND_HASH_FILE"
else
  echo "[1/5] Reusing current backend image..."
fi

if ! docker image inspect docker-tool-sandbox-base:latest >/dev/null 2>&1; then
  FORCE_BUILD_SANDBOX_TOOLS=1
fi

if [[ "$FORCE_BUILD_SANDBOX_TOOLS" == "1" ]]; then
  echo "[1a/5] Rebuilding sandbox tools base image..."
  docker build -f "$ROOT_DIR/infra/docker/sandbox-tools.Dockerfile" -t docker-tool-sandbox-base:latest "$ROOT_DIR"
  printf '%s\n' "$CURRENT_SANDBOX_TOOLS_HASH" > "$SANDBOX_TOOLS_HASH_FILE"
elif [[ "$SANDBOX_TOOLS_CHANGED" == "1" ]]; then
  echo "[1a/5] Sandbox tools definition changed, but reusing the current tools base image."
  echo "        Run './scripts/run-desktop-with-docker.sh --reinstall-sandbox-tools' when you want to rebuild security tools."
  printf '%s\n' "$CURRENT_SANDBOX_TOOLS_HASH" > "$SANDBOX_TOOLS_HASH_FILE"
else
  echo "[1a/5] Reusing current sandbox tools base image..."
fi

if [[ "$FORCE_BUILD_SANDBOX" == "1" ]]; then
  echo "[1b/5] Rebuilding sandbox image..."
  docker compose "${COMPOSE_PROFILE_ARGS[@]}" -f "$COMPOSE_FILE" build tool-sandbox
  printf '%s\n' "$CURRENT_SANDBOX_HASH" > "$SANDBOX_HASH_FILE"
elif [[ "$SANDBOX_CHANGED" == "1" ]]; then
  echo "[1b/5] Sandbox bootstrap files changed, but reusing the current sandbox image."
  echo "        Run './scripts/run-desktop-with-docker.sh --build-sandbox' when you want to rebuild the sandbox app layer."
else
  echo "[1b/5] Reusing current sandbox image..."
fi

echo "[2/5] Starting Docker backend stack..."
docker compose "${COMPOSE_PROFILE_ARGS[@]}" -f "$COMPOSE_FILE" "${COMPOSE_ARGS[@]}"

echo "[3/5] Waiting for backend health at $API_HEALTH_URL ..."
for _ in $(seq 1 60); do
  if curl -fsS "$API_HEALTH_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! curl -fsS "$API_HEALTH_URL" >/dev/null 2>&1; then
  echo "Backend did not become healthy at $API_HEALTH_URL" >&2
  exit 1
fi

echo "[4/5] Ensuring sandbox toolchain and embedding model are ready..."
if ! docker compose "${COMPOSE_PROFILE_ARGS[@]}" -f "$COMPOSE_FILE" exec -T tool-sandbox bash -lc \
  'test -f /opt/pentaforge-tools/INSTALL-REPORT.txt' >/dev/null 2>&1; then
  echo "        Sandbox toolchain marker is missing; skipping automatic in-container install."
  echo "        Run './scripts/run-desktop-with-docker.sh --reinstall-sandbox-tools --build-sandbox' to rebuild it deliberately."
fi
docker compose "${COMPOSE_PROFILE_ARGS[@]}" -f "$COMPOSE_FILE" exec -T backend python -m server.scripts.warm_embedding_model

echo "[5/5] Launching Tauri desktop app..."
cd "$UI_DIR"
set +e
npm run dev
APP_EXIT_CODE=$?
set -e

if [[ "$APP_EXIT_CODE" == "130" || "$APP_EXIT_CODE" == "143" ]]; then
  STOP_STACK_ON_EXIT=1
fi

cleanup_stack_if_needed
exit "$APP_EXIT_CODE"
