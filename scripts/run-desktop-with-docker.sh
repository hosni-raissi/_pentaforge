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
# Default behavior: rebuild backend and sandbox app layers on every launch.
FORCE_BUILD_BACKEND=1
FORCE_BUILD_SANDBOX=1
FORCE_BUILD_SANDBOX_TOOLS=0
STOP_STACK_ON_EXIT=0
COMPOSE_PROFILE_ARGS=()
DOCKER_BUILD_RETRIES="${PENTAFORGE_DOCKER_BUILD_RETRIES:-3}"
DOCKER_BUILD_RETRY_DELAY_SECONDS="${PENTAFORGE_DOCKER_BUILD_RETRY_DELAY_SECONDS:-5}"
DOCKER_BUILD_CLASSIC_FALLBACK="${PENTAFORGE_DOCKER_BUILD_CLASSIC_FALLBACK:-1}"
LAST_BUILD_FAILURE_LOG=""

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

run_with_retries() {
  local description="$1"
  shift

  local attempt=1
  local max_attempts="$DOCKER_BUILD_RETRIES"
  local delay="$DOCKER_BUILD_RETRY_DELAY_SECONDS"

  while true; do
    local failure_log
    failure_log="$(mktemp)"
    if "$@" 2> >(tee "$failure_log" >&2); then
      rm -f "$failure_log"
      LAST_BUILD_FAILURE_LOG=""
      return 0
    fi
    LAST_BUILD_FAILURE_LOG="$failure_log"

    if [[ "$attempt" -ge "$max_attempts" ]]; then
      echo "$description failed after $attempt attempt(s)." >&2
      return 1
    fi

    echo "$description failed on attempt $attempt/$max_attempts. Retrying in ${delay}s..." >&2
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

docker_image_exists() {
  local image_name="$1"
  docker image inspect "$image_name" >/dev/null 2>&1
}

build_failed_due_to_registry_resolution() {
  local log_file="$1"
  [[ -n "$log_file" && -f "$log_file" ]] || return 1
  grep -qiE \
    "Temporary failure in name resolution|TLS handshake timeout|failed to resolve source metadata|lookup registry-1\\.docker\\.io|dial tcp: lookup" \
    "$log_file"
}

reuse_local_image_if_possible() {
  local description="$1"
  local image_name="$2"

  if docker_image_exists "$image_name"; then
    echo "$description could not reach Docker Hub, but a local image cache exists. Reusing $image_name." >&2
    return 0
  fi

  echo "$description could not reach Docker Hub and no local image cache exists for $image_name." >&2
  echo "Restore DNS/network access to docker.io, or prebuild/pull the required images once while online." >&2
  return 1
}

run_build_with_fallback() {
  local description="$1"
  local image_name="$2"
  shift
  shift

  if run_with_retries "$description" "$@"; then
    [[ -n "$LAST_BUILD_FAILURE_LOG" ]] && rm -f "$LAST_BUILD_FAILURE_LOG" || true
    return 0
  fi

  if build_failed_due_to_registry_resolution "$LAST_BUILD_FAILURE_LOG"; then
    if reuse_local_image_if_possible "$description" "$image_name"; then
      [[ -n "$LAST_BUILD_FAILURE_LOG" ]] && rm -f "$LAST_BUILD_FAILURE_LOG" || true
      LAST_BUILD_FAILURE_LOG=""
      return 0
    fi
  fi

  if [[ "$DOCKER_BUILD_CLASSIC_FALLBACK" != "1" ]]; then
    [[ -n "$LAST_BUILD_FAILURE_LOG" ]] && rm -f "$LAST_BUILD_FAILURE_LOG" || true
    return 1
  fi

  echo "$description still failed after BuildKit retries. Falling back to the classic Docker builder..." >&2
  if run_with_retries \
    "$description (classic builder fallback)" \
    env DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 "$@"; then
    [[ -n "$LAST_BUILD_FAILURE_LOG" ]] && rm -f "$LAST_BUILD_FAILURE_LOG" || true
    LAST_BUILD_FAILURE_LOG=""
    return 0
  fi

  if build_failed_due_to_registry_resolution "$LAST_BUILD_FAILURE_LOG"; then
    reuse_local_image_if_possible "$description (classic builder fallback)" "$image_name"
  fi
  [[ -n "$LAST_BUILD_FAILURE_LOG" ]] && rm -f "$LAST_BUILD_FAILURE_LOG" || true
  LAST_BUILD_FAILURE_LOG=""
  return 1
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
  run_build_with_fallback \
    "Backend image build" \
    "docker-backend:latest" \
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
  run_build_with_fallback \
    "Sandbox tools base image build" \
    "docker-tool-sandbox-base:latest" \
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
  run_build_with_fallback \
    "Sandbox image build" \
    "docker-tool-sandbox:latest" \
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
