#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./scripts/remove-sandbox-tool.sh <tool_name>"
  echo "Example: ./scripts/remove-sandbox-tool.sh ffuf"
  exit 1
fi

TOOL_NAME="$1"
COMPOSE_FILE="infra/docker/docker-compose.yml"

echo "Checking for $TOOL_NAME in tool-sandbox..."

# First check if the tool is a binary in /opt/pentaforge-tools/bin/
if docker compose -f "$COMPOSE_FILE" exec -T tool-sandbox bash -c "test -f /opt/pentaforge-tools/bin/$TOOL_NAME"; then
  echo "Found $TOOL_NAME binary in /opt/pentaforge-tools/bin. Deleting..."
  docker compose -f "$COMPOSE_FILE" exec -T tool-sandbox rm -f "/opt/pentaforge-tools/bin/$TOOL_NAME"
  
  # Also clean up the marker if it exists
  docker compose -f "$COMPOSE_FILE" exec -T tool-sandbox rm -f "/opt/pentaforge-tools/.installed_markers/$TOOL_NAME"
  echo "✅ $TOOL_NAME binary and marker removed successfully from the persistent volume."
  
else
  # Check if there is a marker for it (meaning it was a repo clone or similar)
  if docker compose -f "$COMPOSE_FILE" exec -T tool-sandbox bash -c "test -f /opt/pentaforge-tools/.installed_markers/$TOOL_NAME"; then
    echo "Found marker for $TOOL_NAME. Deleting marker..."
    docker compose -f "$COMPOSE_FILE" exec -T tool-sandbox rm -f "/opt/pentaforge-tools/.installed_markers/$TOOL_NAME"
    
    # Try to delete the repo directory if it exists
    if docker compose -f "$COMPOSE_FILE" exec -T tool-sandbox bash -c "test -d /opt/pentaforge-tools/$TOOL_NAME"; then
      echo "Found directory /opt/pentaforge-tools/$TOOL_NAME. Deleting..."
      docker compose -f "$COMPOSE_FILE" exec -T tool-sandbox rm -rf "/opt/pentaforge-tools/$TOOL_NAME"
    fi
    echo "✅ $TOOL_NAME removed successfully from the persistent volume."
    
  else
    echo "❌ Could not find '$TOOL_NAME' in /opt/pentaforge-tools/bin/ or in markers."
    echo "If it is an apt, npm, or pip package, it is baked into the Docker image and cannot be removed this way."
    exit 1
  fi
fi

echo ""
echo "⚠️  NOTE: Don't forget to also remove $TOOL_NAME from infra/docker/install-sandbox-tools.sh,"
echo "   otherwise it will be reinstalled the next time you start the Docker container!"
