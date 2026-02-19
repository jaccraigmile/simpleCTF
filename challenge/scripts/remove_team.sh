#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yaml"

TEAM="${1:-}"

if [[ -z "$TEAM" ]]; then
    echo "Usage: $0 <team_name>"
    exit 1
fi

PROJECT_NAME="ctf_${TEAM}"

echo "Removing instance for team '$TEAM'..."

docker compose \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    down -v

echo "Team '$TEAM' removed."
