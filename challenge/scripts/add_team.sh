#!/usr/bin/env bash
set -euo pipefail

# Resolve the project directory (one level up from scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yaml"

TEAM="${1:-}"
PORT="${2:-}"

usage() {
    echo "Usage: $0 <team_name> [port]"
    echo "  team_name  alphanumeric, hyphens, underscores (e.g. alpha, team-01)"
    echo "  port       host port to bind (default: auto-assigned from 8000)"
    exit 1
}

[[ -z "$TEAM" ]] && usage

if ! [[ "$TEAM" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: team name must contain only letters, numbers, hyphens, or underscores."
    exit 1
fi

PROJECT_NAME="ctf_${TEAM}"

# Check if this team is already running
if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" ps --quiet 2>/dev/null | grep -q .; then
    echo "Error: team '$TEAM' already exists. Use remove_team.sh to tear it down first."
    exit 1
fi

# Auto-assign port if not provided
if [[ -z "$PORT" ]]; then
    PORT=8000
    while docker ps --format '{{.Ports}}' 2>/dev/null | grep -q "0\.0\.0\.0:${PORT}->"; do
        PORT=$((PORT + 1))
    done
    echo "Auto-assigned port: $PORT"
fi

echo "Starting instance for team '$TEAM' on port $PORT..."

PORT="$PORT" docker compose \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    up --build -d

echo ""
echo "Team '$TEAM' is up."
echo "  URL : http://localhost:$PORT"
echo "  Stop: scripts/remove_team.sh $TEAM"
