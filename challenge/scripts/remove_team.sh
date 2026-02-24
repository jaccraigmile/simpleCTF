#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yaml"

# Manager DB — override with MANAGER_DB env var if layout differs
MANAGER_DB="${MANAGER_DB:-$(dirname "$PROJECT_DIR")/manager/data/manager.db}"

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

echo "Team '$TEAM' Docker instance removed."

# ── Manager DB cleanup ───────────────────────────────────────────────────────
if [[ ! -f "$MANAGER_DB" ]]; then
    echo "Warning: manager DB not found at $MANAGER_DB — manager DB unchanged."
elif ! command -v python3 &>/dev/null; then
    echo "Warning: python3 not available — manager DB unchanged."
else
    MANAGER_DB="$MANAGER_DB" TEAM_NAME="$TEAM" python3 - <<'PYEOF'
import os, sqlite3
db   = os.environ['MANAGER_DB']
team = os.environ['TEAM_NAME']
conn = sqlite3.connect(db)
conn.execute("DELETE FROM hint_purchases WHERE team_name = ?", (team,))
conn.execute("DELETE FROM name_purchases WHERE team_name = ?", (team,))
conn.execute("DELETE FROM submissions    WHERE team_name = ?", (team,))
conn.execute("DELETE FROM teams          WHERE name = ?",      (team,))
conn.commit()
conn.close()
PYEOF
    echo "Team '$TEAM' removed from manager DB."
fi
