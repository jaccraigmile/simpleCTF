#!/bin/bash
# reset.sh — full wipe and redeploy of BankingAI CTF
# Run from anywhere on the host: bash ~/bankingai-ctf/reset.sh

set -e

REPO="$HOME/bankingai-ctf"

echo ""
echo "=========================================="
echo "  BankingAI CTF — Full Reset & Redeploy"
echo "=========================================="
echo ""

# ── 1. Stop and remove all CTF containers ──────────────────────────────────
echo "[1/6] Stopping and removing CTF containers..."
CONTAINERS=$(sudo docker ps -aq --filter "name=ctf_")
if [ -n "$CONTAINERS" ]; then
    sudo docker rm -f $CONTAINERS
    echo "      Removed $(echo "$CONTAINERS" | wc -w) container(s)."
else
    echo "      No containers found."
fi

# ── 2. Remove all CTF volumes ──────────────────────────────────────────────
echo "[2/6] Removing CTF volumes..."
VOLUMES=$(sudo docker volume ls -q --filter "name=ctf_")
if [ -n "$VOLUMES" ]; then
    sudo docker volume rm $VOLUMES
    echo "      Removed $(echo "$VOLUMES" | wc -w) volume(s)."
else
    echo "      No volumes found."
fi

# ── 3. Wipe manager database ───────────────────────────────────────────────
echo "[3/6] Wiping manager database..."
sudo rm -rf "$REPO/manager/data/"
echo "      Done."

# ── 4. Pull latest from GitHub ─────────────────────────────────────────────
echo "[4/6] Pulling latest code from GitHub..."
cd "$REPO" && git pull
echo "      Done."

# ── 5. Rebuild challenge image ─────────────────────────────────────────────
echo "[5/6] Building challenge image..."
cd "$REPO/challenge" && sudo docker compose build
echo "      Done."

# ── 6. Start manager ───────────────────────────────────────────────────────
echo "[6/6] Starting manager..."
cd "$REPO/manager" && sudo docker compose up --build -d
echo "      Done."

echo ""
echo "=========================================="
echo "  All done! Manager is up."
echo "  Browse to http://$(hostname -I | awk '{print $1}')"
echo "  (or whatever port you mapped in manager/docker-compose.yaml)"
echo "=========================================="
echo ""
