#!/usr/bin/env bash
# List all running CTF team instances with their ports.

printf "%-20s %-10s %s\n" "TEAM" "PORT" "STATUS"
printf "%-20s %-10s %s\n" "----" "----" "------"

docker ps --format '{{.Names}}|{{.Ports}}|{{.Status}}' | grep '^ctf_.*-web-' | \
while IFS='|' read -r name ports status; do
    team="${name#ctf_}"
    team="${team%-web-*}"
    port="$(echo "$ports" | grep -oP '(?<=:)\d+(?=->80)' | head -1)"
    printf "%-20s %-10s %s\n" "$team" "${port:-?}" "$status"
done
