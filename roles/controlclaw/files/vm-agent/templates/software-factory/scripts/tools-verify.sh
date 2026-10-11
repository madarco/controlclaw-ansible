#!/bin/bash
# These come with every agent. This step only checks them, and says which one is missing.
missing=""
for tool in make git node pnpm python3 jq; do command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"; done
docker compose version >/dev/null 2>&1 || missing="$missing docker-compose"
[ -z "$missing" ] || { echo "missing:$missing"; exit 1; }
