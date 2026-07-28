#!/usr/bin/env bash
# Noir Docker Runner
# Usage: ./docker-run.sh scan http://localhost:3000
#        ./docker-run.sh attack http://target.com
#        ./docker-run.sh --help

set -euo pipefail

IMAGE="noir:latest"

# Build image if not present
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "[*] Building Noir Docker image..."
    docker build -t "$IMAGE" .
fi

# Persist findings DB and reports on host
mkdir -p "$HOME/.noir" noir_reports

CMD="${1:-help}"
shift 2>/dev/null || true

exec docker run --rm -it \
    -v "$HOME/.noir:/root/.noir" \
    -v "$(pwd)/noir_reports:/workspace/noir_reports" \
    -v "$(pwd)/.opencode:/workspace/.opencode:ro" \
    -v "$(pwd)/opencode.jsonc:/workspace/opencode.jsonc:ro" \
    -v "$(pwd)/tools:/workspace/tools:ro" \
    -v "$(pwd)/scripts:/workspace/scripts:ro" \
    -e OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
    -e ROUTER_API_KEY="${ROUTER_API_KEY:-}" \
    -e LLM_API_BASE="${LLM_API_BASE:-}" \
    --network host \
    "$IMAGE" \
    "$CMD" "$@"
