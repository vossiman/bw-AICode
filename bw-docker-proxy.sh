#!/bin/bash
# bw-docker-proxy — Start/stop the Docker socket proxy for bwrap sandboxes
set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
exec docker compose -f "$SCRIPT_DIR/docker-compose.yml" "$@"
