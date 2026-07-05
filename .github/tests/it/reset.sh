#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-spiffe-helper-integration}

docker compose down --volumes --remove-orphans
rm -f spire/agent/bootstrap.crt
