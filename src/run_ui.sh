#!/usr/bin/env bash
# Double-click / 1-click shortcut to launch Workbench UI
set -euo pipefail
cd "$(dirname "$0")"

export HOST_DIR="$(pwd)"
if [ -f .env ]; then
    if grep -q "^HOST_DIR=" .env 2>/dev/null; then
        sed -i "s|^HOST_DIR=.*|HOST_DIR=${HOST_DIR}|" .env
    else
        echo "HOST_DIR=${HOST_DIR}" >> .env
    fi
fi

if docker info >/dev/null 2>&1; then
    echo "==> Starting containerized Workbench UI..."
    docker compose up -d ui
    echo "==> Workbench UI accessible at: http://localhost:8080/"
else
    echo "==> Docker daemon not reachable, falling back to local Python server..."
    exec ./ui/run.sh "$@"
fi
