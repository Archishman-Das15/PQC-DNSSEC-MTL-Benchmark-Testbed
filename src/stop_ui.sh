#!/usr/bin/env bash
# Double-click / 1-click shortcut to stop Workbench UI
set -euo pipefail
cd "$(dirname "$0")"

docker compose stop ui 2>/dev/null || true
./ui/stop.sh 2>/dev/null || true
echo "==> Workbench UI stopped."
