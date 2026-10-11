#!/usr/bin/env bash
# Launch script for the PQC-DNSSEC MTL Benchmark Workbench UI
set -euo pipefail

UI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8080}"
HOST="${HOST:-0.0.0.0}"

# Free port if held by a previous instance
fuser -k "${PORT}/tcp" 2>/dev/null || true

echo "================================================================="
echo " Starting PQC DNSSEC MTL Benchmark Workbench"
echo " Access URL: http://localhost:${PORT}/"
echo "================================================================="

cd "$(dirname "$UI_DIR")"
exec python3 "${UI_DIR}/server.py"
