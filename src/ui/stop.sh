#!/usr/bin/env bash
# Stop script for the PQC-DNSSEC MTL Benchmark Workbench UI
set -euo pipefail

PORT="${PORT:-8080}"

echo "================================================================="
echo " Stopping PQC DNSSEC MTL Benchmark Workbench (Port: ${PORT})"
echo "================================================================="

fuser -k "${PORT}/tcp" 2>/dev/null || true
pkill -f "ui/server.py" 2>/dev/null || true

echo "Workbench UI server stopped."
