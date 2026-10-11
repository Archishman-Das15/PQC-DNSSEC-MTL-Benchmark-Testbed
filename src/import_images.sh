#!/usr/bin/env bash
# One-click Docker image loader for Linux (Ubuntu / Debian)
set -euo pipefail
cd "$(dirname "$0")"

ARCHIVE="pqc_docker_images.tar.gz"
if [ ! -f "$ARCHIVE" ]; then
  echo "[ERROR] Image archive '$ARCHIVE' not found in current directory."
  exit 1
fi

echo "================================================================="
echo " Loading Pre-Compiled PQC DNSSEC Docker Images..."
echo "================================================================="
docker load -i "$ARCHIVE"
echo "================================================================="
echo " All images loaded successfully!"
echo " To start the entire testbed hierarchy and Workbench UI, run:"
echo "   ./tb.sh up"
echo "================================================================="
