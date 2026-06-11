#!/usr/bin/env bash
# Run this on the OFFLINE machine after transferring the folder.
# Loads all saved Docker image tarballs from ./images/ into the local Docker daemon.

set -euo pipefail

IMAGES_DIR="$(cd "$(dirname "$0")" && pwd)/images"

if [ ! -d "$IMAGES_DIR" ]; then
  echo "ERROR: images/ directory not found."
  echo "Run save-images.sh on a connected machine first, then transfer the folder here."
  exit 1
fi

shopt -s nullglob
TARS=("$IMAGES_DIR"/*.tar)

if [ ${#TARS[@]} -eq 0 ]; then
  echo "ERROR: No .tar files found in $IMAGES_DIR"
  exit 1
fi

echo "==> Loading Docker images from $IMAGES_DIR ..."
for tar in "${TARS[@]}"; do
  echo "  Loading $(basename "$tar")"
  docker load -i "$tar"
done

echo ""
echo "All images loaded. You can now run:"
echo "  docker compose up -d"
