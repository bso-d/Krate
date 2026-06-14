#!/usr/bin/env bash
# Run this ONCE on a machine with internet access.
# Pulls all required Docker images and saves them to ./images/ as .tar files.
# Then transfer the whole folder (including images/) to the offline machine.

set -euo pipefail

IMAGES_DIR="$(cd "$(dirname "$0")" && pwd)/images"
mkdir -p "$IMAGES_DIR"

EXTERNAL_IMAGES=(
  "confluentinc/cp-zookeeper:7.6.1"
  "confluentinc/cp-kafka:7.6.1"
  "confluentinc/cp-schema-registry:7.6.1"
  "kafbat/kafka-ui:latest"
  "nginx:1.27-alpine"
)

echo "==> Pulling external images..."
for img in "${EXTERNAL_IMAGES[@]}"; do
  echo "  Pulling $img"
  docker pull "$img"
done

echo "==> Saving images to $IMAGES_DIR ..."
for img in "${EXTERNAL_IMAGES[@]}"; do
  # turn slashes and colons into underscores for the filename
  filename="${img//\//__}"
  filename="${filename//:/_}.tar"
  echo "  Saving $img -> images/$filename"
  docker save "$img" -o "$IMAGES_DIR/$filename"
done

echo ""
echo "Done. Transfer this entire folder (including images/) to the offline machine"
echo "and run ./load-images.sh followed by docker compose up -d"
