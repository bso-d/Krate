#!/usr/bin/env bash
# make-bundle.sh — Build portable offline install bundles for Kafka
#
# Usage:
#   ./make-bundle.sh --version v2 [--mode zk|kraft|both] [--arch amd64|arm64] [--no-pull] [--include-docker]
#
# Output:
#   dist/kafka-zk-v2-<arch>.tar.gz
#   dist/kafka-kraft-v2-<arch>.tar.gz
#
# Prerequisites:
#   - Docker running on this machine
#   - Internet access (pulls images during build), or use --no-pull if already local
#     (with --no-pull the local image's architecture must match --arch)
#   - For --include-docker: run download-docker-debs.sh --arch <arch> first

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
VERSION=""
MODE="both"
INCLUDE_DOCKER=false
NO_PULL=false

# Default to the build host's architecture (x86_64 → amd64, aarch64 → arm64).
case "$(uname -m)" in
  x86_64|amd64)   ARCH="amd64" ;;
  aarch64|arm64)  ARCH="arm64" ;;
  *)              ARCH="" ;;
esac

# ─── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ "${2:-}" =~ ^v[0-9]+$ ]] || { echo "--version must be in the form vN (e.g. v2)"; exit 1; }
      VERSION="$2"; shift 2 ;;
    --mode)
      [[ "${2:-}" =~ ^(zk|kraft|both)$ ]] || { echo "--mode must be: zk, kraft, or both"; exit 1; }
      MODE="$2"; shift 2 ;;
    --arch)
      [[ "${2:-}" =~ ^(amd64|arm64)$ ]] || { echo "--arch must be: amd64 or arm64"; exit 1; }
      ARCH="$2"; shift 2 ;;
    --include-docker)
      INCLUDE_DOCKER=true; shift ;;
    --no-pull)
      NO_PULL=true; shift ;;
    -h|--help)
      echo "Usage: $0 --version vN [--mode zk|kraft|both] [--arch amd64|arm64] [--no-pull] [--include-docker]"
      exit 0 ;;
    *)
      echo "Unknown option: $1"; exit 1 ;;
  esac
done

[[ -n "$VERSION" ]] || { echo "Error: --version is required (e.g. --version v2)"; exit 1; }
[[ -n "$ARCH" ]] || { echo "Error: could not detect host arch; pass --arch amd64|arm64"; exit 1; }

# Use `docker save --platform` when available so multi-platform tags (containerd
# image store) export exactly the requested arch instead of the host's.
SAVE_PLATFORM=()
if docker save --help 2>&1 | grep -q -- '--platform'; then
  SAVE_PLATFORM=(--platform "linux/$ARCH")
fi

# ─── Image lists ──────────────────────────────────────────────────────────────
ZK_IMAGES=(
  "confluentinc/cp-zookeeper:7.6.1"
  "confluentinc/cp-kafka:7.6.1"
  "kafbat/kafka-ui:latest"
  "nginx:1.27-alpine"
)

KRAFT_IMAGES=(
  "confluentinc/cp-kafka:7.6.1"
  "kafbat/kafka-ui:latest"
  "nginx:1.27-alpine"
)

# ─── Helpers ──────────────────────────────────────────────────────────────────
info() { echo "==> $*"; }
ok()   { echo "  ✓ $*"; }
warn() { echo "  ! $*"; }
die()  { echo "  ✗ $*" >&2; exit 1; }

image_filename() {
  local img="$1"
  local name="${img//\//__}"
  echo "${name//:/_}.tar"
}

# ─── Build one bundle ─────────────────────────────────────────────────────────
build_bundle() {
  local mode="$1"        # zk or kraft
  local bundle_name="kafka-${mode}-${VERSION}-${ARCH}"
  local bundle_dir="$DIST_DIR/staging/$bundle_name"
  local out_file="$DIST_DIR/${bundle_name}.tar.gz"

  info "Building bundle: $bundle_name"
  echo ""

  # Staging dir
  rm -rf "$bundle_dir"
  mkdir -p "$bundle_dir/images"

  # Pick the right image list
  local -a images
  if [[ "$mode" == "zk" ]]; then
    images=("${ZK_IMAGES[@]}")
  else
    images=("${KRAFT_IMAGES[@]}")
  fi

  # ── Pull images (skip if --no-pull) ──
  if $NO_PULL; then
    info "Skipping pull (--no-pull) — verifying local images match $ARCH..."
    for img in "${images[@]}"; do
      local img_arch
      img_arch="$(docker image inspect "$img" --format '{{.Architecture}}' 2>/dev/null || true)"
      if [[ -z "$img_arch" ]]; then
        die "Image not found locally: $img  (remove --no-pull to fetch it)"
      elif [[ "$img_arch" != "$ARCH" ]]; then
        die "Local $img is $img_arch but --arch is $ARCH. Remove --no-pull to fetch the $ARCH image."
      fi
      ok "$img ($img_arch)"
    done
  else
    info "Pulling $ARCH images..."
    for img in "${images[@]}"; do
      echo "    $img"
      docker pull --platform "linux/$ARCH" "$img"
    done
  fi
  echo ""

  # ── Save images ──
  # Pass --platform so we export exactly $ARCH. On Docker's containerd image
  # store a tag can hold multiple platforms, and a plain `docker save` exports
  # the host's arch — which silently produced wrong-arch bundles. (SAVE_PLATFORM
  # is empty on older Docker that lacks the flag, where the tag is single-arch.)
  info "Saving $ARCH images to images/..."
  for img in "${images[@]}"; do
    local fname
    fname="$(image_filename "$img")"
    echo "    $img  →  images/$fname"
    docker save "${SAVE_PLATFORM[@]}" "$img" -o "$bundle_dir/images/$fname"
  done
  echo ""

  # ── Copy source directory contents (compose, CLI, template) ──
  local src_dir="$SCRIPT_DIR/$mode"
  [[ -d "$src_dir" ]] || die "Source directory not found: $src_dir"

  cp "$src_dir/docker-compose.yml" "$bundle_dir/docker-compose.yml"
  ok "docker-compose.yml"

  cp "$src_dir/nginx.conf" "$bundle_dir/nginx.conf"
  ok "nginx.conf"

  cp "$src_dir/kafka" "$bundle_dir/kafka"
  chmod +x "$bundle_dir/kafka"
  ok "kafka (CLI)"

  cp "$src_dir/.env.template" "$bundle_dir/.env.template"
  ok ".env.template"

  # Record the bundle's architecture so `kafka doctor` can flag an arch mismatch.
  echo "$ARCH" > "$bundle_dir/.bundle-arch"
  ok ".bundle-arch ($ARCH)"

  # ── Optionally include Docker offline packages (per-arch) ──
  if $INCLUDE_DOCKER; then
    local deb_dir="$SCRIPT_DIR/docker-offline/$ARCH"
    if [[ -d "$deb_dir" ]] && find "$deb_dir" -name "*.deb" -maxdepth 1 | grep -q .; then
      cp -r "$deb_dir" "$bundle_dir/docker-offline"
      ok "docker-offline/ ($(find "$deb_dir" -name "*.deb" -maxdepth 1 | wc -l | xargs) $ARCH packages)"
    else
      warn "docker-offline/$ARCH has no .deb files — skipping Docker packages."
      warn "Run ./download-docker-debs.sh --arch $ARCH first, then rebuild with --include-docker."
    fi
  fi

  echo ""

  # ── Create tarball ──
  info "Creating tarball..."
  tar -czf "$out_file" -C "$DIST_DIR/staging" "$bundle_name"
  rm -rf "$bundle_dir"

  # ── Checksum ──
  # Generate the checksum with a bare filename (no path) so `sha256sum -c`
  # works on the VM regardless of where the bundle is downloaded to. Running
  # the hash tool from inside DIST_DIR keeps only "<hash>  <bundle>.tar.gz".
  if command -v sha256sum &>/dev/null; then
    ( cd "$DIST_DIR" && sha256sum "${bundle_name}.tar.gz" ) > "${out_file}.sha256"
  elif command -v shasum &>/dev/null; then
    ( cd "$DIST_DIR" && shasum -a 256 "${bundle_name}.tar.gz" ) > "${out_file}.sha256"
  fi

  local size
  size="$(du -sh "$out_file" | cut -f1)"

  echo ""
  echo "────────────────────────────────────────────────"
  ok "Bundle : $out_file  ($size)"
  ok "SHA256 : ${out_file}.sha256"
  echo "────────────────────────────────────────────────"
  echo ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────
mkdir -p "$DIST_DIR/staging"

case "$MODE" in
  zk)    build_bundle "zk" ;;
  kraft) build_bundle "kraft" ;;
  both)  build_bundle "zk"; build_bundle "kraft" ;;
esac

rm -rf "$DIST_DIR/staging"

echo ""
echo "Transfer bundle(s) to the VM, then:"
echo ""
echo "  tar -xzf kafka-<mode>-${VERSION}-${ARCH}.tar.gz"
echo "  cd kafka-<mode>-${VERSION}-${ARCH}"
echo "  ./kafka docker-check          # verify Docker is ready"
echo "  ./kafka docker-install        # only if Docker isn't working"
echo "  ./kafka install               # load images + start cluster"
echo ""
