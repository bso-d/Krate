#!/usr/bin/env bash
# download-docker-debs.sh — Download Docker CE ARM64 .deb packages
#
# Runs an Ubuntu ARM64 container on this machine to download the packages,
# so they can be bundled for offline installation on an ARM Ubuntu VM.
#
# Usage:
#   ./download-docker-debs.sh [--ubuntu-version jammy|noble]
#
# Ubuntu versions:
#   jammy  = 22.04 LTS  (default)
#   noble  = 24.04 LTS
#
# Output:
#   ./docker-offline/*.deb
#   ./docker-offline/install-docker.sh
#
# After this runs, rebuild the bundle with:
#   ./make-bundle.sh --include-docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UBUNTU_VERSION="jammy"
ARCH="arm64"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ubuntu-version) UBUNTU_VERSION="$2"; shift 2 ;;
    --arch)           ARCH="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--ubuntu-version jammy|noble] [--arch amd64|arm64]"
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[[ "$UBUNTU_VERSION" =~ ^(jammy|noble)$ ]] || {
  echo "Unsupported Ubuntu version: $UBUNTU_VERSION (use: jammy or noble)"
  exit 1
}
[[ "$ARCH" =~ ^(amd64|arm64)$ ]] || {
  echo "Unsupported arch: $ARCH (use: amd64 or arm64)"
  exit 1
}

# Packages are kept per-arch so a bundle includes only the set it needs.
OUTPUT_DIR="$SCRIPT_DIR/docker-offline/$ARCH"
mkdir -p "$OUTPUT_DIR"

echo "==> Downloading Docker CE $ARCH packages"
echo "    Ubuntu : $UBUNTU_VERSION"
echo "    Arch   : $ARCH"
echo "    Output : $OUTPUT_DIR"
echo ""

# Run a matching-arch Ubuntu container to download the deb packages, so we get
# the right architecture regardless of the host machine (emulated if needed).
docker run --rm --platform "linux/$ARCH" \
  -v "$OUTPUT_DIR:/output" \
  "ubuntu:${UBUNTU_VERSION}" bash -c "
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    echo '--- Updating package lists ---'
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl

    echo '--- Adding Docker APT repo ---'
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo \"deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_VERSION} stable\" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq

    echo '--- Downloading packages ---'
    cd /tmp
    apt-get download \
      containerd.io \
      docker-ce-cli \
      docker-ce \
      docker-compose-plugin

    mv /tmp/*.deb /output/
    echo 'Done.'
  "

echo ""
echo "==> Downloaded packages:"
ls -lh "$OUTPUT_DIR"/*.deb
echo ""

# Write the standalone install script that will be included in the bundle
cat > "$OUTPUT_DIR/install-docker.sh" << 'INSTALL_SCRIPT'
#!/usr/bin/env bash
# Install Docker CE from bundled .deb packages (Ubuntu).
# Run this on the VM if Docker is not installed or not working.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing Docker CE..."
echo ""

install_pkg() {
  local pkg="$1"
  local deb
  deb=$(ls "$SCRIPT_DIR/${pkg}_"*.deb 2>/dev/null | head -1 || true)
  if [[ -n "$deb" ]]; then
    echo "    $(basename "$deb")"
    sudo dpkg -i "$deb" || true   # ignore exit code; apt-get -f install fixes deps
  else
    echo "    WARNING: $pkg not found in bundle — skipping"
  fi
}

# Install in dependency order
for pkg in containerd.io docker-ce-cli docker-ce docker-compose-plugin; do
  install_pkg "$pkg"
done

echo ""
echo "==> Fixing any unmet dependencies..."
sudo apt-get install -f -y 2>/dev/null || true

echo ""
echo "==> Enabling Docker service..."
sudo systemctl enable --now docker

if ! groups "$USER" 2>/dev/null | grep -q '\bdocker\b'; then
  sudo usermod -aG docker "$USER"
  echo ""
  echo "NOTE: Added $USER to the docker group."
  echo "      Run 'newgrp docker' or log out and back in."
fi

echo ""
docker --version
docker compose version
echo ""
echo "Docker installed. Run: ./kafka docker-check"
INSTALL_SCRIPT

chmod +x "$OUTPUT_DIR/install-docker.sh"

echo "==> Created install-docker.sh"
echo ""
echo "Next step:"
echo "  ./make-bundle.sh --version vN --arch $ARCH --include-docker"
echo ""
