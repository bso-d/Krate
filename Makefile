SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.ONESHELL:
.RECIPEPREFIX := >
.DEFAULT_GOAL := help

VERSION ?=
MODE ?= both
ARCH ?= $(shell case "$$(uname -m)" in x86_64|amd64) echo amd64 ;; aarch64|arm64) echo arm64 ;; *) echo unknown ;; esac)
UBUNTU_VERSION ?= noble
RHEL_VERSION ?= 9
# Which prepared package set `bundle` ships when INCLUDE_DOCKER=1. Defaults to
# the Ubuntu release so existing invocations keep working; set TARGET_OS=rhel9
# for a RHEL target.
TARGET_OS ?= $(UBUNTU_VERSION)
RHEL_BUILDER_IMAGE ?= almalinux:9
INCLUDE_DOCKER ?= 0
NO_PULL ?= 0

DIST_DIR := dist
DOCKER_OFFLINE_DIR := docker-offline
CLI_FILES := zk/kafka kraft/kafka epc/kafka

ZK_IMAGES := confluentinc/cp-zookeeper:7.6.1 confluentinc/cp-kafka:7.6.1 kafbat/kafka-ui:v1.5.0 nginx:1.27-alpine
# KRaft images are derived from kraft/.env.template — the single source of truth
# shared with kraft/docker-compose.yml — so the bundle can never ship images that
# differ from what the cluster actually runs.
KRAFT_IMAGES := $(shell . ./kraft/.env.template >/dev/null 2>&1; echo "$$KAFKA_IMAGE $$KAFKA_UI_IMAGE $$NGINX_IMAGE")
EPC_IMAGES := $(shell . ./epc/.env.template >/dev/null 2>&1; echo "$$KAFKA_IMAGE $$KAFKA_UI_IMAGE $$NGINX_IMAGE")
DOCKER_PACKAGES := containerd.io docker-ce-cli docker-ce docker-compose-plugin
# RHEL needs buildx explicitly; on Debian it arrives as a docker-ce dependency.
DOCKER_RPM_PACKAGES := containerd.io docker-ce docker-ce-cli docker-compose-plugin docker-buildx-plugin

.PHONY: help check test validate syntax lint compose-check bundle bundle-zk bundle-kraft bundle-epc docker-debs docker-rpms clean dist-clean
.SILENT: help

help:
>cat <<'EOF'
>Kafka offline bundle workflow
>
>Targets:
>  make check                                     Run syntax, ShellCheck, and Compose validation
>  make test                                      Alias for make check
>  make validate                                  Alias for make check
>  make bundle VERSION=v5 ARCH=amd64              Build both zk and kraft bundles
>  make bundle VERSION=v5 MODE=zk ARCH=arm64      Build one bundle variant
>  make bundle VERSION=v5 ARCH=amd64 INCLUDE_DOCKER=1
>  make bundle VERSION=v1 MODE=epc ARCH=amd64 TARGET_OS=rhel9 INCLUDE_DOCKER=1
>  make docker-debs UBUNTU_VERSION=noble ARCH=amd64
>  make docker-rpms RHEL_VERSION=9 ARCH=amd64
>  make clean                                     Remove bundle staging only
>  make dist-clean                                Remove dist/ and docker-offline/
>
>Variables:
>  VERSION=vN              Required for bundle targets
>  MODE=zk|kraft|epc|both  Default: both (epc = 2-broker EPC variant)
>  ARCH=amd64|arm64        Default: detected host architecture
>  UBUNTU_VERSION=jammy|noble
>                          Target Ubuntu release for docker-debs; default: noble
>  RHEL_VERSION=8|9|10     Target RHEL release for docker-rpms; default: 9
>  TARGET_OS=noble|jammy|rhel9
>                          Which prepared package set INCLUDE_DOCKER=1 ships
>  NO_PULL=1               Reuse local Docker images; they must match ARCH
>  INCLUDE_DOCKER=1        Copy Docker packages prepared for the target Ubuntu/ARCH
>EOF

check: syntax lint compose-check

test validate: check

syntax:
>bash -n $(CLI_FILES)

lint:
>shellcheck $(CLI_FILES)

compose-check:
>docker compose --env-file zk/.env.template -f zk/docker-compose.yml config --quiet
>docker compose --env-file kraft/.env.template -f kraft/docker-compose.yml config --quiet
>docker compose --env-file epc/.env.template -f epc/docker-compose.yml config --quiet

bundle-zk:
>$(MAKE) bundle MODE=zk VERSION="$(VERSION)" ARCH="$(ARCH)" INCLUDE_DOCKER="$(INCLUDE_DOCKER)" NO_PULL="$(NO_PULL)"

bundle-kraft:
>$(MAKE) bundle MODE=kraft VERSION="$(VERSION)" ARCH="$(ARCH)" INCLUDE_DOCKER="$(INCLUDE_DOCKER)" NO_PULL="$(NO_PULL)"

bundle-epc:
>$(MAKE) bundle MODE=epc VERSION="$(VERSION)" ARCH="$(ARCH)" TARGET_OS="$(TARGET_OS)" INCLUDE_DOCKER="$(INCLUDE_DOCKER)" NO_PULL="$(NO_PULL)"

bundle:
>[[ "$(VERSION)" =~ ^v[0-9]+$$ ]] || { echo "VERSION must be in the form vN, e.g. VERSION=v5" >&2; exit 1; }
>[[ "$(MODE)" =~ ^(zk|kraft|epc|both)$$ ]] || { echo "MODE must be zk, kraft, epc, or both" >&2; exit 1; }
>[[ "$(ARCH)" =~ ^(amd64|arm64)$$ ]] || { echo "ARCH must be amd64 or arm64" >&2; exit 1; }
>
>enabled() { [[ "$$1" =~ ^(1|true|yes|on)$$ ]]; }
>image_filename() {
>  local image="$$1" name
>  name="$${image//\//__}"
>  printf '%s.tar\n' "$${name//:/_}"
>}
>save_platform=()
>if docker save --help 2>&1 | grep -q -- '--platform'; then
>  save_platform=(--platform "linux/$(ARCH)")
>fi
>
>build_one() {
>  local mode="$$1"
>  local bundle_name="kafka-$${mode}-$(VERSION)-$(ARCH)"
>  local bundle_dir="$(DIST_DIR)/staging/$${bundle_name}"
>  local out_file="$(DIST_DIR)/$${bundle_name}.tar.gz"
>  local src_dir="$$mode"
>  local -a images
>
>  case "$$mode" in
>    zk)    images=($(ZK_IMAGES)) ;;
>    epc)   images=($(EPC_IMAGES)) ;;
>    *)     images=($(KRAFT_IMAGES)) ;;
>  esac
>
>  echo "==> Building bundle: $$bundle_name"
>  rm -rf "$$bundle_dir"
>  mkdir -p "$$bundle_dir/images"
>
>  if enabled "$(NO_PULL)"; then
>    echo "==> Verifying local images match $(ARCH)"
>    for image in "$${images[@]}"; do
>      image_arch="$$(docker image inspect "$$image" --format '{{.Architecture}}' 2>/dev/null || true)"
>      [[ -n "$$image_arch" ]] || { echo "Image not found locally: $$image" >&2; exit 1; }
>      [[ "$$image_arch" == "$(ARCH)" ]] || { echo "$$image is $$image_arch, expected $(ARCH)" >&2; exit 1; }
>      echo "  ok $$image ($$image_arch)"
>    done
>  else
>    echo "==> Pulling $(ARCH) images"
>    for image in "$${images[@]}"; do
>      docker pull --platform "linux/$(ARCH)" "$$image"
>    done
>  fi
>
>  echo "==> Saving images"
>  for image in "$${images[@]}"; do
>    filename="$$(image_filename "$$image")"
>    docker save "$${save_platform[@]}" "$$image" -o "$$bundle_dir/images/$$filename"
>  done
>
>  cp "$$src_dir/docker-compose.yml" "$$bundle_dir/docker-compose.yml"
>  cp "$$src_dir/nginx.conf" "$$bundle_dir/nginx.conf"
>  cp "$$src_dir/kafka" "$$bundle_dir/kafka"
>  chmod +x "$$bundle_dir/kafka"
>  cp "$$src_dir/.env.template" "$$bundle_dir/.env.template"
>  printf '%s\n' "$(ARCH)" > "$$bundle_dir/.bundle-arch"
>
>  if enabled "$(INCLUDE_DOCKER)"; then
>    pkg_dir="$(DOCKER_OFFLINE_DIR)/$(TARGET_OS)/$(ARCH)"
>    if [[ -d "$$pkg_dir" ]] && find "$$pkg_dir" -maxdepth 1 \( -name '*.deb' -o -name '*.rpm' \) -print -quit | grep -q .; then
>      # Packages are OS-family and release specific. Installing a noble set on
>      # jammy, or a deb set on RHEL, fails on the VM long after the bundle was
>      # built — so verify here rather than ship a broken install path.
>      manifest="$$pkg_dir/.docker-manifest"
>      if [[ ! -f "$$manifest" ]]; then
>        echo "$$pkg_dir has no .docker-manifest — cannot prove the packages match $(TARGET_OS)/$(ARCH)." >&2
>        echo "Run: make docker-debs UBUNTU_VERSION=$(TARGET_OS) ARCH=$(ARCH)   (or make docker-rpms for RHEL)" >&2
>        exit 1
>      fi
>      m_arch="$$(awk -F= '/^ARCH=/{print $$2}' "$$manifest")"
>      m_os="$$(awk -F= '/^OS_TARGET=/{print $$2}' "$$manifest")"
>      if [[ "$$m_arch" != "$(ARCH)" || "$$m_os" != "$(TARGET_OS)" ]]; then
>        echo "$$pkg_dir holds packages for $$m_os/$$m_arch, but this bundle is $(TARGET_OS)/$(ARCH)." >&2
>        exit 1
>      fi
>      echo "==> Bundling Docker CE for $$m_os/$$m_arch"
>      cp -r "$$pkg_dir" "$$bundle_dir/docker-offline"
>    else
>      echo "$(DOCKER_OFFLINE_DIR)/$(TARGET_OS)/$(ARCH) has no packages." >&2
>      echo "Run: make docker-debs UBUNTU_VERSION=<jammy|noble> ARCH=$(ARCH)   (or make docker-rpms RHEL_VERSION=9 ARCH=$(ARCH))" >&2
>      exit 1
>    fi
>  fi
>
>  mkdir -p "$(DIST_DIR)"
>  COPYFILE_DISABLE=1 tar -czf "$$out_file" -C "$(DIST_DIR)/staging" "$$bundle_name"
>  rm -rf "$$bundle_dir"
>
>  if command -v sha256sum >/dev/null 2>&1; then
>    ( cd "$(DIST_DIR)" && sha256sum "$${bundle_name}.tar.gz" ) > "$${out_file}.sha256"
>  elif command -v shasum >/dev/null 2>&1; then
>    ( cd "$(DIST_DIR)" && shasum -a 256 "$${bundle_name}.tar.gz" ) > "$${out_file}.sha256"
>  else
>    echo "No sha256sum or shasum found; checksum sidecar not written" >&2
>  fi
>
>  echo "==> Wrote $$out_file"
>}
>
>mkdir -p "$(DIST_DIR)/staging"
>case "$(MODE)" in
>  zk) build_one zk ;;
>  kraft) build_one kraft ;;
>  epc) build_one epc ;;
>  both) build_one zk; build_one kraft ;;
>esac

docker-debs:
>[[ "$(UBUNTU_VERSION)" =~ ^(jammy|noble)$$ ]] || { echo "UBUNTU_VERSION must be jammy or noble" >&2; exit 1; }
>[[ "$(ARCH)" =~ ^(amd64|arm64)$$ ]] || { echo "ARCH must be amd64 or arm64" >&2; exit 1; }
>output_dir="$(DOCKER_OFFLINE_DIR)/$(UBUNTU_VERSION)/$(ARCH)"
>rm -rf "$$output_dir"
>mkdir -p "$$output_dir"
>echo "==> Downloading Docker CE packages"
>echo "    Ubuntu : $(UBUNTU_VERSION)"
>echo "    Arch   : $(ARCH)"
>echo "    Output : $$output_dir"
>
>docker run --rm --platform "linux/$(ARCH)" \
>  -v "$$(pwd)/$$output_dir:/output" \
>  "ubuntu:$(UBUNTU_VERSION)" bash -c '
>    set -euo pipefail
>    export DEBIAN_FRONTEND=noninteractive
>    apt-get update -qq
>    apt-get install -y -qq ca-certificates curl
>    install -m 0755 -d /etc/apt/keyrings
>    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
>    chmod a+r /etc/apt/keyrings/docker.asc
>    echo "deb [arch=$(ARCH) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(UBUNTU_VERSION) stable" > /etc/apt/sources.list.d/docker.list
>    apt-get update -qq
>    cd /tmp
>    apt-get download $(DOCKER_PACKAGES)
>    mv /tmp/*.deb /output/
>  '
>
>cat > "$$output_dir/install-docker.sh" <<-'INSTALL_SCRIPT'
>#!/usr/bin/env bash
>set -euo pipefail
>
>SCRIPT_DIR="$$(cd "$$(dirname "$${BASH_SOURCE[0]}")" && pwd)"
>
>install_pkg() {
>  local pkg="$$1"
>  local -a matches
>  shopt -s nullglob
>  matches=("$$SCRIPT_DIR/$${pkg}_"*.deb)
>  shopt -u nullglob
>  if [[ $${#matches[@]} -eq 1 ]]; then
>    sudo dpkg -i "$${matches[0]}" || true
>  elif [[ $${#matches[@]} -eq 0 ]]; then
>    echo "WARNING: $$pkg not found in bundle; skipping"
>  else
>    echo "ERROR: multiple packages found for $$pkg" >&2
>    printf '  %s\n' "$${matches[@]}" >&2
>    return 1
>  fi
>}
>
>for pkg in containerd.io docker-ce-cli docker-ce docker-compose-plugin; do
>  install_pkg "$$pkg"
>done
>
>sudo apt-get install -f -y 2>/dev/null || true
>sudo systemctl enable --now docker
>
>target_user="$${SUDO_USER:-}"
>if [[ -z "$$target_user" || "$$target_user" == "root" ]]; then
>  target_user="$${USER:-}"
>fi
>if [[ -z "$$target_user" || "$$target_user" == "root" ]]; then
>  target_user="$$(id -un 2>/dev/null || true)"
>fi
>
>if [[ -n "$$target_user" && "$$target_user" != "root" ]] && id "$$target_user" >/dev/null 2>&1; then
>  if ! id -nG "$$target_user" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
>    sudo usermod -aG docker "$$target_user"
>    echo "Added $$target_user to the docker group. Run 'newgrp docker' or log out and back in."
>  fi
>else
>  echo "No non-root local user detected for docker group membership; add one manually if needed:"
>  echo "  sudo usermod -aG docker <username>"
>fi
>
>docker --version
>docker compose version
>INSTALL_SCRIPT
>chmod +x "$$output_dir/install-docker.sh"
>
># Record what these packages were built for. `bundle` refuses to ship them
># unless this matches the TARGET_OS/ARCH being built.
>{
>  echo "OS_TARGET=$(UBUNTU_VERSION)"
>  echo "OS_FAMILY=debian"
>  echo "ARCH=$(ARCH)"
>  echo "PREPARED=$$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
>  for pkg in "$$output_dir"/*.deb; do echo "PACKAGE=$$(basename "$$pkg")"; done
>} > "$$output_dir/.docker-manifest"
>echo "==> Prepared Docker CE for $(UBUNTU_VERSION)/$(ARCH):"
>sed 's/^/    /' "$$output_dir/.docker-manifest"
>find "$$output_dir" -maxdepth 1 -name '*.deb' -exec du -h {} \;

docker-rpms:
>[[ "$(RHEL_VERSION)" =~ ^(8|9|10)$$ ]] || { echo "RHEL_VERSION must be 8, 9 or 10" >&2; exit 1; }
>[[ "$(ARCH)" =~ ^(amd64|arm64)$$ ]] || { echo "ARCH must be amd64 or arm64" >&2; exit 1; }
>case "$(ARCH)" in
>  amd64) rpm_arch=x86_64 ;;
>  arm64) rpm_arch=aarch64 ;;
>esac
>output_dir="$(DOCKER_OFFLINE_DIR)/rhel$(RHEL_VERSION)/$(ARCH)"
>rm -rf "$$output_dir"
>mkdir -p "$$output_dir"
>echo "==> Downloading Docker CE packages"
>echo "    RHEL   : $(RHEL_VERSION) ($$rpm_arch)"
>echo "    Arch   : $(ARCH)"
>echo "    Builder: $(RHEL_BUILDER_IMAGE)"
>echo "    Output : $$output_dir"
>
># --resolve also pulls dependencies the builder image lacks (container-selinux
># being the one a minimal RHEL host usually needs), so the set installs with
># dnf --disablerepo='*' on an air-gapped VM.
>docker run --rm --platform "linux/$(ARCH)" \
>  -e BASEURL="https://download.docker.com/linux/rhel/$(RHEL_VERSION)/$$rpm_arch/stable" \
>  -e PKGS="$(DOCKER_RPM_PACKAGES)" \
>  -v "$$(pwd)/$$output_dir:/output" \
>  "$(RHEL_BUILDER_IMAGE)" bash -c '
>    set -euo pipefail
>    printf "[docker-ce-stable]\nname=Docker CE Stable\nbaseurl=%s\nenabled=1\ngpgcheck=1\ngpgkey=https://download.docker.com/linux/rhel/gpg\n" "$$BASEURL" > /etc/yum.repos.d/docker-ce.repo
>    dnf install -y -q dnf-plugins-core
>    dnf download --resolve --destdir /output $$PKGS
>    chmod 0644 /output/*.rpm
>  '
>
>cat > "$$output_dir/install-docker.sh" <<'INSTALL_RPM'
>#!/usr/bin/env bash
># Install Docker CE from the bundled RPM packages (RHEL family).
>set -euo pipefail
>SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
>
>installer=dnf
>command -v dnf >/dev/null 2>&1 || installer=yum
>
>echo "==> Installing Docker CE from bundled RPMs..."
># --disablerepo='*' keeps this strictly offline: every dependency must be on
># the host already or in this directory. It fails loudly rather than silently
># reaching for a network repo that an air-gapped VM does not have.
>sudo "$installer" install -y --disablerepo='*' "$SCRIPT_DIR"/*.rpm
>
>echo "==> Enabling Docker service..."
>sudo systemctl enable --now docker
>
>target_user="${SUDO_USER:-${USER:-$(id -un)}}"
>if [[ -n "$target_user" && "$target_user" != "root" ]]; then
>  if ! id -nG "$target_user" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
>    sudo usermod -aG docker "$target_user"
>    echo "Added $target_user to the docker group. Run 'newgrp docker' or log out and back in."
>  fi
>fi
>
>docker --version
>docker compose version
>INSTALL_RPM
>chmod +x "$$output_dir/install-docker.sh"
>
>{
>  echo "OS_TARGET=rhel$(RHEL_VERSION)"
>  echo "OS_FAMILY=rhel"
>  echo "ARCH=$(ARCH)"
>  echo "PREPARED=$$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
>  for pkg in "$$output_dir"/*.rpm; do echo "PACKAGE=$$(basename "$$pkg")"; done
>} > "$$output_dir/.docker-manifest"
>echo "==> Prepared Docker CE for rhel$(RHEL_VERSION)/$(ARCH):"
>sed 's/^/    /' "$$output_dir/.docker-manifest"
>du -sh "$$output_dir"

clean:
>rm -rf "$(DIST_DIR)/staging"

dist-clean:
>rm -rf "$(DIST_DIR)" "$(DOCKER_OFFLINE_DIR)"
