SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.ONESHELL:
.RECIPEPREFIX := >
.DEFAULT_GOAL := help

VERSION ?=
MODE ?= both
ARCH ?= $(shell case "$$(uname -m)" in x86_64|amd64) echo amd64 ;; aarch64|arm64) echo arm64 ;; *) echo unknown ;; esac)
UBUNTU_VERSION ?= noble
INCLUDE_DOCKER ?= 0
NO_PULL ?= 0

DIST_DIR := dist
IMAGE_DIR := images
DOCKER_OFFLINE_DIR := docker-offline
CLI_FILES := zk/kafka kraft/kafka

ZK_IMAGES := confluentinc/cp-zookeeper:7.6.1 confluentinc/cp-kafka:7.6.1 kafbat/kafka-ui:latest nginx:1.27-alpine
KRAFT_IMAGES := confluentinc/cp-kafka:7.6.1 kafbat/kafka-ui:latest nginx:1.27-alpine
REFERENCE_IMAGES := confluentinc/cp-zookeeper:7.6.1 confluentinc/cp-kafka:7.6.1 confluentinc/cp-schema-registry:7.6.1 kafbat/kafka-ui:latest nginx:1.27-alpine
DOCKER_PACKAGES := containerd.io docker-ce-cli docker-ce docker-compose-plugin

.PHONY: help check test validate syntax lint compose-check bundle bundle-zk bundle-kraft docker-debs save-images load-images clean dist-clean
.SILENT: help

help:
>cat <<'EOF'
>Kafka offline bundle workflow
>
>Targets:
>  make check                                      Run syntax, ShellCheck, and Compose validation
>  make test                                       Alias for make check
>  make validate                                   Alias for make check
>  make bundle VERSION=v5 ARCH=amd64              Build both zk and kraft bundles
>  make bundle VERSION=v5 MODE=zk ARCH=arm64      Build one bundle variant
>  make bundle VERSION=v5 ARCH=amd64 INCLUDE_DOCKER=1
>  make docker-debs UBUNTU_VERSION=noble ARCH=amd64
>  make save-images ARCH=amd64                    Pull/save reference images for one architecture
>  make load-images                               Load images/*.tar into local Docker
>  make clean                                     Remove bundle staging only
>  make dist-clean                                Remove dist/, images/, and docker-offline/
>
>Variables:
>  VERSION=vN              Required for bundle targets
>  MODE=zk|kraft|both      Default: both
>  ARCH=amd64|arm64        Default: detected host architecture
>  UBUNTU_VERSION=jammy|noble
>                          Target Ubuntu release for docker-debs; default: noble
>  NO_PULL=1               Reuse local Docker images; they must match ARCH
>  INCLUDE_DOCKER=1        Copy docker-offline/ARCH into the bundle
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

bundle-zk:
>$(MAKE) bundle MODE=zk VERSION="$(VERSION)" ARCH="$(ARCH)" INCLUDE_DOCKER="$(INCLUDE_DOCKER)" NO_PULL="$(NO_PULL)"

bundle-kraft:
>$(MAKE) bundle MODE=kraft VERSION="$(VERSION)" ARCH="$(ARCH)" INCLUDE_DOCKER="$(INCLUDE_DOCKER)" NO_PULL="$(NO_PULL)"

bundle:
>[[ "$(VERSION)" =~ ^v[0-9]+$$ ]] || { echo "VERSION must be in the form vN, e.g. VERSION=v5" >&2; exit 1; }
>[[ "$(MODE)" =~ ^(zk|kraft|both)$$ ]] || { echo "MODE must be zk, kraft, or both" >&2; exit 1; }
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
>  if [[ "$$mode" == "zk" ]]; then
>    images=($(ZK_IMAGES))
>  else
>    images=($(KRAFT_IMAGES))
>  fi
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
>    deb_dir="$(DOCKER_OFFLINE_DIR)/$(ARCH)"
>    if [[ -d "$$deb_dir" ]] && find "$$deb_dir" -maxdepth 1 -name '*.deb' -print -quit | grep -q .; then
>      cp -r "$$deb_dir" "$$bundle_dir/docker-offline"
>    else
>      echo "docker-offline/$(ARCH) has no .deb files; run make docker-debs ARCH=$(ARCH) first" >&2
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
>  both) build_one zk; build_one kraft ;;
>esac

docker-debs:
>[[ "$(UBUNTU_VERSION)" =~ ^(jammy|noble)$$ ]] || { echo "UBUNTU_VERSION must be jammy or noble" >&2; exit 1; }
>[[ "$(ARCH)" =~ ^(amd64|arm64)$$ ]] || { echo "ARCH must be amd64 or arm64" >&2; exit 1; }
>output_dir="$(DOCKER_OFFLINE_DIR)/$(ARCH)"
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
>find "$$output_dir" -maxdepth 1 -name '*.deb' -exec du -h {} \;

save-images:
>[[ "$(ARCH)" =~ ^(amd64|arm64)$$ ]] || { echo "ARCH must be amd64 or arm64" >&2; exit 1; }
>mkdir -p "$(IMAGE_DIR)"
>save_platform=()
>if docker save --help 2>&1 | grep -q -- '--platform'; then
>  save_platform=(--platform "linux/$(ARCH)")
>fi
>for image in $(REFERENCE_IMAGES); do
>  docker pull --platform "linux/$(ARCH)" "$$image"
>  image_arch="$$(docker image inspect "$$image" --format '{{.Architecture}}')"
>  [[ "$$image_arch" == "$(ARCH)" ]] || { echo "$$image is $$image_arch, expected $(ARCH)" >&2; exit 1; }
>  name="$${image//\//__}"
>  filename="$${name//:/_}.tar"
>  docker save "$${save_platform[@]}" "$$image" -o "$(IMAGE_DIR)/$$filename"
>done

load-images:
>[[ -d "$(IMAGE_DIR)" ]] || { echo "$(IMAGE_DIR)/ directory not found" >&2; exit 1; }
>shopt -s nullglob
>tars=($(IMAGE_DIR)/*.tar)
>shopt -u nullglob
>[[ $${#tars[@]} -gt 0 ]] || { echo "No .tar files found in $(IMAGE_DIR)" >&2; exit 1; }
>for tarball in "$${tars[@]}"; do
>  docker load -i "$$tarball"
>done

clean:
>rm -rf "$(DIST_DIR)/staging"

dist-clean:
>rm -rf "$(DIST_DIR)" "$(IMAGE_DIR)" "$(DOCKER_OFFLINE_DIR)"
