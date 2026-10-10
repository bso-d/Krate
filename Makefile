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
# Builder for the RHEL-family RPM set. Its distro supplies the optional/ packages
# (container-selinux, nftables and its libraries). This is the Rocky Linux project's
# own image (the Docker Official Image rockylinux:9 is no longer updated), pinned by
# digest like every other build input; its packages resolve from Rocky's current
# repositories, which follow the RHEL 9 minor releases. For a target whose
# selinux-policy is older or newer, build with that target's own distro image or let
# `krate docker-install` name the package to take from the OS media. To move the pin:
# docker buildx imagetools inspect rockylinux/rockylinux:9 (the index Digest line).
RHEL_BUILDER_IMAGE ?= rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f
INCLUDE_DOCKER ?= 0
NO_PULL ?= 0

DIST_DIR := dist
DOCKER_OFFLINE_DIR := docker-offline
CLI_FILES := zk/kafka kraft/krate epc/krate sso/activate.sh scripts/package-release.sh scripts/gate-identity.sh
VARIANT ?= kraft
SSO_APP ?= kafbat
SSO_SETTINGS ?= sso/site.json
SSO_OUTPUT ?= $(VARIANT)/auth/ui/pingfederate.yml
MONITOR_IMAGES := $(shell awk -F= '/^[A-Z0-9_]+_IMAGE=/{print $$2}' monitoring/.env.template)

# Image references are read from the runtime environment templates.
ZK_IMAGES := $(shell awk -F= '/^[A-Z0-9_]+_IMAGE=/{print $$2}' zk/.env.template)
KRAFT_IMAGES := $(shell awk -F= '/^[A-Z0-9_]+_IMAGE=/{print $$2}' kraft/.env.template)
EPC_IMAGES := $(shell awk -F= '/^[A-Z0-9_]+_IMAGE=/{print $$2}' epc/.env.template)
ZK_MONITOR_IMAGES := $(shell awk -F= '/^[A-Z0-9_]+_IMAGE=/{print $$2}' zk/monitoring/.env.template)
DOCKER_PACKAGES := containerd.io docker-ce-cli docker-ce docker-compose-plugin
# RHEL needs buildx explicitly; on Debian it arrives as a docker-ce dependency.
DOCKER_RPM_PACKAGES := containerd.io docker-ce docker-ce-cli docker-ce-rootless-extras docker-compose-plugin docker-buildx-plugin
# Base-OS dependencies a minimal or cloud host may lack go to optional/, never to
# the main set: containerd.io requires container-selinux (coupled to the host's
# selinux-policy minor version: a newer build FAILS on an older host that was fine),
# and docker-ce 29 requires nftables, which requires libnftnl and jansson (libnftnl
# in turn libmnl). `krate docker-install` and the bundled install-docker.sh add an
# optional package only when it provides a capability dnf names as missing on that
# host. Build with the default RHEL_BUILDER_IMAGE (or the target's own distro image)
# so the optional builds match the target's policy; otherwise install them from the
# OS media.
DOCKER_RPM_OPTIONAL := container-selinux nftables libnftnl jansson libmnl

.PHONY: help check test validate syntax lint compose-check bundle bundle-zk bundle-kraft bundle-epc docker-debs docker-rpms monitor-up monitor-down monitor-status monitor-logs clean dist-clean
.SILENT: help

help:
>cat <<'EOF'
>Krate offline bundle workflow
>
>Operators use ./krate in kraft/ or epc/ (start, setup, credentials, build,
>package); it runs these targets. Call them directly only for CI or the frozen
>zk edition.
>
>Targets:
>  make check                                     Run syntax, ShellCheck, Compose, offline-policy and identity validation
>  make offline-check                             Verify offline application defaults (Python 3 + Compose v2)
>  make identity-check                            Verify the identity templates, realm plan and Compose wiring (Python 3 + Compose v2)
>  make offline-smoke                             Test pinned Kafbat locally with networking disabled
>  make sso-config VARIANT=epc SSO_SETTINGS=sso/site.json
>                                                Generate opt-in SSO config (no activation)
>  make kafbat-ui ARCH=amd64                     Build native Kafbat login + SSO image (online build host)
>  make dual-config SSO_SETTINGS=sso/site.json     Generate shared Admin + SSO configuration
>  make test                                      Alias for make check
>  make validate                                  Alias for make check
>  make bundle VERSION=v2 ARCH=amd64              Build Krate and EPC bundles
>  make bundle VERSION=v5 MODE=zk ARCH=arm64      Build the archived ZooKeeper variant
>  make bundle VERSION=v5 ARCH=amd64 INCLUDE_DOCKER=1
>  make bundle VERSION=v2 MODE=epc ARCH=amd64 TARGET_OS=rhel9 INCLUDE_DOCKER=1
>  make docker-debs UBUNTU_VERSION=noble ARCH=amd64
>  make docker-rpms RHEL_VERSION=9 ARCH=amd64
>  make monitor-up VARIANT=kraft                  Start Grafana/Prometheus/Loki for a variant
>  make monitor-down VARIANT=epc
>  make clean                                     Remove bundle staging only
>  make dist-clean                                Remove dist/ and docker-offline/
>
>Variables:
>  VERSION=vN              Required for bundle targets
>  MODE=kraft|epc|both|zk  Default: both (Krate and EPC; zk is archived)
>  ARCH=amd64|arm64        Default: detected host architecture
>  UBUNTU_VERSION=jammy|noble
>                          Target Ubuntu release for docker-debs; default: noble
>  RHEL_VERSION=8|9|10     Target RHEL release for docker-rpms; default: 9
>  TARGET_OS=noble|jammy|rhel9
>                          Which prepared package set INCLUDE_DOCKER=1 ships
>  NO_PULL=1               Reuse local Docker images; they must match ARCH
>  INCLUDE_DOCKER=1        Copy Docker packages prepared for the target Ubuntu/ARCH
>  VARIANT=kraft|epc       Which cluster the monitor-* targets act on
>EOF

.PHONY: offline-check identity-check
.PHONY: sso-config
.PHONY: dual-config kafbat-ui

kafbat-ui:
>python3 kafbat-ui/build.py --arch "$(ARCH)"

dual-config:
>python3 sso/configure-dual.py --settings "$(SSO_SETTINGS)" --output-dir "$(VARIANT)/auth"

sso-config:
>python3 sso/configure.py --app "$(SSO_APP)" --settings "$(SSO_SETTINGS)" --output "$(SSO_OUTPUT)"

check: syntax lint compose-check offline-check identity-check

offline-check:
>python3 scripts/check-offline.py

identity-check:
>python3 scripts/check-identity.py

offline-smoke: offline-check
>bash

test validate: check

syntax:
>for file in $(CLI_FILES); do bash -n "$$file"; done

lint:
>shellcheck $(CLI_FILES)

compose-check:
>for template in zk/.env.template kraft/.env.template epc/.env.template monitoring/.env.template zk/monitoring/.env.template; do
>  while IFS='=' read -r key image; do
>    [[ "$$key" == *_IMAGE ]] || continue
>    [[ "$$image" =~ @sha256:[a-f0-9]{64}$$ ]] || { echo "Image must be digest-pinned: $$key=$$image" >&2; exit 1; }
>  done < "$$template"
>done
>docker compose --env-file zk/.env.template -f zk/docker-compose.yml config --quiet
>docker compose --env-file kraft/.env.template -f kraft/docker-compose.yml config --quiet
>docker compose --env-file epc/.env.template -f epc/docker-compose.yml config --quiet
>docker compose --env-file monitoring/.env.template -f monitoring/docker-compose.yml config --quiet
>KAFKA_NETWORK=zk-validation-network docker compose --env-file zk/monitoring/.env.template -f zk/monitoring/docker-compose.yml config --quiet

bundle-zk:
>$(MAKE) bundle MODE=zk VERSION="$(VERSION)" ARCH="$(ARCH)" INCLUDE_DOCKER="$(INCLUDE_DOCKER)" NO_PULL="$(NO_PULL)"

bundle-kraft:
>$(MAKE) bundle MODE=kraft VERSION="$(VERSION)" ARCH="$(ARCH)" INCLUDE_DOCKER="$(INCLUDE_DOCKER)" NO_PULL="$(NO_PULL)"

bundle-epc:
>$(MAKE) bundle MODE=epc VERSION="$(VERSION)" ARCH="$(ARCH)" TARGET_OS="$(TARGET_OS)" INCLUDE_DOCKER="$(INCLUDE_DOCKER)" NO_PULL="$(NO_PULL)"

bundle: offline-check
>[[ "$(VERSION)" =~ ^v[0-9]+$$ ]] || { echo "VERSION must be in the form vN, e.g. VERSION=v5" >&2; exit 1; }
>[[ "$(MODE)" =~ ^(zk|kraft|epc|both)$$ ]] || { echo "MODE must be zk, kraft, epc, or both" >&2; exit 1; }
>[[ "$(ARCH)" =~ ^(amd64|arm64)$$ ]] || { echo "ARCH must be amd64 or arm64" >&2; exit 1; }
>if [[ "$(MODE)" == both ]] && [[ "$(INCLUDE_DOCKER)" =~ ^(1|true|yes|on)$$ ]]; then
>  echo "Build Krate and EPC separately when INCLUDE_DOCKER=1; they need different OS packages." >&2
>  exit 1
>fi
>
>enabled() { [[ "$$1" =~ ^(1|true|yes|on)$$ ]]; }
>image_filename() {
>  local image="$$1" name
>  name="$${image//\//__}"
>  printf '%s.tar\n' "$${name//:/_}"
>}
># The Kafbat UI image is built locally and pinned as name@<image ID>. It has
># no registry digest, and the classic Docker image store only resolves
># name@digest against registry digests, so look local builds up by image ID.
>local_ref() {
>  local image="$$1"
>  if [[ "$$image" == krate/kafka-ui:1.5.0-sso.*@sha256:* ]]; then
>    printf '%s\n' "$${image##*@}"
>  else
>    printf '%s\n' "$$image"
>  fi
>}
>inspect_platform=()
>if docker image inspect --help 2>&1 | grep -q -- '--platform'; then
>  inspect_platform=(--platform "linux/$(ARCH)")
>fi
>save_platform=()
>if docker save --help 2>&1 | grep -q -- '--platform'; then
>  save_platform=(--platform "linux/$(ARCH)")
>fi
>
>build_one() {
>  local mode="$$1"
>  # The frozen ZooKeeper edition keeps its published kafka-* naming; everything
>  # else is Krate.
>  local bundle_name="krate-$${mode}-$(VERSION)-$(ARCH)"
>  if [[ "$$mode" == "zk" ]]; then
>    bundle_name="kafka-zk-$(VERSION)-$(ARCH)"
>  fi
>  local bundle_dir="$(DIST_DIR)/staging/$${bundle_name}"
>  local out_file="$(DIST_DIR)/$${bundle_name}.tar.gz"
>  local src_dir="$$mode"
>  local -a images
>
>  case "$$mode" in
>    zk)    images=($(ZK_IMAGES) $(ZK_MONITOR_IMAGES)) ;;
>    epc)   images=($(EPC_IMAGES) $(MONITOR_IMAGES)) ;;
>    *)     images=($(KRAFT_IMAGES) $(MONITOR_IMAGES)) ;;
>  esac
>
>  for image in "$${images[@]}"; do
>    [[ "$$image" =~ @sha256:[a-f0-9]{64}$$ ]] || { echo "Bundle image must be digest-pinned: $$image" >&2; exit 1; }
>  done
>
>  echo "==> Building bundle: $$bundle_name"
>  rm -rf "$$bundle_dir"
>  mkdir -p "$$bundle_dir/images"
>
>  if enabled "$(NO_PULL)"; then
>    echo "==> Verifying local images match $(ARCH)"
>    for image in "$${images[@]}"; do
>      image_arch="$$(docker image inspect "$${inspect_platform[@]}" "$$(local_ref "$$image")" --format '{{.Architecture}}' 2>/dev/null || true)"
>      [[ -n "$$image_arch" ]] || { echo "Image not found locally: $$image" >&2; exit 1; }
>      [[ "$$image_arch" == "$(ARCH)" ]] || { echo "$$image is $$image_arch, expected $(ARCH)" >&2; exit 1; }
>      echo "  ok $$image ($$image_arch)"
>    done
>  else
>    echo "==> Pulling $(ARCH) images"
>    for image in "$${images[@]}"; do
>      if [[ "$$image" == krate/kafka-ui:1.5.0-sso.*@sha256:* ]]; then
>        image_arch="$$(docker image inspect "$$(local_ref "$$image")" --format '{{.Architecture}}' 2>/dev/null || true)"
>        [[ "$$image_arch" == "$(ARCH)" ]] || { echo "Build the UI first: make kafbat-ui ARCH=$(ARCH)" >&2; exit 1; }
>      else
>        docker pull --platform "linux/$(ARCH)" "$$image"
>      fi
>    done
>  fi
>
>  echo "==> Saving images"
>  printf 'source_reference\truntime_reference\timage_id\trepo_digests\tarchive\tarchive_sha256\tplatform\n' > "$$bundle_dir/images.lock.tsv"
>  for image in "$${images[@]}"; do
>    ref="$$(local_ref "$$image")"
>    image_id="$$(docker image inspect "$${inspect_platform[@]}" "$$ref" --format '{{.Id}}')"
>    image_arch="$$(docker image inspect "$${inspect_platform[@]}" "$$ref" --format '{{.Architecture}}')"
>    [[ "$$image_arch" == "$(ARCH)" ]] || { echo "$$image is $$image_arch, expected $(ARCH)" >&2; exit 1; }
>    # Archive tags contain the image ID; loaded archives retain these tags.
>    runtime_image="krate-offline/image:sha256-$${image_id#sha256:}"
>    docker tag "$$ref" "$$runtime_image"
>    filename="$$(image_filename "$$image")"
>    docker save "$${save_platform[@]}" "$$runtime_image" -o "$$bundle_dir/images/$$filename"
>    repo_digests="$$(docker image inspect "$${inspect_platform[@]}" "$$ref" --format '{{json .RepoDigests}}')"
>    if command -v sha256sum >/dev/null 2>&1; then
>      archive_sha="$$(sha256sum "$$bundle_dir/images/$$filename" | awk '{print $$1}')"
>    else
>      archive_sha="$$(shasum -a 256 "$$bundle_dir/images/$$filename" | awk '{print $$1}')"
>    fi
>    printf '%s\t%s\t%s\t%s\timages/%s\t%s\tlinux/%s\n' "$$image" "$$runtime_image" "$$image_id" "$$repo_digests" "$$filename" "$$archive_sha" "$(ARCH)" >> "$$bundle_dir/images.lock.tsv"
>  done
>
>  cp "$$src_dir/docker-compose.yml" "$$bundle_dir/docker-compose.yml"
>  if [[ "$$mode" == "epc" ]]; then
>    cp "$$src_dir/kafbat.yml" "$$bundle_dir/kafbat.yml"
>  fi
>  cp "$$src_dir/nginx.conf" "$$bundle_dir/nginx.conf"
>  # Krate's AGPL licence, and where the image components' corresponding source is
>  # published, including the components it could not be obtained for.
>  cp LICENSE LICENSE-SOURCES.md "$$bundle_dir/"
>  if [[ "$$mode" != "zk" ]]; then
>    mkdir -p "$$bundle_dir/auth/ui" "$$bundle_dir/auth/keycloak/truststores" "$$bundle_dir/sso/logrotate" "$$bundle_dir/docs"
>    cp "$$src_dir/auth/ui/local.yml" "$$bundle_dir/auth/ui/local.yml"
>    cp sso/configure.py sso/example.json sso/configure-dual.py sso/dual-example.json sso/activate.sh sso/preflight.py sso/probe.py sso/identity.py "$$bundle_dir/sso/"
>    # Rendered by `krate identity logrotate` with the installation's journal path.
>    cp sso/logrotate/krate-identity.conf "$$bundle_dir/sso/logrotate/"
>    cp sso/guides/identity-foundation.md sso/guides/dual-login.md sso/guides/pingfederate-sso.md sso/guides/pingfederate-iam-guide.md sso/guides/sso-flows.md sso/guides/perses-sso.md "$$bundle_dir/docs/"
>  fi
>  # The CLI ships as ./krate everywhere except the frozen ZooKeeper edition,
>  # whose published v5 bundle documents ./kafka.
>  local cli_name="krate"
>  if [[ "$$mode" == "zk" ]]; then
>    cli_name="kafka"
>  fi
>  cp "$$src_dir/$$cli_name" "$$bundle_dir/$$cli_name"
>  chmod +x "$$bundle_dir/$$cli_name"
>
>  # The observability stack is shared, so it is copied in rather than duplicated
>  # per variant. The frozen ZooKeeper edition is skipped.
>  if [[ "$$mode" != "zk" && -d monitoring ]]; then
>    mkdir -p "$$bundle_dir/monitoring"
>    cp monitoring/docker-compose.yml monitoring/.env.template monitoring/seed-alerting.py monitoring/render.py "$$bundle_dir/monitoring/"
>    cp monitoring/README.md "$$bundle_dir/monitoring/"
>    cp -r monitoring/grafana monitoring/loki monitoring/prometheus monitoring/fluent-bit monitoring/perses "$$bundle_dir/monitoring/"
>    # Local test runs leave Python bytecode beside discovery.py; never ship it.
>    find "$$bundle_dir/monitoring" -name __pycache__ -type d -prune -exec rm -rf {} +
>    # Only the local default is copied: never stage site auth files or secrets.
>    mkdir -p "$$bundle_dir/monitoring/auth"
>    cp monitoring/auth/local.ini "$$bundle_dir/monitoring/auth/local.ini"
>  fi
>  cp "$$src_dir/.env.template" "$$bundle_dir/.env.template"
>  printf '%s\n' "$(ARCH)" > "$$bundle_dir/.bundle-arch"
>
>  # zk bundles ship the observability stack (kafka monitor up)
>  if [[ "$$mode" == "zk" && -d "$$src_dir/monitoring" ]]; then
>    cp -r "$$src_dir/monitoring" "$$bundle_dir/monitoring"
>    rm -f "$$bundle_dir/monitoring/.env"
>  fi
>
>  # Environment templates select the tagged images stored in the archives.
>  for env_template in "$$bundle_dir/.env.template" "$$bundle_dir/monitoring/.env.template"; do
>    awk -F '\t' 'NR==FNR { runtime[$$1]=$$2; next } /^[A-Z0-9_]+_IMAGE=/ { split($$0, entry, "="); if (entry[2] in runtime) $$0=entry[1] "=" runtime[entry[2]] } { print }' "$$bundle_dir/images.lock.tsv" "$$env_template" > "$$env_template.tmp"
>    mv "$$env_template.tmp" "$$env_template"
>  done
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
>  if [[ "$$mode" != "zk" ]]; then
>    python3 scripts/check-bundle.py "$$bundle_dir"
>  fi
>  mkdir -p "$(DIST_DIR)"
>
>  # Strip macOS/Docker-Desktop extended attributes before archiving. Files copied
>  # on macOS carry com.apple.provenance, and anything a builder container wrote
>  # through a bind mount carries com.docker.grpcfuse.ownership. bsdtar stores
>  # those as LIBARCHIVE.xattr.* PAX headers, which GNU tar on the target VM then
>  # reports as "Ignoring unknown extended header keyword" for every file.
>  # COPYFILE_DISABLE only suppresses AppleDouble ._* files, not xattrs.
>  if command -v xattr >/dev/null 2>&1; then
>    xattr -cr "$$bundle_dir" 2>/dev/null || true
>  fi
>  tar_opts=()
>  for opt in --no-xattrs --no-mac-metadata; do
>    if tar "$$opt" -cf /dev/null -T /dev/null >/dev/null 2>&1; then
>      tar_opts+=("$$opt")
>    fi
>  done
>  local release_dir cleanup_command
>  release_dir="$$(mktemp -d "$(DIST_DIR)/.$${bundle_name}.release.XXXXXX")"
>  printf -v cleanup_command 'rm -rf -- %q' "$$release_dir"
>  trap "$$cleanup_command" EXIT
>  COPYFILE_DISABLE=1 tar "$${tar_opts[@]}" -czf "$$release_dir/$${bundle_name}.tar.gz" -C "$(DIST_DIR)/staging" "$$bundle_name"
>  cp "$$bundle_dir/images.lock.tsv" "$$release_dir/$${bundle_name}.tar.gz.images.lock.tsv"
>
>  if command -v sha256sum >/dev/null 2>&1; then
>    ( cd "$$release_dir" && sha256sum "$${bundle_name}.tar.gz" ) > "$$release_dir/$${bundle_name}.tar.gz.sha256"
>  elif command -v shasum >/dev/null 2>&1; then
>    ( cd "$$release_dir" && shasum -a 256 "$${bundle_name}.tar.gz" ) > "$$release_dir/$${bundle_name}.tar.gz.sha256"
>  else
>    echo "No sha256sum or shasum found; bundle not published" >&2
>    exit 1
>  fi
>
>  # Release paths receive the staged archive, lock manifest and checksum.
>  for suffix in "" .images.lock.tsv .sha256; do
>    mv "$$release_dir/$${bundle_name}.tar.gz$$suffix" "$$out_file$$suffix"
>  done
>  rm -rf "$$release_dir" "$$bundle_dir"
>  trap - EXIT
>
>  echo "==> Wrote $$out_file"
>}
>
>mkdir -p "$(DIST_DIR)/staging"
>case "$(MODE)" in
>  zk) build_one zk ;;
>  kraft) build_one kraft ;;
>  epc) build_one epc ;;
>  both) build_one kraft; build_one epc ;;
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
># The main set is exactly the Docker CE packages; optional/ carries the base-OS
># dependencies a minimal host may lack, so the set installs with
># dnf --disablerepo='*' on an air-gapped VM (see DOCKER_RPM_OPTIONAL).
>docker run --rm --platform "linux/$(ARCH)" \
>  -e BASEURL="https://download.docker.com/linux/rhel/$(RHEL_VERSION)/$$rpm_arch/stable" \
>  -e PKGS="$(DOCKER_RPM_PACKAGES)" \
>  -e OPTIONAL="$(DOCKER_RPM_OPTIONAL)" \
>  -v "$$(pwd)/$$output_dir:/output" \
>  "$(RHEL_BUILDER_IMAGE)" bash -c '
>    set -euo pipefail
>    printf "[docker-ce-stable]\nname=Docker CE Stable\nbaseurl=%s\nenabled=1\ngpgcheck=1\ngpgkey=https://download.docker.com/linux/rhel/gpg\n" "$$BASEURL" > /etc/yum.repos.d/docker-ce.repo
>    dnf install -y -q dnf-plugins-core
>    # Make the builder resemble a real RHEL host before resolving. The builder
>    # image is minimal, so without this dnf treats base OS packages as missing
>    # and downloads the builder distro'"'"'s builds of selinux-policy,
>    # policycoreutils, iptables and friends — which would replace Red Hat'"'"'s own
>    # packages on the target VM, at a different minor version. A RHEL host
>    # already has these.
>    dnf install -y -q policycoreutils selinux-policy-targeted iptables-nft nftables diffutils
>    # No --resolve on the main set: take exactly the named Docker packages, so
>    # the bundle can never carry a base OS package built by another distro.
>    dnf download --destdir /output $$PKGS
>    mkdir -p /output/optional
>    dnf download --destdir /output/optional $$OPTIONAL
>    chmod 0644 /output/*.rpm
>  '
>
>cat > "$$output_dir/install-docker.sh" <<'INSTALL_RPM'
>#!/usr/bin/env bash
># Install Docker CE from the bundled RPM packages (RHEL family).
>#
># Strictly offline: --disablerepo='*' means every dependency must already be on
># the host or in this directory. It fails loudly rather than silently reaching
># for a network repo an air-gapped VM does not have.
>#
># Usage: ./install-docker.sh [--yes]
>set -euo pipefail
>
>SCRIPT_DIR="$$(cd "$$(dirname "$${BASH_SOURCE[0]}")" && pwd)"
>
>ASSUME_YES=0
>if [[ "$${1:-}" == "--yes" || "$${1:-}" == "-y" ]]; then
>  ASSUME_YES=1
>fi
>
>installer=dnf
>command -v dnf >/dev/null 2>&1 || installer=yum
>
>run() {
>  if [[ "$$(id -u)" -eq 0 ]]; then "$$@"; else sudo "$$@"; fi
>}
>
># ── Conflicts ────────────────────────────────────────────────────────────────
># podman-docker ships /usr/bin/docker and conflicts with docker-ce-cli. Removing
># it does NOT remove podman — only the docker CLI alias. The rest are the legacy
># docker packages Red Hat shipped before RHEL 9.
>conflicts=()
>for p in podman-docker docker docker-engine docker-client docker-client-latest \
>         docker-common docker-latest docker-latest-logrotate docker-logrotate \
>         docker-engine-selinux runc-docker; do
>  if rpm -q "$$p" >/dev/null 2>&1; then
>    conflicts+=("$$p")
>  fi
>done
>
>if [[ $${#conflicts[@]} -gt 0 ]]; then
>  echo ""
>  echo "These installed packages conflict with Docker CE and will be REMOVED:"
>  printf '  %s\n' "$${conflicts[@]}"
>  echo ""
>  echo "podman and runc themselves are not affected."
>  if [[ "$$ASSUME_YES" -ne 1 ]]; then
>    if [[ -t 0 ]]; then
>      read -r -p "Proceed? [y/N] " ans
>      if [[ ! "$$ans" =~ ^[Yy]$$ ]]; then
>        echo "Aborted. Re-run with --yes to skip this prompt."
>        exit 1
>      fi
>    else
>      echo "Not a terminal and --yes was not given; refusing to remove packages."
>      exit 1
>    fi
>  fi
>fi
>
># ── Install ──────────────────────────────────────────────────────────────────
>shopt -s nullglob
>pkgs=("$$SCRIPT_DIR"/*.rpm)
>optional=("$$SCRIPT_DIR"/optional/*.rpm)
>shopt -u nullglob
>
>if [[ $${#pkgs[@]} -eq 0 ]]; then
>  echo "No .rpm files in $$SCRIPT_DIR" >&2
>  exit 1
>fi
>
># dnf names what the host lacks ("nothing provides <capability> needed by
># <package>"). Only the optional/ packages that provide a named capability are
># added, round by round (an added package can name its own missing dependency),
># so a host that already has them never gets another distro's build. Same
># selection as `krate docker-install` (epc/krate); the two functions below are
># kept identical to its copies (scripts/check-identity.py compares them).
>rpm_missing_capabilities() {
>  sed -n 's/.*nothing provides \([^ ]*\).*/\1/p' "$$1" | sort -u
>}
>
>rpm_providers_of() {
>  local need="$$1" file listing
>  shift
>  for file in "$$@"; do
>    if [[ "$$need" == /* ]]; then
>      listing="$$(rpm -qpl "$$file" 2>/dev/null)" || continue
>    else
>      listing="$$(rpm -qp --provides "$$file" 2>/dev/null | awk '{print $$1}')" || continue
>    fi
>    if [[ $$'\n'"$$listing"$$'\n' == *$$'\n'"$$need"$$'\n'* ]]; then echo "$$file"; fi
>  done
>}
>
>echo "==> Installing Docker CE from $${#pkgs[@]} bundled packages..."
>attempt_log="$$(mktemp)"
>wanted=()
>missing=()
>unresolved=()
>installed=0
>for round in 0 1 2 3; do
>  rc=0
>  # stderr goes to the file and is printed after dnf has exited, so the file is
>  # complete when it is read.
>  run "$$installer" install -y --allowerasing --disablerepo='*' "$${pkgs[@]}" "$${wanted[@]}" 2>"$$attempt_log" || rc=$$?
>  cat "$$attempt_log" >&2
>  if [[ "$$rc" -eq 0 ]]; then
>    installed=1
>    break
>  fi
>  [[ "$$round" -lt 3 ]] || break
>  mapfile -t missing < <(rpm_missing_capabilities "$$attempt_log")
>  added=()
>  unresolved=()
>  for need in "$${missing[@]}"; do
>    mapfile -t providers < <(rpm_providers_of "$$need" "$${optional[@]}")
>    if [[ $${#providers[@]} -eq 0 ]]; then
>      unresolved+=("$$need")
>      continue
>    fi
>    for file in "$${providers[@]}"; do
>      [[ " $${wanted[*]} $${added[*]} " == *" $$file "* ]] || added+=("$$file")
>    done
>  done
>  [[ $${#added[@]} -gt 0 ]] || break
>  echo ""
>  echo "==> Adding the bundled dependencies this host lacks: $${added[*]##*/}"
>  wanted+=("$${added[@]}")
>done
>rm -f "$$attempt_log"
>if [[ "$$installed" -ne 1 ]]; then
>  if [[ $${#wanted[@]} -eq 0 ]]; then
>    echo "Offline install failed: this host lacks $${missing[*]:-a dependency dnf did not name}, and the bundle has no package for it." >&2
>  else
>    echo "Offline install failed even with the bundled dependencies ($${wanted[*]##*/})$${unresolved[*]:+; no bundled package provides $${unresolved[*]}}." >&2
>  fi
>  echo "Install it from your RHEL media or Satellite (container-selinux must match this host's selinux-policy build), then re-run." >&2
>  exit 1
>fi
>
># ── Service + group ──────────────────────────────────────────────────────────
>echo ""
>echo "==> Enabling Docker service..."
>run systemctl enable --now docker
>
>target_user="$${SUDO_USER:-$${USER:-$$(id -un)}}"
>if [[ -n "$$target_user" && "$$target_user" != "root" ]]; then
>  if ! id -nG "$$target_user" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
>    run usermod -aG docker "$$target_user"
>    echo "Added $$target_user to the docker group. Run 'newgrp docker' or log out and back in."
>  fi
>fi
>
>echo ""
>docker --version
>docker compose version
>echo ""
>echo "Docker installed. Next: ./krate doctor"
>INSTALL_RPM
>chmod +x "$$output_dir/install-docker.sh"
>
>{
>  echo "OS_TARGET=rhel$(RHEL_VERSION)"
>  echo "OS_FAMILY=rhel"
>  echo "ARCH=$(ARCH)"
>  echo "PREPARED=$$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
>  for pkg in "$$output_dir"/*.rpm; do echo "PACKAGE=$$(basename "$$pkg")"; done
>  for pkg in "$$output_dir"/optional/*.rpm; do echo "OPTIONAL=$$(basename "$$pkg")"; done
>} > "$$output_dir/.docker-manifest"
>echo "==> Prepared Docker CE for rhel$(RHEL_VERSION)/$(ARCH):"
>sed 's/^/    /' "$$output_dir/.docker-manifest"
>du -sh "$$output_dir"

monitor-up monitor-down monitor-status monitor-logs:
>[[ "$(VARIANT)" =~ ^(kraft|epc)$$ ]] || { echo "VARIANT must be kraft or epc" >&2; exit 1; }
>cd "$(VARIANT)" && ./krate monitor "$(subst monitor-,,$@)"

clean:
>rm -rf "$(DIST_DIR)/staging"

dist-clean:
>rm -rf "$(DIST_DIR)" "$(DOCKER_OFFLINE_DIR)"

# Corresponding source for the copyleft components in a package's container images
# (see LICENSE-SOURCES.md). Uses the package's images.lock.tsv when it has been built,
# otherwise the digest-pinned images in the edition's .env.template files.
#   make sources MODE=kraft ARCH=amd64 VERSION=v1
.PHONY: sources
sources:
>[[ "$(VERSION)" =~ ^v[0-9]+$$ ]] || { echo "VERSION must be in the form vN, e.g. VERSION=v1" >&2; exit 1; }
>[[ "$(MODE)" =~ ^(zk|kraft|epc)$$ ]] || { echo "MODE must be kraft, epc or zk" >&2; exit 1; }
>[[ "$(ARCH)" =~ ^(amd64|arm64)$$ ]] || { echo "ARCH must be amd64 or arm64" >&2; exit 1; }
>bundle_name="krate-$(MODE)-$(VERSION)-$(ARCH)"
>[[ "$(MODE)" != zk ]] || bundle_name="kafka-zk-$(VERSION)-$(ARCH)"
>input=(--templates --arch "$(ARCH)")
>for lock in "$(DIST_DIR)/$${bundle_name}.tar.gz.images.lock.tsv" \
>            "$(DIST_DIR)/release/package-$(MODE)-$(VERSION)/$${bundle_name}.tar.gz.images.lock.tsv"; do
>  if [[ -f "$$lock" ]]; then input=(--lock "$$lock"); break; fi
>done
>echo "==> Collecting corresponding source for $${bundle_name} ($${input[*]})"
>python3 scripts/collect-sources.py --edition "$(MODE)" "$${input[@]}" \
>  --out "$(DIST_DIR)/sources/$${bundle_name}" --archive "$(DIST_DIR)/$${bundle_name}-sources.tar"
