#!/usr/bin/env bash
# Krate VM survey — read-only. No sudo, no packages, no files, no services.
set -uo pipefail

if [[ -t 1 ]]; then B=$'\033[1m'; R=$'\033[0m'; G=$'\033[32m'; Y=$'\033[33m'; E=$'\033[31m'; D=$'\033[2m'
else B=''; R=''; G=''; Y=''; E=''; D=''; fi

FAILS=0; WARNS=0; KV=()
ok()   { printf '  %s[ ok ]%s %s\n' "$G" "$R" "$*"; }
warn() { printf '  %s[warn]%s %s\n' "$Y" "$R" "$*"; WARNS=$((WARNS+1)); }
bad()  { printf '  %s[FAIL]%s %s\n' "$E" "$R" "$*"; FAILS=$((FAILS+1)); }
note() { printf '  %s       %s%s\n' "$D" "$*" "$R"; }
sec()  { printf '\n%s== %s ==%s\n' "$B" "$*" "$R"; }
kv()   { KV+=("$1=$2"); }
have() { command -v "$1" >/dev/null 2>&1; }
ver_gte() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
gb() { awk -v k="${1:-0}" 'BEGIN{printf "%.1f", k/1048576}'; }
freegb() { local k; k="$(df -Pk "$1" 2>/dev/null | awk 'NR==2{print $4}')"; if [[ "$k" =~ ^[0-9]+$ ]]; then gb "$k"; else echo "?"; fi; }

printf '%s──────────────────────────────────────────────────────────────%s\n' "$B" "$R"
printf '%s  Krate VM survey — %s%s\n' "$B" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$R"
printf '%s──────────────────────────────────────────────────────────────%s\n' "$B" "$R"

sec "Host"
HOST_N="$(hostname 2>/dev/null || echo unknown)"
FQDN="$(timeout 2 hostname -f 2>/dev/null || echo "$HOST_N")"
IPADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -z "$IPADDR" ]] && IPADDR="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
ok "hostname: $HOST_N"
ok "fqdn:     ${FQDN:-<none>}  ${D}(candidate for KAFKA_UI_FQDN / TLS SAN)${R}"
ok "ip:       ${IPADDR:-<none>}"
have systemd-detect-virt && ok "virtualization: $(systemd-detect-virt 2>/dev/null || echo none)"
kv HOSTNAME "$HOST_N"; kv FQDN "${FQDN:-}"; kv IP "${IPADDR:-}"

sec "Architecture"
UM="$(uname -m 2>/dev/null || echo unknown)"
case "$UM" in
  x86_64|amd64)  BARCH=amd64 ;;
  aarch64|arm64) BARCH=arm64 ;;
  *)             BARCH=UNSUPPORTED ;;
esac
ok "kernel machine (uname -m): $UM"
DARCH=""
if have dpkg; then
  DARCH="$(dpkg --print-architecture 2>/dev/null)"
  ok "userland (dpkg):          $DARCH  ${D}(this is what the Docker .debs must match)${R}"
fi
if [[ "$BARCH" == UNSUPPORTED ]]; then
  bad "'$UM' is neither amd64 nor arm64 — Krate builds bundles for those two only."
else
  ok "→ ${B}ARCH=$BARCH${R}"
fi
if [[ -n "$DARCH" && "$BARCH" != UNSUPPORTED && "$DARCH" != "$BARCH" ]]; then
  bad "kernel is $UM but userland is $DARCH — mixed userland; Docker .debs will not match."
fi
QEMU=no
for h in /proc/sys/fs/binfmt_misc/qemu-*; do [[ -e "$h" ]] && { QEMU=yes; break; }; done
if [[ "$QEMU" == yes ]]; then
  warn "qemu binfmt emulation registered — a wrong-arch bundle may appear to boot but run emulated."
  note "trust ARCH above, not a successful container start."
fi
kv UNAME_M "$UM"; kv DPKG_ARCH "${DARCH:-}"; kv BUNDLE_ARCH "$BARCH"; kv BINFMT_QEMU "$QEMU"

sec "Operating system"
OS_ID=""; OS_VER=""; CODENAME=""; PRETTY=""
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"; CODENAME="${VERSION_CODENAME:-}"; PRETTY="${PRETTY_NAME:-}"
fi
ok "${PRETTY:-unknown}"
ok "kernel: $(uname -r 2>/dev/null)"
case "$OS_ID:$CODENAME" in
  ubuntu:noble|ubuntu:jammy) ok "→ ${B}UBUNTU_VERSION=$CODENAME${R}  ${D}(selects the Docker .deb set)${R}" ;;
  ubuntu:*) bad "Ubuntu '$CODENAME' ($OS_VER) — Docker .debs are built for jammy (22.04) and noble (24.04) only." ;;
  *) bad "not Ubuntu (ID='${OS_ID:-unknown}') — the bundled Docker install path is Ubuntu-only." ;;
esac
kv OS_ID "$OS_ID"; kv OS_VERSION "$OS_VER"; kv OS_CODENAME "$CODENAME"

sec "Docker"
DV=""; DOK=no; DSARCH=""; DROOT=""; CK=none; CV=""
if have docker; then
  DV="$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [[ -n "$DV" ]] && ver_gte "$DV" 25.0.3; then ok "engine $DV (>= 25.0.3)"; else warn "engine ${DV:-unknown} — Krate requires >= 25.0.3"; fi
  if docker info >/dev/null 2>&1; then
    DOK=yes; ok "daemon reachable as $(id -un)"
    DSARCH="$(docker version --format '{{.Server.Arch}}' 2>/dev/null)"
    DROOT="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)"
    ok "server arch: ${DSARCH:-?}  ${D}(what 'kafka doctor' compares to .bundle-arch)${R}"
    [[ -n "$DSARCH" && "$DSARCH" != "$BARCH" ]] && bad "Docker says '$DSARCH', kernel implies '$BARCH' — resolve before building."
  else
    warn "docker present but daemon not reachable as $(id -un)"
  fi
else
  ok "docker not installed  ${D}(expected — the bundle will ship and install it)${R}"
fi
if docker compose version >/dev/null 2>&1; then CK=v2; CV="$(docker compose version --short 2>/dev/null | tr -d v)"
elif have docker-compose; then CK=v1; CV="$(docker-compose --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"; fi
[[ "$CK" != none ]] && ok "compose $CK $CV"

if [[ "$DOK" == yes ]] && ver_gte "${DV:-0}" 25.0.3 && ver_gte "${CV:-0}" 1.29.2; then
  INCD=0; ok "→ Docker already usable: ${B}INCLUDE_DOCKER=0${R}"
elif [[ -n "$DV" ]] && ver_gte "$DV" 25.0.3 && ver_gte "${CV:-0}" 1.29.2; then
  INCD=0; warn "→ versions fine but daemon unreachable: ${B}INCLUDE_DOCKER=0${R}"
  note "bundling .debs will NOT fix this — start the daemon / fix docker group on the VM."
else
  INCD=1; ok "→ ship Docker with the bundle: ${B}INCLUDE_DOCKER=1${R}"
fi
kv DOCKER_VERSION "${DV:-}"; kv DOCKER_DAEMON "$DOK"; kv DOCKER_SERVER_ARCH "${DSARCH:-}"
kv COMPOSE "${CK}:${CV:-}"; kv INCLUDE_DOCKER "$INCD"

sec "Prerequisites for the bundled Docker install"
for t in sudo systemctl dpkg apt-get openssl tar gzip sha256sum; do
  if have "$t"; then ok "$t"; else bad "$t missing — needed by docker-offline/install-docker.sh or the bundle"; fi
done
if have sudo; then
  if sudo -n true 2>/dev/null; then ok "passwordless sudo available"
  else note "sudo will prompt for a password during install-docker.sh (fine, just be at the terminal)"; fi
fi
kv SUDO "$(have sudo && echo yes || echo no)"
kv OPENSSL "$(have openssl && echo yes || echo no)"

sec "Capacity ${D}(advisory — repo defines no hard minimums)${R}"
CPUS="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"
MK="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
if [[ "$MK" =~ ^[0-9]+$ ]]; then MG="$(gb "$MK")"; else MG="?"; fi
if [[ "$CPUS" =~ ^[0-9]+$ ]] && (( CPUS >= 4 )); then ok "cpu cores: $CPUS"; else warn "cpu cores: $CPUS (4 brokers + UI + proxy on one host)"; fi
if [[ "$MG" == "?" ]]; then warn "memory: could not read /proc/meminfo"
elif awk -v g="$MG" 'BEGIN{exit !(g+0>=8)}'; then ok "memory: ${MG} GB"
else warn "memory: ${MG} GB (advisory: 8 GB+ for 4 brokers)"; fi
DPATH="${DROOT:-/var/lib/docker}"; [[ -d "$DPATH" ]] || DPATH=/var/lib
DDISK="$(freegb "$DPATH")"
ok "free on $DPATH: ${DDISK} GB  ${D}(Kafka volumes + ~200 MB of Docker .debs land here)${R}"
ok "free on \$HOME: $(freegb "${HOME:-/root}") GB  ${D}(bundle ~0.9 GB + extracted copy)${R}"
awk -v g="$DDISK" 'BEGIN{exit !(g+0<20)}' && warn "under 20 GB free — size log retention accordingly."
kv CPUS "$CPUS"; kv MEM_GB "$MG"; kv DISK_DOCKER_GB "$DDISK"

sec "Host ports required by the KRaft stack"
BUSY=""
if have ss || have netstat; then
  for p in 9092 9093 9094 9095 19092 19093 19094 19095 80 443; do
    if have ss; then L="$(ss -Hltn 2>/dev/null | awk '{print $4}' | sed 's/.*://')"
    else L="$(netstat -ltn 2>/dev/null | awk 'NR>2{print $4}' | sed 's/.*://')"; fi
    grep -qx "$p" <<< "$L" && BUSY="$BUSY $p"
  done
  if [[ -n "$BUSY" ]]; then
    warn "in use:$BUSY"
    case "$BUSY" in *" 80"*|*" 443"*) note "80/443 remap via: ./kafka config set KAFKA_UI_HTTP_PORT=8080 KAFKA_UI_HTTPS_PORT=8443" ;; esac
    case "$BUSY" in *909*) note "broker ports are not remappable without editing docker-compose.yml — free them." ;; esac
  else
    ok "all 10 free (9092-9095, 19092-19095, 80, 443)"
  fi
else
  warn "neither ss nor netstat — could not check ports"; BUSY=unknown
fi
kv PORTS_BUSY "${BUSY:-none}"

sec "Firewall"
FW=none
if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
  FW=firewalld
  if firewall-cmd --get-zones 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    TGT="$(firewall-cmd --info-zone=docker 2>/dev/null | awk -F': ' '/target:/{print $2}' | tr -d '[:space:]')"
    if [[ "$TGT" == ACCEPT ]]; then ok "firewalld active, docker zone ACCEPT"
    else warn "firewalld docker zone target='${TGT:-unknown}' (want ACCEPT)"; fi
  else
    warn "firewalld active with no 'docker' zone — Docker can fail: Failed to program NAT chain: INVALID_ZONE: docker"
    note "fix: firewall-cmd --permanent --new-zone=docker && firewall-cmd --permanent --zone=docker --set-target=ACCEPT && firewall-cmd --reload && systemctl restart docker"
  fi
elif have ufw; then
  U="$(systemctl is-active ufw 2>/dev/null || echo unknown)"; FW="ufw:$U"
  if [[ "$U" == active ]]; then warn "ufw active — allow 19092-19095 and 80/443 for external clients"; else ok "ufw present but $U"; fi
else
  ok "no firewalld/ufw detected"
fi
kv FIREWALL "$FW"

sec "Verdict"
if [[ "$BARCH" == UNSUPPORTED || "$OS_ID" != ubuntu ]]; then
  bad "cannot build a supported bundle for this host"
else
  printf '  On the build machine:\n\n'
  [[ "$INCD" == 1 ]] && printf '    %smake docker-debs UBUNTU_VERSION=%s ARCH=%s%s\n' "$B" "$CODENAME" "$BARCH" "$R"
  printf '    %smake bundle VERSION=<vN> MODE=kraft ARCH=%s INCLUDE_DOCKER=%s%s\n\n' "$B" "$BARCH" "$INCD" "$R"
fi
printf '  %s%d blocking, %d warnings%s\n' "$B" "$FAILS" "$WARNS" "$R"

echo ""
echo "----- MACHINE-READABLE — paste this block back -----"
printf '%s\n' "${KV[@]}"
printf 'BLOCKING=%s\nWARNINGS=%s\n' "$FAILS" "$WARNS"
echo "----- END -----"
