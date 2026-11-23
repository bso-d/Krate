#!/usr/bin/env bash
# Shared Linux preflight and the broker's fail-closed entrypoint.
set -euo pipefail

epc_storage_error() {
  printf 'EPC storage: %s\n' "$*" >&2
  return 1
}

epc_storage_device_id() {
  local device="$1" value major minor
  [[ -b "$device" ]] || return 1
  value="$(LC_ALL=C stat -L -c '%t:%T' -- "$device")" || return 1
  [[ "$value" =~ ^([[:xdigit:]]+):([[:xdigit:]]+)$ ]] || return 1
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  printf '%d:%d\n' "0x$major" "0x$minor"
}

epc_storage_mount_row() {
  local target="$1" table="$2"
  # Linux mountinfo escapes whitespace and backslash in path fields.
  target="${target//\\/\\134}"
  target="${target// /\\040}"
  target="${target//$'\t'/\\011}"
  target="${target//$'\n'/\\012}"
  KRATE_MOUNT_TARGET="$target" awk '
    $5 == ENVIRON["KRATE_MOUNT_TARGET"] {
      count++
      for (i = 7; i <= NF; i++)
        if ($i == "-" && i + 3 == NF)
          row = $3 " " $4 " " $6 " " $(i+1) " " $(i+3)
    }
    END { if (count != 1 || row == "") exit 1; print row }
  ' "$table"
}

epc_storage_mount_check() {
  local target="$1" wanted_root="$2" wanted_device="$3" table="$4"
  local row actual_device fsroot mount_options fstype super_options
  if ! row="$(epc_storage_mount_row "$target" "$table")"; then
    epc_storage_error "$target must be an unambiguous exact mount; mount the expected disk and retry."
    return 1
  fi
  read -r actual_device fsroot mount_options fstype super_options <<< "$row"
  if [[ "$actual_device" != "$wanted_device" ]]; then
    epc_storage_error "$target device $actual_device does not match expected device $wanted_device."
    return 1
  fi
  if [[ "$fsroot" != "$wanted_root" ]]; then
    epc_storage_error "$target starts at $fsroot, not expected filesystem root $wanted_root."
    return 1
  fi
  if [[ "$fstype" != ext4 && "$fstype" != xfs ]]; then
    epc_storage_error "$target uses $fstype; only ext4 or XFS is supported for guarded EPC storage."
    return 1
  fi
  if [[ ",$mount_options," != *,rw,* || ",$super_options," != *,rw,* ]]; then
    epc_storage_error "$target is read-only; restore the expected read-write mount first."
    return 1
  fi
}

epc_storage_host() {
  local base="$1" uuid="$2" canonical device root_row
  if [[ ! "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    epc_storage_error 'set KAFKA_DATA_FS_UUID to the independently verified lowercase UUID of the intended ext4/XFS filesystem in the site .env.'
    return 1
  fi
  if [[ ! -r /proc/self/mountinfo ]]; then
    epc_storage_error 'a Linux mount namespace is required; run on the EPC host.'
    return 1
  fi
  if ! canonical="$(readlink -e -- "$base")" || [[ "$base" != "$canonical" || "$base" == / || ! -d "$base" ]]; then
    epc_storage_error "$base must be an existing canonical, non-root mountpoint."
    return 1
  fi
  if ! device="$(epc_storage_device_id "/dev/disk/by-uuid/$uuid")"; then
    epc_storage_error "expected filesystem UUID $uuid has no visible block device."
    return 1
  fi
  if ! root_row="$(epc_storage_mount_row / /proc/self/mountinfo)"; then
    epc_storage_error 'could not identify the Linux root filesystem.'
    return 1
  fi
  if [[ "${root_row%% *}" == "$device" ]]; then
    epc_storage_error "UUID $uuid is the system root filesystem, not a dedicated data filesystem."
    return 1
  fi
  epc_storage_mount_check "$base" / "$device" /proc/self/mountinfo
}

epc_storage_value() {
  local key="$1" settings="$2"
  [[ -f "$settings" ]] || return 0
  awk -v key="$key" 'index($0, key "=") == 1 { value=substr($0, length(key)+2) }
    END { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value }' "$settings" |
    sed -e "s/^'\(.*\)'$/\1/" -e 's/^"\(.*\)"$/\1/'
}

epc_storage_site() {
  local settings="$1" base uuid
  base="$(epc_storage_value KAFKA_DATA_DIR "$settings")"
  base="${base:-/data}"
  uuid="$(epc_storage_value KAFKA_DATA_FS_UUID "$settings")"
  # Compose would take an exported override ahead of the pinned site settings.
  if [[ "${KAFKA_DATA_DIR-$base}" != "$base" || "${KAFKA_DATA_FS_UUID-$uuid}" != "$uuid" ]]; then
    epc_storage_error "storage settings must match $settings, not an exported override."
    return 1
  fi
  epc_storage_host "$base" "$uuid"
}

epc_storage_broker() {
  local device node="${KAFKA_NODE_ID:-}"
  if [[ "$node" != 92 && "$node" != 93 ]]; then
    epc_storage_error 'broker node must be 92 or 93.'
    return 1
  fi
  # Only inspect metadata; no file on the data disk can attest to device identity.
  if ! device="$(epc_storage_device_id /run/krate/expected-storage-device)"; then
    epc_storage_error 'expected storage device metadata is missing; broker startup refused.'
    return 1
  fi
  epc_storage_mount_check /var/lib/kafka/data "/krate/broker-$node" "$device" /proc/self/mountinfo
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    host) [[ "$#" == 3 ]] && epc_storage_host "$2" "$3" ;;
    site) [[ "$#" == 2 ]] && epc_storage_site "$2" ;;
    broker) epc_storage_broker && exec /etc/kafka/docker/run ;;
    *) epc_storage_error 'unknown guard invocation.' ;;
  esac
fi
