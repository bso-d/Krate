#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/epc/storage-guard.sh"
failure() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
working="$(mktemp -d)"
fixture="$working/mountinfo"
trap 'rm -r -- "$working"' EXIT
run() {
  local label="$1" mount="$2" fsroot="$3" device="$4" expected="$5" output status=0
  output="$(epc_storage_mount_check "$mount" "$fsroot" "$device" "$fixture" 2>&1)" || status=$?
  if [[ "$expected" = pass ]]; then
    [[ "$status" = 0 ]] || failure "$label rc=$status: $output"
  else
    [[ "$status" != 0 && "$output" = *"$expected"* ]] || failure "$label rc=$status: $output"
  fi
  printf 'PASS %-25s %s\n' "$label" "$output"
}
cat > "$fixture" <<'END'
10 8 8:1 / / rw,relatime - ext4 /dev/vda1 rw
11 10 8:16 / /data rw,relatime - ext4 /dev/vdb rw
12 10 8:16 /krate/broker-92 /var/lib/kafka/data rw,relatime - ext4 /dev/vdb rw
13 10 8:16 / /bad-fs rw - btrfs /dev/vdb rw
14 10 8:16 / /read-only ro - ext4 /dev/vdb ro
15 10 8:16 / /readonly-super rw - ext4 /dev/vdb ro
16 10 8:16 / /stacked rw - xfs /dev/vdb rw
17 16 8:17 / /stacked rw - xfs /dev/vdc rw
18 10 8:1 /stale/krate/broker-92 /bad-data rw - ext4 /dev/vda1 rw
19 10 8:16 / /xfs rw - xfs /dev/vdb rw
20 10 8:16 / /data\040disk rw - ext4 /dev/vdb rw
END
run 'right mounted disk' /data / 8:16 pass
run 'absent mount' /unmounted-data / 8:16 'exact mount'
run 'different device' /data / 8:17 'expected device'
run 'whole disk required' /var/lib/kafka/data / 8:16 'expected filesystem root'
run 'broker bind correct' /var/lib/kafka/data /krate/broker-92 8:16 pass
run 'broker bind wrong peer' /var/lib/kafka/data /krate/broker-93 8:16 'expected filesystem root'
run 'bad fs' /bad-fs / 8:16 'ext4 or XFS'
run 'read-only mount' /read-only / 8:16 'read-only'
run 'read-only superblock' /readonly-super / 8:16 'read-only'
run 'stacked mount' /stacked / 8:16 'exact mount'
run 'stale root fallback' /bad-data /krate/broker-92 8:16 'expected device'
run 'xfs compatible' /xfs / 8:16 pass
run 'escaped mount path' '/data disk' / 8:16 pass

epc_storage_no_child_mounts /var/lib/kafka/data "$fixture" no
cat >> "$fixture" <<'END'
21 12 8:1 / /var/lib/kafka/data/topic-0 rw - ext4 /dev/vda1 rw
22 11 8:16 /elsewhere /data/krate/broker-92/override rw - ext4 /dev/vdb rw
END
if epc_storage_no_child_mounts /var/lib/kafka/data "$fixture" no; then
  failure 'root filesystem nested below broker bind'
fi
if epc_storage_no_child_mounts /data/krate "$fixture"; then
  failure 'same-filesystem submount nested in host broker tree'
fi
printf 'PASS %s\n' 'reject mounted child paths on host and in broker'

printf '%s\n' 'KAFKA_DATA_DIR=/data' 'KAFKA_DATA_FS_UUID=00000000-1111-2222-3333-444444444444' > "$fixture"
[[ "$(epc_storage_value KAFKA_DATA_DIR "$fixture")" == /data ]]
if message="$(KAFKA_DATA_DIR=/ bash "$root/epc/storage-guard.sh" site "$fixture" 2>&1)" ||
   [[ "$message" != *'not an exported override'* ]]; then
  failure 'ambient Compose override not rejected'
fi
printf '%s\n' 'export KAFKA_DATA_DIR=/' >> "$fixture"
if epc_storage_value KAFKA_DATA_DIR "$fixture"; then failure 'dotenv export shadowed canonical value'; fi
printf '%s\n' 'KAFKA_DATA_DIR=/data' 'KAFKA_DATA_DIR=/elsewhere' > "$fixture"
if epc_storage_value KAFKA_DATA_DIR "$fixture"; then failure 'duplicate dotenv assignment accepted'; fi
printf '%s\n' "KAFKA_DATA_DIR=/data/\$PATH" > "$fixture"
if epc_storage_value KAFKA_DATA_DIR "$fixture"; then failure 'interpolated storage path accepted'; fi
printf 'PASS %s\n' 'reject ambiguous dotenv storage pins and ambient overrides'

mkdir -p "$working/sys/vdb1"
printf '%s\n' '253:17' > "$working/sys/vdb1/dev"
printf '%s\n' '31 30 0:6 /vdb1 /run/krate/expected-storage-device ro,nosuid - devtmpfs devtmpfs rw' > "$fixture"
[[ "$(epc_storage_broker_device_id "$fixture" "$working/sys")" == 253:17 ]]
printf '%s\n' '31 30 0:6 /vdb1 /run/krate/expected-storage-device rw,nosuid - devtmpfs devtmpfs rw' > "$fixture"
if epc_storage_broker_device_id "$fixture" "$working/sys"; then failure 'accepted writable expected metadata bind'; fi
printf '%s\n' '31 30 0:6 /vdb1 /run/krate/expected-storage-device ro - ext4 disk rw' > "$fixture"
if epc_storage_broker_device_id "$fixture" "$working/sys"; then failure 'accepted fake expected metadata on ordinary disk'; fi
printf 'PASS %s\n' 'source expected device number from read-only devtmpfs bind and Linux sysfs'

mkdir -p "$working/auth/certs"
if epc_storage_broker_config "$working/auth" local; then failure 'empty auth bind accepted'; fi
printf '%s\n' 'local fixture' > "$working/auth/server.properties"
epc_storage_broker_config "$working/auth" local
if epc_storage_broker_config "$working/auth" oauth_ssl; then failure 'OAuth bind with missing broker keystore accepted'; fi
printf '%s\n' 'keystore fixture' > "$working/auth/certs/broker.p12"
epc_storage_broker_config "$working/auth" oauth_ssl
if epc_storage_broker_config "$working/auth" invalid; then failure 'unknown broker auth mode accepted'; fi
printf 'PASS %s\n' 'start fails closed if legacy relabel bind has no required auth config'

# Drive the actual restart dispatch with simulated daemon container metadata.
restart_driver="$working/restart-driver.sh"
{
  cat <<'DRIVER'
set -euo pipefail
err() { printf '%s\n' "$*" >&2; }
bash() {
  [[ "$1" == */storage-guard.sh && "$2" == pins ]] || exit 2
  printf '/new-data\t%s\n' "$wanted_uuid"
}
docker() {
  [[ "$1" == inspect && "${*: -1}" == epc-broker-* ]] || exit 2
  inspected="${*: -1}"
  printf '%s\n' "$inspected" >> "$trace"
  [[ "$fixture_case" != inspect_error ]] || return 1
  local node="${inspected##*-}" data="/new-data" uuid="$wanted_uuid" read_only=true
  [[ "$fixture_case" != old_path || "$node" != 92 ]] || data=/data
  [[ "$fixture_case" != old_uuid || "$node" != 93 ]] || uuid=00000000-0000-0000-0000-000000000000
  [[ "$fixture_case" != mutable_device || "$node" != 92 ]] || read_only=false
  local project=krate-epc
  [[ "$fixture_case" != wrong_project ]] || project=other-project
  printf '%s\tkafka-%s\n' "$project" "$node"
  printf '/var/lib/kafka/data\tbind\t%s/krate/broker-%s\tfalse\n' "$data" "$node"
  [[ "$fixture_case" != missing_device ]] || return 0
  printf '/run/krate/expected-storage-device\tbind\t/dev/disk/by-uuid/%s\t%s\n' "$uuid" "$read_only"
}
cluster_project() { printf 'krate-epc\n'; }
sso_dir() { :; }
sync_image_pins() { :; }
resolve_local_ui_image() { :; }
compose_passthrough() { printf 'compose %s\n' "${*: -1}" >> "$trace"; }
COMPOSE_BIN=(compose_passthrough)
SCRIPT_DIR=/fake ENV_FILE=/nonexistent ENV_TEMPLATE=unused COMPOSE_FILE=unused
wanted_uuid=10000000-1111-2222-3333-444444444444
fixture_case="$1" trace="$2"
shift 2
DRIVER
  sed -n '/^epc_require_restart_storage() {$/,/^}$/p; /^compose_cmd() {$/,/^}$/p' "$root/epc/krate"
  printf '%s\n' 'compose_cmd restart "$@"'
} > "$restart_driver"
for fixture_case in old_path old_uuid inspect_error missing_device mutable_device wrong_project unchanged; do
  trace="$working/restart-trace"
  : > "$trace"
  status=0
  output="$(bash "$restart_driver" "$fixture_case" "$trace" 2>&1)" || status=$?
  if [[ "$fixture_case" == unchanged ]]; then
    [[ "$status" == 0 && "$(cat "$trace")" == $'epc-broker-92\nepc-broker-93\ncompose restart' ]] ||
      failure "unchanged restart rc=$status: $output"
  else
    [[ "$status" != 0 && "$output" == *'restart refused'* && "$(cat "$trace")" != *compose* ]] ||
      failure "restart with $fixture_case reached Compose or lacked guidance: $output"
  fi
  printf 'PASS EPC restart: %s\n' "$fixture_case"
done
: > "$trace"
bash "$restart_driver" old_path "$trace" kafka-93
[[ "$(cat "$trace")" == $'epc-broker-93\ncompose kafka-93' ]] || failure 'targeted restart inspected the wrong broker'
: > "$trace"
bash "$restart_driver" inspect_error "$trace" proxy
[[ "$(cat "$trace")" == 'compose proxy' ]] || failure 'non-broker restart inspected a broker'
printf 'PASS EPC restart: targeted broker and non-broker dispatch\n'
: > "$trace"
if bash "$restart_driver" old_path "$trace" --no-deps || [[ -s "$trace" ]]; then
  failure 'Compose option could remove the service selector from restart'
fi
printf '%s\n' 'PASS EPC restart: Compose option cannot restart unverified brokers'
