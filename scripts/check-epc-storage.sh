#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/epc/storage-guard.sh"
failure() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
fixture="$(mktemp)"
trap 'rm -f -- "$fixture"' EXIT
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
