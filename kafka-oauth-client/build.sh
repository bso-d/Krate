#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Usage: build.sh <pinned-kafka-3.9.1-libs-dir> <output-dir>' >&2
  exit 2
fi

lib_dir="$1"
output_dir="$2"

python3 - "$lib_dir" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
expected = {
    'kafka-clients-3.9.1.jar': '25c5e4eb059c35766f645c0e0bd2fe623a1ebdc18250957506b1edbf476d1272',
    'jackson-databind-2.16.2.jar': '53b6025d98c357068296e4b134242443a248c2c582800879f1c4ea93b54bafa6',
    'jackson-core-2.16.2.jar': '4f43e2f1430b2d2413e8e5a3d79138e57e891d6a961b18c28ac90859639d8664',
    'jackson-annotations-2.16.2.jar': 'd1cdd269ebaa753d1842933194e17d61958f058952d63e03dbfb3d1d78a6926e',
}
for name, digest in expected.items():
    path = root / name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit(f'pinned Kafka build dependency missing or mismatched: {name}')
PY

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd -P)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
build_dir="$(mktemp -d "$output_dir/.krate-oauth-build.XXXXXX")"
trap 'rm -rf -- "$build_dir"' EXIT

mkdir -p "$build_dir/classes"
javac --release 17 -cp "$lib_dir/*" -d "$build_dir/classes" \
  "$script_dir"/src/main/java/com/krate/kafka/oauth/*.java
jar --create --date=2020-01-01T00:00:00Z \
  --file "$build_dir/krate-kafka-oauth-client.jar" -C "$build_dir/classes" .
mv -f -- "$build_dir/krate-kafka-oauth-client.jar" "$output_dir/krate-kafka-oauth-client.jar"
printf 'Built %s\n' "$output_dir/krate-kafka-oauth-client.jar"
