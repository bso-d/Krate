#!/usr/bin/env bash
# Stage the pinned Keycloak image's OpenJDK for the offline host credential CLI.
set -euo pipefail

[[ $# -eq 3 ]] || { echo "Usage: $0 KEYCLOAK_IMAGE ARCH OUTPUT_DIR" >&2; exit 2; }
image="$1"
arch="$2"
output="$3"
[[ "$image" =~ @sha256:[a-f0-9]{64}$ ]] || { echo "Keycloak image must be digest-pinned" >&2; exit 2; }
[[ "$arch" == amd64 || "$arch" == arm64 ]] || { echo "Unsupported architecture: $arch" >&2; exit 2; }
[[ ! -e "$output" && ! -L "$output" ]] || { echo "JRE output already exists: $output" >&2; exit 2; }

jre_path="$(docker run --rm --network none --platform "linux/$arch" --entrypoint /bin/sh "$image" -c \
  'find /usr/lib/jvm -mindepth 1 -maxdepth 1 -type d -name "java-21-openjdk-*"')"
[[ "$jre_path" == /usr/lib/jvm/java-21-openjdk-* && "$jre_path" != *$'\n'* ]] \
  || { echo "Expected one Red Hat OpenJDK 21 runtime in the pinned Keycloak image" >&2; exit 1; }

container="$(docker create --platform "linux/$arch" --entrypoint /bin/true "$image")"
trap 'docker rm "$container" >/dev/null 2>&1 || true' EXIT
mkdir -p "$(dirname "$output")"
docker cp -L "$container:$jre_path" "$output"

# Docker cp -L dereferences only the selected source. Materialize the JRE's
# system configuration and timezone data so an air-gapped host needs no Java RPM.
for relative in conf lib/security lib/tzdb.dat lib/security/cacerts; do
  target="$output/$relative"
  if [[ -L "$target" && "$(readlink "$target")" == /* ]]; then
    unlink "$target"
    docker cp -L "$container:$jre_path/$relative" "$target"
  fi
done

while IFS= read -r -d '' link; do
  [[ "$(readlink "$link")" != /* ]] \
    || { echo "JRE has an unresolved absolute link: $link" >&2; exit 1; }
done < <(find "$output" -type l -print0)
[[ -x "$output/bin/java" && -s "$output/lib/tzdb.dat" && -s "$output/lib/security/cacerts" ]] \
  || { echo "Extracted JRE is incomplete" >&2; exit 1; }
echo "Staged pinned Keycloak OpenJDK 21 runtime for linux/$arch"
