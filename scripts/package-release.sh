#!/usr/bin/env bash
# Build one edition's offline install package (not broker images), including the SSO UI image.
#
# Usage: scripts/package-release.sh <kraft|epc> <vN> <amd64|arm64> [auto|none|noble|jammy|rhel9]
#
# The same script runs locally and in .github/workflows/package-release.yml.
# Output: dist/release/package-<edition>-<vN>/ holding the package, checksum,
# image lock file and release notes. Tracked .env.template files are restored
# on exit; the bundled copies keep the locally built Kafbat UI image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

edition="${1:-}"
version="${2:-}"
arch="${3:-}"
target_os="${4:-auto}"
MAKE="${MAKE:-make}"

die() { echo "package-release: $*" >&2; exit 1; }

[[ "$edition" =~ ^(kraft|epc)$ ]] || die "edition must be kraft or epc"
[[ "$version" =~ ^v[0-9]+$ ]] || die "version must be vN, e.g. v2"
[[ "$arch" =~ ^(amd64|arm64)$ ]] || die "arch must be amd64 or arm64"
if [[ "$target_os" == auto ]]; then
  target_os=noble
  [[ "$edition" == kraft ]] || target_os=rhel9
fi
case "$edition/$target_os" in
  kraft/noble|kraft/jammy|kraft/none|epc/rhel9|epc/none) ;;
  *) die "target OS $target_os does not apply to $edition (kraft: noble|jammy|none; epc: rhel9|none)" ;;
esac
"$MAKE" --version 2>/dev/null | grep -q 'GNU Make [4-9]' || die "GNU Make 4.0+ required; set MAKE=gmake on macOS"

tag="package-${edition}-${version}"
bundle="krate-${edition}-${version}-${arch}"
out_dir="dist/release/${tag}"

# build.py pins its image ID into both templates; keep the checkout clean.
backup="$(mktemp -d)"
cp kraft/.env.template "$backup/kraft.env.template"
cp epc/.env.template "$backup/epc.env.template"
restore() {
  cp "$backup/kraft.env.template" kraft/.env.template
  cp "$backup/epc.env.template" epc/.env.template
  rm -rf "$backup"
}
trap restore EXIT

echo "==> Building Kafbat UI image for $arch"
python3 kafbat-ui/build.py --arch "$arch"

include_docker=0
if [[ "$target_os" != none ]]; then
  include_docker=1
  if [[ "$target_os" == rhel9 ]]; then
    "$MAKE" docker-rpms RHEL_VERSION=9 ARCH="$arch"
  else
    "$MAKE" docker-debs UBUNTU_VERSION="$target_os" ARCH="$arch"
  fi
fi

"$MAKE" bundle VERSION="$version" MODE="$edition" ARCH="$arch" \
  TARGET_OS="$target_os" INCLUDE_DOCKER="$include_docker"

mkdir -p "$out_dir"
for suffix in "" .sha256 .images.lock.tsv; do
  mv "dist/${bundle}.tar.gz${suffix}" "$out_dir/"
done

# GitHub rejects release assets of 2 GiB or more.
size="$(wc -c < "$out_dir/${bundle}.tar.gz" | tr -d ' ')"
(( size < 2147483648 )) || die "${bundle}.tar.gz is ${size} bytes; GitHub release assets must be under 2 GiB"

checksum="$(awk '{print $1}' "$out_dir/${bundle}.tar.gz.sha256")"
docker_note="not included"
[[ "$include_docker" == 1 ]] && docker_note="included for \`${target_os}\`"
{
  printf '### %s\n\n' "$bundle"
  # shellcheck disable=SC2016  # backticks are Markdown code spans
  printf -- '- SHA-256: `%s`\n' "$checksum"
  printf -- '- Docker packages: %s\n\n' "$docker_note"
  printf '| Image | Image ID | Platform |\n|---|---|---|\n'
  awk -F '\t' 'NR > 1 {
    ref = $1; sub(/@.*/, "", ref)
    id = $3; sub(/^sha256:/, "", id)
    printf "| `%s` | `sha256:%s…` | %s |\n", ref, substr(id, 1, 12), $7
  }' "$out_dir/${bundle}.tar.gz.images.lock.tsv"
  printf '\n'
} > "$out_dir/${bundle}.notes.md"

echo "==> Release files in $out_dir:"
ls -l "$out_dir"
