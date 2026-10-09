# Monitoring image notices (Perses stack)

Licence and notice evidence for the container images and plugin archives that the
Perses-based monitoring stack adds to the offline bundle. The layout follows the
collector notices in `monitoring/fluent-bit/vendor/`. Each directory holds a flat set of
files plus an `inventory.json`. In an object inventory, every row of `copyrights[]` and
`common_licenses[]` has `file` and `sha256`. In a list inventory, every row has them.
This is the shape that `scripts/check-bundle.py` already verifies for the collector, so
the same check can cover these directories:

| Directory | Inventory form | Rows |
| --- | --- | --- |
| `perses/` | object (packages, copyrights, common_licenses, index_digest, platform_manifests) | 27 |
| `perses/go-modules/` | list | 249 |
| `perses/ui-npm/` | list (+ `packages.json`, hashed as a row) | 342 |
| `perses-plugins/` | object (`archives[]`, `copyrights[]`, empty `common_licenses[]`) | 477 |
| `oauth2-proxy/` | object | 34 |
| `oauth2-proxy/go-modules/` | list | 76 |
| `victorialogs/` | object | 27 |
| `victorialogs/go-modules/` | list | 30 |
| `alertmanager/` | object | 15 |
| `alertmanager/go-modules/` | list | 160 |
| `nginx/` | object (existing pin, recorded only) | 5 |

## Digests

All index digests below are the SHA-256 of the raw index bytes fetched from the
registry with `docker buildx imagetools inspect --raw`. Each platform manifest was pulled
by digest for `linux/amd64` and `linux/arm64`. It was then exported with
`docker create` + `docker export`, without being run, and the container was removed.
Both architectures exist for every image.

| Image | Index digest | linux/amd64 | linux/arm64 |
| --- | --- | --- | --- |
| `docker.io/persesdev/perses:v0.54.0` | `sha256:a0e34ddaf9d7599d96036611af205b948c1179646844202d869f3bcf3d5d9e9c` | `sha256:6def46a662a22e790b49c01865c80f547d11d16a83213ac102a0e722d27ece13` | `sha256:3d73e476d621b83098637dc4864eb90cf9748a7949eade73abe6774d4b8ef379` |
| `quay.io/oauth2-proxy/oauth2-proxy:v7.15.5` | `sha256:8498b0d0ef0a7b29686414000a08aee467f02d0299c9ed1e006a8f33fc017916` | `sha256:0d989b27d90d5e527fb2b045d864c4001c3104bdd763b3211b7e9ba2110380ea` | `sha256:755fb16f07f22a277149a06057e06e2cfc15557621c5be2ae71645999748746d` |
| `docker.io/victoriametrics/victoria-logs:v1.53.0` | `sha256:251121fa882af99b95ba0c230a4a2f412ea602d2698c64a96c58dc9842bb755d` (matches expected) | `sha256:45dc9bef07c0c404255790e41f2c22c62ff55a690a1d556e0f9cb6f6e2556f1b` | `sha256:9beccb5e7d38e3db891578249f90ef16f572c37665062ca19cbcc753055431c9` |
| `docker.io/prom/alertmanager:v0.34.1` (= `quay.io/prometheus/alertmanager:v0.34.1`, same index) | `sha256:e9733bafb1bdef9b00e25a21f8f99dc26a22224bf16641ad754d1649f4c3357a` (matches expected) | `sha256:84967b9b7ba45e38a9278d3e594305f43d4993c310df3905b51138b816c365f3` | `sha256:47a1dc7e74f1e755e29f74d392262f8d1da41f2ada5653911199bf07219e41d9` |
| `nginx:1.27-alpine` (existing `NGINX_IMAGE` pin) | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | `sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8` | `sha256:63ffc0d1f14e4082b832c6a42e606e9a0384a526f16ddd720af7c1f018f2f7c4` (`arm64/v8`) |

How we confirmed each image is official:

- **Perses:** the image labels carry `org.opencontainers.image.source=https://github.com/perses/perses` and `revision=4c719fc19fa21d333797e84c4fe7e3d81c25f4f5`. The image `/LICENSE` is byte-identical to that commit's LICENSE.
- **OAuth2 Proxy:** the upstream README for v7.15.5 says that all images are published at `quay.io/oauth2-proxy/oauth2-proxy`, and the Makefile sets `REGISTRY ?= quay.io/oauth2-proxy`. The image labels match.
- **VictoriaLogs:** the labels name `VictoriaMetrics/VictoriaLogs` v1.53.0.
- **Alertmanager:** the Docker Hub and Quay indexes are identical.

## Verification method

1. **Debian packages.** Packages come from each image's `var/lib/dpkg/status.d`.
   Copyright files and `usr/share/common-licenses` were copied verbatim from the exported
   image, and the build fails unless the amd64 and arm64 bytes are identical. `url` gives
   the matching Debian metadata service location; `origin` gives the in-image path.
2. **Go binaries.** We ran `go version -m` (Go 1.27.1, local) on every shipped Go binary
   for both architectures:
   - Perses: `/bin/perses` and `/bin/percli`
   - OAuth2 Proxy: `/bin/oauth2-proxy`
   - VictoriaLogs: `/victoria-logs-prod`
   - Alertmanager: `/bin/alertmanager` and `/bin/amtool`

   The amd64 and arm64 module lists are identical. Each `dep` was fetched with
   `go mod download -json`, which goes through the module proxy and checks
   sum.golang.org. Where the binary embeds an `h1:` hash, the build also requires it to
   equal the downloaded module `Sum`. VictoriaLogs records no `h1:` hashes, so its
   modules are verified by sumdb only. Files named LICENSE, COPYING, NOTICE, PATENTS,
   UNLICENSE, COPYRIGHT or LEGAL were copied from each whole module tree, excluding
   `testdata/` and code files. They were then classified with `google/licensecheck`
   v0.3.1. Every module yielded at least one licence file. Rows with 0% coverage are
   NOTICE/COPYRIGHT attribution files, not unknown licences. The Go standard library
   `LICENSE` and `PATENTS` for each toolchain come from the `golang/go` tag (go1.26.5,
   go1.26.8, go1.27.1). The pinned Perses `go.mod` was read for reference only; the
   binary's build info is authoritative.
3. **Perses UI.** The UI is embedded in `/bin/perses` through Go `embed.FS`
   (`app/dist/*`, 111 files). A small ELF reader extracted those files; the amd64 and
   arm64 copies are identical. The two webpack-emitted `*.js.LICENSE.txt.gz` files are
   the only licence output the UI ships. They are stored gunzipped (`ui__*`), with the
   embedded `.gz` hash kept as `embedded_gz_sha256`. Those banners are not a complete
   dependency list, so `ui-npm/` adds one. It takes every package-lock entry without
   `dev: true` from the pinned `ui/package-lock.json` at commit 4c719fc (339 packages and
   4 workspace links). Each tarball was downloaded from its `resolved` URL and checked
   against the lockfile `integrity` before licence files were copied out. That list is
   a superset of what webpack actually bundles. Seventeen packages ship no licence file;
   only their declared licence is recorded (`packages.json`).
4. **Plugin archives.** The Perses image bakes **30** plugin archives into
   `/etc/perses/plugins-archive/`. Their bytes are identical across the two
   architectures, and their SHA-256 values are in `perses-plugins/inventory.json`. The
   five core archives in `dashboard-conversion/plugin-archives/` match
   `offline-assets.json` and are byte-identical to the image copies.
   `VictoriaLogs-0.4.0.tar.gz`, downloaded from the GitHub release, has SHA-256
   `eafacacb0827a39a7495646e2229010c7ba711adb24762b86f294bbfd238ed2f`, as expected, and is
   also identical to the copy in the image. All licence, notice and `*.js.LICENSE.txt`
   files were extracted from all 30 archives. Every archive's `LICENSE` and bundled CUE
   module `LICENSE` is Apache-2.0.
5. **Alertmanager base.**
   - `/bin/busybox` is static and stripped, and prints `BusyBox v1.38.0`. The base layer
     history reads `BusyBox 1.38.0 (uclibc), Buildroot 2026.05.1, Debian 13`.
   - The BusyBox 1.38.0 tarball hash matches docker-library/busybox `versions.json`.
   - The uClibc-ng 1.0.57 version is taken from Buildroot 2026.05.1 `uclibc.mk`, and the
     tarball and `COPYING.LIB` hashes match Buildroot's `uclibc.hash`.
   - The Debian files that prometheus/busybox adds were matched to known versions as
     follows:
     - `ca-certificates.crt` and `/etc/services` are byte-identical to ca-certificates
       20250419 and netbase 6.5.
     - `tzdata.zi` reports 2026b.

## Per image

### Perses v0.54.0

- **Base and packages.** The base is `gcr.io/distroless/static-debian12:nonroot`
  (bookworm), with no libc. It contains base-files 12.4+deb12u15, media-types 10.0.0,
  netbase 6.4 and tzdata 2026b-0+deb12u1. It also has a ca-certificates doc and bundle
  without a dpkg entry, so that version is not recorded.
- **Licences.** The project is Apache-2.0. The binary links 187 Go modules across
  perses and percli, mostly MIT, Apache-2.0 and BSD; there is also ISC, 0BSD and
  Unlicense. The UI is mostly MIT.
- **Copyleft and weak copyleft:**
  - MPL-2.0 Go modules: `github.com/go-sql-driver/mysql` v1.10.0 and
    `github.com/hashicorp/golang-lru/v2` v2.0.7.
  - UI: DOMPurify 3.4.11 is MPL-2.0 OR Apache-2.0, so Apache-2.0 can be elected.
  - Fonts: `@fontsource/inter` 5.2.8 is OFL-1.1. The Inter WOFF files are embedded in
    the UI and in the plugin archives. The OFL text is in
    `ui-npm/@fontsource_inter@5.2.8__LICENSE`.
  - Not shipped as code: `go-digest` `LICENSE.docs` (CC-BY-SA-4.0, documentation only)
    and caniuse-lite (CC-BY-4.0 data, most likely build-time only).
  - Base packages: Debian base-files and netbase carry GPL-licensed data and scripts in
    the base layer.

### OAuth2 Proxy v7.15.5

- **Base and packages.** The base is `gcr.io/distroless/static:nonroot` (trixie), with
  no libc. It contains base-files 13.8+deb13u7, ca-certificates 20250419, media-types
  13.0.0, netbase 6.5, and tzdata and tzdata-legacy 2026c-0+deb13u1.
- **Licences.** The project is MIT. The licence comes from the tag, because the image
  ships none. It links 58 Go modules, all Apache-2.0, MIT, BSD-2-Clause or BSD-3-Clause.
- **Copyleft:** no copyleft Go module. The only copyleft is the Debian base data.
  ca-certificates is MPL-2.0 for the Mozilla data and GPL-2+ for its tooling.

### VictoriaLogs v1.53.0

- **Base and packages.** The base is distroless static Debian 13 (trixie). It contains
  base-files 13.8+deb13u4, media-types 13.0.0, netbase 6.5, and tzdata and
  tzdata-legacy 2026a-0+deb13u1.
- **Licences.** The project is Apache-2.0. It links 16 Go modules.
- **Copyleft:**
  - **Static glibc.** `/victoria-logs-prod` is built with `CGO_ENABLED=1` and statically
    linked. It contains glibc and libgcc runtime code; `.comment` reads
    `GCC: (Debian 14.2.0-19)`. glibc is LGPL-2.1-or-later, so a static link brings the
    LGPL §6 requirement to let users relink. That means providing the object files or
    the complete corresponding source of the application and of glibc.
  - **Version uncertainty.** The exact Debian glibc revision is not recorded in the
    binary. `glibc_2.41-12+deb13u4_copyright.txt` is an inference, byte-identical to the
    collector copy. The libgcc parts are under GPL-3 with the GCC Runtime Library
    Exception.
  - **zstd.** gozstd v1.26.0 bundles zstd, which is BSD-3-Clause OR GPL-2.0, so
    BSD-3-Clause can be elected. Both texts are kept.

### Alertmanager v0.34.1

- **Base and contents.** The base is `quay.io/prometheus/busybox` (uClibc). That is
  docker-library `busybox:uclibc` plus Debian trixie `ca-certificates.crt`, zoneinfo,
  `/etc/services` and `nsswitch.conf`.
- **Licences.** The project is Apache-2.0. `ALERTMANAGER-NOTICE` (311 bytes, from the
  tag) is reproduced verbatim. It links 117 Go modules across alertmanager and amtool.
  The image itself ships no licence or NOTICE files.
- **Copyleft:**
  - **BusyBox 1.38.0, GPL-2.0-only.** The binary is static, with 411 applet links. If
    the bundle redistributes this image, the GPL-2.0 §3 obligation applies:
    - either ship the complete corresponding source with the bundle, or include a
      written offer, valid for at least three years, to provide it;
    - the corresponding source is BusyBox 1.38.0, the BusyBox `.config`, and the
      Buildroot 2026.05.1 configuration and scripts used by docker-library/busybox
      commit 1dbf72408aa7d10a0336461393be964a3d163995;
    - the §3(c) "pass on the upstream offer" route is only available to noncommercial
      distribution.
  - **uClibc-ng 1.0.57, LGPL-2.1-or-later.** It is statically linked into BusyBox, so
    the LGPL §6 relinking material or source must also be provided. In practice the
    same source package covers it.
  - **MPL-2.0 Go modules.** The binary links seven MPL-2.0 Go modules:
    - `hashicorp/errwrap` v1.1.0
    - `hashicorp/go-immutable-radix` v1.3.1
    - `hashicorp/go-multierror` v1.1.1
    - `hashicorp/go-sockaddr` v1.0.7
    - `hashicorp/golang-lru` v0.5.4
    - `hashicorp/golang-lru/v2` v2.0.7
    - `hashicorp/memberlist` v0.6.0
  - **Debian data files:** ca-certificates (MPL-2.0 data) and netbase (GPL-2).

### nginx (existing pin, no new version selected)

- **Pin.** `kraft/.env.template` and `epc/.env.template` both pin
  `NGINX_IMAGE=nginx:1.27-alpine@sha256:65645c7b…`. The image is Alpine 3.21.3 with
  nginx 1.27.5 and njs 0.8.10. The 68 apk packages are the same on both architectures.
- **Repository coverage before this change.** The repository had no notice files or
  inventory for this image; nginx appears only in the README component credits.
  `nginx/` records the apk-declared licences and the five in-image nginx `COPYRIGHT`
  files. Alpine installs no per-package licence texts, and they were not collected.
- **Copyleft packages already shipped by the existing bundle:**
  - GPL-2.0: busybox 1.37.0-r12, busybox-binsh, ssl_client, apk-tools, alpine-baselayout
    and scanelf.
  - LGPL-2.1+: geoip, libintl, libgcrypt and libgpg-error.
  - GPL-3.0+ AND LGPL: gettext-envsubst.
  - Mixed licences that include GPL or LGPL terms: xz-libs, musl-utils, freetype,
    libidn2, libunistring and zstd-libs.
  - MPL-2.0: ca-certificates.

## Obligations and how the repository handles them

The collector notices (`monitoring/fluent-bit/vendor/image-notices/README.md`) handle
LGPL and GPL components by shipping notices and stating that "these notices do not
themselves satisfy every corresponding-source or relinking obligation". They defer
source provision to release review. The repository has no source-offer file, no
corresponding-source archive and no relinking kit anywhere. These notices follow the
same approach and **do not fulfil** the following, which must be resolved before the
offline bundle is redistributed:

1. **GPL-2.0 BusyBox, in the Alertmanager image and in the existing nginx pin.** Ship
   the corresponding source in the bundle, or a written offer valid for three years.
2. **LGPL-2.1 static libc.** This covers uClibc-ng in the Alertmanager BusyBox and glibc
   in VictoriaLogs. Provide relinkable object files or complete source, and confirm the
   exact glibc revision with upstream.
3. **MPL-2.0 Go modules, used by Perses and Alertmanager.** Tell recipients where the
   Source Code Form of those files is available, as MPL-2.0 §3.2(a) requires. The
   unmodified module zips are at the `url` recorded in each go-modules row
   (proxy.golang.org).
4. **OFL-1.1 fonts.** Keep the OFL text with the Perses UI and plugin fonts. It is
   included here.

Notices describe whole source packages or modules. They are not a statement that every
listed file applies to every shipped binary, and they are not a complete binary linkage
SBOM. The buildkit attestation manifests (`unknown/unknown`) in the indexes were not
used. No image was run and no network access occurs at runtime.

The helper scripts used to regenerate these files live in the gitignored `tests/perses-notices/`:

- `build.py`, `nginx.py`, `gomodules.py` and `npmlicenses.py` generate the inventories and copy the files.
- `embedfs/` is the embed.FS extractor.
- `classify/` is the licensecheck wrapper.
- `verify.py` runs the check-bundle-style hash check.
