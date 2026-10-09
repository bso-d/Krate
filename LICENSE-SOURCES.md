# Corresponding source for third-party components

Krate itself is licensed under the GNU Affero General Public License v3.0 (see
`LICENSE`). Its own source is this repository; the scripts and configuration in every
offline package are that source.

The offline install packages also redistribute third-party container images (Apache
Kafka, Kafbat UI, Keycloak, PostgreSQL, nginx, Prometheus, Alertmanager, Grafana, Loki,
Fluent Bit, Perses, VictoriaLogs, OAuth2 Proxy, node-exporter, kafka-exporter, the
Python runtime for log discovery and, in the frozen ZooKeeper edition, Confluent
Platform). Those images contain components under copyleft licences. For every one of
them, each package release ships the **complete corresponding source** as a separate
release asset. There is no written offer: the source is published next to the package.

## Where to find it

Every release that carries `krate-<edition>-vN-<arch>.tar.gz` also carries:

| Asset | Content |
| --- | --- |
| `krate-<edition>-vN-<arch>-sources.tar` | the corresponding source for that package's images |
| `krate-<edition>-vN-<arch>-sources.tar.sha256` | SHA-256 of the tar (and of each part, if split) |

The ZooKeeper edition uses `kafka-zk-vN-<arch>-sources.tar`.

GitHub limits a release asset to 2 GiB. A larger source archive is attached as
`...-sources.tar.part000`, `.part001`, ... Reassemble and check it with:

```bash
cat krate-kraft-v9-arm64-sources.tar.part* > krate-kraft-v9-arm64-sources.tar
sha256sum -c --ignore-missing krate-kraft-v9-arm64-sources.tar.sha256
tar -xf krate-kraft-v9-arm64-sources.tar
```

Inside the archive:

- `SOURCES.md`: human-readable index: every image with its distribution, the number of
  copyleft components and the source size; every component with version, licence and
  files; and an **UNRESOLVED** section (see below).
- `manifest.json`: machine-readable record (`krate-corresponding-source/1`): for each
  component its ecosystem, name, exact version, licence, the images and platforms it
  was found in (and the evidence, such as the package database entry or binary path),
  and each file with its SHA-256, size, origin URL and how it was verified.
- `sources/<ecosystem>/<name>/<version>/...`: the files, stored once.
- `by-image/<image>/...`: links into `sources/` for each image.

## What is included

The collector (`scripts/collect-sources.py` with `scripts/source-handlers/`) reads each
image offline (`docker create` + `docker export`; images are never started) and
inventories it. It ships source for every component whose licence is copyleft (GPL,
LGPL, AGPL, MPL, EPL, CDDL, EUPL, OSL, Sleepycat, CC-BY-SA, OFL and similar) or cannot
be classified. Components that offer a permissive alternative (for example
`MPL-2.0 OR Apache-2.0`) are shipped under the permissive option and listed as such.
Where a component lists several licences without saying which applies, it is treated
as copyleft.

| Found in the image | Source shipped | Verified against |
| --- | --- | --- |
| Debian packages (`/var/lib/dpkg/status`, distroless `status.d`), including `Built-Using` | `.dsc`, orig and Debian tarballs of the exact source version | SHA-1 file ids on snapshot.debian.org and the `.dsc` `Checksums-Sha256` |
| Alpine packages (`/lib/apk/db/installed`) | the `aports` directory at the package's recorded build commit, plus every distfile | git blob ids of that commit (GitLab), APKBUILD `sha512sums` |
| RPM packages (Red Hat UBI images: Keycloak, Confluent) | the exact `.src.rpm`, from Red Hat's public UBI source repositories or, for builds those repositories no longer carry, from Red Hat's UBI source container images (`<ubi>:<tag>-source`) | SHA-256 in the repository's `primary.xml`; or the source-container layer digest from the registry manifest plus the SRPM's content-addressed blob name |
| Java libraries (JAR files, including Spring Boot nested JARs) | `-sources.jar` and POM of the exact version | the repository's published checksum; the shipped JAR is compared with the published binary |
| Go binaries (`go version -m`) | module zips of copyleft modules (for example the MPL-2.0 HashiCorp modules) | `go mod download` against sum.golang.org, and the `h1:` hash in the binary |
| Grafana and Loki (AGPL-3.0) | complete tree of the commit the image was built from | git commit id |
| VictoriaLogs (statically links glibc) | its complete source and every Debian glibc revision it can have been linked with, for LGPL relinking | git commit id; Debian as above |
| Eclipse Temurin JDK | Adoptium's `-jdk-sources` tarball for the exact release, plus the temurin-build scripts at `BUILD_SOURCE` | Adoptium's `.sha256.txt` |
| BusyBox in `prometheus/busybox` and distroless `:debug` bases | BusyBox, Buildroot and uClibc-ng tarballs and the docker-library/busybox recipe at the build commit | the binary's SHA-256 matched in docker-library's published root filesystems; hashes from the git-pinned Dockerfile, the Buildroot `.sign` file and Buildroot's `uclibc.hash` |
| Debian data files without a package database (`ca-certificates.crt`, `/etc/services`) | the matching Debian source packages | content match against the Debian binary packages; Debian as above |
| Python packages installed with pip, and the libraries pip vendors | sdist from PyPI | PyPI's SHA-256 |
| JavaScript bundled in Grafana, Perses and Kafbat UI | npm tarballs of copyleft packages in the production dependency closure of the lockfile at the build commit | registry.npmjs.org `dist.integrity` |

The Red Hat OpenJDK in Keycloak is an RPM; its source is the `java-21-openjdk` SRPM.

## UNRESOLVED components

Anything whose corresponding source could not be obtained from an authoritative origin
is listed under **UNRESOLVED** in `SOURCES.md` and `manifest.json` with the reason. It
is never skipped silently. Known cases:

- **Azul Zulu JDK** (Kafbat UI image; Confluent images in the ZooKeeper edition). Azul
  does not publish source archives. Its third-party licence document offers the
  complete source on request (azul_openJDK@azul.com, valid for three years). Until that
  source is obtained and added, or the image is moved to a JDK whose source is
  published, this is an open obligation.
- **ZooKeeper edition, Confluent images** (`cp-kafka`, `cp-zookeeper` 7.6.1, frozen):
  a few RHEL 8 packages that Confluent installed from the UBI repositories at build
  time (for example `wget`, `libsemanage`, `python3x-pip`) are older builds that Red
  Hat's public UBI repositories and UBI source containers no longer carry, and
  Confluent's `confluent-docker-utils` is not published on PyPI. Red Hat provides
  RHEL sources to customers through the Customer Portal; Confluent publishes the
  utility on GitHub.
- Any other entry in the release's `SOURCES.md`, with its specific reason.

## Rebuilding the source archive

The archive is produced by `scripts/package-release.sh` for every package, and can be
rebuilt from a checkout on any machine with Docker, Python 3.11+, Go and git:

```bash
# from the package's image lock file (exact images that were shipped)
python3 scripts/collect-sources.py --edition kraft \
  --lock dist/release/package-kraft-v9/krate-kraft-v9-arm64.tar.gz.images.lock.tsv \
  --out dist/sources --archive dist/krate-kraft-v9-arm64-sources.tar

# or from the digest-pinned .env.template images
make sources MODE=epc ARCH=amd64 VERSION=v1
```

By default every registry image is inventoried for both `linux/amd64` and
`linux/arm64`; package versions that differ by platform are recorded separately and
both are fetched. The release build passes `--platforms input`, because each package
only contains its own platform. Downloads are cached by verified digest in
`dist/sources-cache/`.

Verify an extracted archive against its manifest:

```bash
cd krate-kraft-v9-arm64-sources
python3 -c 'import json,hashlib; m=json.load(open("manifest.json")); bad=[f["path"] for c in m["components"] for f in c["files"] if hashlib.sha256(open(f["path"],"rb").read()).hexdigest()!=f["sha256"]]; print(bad or "all files OK")'
```

## Limits

- Licence classification relies on package metadata (dpkg copyright files, apk/RPM
  licence fields, POMs, deps.dev records and licence files). It errs towards shipping
  source.
- Front-end dependency lists come from the project lockfile at the build commit, so they
  can include packages that the bundler removed.
- PGP signatures of Debian `.dsc` files and Buildroot `.sign` files are not checked by
  the collector; the files are pinned by the hashes listed above.
- The Docker CE packages (`docker-offline/`) bundled with some packages are not
  container images and are not covered by this archive.
