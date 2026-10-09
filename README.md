<a id="readme-top"></a>

<div align="center">
  <img src="assets/krate-logo.png" alt="Krate logo: a blue and teal crate with connected nodes" width="240">

  <h1>Krate</h1>

  <p>Portable Kafka packages for Ubuntu and RHEL virtual machines.</p>

  <p>
    <a href="https://github.com/bso-d/Krate/actions/workflows/broker-ci.yml">
      <img src="https://github.com/bso-d/Krate/actions/workflows/broker-ci.yml/badge.svg?branch=main" alt="Broker images CI">
    </a>
    <a href="https://github.com/bso-d/Krate/actions/workflows/codeql.yml">
      <img src="https://github.com/bso-d/Krate/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL checks">
    </a>
    <img src="https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white" alt="Docker">
    <img src="https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white" alt="Bash">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue" alt="License: AGPL-3.0"></a>
  </p>

  <p>
    <a href="#start-on-a-connected-machine">Get started</a> ·
    <a href="#build-an-offline-package">Build a package</a> ·
    <a href="https://github.com/bso-d/Krate/releases">Downloads</a> ·
    <a href="#guides">Guides</a>
  </p>
</div>

<details>
  <summary>Contents</summary>

  - [What Krate does](#what-krate-does)
  - [Problems Krate solves](#problems-krate-solves)
  - [How it differs from similar repositories](#how-it-differs-from-similar-repositories)
  - [Choose an edition](#choose-an-edition)
  - [What you need](#what-you-need)
  - [Start on a connected machine](#start-on-a-connected-machine)
  - [Build an offline package](#build-an-offline-package)
  - [Install the package on a VM](#install-the-package-on-a-vm)
  - [Everyday commands](#everyday-commands)
  - [Monitoring](#monitoring)
  - [How the parts fit together](#how-the-parts-fit-together)
  - [Limits to understand](#limits-to-understand)
  - [Development and checks](#development-and-checks)
  - [Component credits](#component-credits)
  - [Contributing and community conduct](#contributing-and-community-conduct)

</details>

## What Krate does

[Apache Kafka](https://kafka.apache.org/) lets applications send, store, and read streams of messages. A Kafka **broker** is a server that handles those messages. Several brokers working together form a **cluster**.

Krate supplies the files and command-line tools to run a Kafka cluster with [Docker](https://www.docker.com/), which runs software in containers. It can also collect the container images and setup files into one compressed package. Build that package on a machine with internet access, copy it to a matching virtual machine (VM), and install it there without downloading the images again.

Each edition includes [Kafbat UI](https://github.com/kafbat/kafka-ui), a browser interface for viewing brokers, topics (named message streams), and consumer groups (applications sharing the work of reading messages). The UI sits behind an nginx web proxy with HTTPS and a login.

## Problems Krate solves

| Problem | What Krate provides |
| --- | --- |
| The VM cannot download container images | A package containing the images and setup files, plus a checksum to check the transferred file |
| The VM has a different processor or operating system from the build machine | A build for the chosen processor, a processor check before installation, and matching Ubuntu or RHEL Docker packages when requested |
| Setup steps are spread across separate commands and files | A command script for installation, health checks, logs, and message backlog, with the UI already configured |
| Measurements and logs need separate setup | Included monitoring files and images, started with a separate command when needed |

You still need suitable disk space, OS dependencies, and working network settings. Krate prepares the software and runs host checks; the deployment guides cover the remaining host setup.

## How it differs from similar repositories

| Repository | Main purpose | Krate's focus |
| --- | --- | --- |
| [Apache Kafka Docker examples](https://github.com/apache/kafka/tree/trunk/docker/examples) | Show how to configure single-node and multi-node Kafka containers, including encrypted and authenticated connections | Provide selected cluster setups with an offline package builder, optional Docker installer, management commands, UI, and monitoring |
| [Confluent cp-all-in-one](https://github.com/confluentinc/cp-all-in-one) | Run examples of the broader Confluent Platform, including schema management, connectors, and stream-processing services | Package Kafka, its UI, and monitoring for VM installation; those extra Confluent services are not included |

Krate adds package builds and host management commands around Kafka and Docker, especially for a VM without internet access. Its supplied clusters share one host and need additional configuration for secure remote application access.

## Choose an edition

Ubuntu and Red Hat Enterprise Linux (RHEL) are the target operating systems.

| Edition | What it runs | Intended host | Command |
| --- | --- | --- | --- |
| **Krate (default)** | Four brokers; Kafka manages its own coordination | Ubuntu 22.04 or 24.04, x86_64 or ARM64 | `kraft/krate` |
| **EPC** | Two brokers using KRaft, with message data stored under `/data` | Tailored for RHEL 9 on x86_64 | `epc/krate` |

These are the two active releases. Each package contains its own security features and monitoring files. The `zk/` directory is a frozen legacy package for existing users. EPC is the tailored RHEL deployment.

For a first local run, the steps below use KRaft. All brokers in these setups run on the same host.

### Ready-made downloads

The [releases page](https://github.com/bso-d/Krate/releases) holds two kinds of release. Check the tag prefix and title before downloading:

| Kind | Tag | Title starts with | What you get |
| --- | --- | --- | --- |
| **Offline install package** | `package-kraft-vN`, `package-epc-vN` | `Offline install package` | A `.tar.gz` to copy to the VM, its `.sha256` checksum and the image lock file. Install it with `./krate install`. |
| **Broker images** | `kraft-vX.Y.Z`, `zk-vX.Y.Z` | `Broker images` | References to container images on GHCR. Nothing to install on a VM; the default setups do not use these images. |

Offline install packages published so far, all x86_64:

| Release | Package |
| --- | --- |
| [`epc-v2`](https://github.com/bso-d/Krate/releases/tag/epc-v2) | RHEL/EPC with Keycloak SSO: `krate-epc-v2-amd64.tar.gz` |
| [`epc-v1`](https://github.com/bso-d/Krate/releases/tag/epc-v1) | RHEL/EPC: `kafka-epc-v1-amd64.tar.gz` |
| [`v1.0.0`](https://github.com/bso-d/Krate/releases/tag/v1.0.0) | Archived ZooKeeper package: `kafka-zk-v5-amd64.tar.gz` |

These were published before the `package-` tags existed. New KRaft and EPC packages are released as `package-kraft-vN` and `package-epc-vN`; see [Release an offline install package](#release-an-offline-install-package). Until a KRaft package is released, build it from source using the commands below. Existing downloads keep their original `kafka-*` names. New KRaft and EPC packages use `krate-*`; ZooKeeper keeps `kafka-zk-*`.

## What you need

- **To run a cluster:** Docker Engine 25.0.3 or newer, a working Docker service, and Docker Compose. The scripts accept the `docker compose` plugin or standalone `docker-compose` 1.29.2 or newer; the examples use the plugin.
- **To create the UI certificate:** OpenSSL, or your own certificate and key at `certs/server.crt` and `certs/server.key`.
- **To build packages:** a connected machine with Docker, Bash, Git, and GNU Make 4.0 or newer. On macOS, use `gmake` wherever the examples say `make`.
- **For KRaft/EPC monitoring:** Python 3 on the host, in addition to Docker.

Choose the package for the target VM's processor: `amd64` means x86_64; `arm64` means ARM64. Leave room for the package, loaded images, and stored messages. The EPC guide explains how to budget its `/data` disk.

## Start on a connected machine

1. Clone the repository and create the KRaft settings file.

   ```bash
   git clone https://github.com/bso-d/Krate.git
   cd Krate/kraft
   cp .env.template .env
   ```

2. Edit `.env`. Set `KAFKA_UI_USER` and `KAFKA_UI_PASSWORD` to your own login details. Set `KAFKA_UI_FQDN` to the hostname you will use to open the UI. The default login is `admin` / `changeme`; replace it before exposing the UI.

3. Start the cluster and check it.

   ```bash
   ./krate gen-cert
   ./krate start
   ./krate health
   ./krate ui
   ```

Docker downloads the images on this first run. When startup is complete, `health` should report healthy services. `ui` prints the address and login details; open that HTTPS address to view the four brokers in Kafbat UI.

The generated certificate is self-signed, so the browser will show a trust warning. You can trust `certs/server.crt` or supply a certificate trusted by your browser.

For ZooKeeper, use `cd Krate/zk` and `./kafka` instead of `./krate`. Use `start` when running directly from the repository. The `install` command is for an extracted package containing saved images.

## Build an offline package

Run these commands from the repository root on the connected machine:

```bash
# KRaft package for an x86_64 VM
make bundle VERSION=v1 MODE=kraft ARCH=amd64

# KRaft package for an ARM64 VM
make bundle VERSION=v1 MODE=kraft ARCH=arm64
```

`VERSION` is a package label in the form `vN`, such as `v1` or `v5`. `MODE=both` builds default Krate and EPC. `MODE=zk` builds only the frozen legacy package. `ARCH` defaults to the build machine's processor when omitted.

Each build writes a package, a SHA-256 checksum, and a record of the saved images under `dist/`. For the first command above:

```text
dist/
├── krate-kraft-v1-amd64.tar.gz
├── krate-kraft-v1-amd64.tar.gz.sha256
└── krate-kraft-v1-amd64.tar.gz.images.lock.tsv
```

The package includes the cluster files, its command script, saved Docker images, and monitoring files. The image record lists the exact images, their checksums, and their processor type; a copy is also inside the package. `NO_PULL=1` reuses images already on the build machine; they must match `ARCH`.

### Include Docker for a VM that does not have it

For Ubuntu 24.04 on x86_64:

```bash
make docker-debs UBUNTU_VERSION=noble ARCH=amd64
make bundle VERSION=v1 MODE=kraft ARCH=amd64 TARGET_OS=noble INCLUDE_DOCKER=1
```

Use `jammy` for Ubuntu 22.04 and `arm64` for an ARM64 VM. Prepared packages live under `docker-offline/<os>/<arch>/`. The build checks that these match the requested OS and processor. Docker package versions are selected at download time.

For the RHEL 9 EPC edition:

```bash
make docker-rpms RHEL_VERSION=9 ARCH=amd64
make bundle VERSION=v2 MODE=epc ARCH=amd64 TARGET_OS=rhel9 INCLUDE_DOCKER=1
```

The Ubuntu installer uses `dpkg` and may try `apt-get` to repair missing dependencies. Make sure the target has the required OS dependencies before relying on a fully offline install. The RHEL installer disables network repositories; missing OS dependencies must be supplied locally.

## Install the package on a VM

Copy the package and its `.sha256` file to the VM. For the KRaft package built above:

```bash
sha256sum -c krate-kraft-v1-amd64.tar.gz.sha256
tar -xzf krate-kraft-v1-amd64.tar.gz
cd krate-kraft-v1-amd64
cp .env.template .env
```

The checksum should report `OK`. Edit `.env` to set your UI login and hostname, as in the connected setup.

If Docker is missing and you included its packages, run `./krate docker-install` first. It needs administrator access. Then run:

```bash
./krate doctor
./krate install
./krate health
./krate ui
```

`doctor` checks Docker, package architecture, certificates, host ports, and firewall settings. `install` runs those checks again, loads the saved images, creates a UI certificate if needed, and starts the cluster.

For a downloaded ZooKeeper package, use `./kafka`. For EPC, set `KAFKA_ADVERTISED_HOST` for clients on other machines and review the data directory before the first start.

## Everyday commands

Run these inside the KRaft or EPC directory, or an extracted package:

| Command | What it does |
| --- | --- |
| `./krate status` | Lists the services and their state |
| `./krate health` | Checks whether services are healthy |
| `./krate logs -f kafka-92` | Follows one broker's logs |
| `./krate lag` | Shows how many messages consumer groups still need to read |
| `./krate lag my-group` | Shows that backlog for one group |
| `./krate stop` / `./krate start` | Stops or starts services, keeping stored messages |
| `./krate down` | Removes containers while keeping stored messages |
| `./krate help` | Lists the available commands |

Use `./kafka` for the ZooKeeper edition. EPC also has `./krate disk` to show data-disk usage against the configured budget.

Settings live in `.env`. For example, `./krate config set KAFKA_UI_FQDN=kafka.example.com` updates the UI hostname setting. After changing a setting used by a container, run `./krate start` to apply it. After changing the certificate hostname, also run `./krate gen-cert` and `./krate restart proxy`.

In the supplied KRaft and ZooKeeper setups, `uninstall --purge` deletes stored Kafka messages by removing their Docker storage volumes. EPC stores messages in host folders under `KAFKA_DATA_DIR` (default `/data`), so those messages remain after purge. Deleting EPC messages requires stopping the cluster and separately removing its broker folders. Purge is not part of the normal stop/start workflow.

## SSO for EPC and regular Krate

The SSO integration uses the same dark Kafbat login page for the
shared Admin account and Keycloak SSO. Keycloak connects to PingFederate.
AD groups determine Viewer and Admin access. Keycloak and its database use
the `sso` profile in each release's existing Compose file.
SSO requires Compose 2.20.2 or newer. `./krate auth apply` validates the
installation and reconciles only the identity/UI services, using locally loaded
images. Keycloak and PostgreSQL are included in both offline packages even when
the SSO profile is inactive.
See the [IAM configuration guide](sso/guides/pingfederate-iam-guide.md) and
[operator setup guide](sso/guides/dual-login.md).

For this checkout, build the customized image with `make kafbat-ui ARCH=amd64`
before starting or bundling EPC or KRaft; see the [build notes](kafbat-ui/README.md).
The resulting offline bundles include that image. EPC packages include SSO from
`epc-v2`; KRaft packages include it from the first `package-kraft-vN` release.

## Monitoring

Krate and EPC each include monitoring files in their package. Prometheus collects measurements and evaluates alert rules, and a host exporter supplies disk, CPU, and memory measurements. Fluent Bit collects container logs. Two dashboard and alerting paths run side by side: Grafana with Loki and Grafana email, and Perses (HTTPS) with VictoriaLogs and Alertmanager email. See the [monitoring guide](monitoring/README.md).

Before starting it, copy `monitoring/.env.template` to `monitoring/.env`, change the Grafana login and set `PERSES_ADMIN_PASSWORD`. Perses uses the cluster certificate in `certs/`. From inside an extracted package, `monitoring/` is beside `krate`; in the repository, it is at the root. With the cluster already running:

```bash
./krate monitor up
./krate monitor status
./krate monitor ui
```

The default Grafana address uses port `3000`; Perses uses HTTPS on `3443`, Prometheus uses `9090` and Loki uses `3100`. Email alerts require your own mail server and recipients; they are off by default. When enabled, Grafana and Alertmanager both send them. Perses supports company SSO with native IdP-group roles; see the [Perses SSO guide](sso/guides/perses-sso.md).

ZooKeeper has its own smaller stack: Kafka measurements, Prometheus, and Grafana, started with `./kafka monitor up`. It does not include Loki or host measurements.

## How the parts fit together

A connected machine prepares the package. The target VM runs the containers from that package:

```mermaid
flowchart LR
    Build["Connected machine"] --> Package["Package + checksum"]
    Package --> VM["Target VM"]
    VM --> Brokers["Kafka brokers"]
    Apps["Your applications"] -->|messages| Brokers
    Browser["Your browser"] -->|HTTPS| Proxy["nginx proxy"]
    Proxy --> UI["Kafbat UI"]
    UI --> Brokers
    Brokers --- Data["Stored message data"]
```

KRaft's four containers each handle messages and participate in cluster coordination. ZooKeeper handles coordination in a separate container. EPC uses two combined broker/coordination containers. KRaft and ZooKeeper store data in Docker volumes; EPC uses host directories under `/data` by default.

### Repository layout

```text
kraft/       Four-broker KRaft setup and krate command script
zk/          Frozen ZooKeeper setup and kafka command script
epc/         Two-broker RHEL setup and krate command script
monitoring/  Shared KRaft/EPC dashboards, alerts, and log collection
docker/      Broker image definitions: release and debug versions
sso/         SSO activation helpers and operator guides
kafbat-ui/   Customized Kafbat UI build for shared login and SSO
Makefile     Package builds and source checks
```

Separate KRaft and ZooKeeper image release workflows build regular and diagnostic images for both processors. The default setup still uses the upstream Kafka images selected in each edition's `.env.template`; the release workflow requires an edition-specific tag before publishing to GHCR, GitHub's container registry.

### Release an offline install package

The [package release workflow](.github/workflows/package-release.yml) runs `scripts/package-release.sh`. That script builds the Kafbat UI image, prepares the Docker packages, builds the package and writes the release files to `dist/release/package-<edition>-vN/`. Run the same script locally first, and start the workflow only after the local package installs:

```bash
# macOS: MAKE=gmake; Node 22 recommended
scripts/package-release.sh kraft v2 amd64        # Docker packages: noble for kraft, rhel9 for epc
scripts/package-release.sh epc v3 amd64 none     # without Docker packages
```

Then start **Release offline install packages** from `main` in GitHub Actions with the same edition, version, processor and Docker package choice. The workflow creates the `package-<edition>-vN` tag and refuses a version that already exists. For EPC, it also refuses a version already released under the earlier `epc-vN` tags. Broker image releases use the separate [broker release workflow](.github/workflows/broker-release.yml) and `kraft-v*`/`zk-v*` tags.

## Limits to understand

- **One host is one point of failure.** Multiple brokers on the same VM do not protect against losing that VM. EPC also needs both of its coordination nodes available; losing either prevents its two-node group from reaching agreement.
- **Remote application connections need configuration.** KRaft and ZooKeeper advertise `localhost` on ports `19092–19095` by default. Change their Compose listener settings for clients on other machines. EPC uses `KAFKA_ADVERTISED_HOST` and host ports `9092/9093`.
- **HTTPS protects the UI only.** The Kafka listeners use plaintext, without client authentication. The monitoring web endpoints use HTTP. Restrict access or add the protection your deployment needs.
- **Disk use grows with messages and topics.** EPC limits how much data each part of a topic can keep and requires topics to be created explicitly by default.
- **Host checks still matter.** A valid package and healthy containers do not verify your network, remote clients, storage capacity, or email delivery. Follow the relevant runbook on the target VM.

## Development and checks

From the repository root:

```bash
make help
make check
```

`make check` checks Bash syntax, runs ShellCheck, and validates the Compose files. It needs GNU Make, Bash, ShellCheck, and the Docker Compose plugin. On macOS, run `gmake check`. `make test` and `make validate` are aliases for these same checks; they do not start a cluster.

The [broker CI workflow](.github/workflows/broker-ci.yml) separately builds the broker images and checks message delivery on GitHub Actions. Use the installation and operations guides for checks on your target host.

Keep contributions focused, work on a separate branch, and describe the checks run in the pull request. Keep local test scripts and validation output out of commits.

## Component credits

Krate uses the projects below. Credit belongs to their owners, maintainers, and contributors; each project has its own license and notices.

| Component | Credit | Used for |
| --- | --- | --- |
| [Apache Kafka](https://kafka.apache.org/) and [ZooKeeper](https://zookeeper.apache.org/) | Apache Software Foundation and project contributors | Message handling and legacy cluster coordination |
| [Confluent container images](https://github.com/confluentinc/cp-docker-images) | Confluent and contributors | Kafka and ZooKeeper images in the legacy edition |
| [Docker Engine](https://www.docker.com/), [Compose](https://github.com/docker/compose), and [Buildx](https://github.com/docker/buildx) | Docker and project contributors | Running containers and building broker images |
| [containerd](https://containerd.io/) | containerd maintainers and contributors; a CNCF project | Container runtime included with the Docker packages |
| [Kafbat UI](https://github.com/kafbat/kafka-ui) | Kafbat and contributors | Browser interface for Kafka. KRaft and EPC ship a modified v1.5.0 build that adds the SSO button; the image contains the upstream license, notice, and patches. See the [build notes](kafbat-ui/README.md). |
| [Eclipse Temurin](https://adoptium.net/) | Eclipse Adoptium Working Group and OpenJDK contributors | Java runtime of the KRaft and EPC Kafbat UI image |
| [Keycloak](https://github.com/keycloak/keycloak) | Keycloak project and contributors; a CNCF project | SSO connection between Kafbat and the company identity provider |
| [PostgreSQL](https://www.postgresql.org/) | PostgreSQL Global Development Group | Keycloak data storage |
| [nginx](https://github.com/nginx/nginx) | NGINX authors, F5, and contributors | HTTPS access to the UI |
| [Kafka Exporter](https://github.com/danielqsj/kafka_exporter) | danielqsj and contributors | Kafka measurements |
| [Prometheus](https://prometheus.io/) and [Node Exporter](https://github.com/prometheus/node_exporter) | Prometheus maintainers and contributors; a CNCF project | Kafka and host measurements |
| [Grafana](https://github.com/grafana/grafana), [Loki and Promtail](https://github.com/grafana/loki) | Grafana Labs and contributors | Dashboards and alerts; Promtail remains in the frozen ZooKeeper edition |
| [Perses](https://github.com/perses/perses) and its [plugins](https://github.com/perses/plugins) | The Perses Authors | Parallel dashboards |
| [VictoriaLogs](https://github.com/VictoriaMetrics/VictoriaLogs) | VictoriaMetrics and contributors | Parallel log storage |
| [Alertmanager](https://github.com/prometheus/alertmanager) | Prometheus maintainers and contributors | Parallel alert email |
| [OAuth2 Proxy](https://github.com/oauth2-proxy/oauth2-proxy) | OAuth2 Proxy maintainers and contributors | SSO session for Perses |
| [Fluent Bit](https://github.com/fluent/fluent-bit), [dkjson](https://dkolf.de/dkjson-lua/) and [Python](https://www.python.org/) | Fluent Bit contributors, David Heiko Kolf, and the Python Software Foundation/contributors | Shared KRaft/EPC container log collection and metadata discovery; see [monitoring transition and notices](monitoring/README.md) |
| [Ubuntu](https://ubuntu.com/) | Canonical and the Ubuntu community | Ubuntu targets and Docker package preparation |
| [Red Hat Enterprise Linux](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux) | Red Hat and contributors | RHEL target for the EPC edition |
| [AlmaLinux](https://almalinux.org/) | AlmaLinux OS Foundation and community | Default container used to prepare RHEL packages |
| [Alpine Linux](https://www.alpinelinux.org/) | Alpine Linux contributors | Base system used by some upstream containers |
| [Bash](https://www.gnu.org/software/bash/) and [GNU Make](https://www.gnu.org/software/make/) | GNU project, Free Software Foundation, and contributors | Command scripts and package builds |
| [Git](https://git-scm.com/) | Git maintainers and contributors | Source checkout |
| [ShellCheck](https://github.com/koalaman/shellcheck) | koalaman and contributors | Shell script checks |
| [Python](https://www.python.org/psf/) | Python Software Foundation and contributors | Monitoring alert setup |
| [OpenSSL](https://openssl-library.org/) | OpenSSL project and contributors | UI certificate creation |
| [GitHub Actions and GHCR](https://github.com/features/actions) | GitHub | Automated checks and container publishing |

The diagnostic broker images also use [BIND](https://www.isc.org/bind/) (ISC), [curl](https://curl.se/) (curl project), [iproute2](https://wiki.linuxfoundation.org/networking/iproute2) (Linux networking contributors), [jq](https://jqlang.org/) (jqlang contributors), [OpenBSD netcat](https://www.openbsd.org/) (OpenBSD project) or [Ncat](https://nmap.org/ncat/) (Nmap project), [procps-ng](https://gitlab.com/procps-ng/procps) (procps-ng contributors), and [strace](https://strace.io/) (strace contributors).

## License

Krate is licensed under the [GNU Affero General Public License v3.0](LICENSE) (`AGPL-3.0-only`). If you modify Krate and let others use it over a network, you must offer them the source of your modified version.

The third-party software Krate runs and packages, listed under [Component credits](#component-credits), keeps its own license. Offline packages include `LICENSE`, `LICENSE-SOURCES.md` and the license and notice files for those components; see `monitoring/fluent-bit/vendor/` and `monitoring/perses/vendor/notices/`.

Each KRaft and EPC package release also carries the complete corresponding source of the copyleft components in its container images, as a `-sources.tar` asset; see [LICENSE-SOURCES.md](LICENSE-SOURCES.md).

**Exception: the frozen ZooKeeper edition.** Its upstream Confluent and Kafbat images contain six copyleft components whose source is not publicly available (two Azul Zulu JDKs, three old RHEL 8 packages and `confluent-docker-utils`). Krate does not rebuild those images, so a ZooKeeper package ships without the source of those six components. They are listed in [LICENSE-SOURCES.md](LICENSE-SOURCES.md#unresolved-components) and in every ZooKeeper source archive.

## Contributing and community conduct

See the [contributing guidelines](CONTRIBUTING.md) for setup, validation, and pull request expectations.

Participation in Krate is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing or joining project discussions.

<p align="right"><a href="#readme-top">Back to top</a></p>
