# Krate

Portable, offline-ready Kafka cluster packages for **x86_64 and ARM64** Ubuntu VMs. Pick up the bundle matching your VM's CPU on a connected machine, drop it on a VM, and have a running cluster in one command.

Two variants — choose based on your coordination layer preference:

| Variant | Coordination | Directory |
|---|---|---|
| `zk` | ZooKeeper | `zk/` |
| `kraft` | KRaft (no ZooKeeper) | `kraft/` |

Both include 4 brokers, 24 partitions per topic, and [Kafbat UI](https://github.com/kafbat/kafka-ui) for cluster visibility.

**Requirements:** Docker Engine ≥25.0.3 and Docker Compose ≥1.29.2 (`docker compose` plugin or standalone `docker-compose`)

**Architecture:** see [`docs/architecture.html`](docs/architecture.html) for the KRaft microarchitecture (producer, consumer, brokers, replication, quorum) and the operational/build planes.

---

## Quick Start (online machine)

```bash
# Test locally — no bundling needed
cd zk                        # or: cd kraft
cp .env.template .env
./krate gen-cert             # generate the self-signed TLS cert the proxy needs
docker compose up -d
```

Kafbat UI → `https://<hostname>/` (TLS-terminated by nginx; self-signed cert, so accept the browser warning). Set `KAFKA_UI_FQDN` in `.env` to control the cert's name.

---

## Building Offline Bundles

Run on any machine with Docker, GNU Make 4.0 or newer, and internet access. Bundles are **architecture-specific** — build one per target CPU (`amd64` for x86_64 VMs, `arm64` for ARM). `ARCH` defaults to the build host's architecture.

```bash
# Build both variants for a given arch
make bundle VERSION=v2 ARCH=amd64
make bundle VERSION=v2 ARCH=arm64

# Build one variant
make bundle VERSION=v2 ARCH=amd64 MODE=zk

# Skip re-pulling if images are already local (must match ARCH)
make bundle VERSION=v2 ARCH=arm64 NO_PULL=1

# Include Docker CE .deb packages for fully offline VM installs (per-arch)
make docker-debs UBUNTU_VERSION=noble ARCH=amd64
make bundle VERSION=v2 ARCH=amd64 INCLUDE_DOCKER=1
```

Set `UBUNTU_VERSION=jammy` for Ubuntu 22.04 targets or `UBUNTU_VERSION=noble` for Ubuntu 24.04 targets. The command replaces any existing Docker packages under `docker-offline/<arch>/`, so run the matching `bundle` command before preparing the same architecture for a different Ubuntu release.

Output lands in `dist/` (one set per arch):

```
dist/
├── kafka-zk-v5-amd64.tar.gz       (+ .sha256)
├── krate-kraft-v5-amd64.tar.gz    (+ .sha256)
├── kafka-zk-v5-arm64.tar.gz       (+ .sha256)
└── krate-kraft-v5-arm64.tar.gz    (+ .sha256)
```

> KRaft bundle (~720 MB) is smaller than ZK (~1.2 GB) since it doesn't need the ZooKeeper image.
> Pick the bundle matching the VM's CPU — `krate doctor` will flag an arch mismatch before install.

---

## Installing on the VM

The current [release](https://github.com/bso-d/kafka-offline-install-package/releases/latest) publishes the **ZooKeeper / amd64** bundle (`kafka-zk-v5-amd64.tar.gz`), for x86_64 Ubuntu VMs. Other variants/arches build from source — see [Other variants & architectures](#other-variants--architectures).

### Install the ZooKeeper bundle (amd64)

For an x86_64 VM (`uname -m` → `x86_64`):

```bash
# 1 — Download (on the VM, or transfer manually)
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-v5-amd64.tar.gz
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-v5-amd64.tar.gz.sha256

# 2 — Verify integrity
sha256sum -c kafka-zk-v5-amd64.tar.gz.sha256

# 3 — Extract
tar -xzf kafka-zk-v5-amd64.tar.gz
cd kafka-zk-v5-amd64

# 4 — Install
./kafka doctor             # preflight: ports, firewalld, Docker, architecture
./kafka docker-check       # verify Docker is ready
./kafka docker-install     # only if Docker isn't installed (bundle ships amd64 .debs)
./kafka install            # load images → configure → start cluster
```

Then open Kafbat UI at **`https://<fqdn>/`** (TLS-terminated by nginx; `kafka install` auto-generates a self-signed cert for `KAFKA_UI_FQDN`, so accept the browser warning or trust `certs/server.crt`). Credentials are in `.env` — change them with `kafka config set`. Run `kafka ui` to print the exact URL.

> `kafka doctor` runs automatically at the start of `kafka install`, so a port conflict, a firewalld `docker`-zone issue, or an architecture mismatch is caught before anything starts.

### EPC deployment (RHEL 9)

A tailored 2-broker deployment for RHEL 9 / x86_64 hosts, published separately as
[`epc-v1`](https://github.com/bso-d/Krate/releases/tag/epc-v1). It differs from the
baseline: 2 brokers on host ports **9092/9093**, RF 2 with `min.insync.replicas` 1,
broker data bind-mounted on **`/data`**, byte-capped retention, and an offline
Docker CE install from bundled **RPMs** rather than `.deb`s.

```bash
sha256sum -c kafka-epc-v1-amd64.tar.gz.sha256
tar -xzf kafka-epc-v1-amd64.tar.gz && cd kafka-epc-v1-amd64
./krate doctor && ./krate docker-install && ./krate install
```

Build it with `make bundle VERSION=vN MODE=epc ARCH=amd64 TARGET_OS=rhel9 INCLUDE_DOCKER=1`
(prepare packages first with `make docker-rpms RHEL_VERSION=9 ARCH=amd64`). Full
steps in [docs/epc-install-runbook.md](docs/epc-install-runbook.md).

> The published `epc-v1` asset predates the Krate rename, so it is named
> `kafka-epc-v1-amd64.tar.gz`; bundles built after it are `krate-<mode>-<version>-<arch>.tar.gz`.

### Other variants & architectures

The KRaft variant and arm64 builds aren't published in the current release, but build from source on a machine with Docker + internet:

```bash
make docker-debs UBUNTU_VERSION=noble ARCH=arm64
make bundle VERSION=v5 ARCH=arm64 INCLUDE_DOCKER=1        # arm64 ZK + KRaft
make docker-debs UBUNTU_VERSION=noble ARCH=amd64
make bundle VERSION=v5 ARCH=amd64 MODE=kraft INCLUDE_DOCKER=1
```

See [Building Offline Bundles](#building-offline-bundles) for details.

---

## `krate` CLI

The `krate` script in each bundle (and in `kraft/` / `epc/`) — the frozen ZooKeeper edition still ships it as `kafka` is a wrapper over `docker compose` with cluster-aware helpers.

```
krate install                   First-time setup: load images, configure, start
krate start                     Start all services
krate stop                      Stop all services (data preserved)
krate restart [service]         Restart all or a specific service
krate down                      Remove containers (volumes preserved)
krate status                    Show running service state
krate logs [-f] [service]       Show logs; -f to follow
krate health                    Health check of all services
krate lag                       Summary of all consumer group lag
krate lag <group>               Per-partition lag for a specific group
krate lag --topic <topic>       Lag filtered to a specific topic
krate ui                        Show Kafbat UI URL and credentials
krate config                    Show current .env config
krate config set KEY=VALUE      Set a config value
krate load-images               Load Docker images without starting
krate uninstall                 Remove containers (volumes kept)
krate uninstall --purge         Remove containers AND delete all data
krate doctor                    Preflight checks (ports, firewalld, Docker) before install
krate gen-cert                  (Re)generate the self-signed TLS cert for the UI
krate docker-check              Verify Docker installation
krate docker-install            Install Docker from bundled .deb packages
```

### Examples

```bash
krate install
krate logs -f kafka-92
krate lag
krate lag my-consumer-group
krate lag --topic payments
krate config set KAFKA_UI_USER=admin
krate health
krate uninstall --purge
```

---

## Cluster Configuration

Both variants use the same broker sizing:

| Setting | Value |
|---|---|
| Brokers | 4 (ports 9092–9095) |
| Default partitions | 24 |
| Replication factor | 3 |
| Min in-sync replicas | 2 |
| Log retention | 168 h (7 days) |
| Log segment size | 1 GB |

External client ports (host → broker): `19092–19095`

### ZooKeeper variant

```
zk-zookeeper   :2181
zk-broker-92   :9092  :19092
zk-broker-93   :9093  :19093
zk-broker-94   :9094  :19094
zk-broker-95   :9095  :19095
zk-kafbat      (internal only — fronted by zk-proxy)
zk-proxy       :443 (HTTPS UI)  :80 (→ redirects to 443)
```

### KRaft variant

Each broker runs in combined mode (broker + controller). Controller quorum is internal-only on ports 29092–29095.

```
krate-broker-92   :9092  :19092
krate-broker-93   :9093  :19093
krate-broker-94   :9094  :19094
krate-broker-95   :9095  :19095
krate-kafbat      (internal only — fronted by krate-proxy)
krate-proxy       :443 (HTTPS UI)  :80 (→ redirects to 443)
```

---

## Credentials & TLS

Kafbat UI login and the UI's hostname are configured via `.env` (not committed). Copy the template and edit before starting:

```bash
cp .env.template .env
# edit KAFKA_UI_USER, KAFKA_UI_PASSWORD, and KAFKA_UI_FQDN
```

Or use the CLI:

```bash
krate config set KAFKA_UI_USER=admin
krate config set KAFKA_UI_PASSWORD=yourpassword
krate config set KAFKA_UI_FQDN=kafka.internal.example
```

The UI is served over **HTTPS** by the nginx proxy (HTTP on :80 redirects to :443). `krate install` auto-generates a **self-signed** cert with `KAFKA_UI_FQDN` (falling back to the host's FQDN) as the CN/SAN. To use your own cert instead, drop it in as `certs/server.crt` + `certs/server.key` and `krate restart proxy`. Regenerate the self-signed one anytime with `krate gen-cert`.

---

## Offline Docker Install

If Docker is not installed or not working on the VM, build a bundle that includes Docker CE packages. Choose the `UBUNTU_VERSION` and `ARCH` that match the target VM. Package versions are not pinned: `docker-debs` downloads the current candidate versions from Docker's APT repository at build time.

```bash
# On the connected machine (downloads current candidates for the target Ubuntu release and arch)
make docker-debs UBUNTU_VERSION=noble ARCH=amd64   # or ARCH=arm64

make bundle VERSION=v5 ARCH=amd64 INCLUDE_DOCKER=1
```

On the VM:

```bash
./krate docker-install   # installs containerd, docker-ce, docker-compose-plugin
./krate install
```

If Docker ≥25.0.3 is already installed with the legacy `docker-compose` (v1 ≥1.29.2), `krate install` will use it automatically — no reinstall needed.

---

## Repository Layout

```
├── zk/
│   ├── docker-compose.yml    ZooKeeper + Kafka + Kafbat
│   ├── .env.template
│   └── kafka                 CLI tool
├── kraft/
│   ├── docker-compose.yml    KRaft + Kafka + Kafbat
│   ├── .env.template
│   └── kafka                 CLI tool
├── Makefile                  Build, validation, and image-transfer workflow
└── docs/
    └── architecture.html     Microarchitecture + operational/build diagrams
```


## Monitoring and pre-merge tests

KRaft and EPC bundles include kafka-exporter, node-exporter, Prometheus, Loki,
promtail, and Grafana. With Python 3 installed on the host, start the cluster
and run `./krate monitor up`. SMTP is opt-in; recipients and notification rules
are editable in Grafana. See the [Phase 2 runbook](docs/phase-2-runbook.md).

Each phase stays on its own branch until `make check`, `make test`, and
`make test-bundle` pass. The test target now exercises a real disposable cluster
and local alert-email delivery; it is no longer an alias for static checks.
Use `gmake` on macOS.
