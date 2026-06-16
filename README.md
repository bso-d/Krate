# kafka-offline-install-package

Portable, offline-ready Kafka cluster packages for **x86_64 and ARM64** Ubuntu VMs. Pick up the bundle matching your VM's CPU on a connected machine, drop it on a VM, and have a running cluster in one command.

Two variants — choose based on your coordination layer preference:

| Variant | Coordination | Directory |
|---|---|---|
| `zk` | ZooKeeper | `zk/` |
| `kraft` | KRaft (no ZooKeeper) | `kraft/` |

Both include 4 brokers, 24 partitions per topic, and [Kafbat UI](https://github.com/kafbat/kafka-ui) for cluster visibility.

**Requirements:** Docker Engine ≥25.0.3 and Docker Compose ≥1.29.2 (`docker compose` plugin or standalone `docker-compose`)

---

## Quick Start (online machine)

```bash
# Test locally — no bundling needed
cd zk                        # or: cd kraft
cp .env.template .env
./kafka gen-cert             # generate the self-signed TLS cert the proxy needs
docker compose up -d
```

Kafbat UI → `https://<hostname>/` (TLS-terminated by nginx; self-signed cert, so accept the browser warning). Set `KAFKA_UI_FQDN` in `.env` to control the cert's name.

---

## Building Offline Bundles

Run on any machine with Docker and internet access. Bundles are **architecture-specific** — build one per target CPU (`amd64` for x86_64 VMs, `arm64` for ARM). `--arch` defaults to the build host's architecture.

```bash
# Build both variants for a given arch
./make-bundle.sh --version v2 --arch amd64
./make-bundle.sh --version v2 --arch arm64

# Build one variant
./make-bundle.sh --version v2 --arch amd64 --mode zk

# Skip re-pulling if images are already local (must match --arch)
./make-bundle.sh --version v2 --arch arm64 --no-pull

# Include Docker CE .deb packages for fully offline VM installs (per-arch)
./download-docker-debs.sh --ubuntu-version noble --arch amd64
./make-bundle.sh --version v2 --arch amd64 --include-docker
```

Output lands in `dist/` (one set per arch):

```
dist/
├── kafka-zk-v4-amd64.tar.gz       (+ .sha256)
├── kafka-kraft-v4-amd64.tar.gz    (+ .sha256)
├── kafka-zk-v4-arm64.tar.gz       (+ .sha256)
└── kafka-kraft-v4-arm64.tar.gz    (+ .sha256)
```

> KRaft bundle (~720 MB) is smaller than ZK (~1.2 GB) since it doesn't need the ZooKeeper image.
> Pick the bundle matching the VM's CPU — `kafka doctor` will flag an arch mismatch before install.

---

## Installing on the VM

The current [release](https://github.com/bso-d/kafka-offline-install-package/releases/latest) publishes the **ZooKeeper / amd64** bundle (`kafka-zk-v4-amd64.tar.gz`), for x86_64 Ubuntu VMs. Other variants/arches build from source — see [Other variants & architectures](#other-variants--architectures).

### Install the ZooKeeper bundle (amd64)

For an x86_64 VM (`uname -m` → `x86_64`):

```bash
# 1 — Download (on the VM, or transfer manually)
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-v4-amd64.tar.gz
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-v4-amd64.tar.gz.sha256

# 2 — Verify integrity
sha256sum -c kafka-zk-v4-amd64.tar.gz.sha256

# 3 — Extract
tar -xzf kafka-zk-v4-amd64.tar.gz
cd kafka-zk-v4-amd64

# 4 — Install
./kafka doctor             # preflight: ports, firewalld, Docker, architecture
./kafka docker-check       # verify Docker is ready
./kafka docker-install     # only if Docker isn't installed (bundle ships amd64 .debs)
./kafka install            # load images → configure → start cluster
```

Then open Kafbat UI at **`https://<fqdn>/`** (TLS-terminated by nginx; `kafka install` auto-generates a self-signed cert for `KAFKA_UI_FQDN`, so accept the browser warning or trust `certs/server.crt`). Credentials are in `.env` — change them with `kafka config set`. Run `kafka ui` to print the exact URL.

> `kafka doctor` runs automatically at the start of `kafka install`, so a port conflict, a firewalld `docker`-zone issue, or an architecture mismatch is caught before anything starts.

### Other variants & architectures

The KRaft variant and arm64 builds aren't published in the current release, but build from source on a machine with Docker + internet:

```bash
./download-docker-debs.sh --ubuntu-version noble --arch arm64
./make-bundle.sh --version v4 --arch arm64 --include-docker        # arm64 ZK + KRaft
./make-bundle.sh --version v4 --arch amd64 --mode kraft --include-docker
```

See [Building Offline Bundles](#building-offline-bundles) for details.

---

## `kafka` CLI

The `kafka` script in each bundle (and in `zk/` / `kraft/`) is a wrapper over `docker compose` with cluster-aware helpers.

```
kafka install                   First-time setup: load images, configure, start
kafka start                     Start all services
kafka stop                      Stop all services (data preserved)
kafka restart [service]         Restart all or a specific service
kafka down                      Remove containers (volumes preserved)
kafka status                    Show running service state
kafka logs [-f] [service]       Show logs; -f to follow
kafka health                    Health check of all services
kafka lag                       Summary of all consumer group lag
kafka lag <group>               Per-partition lag for a specific group
kafka lag --topic <topic>       Lag filtered to a specific topic
kafka ui                        Show Kafbat UI URL and credentials
kafka config                    Show current .env config
kafka config set KEY=VALUE      Set a config value
kafka load-images               Load Docker images without starting
kafka uninstall                 Remove containers (volumes kept)
kafka uninstall --purge         Remove containers AND delete all data
kafka doctor                    Preflight checks (ports, firewalld, Docker) before install
kafka gen-cert                  (Re)generate the self-signed TLS cert for the UI
kafka docker-check              Verify Docker installation
kafka docker-install            Install Docker from bundled .deb packages
```

### Examples

```bash
kafka install
kafka logs -f kafka-92
kafka lag
kafka lag my-consumer-group
kafka lag --topic payments
kafka config set KAFKA_UI_USER=admin
kafka health
kafka uninstall --purge
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
kraft-broker-92   :9092  :19092
kraft-broker-93   :9093  :19093
kraft-broker-94   :9094  :19094
kraft-broker-95   :9095  :19095
kraft-kafbat      (internal only — fronted by kraft-proxy)
kraft-proxy       :443 (HTTPS UI)  :80 (→ redirects to 443)
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
kafka config set KAFKA_UI_USER=admin
kafka config set KAFKA_UI_PASSWORD=yourpassword
kafka config set KAFKA_UI_FQDN=kafka.internal.example
```

The UI is served over **HTTPS** by the nginx proxy (HTTP on :80 redirects to :443). `kafka install` auto-generates a **self-signed** cert with `KAFKA_UI_FQDN` (falling back to the host's FQDN) as the CN/SAN. To use your own cert instead, drop it in as `certs/server.crt` + `certs/server.key` and `kafka restart proxy`. Regenerate the self-signed one anytime with `kafka gen-cert`.

---

## Offline Docker Install

If Docker is not installed or not working on the VM, build a bundle that includes Docker CE packages (installs Docker Engine 29.5.3 + Compose plugin 5.1.4):

```bash
# On the connected machine (downloads .deb packages for the target arch via Docker)
./download-docker-debs.sh --ubuntu-version noble --arch amd64   # or --arch arm64

./make-bundle.sh --version v4 --arch amd64 --include-docker
```

On the VM:

```bash
./kafka docker-install   # installs containerd, docker-ce, docker-compose-plugin
./kafka install
```

If Docker ≥25.0.3 is already installed with the legacy `docker-compose` (v1 ≥1.29.2), `kafka install` will use it automatically — no reinstall needed.

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
├── make-bundle.sh            Builds tar.gz install bundles
├── download-docker-debs.sh   Downloads Docker .deb packages (amd64/arm64)
└── docker-compose.yml        Original multi-cluster reference setup
```

---

Built with [Claude](https://claude.ai) by Anthropic.
