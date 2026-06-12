# kafka-offline-install-package

Portable, offline-ready Kafka cluster packages for ARM64 Ubuntu VMs. Pick up a bundle on a connected machine, drop it on a VM, and have a running cluster in one command.

Two variants — choose based on your coordination layer preference:

| Variant | Coordination | Directory |
|---|---|---|
| `zk` | ZooKeeper | `zk/` |
| `kraft` | KRaft (no ZooKeeper) | `kraft/` |

Both include 4 brokers, 24 partitions per topic, and [Kafbat UI](https://github.com/kafbat/kafka-ui) for cluster visibility.

---

## Quick Start (online machine)

```bash
# Test locally — no bundling needed
cd zk                        # or: cd kraft
cp .env.template .env
docker compose up -d
```

Kafbat UI → `http://localhost:8080`

---

## Building Offline Bundles

Run on any machine with Docker and internet access.

```bash
# Build both bundles
./make-bundle.sh

# Build one variant
./make-bundle.sh --mode zk
./make-bundle.sh --mode kraft

# Skip re-pulling if images are already local
./make-bundle.sh --no-pull

# Include Docker CE .deb packages for fully offline VM installs
./download-docker-debs.sh
./make-bundle.sh --include-docker
```

Output lands in `dist/`:

```
dist/
├── kafka-zk-bundle-YYYYMMDD.tar.gz
├── kafka-zk-bundle-YYYYMMDD.tar.gz.sha256
├── kafka-kraft-bundle-YYYYMMDD.tar.gz
└── kafka-kraft-bundle-YYYYMMDD.tar.gz.sha256
```

> KRaft bundle (~650 MB) is smaller than ZK (~1 GB) since it doesn't need the ZooKeeper image.

---

## Installing on the VM

Pre-built bundles are available on the [Releases](https://github.com/bso-d/kafka-offline-install-package/releases/latest) page.

**Step 1 — Download the bundle (on the VM or transfer manually)**

Use the `--include-docker` bundles (`20260612`) — they contain Docker CE 29.5.3 + Compose Plugin 5.1.4 for Ubuntu 24.04 noble ARM64 so the cluster is fully self-contained.

```bash
# ZooKeeper variant
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-bundle-20260612.tar.gz
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-bundle-20260612.tar.gz.sha256

# KRaft variant
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-kraft-bundle-20260612.tar.gz
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-kraft-bundle-20260612.tar.gz.sha256
```

**Step 2 — Verify integrity**

```bash
sha256sum -c kafka-zk-bundle-20260612.tar.gz.sha256
```

**Step 3 — Extract**

```bash
tar -xzf kafka-zk-bundle-20260612.tar.gz
cd kafka-zk-bundle-20260612
```

**Step 4 — Install**

```bash
./kafka docker-check       # verify Docker is ready
./kafka docker-install     # only if Docker isn't working (needs --include-docker bundle)
./kafka install            # load images → configure → start cluster
```

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
zk-kafbat      :8080
```

### KRaft variant

Each broker runs in combined mode (broker + controller). Controller quorum is internal-only on ports 29092–29095.

```
kraft-broker-92   :9092  :19092
kraft-broker-93   :9093  :19093
kraft-broker-94   :9094  :19094
kraft-broker-95   :9095  :19095
kraft-kafbat      :8080
```

---

## Credentials

Kafbat UI login is configured via `.env` (not committed). Copy the template and edit before starting:

```bash
cp .env.template .env
# edit KAFKA_UI_USER and KAFKA_UI_PASSWORD
```

Or use the CLI:

```bash
kafka config set KAFKA_UI_USER=admin
kafka config set KAFKA_UI_PASSWORD=yourpassword
```

---

## Offline Docker Install

If Docker is not installed or not working on the VM, build a bundle that includes Docker CE packages:

```bash
# On the connected machine (downloads ARM64 .deb packages via Docker)
./download-docker-debs.sh --ubuntu-version noble   # Ubuntu 24.04 (target)

./make-bundle.sh --no-pull --include-docker
```

On the VM:

```bash
./kafka docker-install   # installs containerd, docker-ce, docker-compose-plugin
./kafka install
```

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
├── download-docker-debs.sh   Downloads Docker ARM64 .deb packages
└── docker-compose.yml        Original multi-cluster reference setup
```

---

Built with [Claude](https://claude.ai) by Anthropic.
