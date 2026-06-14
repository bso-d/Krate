# Kafka Offline Install Package — Handoff Document

**Repo:** https://github.com/bso-d/kafka-offline-install-package  
**Current release:** v1.0.0 — bundles `kafka-zk-v3.tar.gz` and `kafka-kraft-v3.tar.gz`  
**Target VM:** ARM64 Ubuntu 24.04 (noble)

---

## What This Is

A portable, offline-installable Kafka cluster packaged as a self-contained tar.gz. You build the bundle on a machine with internet access, SCP it to an air-gapped or restricted VM, and run one command to start the cluster.

Two variants are maintained in parallel under `zk/` and `kraft/`:

| Variant | Coordination | Bundle |
|---|---|---|
| `zk` | Apache ZooKeeper (Confluent 7.6.1) | `kafka-zk-v3.tar.gz` |
| `kraft` | KRaft combined mode, no ZooKeeper | `kafka-kraft-v3.tar.gz` |

Both ship 4 brokers (IDs 92–95), 24 partitions per topic, replication factor 3, and Kafbat UI behind an nginx reverse proxy.

---

## Repository Layout

```
├── zk/
│   ├── docker-compose.yml      ZooKeeper + 4 brokers + Kafbat + nginx
│   ├── nginx.conf              Security headers proxy config
│   ├── .env.template           Credential + port template
│   └── kafka                   CLI tool (wrapper over docker compose)
├── kraft/
│   ├── docker-compose.yml      KRaft 4-broker combined mode + Kafbat + nginx
│   ├── nginx.conf              Security headers proxy config (identical to zk/)
│   ├── .env.template           Credential + port template
│   └── kafka                   CLI tool (identical logic to zk/kafka)
├── make-bundle.sh              Builds tar.gz bundles
├── download-docker-debs.sh     Downloads Docker ARM64 .deb packages offline
├── security-reports/           SAST/DAST scan outputs + HTML report
│   └── generate-report.py      Combines scan JSONs into one HTML report
└── README.md
```

Files in `.gitignore` (not committed, built locally):
- `dist/` — built tar.gz bundles
- `images/` — docker-saved .tar image files (staging)
- `docker-offline/` — Docker CE .deb packages
- `zk/.env`, `kraft/.env` — actual credentials

---

## Cluster Architecture

### ZooKeeper variant (`zk/`)

```
Host port   Container name    Role
─────────   ──────────────    ────
2181        zk-zookeeper      ZooKeeper ensemble (single node)
9092/19092  zk-broker-92      Broker 0   (INTERNAL/EXTERNAL listeners)
9093/19093  zk-broker-93      Broker 1
9094/19094  zk-broker-94      Broker 2
9095/19095  zk-broker-95      Broker 3
(internal)  zk-kafbat         Kafbat UI (port 8080 inside network only)
8080*       zk-proxy          nginx reverse proxy → Kafbat
```

Brokers use `/cluster1` ZooKeeper chroot so the ZK node can be shared.

### KRaft variant (`kraft/`)

```
Host port   Container name      Role
─────────   ──────────────      ────
9092/19092  kraft-broker-92     Broker+Controller (node ID 92)
9093/19093  kraft-broker-93     Broker+Controller (node ID 93)
9094/19094  kraft-broker-94     Broker+Controller (node ID 94)
9095/19095  kraft-broker-95     Broker+Controller (node ID 95)
(internal)  kraft-kafbat        Kafbat UI
8080*       kraft-proxy         nginx reverse proxy → Kafbat
```

Controller quorum uses internal ports 29092–29095 (not exposed to host).  
`CLUSTER_ID: 4GThRKJoQF2BmLyqAl4JlQ` — fixed, embedded in on-disk storage on first boot. **Do not change after first `kafka install`.**

`*` Port 8080 is the default — configurable via `KAFKA_UI_PORT` in `.env`.

### Listener model (both variants)

| Listener | Port | Purpose |
|---|---|---|
| `INTERNAL` | 9092–9095 | Inter-broker and Kafbat communication inside Docker network |
| `EXTERNAL` | 19092–19095 | Client access from host machine or external clients |
| `CONTROLLER` | 29092–29095 | KRaft quorum only (kraft variant, not host-exposed) |

### Broker sizing

| Setting | Value |
|---|---|
| Default partitions | 24 |
| Replication factor | 3 |
| Min in-sync replicas | 2 |
| Log retention | 168 h (7 days) |
| Log segment size | 1 GB |
| Log max size per container | 100 MB × 3 files |

---

## The `.env` File

Copied from `.env.template` on first install. Controls three things:

```bash
KAFKA_UI_USER=admin          # Kafbat UI login username
KAFKA_UI_PASSWORD=changeme   # Kafbat UI login password
KAFKA_UI_PORT=8080           # Host port for the nginx proxy
```

Set via CLI: `kafka config set KAFKA_UI_PORT=9090`  
Takes effect on next `kafka start` or `kafka restart proxy`.

---

## The `kafka` CLI

Lives at `zk/kafka` and `kraft/kafka`. Both are identical except `zk/kafka` lists `zookeeper` in the help services list.

### Compose binary detection

At startup the script detects which compose binary is available and stores it as a bash array `COMPOSE_BIN`. All `compose_cmd()` calls dispatch through this array — transparent to the user.

```bash
# Detection order (first found wins):
docker compose   →  COMPOSE_BIN=(docker compose)    # v2 plugin
docker-compose   →  COMPOSE_BIN=(docker-compose)    # v1 standalone
```

Minimum versions enforced by `kafka docker-check`:
- Docker Engine ≥ 25.0.3
- Compose ≥ 1.29.2 (v1 or v2)

### Commands

| Command | What it does |
|---|---|
| `kafka install` | Load images → copy .env → `docker compose up -d` |
| `kafka start` | `docker compose up -d` |
| `kafka stop` | Stop containers, preserve volumes |
| `kafka restart [svc]` | Restart all or one service |
| `kafka down` | Remove containers, preserve named volumes |
| `kafka status` | `docker compose ps` |
| `kafka logs [-f] [svc]` | Tail logs (100 lines default, 50 on follow) |
| `kafka health` | Per-container health status with colour |
| `kafka lag` | Summary of all consumer group lag |
| `kafka lag <group>` | Per-partition lag for one group |
| `kafka lag --topic <t>` | Filter lag by topic |
| `kafka ui` | Print URL + credentials from .env |
| `kafka config` | Show .env |
| `kafka config set K=V` | Write a key into .env |
| `kafka load-images` | Load .tar images without starting |
| `kafka uninstall` | Remove containers (volumes kept) |
| `kafka uninstall --purge` | Remove containers + delete all named volumes |
| `kafka docker-check` | Validate Docker version + daemon + compose |
| `kafka docker-install` | `dpkg -i` all .deb files from `docker-offline/` |

### `kafka lag` internals

Runs `kafka-consumer-groups.sh` inside the first running broker container via `docker exec`. Finds the broker by iterating `kafka-92` → `kafka-95` and checking container state.

---

## nginx Proxy

Both variants put Kafbat UI behind nginx (`nginx:1.27-alpine`). nginx is the only container with a host port for the UI. Kafbat has no host port.

**Why:** DAST scan (OWASP ZAP) found missing security headers on the raw Kafbat endpoint. nginx injects them:

- `Content-Security-Policy`
- `Permissions-Policy`
- `Cross-Origin-Resource-Policy: same-origin`
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

nginx also handles WebSocket upgrade headers (`Upgrade`, `Connection`) required by Kafbat's live-reload UI.

---

## Building Bundles

### Requirements (build machine)
- Docker running with internet access
- `make-bundle.sh` and `download-docker-debs.sh` in repo root

### Steps

```bash
# 1. Download Docker CE ARM64 .deb packages (one-time or when Docker version changes)
./download-docker-debs.sh --ubuntu-version noble

# 2. Build both bundles
./make-bundle.sh --version v4 --no-pull --include-docker

# Output:
# dist/kafka-zk-v4.tar.gz       ~1.1 GB
# dist/kafka-zk-v4.tar.gz.sha256
# dist/kafka-kraft-v4.tar.gz    ~730 MB
# dist/kafka-kraft-v4.tar.gz.sha256
```

`--no-pull` skips re-pulling images (use when images are already local).  
`--include-docker` bundles Docker CE 29.5.3 + Compose plugin 5.1.4 `.deb` files.  
`--version` is required — use the next vN after the last released bundle.

### What goes into each bundle

```
kafka-zk-v3/
├── docker-compose.yml
├── nginx.conf
├── .env.template
├── kafka                        CLI tool
├── images/
│   ├── confluentinc__cp-zookeeper_7.6.1.tar
│   ├── confluentinc__cp-kafka_7.6.1.tar
│   ├── kafbat__kafka-ui_latest.tar
│   └── nginx_1.27-alpine.tar
└── docker-offline/              (only with --include-docker)
    ├── containerd.io_*_arm64.deb
    ├── docker-ce_*_arm64.deb
    ├── docker-ce-cli_*_arm64.deb
    ├── docker-compose-plugin_*_arm64.deb
    └── install-docker.sh
```

### Uploading to GitHub Release

```bash
gh release upload v1.0.0 \
  dist/kafka-zk-v4.tar.gz dist/kafka-zk-v4.tar.gz.sha256 \
  dist/kafka-kraft-v4.tar.gz dist/kafka-kraft-v4.tar.gz.sha256 \
  --clobber

# Remove previous version assets
for a in kafka-zk-v3.tar.gz kafka-zk-v3.tar.gz.sha256 \
          kafka-kraft-v3.tar.gz kafka-kraft-v3.tar.gz.sha256; do
  gh release delete-asset v1.0.0 "$a" --yes
done
```

---

## Installing on the VM

```bash
# Download (or SCP the file manually)
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-v3.tar.gz
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-v3.tar.gz.sha256

# Verify
sha256sum -c kafka-zk-v3.tar.gz.sha256
```

> **Known sha256sum issue:** The `.sha256` file contains an absolute path from the build machine
> (e.g. `/Users/shoji/.../dist/kafka-zk-v3.tar.gz`). On the VM, run:
> ```bash
> sha256sum kafka-zk-v3.tar.gz | awk '{print $1}' > actual.sum
> grep -oE '[a-f0-9]{64}' kafka-zk-v3.tar.gz.sha256 > expected.sum
> diff actual.sum expected.sum && echo "OK" || echo "MISMATCH"
> ```
> **This needs to be fixed** in `make-bundle.sh` — see Known Issues below.

```bash
# Extract (macOS xattrs warning is harmless on Linux)
tar -xzf kafka-zk-v3.tar.gz
cd kafka-zk-v3

# Check Docker
./kafka docker-check

# Install Docker if needed (--include-docker bundle only)
./kafka docker-install

# Start cluster
./kafka install
```

---

## Known Issues & Next Actions

### 1. sha256sum path bug (HIGH — breaks verification on VM)

The `.sha256` file stores the full absolute path from the build machine:
```
abc123...  /Users/shoji/projects/.../dist/kafka-zk-v3.tar.gz
```
On the VM `sha256sum -c` fails because that path doesn't exist.

**Fix needed in `make-bundle.sh`:** Change the checksum generation to use a relative or bare filename:
```bash
# Current (broken on VM):
sha256sum "$out_file" > "${out_file}.sha256"

# Fixed:
(cd "$DIST_DIR" && sha256sum "${bundle_name}.tar.gz") > "${out_file}.sha256"
# or:
sha256sum "$out_file" | sed "s|.*/||" > "${out_file}.sha256"
```

### 2. NAT chain error on install (`INVALID_ZONE: docker`)

Observed on the target VM:
```
ERROR: Failed to program NAT chain: INVALID_ZONE: docker
```
This is a firewalld/iptables conflict. Docker 25.0.3 with Compose v1 tries to create a bridge network, and firewalld blocks iptables manipulation.

**Fix options (on VM):**
```bash
# Option A — add docker zone to firewalld
sudo firewall-cmd --permanent --zone=trusted --add-interface=docker0
sudo firewall-cmd --reload
sudo systemctl restart docker

# Option B — disable firewalld if not needed
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo systemctl restart docker

# Option C — use iptables backend instead of nftables
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
sudo systemctl restart docker
```

### 3. `tar` macOS xattr warnings (cosmetic)

```
tar: Ignoring unknown extended header keyword 'LIBARCHIVE.xattr.com.apple.provenance'
```
These come from macOS's tar adding Apple extended attributes. They are harmless — extraction completes correctly. No action needed, but can be eliminated by building bundles in a Linux environment or using `COPYFILE_DISABLE=1 tar ...` in `make-bundle.sh`.

Fix in `make-bundle.sh`:
```bash
# Current:
tar -czf "$out_file" -C "$DIST_DIR/staging" "$bundle_name"

# Fixed (suppresses macOS xattr metadata):
COPYFILE_DISABLE=1 tar -czf "$out_file" -C "$DIST_DIR/staging" "$bundle_name"
```

---

## Security

SAST scans run with shellcheck, hadolint, trivy, and gitleaks. DAST run with OWASP ZAP. Reports in `security-reports/`. All findings from the initial scan were resolved:

| Tool | Finding | Resolution |
|---|---|---|
| shellcheck SC2059 | `printf` with variable format string | Changed to `echo -e` |
| shellcheck SC2012 | `ls` used for counting | Changed to `find` |
| trivy DS-0002 | Dockerfile runs as root | Added non-root user in `visualizer/Dockerfile` |
| trivy DS-0026 | No HEALTHCHECK | Added wget HEALTHCHECK |
| ZAP WARN | Missing CSP / Permissions-Policy / CORP headers | Added nginx reverse proxy with full header set |

Credentials (`KAFKA_UI_USER`, `KAFKA_UI_PASSWORD`) are login-form auth enforced by Kafbat's Spring Security. Not TLS-terminated — suitable for internal/VM use, not public internet exposure.

---

## Docker Images Used

| Image | Version | Size |
|---|---|---|
| `confluentinc/cp-zookeeper` | 7.6.1 | ~500 MB |
| `confluentinc/cp-kafka` | 7.6.1 | ~800 MB |
| `kafbat/kafka-ui` | latest | ~300 MB |
| `nginx` | 1.27-alpine | ~15 MB |

Bundled Docker CE (noble ARM64):
- `containerd.io` 2.2.4
- `docker-ce` 29.5.3
- `docker-ce-cli` 29.5.3
- `docker-compose-plugin` 5.1.4

---

## Environment Compatibility

| Component | Minimum | Tested |
|---|---|---|
| Docker Engine | 25.0.3 | 25.0.3, 29.5.3 |
| Docker Compose | 1.29.2 | 1.29.2 (v1), 5.1.4 (v2 plugin) |
| Ubuntu | 22.04 (jammy) | 24.04 noble |
| Architecture | ARM64 | ARM64 |

The `kafka` CLI auto-detects `docker compose` (v2) or `docker-compose` (v1) at startup.

---

## What Is Not In The Bundle

- **TLS / HTTPS** — Kafka listeners are PLAINTEXT. For production, add SSL listener config and certificates.
- **Authentication** — Brokers use no SASL. Kafbat UI has form-based auth only.
- **Multi-node VM** — All 4 brokers run on a single VM. Not a multi-host setup.
- **Monitoring** — No Prometheus/Grafana. Kafbat provides basic lag/offset visibility.
- **Stream visualizer** — A React/Node topology visualizer previously lived in `visualizer/` and the root reference setup. It was never part of the shipped `zk/`/`kraft/` bundles and has been removed from the repo to keep the focus on the Kafka + ZooKeeper cluster.
