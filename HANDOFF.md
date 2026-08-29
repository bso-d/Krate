# Kafka Offline Install Package — Handoff Document

**Repo:** https://github.com/bso-d/kafka-offline-install-package  
**Current release:** v1.0.0 — arch-suffixed bundles `kafka-{zk,kraft}-v5-{amd64,arm64}.tar.gz`  
**Target VM:** Ubuntu 24.04 (noble), x86_64 or ARM64 — pick the matching bundle

---

## Session Log — 2026-08-29

Phase 1 merged; target VMs turned out to be RHEL, which forced a new variant and
RHEL packaging support. Work is on `epc-rhel-2broker`.

### 1. Phase 1 landed
PR #11 squash-merged as `05ddd5c`. Last blocker before merge was a floating
`kafbat/kafka-ui:latest` in the ZooKeeper edition (`zk/docker-compose.yml` and
the Makefile's `ZK_IMAGES`); pinned to `v1.5.0` to match KRaft. ZK stays frozen —
this counted as a reproducibility/security fix, not a feature.

### 2. Target VM survey — the VMs are RHEL, not Ubuntu
Surveyed `epc-appkfk-03` (Hyper-V guest, `10.100.178.54`):
**RHEL 9.6, x86_64, 8 cores, 62 GB RAM, no Docker installed.** All 10 host ports
free, no firewalld/ufw, passwordless sudo, openssl present.

That invalidated the packaging half of the plan: the offline Docker path was
Ubuntu-only end to end — `make docker-debs` (jammy/noble, downloads inside an
`ubuntu:` container), the `.deb` files, `kafka docker-install` (`dpkg -i` +
`apt-get install -f`), and the generated `install-docker.sh`. Decision: **option
B — add RHEL support** rather than install Docker out of band.

Two RHEL-specific risks surfaced:
- **SELinux** is enforcing on RHEL 9; the proxy's `nginx.conf`/`certs` bind
  mounts carried no `:z`/`:Z` label and would have failed with permission denied.
- **Disk is tight** — 15.1 GB free on `/var/lib`, 13.4 GB on `$HOME`, which is
  why the install was moved to the `/data` disk.

### 3. New `epc/` variant (2 brokers, host ports 9092/9093, /data)
A third variant alongside `zk/` and `kraft/`, shipped as its own release
(`MODE=epc`). Requirements came from the EPC install:
- **2 brokers** (node ids 92/93), one independent cluster per VM.
- **Host ports 9092/9093** — the 190xx range is gone. EXTERNAL binds container
  9092/9093 and is published 1:1; INTERNAL moved to 19092/19093 (container-only,
  inter-broker); CONTROLLER stays 29092/29093.
- **RF=2, min.insync.replicas=1** so a single broker outage does not stop
  producers. `KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR`,
  `KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR` (both 2) and
  `KAFKA_TRANSACTION_STATE_LOG_MIN_ISR` (1) had to be set explicitly — their
  defaults of 3/2 are unsatisfiable on 2 brokers and would have broken
  `__consumer_offsets` creation. The 4-broker `kraft/` config never set them.
- **Data on `/data`** — broker logs are bind mounts
  (`${KAFKA_DATA_DIR:-/data}/krate/broker-{92,93}`) with `:Z`, not named volumes
  under `/var/lib/docker`. Bind mounts keep host ownership, so `epc/kafka` gained
  `ensure_data_dirs()` to create them and chown to `KAFKA_UID:KAFKA_GID` (1000)
  before start — without it the broker exits unable to write its log dir.
- `KAFKA_ADVERTISED_HOST` added: EXTERNAL advertised `localhost` only works for
  on-box clients, so it must be set to the FQDN/IP before remote clients connect.

**Caveat recorded deliberately:** with 2 combined nodes the controller quorum is
2, so a majority is both. Losing either node stops the cluster regardless of
RF=2/minISR=1. Accepted — both nodes share one VM, so they share a failure
domain. Splitting out 3 dedicated controllers is the fix if that changes.

### 4. RHEL packaging (`make docker-rpms`)
- `docker-rpms RHEL_VERSION=9 ARCH=amd64` downloads
  `containerd.io docker-ce docker-ce-cli docker-compose-plugin docker-buildx-plugin`
  (+ deps via `dnf download --resolve`) inside an `almalinux:9` builder, from
  `https://download.docker.com/linux/rhel/9/<rpm_arch>/stable` (verified live,
  both x86_64 and aarch64). Generates an rpm-flavoured `install-docker.sh` using
  `dnf install --disablerepo='*'` so it stays strictly offline.
- `kafka docker-install` now detects `.rpm` vs `.deb` and dispatches to
  `docker_install_rpm` / `docker_install_deb`; refuses to guess if both are
  present. The rpm failure message calls out `container-selinux`, the dependency
  a minimal RHEL host most often lacks.
- **Package layout changed** to `docker-offline/<target-os>/<arch>/`
  (`noble/amd64`, `rhel9/amd64`, …) so several targets can be staged at once —
  previously `docker-debs` wiped the arch dir on every run. Existing noble sets
  were migrated in place.
- Every prepared set now carries a `.docker-manifest` (OS_TARGET, OS_FAMILY,
  ARCH, packages) and `bundle INCLUDE_DOCKER=1` **refuses** to ship a set whose
  manifest does not match `TARGET_OS`/`ARCH`. Prevents a noble deb set landing in
  a RHEL bundle and failing on the VM long after the build.

### 5. Disk ceiling on /data (1000 GB, both VMs)
`/data` is 1000 GB on each VM and must not be run to the limit. Two facts drive
the sizing: both brokers write to the **same** disk, and RF=2 means every record
is stored twice — so `/data` holds **2x the logical data**. Time-based retention
alone cannot bound that; a traffic spike fills the disk long before 168 h elapses.

- Added `KAFKA_LOG_RETENTION_BYTES` (default **2 GiB**, per partition replica) so
  whichever limit is hit first — time or bytes — triggers deletion.
- The real ceiling is `topics x partitions x RF x cap`. At 24 partitions and the
  2 GiB default that is **~96 GB of /data per topic**, so a 60 % budget
  (600 GB) covers about **6 topics**. The table is in `epc/.env.template`.
- `KAFKA_DATA_BUDGET_PCT` (default 60) plus a new **`./kafka disk`** command
  reports actual per-broker usage, the share of the disk used, and how many
  topics the current settings still allow. `ensure_data_dirs` warns below 50 GB
  free.
- `auto.create.topics.enable` is now a knob, **default `false`**, so the ceiling
  above actually holds — clients cannot silently add topics and disk. Explicit
  creation is unaffected: the Kafbat UI, `kafka-topics.sh` and any AdminClient
  use the CreateTopics API, which this setting does not govern, and Kafka's
  internal topics (`__consumer_offsets`, `__transaction_state`) are created
  regardless. Set `KAFKA_AUTO_CREATE_TOPICS_ENABLE=true` if a producer needs to
  write to a topic that does not exist yet. **Unverified at runtime** — the UI
  create path has not been exercised, since nothing has been booted.

### 6. CLI renamed to `krate` (EPC only)
The EPC bundle ships its CLI as **`./krate`** (`./krate status`, `./krate disk`,
…) rather than `./kafka`. `epc/kafka` → `epc/krate`, all self-referential usage
strings updated, and `bundle` picks the CLI filename per mode. `zk/` and
`kraft/` still ship `./kafka` — zk is frozen, and renaming kraft would churn the
just-merged Phase 1 docs. Worth unifying if the kraft edition is ever released.

### 7. First EPC bundle built — `dist/kafka-epc-v1-amd64.tar.gz` (528 MB)
Docker came up on the build machine, so the RHEL path was exercised end to end.

- **`make docker-rpms RHEL_VERSION=9 ARCH=amd64`** — ships `docker-ce 29.7.2`,
  `docker-ce-cli`, `docker-ce-rootless-extras`, `containerd.io 2.3.4`,
  `docker-compose-plugin 5.5.0`, `docker-buildx-plugin 0.36.1` (all from
  download.docker.com) plus `container-selinux 2.245.0`. 106 MB.
- **`make bundle VERSION=v1 MODE=epc ARCH=amd64 TARGET_OS=rhel9 INCLUDE_DOCKER=1`**
  → 528 MB, sha256 sidecar verifies.

Two problems found and fixed during the build:

1. **AlmaLinux base packages leaked into the RPM set.** The first `docker-rpms`
   run resolved dependencies inside a minimal `almalinux:9` builder, so dnf
   treated base OS packages as missing and downloaded AlmaLinux builds of
   `selinux-policy`/`selinux-policy-targeted` (at **el9_8**, against a 9.6
   target), `policycoreutils`, `nftables`, `iptables-nft` and their libs.
   Installing that on the VMs would have replaced Red Hat's own SELinux policy
   during a Docker install. Fixed by pre-installing those base packages in the
   builder so `--resolve` only fetches what a real RHEL host genuinely lacks.
2. **The generated RPM `install-docker.sh` was mangled by Make.** It was written
   with single `$` inside a quoted heredoc, so Make expanded the variables before
   bash saw them (`$installer` → `$i` + `nstaller`; `$SCRIPT_DIR` → `CRIPT_DIR`).
   `docker-debs`' heredoc had always used `$$`. Now escaped; the regenerated
   script is shellcheck-clean. Note `make check` does **not** cover generated
   artifacts — only the three CLIs — so this class of bug needs a bundle-level
   check to catch automatically.

Bundle verified after rebuild: sha256 OK; all three images are genuinely
**amd64/linux** inside the tarball (`docker save --platform` did its job on an
arm64 build host — `docker image inspect` still reports arm64 for a
multi-platform tag, so **`NO_PULL=1` must not be used** for cross-arch builds);
CLI ships as `./krate`; `.bundle-arch` = amd64; and `./krate doctor` correctly
refused to run on the arm64 build machine with "bundle is amd64 but this host is
arm64", proving the arch guard works.

### 8. Not done yet
- [x] Bundle **built** (see 7). Still **never booted** — the cluster has not run
      anywhere, so first boot on a VM is the real gate: KRaft quorum forming with
      2 voters, the `/data` bind mounts under SELinux, the offline
      `krate docker-install`, and creating a topic from the UI with
      auto-creation off.
- [x] `/data` sized — 1000 GB on both VMs; byte cap and budget added (see 5).
- [ ] VM2 confirmed **RHEL 9.6 / x86_64**, same as `-03`, so one
      `rhel9/amd64` bundle serves both. Neither has been surveyed post-change.
- [ ] EPC release version/tag not chosen; `README` still documents zk/kraft only
      and does not mention `./krate` or the `epc` mode.
- [ ] A throwaway VM survey script lives at repo root (`vm-survey.sh`,
      `vm-survey.mk`) — interim tooling, deliberately untracked.

---

## Session Log — 2026-07-14

Planning + docs session on `shoji-dev`. No runtime code changed. Reconciled the
handoff against git, authored the forward roadmap, and produced an architecture
reference.

### 1. State reconciliation (handoff vs. git)
The prior handoff's "Branch/PR state" / "Open items" were inaccurate:
- The KRaft mirror fixes are **not** uncommitted on `shoji-dev` (tree clean; both
  `kraft/kafka` and `kraft/docker-compose.yml` still carry the buggy `.sh` /
  `localhost` forms — `zk/` on `shoji-dev` is buggy too). The fixes live once,
  inside an **unpushed local WIP `d4a8e21`** on the local `zk-freeze` head, mixed
  with a root `monitoring/` scaffold. `origin/zk-freeze` = `983e1fa`, so PR #10 is
  unaffected. Decision: leave `zk-freeze`/PR #10 frozen; all forward KRaft work on
  `shoji-dev`.
- Nuance for the image refactor: on `apache/kafka` the CLI scripts keep the `.sh`
  suffix, so `kraft/kafka`'s current `kafka-consumer-groups.sh` is **correct** for
  Apache — the Confluent-era "fix" reverses under Phase 1.

### 2. Development roadmap agreed
No written roadmap existed before this session (verified across disk/all
refs/reflog/stashes). One was laid out for KRaft: 4 guiding principles (Makefile-driven, KRaft-only,
offline-first, single source of truth) + 5 phases — (1) Confluent→`apache/kafka`
image refactor [also the licensing prerequisite: `cp-kafka` is Confluent Community
License, `apache/kafka` is Apache-2.0], (2) KRaft observability + email alerting
(metrics + logs + Grafana Alerting; phone/Twilio dropped), (3) cluster configurator
(sizes every README "Cluster Configuration" field, front door to the build) +
benchmarking, (4) Apache-2.0 licensing (Grafana/Loki are AGPLv3 — aggregation
only), (5) Kubernetes (last). New capabilities ship as standalone scripts + Make
targets.

### 3. Architecture reference — `docs/architecture.html`
Self-contained, theme-aware HTML with two SVG diagrams (linked from `README.md`):
- **Runtime microarchitecture** — producer → P0 leader (`broker-92`) →
  replicate to ISR followers (`broker-93/94`, RF 3, min ISR 2) over INTERNAL
  :9092–9095; consumer group reads from the leader; all 4 nodes are
  broker+controller and vote in the KRaft Raft quorum (`__cluster_metadata`,
  :29092–29095); host clients bootstrap via EXTERNAL :19092–19095.
- **Operational & build planes** — configurator → `.env` (single source of truth)
  → Makefile/CLI → cluster; benchmark drives + recalibrates; kafka-exporter +
  promtail → Prometheus/Loki → Grafana → email; Docker/VM today, K8s planned.
  Solid = today, dashed = planned phase.

#### Prompt / thinking / response (per request, for the record)
- **Prompt:** "Based on the current state & future intended phases, draw a detailed
  microarchitecture diagram depicting the internals of this system including
  producer & consumer." (then: HTML reference in `docs/`, link from README, log
  this in the handoff.)
- **Thinking:** the system is layered, so one dense 680px-wide diagram would
  overcrowd — split into (a) the runtime data path/internals and (b) the
  surrounding operational/build planes, with prose between. Encode data plane
  (solid blue), KRaft metadata (amber dashed), telemetry (green dashed),
  alert/email (red), build/control (grey); solid vs dashed borders = built vs
  planned. Ground every element in the real compose/Makefile (ports, node IDs,
  quorum, listeners) rather than a generic Kafka picture.
- **Response / caveats surfaced:** delivered both diagrams + the HTML page. Flagged
  honestly: (i) combined mode (all 4 vote) matches today's compose, but raising
  broker count in Phase 3 should split into dedicated controllers (3/5) + brokers,
  changing the quorum row; (ii) two Phase 2 alerts (consumer rebalancing, producer
  connection break) may lack a backing `kafka-exporter` metric — pipeline shown,
  metric-availability still to be verified — planned as part of the
  observability work.

### 4. Open items (carried forward)
- [ ] Reconcile this file's older 2026-07-13 "Branch/PR state" / "Open items" with
      the corrections above (kept for history for now).
- [ ] Begin Phase 1 (`apache/kafka` refactor) when ready — first executable gate is
      `make compose-check`.
- [ ] (optional) `git lfs prune` (~1.8 GB orphaned LFS).

---

## Session Log — 2026-07-13

One session on `shoji-dev`. The GitHub repo has been **renamed to `Krate`** (the
old name redirects). ZK observability was split into its own branch `zk-freeze`
→ **PR #10**.

### 1. Repo cleanup — reclaimed 3.35 GB
- Deleted `dist/` (3.3 GB build output), `.DS_Store`, and `docker-compose-ref.yml`
  — all gitignored / regenerable.
- **Not done (optional):** `.git/lfs/objects` still holds **1.8 GB of orphaned
  Git LFS cache** — old `dist` bundles committed via LFS (`e918425`) then removed
  in favour of GitHub Releases (`56a69d5`); nothing in the tree references them.
  Reclaim any time with `git lfs prune`.

### 2. ZK cluster run + two bugs fixed (in BOTH `zk/` and `kraft/`)
Brought the `zk/` cluster up and tested produce/consume, replication, and ISR.
Two real bugs surfaced and were fixed in both variants:

| Bug | Fix |
|---|---|
| `kafka lag` called `kafka-consumer-groups.sh`, absent from `cp-kafka:7.6.1` (only `kafka-consumer-groups` is on PATH) — `lag` failed every time | use `kafka-consumer-groups` |
| Proxy / Kafbat healthchecks probed `localhost` (resolves to IPv6 `::1`) while services bind IPv4 `0.0.0.0` — containers marked unhealthy while serving fine | probe `127.0.0.1` |

Local-dev notes: on macOS the UI proxy was remapped to `8080/8443` (host port 80
busy), and `make check` needs **GNU Make 4.x (`gmake`)** — the system `make`
(3.81) can't parse `.RECIPEPREFIX`.

### 3. ZK observability built + frozen (v5)
The ZooKeeper edition is now **feature-complete and frozen** — ZK is being removed
from modern Kafka, so no new features land here (bug/security fixes only). Added a
self-contained observability stack (details in `docs/zk-v5-freeze-release-notes.md`):
- `zk/monitoring/` — **kafka-exporter → Prometheus (15d TSDB + dynamic alert
  rules) → Grafana** (provisioned datasource + Overview and Consumer-Groups
  dashboards). Exporter reads metrics as a Kafka client; no JMX agent, no broker
  restart.
- `kafka monitor {up,down,status,logs,ui}` subcommand in `zk/kafka`.
- `Makefile` ships the monitoring images/config in the `zk` bundle
  (`make bundle VERSION=v5 MODE=zk`).
- Verified end-to-end: targets UP, `kafka_brokers=4`, under-replicated `=0`,
  injected consumer lag `=150` visible through exporter → Prometheus → Grafana,
  4 alert rules `health=ok`, both dashboards provisioned.
- Overview page: `docs/zk-observability.html`
  (published https://claude.ai/code/artifact/d5b92794-d920-4596-b0dd-7a2817f461c9).

> This supersedes the "Monitoring — No Prometheus/Grafana" note under
> *What Is Not In The Bundle* **for the `zk/` variant**.

### 4. Branch / PR state
- **`zk-freeze`** (commit `983e1fa`) — strictly ZK; **PR #10 → `main`**, reviewer
  `fwnh67-20`: https://github.com/bso-d/Krate/pull/10
- **Still uncommitted on `shoji-dev`:** the KRaft mirror of the two fixes
  (`kraft/kafka`, `kraft/docker-compose.yml`). They need their own branch/PR.

### 5. Open items
- [ ] Commit the KRaft mirror fixes on their own branch → PR.
- [ ] (optional) `git lfs prune` to reclaim ~1.8 GB from `.git/lfs`.
- [ ] Log aggregation (Loki/promtail) not shipped — promtail's container-log mount
      is unreliable on Docker Desktop for macOS, so it wasn't verified. Clean to
      add on a Linux host.

---

## What This Is

A portable, offline-installable Kafka cluster packaged as a self-contained tar.gz. You build the bundle on a machine with internet access, SCP it to an air-gapped or restricted VM, and run one command to start the cluster.

Two variants are maintained in parallel under `zk/` and `kraft/`:

| Variant | Coordination | Bundle |
|---|---|---|
| `zk` | Apache ZooKeeper (Confluent 7.6.1) | `kafka-zk-v5-<arch>.tar.gz` |
| `kraft` | KRaft combined mode, no ZooKeeper | `kafka-kraft-v5-<arch>.tar.gz` |

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
├── Makefile                    Build, validation, Docker package, and image-transfer workflow
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
443/80*     zk-proxy          nginx TLS proxy → Kafbat (80 redirects to 443)
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
443/80*     kraft-proxy         nginx TLS proxy → Kafbat (80 redirects to 443)
```

Controller quorum uses internal ports 29092–29095 (not exposed to host).  
`CLUSTER_ID: 4GThRKJoQF2BmLyqAl4JlQ` — fixed, embedded in on-disk storage on first boot. **Do not change after first `kafka install`.**

`*` 443/80 are the defaults — configurable via `KAFKA_UI_HTTPS_PORT` / `KAFKA_UI_HTTP_PORT` in `.env`.

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

Copied from `.env.template` on first install:

```bash
KAFKA_UI_USER=admin          # Kafbat UI login username
KAFKA_UI_PASSWORD=changeme   # Kafbat UI login password
KAFKA_UI_FQDN=               # FQDN for the UI / TLS cert CN+SAN (blank → host FQDN)
KAFKA_UI_HTTPS_PORT=443      # Host port for HTTPS
KAFKA_UI_HTTP_PORT=80        # Host port for HTTP (redirects to HTTPS)
```

Set via CLI: `kafka config set KAFKA_UI_FQDN=kafka.internal.example`  
Takes effect on next `kafka start` or `kafka restart proxy`. Changing `KAFKA_UI_FQDN`? Re-run `kafka gen-cert` so the cert matches.

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
| `kafka doctor` | Preflight: Docker/Compose versions, host port availability, architecture match, firewalld `docker` zone (presence + ACCEPT target), and iptables legacy↔nft split-brain. Runs automatically at the top of `kafka install` |
| `kafka gen-cert` | (Re)generate the self-signed TLS cert (`certs/server.crt`+`.key`) for the UI proxy, using `KAFKA_UI_FQDN` |
| `kafka docker-check` | Validate Docker version + daemon + compose |
| `kafka docker-install` | Install the bundled containerd, Docker CE, CLI, and Compose plugin `.deb` files |

### `kafka lag` internals

Runs `kafka-consumer-groups.sh` inside the first running broker container via `docker exec`. Finds the broker by iterating `kafka-92` → `kafka-95` and checking container state.

---

## nginx Proxy (TLS termination)

Both variants put Kafbat UI behind nginx (`nginx:1.27-alpine`). nginx is the only container with host ports — it serves the UI over **HTTPS on :443** and redirects **:80 → :443**. Kafbat itself has no host port.

**TLS:** nginx terminates TLS with a **self-signed** cert at `certs/server.crt` + `certs/server.key`, mounted read-only into the container at `/etc/nginx/certs/`. `kafka install`/`kafka start` auto-generate it (via `ensure_cert` → `openssl`) if missing, using `KAFKA_UI_FQDN` (or the host FQDN) as CN/SAN plus the host's primary IP. Regenerate with `kafka gen-cert`; swap in an org-CA cert by replacing the two files and `kafka restart proxy`. The `certs/` dir is git-ignored and not shipped in the bundle — it's created on the VM at install time.

**Why nginx at all:** a DAST scan (OWASP ZAP) found missing security headers on the raw Kafbat endpoint. nginx injects them (and now adds HSTS):

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
- GNU Make 4.0 or newer

### Steps

Bundles are **per-architecture** (`amd64` / `arm64`). Build one set per target CPU.

```bash
# 1. Download Docker CE .deb packages for each target Ubuntu release and arch
make docker-debs UBUNTU_VERSION=noble ARCH=amd64
make docker-debs UBUNTU_VERSION=noble ARCH=arm64

# 2. Build both variants for each arch
make bundle VERSION=v5 ARCH=arm64 NO_PULL=1 INCLUDE_DOCKER=1   # arm64 host: local images
make bundle VERSION=v5 ARCH=amd64 INCLUDE_DOCKER=1             # pulls amd64 images

# Output:
# dist/kafka-zk-v5-amd64.tar.gz     ~1.1 GB   (+ .sha256)
# dist/kafka-kraft-v5-amd64.tar.gz  ~730 MB   (+ .sha256)
# dist/kafka-zk-v5-arm64.tar.gz     ~1.1 GB   (+ .sha256)
# dist/kafka-kraft-v5-arm64.tar.gz  ~720 MB   (+ .sha256)
```

- `ARCH=amd64|arm64` selects the target CPU (defaults to the build host's arch).
- `UBUNTU_VERSION=jammy|noble` selects the target Ubuntu release for `docker-debs` (defaults to `noble`). Preparing another release for the same architecture replaces that architecture's existing package directory.
- `NO_PULL=1` skips re-pulling images — only valid when local images already match `ARCH`.
- `INCLUDE_DOCKER=1` bundles the Docker CE `.deb` files from `docker-offline/<arch>/`. Package versions are not pinned; `docker-debs` downloads the current candidates from Docker's APT repository for the selected `UBUNTU_VERSION` and `ARCH`.
- `VERSION=vN` is required — use the next vN after the last released bundle.

> **Build note (containerd image store):** the `bundle` target passes `docker save --platform` so multi-platform tags export exactly the requested arch. Without it, a plain `docker save` on Docker's containerd store exports the *host* arch — which silently produced a wrong-arch bundle (an amd64-named bundle full of arm64 images that died on the VM with `exec format error`). The bundled `.bundle-arch` marker + `kafka doctor`'s architecture check now catch any mismatch before install.

### What goes into each bundle

```
kafka-zk-v5-<arch>/
├── docker-compose.yml
├── nginx.conf
├── .env.template
├── kafka                        CLI tool
├── images/
│   ├── confluentinc__cp-zookeeper_7.6.1.tar
│   ├── confluentinc__cp-kafka_7.6.1.tar
│   ├── kafbat__kafka-ui_latest.tar
│   └── nginx_1.27-alpine.tar
├── .bundle-arch                 amd64 | arm64 (checked by `kafka doctor`)
└── docker-offline/              (only with INCLUDE_DOCKER=1; arch-matched)
    ├── containerd.io_*_<arch>.deb
    ├── docker-ce_*_<arch>.deb
    ├── docker-ce-cli_*_<arch>.deb
    ├── docker-compose-plugin_*_<arch>.deb
    └── install-docker.sh
```

### Uploading to GitHub Release

```bash
# Upload all four arch-suffixed bundles (+ sidecars)
gh release upload v1.0.0 \
  dist/kafka-zk-v5-amd64.tar.gz    dist/kafka-zk-v5-amd64.tar.gz.sha256 \
  dist/kafka-kraft-v5-amd64.tar.gz dist/kafka-kraft-v5-amd64.tar.gz.sha256 \
  dist/kafka-zk-v5-arm64.tar.gz    dist/kafka-zk-v5-arm64.tar.gz.sha256 \
  dist/kafka-kraft-v5-arm64.tar.gz dist/kafka-kraft-v5-arm64.tar.gz.sha256 \
  --clobber

# Remove previous (unsuffixed / older vN) assets
for a in kafka-zk-v4.tar.gz kafka-zk-v4.tar.gz.sha256 \
          kafka-kraft-v4.tar.gz kafka-kraft-v4.tar.gz.sha256; do
  gh release delete-asset v1.0.0 "$a" --yes
done
```

---

## Installing on the VM

```bash
# Pick the bundle for the VM's CPU: `uname -m` → x86_64 = amd64, aarch64 = arm64.
# Example uses the amd64 ZooKeeper bundle.
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-v5-amd64.tar.gz
wget https://github.com/bso-d/kafka-offline-install-package/releases/download/v1.0.0/kafka-zk-v5-amd64.tar.gz.sha256

# Verify
sha256sum -c kafka-zk-v5-amd64.tar.gz.sha256
```

`sha256sum -c` works as-is from v4 onward — the sidecar now carries a bare
filename. (Older v3 bundles embedded the build machine's absolute path; see
Known Issues #1 for the fix history.)

```bash
# Extract (macOS xattrs warning is harmless on Linux)
tar -xzf kafka-zk-v5-amd64.tar.gz
cd kafka-zk-v5-amd64

# Preflight (also catches an arch mismatch before install)
./kafka doctor

# Check Docker
./kafka docker-check

# Install Docker if needed (INCLUDE_DOCKER=1 bundle only)
./kafka docker-install

# Start cluster
./kafka install
```

---

## Known Issues & Next Actions

### 1. sha256sum path bug — ✅ RESOLVED in v4 (PR #2)

The v3 `.sha256` files stored the build machine's absolute path, so
`sha256sum -c` failed on the VM. The Makefile `bundle` target generates the
hash from inside `DIST_DIR` so the sidecar holds only `<hash>  <bundle>.tar.gz`:
```bash
(cd "$DIST_DIR" && sha256sum "${bundle_name}.tar.gz") > "${out_file}.sha256"
```
The v4 release assets were re-cut with the fix; the old v3 assets were removed.

### 2. NAT chain error on install (`INVALID_ZONE: docker`)

Observed on the target VM:
```
ERROR: Failed to program NAT chain: INVALID_ZONE: docker
```
This is a firewalld/iptables conflict. Docker 25.0.3 with Compose v1 tries to create a bridge network, and firewalld blocks iptables manipulation. As of v4, `kafka doctor` (and `kafka install`) detects this up front — firewalld active without a `docker` zone — and prints the fix instead of letting the install abort mid-way.

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
These come from macOS's tar adding Apple extended attributes. They are harmless — extraction completes correctly. The Makefile `bundle` target sets `COPYFILE_DISABLE=1` when creating tarballs to suppress this metadata when available.

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

Optional offline Docker packages are selected from Docker's APT repository when `make docker-debs` runs. Their exact versions therefore depend on the repository state at build time; inspect the generated `.deb` filenames in `docker-offline/<arch>/` to record the versions included in a bundle.

---

## Environment Compatibility

| Component | Minimum or accepted value | Notes |
|---|---|---|
| Docker Engine | 25.0.3 | Docker CE packages or an existing installation |
| Docker Compose | 1.29.2 | Standalone v1 or the v2 plugin |
| Ubuntu | 22.04 (jammy) | 24.04 (noble) is also supported |
| Architecture | amd64 or arm64 | Build a separate bundle for each architecture |

The `kafka` CLI auto-detects `docker compose` (v2) or `docker-compose` (v1) at startup.

---

## What Is Not In The Bundle

- **TLS / HTTPS** — Kafka listeners are PLAINTEXT. For production, add SSL listener config and certificates.
- **Authentication** — Brokers use no SASL. Kafbat UI has form-based auth only.
- **Multi-node VM** — All 4 brokers run on a single VM. Not a multi-host setup.
- **Monitoring** — No Prometheus/Grafana. Kafbat provides basic lag/offset visibility.
- **Stream visualizer** — A React/Node topology visualizer previously lived in `visualizer/` and the root reference setup. It was never part of the shipped `zk/`/`kraft/` bundles and has been removed from the repo to keep the focus on the Kafka + ZooKeeper cluster.
