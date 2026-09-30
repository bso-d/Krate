# Phase 1 — Manual verification runbook (apache/kafka refactor)

Run this from a clean slate to verify the KRaft edition on the official
`apache/kafka` image before the Phase 1 changes are committed. Everything below is
copy-pasteable. Commands assume repo root `/Users/shoji/projects/Krate` and the
`phase-1-apache-images` branch.

## What you are verifying

- Brokers run on `apache/kafka:3.9.1` (was `confluentinc/cp-kafka:7.6.1`).
- Image pins live once in `kraft/.env.template` (`KAFKA_IMAGE`, `KAFKA_UI_IMAGE`,
  `NGINX_IMAGE`) and both `docker-compose.yml` and the Makefile read them.
- The four broker healthchecks use `nc -z 127.0.0.1 <port>` (Confluent's `cub` is
  gone); kafbat `:8080` healthcheck fixed to `127.0.0.1`.
- `kraft/kafka lag` calls `/opt/kafka/bin/kafka-consumer-groups.sh` by full path
  (apache image doesn't put the CLI scripts on `PATH`).

## Prerequisites

- Docker running (`docker info` works).
- **GNU Make 4.x** — on macOS the system `make` is 3.81 and cannot parse the
  Makefile; use `gmake` (`brew install make`).
- `openssl` (for the UI proxy cert; preinstalled on macOS).

---

## Step 0 — Clean slate

Remove any previous KRaft cluster **and its volumes** so you get a true first
boot (storage auto-formats from `CLUSTER_ID`).

```bash
cd /Users/shoji/projects/Krate
docker compose --env-file kraft/.env.template -f kraft/docker-compose.yml down -v 2>/dev/null
docker rm -f $(docker ps -aq --filter name=kraft-) 2>/dev/null   # belt-and-suspenders
docker ps -a --filter name=kraft- --format '{{.Names}}'          # expect: (empty)
```

Optional — prove the old Confluent image isn't what boots:

```bash
docker image rm confluentinc/cp-kafka:7.6.1 2>/dev/null || true
```

## Step 1 — Static validation

```bash
gmake check      # bash -n + shellcheck + docker compose config, for zk and kraft
```

Expect: no errors, exit 0. (Confirms the compose file interpolates the new image
vars and `kraft/kafka` still lints.)

Confirm the Makefile now derives images from the env template:

```bash
gmake -p 2>/dev/null | grep '^KRAFT_IMAGES :='
# KRAFT_IMAGES := apache/kafka:3.9.1 kafbat/kafka-ui:v1.0.0 nginx:1.27-alpine
```

## Step 2 — Run the cluster (online dev flow)

> Note: `./kafka install` is the **offline** path — it loads images from a
> bundled `images/` dir and will refuse to run without one. On this online dev
> box use `./kafka start`, which uses local/pulled images, auto-creates `.env`
> from the template, and generates a self-signed UI cert.

```bash
cd kraft
cp .env.template .env          # start would do this for you; explicit is clearer
# If host ports 80/443 are busy (common on macOS), remap before starting:
#   ./kafka config set KAFKA_UI_HTTP_PORT=8080
#   ./kafka config set KAFKA_UI_HTTPS_PORT=8443
./kafka start
./kafka status
./kafka health                 # wait until all 6 services report healthy
cd ..
```

## Step 3 — Verify KRaft on apache/kafka

```bash
B=/opt/kafka/bin

# 3a. One quorum of 4 voters, a leader elected, followers caught up
docker exec kraft-broker-92 $B/kafka-metadata-quorum.sh \
  --bootstrap-server 127.0.0.1:9092 describe --status \
  | grep -E "LeaderId|CurrentVoters|MaxFollowerLag"

# 3b. 4 brokers registered
docker exec kraft-broker-92 $B/kafka-broker-api-versions.sh \
  --bootstrap-server 127.0.0.1:9092 2>/dev/null | grep -c "id:"     # expect 4

# 3c. Topic honours our config (RF=3, min.insync.replicas=2, 1 GiB segments)
docker exec kraft-broker-92 $B/kafka-topics.sh --bootstrap-server 127.0.0.1:9092 \
  --create --topic phase1-test --partitions 6 --replication-factor 3
docker exec kraft-broker-92 $B/kafka-topics.sh --bootstrap-server 127.0.0.1:9092 \
  --describe --topic phase1-test | head -3

# 3d. Produce 100, consume 100
docker exec kraft-broker-92 sh -c \
  "seq 100 | $B/kafka-console-producer.sh --bootstrap-server 127.0.0.1:9092 --topic phase1-test"
docker exec kraft-broker-92 $B/kafka-console-consumer.sh \
  --bootstrap-server 127.0.0.1:9092 --topic phase1-test \
  --from-beginning --max-messages 100 --timeout-ms 15000 2>/dev/null | wc -l   # expect 100

# 3e. The lag command's fixed exec path resolves (was 'command not found')
docker exec kraft-broker-92 $B/kafka-consumer-groups.sh \
  --bootstrap-server 127.0.0.1:9092 --list

# 3f. UI: print URL + credentials, then open it
( cd kraft && ./kafka ui )
# Browse https://localhost:443 (or :8443 if you remapped). Self-signed cert warning
# is expected. Login with KAFKA_UI_USER / KAFKA_UI_PASSWORD from kraft/.env.
```

**Pass criteria**

- [ ] `CurrentVoters` lists ids 92, 93, 94, 95; a `LeaderId` is set; `MaxFollowerLag: 0`.
- [ ] Broker count = 4.
- [ ] `--describe` shows `ReplicationFactor: 3`, `min.insync.replicas=2`, full ISR.
- [ ] Consumed count = 100.
- [ ] `kafka-consumer-groups.sh` lists the console-consumer group (exit 0).
- [ ] Kafbat UI loads over HTTPS and shows `cluster-1-kraft` with 4 brokers.

## Step 4 — Teardown

```bash
docker compose --env-file kraft/.env.template -f kraft/docker-compose.yml down -v
docker ps -a --filter name=kraft- --format '{{.Names}}'   # expect: (empty)
```

---

## Optional — full offline-bundle simulation (the real end-user path)

Proves `./kafka install` works air-gapped with the apache images baked into a
bundle. `NO_PULL=1` reuses the images you already pulled.

```bash
cd /Users/shoji/projects/Krate
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/arm64/arm64/; s/aarch64/arm64/')
gmake bundle VERSION=v6 MODE=kraft ARCH=$ARCH NO_PULL=1
mkdir -p /tmp/krate-test && tar -xzf dist/kafka-kraft-v6-$ARCH.tar.gz -C /tmp/krate-test
cd /tmp/krate-test/kafka-kraft-v6-$ARCH
./kafka doctor      # arch marker + port/preflight checks
./kafka install     # loads bundled images, generates cert, starts cluster
./kafka health
# ...repeat Step 3 checks against kraft-broker-92...
./kafka uninstall --purge   # or: ./kafka down
```

## Troubleshooting

- **`make: .RECIPEPREFIX` errors** → you're on system `make` 3.81. Use `gmake`.
- **`./kafka install` says "images/ directory not found"** → that's the offline
  path. Use `./kafka start` for online dev, or build a bundle (optional section).
- **Proxy won't bind / port in use** → set `KAFKA_UI_HTTP_PORT` / `KAFKA_UI_HTTPS_PORT`
  via `./kafka config set …`, then `./kafka restart proxy`.
- **Broker exits immediately, `Permission denied` on data dir** → not expected;
  `apache/kafka`'s `/var/lib/kafka/data` is owned by the non-root `appuser` and a
  fresh named volume inherits that. Only happens if you bind-mount a host dir
  owned by root — use the named volumes as shipped.
- **Cert/openssl warning about `hostname -I`** → harmless on macOS; the cert is
  generated with a DNS SAN only (no host IP), which is fine for local testing.
