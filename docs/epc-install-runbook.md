# EPC install runbook — Krate 2-broker on RHEL 9

For `epc-appkfk-03` and its twin. Both are RHEL 9.6 / x86_64, so **one bundle
serves both**: `kafka-epc-v1-amd64.tar.gz`.

What this installs: Docker CE 29.7.2 (offline, from bundled RPMs) and a 2-broker
KRaft cluster on host ports **9092/9093**, with broker data on **/data** and the
Kafbat UI behind an nginx TLS proxy.

---

## 0. Transfer and verify

```bash
scp dist/kafka-epc-v1-amd64.tar.gz dist/kafka-epc-v1-amd64.tar.gz.sha256 root@<vm>:/opt/
```

On the VM:

```bash
cd /opt
sha256sum -c kafka-epc-v1-amd64.tar.gz.sha256     # must print: OK
tar -xzf kafka-epc-v1-amd64.tar.gz
cd kafka-epc-v1-amd64
```

## 1. Preflight

```bash
./krate doctor
```

Expect: Docker reported missing (that is next), `.bundle-arch` amd64 matching the
host, all 10 ports free, SELinux state reported, and the package-conflict check.

**If it lists `podman-docker`** — that is expected on RHEL and is handled in the
next step. `podman` and `runc` are not touched.

## 2. Install Docker (offline)

```bash
./krate docker-install
```

This removes any conflicting package (normally just `podman-docker`, which owns
`/usr/bin/docker`), then installs the six bundled Docker packages with
`dnf --disablerepo='*'` so nothing is fetched from the network. If the host has
no `container-selinux`, it automatically retries with the bundled copy under
`docker-offline/optional/`.

Verify:

```bash
docker --version          # Docker version 29.7.2
docker compose version    # v5.5.0
systemctl is-active docker
```

> Both paths were tested offline in a Red Hat UBI 9 container — with
> `podman-docker` present, and on a host lacking `container-selinux`.

## 3. Size the disk before first boot

`/data` is 1000 GB and holds **two copies** of everything (both brokers write to
it, RF=2). Defaults: 2 GiB per partition replica, 24 partitions, 168 h — about
**96 GB of /data per topic**.

```bash
./krate config set KAFKA_DATA_DIR=/data
./krate config set KAFKA_ADVERTISED_HOST=$(hostname -f)   # required for off-box clients
```

`KAFKA_ADVERTISED_HOST` matters: brokers advertise this name, so leaving it as
`localhost` means only on-box clients can connect.

## 4. Install the cluster

```bash
./krate install
```

Loads the three images from `images/`, creates `/data/krate/broker-{92,93}`
owned by uid 1000, generates a self-signed TLS cert, starts all four containers,
and waits for health.

## 5. Verify

```bash
./krate status
./krate health          # 4/4 healthy
./krate disk            # usage vs the 60% budget
```

```bash
B=/opt/kafka/bin

# 2-voter quorum, leader elected, followers caught up
docker exec epc-broker-92 $B/kafka-metadata-quorum.sh \
  --bootstrap-server 127.0.0.1:19092 describe --status | grep -E "LeaderId|CurrentVoters|MaxFollowerLag"

# both brokers registered
docker exec epc-broker-92 $B/kafka-broker-api-versions.sh \
  --bootstrap-server 127.0.0.1:19092 2>/dev/null | grep -c "id:"     # expect 2

# topic honours RF=2 / minISR=1
docker exec epc-broker-92 $B/kafka-topics.sh --bootstrap-server 127.0.0.1:19092 \
  --create --topic epc-smoke --partitions 6 --replication-factor 2
docker exec epc-broker-92 $B/kafka-topics.sh --bootstrap-server 127.0.0.1:19092 \
  --describe --topic epc-smoke | head -3

# produce/consume 100
docker exec epc-broker-92 sh -c \
  "seq 100 | $B/kafka-console-producer.sh --bootstrap-server 127.0.0.1:19092 --topic epc-smoke"
docker exec epc-broker-92 $B/kafka-console-consumer.sh \
  --bootstrap-server 127.0.0.1:19092 --topic epc-smoke \
  --from-beginning --max-messages 100 --timeout-ms 15000 2>/dev/null | wc -l   # expect 100

# data really is on /data, owned by uid 1000
ls -ld /data/krate/broker-92 && du -sh /data/krate/broker-9*
```

**From another machine** (proves the 9092/9093 listeners and advertised host):

```bash
kafka-console-producer.sh --bootstrap-server <vm-fqdn>:9092 --topic epc-smoke
```

**From the UI** — `./krate ui` prints the URL and credentials. Log in, confirm
`cluster-epc` shows 2 brokers, then **create a topic from the UI**. This is the
one behaviour to confirm by hand: topic auto-creation is off, so the UI's
CreateTopics path is how topics get made. It is expected to work — the setting
governs only implicit creation — but it has not been exercised on a live cluster.

### Pass criteria

- [ ] `CurrentVoters` lists 92 and 93; a `LeaderId` is set; `MaxFollowerLag: 0`
- [ ] broker count = 2
- [ ] `--describe` shows `ReplicationFactor: 2`, `min.insync.replicas=1`, full ISR
- [ ] consumed count = 100
- [ ] `/data/krate/broker-9*` are populated and owned by 1000
- [ ] UI loads over HTTPS, shows 2 brokers, and can create a topic
- [ ] a remote client reaches `<fqdn>:9092`

## Troubleshooting

- **`dnf` conflict on install** → `./krate docker-install` handles `podman-docker`.
  For anything else, the error names the package; removing it is safe if it is a
  legacy `docker-*` package.
- **Broker exits with a permission error on its log dir** → `/data/krate/broker-N`
  is not owned by uid 1000. `sudo chown -R 1000:1000 /data/krate`.
- **Containers cannot reach each other / NAT errors** → firewalld with no `docker`
  zone. `./krate doctor` prints the exact fix.
- **Off-box clients get connection refused after connecting** → `KAFKA_ADVERTISED_HOST`
  is still `localhost`. Set it, then `./krate restart`.
- **SELinux denials on the proxy** → the mounts carry `:z`/`:Z`; check
  `ausearch -m avc -ts recent`.
- **Disk filling** → `./krate disk`. Lower `KAFKA_LOG_RETENTION_BYTES` or
  `KAFKA_LOG_RETENTION_HOURS`, then `./krate restart`.

## Known limits

- Both nodes share one VM, so the controller quorum is 2: **losing either node
  stops the cluster**, regardless of RF=2/minISR=1. Accepted — one host is one
  failure domain.
- The cluster has never been booted anywhere. This runbook is the first run.
