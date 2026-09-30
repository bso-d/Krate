# Kafka Offline Install Package — ZooKeeper Edition v5 (Freeze Release)

**Status:** Frozen (legacy) — bug and security fixes only from here on.
**Date:** 2026-07-13
**Scope:** ZooKeeper-based deployment (`zk/`) only.

ZooKeeper is being removed from modern Kafka, so this edition is closed to new
features. This release brings the ZK install to a complete, self-contained state —
the one remaining gap, **observability**, is now built in — and then freezes it.

---

## Added — Observability

- **`kafka monitor` subcommand** — `up`, `down`, `status`, `logs`, `ui`.
- **kafka-exporter → Prometheus → Grafana**, attached to the running cluster's
  Docker network:
  - **kafka-exporter** reads metrics as an ordinary Kafka client — no JMX
    java-agent, no broker restart.
  - **Prometheus** — 15-day TSDB plus alert rules that are *dynamic* (no hardcoded
    broker count).
  - **Grafana** — provisioned Prometheus datasource and two dashboards:
    *Kafka (ZK) — Overview* and *Kafka (ZK) — Consumer Groups*.
- **Alert rules:** `KafkaExporterDown`, `KafkaBrokerDisappeared`,
  `UnderReplicatedPartitions`, `ConsumerGroupHighLag`.
- **Offline bundle** now ships the monitoring images and config —
  `make bundle VERSION=v5 MODE=zk`.

## Fixed

- **`kafka lag`** called `kafka-consumer-groups.sh`, which is absent from
  `cp-kafka:7.6.1` (only `kafka-consumer-groups` is on `PATH`) — the command
  failed every time. Corrected.
- **Healthchecks** for the UI proxy and Kafbat probed `localhost` (which resolves
  to IPv6 `::1`) while the services bind IPv4 `0.0.0.0` — containers were marked
  unhealthy while serving traffic normally. Switched to `127.0.0.1`.

## Verified

Tested end-to-end against a live 10-container stack (2026-07-13):

- Scrape targets **UP** (`kafka`, `prometheus`); `kafka_brokers = 4`;
  under-replicated partitions = **0**.
- An injected consumer-group lag of **150** surfaced identically through the
  exporter, Prometheus, and Grafana's query API.
- All 4 alert rules evaluate cleanly (`health=ok`); both dashboards provisioned;
  Grafana ↔ Prometheus datasource **OK**.
- `bash -n` + `shellcheck` + `docker compose config` pass for all ZK CLI and
  compose files.

## Run

```sh
kafka start          # 4-broker ZK cluster
kafka monitor up     # kafka-exporter + Prometheus + Grafana
kafka monitor ui     # Grafana :3000 · Prometheus :9090
```

## Not included (by design)

- **Log aggregation (Loki / promtail):** direction scaffolded but not shipped —
  promtail's container-log mount is unreliable on Docker Desktop for macOS, so it
  could not be verified here. Clean to add on a Linux host.

## Reference

- Feature schema & observability overview: [`docs/zk-observability.html`](./zk-observability.html)
- Published artifact: https://claude.ai/code/artifact/d5b92794-d920-4596-b0dd-7a2817f461c9
