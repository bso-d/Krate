# Stable monitoring transition

The shared KRaft/EPC stack keeps Grafana, Loki, Prometheus and the existing
exporters. It replaces Promtail with Fluent Bit. The frozen ZooKeeper stack is
unchanged. Grafana's dashboards, OIDC group-to-Viewer/Admin configuration and
editable email contact point/rules remain in place.

## Operator cutover

1. In the **old installation**, run `./krate monitor down` before replacing the
   monitoring files. This stops the old collector and prevents duplicate
   collectors under the same Compose project. Do not use `down -v`.
2. Copy the new monitoring tree and merge the new `.env.template` into the site
   `.env`, preserving ports, SMTP, Grafana credentials and auth/token-file
   settings. Replace `PROMTAIL_IMAGE` with the new `FLUENT_BIT_IMAGE` reference
   from the **same extracted offline bundle**; its saved runtime tag is what
   the disconnected host can load. Keep existing `grafana_data`, `loki_data`
   and `prometheus_data` volumes. Keep the old Promtail positions volume for
   rollback; Fluent Bit does not import that positions file.
3. Load the new bundle's saved images before running `./krate monitor up`.
   The CLI still seeds the editable Grafana notification rules. Check Grafana
   Explore for `job="containerlogs"` with the expected container labels and
   check the collector logs for metadata, tail, storage or output failures.

On the first Fluent Bit run, available files are replayed from the head, subject
to the seven-day cutoff. Existing Loki lines can therefore be duplicated;
the old and new offset formats are different. Subsequent starts reuse Fluent
Bit's persistent offsets/chunks. Back up data/configuration before cutover.
For rollback, stop the new monitoring project without deleting volumes and
restore the old tree/image references; retain both collectors' state volumes.

See [collector behavior, limits and notices](fluent-bit/README.md). The migration
does not establish lossless collection during abrupt termination of an unfinished
multiline record, disk exhaustion, unreadable Docker metadata or source rotation
before recovery. Verify the site's Docker `json-file` path, permissions and
SELinux access on the target host; no automatic host relabeling is performed.

## Proposal evaluation (2026-10-08)

| Proposal | Verified repository/source facts | Decision |
| --- | --- | --- |
| Keep Prometheus/exporters | `prometheus/prometheus.yml` scrapes Kafka, node and Prometheus; `alerts.yml` owns thresholds/pending periods. | Keep unchanged. |
| Replace Grafana with Perses | Stable v0.54.0 supports OIDC but its released authentication documentation lacks automatic IdP role/group synchronization. v0.55.0-rc.0, published October 8, adds claim mappings; referenced roles must already exist, permissions are additive, and claims are retained through refresh. | Keep stable releases and Grafana until stable mapping is available and the revocation behavior is accepted/tested. |
| Convert dashboards | Three dashboard JSON files contain 14 panels and 15 PromQL targets: two tables with organize/rename transformations, one gauge, four stats and seven time-series panels. | Conversion is deferred with the UI; count/query compatibility alone cannot certify table columns, units, thresholds, legends or visual fidelity. |
| Replace Grafana notification delivery | `seed-alerting.py` provisions an email contact point and notification rules from Prometheus firing `ALERTS`; both edition CLIs invoke it. Prometheus has no Alertmanager target. | Retain current delivery. A future UI removal must add and exercise Alertmanager, migrate operator routes/recipients and avoid concurrent email paths. |
| VictoriaLogs + Fluent Bit | VictoriaLogs documents Fluent Bit ingestion via Elasticsearch-compatible output; Perses has a VictoriaLogs plugin. Loki's LogQL and VictoriaLogs' LogsQL differ. | Retain Loki for this stage; plugin assets, queries, retention and existing log access require a separate verified migration. |
| Replace EOL Promtail | Promtail reached EOL on March 2, 2026. Current shared config discovers names using Docker API and persists offsets but has no Java multiline or filesystem output spool. | Use the pinned stable Fluent Bit collector and document its replay/durability limits. |
| Offline packages | The Makefile explicitly stages monitoring files and enumerates all `*_IMAGE` entries. `check-offline.py` verifies effective Grafana/Kafbat outbound-disabled defaults. | Bundle the collector, decoder and notices; require its runtime files in `check-bundle.py`; keep existing outbound policies. |
| License priority | Perses, Alertmanager, VictoriaLogs and Fluent Bit upstream projects use Apache-2.0. The pinned Fluent Bit amd64/arm64 image layers contain the same 49 Debian packages, including LGPL libraries; exact-version notices and source-version inventory are bundled. Grafana/Loki remain in use for the accepted stable stage. | This stage is not an all-permissive monitoring distribution. Notice copies do not complete corresponding-source/relinking obligations; review/fulfill these before redistributing a release. |

Perses migration is best effort and does not migrate Grafana users or alerts.
OpenSearch/Dashboards remains an alternative evaluation, with search-node/index
management and host tuning costs. A reduced expression browser/log explorer
would remove curated dashboards and is not the selected approach.

Primary references: [Perses v0.54.0 authentication](https://github.com/perses/perses/blob/v0.54.0/docs/concepts/authentication.md),
[v0.55.0-rc.0 claim/revocation behavior](https://github.com/perses/perses/blob/v0.55.0-rc.0/docs/concepts/authentication.md),
[migration scope](https://perses.dev/perses/docs/migration/),
[Prometheus alert delivery](https://prometheus.io/docs/alerting/latest/overview/),
[VictoriaLogs ingestion](https://docs.victoriametrics.com/victorialogs/data-ingestion/fluentbit/),
[Promtail EOL](https://grafana.com/docs/loki/latest/send-data/promtail/).
