# Phase 2 — monitoring and the merge gate

Each phase is developed and tested on its own branch, then merged into `main`
through a pull request. Fix failed checks on the phase branch. `main` should
always represent the last validated phase.

## Before merging

Validate changes locally on the phase branch before merging. Keep test scripts,
test workflows, and generated validation artifacts out of the remote repository.
`make check` remains the static source check (Bash syntax, ShellCheck, and the
four Compose configurations); `make test` is an alias for it. Use `gmake` on
macOS. Runtime and offline-bundle validation are performed with local tooling.
Record the outcome and any deployment-specific limitations in the handoff.

## Operating monitoring

Requires Python 3 on the operator host for Grafana initialization (standard
library only; no pip downloads). Start the Kafka cluster first, then:

```bash
make monitor-up VARIANT=kraft       # or epc
make monitor-status VARIANT=kraft
# In an extracted offline bundle:
./krate load-images
./krate monitor up
./krate monitor ui
./krate monitor logs
./krate monitor down
```

The CLI discovers the running cluster's network and internal broker addresses.
The repository shares `monitoring/.env`; separate extracted bundles have their
own copies. Use distinct published ports if running multiple monitoring stacks
on one host. Grafana, Prometheus, and Loki use HTTP on their configured host
ports; deploy them on the intended internal network.

Edit SMTP settings in `monitoring/.env`, then run `./krate monitor up` again.
With SMTP disabled, alerts remain visible but email is not delivered. Grafana's
`krate-email` contact point and individual notification rules are seeded once
through its API with editing enabled. Change recipients, pause rules, or choose
contact points in Grafana's UI. Re-running initialization preserves those edits.
After changing the Grafana login in its UI, keep `GRAFANA_USER` and
`GRAFANA_PASSWORD` in `.env` synchronized for subsequent initialization.

Prometheus owns the thresholds and pending periods in
`monitoring/prometheus/alerts.yml`. Grafana watches each rule's firing `ALERTS`
series and sends notifications, adding up to one evaluation interval of delay.
After changing thresholds, use `./krate monitor reload`. New rule names are
seeded on the next `monitor up`; remove retired notification rules in Grafana.
Consumers rebalancing, ingest stopping, and consumers stalling are explicitly
labelled proxy signals, not direct evidence of a disconnected client.

Loki retains logs for seven days through its compactor. Promtail discovers only
containers whose names start with `krate-` or `epc-`, uses Docker socket access,
and persists read positions across restarts. Its pinned version remains part of
this phase; log-agent upgrades need their own compatibility validation.

## Validation recorded for this merge

On 2026-09-05, static checks, the live KRaft integration test including SMTP
delivery, and the real ARM64 bundle test passed on Docker Desktop. The same
tests also passed on Linux/amd64 in CI before PR #15 merged.
The temporary test workflow and scripts were subsequently removed from tracking
under the source-and-releases repository convention. This does not establish
RHEL SELinux compatibility or
delivery through an organization's SMTP relay: those remain deployment checks
on the target host. Follow the EPC runbook for its two-broker first boot.
