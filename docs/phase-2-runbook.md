# Phase 2 — monitoring and the merge gate

Each phase is developed and tested on its own branch, then merged into `main`
through a pull request. Fix failed checks on the phase branch. `main` should
always represent the last validated phase.

## Before merging

Run from the phase branch, with Docker running and GNU Make 4+ (`gmake` on macOS):

```bash
make check
# Connected preparation step; integration tests themselves never pull images.
docker compose --env-file kraft/.env.template -f kraft/docker-compose.yml pull
docker compose --env-file monitoring/.env.template -f monitoring/docker-compose.yml pull
make test
make test-bundle
```

`make check` is the required static gate: Bash syntax for each CLI, ShellCheck,
and all four Compose configurations. `make test` also runs the isolated Phase 2
integration test. It requires Python 3 and Docker, uses unique container/network/
volume names and temporary ports, and removes only its own resources afterward.
It verifies:

- Four healthy brokers, 100 produced messages, 40 consumed, committed lag 60,
  and no under-replicated partitions.
- Three live scrape targets, three dashboards, and logs in Loki.
- Fourteen editable Grafana notification rules; a real lag alert delivered to
  a temporary local SMTP sink. The test lowers the lag threshold and pending
  period only in its copied configuration; no email leaves the test machine.
- Operator edits survive alert initialization, and monitoring can be stopped
  after the Kafka containers are removed.

`make test-bundle` builds a real temporary KRaft bundle from cached images,
verifies the checksum and all nine image manifests/architectures, checks that
monitoring configuration is present and credentials are absent, then removes it.
The same monitoring image set is included in EPC bundles.

The `Phase merge checks` GitHub workflow runs these checks on pull requests and
on `main`. Repository administrators must make its `check` job a required
status check in branch protection/rulesets to prevent bypassing it. Adding the
workflow alone does not enforce this.

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
delivery, and the real ARM64 bundle test passed on Docker Desktop. CI repeats
the tests on Linux/amd64. This does not establish RHEL SELinux compatibility or
delivery through an organization's SMTP relay: those remain deployment checks
on the target host. Follow the EPC runbook for its two-broker first boot.
