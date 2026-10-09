# Krate monitoring

The shared KRaft/EPC monitoring stack runs two dashboard and alerting paths side
by side. The frozen ZooKeeper stack is unchanged.

| Path | Dashboards | Logs | Alert delivery |
| --- | --- | --- | --- |
| Existing | Grafana on `GRAFANA_PORT` (3000), with its SSO and editable email rules | Loki | Grafana email |
| Parallel | Perses on `PERSES_PORT` (3443, HTTPS) | VictoriaLogs | Alertmanager email |

Both paths use the same Prometheus, exporters and alert rules, and the same
Fluent Bit collector, which ships every selected container log to Loki and to
VictoriaLogs through separate outputs and queues. See
[collector behavior, limits and notices](fluent-bit/README.md).

`./krate monitor up` starts everything; `./krate monitor ui` prints both
addresses. Grafana, its SSO configuration, its dashboards and its email rules
are not changed by the parallel path.

## Perses

Perses v0.54.0 is reachable only through the `perses-gateway` nginx service on
`PERSES_PORT`, which serves HTTPS with the cluster certificate
(`certs/server.crt` and `certs/server.key`; create them with `./krate gen-cert`
or install your own). Perses, VictoriaLogs, Alertmanager, OAuth2 Proxy and the
access guard publish no host ports. Perses, the gateway, OAuth2 Proxy and the
guard run on their own `perses` network, which Prometheus and VictoriaLogs join
as Perses' datasources; Grafana and the other monitoring services cannot reach
Perses or the guard. The network is not internal, because Perses and OAuth2
Proxy call the IdP.

Dashboards: **Krate — Cluster Overview**, **Consumer Groups**, **Host & Disk**
(the Grafana dashboards with the same queries, units, thresholds and layout,
in Perses' own styling) and **Container logs** (VictoriaLogs). They live in the
`krate` project. The `perses-seed` step creates missing dashboards and replaces
one only when its shipped file changed, so edits made in the UI persist across
restarts, as with Grafana. All plugins are built into the pinned Perses image;
nothing is downloaded at runtime. Mapping details:
[dashboards/README.md](perses/dashboards/README.md).

### Sign-in modes (`PERSES_AUTH_MODE` in `monitoring/.env`)

| Mode | Who can sign in | Roles |
| --- | --- | --- |
| `local` (default) | `PERSES_ADMIN_USER` with `PERSES_ADMIN_PASSWORD` (12+ characters, required) | That user is a full Perses admin. |
| `native` | Company SSO users in the Viewer or Admin IdP group | IdP groups become native Perses roles (recommended SSO mode). |
| `gateway` | Company SSO users in the Viewer or Admin IdP group | The gateway enforces roles; Perses' own auth is off. |

For `native` and `gateway`, follow the [Perses SSO guide](../sso/guides/perses-sso.md).
In both SSO modes, OAuth2 Proxy holds the IdP session and the `perses-sync`
guard checks every request:

- **Viewer** can read projects, dashboards, datasources, variables and folders
  and run queries through saved datasources (PromQL and LogsQL read endpoints
  only). Secrets, roles, role bindings and users cannot be read, in either
  mode. Every change, unsaved-datasource proxying and other proxy paths are
  refused.
- **Admin** has full Perses access, including creating projects.
- In `native` mode the guard keeps each user's native Perses role bindings equal
  to their current groups and confirms the user's live permissions before a
  request passes. Demotion or removal also revokes the owner grants Perses
  creates for projects the user made. Grants of users not seen with a current
  IdP session for `group_proof_minutes` plus two minutes are revoked, and a
  restart revokes all managed grants until users return.
- The IdP session is refreshed every `group_proof_minutes` (default 15), which
  brings current groups without signing out. Groups from an ID token older than
  that period (plus one minute) are not accepted. A revoked IdP session ends at the
  next refresh. Sessions last `session_hours` (default 8).
- Any failure denies the request; nothing falls back to an earlier grant.

In both SSO modes the gateway adds a small script to Perses' pages that asks the
guard for the user's current role. For a Viewer it hides Perses' write controls
(Edit, create, import, duplicate, rename and delete), the tabs for secrets,
roles, role bindings and users, and the edit-mode (`D` then `M`) and save
(`Ctrl`/`⌘`+`S`) shortcuts. If the role cannot be read, the controls stay hidden.
This only keeps the UI consistent: the guard and, in `native` mode, Perses refuse
every change by a Viewer either way. The script matches Perses v0.54.0 labels
and icons and must be re-checked when Perses is upgraded.

Switching modes: change `PERSES_AUTH_MODE` and run `./krate monitor up`. The CLI
re-renders configuration and recreates the affected services. Grants from the
previous mode are removed:

- To `native` or `gateway`: the guard removes the local admin's grant and every
  grant it manages when it starts, before it reports healthy.
- To `local`: the CLI first removes OAuth2 Proxy and the guard; then the
  `perses-seed` step removes the SSO role bindings, the guard's service binding
  and the SSO users, including their place in project owner bindings. Perses
  signs sessions with a key that does not change between modes, so a session
  from an SSO mode stays signed-in but has no access left.

### Configuration and secrets

The one-shot `monitoring-init` service renders each service's configuration
into that service's own volume from `monitoring/.env` and the site settings in
`monitoring/auth/perses/perses.json`. Secrets stay in `monitoring/.env`
(mode 600): `./krate monitor up` generates `PERSES_ENCRYPTION_KEY` and, for SSO,
`OAUTH2_PROXY_COOKIE_SECRET` when they are empty. A change to `.env`, the site
settings or any shipped monitoring file recreates the services that use it.

## VictoriaLogs

VictoriaLogs v1.53.0 keeps `VICTORIALOGS_RETENTION` (default `7d`) of container
logs in its own volume, with the same `job`, `container`, `container_id` and
`stream` labels and exact message text as Loki. It receives only logs collected
after it is added; existing Loki data is not imported. If VictoriaLogs is down,
Fluent Bit keeps delivering to Loki and queues up to 1 GiB for VictoriaLogs.

## Alertmanager

Prometheus sends its alerts to Alertmanager v0.34.1, which emails them to
`ALERT_EMAIL_TO` through the `GF_SMTP_*` relay, grouped by alert name, with a
10 s group wait, 5 min group interval, 4 h repeat and resolved notices.
`ALERTMANAGER_EMAIL_ENABLED` follows `GF_SMTP_ENABLED` unless set. While
Grafana email is also enabled, recipients receive both emails.
`ALERTMANAGER_SMTP_REQUIRE_TLS=true` (default) requires STARTTLS; port 465 uses
implicit TLS; `GF_SMTP_SKIP_VERIFY` also applies. Silences and notification
state persist in the `alertmanager_data` volume.

## Upgrading an existing installation

1. In the **old installation**, run `./krate monitor down` (never `down -v`).
2. Copy the site `monitoring/.env` into the new package and set
   `PERSES_ADMIN_PASSWORD`. Keep existing ports, SMTP, Grafana and token-file
   settings, and the existing data volumes. `krate` updates the `*_IMAGE` lines
   to the new package's `monitoring/.env.template` on the next `monitor` command.
3. Load the new package's images (`./krate install` or `./krate load-images`)
   and run `./krate monitor up`.
4. Check Grafana and Perses dashboards, Loki and VictoriaLogs for
   `job="containerlogs"`, and `./krate monitor status`.

Fluent Bit replaces the end-of-life Promtail collector. Its first run replays
available files from the head, subject to the seven-day cutoff, so recent Loki
lines can be duplicated once; later starts reuse its persistent offsets. To
roll back, stop the new monitoring project without deleting volumes and restore
the previous files and image references.

Verify the site's Docker `json-file` log path, permissions and SELinux access on
the target host; no automatic relabelling is performed.

## Licenses

Krate is AGPL-3.0. The bundled images keep their own licenses; their notices
and per-image inventories are in `fluent-bit/vendor/` and
`perses/vendor/notices/` (see its README for copyleft components).
