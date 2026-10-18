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

`./krate monitor up` starts everything; `./krate credentials` (or
`./krate monitor ui`) prints both addresses and logins. Grafana, its SSO configuration, its dashboards and its email rules
are not changed by the parallel path.

Grafana's sign-in is `GRAFANA_AUTH_CONFIG`: `local.ini` (Grafana's own login, the
default) or `realm.ini` (Krate sign-in; see
[`sso/guides/grafana-sso.md`](../sso/guides/grafana-sso.md)). Grafana keeps its sessions
in its database, which a recreate does not touch, so the `./krate monitor up` that
switches between the two ends the sessions the new sign-in does not allow. Going to
`realm.ini` it signs every user out of Grafana before it recreates Grafana (only Grafana's
own admin login can, and `realm.ini` turns that login off); going back to `local.ini` it
signs external-login users out right after Grafana is up again, including Krate sign-in users. Each prints
`Ended N Grafana session(s) of K user(s)`, a `monitor up` that changes nothing ends
nothing, and a switch that cannot end the sessions stops with the command that continues
it. `GRAFANA_AUTH_APPLIED` in `monitoring/.env` lists the sign-ins whose sessions
Grafana's database may hold (`local`, `realm` or `local,realm`) and is managed by krate: do
not edit it. What a refused or interrupted switch still owes stays in it, so the next
`./krate monitor up` repeats the step.

Prometheus (`PROM_PORT`, 9090) and Loki (`LOKI_PORT`, 3100) have no login of
their own, so they are published on the host's loopback interface only
(`PROM_BIND=127.0.0.1`, `LOKI_BIND=127.0.0.1` in `monitoring/.env`); set
`0.0.0.0` to publish them on every interface. Grafana and Perses reach them
inside the Docker network either way.

`prometheus/prometheus.yml` and `prometheus/alerts.yml` are bind-mounted as
single files, so edit them in place and run `./krate monitor reload`. It sends
Prometheus `SIGHUP` — its lifecycle API is off, so nothing on the network can
reload or stop it — and then reads Prometheus's own reload metrics: the command
fails when Prometheus rejected the file, and Prometheus keeps running with the
previous configuration in that case (`./krate monitor logs prometheus` shows
why). Editors that replace a file instead of writing it in place (vim's
default, `sed -i`) leave the container reading the old inode: the reload then
succeeds on the old content while your change is not in effect. After such an
edit run `./krate monitor up` (it recreates prometheus), or verify with
`docker exec <prometheus container> cat /etc/prometheus/prometheus.yml` that
the container sees your change.

## Perses

Perses v0.54.0 is reachable only through the `perses-gateway` nginx service on
`PERSES_PORT`, which serves HTTPS with the cluster certificate
(`certs/server.crt` and `certs/server.key`; `./krate` creates a self-signed pair
when none exists, or install your own). Perses, VictoriaLogs, Alertmanager, OAuth2 Proxy and the
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
| `local` (default) | `PERSES_ADMIN_USER` with `PERSES_ADMIN_PASSWORD` (generated when empty; `krate monitor ui` shows it) | That user is a full Perses admin. |
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
2. Run the new package's `./krate install`. It keeps `monitoring/.env` (taking it
   over from an installation made before `/opt/krate`), updates its `*_IMAGE`
   lines and fills new settings such as `PERSES_ADMIN_PASSWORD`; ports, SMTP,
   Grafana and token-file settings and the data volumes stay.
3. Run `./krate monitor up` in the installation directory.
4. Check Grafana and Perses dashboards, Loki and VictoriaLogs for
   `job="containerlogs"`, and `./krate monitor status`.

Fluent Bit replaces the end-of-life Promtail collector. Its first run replays
available files from the head, subject to the seven-day cutoff, so recent Loki
lines can be duplicated once; later starts reuse its persistent offsets. To
roll back, stop the new monitoring project without deleting volumes and restore
the previous files and image references.

Verify the site's Docker `json-file` log path, permissions and SELinux access on
the target host; no automatic relabelling is performed.

## Table 1 — Service exposure and enforcement

| component | host publish | networks | login | enforcement | residual |
| --- | --- | --- | --- | --- | --- |
| `grafana` | realm: `127.0.0.1:3000` (local: `0.0.0.0:3000`) | `monitoring`, `kafka-network` (alias `krate-grafana`) | realm: only the Krate realm — generic_oauth in `realm.ini`; login form and Basic off (`disable_login`, `[auth.basic] enabled = false`); no Grafana password works for people, and the `monitor up` that switches to it ends every session made with Grafana's own login (local: `GRAFANA_USER` Basic + login form) | `native OIDC` — Grafana's own backend maps realm groups to org roles (`role_attribute_path`, `role_attribute_strict = true`); a Viewer's write is refused by Grafana itself: no dashboard save, folder/datasource/alert-rule create, no user list (U6); no Loki write or lifecycle (U7, via `loki-gateway`); no Prometheus reload/quit/admin/remote-write (U8, lifecycle off) | public entry is the cluster proxy at `https://<host>/grafana/` (TLS); its own port is loopback-only in realm mode (U21a/b) and has **no login left** there, so every `monitoring` and `kafka-network` peer and host-local processes reach `:3000` unauthenticated (table 2 rows `kafka-network → grafana:3000`, `monitoring → grafana:3000`, `host → *:*`); anonymous `/grafana/healthz`, `/grafana/public/build/*`, `/grafana/avatar/*` answer through the proxy (U21a, table 2); a Grafana **Admin** reaches any HTTP service on both its networks through a created datasource (U28, table 2 `grafana-admin-datasource` rows); Grafana itself reaches every `monitoring` and `kafka-network` listener (table 2 `grafana` rows). Local mode keeps main's exposure: `0.0.0.0:3000` with anonymous `/metrics` and versioned `/api/health` — owner decision, plan §7 (rollback U22 returns to it) |
| `perses` | none | `perses` | realm: two RPs per sign-in — oauth2-proxy at the gateway **and** Perses' own OIDC (`PERSES_IDP=krate` → `enable_auth: true`, client `krate-perses`; native login off, its route denied by the guard) (local: `PERSES_ADMIN_USER` password) | `gateway` + `native OIDC` — the perses-sync guard checks every request at the gateway (group proof, role, Viewer allow-list, `whoami` subject match) **and** Perses RBAC enforces per-user bindings the guard keeps equal to the realm groups; Perses itself refuses Viewer writes even with the guard bypassed (V6, lab7 Q5) | no host port; `:8080` is open to every `perses`-network peer but answers 401 without a realm token in realm mode (V2; table 2 row `perses → perses:8080`); host-local processes reach the IP and get the same 401; gateway mode (`enable_auth: false`, full `:8080` bypass, defect 6) is **refused** with the realm (V1); a Viewer cannot create/change projects, dashboards, datasources, secrets, users, roles or use the unsaved-datasource relay (V5/V6) |
| `perses-gateway` | `0.0.0.0:3443` (all interfaces — the stack's only all-interface publish; the people entry) | `perses` | none of its own — nginx; unauthenticated browsers are sent to the realm sign-in (`/oauth2/start` → oauth2-proxy → Keycloak) in SSO modes, or to Perses' own login in local mode | `gateway` — every `location /` request runs `auth_request /_krate_guard` → perses-sync `/guard` (2xx allows, 401/403 deny; nginx subrequest auth), `/oauth2/` proxies to oauth2-proxy, TLS with the cluster certificate; the guard, not nginx, decides | whoever reaches `<host>:3443` gets the sign-in flow, nothing else (401/302 until a realm session); in-container `:80` (301 → HTTPS) and `:3443` are open to `perses` peers (table 2 rows `perses → perses-gateway:80` and `:3443`) and to host-local processes (`host → *:*`) |
| `oauth2-proxy` | none | `perses` | n/a — it is the authenticator: OIDC client `krate-perses` (PKCE S256), holds the realm session in cookies, `allowed_groups` = the two realm groups | `gateway` (component) — proves the live realm session to the guard (`GET /oauth2/auth`: 202 + subject + groups + ID token no older than the group-proof window) | `:4180` (rendered `http_address 0.0.0.0:4180`) open to `perses` peers (table 2 row `perses → oauth2-proxy:4180`) and host-local; `trusted_proxy_ips` limited to RFC1918; no host port; request logging off (no `code`/`state` in logs, Z4b) |
| `perses-sync` | none | `perses` | none (machine identity: guard client `krate-perses-sync`, client-credentials) | `gateway` (component) — the guard: per-request group proof, role mapping (admin wins, no group → 403), Viewer read allow-list, Perses `whoami` issuer+subject match, binding reconciliation; any failure denies | `:9091` open to `perses` peers (table 2 row `perses → perses-sync:9091`) and host-local; no host port |
| `perses-seed` | none | `perses` | none | none — client only; seeds dashboards with the admin/service credentials from its environment | no listener (`ExposedPorts null`, no socket in `seed.py`); while running it is a `perses` peer that can reach `perses:8080` with its credentials; nothing can reach it |
| `perses-migrate` | none | none (`network_mode: none`) | none | none — file I/O on `perses_data` (removes foreign-issuer OIDC users and stale guard bindings, never native users) | unreachable (no network namespace); W1 lists it with the no-host-port services |
| `monitoring-init` | none | none (`network_mode: none`) | none | none — renders configs/secrets into each consumer's volume (0400, consumer uid); `cap_drop ALL` + `CHOWN/FOWNER/DAC_OVERRIDE`, `read_only`, no-new-privileges | unreachable (no network namespace); secrets travel via volumes, never argv/network |
| `idp-wait` | none | `monitoring` | none | none — GETs the realm discovery document through the host-gateway `extra_hosts` route, verifies `issuer`, exits; holds Grafana/oauth2-proxy/Perses via `depends_on: service_completed_successfully` (E4/U13/V16) | no listener (`ExposedPorts null`); while running it is a `monitoring` peer (client only); exits 0 at once when `IDP_DISCOVERY_URL` is empty (local mode, render A) |
| `prometheus` | `127.0.0.1:9090` (both modes; `PROM_BIND` default — `0.0.0.0` if the operator sets it, commit 12 adds the `monitor_prepare` warning) | `monitoring`, `perses` | none — no OIDC at v3.6.0 (`--web.config.file` = TLS/bcrypt basic auth only, unused; research-backing §3.2/§4.4) | none — anyone reaching it "has access to all time series information contained in the database" (Prometheus security model, quoted in the compose comment); hardening: lifecycle API **off** (no `--web.enable-lifecycle`, commit 2 → `/-/reload`, `/-/quit` 403, W2/U8), admin API off, remote-write receiver off, `krate monitor reload` uses SIGHUP | loopback publish: every host-local user gets the full query API and UI with no login (table 2 `host → *:*`; lab3 L-1); `monitoring` **and** `perses` peers reach `:9090` (table 2 rows); Grafana Viewers query through the datasource proxy (any signed-in user can query; plugin route rules refuse Viewer non-GET writes, `ds_proxy.go:324-334`, and lifecycle is off); CORS echoes any Origin |
| `loki` | `127.0.0.1:3100` (both modes; `LOKI_BIND` default) | `monitoring` | none — Loki "does not come with any included authentication layer" (3.5.0 docs, research-backing §4.1); `auth_enabled: false` is tenant selection, not auth | none of its own; the **Grafana path** is enforced by `loki-gateway` (read-only allow-list, U7); Fluent Bit writes directly by design | loopback publish: host-local push/query/delete with no login (deletion endpoints available at documented defaults — `retention_enabled: true`, no `deletion_mode`; research-backing §4.1, doc-derived); `monitoring` peers reach `:3100` unauthenticated including push (table 2 rows `monitoring → loki:3100`, `grafana → loki:3100`, `host → *:*`); Grafana Viewers/Admins reach it only via the gateway or an Admin-created datasource (U7/U28) |
| `loki-gateway` | none | `monitoring` | none — nginx; no authentication (identity stays with Grafana's session) | none (of people) — it is an **authorization filter**: forwards only Loki's query API (GET/POST query paths, GET label values, GET+Upgrade tail, GET `/ready`); everything else — push, delete, `/config`, flush, ingester shutdown — 403 (gateway.conf); this is what makes U7 pass | `:3100` (read-only subset) open to `monitoring` peers and host-local (table 2 rows `monitoring → loki-gateway:3100`, `grafana → loki-gateway:3100`); the nginx image's exposed `:80` has **no listener** (probes refused; finding F1 covers the census enumeration) |
| `victorialogs` | none | `monitoring`, `perses` | none — `-httpAuth.*` basic auth exists at v1.53.0 but is unused; no OIDC (research-backing §3.4) | none — unauthenticated insert/select/vmui/metrics/flags; delete disabled (no `-delete.enable`); Perses reaches it only through 4 allowedEndpoints (POST select paths) | `:9428` open to all `monitoring` **and** `perses` peers and host-local, unauthenticated read+write (table 2 rows `monitoring → victorialogs:9428`, `perses → victorialogs:9428`, `grafana → victorialogs:9428`, `host → *:*`) |
| `alertmanager` | none | `monitoring` | none — `--web.config.file` basic auth exists at v0.34.1, unused; no OIDC (research-backing §3.3) | none — unauthenticated UI, config dump and **writes** (silences, alert injection, `-/reload`) from any `monitoring` peer; cluster gossip off (`--cluster.listen-address=` empty; `:9094` not listening, not exposed) | `:9093` open to `monitoring` peers and host-local (table 2 rows `monitoring → alertmanager:9093`, `grafana → alertmanager:9093`, `host → *:*`); owner decision: recorded, private `alerting` network rejected (plan §7); no UI consumer |
| `node-exporter` | none | `monitoring` | none (`--web.config.file` available, unused) | none | `:9100` host metrics (incl. `/debug/pprof/*` links) open to `monitoring` peers and host-local (table 2 rows `monitoring → node-exporter:9100`, `grafana → node-exporter:9100`); runs `pid: host` with `/proc`, `/sys`, `/` mounted read-only — host visibility tradeoff, recorded |
| `kafka-exporter` | none | `kafka-network`, `monitoring` | none — TLS/mTLS flags only at v1.8.0, no basic auth (research-backing §4.2) | none | `:9308` metrics open to both networks' peers and host-local (table 2 rows `monitoring → kafka-exporter:9308`, `kafka-network → kafka-exporter:9308`, `grafana → kafka-exporter:9308`); it is a Kafka client on the brokers' PLAINTEXT listener — the cluster's own trust model, unchanged (plan §7) |
| `fluent-bit` | none | `monitoring` | none | none — **no listener at all**: Krate's `[SERVICE]` sets no `HTTP_Server` (default off at 5.1.3, research-backing §4.3); client to `loki:3100` and `victorialogs:9428` only | the image exposes `:2020` but nothing listens (census probes are refused — no table-2 row); reads host container logs read-only (`/var/lib/docker/containers:ro`, metadata only, no Docker socket) |
| `log-discovery` | none | none (`network_mode: none`) | none | none — `read_only`, `cap_drop ALL`, no-new-privileges, tmpfs `/run/krate` | unreachable (no network namespace); shares `fluent_bit_sources` volume with fluent-bit (metadata-only file admission) |

## Table 2 — Accepted residual reachability

Networks and each service's own authorization separate the UIs from the backing
services, but a Docker network is a trust boundary, not a firewall: a container reaches
every other container on a network it shares, on any port that container listens on. This
table is the complete list of what stays reachable, and it is the list the executable gate
enforces: the census (row W4, `scripts/gate-identity.sh --phase 4c`) probes every container
port from five sources and fails on any reachable pair that is not here, and row U28
measures a Grafana administrator's datasource reach against the same table. A new row needs
the owner's approval.

`source` is where the probe runs, `target` is a Compose service name (or a shell-style pattern
of one: `kafka-[0-9]*` is every broker) and `port` a port that target listens on; `*` in
either column means "any". Target may carry an HTTP path suffix
`service:/path` for residuals measured through the cluster proxy (source `anonymous-https`,
port 443). Table 1 lists, per service, what it publishes and who authenticates it.

| source | target | port | why accepted |
| --- | --- | --- | --- |
| `grafana-admin-datasource` | `loki` | 3100 | A Grafana **Admin** can create a datasource and reach any HTTP service on Grafana's networks through it: Grafana applies `data_source_proxy_whitelist` only in the legacy proxy (`pkg/api/pluginproxy/ds_proxy.go:392` at v12.2.0), not on the datasource proxy and `resources` paths. A Viewer cannot (`POST /api/datasources` answers 403, row U6). Grafana's own Loki datasource points at the read-only `loki-gateway`, so the ordinary path cannot write to Loki (row U7); reaching `loki` directly needs a datasource an Admin created. |
| `grafana-admin-datasource` | `kafka-ui` | 8080 | The same Admin-only reach, to Kafbat's unauthenticated `/metrics` and `/actuator/` (`kafbat-ui/README.md`): the cluster proxy answers 404 for both publicly (row K27), but on `kafka-network` they are open. |
| `host` | `*` | `*` | Every container IP of both projects is open to any process on the Docker host, regardless of `ports:` or `internal:` — documented Linux-bridge behaviour (docker/docs port-publishing.md:19-23, research-backing §2) and measured on Rocky 9.8 with and without firewalld as uid 65534 and root (lab3 L-1: unpublished ports of bridge **and** internal-network containers reachable from host processes). Owner-accepted host-process residual (plan §7); the loopback publishes of prometheus/loki/grafana(realm) are the same trust in explicit form. W3 proves no *foreign* host can route to these IPs. |
| `monitoring` | `alertmanager` | 9093 | Prometheus alerts it and Grafana's provisioning reads it; any monitoring-network peer gets unauthenticated read **and write** (silences, alert injection, reload — verified research-backing §3.3). Owner decision: recorded, not firewalled (plan §7 "Alertmanager peers"); the private `alerting` network was the rejected alternative. |
| `monitoring` | `prometheus` | 9090 | The scrape/query bus: Grafana and Perses proxy it server-side; every monitoring peer can query all series with no login (Prometheus security model). Lifecycle/admin/remote-write off (commit 2, U8/W2), loopback-only publish (W1). |
| `monitoring` | `loki` | 3100 | Fluent Bit pushes here directly by design (the write path must not pass the read-only gateway); any monitoring peer can push/query/delete with no login (Loki has no auth layer, research-backing §4.1; deletion endpoints doc-derived, not runtime-verified). Grafana's path is the gateway (U7). |
| `monitoring` | `loki-gateway` | 3100 | Read-only Loki facade for Grafana (commit 3); monitoring peers get the query allow-list only, everything else 403 (gateway.conf). |
| `monitoring` | `victorialogs` | 9428 | Fluent Bit's second output and Perses' log datasource; monitoring peers get unauthenticated insert/select/vmui (verified research-backing §3.4); delete disabled (no `-delete.enable`). |
| `monitoring` | `node-exporter` | 9100 | Prometheus scrapes it; host metrics (and pprof links) are open to monitoring peers by design — that is the product's disk-capacity alerting path. |
| `monitoring` | `kafka-exporter` | 9308 | Prometheus scrapes it; metrics-only endpoint, no auth option at v1.8.0 beyond TLS (research-backing §4.2). |
| `monitoring` | `grafana` | 3000 | Grafana needs the monitoring network for its datasources; in realm mode its own port has no login left, so monitoring peers reach the same port the loopback publish exposes — answering only through the realm (as the `kafka-network` row already records). |
| `perses` | `perses` | 8080 | The gateway, guard, seed and migrate path share this network by design; in realm mode direct `:8080` answers 401 without a realm token (`enable_auth: true`, V2) — the gateway-mode full bypass (research-backing §3.6) is refused with the realm (V1). |
| `perses` | `oauth2-proxy` | 4180 | Only the gateway and the guard talk to it (auth endpoints); no host port, `trusted_proxy_ips` limited to RFC1918 (render.py:266). A perses-network peer can hit its endpoints but cannot mint a session without the realm. |
| `perses` | `perses-sync` | 9091 | The guard's API for the gateway (`/guard`, `/refresh`, `/role`); no host port. Not in the plan's W4 expected content — must be added or W4 fails on a reachable, unlisted pair. |
| `perses` | `perses-gateway` | 80 | The gateway's in-container HTTP listener (301 → HTTPS, render.py:327-330); perses peers reach it as they reach 3443. |
| `perses` | `perses-gateway` | 3443 | The public TLS entry is also a perses-network listener; from inside the network it is the same sign-in-gated surface as from outside. |
| `perses` | `prometheus` | 9090 | Perses' metrics datasource (HTTPProxy with allowedEndpoints, krate.json:30-58); network peers get the full unauthenticated query API as on the monitoring side. |
| `perses` | `victorialogs` | 9428 | Perses' logs datasource (4 POST select endpoints via allowedEndpoints, krate.json:76-99); network peers get unauthenticated insert/select as above. |
| `kafka-network` | `grafana` | 3000 | Grafana joins the cluster's `kafka-network` so the cluster proxy can serve it at `/grafana/` over TLS. Any peer of that network can reach the port; in realm mode the port has no login left (Basic authentication and the login form are off) and answers only through the realm, and on the host it is published on 127.0.0.1 only. |
| `kafka-network` | `kafka-[0-9]*` | `*` | The cluster's own trust model, unchanged by Phase 4: every kafka-network peer reaches the brokers' PLAINTEXT listeners (research-backing §1.3; Kafka client security deferred by the owner). |
| `kafka-network` | `kafka-ui` | 8080 | Kafbat's unauthenticated `/metrics` and `/actuator/` are open on the shared network (the cluster proxy 404s them publicly, K27); unchanged by Phase 4. |
| `kafka-network` | `proxy` | `*` | The cluster proxy listens on 80/443 for its networks; it answers only the hosts and paths it serves (same wording as the existing `grafana → proxy:*` row). |
| `kafka-network` | `kafka-exporter` | 9308 | The exporter joins the cluster network to reach brokers by name (compose:41-48); its metrics endpoint is open to that network as it is to `monitoring`. |
| `grafana` | `kafka-[0-9]*` | `*` | Grafana is a `kafka-network` peer, so the brokers' listeners are open to it exactly as they are to every other peer of that network (the cluster's own trust model, unchanged). |
| `grafana` | `kafka-ui` | 8080 | As above: Kafbat's unauthenticated `/metrics` and `/actuator/` on the shared network. |
| `grafana` | `kafka-exporter` | 9308 | A metrics endpoint with no login, on the two networks Grafana needs for its datasources. |
| `grafana` | `proxy` | `*` | The cluster proxy, reachable from `kafka-network`; it answers only the hosts and paths it serves. |
| `grafana` | `alertmanager` | 9093 | Grafana shares `monitoring`; alerting API open as row 2. (Provisioned alerting goes through Grafana itself; no Alertmanager datasource ships — research-backing §5.) |
| `grafana` | `prometheus` | 9090 | Grafana's provisioned Prometheus datasource (`access: proxy`, datasources.yml:4-12): the server-side query path every signed-in user gets; Viewer non-GET writes refused by the plugin route rules (ds_proxy.go:324-334) and lifecycle off (U8). |
| `grafana` | `loki` | 3100 | Grafana shares `monitoring` with Loki; the *provisioned* path is the gateway (row 24), but the container can reach Loki directly — which is exactly what an Admin-created datasource abuses (U28 row `grafana-admin-datasource → loki:3100`). |
| `grafana` | `loki-gateway` | 3100 | The provisioned Loki datasource URL (datasources.yml:20, commit 3): read-only allow-list; this is the enforced Viewer path (U7). |
| `grafana` | `victorialogs` | 9428 | Grafana shares `monitoring`; unauthenticated insert/select as row 6 (no VictoriaLogs datasource ships; reach is network membership only). |
| `grafana` | `node-exporter` | 9100 | Grafana shares `monitoring`; host metrics open as row 7. |
| `anonymous-https` | `proxy:/grafana/healthz` | 443 | Grafana's liveness endpoint, answered without a sign-in through the cluster proxy. It says whether Grafana is up and carries no user, organisation, datasource or metrics data (row U21a fails on any such body). |
| `anonymous-https` | `proxy:/grafana/public/build/` | 443 | One hashed front-end asset, so the login page can render before anybody signs in. Static content from the image; no Krate data. |
| `anonymous-https` | `proxy:/grafana/avatar/<hash>` | 443 | Grafana's avatar endpoint, which fetches a gravatar image for an e-mail hash. Offline it answers an error and never returns Krate data; the hash is not a Krate identifier. |

## Licenses

Krate is AGPL-3.0. The bundled images keep their own licenses; their notices
and per-image inventories are in `fluent-bit/vendor/` and
`perses/vendor/notices/` (see its README for copyleft components).
