# Identity foundation (Keycloak first, Phase 1 and the Phase 2 infrastructure)

This guide describes the identity service that Krate runs beside the cluster:
Keycloak 26.8.0 with a PostgreSQL 17 database, both in the `sso` Compose
profile of the edition's `docker-compose.yml`. It covers EPC and regular
Krate. The frozen ZooKeeper edition has no identity service.

Phase 1 is the foundation only. Keycloak runs, holds local users in the realm
`krate`, and is managed with `./krate identity`. Kafbat keeps its shared Admin
login (`auth/ui/local.yml`) until Phase 2 switches it to `runtime.yml`, where
Kafbat signs users in through the realm only (no shared form login; roles from
the realm groups). Phase 2 uses local Keycloak users only. PingFederate
brokering is Phase 3. The Kafbat side is described in
[dual-login.md](dual-login.md).

The first Phase 2 commits implement the owner decisions 7, 8, 9 and 13 (see
"Open owner decisions"): a private `identity` Compose network with a fixed
proxy address that Keycloak trusts for forwarded headers, Prometheus and Loki
bound to the loopback interface, `./krate identity renew-db-tls` for the
database certificate, and `./krate identity logrotate` for the journal.

Operator flow, in order:

1. `./krate setup` (or the first `./krate start`) creates `.env`, generates
   passwords and secrets and the UI certificate. Set `KEYCLOAK_PUBLIC_URL`
   now if the default (`https://localhost/identity`) is not the final address.
2. `./krate start` starts brokers, Kafbat and the nginx proxy. Until
   `identity up` has run, `start` prints
   `Identity services skipped (run: krate identity up)` and leaves Keycloak
   and its database out.
3. `./krate identity up` generates the database TLS material and the realm
   plan, checks that no other Docker network uses the identity subnet, starts
   PostgreSQL and Keycloak, creates the permanent Keycloak admin and sets
   `KEYCLOAK_ENABLED=true`. Optionally `./krate identity logrotate --install`
   hands the journal to the host's logrotate (`./krate install` prints the
   hint).
4. Phase 2: `./krate auth configure` writes `auth/ui/runtime.yml` from `.env`
   and the edition's cluster list (Keycloak as the only issuer, the two roles
   mapped from the realm groups, no shared form login);
   `./krate config set KAFKA_UI_AUTH_CONFIG=runtime.yml` and
   `./krate auth apply` switch Kafbat to that login. The realm file
   `auth/keycloak/krate-realm.json` stays owned by `identity up`. See
   [dual-login.md](dual-login.md).
5. Phase 3: `./krate auth configure <site.json>` also writes the
   identity-provider plan `auth/keycloak/pingfederate-idp.json`, which is
   applied to the realm; PingFederate brokering returns behind the same issuer.

Items marked **PROPOSED** are the lead's defaults. The owner confirms or
changes them before Phase 2.

## Stage 0 contracts

### Mode interpretation

Two `.env` keys describe the identity mode:

| `KEYCLOAK_ENABLED` | `KAFKA_UI_AUTH_CONFIG` | Meaning | Keycloak runs |
| --- | --- | --- | --- |
| `false` | `local.yml` | Phase 0. Kafbat shared Admin only. | No |
| `true` | `local.yml` | Phase 1. Keycloak runs with local users; Kafbat still uses the shared Admin login. | Yes |
| `true` | `runtime.yml` | Phase 2. Kafbat signs users in through Keycloak only (no shared form login) with local Keycloak users; the realm has no identity providers. PingFederate brokering is Phase 3. | Yes |
| `false` | `runtime.yml` | Transitional. `krate` still adds the `sso` profile; `auth apply` stops and tells you to run `./krate identity up` when Keycloak is not ready. **PROPOSED:** treat as "identity required" rather than as an error. | Yes |

Rules:

- `krate` adds `--profile sso` to every Compose call when `KEYCLOAK_ENABLED=true`
  or `KAFKA_UI_AUTH_CONFIG=runtime.yml`.
- Exception for `start` (and any other `up`): when the realm plan
  `auth/keycloak/krate-realm.json` or `auth/keycloak/db-tls/ca.crt` is missing,
  or the database state is pristine, `krate` prints
  `Identity services skipped (run: krate identity up)` and runs that `up`
  without the `sso` profile. Brokers never wait for identity. The
  `runtime.yml` preflight still stops `start` when Kafbat needs Keycloak and
  it is not ready.
- `identity up` sets `KEYCLOAK_ENABLED=true`. `identity down` stops the two
  identity containers and changes nothing else.
- "Local mode" means the realm has no `identityProviders`. Users exist only in
  Keycloak and are managed with `krate identity users`.

### Admin scopes

| Scope | Who | Can do | Cannot do |
| --- | --- | --- | --- |
| Host operator | Anyone in the `docker` group or root on the VM | Everything: `./krate`, `docker exec`, read `.env`, read the backups | Nothing is withheld; protect the VM account |
| Keycloak master admin | `KEYCLOAK_ADMIN_USER` in realm `master` | Any Keycloak change. Used by `identity up`, `identity rotate`, recovery, and by the operator through `kcadm` from the host | Reach Keycloak through the proxy; the admin console and the `master` realm are not published |
| `krate-cli` service account | Client `krate-cli` in realm `krate` | Realm `krate` user management only: `manage-users`, `view-users`, `query-users`, `query-groups` | Change clients, groups, flows or the realm; touch `master` |
| Kafbat administrator | Members of `KEYCLOAK_ADMIN_GROUP` (default `KRATE_ADMINS`) | Kafbat administrator role on the configured clusters (Phase 2) | Anything in Keycloak |
| Kafbat viewer | Members of `KEYCLOAK_VIEWER_GROUP` (default `KRATE_VIEWERS`) | Kafbat viewer role (Phase 2) | Anything in Keycloak |
| Shared Admin | `KAFKA_UI_USER` / `KAFKA_UI_PASSWORD` | Kafbat administrator through the local form while `KAFKA_UI_AUTH_CONFIG=local.yml` | Sign in while `runtime.yml` is active (Kafbat then has no form login); anything in Keycloak; it is not a Keycloak account |

**PROPOSED:** no human account gets realm-admin rights in realm `krate`. Realm
changes go through `./krate` or `kcadm` from the host, with a backup first.

### Support visibility

**PROPOSED (owner to confirm):** a support engineer who is not a host operator
may see `./krate identity status`, the identity journal, and
`./krate identity users list`. They do not get `.env`, `./krate credentials`,
or the backups. In Kafbat (Phase 2) a viewer sees metrics, consumer lag and
topic metadata, and does not see message payloads unless the site opts in with
`KAFKA_UI_VIEWER_MESSAGES=true` (the table of what a viewer can and cannot do
is in [dual-login.md](dual-login.md)).

### Claim-to-permission contract

Keycloak issues a `groups` claim (group membership mapper, `full.path=false`,
in ID token, access token and userinfo). Kafbat (Phase 2) reads it from the
ID token after validating signature, issuer and audience; the user's identity
in Kafbat is the OIDC `sub`:

| `groups` contains | Kafbat role |
| --- | --- |
| `KEYCLOAK_ADMIN_GROUP` (`KRATE_ADMINS`) | administrator |
| `KEYCLOAK_VIEWER_GROUP` (`KRATE_VIEWERS`) | viewer |
| both | administrator (**PROPOSED:** the higher role wins) |
| neither, or no claim | login denied; the customized Kafbat image rejects an OIDC login with no mapped role |

Group names are written into the realm plan when the realm is first created.
Changing `KEYCLOAK_*_GROUP` in `.env` later does not rename the realm groups;
`identity up` regenerates the plan but reconciles only the `krate-ui` client
settings and the realm's OTP look-ahead window (see "`./krate identity up`").

## Resource inventory

Read from `kraft/docker-compose.yml`, `epc/docker-compose.yml` and
`monitoring/docker-compose.yml` on this branch.

### Compose projects

| Project | Set by | Compose file |
| --- | --- | --- |
| `krate-kraft` or `krate-epc` (or `KRATE_PROJECT` in `.env` for an installation made before `/opt/krate`) | `./krate` | `<edition>/docker-compose.yml` |
| `krate-kraft-monitoring` or `krate-epc-monitoring` | `./krate monitor` (`MONITOR_PROJECT`) | `monitoring/docker-compose.yml` |

### Services and published host ports: cluster

| Service | Container name | Profile | Published ports | Notes |
| --- | --- | --- | --- | --- |
| `kafka-92`..`kafka-95` (KRaft) | `krate-broker-9x` | default | `9092`-`9095`, `19092`-`19095` | PLAINTEXT listeners |
| `kafka-92`, `kafka-93` (EPC) | `epc-broker-9x` | default | `KAFKA_BROKER_92_PORT` (9092), `KAFKA_BROKER_93_PORT` (9093) | PLAINTEXT listeners |
| `kafka-ui` | `krate-kafbat` / `epc-kafbat` | default | none | Reached only through the proxy. Does not depend on `keycloak`. Networks `kafka-network` and `identity` |
| `proxy` | `krate-proxy` / `epc-proxy` | default | `KAFKA_UI_HTTP_PORT` (80), `KAFKA_UI_HTTPS_PORT` (443) | TLS from `certs/`; forwards only `/identity/realms/krate/` and `/identity/resources/` to Keycloak. Networks `kafka-network` and `identity`, with the fixed address `KRATE_IDENTITY_PROXY_IP` (172.29.250.10) on `identity` |
| `keycloak-db` | Compose default (`<project>-keycloak-db-1`) | `sso` | none | PostgreSQL 17, TLS on, `pg_hba.conf` from `auth/keycloak/db-tls/`. Network `identity` only |
| `keycloak` | Compose default (`<project>-keycloak-1`) | `sso` | none | HTTP 8080 and management 9000 stay inside the network. Networks `identity` and `identity-egress`; not on `kafka-network`. `KC_PROXY_TRUSTED_ADDRESSES` = the proxy address |

### Services and published host ports: monitoring

| Service | Published ports | Networks | Notes |
| --- | --- | --- | --- |
| `kafka-exporter` | none | cluster network, `monitoring` | Joins the cluster's network to reach brokers by name |
| `node-exporter` | none | `monitoring` | `pid: host`; mounts `/proc`, `/sys`, `/` read-only |
| `prometheus` | `PROM_BIND:PROM_PORT` (127.0.0.1:9090) | `monitoring`, `perses` | HTTP, no authentication; loopback only by default. `PROM_BIND=0.0.0.0` publishes it on every interface |
| `loki` | `LOKI_BIND:LOKI_PORT` (127.0.0.1:3100) | `monitoring` | HTTP, no authentication; loopback only by default. `LOKI_BIND=0.0.0.0` publishes it on every interface |
| `log-discovery` | none | none | Reads `/var/lib/docker/containers` read-only |
| `fluent-bit` | none | `monitoring` | Reads `/var/lib/docker/containers` read-only |
| `grafana` | `GRAFANA_PORT` (3000) | `monitoring` | HTTP, Grafana login |
| `monitoring-init`, `perses-seed` | none | none / `perses` | One-shot renderers |
| `victorialogs` | none | `monitoring`, `perses` | |
| `alertmanager` | none | `monitoring` | Listens on 9093 inside the network only |
| `perses` | none | `perses` | Reached only through `perses-gateway` |
| `perses-gateway` | `PERSES_PORT` (3443) | `perses` | HTTPS with the cluster certificate (`PERSES_CERTS_DIR`) |
| `oauth2-proxy`, `perses-sync` | none | `perses` | profile `perses-sso` |

Prometheus and Loki answer without any login, so since owner decision 8 they
are bound to the host's loopback interface (`PROM_BIND`, `LOKI_BIND` in
`monitoring/.env`, default `127.0.0.1`): the Compose short port syntax
`[HOST:]CONTAINER` with `HOST` = `[IP:]port`; when the IP "is not set, it
binds to all network interfaces (`0.0.0.0`)" (Compose specification [S2]).
`./krate monitor up` prints the Prometheus address with that bind. Grafana
(3000) keeps its own login and stays on every interface over plain HTTP until
Phase 4; Perses (3443) uses the cluster certificate.

### Networks

| Network | Driver | Members |
| --- | --- | --- |
| `<project>_kafka-network` | bridge | brokers, `kafka-ui`, `proxy`; `kafka-exporter` from the monitoring project joins it as an external network. `keycloak` and `keycloak-db` are no longer on it |
| `<project>_identity` | bridge, `internal: true`, subnet `KRATE_IDENTITY_SUBNET` (172.29.250.0/24), dynamic pool `KRATE_IDENTITY_IP_RANGE` (172.29.250.128/25) | `keycloak-db`, `keycloak`, `proxy` (fixed address `KRATE_IDENTITY_PROXY_IP`, 172.29.250.10, outside the dynamic pool so no other container can take it), `kafka-ui`. Exactly these four (the preflight checks membership). No route to the host or outside; nothing from the monitoring project |
| `<project>_identity-egress` | bridge | `keycloak` only: its route out of the host for the Phase 3 identity provider (an internal network has none) |
| `<monitoring project>_monitoring` | bridge | exporters, Prometheus, Loki, Fluent Bit, Grafana, VictoriaLogs, Alertmanager |
| `<monitoring project>_perses` | bridge | Prometheus, VictoriaLogs, Perses, its gateway, seed and SSO helpers |

`./krate identity up` refuses to continue when a Docker network outside this
Compose project (another project, Docker's own `bridge`, a hand-made network)
already covers the identity subnet; it names the network and the two keys to
change together (`KRATE_IDENTITY_SUBNET`, `KRATE_IDENTITY_PROXY_IP`). The
preflight checks the rendered configuration: `identity` is `internal: true`
with one subnet, `keycloak-db` is attached to `identity` only, `keycloak` is
not on `kafka-network`, the proxy has a fixed `ipv4_address` on `identity`
equal to `KC_PROXY_TRUSTED_ADDRESSES`, and that address is a host address
inside the subnet. The Compose specification: `internal`, "when set to `true`,
lets you create an externally isolated network"; `ipv4_address` lets you
"Specify a static IP address for a service container when joining the
network", and the network "must have an `ipam` attribute with subnet
configurations covering each static address" [S2].

To reach `keycloak-db` from the host for an ad-hoc `psql`, use the container
itself (`docker exec -it <project>-keycloak-db-1 psql -U keycloak -d keycloak`,
local socket, no password) or join the identity network with a one-off
container: `docker run --rm -it --network <project>_identity <KEYCLOAK_DB_IMAGE
from .env> psql "host=keycloak-db sslmode=verify-full sslrootcert=..."`. No
other network reaches it.

### Named volumes

| Volume | Project | Holds |
| --- | --- | --- |
| `kafka-92-data`..`kafka-95-data` | cluster (KRaft only) | broker logs |
| `keycloak_db_data` | cluster | the Keycloak database: realms, users, clients, sessions |
| `prometheus_data`, `grafana_data`, `loki_data`, `fluent_bit_state`, `fluent_bit_sources`, `victorialogs_data`, `alertmanager_data`, `perses_data`, `perses_seed_state`, `perses_sync_state`, `perses_rendered`, `gateway_rendered`, `alertmanager_rendered`, `oauth2_proxy_rendered`, `perses_sync_rendered` | monitoring | metrics, logs, dashboards, rendered configuration |

`./krate uninstall --purge` deletes the cluster project's volumes, including
`keycloak_db_data`. EPC broker data is not in a volume (next table) and
survives purge.

### Bind mounts and host paths

| Host path | Mounted into | Mode |
| --- | --- | --- |
| `.env`, `monitoring/.env` | not mounted; read by Compose | 600 |
| `certs/server.crt`, `certs/server.key` | `proxy` and `perses-gateway` | read-only; key 600 |
| `nginx.conf` | `proxy` | read-only |
| `auth/ui/` (`local.yml`, generated `runtime.yml`) | `kafka-ui` at `/etc/krate/auth` | read-only |
| `kafbat.yml` (EPC) | `kafka-ui` | read-only |
| `auth/keycloak/krate-realm.json` | `keycloak` at `/opt/keycloak/data/import/` | read-only; regenerated from `.env` by every `identity up`; imported only when realm `krate` does not exist |
| `auth/keycloak/pingfederate-idp.json` (from `auth configure <site.json>`) | not mounted | identity-provider plan; applied to the realm in Phase 3 |
| `auth/keycloak/truststores/` | `keycloak` at `/opt/keycloak/conf/truststores` | read-only; enterprise CA for PingFederate |
| `auth/keycloak/db-tls/` (`ca.crt`, `ca.key`, `server.crt`, `server.key`, `pg_hba.conf`) | `keycloak-db` at `/run/krate-db-tls` | read-only; keys 600 |
| `auth/keycloak/db-tls/ca.crt` | `keycloak` at `/opt/keycloak/conf/db-tls/ca.crt` | read-only |
| `auth/identity-journal.log` | not mounted | append-only log, no secrets |
| `auth/.identity.lock/` | not mounted | lock directory of a running `identity` command |
| `${KAFKA_DATA_DIR:-/data}/krate/broker-92`, `broker-93` (EPC) | brokers at `/var/lib/kafka/data` | read-write, SELinux private label |
| `monitoring/prometheus/`, `loki/`, `fluent-bit/`, `grafana/`, `perses/`, `auth/`, `render.py` | monitoring services | read-only |
| `/var/lib/docker/containers`, `/proc`, `/sys`, `/` | log collectors and `node-exporter` | read-only |

### Credential authority

"Authoritative store" is the place that decides whether a login works. `.env`
holds a copy that the containers and `./krate` read. When the two disagree,
the authoritative store wins and `./krate` fails to log in.

| Secret | Authoritative store | Copy | Change with |
| --- | --- | --- | --- |
| `KAFKA_UI_PASSWORD` | `.env` (Kafbat reads it at start) | none | `./krate config set`, then `./krate start` |
| `KEYCLOAK_DB_PASSWORD` | PostgreSQL role `keycloak` in `keycloak_db_data`. `POSTGRES_PASSWORD` is used only when the database is initialised. | `.env` | `./krate identity rotate KEYCLOAK_DB_PASSWORD` |
| `KEYCLOAK_ADMIN_PASSWORD` | user `KEYCLOAK_ADMIN_USER` in realm `master` | `.env` | `./krate identity rotate KEYCLOAK_ADMIN_PASSWORD` |
| `KEYCLOAK_CLI_CLIENT_SECRET` | client `krate-cli` in realm `krate`, once imported | `.env`, realm plan placeholder | `./krate identity rotate KEYCLOAK_CLI_CLIENT_SECRET` |
| `KEYCLOAK_KAFBAT_CLIENT_SECRET` | client `krate-ui` in realm `krate`, once imported | `.env`, realm plan placeholder, `runtime.yml` (Phase 2) | `./krate identity rotate KEYCLOAK_KAFBAT_CLIENT_SECRET` |
| `PING_KEYCLOAK_CLIENT_SECRET` | PingFederate (IAM) | `.env`, identity-provider plan `auth/keycloak/pingfederate-idp.json` (applied in Phase 3) | value from IAM, `./krate config set`, then `auth apply` |
| temporary bootstrap admin password (`temp-admin`, or `temp-admin-<random>` from `recover-admin`) | nowhere after the command ends | held only by the `identity up` or `identity recover-admin` process while it runs `kc.sh bootstrap-admin user`; never written to `.env` | not applicable; the account is deleted |
| `GRAFANA_PASSWORD` | Grafana's database in `grafana_data` after first start | `monitoring/.env` | Grafana UI or `grafana cli admin reset-admin-password`, then `./krate config set` |
| `PERSES_ADMIN_PASSWORD`, `PERSES_ENCRYPTION_KEY`, `OAUTH2_PROXY_*`, `PERSES_SYNC_CLIENT_SECRET` | `monitoring/.env`, rendered by `monitoring-init` | rendered volumes | `./krate config set`, then `./krate monitor up` |
| `certs/server.key` | host file | none | `./krate gen-cert` or your own certificate |
| `auth/keycloak/db-tls/server.key` | host file | copied into `keycloak-db` at start | `./krate identity renew-db-tls` (new key and certificate under the same CA) |
| `auth/keycloak/db-tls/ca.key` | host file | none | delete the directory and run `./krate identity up` while Keycloak is stopped (see "Database TLS material") |
| `KRATE_BACKUP_PASSPHRASE` | the operator | never stored | not applicable |

Placeholders in `.env.template` are only empty or `REPLACE_ME`. `./krate`
fills them before the database first starts. The old template default
`changeme` is also treated as a placeholder, but only while nothing uses it: `setup`/`start`
replace it with a generated password as long as no Kafbat UI container exists,
and `monitor up` does the same for Grafana while its volume does not exist.
Once a value is live, `start` refuses to run with `changeme` until you set a
password (or empty the key to have one generated), `monitor up` refuses until
the Grafana admin password is changed in Grafana and recorded, and `identity
up`, `auth apply` and the preflight refuse it as well. A live value is never
replaced silently.

`start`, `stop`, `restart`, `down`, `install` and `uninstall` take the identity
lock once `KEYCLOAK_ENABLED=true` (or `runtime.yml` is selected), so they wait
for a running `identity backup`, `restore`, `rotate` or `recover-admin`.

## Trust boundaries

| Hop | Protection | Status |
| --- | --- | --- |
| Browser to `proxy` (443) | TLS with `certs/server.crt` | Users must trust the certificate's issuer |
| `proxy` to `kafka-ui` (8080) | plain HTTP inside the Compose bridge network | Accepted boundary |
| `proxy` to `keycloak` (8080) | plain HTTP inside the internal `identity` network; `KC_PROXY_HEADERS=xforwarded`, `KC_PROXY_TRUSTED_ADDRESSES` = the proxy's fixed address, `KC_HOSTNAME=KEYCLOAK_PUBLIC_URL` | Accepted boundary. Only `/identity/realms/krate/` and `/identity/resources/` are forwarded; `/admin/`, `/realms/master/`, `/metrics`, `/health` are not reachable through the proxy. Kafbat's unauthenticated `/metrics`, `/actuator/` and its back-channel endpoint `/logout/connect/` are answered 404 by the proxy as well. Forwarded headers are used only when they arrive from the proxy address (owner decision 7). The proxy sends `X-Forwarded-For/Proto/Host` only and clears a client's `Forwarded`, `X-Forwarded-Prefix`, `X-Forwarded-Ssl`, `X-Forwarded-Port` |
| `keycloak` to `keycloak-db` (5432) | TLS, `KC_DB_TLS_MODE=verify-server`, trust store `ca.crt`, server certificate SAN `DNS:keycloak-db` | Enforced. `pg_hba.conf` rejects plaintext TCP |
| Keycloak management port 9000 | not published; the Docker healthcheck and `identity status` use it inside the container | Enforced |
| `kcadm` administration | `docker exec` into the `keycloak` container against `http://localhost:8080/identity` | Host operator only |
| PostgreSQL local socket | `local all all trust` in `pg_hba.conf`; used by `pg_isready`, `identity rotate`, `backup` and `restore` through `docker exec` | Accepted: only the `postgres` process and `docker exec` (host operator) can use the socket |
| `kafka-ui` (and `proxy`) to `keycloak:8080` | plain HTTP inside the `identity` network; the admin API answers there and is protected by credentials only | Accepted: those two are the only other members; brokers and the monitoring project's `kafka-exporter` have no route to Keycloak or its database any more |
| `keycloak` to the outside (Phase 3 identity provider) | `identity-egress` bridge network, Keycloak only | Enforced membership; the identity provider's TLS is checked against `auth/keycloak/truststores/` |
| Prometheus 9090 and Loki 3100 | plain HTTP, bound to `127.0.0.1` on the host (`PROM_BIND`, `LOKI_BIND`) | Enforced by default; an operator may open them with `0.0.0.0` |
| Grafana 3000 | plain HTTP on every interface, Grafana login | Unchanged until Phase 4 (owner decision 8, option D) |

Why the sources say so:

- Keycloak `db-tls-mode`: "Valid values are `disabled` and `verify-server`."
  "When set to `verify-server`, it enables encryption and server identity
  verification." For PostgreSQL "The truststore file must be a PEM-encoded
  certificate." (Keycloak 26.8.0 `db.adoc`.)
- Keycloak reverse proxy: "You should not proxy port 9000 because health checks
  and metrics use that port directly". "Exposed admin paths lead to an
  unnecessary attack vector." (Keycloak 26.8.0 `reverseproxy.adoc`.)
- Keycloak trusted proxies: "To ensure that proxy headers are used only from
  proxies you trust, set the `proxy-trusted-addresses` option to a
  comma-separated list of IP addresses"; "Without this restriction, clients
  could bypass the proxy and send forged forwarded headers directly to
  Keycloak."; and the limit, "Note that this is only weak protection because
  IP addresses can be spoofed." (Keycloak 26.8.0 `reverseproxy.adoc` [S1].)
  That is why the proxy holds a fixed address on a network that nothing but
  the four identity members can join.
- Prometheus: "It is presumed that untrusted users have access to the
  Prometheus HTTP endpoint and logs. They have access to all time series
  information contained in the database"; its endpoints "should not be exposed
  to publicly accessible networks like the internet" [S3]. Loki: "Grafana Loki
  does not come with any included authentication layer. You must run an
  authenticating reverse proxy in front of your services." [S4]. Hence the
  loopback binds.
- PostgreSQL key file: "the permissions on `server.key` must disallow any
  access to world or group; achieve this by the command `chmod 0600
  server.key`." The `keycloak-db` entrypoint wrapper copies the key with
  `install -o postgres -g postgres -m 600` before the server starts, because a
  bind-mounted file keeps the host owner. (PostgreSQL 17, "Secure TCP/IP
  Connections with SSL".)
- `pg_hba.conf`: `hostssl` "matches connection attempts made using TCP/IP, but
  only when the connection is made with SSL encryption"; `reject` means
  "Reject the connection unconditionally"; "The first record with a matching
  connection type, client address, requested database, and user name is used".
  (PostgreSQL 17, "The pg_hba.conf File".) The generated file is:

  ```text
  local   all all                     trust
  hostssl all all 0.0.0.0/0           scram-sha-256
  hostssl all all ::/0                scram-sha-256
  host    all all all                 reject
  ```

- The postgres image's `docker-entrypoint.sh` starts as root and switches
  user itself: `if [ "$(id -u)" = '0' ]; then` ... `exec gosu postgres
  "$BASH_SOURCE" "$@"`. That is why the wrapper can `install` the key as root
  and then `exec docker-entrypoint.sh postgres -c ...`. The image README
  states that "any option available in a `.conf` file can be set via `-c`".

## Database TLS material

`./krate identity up` generates, once, under `auth/keycloak/db-tls/`:

| File | Mode | Purpose |
| --- | --- | --- |
| `ca.crt` | 644 | private CA, valid 1825 days; Keycloak's trust store |
| `ca.key` | 600 | signs `server.crt` |
| `server.crt` | 644 | SAN `DNS:keycloak-db`, valid 398 days; renewed with `./krate identity renew-db-tls` |
| `server.key` | 600 | copied into the container as `postgres` 600 at every start |
| `pg_hba.conf` | 644 | the rules above |

Existing files are kept. The preflight refuses a `server.crt` that is not
signed by `ca.crt`, lacks the SAN, or expires within a day, and prints a
warning (the command continues) when it expires within 30 days:
`warning: auth/keycloak/db-tls/server.crt expires within 30 days (...); run
krate identity renew-db-tls`; the same two checks apply to `ca.crt`. The
renewal reissues the server key and certificate under the same CA, so
Keycloak's trust store does not change, unless the CA would expire before the
new certificate: then the CA is renewed too and Keycloak is restarted to read
it (see "`./krate identity renew-db-tls`"). To replace the CA by hand:
`./krate identity down`, move the directory away, `./krate identity up`;
Keycloak and PostgreSQL both read their files at start.

## Operator procedures

Run every command in the installation directory (`/opt/krate/kraft` or
`/opt/krate/epc`) or a checkout's `kraft/` or `epc/`. Brokers do not need to be
running for any `identity` command. Every command that changes something
(`up`, `down`, `users add|enable|disable|reset-password`, `rotate`, `backup`,
`restore`, `recover-admin`, `renew-db-tls`, `logrotate --install`) takes the
lock `auth/.identity.lock/` and appends one line to
`auth/identity-journal.log`: `<ISO8601> <command> <outcome> <detail>`, never a
secret. The read-only commands `status`, `users list`, `users groups` and
`logrotate` (without `--install`) take no lock and write no journal line.

### `./krate identity up`

1. Takes the lock.
2. Fills empty or `REPLACE_ME` identity secrets in `.env` only when the
   database volume does not exist yet ("pristine"). On an existing database it
   never generates a secret.
3. Generates the database TLS material when absent. Regenerates the realm
   plan `auth/keycloak/krate-realm.json` from `.env` on every run; the file is
   rewritten only when its content differs. Keycloak imports it only when
   realm `krate` does not exist yet.
4. Runs `sso/preflight.py --mode identity`. It checks `.env` mode 600, the
   public URL, `KEYCLOAK_ADMIN_USER` (lowercase, not starting with
   `temp-admin`), the group names, the five identity secrets (16+ characters,
   not placeholders, all different), `KC_DB_TLS_MODE=verify-server`, the TLS
   files, the realm file, that neither identity service publishes a port, and
   the identity network (internal, one subnet, members, the proxy's fixed
   address equal to `KC_PROXY_TRUSTED_ADDRESSES` and inside the subnet). It
   warns when the database certificate expires within 30 days.
   Then it lists every Docker network and stops when one outside this Compose
   project overlaps `KRATE_IDENTITY_SUBNET`, naming it and the two keys to
   change (`KRATE_IDENTITY_SUBNET`, `KRATE_IDENTITY_PROXY_IP`).
5. Stops if the database state is unknown (Docker unavailable, or volumes
   named `keycloak_db_data` in more than one project; the other edition's
   fixed project and `*-monitoring` projects are ignored).
6. Starts `keycloak-db` and waits for health, then reads the database over
   its local socket:
   - no `realm` table or no `master` realm ("unbootstrapped"; a pristine
     volume, or a volume whose first start never completed): stops `keycloak`
     if it is running, because "all the Keycloak nodes need to be stopped
     prior to using this command", then runs Keycloak's own
     `kc.sh bootstrap-admin user --username temp-admin` in a one-off
     container (the guide allows this "even before the first-ever start") with
     a one-time random password passed through an environment variable. That
     creates the master realm, so no bootstrap variables are ever needed in
     the Compose file. Then it starts `keycloak`, which imports realm `krate`.
   - `master` exists but has no user `KEYCLOAK_ADMIN_USER` ("no-admin"):
     writes the journal line and stops with the hint
     `krate identity recover-admin`. Nothing is recovered automatically.
   - otherwise ("bootstrapped"): starts `keycloak` and continues.
7. Unbootstrapped only: with `kcadm` inside the container, logged in as
   `temp-admin`, creates the permanent master user `KEYCLOAK_ADMIN_USER` with
   `KEYCLOAK_ADMIN_PASSWORD` and realm role `admin`, verifies a login as that
   user, then deletes `temp-admin`.
8. Every run: verifies the admin login and a client-credentials login of
   `krate-cli` against realm `krate`.
9. Bootstrapped only: compares client `krate-ui` in the realm with the plan
   and updates its `redirectUris`, `webOrigins`, `frontchannelLogout` (off:
   logout reaches Kafbat over the back channel only) and client attributes
   (`pkce.code.challenge.method`, `post.logout.redirect.uris`,
   `backchannel.logout.url`, `backchannel.logout.session.required`,
   `backchannel.logout.revoke.offline.tokens`) when they differ (journal line
   `up reconciled krate-ui urls and attributes`). It then compares the realm's
   `otpPolicyLookAheadWindow` with the plan (1) and sets it when it differs
   (`kcadm.sh update realms/krate -s otpPolicyLookAheadWindow=1`; journal line
   `up reconciled realm policy`), and each planned required action's
   `enabled`/`defaultAction` with the realm: a realm from Phase 1 still has
   `CONFIGURE_TOTP` as a default action, which a user PingFederate brokers in
   would be asked for; it is read with `GET authentication/required-actions/
   CONFIGURE_TOTP`, changed in that full representation and `PUT` back (never
   a partial `-n` update, which replaces the representation and wipes alias
   and name; journal line `up reconciled required action CONFIGURE_TOTP`).
   A realm created before these settings were planned receives them on the
   next `identity up`: an older realm has a look-ahead window of 0, which
   refuses a TOTP code typed across the 30-second boundary. Nothing else in
   the realm is reconciled: groups, token lifetimes, session limits and the
   other clients keep the values they were created with.
10. With the PingFederate plan `auth/keycloak/pingfederate-idp.json` present
    and `PING_KEYCLOAK_CLIENT_SECRET` set, applies the plan to the realm
    exactly as `auth apply` does (flows, provider, mappers, browser flow;
    journal line `up reconciled identity provider pingfederate: ...`, or
    `No changes`); with the secret unset it says so and leaves the realm
    alone; with the plan file absent and the provider present it removes the
    provider, its mappers and flows and rebinds the `browser` flow. Before
    all this, right after the realm plan, it records the truststore digest
    `KRATE_TRUSTSTORE_SHA` in `.env`, so step 6 recreates Keycloak when a
    PEM in `auth/keycloak/truststores/` changed. See
    [dual-login.md](dual-login.md), "Company SSO through PingFederate".
11. Sets `KEYCLOAK_ENABLED=true`, writes the journal line and prints
    `identity status`.

A second run with nothing to do prints `No changes`. When an admin or
`krate-cli` login fails on an existing database, the command stops with a
recovery hint (see "Recovery").

`KEYCLOAK_PUBLIC_URL` should be final before the first `identity up`. It can
be changed later with `./krate config set`; the next `identity up` reconciles
the `krate-ui` URLs, and `./krate auth configure --force` followed by
`./krate auth apply` (Phase 2) rewrites and applies `runtime.yml`. A
changed `KEYCLOAK_*_GROUP` is not applied to an existing realm (owner
decision 6).

### `./krate identity status`

One line per probe: `keycloak-db` container health; Keycloak `started`,
`ready` and `live` (management port 9000, read from inside the container);
realm `krate` present; the last journal lines. Exit code 1 when Keycloak is
not ready. Safe to run at any time.

### `./krate identity down`

Stops `keycloak` and `keycloak-db`. The volume stays. `.env` is not changed, so
the next `./krate start` brings both back.

### `./krate identity users ...`

All subcommands use `kcadm` with the `krate-cli` client credentials in realm
`krate`. The master admin is not involved.

| Command | Effect |
| --- | --- |
| `users list` | one line per user: `USERNAME ENABLED EMAIL`; groups are shown by `users groups <username>` |
| `users add <username> [--admin\|--viewer] [--email <addr>]` | creates the user in the chosen group, prints a one-time temporary password once, and sets the user's `requiredActions` to `CONFIGURE_TOTP` and `UPDATE_PASSWORD` (`identity.USER_REQUIRED_ACTIONS`); neither is a realm default action, so a user PingFederate brokers in is never asked for them |
| `users disable <username>` / `users enable <username>` | toggles the account |
| `users reset-password <username>` | new one-time temporary password, printed once, same required actions |
| `users groups <username>` | shows group membership |

Passwords are never accepted on the command line. The user changes the
temporary password and enrols TOTP at first login.

### `./krate identity rotate KEY`

`KEY` is one of `KEYCLOAK_DB_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`,
`KEYCLOAK_CLI_CLIENT_SECRET`, `KEYCLOAK_KAFBAT_CLIENT_SECRET`. Order:

1. Change the authoritative store first: `ALTER ROLE` through `psql` in
   `keycloak-db`; `kcadm set-password` in `master`; or
   `kcadm update clients/<id> -s secret=...` in `krate`.
2. Write `.env` atomically (temporary file, mode 600, rename).
3. Recreate the consumer: `keycloak` for the database password; `kafka-ui`
   for the Kafbat client secret only when `KAFKA_UI_AUTH_CONFIG=runtime.yml`.
4. Verify (ready, login) and write the journal line.

The new value is generated (24 characters) unless `--value` reads one from
standard input; a supplied value must be 16 or more characters from
`A-Z a-z 0-9 . _ -`.

Phase 3 adds `PING_KEYCLOAK_CLIENT_SECRET`, with `--value` required (the
value is issued by PingFederate, never generated, and accepted as issued: 16 or
more printable ASCII characters without whitespace, quotes, backslash, backtick
or `$`): `.env` is written first,
then, when the identity provider `pingfederate` exists in the realm, the
provider is `PUT` from the plan with the new secret (`Identity provider
pingfederate: secret updated`; journal `rotate PING_KEYCLOAK_CLIENT_SECRET
applied to identity provider pingfederate`); without the provider only `.env`
changes (`Identity provider pingfederate: not applied yet (krate auth
apply)`). The provider is never removed, so the users' federated-identity
links survive; `keycloak` is recreated once because the key is part of its
Compose environment. This is also the non-terminal way to set the secret the first
time (`auth apply` asks for it on a terminal). See
[dual-login.md](dual-login.md), "Rotating the PingFederate client secret".

`./krate config set` accepts these four keys only while
the database state is pristine; on any other state (`existing`, `unknown`) it
stops, quotes the state line and points to `rotate`. Because that state comes
from Docker, setting one of these keys needs a running Docker daemon.

### `./krate identity backup <file>`

Writes an encrypted archive that holds `db.dump` (`pg_dump -Fc` from
`keycloak-db`) and `identity.env` with exactly four keys:
`KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD`, `KEYCLOAK_CLI_CLIENT_SECRET`
and `KEYCLOAK_KAFBAT_CLIENT_SECRET`. The archive is encrypted with
`openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt` and then sealed with an
HMAC-SHA256 tag whose key is derived from the same passphrase with a separate
PBKDF2 salt (encrypt-then-MAC; `openssl enc` offers no authenticated mode).
`restore` verifies the tag before any byte is decrypted, unpacked or restored
and refuses a modified file. The passphrase comes
from `KRATE_BACKUP_PASSPHRASE` or is asked twice on a terminal. The file is
written with mode 600. Keycloak may stay running. Keep the passphrase with the
backup under site policy; without it the backup cannot be read.

`KEYCLOAK_DB_PASSWORD` is not in the archive: it is a PostgreSQL role, and
roles are not part of a single-database dump.

### `./krate identity restore <file>`

Refuses while `keycloak` is running (`./krate identity down` first) and when
the database state is unknown. A missing volume is accepted (the "volume
lost" case): `keycloak-db` then starts with a fresh database. Order:

1. Takes the lock, asks for the passphrase, starts `keycloak-db`.
2. Runs `pg_restore --clean --if-exists --single-transaction --no-owner` into
   the `keycloak` database. If `pg_restore` fails, the command stops and says
   that the database may be partially restored; run
   `./krate identity restore <file>` again, or follow "Database volume lost".
3. Writes the four keys from `identity.env` into `.env` where they differ
   (atomic write; journal line `restore reconciled .env: KEY1 KEY2`, never a
   value). `.env` then matches the restored store again.
4. Starts `keycloak` and verifies readiness, the admin login and the
   `krate-cli` login.
5. Regenerates the realm plan from this installation's `.env` and reconciles
   the `krate-ui` client and the realm's `otpPolicyLookAheadWindow` with it,
   as `identity up` does (journal lines `restore reconciled krate-ui urls and
   attributes` and `restore reconciled realm policy` when something changed):
   the dump carries the backup host's URLs and an older backup the older
   policy. Writes the journal line `restore ok <file>`.

The database password is kept as it is: the restored dump contains no roles,
so a restore from before a `rotate KEYCLOAK_DB_PASSWORD` changes nothing about
that password.

### `./krate identity recover-admin`

Recreates the permanent master admin from `.env` with Keycloak's
bootstrap-admin recovery. Requires `keycloak` to be stopped. See "Recovery"
below for what it does and when to use it.

### `./krate identity renew-db-tls`

Reissues `auth/keycloak/db-tls/server.key` and `server.crt` for 398 days and
puts them into use; when the CA would expire before that new certificate, the
CA is renewed with it (1825 days). Requires an existing identity database with
`keycloak-db` running. Order:

1. Takes the lock. `sso/identity.py db-tls --renew-server` checks that the
   full set of five files exists (an incomplete directory is refused: the CA
   is needed), removes work directories and `*.prev` files a killed earlier
   run left behind (so a rollback restores exactly this renewal's set, never
   an older CA beside a server certificate from the new one), issues the new
   material in a private temporary directory, keeps the files it replaces as
   `*.prev` and moves the new ones into place (`*.new`, then rename), key
   first, then certificate. It prints `renewed server
   certificate, valid until <date>` or `renewed CA and server certificate,
   valid until <date>`. `pg_hba.conf` does not change.
2. Restarts `keycloak-db` alone (`docker compose restart --no-deps`, "Don't
   restart dependent services" [S17]) and waits for its health. The container's
   entrypoint wrapper copies the files at start, which is how PostgreSQL loads
   them: "The server reads these files at server start and whenever the
   server configuration is reloaded" [S8]. Keycloak's open database
   connections drop with that restart. When the database does not come back
   healthy, the command restores the `*.prev` files (`db-tls --rollback`),
   restarts the database again, writes `renew-db-tls rolled back` to the
   journal and exits 1; the previous certificate is in service.
3. When the CA was renewed and `keycloak` is running, the `*.prev` files are
   kept until Keycloak has proven it trusts the new CA: the database's
   healthcheck does not exercise Keycloak's TLS chain. The command restarts
   `keycloak` with `--no-deps` (its trust store is the mounted `ca.crt`, read
   at start), waits for its health and logs in as the admin (both read the
   database over the new chain), and only then removes the `*.prev` files.
   When Keycloak does not come back healthy or refuses the login, the command
   restores the `*.prev` files, restarts `keycloak-db` and then `keycloak` on
   them, writes `renew-db-tls rolled back` and exits 1.
   With the same CA, it removes the `*.prev` files once the database is
   healthy, then waits up to 30 seconds for Keycloak to report ready again
   (its readiness includes the database); when it does not, restarts
   `keycloak` and verifies the admin login. When `keycloak` was not running
   at the start, the `*.prev` files are removed, Keycloak is left stopped and
   uses the new files on its next start.
4. Writes the journal line `renew-db-tls ok <what was renewed, new expiry>`.

Run it when the preflight warns about the 30-day window, or on a site
schedule. Nothing renews the certificate automatically.

### `./krate identity logrotate [--install]`

Renders `sso/logrotate/krate-identity.conf` with this installation's absolute
journal path (`<installation>/auth/identity-journal.log`) and, without
`--install`, prints it. With `--install` it writes the result to
`/etc/logrotate.d/krate-identity-<edition>` with mode 644 (through `sudo`
when not root, as the installation directory is created), takes the lock and
writes the journal line `logrotate installed <path>`. `./krate install` prints
the command as a hint. The rules:

```text
<installation>/auth/identity-journal.log {
    monthly
    rotate 12
    maxage 400
    copytruncate
    missingok
    notifempty
    compress
    delaycompress
}
```

logrotate(8) [S14]: `copytruncate` means "Truncate the original log file to
zero size in place after creating a copy", so krate's append-only writer needs
no reopen; `rotate 12`: "Log files are rotated count times before being
removed"; `maxage 400`: "Remove rotated logs older than <count> days";
`notifempty`: "Do not rotate the log if it is empty"; `delaycompress`:
"Postpone compression of the previous log file to the next rotation cycle".
Check the file with `sudo logrotate -d /etc/logrotate.d/krate-identity-<edition>`.
The installation path must not contain whitespace, quotes or backslashes
(logrotate's file syntax); `--install` refuses otherwise.

### Relationship with `auth apply` (Phase 2)

`./krate auth configure` (no settings file) plans Kafbat's Keycloak login,
`auth/ui/runtime.yml`, with `sso/identity.py runtime`: the same module that
plans the realm, so the client, the callback, the `groups` claim, the group
names and the session idle limit have one source, `.env`. The viewer gets
message payloads only when `KAFKA_UI_VIEWER_MESSAGES=true`
(`auth configure --viewer-messages` sets it). A `runtime.yml` that differs
from the plan is replaced only with `--force`.

`./krate auth apply` does not start Keycloak and does not run the
`identity up` logic. With `KAFKA_UI_AUTH_CONFIG=runtime.yml` it checks that
Keycloak is ready; when it is not, it stops with
`Keycloak is not ready. Run: krate identity up (then: krate identity status)`.
When Keycloak is ready it runs `sso/preflight.py --mode runtime.yml` (which
also checks `runtime.yml` against the plan and the realm's back-channel
logout attributes, and `kafbat.yml` on EPC for anything beyond the `kafka:`
section), records the digest of the applied auth file in `.env`
(`KRATE_UI_AUTH_SHA`, part of `kafka-ui`'s environment) and runs `up -d` for
`kafka-ui` and the proxy: Compose recreates `kafka-ui` only when that digest
or the image changed, so an unchanged re-apply keeps every signed-in session
(`Kafbat UI unchanged ... user sessions kept`). It then verifies public
discovery and prints the login model (`Sign-in: Keycloak (realm krate)`).
Brokers must be healthy for that recreation only. The realm client `krate-ui`
sends OIDC back-channel logout requests to
`http://kafka-ui:8080/logout/connect/back-channel/keycloak` over the
`identity` network, so a Keycloak logout or admin sign-out ends the Kafbat
session; disabling a user does not end an existing session (see
[dual-login.md](dual-login.md), "Revocation and session behaviour").

Phase 3: with the PingFederate plan `auth/keycloak/pingfederate-idp.json`
present, `auth apply` also takes the identity lock, records the truststore
digest `KRATE_TRUSTSTORE_SHA` and runs `up -d` for `keycloak` (recreated
exactly when a PEM in `auth/keycloak/truststores/` changed), then applies
the plan to the realm with `kcadm`; `identity up` re-applies it. Both are
described in [dual-login.md](dual-login.md), "Company SSO through
PingFederate (Phase 3)".

## Recovery

### Keycloak admin password lost or `.env` out of step

Symptom: `identity up` or `rotate` stops with "login failed" on an existing
database, or `identity up` stops with the hint `krate identity recover-admin`
because realm `master` has no user `KEYCLOAK_ADMIN_USER`.

Option A, restore: `./krate identity restore <backup>`. The archive carries
the admin user, admin password and the two client secrets that were valid
when it was taken, and `restore` writes them back into `.env`.

Option B, `./krate identity recover-admin`. It is an explicit operator action
and is never run automatically. It uses Keycloak's bootstrap-admin recovery.
Keycloak documents it: "For recovering lost admin access, use the dedicated
command described in the sections below." "Bear in mind that all the Keycloak
nodes need to be stopped prior to using this command." The account it creates
"is temporary" and "needs to be removed manually".

```bash
./krate identity down
./krate identity recover-admin
```

What it does: refuses while `keycloak` is running (run `./krate identity
down` first); starts `keycloak-db`; runs
`kc.sh bootstrap-admin user --username temp-admin-<random8> --password:env ...
--no-prompt` in a one-off container, with a one-time random password passed
through an environment variable; starts `keycloak`; logs in as that temporary
user; creates `KEYCLOAK_ADMIN_USER` in realm `master` if it is absent, sets its
password to the value `.env` holds and grants it realm role `admin`; verifies
the permanent login; deletes the temporary user and any leftover `temp-admin`;
verifies the `krate-cli` login; writes the journal line `recover-admin ok`.
The temporary password is never printed or stored. The permanent admin gets
the password that `.env` holds now; to change it afterwards, run
`./krate identity rotate KEYCLOAK_ADMIN_PASSWORD`.

Afterwards run `./krate identity up` to confirm the state and journal it.

### `krate-cli` client secret lost

Rotate it with the master admin: `./krate identity rotate
KEYCLOAK_CLI_CLIENT_SECRET`. If the master admin also fails, recover the admin
first.

### Database password lost

`./krate identity rotate KEYCLOAK_DB_PASSWORD` changes the role over the local
socket (no password needed), so it works even when `.env` is wrong.

### Database volume lost

With a backup: `./krate identity down` (if anything is running), then
`./krate identity restore <backup>`. `restore` accepts the missing volume,
starts `keycloak-db` with a fresh database, restores the dump into it, writes
the four keys from the archive back into `.env`, starts `keycloak` and
verifies the logins. The database password stays the current `.env` value,
because the fresh database was initialised with it. Without a backup, every
local user is gone; `./krate identity up` recreates the realm and the service
accounts from the plan and `.env`, and users are added again with
`./krate identity users add`.

## Upgrading from the previous Keycloak setup

Symptom: an `identity` command stops with "This `.env` or Keycloak database
predates `krate identity`" and points here. The installation has a
`keycloak_db_data` volume that was created before `krate identity` existed:
its realm `krate` has no `krate-cli` client, and `.env` has no
`KEYCLOAK_CLI_CLIENT_SECRET` (and usually none of the other new identity
keys). Phase 1 does not migrate such a database. Users, the PingFederate
identity provider and the browser flow in it are not carried over.

The preflight now also refuses a `KEYCLOAK_ADMIN_USER` outside
`a-z 0-9 . _ @ -` (Keycloak stores usernames in lower case) or starting with
`temp-admin`; rename it in `.env` before the first `identity up`.

Procedure:

1. With the old setup still running, back up its database with the previous
   procedure (plain `pg_dump`, outside `krate`), and keep a copy of `.env`:

   ```bash
   docker compose -p krate-<edition> --env-file .env --profile sso \
     exec -T keycloak-db pg_dump -Fc -U keycloak keycloak > keycloak-pre-identity.dump
   chmod 600 keycloak-pre-identity.dump
   ```

   `<edition>` is `kraft` or `epc`. For an installation made before
   `/opt/krate`, use the `KRATE_PROJECT` value from `.env` instead of
   `krate-<edition>`.
2. `./krate identity down`.
3. Remove the old volume explicitly by name; nothing in `krate` removes it for
   you:

   ```bash
   docker volume ls --filter label=com.docker.compose.volume=keycloak_db_data
   docker volume rm krate-<edition>_keycloak_db_data
   ```

   This deletes every local Keycloak user and session of the old setup.
4. `./krate identity up`. The database is pristine again: the missing identity
   keys are filled in `.env`, the realm is created from the plan, and the
   permanent admin is created.
5. Recreate the local users with `./krate identity users add`.
6. If Kafbat used Keycloak login (`KAFKA_UI_AUTH_CONFIG=runtime.yml`), run
   `./krate auth configure --force` (or `./krate auth configure <site.json>`
   after removing the old generated files) and `./krate auth apply` again.
   PingFederate brokering is not available in Phase 1 and Phase 2; it returns
   in Phase 3, when the identity-provider plan is applied to the realm.

## Upgrading an installation to the Phase 2 network and ports

The next `./krate start` (or any `up`) after this release recreates
`keycloak`, `keycloak-db`, `kafka-ui` and `proxy`, because their network
attachments changed; Compose creates `<project>_identity` and
`<project>_identity-egress` first. The brokers are not touched: their
configuration is unchanged, and `kafka-network` keeps its settings. Expect a
short Kafbat and Keycloak interruption; the Keycloak database volume and all
realm data stay. `.env` files from before this release lack
`KRATE_IDENTITY_SUBNET` and `KRATE_IDENTITY_PROXY_IP`; the Compose defaults
(172.29.250.0/24, 172.29.250.10) apply until you set them. If that range is in
use on the host, `./krate identity up` stops and names the clashing network
before anything is recreated; set both keys with `./krate config set`, then
run it again. If you change the subnet after the identity network exists,
remove the old network first (`./krate down`, then `docker network rm
<project>_identity`), since Compose does not change the IPAM of an existing
network.

From then on the identity containers are unreachable from the monitoring
project: `kafka-exporter` sits on `kafka-network`, and `keycloak` and
`keycloak-db` are not. Nothing in the monitoring stack scraped them. For an
ad-hoc `psql` see "Networks".

`./krate monitor up` publishes Prometheus and Loki on `127.0.0.1` only from
this release. An existing `monitoring/.env` without `PROM_BIND`/`LOKI_BIND`
gets the loopback default. If something outside the host read those endpoints
(nothing shipped by Krate does), set `./krate config set PROM_BIND=0.0.0.0`
and `LOKI_BIND=0.0.0.0` and run `./krate monitor up` again.

The database certificate issued by an earlier `identity up` keeps its 825-day
lifetime, and so does its CA (the old code issued both for 825 days); the
preflight warns 30 days before either expires, and `./krate identity
renew-db-tls` replaces the certificate with a 398-day one at any time, renewing
the CA with it when the CA would expire first.

## Residual risks

- `kafka-ui` and `proxy` can reach `keycloak:8080`, including the admin API
  and the `master` realm, over plain HTTP inside the `identity` network.
  Credentials still protect it. No other container has a route there any
  more (owner decision 7, implemented).
- `kafka-ui` and `proxy` can reach `keycloak-db:5432`. TLS and SCRAM are
  required; the password is in `.env` and the Keycloak container.
- `KC_PROXY_TRUSTED_ADDRESSES` is the proxy's fixed address, and Keycloak's
  guide notes that "this is only weak protection because IP addresses can be
  spoofed" [S1]. The address can only be claimed by a container attached to
  the internal `identity` network, which Compose limits to the four members;
  a host operator with Docker access could attach another container to it.
- The local socket in `keycloak-db` is `trust`. Only processes inside that
  container reach it, which means the host operator through `docker exec`.
- `ssl_ca_file` is set but client certificates are not required
  (`clientcert` is not used in `pg_hba.conf`).
- The Compose file carries no `KC_BOOTSTRAP_ADMIN_*` variables. Passing them
  empty was tried and rejected by Keycloak 26.8.0 ("bootstrap-admin-username
  available only when bootstrap admin password is set"), so the master realm
  is created by `kc.sh bootstrap-admin user` in a one-off container instead.
- The realm plan is imported once. Realm import "is skipped" when the realm
  exists. `identity up` (and `restore`) reconcile only the `krate-ui` client
  settings and the realm's OTP look-ahead window afterwards; later changes to
  groups, token lifetimes or session limits in `.env` do not reach an
  existing realm.
- The database TLS server certificate (398 days) is not renewed
  automatically. The preflight warns 30 days before expiry and refuses within
  a day; `./krate identity renew-db-tls` is an operator action. The CA (1825
  days) has no renewal command: replacing it means regenerating the directory
  with Keycloak stopped (see "Database TLS material").
- Backups are only as safe as their passphrase. A lost passphrase means a lost
  backup.
- `monitoring/docker-compose.yml` still falls back to `changeme` when
  `GRAFANA_PASSWORD` is empty and `krate` did not generate one (manual Compose
  runs). `./krate monitor up` generates the password before the Grafana volume
  exists.
- Grafana (3000) remains plain HTTP on every host interface with its own
  login until Phase 4; Prometheus and Loki are loopback-only unless an
  operator sets `PROM_BIND`/`LOKI_BIND` to `0.0.0.0`; Perses (3443) uses the
  cluster certificate. A process on the host itself still reaches Prometheus
  and Loki without a login.
- The identity journal is a plain append-only file owned by the operator. It
  is not tamper-evident. Rotation is in place only after
  `./krate identity logrotate --install` ran on the host; the file is small
  (one line per identity operation) but unbounded otherwise.

## Open owner decisions

Items 1 to 4 confirm what Phase 1 implements. Items 5 to 13 need a choice.
Each item lists the options, the recommended one, why, and the sources.
Quotes are from the sources listed at the end of this section.

**Decided 2026-10-10 (owner):** items 1 to 4 confirmed; for items 5 to 13 the
recommended option was accepted. Items 7 (B), 8 (B), 9 (B) and 13 (B) are the
first Phase 2 commits and are implemented on this branch (each item below
says what landed); item 6 (B) is revisited when Phase 2 adds the Kafbat side;
item 8 (D) belongs to Phase 4.

### 1. Local mode (confirm)

Implemented: local user accounts in realm `krate`; every integrated UI uses
the same Keycloak issuer whether or not an upstream identity provider is
enabled. Source: the handover ("apps keep the same Keycloak issuer in both
modes").

### 2. Administrative scope (confirm)

Implemented: one permanent master-realm admin (`KEYCLOAK_ADMIN_USER`) used by
`./krate` and host-side `kcadm`; realm user management through the `krate-cli`
service account with `manage-users`, `view-users`, `query-users`,
`query-groups`; no human realm-admin in `krate`; Keycloak administration does
not grant Kafka or host access. Why: the smallest set of permissions that
covers the required user lifecycle; the master realm stays off the proxy
(Keycloak: "Exposed admin paths lead to an unnecessary attack vector" [S1]).

### 3. Support visibility (confirm)

Implemented for Phase 1: `identity status`, the journal and `users list`; no
`.env`, no `credentials`, no backups. Implemented for Phase 2 (Kafbat side):
viewer = `view` on every resource plus `analysis_view` on topics,
`messages_read` only when the site sets `KAFKA_UI_VIEWER_MESSAGES=true` in
`.env`; never `create`, `edit`, `delete`, `messages_produce`,
`messages_delete`, `reset_offsets`, and never `ksql` (the Kafbat action names
are from its RBAC reference [S12]). The preflight refuses a `runtime.yml`
whose viewer reads messages without that opt-in. Source: the handover
("Default support visibility should be metrics, lag and approved metadata").

### 4. MFA and session defaults (confirm)

Implemented: TOTP enrolment forced at first login for every local user
(assigned per user by `identity users add`, together with the password
change; `CONFIGURE_TOTP` is enabled in the realm but not a realm default
action since Phase 3, decision D1 in [dual-login.md](dual-login.md): a
default would also apply to users PingFederate brokers in, whose MFA is the
enterprise identity provider's); access token 5 minutes; session idle 15
minutes; session maximum 8 hours; no self-registration, no e-mail password
reset, no offline tokens. Why: NIST
SP 800-63B requires two factors at AAL2 ("Proof of possession and control of
two distinct authentication factors is required") and reauthentication "at
least once per 12 hours" and "following any period of inactivity lasting 30
minutes or longer" [S6]; 8 hours and 15 minutes are inside those bounds, and
15 minutes matches the stricter AAL3 inactivity limit. The 5-minute token
bounds how long a revoked user keeps a valid bearer token (the handover's
"residual-access deadline"); Keycloak documents the three realm settings that
carry these values [S7]. For comparison, Keycloak's own defaults for a new
realm are 300 s access token, 30 minutes idle and 10 hours maximum
(`Constants.DEFAULT_ACCESS_TOKEN_LIFESPAN`, `DEFAULT_SESSION_IDLE_TIMEOUT`,
`DEFAULT_SESSION_MAX_LIFESPAN`, applied by `DefaultExportImportManager`
[S18]): the token value is Keycloak's default, the two session limits are
stricter.

### 5. Group precedence

Options: (A) a user in both groups is an administrator; (B) the viewer group
wins (membership in both yields viewer); (C) refuse login for a user in both
groups.

Recommended: A. Why: Kafbat's own authorization computes the union of every
role whose name is in the user's groups (`.filter(filterRole(user))` then
`.flatMap(role -> role.getPermissions().stream())`, with `filterRole` =
`user.groups().contains(role.getName())` [S11]). Option B would need a Kafbat
code change in the fork, and option C would need a Keycloak flow step; both add
surface to a Phase 2 patch that is meant to shrink it. Membership in both
groups is an administration mistake made visible by `users groups <u>`.

### 6. Renaming groups after the realm exists

Options: (A) document that `KEYCLOAK_*_GROUP` in `.env` is read only when the
realm is created, and rename groups through Keycloak administration together
with the Kafbat role mapping; (B) add `krate identity reconcile-groups`, which
renames the realm groups to the `.env` values and rewrites `runtime.yml`.

Recommended: A for Phase 1; revisit B when Phase 2 adds the Kafbat side.
Phase 2 status: `auth configure` plans the Kafbat roles from the same
`KEYCLOAK_*_GROUP` values and the preflight refuses a `runtime.yml` whose role
subjects differ from `.env`, so the two sides cannot drift apart; a rename of
the realm groups themselves is still an administration step (A).
Why: realm import is skipped for an existing realm ("If a realm already
exists in the server, the import operation is skipped" [S15]), so any rename
is an Admin REST operation (`PUT /admin/realms/{realm}/groups/{group-id}`
[S16]) that must change the Kafbat role subjects in the same step, otherwise
every user loses access. That coupling belongs to Phase 2, where both sides
exist.

### 7. Network separation and trusted proxy addresses

Options: (A) keep Keycloak and its database on the cluster network, no
`KC_PROXY_TRUSTED_ADDRESSES` (current); (B) Phase 2: an identity-only
Compose network marked `internal: true` with Keycloak, its database, the proxy
and Kafbat as the only members, the proxy with a static address, and
`KC_PROXY_TRUSTED_ADDRESSES` set to it; (C) option B plus TLS between the proxy
and Keycloak.

Recommended: B in Phase 2, on a fresh identity network. Why: Keycloak's guide
asks for the trusted list ("To ensure that proxy headers are used only from
proxies you trust, set the `proxy-trusted-addresses` option to a
comma-separated list of IP addresses", and warns that "rogue clients can
inject false values" otherwise; it also notes the limit: "this is only weak
protection because IP addresses can be spoofed" [S1]). A static address needs
a Compose network with an `ipam` subnet ("Specify a static IP address for a
service container when joining the network"; the network "must have an
`ipam` attribute with subnet configurations covering each static address"
[S2]). Changing the existing cluster network's IPAM would recreate the broker
containers, which Phase 1 must not do; a new `internal: true` network ("lets
you create an externally isolated network" [S2]) avoids that. C is not
recommended now: the hop is inside one Docker host and the certificate
lifecycle for a second internal CA adds operations without a changed threat.

**Decided: B, implemented.** Both Compose files define `identity`
(`internal: true`, `ipam` subnet `KRATE_IDENTITY_SUBNET`) and
`identity-egress`; `keycloak-db` is on `identity` only, `keycloak` on
`identity` and `identity-egress`, `proxy` and `kafka-ui` on `kafka-network`
and `identity`, the proxy with `ipv4_address: KRATE_IDENTITY_PROXY_IP` and
Keycloak with `KC_PROXY_TRUSTED_ADDRESSES` set to the same value. `identity
up` checks for a subnet clash; the preflight and `scripts/check-identity.py`
assert the rendered wiring in both editions. See "Networks" and "Upgrading an
installation to the Phase 2 network and ports".

### 8. Monitoring host ports 9090, 3100, 3000 over plain HTTP

Options: (A) unchanged; (B) bind Prometheus and Loki to `127.0.0.1` on the
host (`127.0.0.1:9090:9090`, `127.0.0.1:3100:3100`) and keep Grafana on 3000
until Phase 4; (C) put Prometheus, Loki and Grafana behind the existing nginx
proxy with TLS and Grafana login, and publish nothing else; (D) C plus
Keycloak login for Grafana (Phase 4).

Recommended: B now, as the first Phase 2 commit, then D in Phase 4. Why:
Prometheus states that anyone reaching its HTTP endpoint has "access to all
time series information contained in the database" and that the endpoints
"should not be exposed to publicly accessible networks" [S3]; Loki "does not
come with any included authentication layer" and "You must run an
authenticating reverse proxy in front of your services" [S4]; Grafana's
secure cookie "The default value is false" and needs HTTPS [S5]. The handover
requires reachable unauthenticated backing services to be closed before a
protected UI is accepted. B removes the unauthenticated endpoints from the
network with a two-line change and no new component; Grafana keeps its login
and the dashboards stay reachable. Who needs remote Prometheus or Loki access
(none is known) decides whether C is needed before Phase 4.

**Decided: B, implemented.** `monitoring/docker-compose.yml` publishes
`${PROM_BIND:-127.0.0.1}:${PROM_PORT:-9090}:9090` and
`${LOKI_BIND:-127.0.0.1}:${LOKI_PORT:-3100}:3100`; `monitoring/.env.template`
ships `PROM_BIND=127.0.0.1` and `LOKI_BIND=127.0.0.1`; `./krate monitor up`
prints the Prometheus address with the bind; `scripts/check-identity.py`
asserts the rendered binds. Grafana (3000) and Perses (3443) are unchanged.

### 9. Database TLS certificate lifetime and renewal

Options: (A) private CA, 825-day server certificate, manual renewal (current);
(B) 398-day certificate with a `krate identity renew-db-tls` command that
re-issues the server certificate under the same CA and reloads PostgreSQL;
(C) certificates from the site CA.

Recommended: A now, B as a Phase 2 addition. Why: the certificate is used on
one Docker-internal hop between two containers of one host, so public
certificate-lifetime policy does not apply, and the preflight refuses a
certificate that expires within a day, so expiry is caught before a start.
Renewal under the same CA needs no Keycloak trust change, and PostgreSQL
re-reads the files on reload ("The server reads these files at server start
and whenever the server configuration is reloaded" [S8]), so B can be done
without downtime for the database. C is right only when the site runs an
internal CA with automation; it adds an external dependency to a private hop.

**Decided: B, implemented.** New installs get a 398-day server certificate
and a 1825-day CA (`sso/identity.py`: `SERVER_CERT_DAYS`, `CA_CERT_DAYS`).
`./krate identity renew-db-tls` reissues the server pair under the existing
CA (or renews the CA too when it would expire first, then restarts Keycloak)
and restarts `keycloak-db` alone, rolling the files back when the database
does not come back healthy; the preflight warns 30 days before either
certificate expires. The restart (not a reload) was chosen because the container's
entrypoint wrapper copies the key into the container at start, so a reload
would still see the old copy; the database is down for the seconds of the
restart and Keycloak reconnects. See "`./krate identity renew-db-tls`".

### 10. Backups

Options: (A) operator-run `identity backup` on a site schedule, retention and
passphrase custody by site policy (current); (B) a `krate identity backup`
timer (systemd) writing daily to a directory with N retained files; (C) B plus
off-host copy.

Recommended: A for Phase 1 with a stated minimum: one backup before every
`rotate`, `restore`, Keycloak upgrade and Phase change, kept with its
passphrase in the site's secret store, retention at least the last five.
Why: the archive is consistent while Keycloak runs ("It makes consistent
backups even if the database is being used concurrently" [S9]); it holds one
database only, so the database role password is not in it ("pg_dump only dumps
a single database"; roles need `pg_dumpall` [S9]), which is why the archive
carries the four identity `.env` keys instead. The passphrase derivation uses
PBKDF2 with 600,000 iterations, the OWASP figure for PBKDF2-HMAC-SHA256
("600,000 iterations (recommended)" [S10]). A timer (B) is a small addition
once the schedule is known; it should not be invented before the owner names
one.

### 11. Transitional state `KEYCLOAK_ENABLED=false` with `runtime.yml`

Options: (A) tolerate it: `start` refuses until `identity up` has run and
tells the operator so (current); (B) refuse the combination in `config set`
and `auth apply` as a contradiction.

Recommended: A. Why: the state arises legitimately when a site `.env` is
restored on a new host or when `auth configure` runs before `identity up`; the
current behaviour fails closed (Kafbat is never started without its issuer)
and names the one command that resolves it. B would only move the same
message earlier and block `config set` of an unrelated key in the same file.

### 12. Temporary-admin cleanup failure

Options: (A) the command fails when a temporary admin cannot be deleted
(current); (B) warn, journal and continue.

Recommended: A. Why: Keycloak documents the account as temporary and says
"After that, the account needs to be removed manually" [S13]; a leftover
temporary admin with the realm role `admin` is an unaccounted credential. A
failed deletion means the admin session or the server is in an unexpected
state, which is a reason to stop and show it, not to continue. The next
`identity up` or `recover-admin` removes every `temp-admin*` account it finds.

### 13. Journal retention and rotation

Options: (A) append-only file, no rotation (current); (B) rotate with the
host's logrotate (`rotate 12`, monthly, `copytruncate`, keep under
`auth/`); (C) ship the lines to the monitoring stack's log pipeline.

Recommended: B, as a drop-in file the package installs under
`/etc/logrotate.d/` in Phase 2, with `copytruncate` so the append-only writer
needs no reopen ("Truncate the original log file to zero size in place after
creating a copy" [S14]); retention `rotate 12` ("Log files are rotated count
times before being removed") and `maxage 400` [S14]. Why: the journal grows
by one line per identity operation, so volume is small, but an unbounded
file on the installation disk is still an operational risk, and logrotate is
present on Ubuntu and RHEL without a new component. C depends on Phase 4.

**Decided: B, implemented.** `sso/logrotate/krate-identity.conf` ships in
the package (`sso/logrotate/` in a bundle); `./krate identity logrotate`
renders it with the installation's journal path and `--install` writes
`/etc/logrotate.d/krate-identity-<edition>`; `./krate install` prints the
hint. See "`./krate identity logrotate [--install]`".

### Sources

- [S1] Keycloak 26.8.0, "Using a reverse proxy":
  <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/server/reverseproxy.adoc>
- [S2] Compose Specification, networks and services:
  <https://docs.docker.com/reference/compose-file/networks/>,
  <https://docs.docker.com/reference/compose-file/services/>
- [S3] Prometheus, "Security model": <https://prometheus.io/docs/operating/security/>
- [S4] Grafana Loki, "Authentication":
  <https://grafana.com/docs/loki/latest/operations/authentication/>
- [S5] Grafana, "Configure security hardening":
  <https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-security-hardening/>
- [S6] NIST SP 800-63B, sections 4.2, 4.2.3 and 4.3.3:
  <https://pages.nist.gov/800-63-3/sp800-63b.html>
- [S7] Keycloak 26.8.0, session and token timeouts:
  <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/sessions/timeouts.adoc>
- [S8] PostgreSQL 17, "Secure TCP/IP Connections with SSL", 18.9.4:
  <https://www.postgresql.org/docs/17/ssl-tcp.html>
- [S9] PostgreSQL 17, pg_dump: <https://www.postgresql.org/docs/17/app-pgdump.html>
- [S10] OWASP Password Storage Cheat Sheet:
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- [S11] Kafbat v1.5.0 (pinned commit), `AccessControlService.getUserPermissions`:
  <https://github.com/kafbat/kafka-ui/blob/afc9c918e13c4422268a3a5b7933c7b448746c82/api/src/main/java/io/kafbat/ui/service/rbac/AccessControlService.java>
- [S12] Kafbat UI, RBAC reference:
  <https://ui.docs.kafbat.io/configuration/rbac-role-based-access-control>
- [S13] Keycloak 26.8.0, "Bootstrapping and recovering an admin account":
  <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/server/bootstrap-admin-recovery.adoc>
- [S14] logrotate(8): <https://man7.org/linux/man-pages/man8/logrotate.8.html>
- [S15] Keycloak 26.8.0, "Importing and exporting realms":
  <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/server/importExport.adoc>
- [S16] Keycloak 26.8.0 Admin REST API:
  <https://www.keycloak.org/docs-api/26.8.0/rest-api/index.html>
- [S18] Keycloak 26.8.0 realm defaults:
  <https://github.com/keycloak/keycloak/blob/26.8.0/server-spi-private/src/main/java/org/keycloak/models/Constants.java#L59>,
  <https://github.com/keycloak/keycloak/blob/26.8.0/model/storage-private/src/main/java/org/keycloak/storage/datastore/DefaultExportImportManager.java#L255-L266>
- [S17] Docker Compose CLI reference, `docker compose restart`:
  <https://docs.docker.com/reference/cli/docker/compose/restart/>
