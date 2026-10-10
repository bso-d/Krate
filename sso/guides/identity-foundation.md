# Identity foundation (Keycloak first, Phase 1)

This guide describes the identity service that Krate runs beside the cluster:
Keycloak 26.8.0 with a PostgreSQL 17 database, both in the `sso` Compose
profile of the edition's `docker-compose.yml`. It covers EPC and regular
Krate. The frozen ZooKeeper edition has no identity service.

Phase 1 is the foundation only. Keycloak runs, holds local users in the realm
`krate`, and is managed with `./krate identity`. Kafbat keeps its shared Admin
login (`auth/ui/local.yml`) until Phase 2 switches it to `runtime.yml`.
Phase 2 uses local Keycloak users only. PingFederate brokering is Phase 3.

Operator flow, in order:

1. `./krate setup` (or the first `./krate start`) creates `.env`, generates
   passwords and secrets and the UI certificate. Set `KEYCLOAK_PUBLIC_URL`
   now if the default (`https://localhost/identity`) is not the final address.
2. `./krate start` starts brokers, Kafbat and the nginx proxy. Until
   `identity up` has run, `start` prints
   `Identity services skipped (run: krate identity up)` and leaves Keycloak
   and its database out.
3. `./krate identity up` generates the database TLS material and the realm
   plan, starts PostgreSQL and Keycloak, creates the permanent Keycloak admin
   and sets `KEYCLOAK_ENABLED=true`.
4. Phase 2: `./krate auth configure` writes `auth/ui/runtime.yml` and the
   identity-provider plan `auth/keycloak/pingfederate-idp.json`; `./krate auth
   apply` switches Kafbat to Keycloak login. The realm file
   `auth/keycloak/krate-realm.json` stays owned by `identity up`. See
   [dual-login.md](dual-login.md).
5. Phase 3: the identity-provider plan is applied to the realm and PingFederate
   brokering returns.

Items marked **PROPOSED** are the lead's defaults. The owner confirms or
changes them before Phase 2.

## Stage 0 contracts

### Mode interpretation

Two `.env` keys describe the identity mode:

| `KEYCLOAK_ENABLED` | `KAFKA_UI_AUTH_CONFIG` | Meaning | Keycloak runs |
| --- | --- | --- | --- |
| `false` | `local.yml` | Phase 0. Kafbat shared Admin only. | No |
| `true` | `local.yml` | Phase 1. Keycloak runs with local users; Kafbat still uses the shared Admin login. | Yes |
| `true` | `runtime.yml` | Phase 2. Kafbat offers Keycloak login with local Keycloak users only; the realm has no identity providers. PingFederate brokering is Phase 3. | Yes |
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
| Shared Admin | `KAFKA_UI_USER` / `KAFKA_UI_PASSWORD` | Kafbat administrator through the local form | Nothing in Keycloak; it is not a Keycloak account |

**PROPOSED:** no human account gets realm-admin rights in realm `krate`. Realm
changes go through `./krate` or `kcadm` from the host, with a backup first.

### Support visibility

**PROPOSED (owner to confirm):** a support engineer who is not a host operator
may see `./krate identity status`, the identity journal, and
`./krate identity users list`. They do not get `.env`, `./krate credentials`,
or the backups. In Kafbat (Phase 2) a viewer sees metrics, consumer lag and
topic metadata, and does not see messages.

### Claim-to-permission contract

Keycloak issues a `groups` claim (group membership mapper, `full.path=false`,
in ID token, access token and userinfo). Kafbat (Phase 2) reads it:

| `groups` contains | Kafbat role |
| --- | --- |
| `KEYCLOAK_ADMIN_GROUP` (`KRATE_ADMINS`) | administrator |
| `KEYCLOAK_VIEWER_GROUP` (`KRATE_VIEWERS`) | viewer |
| both | administrator (**PROPOSED:** the higher role wins) |
| neither, or no claim | login denied; the customized Kafbat image rejects an OIDC login with no mapped role |

Group names are written into the realm plan when the realm is first created.
Changing `KEYCLOAK_*_GROUP` in `.env` later does not rename the realm groups;
`identity up` regenerates the plan but reconciles only the `krate-ui` URLs
(see "`./krate identity up`").

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
| `kafka-ui` | `krate-kafbat` / `epc-kafbat` | default | none | Reached only through the proxy. Does not depend on `keycloak`. |
| `proxy` | `krate-proxy` / `epc-proxy` | default | `KAFKA_UI_HTTP_PORT` (80), `KAFKA_UI_HTTPS_PORT` (443) | TLS from `certs/`; forwards only `/identity/realms/krate/` and `/identity/resources/` to Keycloak |
| `keycloak-db` | Compose default (`<project>-keycloak-db-1`) | `sso` | none | PostgreSQL 17, TLS on, `pg_hba.conf` from `auth/keycloak/db-tls/` |
| `keycloak` | Compose default (`<project>-keycloak-1`) | `sso` | none | HTTP 8080 and management 9000 stay inside the network |

### Services and published host ports: monitoring

| Service | Published ports | Networks | Notes |
| --- | --- | --- | --- |
| `kafka-exporter` | none | cluster network, `monitoring` | Joins the cluster's network to reach brokers by name |
| `node-exporter` | none | `monitoring` | `pid: host`; mounts `/proc`, `/sys`, `/` read-only |
| `prometheus` | `PROM_PORT` (9090) | `monitoring`, `perses` | HTTP, no authentication |
| `loki` | `LOKI_PORT` (3100) | `monitoring` | HTTP, no authentication |
| `log-discovery` | none | none | Reads `/var/lib/docker/containers` read-only |
| `fluent-bit` | none | `monitoring` | Reads `/var/lib/docker/containers` read-only |
| `grafana` | `GRAFANA_PORT` (3000) | `monitoring` | HTTP, Grafana login |
| `monitoring-init`, `perses-seed` | none | none / `perses` | One-shot renderers |
| `victorialogs` | none | `monitoring`, `perses` | |
| `alertmanager` | none | `monitoring` | Listens on 9093 inside the network only |
| `perses` | none | `perses` | Reached only through `perses-gateway` |
| `perses-gateway` | `PERSES_PORT` (3443) | `perses` | HTTPS with the cluster certificate (`PERSES_CERTS_DIR`) |
| `oauth2-proxy`, `perses-sync` | none | `perses` | profile `perses-sso` |

Prometheus, Loki and Grafana are published over plain HTTP. Changing that is an
owner decision (see "Open owner decisions"); Phase 1 leaves the ports as they
are.

### Networks

| Network | Driver | Members |
| --- | --- | --- |
| `<project>_kafka-network` | bridge | all cluster services, including `keycloak` and `keycloak-db`; `kafka-exporter` from the monitoring project joins it as an external network |
| `<monitoring project>_monitoring` | bridge | exporters, Prometheus, Loki, Fluent Bit, Grafana, VictoriaLogs, Alertmanager |
| `<monitoring project>_perses` | bridge | Prometheus, VictoriaLogs, Perses, its gateway, seed and SSO helpers |

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
| `auth/keycloak/pingfederate-idp.json` (Phase 2, from `auth configure`) | not mounted | identity-provider plan; applied to the realm in Phase 3 |
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
| `auth/keycloak/db-tls/ca.key`, `server.key` | host files | none | delete the directory and run `./krate identity up` while Keycloak is stopped (see "Database TLS material") |
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
| `proxy` to `keycloak` (8080) | plain HTTP inside the Compose bridge network; `KC_PROXY_HEADERS=xforwarded`, `KC_HOSTNAME=KEYCLOAK_PUBLIC_URL` | Accepted boundary. Only `/identity/realms/krate/` and `/identity/resources/` are forwarded; `/admin/`, `/realms/master/`, `/metrics`, `/health` are not reachable through the proxy. `KC_PROXY_TRUSTED_ADDRESSES` is not set, so Keycloak accepts `X-Forwarded-*` from any peer on the network (residual risk below) |
| `keycloak` to `keycloak-db` (5432) | TLS, `KC_DB_TLS_MODE=verify-server`, trust store `ca.crt`, server certificate SAN `DNS:keycloak-db` | Enforced. `pg_hba.conf` rejects plaintext TCP |
| Keycloak management port 9000 | not published; the Docker healthcheck and `identity status` use it inside the container | Enforced |
| `kcadm` administration | `docker exec` into the `keycloak` container against `http://localhost:8080/identity` | Host operator only |
| PostgreSQL local socket | `local all all trust` in `pg_hba.conf`; used by `pg_isready`, `identity rotate`, `backup` and `restore` through `docker exec` | Accepted: only the `postgres` process and `docker exec` (host operator) can use the socket |
| Any container on the cluster network to `keycloak:8080` | plain HTTP; the admin API answers there and is protected by credentials only | Residual risk (see below) |
| Monitoring web endpoints 9090, 3100, 3000 | plain HTTP on the host | Unchanged; owner decision |

Why the sources say so:

- Keycloak `db-tls-mode`: "Valid values are `disabled` and `verify-server`."
  "When set to `verify-server`, it enables encryption and server identity
  verification." For PostgreSQL "The truststore file must be a PEM-encoded
  certificate." (Keycloak 26.8.0 `db.adoc`.)
- Keycloak reverse proxy: "You should not proxy port 9000 because health checks
  and metrics use that port directly". "Exposed admin paths lead to an
  unnecessary attack vector." (Keycloak 26.8.0 `reverseproxy.adoc`.)
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
| `ca.crt` | 644 | private CA; Keycloak's trust store |
| `ca.key` | 600 | signs `server.crt` |
| `server.crt` | 644 | SAN `DNS:keycloak-db` |
| `server.key` | 600 | copied into the container as `postgres` 600 at every start |
| `pg_hba.conf` | 644 | the rules above |

Existing files are kept. To renew: `./krate identity down`, move the directory
away, `./krate identity up`. The preflight refuses a `server.crt` that is not
signed by `ca.crt`, lacks the SAN, or expires within a day. Keycloak and
PostgreSQL both read the files at start, so a renewal needs a restart of both.

## Operator procedures

Run every command in the installation directory (`/opt/krate/kraft` or
`/opt/krate/epc`) or a checkout's `kraft/` or `epc/`. Brokers do not need to be
running for any `identity` command. Every command that changes something
(`up`, `down`, `users add|enable|disable|reset-password`, `rotate`, `backup`,
`restore`, `recover-admin`) takes the lock `auth/.identity.lock/` and appends
one line to `auth/identity-journal.log`: `<ISO8601> <command> <outcome>
<detail>`, never a secret. The read-only commands `status`, `users list` and
`users groups` take no lock and write no journal line.

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
   files, the realm file, and that neither identity service publishes a port.
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
   and updates its `redirectUris`, `webOrigins` and
   `post.logout.redirect.uris` when they differ (journal line
   `up reconciled krate-ui urls`). Nothing else in the realm is reconciled:
   groups, token lifetimes, session limits and the other clients keep the
   values they were created with.
10. Sets `KEYCLOAK_ENABLED=true`, writes the journal line and prints
    `identity status`.

A second run with nothing to do prints `No changes`. When an admin or
`krate-cli` login fails on an existing database, the command stops with a
recovery hint (see "Recovery").

`KEYCLOAK_PUBLIC_URL` should be final before the first `identity up`. It can
be changed later with `./krate config set`; the next `identity up` reconciles
the `krate-ui` URLs and `auth apply` (Phase 2) rewrites `runtime.yml`. A
changed `KEYCLOAK_*_GROUP` is not applied to an existing realm (owner
decision 4).

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
| `users add <username> [--admin\|--viewer] [--email <addr>]` | creates the user in the chosen group, prints a one-time temporary password once, and sets required actions `UPDATE_PASSWORD` and `CONFIGURE_TOTP` |
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
`A-Z a-z 0-9 . _ -`. `./krate config set` accepts these four keys only while
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
   `krate-cli` login. Writes the journal line.

The database password is kept as it is: the restored dump contains no roles,
so a restore from before a `rotate KEYCLOAK_DB_PASSWORD` changes nothing about
that password.

### `./krate identity recover-admin`

Recreates the permanent master admin from `.env` with Keycloak's
bootstrap-admin recovery. Requires `keycloak` to be stopped. See "Recovery"
below for what it does and when to use it.

### Relationship with `auth apply` (Phase 2)

`./krate auth apply` does not start Keycloak and does not run the
`identity up` logic. With `KAFKA_UI_AUTH_CONFIG=runtime.yml` it checks that
Keycloak is ready; when it is not, it stops with
`Keycloak is not ready. Run: krate identity up (then: krate identity status)`.
When Keycloak is ready it recreates only `kafka-ui` and checks the proxy.
Brokers must be healthy for that recreation only.

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
   `./krate auth configure <site.json>` and `./krate auth apply` again.
   PingFederate brokering is not available in Phase 1 and Phase 2; it returns
   in Phase 3, when the identity-provider plan is applied to the realm.

## Residual risks

- Any container on the cluster network can reach `keycloak:8080`, including
  the admin API and the `master` realm, over plain HTTP. Credentials still
  protect it. `kafka-exporter` from the monitoring project is on that network.
  A separate identity network is a Phase 2 candidate.
- Any container on the cluster network can reach `keycloak-db:5432`. TLS and
  SCRAM are required; the password is in `.env` and the Keycloak container.
- The local socket in `keycloak-db` is `trust`. Only processes inside that
  container reach it, which means the host operator through `docker exec`.
- `ssl_ca_file` is set but client certificates are not required
  (`clientcert` is not used in `pg_hba.conf`).
- The Compose file carries no `KC_BOOTSTRAP_ADMIN_*` variables. Passing them
  empty was tried and rejected by Keycloak 26.8.0 ("bootstrap-admin-username
  available only when bootstrap admin password is set"), so the master realm
  is created by `kc.sh bootstrap-admin user` in a one-off container instead.
- The realm plan is imported once. Realm import "is skipped" when the realm
  exists. `identity up` reconciles only the `krate-ui` URLs afterwards; later
  changes to groups, token lifetimes or session limits in `.env` do not reach
  an existing realm.
- Keycloak trusts `X-Forwarded-*` headers from any peer on the cluster
  network: `KC_PROXY_HEADERS=xforwarded` is set and
  `KC_PROXY_TRUSTED_ADDRESSES` is not. The 26.8.0 reverse proxy guide says:
  "To ensure that proxy headers are used only from proxies you trust, set the
  `proxy-trusted-addresses` option to a comma-separated list of IP
  addresses", and "Without this restriction, clients could bypass the proxy
  and send forged forwarded headers directly to Keycloak." Today the peers are
  the cluster containers and `kafka-exporter`; Keycloak is not published on
  the host, and the proxy overwrites the headers it forwards. Setting the
  trusted addresses needs a fixed proxy address inside the Compose network,
  which is part of owner decision 5.
- The database TLS certificate is self-signed by a local CA with a fixed
  lifetime chosen at generation; nothing renews it automatically. The preflight
  warns within a day of expiry.
- Backups are only as safe as their passphrase. A lost passphrase means a lost
  backup.
- `monitoring/docker-compose.yml` still falls back to `changeme` when
  `GRAFANA_PASSWORD` is empty and `krate` did not generate one (manual Compose
  runs). `./krate monitor up` generates the password before the Grafana volume
  exists.
- Prometheus (9090), Loki (3100) and Grafana (3000) remain plain HTTP on the
  host; Perses (3443) uses the cluster certificate.
- The identity journal is a plain append-only file owned by the operator. It
  is not tamper-evident.

## Open owner decisions

Items 1 to 4 confirm what Phase 1 implements. Items 5 to 13 need a choice.
Each item lists the options, the recommended one, why, and the sources.
Quotes are from the sources listed at the end of this section.

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
`.env`, no `credentials`, no backups. Proposed for Phase 2: Kafbat viewer =
`view` on every resource plus `analysis_view` on topics, `messages_read` only
when the site sets `viewer_messages`; never `create`, `edit`, `delete`,
`messages_produce`, `messages_delete`, `reset_offsets` (the Kafbat action
names are from its RBAC reference [S12]). Source: the handover ("Default
support visibility should be metrics, lag and approved metadata").

### 4. MFA and session defaults (confirm)

Implemented: TOTP enrolment forced at first login for every local user;
access token 5 minutes; session idle 15 minutes; session maximum 8 hours; no
self-registration, no e-mail password reset, no offline tokens. Why: NIST
SP 800-63B requires two factors at AAL2 ("Proof of possession and control of
two distinct authentication factors is required") and reauthentication "at
least once per 12 hours" and "following any period of inactivity lasting 30
minutes or longer" [S6]; 8 hours and 15 minutes are inside those bounds, and
15 minutes matches the stricter AAL3 inactivity limit. The 5-minute token
bounds how long a revoked user keeps a valid bearer token (the handover's
"residual-access deadline"); Keycloak documents the three realm settings that
carry these values [S7].

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
