# Grafana sign-in through the Krate realm

Grafana signs people in through the Krate realm (`<KEYCLOAK_PUBLIC_URL>/realms/krate`) with
its own generic OAuth support — no gateway in front of it — and enforces the realm groups in
its own backend. Users reach it over TLS at `https://<public host>/grafana/`, served by the
same cluster proxy that serves Kafbat. This is the operator procedure, the measured session
bounds and the residuals that stay accepted.

The frozen ZooKeeper edition has no monitoring sign-in and is not affected.

## What changes when you switch

| | before (`GRAFANA_AUTH_CONFIG=local.ini`) | after (`GRAFANA_AUTH_CONFIG=realm.ini`) |
| --- | --- | --- |
| Who authenticates | Grafana's own login form and HTTP Basic | the Krate realm only (`disable_login_form`, `disable_login`, `[auth.basic] enabled = false`) |
| Roles | Grafana's local users and their org roles | the realm groups: `KEYCLOAK_VIEWER_GROUP` → Viewer, `KEYCLOAK_ADMIN_GROUP` → Admin, both → Admin, neither → the sign-in is refused |
| Where roles are enforced | Grafana | Grafana itself: a Viewer's write is answered 403 by Grafana's API, not only hidden in the UI |
| Grafana's own port | published on every interface | published on `127.0.0.1` only (`GRAFANA_BIND`, set by `krate monitor up`) |
| Loki through a datasource | read **and write** (push, delete, flush, ingester shutdown) | read only: the datasource points at `loki-gateway`, which forwards Loki's query API and refuses everything else with 403 |
| Prometheus through a datasource | reload and quit reachable (`--web.enable-lifecycle`) | refused: the lifecycle API is off, the admin API and the remote-write receiver were never on |
| Public surfaces | `/metrics` and `/api/health` (with version and commit) answered without a login | `[metrics] enabled = false`, `[auth.anonymous] hide_version = true`, `[public_dashboards]` and `[snapshots]` off, and the port is on the loopback interface |
| Machine identities | the Basic admin, used by `monitoring/seed-alerting.py` | the `krate-seed` service account and its token (see below); no password is used by anything |
| Sessions | the ones made with Grafana's own login | only the ones made through Krate sign-in: the `krate monitor up` that applies the switch ends every session made with Grafana's own login, and people sign in again through Krate sign-in |

Two things keep working unchanged: the provisioned dashboards and their uid bindings
(`prometheus`, `loki`), and alert seeding — `seed-alerting.py` reads
`GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE` instead of the Basic admin.

## Prerequisites

1. The cluster and the identity stack run, in this order: `./krate identity up`,
   `./krate start`, `./krate auth apply`, `./krate monitor up` (Grafana still local).
   `auth apply` needs the running cluster, so it comes after `start`.
2. `KEYCLOAK_PUBLIC_URL` names a host that resolves to this installation for browsers
   **and** from inside containers — not `localhost`, `127.0.0.1` or `[::1]`: inside a
   container, `localhost` is the container. `krate monitor realm` and `krate monitor up`
   both refuse a loopback host before they change anything.
3. The certificate covers that host: `./krate gen-cert`, then `./krate auth apply`.
   Grafana verifies the issuer with the cluster CA (`tls_client_ca`), so certificate
   checks are never turned off.
4. The realm users who will sign in are in `KEYCLOAK_VIEWER_GROUP` or
   `KEYCLOAK_ADMIN_GROUP` and **have an e-mail address**: Grafana reads the address from
   userinfo and refuses a sign-in without one (`identity users add --email`, or
   `identity users set-email` for an existing user).

## Procedure

```bash
./krate config set KEYCLOAK_PUBLIC_URL=https://<fqdn>/identity
./krate gen-cert
./krate auth apply
./krate monitor up                       # Grafana still local: monitor realm reads it with the Basic admin
./krate monitor realm                    # checks, creates the client, secret, seed token, realm.ini
./krate config set GRAFANA_AUTH_CONFIG=realm.ini
./krate monitor up                       # ends every Grafana session, then recreates Grafana (and the one-shot that renders its secret)
./krate identity users add <name> --viewer --email <address>
```

`./krate monitor realm` runs **while Grafana is still local**, because only the Basic admin
can read what it checks. It refuses to run when Grafana already uses another
`GRAFANA_AUTH_CONFIG`; every later `./krate monitor up` regenerates `monitoring/auth/realm.ini`
and reconciles the client, so there is nothing to re-run by hand. In order it:

1. refuses a loopback `KEYCLOAK_PUBLIC_URL` host;
2. reads Grafana with the Basic admin and **refuses** when a database SSO setting for
   `generic_oauth` exists, or a public dashboard or a snapshot exists — after the switch
   those are hidden from the API (404/403), so they are counted and named before it;
3. generates `GRAFANA_OAUTH_CLIENT_SECRET` in `monitoring/.env` (0600) when it is empty;
4. creates the `krate-seed` service account (Admin) and a 90-day token, writes them to
   `monitoring/auth/secrets/grafana-seed.token` and `…/grafana-seed.meta` (directory 0700,
   files 0600, host only) and sets `GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE`;
5. lists every local Grafana user whose e-mail a realm user also has, each with the command
   that retires it;
6. creates the realm client `krate-grafana` (confidential, standard flow with PKCE S256,
   redirect `<origin>/grafana/login/generic_oauth`, no back-channel logout URL — Grafana has
   no such endpoint) and writes `monitoring/auth/realm.ini`.

Then retire the collisions it listed, one by one:

```bash
./krate monitor grafana-user retire <login>
```

Retiring sets the local user's e-mail to `<login>+retired@invalid` **and** disables it;
disabling alone is not enough, because Grafana matches on the address and the realm sign-in
would fail with "User sync failed". The retired user's folders and dashboards stay, and no
local user is taken over: the realm user signs in as a **new** Grafana user with the role
their group gives.

After `./krate config set GRAFANA_AUTH_CONFIG=realm.ini` and `./krate monitor up`, Grafana is
recreated (its `KRATE_GRAFANA_AUTH_SHA` covers `realm.ini`, the cluster certificate and the
client secret) and `monitoring-init` re-renders the secret into the volume Grafana mounts at
`/etc/krate/grafana/client-secret` (uid 472, mode 0400). No other monitoring container is
recreated, and no broker, Kafbat, Keycloak or proxy container is touched.

**A sign-in switch ends the sessions described below, with the stated timing limits.** Grafana keeps its sessions in its database, which
the recreate keeps, and a browser's session cookie names no port: without this step a session
made with Grafana's own login would still answer at `https://<host>/grafana/` after the
switch (seen on 2026-10-17: the local admin's session, created before the switch, was still
active after it). So `./krate monitor up`, when Grafana's sessions may still include ones made
with its own login, first signs every Grafana user out through Grafana's admin API with the
local admin's Basic login — the one credential that can, because realm mode turns it off and a
service account may not call the user endpoints — and prints
`Ended N Grafana session(s) of K user(s)`. Only then does it recreate Grafana. The caller's own
user, the local admin, cannot be signed out by the logout endpoint, so its sessions are revoked
one by one. A `monitor up` that does not change the sign-in ends nothing, and service accounts
and their tokens are never touched. Any config file other than `realm.ini` counts as Grafana's
own login.
If Grafana does not answer with the local admin login, the run stops before it recreates
Grafana. Health polling has a 30-second budget; individual requests and revocation can extend
the step. It also refuses a stopped cluster before it signs anyone
out. If Grafana is stopped, or already runs with Krate sign-in, start it with its own login first
(`./krate config set GRAFANA_AUTH_CONFIG=local.ini && ./krate monitor up`) and switch again.
The sign-ins whose sessions Grafana's database may hold are listed in `GRAFANA_AUTH_APPLIED`
(`monitoring/.env`, managed by krate), which `monitor up` and `monitor down` keep widened by the
sign-in Grafana runs, so a refused or interrupted run is repeated by the next one.
Limits: a browser that signs in with Grafana's own login after the sign-out and before Grafana
is recreated keeps that session (normally a few seconds; Compose first runs `monitoring-init`
and `idp-wait`, which waits up to two minutes for a realm that is down). An installation that has
no record yet — it was last started by an older Krate — and whose Grafana container is gone when
`monitor up` runs has nothing to read its previous sign-in from, so it ends nothing; after one
`monitor up` of this version the record exists, and one trip back to `local.ini` and forward
again ends the old sessions of an installation an older Krate switched.

## Seed token renewal

`./krate monitor up` renews the token when less than 30 days of its 90-day life are left: it
creates a 90-day successor with the current token (a service account may manage its own
tokens), writes token and meta, and only then deletes the old token by id. Grafana keeps
expired tokens listed, so the deletion is by id, not by name. Nothing else uses the Basic
admin in realm mode.

## Sessions, revocation and logout

Bounds at the shipped defaults (`KEYCLOAK_SESSION_MAX_HOURS=8`,
`KEYCLOAK_SESSION_IDLE_MINUTES=15`, access token 5 min), measured on the fixture:

| event | when the Grafana session ends |
| --- | --- |
| The user signs out in Grafana | at once: Grafana's logout goes to the realm's end-session endpoint with `post_logout_redirect_uri`, so both the Grafana and the Keycloak session end, with no confirmation page |
| `./krate identity users disable <name>` + `./krate identity users logout <name>` | within 300 s: Grafana refreshes its token ~10 s before expiry, and the refresh of a logged-out session fails. `disable` alone does not end a live session |
| Removing the user from `KEYCLOAK_ADMIN_GROUP` | at their next sign-in, which `./krate identity users logout <name>` forces now; the session is refused within 300 s and the next sign-in is a Viewer |
| Inactivity | at the first request after at most 15 min without one (measured 16 min). No lower bound is claimed: Grafana counts inactivity from its last session rotation (every 10 min) and the realm from its last token refresh, so a prompt can come 5 min after the last request |
| Session maximum | an active user is not prompted before 8 h and is prompted once it is reached: the realm caps every token at the session maximum |
| `GRAFANA_AUTH_CONFIG` switched between `local.ini` and `realm.ini`, then `./krate monitor up` | all human users before recreation going to `realm.ini`; external-login users after recreation going back to `local.ini`, once the API revocation completes; timing limits are below |
| Keycloak stopped | new sign-ins fail closed (the proxy answers 502); live sessions end at their next token check, within 300 s; running containers keep running (Grafana contacts the realm only at sign-in and refresh, with explicit endpoint URLs) and recover by themselves when it returns; containers that could not start during the outage start at the next `./krate monitor up`, which exits non-zero naming `idp-wait` while the realm is down |

Kafbat sessions are unaffected by any of this except `identity users logout`, which ends them
at once through the back-channel logout token.

## Rollback

```bash
./krate config set GRAFANA_AUTH_CONFIG=local.ini
./krate monitor up
```

Only Grafana (and the one-shot that renders configs) is recreated; brokers, Kafbat, Keycloak,
the proxy, Perses and every data volume stay as they are, and the local admin login works
again **on Grafana's own port**, which local mode publishes on every interface as before:
`http://<host>:<GRAFANA_PORT>/`. In local mode every `https://<host>/grafana…` path answers
`302` to the cluster proxy's `/login`, which is Kafbat's — that is expected, not a fault.
The realm client and the seed token are left in place, so switching back is the two commands
above. The same `./krate monitor up` ends external-login users' sessions, including those of
Krate sign-in users, right after Grafana is up again, with the local admin login, because Grafana's own login does not accept
them; it prints `Ended N Grafana session(s) of K user(s)`. External-login users' sessions stay valid on
Grafana's own port from the recreate until that line. Health polling has a 120-second budget,
but an in-flight request and per-user revocation can extend the run; there is no two-minute
limit for the whole step. If Grafana does not answer with that login the run
stops with an error after the recreate, and the next `./krate monitor up` repeats the step
(`GRAFANA_AUTH_APPLIED` in `monitoring/.env` still lists `realm`).
External classification requires consistent user-list authentication labels and a boolean
external-user profile flag; missing or conflicting metadata stops the command. It identifies
users with any external login, not ownership by the current realm or the origin of each
session. Local users are preserved on rollback; service accounts and their tokens are untouched.
A failed Docker inventory/config read or Compose action stops the command; unknown container
state is never treated as an absent Grafana or a completed switch.

## Residuals that stay accepted

- A Grafana **Admin** can create a datasource and through it reach any HTTP service on
  Grafana's networks (`loki:3100`, `kafka-ui:8080`): Grafana applies
  `data_source_proxy_whitelist` only in the legacy proxy
  (`pkg/api/pluginproxy/ds_proxy.go:392` at v12.2.0), not on the datasource proxy and
  `resources` paths a modern datasource uses. Only Admins can create datasources, and the
  reach is measured by the gate (row U28) and listed in
  [`monitoring/README.md`](../../monitoring/README.md) table 2.
- Grafana is a peer of the cluster's `kafka-network`, so it can reach the brokers' listeners,
  `kafka-exporter:9308` and Kafbat's unauthenticated `/metrics` and `/actuator/` on
  `kafka-ui:8080` (the cluster proxy hides both publicly). Same table, same census (row W4).
- Grafana's anonymous surfaces in realm mode: `/grafana/healthz`, one asset under
  `/grafana/public/build/` and `/grafana/avatar/<hash>` answer without a sign-in and return
  no user, org, datasource or metrics data (row U21a).
- `/grafana/api/health` no longer carries a version, and `/grafana/metrics` returns no
  metrics; the port itself is refused from another host over IPv4 and IPv6 (row U21b).

## Troubleshooting

| symptom | cause and fix |
| --- | --- |
| `x509: certificate signed by unknown authority` in Grafana's log | the certificate `KEYCLOAK_PUBLIC_URL` presents is not the one Grafana trusts. Run `./krate gen-cert`, then **`./krate auth apply`** and `./krate monitor up` — in that order, and both of them. nginx reads its certificate at start only, so `auth apply` is what recreates the cluster proxy (`KRATE_PROXY_CONF_SHA` digests `certs/server.crt` and `server.key`), while `monitor up` recreates Grafana (`KRATE_GRAFANA_AUTH_SHA` covers the same file). Running only `monitor up` leaves the proxy presenting the **previous** certificate while Grafana trusts the new one, and every token exchange then fails with x509 (measured: `harness/phase4/live4a/logs/165-d3-proxy-cert.log` — the fingerprints differ and the proxy's StartedAt predates the new `server.crt`) |
| A Loki query that worked before an edit to `monitoring/loki/gateway.conf` now fails, or the edit seems to have no effect | the gateway keeps serving the previous configuration: that file is a single-file bind mount, and replacing its contents leaves the running nginx holding a stale inode (`ESTALE` on Docker Desktop, observed in the live walk). `krate monitor up` does not recreate the container for a content-only change, because nothing it digests changed. Recreate it explicitly: `cd monitoring && docker compose -p krate-<variant>-monitoring up -d --force-recreate --no-deps loki-gateway`, then reload it with `nginx -s reload` if you only edited a query path |
| "IdP did not return a role attribute" | the user is in neither realm group: `./krate identity users groups <name>`, then add them (`role_attribute_strict = true` refuses a sign-in with no role) |
| `loginError: InternalError` and `/userinfo/emails` 404 in Grafana's log | the realm user has no e-mail address: `./krate identity users set-email <name> <address>` |
| "User sync failed" | a disabled local Grafana user still holds that e-mail. `./krate monitor grafana-user retire <login>` speaks to Grafana as the Basic admin, which realm mode turns off, so roll back first: `./krate config set GRAFANA_AUTH_CONFIG=local.ini && ./krate monitor up`, retire, then `./krate config set GRAFANA_AUTH_CONFIG=realm.ini && ./krate monitor up` |
| `krate monitor up` exits non-zero naming `idp-wait` | the realm did not answer within 120 s: start Keycloak (`./krate identity up`), then `./krate monitor up` again — the consumers were created, not started, and are not restart-looping. During such an outage `monitor up` also warns that it skipped the client reconcile (and a due seed-token renewal) and does both on a later run |
| `krate monitor up` stops with "Grafana was not recreated and Krate sign-in is not applied" | the sessions made with Grafana's own login could not be ended: Grafana is stopped or already on Krate sign-in, or `GRAFANA_PASSWORD` is not the password Grafana's volume holds (`./krate monitor status`; the message gives the `grafana cli admin reset-admin-password` command). Nothing was recreated. Each try is a login Grafana counts and it locks a login out after repeated failures, so correct the password first. Start Grafana with its own login (`./krate config set GRAFANA_AUTH_CONFIG=local.ini && ./krate monitor up`), then switch again |
| `krate monitor up` stops with "external-login users' sessions could not be ended" | going back to `local.ini`: Grafana is up with its own login, but authentication, a user API step or authentication-metadata validation failed. Correct the cause printed above; if the password is wrong, fix `GRAFANA_PASSWORD` to match Grafana's volume. Run `./krate monitor up` again: it retains the owed step until it succeeds |
| `krate monitor up` refuses with "run krate monitor realm first" | `GRAFANA_AUTH_CONFIG=realm.ini` was set by hand on an installation that never ran the switch: run `./krate monitor realm` (or roll back) |
| Alerts stopped provisioning | the seed token expired or its file is missing: `./krate monitor up` renews it; `ls -l monitoring/auth/secrets/` and `./krate monitor logs` show the rest |
