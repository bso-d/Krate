# Shared Admin login and company SSO

These steps apply to EPC and regular Krate. Both use their existing
`docker-compose.yml`. Keycloak and PostgreSQL run in the `sso` profile.
Kafbat uses Keycloak for SSO. In Phase 2 the users are local Keycloak users;
in Phase 3 Keycloak sends the user to PingFederate. The shared Admin login
stays in Kafbat and does not use Keycloak.

Keycloak itself is started and administered with `./krate identity`; the
[identity foundation guide](identity-foundation.md) describes that service,
its inventory, credentials and recovery. The order is: `./krate setup` or
`./krate start`, then `./krate identity up`, then `./krate auth configure` and
`./krate auth apply` as described here.

## Before you start

SSO requires the Docker Compose plugin **2.20.2 or newer**. The packaged Ubuntu
and RHEL Docker installers include a newer plugin. Ordinary shared-login cluster
operation retains Compose 1.29.2 compatibility. Use the same edition
`docker-compose.yml` for brokers, Kafbat, nginx, Keycloak and PostgreSQL; no
authentication override file is required. Every SSO image is included even when
the optional profile is inactive.


Agree the values in the [IAM guide](pingfederate-iam-guide.md). Use a real HTTPS
application FQDN and a certificate trusted by users. The VM and the user's
browser must reach PingFederate on the ports in its approved endpoint URLs.
Place the enterprise CA PEM file in `auth/keycloak/truststores/`. Keycloak uses
it to check PingFederate TLS. Do not turn off certificate checks.

## Set up the installation

1. Copy `sso/dual-example.json` to a private site file. Set `public_url`, the
   PingFederate issuer, client ID and endpoints, the two AD group names, and
   `groups_claim`. Set `clusters` to every exact Kafbat cluster name this UI
   shows. Include remote clusters when used.
2. Run `./krate auth configure /path/to/site.json`. This creates
   `auth/ui/runtime.yml` (the Kafbat configuration) and
   `auth/keycloak/pingfederate-idp.json` (the identity-provider plan: identity
   provider, mappers and browser flow). The plan is applied to the realm in
   Phase 3; Phase 2 uses local Keycloak users. The realm file
   `auth/keycloak/krate-realm.json` is owned by `./krate identity up`, which
   regenerates it from `.env`. `auth configure` does not replace existing
   files or start services. Review both files it wrote. It also sets
   `KEYCLOAK_PUBLIC_URL` (`public_url` plus `/identity`) in `.env`, and
   `KAFKA_UI_FQDN` to the `public_url` host when that is still blank. Set
   `KEYCLOAK_PUBLIC_URL` before the first `./krate identity up` where you
   can; if it changes later, the next `./krate identity up` updates the
   `krate-ui` redirect URLs in the realm.
3. Nothing else needs setting by hand. `./krate` generates the shared Admin
   password and the Keycloak admin, database, Kafbat client and `krate-cli`
   client secrets (24 random characters each, all different) before Keycloak's
   database first starts, and keeps `.env` at mode 600. After that first start,
   change a Keycloak secret only with `./krate identity rotate KEY`. `./krate auth apply` asks for the one
   value it cannot generate, the client secret PingFederate issued for
   Keycloak, or set it beforehand with
   `./krate config set PING_KEYCLOAK_CLIENT_SECRET=<secret-from-IAM>`.
   `./krate credentials` shows the Keycloak admin login.
4. Protect `.env` with your site secret controls.
5. Install/load the packaged images and start the broker cluster in shared-login
   mode first. Provision a matching TLS certificate and private key at
   `certs/server.crt` and `certs/server.key` (private key mode 600). The certificate must match
   `public_url` and remain valid for at least another day. Users must trust its
   issuing CA. Until `./krate identity up` has run, `./krate start` prints
   `Identity services skipped (run: krate identity up)` and starts the
   cluster without Keycloak. Run `./krate identity up` if it has not run yet:
   it generates the database TLS material, starts PostgreSQL and Keycloak,
   creates the permanent Keycloak admin and sets `KEYCLOAK_ENABLED=true`.
   Check it with `./krate identity status`. Then run
   `./krate config set KAFKA_UI_AUTH_CONFIG=runtime.yml`.
6. Run `./krate auth apply`. Preflight verifies credentials, configuration, TLS,
   the Compose version, running brokers and locally available service images.
   It does not start Keycloak: when Keycloak is not ready it stops with
   `Keycloak is not ready. Run: krate identity up (then: krate identity status)`.
   When Keycloak is ready it recreates Kafbat and waits for Kafbat/nginx
   health, then verifies HTTPS discovery
   through the public identity route. The installation host must resolve and
   reach its own public application URL. Each service wait is bounded to 180
   seconds; public discovery has a 15-second deadline. It never pulls images,
   builds assets, reconciles brokers or deletes volumes. On failure the command
   exits nonzero; inspect `./krate status`, `./krate identity status` and
   service logs before retrying. Avoid sharing logs containing tokens or
   personal information.

Keycloak health runs on its internal management port 9000 with metrics enabled
for database readiness. No identity or database port is published on the host.
Only nginx exposes the browser routes. A healthy service does not establish
successful enterprise login; complete the site's IAM acceptance procedure on
the production network before granting access.

The login page has a shared username/password form and an SSO button. The
username/email field supplies an optional `login_hint` on the SSO route. A
hint is not proof of identity. PingFederate decides whether an existing
enterprise session is enough or a new sign-in or MFA is required. The shared
password is never sent on the SSO route.

## Keycloak administration

The proxy sends only `/identity/realms/krate/` and `/identity/resources/` to
Keycloak. All other `/identity/` paths return 404. This blocks the Keycloak
admin console, the Admin REST API and the `master` realm on the application
URL. The proxy also rejects identity paths that contain `..`, `;` or encoded
separators, limits identity requests per client address, and logs them
without query strings.

Administer Keycloak only from the installation host. Run these commands in the
installation directory. Local users in realm `krate` are managed with
`./krate identity users list|add|disable|enable|reset-password|groups`; that
is the supported path and it does not need the master admin. A lost admin
login is repaired with `./krate identity recover-admin` (Keycloak stopped);
see the identity foundation guide. Use the admin CLI in the Keycloak container
only for realm-level changes such as the ones below. The Compose file has no
`name:` entry, so every raw `docker compose` call needs the project, the env
file and the profile: `-p krate-<edition> --env-file .env --profile sso`,
where `<edition>` is `kraft` or `epc` (or the `KRATE_PROJECT` value from
`.env` for an installation made before `/opt/krate`). The CLI asks for the
`KEYCLOAK_ADMIN_PASSWORD`; do not type it on the command line:

```bash
docker compose -p krate-<edition> --env-file .env --profile sso exec keycloak \
  /opt/keycloak/bin/kcadm.sh config credentials \
  --config /tmp/kcadm.config --server http://localhost:8080/identity --realm master --user admin
docker compose -p krate-<edition> --env-file .env --profile sso exec keycloak \
  /opt/keycloak/bin/kcadm.sh get realms/krate \
  --config /tmp/kcadm.config --fields realm,bruteForceProtected
docker compose -p krate-<edition> --env-file .env --profile sso exec keycloak \
  rm -f /tmp/kcadm.config
```

Use the `KEYCLOAK_ADMIN_USER` value in place of `admin` if you changed it.

New installations create the `krate` realm with brute-force protection. Realm
import does not change an existing realm. For an installation that existed
before this change, and for the `master` realm, turn the protection on once:

```bash
docker compose -p krate-<edition> --env-file .env --profile sso exec keycloak \
  /opt/keycloak/bin/kcadm.sh update realms/krate \
  --config /tmp/kcadm.config -s bruteForceProtected=true -s failureFactor=5
docker compose -p krate-<edition> --env-file .env --profile sso exec keycloak \
  /opt/keycloak/bin/kcadm.sh update realms/master \
  --config /tmp/kcadm.config -s bruteForceProtected=true -s failureFactor=5
```

## Updates and recovery

Keycloak stores users, broker links and sessions in the named PostgreSQL volume.
Back it up with `./krate identity backup <file>` (encrypted `pg_dump`) and
restore with `./krate identity restore <file>`; see the identity foundation
guide. Realm import only creates a realm when it does not already exist.
`./krate identity up` regenerates the realm file from `.env` and reconciles
only the `krate-ui` redirect URLs in an existing realm; editing the file by
hand is overwritten and does not change the realm. Review other changes with
IAM and apply them through Keycloak administration or a controlled realm
migration.

To switch Kafbat back to shared login only, set
`KAFKA_UI_AUTH_CONFIG=local.yml` and recreate only `kafka-ui` with Compose.
Run `./krate auth apply` after changing back to `local.yml`. The same command
recreates only the UI and checks the proxy. Identity services and their database
are retained for recovery. Do not use `down -v` on a live cluster.

Both image references are fixed by version and SHA-256 digest in
`.env.template`. The offline bundle contains those exact images. Use the
[build notes](../../kafbat-ui/README.md) for the customized Kafbat image.

## Site acceptance

Use the site's approved browser and IAM test identities to verify shared Admin,
SSO Viewer/Admin, unmapped-user denial, logout and identity-provider outage
behavior. The repository-side qualification uses disposable local identities;
actual enterprise federation acceptance is performed on the production network.

## Backup, restore and upgrades

Before an identity upgrade, take a backup. `./krate identity backup <file>`
writes an encrypted and integrity-sealed archive (AES-256 plus an HMAC-SHA256
tag that `restore` verifies before decrypting; passphrase from
`KRATE_BACKUP_PASSPHRASE` or prompted) with mode 600. It holds the `pg_dump`
and the admin user, admin password and the two client secrets that were valid
at that time. Protect the backup and its passphrase as identity data under
site policy.

For recovery, use a separately provisioned recovery host with the same pinned
PostgreSQL and Keycloak versions. Run `./krate identity up` there, then
`./krate identity down` and `./krate identity restore <file>`. `restore`
refuses to run while Keycloak is up, writes the four secrets from the archive
into that host's `.env` where they differ, and verifies readiness, the admin
login and the `krate-cli` login afterwards. The database password stays the
recovery host's own: roles are not part of the dump. Never restore over an
active production database. Validate shared login, identity login and roles
there before a cutover.

A Keycloak database from before `krate identity` is not migrated; see
"Upgrading from the previous Keycloak setup" in the identity foundation
guide.

Realm imports do not update existing realms. Use the approved Keycloak admin
procedure for group mappings, client changes and session-policy changes; back up
first. Repeat `auth apply` after changing runtime UI configuration. It preserves
broker containers and the existing identity database. The realm's session idle
limit and maximum lifetime come from `KEYCLOAK_SESSION_IDLE_MINUTES` and
`KEYCLOAK_SESSION_MAX_HOURS` in `.env` when the realm is created (defaults 15
minutes and 8 hours); the site file does not set them. Kafbat's own session
idle limit comes from `session_idle_minutes` in the site file (default 30);
keep it equal to `KEYCLOAK_SESSION_IDLE_MINUTES`, otherwise the shorter of
the two ends the browser session. Kafbat logout ends its
local session; an upstream SSO
session can sign the user back in until IAM revokes it.

## Package and release checks

Build each package from its edition directory; each includes its OS-specific
Docker installers:

```bash
cd kraft && ./krate package v3 amd64     # Ubuntu 24.04 Docker packages
cd ../epc && ./krate package v3 amd64    # RHEL 9 Docker packages
```

The builder verifies all Compose profile images are saved and recorded in
`images.lock.tsv`, including Keycloak and PostgreSQL, and ships the activation
and identity helpers (`sso/activate.sh`, `sso/preflight.py`, `sso/identity.py`)
with this guide and the identity foundation guide under `docs/`. Site `.env`, generated realm/runtime files, certificates and credentials
are excluded. Verify the package SHA-256 before extraction. Runtime SSO needs
only these saved images; PingFederate is an external site service and is never
packaged.
