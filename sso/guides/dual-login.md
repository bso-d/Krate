# Shared Admin login and company SSO

These steps apply to EPC and regular Krate. Both use their existing
`docker-compose.yml`. Keycloak and PostgreSQL run in the `sso` profile.
Kafbat uses Keycloak for SSO. Keycloak sends the user to PingFederate.
The shared Admin login stays in Kafbat and does not use Keycloak.

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
   `auth/ui/runtime.yml` and `auth/keycloak/krate-realm.json`. It does not
   replace existing files or start services. Review both files. It also sets
   `KEYCLOAK_PUBLIC_URL` (`public_url` plus `/identity`) in `.env`, and
   `KAFKA_UI_FQDN` to the `public_url` host when that is still blank.
3. Nothing else needs setting by hand. `./krate` generates the shared Admin
   password and the Keycloak admin, database and Kafbat client secrets (24
   random characters each, all different) before Keycloak's database first
   starts, and keeps `.env` at mode 600. `./krate auth apply` asks for the one
   value it cannot generate, the client secret PingFederate issued for
   Keycloak, or set it beforehand with
   `./krate config set PING_KEYCLOAK_CLIENT_SECRET=<secret-from-IAM>`.
   `./krate credentials` shows the Keycloak admin login.
4. Protect `.env` with your site secret controls.
5. Install/load the packaged images and start the broker cluster in shared-login
   mode first. Provision a matching TLS certificate and private key at
   `certs/server.crt` and `certs/server.key` (private key mode 600). The certificate must match
   `public_url` and remain valid for at least another day. Users must trust its
   issuing CA. Then run `./krate config set KAFKA_UI_AUTH_CONFIG=runtime.yml`.
6. Run `./krate auth apply`. Preflight verifies credentials, configuration, TLS,
   the Compose version, running brokers and locally available service images.
   It starts PostgreSQL and waits for database health, starts Keycloak and waits
   for its readiness endpoint, then recreates Kafbat and waits for Kafbat/nginx
   health, then verifies HTTPS discovery through the public identity route. The
   installation host must resolve and reach its own public application URL. Each service wait is bounded to 180 seconds; public discovery has a 15-second
   deadline. It never pulls images, builds
   assets, reconciles brokers or deletes volumes. On failure the command exits
   nonzero; inspect `./krate status` and service logs before retrying. Avoid
   sharing logs containing tokens or personal information.

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
installation directory. Use the admin CLI in the Keycloak container. The CLI asks for the `KEYCLOAK_ADMIN_PASSWORD`; do not
type it on the command line:

```bash
docker compose --profile sso exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --config /tmp/kcadm.config --server http://localhost:8080/identity --realm master --user admin
docker compose --profile sso exec keycloak /opt/keycloak/bin/kcadm.sh get realms/krate \
  --config /tmp/kcadm.config --fields realm,bruteForceProtected
docker compose --profile sso exec keycloak rm -f /tmp/kcadm.config
```

Use the `KEYCLOAK_ADMIN_USER` value in place of `admin` if you changed it.

New installations create the `krate` realm with brute-force protection. Realm
import does not change an existing realm. For an installation that existed
before this change, and for the `master` realm, turn the protection on once:

```bash
docker compose --profile sso exec keycloak /opt/keycloak/bin/kcadm.sh update realms/krate \
  --config /tmp/kcadm.config -s bruteForceProtected=true -s failureFactor=5
docker compose --profile sso exec keycloak /opt/keycloak/bin/kcadm.sh update realms/master \
  --config /tmp/kcadm.config -s bruteForceProtected=true -s failureFactor=5
```

## Updates and recovery

Keycloak stores users, broker links and sessions in the named PostgreSQL volume.
Back up that volume with the approved database process. Realm import only
creates a realm when it does not already exist. Editing the generated realm
file does not change an existing realm. Review changes with IAM and apply them
through Keycloak administration or a controlled realm migration.

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

Before an identity upgrade, take a PostgreSQL logical backup using the same
manifest. Protect the backup as identity data and encrypt it under site policy:

```bash
umask 077
docker compose --profile sso exec -T keycloak-db pg_dump -U keycloak -d keycloak > keycloak-backup.sql
```

For recovery, use a separately provisioned recovery host with the same pinned
PostgreSQL and Keycloak versions. Restore into its empty database with
`docker compose --profile sso exec -T keycloak-db psql -U keycloak -d keycloak < keycloak-backup.sql`
before starting Keycloak. Never restore over an active production database.
Validate shared login, identity login and roles there before a cutover.

Realm imports do not update existing realms. Use the approved Keycloak admin
procedure for group mappings, client changes and session-policy changes; back up
first. Repeat `auth apply` after changing runtime UI configuration. It preserves
broker containers and the existing identity database. The default session idle
limit comes from `session_idle_minutes`; the generated realm maximum session
lifetime is eight hours. Kafbat logout ends its local session; an upstream SSO
session can sign the user back in until IAM revokes it.

## Package and release checks

Build each package from its edition directory; each includes its OS-specific
Docker installers:

```bash
cd kraft && ./krate package v3 amd64     # Ubuntu 24.04 Docker packages
cd ../epc && ./krate package v3 amd64    # RHEL 9 Docker packages
```

The builder verifies all Compose profile images are saved and recorded in
`images.lock.tsv`, including Keycloak and PostgreSQL, and ships both activation
helpers. Site `.env`, generated realm/runtime files, certificates and credentials
are excluded. Verify the package SHA-256 before extraction. Runtime SSO needs
only these saved images; PingFederate is an external site service and is never
packaged.
