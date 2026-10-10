# Identity acceptance gate (Phase 1, Phase 2 and Phase 3)

This is the executable gate for the Keycloak-first programme. It answers, per
acceptance criterion of the owner's handover, which test proves it, how that
test is run, and what the last run produced. The gate is a script,
`scripts/gate-identity.sh`; its receipt is the evidence, and the owner signs
off on the receipt, not on prose. Phase 2 is accepted only together with
Phase 1, and Phase 3 (PingFederate brokering, proven against a stand-in IdP)
only together with both: they run against one candidate commit, in one receipt.

## How to run it

```bash
# a disposable checkout, or a fixture installation made for the gate (the run creates and destroys
# .env, auth/keycloak, certs, the journal, monitoring/.env and the monitoring volumes of that edition)
git -C /path/to/Krate worktree add --detach harness/worktrees/gate HEAD
scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe            # Phase 1 + screenshots + Phase 2 + Phase 3 (--phase all)
scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe --phase 2  # Phases 1 and 2 only
scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe --phase 3 --stub-port 18444   # all three; the stand-in IdP on another port
scripts/gate-identity.sh --edition-dir /opt/krate/epc --wipe --no-static --no-screenshots --candidate <sha>   # on the RHEL/Rocky VM, from the bundle
scripts/gate-identity.sh --edition-dir /opt/krate/epc --wipe --candidate <sha> --repo ~/gate/repo             # the same with the full inventory (see below)
```

Two invocations exist for a bundle host. The reduced one, `--no-static
--no-screenshots --candidate <sha>`, leaves S1–S4 and X1 out of the inventory
(NOT_RUN: not validated on that host, only on the host whose receipt has them
PASS); run it when the prerequisites below are not on the host, because
without the two skip flags the rows stay inside the inventory and the verdict
can never be PASS: S1 is NOT_RUN without a Makefile and S3 without the
shellcheck image (INCOMPLETE), S2 (no git metadata), S4 (no `scripts/`) and X1
(no browser image) FAIL. The full one adds `--repo DIR`:
the static block (S1–S4) runs against a checkout whose HEAD is the
`--candidate` commit. The bundle's edition directory itself carries no git
metadata (the receipt binds it by file digests); the full inventory needs, in
addition, a `git` executable and that separate checkout (a `git clone -b
<branch>` of a `git bundle` carried into the air gap), `gmake`, `shellcheck`
(the `koalaman/shellcheck:v0.9.0` image behind a `shellcheck` wrapper on
`PATH`), `docker compose`, and an nginx image for `check-identity`'s render
check: the pinned `nginx:1.27-alpine@sha256:…` reference does not resolve after
`docker load` (the registry digest is not preserved), so set
`KRATE_CHECK_NGINX_IMAGE` to the image the bundle loaded (the `NGINX_IMAGE`
value of the installed `.env.template`); the check's last line, and so the S4
evidence, names the image it rendered with. X1 needs the
`krate-harness/playwright:1.60.0` image loaded from a saved archive (3.8 GB on
disk, 0.94 GB gzipped, arm64), and J7 needs root.

The runner refuses to start when another Krate installation runs on the host or
when monitoring volumes of the edition's project already exist, because it would
destroy them. On a bundle host there is no git: `--candidate <sha>` states the
commit and the receipt records the sha256 of every edition file under test; a
receipt without either binding is INCOMPLETE.

Prerequisites: Docker with Compose ≥ 2.20.2, python3, openssl, curl; the
candidate's images on the host (`krate/kafka-ui:1.5.0-sso.7` built with `make
kafbat-ui`); nothing else from Krate running on the host (the product allows
one Keycloak deployment per Docker host: a second `keycloak_db_data` volume or
the fixed `krate-proxy` name makes `identity up` refuse). The screenshot story
builds a small harness image once (`krate-harness/playwright:1.60.0`, network
needed that one time). Phase 3 (`--phase 3` or `all`) adds a stand-in enterprise
IdP, `scripts/gate/stub_idp.sh`: a second Keycloak started from the edition's own
`KEYCLOAK_IMAGE` (on a bundle host the loaded offline tag; nothing is pulled),
realm `pingstub`, published on `127.0.0.1:18443` only (`--stub-port N` when that
port is taken) and joined to the fixture's `identity-egress` network under the alias
`pingstub`; its certificate and secrets are generated per run under the receipt's
state directory (0600) and removed with it. A missing image, a taken port or a
missing network fails every Phase 3 row with that reason (the rows stay in the
inventory; they are never silently NOT_RUN).

The run takes about 35 minutes for Phase 1 (eleven Keycloak start cycles),
about 15 minutes for Phase 2 and about 10 minutes for Phase 3 (the stand-in's
start and three Keycloak recreations). Output: `harness/gate-receipts/<edition>-<sha>-<time>/`
with `receipt.md` (the table below, generated), `receipt.tsv`, `run.log`
(every command output, secret values replaced by `<redacted>`) and
`screenshots/*.png` with `manifest.json` captions.

## What a receipt binds the results to

| field | meaning |
|---|---|
| candidate commit | `git rev-parse HEAD` of the fixture checkout, or the `--candidate` sha on a host without git; neither → `bound: false` and the verdict is INCOMPLETE. With `--repo`, the row also names the checkout's HEAD the static block ran on (it must start with the candidate sha) |
| edition file digests | sha256 (16 hex) of `krate`, `docker-compose.yml`, `.env.template`, `nginx.conf`, `sso/identity.py`, `sso/preflight.py`, `sso/activate.sh`, `sso/configure-dual.py` of the fixture: what was actually tested, also when the candidate is only stated. To check a bundle-host receipt against the repository: `git show <sha>:epc/<file> \| shasum -a 256` must match for seven of the eight; `.env.template` differs by design, because `make bundle` rewrites its five `*_IMAGE` lines to the offline runtime tags (the receipt's `images` row shows them) and nothing else |
| dirty tracked files | `git status --porcelain --untracked-files=no` of the whole fixture repository at run time, unfiltered (must be empty for a sign-off receipt; `unknown` without git; with `--repo`, the checkout's dirty state is listed after `--repo:`) |
| images | every `*_IMAGE` digest of the edition template |
| runner | gate version, sha256 of `scripts/gate-identity.sh` and one digest over `scripts/gate/*.py`, `*.mjs` and `*.sh` (file list, sorted; `stub_idp.sh` is bound by this digest and linted by S3 with the runner), plus the commit (and dirty state) of the repository the runner was executed from |
| host | OS, Docker, Compose, python, openssl versions |
| verdict | PASS only when no test failed, every id of the selected inventory passed, and the candidate is bound. The inventory is `REQUIRED_P1`; `REQUIRED_P2` is added unless `--phase 1`; `REQUIRED_P3` with `--phase 3` or `all`; `X1` unless `--no-screenshots`; `S1`–`S4` leave it under `--no-static`. Ids outside the selected inventory, and J7 on a host without root or sudo or without a `logrotate` binary (the runner computes this up front), are NOT_RUN rows that carry information but do not decide. A selected id that is FAIL gives FAIL; NOT_RUN or absent gives INCOMPLETE |

The required inventory is declared in the runner before anything runs
(`REQUIRED_P1`, `REQUIRED_P2`, `REQUIRED_P3`, `REQUIRED_X`): a test that never reports cannot
pass by absence. Secret values never travel on a command line (the runner reads
`.env` in the shell, passes secrets through the environment or 0600 files, runs
every helper with `python3 -I`, and works under `umask 077`); the receipt files
and `run.log` are redacted from the list of every secret value seen.

## Criteria and their tests

The letters are the criteria; the handover sentence each comes from is quoted.
Every id is one row of the receipt.

### S: the candidate is statically sound

| id | test | pass condition |
|---|---|---|
| S1 | `gmake check` (syntax, shellcheck, digest pinning, Compose rendering of every stack, offline policy, `scripts/check-identity.py`) | exit 0 |
| S2 | `git diff --check` | clean |
| S3 | shellcheck 0.9.0 (the CI version) on both CLIs, `sso/activate.sh`, the runner and `scripts/gate/stub_idp.sh` | exit 0 |
| S4 | `scripts/check-identity.py` alone (templates, realm plan, runtime plan, names, Compose, networks, monitoring binds, logrotate, CLI wiring, parity, zk frozen, writers, renewal incl. CA path and rollback, backup seal tamper, preflight refusals, exposure) | exit 0 |

### H: "Bootstrap only proven-pristine state using securely generated independent credentials. Missing environment text is not evidence that a stored credential is unused."

| id | test | pass condition |
|---|---|---|
| H1 | `gen-cert` on the fixture | exit 0 |
| H2 | master realm users right after the first `identity up` | exactly `KEYCLOAK_ADMIN_USER` (the temporary bootstrap admin is gone) |
| H3 | a fresh `.env` (template copy) over the existing database, then `identity up` | refused naming the missing keys; the stored database password still works afterwards (nothing was regenerated or rotated) |

### F: "identity health works without brokers. Use distinct startup, readiness, liveness and authentication probes. Readiness failure must not drive restart loops."

| id | test | pass condition |
|---|---|---|
| F1 | `identity up` from pristine state with no broker container | exit 0; running services are exactly `keycloak`, `keycloak-db` |
| F2 | `identity status` | exit 0 and one line per probe |
| F3 | `/health/started`, `/health/ready`, `/health/live` on management port 9000 and the realm on 8080, each queried separately from inside the identity network | four distinct 200s |
| F4 | authentication probe: `client_credentials` of `krate-cli` through the proxy | 200 (health and authentication are different probes) |
| F5 | `docker stop keycloak-db`: readiness vs liveness, `identity status`, Keycloak's restart count after 60 s, recovery when the database returns | `ready=503 live=200`; status exit 1; `RestartCount` 0 and state `running`; ready again afterwards |
| F6 | `identity status` after recovery | exit 0 (the command's own status, with its lines as evidence) |

### G: "Protect every relevant link: trusted browser-facing HTTPS and issuer URLs; explicitly trusted proxy headers; private management endpoints; database TLS with certificate and hostname verification. … audit and close reachable unauthenticated backing-service paths, including published monitoring endpoints."

| id | test | pass condition |
|---|---|---|
| G1 | `docker port` of keycloak and keycloak-db | nothing published |
| G2 | proxy paths sent as-is (`curl --path-as-is`): realm discovery and account console; admin console, master realm, metrics, health, bare `/identity`; a dot segment that lands on the master realm; a dot segment that lands on an allowed path; a path parameter (`;x=1`) | 200, 200; the blocked paths 404; `../master` 404 (the normalised target is blocked); `../krate/account` 400 and `;x=1` 400 (refused before any target) |
| G3 | network membership and addresses: keycloak-db on `identity` only; keycloak on `identity` + `identity-egress`; `identity` internal with the configured subnet and `ip_range`; proxy at `KRATE_IDENTITY_PROXY_IP` = `KC_PROXY_TRUSTED_ADDRESSES` | all equal to the configuration |
| G4 | a dynamically addressed container on `identity` | its address is inside `KRATE_IDENTITY_IP_RANGE` and is not the proxy address |
| G5 | name resolution of `keycloak` from the brokers' network | no such name |
| G6 | forged `X-Forwarded-For: 9.9.9.9` sent straight to keycloak:8080 by a non-proxy peer | the Keycloak event records the peer's own address, not 9.9.9.9 |
| G7 | the same header sent through the proxy | the event records neither 9.9.9.9 nor the peer: nginx replaces the header with the real client address |
| G8 | database TLS from a client container: plaintext, `verify-full` against the generated CA, wrong password | plaintext rejected by `pg_hba`; `t\|TLSv1.3`; wrong password rejected |
| K27/K28 (Phase 2) | Kafbat's `/metrics`, `/actuator/*`, `/logout/connect/*` through the proxy; anonymous API call | 404; redirect to the Keycloak login |
| M1/M2 (Phase 2) | `monitor up`: Prometheus and Loki bind addresses; kafka-exporter's networks | 127.0.0.1 only; Grafana unchanged; exporter on the brokers' network, not on `identity` |

### A and B: "local account lifecycle and MFA work; unauthorized users are denied"

| id | test | pass condition |
|---|---|---|
| A1 | `users add` (viewer, admin with email, no group, viewer) then `users list` | all four listed, enabled |
| A2 | `users groups`; `users add 'bad name'`; duplicate `users add` | admin group shown; both refusals |
| A3 | first login through the proxy with the temporary password (headless browser flow, `scripts/gate/keycloak_login_flow.py`): TOTP enrolment, forced password change, second login asks for the OTP, wrong OTP refused, old password refused | all steps observed; ID token `aud=krate-ui`, `groups=[viewer group]`, `expires_in` 300 or 299 (the 300 s lifespan less the second that may pass between issue and read) |
| A4 | `reset-password` then login with the previous password | refused |
| A5 | `users list` at the end of the ladder | exit 0 |
| B1 | claims contract: admin user → `groups=[admin group]`; user without group → no `groups` claim | as stated (nothing to map a role from) |
| B2 | correct password + OTP accepted; wrong password refused | accepted; the refusal is the login form again carrying `Invalid username or password.` (an OTP prompt, a required-action page or a 5xx is not a refusal) |
| B3 | `users disable`, login, `users enable` | disable exit 0; the login form carries `Account is disabled`; enable exit 0 |
| B4 | direct password grant on `krate-ui` | 400/401 (standard flow only) |
| B5 | five rapid wrong passwords | brute-force detection reports the account temporarily `disabled: true` (Keycloak's quick-login check locks after two rapid failures; later attempts are not counted) |
| B6 | `reset-password` | a new temporary password is issued (shown once) |
| B7 | login with the one-time code of the previous 30-second step | accepted: the realm's look-ahead window is 1 (Keycloak's documented default; the plan now sets it, the import otherwise leaves 0) |

### C: "restart/reapply preserve identity and secrets"

| id | test | pass condition |
|---|---|---|
| C1 | identical `identity up` rerun | `No changes`; `.env` digest unchanged |
| C2 | `docker compose restart keycloak`, then `users list` and `identity up` | users present; `No changes` |
| C3 | `identity down` + `identity up` | users present; an enrolled user logs in with password + OTP |
| C4 | `identity renew-db-tls` | new expiry, chains to the CA, `.prev` discarded, journal `renew-db-tls ok`, Keycloak ready |
| C5 | `renew-db-tls` with an injected restart failure (a `docker` wrapper on `PATH` fails `compose restart`) | exit 1; `server.crt` byte-identical to before; `.prev` consumed; journal `renew-db-tls rolled back`; `keycloak-db` reports `healthy` on the old certificate |
| C6 | `otpPolicyLookAheadWindow` set to 0 in Keycloak behind the CLI's back, then `identity up` | window back to 1 from the realm plan; journal `up reconciled realm policy` |

### I: "Implement credential-specific changes through the authoritative store and verify the consumer. Editing .env or regenerating realm JSON is insufficient evidence."

| id | test | pass condition |
|---|---|---|
| I1 | `rotate KEYCLOAK_DB_PASSWORD` | old password rejected by PostgreSQL, new accepted, Keycloak ready |
| I2 | `rotate KEYCLOAK_ADMIN_PASSWORD` | old refused by kcadm, new lists the master users |
| I3 | `rotate KEYCLOAK_CLI_CLIENT_SECRET` | `users list` works, new secret authenticates, `identity up` → `No changes` |
| I4 | `config set KEYCLOAK_DB_PASSWORD=…` on a live database | refused with the `rotate` hint |
| I5 | `rotate KEYCLOAK_ADMIN_PASSWORD --value` fed the database password's value | refused naming `KEYCLOAK_DB_PASSWORD`; `.env` unchanged; the admin still logs in |

### D: "a database/configuration restore is demonstrated"

| id | test | pass condition |
|---|---|---|
| D1 | `identity backup` | file mode 600, magic `krate-identity-backup/1` |
| D2 | `identity restore` while Keycloak runs | refused |
| D3 | a tampered archive (one bit flipped); a wrong passphrase | both refused before decryption (`integrity check failed`) |
| D4 | after a secret rotation and a marker user: `identity down`, `identity restore` | marker gone, earlier users present, Keycloak verified |
| D5 | the restored `.env` | `KEYCLOAK_CLI_CLIENT_SECRET` back to the backup's value, `KEYCLOAK_DB_PASSWORD` untouched (a database role, not part of the dump); journal `restore reconciled` |
| D6 | restore on a host with another `KEYCLOAK_PUBLIC_URL` (`https://recovery.example.test/identity`), then the original URL and `identity up` | the `krate-ui` redirect URI follows the new host; journal `restore reconciled krate-ui urls`; `identity up` reconciles it back |
| D7 | `identity backup` with a 5-character `KRATE_BACKUP_PASSPHRASE` | refused (`at least 8 characters`); no archive written |

### E: "failure injection reveals no false success, secret leakage or silent replacement"

| id | test | pass condition |
|---|---|---|
| E1 | wrong `KEYCLOAK_DB_PASSWORD` in `.env` on an existing database | `identity up` exit 1; `.env` still holds the wrong value (not regenerated); the value appears in neither the output nor the journal |
| E2 | `server.key` removed | refused as incomplete; no new key written |
| E3 | wrong `KEYCLOAK_ADMIN_PASSWORD` in `.env` | `identity up` exit 1 with the `recover-admin` hint; `recover-admin` refused while running; after `identity down` it recreates the admin; master users = the admin only |
| E4 | the master admin deleted in Keycloak (lost admin) | `identity up` exit 1; `recover-admin` after `down` recreates it |
| E5 | database volume present but no master realm (a failed first run) | `identity up` detects it and bootstraps; the temporary admin is removed |
| E6 | the identity lock held by a live process; then that process dies | the command is refused naming the pid; afterwards the stale lock is removed and the command proceeds |
| E7 | two mutating commands started at the same instant | refusals + created = 2 with at least one created: one refused and one created, or both serialised; never two half-made users (the deterministic lock proof is E6) |
| E8 | `krate stop` while an identity command holds the lock and `KEYCLOAK_ENABLED=false` | refused naming the pid; keycloak and keycloak-db untouched |
| Z1/Z2 | every secret value seen during the run (each `.env` and `monitoring/.env` password, secret, passphrase and key before and after rotations, the backup passphrase, every temporary password, every enrolled password and TOTP seed) searched in the raw log (temporary passwords: outside their one-time display line), the journal, the plan files, the receipt rows, the screenshot captions and the keycloak, keycloak-db, kafka-ui, proxy and monitoring logs | 0 hits |

### J: "Make configuration planning pure and application explicit: validate prerequisites before mutation, lock concurrent applies, stage a complete generation, redact diffs and journal transitions."

| id | test | pass condition |
|---|---|---|
| J1 | a Docker network already covering the identity subnet (named `<project>-gate-clash`, removed by the gate), then `identity up` | refused naming the network, `KRATE_IDENTITY_SUBNET` and `KRATE_IDENTITY_PROXY_IP`; no container created |
| J2 | the same with `start` | refused the same way; no container created |
| J3 | journal after the first `identity up` | `up bootstrapped` |
| J4 | `krate-realm.json` | placeholders only, none of the secret values |
| J5 | journal lines of `users add` / `reset-password` | user names only |
| J6 | `identity logrotate` | renders the drop-in for this journal |
| J7 | `identity logrotate --install` and `logrotate -d`; the gate removes the installed drop-in again | accepted (root; informational on a host without root, proven on the Linux VM) |

### X: the end user's view (owner rule 10)

| id | test | pass condition |
|---|---|---|
| X1 | a real browser (Playwright, Chromium in the harness container, reaching the published proxy port through the Docker host gateway as a browser on the host does): account console asks to sign in → login form → TOTP enrolment (QR code and secret masked before the capture) → forced password change → signed-in console → second login asks the OTP → wrong OTP → wrong password → disabled user → admin console, master realm and metrics blocked | every step's outcome asserted (OTP prompt without a password field, `Invalid authenticator code`, `Invalid username or password`, `Account is disabled`, HTTP 404 on the three blocked paths); the story needs both users; one PNG per step in `screenshots/`, captions and the assertions in `manifest.json` |

### K: Phase 2, "the first UI uses the Keycloak issuer in local mode and enforces approved roles at its backend"

| id | test | pass condition |
|---|---|---|
| K1 | `auth configure --local`, `config set KAFKA_UI_AUTH_CONFIG=runtime.yml`, `start`, `auth apply` | all exit 0 (preflight inside apply); broker containers untouched; `runtime.yml` has no shared login |
| K30 | a second `auth apply` | kafka-ui container unchanged; prints `unchanged … sessions kept` |
| K2–K26, K31, K32 | the Kafbat authorization ladder, `scripts/gate/phase2_kafbat.py` (viewer reads; every mutation refused by the backend with 403; admin mutates; no-group user refused at login; disabled user refused; shared login absent; ID-token issuer/audience checks; identity = `sub`; CSRF; POST-only logout ending the Keycloak session; back-channel logout measured; disabled user's session lifetime measured; open-redirect and proxy-header spoofing; both-groups user = administrator; group rename in `.env` leaves the realm alone; K31: XSRF cookie `Secure`, not HttpOnly, rotated at login; K32: error bodies carry no stack trace; the viewer's `GET /api/config` 403 is part of K2) | each case PASS with the observed status codes and measured seconds in the evidence |
| K27 | public proxy paths as-is: `/metrics`, `/actuator`, `/actuator/`, `/actuator/health`, `/actuator/prometheus`, `/actuator;x/prometheus`, `/logout/connect`, `/logout/connect/back-channel/keycloak`, `/api/clusters;x`, `/api/clusters` | 404 for the seven blocked paths (the base paths and the paths below them), 400 for the two path parameters, 302 for the API |
| K28 | anonymous `/api/clusters` | redirects to `/oauth2/authorization/keycloak` on the public origin |
| K33 | `Host: evil.example.test` on the public port (Keycloak sign-in mode sets `KRATE_PROXY_PUBLIC_HOST` to the public authority, port included; the raw header is compared); the public authority as Host; plain HTTP on the HTTP port with `Host: localhost` | 444: connection closed without a response (curl exit 52); the public authority answers 302; plain HTTP answers 301 to the public origin (the HTTPS port carried by the public authority, not by the plain-HTTP Host) |
| K34 | `gen-cert` then `auth apply`, then a second `auth apply` | `KRATE_PROXY_CONF_SHA` changed and the proxy container was recreated; the second apply keeps the container; the proxy serves |
| M1/M2 | see G above | |
| K17 | EPC | informational row (`owned by runner`): the EPC Compose rendering and CLI parity are S1/S4; the EPC runtime is the Phase 1 gate run inside the Rocky 9 VM (`--no-static --no-screenshots`, receipt under `harness/gate-receipts/epc-vm-<sha>/`) |

### P: Phase 3, "PingFederate brokering applied to the realm" (owner decisions D1–D4 of the Phase 3 contract)

The stand-in IdP (`scripts/gate/stub_idp.sh`, above) plays PingFederate: users
`ping-viewer` (AD group APP-KAFKA-VIEWERS), `ping-admin` (APP-KAFKA-ADMINS),
`ping-both` (both), `ping-none` (none), a `groups` claim, client `krate-keycloak`
whose redirect is the realm's broker endpoint. The rows run on the Phase 2 stack
(brokers, Kafbat in `runtime.yml` mode, proxy, identity). P1–P4, P14 and P15 are
the runner's (CLI, `.env`, journal, container state and `scripts/gate/phase3_realm.py`,
which reads the realm's brokering state through kcadm as the master admin and
compares it with the plan file); P5–P13 are `scripts/gate/phase3_broker.py`, a
headless browser that starts every sign-in at Kafbat's `/oauth2/authorization/keycloak`,
follows the hops through the realm to the stand-in's login form, posts the
credentials there and follows the way back, recording each hop; its TLS is pinned on
`certs/server.crt` and the stand-in's certificate, and a certificate that does not
verify fails every row (no unverified fallback). Secret values
(the stand-in's passwords and client secret, the local users' temporary
passwords) travel through 0600 files and the environment and are redacted
from every published line.

| id | test | pass condition |
|---|---|---|
| P1 | `auth configure <site.json>` with the stand-in's site file (after removing the Phase 2 `runtime.yml`, which configure refuses to replace) | exit 0; `auth/keycloak/pingfederate-idp.json` has the D2/D3 shape (`phase3_realm.py --shape`): provider `pingfederate` with `firstBrokerLoginFlowAlias` `krate first broker login`, `syncMode FORCE`; flow `krate browser` = `auth-cookie` ALTERNATIVE 10, `identity-provider-redirector` ALTERNATIVE 20 with config `PingFederate redirect` → `defaultProvider pingfederate`, sub-flow `krate forms` ALTERNATIVE 30 = `auth-username-password-form` REQUIRED 10 + sub-flow `krate otp` CONDITIONAL 20 = `conditional-user-configured` REQUIRED + `auth-otp-form` REQUIRED; flow `krate first broker login` = `idp-create-user-if-unique` REQUIRED; `browserFlow` `krate browser`; two `oidc-advanced-group-idp-mapper` mappers with `syncMode FORCE`; the file carries the `${PING_KEYCLOAK_CLIENT_SECRET}` placeholder and none of the run's secret values |
| P2 | preflight `--mode runtime.yml` in ping mode (the stand-in's PEM in `auth/keycloak/truststores`, 644): without `PING_KEYCLOAK_CLIENT_SECRET`; with the PEM at 600; with the plan's `tokenUrl` rewritten to `http://`; then restored | the three runs exit non-zero naming `PING_KEYCLOAK_CLIENT_SECRET is not set`, `must be world-readable (chmod 644)` and `tokenUrl must be an https URL`; the restored run exits 0 (positive control). The secret is written into `.env` through the environment, never on a command line |
| P3 | `auth apply` with the plan, then a second `auth apply` | first apply exit 0; `phase3_realm.py --expect <plan>`: the provider (every non-secret config key), its two mappers (type, claims, group, syncMode), the four flows with each execution's authenticator or sub-flow, requirement and priority, the redirector's config and the realm `browserFlow` equal the plan (a top-level plan key outside these, such as `truststore`, is not compared); journal `apply reconciled identity provider`; the second apply exits 0, prints the line `Identity provider pingfederate: No changes` and adds no reconciliation line |
| P4 | the PEM added before P3; a second PEM added after P3; container ids and `KRATE_TRUSTSTORE_SHA` around each apply | the first apply recreated Keycloak (new container id) and set `KRATE_TRUSTSTORE_SHA` in `.env` and in the container's environment; the second apply (nothing changed) kept the container; a second PEM → recreated again with a new digest; journal `apply recreated keycloak: truststores changed`; the Keycloak log's truststore line is quoted |
| P5 | `ping-viewer` through the stand-in | lands in Kafbat with a session; permissions `TOPIC:VIEW,ANALYSIS_VIEW` only (no CREATE); `POST …/topics` 403; `GET …/topics` 200; hops recorded |
| P6 | `ping-admin` | topic create 200 (the topic is deleted again) |
| P7 | `ping-both` | topic create 200; its permission entries include every entry of `ping-admin`'s set (union of viewer and administrator = administrator) |
| P8 | `ping-none` | refused at Kafbat's callback: `/login?error` (no mapped role) |
| P9 | `ping-both` removed from APP-KAFKA-ADMINS and `ping-admin` removed from it in the stand-in (`stub_idp.sh remove-group`), then new sign-ins | `ping-both`: viewer only (create 403, list 200, realm groups = the viewer group); `ping-admin`: `/login?error`; syncMode FORCE re-evaluated the mappers at sign-in |
| P10 | the hop trails of P5–P7 and the brokered users' `requiredActions` | no realm hop answered 200 (every realm step is a redirect), no hop names `required-action`, `update-profile` or `review-profile`; `requiredActions` empty for the three users (D1: no Keycloak TOTP or profile page for SSO users) |
| P11 | break-glass (D3): Kafbat's authorization request to the realm as is; the same with `&kc_idp_hint=` (empty); the local user `gate3local` (made by `identity users add --admin`) posted on that form; the hint-less path again afterwards | default path 303 to `…/broker/pingfederate/login`; with the empty hint 200 with the login form; the local user's temporary password is accepted and the next step is its required action (`CONFIGURE_TOTP` or `UPDATE_PASSWORD`); the hint-less path still answers 303 to the broker login |
| P12 | local user `gate3clash` (`identity users add --viewer`) and a stand-in user of the same name signing in through the broker (D2) | the first-broker-login flow answers HTTP 409 at `…/login-actions/first-broker-login` with "User with username gate3clash already exists. Please login to account management to link the account." (seen live on the development fixture); the local user has no federated identity; the realm still holds exactly one `gate3clash` |
| P13 | `ping-viewer` signed in, Kafbat `POST /logout` (XSRF token), the realm end-session, then a new sign-in in the same browser | the logout redirects to Keycloak's end-session; exactly the session this browser made is gone from the user's realm sessions; the next sign-in's hops include `…/broker/pingfederate/login` and the stand-in (the realm asked the IdP; no cookie login) |
| P16 | the stand-in's client secret rotated (`stub_idp.sh rotate-secret`, new value in its 0600 file); a brokered sign-in; `identity rotate PING_KEYCLOAK_CLIENT_SECRET --value` with the value on stdin (the Phase 1 convention); a brokered sign-in | before the rotate the realm presents the old secret and `ping-viewer`'s sign-in fails at the realm (status and hop recorded); the rotate exits 0, prints the line `Identity provider pingfederate: secret updated`, journals `rotate PING_KEYCLOAK_CLIENT_SECRET applied to identity provider pingfederate` and `.env` carries the new value; afterwards `ping-viewer` signs in again with its federated identity kept (1 link, no clash page) |
| P14 | the plan file removed, `auth apply`, then Kafbat's default path | exit 0; `phase3_realm.py --expect-absent`: no `pingfederate` provider, no `krate …` flow, `browserFlow` `browser`; journal `apply removed identity provider`; the realm's authorization endpoint answers 200 with the login form (local login on the default path) |
| P15 | the plan file restored, `CONFIGURE_TOTP` `defaultAction` set to true behind the CLI's back (full representation PUT), `identity up` | drift confirmed before; `identity up` exit 0; afterwards `defaultAction` false and the realm matches the plan again (the provider re-applied after P14's removal); journal `up reconciled required action CONFIGURE_TOTP` and `up reconciled identity provider` |
| Z3 | the leak scan of Z1/Z2 after Phase 3, with the stand-in's log and its admin password, client secrets (both) and user password in the searched set | 0 hits |

`REQUIRED_P3` is P1–P16 and Z3 (17 ids); with screenshots and the static block the
full inventory of `--phase 3`/`all` is 119 ids (113 with `--no-static --no-screenshots`).
The rows run in the order P1, P2, P3, P4, P5–P13 (helper), P16, P14, P15, Z3.
On an EPC edition directory the Phase 3 rows are NOT_RUN for the same reason as
Phase 2 (the Kafbat runtime fixture is KRaft on this runner).

### Not covered by this runner, proven elsewhere

| what | where | result |
|---|---|---|
| EPC runtime, offline bundle install on a RHEL-9 class host (SELinux enforcing), `logrotate --install` | Rocky Linux 9 Lima VM, `harness/linux-vm/RUNBOOK.md` (clean-room run 2 at 0b32a40: all steps passed offline) and the Phase 1 gate run inside the VM (`harness/gate-receipts/epc-vm-<sha>/receipt.md`) | runbook run 2: PASS; gate receipt: see its verdict |
| Ubuntu deb install | not run (no Ubuntu host in this programme yet) | open |
| amd64 image builds | CI `broker-ci.yml` matrix; the Kafbat image is built per arch with `make kafbat-ui ARCH=amd64` on the bundling host | CI |

## Last run

Phase 3 (runner v6, rows P1–P16 and Z3) has no receipt yet: the rows were
exercised by hand and through `phase3_broker.py --only …` against the Phase 3
development fixture (`harness/phase3/`), and the first full receipt is pasted
here when the owner's Phase 3 candidate is final.

The receipt tables below are pasted verbatim from the two receipts of candidate
cda07a0 (2026-10-10, gate runner v4, each run alone on its host). Both verdicts
read PASS. The owner's acceptance is recorded in the Serena tracker and in PR
#39, not here. Earlier receipts of the day (c88de6a with runner v1; the void
runs 7–10 and the two failed EPC runs at 5b803c6, which found the umask-077
directory defect fixed in d119da4) stay under `harness/gate-receipts/` as
evidence only.

### KRaft, full gate on the development Mac (Phase 1 + screenshots + Phase 2)

Receipt folder: `harness/gate-receipts/kraft-cda07a0-20261010T173432Z/` (receipt.md, receipt.tsv,
run.log with every secret value replaced, `screenshots/01…11-*.png` with
`manifest.json`: captions and the asserted outcomes per step). The two NOT_RUN
rows are outside the inventory on this host: J7 (no root, decided by the VM
receipt) and K17 (owned by the runner, the EPC runtime is the VM receipt).

| field | value |
|---|---|
| verdict | **PASS** (PASS 102, FAIL 0, NOT_RUN 2, required missing 0: none; required not run: 0; bound: true) |
| candidate commit | cda07a0b59c4d096714350fee3f884abde94b235 |
| dirty tracked files at run time | none |
| edition file digests (sha256, 16 hex) | kraft/krate=208317cd22aa20c9 kraft/docker-compose.yml=c7c1a38fa72e0e6a kraft/.env.template=e6eac0c698061b47 kraft/nginx.conf=5476aee8ca36324b sso/identity.py=aabfa1262853ad16 sso/preflight.py=84722aa52447faed sso/activate.sh=b231d9332395f18e |
| edition / fixture | kraft in /Users/shamirkhannabil/Development/Krate/harness/worktrees/gate-phase1/kraft, Compose project krate-gate1, https://localhost:8443, identity 172.29.250.0/24 (pool 172.29.250.128/25, proxy 172.29.250.10) |
| phases | all; screenshots: true; static: true |
| host | Darwin 27.0.0 arm64; Docker 29.8.0; Compose 5.5.1; Python 3.14.8; OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026) |
| images | apache/kafka:3.9.1@sha256:4ceccc577f03f51f6af8dbfda55194d0d892f4fa7913ffbded567ce3895622ed krate/kafka-ui:1.5.0-sso.7@sha256:3aa5e5919571b74c0b83ffa68287f06481ea7318c4a001c58d418534f50da28b nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10 quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94  |
| runner | gate-identity.sh v4 sha256 dce78cac31e9e4bb; gate/ 26f52d1fbaedd0a8; runner repository commit cda07a0b59c4d096714350fee3f884abde94b235 |
| started / finished (UTC) | 20261010T173432Z / 20261010T181054Z |

| id | phase | criterion | result | evidence |
|---|---|---|---|---|
| S1 | static | S | PASS | gmake check (syntax, lint, compose-check, offline-check, identity-check): Identity foundation verified: templates, realm plan, Kafbat runtime plan, names, Compose services and identity network,  |
| S2 | static | S | PASS | git diff --check clean |
| S3 | static | S | PASS | shellcheck 0.9.0 (CI version) on kraft/krate epc/krate sso/activate.sh and this runner |
| S4 | static | S | PASS | check-identity: Identity foundation verified: templates, realm plan, Kafbat runtime plan, names, Compose services and identity network, monitoring binds, logrotate drop-in, CLI |
| H1 | 1 | H | PASS | gen-cert:   ✓ Certificate written to certs/server.crt (replace with an org-CA cert anytime) |
| J1 | 1 | J | PASS | identity up exit=1; overlaps the identity subnet 172; both keys named; no container created |
| J2 | 1 | J | PASS | start exit=1 with the clash named; no container created |
| F1 | 1 | F | PASS | identity up exit=0 in pristine state; running services: [keycloak keycloak-db ] (no broker) |
| F2 | 1 | F | PASS | identity status exit=0: keycloak started yes, ready yes, live yes |
| H2 | 1 | H | PASS | master realm users after bootstrap: [admin ] (temp-admin removed) |
| J3 | 1 | J | PASS | journal: 2026-10-10T17:37:00Z up bootstrapped database initialised; permanent admin admin created; temp-admin removed |
| J4 | 1 | J | PASS | krate-realm.json holds placeholders, none of the 4 secret values |
| C1 | 1 | C | PASS | second identity up: 'No changes', .env sha d573d036d94716a0 unchanged |
| F3 | 1 | F | PASS | management port 9000 probes: started=200 ready=200 live=200 realm=200 |
| G1 | 1 | G | PASS | no host ports published: keycloak:[] keycloak-db:[] |
| F4 | 1 | F | PASS | authentication probe (krate-cli client_credentials via proxy) HTTP 200; health probes are separate (F3) |
| G2 | 1 | G | PASS | proxy paths sent as-is (realm discovery and account 200; admin, master realm, metrics, health, bare /identity 404; a dot segment onto the master realm 404; a dot segment onto an allowed path 400; a path parameter 400): /identity/realms/krate/.well-known/openid-configuration=200 /identity/realms/krate/account=200 /identity/admin/=404 /identity/admin/master/console/=404 /identity/realms/master=404 /identity/realms/master/account=404 /identity/metrics=404 /identity/health=404 /identity/health/ready=404 /identity=404 /identity/realms/krate/../master=404 /identity/realms/krate/../krate/account=400 /identity/realms/krate;x=1/account=400 |
| G3 | 1 | G | PASS | db=[krate-gate1_identity ] kc=[krate-gate1_identity krate-gate1_identity-egress ] identity.internal=true subnet=172.29.250.0/24 range=172.29.250.128/25 proxy=172.29.250.10 trusted=172.29.250.10 |
| G4 | 1 | G | PASS | probe container address 172.29.250.131 is inside 172.29.250.128/25 and not 172.29.250.10 |
| G5 | 1 | G | PASS | no route: keycloak is not a name on kafka-network |
| G6 | 1 | G | PASS | forged X-Forwarded-For 9.9.9.9 from peer 172.29.250.131: Keycloak event ipAddress=[172.29.250.131,CLIENT_LOGIN_ERROR ] (peer address recorded, header ignored) |
| G7 | 1 | G | PASS | same request through the proxy with a client-supplied X-Forwarded-For: event ipAddress=192.168.65.1 (nginx replaces the header with the real client address) |
| G8 | 1 | G | PASS | plain:[psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  pg_hba.conf rejects connection for host "172.29.250.131", user "keycloak", database "keycloak", no encryption] tls:[t\|TLSv1.3] wrongpw:[psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  password authentication failed for user "keycloak"] |
| A1 | 1 | A | PASS | users add (viewer, admin+email, no group, viewer) then list: [gatea:true gated:true gaten:true gatev:true ] |
| A2 | 1 | A | PASS | gatea groups=[KRATE_ADMINS]; 'bad name' refused (exit 1); duplicate gatev refused (exit 1) |
| A3 | 1 | A | PASS | first login: TOTP enrolment + forced password change, OTP required on the 2nd login, wrong OTP refused, old password refused: ENROLLED ['CONFIGURE_TOTP', 'UPDATE_PASSWORD'] aud=krate-ui groups=['KRATE_VIEWERS'] exp=300 iss=https://localhost:8443/identity/realms/krate |
| B1 | 1 | B | PASS | claims contract: gatea → ENROLLED groups=['KRATE_ADMINS']; gaten (no group) → ENROLLED groups=None (no groups claim: nothing to map a role from) |
| B2 | 1 | B | PASS | gatev: correct password+OTP accepted; wrong password refused on the login form with: REFUSED Invalid username or password. |
| B3 | 1 | B | PASS | users disable (exit 0); login refused with: REFUSED Account is disabled, contact your administrator.; users enable (exit 0) |
| B4 | 1 | B | PASS | direct password grant on krate-ui refused: HTTP 400 (standard flow only) |
| B5 | 1 | B | PASS | after 5 rapid wrong passwords the account is temporarily locked (Keycloak's quick-login check locks after two rapid failures, later attempts are not counted): {"failedLoginNotBefore":1791654010,"numFailures":2,"numTemporaryLockouts":0,"disabled":true,"numSecondaryAuthFailures":0,"lastIPFailure":"192.168.65.1","lastFailure":1791653950676} |
| B7 | 1 | B | PASS | a one-time code from the previous 30-second step is accepted (realm look-ahead window 1): {"result": "OK", "claims": {"iss": "https://localhost:8443/i |
| B6 | 1 | B | PASS | reset-password sets a new temporary password (exit 0; shown once) |
| A4 | 1 | A | PASS | old password refused after reset-password (REFUSED Invalid username or password.) |
| J5 | 1 | J | PASS | journal lines of users add/reset-password carry no secret value: 2026-10-10T17:37:33Z users add ok gatev group=KRATE_VIEWERS |
| C2 | 1 | C | PASS | after 'compose restart keycloak': 5 gate users still listed; identity up → No changes |
| C3 | 1 | C | PASS | identity down + up: 5 users kept; gatea logs in with password+OTP (credentials preserved) |
| H3 | 1 | H | PASS | fresh .env over an existing database: identity up exit=1 (identity database exists but .env lacks KEYCLOAK_ADMIN_PASSWORD KEYCLOAK_DB_PASSWORD KEYCLOAK_KAFBAT_CLIENT_SECRET KEYCLOAK_CLI_CLIENT_SECRET); the stored DB password still works (nothing rotated) |
| I1 | 1 | I | PASS | rotate KEYCLOAK_DB_PASSWORD: old rejected (psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  password authentication failed for user "keycloak"), new accepted, Keycloak ready again |
| I2 | 1 | I | PASS | rotate KEYCLOAK_ADMIN_PASSWORD: old password refused by kcadm (exit 1), new one lists master users [admin ] |
| I3 | 1 | I | PASS | rotate KEYCLOAK_CLI_CLIENT_SECRET: users list works, new secret authenticates (HTTP 200), identity up → No changes |
| I5 | 1 | I | PASS | rotate --value with the database password's value: refused (exit 1) naming KEYCLOAK_DB_PASSWORD; .env and Keycloak unchanged (admin login still works) |
| I4 | 1 | I | PASS | config set of a live identity secret refused with the rotate hint (exit 1) |
| D7 | 1 | D | PASS | KRATE_BACKUP_PASSPHRASE of 5 characters refused (exit 1), no archive written |
| D1 | 1 | D | PASS | identity backup: exit 0; mode=600 magic=krate-identity-backup/1; 276568 bytes |
| D2 | 1 | D | PASS | restore while Keycloak runs refused (exit 1):   ✗ Keycloak is running; stop it first: krate identity down |
| D3 | 1 | D | PASS | tampered archive (one bit flipped) refused before decryption: 'integrity check failed: the backup was modified or the passphrase is wrong' (exit 1); wrong passphrase refused the same way (exit 1) |
| D4 | 1 | D | PASS | restore: exit 0; marker user gatem gone; the 5 users of the backup present (now 5); Keycloak verified |
| D5 | 1 | D | PASS | restore reconciled .env: KEYCLOAK_CLI_CLIENT_SECRET back to the backup's value, KEYCLOAK_DB_PASSWORD (a database role) untouched; journal:  restore reconciled .env: KEYCLOAK_CLI_CLIENT_SECRET |
| E1 | 1 | E | PASS | wrong DB password in .env: identity up exit=1; .env not regenerated (still the wrong value); the value appears in neither output nor journal; journal:  start failed keycloak not healthy within 180s |
| E2 | 1 | E | PASS | server.key removed: identity up exit=1 (db-tls is incomplete; missing server); no new key generated |
| E3 | 1 | E | PASS | wrong admin password: up exit=1 with recover-admin hint; recover-admin refused while running (exit 1); after down it recreates the admin (exit 0); master users [admin ] |
| E4 | 1 | E | PASS | admin deleted in Keycloak (lost admin): up exit=1; recover-admin after down recreates it (exit 0); master users [admin ] |
| E5 | 1 | E | PASS | volume exists but no master realm (failed first run): identity up detects it, bootstraps (temp-admin created and removed); master users [admin ] |
| E6 | 1 | E | PASS | lock held by a live process: 'Another krate identity command is running (pid 54781)' (exit 1); after that process died: 'Removing the stale identity lock left by process 54781' and the command proceeds (exit 0) |
| E8 | 1 | E | PASS | 'krate stop' while an identity command holds the lock and KEYCLOAK_ENABLED is still false: 'Another krate identity command is running (pid 54977)' (exit 1); identity services untouched [keycloak keycloak-db proxy ] |
| E7 | 1 | E | PASS | two simultaneous mutating commands: refusals=1 created=1 (one refused and one created, or both serialised; never two half-made users) |
| F5 | 1 | F | PASS | database stopped: ready=503 live=200 (readiness down, liveness up); identity status exit=1; after 60 s restarts=0 state=running health=healthy (no restart loop); database back → ready again (status exit 0) |
| F6 | 1 | F | PASS | identity status after recovery exit=0: keycloak started yes, ready yes, live yes realm krate present KEYCLOAK_ENABLED true 2026-10-10T17:46:27Z down ok keycloak and keycloak-db stopped; volume kept |
| C4 | 1 | C | PASS | renew-db-tls: notAfter=Nov 12 17:36:02 2027 GMT → notAfter=Nov 12 17:49:18 2027 GMT, chains to the CA, .prev discarded, journal ok, Keycloak ready |
| C5 | 1 | C | PASS | injected restart failure: renew-db-tls exit=1, server.crt byte-identical to before (e0acc8374bb22db6), .prev consumed, journal 'rolled back'; database healthy on the old certificate (healthy) |
| C6 | 1 | C | PASS | otpPolicyLookAheadWindow set to 0 in Keycloak; identity up (exit 0) reconciled it to 1; journal 'up reconciled realm policy' |
| J6 | 1 | J | PASS | logrotate render names this journal: /Users/shamirkhannabil/Development/Krate/harness/worktrees/gate-phase1/kraft/auth/identity-journal.log { rotate 12 maxage 400 copytruncate |
| J7 | 1 | J | NOT_RUN | needs root (or sudo) and a logrotate binary: outside the inventory on this host; decided by the Linux VM receipt |
| A5 | 1 | A | PASS | users list after the whole ladder: 2 gate users |
| D6 | 1 | D | PASS | restore with KEYCLOAK_PUBLIC_URL=https://recovery.example.test/identity: exit 0; krate-ui redirect now [https://recovery.example.test/login/oauth2/code/keycloak]; journal 'restore reconciled krate-ui urls'; set back and identity up (exit 0) reconciles again |
| X1 | 1 | X | PASS | 11 screenshots in /Users/shamirkhannabil/Development/Krate/harness/gate-receipts/kraft-cda07a0-20261010T173432Z/screenshots (manifest.json has the captions and the asserted outcomes): STORY OK: 7 assertions over 11 screenshots |
| Z1 | 1 | Z | PASS | 27 distinct secret values (.env and monitoring/.env passwords/secrets/keys, the backup passphrase, 17 temporary passwords, enrolled passwords and TOTP seeds) searched in the raw log (temporary passwords: outside their one-time display line), journal, plan files, receipt rows, screenshot captions and the keycloak, keycloak-db, kafka-ui, proxy and monitoring logs: 0 hits |
| K1 | 2 | K | PASS | auth configure --local (exit 0; Kafbat plan: Keycloak login only (no shared form login), roles from the groups claim /Users/shamirkhannabil/Development/); start (exit 0); auth apply (exit 0, preflight inside); broker container untouched by apply; runtime.yml has no shared login |
| K30 | 2 | K | PASS | second auth apply: exit 0, kafka-ui container unchanged (f879e3ad9082 == f879e3ad9082), prints 'unchanged ... sessions kept' |
| K27 | 2 | K | PASS | public proxy, paths as-is: /metrics=404 /actuator=404 /actuator/=404 /actuator/health=404 /actuator/prometheus=404 /actuator;x/prometheus=400 /logout/connect=404 /logout/connect/back-channel/keycloak=404 /api/clusters;x=400 /api/clusters=302 (metrics/actuator/back-channel 404; path parameters 400; API redirects anonymous callers to login) |
| K33 | 2 | K | PASS | Host: evil.example.test → HTTP 000, curl exit 52 (444: empty reply); Host: localhost:8443 → 302; plain HTTP with Host: localhost → 301 https://localhost:8443/api/clusters (redirect to the public authority); KRATE_PROXY_PUBLIC_HOST=localhost:8443 |
| K34 | 2 | K | PASS | gen-cert changed KRATE_PROXY_CONF_SHA (b4f254b4379396ca081d69652cc4be9d → e1156e81137328043fcbaee752b9c04e); auth apply recreated the proxy (269d27fb4749 → 10b874930bcb, exit 0); second apply kept it (exit 0); proxy serves |
| K28 | 2 | K | PASS | anonymous API call redirects to https://localhost:8443/oauth2/authorization/keycloak |
| M1 | 2 | M | PASS | monitor up exit=0; Prometheus and Loki bound to 127.0.0.1 only, Grafana on all interfaces: prom=[9090/tcp -> 127.0.0.1:19090 ] loki=[3100/tcp -> 127.0.0.1:13100 ] grafana=[3000/tcp -> 0.0.0.0:13000 3000/tcp -> [::]:13000 ] |
| M2 | 2 | M | PASS | kafka-exporter networks: [krate-gate1_kafka-network krate-kraft-monitoring_monitoring ] (brokers' network, not identity) |
| K2 | 2 | K | PASS | 12/12 core reads 200; cluster listed=True lag field=True; other: broker-metrics=200 acls=500 activeproducers=200 config=403 |
| K3 | 2 | K | PASS | 26/26 RBAC-checked mutations 403 (valid CSRF token, body Access Denied); feature absent, refused before RBAC: connector*=500 x4 schema*=400 x2; new topic GET=404, fixture topic 200 |
| K4 | 2 | K | PASS | messages/v2=403 smartfilter-register=403; runtime.yml viewer messages_read=False (KAFKA_UI_VIEWER_MESSAGES=unset) |
| K5 | 2 | K | PASS | admin1 core 11/11 2xx (create,config,partitions,produce,read,msg-delete,offsets-reset,offsets-delete,group-delete,broker-config,delete); not 403: acl-create=500 ksql=200 connector=500 schema=400; d... |
| K6 | 2 | K | PASS | Keycloak login completed (TOTP enrolled); Kafbat callback 302 Location=/login?error; /api/clusters with jar=302 |
| K7 | 2 | K | PASS | after krate identity users disable: new login refused at Keycloak (Account is disabled, contact your administrator.), no code issued; credentials: same password and TOTP signed in twice just before... |
| K8 | 2 | K | PASS | GET /login=200; POST /login=405 ; POST /api/config/authentication=405; then /api/clusters=302; authType=OAUTH2 |
| K9 | 2 | K | PASS | deployed image 3aa5e5919571 vs stub IdP: control=accepted wrong-iss=refused wrong-aud=refused expired=refused bad-signature=refused; no session after each refusal=True |
| K10 | 2 | K | PASS | Kafbat username = Keycloak sub before; after e-mail/first/last name change (username read-only in the user profile): username = same sub True, same permissions True |
| K11 | 2 | K | PASS | admin group removed: open session kept admin (create topic 200); kcadm logout (3 KC sessions) 0.58s, old SESSION 302 after 0.01s; re-login without group: kafbat-refused /login?error |
| K12 | 2 | K | PASS | cross-site POST create-topic with SESSION, no token: 403 (Access Denied); topic GET=404; cross-site POST /logout=403; session still 200 |
| K13 | 2 | K | PASS | GET /logout=200 , session then 200; POST /logout without token=403, session then 200 |
| K14 | 2 | K | PASS | SESSION before login present=True, after login changed=True; old id -> 302, new id -> 200 |
| K15 | 2 | K | PASS | authz redirect_uri=callback; KC auth evil redirect_uri=400; KC logout evil target=400; GET //evil.example/ 302->/oauth2/authorization/keycloak; post-login Location /evil.example/ |
| K16 | 2 | K | PASS | via proxy: Location /oauth2/authorization/keyclo (unspoofed /oauth2/authorization/keyclo); non-proxy peer on kafka-network -> kafka-ui:8080: 302 /gate-spoof/oauth2/authoriza; honoured from non-prox... |
| K17 | 2 | K | NOT_RUN | owned by runner |
| K18 | 2 | K | PASS | ID token aud/azp=krate-cli: callback /login?error, /api/clusters=302; wrong iss: callback /login?error, /api/clusters=302 |
| K19 | 2 | K | PASS | krate-ui user token: /api/clusters=302 userInfo=False; krate-ui ID token: /api/clusters=302 userInfo=False; krate-cli token: /api/clusters=302 userInfo=False |
| K20 | 2 | K | PASS | viewer PUT /api/smartfilters/testexecutions=200 ({"result":true,"error":null}); POST /api/clusters/cluster-1-kraft/cache=200; guide: reachable by every signed-in user |
| K21 | 2 | K | PASS | kcadm users/{id}/logout (2 KC sessions) returned in 0.54s; old SESSION -> 302 /oauth2/authorization/keycloak after 0.01s |
| K22 | 2 | K | PASS | sessions survived the disable (200/200, new login refused: K7); idle limit 900s: after 840s idle 200, after 960s idle 302 /oauth2/authorization/keycloak |
| K23 | 2 | K | PASS | admin no header=403 (Access Denied); wrong token=403; valid token=200; viewer valid token=403 (Access Denied) |
| K24 | 2 | K | PASS | POST /logout+token 302 -> KC end_session; old SESSION 302; id_token_hint yes, post_logout_redirect_uri=https://localhost:8443; KC end-session 302 https://localhost:8443; Keycloak SSO session ended=... |
| K25 | 2 | K | PASS | both1 groups KRATE_ADMINS,KRATE_VIEWERS; permissions include administrator-only ksql=True (20 entries); topic create=200 delete=200 |
| K26 | 2 | K | PASS | identity up rc 0: realm krate present; realm groups before KRATE_ADMINS,KRATE_VIEWERS after KRATE_ADMINS,KRATE_VIEWERS; .env restored rc 0, identity up rc 0; guide documents admin-side rename=True |
| K31 | 2 | K | PASS | Secure=True HttpOnly=False; token before login set, cleared at login=True, new token after=True; session=200 |
| K32 | 2 | K | PASS | missing topic=404 invalid body=400 viewer denied=403; bodies without stackTrace=True |
| Z2 | 2 | Z | PASS | 28 distinct secret values (.env and monitoring/.env passwords/secrets/keys, the backup passphrase, 17 temporary passwords, enrolled passwords and TOTP seeds) searched in the raw log (temporary passwords: outside their one-time display line), journal, plan files, receipt rows, screenshot captions and the keycloak, keycloak-db, kafka-ui, proxy and monitoring logs: 0 hits |

### EPC, Phase 1 inside the air-gapped Rocky Linux 9 VM (bundle v101, product files of cda07a0)

Receipt folder: `harness/gate-receipts/epc-vm-cda07a0/` (receipt.md, receipt.tsv, run.log, the redacted
console log and the exit code). The bundle was built from a clean `git archive`
of c5a527a, whose edition files are byte-identical to cda07a0's (the later
commits touch the gate only); the runner is cda07a0's, invoked with
`--candidate cda07a0 --project krate-epc --phase 1 --wipe --no-static
--no-screenshots`, so S1–S4 and X1 are NOT_RUN by invocation and outside the
inventory. The air gap was on throughout (`dnf makecache` rc 1, `curl 1.1.1.1`
rc 28 before the run), the Mac ran nothing else, and the fixture left 0
containers. Six of the seven edition digests match `git show cda07a0:epc/…`;
`.env.template` differs by its five rewritten `*_IMAGE` lines only.

| field | value |
|---|---|
| verdict | **PASS** (PASS 63, FAIL 0, NOT_RUN 5, required missing 0: none; required not run: 0; bound: true) |
| candidate commit | cda07a0 (stated; no git here, bound by the edition file digests) |
| dirty tracked files at run time | unknown (no git); the file digests bind the candidate |
| edition file digests (sha256, 16 hex) | epc/krate=bcae176b14d33fbc epc/docker-compose.yml=44dca2e521e90e56 epc/.env.template=57048975b5dfbf65 epc/nginx.conf=5476aee8ca36324b epc/sso/identity.py=aabfa1262853ad16 epc/sso/preflight.py=84722aa52447faed epc/sso/activate.sh=b231d9332395f18e |
| edition / fixture | epc in /opt/krate/epc, Compose project krate-epc, https://localhost, identity 172.29.250.0/24 (pool 172.29.250.128/25, proxy 172.29.250.10) |
| phases | 1; screenshots: false; static: false |
| host | Linux 5.14.0-687.10.1.el9_8.0.1.aarch64 aarch64; Docker 29.9.0; Compose 5.6.0; Python 3.9.25; OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026) |
| images | krate-offline/image:sha256-39bc3b30084ad6ab33ad2c9a525f15c942bf097b18cb2a1825afa6df3411f8b5 krate-offline/image:sha256-e701673a1643cc8a4f196ea98b40b43c629e38f1dc0d57ffb7207dd2c7d9e3fb krate-offline/image:sha256-63ffc0d1f14e4082b832c6a42e606e9a0384a526f16ddd720af7c1f018f2f7c4 krate-offline/image:sha256-6741e706bd2cc2fcc2c97a74f227589c7283e44cdb210e47ea99258f243f6f74 krate-offline/image:sha256-9b9fb55f7e3b2149854def33c728b781dc44d1c5e86492ad62912a527ae234b3  |
| runner | gate-identity.sh v4 sha256 dce78cac31e9e4bb; gate/ 26f52d1fbaedd0a8; runner repository commit no git |
| started / finished (UTC) | 20261010T171803Z / 20261010T173413Z |

| id | phase | criterion | result | evidence |
|---|---|---|---|---|
| S1 | static | S | NOT_RUN | --no-static (outside the inventory) |
| S2 | static | S | NOT_RUN | --no-static (outside the inventory) |
| S3 | static | S | NOT_RUN | --no-static (outside the inventory) |
| S4 | static | S | NOT_RUN | --no-static (outside the inventory) |
| H1 | 1 | H | PASS | gen-cert:   ✓ Certificate written to certs/server.crt (replace with an org-CA cert anytime) |
| J1 | 1 | J | PASS | identity up exit=1; overlaps the identity subnet 172; both keys named; no container created |
| J2 | 1 | J | PASS | start exit=1 with the clash named; no container created |
| F1 | 1 | F | PASS | identity up exit=0 in pristine state; running services: [keycloak keycloak-db ] (no broker) |
| F2 | 1 | F | PASS | identity status exit=0: keycloak started yes, ready yes, live yes |
| H2 | 1 | H | PASS | master realm users after bootstrap: [admin ] (temp-admin removed) |
| J3 | 1 | J | PASS | journal: 2026-10-10T17:18:55Z up bootstrapped database initialised; permanent admin admin created; temp-admin removed |
| J4 | 1 | J | PASS | krate-realm.json holds placeholders, none of the 4 secret values |
| C1 | 1 | C | PASS | second identity up: 'No changes', .env sha 93deecd677cf0352 unchanged |
| F3 | 1 | F | PASS | management port 9000 probes: started=200 ready=200 live=200 realm=200 |
| G1 | 1 | G | PASS | no host ports published: keycloak:[] keycloak-db:[] |
| F4 | 1 | F | PASS | authentication probe (krate-cli client_credentials via proxy) HTTP 200; health probes are separate (F3) |
| G2 | 1 | G | PASS | proxy paths sent as-is (realm discovery and account 200; admin, master realm, metrics, health, bare /identity 404; a dot segment onto the master realm 404; a dot segment onto an allowed path 400; a path parameter 400): /identity/realms/krate/.well-known/openid-configuration=200 /identity/realms/krate/account=200 /identity/admin/=404 /identity/admin/master/console/=404 /identity/realms/master=404 /identity/realms/master/account=404 /identity/metrics=404 /identity/health=404 /identity/health/ready=404 /identity=404 /identity/realms/krate/../master=404 /identity/realms/krate/../krate/account=400 /identity/realms/krate;x=1/account=400 |
| G3 | 1 | G | PASS | db=[krate-epc_identity ] kc=[krate-epc_identity krate-epc_identity-egress ] identity.internal=true subnet=172.29.250.0/24 range=172.29.250.128/25 proxy=172.29.250.10 trusted=172.29.250.10 |
| G4 | 1 | G | PASS | probe container address 172.29.250.131 is inside 172.29.250.128/25 and not 172.29.250.10 |
| G5 | 1 | G | PASS | no route: keycloak is not a name on kafka-network |
| G6 | 1 | G | PASS | forged X-Forwarded-For 9.9.9.9 from peer 172.29.250.131: Keycloak event ipAddress=[172.29.250.131,CLIENT_LOGIN_ERROR ] (peer address recorded, header ignored) |
| G7 | 1 | G | PASS | same request through the proxy with a client-supplied X-Forwarded-For: event ipAddress=172.19.0.1 (nginx replaces the header with the real client address) |
| G8 | 1 | G | PASS | plain:[psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  pg_hba.conf rejects connection for host "172.29.250.131", user "keycloak", database "keycloak", no encryption] tls:[t\|TLSv1.3] wrongpw:[psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  password authentication failed for user "keycloak"] |
| A1 | 1 | A | PASS | users add (viewer, admin+email, no group, viewer) then list: [gatea:true gated:true gaten:true gatev:true ] |
| A2 | 1 | A | PASS | gatea groups=[KRATE_ADMINS]; 'bad name' refused (exit 1); duplicate gatev refused (exit 1) |
| A3 | 1 | A | PASS | first login: TOTP enrolment + forced password change, OTP required on the 2nd login, wrong OTP refused, old password refused: ENROLLED ['CONFIGURE_TOTP', 'UPDATE_PASSWORD'] aud=krate-ui groups=['KRATE_VIEWERS'] exp=300 iss=https://localhost/identity/realms/krate |
| B1 | 1 | B | PASS | claims contract: gatea → ENROLLED groups=['KRATE_ADMINS']; gaten (no group) → ENROLLED groups=None (no groups claim: nothing to map a role from) |
| B2 | 1 | B | PASS | gatev: correct password+OTP accepted; wrong password refused on the login form with: REFUSED Invalid username or password. |
| B3 | 1 | B | PASS | users disable (exit 0); login refused with: REFUSED Account is disabled, contact your administrator.; users enable (exit 0) |
| B4 | 1 | B | PASS | direct password grant on krate-ui refused: HTTP 400 (standard flow only) |
| B5 | 1 | B | PASS | after 5 rapid wrong passwords the account is temporarily locked (Keycloak's quick-login check locks after two rapid failures, later attempts are not counted): {"failedLoginNotBefore":1791652929,"numFailures":2,"numTemporaryLockouts":0,"disabled":true,"numSecondaryAuthFailures":0,"lastIPFailure":"172.19.0.1","lastFailure":1791652869189} |
| B7 | 1 | B | PASS | a one-time code from the previous 30-second step is accepted (realm look-ahead window 1): {"result": "OK", "claims": {"iss": "https://localhost/identi |
| B6 | 1 | B | PASS | reset-password sets a new temporary password (exit 0; shown once) |
| A4 | 1 | A | PASS | old password refused after reset-password (REFUSED Invalid username or password.) |
| J5 | 1 | J | PASS | journal lines of users add/reset-password carry no secret value: 2026-10-10T17:19:33Z users add ok gatev group=KRATE_VIEWERS |
| C2 | 1 | C | PASS | after 'compose restart keycloak': 5 gate users still listed; identity up → No changes |
| C3 | 1 | C | PASS | identity down + up: 5 users kept; gatea logs in with password+OTP (credentials preserved) |
| H3 | 1 | H | PASS | fresh .env over an existing database: identity up exit=1 (identity database exists but .env lacks KEYCLOAK_ADMIN_PASSWORD KEYCLOAK_DB_PASSWORD KEYCLOAK_KAFBAT_CLIENT_SECRET KEYCLOAK_CLI_CLIENT_SECRET); the stored DB password still works (nothing rotated) |
| I1 | 1 | I | PASS | rotate KEYCLOAK_DB_PASSWORD: old rejected (psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  password authentication failed for user "keycloak"), new accepted, Keycloak ready again |
| I2 | 1 | I | PASS | rotate KEYCLOAK_ADMIN_PASSWORD: old password refused by kcadm (exit 1), new one lists master users [admin ] |
| I3 | 1 | I | PASS | rotate KEYCLOAK_CLI_CLIENT_SECRET: users list works, new secret authenticates (HTTP 200), identity up → No changes |
| I5 | 1 | I | PASS | rotate --value with the database password's value: refused (exit 1) naming KEYCLOAK_DB_PASSWORD; .env and Keycloak unchanged (admin login still works) |
| I4 | 1 | I | PASS | config set of a live identity secret refused with the rotate hint (exit 1) |
| D7 | 1 | D | PASS | KRATE_BACKUP_PASSPHRASE of 5 characters refused (exit 1), no archive written |
| D1 | 1 | D | PASS | identity backup: exit 0; mode=600 magic=krate-identity-backup/1; 276568 bytes |
| D2 | 1 | D | PASS | restore while Keycloak runs refused (exit 1):   ✗ Keycloak is running; stop it first: krate identity down |
| D3 | 1 | D | PASS | tampered archive (one bit flipped) refused before decryption: 'integrity check failed: the backup was modified or the passphrase is wrong' (exit 1); wrong passphrase refused the same way (exit 1) |
| D4 | 1 | D | PASS | restore: exit 0; marker user gatem gone; the 5 users of the backup present (now 5); Keycloak verified |
| D5 | 1 | D | PASS | restore reconciled .env: KEYCLOAK_CLI_CLIENT_SECRET back to the backup's value, KEYCLOAK_DB_PASSWORD (a database role) untouched; journal:  restore reconciled .env: KEYCLOAK_CLI_CLIENT_SECRET |
| E1 | 1 | E | PASS | wrong DB password in .env: identity up exit=1; .env not regenerated (still the wrong value); the value appears in neither output nor journal; journal:  start failed keycloak not healthy within 180s |
| E2 | 1 | E | PASS | server.key removed: identity up exit=1 (db-tls is incomplete; missing server); no new key generated |
| E3 | 1 | E | PASS | wrong admin password: up exit=1 with recover-admin hint; recover-admin refused while running (exit 1); after down it recreates the admin (exit 0); master users [admin ] |
| E4 | 1 | E | PASS | admin deleted in Keycloak (lost admin): up exit=1; recover-admin after down recreates it (exit 0); master users [admin ] |
| E5 | 1 | E | PASS | volume exists but no master realm (failed first run): identity up detects it, bootstraps (temp-admin created and removed); master users [admin ] |
| E6 | 1 | E | PASS | lock held by a live process: 'Another krate identity command is running (pid 268276)' (exit 1); after that process died: 'Removing the stale identity lock left by process 268276' and the command proceeds (exit 0) |
| E8 | 1 | E | PASS | 'krate stop' while an identity command holds the lock and KEYCLOAK_ENABLED is still false: 'Another krate identity command is running (pid 269054)' (exit 1); identity services untouched [keycloak keycloak-db proxy ] |
| E7 | 1 | E | PASS | two simultaneous mutating commands: refusals=1 created=1 (one refused and one created, or both serialised; never two half-made users) |
| F5 | 1 | F | PASS | database stopped: ready=503 live=200 (readiness down, liveness up); identity status exit=1; after 60 s restarts=0 state=running health=healthy (no restart loop); database back → ready again (status exit 0) |
| F6 | 1 | F | PASS | identity status after recovery exit=0: keycloak started yes, ready yes, live yes realm krate present KEYCLOAK_ENABLED true 2026-10-10T17:28:42Z down ok keycloak and keycloak-db stopped; volume kept |
| C4 | 1 | C | PASS | renew-db-tls: notAfter=Nov 12 17:18:04 2027 GMT → notAfter=Nov 12 17:32:01 2027 GMT, chains to the CA, .prev discarded, journal ok, Keycloak ready |
| C5 | 1 | C | PASS | injected restart failure: renew-db-tls exit=1, server.crt byte-identical to before (a0489c94f20b233f), .prev consumed, journal 'rolled back'; database healthy on the old certificate (healthy) |
| C6 | 1 | C | PASS | otpPolicyLookAheadWindow set to 0 in Keycloak; identity up (exit 0) reconciled it to 1; journal 'up reconciled realm policy' |
| J6 | 1 | J | PASS | logrotate render names this journal: /opt/krate/epc/auth/identity-journal.log { rotate 12 maxage 400 copytruncate |
| J7 | 1 | J | PASS | logrotate --install (exit 0) and 'logrotate -d' dry run accepted; the installed drop-in is removed again by the gate |
| A5 | 1 | A | PASS | users list after the whole ladder: 2 gate users |
| D6 | 1 | D | PASS | restore with KEYCLOAK_PUBLIC_URL=https://recovery.example.test/identity: exit 0; krate-ui redirect now [https://recovery.example.test/login/oauth2/code/keycloak]; journal 'restore reconciled krate-ui urls'; set back and identity up (exit 0) reconciles again |
| X1 | 1 | X | NOT_RUN | --no-screenshots (outside the inventory) |
| Z1 | 1 | Z | PASS | 25 distinct secret values (.env and monitoring/.env passwords/secrets/keys, the backup passphrase, 15 temporary passwords, enrolled passwords and TOTP seeds) searched in the raw log (temporary passwords: outside their one-time display line), journal, plan files, receipt rows, screenshot captions and the keycloak, keycloak-db, kafka-ui, proxy and monitoring logs: 0 hits |

### EPC, full Phase 1 inventory inside the air-gapped Rocky Linux 9 VM (bundle v102 = product files of cda07a0, runner 315eff9)

The reduced EPC invocation above left S1–S4 and X1 NOT_RUN on that host; the
owner read that as "not validated there". This run validates every Phase 1 id on
the target OS inside the air gap: `--repo ~/gate/repo` (a `git clone -b
feat/gate-repo-option` of a git bundle at 315eff9, whose product files are
byte-identical to cda07a0 and to the installed v102), `gmake` 4.3 and `git`
2.52 installed from Rocky's repositories before the gap was applied (test
toolchain, not the product), `shellcheck` 0.9.0 from the loaded image behind a
`PATH` wrapper, `KRATE_CHECK_NGINX_IMAGE` set to the bundle's own nginx image,
the Playwright harness image loaded from a 939 MB archive, and root for J7.
Receipt folder: `harness/gate-receipts/epc-vm-315eff9-full/` (receipt.md, receipt.tsv, run.log, redacted console
log, exit code, `screenshots/01…11-*.png` with `manifest.json`). VERDICT PASS
68 / 0 / 0, 0 containers left; air gap on before, during and after (`dnf
makecache` rc 1, `curl 1.1.1.1` rc 28).

| field | value |
|---|---|
| verdict | **PASS** (PASS 68, FAIL 0, NOT_RUN 0, required missing 0: none; required not run: 0; bound: true) |
| candidate commit | 315eff9364a363d114ba3839e86c8738ab0b4e54 (stated as 315eff9364a363d114ba3839e86c8738ab0b4e54 and resolved in --repo; edition files bound by digest; static block on that checkout) |
| dirty tracked files at run time | edition: unknown (no git); --repo:  |
| edition file digests (sha256, 16 hex) | epc/krate=bcae176b14d33fbc epc/docker-compose.yml=44dca2e521e90e56 epc/.env.template=57048975b5dfbf65 epc/nginx.conf=5476aee8ca36324b epc/sso/identity.py=aabfa1262853ad16 epc/sso/preflight.py=84722aa52447faed epc/sso/activate.sh=b231d9332395f18e |
| edition / fixture | epc in /opt/krate/epc, Compose project krate-epc, https://localhost, identity 172.29.250.0/24 (pool 172.29.250.128/25, proxy 172.29.250.10) |
| phases | 1; screenshots: true; static: true |
| host | Linux 5.14.0-687.10.1.el9_8.0.1.aarch64 aarch64; Docker 29.9.0; Compose 5.6.0; Python 3.9.25; OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026) |
| images | krate-offline/image:sha256-39bc3b30084ad6ab33ad2c9a525f15c942bf097b18cb2a1825afa6df3411f8b5 krate-offline/image:sha256-e701673a1643cc8a4f196ea98b40b43c629e38f1dc0d57ffb7207dd2c7d9e3fb krate-offline/image:sha256-63ffc0d1f14e4082b832c6a42e606e9a0384a526f16ddd720af7c1f018f2f7c4 krate-offline/image:sha256-6741e706bd2cc2fcc2c97a74f227589c7283e44cdb210e47ea99258f243f6f74 krate-offline/image:sha256-9b9fb55f7e3b2149854def33c728b781dc44d1c5e86492ad62912a527ae234b3  |
| runner | gate-identity.sh v5 sha256 e9b8c9988e11c17c; gate/ 26f52d1fbaedd0a8; runner repository commit no git |
| started / finished (UTC) | 20261010T185649Z / 20261010T191050Z |

| id | phase | criterion | result | evidence |
|---|---|---|---|---|
| S1 | static | S | PASS | gmake check (syntax, lint, compose-check, offline-check, identity-check): [nginx render image: krate-offline/image:sha256-63ffc0d1f14e4082b832c6a42e606e9a0384a526f16ddd720af7c1f018f2f7c4 (KRATE_ |
| S2 | static | S | PASS | git diff --check clean |
| S3 | static | S | PASS | shellcheck 0.9.0 (CI version) on kraft/krate epc/krate sso/activate.sh and this runner |
| S4 | static | S | PASS | check-identity: [nginx render image: krate-offline/image:sha256-63ffc0d1f14e4082b832c6a42e606e9a0384a526f16ddd720af7c1f018f2f7c4 (KRATE_CHECK_NGINX_IMAGE, in place of the pinne |
| H1 | 1 | H | PASS | gen-cert:   ✓ Certificate written to certs/server.crt (replace with an org-CA cert anytime) |
| J1 | 1 | J | PASS | identity up exit=1; overlaps the identity subnet 172; both keys named; no container created |
| J2 | 1 | J | PASS | start exit=1 with the clash named; no container created |
| F1 | 1 | F | PASS | identity up exit=0 in pristine state; running services: [keycloak keycloak-db ] (no broker) |
| F2 | 1 | F | PASS | identity status exit=0: keycloak started yes, ready yes, live yes |
| H2 | 1 | H | PASS | master realm users after bootstrap: [admin ] (temp-admin removed) |
| J3 | 1 | J | PASS | journal: 2026-10-10T18:58:24Z up bootstrapped database initialised; permanent admin admin created; temp-admin removed |
| J4 | 1 | J | PASS | krate-realm.json holds placeholders, none of the 4 secret values |
| C1 | 1 | C | PASS | second identity up: 'No changes', .env sha 687571a2cf4fc75c unchanged |
| F3 | 1 | F | PASS | management port 9000 probes: started=200 ready=200 live=200 realm=200 |
| G1 | 1 | G | PASS | no host ports published: keycloak:[] keycloak-db:[] |
| F4 | 1 | F | PASS | authentication probe (krate-cli client_credentials via proxy) HTTP 200; health probes are separate (F3) |
| G2 | 1 | G | PASS | proxy paths sent as-is (realm discovery and account 200; admin, master realm, metrics, health, bare /identity 404; a dot segment onto the master realm 404; a dot segment onto an allowed path 400; a path parameter 400): /identity/realms/krate/.well-known/openid-configuration=200 /identity/realms/krate/account=200 /identity/admin/=404 /identity/admin/master/console/=404 /identity/realms/master=404 /identity/realms/master/account=404 /identity/metrics=404 /identity/health=404 /identity/health/ready=404 /identity=404 /identity/realms/krate/../master=404 /identity/realms/krate/../krate/account=400 /identity/realms/krate;x=1/account=400 |
| G3 | 1 | G | PASS | db=[krate-epc_identity ] kc=[krate-epc_identity krate-epc_identity-egress ] identity.internal=true subnet=172.29.250.0/24 range=172.29.250.128/25 proxy=172.29.250.10 trusted=172.29.250.10 |
| G4 | 1 | G | PASS | probe container address 172.29.250.131 is inside 172.29.250.128/25 and not 172.29.250.10 |
| G5 | 1 | G | PASS | no route: keycloak is not a name on kafka-network |
| G6 | 1 | G | PASS | forged X-Forwarded-For 9.9.9.9 from peer 172.29.250.131: Keycloak event ipAddress=[172.29.250.131,CLIENT_LOGIN_ERROR ] (peer address recorded, header ignored) |
| G7 | 1 | G | PASS | same request through the proxy with a client-supplied X-Forwarded-For: event ipAddress=172.19.0.1 (nginx replaces the header with the real client address) |
| G8 | 1 | G | PASS | plain:[psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  pg_hba.conf rejects connection for host "172.29.250.131", user "keycloak", database "keycloak", no encryption] tls:[t\|TLSv1.3] wrongpw:[psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  password authentication failed for user "keycloak"] |
| A1 | 1 | A | PASS | users add (viewer, admin+email, no group, viewer) then list: [gatea:true gated:true gaten:true gatev:true ] |
| A2 | 1 | A | PASS | gatea groups=[KRATE_ADMINS]; 'bad name' refused (exit 1); duplicate gatev refused (exit 1) |
| A3 | 1 | A | PASS | first login: TOTP enrolment + forced password change, OTP required on the 2nd login, wrong OTP refused, old password refused: ENROLLED ['CONFIGURE_TOTP', 'UPDATE_PASSWORD'] aud=krate-ui groups=['KRATE_VIEWERS'] exp=300 iss=https://localhost/identity/realms/krate |
| B1 | 1 | B | PASS | claims contract: gatea → ENROLLED groups=['KRATE_ADMINS']; gaten (no group) → ENROLLED groups=None (no groups claim: nothing to map a role from) |
| B2 | 1 | B | PASS | gatev: correct password+OTP accepted; wrong password refused on the login form with: REFUSED Invalid username or password. |
| B3 | 1 | B | PASS | users disable (exit 0); login refused with: REFUSED Account is disabled, contact your administrator.; users enable (exit 0) |
| B4 | 1 | B | PASS | direct password grant on krate-ui refused: HTTP 400 (standard flow only) |
| B5 | 1 | B | PASS | after 5 rapid wrong passwords the account is temporarily locked (Keycloak's quick-login check locks after two rapid failures, later attempts are not counted): {"failedLoginNotBefore":1791658898,"numFailures":2,"numTemporaryLockouts":0,"disabled":true,"numSecondaryAuthFailures":0,"lastIPFailure":"172.19.0.1","lastFailure":1791658838828} |
| B7 | 1 | B | PASS | a one-time code from the previous 30-second step is accepted (realm look-ahead window 1): {"result": "OK", "claims": {"iss": "https://localhost/identi |
| B6 | 1 | B | PASS | reset-password sets a new temporary password (exit 0; shown once) |
| A4 | 1 | A | PASS | old password refused after reset-password (REFUSED Invalid username or password.) |
| J5 | 1 | J | PASS | journal lines of users add/reset-password carry no secret value: 2026-10-10T18:58:58Z users add ok gatev group=KRATE_VIEWERS |
| C2 | 1 | C | PASS | after 'compose restart keycloak': 5 gate users still listed; identity up → No changes |
| C3 | 1 | C | PASS | identity down + up: 5 users kept; gatea logs in with password+OTP (credentials preserved) |
| H3 | 1 | H | PASS | fresh .env over an existing database: identity up exit=1 (identity database exists but .env lacks KEYCLOAK_ADMIN_PASSWORD KEYCLOAK_DB_PASSWORD KEYCLOAK_KAFBAT_CLIENT_SECRET KEYCLOAK_CLI_CLIENT_SECRET); the stored DB password still works (nothing rotated) |
| I1 | 1 | I | PASS | rotate KEYCLOAK_DB_PASSWORD: old rejected (psql: error: connection to server at "keycloak-db" (172.29.250.129), port 5432 failed: FATAL:  password authentication failed for user "keycloak"), new accepted, Keycloak ready again |
| I2 | 1 | I | PASS | rotate KEYCLOAK_ADMIN_PASSWORD: old password refused by kcadm (exit 1), new one lists master users [admin ] |
| I3 | 1 | I | PASS | rotate KEYCLOAK_CLI_CLIENT_SECRET: users list works, new secret authenticates (HTTP 200), identity up → No changes |
| I5 | 1 | I | PASS | rotate --value with the database password's value: refused (exit 1) naming KEYCLOAK_DB_PASSWORD; .env and Keycloak unchanged (admin login still works) |
| I4 | 1 | I | PASS | config set of a live identity secret refused with the rotate hint (exit 1) |
| D7 | 1 | D | PASS | KRATE_BACKUP_PASSPHRASE of 5 characters refused (exit 1), no archive written |
| D1 | 1 | D | PASS | identity backup: exit 0; mode=600 magic=krate-identity-backup/1; 276568 bytes |
| D2 | 1 | D | PASS | restore while Keycloak runs refused (exit 1):   ✗ Keycloak is running; stop it first: krate identity down |
| D3 | 1 | D | PASS | tampered archive (one bit flipped) refused before decryption: 'integrity check failed: the backup was modified or the passphrase is wrong' (exit 1); wrong passphrase refused the same way (exit 1) |
| D4 | 1 | D | PASS | restore: exit 0; marker user gatem gone; the 5 users of the backup present (now 5); Keycloak verified |
| D5 | 1 | D | PASS | restore reconciled .env: KEYCLOAK_CLI_CLIENT_SECRET back to the backup's value, KEYCLOAK_DB_PASSWORD (a database role) untouched; journal:  restore reconciled .env: KEYCLOAK_CLI_CLIENT_SECRET |
| E1 | 1 | E | PASS | wrong DB password in .env: identity up exit=1; .env not regenerated (still the wrong value); the value appears in neither output nor journal; journal:  start failed keycloak not healthy within 180s |
| E2 | 1 | E | PASS | server.key removed: identity up exit=1 (db-tls is incomplete; missing server); no new key generated |
| E3 | 1 | E | PASS | wrong admin password: up exit=1 with recover-admin hint; recover-admin refused while running (exit 1); after down it recreates the admin (exit 0); master users [admin ] |
| E4 | 1 | E | PASS | admin deleted in Keycloak (lost admin): up exit=1; recover-admin after down recreates it (exit 0); master users [admin ] |
| E5 | 1 | E | PASS | volume exists but no master realm (failed first run): identity up detects it, bootstraps (temp-admin created and removed); master users [admin ] |
| E6 | 1 | E | PASS | lock held by a live process: 'Another krate identity command is running (pid 92802)' (exit 1); after that process died: 'Removing the stale identity lock left by process 92802' and the command proceeds (exit 0) |
| E8 | 1 | E | PASS | 'krate stop' while an identity command holds the lock and KEYCLOAK_ENABLED is still false: 'Another krate identity command is running (pid 93519)' (exit 1); identity services untouched [keycloak keycloak-db proxy ] |
| E7 | 1 | E | PASS | two simultaneous mutating commands: refusals=1 created=1 (one refused and one created, or both serialised; never two half-made users) |
| F5 | 1 | F | PASS | database stopped: ready=503 live=200 (readiness down, liveness up); identity status exit=1; after 60 s restarts=0 state=running health=healthy (no restart loop); database back → ready again (status exit 0) |
| F6 | 1 | F | PASS | identity status after recovery exit=0: keycloak started yes, ready yes, live yes realm krate present KEYCLOAK_ENABLED true 2026-10-10T19:06:42Z down ok keycloak and keycloak-db stopped; volume kept |
| C4 | 1 | C | PASS | renew-db-tls: notAfter=Nov 12 18:57:43 2027 GMT → notAfter=Nov 12 19:08:57 2027 GMT, chains to the CA, .prev discarded, journal ok, Keycloak ready |
| C5 | 1 | C | PASS | injected restart failure: renew-db-tls exit=1, server.crt byte-identical to before (573f10d58abdcf3c), .prev consumed, journal 'rolled back'; database healthy on the old certificate (healthy) |
| C6 | 1 | C | PASS | otpPolicyLookAheadWindow set to 0 in Keycloak; identity up (exit 0) reconciled it to 1; journal 'up reconciled realm policy' |
| J6 | 1 | J | PASS | logrotate render names this journal: /opt/krate/epc/auth/identity-journal.log { rotate 12 maxage 400 copytruncate |
| J7 | 1 | J | PASS | logrotate --install (exit 0) and 'logrotate -d' dry run accepted; the installed drop-in is removed again by the gate |
| A5 | 1 | A | PASS | users list after the whole ladder: 2 gate users |
| D6 | 1 | D | PASS | restore with KEYCLOAK_PUBLIC_URL=https://recovery.example.test/identity: exit 0; krate-ui redirect now [https://recovery.example.test/login/oauth2/code/keycloak]; journal 'restore reconciled krate-ui urls'; set back and identity up (exit 0) reconciles again |
| X1 | 1 | X | PASS | 11 screenshots in /home/shamirkhannabil.guest/gate/receipt-epc-315eff9364a363d114ba3839e86c8738ab0b4e54/screenshots (manifest.json has the captions and the asserted outcomes): STORY OK: 7 assertions over 11 screenshots |
| Z1 | 1 | Z | PASS | 27 distinct secret values (.env and monitoring/.env passwords/secrets/keys, the backup passphrase, 17 temporary passwords, enrolled passwords and TOTP seeds) searched in the raw log (temporary passwords: outside their one-time display line), journal, plan files, receipt rows, screenshot captions and the keycloak, keycloak-db, kafka-ui, proxy and monitoring logs: 0 hits |

## Sign-off

The owner accepts a phase by recording the receipt folder, the candidate
commit and the verdict in the Serena memory `project/keycloak-first-tracker`
(phase table) and in the pull request. A receipt with dirty tracked files, an
unbound candidate, a FAIL, or a NOT_RUN or missing id inside the selected
inventory is not acceptable.
