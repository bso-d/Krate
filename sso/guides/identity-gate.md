# Identity acceptance gate (Phase 1 and Phase 2)

This is the executable gate for the Keycloak-first programme. It answers, per
acceptance criterion of the owner's handover, which test proves it, how that
test is run, and what the last run produced. The gate is a script,
`scripts/gate-identity.sh`; its receipt is the evidence, and the owner signs
off on the receipt, not on prose. Phase 2 is accepted only together with
Phase 1: both run against one candidate commit, in one receipt.

## How to run it

```bash
# a disposable checkout (never the operator's installation; the run creates and destroys .env, auth/keycloak, certs)
git -C /path/to/Krate worktree add --detach harness/worktrees/gate HEAD
scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe            # Phase 1 + screenshots + Phase 2
scripts/gate-identity.sh --edition-dir /opt/krate/epc --wipe --no-static --no-screenshots   # on the RHEL/Rocky VM, from the bundle
```

Prerequisites: Docker with Compose ≥ 2.20.2, python3, openssl, curl; the
candidate's images on the host (`krate/kafka-ui:1.5.0-sso.7` built with `make
kafbat-ui`); nothing else from Krate running on the host (the product allows
one Keycloak deployment per Docker host: a second `keycloak_db_data` volume or
the fixed `krate-proxy` name makes `identity up` refuse). The screenshot story
builds a small harness image once (`krate-harness/playwright:1.60.0`, network
needed that one time).

The run takes about 35 minutes for Phase 1 (eleven Keycloak start cycles) and
about 15 minutes for Phase 2. Output: `harness/gate-receipts/<edition>-<sha>-<time>/`
with `receipt.md` (the table below, generated), `receipt.tsv`, `run.log`
(every command output, secret values replaced by `<redacted>`) and
`screenshots/*.png` with `manifest.json` captions.

## What a receipt binds the results to

| field | meaning |
|---|---|
| candidate commit | `git rev-parse HEAD` of the fixture checkout |
| dirty tracked files | `git status --porcelain` on kraft, epc, sso, scripts, Makefile, monitoring, kafbat-ui at run time (must be empty for a sign-off receipt) |
| images | every `*_IMAGE` digest of the edition template |
| runner | sha256 of `scripts/gate-identity.sh` and of `scripts/gate/*` |
| host | OS, Docker, Compose, python, openssl versions |
| verdict | PASS only when no test failed and every id of the required inventory passed; a required id that is NOT_RUN or absent makes it INCOMPLETE. Rows outside the inventory (J7 on a host without root) are informational |

The required inventory is declared in the runner before anything runs
(`REQUIRED_P1`, `REQUIRED_P2`, `REQUIRED_X`): a test that never reports cannot
pass by absence.

## Criteria and their tests

The letters are the criteria; the handover sentence each comes from is quoted.
Every id is one row of the receipt.

### S: the candidate is statically sound

| id | test | pass condition |
|---|---|---|
| S1 | `gmake check` (syntax, shellcheck, digest pinning, Compose rendering of every stack, offline policy, `scripts/check-identity.py`) | exit 0 |
| S2 | `git diff --check` | clean |
| S3 | shellcheck 0.9.0 (the CI version) on both CLIs, `sso/activate.sh` and the runner | exit 0 |
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
| F6 | `identity status` after recovery | exit 0 |

### G: "Protect every relevant link: trusted browser-facing HTTPS and issuer URLs; explicitly trusted proxy headers; private management endpoints; database TLS with certificate and hostname verification. … audit and close reachable unauthenticated backing-service paths, including published monitoring endpoints."

| id | test | pass condition |
|---|---|---|
| G1 | `docker port` of keycloak and keycloak-db | nothing published |
| G2 | proxy paths: realm discovery and account console; admin console, master realm, metrics, health, bare `/identity`, dot-segment traversal | 200, 200; the rest 404 (traversal 400) |
| G3 | network membership and addresses: keycloak-db on `identity` only; keycloak on `identity` + `identity-egress`; `identity` internal with the configured subnet and `ip_range`; proxy at `KRATE_IDENTITY_PROXY_IP` = `KC_PROXY_TRUSTED_ADDRESSES` | all equal to the configuration |
| G4 | a dynamically addressed container on `identity` | its address is inside `KRATE_IDENTITY_IP_RANGE` and is not the proxy address |
| G5 | name resolution of `keycloak` from the brokers' network | no such name |
| G6 | forged `X-Forwarded-For: 9.9.9.9` sent straight to keycloak:8080 by a non-proxy peer | the Keycloak event records the peer's own address, not 9.9.9.9 |
| G7 | the same header sent through the proxy | the event records neither 9.9.9.9 nor the peer: nginx replaces the header with the real client address |
| G8 | database TLS from a client container: plaintext, `verify-full` against the generated CA, wrong password | plaintext rejected by `pg_hba`; `t|TLSv1.3`; wrong password rejected |
| K27/K28 (Phase 2) | Kafbat's `/metrics`, `/actuator/*`, `/logout/connect/*` through the proxy; anonymous API call | 404; redirect to the Keycloak login |
| M1/M2 (Phase 2) | `monitor up`: Prometheus and Loki bind addresses; kafka-exporter's networks | 127.0.0.1 only; Grafana unchanged; exporter on the brokers' network, not on `identity` |

### A and B: "local account lifecycle and MFA work; unauthorized users are denied"

| id | test | pass condition |
|---|---|---|
| A1 | `users add` (viewer, admin with email, no group, viewer) then `users list` | all four listed, enabled |
| A2 | `users groups`; `users add 'bad name'`; duplicate `users add` | admin group shown; both refusals |
| A3 | first login through the proxy with the temporary password (headless browser flow, `scripts/gate/keycloak_login_flow.py`): TOTP enrolment, forced password change, second login asks for the OTP, wrong OTP refused, old password refused | all steps observed; ID token `aud=krate-ui`, `groups=[viewer group]`, `expires_in=300` |
| A4 | `reset-password` then login with the previous password | refused |
| A5 | `users list` at the end of the ladder | exit 0 |
| B1 | claims contract: admin user → `groups=[admin group]`; user without group → no `groups` claim | as stated (nothing to map a role from) |
| B2 | correct password + OTP accepted; wrong password refused | as stated |
| B3 | disabled user refused; `enable` works | as stated |
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
| C5 | `renew-db-tls` with an injected restart failure (a `docker` wrapper on `PATH` fails `compose restart`) | exit 1; `server.crt` byte-identical to before; journal `renew-db-tls rolled back`; database healthy on the old certificate |

### I: "Implement credential-specific changes through the authoritative store and verify the consumer. Editing .env or regenerating realm JSON is insufficient evidence."

| id | test | pass condition |
|---|---|---|
| I1 | `rotate KEYCLOAK_DB_PASSWORD` | old password rejected by PostgreSQL, new accepted, Keycloak ready |
| I2 | `rotate KEYCLOAK_ADMIN_PASSWORD` | old refused by kcadm, new lists the master users |
| I3 | `rotate KEYCLOAK_CLI_CLIENT_SECRET` | `users list` works, new secret authenticates, `identity up` → `No changes` |
| I4 | `config set KEYCLOAK_DB_PASSWORD=…` on a live database | refused with the `rotate` hint |

### D: "a database/configuration restore is demonstrated"

| id | test | pass condition |
|---|---|---|
| D1 | `identity backup` | file mode 600, magic `krate-identity-backup/1` |
| D2 | `identity restore` while Keycloak runs | refused |
| D3 | a tampered archive (one bit flipped); a wrong passphrase | both refused before decryption (`integrity check failed`) |
| D4 | after a secret rotation and a marker user: `identity down`, `identity restore` | marker gone, earlier users present, Keycloak verified |
| D5 | the restored `.env` | `KEYCLOAK_CLI_CLIENT_SECRET` back to the backup's value, `KEYCLOAK_DB_PASSWORD` untouched (a database role, not part of the dump); journal `restore reconciled` |

### E: "failure injection reveals no false success, secret leakage or silent replacement"

| id | test | pass condition |
|---|---|---|
| E1 | wrong `KEYCLOAK_DB_PASSWORD` in `.env` on an existing database | `identity up` exit 1; `.env` still holds the wrong value (not regenerated); the value appears in neither the output nor the journal |
| E2 | `server.key` removed | refused as incomplete; no new key written |
| E3 | wrong `KEYCLOAK_ADMIN_PASSWORD` in `.env` | `identity up` exit 1 with the `recover-admin` hint; `recover-admin` refused while running; after `identity down` it recreates the admin; master users = the admin only |
| E4 | the master admin deleted in Keycloak (lost admin) | `identity up` exit 1; `recover-admin` after `down` recreates it |
| E5 | database volume present but no master realm (a failed first run) | `identity up` detects it and bootstraps; the temporary admin is removed |
| E6 | the identity lock held by a live process; then that process dies | the command is refused naming the pid; afterwards the stale lock is removed and the command proceeds |
| E7 | two mutating commands started at the same instant | recorded (refusal count); the deterministic proof is E6 |
| Z1/Z2 | every secret value seen during the run (each `.env` password/secret before and after rotations, the backup passphrase) searched in the raw log, the journal, the plan files, the keycloak and keycloak-db logs | 0 hits |

### J: "Make configuration planning pure and application explicit: validate prerequisites before mutation, lock concurrent applies, stage a complete generation, redact diffs and journal transitions."

| id | test | pass condition |
|---|---|---|
| J1 | a Docker network already covering the identity subnet, then `identity up` | refused naming the network and both keys; no container created |
| J2 | the same with `start` | refused the same way; no container created |
| J3 | journal after the first `identity up` | `up bootstrapped` |
| J4 | `krate-realm.json` | placeholders only, none of the secret values |
| J5 | journal lines of `users add` / `reset-password` | user names only |
| J6 | `identity logrotate` | renders the drop-in for this journal |
| J7 | `identity logrotate --install` and `logrotate -d` | accepted (root; informational on a host without root, proven on the Linux VM) |

### X: the end user's view (owner rule 10)

| id | test | pass condition |
|---|---|---|
| X1 | a real browser (Playwright, Chromium) in the proxy's network namespace: account console asks to sign in → login form → TOTP enrolment → forced password change → signed-in console → second login asks the OTP → wrong OTP → wrong password → disabled user → admin console, master realm and metrics blocked | every step reached; one PNG per step in `screenshots/`, captions in `manifest.json` |

### K: Phase 2, "the first UI uses the Keycloak issuer in local mode and enforces approved roles at its backend"

| id | test | pass condition |
|---|---|---|
| K1 | `auth configure --local`, `config set KAFKA_UI_AUTH_CONFIG=runtime.yml`, `start`, `auth apply` | all exit 0 (preflight inside apply); broker containers untouched; `runtime.yml` has no shared login |
| K30 | a second `auth apply` | kafka-ui container unchanged; prints `unchanged … sessions kept` |
| K2–K26, K31, K32 | the Kafbat authorization ladder, `scripts/gate/phase2_kafbat.py` (viewer reads; every mutation refused by the backend with 403; admin mutates; no-group user refused at login; disabled user refused; shared login absent; ID-token issuer/audience checks; identity = `sub`; CSRF; POST-only logout ending the Keycloak session; back-channel logout measured; disabled user's session lifetime measured; open-redirect and proxy-header spoofing; both-groups user = administrator; group rename in `.env` leaves the realm alone; K31: XSRF cookie `Secure`, not HttpOnly, rotated at login; K32: error bodies carry no stack trace; the viewer's `GET /api/config` 403 is part of K2) | each case PASS with the observed status codes and measured seconds in the evidence |
| K27/K28, M1/M2 | see G above | |

### Not covered by this runner, proven elsewhere

| what | where | result |
|---|---|---|
| EPC runtime, offline bundle install on a RHEL-9 class host (SELinux enforcing), `logrotate --install` | Rocky Linux 9 Lima VM, `harness/linux-vm/RUNBOOK.md` (run 2 with commit ≥ 0b32a40) | see the run-2 section of the runbook |
| Ubuntu deb install | not run (no Ubuntu host in this programme yet) | open |
| amd64 image builds | CI `broker-ci.yml` matrix; the Kafbat image is built per arch with `make kafbat-ui ARCH=amd64` on the bundling host | CI |

## Last run

The receipt table of the last accepted run is pasted here verbatim by the
person who ran it, with the receipt folder name. Until then this section
reads "no accepted run".

no accepted run

## Sign-off

The owner accepts a phase by recording the receipt folder, the candidate
commit and the verdict in the Serena memory `project/keycloak-first-tracker`
(phase table) and in the pull request. A receipt with dirty tracked files,
a FAIL, a NOT_RUN or a missing required id is not acceptable.
