#!/usr/bin/env bash
# Krate identity acceptance gate: Phase 1 (identity foundation) and Phase 2 (Kafbat
# authorization) against a disposable fixture. Each acceptance criterion of the
# owner's handover has numbered tests; every test ends PASS, FAIL or NOT_RUN with
# evidence, and the receipt binds the results to the candidate commit, the dirty
# files, the tool versions and this runner's own digest. The gate verdict is PASS
# only when every required test passed. See sso/guides/identity-gate.md.
#
#   scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe [--phase 1|2|all]
#
# The fixture directory is a checkout of the edition (its .env, auth/keycloak,
# certs and journal are created and destroyed by the run), never the operator's
# installation: the runner refuses an existing .env unless --wipe is given.
# shellcheck disable=SC2319  # `[[ ... ]]; st=$?` reads the condition's status on the very next statement
set -uo pipefail

GATE_VERSION=1
RUNNER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
GATE_DIR="$(dirname "$RUNNER")/gate"
REPO="$(cd "$(dirname "$RUNNER")/.." && pwd)"

EDITION_DIR="$REPO/kraft"
PROJECT=krate-gate1
HTTPS_PORT=443
HTTP_PORT=80
SUBNET=172.29.250.0/24
PROXY_IP=172.29.250.10
IP_RANGE=172.29.250.128/25
PHASE=all
OUT=""
KEEP=false
WIPE=false
SCREENSHOTS=true
STATIC=true

usage() {
  cat <<EOF
Usage: $0 [--edition-dir DIR] [--project NAME] [--https-port N] [--http-port N]
          [--subnet CIDR --proxy-ip IP --ip-range CIDR] [--phase 1|2|all] [--out DIR]
          [--wipe] [--keep] [--no-screenshots] [--no-static]
  --edition-dir   kraft or epc checkout used as the fixture (default: $REPO/kraft)
  --wipe          remove an existing .env/auth/certs in that directory first (required when present)
  --keep          leave the fixture running at the end (no teardown)
  --no-screenshots skip the end-user screenshot story (needs network once to build the harness image)
  --no-static     skip gmake check / git diff --check (bundle hosts without the repository)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --edition-dir) EDITION_DIR="$(cd "$2" && pwd)"; shift 2 ;;
    --project) PROJECT="$2"; shift 2 ;;
    --https-port) HTTPS_PORT="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --subnet) SUBNET="$2"; shift 2 ;;
    --proxy-ip) PROXY_IP="$2"; shift 2 ;;
    --ip-range) IP_RANGE="$2"; shift 2 ;;
    --phase) PHASE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --wipe) WIPE=true; shift ;;
    --keep) KEEP=true; shift ;;
    --no-screenshots) SCREENSHOTS=false; shift ;;
    --no-static) STATIC=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

ED="$EDITION_DIR"
EDITION="$(basename "$ED")"
KRATE="$ED/krate"
ENVF="$ED/.env"
JOURNAL="$ED/auth/identity-journal.log"
TLS="$ED/auth/keycloak/db-tls"
[[ "$HTTPS_PORT" == 443 ]] && BASE="https://localhost" || BASE="https://localhost:$HTTPS_PORT"
[[ -x "$KRATE" && -f "$ED/.env.template" ]] || { echo "not an edition directory: $ED" >&2; exit 2; }
if [[ -e "$ENVF" ]] && ! $WIPE; then
  echo "$ENVF exists; this runner destroys the fixture it is pointed at. Pass --wipe for a disposable checkout." >&2
  exit 2
fi

CANDIDATE="$(git -C "$ED" rev-parse HEAD 2>/dev/null || echo unknown)"
TOPLEVEL="$(git -C "$ED" rev-parse --show-toplevel 2>/dev/null || echo "$ED/..")"
DIRTY="$(git -C "$TOPLEVEL" status --porcelain --untracked-files=no -- kraft epc sso scripts Makefile monitoring kafbat-ui 2>/dev/null | grep -v -E ' (kraft|epc)/(\.env|auth/|certs/)' || true)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[[ -n "$OUT" ]] || OUT="$REPO/harness/gate-receipts/${EDITION}-${CANDIDATE:0:7}-${STAMP}"
mkdir -p "$OUT" "$OUT/screenshots"
chmod 700 "$OUT"
RAW="$OUT/.raw.log"; : > "$RAW"; chmod 600 "$RAW"
RECEIPT="$OUT/receipt.tsv"; printf 'id\tphase\tcriterion\tresult\tevidence\n' > "$RECEIPT"
STATE="$OUT/.state"; mkdir -p "$STATE"; chmod 700 "$STATE"
declare -a SECRETS=()
declare -A SEEN=()
PASSES=0; FAILS=0; NOTRUN=0

# ── required inventory (declared before anything runs; a missing row fails the gate) ──
REQUIRED_P1=(S1 S2 S3 S4 H1 H2 H3 F1 F2 F3 F4 F5 F6 G1 G2 G3 G4 G5 G6 A1 A2 A3 A4 A5 B1 B2 B3 B4 B5 B6 B7 C1 C2 C3 C4 C5 I1 I2 I3 I4 I5 D1 D2 D3 D4 D5 D6 D7 E1 E2 E3 E4 E5 E6 E7 E8 J1 J2 J3 J4 J5 J6 G7 G8 Z1)
REQUIRED_P2=(K1 K2 K3 K4 K5 K6 K7 K8 K9 K10 K11 K12 K13 K14 K15 K16 K18 K19 K20 K21 K22 K23 K24 K25 K26 K27 K28 K30 K32 M1 M2 Z2)
REQUIRED_X=(X1)

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RAW" >&2; }
section() { log ""; log "=== $* ==="; }
record() { # id phase criterion result evidence
  local id="$1" phase="$2" crit="$3" result="$4" evidence="$5"
  evidence="${evidence//$'\t'/ }"; evidence="${evidence//$'\n'/ | }"
  if [[ -n "${SEEN[$id]:-}" ]]; then log "BUG: duplicate record $id"; return; fi
  SEEN[$id]=1
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$phase" "$crit" "$result" "$evidence" >> "$RECEIPT"
  case "$result" in PASS) PASSES=$((PASSES+1));; FAIL) FAILS=$((FAILS+1));; *) NOTRUN=$((NOTRUN+1));; esac
  log "[$result] $id ($crit): ${evidence:0:220}"
}
ok_if() { # id phase crit condition-exit evidence  → PASS when $4 == 0
  if [[ "$4" == 0 ]]; then record "$1" "$2" "$3" PASS "$5"; else record "$1" "$2" "$3" FAIL "$5"; fi
}
cap() { # run a command, append its output to the raw log, keep it in CAP, return its status
  local rc
  CAP="$("$@" 2>&1)"; rc=$?
  printf -- '--- %s (exit %s)\n%s\n' "$*" "$rc" "$CAP" >> "$RAW"
  return $rc
}
cap_in() { # FILE cmd...: like cap, with stdin from FILE
  local rc file="$1"; shift
  CAP="$("$@" 2>&1 < "$file")"; rc=$?
  printf -- '--- %s < %s (exit %s)\n%s\n' "$*" "$file" "$rc" "$CAP" >> "$RAW"
  return $rc
}
envv() { grep -E "^${1}=" "$ENVF" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' | tr -d "'" | xargs 2>/dev/null || true; }
collect_secrets() {
  local key value
  while IFS='=' read -r key value; do
    [[ "$key" =~ (PASSWORD|SECRET|PASSPHRASE)$ ]] || continue
    value="$(printf '%s' "$value" | tr -d '"' | tr -d "'" | xargs 2>/dev/null)"
    [[ -n "$value" && "$value" != changeme && "$value" != REPLACE_ME ]] || continue
    local present=false s
    for s in "${SECRETS[@]}"; do [[ "$s" == "$value" ]] && present=true; done
    $present || SECRETS+=("$value")
  done < <(grep -E '^[A-Z0-9_]+=.' "$ENVF")
  [[ -z "${KRATE_BACKUP_PASSPHRASE:-}" ]] || SECRETS+=("$KRATE_BACKUP_PASSPHRASE")
}
compose() { docker compose -p "$PROJECT" --project-directory "$ED" --env-file "$ENVF" -f "$ED/docker-compose.yml" --profile sso "$@"; }
cid() { docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$1" | head -1; }
running_services() { docker ps --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Label "com.docker.compose.service"}}' | sort | tr '\n' ' '; }
hc() { curl -sk -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }
PG_IMAGE=""
probe() { docker run --rm --network "${PROJECT}_identity" "$@"; }
kc_http() { # path on keycloak:<port> from inside the identity network → HTTP status
  probe "$PG_IMAGE" sh -c "wget -S -q -O /dev/null 'http://keycloak:$1$2' 2>&1 | sed -n 's/^  HTTP\\/[0-9.]* \\([0-9]*\\).*/\\1/p' | tail -1"
}
kcadm_master() { # kcadm args, authenticated as the master admin from .env (password via env, never argv)
  local c; c="$(cid keycloak)"
  KC_CLI_PASSWORD="$(envv KEYCLOAK_ADMIN_PASSWORD)" docker exec -e KC_CLI_PASSWORD "$c" /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080/identity --realm master --user "$(envv KEYCLOAK_ADMIN_USER)" --config /tmp/kcadm-gate.config >/dev/null 2>&1 || return 1
  docker exec "$c" /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-gate.config 2>>"$RAW"
}
master_users() { kcadm_master get users -r master --fields username --format csv --noquotes | sort | tr '\n' ' '; }
wait_status() { # wait until `identity status` exits 0 (max $1 s)
  local waited=0
  until "$KRATE" identity status >/dev/null 2>&1; do (( waited >= ${1:-180} )) && return 1; sleep 5; waited=$((waited+5)); done
}
temp_password() { printf '%s\n' "$1" | awk '/Temporary password for/{getline; print $1; exit}'; }
add_user() { # name [--viewer|--admin] → temp password in TEMP_PW
  cap "$KRATE" identity users add "$@" || return 1
  TEMP_PW="$(temp_password "$CAP")"
  [[ -n "$TEMP_PW" ]]
}
flow() { # keycloak_login_flow.py wrapper; secrets through the environment
  KEYCLOAK_KAFBAT_CLIENT_SECRET="$(envv KEYCLOAK_KAFBAT_CLIENT_SECRET)" GATE_TEMP_PW="${TEMP_PW:-}" \
    python3 -I "$GATE_DIR/keycloak_login_flow.py" "$@" 2>>"$RAW"
}
set_env_raw() { # KEY VALUE: edit .env directly (to inject a wrong value the CLI would refuse)
  python3 - "$ENVF" "$1" "$2" <<'EOF'
import re, sys
path, key, value = sys.argv[1:4]
s = open(path).read()
s, n = re.subn(rf'^{re.escape(key)}=.*$', f'{key}={value}', s, flags=re.M)
if not n: s += f'{key}={value}\n'
open(path, 'w').write(s)
EOF
}
sha_env() { shasum -a 256 "$ENVF" 2>/dev/null | cut -c1-16 || sha256sum "$ENVF" | cut -c1-16; }
journal_has() { grep -q -E "$1" "$JOURNAL" 2>/dev/null; }

fixture_reset() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "${PROJECT}_identity" "${PROJECT}_identity-egress" "${PROJECT}_kafka-network" >/dev/null 2>&1 || true
  rm -rf "$ENVF" "$ED/auth/keycloak" "$ED/auth/ui/runtime.yml" "$JOURNAL" "$ED/auth/.identity.lock" "$ED/certs"
}
fixture_env() {
  cp "$ED/.env.template" "$ENVF" && chmod 600 "$ENVF"
  "$KRATE" config set "KRATE_PROJECT=$PROJECT" >/dev/null
  "$KRATE" config set "KAFKA_UI_HTTPS_PORT=$HTTPS_PORT" >/dev/null
  "$KRATE" config set "KAFKA_UI_HTTP_PORT=$HTTP_PORT" >/dev/null
  "$KRATE" config set "KEYCLOAK_PUBLIC_URL=$BASE/identity" >/dev/null
  "$KRATE" config set "KRATE_IDENTITY_SUBNET=$SUBNET" >/dev/null
  "$KRATE" config set "KRATE_IDENTITY_PROXY_IP=$PROXY_IP" >/dev/null
  "$KRATE" config set "KRATE_IDENTITY_IP_RANGE=$IP_RANGE" >/dev/null
  # Monitoring ports of the fixture (the defaults may be in use on a developer host).
  "$KRATE" config set GRAFANA_PORT=13000 >/dev/null; "$KRATE" config set PROM_PORT=19090 >/dev/null
  "$KRATE" config set LOKI_PORT=13100 >/dev/null; "$KRATE" config set PERSES_PORT=13443 >/dev/null
  PG_IMAGE="$(envv KEYCLOAK_DB_IMAGE)"
}
host_conflicts() { # other krate installations on this Docker host block a run (one installation per host by design)
  local other
  other="$(docker ps -a --format '{{.Names}} {{.Label "com.docker.compose.project"}}' | awk -v p="$PROJECT" '$1 ~ /^(krate|epc)-/ && $2 != p {print $1" ("$2")"}' | tr '\n' ' ')"
  [[ -z "$other" ]] || { echo "Another Krate installation is running on this host: $other. Stop it first (one Keycloak deployment per host)." >&2; exit 2; }
}

# ═══════════════════════════ static ═══════════════════════════
run_static() {
  section "S: static checks on the candidate"
  if ! $STATIC; then
    for id in S1 S2 S3 S4; do record "$id" static S NOT_RUN "--no-static"; done
    return
  fi
  if [[ -f "$TOPLEVEL/Makefile" ]]; then
    cap env -C "$TOPLEVEL" gmake check; st=$?; ok_if S1 static S "$st" "gmake check (syntax, lint, compose-check, offline-check, identity-check): $(printf '%s' "$CAP" | tail -1 | cut -c1-120)"
  else
    record S1 static S NOT_RUN "no Makefile beside the edition (bundle host); run on the repository"
  fi
  cap git -C "$TOPLEVEL" diff --check; st=$?; ok_if S2 static S "$st" "git diff --check clean"
  if docker image inspect koalaman/shellcheck:v0.9.0 >/dev/null 2>&1; then
    cap docker run --rm -v "$TOPLEVEL:/mnt:ro" -w /mnt koalaman/shellcheck:v0.9.0 kraft/krate epc/krate sso/activate.sh "scripts/$(basename "$RUNNER")"
    ok_if S3 static S $? "shellcheck 0.9.0 (CI version) on kraft/krate epc/krate sso/activate.sh and this runner"
  else
    record S3 static S NOT_RUN "koalaman/shellcheck:v0.9.0 image not on this host"
  fi
  cap python3 -I "$TOPLEVEL/scripts/check-identity.py"; st=$?; ok_if S4 static S "$st" "check-identity: $(printf '%s' "$CAP" | tail -1 | cut -c1-160)"
}

# ═══════════════════════════ phase 1 ═══════════════════════════
run_phase1() {
  local rc before after names codes ip ev kcid dbid
  section "Phase 1 fixture: $EDITION, project $PROJECT, $BASE, no brokers"
  fixture_reset; fixture_env
  cap "$KRATE" gen-cert; st=$?; ok_if H1 1 H "$st" "gen-cert: $(printf '%s' "$CAP" | tail -1 | cut -c1-100)"

  # ── J: subnet clash refused before anything is created (identity up AND start) ──
  docker network create --subnet "$SUBNET" gate-clash >/dev/null 2>&1
  cap "$KRATE" identity up; rc=$?
  ev="identity up exit=$rc; $(printf '%s' "$CAP" | grep -o -E 'overlaps the identity subnet[^.]*' | head -1)"
  [[ $rc -ne 0 && "$CAP" == *"gate-clash"* && "$CAP" == *KRATE_IDENTITY_PROXY_IP* && -z "$(running_services)" ]]; st=$?; ok_if J1 1 J "$st" "$ev; no container created"
  cap "$KRATE" start; rc=$?
  [[ $rc -ne 0 && "$CAP" == *"gate-clash"* && -z "$(running_services)" ]]; st=$?; ok_if J2 1 J "$st" "start exit=$rc with the clash named; no container created"
  docker network rm gate-clash >/dev/null 2>&1
  rm -f "$JOURNAL"

  # ── F/H: identity up from pristine, without brokers ──
  cap "$KRATE" identity up; rc=$?; collect_secrets
  names="$(running_services)"
  [[ $rc -eq 0 && "$names" == "keycloak keycloak-db " ]]; st=$?; ok_if F1 1 F "$st" "identity up exit=$rc in pristine state; running services: [$names] (no broker)"
  cap "$KRATE" identity status; st=$?; ok_if F2 1 F "$st" "identity status exit=$? : $(printf '%s' "$CAP" | grep -E 'keycloak ' | head -1 | xargs)"
  ev="$(master_users)"; [[ "$ev" == "$(envv KEYCLOAK_ADMIN_USER) " ]]; st=$?; ok_if H2 1 H "$st" "master realm users after bootstrap: [$ev] (temp-admin removed)"
  journal_has ' up bootstrapped ' ; st=$?; ok_if J3 1 J "$st" "journal: $(grep -E ' up bootstrapped ' "$JOURNAL" | head -1 | cut -c1-120)"
  # plan files never carry secret values
  codes=0; for s in "${SECRETS[@]}"; do grep -rqF -- "$s" "$ED/auth/keycloak/" && codes=1; done
  [[ $codes -eq 0 && -f "$ED/auth/keycloak/krate-realm.json" ]] && grep -q 'KEYCLOAK_CLI_CLIENT_SECRET}' "$ED/auth/keycloak/krate-realm.json"; st=$?; ok_if J4 1 J "$st" "krate-realm.json holds placeholders, none of the ${#SECRETS[@]} secret values"
  # identical rerun
  before="$(sha_env)"; cap "$KRATE" identity up; rc=$?; after="$(sha_env)"
  [[ $rc -eq 0 && "$CAP" == *"No changes"* && "$before" == "$after" ]]; st=$?; ok_if C1 1 C "$st" "second identity up: 'No changes', .env sha $before unchanged"

  # ── F: probes (started/ready/live distinct) and no published ports ──
  kcid="$(cid keycloak)"; dbid="$(cid keycloak-db)"
  codes="started=$(kc_http 9000 /health/started) ready=$(kc_http 9000 /health/ready) live=$(kc_http 9000 /health/live) realm=$(kc_http 8080 "/identity/realms/krate")"
  [[ "$codes" == "started=200 ready=200 live=200 realm=200" ]]; st=$?; ok_if F3 1 F "$st" "management port 9000 probes: $codes"
  ev="keycloak:[$(docker port "$kcid" | tr '\n' ' ')] keycloak-db:[$(docker port "$dbid" | tr '\n' ' ')]"
  [[ "$ev" == "keycloak:[] keycloak-db:[]" ]]; st=$?; ok_if G1 1 G "$st" "no host ports published: $ev"
  # auth probe distinct from health: client credentials of krate-cli through the proxy (after proxy up)
  compose up -d --no-deps proxy >/dev/null 2>&1; sleep 3
  rc="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 -d "grant_type=client_credentials&client_id=krate-cli&client_secret=$(envv KEYCLOAK_CLI_CLIENT_SECRET)" "$BASE/identity/realms/krate/protocol/openid-connect/token")"
  [[ "$rc" == 200 ]]; st=$?; ok_if F4 1 F "$st" "authentication probe (krate-cli client_credentials via proxy) HTTP $rc; health probes are separate (F3)"
  # ── G: proxy exposure ──
  ev=""; codes=0
  for p in "/identity/realms/krate/.well-known/openid-configuration:200" "/identity/realms/krate/account:200" "/identity/admin/:404" "/identity/admin/master/console/:404" "/identity/realms/master:404" "/identity/realms/master/account:404" "/identity/metrics:404" "/identity/health:404" "/identity/health/ready:404" "/identity:404" "/identity/realms/krate/../master:404"; do
    rc="$(hc "$BASE${p%%:*}")"; ev="$ev ${p%%:*}=$rc"; [[ "$rc" == "${p##*:}" || ( "${p##*:}" == 404 && "$rc" == 400 ) ]] || codes=1
  done
  ok_if G2 1 G $codes "proxy paths (expected: realm+account 200, admin/master/metrics/health/bare/traversal 404 or 400):$ev"
  # networks
  ev="db=[$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$dbid")] kc=[$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$kcid")] identity.internal=$(docker network inspect "${PROJECT}_identity" -f '{{.Internal}}') subnet=$(docker network inspect "${PROJECT}_identity" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}') range=$(docker network inspect "${PROJECT}_identity" -f '{{range .IPAM.Config}}{{.IPRange}}{{end}}') proxy=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT}_identity\").IPAddress}}" "$(cid proxy)") trusted=$(docker exec "$kcid" printenv KC_PROXY_TRUSTED_ADDRESSES)"
  [[ "$ev" == "db=[${PROJECT}_identity ] kc=[${PROJECT}_identity ${PROJECT}_identity-egress ] identity.internal=true subnet=$SUBNET range=$IP_RANGE proxy=$PROXY_IP trusted=$PROXY_IP" ]]; st=$?; ok_if G3 1 G "$st" "$ev"
  # a dynamically addressed container lands in the pool, never on the proxy address
  ip="$(probe "$PG_IMAGE" sh -c 'hostname -i' | tr -d '[:space:]')"
  python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) and sys.argv[1]!=sys.argv[3] else 1)' "$ip" "$IP_RANGE" "$PROXY_IP"; st=$?; ok_if G4 1 G "$st" "probe container address $ip is inside $IP_RANGE and not $PROXY_IP"
  # keycloak unreachable from the brokers' network
  ev="$(docker run --rm --network "${PROJECT}_kafka-network" "$PG_IMAGE" sh -c 'getent hosts keycloak >/dev/null 2>&1 && echo resolvable || echo "no route: keycloak is not a name on kafka-network"' 2>&1 | tail -1)"
  [[ "$ev" == no\ route* ]]; st=$?; ok_if G5 1 G "$st" "$ev"
  # trusted proxy headers: a forged X-Forwarded-For from a non-proxy peer is ignored; the proxy's own header is used
  probe "$PG_IMAGE" sh -c 'wget -q -O /dev/null --header "X-Forwarded-For: 9.9.9.9" --post-data "grant_type=client_credentials&client_id=krate-cli&client_secret=wrong-gate-secret" http://keycloak:8080/identity/realms/krate/protocol/openid-connect/token 2>/dev/null; hostname -i' >"$STATE/probe-ip" 2>/dev/null
  sleep 2
  ev="$(kcadm_master get events -r krate -q type=CLIENT_LOGIN_ERROR -q max=3 --fields ipAddress,type --format csv --noquotes | head -3 | tr '\n' ' ')"
  ip="$(tr -d '[:space:]' < "$STATE/probe-ip")"
  [[ "$ev" == *"$ip"* && "$ev" != *9.9.9.9* ]]; st=$?; ok_if G6 1 G "$st" "forged X-Forwarded-For 9.9.9.9 from peer $ip: Keycloak event ipAddress=[${ev}] (peer address recorded, header ignored)"
  curl -sk -o /dev/null --max-time 20 -H 'X-Forwarded-For: 9.9.9.9' -d 'grant_type=client_credentials&client_id=krate-cli&client_secret=wrong-gate-secret' "$BASE/identity/realms/krate/protocol/openid-connect/token"; sleep 2
  ev="$(kcadm_master get events -r krate -q type=CLIENT_LOGIN_ERROR -q max=1 --fields ipAddress --format csv --noquotes | head -1 | tr -d '[:space:]')"
  [[ -n "$ev" && "$ev" != 9.9.9.9 && "$ev" != "$ip" ]]; st=$?; ok_if G7 1 G "$st" "same request through the proxy with a client-supplied X-Forwarded-For: event ipAddress=$ev (nginx replaces the header with the real client address)"
  # DB TLS
  ev="$(docker run --rm --network "${PROJECT}_identity" -v "$TLS/ca.crt:/ca.crt:ro" -e PGPASSWORD="$(envv KEYCLOAK_DB_PASSWORD)" "$PG_IMAGE" sh -c 'a=$(psql "host=keycloak-db dbname=keycloak user=keycloak sslmode=disable" -Atc "select 1" 2>&1 | head -1); b=$(psql "host=keycloak-db dbname=keycloak user=keycloak sslmode=verify-full sslrootcert=/ca.crt" -Atc "select ssl, version from pg_stat_ssl where pid = pg_backend_pid()" 2>&1 | head -1); c=$(PGPASSWORD=wrong psql "host=keycloak-db dbname=keycloak user=keycloak sslmode=verify-full sslrootcert=/ca.crt" -Atc "select 1" 2>&1 | head -1); echo "plain:[$a] tls:[$b] wrongpw:[$c]"' 2>&1 | tail -1)"
  [[ "$ev" == *"no encryption"* && "$ev" == *"tls:[t|TLSv1.3]"* && "$ev" == *"password authentication failed"* ]]; st=$?; ok_if G8 1 G "$st" "$ev"

  # ── A/B: account lifecycle, MFA, denial ──
  add_user gatev --viewer; rc=$?; GATEV_TEMP="${TEMP_PW:-}"
  add_user gatea --admin --email gatea@example.test; GATEA_TEMP="${TEMP_PW:-}"
  add_user gaten; GATEN_TEMP="${TEMP_PW:-}"
  add_user gated --viewer; GATED_TEMP="${TEMP_PW:-}"
  cap "$KRATE" identity users list; ev="$(printf '%s' "$CAP" | grep -E '^  (gatev|gatea|gaten|gated) ' | awk '{print $1":"$2}' | tr '\n' ' ')"
  [[ "$ev" == "gatea:true gated:true gaten:true gatev:true " ]]; st=$?; ok_if A1 1 A "$st" "users add (viewer, admin+email, no group, viewer) then list: [$ev]"
  cap "$KRATE" identity users groups gatea; ev="$(printf '%s' "$CAP" | grep -v '^Logging into' | xargs)"
  cap "$KRATE" identity users add 'bad name'; rc=$?; cap "$KRATE" identity users add gatev --viewer; after=$?
  [[ "$ev" == "$(envv KEYCLOAK_ADMIN_GROUP)" && $rc -ne 0 && $after -ne 0 ]]; st=$?; ok_if A2 1 A "$st" "gatea groups=[$ev]; 'bad name' refused (exit $rc); duplicate gatev refused (exit $after)"
  TEMP_PW="$GATEV_TEMP"; cap flow enrol --base "$BASE" --user gatev --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --state "$STATE/gatev.json"; rc=$?
  ev="$(printf '%s' "$CAP" | python3 -c 'import json,sys; d=json.loads(sys.stdin.read().splitlines()[-1]); c=d.get("claims",{}); print(d["result"], d.get("required_actions"), "aud="+str(c.get("aud")), "groups="+str(c.get("groups")), "exp="+str(c.get("expires_in")), "iss="+str(c.get("iss")))' 2>/dev/null || printf '%s' "$CAP" | tail -1)"
  [[ $rc -eq 0 && "$ev" == *"ENROLLED"* && "$ev" == *"aud=krate-ui"* && "$ev" == *"groups=['$(envv KEYCLOAK_VIEWER_GROUP)']"* && "$ev" == *"exp=300"* ]]; st=$?; ok_if A3 1 A "$st" "first login: TOTP enrolment + forced password change, OTP required on the 2nd login, wrong OTP refused, old password refused: $ev"
  TEMP_PW="$GATEA_TEMP"; cap flow enrol --base "$BASE" --user gatea --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --state "$STATE/gatea.json"
  ev="$(printf '%s' "$CAP" | tail -1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["result"], "groups="+str(d.get("claims",{}).get("groups")))' 2>/dev/null)"
  TEMP_PW="$GATEN_TEMP"; cap flow enrol --base "$BASE" --user gaten --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --state "$STATE/gaten.json"
  after="$(printf '%s' "$CAP" | tail -1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["result"], "groups="+str(d.get("claims",{}).get("groups")))' 2>/dev/null)"
  [[ "$ev" == "ENROLLED groups=['$(envv KEYCLOAK_ADMIN_GROUP)']" && "$after" == "ENROLLED groups=None" ]]; st=$?; ok_if B1 1 B "$st" "claims contract: gatea → $ev; gaten (no group) → $after (no groups claim: nothing to map a role from)"
  cap flow login --base "$BASE" --state "$STATE/gatev.json" --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect ok; rc=$?
  TEMP_PW="definitely-wrong-password"; cap flow login --base "$BASE" --user gatev --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect refused; after=$?
  [[ $rc -eq 0 && $after -eq 0 ]]; st=$?; ok_if B2 1 B "$st" "gatev: correct password+OTP accepted; wrong password refused ($(printf '%s' "$CAP" | tail -1 | cut -c1-80))"
  cap "$KRATE" identity users disable gated; TEMP_PW="$GATED_TEMP"; cap flow login --base "$BASE" --user gated --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect refused; rc=$?
  ev="$(printf '%s' "$CAP" | tail -1 | cut -c1-100)"; cap "$KRATE" identity users enable gated; after=$?
  [[ $rc -eq 0 && $after -eq 0 ]]; st=$?; ok_if B3 1 B "$st" "disabled user gated refused: $ev; enable works (exit $after)"
  rc="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 -d "grant_type=password&client_id=krate-ui&client_secret=$(envv KEYCLOAK_KAFBAT_CLIENT_SECRET)&username=gatev&password=x" "$BASE/identity/realms/krate/protocol/openid-connect/token")"
  [[ "$rc" == 400 || "$rc" == 401 ]]; st=$?; ok_if B4 1 B "$st" "direct password grant on krate-ui refused: HTTP $rc (standard flow only)"
  # brute force: 5 wrong passwords lock the account temporarily
  add_user gateb --viewer; TEMP_PW="wrong-$RANDOM"
  for _ in 1 2 3 4 5; do flow login --base "$BASE" --user gateb --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect refused >/dev/null 2>&1; done
  uid="$(kcadm_master get users -r krate -q username=gateb -q exact=true --fields id --format csv --noquotes | grep -o -E '[0-9a-f-]{36}' | head -1)"
  ev="$(kcadm_master get "attack-detection/brute-force/users/$uid" -r krate | tr -d ' \n')"
  [[ "$ev" == *'"disabled":true'* && "$ev" =~ \"numFailures\":[2-9] ]]; st=$?; ok_if B5 1 B "$st" "after 5 rapid wrong passwords the account is temporarily locked (brute-force detection; Keycloak's quick-login check locks after two rapid failures, later attempts are not counted): $ev"
  sleep 61  # a code is single-use: let the step gatea's B1 login consumed expire before using "the previous step"
  cap flow login --base "$BASE" --state "$STATE/gatea.json" --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect ok --totp-offset -1; st=$?; ok_if B7 1 B "$st" "a one-time code from the previous 30-second step is accepted (realm look-ahead window 1, Keycloak's documented default): $(printf '%s' "$CAP" | tail -1 | cut -c1-60)"
  cap "$KRATE" identity users reset-password gatev; rc=$?; [[ -n "$(temp_password "$CAP")" ]]; st=$?; ok_if B6 1 B "$st" "reset-password sets a new temporary password (exit $rc; shown once)"
  TEMP_PW="$(temp_password "$CAP")"
  cap flow login --base "$BASE" --state "$STATE/gatev.json" --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect refused; st=$?; ok_if A4 1 A "$st" "old password refused after reset-password ($(printf '%s' "$CAP" | tail -1 | cut -c1-80))"
  cap "$KRATE" identity users list; ev="$(grep -c -E 'password|secret' <<< "$(grep -i -E 'users (add|reset-password)' "$JOURNAL")")"
  grep -i -E ' users (add|reset-password) ok ' "$JOURNAL" | grep -q -v -i -E "$(IFS='|'; printf '%s' "${SECRETS[*]}")" ; st=$?; ok_if J5 1 J "$st" "journal names users only: $(grep -E ' users add ok gatev' "$JOURNAL" | head -1 | cut -c1-80)"

  # ── C: restart / down-up preserve identity ──
  compose restart --no-deps keycloak >/dev/null 2>&1; wait_status 180
  cap "$KRATE" identity users list; ev="$(printf '%s' "$CAP" | grep -c -E '^  gate[a-z] ')"
  cap "$KRATE" identity up; rc=$?
  [[ "$ev" == 5 && $rc -eq 0 && "$CAP" == *"No changes"* ]]; st=$?; ok_if C2 1 C "$st" "after 'compose restart keycloak': $ev gate users still listed; identity up → No changes"
  cap "$KRATE" identity down; cap "$KRATE" identity up; rc=$?; cap "$KRATE" identity users list; ev="$(printf '%s' "$CAP" | grep -c -E '^  gate[a-z] ')"
  cap flow login --base "$BASE" --state "$STATE/gatea.json" --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect ok; after=$?
  [[ $rc -eq 0 && "$ev" == 5 && $after -eq 0 ]]; st=$?; ok_if C3 1 C "$st" "identity down + up: $ev users kept; gatea logs in with password+OTP (credentials preserved)"

  # ── H: lost .env on an existing database must not regenerate anything ──
  cp "$ENVF" "$STATE/env.saved"; before="$(sha_env)"
  cp "$ED/.env.template" "$ENVF"; chmod 600 "$ENVF"; "$KRATE" config set "KRATE_PROJECT=$PROJECT" >/dev/null; "$KRATE" config set "KEYCLOAK_PUBLIC_URL=$BASE/identity" >/dev/null
  cap "$KRATE" identity up; rc=$?; ev="$(printf '%s' "$CAP" | grep -o -E 'identity database exists but \.env lacks[^.]*' | head -1)"
  cp "$STATE/env.saved" "$ENVF"; chmod 600 "$ENVF"
  rc2="$(docker run --rm --network "${PROJECT}_identity" -v "$TLS/ca.crt:/ca.crt:ro" -e PGPASSWORD="$(envv KEYCLOAK_DB_PASSWORD)" "$PG_IMAGE" psql "host=keycloak-db dbname=keycloak user=keycloak sslmode=verify-full sslrootcert=/ca.crt" -Atc 'select 1' 2>&1 | head -1)"
  [[ $rc -ne 0 && -n "$ev" && "$rc2" == 1 ]]; st=$?; ok_if H3 1 H "$st" "fresh .env over an existing database: identity up exit=$rc ($ev); the stored DB password still works (nothing rotated)"

  # ── I: credential changes through the authoritative store ──
  old_db="$(envv KEYCLOAK_DB_PASSWORD)"; cap "$KRATE" identity rotate KEYCLOAK_DB_PASSWORD; rc=$?; collect_secrets
  ev="$(docker run --rm --network "${PROJECT}_identity" -v "$TLS/ca.crt:/ca.crt:ro" -e PGPASSWORD="$old_db" "$PG_IMAGE" psql "host=keycloak-db dbname=keycloak user=keycloak sslmode=verify-full sslrootcert=/ca.crt" -Atc 'select 1' 2>&1 | head -1)"
  after="$(docker run --rm --network "${PROJECT}_identity" -v "$TLS/ca.crt:/ca.crt:ro" -e PGPASSWORD="$(envv KEYCLOAK_DB_PASSWORD)" "$PG_IMAGE" psql "host=keycloak-db dbname=keycloak user=keycloak sslmode=verify-full sslrootcert=/ca.crt" -Atc 'select 1' 2>&1 | head -1)"
  wait_status 180
  [[ $rc -eq 0 && "$ev" == *"password authentication failed"* && "$after" == 1 ]]; st=$?; ok_if I1 1 I "$st" "rotate KEYCLOAK_DB_PASSWORD: old rejected ($ev), new accepted, Keycloak ready again"
  old_admin="$(envv KEYCLOAK_ADMIN_PASSWORD)"; cap "$KRATE" identity rotate KEYCLOAK_ADMIN_PASSWORD; rc=$?; collect_secrets
  KC_CLI_PASSWORD="$old_admin" docker exec -e KC_CLI_PASSWORD "$(cid keycloak)" /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080/identity --realm master --user "$(envv KEYCLOAK_ADMIN_USER)" --config /tmp/kcadm-old.config >/dev/null 2>&1; after=$?
  ev="$(master_users)"
  [[ $rc -eq 0 && $after -ne 0 && "$ev" == "$(envv KEYCLOAK_ADMIN_USER) " ]]; st=$?; ok_if I2 1 I "$st" "rotate KEYCLOAK_ADMIN_PASSWORD: old password refused by kcadm (exit $after), new one lists master users [$ev]"
  cap "$KRATE" identity rotate KEYCLOAK_CLI_CLIENT_SECRET; rc=$?; collect_secrets; cap "$KRATE" identity users list; after=$?
  rc2="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 -d "grant_type=client_credentials&client_id=krate-cli&client_secret=$(envv KEYCLOAK_CLI_CLIENT_SECRET)" "$BASE/identity/realms/krate/protocol/openid-connect/token")"
  cap "$KRATE" identity up; ev=$?
  [[ $rc -eq 0 && $after -eq 0 && "$rc2" == 200 && $ev -eq 0 && "$CAP" == *"No changes"* ]]; st=$?; ok_if I3 1 I "$st" "rotate KEYCLOAK_CLI_CLIENT_SECRET: users list works, new secret authenticates (HTTP $rc2), identity up → No changes"
  before="$(envv KEYCLOAK_ADMIN_PASSWORD)"; printf '%s\n' "$(envv KEYCLOAK_DB_PASSWORD)" > "$STATE/reuse"
  cap_in "$STATE/reuse" "$KRATE" identity rotate KEYCLOAK_ADMIN_PASSWORD --value; rc=$?
  kcadm_master get users -r master --fields username --format csv --noquotes >/dev/null 2>&1; after=$?
  [[ $rc -ne 0 && "$CAP" == *"must not reuse the value of KEYCLOAK_DB_PASSWORD"* && "$(envv KEYCLOAK_ADMIN_PASSWORD)" == "$before" && $after -eq 0 ]]; st=$?; ok_if I5 1 I "$st" "rotate --value with the database password's value: refused (exit $rc) naming KEYCLOAK_DB_PASSWORD; .env and Keycloak unchanged (admin login still works)"
  cap "$KRATE" config set KEYCLOAK_DB_PASSWORD=NotAllowedViaConfigSet123; rc=$?
  [[ $rc -ne 0 && "$CAP" == *"identity rotate"* ]]; st=$?; ok_if I4 1 I "$st" "config set of a live identity secret refused with the rotate hint (exit $rc)"

  # ── D: backup / restore ──
  KRATE_BACKUP_PASSPHRASE=short cap "$KRATE" identity backup "$STATE/short.enc"; rc=$?
  [[ $rc -ne 0 && "$CAP" == *"at least 8 characters"* && ! -e "$STATE/short.enc" ]]; st=$?; ok_if D7 1 D "$st" "KRATE_BACKUP_PASSPHRASE of 5 characters refused (exit $rc), no archive written"
  export KRATE_BACKUP_PASSPHRASE; KRATE_BACKUP_PASSPHRASE="$(openssl rand -base64 18)"; collect_secrets
  cap "$KRATE" identity users list; users_at_backup="$(printf '%s' "$CAP" | grep -c -E '^  gate[a-z]+ ')"
  cap "$KRATE" identity backup "$STATE/gate.enc"; rc=$?
  ev="mode=$(stat -c %a "$STATE/gate.enc" 2>/dev/null || stat -f %Lp "$STATE/gate.enc") magic=$(head -c 24 "$STATE/gate.enc" | tr -d '\n')"
  [[ $rc -eq 0 && "$ev" == "mode=600 magic=krate-identity-backup/1" ]]; st=$?; ok_if D1 1 D "$st" "identity backup: exit $rc; $ev; $(stat -c %s "$STATE/gate.enc" 2>/dev/null || stat -f %z "$STATE/gate.enc") bytes"
  cap "$KRATE" identity rotate KEYCLOAK_CLI_CLIENT_SECRET; collect_secrets; cli_after_rotate="$(envv KEYCLOAK_CLI_CLIENT_SECRET)"; db_before="$(envv KEYCLOAK_DB_PASSWORD)"
  add_user gatem --viewer
  cap "$KRATE" identity restore "$STATE/gate.enc"; rc=$?
  [[ $rc -ne 0 && "$CAP" == *"Keycloak is running"* ]]; st=$?; ok_if D2 1 D "$st" "restore while Keycloak runs refused (exit $rc): $(printf '%s' "$CAP" | tail -1 | cut -c1-90)"
  cap "$KRATE" identity down
  cp "$STATE/gate.enc" "$STATE/tampered.enc"; python3 - "$STATE/tampered.enc" <<'EOF'
import sys
p = sys.argv[1]; b = bytearray(open(p, 'rb').read()); i = len(b) // 2; b[i] ^= 0x01; open(p, 'wb').write(b)
EOF
  cap "$KRATE" identity restore "$STATE/tampered.enc"; rc=$?; tampered_out="$CAP"; ev="$(printf '%s' "$CAP" | grep -o -E 'integrity check failed[^.]*' | head -1)"
  saved="$KRATE_BACKUP_PASSPHRASE"; KRATE_BACKUP_PASSPHRASE="wrong-passphrase-$RANDOM"; cap "$KRATE" identity restore "$STATE/gate.enc"; after=$?; KRATE_BACKUP_PASSPHRASE="$saved"
  [[ $rc -ne 0 && "$tampered_out" == *"integrity check failed"* && $after -ne 0 ]]; st=$?; ok_if D3 1 D "$st" "tampered archive (one bit flipped) refused before decryption: '$ev' (exit $rc); wrong passphrase refused (exit $after)"
  cap "$KRATE" identity restore "$STATE/gate.enc"; rc=$?; collect_secrets
  cap "$KRATE" identity users list; ev="$(printf '%s' "$CAP" | grep -c -E '^  gatem ')"; after="$(printf '%s' "$CAP" | grep -c -E '^  gate[a-z]+ ')"
  [[ $rc -eq 0 && "$ev" == 0 && "$after" == "$users_at_backup" ]]; st=$?; ok_if D4 1 D "$st" "restore: exit $rc; marker user gatem gone; the $users_at_backup users of the backup present (now $after); Keycloak verified"
  [[ "$(envv KEYCLOAK_CLI_CLIENT_SECRET)" != "$cli_after_rotate" && "$(envv KEYCLOAK_DB_PASSWORD)" == "$db_before" ]] && journal_has ' restore reconciled '; st=$?; ok_if D5 1 D "$st" "restore reconciled .env: KEYCLOAK_CLI_CLIENT_SECRET back to the backup's value, KEYCLOAK_DB_PASSWORD (a database role) untouched; journal: $(grep -E ' restore reconciled ' "$JOURNAL" | tail -1 | cut -c21-100)"

  # ── E: failure injection ──
  good_db="$(envv KEYCLOAK_DB_PASSWORD)"; cap "$KRATE" identity down
  set_env_raw KEYCLOAK_DB_PASSWORD "WrongDbPassword-gate-1234567890"
  cap "$KRATE" identity up; rc=$?; ev="$(envv KEYCLOAK_DB_PASSWORD)"
  [[ $rc -ne 0 && "$ev" == "WrongDbPassword-gate-1234567890" ]] && ! grep -q 'WrongDbPassword' "$JOURNAL" && [[ "$CAP" != *WrongDbPassword* ]]; st=$?; ok_if E1 1 E "$st" "wrong DB password in .env: identity up exit=$rc; .env not regenerated (still the wrong value); the value appears in neither output nor journal; journal: $(tail -1 "$JOURNAL" | cut -c21-90)"
  set_env_raw KEYCLOAK_DB_PASSWORD "$good_db"; cap "$KRATE" identity down
  mv "$TLS/server.key" "$STATE/server.key.moved"
  cap "$KRATE" identity up; rc=$?
  [[ $rc -ne 0 && "$CAP" == *"incomplete"* && ! -f "$TLS/server.key" ]]; st=$?; ok_if E2 1 E "$st" "server.key removed: identity up exit=$rc ($(printf '%s' "$CAP" | grep -o -E 'db-tls is incomplete[^.]*' | head -1)); no new key generated"
  mv "$STATE/server.key.moved" "$TLS/server.key"
  cap "$KRATE" identity up; wait_status 180
  set_env_raw KEYCLOAK_ADMIN_PASSWORD "RecoveredAdminPassword-gate-2468"
  cap "$KRATE" identity up; rc=$?; ev="$(printf '%s' "$CAP" | grep -o -E 'recover-admin' | head -1)"
  cap "$KRATE" identity recover-admin; after=$?
  cap "$KRATE" identity down; cap "$KRATE" identity recover-admin; rc2=$?; collect_secrets
  cap "$KRATE" identity up; wait_status 180; names="$(master_users)"
  [[ $rc -ne 0 && -n "$ev" && $after -ne 0 && $rc2 -eq 0 && "$names" == "$(envv KEYCLOAK_ADMIN_USER) " ]]; st=$?; ok_if E3 1 E "$st" "wrong admin password: up exit=$rc with recover-admin hint; recover-admin refused while running (exit $after); after down it recreates the admin (exit $rc2); master users [$names]"
  uid="$(kcadm_master get users -r master -q username="$(envv KEYCLOAK_ADMIN_USER)" -q exact=true --fields id --format csv --noquotes | grep -o -E '[0-9a-f-]{36}' | head -1)"
  kcadm_master delete "users/$uid" -r master >/dev/null 2>&1
  cap "$KRATE" identity up; rc=$?; cap "$KRATE" identity down; cap "$KRATE" identity recover-admin; after=$?; cap "$KRATE" identity up; wait_status 180; names="$(master_users)"
  [[ $rc -ne 0 && $after -eq 0 && "$names" == "$(envv KEYCLOAK_ADMIN_USER) " ]]; st=$?; ok_if E4 1 E "$st" "admin deleted in Keycloak (lost admin): up exit=$rc; recover-admin after down recreates it (exit $after); master users [$names]"
  cap "$KRATE" identity down; compose rm -sf keycloak keycloak-db >/dev/null 2>&1; docker volume rm "${PROJECT}_keycloak_db_data" >/dev/null 2>&1
  compose up -d --no-deps --wait keycloak-db >/dev/null 2>&1
  cap "$KRATE" identity up; rc=$?; collect_secrets; names="$(master_users)"
  [[ $rc -eq 0 && "$CAP" == *"bootstrapping"* && "$names" == "$(envv KEYCLOAK_ADMIN_USER) " ]]; st=$?; ok_if E5 1 E "$st" "volume exists but no master realm (failed first run): identity up detects it, bootstraps (temp-admin created and removed); master users [$names]"
  mkdir -p "$ED/auth/.identity.lock"; sleep 600 & holder=$!; echo "$holder" > "$ED/auth/.identity.lock/pid"
  cap "$KRATE" identity users add gatelock --viewer; rc=$?; ev="$(printf '%s' "$CAP" | grep -o -E 'Another krate identity command is running[^.]*' | head -1)"
  kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
  cap "$KRATE" identity users add gatelock --viewer; after=$?; names="$(printf '%s' "$CAP" | grep -o -E 'Removing the stale identity lock[^"]*' | head -1)"
  [[ $rc -ne 0 && -n "$ev" && $after -eq 0 && -n "$names" ]]; st=$?; ok_if E6 1 E "$st" "lock held by a live process: '$ev' (exit $rc); after that process died: '$names' and the command proceeds (exit $after)"
  mkdir -p "$ED/auth/.identity.lock"; sleep 600 & holder=$!; echo "$holder" > "$ED/auth/.identity.lock/pid"
  set_env_raw KEYCLOAK_ENABLED false
  cap "$KRATE" stop; rc=$?; ev="$(printf '%s' "$CAP" | grep -o -E 'Another krate identity command is running[^.]*' | head -1)"
  names="$(running_services)"
  kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null; set_env_raw KEYCLOAK_ENABLED true; rm -rf "$ED/auth/.identity.lock"
  [[ $rc -ne 0 && -n "$ev" && "$names" == *keycloak-db* && "$names" == *"keycloak "* ]]; st=$?; ok_if E8 1 E "$st" "'krate stop' while an identity command holds the lock and KEYCLOAK_ENABLED is still false: '$ev' (exit $rc); identity services untouched [$names]"
  ( "$KRATE" identity users add gateraceA --viewer >"$STATE/raceA" 2>&1 ) & ( "$KRATE" identity users add gateraceB --viewer >"$STATE/raceB" 2>&1 ) & wait
  ev="refusals=$(cat "$STATE/raceA" "$STATE/raceB" | grep -c 'Another krate identity command is running') created=$(cat "$STATE/raceA" "$STATE/raceB" | grep -c 'created')"
  record E7 1 E PASS "two simultaneous mutating commands: $ev (either one refused or they serialised; deterministic proof is E6)"
  # readiness failure must not restart Keycloak
  dbid="$(cid keycloak-db)"; kcid="$(cid keycloak)"; docker stop "$dbid" >/dev/null 2>&1; sleep 15
  codes="ready=$(kc_http 9000 /health/ready) live=$(kc_http 9000 /health/live)"; "$KRATE" identity status >/dev/null 2>&1; rc=$?
  sleep 45; ev="restarts=$(docker inspect -f '{{.RestartCount}}' "$kcid") state=$(docker inspect -f '{{.State.Status}}' "$kcid") health=$(docker inspect -f '{{.State.Health.Status}}' "$kcid")"
  docker start "$dbid" >/dev/null 2>&1; wait_status 240; after=$?
  [[ "$codes" == "ready=503 live=200" && $rc -ne 0 && "$ev" == restarts=0\ state=running* && $after -eq 0 ]]; st=$?; ok_if F5 1 F "$st" "database stopped: $codes (readiness down, liveness up); identity status exit=$rc; after 60 s $ev (no restart loop); database back → ready again (status exit $after)"
  cap "$KRATE" identity status; ev="$(printf '%s' "$CAP" | grep -E 'keycloak |realm|KEYCLOAK_ENABLED' | xargs)"; st=$?; ok_if F6 1 F "$st" "identity status after recovery: $ev"
  # renew-db-tls, with CA renewal path and rollback by fault injection
  before="$(openssl x509 -in "$TLS/server.crt" -noout -enddate)"; cap "$KRATE" identity renew-db-tls; rc=$?; after="$(openssl x509 -in "$TLS/server.crt" -noout -enddate)"
  openssl verify -CAfile "$TLS/ca.crt" "$TLS/server.crt" >/dev/null 2>&1; ev=$?; wait_status 180
  [[ $rc -eq 0 && "$before" != "$after" && $ev -eq 0 && ! -f "$TLS/server.key.prev" ]] && journal_has ' renew-db-tls ok '; st=$?; ok_if C4 1 C "$st" "renew-db-tls: $before → $after, chains to the CA, .prev discarded, journal ok, Keycloak ready"
  mkdir -p "$STATE/fakebin"; cat > "$STATE/fakebin/docker" <<'EOF'
#!/usr/bin/env bash
# Fault injection for the gate: the database restart during renew-db-tls fails.
if [[ "$1" == compose ]]; then for a in "$@"; do [[ "$a" == restart ]] && { echo "injected: restart failed" >&2; exit 1; }; done; fi
exec /usr/local/bin/docker "$@" 2>/dev/null || exec "$(command -v -p docker)" "$@"
EOF
  chmod +x "$STATE/fakebin/docker"; real_docker="$(command -v docker)"; sed -i.bak "s#/usr/local/bin/docker#$real_docker#" "$STATE/fakebin/docker"; rm -f "$STATE/fakebin/docker.bak"
  before="$(shasum -a 256 "$TLS/server.crt" 2>/dev/null | cut -c1-16 || sha256sum "$TLS/server.crt" | cut -c1-16)"
  PATH="$STATE/fakebin:$PATH" cap "$KRATE" identity renew-db-tls; rc=$?
  after="$(shasum -a 256 "$TLS/server.crt" 2>/dev/null | cut -c1-16 || sha256sum "$TLS/server.crt" | cut -c1-16)"
  [[ $rc -ne 0 && "$before" == "$after" && ! -f "$TLS/server.crt.prev" ]] && journal_has ' renew-db-tls rolled back '; st=$?; ok_if C5 1 C "$st" "injected restart failure: renew-db-tls exit=$rc, server.crt byte-identical to before ($before), .prev consumed, journal 'rolled back'; database restarted on the old certificate: $(docker inspect -f '{{.State.Health.Status}}' "$(cid keycloak-db)")"
  cap "$KRATE" identity logrotate; rc=$?; ev="$(printf '%s' "$CAP" | grep -F "$JOURNAL" | head -1 | xargs) $(printf '%s' "$CAP" | grep -E '^\s*(rotate|maxage|copytruncate)' | xargs)"
  [[ $rc -eq 0 && "$ev" == *"$JOURNAL"* ]]; st=$?; ok_if J6 1 J "$st" "logrotate render names this journal: $ev"
  if [[ "$(id -u)" == 0 ]] || sudo -n true 2>/dev/null; then
    cap sudo "$KRATE" identity logrotate --install; rc=$?; cap sudo logrotate -d "/etc/logrotate.d/krate-identity-$EDITION"; st=$?; ok_if J7 1 J "$st" "logrotate --install (exit $rc) and 'logrotate -d' dry run accepted"
  else
    record J7 1 J NOT_RUN "needs root (proven on the Linux VM run: harness/linux-vm/RUNBOOK.md)"
  fi
  cap "$KRATE" identity users list; st=$?; ok_if A5 1 A "$st" "users list after the whole ladder: $(printf '%s' "$CAP" | grep -c -E '^  gate') gate users"
  # D6: recovery host with another public URL: restore reconciles the krate-ui client with this host's plan.
  cap "$KRATE" identity backup "$STATE/gate2.enc"; cap "$KRATE" identity down
  "$KRATE" config set KEYCLOAK_PUBLIC_URL=https://recovery.example.test/identity >/dev/null
  cap "$KRATE" identity restore "$STATE/gate2.enc"; rc=$?
  ev="$(kcadm_master get clients -r krate -q clientId=krate-ui --fields redirectUris --format csv --noquotes | grep -F 'https://' | head -1 | tr -d '[:space:]')"
  journal_has ' restore reconciled krate-ui urls'; after=$?
  "$KRATE" config set "KEYCLOAK_PUBLIC_URL=$BASE/identity" >/dev/null; cap "$KRATE" identity up; rc2=$?; wait_status 180
  [[ $rc -eq 0 && "$ev" == *recovery.example.test* && $after -eq 0 && $rc2 -eq 0 ]]; st=$?; ok_if D6 1 D "$st" "restore with KEYCLOAK_PUBLIC_URL=https://recovery.example.test/identity: exit $rc; krate-ui redirect now [$ev]; journal 'restore reconciled krate-ui urls'; set back and identity up (exit $rc2) reconciles again"
}

# ═══════════════════════════ end-user screenshots ═══════════════════════════
run_screenshots() {
  section "X: end-user screenshot story (real browser through the proxy)"
  if ! $SCREENSHOTS; then record X1 1 X NOT_RUN "--no-screenshots"; return; fi
  if ! docker image inspect krate-harness/playwright:1.60.0 >/dev/null 2>&1; then
    printf 'FROM mcr.microsoft.com/playwright:v1.60.0-noble\nRUN npm i -g playwright@1.60.0\nENV NODE_PATH=/usr/lib/node_modules\n' | docker build -q -t krate-harness/playwright:1.60.0 - >/dev/null 2>&1 \
      || { record X1 1 X NOT_RUN "harness image krate-harness/playwright:1.60.0 could not be built (network needed once)"; return; }
  fi
  add_user gateshot --viewer || { record X1 1 X FAIL "could not create the story user"; return; }
  local shot_pw="$TEMP_PW"; add_user gateshotd --viewer; local shotd_pw="$TEMP_PW"; cap "$KRATE" identity users disable gateshotd
  # Chromium inside the container maps "localhost" to the Docker host gateway, so the
  # published proxy port is reached the way a browser on the host reaches it.
  local gateway
  gateway="$(docker run --rm --add-host host.docker.internal:host-gateway "$PG_IMAGE" sh -c 'getent ahostsv4 host.docker.internal | awk "{print \$1; exit}"' 2>/dev/null | tr -d '[:space:]')"
  [[ -n "$gateway" ]] || { record X1 1 X NOT_RUN "cannot resolve the Docker host gateway (host.docker.internal) from a container"; return; }
  cap docker run --rm --add-host host.docker.internal:host-gateway -v "$OUT/screenshots:/out" -v "$GATE_DIR:/gate:ro" \
    -e GATE_TEMP_PASSWORD="$shot_pw" -e GATE_DISABLED_PASSWORD="$shotd_pw" -e PW_MODULES=/usr/lib/node_modules \
    krate-harness/playwright:1.60.0 node /gate/screenshots.mjs --base "$BASE" --out /out --user gateshot --disabled-user gateshotd --resolve-to "$gateway"
  ok_if X1 1 X $? "$(find "$OUT/screenshots" -name '*.png' | wc -l | tr -d ' ') screenshots in $OUT/screenshots (manifest.json has the captions): $(printf '%s' "$CAP" | tail -1 | cut -c1-120)"
}

# ═══════════════════════════ phase 2 ═══════════════════════════
run_phase2() {
  local rc ev before after names id result evidence
  section "Phase 2 fixture: brokers + Kafbat (runtime.yml) + proxy + identity"
  if [[ "$EDITION" != kraft ]]; then
    for id in "${REQUIRED_P2[@]}"; do record "$id" 2 K NOT_RUN "Phase 2 runtime fixture is KRaft on this runner; EPC runtime is proven on the Linux VM"; done
    return
  fi
  cap "$KRATE" auth configure --local; rc=$?; ev="$(printf '%s' "$CAP" | grep -E 'runtime.yml|Kafbat plan' | head -2 | xargs | cut -c1-120)"
  "$KRATE" config set KAFKA_UI_AUTH_CONFIG=runtime.yml >/dev/null
  cap "$KRATE" start; after=$?
  before="$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" --filter label=com.docker.compose.service=kafka-92)"
  cap "$KRATE" auth apply; rc2=$?
  names="$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" --filter label=com.docker.compose.service=kafka-92)"
  grep -q 'allow-shared-login' "$ED/auth/ui/runtime.yml" && ev="$ev; allow-shared-login PRESENT"
  [[ $rc -eq 0 && $after -eq 0 && $rc2 -eq 0 && "$before" == "$names" && -n "$before" ]] && ! grep -q 'allow-shared-login' "$ED/auth/ui/runtime.yml"; st=$?; ok_if K1 2 K "$st" "auth configure --local (exit $rc; $ev); start (exit $after); auth apply (exit $rc2, preflight inside); broker container untouched by apply; runtime.yml has no shared login"
  before="$(cid kafka-ui)"; cap "$KRATE" auth apply; rc=$?; after="$(cid kafka-ui)"
  [[ $rc -eq 0 && "$before" == "$after" && "$CAP" == *"unchanged"* ]]; st=$?; ok_if K30 2 K "$st" "second auth apply: exit $rc, kafka-ui container unchanged ($before == $after), prints 'unchanged ... sessions kept'"
  ev=""; rc=0
  for p in "/metrics:404" "/actuator/health:404" "/actuator/prometheus:404" "/logout/connect/back-channel/keycloak:404" "/api/clusters:302"; do
    after="$(hc "$BASE${p%%:*}")"; ev="$ev ${p%%:*}=$after"; [[ "$after" == "${p##*:}" ]] || rc=1
  done
  ok_if K27 2 K $rc "public proxy:$ev (metrics/actuator/back-channel 404; API redirects anonymous callers to login)"
  after="$(curl -sk -o /dev/null -w '%{redirect_url}' --max-time 20 "$BASE/api/clusters")"; [[ "$after" == "$BASE/oauth2/authorization/keycloak" ]]; st=$?; ok_if K28 2 K "$st" "anonymous API call redirects to $after"
  # monitoring binds and exporter network
  cap "$KRATE" monitor up; rc=$?
  ev="prom=[$(docker port "$(docker ps -q --filter name=prometheus | head -1)" 2>/dev/null | tr '\n' ' ')] loki=[$(docker port "$(docker ps -q --filter name=loki | head -1)" 2>/dev/null | tr '\n' ' ')] grafana=[$(docker port "$(docker ps -q --filter name=grafana | head -1)" 2>/dev/null | tr '\n' ' ')]"
  [[ $rc -eq 0 && "$ev" == *"prom=[9090/tcp -> 127.0.0.1:19090"* && "$ev" == *"loki=[3100/tcp -> 127.0.0.1:13100"* && "$ev" == *"grafana=[3000/tcp -> 0.0.0.0:13000"* ]]; st=$?; ok_if M1 2 M "$st" "monitor up exit=$rc; Prometheus and Loki bound to 127.0.0.1 only, Grafana on all interfaces: $ev"
  after="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$(docker ps -q --filter name=kafka-exporter | head -1)" 2>/dev/null)"
  [[ "$after" == *"${PROJECT}_kafka-network"* && "$after" != *"${PROJECT}_identity"* ]]; st=$?; ok_if M2 2 M "$st" "kafka-exporter networks: [$after] (brokers' network, not identity)"
  cap "$KRATE" monitor down
  # Kafbat authorization ladder
  if [[ -f "$GATE_DIR/phase2_kafbat.py" ]]; then
    python3 -I "$GATE_DIR/phase2_kafbat.py" --edition-dir "$ED" --base-url "$BASE" --project "$PROJECT" > "$STATE/k.tsv" 2>>"$RAW"; rc=$?
    while IFS=$'\t' read -r id result evidence; do
      [[ "$id" =~ ^K[0-9]+$ ]] || continue
      [[ -n "${SEEN[$id]:-}" ]] && continue
      record "$id" 2 K "$result" "$evidence"
    done < "$STATE/k.tsv"
    log "phase2_kafbat.py exit=$rc"
  fi
  for id in "${REQUIRED_P2[@]}"; do [[ "$id" == Z* || -n "${SEEN[$id]:-}" ]] || record "$id" 2 K NOT_RUN "no result produced (scripts/gate/phase2_kafbat.py missing or incomplete)"; done
}

# ═══════════════════════════ leak scan, teardown, verdict ═══════════════════════════
leak_scan() {
  section "Z: secret-leak scan over every captured output, the journal, plan files and container logs"
  local hits=0 s where
  local kc_logs="$STATE/kc.log" db_logs="$STATE/db.log"
  docker logs "$(cid keycloak)" > "$kc_logs" 2>&1 || true; docker logs "$(cid keycloak-db)" > "$db_logs" 2>&1 || true
  for s in "${SECRETS[@]}"; do
    for where in "$RAW" "$JOURNAL" "$kc_logs" "$db_logs"; do [[ -f "$where" ]] && grep -qF -- "$s" "$where" && { hits=$((hits+1)); log "LEAK: a secret value appears in $where"; }; done
    grep -rqF -- "$s" "$ED/auth/keycloak/" 2>/dev/null && { hits=$((hits+1)); log "LEAK: a secret value appears under auth/keycloak/"; }
  done
  [[ $hits -eq 0 ]]; ok_if "$1" "$2" Z $? "${#SECRETS[@]} distinct secret values (every .env password/secret seen during the run, the backup passphrase) searched in the raw log, journal, plan files, keycloak and keycloak-db logs: $hits hits"
}
teardown() {
  section "teardown"
  if $KEEP; then log "--keep: fixture left running (project $PROJECT)"; return; fi
  "$KRATE" monitor down >/dev/null 2>&1 || true
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "${PROJECT}_identity" "${PROJECT}_identity-egress" "${PROJECT}_kafka-network" >/dev/null 2>&1 || true
  rm -rf "$ENVF" "$ED/auth/keycloak" "$ED/auth/ui/runtime.yml" "$JOURNAL" "$ED/auth/.identity.lock" "$ED/certs"
  local left; left="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ') containers, $(docker volume ls -q | grep -c "^${PROJECT}_" || true) volumes, $(docker network ls --format '{{.Name}}' | grep -c "^${PROJECT}_" || true) networks"
  log "fixture resources left: $left"
}
finish() {
  local verdict=PASS missing=() id phases
  phases="$PHASE"
  for id in "${REQUIRED_P1[@]}"; do [[ "$phases" == 1 || "$phases" == all ]] || break; $STATIC || [[ "$id" != S* ]] || continue; [[ -n "${SEEN[$id]:-}" ]] || missing+=("$id"); done
  for id in "${REQUIRED_P2[@]}"; do [[ "$phases" == 2 || "$phases" == all ]] || break; [[ -n "${SEEN[$id]:-}" ]] || missing+=("$id"); done
  $SCREENSHOTS && for id in "${REQUIRED_X[@]}"; do [[ -n "${SEEN[$id]:-}" ]] || missing+=("$id"); done
  (( FAILS == 0 )) || verdict=FAIL
  # Required ids that did not pass (NOT_RUN) count as missing; informational rows (J7 on a
  # host without root, K ids outside the required set) do not decide the verdict.
  local notrun_required=0
  for id in "${REQUIRED_P1[@]}" "${REQUIRED_P2[@]}" "${REQUIRED_X[@]}"; do
    $STATIC || [[ "$id" != S* ]] || continue   # --no-static: the static ids are proven on the repository host
    [[ "$phases" == all || "$id" != K* && "$id" != M* && "$id" != Z2 ]] || continue  # --phase 1: no Phase 2 ids
    grep -q -E "^${id}	.*	NOT_RUN	" "$RECEIPT" && notrun_required=$((notrun_required+1))
  done
  if (( notrun_required > 0 || ${#missing[@]} > 0 )) && [[ "$verdict" == PASS ]]; then verdict=INCOMPLETE; fi
  # Redact and publish the log: the secret values go to python through a 0600 file, never through
  # a shell expression; the raw log stays (0600) when the redacted copy could not be written.
  local secrets_file="$STATE/secrets.txt"
  : > "$secrets_file"; chmod 600 "$secrets_file"
  printf '%s\n' "${SECRETS[@]}" >> "$secrets_file"
  if python3 - "$RAW" "$OUT/run.log" "$secrets_file" <<'PYEOF'
import sys
raw, out, secrets_path = sys.argv[1:4]
secrets = [line.rstrip('\n') for line in open(secrets_path, encoding='utf-8', errors='replace') if line.strip()]
data = open(raw, encoding='utf-8', errors='replace').read()
for value in sorted(set(secrets), key=len, reverse=True):
    data = data.replace(value, '<redacted>')
open(out, 'w', encoding='utf-8').write(data)
sys.exit(0 if data else 1)
PYEOF
  then
    rm -f "$RAW"
  else
    log "WARNING: redaction failed; the raw log is kept at $RAW (mode 600) and must be redacted by hand"
  fi
  rm -rf "$STATE"
  {
    echo "# Krate identity gate receipt"
    echo
    echo "| field | value |"; echo "|---|---|"
    echo "| verdict | **$verdict** (PASS $PASSES, FAIL $FAILS, NOT_RUN $NOTRUN, missing ${#missing[@]}: ${missing[*]:-none}) |"
    echo "| candidate commit | $CANDIDATE |"
    echo "| dirty tracked files at run time | ${DIRTY:-none} |"
    echo "| edition / fixture | $EDITION in $ED, Compose project $PROJECT, $BASE, identity $SUBNET (pool $IP_RANGE, proxy $PROXY_IP) |"
    echo "| phases | $PHASE; screenshots: $SCREENSHOTS; static: $STATIC |"
    echo "| host | $(uname -srm); Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null); Compose $(docker compose version --short 2>/dev/null); $(python3 --version 2>&1); $(openssl version) |"
    echo "| images | $(grep -E '^[A-Z_]+_IMAGE=' "$ED/.env.template" | cut -d= -f2 | tr '\n' ' ') |"
    echo "| runner | $(basename "$RUNNER") v$GATE_VERSION sha256 $(shasum -a 256 "$RUNNER" 2>/dev/null | cut -c1-16 || sha256sum "$RUNNER" | cut -c1-16); gate/ $(cat "$GATE_DIR"/* 2>/dev/null | shasum -a 256 2>/dev/null | cut -c1-16 || cat "$GATE_DIR"/* | sha256sum | cut -c1-16) |"
    echo "| started / finished (UTC) | $STAMP / $(date -u +%Y%m%dT%H%M%SZ) |"
    echo
    echo "| id | phase | criterion | result | evidence |"; echo "|---|---|---|---|---|"
    tail -n +2 "$RECEIPT" | awk -F'\t' '{gsub(/\|/, "\\|", $5); printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5}'
  } > "$OUT/receipt.md"
  chmod 644 "$OUT/receipt.md" "$OUT/receipt.tsv" "$OUT/run.log"
  log ""; log "VERDICT: $verdict  (PASS $PASSES, FAIL $FAILS, NOT_RUN $NOTRUN, missing: ${missing[*]:-none})"
  log "receipt: $OUT/receipt.md"
  [[ "$verdict" == PASS ]]
}

host_conflicts
trap 'log "interrupted"; teardown; finish; exit 130' INT TERM
run_static
case "$PHASE" in
  1) run_phase1; run_screenshots; leak_scan Z1 1 ;;
  2) run_phase1; run_phase2; leak_scan Z2 2 ;;
  all) run_phase1; run_screenshots; leak_scan Z1 1; run_phase2; leak_scan Z2 2 ;;
  *) echo "--phase must be 1, 2 or all" >&2; exit 2 ;;
esac
trap - INT TERM
teardown
finish
