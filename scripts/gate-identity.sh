#!/usr/bin/env bash
# Krate identity acceptance gate: Phase 1 (identity foundation) and Phase 2 (Kafbat
# authorization) against a disposable fixture. Each acceptance criterion of the
# owner's handover has numbered tests; every test ends PASS, FAIL or NOT_RUN with
# evidence, and the receipt binds the results to the candidate (commit or file
# digests), the dirty files, the tool versions and this runner's own digest. The
# verdict is PASS only when every required test passed and the candidate is bound.
# See sso/guides/identity-gate.md.
#
#   scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe [--phase 1|2|all]
#   scripts/gate-identity.sh --edition-dir /opt/krate/epc --wipe --no-static --no-screenshots --candidate <sha>
#
# The fixture directory is a disposable checkout or a fixture installation whose
# .env, auth/keycloak, certs, journal and monitoring state the run creates and
# destroys. The runner refuses an existing .env unless --wipe is given. Secret
# values never appear on a command line: they travel through the environment or
# through 0600 files, and every captured output is redacted before it is published.
# shellcheck disable=SC2319  # `[[ ... ]]; st=$?` reads the condition's status on the very next statement
set -uo pipefail
umask 077
(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )) || { echo "bash 4.4 or newer is required (this is $BASH_VERSION)" >&2; exit 2; }

GATE_VERSION=5
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
CANDIDATE_ARG=""
REPO_ARG=""

usage() {
  cat <<EOF
Usage: $0 [--edition-dir DIR] [--project NAME] [--https-port N] [--http-port N]
          [--subnet CIDR --proxy-ip IP --ip-range CIDR] [--phase 1|2|all] [--out DIR]
          [--candidate SHA] [--wipe] [--keep] [--no-screenshots] [--no-static]
  --edition-dir    kraft or epc checkout or fixture installation (default: $REPO/kraft)
  --candidate SHA  the commit the edition files come from, when the directory has no git (a bundle install);
                   the receipt also records the sha256 of the edition files and is INCOMPLETE without a binding
  --repo DIR       a checkout of the candidate for the static block (S1-S4) when the edition directory is a bundle
                   install without Makefile or git; its HEAD must be the --candidate commit
  --wipe           remove an existing .env/auth/certs in that directory first (required when present)
  --keep           leave the fixture running at the end (no teardown)
  --no-screenshots skip the end-user screenshot story (X1 leaves the required inventory)
  --no-static      skip gmake check / git diff --check (S1-S4 leave the required inventory)
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
    --candidate) CANDIDATE_ARG="$2"; shift 2 ;;
    --repo) REPO_ARG="$(cd "$2" && pwd)"; shift 2 ;;
    --wipe) WIPE=true; shift ;;
    --keep) KEEP=true; shift ;;
    --no-screenshots) SCREENSHOTS=false; shift ;;
    --no-static) STATIC=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$PHASE" == 1 || "$PHASE" == 2 || "$PHASE" == all ]] || { echo "--phase must be 1, 2 or all" >&2; exit 2; }

ED="$EDITION_DIR"
EDITION="$(basename "$ED")"
KRATE="$ED/krate"
ENVF="$ED/.env"
JOURNAL="$ED/auth/identity-journal.log"
TLS="$ED/auth/keycloak/db-tls"
MON_PROJECT="krate-${EDITION}-monitoring"
CLASH_NET="${PROJECT}-gate-clash"
[[ "$HTTPS_PORT" == 443 ]] && BASE="https://localhost" || BASE="https://localhost:$HTTPS_PORT"
[[ -x "$KRATE" && -f "$ED/.env.template" ]] || { echo "not an edition directory: $ED" >&2; exit 2; }
if [[ -d "$ED/sso" ]]; then SSO="$ED/sso"; elif [[ -d "$ED/../sso" ]]; then SSO="$(cd "$ED/../sso" && pwd)"; else echo "no sso/ beside $ED" >&2; exit 2; fi
if [[ -e "$ENVF" ]] && ! $WIPE; then
  echo "$ENVF exists; this runner destroys the fixture it is pointed at. Pass --wipe for a disposable checkout." >&2
  exit 2
fi

# ── candidate binding: a commit (git or --candidate) plus the digests of the files under test ──
sha256file() { { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"; } | cut -c1-16; }
BOUND=true
if git -C "$ED" rev-parse HEAD >/dev/null 2>&1; then
  CANDIDATE="$(git -C "$ED" rev-parse HEAD)"
  TOPLEVEL="$(git -C "$ED" rev-parse --show-toplevel)"
  DIRTY="$(git -C "$TOPLEVEL" status --porcelain --untracked-files=no 2>/dev/null | tr '\n' ';')"
  [[ -z "$CANDIDATE_ARG" || "$CANDIDATE" == "$CANDIDATE_ARG"* ]] || { echo "--candidate $CANDIDATE_ARG differs from the checkout's HEAD $CANDIDATE" >&2; exit 2; }
elif [[ -n "$CANDIDATE_ARG" ]]; then
  CANDIDATE="$CANDIDATE_ARG (stated; no git here, bound by the edition file digests)"
  TOPLEVEL="$(cd "$ED/.." && pwd)"
  DIRTY="unknown (no git); the file digests bind the candidate"
else
  CANDIDATE="unbound (no git and no --candidate)"
  TOPLEVEL="$(cd "$ED/.." && pwd)"
  DIRTY="unknown (no git)"
  BOUND=false
fi
EDITION_DIGESTS=""
for f in "$ED/krate" "$ED/docker-compose.yml" "$ED/.env.template" "$ED/nginx.conf" "$SSO/identity.py" "$SSO/preflight.py" "$SSO/activate.sh"; do
  [[ -f "$f" ]] && EDITION_DIGESTS="$EDITION_DIGESTS ${f#"$TOPLEVEL"/}=$(sha256file "$f")"
done
if [[ -n "$REPO_ARG" ]]; then
  [[ -f "$REPO_ARG/Makefile" ]] || { echo "--repo $REPO_ARG has no Makefile" >&2; exit 2; }
  repo_head="$(git -C "$REPO_ARG" rev-parse HEAD 2>/dev/null)" || { echo "--repo $REPO_ARG is not a git checkout" >&2; exit 2; }
  [[ -n "$CANDIDATE_ARG" && "$repo_head" == "$CANDIDATE_ARG"* ]] || [[ "$repo_head" == "${CANDIDATE%% *}"* ]] \
    || { echo "--repo HEAD $repo_head is not the candidate (${CANDIDATE_ARG:-$CANDIDATE})" >&2; exit 2; }
  TOPLEVEL="$REPO_ARG"
  CANDIDATE="${CANDIDATE%% *} (stated; edition files bound by digest; static block on --repo at $repo_head)"
  DIRTY="edition: unknown (no git); --repo: $(git -C "$REPO_ARG" status --porcelain --untracked-files=no 2>/dev/null | tr '\n' ';')"
fi
RUNNER_COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo 'no git')"
RUNNER_DIRTY="$(git -C "$REPO" status --porcelain --untracked-files=no -- scripts/gate-identity.sh scripts/gate 2>/dev/null | tr '\n' ';')"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[[ -n "$OUT" ]] || OUT="$REPO/harness/gate-receipts/${EDITION}-${CANDIDATE:0:7}-${STAMP}"
RAW="$OUT/.raw.log"; RECEIPT="$OUT/receipt.tsv"; STATE="$OUT/.state"; SECRETS_FILE="$STATE/secrets.txt"
open_receipt() { # the receipt folder exists only once the host accepted the run (a refused run leaves nothing behind)
  if ! { mkdir -p "$OUT" "$OUT/screenshots" && chmod 700 "$OUT"; }; then echo "cannot create $OUT" >&2; exit 2; fi
  : > "$RAW"; chmod 600 "$RAW" || exit 2
  printf 'id\tphase\tcriterion\tresult\tevidence\n' > "$RECEIPT"
  mkdir -p "$STATE" && chmod 700 "$STATE" || exit 2
  : > "$SECRETS_FILE"; chmod 600 "$SECRETS_FILE"
}
declare -a SECRETS=()
declare -a TEMP_SECRETS=()
declare -a HOLDERS=()
declare -A SEEN=()
PASSES=0; FAILS=0; NOTRUN=0
CHILD=""
FIXTURE_OWNED=false  # set by fixture_env: only then may teardown touch Compose projects, volumes and networks
J7_REQUIRED=false

# ── required inventory (declared before anything runs; a missing row fails the gate) ──
REQUIRED_P1=(S1 S2 S3 S4 H1 H2 H3 F1 F2 F3 F4 F5 F6 G1 G2 G3 G4 G5 G6 G7 G8 A1 A2 A3 A4 A5 B1 B2 B3 B4 B5 B6 B7 C1 C2 C3 C4 C5 C6 I1 I2 I3 I4 I5 D1 D2 D3 D4 D5 D6 D7 E1 E2 E3 E4 E5 E6 E7 E8 J1 J2 J3 J4 J5 J6 J7 Z1)
as_root() { if [[ "$(id -u)" == 0 ]]; then "$@"; else sudo "$@"; fi; }
if { [[ "$(id -u)" == 0 ]] || sudo -n true 2>/dev/null; } && command -v logrotate >/dev/null 2>&1; then J7_REQUIRED=true; fi
REQUIRED_P2=(K1 K2 K3 K4 K5 K6 K7 K8 K9 K10 K11 K12 K13 K14 K15 K16 K18 K19 K20 K21 K22 K23 K24 K25 K26 K27 K28 K30 K31 K32 K33 K34 M1 M2 Z2)
REQUIRED_X=(X1)
required_ids() { # the inventory that decides the verdict, given the flags
  local id
  for id in "${REQUIRED_P1[@]}"; do
    if ! $STATIC && [[ "$id" == S* ]]; then continue; fi
    if [[ "$id" == J7 ]] && ! $J7_REQUIRED; then continue; fi
    echo "$id"
  done
  if [[ "$PHASE" != 1 ]]; then for id in "${REQUIRED_P2[@]}"; do echo "$id"; done; fi
  if $SCREENSHOTS; then for id in "${REQUIRED_X[@]}"; do echo "$id"; done; fi
}

log() { if [[ -n "${RAW_CLOSED:-}" ]]; then printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; else printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RAW" >&2; fi; }
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
trim() { local v="$1"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"; printf '%s' "$v"; }
envv() { # value of KEY in the fixture .env (no subprocess sees the value)
  local line value=""
  line="$(grep -E "^${1}=" "$ENVF" 2>/dev/null | tail -1)" || true
  value="${line#*=}"; value="${value//\"/}"; value="${value//\'/}"
  trim "$value"
}
add_secret() { # VALUE [temp]: a value redacted from every published file and searched for by the leak scan
  local s
  [[ -n "$1" && "$1" != changeme && "$1" != REPLACE_ME ]] || return 0
  for s in "${SECRETS[@]}"; do [[ "$s" == "$1" ]] && return 0; done
  SECRETS+=("$1"); printf '%s\n' "$1" >> "$SECRETS_FILE"
  [[ "${2:-}" != temp ]] || TEMP_SECRETS+=("$1")
}
collect_secrets() { # every password/secret/key of the fixture .env files
  local file key value
  for file in "$ENVF" "$ED/monitoring/.env"; do
    [[ -f "$file" ]] || continue
    while IFS='=' read -r key value; do
      [[ "$key" =~ (PASSWORD|SECRET|PASSPHRASE|_KEY)$ ]] || continue
      value="${value//\"/}"; value="${value//\'/}"; add_secret "$(trim "$value")"
    done < <(grep -E '^[A-Z0-9_]+=.' "$file")
  done
  [[ -z "${KRATE_BACKUP_PASSPHRASE:-}" ]] || add_secret "$KRATE_BACKUP_PASSPHRASE"
}
add_flow_state_secrets() { # the password and TOTP seed an enrolment wrote to its state file
  [[ -f "$1" ]] || return 0
  local v
  while IFS= read -r v; do add_secret "$v" temp; done < <(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["password"]); print(d["totp"])' "$1" 2>/dev/null)
}
compose() { docker compose -p "$PROJECT" --project-directory "$ED" --env-file "$ENVF" -f "$ED/docker-compose.yml" --profile sso "$@"; }
cid() { docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$1" | head -1; }
mon_cid() { docker ps -aq --filter "label=com.docker.compose.project=$MON_PROJECT" --filter "label=com.docker.compose.service=$1" | head -1; }
running_services() { docker ps --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Label "com.docker.compose.service"}}' | sort | tr '\n' ' '; }
hc() { curl -sk --path-as-is -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }  # as-is: dot segments and ; reach the proxy unnormalised
post_secret_form() { # URL BODY → HTTP status; the body (it carries a secret) reaches curl through a 0600 file
  local body_file="$STATE/body.$$"
  printf '%s' "$2" > "$body_file"; chmod 600 "$body_file"
  curl -sk -o /dev/null -w '%{http_code}' --max-time 20 --data-binary "@$body_file" "$1"; rm -f "$body_file"
}
PG_IMAGE=""
probe() { docker run --rm --network "${PROJECT}_identity" "$@"; }
psql_as_keycloak() { # SQL [sslmode] with PGPASSWORD taken from the environment (never argv)
  docker run --rm --network "${PROJECT}_identity" -v "$TLS/ca.crt:/ca.crt:ro" -e PGPASSWORD "$PG_IMAGE" \
    psql "host=keycloak-db dbname=keycloak user=keycloak sslmode=${2:-verify-full} sslrootcert=/ca.crt" -Atc "$1" 2>&1 | head -1
}
kc_http() { # path on keycloak:<port> from inside the identity network → HTTP status
  probe "$PG_IMAGE" sh -c "wget -S -q -O /dev/null 'http://keycloak:$1$2' 2>&1 | sed -n 's/^  HTTP\\/[0-9.]* \\([0-9]*\\).*/\\1/p' | tail -1"
}
kcadm_master() { # kcadm args, authenticated as the master admin from .env (password via env, never argv); the session file is removed again
  local c rc; c="$(cid keycloak)"
  KC_CLI_PASSWORD="$(envv KEYCLOAK_ADMIN_PASSWORD)" docker exec -e KC_CLI_PASSWORD "$c" /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080/identity --realm master --user "$(envv KEYCLOAK_ADMIN_USER)" --config /tmp/kcadm-gate.config >/dev/null 2>&1 || return 1
  docker exec "$c" /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-gate.config 2>>"$RAW"; rc=$?
  docker exec "$c" rm -f /tmp/kcadm-gate.config >/dev/null 2>&1
  return $rc
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
  add_secret "$TEMP_PW" temp
  [[ -n "$TEMP_PW" ]]
}
flow() { # keycloak_login_flow.py wrapper; secrets through the environment; the proxy certificate is pinned
  KEYCLOAK_KAFBAT_CLIENT_SECRET="$(envv KEYCLOAK_KAFBAT_CLIENT_SECRET)" GATE_TEMP_PW="${TEMP_PW:-}" \
    python3 -I "$GATE_DIR/keycloak_login_flow.py" --cafile "$ED/certs/server.crt" "$@" 2>>"$RAW"
}
flow_reason() { printf '%s\n' "$1" | tail -1 | python3 -I -c 'import json,sys; d=json.loads(sys.stdin.read() or "{}"); print(d.get("result",""), d.get("reason",""))' 2>/dev/null; }
set_env_raw() { # KEY VALUE: edit .env directly (to inject a wrong value the CLI would refuse); the value travels in the environment
  KRATE_RAW_KEY="$1" KRATE_RAW_VALUE="$2" python3 -I - "$ENVF" <<'EOF'
import os, re, sys
path = sys.argv[1]; key = os.environ['KRATE_RAW_KEY']; value = os.environ['KRATE_RAW_VALUE']
s = open(path).read()
s, n = re.subn(rf'^{re.escape(key)}=.*$', lambda m: f'{key}={value}', s, flags=re.M)
if not n: s += f'{key}={value}\n'
open(path, 'w').write(s)
EOF
}
sha_env() { sha256file "$ENVF"; }
journal_has() { grep -q -E "$1" "$JOURNAL" 2>/dev/null; }
hold_lock() { # a live process holds the identity lock until release_lock
  mkdir -p "$ED/auth/.identity.lock"; sleep 600 & HOLDER=$!; HOLDERS+=("$HOLDER"); echo "$HOLDER" > "$ED/auth/.identity.lock/pid"
}
release_lock() { kill "$HOLDER" 2>/dev/null; wait "$HOLDER" 2>/dev/null; }

fixture_reset() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "${PROJECT}_identity" "${PROJECT}_identity-egress" "${PROJECT}_kafka-network" "$CLASH_NET" >/dev/null 2>&1 || true
  rm -rf "$ENVF" "$ED/auth/keycloak" "$ED/auth/ui/runtime.yml" "$JOURNAL" "$ED/auth/.identity.lock" "$ED/certs" "$ED/monitoring/.env"
}
fixture_env() {
  FIXTURE_OWNED=true
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
  local other mon
  other="$(docker ps -a --format '{{.Names}} {{.Label "com.docker.compose.project"}}' | awk -v p="$PROJECT" '$1 ~ /^(krate|epc)-/ && $2 != p {print $1" ("$2")"}' | tr '\n' ' ')"
  [[ -z "$other" ]] || { echo "Another Krate installation is running on this host: $other. Stop it first (one Keycloak deployment per host)." >&2; exit 2; }
  mon="$(docker volume ls -q | grep -c "^${MON_PROJECT}_" || true)"
  [[ "$mon" == 0 ]] || { echo "Monitoring volumes of project $MON_PROJECT already exist ($mon); this runner would destroy them. Remove them or use another host." >&2; exit 2; }
}

# ═══════════════════════════ static ═══════════════════════════
gmake_check_in() { ( cd "$1" && gmake check ); }  # env -C is GNU-only
run_static() {
  section "S: static checks on the candidate"
  local id
  if ! $STATIC; then
    for id in S1 S2 S3 S4; do record "$id" static S NOT_RUN "--no-static (outside the inventory)"; done
    return
  fi
  if [[ -f "$TOPLEVEL/Makefile" ]]; then
    cap gmake_check_in "$TOPLEVEL"; st=$?; ok_if S1 static S "$st" "gmake check (syntax, lint, compose-check, offline-check, identity-check): $(printf '%s' "$CAP" | tail -1 | cut -c1-120)"
  else
    record S1 static S NOT_RUN "no Makefile beside the edition (bundle host); run on the repository"
  fi
  cap git -C "$TOPLEVEL" diff --check; st=$?; ok_if S2 static S "$st" "git diff --check clean"
  if docker image inspect koalaman/shellcheck:v0.9.0 >/dev/null 2>&1; then
    cap docker run --rm -v "$TOPLEVEL:/mnt:ro" -w /mnt koalaman/shellcheck:v0.9.0 kraft/krate epc/krate sso/activate.sh "scripts/$(basename "$RUNNER")"; st=$?
    ok_if S3 static S "$st" "shellcheck 0.9.0 (CI version) on kraft/krate epc/krate sso/activate.sh and this runner"
  else
    record S3 static S NOT_RUN "koalaman/shellcheck:v0.9.0 image not on this host"
  fi
  cap python3 -I "$TOPLEVEL/scripts/check-identity.py"; st=$?; ok_if S4 static S "$st" "check-identity: $(printf '%s' "$CAP" | tail -1 | cut -c1-160)"
}

# ═══════════════════════════ phase 1 ═══════════════════════════
run_phase1() {
  local rc rc2 before after names codes ip ev kcid dbid reason uid users_at_backup cli_after_rotate db_before tampered_out wrong_out saved good_db real_docker
  section "Phase 1 fixture: $EDITION, project $PROJECT, $BASE, no brokers"
  fixture_reset; fixture_env
  cap "$KRATE" gen-cert; st=$?; ok_if H1 1 H "$st" "gen-cert: $(printf '%s' "$CAP" | tail -1 | cut -c1-100)"

  # ── J: subnet clash refused before anything is created (identity up AND start) ──
  docker network create --subnet "$SUBNET" "$CLASH_NET" >/dev/null 2>&1
  cap "$KRATE" identity up; rc=$?
  ev="identity up exit=$rc; $(printf '%s' "$CAP" | grep -o -E 'overlaps the identity subnet[^.]*' | head -1)"
  [[ $rc -ne 0 && "$CAP" == *"$CLASH_NET"* && "$CAP" == *KRATE_IDENTITY_SUBNET* && "$CAP" == *KRATE_IDENTITY_PROXY_IP* && -z "$(running_services)" ]]; st=$?; ok_if J1 1 J "$st" "$ev; both keys named; no container created"
  cap "$KRATE" start; rc=$?
  [[ $rc -ne 0 && "$CAP" == *"$CLASH_NET"* && -z "$(running_services)" ]]; st=$?; ok_if J2 1 J "$st" "start exit=$rc with the clash named; no container created"
  docker network rm "$CLASH_NET" >/dev/null 2>&1
  rm -f "$JOURNAL"

  # ── F/H: identity up from pristine, without brokers ──
  cap "$KRATE" identity up; rc=$?; collect_secrets
  names="$(running_services)"
  [[ $rc -eq 0 && "$names" == "keycloak keycloak-db " ]]; st=$?; ok_if F1 1 F "$st" "identity up exit=$rc in pristine state; running services: [$names] (no broker)"
  cap "$KRATE" identity status; st=$?; ok_if F2 1 F "$st" "identity status exit=$st: $(printf '%s' "$CAP" | grep -E 'keycloak ' | head -1 | xargs)"
  ev="$(master_users)"; [[ "$ev" == "$(envv KEYCLOAK_ADMIN_USER) " ]]; st=$?; ok_if H2 1 H "$st" "master realm users after bootstrap: [$ev] (temp-admin removed)"
  journal_has ' up bootstrapped ' ; st=$?; ok_if J3 1 J "$st" "journal: $(grep -E ' up bootstrapped ' "$JOURNAL" | head -1 | cut -c1-120)"
  # plan files never carry secret values
  ! grep -rqF -f "$SECRETS_FILE" "$ED/auth/keycloak/" && [[ -f "$ED/auth/keycloak/krate-realm.json" ]] && grep -q 'KEYCLOAK_CLI_CLIENT_SECRET}' "$ED/auth/keycloak/krate-realm.json"; st=$?; ok_if J4 1 J "$st" "krate-realm.json holds placeholders, none of the ${#SECRETS[@]} secret values"
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
  rc="$(post_secret_form "$BASE/identity/realms/krate/protocol/openid-connect/token" "grant_type=client_credentials&client_id=krate-cli&client_secret=$(envv KEYCLOAK_CLI_CLIENT_SECRET)")"
  [[ "$rc" == 200 ]]; st=$?; ok_if F4 1 F "$st" "authentication probe (krate-cli client_credentials via proxy) HTTP $rc; health probes are separate (F3)"
  # ── G: proxy exposure ──
  ev=""; codes=0
  for p in "/identity/realms/krate/.well-known/openid-configuration:200" "/identity/realms/krate/account:200" "/identity/admin/:404" "/identity/admin/master/console/:404" "/identity/realms/master:404" "/identity/realms/master/account:404" "/identity/metrics:404" "/identity/health:404" "/identity/health/ready:404" "/identity:404" "/identity/realms/krate/../master:404" "/identity/realms/krate/../krate/account:400" "/identity/realms/krate;x=1/account:400"; do
    rc="$(hc "$BASE${p%%:*}")"; ev="$ev ${p%%:*}=$rc"; [[ "$rc" == "${p##*:}" ]] || codes=1
  done
  ok_if G2 1 G $codes "proxy paths sent as-is (realm discovery and account 200; admin, master realm, metrics, health, bare /identity 404; a dot segment onto the master realm 404; a dot segment onto an allowed path 400; a path parameter 400):$ev"
  # networks
  ev="db=[$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$dbid")] kc=[$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$kcid")] identity.internal=$(docker network inspect "${PROJECT}_identity" -f '{{.Internal}}') subnet=$(docker network inspect "${PROJECT}_identity" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}') range=$(docker network inspect "${PROJECT}_identity" -f '{{range .IPAM.Config}}{{.IPRange}}{{end}}') proxy=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT}_identity\").IPAddress}}" "$(cid proxy)") trusted=$(docker exec "$kcid" printenv KC_PROXY_TRUSTED_ADDRESSES)"
  [[ "$ev" == "db=[${PROJECT}_identity ] kc=[${PROJECT}_identity ${PROJECT}_identity-egress ] identity.internal=true subnet=$SUBNET range=$IP_RANGE proxy=$PROXY_IP trusted=$PROXY_IP" ]]; st=$?; ok_if G3 1 G "$st" "$ev"
  # a dynamically addressed container lands in the pool, never on the proxy address
  ip="$(probe "$PG_IMAGE" sh -c 'hostname -i' | tr -d '[:space:]')"
  python3 -I -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) and sys.argv[1]!=sys.argv[3] else 1)' "$ip" "$IP_RANGE" "$PROXY_IP"; st=$?; ok_if G4 1 G "$st" "probe container address $ip is inside $IP_RANGE and not $PROXY_IP"
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
  export PGPASSWORD; PGPASSWORD="$(envv KEYCLOAK_DB_PASSWORD)"
  ev="plain:[$(psql_as_keycloak 'select 1' disable)] tls:[$(psql_as_keycloak 'select ssl, version from pg_stat_ssl where pid = pg_backend_pid()')]"
  PGPASSWORD=wrong-gate-password; ev="$ev wrongpw:[$(psql_as_keycloak 'select 1')]"; unset PGPASSWORD
  [[ "$ev" == *"no encryption"* && "$ev" == *"tls:[t|TLSv1.3]"* && "$ev" == *"password authentication failed"* ]]; st=$?; ok_if G8 1 G "$st" "$ev"

  # ── A/B: account lifecycle, MFA, denial ──
  add_user gatev --viewer; GATEV_TEMP="${TEMP_PW:-}"
  add_user gatea --admin --email gatea@example.test; GATEA_TEMP="${TEMP_PW:-}"
  add_user gaten; GATEN_TEMP="${TEMP_PW:-}"
  add_user gated --viewer; GATED_TEMP="${TEMP_PW:-}"
  cap "$KRATE" identity users list; ev="$(printf '%s' "$CAP" | grep -E '^  (gatev|gatea|gaten|gated) ' | awk '{print $1":"$2}' | tr '\n' ' ')"
  [[ "$ev" == "gatea:true gated:true gaten:true gatev:true " ]]; st=$?; ok_if A1 1 A "$st" "users add (viewer, admin+email, no group, viewer) then list: [$ev]"
  cap "$KRATE" identity users groups gatea; ev="$(printf '%s' "$CAP" | grep -E '^  [A-Za-z0-9_.-]+$' | xargs)"
  cap "$KRATE" identity users add 'bad name'; rc=$?; cap "$KRATE" identity users add gatev --viewer; after=$?
  [[ "$ev" == "$(envv KEYCLOAK_ADMIN_GROUP)" && $rc -ne 0 && $after -ne 0 ]]; st=$?; ok_if A2 1 A "$st" "gatea groups=[$ev]; 'bad name' refused (exit $rc); duplicate gatev refused (exit $after)"
  TEMP_PW="$GATEV_TEMP"; cap flow enrol --base "$BASE" --user gatev --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --state "$STATE/gatev.json"; rc=$?; add_flow_state_secrets "$STATE/gatev.json"
  ev="$(printf '%s' "$CAP" | tail -1 | python3 -I -c 'import json,sys; d=json.loads(sys.stdin.read() or "{}"); c=d.get("claims",{}); print(d.get("result"), d.get("required_actions"), "aud="+str(c.get("aud")), "groups="+str(c.get("groups")), "exp="+str(c.get("expires_in")), "iss="+str(c.get("iss")))' 2>/dev/null)"
  # expires_in is the 300 s lifespan minus the second that may pass between issue and read (299 on a slow host).
  [[ $rc -eq 0 && "$ev" == *"ENROLLED"* && "$ev" == *"aud=krate-ui"* && "$ev" == *"groups=['$(envv KEYCLOAK_VIEWER_GROUP)']"* && "$ev" =~ \ exp=(299|300)\  && "$ev" == *"iss=$BASE/identity/realms/krate"* ]]; st=$?; ok_if A3 1 A "$st" "first login: TOTP enrolment + forced password change, OTP required on the 2nd login, wrong OTP refused, old password refused: $ev"
  TEMP_PW="$GATEA_TEMP"; cap flow enrol --base "$BASE" --user gatea --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --state "$STATE/gatea.json"; add_flow_state_secrets "$STATE/gatea.json"
  ev="$(printf '%s' "$CAP" | tail -1 | python3 -I -c 'import json,sys; d=json.loads(sys.stdin.read() or "{}"); print(d.get("result"), "groups="+str(d.get("claims",{}).get("groups")))' 2>/dev/null)"
  TEMP_PW="$GATEN_TEMP"; cap flow enrol --base "$BASE" --user gaten --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --state "$STATE/gaten.json"; add_flow_state_secrets "$STATE/gaten.json"
  after="$(printf '%s' "$CAP" | tail -1 | python3 -I -c 'import json,sys; d=json.loads(sys.stdin.read() or "{}"); print(d.get("result"), "groups="+str(d.get("claims",{}).get("groups")))' 2>/dev/null)"
  [[ "$ev" == "ENROLLED groups=['$(envv KEYCLOAK_ADMIN_GROUP)']" && "$after" == "ENROLLED groups=None" ]]; st=$?; ok_if B1 1 B "$st" "claims contract: gatea → $ev; gaten (no group) → $after (no groups claim: nothing to map a role from)"
  cap flow login --base "$BASE" --state "$STATE/gatev.json" --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect ok; rc=$?
  TEMP_PW="definitely-wrong-password"; cap flow login --base "$BASE" --user gatev --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect refused --reason 'Invalid username or password.'; after=$?; reason="$(flow_reason "$CAP")"
  [[ $rc -eq 0 && $after -eq 0 && "$reason" == *"Invalid username or password."* ]]; st=$?; ok_if B2 1 B "$st" "gatev: correct password+OTP accepted; wrong password refused on the login form with: $reason"
  cap "$KRATE" identity users disable gated; rc=$?; TEMP_PW="$GATED_TEMP"; cap flow login --base "$BASE" --user gated --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect refused --reason 'Account is disabled'; after=$?; reason="$(flow_reason "$CAP")"
  cap "$KRATE" identity users enable gated; ev=$?
  [[ $rc -eq 0 && $after -eq 0 && "$reason" == *"Account is disabled"* && $ev -eq 0 ]]; st=$?; ok_if B3 1 B "$st" "users disable (exit $rc); login refused with: $reason; users enable (exit $ev)"
  rc="$(post_secret_form "$BASE/identity/realms/krate/protocol/openid-connect/token" "grant_type=password&client_id=krate-ui&client_secret=$(envv KEYCLOAK_KAFBAT_CLIENT_SECRET)&username=gatev&password=x")"
  [[ "$rc" == 400 || "$rc" == 401 ]]; st=$?; ok_if B4 1 B "$st" "direct password grant on krate-ui refused: HTTP $rc (standard flow only)"
  # brute force: rapid wrong passwords lock the account temporarily
  add_user gateb --viewer; TEMP_PW="wrong-$RANDOM"
  for _ in 1 2 3 4 5; do flow login --base "$BASE" --user gateb --password-env GATE_TEMP_PW --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect refused >/dev/null 2>&1; done
  uid="$(kcadm_master get users -r krate -q username=gateb -q exact=true --fields id --format csv --noquotes | grep -o -E '[0-9a-f-]{36}' | head -1)"
  ev="$(kcadm_master get "attack-detection/brute-force/users/$uid" -r krate | tr -d ' \n')"
  [[ "$ev" == *'"disabled":true'* && "$ev" =~ \"numFailures\":[2-9] ]]; st=$?; ok_if B5 1 B "$st" "after 5 rapid wrong passwords the account is temporarily locked (Keycloak's quick-login check locks after two rapid failures, later attempts are not counted): $ev"
  sleep 61  # a code is single-use: let the step gatea's B1 login consumed expire before using "the previous step"
  cap flow login --base "$BASE" --state "$STATE/gatea.json" --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect ok --totp-offset -1; st=$?; ok_if B7 1 B "$st" "a one-time code from the previous 30-second step is accepted (realm look-ahead window 1): $(printf '%s' "$CAP" | tail -1 | cut -c1-60)"
  cap "$KRATE" identity users reset-password gatev; rc=$?; TEMP_PW="$(temp_password "$CAP")"; add_secret "$TEMP_PW" temp
  [[ $rc -eq 0 && -n "$TEMP_PW" ]]; st=$?; ok_if B6 1 B "$st" "reset-password sets a new temporary password (exit $rc; shown once)"
  cap flow login --base "$BASE" --state "$STATE/gatev.json" --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect refused --reason 'Invalid username or password.'; st=$?; ok_if A4 1 A "$st" "old password refused after reset-password ($(flow_reason "$CAP"))"
  [[ "$(grep -c -E ' users (add|reset-password) ok ' "$JOURNAL")" -ge 5 ]] && ! grep -E ' users (add|reset-password) ok ' "$JOURNAL" | grep -qF -f "$SECRETS_FILE"; st=$?; ok_if J5 1 J "$st" "journal lines of users add/reset-password carry no secret value: $(grep -E ' users add ok gatev' "$JOURNAL" | head -1 | cut -c1-80)"

  # ── C: restart / down-up preserve identity ──
  compose restart --no-deps keycloak >/dev/null 2>&1; wait_status 180
  cap "$KRATE" identity users list; ev="$(printf '%s' "$CAP" | grep -c -E '^  gate[a-z] ')"
  cap "$KRATE" identity up; rc=$?
  [[ "$ev" == 5 && $rc -eq 0 && "$CAP" == *"No changes"* ]]; st=$?; ok_if C2 1 C "$st" "after 'compose restart keycloak': $ev gate users still listed; identity up → No changes"
  cap "$KRATE" identity down; cap "$KRATE" identity up; rc=$?; cap "$KRATE" identity users list; ev="$(printf '%s' "$CAP" | grep -c -E '^  gate[a-z] ')"
  cap flow login --base "$BASE" --state "$STATE/gatea.json" --client-secret-env KEYCLOAK_KAFBAT_CLIENT_SECRET --expect ok; after=$?
  [[ $rc -eq 0 && "$ev" == 5 && $after -eq 0 ]]; st=$?; ok_if C3 1 C "$st" "identity down + up: $ev users kept; gatea logs in with password+OTP (credentials preserved)"

  # ── H: lost .env on an existing database must not regenerate anything ──
  cp "$ENVF" "$STATE/env.saved"
  cp "$ED/.env.template" "$ENVF"; chmod 600 "$ENVF"; "$KRATE" config set "KRATE_PROJECT=$PROJECT" >/dev/null; "$KRATE" config set "KEYCLOAK_PUBLIC_URL=$BASE/identity" >/dev/null
  cap "$KRATE" identity up; rc=$?; ev="$(printf '%s' "$CAP" | grep -o -E 'identity database exists but \.env lacks[^.]*' | head -1)"
  cp "$STATE/env.saved" "$ENVF"; chmod 600 "$ENVF"; rm -f "$STATE/env.saved"
  export PGPASSWORD; PGPASSWORD="$(envv KEYCLOAK_DB_PASSWORD)"; rc2="$(psql_as_keycloak 'select 1')"; unset PGPASSWORD
  [[ $rc -ne 0 && -n "$ev" && "$rc2" == 1 ]]; st=$?; ok_if H3 1 H "$st" "fresh .env over an existing database: identity up exit=$rc ($ev); the stored DB password still works (nothing rotated)"

  # ── I: credential changes through the authoritative store ──
  export PGPASSWORD; PGPASSWORD="$(envv KEYCLOAK_DB_PASSWORD)"; cap "$KRATE" identity rotate KEYCLOAK_DB_PASSWORD; rc=$?; collect_secrets
  ev="$(psql_as_keycloak 'select 1')"; PGPASSWORD="$(envv KEYCLOAK_DB_PASSWORD)"; after="$(psql_as_keycloak 'select 1')"; unset PGPASSWORD
  wait_status 180
  [[ $rc -eq 0 && "$ev" == *"password authentication failed"* && "$after" == 1 ]]; st=$?; ok_if I1 1 I "$st" "rotate KEYCLOAK_DB_PASSWORD: old rejected ($ev), new accepted, Keycloak ready again"
  export KC_CLI_PASSWORD; KC_CLI_PASSWORD="$(envv KEYCLOAK_ADMIN_PASSWORD)"; cap "$KRATE" identity rotate KEYCLOAK_ADMIN_PASSWORD; rc=$?; collect_secrets
  docker exec -e KC_CLI_PASSWORD "$(cid keycloak)" /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080/identity --realm master --user "$(envv KEYCLOAK_ADMIN_USER)" --config /tmp/kcadm-old.config >/dev/null 2>&1; after=$?; unset KC_CLI_PASSWORD
  docker exec "$(cid keycloak)" rm -f /tmp/kcadm-old.config >/dev/null 2>&1
  ev="$(master_users)"
  [[ $rc -eq 0 && $after -ne 0 && "$ev" == "$(envv KEYCLOAK_ADMIN_USER) " ]]; st=$?; ok_if I2 1 I "$st" "rotate KEYCLOAK_ADMIN_PASSWORD: old password refused by kcadm (exit $after), new one lists master users [$ev]"
  cap "$KRATE" identity rotate KEYCLOAK_CLI_CLIENT_SECRET; rc=$?; collect_secrets; cap "$KRATE" identity users list; after=$?
  rc2="$(post_secret_form "$BASE/identity/realms/krate/protocol/openid-connect/token" "grant_type=client_credentials&client_id=krate-cli&client_secret=$(envv KEYCLOAK_CLI_CLIENT_SECRET)")"
  cap "$KRATE" identity up; ev=$?
  [[ $rc -eq 0 && $after -eq 0 && "$rc2" == 200 && $ev -eq 0 && "$CAP" == *"No changes"* ]]; st=$?; ok_if I3 1 I "$st" "rotate KEYCLOAK_CLI_CLIENT_SECRET: users list works, new secret authenticates (HTTP $rc2), identity up → No changes"
  before="$(envv KEYCLOAK_ADMIN_PASSWORD)"; printf '%s\n' "$(envv KEYCLOAK_DB_PASSWORD)" > "$STATE/reuse"
  cap_in "$STATE/reuse" "$KRATE" identity rotate KEYCLOAK_ADMIN_PASSWORD --value; rc=$?; rm -f "$STATE/reuse"
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
  cp "$STATE/gate.enc" "$STATE/tampered.enc"; python3 -I - "$STATE/tampered.enc" <<'EOF'
import sys
p = sys.argv[1]; b = bytearray(open(p, 'rb').read()); i = len(b) // 2; b[i] ^= 0x01; open(p, 'wb').write(b)
EOF
  cap "$KRATE" identity restore "$STATE/tampered.enc"; rc=$?; tampered_out="$CAP"; ev="$(printf '%s' "$CAP" | grep -o -E 'integrity check failed[^.]*' | head -1)"
  saved="$KRATE_BACKUP_PASSPHRASE"; KRATE_BACKUP_PASSPHRASE="wrong-passphrase-$RANDOM"; cap "$KRATE" identity restore "$STATE/gate.enc"; after=$?; wrong_out="$CAP"; KRATE_BACKUP_PASSPHRASE="$saved"
  [[ $rc -ne 0 && "$tampered_out" == *"integrity check failed"* && $after -ne 0 && "$wrong_out" == *"integrity check failed"* ]]; st=$?; ok_if D3 1 D "$st" "tampered archive (one bit flipped) refused before decryption: '$ev' (exit $rc); wrong passphrase refused the same way (exit $after)"
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
  hold_lock
  cap "$KRATE" identity users add gatelock --viewer; rc=$?; ev="$(printf '%s' "$CAP" | grep -o -E 'Another krate identity command is running[^.]*' | head -1)"
  release_lock
  cap "$KRATE" identity users add gatelock --viewer; after=$?; add_secret "$(temp_password "$CAP")" temp; names="$(printf '%s' "$CAP" | grep -o -E 'Removing the stale identity lock[^"]*' | head -1)"
  [[ $rc -ne 0 && -n "$ev" && $after -eq 0 && -n "$names" ]]; st=$?; ok_if E6 1 E "$st" "lock held by a live process: '$ev' (exit $rc); after that process died: '$names' and the command proceeds (exit $after)"
  hold_lock
  set_env_raw KEYCLOAK_ENABLED false
  cap "$KRATE" stop; rc=$?; ev="$(printf '%s' "$CAP" | grep -o -E 'Another krate identity command is running[^.]*' | head -1)"
  names="$(running_services)"
  release_lock; set_env_raw KEYCLOAK_ENABLED true; rm -rf "$ED/auth/.identity.lock"
  [[ $rc -ne 0 && -n "$ev" && "$names" == *keycloak-db* && "$names" == *"keycloak "* ]]; st=$?; ok_if E8 1 E "$st" "'krate stop' while an identity command holds the lock and KEYCLOAK_ENABLED is still false: '$ev' (exit $rc); identity services untouched [$names]"
  ( "$KRATE" identity users add gateraceA --viewer >"$STATE/raceA" 2>&1 ) & ( "$KRATE" identity users add gateraceB --viewer >"$STATE/raceB" 2>&1 ) & wait
  add_secret "$(temp_password "$(cat "$STATE/raceA")")" temp; add_secret "$(temp_password "$(cat "$STATE/raceB")")" temp
  rc="$(cat "$STATE/raceA" "$STATE/raceB" | grep -c 'Another krate identity command is running')"; after="$(cat "$STATE/raceA" "$STATE/raceB" | grep -c ' created')"
  [[ $((rc + after)) -eq 2 && $after -ge 1 ]]; st=$?; ok_if E7 1 E "$st" "two simultaneous mutating commands: refusals=$rc created=$after (one refused and one created, or both serialised; never two half-made users)"
  # readiness failure must not restart Keycloak
  dbid="$(cid keycloak-db)"; kcid="$(cid keycloak)"; docker stop "$dbid" >/dev/null 2>&1; sleep 15
  codes="ready=$(kc_http 9000 /health/ready) live=$(kc_http 9000 /health/live)"; "$KRATE" identity status >/dev/null 2>&1; rc=$?
  sleep 45; ev="restarts=$(docker inspect -f '{{.RestartCount}}' "$kcid") state=$(docker inspect -f '{{.State.Status}}' "$kcid") health=$(docker inspect -f '{{.State.Health.Status}}' "$kcid")"
  docker start "$dbid" >/dev/null 2>&1; wait_status 240; after=$?
  [[ "$codes" == "ready=503 live=200" && $rc -ne 0 && "$ev" == restarts=0\ state=running* && $after -eq 0 ]]; st=$?; ok_if F5 1 F "$st" "database stopped: $codes (readiness down, liveness up); identity status exit=$rc; after 60 s $ev (no restart loop); database back → ready again (status exit $after)"
  cap "$KRATE" identity status; st=$?; ev="$(printf '%s' "$CAP" | grep -E 'keycloak |realm|KEYCLOAK_ENABLED' | xargs)"; ok_if F6 1 F "$st" "identity status after recovery exit=$st: $ev"
  # renew-db-tls, with CA renewal path and rollback by fault injection
  before="$(openssl x509 -in "$TLS/server.crt" -noout -enddate)"; cap "$KRATE" identity renew-db-tls; rc=$?; after="$(openssl x509 -in "$TLS/server.crt" -noout -enddate)"
  openssl verify -CAfile "$TLS/ca.crt" "$TLS/server.crt" >/dev/null 2>&1; ev=$?; wait_status 180
  [[ $rc -eq 0 && "$before" != "$after" && $ev -eq 0 && ! -f "$TLS/server.key.prev" ]] && journal_has ' renew-db-tls ok '; st=$?; ok_if C4 1 C "$st" "renew-db-tls: $before → $after, chains to the CA, .prev discarded, journal ok, Keycloak ready"
  mkdir -p "$STATE/fakebin"; real_docker="$(command -v docker)"
  # shellcheck disable=SC2016  # the $1/$@ below are the fake binary's own, written literally
  printf '#!/usr/bin/env bash\n# Fault injection for the gate: the database restart during renew-db-tls fails.\nif [[ "$1" == compose ]]; then for a in "$@"; do [[ "$a" == restart ]] && { echo "injected: restart failed" >&2; exit 1; }; done; fi\nexec %q "$@"\n' "$real_docker" > "$STATE/fakebin/docker"
  chmod 700 "$STATE/fakebin/docker"
  before="$(sha256file "$TLS/server.crt")"
  PATH="$STATE/fakebin:$PATH" cap "$KRATE" identity renew-db-tls; rc=$?
  after="$(sha256file "$TLS/server.crt")"; ev="$(docker inspect -f '{{.State.Health.Status}}' "$(cid keycloak-db)" 2>/dev/null)"
  [[ $rc -ne 0 && "$before" == "$after" && ! -f "$TLS/server.crt.prev" && "$ev" == healthy ]] && journal_has ' renew-db-tls rolled back '; st=$?; ok_if C5 1 C "$st" "injected restart failure: renew-db-tls exit=$rc, server.crt byte-identical to before ($before), .prev consumed, journal 'rolled back'; database healthy on the old certificate ($ev)"
  # C6: realm policy changed behind the CLI's back is reconciled from the plan by identity up.
  kcadm_master update realms/krate -s otpPolicyLookAheadWindow=0 >/dev/null 2>&1; before="$(kcadm_master get realms/krate --fields otpPolicyLookAheadWindow --format csv --noquotes | tr -d '[:space:]')"
  cap "$KRATE" identity up; rc=$?; after="$(kcadm_master get realms/krate --fields otpPolicyLookAheadWindow --format csv --noquotes | tr -d '[:space:]')"
  [[ "$before" == 0 && $rc -eq 0 && "$after" == 1 && "$CAP" == *"look-ahead window"* ]] && journal_has ' up reconciled realm policy'; st=$?; ok_if C6 1 C "$st" "otpPolicyLookAheadWindow set to $before in Keycloak; identity up (exit $rc) reconciled it to $after; journal 'up reconciled realm policy'"
  cap "$KRATE" identity logrotate; rc=$?; ev="$(printf '%s' "$CAP" | grep -F "$JOURNAL" | head -1 | xargs) $(printf '%s' "$CAP" | grep -E '^\s*(rotate|maxage|copytruncate)' | xargs)"
  [[ $rc -eq 0 && "$ev" == *"$JOURNAL"* ]]; st=$?; ok_if J6 1 J "$st" "logrotate render names this journal: $ev"
  if $J7_REQUIRED; then
    cap as_root "$KRATE" identity logrotate --install; rc=$?; cap as_root logrotate -d "/etc/logrotate.d/krate-identity-$EDITION"; st=$?
    [[ $rc -eq 0 && $st -eq 0 ]]; st=$?; ok_if J7 1 J "$st" "logrotate --install (exit $rc) and 'logrotate -d' dry run accepted; the installed drop-in is removed again by the gate"
    as_root rm -f "/etc/logrotate.d/krate-identity-$EDITION"
  else
    record J7 1 J NOT_RUN "needs root (or sudo) and a logrotate binary: outside the inventory on this host; decided by the Linux VM receipt"
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
  section "X: end-user screenshot story (real browser; the TOTP secret and QR code are masked)"
  if ! $SCREENSHOTS; then record X1 1 X NOT_RUN "--no-screenshots (outside the inventory)"; return; fi
  if ! docker image inspect krate-harness/playwright:1.60.0 >/dev/null 2>&1; then
    printf 'FROM mcr.microsoft.com/playwright:v1.60.0-noble\nRUN npm i -g playwright@1.60.0\nENV NODE_PATH=/usr/lib/node_modules\n' | docker build -q -t krate-harness/playwright:1.60.0 - >/dev/null 2>&1 \
      || { record X1 1 X FAIL "harness image krate-harness/playwright:1.60.0 could not be built (network needed once)"; return; }
  fi
  add_user gateshot --viewer || { record X1 1 X FAIL "could not create the story user"; return; }
  local shot_pw="$TEMP_PW"; add_user gateshotd --viewer || { record X1 1 X FAIL "could not create the disabled story user"; return; }
  local shotd_pw="$TEMP_PW"; cap "$KRATE" identity users disable gateshotd || { record X1 1 X FAIL "could not disable the story user"; return; }
  # Chromium inside the container maps "localhost" to the Docker host gateway, so the
  # published proxy port is reached the way a browser on the host reaches it.
  local gateway
  gateway="$(docker run --rm --add-host host.docker.internal:host-gateway "$PG_IMAGE" sh -c 'getent ahostsv4 host.docker.internal | awk "{print \$1; exit}"' 2>/dev/null | tr -d '[:space:]')"
  [[ -n "$gateway" ]] || { record X1 1 X FAIL "cannot resolve the Docker host gateway (host.docker.internal) from a container"; return; }
  chmod 755 "$OUT/screenshots"
  export GATE_TEMP_PASSWORD="$shot_pw" GATE_DISABLED_PASSWORD="$shotd_pw"
  cap docker run --rm --add-host host.docker.internal:host-gateway -v "$OUT/screenshots:/out" -v "$GATE_DIR:/gate:ro" \
    -e GATE_TEMP_PASSWORD -e GATE_DISABLED_PASSWORD -e PW_MODULES=/usr/lib/node_modules \
    krate-harness/playwright:1.60.0 node /gate/screenshots.mjs --base "$BASE" --out /out --user gateshot --disabled-user gateshotd --resolve-to "$gateway"
  st=$?; unset GATE_TEMP_PASSWORD GATE_DISABLED_PASSWORD
  local n; n="$(find "$OUT/screenshots" -name '*.png' | wc -l | tr -d ' ')"
  [[ $st -eq 0 && "$n" == 11 && "$CAP" == *"STORY OK"* ]]; st=$?
  ok_if X1 1 X "$st" "$n screenshots in $OUT/screenshots (manifest.json has the captions and the asserted outcomes): $(printf '%s' "$CAP" | grep -E 'STORY|assert' | tail -1 | cut -c1-120)"
}

# ═══════════════════════════ phase 2 ═══════════════════════════
run_phase2() {
  local rc rc2 ev before after names id result evidence p
  section "Phase 2 fixture: brokers + Kafbat (runtime.yml) + proxy + identity"
  if [[ "$EDITION" != kraft ]]; then
    for id in "${REQUIRED_P2[@]}"; do [[ "$id" == Z* ]] || record "$id" 2 K NOT_RUN "Phase 2 runtime fixture is KRaft on this runner; EPC runtime is covered by the Phase 1 receipt inside the Linux VM"; done
    return
  fi
  cap "$KRATE" auth configure --local; rc=$?; ev="$(printf '%s' "$CAP" | grep -E 'runtime.yml|Kafbat plan' | head -2 | xargs | cut -c1-120)"
  "$KRATE" config set KAFKA_UI_AUTH_CONFIG=runtime.yml >/dev/null
  cap "$KRATE" start; after=$?
  before="$(cid kafka-92)"
  cap "$KRATE" auth apply; rc2=$?
  names="$(cid kafka-92)"
  grep -q 'allow-shared-login' "$ED/auth/ui/runtime.yml" && ev="$ev; allow-shared-login PRESENT"
  [[ $rc -eq 0 && $after -eq 0 && $rc2 -eq 0 && "$before" == "$names" && -n "$before" ]] && ! grep -q 'allow-shared-login' "$ED/auth/ui/runtime.yml"; st=$?; ok_if K1 2 K "$st" "auth configure --local (exit $rc; $ev); start (exit $after); auth apply (exit $rc2, preflight inside); broker container untouched by apply; runtime.yml has no shared login"
  before="$(cid kafka-ui)"; cap "$KRATE" auth apply; rc=$?; after="$(cid kafka-ui)"
  [[ $rc -eq 0 && "$before" == "$after" && "$CAP" == *"unchanged"* ]]; st=$?; ok_if K30 2 K "$st" "second auth apply: exit $rc, kafka-ui container unchanged ($before == $after), prints 'unchanged ... sessions kept'"
  ev=""; rc=0
  for p in "/metrics:404" "/actuator:404" "/actuator/:404" "/actuator/health:404" "/actuator/prometheus:404" "/actuator;x/prometheus:400" "/logout/connect:404" "/logout/connect/back-channel/keycloak:404" "/api/clusters;x:400" "/api/clusters:302"; do
    after="$(hc "$BASE${p%%:*}")"; ev="$ev ${p%%:*}=$after"; [[ "$after" == "${p##*:}" ]] || rc=1
  done
  ok_if K27 2 K $rc "public proxy, paths as-is:$ev (metrics/actuator/back-channel 404; path parameters 400; API redirects anonymous callers to login)"
  # K33: a foreign Host is refused with 444 (connection closed without a response) in Keycloak sign-in mode.
  after="$(curl -sk --max-time 20 -H 'Host: evil.example.test' -o /dev/null -w '%{http_code}' "$BASE/api/clusters")"; rc=$?
  ev="$(hc -H "Host: ${BASE#https://}" "$BASE/api/clusters")"
  names="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 20 -H 'Host: localhost' "http://localhost:$HTTP_PORT/api/clusters")"
  [[ "$after" == 000 && $rc -eq 52 && "$ev" == 302 && "$names" == "301 $BASE/api/clusters" ]]; st=$?; ok_if K33 2 K "$st" "Host: evil.example.test → HTTP $after, curl exit $rc (444: empty reply); Host: ${BASE#https://} → $ev; plain HTTP with Host: localhost → $names (redirect to the public authority); KRATE_PROXY_PUBLIC_HOST=$(envv KRATE_PROXY_PUBLIC_HOST)"
  # K34: a changed certificate changes KRATE_PROXY_CONF_SHA and auth apply recreates the proxy; a second apply keeps it.
  before="$(cid proxy)"; names="$(envv KRATE_PROXY_CONF_SHA)"; cap "$KRATE" gen-cert; cap "$KRATE" auth apply; rc=$?
  after="$(cid proxy)"; ev="$(envv KRATE_PROXY_CONF_SHA)"; cap "$KRATE" auth apply; rc2=$?
  [[ $rc -eq 0 && $rc2 -eq 0 && -n "$before" && "$before" != "$after" && "$names" != "$ev" && "$after" == "$(cid proxy)" && "$(hc "$BASE/api/clusters")" == 302 ]]; st=$?; ok_if K34 2 K "$st" "gen-cert changed KRATE_PROXY_CONF_SHA ($names → $ev); auth apply recreated the proxy (${before:0:12} → ${after:0:12}, exit $rc); second apply kept it (exit $rc2); proxy serves"
  after="$(curl -sk -o /dev/null -w '%{redirect_url}' --max-time 20 "$BASE/api/clusters")"; [[ "$after" == "$BASE/oauth2/authorization/keycloak" ]]; st=$?; ok_if K28 2 K "$st" "anonymous API call redirects to $after"
  # monitoring binds and exporter network (the monitoring project is this fixture's: host_conflicts refused pre-existing volumes)
  cap "$KRATE" monitor up; rc=$?; collect_secrets
  ev="prom=[$(docker port "$(mon_cid prometheus)" 2>/dev/null | tr '\n' ' ')] loki=[$(docker port "$(mon_cid loki)" 2>/dev/null | tr '\n' ' ')] grafana=[$(docker port "$(mon_cid grafana)" 2>/dev/null | tr '\n' ' ')]"
  [[ $rc -eq 0 && "$ev" == *"prom=[9090/tcp -> 127.0.0.1:19090"* && "$ev" == *"loki=[3100/tcp -> 127.0.0.1:13100"* && "$ev" == *"grafana=[3000/tcp -> 0.0.0.0:13000"* && "$ev" != *"9090/tcp -> 0.0.0.0"* && "$ev" != *"3100/tcp -> 0.0.0.0"* ]]; st=$?; ok_if M1 2 M "$st" "monitor up exit=$rc; Prometheus and Loki bound to 127.0.0.1 only, Grafana on all interfaces: $ev"
  after="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$(mon_cid kafka-exporter)" 2>/dev/null)"
  [[ "$after" == *"${PROJECT}_kafka-network"* && "$after" != *"${PROJECT}_identity"* ]]; st=$?; ok_if M2 2 M "$st" "kafka-exporter networks: [$after] (brokers' network, not identity)"
  local svc; for svc in prometheus grafana loki; do [[ -z "$(mon_cid "$svc")" ]] || docker logs "$(mon_cid "$svc")" > "$STATE/mon-$svc.log" 2>&1 || true; done
  cap "$KRATE" monitor down
  # Kafbat authorization ladder (a background child, so an interrupt reaches it)
  if [[ -f "$GATE_DIR/phase2_kafbat.py" ]]; then
    python3 -I "$GATE_DIR/phase2_kafbat.py" --edition-dir "$ED" --base-url "$BASE" --project "$PROJECT" > "$STATE/k.tsv" 2>>"$RAW" & CHILD=$!
    wait "$CHILD"; rc=$?; CHILD=""
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
  section "Z: secret-leak scan over every captured output, the journal, plan files, receipt files and container logs"
  local hits=0 s where t is_temp where_raw svc
  local -a places=("$JOURNAL" "$RECEIPT" "$OUT/screenshots/manifest.json")
  for svc in keycloak keycloak-db kafka-ui proxy; do
    [[ -n "$(cid "$svc")" ]] || continue
    docker logs "$(cid "$svc")" > "$STATE/$svc.log" 2>&1 || true; places+=("$STATE/$svc.log")
  done
  for svc in prometheus grafana loki; do  # captured by run_phase2 before monitor down
    [[ -f "$STATE/mon-$svc.log" ]] && places+=("$STATE/mon-$svc.log")
  done
  local raw_without_display="$STATE/raw-without-display.log"
  awk '/Temporary password for/ {print; skip=1; next} skip {skip=0; next} {print}' "$RAW" > "$raw_without_display"
  local one="$STATE/one-secret.txt"
  for s in "${SECRETS[@]}"; do
    is_temp=false; for t in "${TEMP_SECRETS[@]}"; do [[ "$t" == "$s" ]] && is_temp=true; done
    if $is_temp; then where_raw="$raw_without_display"; else where_raw="$RAW"; fi
    printf '%s\n' "$s" > "$one"; chmod 600 "$one"
    for where in "$where_raw" "${places[@]}"; do [[ -f "$where" ]] && grep -qF -f "$one" "$where" && { hits=$((hits+1)); log "LEAK: a secret value appears in ${where##*/}"; }; done
    grep -rqF -f "$one" "$ED/auth/keycloak/" 2>/dev/null && { hits=$((hits+1)); log "LEAK: a secret value appears under auth/keycloak/"; }
  done
  rm -f "$raw_without_display" "$one"
  [[ $hits -eq 0 ]]; st=$?; ok_if "$1" "$2" Z "$st" "${#SECRETS[@]} distinct secret values (.env and monitoring/.env passwords/secrets/keys, the backup passphrase, ${#TEMP_SECRETS[@]} temporary passwords, enrolled passwords and TOTP seeds) searched in the raw log (temporary passwords: outside their one-time display line), journal, plan files, receipt rows, screenshot captions and the keycloak, keycloak-db, kafka-ui, proxy and monitoring logs: $hits hits"
}
teardown() {
  section "teardown"
  [[ -z "$CHILD" ]] || { kill "$CHILD" 2>/dev/null; wait "$CHILD" 2>/dev/null; CHILD=""; }
  local h; for h in "${HOLDERS[@]}"; do kill "$h" 2>/dev/null; done
  if ! $FIXTURE_OWNED; then log "no fixture was created; nothing to tear down"; return; fi
  if $KEEP; then log "--keep: fixture left running (project $PROJECT)"; return; fi
  "$KRATE" monitor down >/dev/null 2>&1 || true
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  local v; for v in $(docker volume ls -q | grep -E "^${MON_PROJECT}_"); do docker volume rm "$v" >/dev/null 2>&1; done
  docker network rm "${PROJECT}_identity" "${PROJECT}_identity-egress" "${PROJECT}_kafka-network" "$CLASH_NET" "${MON_PROJECT}_monitoring" >/dev/null 2>&1 || true
  local n; for n in $(docker network ls --format '{{.Name}}' | grep -E "^${PROJECT}-gate2-"); do docker network rm "$n" >/dev/null 2>&1; done
  for n in $(docker ps -aq --filter "name=^${PROJECT}-gate2-"); do docker rm -f "$n" >/dev/null 2>&1; done
  rm -rf "$ENVF" "$ED/auth/keycloak" "$ED/auth/ui/runtime.yml" "$JOURNAL" "$ED/auth/.identity.lock" "$ED/certs" "$ED/monitoring/.env"
  local left; left="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ') containers, $(docker volume ls -q | grep -c -E "^${PROJECT}_|^${MON_PROJECT}_" || true) volumes, $(docker network ls --format '{{.Name}}' | grep -c -E "^${PROJECT}_|^${PROJECT}-|^${MON_PROJECT}_|^${CLASH_NET}$" || true) networks"
  log "fixture resources left: $left"
}
finish() {
  local verdict=PASS missing=() id notrun_required=0
  while IFS= read -r id; do
    [[ -n "${SEEN[$id]:-}" ]] || { missing+=("$id"); continue; }
    grep -q -E "^${id}	.*	NOT_RUN	" "$RECEIPT" && notrun_required=$((notrun_required+1))
  done < <(required_ids)
  (( FAILS == 0 )) || verdict=FAIL
  if (( notrun_required > 0 || ${#missing[@]} > 0 )) && [[ "$verdict" == PASS ]]; then verdict=INCOMPLETE; fi
  if ! $BOUND && [[ "$verdict" == PASS ]]; then verdict=INCOMPLETE; fi
  # Redact and publish: the secret values go to python through the 0600 list, never through a
  # shell expression; the raw log stays (0600) when the redacted copy could not be written.
  if python3 -I - "$RAW" "$OUT/run.log" "$RECEIPT" "$OUT/screenshots/manifest.json" "$SECRETS_FILE" <<'PYEOF'
import os, sys
raw, out, receipt, manifest, secrets_path = sys.argv[1:6]
secrets = sorted({line.rstrip('\n') for line in open(secrets_path, encoding='utf-8', errors='replace') if line.strip()}, key=len, reverse=True)
def redact(text):
    for value in secrets:
        text = text.replace(value, '<redacted>')
    return text
data = redact(open(raw, encoding='utf-8', errors='replace').read())
open(out, 'w', encoding='utf-8').write(data)
for path in (receipt, manifest):
    if os.path.isfile(path):
        text = open(path, encoding='utf-8', errors='replace').read()
        open(path, 'w', encoding='utf-8').write(redact(text))
sys.exit(0)
PYEOF
  then
    rm -f "$RAW"; RAW_CLOSED=1
  else
    log "WARNING: redaction failed; the raw log is kept at $RAW (mode 600) and must be redacted by hand"
  fi
  rm -rf "$STATE"
  local gate_digest
  gate_digest="$(find "$GATE_DIR" -type f \( -name '*.py' -o -name '*.mjs' \) | LC_ALL=C sort | while IFS= read -r f; do cat "$f"; done | { shasum -a 256 2>/dev/null || sha256sum; } | cut -c1-16)"
  {
    echo "# Krate identity gate receipt"
    echo
    echo "| field | value |"; echo "|---|---|"
    echo "| verdict | **$verdict** (PASS $PASSES, FAIL $FAILS, NOT_RUN $NOTRUN, required missing ${#missing[@]}: ${missing[*]:-none}; required not run: $notrun_required; bound: $BOUND) |"
    echo "| candidate commit | $CANDIDATE |"
    echo "| dirty tracked files at run time | ${DIRTY:-none} |"
    echo "| edition file digests (sha256, 16 hex) |$EDITION_DIGESTS |"
    echo "| edition / fixture | $EDITION in $ED, Compose project $PROJECT, $BASE, identity $SUBNET (pool $IP_RANGE, proxy $PROXY_IP) |"
    echo "| phases | $PHASE; screenshots: $SCREENSHOTS; static: $STATIC |"
    echo "| host | $(uname -srm); Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null); Compose $(docker compose version --short 2>/dev/null); $(python3 --version 2>&1); $(openssl version) |"
    echo "| images | $(grep -E '^[A-Z_]+_IMAGE=' "$ED/.env.template" | cut -d= -f2 | tr '\n' ' ') |"
    echo "| runner | $(basename "$RUNNER") v$GATE_VERSION sha256 $(sha256file "$RUNNER"); gate/ $gate_digest; runner repository commit $RUNNER_COMMIT${RUNNER_DIRTY:+ (dirty: $RUNNER_DIRTY)} |"
    echo "| started / finished (UTC) | $STAMP / $(date -u +%Y%m%dT%H%M%SZ) |"
    echo
    echo "| id | phase | criterion | result | evidence |"; echo "|---|---|---|---|---|"
    tail -n +2 "$RECEIPT" | awk -F'\t' '{gsub(/\|/, "\\|", $5); printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5}'
  } > "$OUT/receipt.md"
  chmod 644 "$OUT/receipt.md" "$OUT/receipt.tsv" "$OUT/run.log" 2>/dev/null; chmod 755 "$OUT"; [[ -d "$OUT/screenshots" ]] && chmod 755 "$OUT/screenshots" && chmod 644 "$OUT"/screenshots/* 2>/dev/null
  log ""; log "VERDICT: $verdict  (PASS $PASSES, FAIL $FAILS, NOT_RUN $NOTRUN, required missing: ${missing[*]:-none}, bound: $BOUND)"
  log "receipt: $OUT/receipt.md"
  [[ "$verdict" == PASS ]]
}

FINISHED=false
on_signal() { log "interrupted"; trap - EXIT HUP INT TERM; FINISHED=true; teardown; finish; exit 130; }
on_exit() { $FINISHED || { log "unexpected exit"; FINISHED=true; teardown; finish; }; }
host_conflicts
open_receipt
trap on_signal HUP INT TERM
trap on_exit EXIT
run_static
case "$PHASE" in
  1) run_phase1; run_screenshots; leak_scan Z1 1 ;;
  2|all) run_phase1; run_screenshots; leak_scan Z1 1; run_phase2; leak_scan Z2 2 ;;  # Phase 2 is accepted only with Phase 1
esac
FINISHED=true
trap - EXIT HUP INT TERM
teardown
finish
