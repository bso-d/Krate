#!/usr/bin/env bash
# Krate identity acceptance gate: Phase 1 (identity foundation), Phase 2 (Kafbat
# authorization), Phase 3 (PingFederate brokering, with a stand-in IdP from the
# edition's Keycloak image) and Phase 4 (the realm applied to Grafana, Perses and
# the backing services; slices 4a/4b/4c, each with a --session-max-hours companion
# run) against a disposable fixture. Each acceptance criterion of the owner's
# handover has numbered tests; every test ends PASS, FAIL or NOT_RUN with
# evidence, and the receipt binds the results to the candidate (the git checkout's
# commit, or on a bundle host the installed product bytes compared with --repo), the
# dirty files, the tool versions and this runner's own digest. The
# verdict is PASS only when every required test passed and the candidate is bound.
# See sso/guides/identity-gate.md.
#
#   scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe [--phase 1|2|3|all] [--stub-port N]
#   scripts/gate-identity.sh --edition-dir /opt/krate/epc --wipe --candidate <sha> --repo ~/gate/repo
#   scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe --phase 4a --public-host krate-gate.test
#   scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe --phase 4a --public-host krate-gate.test --session-max-hours 1
#   scripts/gate-identity.sh --edition-dir harness/worktrees/gate/kraft --wipe --phase 4b --public-host krate-gate.test --session-max-hours 1
#   scripts/gate-identity.sh --edition-dir /opt/krate/epc --wipe --phase 4c --public-host krate-oi.test \
#     --browser agent --rendezvous ~/gate/rdv --rendezvous-nonce <launcher token>   # on a vzNAT VM, driven by scripts/gate/mac/run-vm-gate.sh
#
# The fixture directory is a disposable checkout or a fixture installation whose
# .env, auth/keycloak, certs, journal and monitoring state the run creates and
# destroys. The runner refuses an existing .env unless --wipe is given. Secret
# values never appear on a command line: they travel through the environment or
# through 0600 files, and every captured output is redacted before it is published.
#
# Phase 4 runs under a non-localhost public host (--public-host, required there
# and refused for 1-3): the realm-mode monitoring UIs refuse a loopback
# KEYCLOAK_PUBLIC_URL. The name is mapped without touching /etc/hosts: the curl()
# wrapper below adds --resolve NAME:PORT:127.0.0.1 for the fixture's HTTPS, HTTP
# and Perses ports, and scripts/gate/netmap.py does the same for the Python
# helpers through $GATE_PUBLIC_HOST (TLS keeps the real name). Containers resolve
# the name through their extra_hosts host-gateway entry.
# shellcheck disable=SC2319  # `[[ ... ]]; st=$?` reads the condition's status on the very next statement
set -uo pipefail
umask 077
(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )) || { echo "bash 4.4 or newer is required (this is $BASH_VERSION)" >&2; exit 2; }

GATE_VERSION=7
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
STUB_PORT=18443
OUT=""
KEEP=false
WIPE=false
SCREENSHOTS=true
STATIC=true
CANDIDATE_ARG=""
REPO_ARG=""
PUBLIC_HOST=""          # Phase 4: the non-loopback public name (--public-host)
SESSION_MAX_HOURS=""    # Phase 4a/4b companion runs: KEYCLOAK_SESSION_MAX_HOURS=N (--session-max-hours)
BROWSER_MODE=container  # container (default, the walked shape) | agent (a Mac agent over the rendezvous, TOPOFIX F4)
RENDEZVOUS=""           # --browser agent only: the guest directory shared with the Mac agent
REND_NONCE=""           # --browser agent only: the run's rendezvous nonce from the Mac launcher (never printed)
# Monitoring ports of the fixture (the defaults may be in use on a developer host);
# fixture_env sets them and the curl() wrapper resolves the public name for them.
GRAFANA_GATE_PORT=13000
PROM_GATE_PORT=19090
LOKI_GATE_PORT=13100
PERSES_GATE_PORT=13443

usage() {
  cat <<EOF
Usage: $0 [--edition-dir DIR] [--project NAME] [--https-port N] [--http-port N]
          [--subnet CIDR --proxy-ip IP --ip-range CIDR] [--phase 1|2|3|4a|4b|4c|all] [--out DIR]
          [--candidate SHA [--repo DIR]] [--stub-port N] [--public-host NAME] [--session-max-hours N]
          [--wipe] [--keep] [--no-screenshots] [--no-static]
  --edition-dir    kraft or epc checkout or fixture installation (default: $REPO/kraft)
  --phase          1, 2, 3, all (= 1-3, the default), or the Phase 4 slices 4a (Grafana),
                   4b (Perses), 4c (backing services); a slice runs REQUIRED_P1 plus its own inventory
  --public-host NAME
                   the non-loopback public host of the fixture (required for 4a/4b/4c, refused
                   for 1-3: the Phase 1-3 inventory and receipts are localhost runs — X1's
                   browser story maps the name 'localhost' in Chromium, and K33 probes plain
                   HTTP with 'Host: localhost' against \$BASE). The name is mapped
                   to 127.0.0.1 for the runner's curl calls (--resolve), for the Python helpers
                   (scripts/gate/netmap.py, \$GATE_PUBLIC_HOST) and for the containers
                   (extra_hosts host-gateway); /etc/hosts is never touched and TLS keeps the
                   real name (the certificate must cover NAME: gen-cert derives its SAN from
                   KEYCLOAK_PUBLIC_URL)
  --session-max-hours N
                   Phase 4a/4b companion run: KEYCLOAK_SESSION_MAX_HOURS=N is set in the
                   fixture .env before the realm is created (the value applies at realm
                   creation only), then REQUIRED_P1 plus U27 and K37 (4a) or U27 and V23 (4b) run,
                   and the receipt names N
  --candidate SHA  the commit the edition files come from, when the directory has no git (a bundle install);
                   it binds only with --repo, which compares the installed product bytes with it
                   (without --repo the receipt is bound: false, at best INCOMPLETE)
  --repo DIR       a checkout of the candidate for the static block (S1-S4) when the edition directory is a bundle
                   install without Makefile or git; its HEAD must be the --candidate commit, and the
                   installed product is compared with it (scripts/gate/candidate_binding.py)
  --stub-port N    Phase 3: the stand-in IdP's port on 127.0.0.1 (default $STUB_PORT; must be free)
  --browser MODE   container (default: the walked krate-harness/playwright container vantage) or
                   agent (the Mac agent over the rendezvous, for a vzNAT VM fixture: TOPOFIX F4; the
                   agent carries W5/W6-W7's row plan, and X rows through it are a later batch)
  --rendezvous DIR --browser agent only: the guest directory shared with the Mac agent
                   (scripts/gate/mac/agent.mjs hello + {schema,id,row,nonce} requests)
  --rendezvous-nonce TOKEN
                   --browser agent only: the rendezvous nonce the Mac launcher generated
                   (scripts/gate/mac/run-vm-gate.sh); every hello and response must carry it; never printed
  --wipe           remove an existing .env/auth/certs in that directory first (required when present)
  --keep           leave the fixture running at the end (no teardown)
  --no-screenshots skip the end-user screenshot story (X1/X3/X4 leave the required inventory)
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
    --stub-port) STUB_PORT="$2"; shift 2 ;;
    --public-host) PUBLIC_HOST="$2"; shift 2 ;;
    --session-max-hours) SESSION_MAX_HOURS="$2"; shift 2 ;;
    --browser) BROWSER_MODE="$2"; shift 2 ;;
    --rendezvous) RENDEZVOUS="$2"; shift 2 ;;
    --rendezvous-nonce) REND_NONCE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --candidate) CANDIDATE_ARG="$2"; shift 2 ;;
    --repo) [[ -d "$2" ]] || { echo "--repo $2 is not a directory" >&2; exit 2; }; REPO_ARG="$(cd "$2" && pwd)"; shift 2 ;;
    --wipe) WIPE=true; shift ;;
    --keep) KEEP=true; shift ;;
    --no-screenshots) SCREENSHOTS=false; shift ;;
    --no-static) STATIC=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
# ── argument validation: every refusal below happens before anything is started (the
# only Docker calls before host_conflicts are the read-only `docker info` and
# `docker image inspect` of the product byte binding), so a refused run leaves nothing behind. ──
[[ "$PHASE" == 1 || "$PHASE" == 2 || "$PHASE" == 3 || "$PHASE" == 4a || "$PHASE" == 4b || "$PHASE" == 4c || "$PHASE" == all ]] \
  || { echo "--phase must be 1, 2, 3, 4a, 4b, 4c or all" >&2; exit 2; }
[[ "$STUB_PORT" =~ ^[0-9]+$ ]] || { echo "--stub-port must be a number" >&2; exit 2; }
if [[ -n "$PUBLIC_HOST" ]]; then
  [[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] \
    || { echo "--public-host must be a DNS name (letters, digits, . and -): $PUBLIC_HOST" >&2; exit 2; }
  case "${PUBLIC_HOST,,}" in
    localhost|127.0.0.1|::1) echo "--public-host must not be a loopback name (the realm-mode UIs refuse it): $PUBLIC_HOST" >&2; exit 2 ;;
  esac
fi
case "$PHASE" in
  4a|4b|4c)
    [[ -n "$PUBLIC_HOST" ]] \
      || { echo "--phase $PHASE requires --public-host NAME: the realm-mode monitoring UIs refuse a loopback KEYCLOAK_PUBLIC_URL (refuse_loopback_public_url)" >&2; exit 2; } ;;
  *)
    [[ -z "$PUBLIC_HOST" ]] \
      || { echo "--public-host is refused with --phase $PHASE: the Phase 1-3 inventory and receipts are localhost runs (X1's browser story maps the name 'localhost' in Chromium, and K33 probes plain HTTP with 'Host: localhost' against \$BASE)" >&2; exit 2; } ;;
esac
if [[ -n "$SESSION_MAX_HOURS" ]]; then
  [[ "$SESSION_MAX_HOURS" =~ ^[0-9]+$ && "$SESSION_MAX_HOURS" -ge 1 ]] \
    || { echo "--session-max-hours must be a whole number of at least 1 (sso/identity.py KEYCLOAK_SESSION_MAX_HOURS)" >&2; exit 2; }
  [[ "$PHASE" == 4a || "$PHASE" == 4b ]] \
    || { echo "--session-max-hours runs with --phase 4a or 4b only (the session-maximum rows are U27, V23 and K37)" >&2; exit 2; }
fi
# ── browser vantage (TOPOFIX F3/F4/F9): the agent is the VM vantage; its preflight reads the
# Mac agent's hello here, before anything is started, like the --repo checks above. ──
case "$BROWSER_MODE" in container|agent) ;; *) echo "--browser must be container or agent: $BROWSER_MODE" >&2; exit 2 ;; esac
agent_preflight() { # hello younger than 60 s, nonce-bound, skew <= 10 s, mac_src_ip inside 10/8, 172.16/12 or 192.168/16 (F7), and the
  # gate_files digests of the Mac worktree must be exactly this runner's own copies (F4: the Mac
  # runs the very bytes the receipt binds)
  [[ -d "$RENDEZVOUS" ]] || { echo "--rendezvous $RENDEZVOUS is not a directory (scripts/gate/mac/agent.mjs writes agent-hello.json there)" >&2; exit 2; }
  local parsed
  parsed="$(python3 -I - "$RENDEZVOUS/agent-hello.json" "$REND_NONCE" "$GATE_DIR" <<'PYPREFLIGHT'
import hashlib, ipaddress, json, os, sys, time
hello_path, nonce, gate_dir = sys.argv[1], sys.argv[2], sys.argv[3]
def refuse(msg):
    sys.stderr.write("agent hello refused: %s\n" % msg)
    sys.exit(2)
if not os.path.isfile(hello_path):
    refuse("%s does not exist (is the Mac agent running?)" % hello_path)
age = time.time() - os.stat(hello_path).st_mtime
if age > 60:
    refuse("the hello is %.1f s old (max 60 s; the agent rewrites it every 15 s)" % age)
try:
    hello = json.load(open(hello_path, "r", encoding="utf-8"))
except ValueError as exc:
    refuse("the hello is not strict JSON: %s" % exc)
if hello.get("schema") != 1:
    refuse("schema %r is not 1" % hello.get("schema"))
if hello.get("nonce") != nonce:
    refuse("the hello carries another run's nonce")
skew = hello.get("clock_skew_ms")
if not isinstance(skew, (int, float)) or abs(skew) > 10000:
    refuse("clock skew %r ms is beyond the 10 s budget (TOTP has 30 s steps); the launcher sets the guest clock from the Mac" % skew)
src = str(hello.get("mac_src_ip") or "")
try:
    addr = ipaddress.ip_address(src)
except ValueError:
    refuse("mac_src_ip %r is not an address" % src)
# F7: network membership, not the stdlib's private-address flag (it is also set for 198.18.0.0/15, 192.0.2.0/24, 203.0.113.0/24 ...):
# the air gap passes only these three private networks, so a Mac source outside them would be rejected there
rfc1918 = [ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
if addr.version != 4 or not any(addr in net for net in rfc1918):
    refuse("mac_src_ip %s is not inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16 (TOPOFIX2 F7: vmnet must give the Mac an RFC1918 address or replies would be rejected by the air gap)" % src)
vm_ip = str(hello.get("vm_ip") or "")
if not ipaddress.ip_address(vm_ip).version == 4:
    refuse("vm_ip %r is not an IPv4 address" % vm_ip)
mismatch = []
for rel, digest in sorted((hello.get("gate_files") or {}).items()):
    # the agent's own directory (agent/probe/package pins) is not copied into the guest: the
    # skip MUST precede the digest read, else every agent run is refused here on the first
    # scripts/gate/mac/* entry (review B1; the checker pins this order)
    if os.path.relpath(rel, "scripts/gate").startswith("mac/"):
        continue
    local = os.path.join(gate_dir, os.path.relpath(rel, "scripts/gate"))
    try:
        actual = hashlib.sha256(open(local, "rb").read()).hexdigest()
    except OSError as exc:
        refuse("gate file %s is not readable in %s: %s" % (rel, gate_dir, exc))
    if actual != digest:
        mismatch.append(rel)
if mismatch:
    refuse("the Mac worktree's gate files differ from this runner's copies: %s (the Mac must run the very bytes the receipt binds, F4)" % ", ".join(mismatch[:6]))
print("VM_IP=%s" % vm_ip)
print("MAC_SRC_IP=%s" % src)
print("VM_G6=%s" % str(hello.get("vm_g6") or ""))
print("MAC_IFACE=%s" % str(hello.get("mac_iface") or ""))
print("CLOCK_SKEW_MS=%d" % skew)
print("HELLO_AGE=%d" % age)
print("AGENT_PLAN=%s" % ",".join(sorted(str(x) for x in (hello.get("plan") or []))))
PYPREFLIGHT
  )"; local rc=$?
  [[ $rc -eq 0 ]] || exit 2
  VM_IP=""; MAC_SRC_IP=""; VM_G6=""; MAC_IFACE=""; CLOCK_SKEW_MS=""; HELLO_AGE=""; AGENT_PLAN=""
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      VM_IP) VM_IP="$v" ;; MAC_SRC_IP) MAC_SRC_IP="$v" ;; VM_G6) VM_G6="$v" ;;
      MAC_IFACE) MAC_IFACE="$v" ;; CLOCK_SKEW_MS) CLOCK_SKEW_MS="$v" ;; HELLO_AGE) HELLO_AGE="$v" ;; AGENT_PLAN) AGENT_PLAN="$v" ;;
    esac
  done <<<"$parsed"
  [[ -n "$VM_IP" && -n "$MAC_SRC_IP" && -n "$AGENT_PLAN" ]] || { echo "agent hello refused: the preflight emitted no VM_IP/MAC_SRC_IP/AGENT_PLAN" >&2; exit 2; }
  echo >&2 "agent hello: vm_ip=$VM_IP mac_src_ip=$MAC_SRC_IP iface=${MAC_IFACE:-?} g6=${VM_G6:-none} skew=${CLOCK_SKEW_MS}ms age=${HELLO_AGE}s plan=$AGENT_PLAN (nonce-bound; the token is not printed)"
}
case "$BROWSER_MODE" in
  agent)
    [[ -n "$RENDEZVOUS" && -n "$REND_NONCE" ]] || { echo "--browser agent requires --rendezvous DIR and --rendezvous-nonce TOKEN (scripts/gate/mac/run-vm-gate.sh generates both)" >&2; exit 2; }
    case "$PHASE" in
      4a|4b|4c) ;;
      *) echo "--browser agent is refused with --phase $PHASE: X1's story maps the name localhost, which no user points at a remote machine, so X1 stays a Mac-fixture row and the agent drives 4a/4b/4c only (TOPOFIX-REVIEW F9)" >&2; exit 2 ;;
    esac
    agent_preflight
    ;;
  container)
    [[ -z "$RENDEZVOUS" && -z "$REND_NONCE" ]] \
      || { echo "--rendezvous/--rendezvous-nonce belong to --browser agent (they name the shared guest directory and its run token)" >&2; exit 2; }
    ;;
esac

ED="$EDITION_DIR"
EDITION="$(basename "$ED")"
KRATE="$ED/krate"
ENVF="$ED/.env"
JOURNAL="$ED/auth/identity-journal.log"
TLS="$ED/auth/keycloak/db-tls"
MON_DIR="$ED/monitoring"
[[ -d "$MON_DIR" ]] || MON_DIR="$(cd "$ED/.." && pwd)/monitoring"
MON_PROJECT="krate-${EDITION}-monitoring"
CLASH_NET="${PROJECT}-gate-clash"
# The public authority of the fixture: localhost for Phases 1-3, --public-host for
# Phase 4 (the two are mutually exclusive, see the validation above).
BASE_HOST="${PUBLIC_HOST:-localhost}"
[[ "$HTTPS_PORT" == 443 ]] && BASE="https://$BASE_HOST" || BASE="https://$BASE_HOST:$HTTPS_PORT"
# ── name mapping without /etc/hosts (Phase 4): every curl call of this runner
# resolves the public name for the fixture's HTTPS, HTTP and Perses ports to
# loopback (--resolve, so SNI, Host and the certificate check keep the real
# name); the Python helpers get the same mapping through netmap.py, which reads
# the exported GATE_PUBLIC_HOST. Empty for Phases 1-3: a pure passthrough.
CURL_RESOLVE=()
if [[ -n "$PUBLIC_HOST" ]]; then
  gate_port=""
  for gate_port in "$HTTPS_PORT" "$HTTP_PORT" "$PERSES_GATE_PORT"; do
    CURL_RESOLVE+=("--resolve" "${PUBLIC_HOST}:${gate_port}:127.0.0.1")
  done
  export GATE_PUBLIC_HOST="$PUBLIC_HOST"
  # auth apply invokes sso/probe.py in a separate process. Give that probe the
  # same local connection address as curl --resolve and netmap on every host;
  # it still verifies the public hostname in TLS and the issuer document.
  export KRATE_PROBE_CONNECT_IP=127.0.0.1
fi
curl() { command curl "${CURL_RESOLVE[@]}" "$@"; }
[[ -x "$KRATE" && -f "$ED/.env.template" ]] || { echo "not an edition directory: $ED" >&2; exit 2; }
if [[ -d "$ED/sso" ]]; then SSO="$ED/sso"; elif [[ -d "$ED/../sso" ]]; then SSO="$(cd "$ED/../sso" && pwd)"; else echo "no sso/ beside $ED" >&2; exit 2; fi
if [[ -e "$ENVF" ]] && ! $WIPE; then
  echo "$ENVF exists; this runner destroys the fixture it is pointed at. Pass --wipe for a disposable checkout." >&2
  exit 2
fi
if [[ ! -d "$ED" || -L "$ED" || ! -d "$ED/auth" || -L "$ED/auth" || ! -d "$ED/auth/ui" || -L "$ED/auth/ui" ]]; then
  echo "$ED, auth, and auth/ui must be real fixture-owned directories before this gate can clean their children." >&2
  exit 2
fi
if [[ ! -d "$MON_DIR" || -L "$MON_DIR" || ! -d "$MON_DIR/auth" || -L "$MON_DIR/auth" ]]; then
  echo "$MON_DIR and its auth directory must be real fixture-owned directories before this gate can clean them." >&2
  exit 2
fi
if [[ ! -d "$MON_DIR/prometheus" || -L "$MON_DIR/prometheus" || ! -f "$MON_DIR/prometheus/prometheus.yml" || -L "$MON_DIR/prometheus/prometheus.yml" ]]; then
  echo "$MON_DIR/prometheus/prometheus.yml must be a real fixture-owned file before the W2 backup and reload probe." >&2
  exit 2
fi
if [[ -e "$MON_DIR/.env" || -L "$MON_DIR/.env" ]]; then
  echo "$MON_DIR/.env exists; this gate requires an empty monitoring fixture before it can own or remove that file." >&2
  exit 2
fi
for monitor_state in "$MON_DIR/auth/realm.ini" "$MON_DIR/auth/secrets" "$MON_DIR/auth/perses"; do
  if [[ -e "$monitor_state" || -L "$monitor_state" ]]; then
    echo "$monitor_state exists; this gate requires empty generated monitoring auth state before it can own or remove it." >&2
    exit 2
  fi
done

# ── candidate binding: a commit (git or --candidate) and, on a bundle host, the installed product bytes compared with it ──
sha256file() { { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"; } | cut -c1-16; }
BOUND=true
CANDIDATE_DIRTY=false
CANDIDATE_GIT_HEAD=""
PRODUCT_BINDING=""
# Product byte binding on a bundle host (audit D6): every file `make bundle` installed must carry the
# candidate's bytes in --repo (scripts/gate/candidate_binding.py: the Makefile copy list; the two
# templates after replaying the bundle's image rewrite from images.lock.tsv). Prints the summary line;
# returns the helper's status (0 match, 1 mismatch, 2 not comparable), the full output on stderr.
bind_product() {
  local out rc
  out="$(python3 -I "$GATE_DIR/candidate_binding.py" --repo "$REPO_ARG" --candidate "$1" --installed "$ED" --edition "$EDITION" --check-images 2>&1)"; rc=$?
  printf '%s\n' "${out%%$'\n'*}"
  (( rc == 0 )) || printf '%s\n' "$out" >&2
  return "$rc"
}
# At the end of a run the installed product must still be the candidate's: an edit during the
# run, or a product that can no longer be compared, voids the binding (bound: false).
recheck_product_binding() {
  local product_end summary
  product_end="$(bind_product "${CANDIDATE%% *}" 2>>"$RAW")"; local rc=$?
  summary="${product_end#PRODUCT_BINDING }"
  PRODUCT_BINDING="$PRODUCT_BINDING; at finish: ${summary:-not comparable}"
  (( rc == 0 )) && return 0
  BOUND=false
  return 1
}
# SF-2: a git checkout only when the edition's own files are tracked there; a bundle extracted
# inside some other work tree is a bundle install and binds through --repo like any other.
if git -C "$ED" rev-parse HEAD >/dev/null 2>&1 &&
   git -C "$ED" ls-files --error-unmatch -- krate docker-compose.yml .env.template nginx.conf >/dev/null 2>&1; then
  CANDIDATE="$(git -C "$ED" rev-parse HEAD)"
  CANDIDATE_GIT_HEAD="$CANDIDATE"
  TOPLEVEL="$(git -C "$ED" rev-parse --show-toplevel)"
  DIRTY="$(git -C "$TOPLEVEL" status --porcelain --untracked-files=no 2>/dev/null | tr '\n' ';')"
  [[ -z "$DIRTY" ]] || CANDIDATE_DIRTY=true
  [[ -z "$CANDIDATE_ARG" || "$CANDIDATE" == "$CANDIDATE_ARG"* ]] || { echo "--candidate $CANDIDATE_ARG differs from the checkout's HEAD $CANDIDATE" >&2; exit 2; }
  PRODUCT_BINDING="git checkout: the edition files are the tracked files of $CANDIDATE (dirty tracked files must be empty)"
elif [[ -n "$CANDIDATE_ARG" ]]; then
  # A stated commit binds nothing by itself: only --repo (below) compares the installed product with it.
  CANDIDATE="$CANDIDATE_ARG (stated; no git here; unbound unless --repo compares the product bytes)"
  TOPLEVEL="$(cd "$ED/.." && pwd)"
  DIRTY="unknown (no git)"
  BOUND=false
  PRODUCT_BINDING="not compared (no --repo)"
else
  CANDIDATE="unbound (no git and no --candidate)"
  TOPLEVEL="$(cd "$ED/.." && pwd)"
  DIRTY="unknown (no git)"
  BOUND=false
  PRODUCT_BINDING="not compared (no git and no --candidate)"
fi
EDITION_DIGESTS=""
for f in "$ED/krate" "$ED/docker-compose.yml" "$ED/.env.template" "$ED/nginx.conf" "$SSO/identity.py" "$SSO/preflight.py" "$SSO/activate.sh" "$SSO/probe.py" "$SSO/configure-dual.py"; do
  [[ -f "$f" ]] && EDITION_DIGESTS="$EDITION_DIGESTS ${f#"$TOPLEVEL"/}=$(sha256file "$f")"
done
if [[ -n "$REPO_ARG" ]]; then
  $STATIC || { echo "--repo runs the static block on that checkout; it cannot be combined with --no-static (drop one)" >&2; exit 2; }
  [[ -z "$CANDIDATE_GIT_HEAD" ]] || { echo "--repo is for a bundle install without git; $ED is a git checkout, its static block runs there already" >&2; exit 2; }
  [[ -n "$CANDIDATE_ARG" ]] || { echo "--repo needs --candidate SHA (the edition directory has no git)" >&2; exit 2; }
  [[ -f "$REPO_ARG/Makefile" ]] || { echo "--repo $REPO_ARG has no Makefile" >&2; exit 2; }
  repo_head="$(git -C "$REPO_ARG" rev-parse HEAD 2>/dev/null)" || { echo "--repo $REPO_ARG is not a git checkout" >&2; exit 2; }
  # --candidate must name exactly one commit of that checkout (at least 7 hex characters, resolved
  # by git, never a prefix match), and that commit must be HEAD.
  [[ "$CANDIDATE_ARG" =~ ^[0-9a-f]{7,40}$ ]] || { echo "--candidate must be a commit id of 7 to 40 hex characters" >&2; exit 2; }
  resolved="$(git -C "$REPO_ARG" rev-parse --verify --quiet "${CANDIDATE_ARG}^{commit}" 2>/dev/null)" \
    || { echo "--candidate $CANDIDATE_ARG is not one commit of --repo $REPO_ARG" >&2; exit 2; }
  [[ "$resolved" == "$repo_head" ]] || { echo "--repo HEAD $repo_head is not the candidate $CANDIDATE_ARG ($resolved)" >&2; exit 2; }
  TOPLEVEL="$REPO_ARG"
  PRODUCT_BINDING="$(bind_product "$resolved")" ||
    { echo "$ED is not bound to the candidate (${PRODUCT_BINDING:-no result}; the lines above name each difference or the error); reinstall the candidate's bundle, delete the files it does not ship and load its images before this gate (a NOTE about the Docker image store is not fixed by reinstalling: it names the likely cause, a different image store, not a bad bundle)" >&2; exit 2; }
  BOUND=true
  CANDIDATE="$resolved (stated as $CANDIDATE_ARG and resolved in --repo; product byte binding in its own row; static block on that checkout)"
  CANDIDATE_GIT_HEAD="$resolved"
  DIRTY="edition: unknown (no git); --repo: $(git -C "$REPO_ARG" status --porcelain --untracked-files=no 2>/dev/null | tr '\n' ';')"
  [[ -z "$(git -C "$REPO_ARG" status --porcelain --untracked-files=no 2>/dev/null)" ]] || CANDIDATE_DIRTY=true
fi
RUNNER_COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo 'no git')"
RUNNER_DIRTY="$(git -C "$REPO" status --porcelain --untracked-files=normal -- scripts/gate-identity.sh scripts/gate 2>/dev/null | tr '\n' ';')"
RUNNER_BOUND=true
if [[ "$RUNNER_COMMIT" == 'no git' ]]; then
  # VM bundle-host runs export the gate beside the bundle. Bind every exported
  # gate source file to the candidate checkout named by --repo.
  # The documented reduced bundle run has no --repo: its receipt states the
  # candidate SHA and source digests, but has no repository equality proof.
  RUNNER_BOUND=true
  if [[ -n "$REPO_ARG" ]] && cmp -s "$RUNNER" "$REPO_ARG/scripts/gate-identity.sh"; then
    RUNNER_BOUND=true
    while IFS= read -r -d '' gate_source; do
      [[ -f "$GATE_DIR/${gate_source#scripts/gate/}" ]] &&
        cmp -s "$GATE_DIR/${gate_source#scripts/gate/}" "$REPO_ARG/$gate_source" || RUNNER_BOUND=false
    done < <(git -C "$REPO_ARG" ls-files -z -- scripts/gate)
    while IFS= read -r -d '' gate_source; do
      git -C "$REPO_ARG" ls-files --error-unmatch -- "scripts/gate/${gate_source#"$GATE_DIR"/}" >/dev/null 2>&1 || RUNNER_BOUND=false
    done < <(find "$GATE_DIR" -type f \( -name '*.py' -o -name '*.mjs' -o -name '*.sh' \) -print0)
  elif [[ -n "$REPO_ARG" ]]; then
    RUNNER_BOUND=false
  fi
else
  [[ "$RUNNER_COMMIT" == "${CANDIDATE%% *}" ]] || RUNNER_BOUND=false
fi
RUNNER_SHA_START="$(sha256file "$RUNNER")"
RUNNER_GATE_SHA_START="$(find "$GATE_DIR" -type f \( -name '*.py' -o -name '*.mjs' -o -name '*.sh' \) | LC_ALL=C sort | while IFS= read -r f; do cat "$f"; done | { shasum -a 256 2>/dev/null || sha256sum; } | cut -c1-16)"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[[ -n "$OUT" ]] || OUT="$REPO/harness/gate-receipts/${EDITION}-${CANDIDATE:0:7}-${STAMP}"
RAW="$OUT/.raw.log"; RECEIPT="$OUT/receipt.tsv"; STATE="$OUT/.state"; SECRETS_FILE="$STATE/secrets.txt"
STUB="$GATE_DIR/stub_idp.sh"; STUB_DIR="$STATE/stub"  # the stand-in IdP's secrets and certificate live under the receipt's state directory
open_receipt() { # the receipt folder exists only once the host accepted the run (a refused run leaves nothing behind)
  if [[ -e "$OUT" || -L "$OUT" ]]; then echo "$OUT already exists; choose a fresh receipt directory" >&2; exit 2; fi
  if ! { mkdir -p "$(dirname "$OUT")" && mkdir "$OUT" && mkdir "$OUT/screenshots" && chmod 700 "$OUT"; }; then echo "cannot create $OUT" >&2; exit 2; fi
  : > "$RAW"; chmod 600 "$RAW" || exit 2
  printf 'id\tphase\tcriterion\tresult\tevidence\n' > "$RECEIPT"
  mkdir -p "$STATE" && chmod 700 "$STATE" || exit 2
  : > "$SECRETS_FILE"; chmod 600 "$SECRETS_FILE"
}
declare -a SECRETS=()
declare -a TEMP_SECRETS=()
declare -a HOLDERS=()
declare -a PHASE4_CHILDREN=()
declare -A SEEN=()
declare -A SEEN_RESULT=()
PASSES=0; FAILS=0; NOTRUN=0
CHILD=""
FIXTURE_OWNED=false  # set by fixture_env: only then may teardown touch Compose projects, volumes and networks
W2_BACKUP_OWNED=false  # set only after this run atomically saves the original Prometheus config
J7_REQUIRED=false

# ── required inventory (declared before anything runs; a missing row fails the gate) ──
REQUIRED_P1=(S1 S2 S3 S4 H1 H2 H3 F1 F2 F3 F4 F5 F6 G1 G2 G3 G4 G5 G6 G7 G8 A1 A2 A3 A4 A5 B1 B2 B3 B4 B5 B6 B7 C1 C2 C3 C4 C5 C6 I1 I2 I3 I4 I5 D1 D2 D3 D4 D5 D6 D7 E1 E2 E3 E4 E5 E6 E7 E8 J1 J2 J3 J4 J5 J6 J7 Z1)
as_root() { if [[ "$(id -u)" == 0 ]]; then "$@"; else sudo "$@"; fi; }
if { [[ "$(id -u)" == 0 ]] || sudo -n true 2>/dev/null; } && command -v logrotate >/dev/null 2>&1; then J7_REQUIRED=true; fi
REQUIRED_P2=(K1 K2 K3 K4 K5 K6 K7 K8 K9 K10 K11 K12 K13 K14 K15 K16 K18 K19 K20 K21 K22 K23 K24 K25 K26 K27 K28 K30 K31 K32 K33 K34 M1 M2 Z2)
REQUIRED_P3=(P1 P2 P3 P4 P5 P6 P7 P8 P9 P10 P11 P12 P13 P14 P15 P16 P18 Z3)
REQUIRED_X=(X1)
# Phase 4 inventories (PHASE4-INSTRUCTIONS-v3.md section 5): a slice is REQUIRED_P1
# plus its own rows, and it holds no Phase 2/3 ids (on an EPC edition directory the
# Phase 2/3 rows would be NOT_RUN and finish() would turn that into INCOMPLETE).
# The session-maximum rows (U27, V23, K37) run only in the --session-max-hours companion
# runs and are not part of the default inventories.
REQUIRED_P4A=(U1 U2 U3 U4 U5 U6 U7 U8 U9 U10 U11 U12 U13 U14 U15 U16 U17 U18 U19 U20 U21a U21b U22 U23 U24 U25 U26 U28 U29 X3 Z4a)
REQUIRED_P4B=(V1 V2 V3 V4 V5 V6 V7 V8 V9 V10 V11 V12 V13 V14 V15 V16 V17 V18 V19 V20 V21 V22 V24 X4 Z4b)
REQUIRED_P4C=(W1 W2 W3 W4 W5 W6 W7)
SESSION_P4A=(U27 K37)
SESSION_P4B=(U27 V23)
phase4_session_ids() { case "$1" in 4a) printf '%s\n' "${SESSION_P4A[@]}" ;; 4b) printf '%s\n' "${SESSION_P4B[@]}" ;; esac; }
# W3 (the foreign-source probe) follows the J7 pattern: on the Mac it runs (a)+(b)
# from the Mac's LAN address; on a VM it needs root (or sudo) and iproute2 for the
# p4probe network namespace, and leaves the inventory when the host cannot do it.
W3_REQUIRED=false
if [[ "$PHASE" == 4c ]]; then
  if [[ "$(uname -s)" == Darwin ]]; then
    W3_REQUIRED=true
  elif { [[ "$(id -u)" == 0 ]] || sudo -n true 2>/dev/null; } && command -v ip >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
    W3_REQUIRED=true
  fi
fi
# W5/W6/W7 are the network-path rows from the Mac vantage (TOPOFIX F6/F7): they test the
# firewall and the published-port surface as a second machine experiences it, which needs the
# Mac agent vantage (--browser agent) on a vzNAT VM fixture. They follow the J7 pattern too:
# outside the inventory without that vantage (a Docker-machine fixture has no second-host
# path to test), recorded NOT_RUN with the reason, decided by the VM receipt.
W5W6W7_REQUIRED=false
if [[ "$PHASE" == 4c && "$BROWSER_MODE" == agent ]]; then
  W5W6W7_REQUIRED=true
fi
required_ids() { # the inventory that decides the verdict, given the flags
  local id
  for id in "${REQUIRED_P1[@]}"; do
    if ! $STATIC && [[ "$id" == S* ]]; then continue; fi
    if [[ "$id" == J7 ]] && ! $J7_REQUIRED; then continue; fi
    echo "$id"
  done
  # The air gap of a bundle host (AG1-AG5, the airgap_* functions): a row that never reports fails the gate there. The Mac and a
  # git checkout record the rows NOT_RUN outside the inventory.
  if [[ "$(airgap_host_kind)" == bundle ]]; then for id in AG1 AG2 AG3 AG4 AG5; do echo "$id"; done; fi
  case "$PHASE" in
    1) ;;
    2) for id in "${REQUIRED_P2[@]}"; do echo "$id"; done ;;
    3|all)
      for id in "${REQUIRED_P2[@]}"; do echo "$id"; done
      for id in "${REQUIRED_P3[@]}"; do echo "$id"; done ;;
    4a|4b|4c)
      if [[ -n "$SESSION_MAX_HOURS" ]]; then
        while IFS= read -r id; do echo "$id"; done < <(phase4_session_ids "$PHASE")
      else
        local -a inv=()
        case "$PHASE" in
          4a) inv=("${REQUIRED_P4A[@]}") ;;
          4b) inv=("${REQUIRED_P4B[@]}") ;;
          4c) inv=("${REQUIRED_P4C[@]}") ;;
        esac
        for id in "${inv[@]}"; do
          if ! $SCREENSHOTS && [[ "$id" == X* ]]; then continue; fi
          if [[ "$id" == W3 ]] && ! $W3_REQUIRED; then continue; fi
          if [[ "$id" == W5 || "$id" == W6 || "$id" == W7 ]] && ! $W5W6W7_REQUIRED; then continue; fi
          echo "$id"
        done
      fi ;;
  esac
  if $SCREENSHOTS && [[ "$PHASE" != 4* ]]; then for id in "${REQUIRED_X[@]}"; do echo "$id"; done; fi
}

log() { if [[ -n "${RAW_CLOSED:-}" ]]; then printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; else printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RAW" >&2; fi; }
section() { log ""; log "=== $* ==="; }
record() { # id phase criterion result evidence
  local id="$1" phase="$2" crit="$3" result="$4" evidence="$5"
  evidence="${evidence//$'\t'/ }"; evidence="${evidence//$'\n'/ | }"
  if [[ -n "${SEEN[$id]:-}" ]]; then
    log "BUG: duplicate record $id"
    printf '%s\t%s\t%s\tFAIL\t%s\n' "${id}.audit" "$phase" "$crit" "duplicate result row for $id" >> "$RECEIPT"
    FAILS=$((FAILS+1))
    return
  fi
  case "$result" in
    PASS|FAIL|NOT_RUN) ;;
    *) evidence="invalid row result '${result//[^A-Za-z0-9_-]/?}'; $evidence"; result=FAIL ;;
  esac
  SEEN[$id]=1
  SEEN_RESULT[$id]="$result"
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
  for file in "$ENVF" "$MON_DIR/.env"; do
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
# Ready and staying ready: Keycloak's readiness is its database connection pool, which recovers
# connection by connection after the database returns (an UP probe can be followed by a DOWN
# one a second later; seen once on the EPC VM). Recovery means $2 (default 3) consecutive
# `identity status` successes at least 3 s apart within $1 s; STABLE_AFTER = seconds until the first of them.
wait_status_stable() {
  local need="${2:-3}" ok=0 waited=0 first=""
  while :; do
    if "$KRATE" identity status >/dev/null 2>&1; then
      (( ok == 0 )) && first=$waited
      ok=$((ok+1))
    else
      ok=0; first=""
    fi
    (( ok >= need )) && { STABLE_AFTER="${first:-0}"; return 0; }
    (( waited >= ${1:-180} )) && return 1
    sleep 3; waited=$((waited+3))
  done
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
  local n; for n in $(docker ps -aq --filter "label=krate.gate=w4-probe"); do docker rm -f "$n" >/dev/null 2>&1; done  # a W4 probe left by a killed run
  for n in $(docker ps -aq --filter "name=^${PROJECT}-gate3-" --filter "name=^${PROJECT}-gate4-"); do docker rm -f "$n" >/dev/null 2>&1; done  # a stale stand-in holds identity-egress; stale gate4 helpers hold the monitoring networks
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "${PROJECT}_identity" "${PROJECT}_identity-egress" "${PROJECT}_kafka-network" "$CLASH_NET" >/dev/null 2>&1 || true
  rm -rf "$ENVF" "$ED/auth/keycloak" "$ED/auth/ui/runtime.yml" "$JOURNAL" "$ED/auth/.identity.lock" "$ED/certs" "$MON_DIR/.env"
}
cleanup_monitor_auth() {
  # Preflight proved these paths absent before the gate; only this fixture can have created them.
  rm -rf "$MON_DIR/auth/realm.ini" "$MON_DIR/auth/secrets" "$MON_DIR/auth/perses"
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
  # Monitoring ports of the fixture (the defaults may be in use on a developer host);
  # the curl() wrapper resolves the public name for PERSES_GATE_PORT.
  "$KRATE" config set "GRAFANA_PORT=$GRAFANA_GATE_PORT" >/dev/null; "$KRATE" config set "PROM_PORT=$PROM_GATE_PORT" >/dev/null
  "$KRATE" config set "LOKI_PORT=$LOKI_GATE_PORT" >/dev/null; "$KRATE" config set "PERSES_PORT=$PERSES_GATE_PORT" >/dev/null
  # --session-max-hours N (Phase 4 companion runs): the value must be in .env before
  # the realm is created — KEYCLOAK_SESSION_MAX_HOURS is applied at realm creation
  # only (the realm plan's ssoSessionMaxLifespan, sso/identity.py), and this gate's
  # realm is new, so the plan applies.
  [[ -z "$SESSION_MAX_HOURS" ]] || "$KRATE" config set "KEYCLOAK_SESSION_MAX_HOURS=$SESSION_MAX_HOURS" >/dev/null
  PG_IMAGE="$(envv KEYCLOAK_DB_IMAGE)"
}
host_conflicts() { # other krate installations on this Docker host block a run (one installation per host by design)
  local other mon
  # A W4 probe (label krate.gate=w4-probe, no Compose project) is a gate artifact of a killed run, not another installation: fixture_reset removes it.
  other="$(docker ps -a --format '{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Label "krate.gate"}}' | awk -F'|' -v p="$PROJECT" '$1 ~ /^(krate|epc)-/ && $2 != p && $3 != "w4-probe" {print $1" ("$2")"}' | tr '\n' ' ')"
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
    cap docker run --rm -v "$TOPLEVEL:/mnt:ro" -w /mnt koalaman/shellcheck:v0.9.0 kraft/krate epc/krate sso/activate.sh "scripts/$(basename "$RUNNER")" scripts/gate/stub_idp.sh scripts/gate/phase4_w3.sh scripts/gate/mac/run-vm-gate.sh; st=$?
    ok_if S3 static S "$st" "shellcheck 0.9.0 (CI version) on kraft/krate epc/krate sso/activate.sh, this runner, scripts/gate/stub_idp.sh, scripts/gate/phase4_w3.sh and scripts/gate/mac/run-vm-gate.sh"
  else
    record S3 static S NOT_RUN "koalaman/shellcheck:v0.9.0 image not on this host"
  fi
  local st_identity st_py=0 py_failed="" py_count=0 helper
  cap python3 -I "$TOPLEVEL/scripts/check-identity.py"; st_identity=$?
  # Every gate helper must compile under this host's python3 (the guests run 3.9), not one named file.
  for helper in "$GATE_DIR"/*.py; do
    [[ -f "$helper" ]] || continue  # an unmatched glob leaves the literal pattern
    py_count=$((py_count+1))
    cap env PYTHONPYCACHEPREFIX="$STATE/pycache" python3 -m py_compile "$helper" || { st_py=1; py_failed="$py_failed $(basename "$helper")"; }
  done
  (( py_count > 0 )) || st_py=1
  [[ $st_identity -eq 0 && $st_py -eq 0 ]]; st=$?
  ok_if S4 static S "$st" "check-identity rc=$st_identity; py_compile of $py_count gate helpers rc=$st_py${py_failed:+ (failed:$py_failed)}"
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
  # a code is single-use: B7 sends the code of the previous step, which must not be one gatea's enrolment consumed.
  # Wait only until the previous step is newer than the newest step the enrolment recorded in its state file
  # (otp_steps), at most the 61 s this row always waited; a state file without otp_steps keeps the full 61 s.
  pause="$(python3 -I -c 'import json,sys,time; s=json.load(open(sys.argv[1])).get("otp_steps") or []; w=61.0 if not s else min(61.0, max(0.0, (max(int(x) for x in s)+2)*30+1-time.time())); time.sleep(w); print("%.0f" % w)' "$STATE/gatea.json" 2>/dev/null || sleep 61)"
  log "B7: waited ${pause:-61}s until the previous TOTP step is newer than gatea's enrolment steps"
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
  docker start "$dbid" >/dev/null 2>&1; STABLE_AFTER=""; wait_status_stable 240; after=$?
  [[ "$codes" == "ready=503 live=200" && $rc -ne 0 && "$ev" == restarts=0\ state=running* && $after -eq 0 ]]; st=$?; ok_if F5 1 F "$st" "database stopped: $codes (readiness down, liveness up); identity status exit=$rc; after 60 s $ev (no restart loop); database back → ready again and staying ready (3 consecutive status probes at least 3 s apart, first success after ${STABLE_AFTER:-?} s; exit $after)"
  cap "$KRATE" identity status; st=$?; ev="$(printf '%s' "$CAP" | grep -E 'keycloak |realm|KEYCLOAK_ENABLED' | xargs)"; ok_if F6 1 F "$st" "identity status after recovery exit=$st: $ev"
  # renew-db-tls, with CA renewal path and rollback by fault injection
  before="$(openssl x509 -in "$TLS/server.crt" -noout -enddate)"; cap "$KRATE" identity renew-db-tls; rc=$?; after="$(openssl x509 -in "$TLS/server.crt" -noout -enddate)"
  openssl verify -CAfile "$TLS/ca.crt" "$TLS/server.crt" >/dev/null 2>&1; ev=$?; wait_status_stable 180  # the database restarted: ready and staying ready (see F5)
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

# ═══════════════════════════ shared fixture bring-up ═══════════════════════════
# start_cluster: the one implementation of the fixture bring-up used by the K1
# prelude and by the Phase 4 slices on both editions (section 5 of
# harness/phase4/PHASE4-INSTRUCTIONS-v3.md): auth configure (extra arguments such
# as the K1 prelude's --local are accepted and ignored by the CLI's
# auth_configure), config set KAFKA_UI_AUTH_CONFIG=runtime.yml, start, auth
# apply, then monitor up. Sets SC_CONFIGURE/SC_SET/SC_START/SC_APPLY/SC_MONITOR
# (exit codes), SC_STUB (the 4b stand-in prelude), SC_CONFIGURE_EV (evidence
# line) and SC_BROKER_BEFORE/AFTER (the kafka-92 container id around auth
# apply); returns non-zero when any step failed. The monitoring secrets are
# collected for the leak scans.
#
# --broker (slice 4b only): the runner owns the stand-in IdP — stub_idp.sh up
# (the Phase 3 project/port convention) BEFORE a plain auth configure, so the
# stand-in is ready but NO broker plan is written or applied: with the broker
# applied, the browser flow redirects every login to the IdP (defaultProvider)
# and no login form remains for enrolment or sign-in. V19 applies the broker
# plan itself (commit 0: trustEmail=true) from the stand-in's site.json,
# exercises it, then removes it again (live4b 119). The prelude removes a
# pre-existing plan and runtime.yml first: since b51fe90 broker_plan REFUSES a
# stale plan whose trustEmail/storeToken/enabled differ, naming the field. The
# two preflight prerequisites Phase 3 proved (P2) are set the same way: the
# stand-in's PEM at 644 in the truststore dir, and
# PING_KEYCLOAK_CLIENT_SECRET through the environment (set_env_raw), never on
# a command line.
SC_CONFIGURE=0; SC_SET=0; SC_START=0; SC_APPLY=0; SC_MONITOR=0; SC_STUB=0; SC_CONFIGURE_EV=""; SC_BROKER_BEFORE=""; SC_BROKER_AFTER=""
stub_up_for_broker() { # the 4b stand-in prelude; sets SC_STUB, writes $STUB_DIR/site.json
  local cluster rc f
  cap "$KRATE" auth configure; rc=$?  # the plain plan: its runtime.yml names the edition's cluster list
  [[ $rc -eq 0 ]] || { SC_STUB=$rc; log "broker prelude: plain auth configure failed (exit $rc)"; return 1; }
  cluster="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["rbac"]["roles"][0]["clusters"][0])' "$ED/auth/ui/runtime.yml" 2>/dev/null)"
  [[ -n "$cluster" ]] || { SC_STUB=1; log "broker prelude: no cluster name in the plain runtime.yml"; return 1; }
  rm -f "$ED/auth/ui/runtime.yml" "$ED/auth/keycloak/pingfederate-idp.json"  # the stale-plan trap (b51fe90)
  cap "$STUB" up --project "$PROJECT" --edition-dir "$ED" --base "$BASE" --port "$STUB_PORT" --out "$STUB_DIR" --cluster "$cluster"; SC_STUB=$?
  [[ $SC_STUB -eq 0 ]] || { log "broker prelude: stub_idp.sh up failed (exit $SC_STUB): $(printf '%s' "$CAP" | grep -E '^stub:' | tail -1 | cut -c1-160)"; return 1; }
  for f in .admin-pw .client-secret .user-pw; do add_secret "$(tr -d '\n' < "$STUB_DIR/$f")"; done
  mkdir -p "$ED/auth/keycloak/truststores"
  cp "$STUB_DIR/stub.crt" "$ED/auth/keycloak/truststores/gate3-stand-in.crt"; chmod 644 "$ED/auth/keycloak/truststores/gate3-stand-in.crt"
  set_env_raw PING_KEYCLOAK_CLIENT_SECRET "$(tr -d '\n' < "$STUB_DIR/.client-secret")"; collect_secrets
  log "broker prelude: stand-in up on 127.0.0.1:$STUB_PORT (cluster $cluster); site file $STUB_DIR/site.json"
}
start_cluster() { # [--local] [--broker]
  local arg broker=false
  local -a cfg_args=()
  for arg in "$@"; do
    case "$arg" in
      --broker) broker=true ;;
      *) cfg_args+=("$arg") ;;
    esac
  done
  SC_CONFIGURE=127; SC_SET=127; SC_START=127; SC_APPLY=127; SC_MONITOR=127
  SC_CONFIGURE_EV=""; SC_STUB=0
  if $broker; then
    # Slice 4b only: the runner owns the stand-in IdP (up, truststore, secret,
    # site.json) but configures plain: the broker plan is applied by V19
    # itself and removed right after (live4b 119). A whole-run broker would
    # redirect every browser login to the IdP (defaultProvider), leaving no
    # login form for enrolment or sign-in.
    stub_up_for_broker || return 1
  fi
  cap "$KRATE" auth configure ${cfg_args[@]+"${cfg_args[@]}"}; SC_CONFIGURE=$?
  # Join, never parse: auth-configure output may carry an apostrophe, which
  # xargs treats as a quote and fails on (emptied evidence, "unmatched single
  # quote" in the log).
  SC_CONFIGURE_EV="$(printf '%s' "$CAP" | grep -E 'runtime.yml|Kafbat plan' | head -2 | tr '\n' ' ' | sed -e 's/^ *//' -e 's/ *$//' | cut -c1-120)"
  "$KRATE" config set KAFKA_UI_AUTH_CONFIG=runtime.yml >/dev/null; SC_SET=$?
  cap "$KRATE" start; SC_START=$?
  SC_BROKER_BEFORE="$(cid kafka-92)"
  cap "$KRATE" auth apply; SC_APPLY=$?
  SC_BROKER_AFTER="$(cid kafka-92)"
  cap "$KRATE" monitor up; SC_MONITOR=$?
  collect_secrets
  [[ $SC_CONFIGURE -eq 0 && $SC_SET -eq 0 && $SC_START -eq 0 && $SC_APPLY -eq 0 && $SC_MONITOR -eq 0 ]]
}

# ═══════════════════════════ phase 2 ═══════════════════════════
run_phase2() {
  local rc rc2 ev before after names id result evidence p
  section "Phase 2 fixture: brokers + Kafbat (runtime.yml) + proxy + identity"
  if [[ "$EDITION" != kraft ]]; then
    for id in "${REQUIRED_P2[@]}"; do [[ "$id" == Z* ]] || record "$id" 2 K NOT_RUN "Phase 2 runtime fixture is KRaft on this runner; EPC runtime is covered by the Phase 1 receipt inside the Linux VM"; done
    return
  fi
  start_cluster --local
  rc="$SC_CONFIGURE"; after="$SC_START"; rc2="$SC_APPLY"; before="$SC_BROKER_BEFORE"; names="$SC_BROKER_AFTER"; ev="$SC_CONFIGURE_EV"
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
  # A monitoring log this copy cannot take is named in logs-not-captured.txt: leak_scan then fails Z2 and Z3 with it listed as not read.
  local svc mid; for svc in prometheus grafana loki; do
    mid="$(mon_cid "$svc")"
    if [[ -z "$mid" ]]; then echo "mon-$svc.log (no container)" >> "$STATE/logs-not-captured.txt"
    else docker logs "$mid" > "$STATE/mon-$svc.log" 2>&1 || echo "mon-$svc.log (docker logs failed)" >> "$STATE/logs-not-captured.txt"; fi
  done
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

# ═══════════════════════════ phase 3 ═══════════════════════════
kcadm_master_in() { # FILE kcadm-args...: kcadm_master with the JSON body FILE on stdin (full representations, never -n)
  local c rc file="$1"; shift; c="$(cid keycloak)"
  KC_CLI_PASSWORD="$(envv KEYCLOAK_ADMIN_PASSWORD)" docker exec -e KC_CLI_PASSWORD "$c" /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080/identity --realm master --user "$(envv KEYCLOAK_ADMIN_USER)" --config /tmp/kcadm-gate.config >/dev/null 2>&1 || return 1
  docker exec -i "$c" /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-gate.config < "$file" 2>>"$RAW"; rc=$?
  docker exec "$c" rm -f /tmp/kcadm-gate.config >/dev/null 2>&1
  return $rc
}
realm_state() { # phase3_realm.py args...: the realm's brokering state (admin password through the environment); diffs on stderr into CAP
  KC_CLI_PASSWORD="$(envv KEYCLOAK_ADMIN_PASSWORD)" python3 -I "$GATE_DIR/phase3_realm.py" --project "$PROJECT" --admin-user "$(envv KEYCLOAK_ADMIN_USER)" "$@"
}
realm_diffs() { printf '%s\n' "$1" | grep -E '^phase3_realm:' | sed 's/^phase3_realm: //' | head -3 | tr '\n' ';'; }
preflight_runtime() { compose config --format json 2>>"$RAW" | python3 -I "$SSO/preflight.py" --directory "$ED" --mode runtime.yml; }
run_phase3() {
  local rc rc2 rc3 ev before after names id result evidence plan pem pem2 sha sha2 cluster a b c j kc1 kc2 kc3 local_pw reason
  local refused stance user_uid events_before events_after pf_rc ap_rc rs_rc ad_rc wd_rc rs2_rc d e f g h w k l e2 jb  # P18's and P14's own variables (the MFA-stance row, P14's journal count)
  section "Phase 3 fixture: the Phase 2 stack + the stand-in IdP (stub_idp.sh, port $STUB_PORT) brokered into realm krate"
  if [[ "$EDITION" != kraft ]]; then
    for id in "${REQUIRED_P3[@]}"; do [[ "$id" == Z* ]] || record "$id" 3 P NOT_RUN "Phase 3 runtime fixture is KRaft on this runner (Phase 2's Kafbat stack); EPC runtime is covered by the Phase 1 receipt inside the Linux VM"; done
    return
  fi
  plan="$ED/auth/keycloak/pingfederate-idp.json"
  cluster="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["rbac"]["roles"][0]["clusters"][0])' "$ED/auth/ui/runtime.yml" 2>/dev/null)"
  # ── the stand-in IdP is a prerequisite inside the inventory: when it cannot start, every row fails with the reason ──
  cap "$STUB" up --project "$PROJECT" --edition-dir "$ED" --base "$BASE" --port "$STUB_PORT" --out "$STUB_DIR" --cluster "${cluster:-cluster-1-kraft}"; rc=$?
  if [[ $rc -ne 0 ]]; then
    reason="$(printf '%s' "$CAP" | grep -E '^stub:' | tail -1 | cut -c1-160)"
    for id in "${REQUIRED_P3[@]}"; do [[ "$id" == Z* ]] || record "$id" 3 P FAIL "stand-in IdP not started (exit $rc): ${reason:-see run.log}"; done
    return
  fi
  for ev in .admin-pw .client-secret .user-pw; do add_secret "$(tr -d '\n' < "$STUB_DIR/$ev")"; done
  log "stand-in: $(printf '%s' "$CAP" | grep -E '^stub: realm' | cut -c1-200)"

  # ── P1: auth configure with the stand-in's site file writes the D3 plan with the secret placeholder only ──
  rm -f "$ED/auth/ui/runtime.yml" "$plan"  # configure refuses to replace an existing runtime.yml
  cap "$KRATE" auth configure "$STUB_DIR/site.json"; rc=$?
  cap realm_state --shape "$plan"; rc2=$?; ev="$(realm_diffs "$CAP")"
  ! grep -rqF -f "$SECRETS_FILE" "$ED/auth/keycloak/" && grep -q 'PING_KEYCLOAK_CLIENT_SECRET}' "$plan" 2>/dev/null; rc3=$?
  [[ $rc -eq 0 && $rc2 -eq 0 && $rc3 -eq 0 && -f "$ED/auth/ui/runtime.yml" ]]; st=$?; ok_if P1 3 P "$st" "auth configure site.json exit $rc; plan ${plan#"$ED"/} shape (provider → krate first broker login; krate browser = cookie ALT 10, redirector ALT 20 → pingfederate, krate forms ALT 30 = password REQ 10 + krate otp CONDITIONAL 20; create-user-if-unique REQUIRED; browserFlow; 2 FORCE mappers): ${ev:-as planned}; placeholder only, none of the ${#SECRETS[@]} secret values"

  # ── P2: preflight in ping mode refuses a missing secret, a 600 PEM and an http endpoint; passes once they are right ──
  pem="$ED/auth/keycloak/truststores/gate3-stand-in.crt"; cp "$STUB_DIR/stub.crt" "$pem"; chmod 644 "$pem"
  cap preflight_runtime; rc=$?; [[ $rc -ne 0 && "$CAP" == *PING_KEYCLOAK_CLIENT_SECRET* ]]; a=$?
  ev="secret missing: exit $rc ($(printf '%s' "$CAP" | grep -o -E 'PING_KEYCLOAK_CLIENT_SECRET is not set[^;]*' | head -1))"
  set_env_raw PING_KEYCLOAK_CLIENT_SECRET "$(tr -d '\n' < "$STUB_DIR/.client-secret")"; collect_secrets  # the value travels through the environment, never argv
  chmod 600 "$pem"; cap preflight_runtime; rc=$?; [[ $rc -ne 0 && "$CAP" == *"chmod 644"* ]]; b=$?
  ev="$ev; PEM 600: exit $rc ($(printf '%s' "$CAP" | grep -o -E 'must be world-readable[^:]*' | head -1))"; chmod 644 "$pem"
  cp "$plan" "$STATE/plan.saved"
  python3 -I - "$plan" <<'EOF'
import json, sys
path = sys.argv[1]; plan = json.load(open(path))
plan['identityProviders'][0]['config']['tokenUrl'] = 'http://' + plan['identityProviders'][0]['config']['tokenUrl'].split('://', 1)[1]
open(path, 'w').write(json.dumps(plan, indent=2) + '\n')
EOF
  cap preflight_runtime; rc=$?; [[ $rc -ne 0 && "$CAP" == *https* ]]; c=$?
  ev="$ev; http tokenUrl: exit $rc ($(printf '%s' "$CAP" | grep -o -E 'tokenUrl must be an https URL' | head -1))"; cp "$STATE/plan.saved" "$plan"; chmod 644 "$plan"
  cap preflight_runtime; rc2=$?
  [[ $a -eq 0 && $b -eq 0 && $c -eq 0 && $rc2 -eq 0 ]]; st=$?; ok_if P2 3 P "$st" "$ev; restored: exit $rc2 (positive control)"

  # ── P3/P4: auth apply applies the plan (Keycloak recreated first for the new PEM); the second apply changes nothing ──
  kc1="$(cid keycloak)"; sha="$(envv KRATE_TRUSTSTORE_SHA)"
  cap "$KRATE" auth apply; rc=$?
  kc2="$(cid keycloak)"; sha2="$(envv KRATE_TRUSTSTORE_SHA)"
  cap realm_state --expect "$plan"; rc2=$?; ev="$(realm_diffs "$CAP")"
  journal_has ' apply reconciled identity provider'; j=$?
  cap "$KRATE" auth apply; rc3=$?; kc3="$(cid keycloak)"
  [[ $rc -eq 0 && $rc2 -eq 0 && $j -eq 0 && $rc3 -eq 0 && "$(grep -c ' apply reconciled identity provider' "$JOURNAL")" == 1 ]] && printf '%s\n' "$CAP" | grep -q -E 'Identity provider pingfederate: No changes$'; st=$?
  ok_if P3 3 P "$st" "auth apply exit $rc: realm vs plan (provider, 2 mappers, flows with requirement/priority, redirector config, browserFlow): ${ev:-identical}; journal 'apply reconciled identity provider'; second apply exit $rc3 prints the line 'Identity provider pingfederate: No changes' and journals nothing more"
  # P4: the first apply saw a new PEM (digest changed → recreated); the second kept the container; another PEM → recreated again
  [[ -n "$kc1" && "$kc1" != "$kc2" && "$sha" != "$sha2" && -n "$sha2" && "$(docker exec "$kc2" printenv KRATE_TRUSTSTORE_SHA 2>/dev/null)" == "$sha2" && "$kc3" == "$kc2" ]]; a=$?
  pem2="$ED/auth/keycloak/truststores/gate3-stand-in-copy.crt"; cp "$STUB_DIR/stub.crt" "$pem2"; chmod 644 "$pem2"
  cap "$KRATE" auth apply; rc=$?; after="$(cid keycloak)"; names="$(envv KRATE_TRUSTSTORE_SHA)"
  ev="$(docker logs "$after" 2>&1 | grep -i -m1 -o -E 'truststore files[^"]{0,120}' | tr -s ' ' | cut -c1-120)"
  [[ $a -eq 0 && $rc -eq 0 && "$after" != "$kc2" && "$names" != "$sha2" && "$(docker exec "$after" printenv KRATE_TRUSTSTORE_SHA 2>/dev/null)" == "$names" ]] && journal_has ' apply recreated keycloak: truststores changed'; st=$?
  ok_if P4 3 P "$st" "PEM added: apply recreated Keycloak (${kc1:0:12} → ${kc2:0:12}), KRATE_TRUSTSTORE_SHA ${sha:-unset} → $sha2 in .env and the container; unchanged PEMs: second apply kept ${kc2:0:12}; a second PEM: recreated again (→ ${after:0:12}, sha $names, exit $rc); journal 'apply recreated keycloak: truststores changed'; Keycloak log: ${ev:-no truststore line found}"

  # ── P5–P13: the brokered sign-ins (a background child, so an interrupt reaches it) ──
  add_user gate3local --admin; local_pw="${TEMP_PW:-}"
  add_user gate3clash --viewer
  if [[ -f "$GATE_DIR/phase3_broker.py" ]]; then
    GATE3_LOCAL_PW="$local_pw" python3 -I "$GATE_DIR/phase3_broker.py" --edition-dir "$ED" --base-url "$BASE" --project "$PROJECT" \
      --stub-dir "$STUB_DIR" --stub-port "$STUB_PORT" --stub-script "$STUB" --local-user gate3local --local-password-env GATE3_LOCAL_PW \
      --clash-user gate3clash > "$STATE/p.tsv" 2>>"$RAW" & CHILD=$!
    wait "$CHILD"; rc=$?; CHILD=""
    while IFS=$'\t' read -r id result evidence; do
      [[ "$id" =~ ^P[0-9]+$ ]] || continue
      [[ -n "${SEEN[$id]:-}" ]] && continue
      record "$id" 3 P "$result" "$evidence"
    done < "$STATE/p.tsv"
    log "phase3_broker.py exit=$rc"
  fi

  # ── P16: the client secret rotated at the IdP → sign-in fails until `identity rotate` carries the new value; the link survives ──
  login_probe() { python3 -I "$GATE_DIR/phase3_broker.py" --edition-dir "$ED" --base-url "$BASE" --project "$PROJECT" --stub-dir "$STUB_DIR" --stub-port "$STUB_PORT" --stub-script "$STUB" --login-probe "$1" 2>>"$RAW" | grep -E '^LOGIN' | cut -f2-; }
  cap "$STUB" rotate-secret --project "$PROJECT" --out "$STUB_DIR"; rc=$?; add_secret "$(tr -d '\n' < "$STUB_DIR/.client-secret")"
  before="$(login_probe ping-viewer)"  # the realm still presents the old secret to the stand-in
  cap_in "$STUB_DIR/.client-secret" "$KRATE" identity rotate PING_KEYCLOAK_CLIENT_SECRET --value; rc2=$?; collect_secrets
  printf '%s\n' "$CAP" | grep -q -E 'Identity provider pingfederate: secret updated$'; a=$?
  journal_has ' rotate PING_KEYCLOAK_CLIENT_SECRET applied to identity provider pingfederate'; j=$?
  after="$(login_probe ping-viewer)"
  [[ $rc -eq 0 && "$before" == error* && $rc2 -eq 0 && $a -eq 0 && $j -eq 0 && "$after" == ok* && "$after" == *"federated identities 1"* && "$(envv PING_KEYCLOAK_CLIENT_SECRET)" == "$(tr -d '\n' < "$STUB_DIR/.client-secret")" ]]; st=$?
  ok_if P16 3 P "$st" "stand-in secret rotated (exit $rc); before identity rotate the brokered sign-in fails at the realm: ${before%%; hops*}; identity rotate PING_KEYCLOAK_CLIENT_SECRET --value (stdin) exit $rc2, line 'Identity provider pingfederate: secret updated', journal 'rotate … applied to identity provider pingfederate', .env carries the new value; afterwards ping-viewer signs in again with its link kept: ${after%%; hops*}"

  # ── P18: the MFA stance (enforce-if-asserted) ──
  # NOT YET RUN ON A LIVE FIXTURE: the hand-walk observes the 502 page, the event pair and the provider update once
  # before this row counts (owner rule 11). What the row asserts, from source (Keycloak 26.8.0) and the existing P16/P5
  # machinery: the applied plan (the stand-in site file opted out, mfa_not_asserted: true, no claim filter) still brokers
  # a sign-in; the preflight — the gate `auth apply` runs — refuses a plan whose site file stated neither stance; then
  # Keycloak's "Verify essential claim" (filteredByClaim/claimFilterName/claimFilterValue on the provider's config; the
  # claim is read from the ID token only, a missing claim and an unmatched value both fail, OIDCIdentityProvider.java
  # 490-512) is applied for `amr` — a claim no stand-in token is expected to carry — through the plan and `auth apply`;
  # a fresh stand-in user's sign-in then ends at the realm as `error` with status 502, no realm user exists before or
  # after, and exactly one more IDENTITY_PROVIDER_LOGIN_ERROR event with error identity_provider_login_failure is
  # stored (EventBuilder.error stores error events immediately; the realm plan's empty enabledEventTypes keeps every
  # save-by-default type). The filter is withdrawn the way an operator withdraws it: the site switches to the opt-out,
  # so the plan (P2's saved copy) no longer carries the three keys, and `auth apply` must UPDATE the live provider (not
  # print "No changes"): the three keys are managed (identity.provider_differs), and the update replaces the provider's
  # configuration (kcadm `update -f -` does not merge; IdentityProviderResource.updateIdpFromRep builds the model from
  # the representation). The same user then signs in, and the brokered users' federated-identity links are untouched
  # (the provider is updated in place, never removed). Every "absent" reading fails closed: a kcadm failure is a FAIL.
  p18_user_ids() { kcadm_master get users -r krate -q username=ping-mfa -q exact=true --fields id --format csv --noquotes; }
  p18_events() { local out; out="$(kcadm_master get events -r krate -q type=IDENTITY_PROVIDER_LOGIN_ERROR -q max=200 --fields type,error --format csv --noquotes)" || return 1
    printf '%s\n' "$out" | grep -c 'identity_provider_login_failure' || true; }
  p18_clean() { local json; json="$(kcadm_master get identity-provider/instances/pingfederate -r krate)" || return 1
    [[ "$json" == *'"pingfederate"'* && "$json" != *filteredByClaim* && "$json" != *claimFilterName* && "$json" != *claimFilterValue* ]]; }
  before="$(login_probe ping-viewer)"  # pre-filter positive control: the opted-out plan still signs in
  [[ "$before" == ok* ]]; c=$?
  python3 -I - "$plan" <<'EOF' >/dev/null 2>>"$RAW"
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data.pop('mfa_not_asserted', None)  # the stance refusal: neither the claim pair nor the opt-out marker
open(path, 'w').write(json.dumps(data, indent=2) + '\n')
EOF
  cap preflight_runtime; pf_rc=$?
  [[ $pf_rc -ne 0 && "$CAP" == *"no MFA stance"* && "$CAP" == *"mfa_claim_name"* && "$CAP" == *"mfa_not_asserted"* ]]; a=$?
  stance="$(printf '%s' "$CAP" | grep -o -E 'states no MFA stance[^;]{0,140}' | head -1)"
  python3 -I - "$plan" <<'EOF' >/dev/null 2>>"$RAW"
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data.pop('mfa_not_asserted', None)  # the filter keys are the stance; the marker must not ride beside them
data['identityProviders'][0]['config']['filteredByClaim'] = 'true'
data['identityProviders'][0]['config']['claimFilterName'] = 'amr'  # no stand-in client carries an amr mapper
data['identityProviders'][0]['config']['claimFilterValue'] = 'otp'
open(path, 'w').write(json.dumps(data, indent=2) + '\n')
EOF
  cap "$KRATE" auth apply; ap_rc=$?
  cap realm_state --expect "$plan"; rs_rc=$?; ev="$(realm_diffs "$CAP")"
  [[ $ap_rc -eq 0 && $rs_rc -eq 0 ]]; b=$?
  cap "$STUB" add-user --project "$PROJECT" --out "$STUB_DIR" ping-mfa APP-KAFKA-VIEWERS; ad_rc=$?
  [[ $ad_rc -eq 0 || "$CAP" == *"already exists"* ]]; d=$?
  user_uid="$(p18_user_ids)"; e=$?
  [[ $e -eq 0 ]] && ! grep -q -E '[0-9a-f-]{36}' <<< "$user_uid"; e=$?
  events_before="$(p18_events)"; h=$?
  refused="$(login_probe ping-mfa)"
  sleep 2
  events_after="$(p18_events)"; h=$((h + $?))
  [[ $h -eq 0 && "$events_before" =~ ^[0-9]+$ && "$events_after" =~ ^[0-9]+$ && $events_before -lt 200 && $events_after -lt 200 && $((events_after - events_before)) -eq 1 ]]; h=$?
  user_uid="$(p18_user_ids)"; f=$?
  [[ $f -eq 0 ]] && ! grep -q -E '[0-9a-f-]{36}' <<< "$user_uid"; f=$?
  [[ "$refused" == error* && "$refused" == *"502"* && "$refused" == *"/identity/realms/krate/"* ]]; g=$?
  # Withdrawn the operator's way: the site switches to the opt-out (P2's saved plan: the marker, no claim keys), auth apply updates the provider.
  cp "$STATE/plan.saved" "$plan"; chmod 644 "$plan"
  cap "$KRATE" auth apply; wd_rc=$?
  [[ $wd_rc -eq 0 ]] && grep -q 'provider updated' <<< "$CAP" && ! grep -q -E 'Identity provider pingfederate: No changes$' <<< "$CAP"; w=$?
  cap realm_state --expect "$plan"; rs2_rc=$?
  p18_clean; e2=$?
  [[ $rs2_rc -eq 0 && $e2 -eq 0 ]]; k=$?
  after="$(login_probe ping-mfa)"
  [[ "$after" == ok* ]]; l=$?
  user_uid="$(p18_user_ids | grep -o -E '[0-9a-f-]{36}' | head -1)"
  [[ -n "$user_uid" ]] && kcadm_master delete "users/$user_uid" -r krate >/dev/null 2>&1
  [[ $a -eq 0 && $b -eq 0 && $c -eq 0 && $d -eq 0 && $e -eq 0 && $f -eq 0 && $g -eq 0 && $h -eq 0 && $w -eq 0 && $k -eq 0 && $l -eq 0 ]]; st=$?
  ok_if P18 3 P "$st" "MFA stance (enforce-if-asserted): the opted-out plan brokers ping-viewer (${before%%; hops*}; pre-filter control); preflight refused the plan that states no MFA stance (exit $pf_rc: ${stance:-not phrased}); the claim filter (filteredByClaim=true, claimFilterName amr, claimFilterValue otp) applied via auth apply (exit $ap_rc; realm vs plan exit $rs_rc: ${ev:-identical}); fresh stand-in user ping-mfa (no realm user before: exit $e) refused: ${refused%%; hops*} (no realm user after: exit $f), IDENTITY_PROVIDER_LOGIN_ERROR(identity_provider_login_failure) events ${events_before:-?} → ${events_after:-?} (+1 and both below the 200-event read cap: exit $h); filter withdrawn by switching the site to the opt-out: auth apply exit $wd_rc printed 'provider updated' and not 'No changes' (exit $w), realm matches the plan (exit $rs2_rc), the live provider carries none of the three keys (exit $e2; both together: exit $k); the same user signs in right after (${after%%; hops*}), its realm user removed afterwards. Mechanism asserted at the stand-in, not yet observed live; the tenant's assertion policy is site work (site mfa_not_asserted today: MFA enforced at Ping only)"

  # ── P14: the plan removed + auth apply → provider, mappers and flows gone, browser flow rebound, local login on the default path ──
  jb="$(grep -c ' apply removed identity provider' "$JOURNAL" 2>/dev/null || true)"  # lines before P14's own apply: the term below needs a NEW line
  rm -f "$plan"
  cap "$KRATE" auth apply; rc=$?
  cap realm_state --expect-absent; rc2=$?; ev="$(realm_diffs "$CAP")"
  [[ "$(grep -c ' apply removed identity provider' "$JOURNAL")" -gt "${jb:-0}" ]]; j=$?
  before="$(curl -sk -o /dev/null -w '%{redirect_url}' --max-time 20 "$BASE/oauth2/authorization/keycloak")"
  after="$(curl -sk -o "$STATE/p14.html" -w '%{http_code}' --max-time 20 "$before")"; names="$(grep -c 'kc-form-login' "$STATE/p14.html")"; rm -f "$STATE/p14.html"
  [[ $rc -eq 0 && $rc2 -eq 0 && $j -eq 0 && "$after" == 200 && "$names" -ge 1 ]]; st=$?
  ok_if P14 3 P "$st" "plan file removed; auth apply exit $rc; realm: ${ev:-provider gone, no krate flow, browserFlow browser}; journal gained an 'apply removed identity provider' line (${jb:-0} before this apply); Kafbat's default path → realm auth answers HTTP $after with the login form ($names form) instead of the broker redirect"

  # ── P15: identity up on the existing realm reconciles CONFIGURE_TOTP default=false and re-applies the provider from the plan ──
  cp "$STATE/plan.saved" "$plan"; chmod 644 "$plan"
  kcadm_master get authentication/required-actions/CONFIGURE_TOTP -r krate > "$STATE/totp.json" 2>/dev/null
  python3 -I - "$STATE/totp.json" <<'EOF'
import json, sys
path = sys.argv[1]; action = json.load(open(path)); action['defaultAction'] = True
open(path, 'w').write(json.dumps(action))
EOF
  kcadm_master_in "$STATE/totp.json" update authentication/required-actions/CONFIGURE_TOTP -r krate -f - >/dev/null 2>&1; rm -f "$STATE/totp.json"
  cap realm_state --required-action CONFIGURE_TOTP=true; before=$?
  cap "$KRATE" identity up; rc=$?
  cap realm_state --expect "$plan" --required-action CONFIGURE_TOTP=false; rc2=$?; ev="$(realm_diffs "$CAP")"
  journal_has ' up reconciled required action CONFIGURE_TOTP' && journal_has ' up reconciled identity provider'; j=$?
  [[ $before -eq 0 && $rc -eq 0 && $rc2 -eq 0 && $j -eq 0 ]]; st=$?
  ok_if P15 3 P "$st" "CONFIGURE_TOTP defaultAction set to true behind the CLI's back (drift confirmed: $before); identity up exit $rc; afterwards defaultAction false and the realm matches the plan again (provider re-applied after P14's removal): ${ev:-identical}; journal 'up reconciled required action CONFIGURE_TOTP' and 'up reconciled identity provider'"
  for id in "${REQUIRED_P3[@]}"; do [[ "$id" == Z* || -n "${SEEN[$id]:-}" ]] || record "$id" 3 P FAIL "no result produced (scripts/gate/phase3_broker.py missing or incomplete)"; done
  docker logs "${PROJECT}-gate3-pingstub" > "$STATE/pingstub.log" 2>&1 || echo "pingstub.log (docker logs failed)" >> "$STATE/logs-not-captured.txt"
}

# ═══════════════════════════ phase 4 ═══════════════════════════
# The Phase 4 slices (4a Grafana, 4b Perses, 4c backing services) run REQUIRED_P1
# plus their own inventory on both editions (the EPC VM receipt is part of the
# slice acceptance), under --public-host NAME: the realm-mode monitoring UIs
# refuse a loopback KEYCLOAK_PUBLIC_URL. The rows live in the slice helpers
# (scripts/gate/phase4_grafana.py, phase4_perses.py, section 5 of
# harness/phase4/PHASE4-INSTRUCTIONS-v3.md); X3/X4 (screenshot stories), Z4a/Z4b
# (the extended leak scans) and W1-W4 are the runner's. A --session-max-hours N
# companion run sets N in fixture_env (before the realm is created) and runs
# REQUIRED_P1 plus U27 and K37 (4a) or U27 and V23 (4b) only.
in_inv() { # id inventory...: membership without a subshell
  local want="$1"; shift; local have
  for have in "$@"; do [[ "$have" == "$want" ]] && return 0; done
  return 1
}
phase4_ingest() { # TSV slice regex: record the helper's rows; its `setup` line is logged, not recorded
  local tsv="$1" slice="$2" regex="$3" id result evidence crit
  [[ -f "$tsv" ]] || return 0
  while IFS=$'\t' read -r id result evidence; do
    if [[ "$id" == setup ]]; then
      log "[$result] $slice setup: ${evidence:0:220}"
      if [[ "$result" != PASS && -z "${SEEN[${slice}-setup]:-}" ]]; then
        record "${slice}-setup" "$slice" setup FAIL "helper setup result $result: $evidence"
      fi
      continue
    fi
    [[ "$id" =~ $regex ]] || continue
    crit="${id%%[0-9]*}"
    record "$id" "$slice" "$crit" "$result" "$evidence"
  done < "$tsv"
}
phase4_stub() { # id slice crit evidence: a runner-owned row whose body awaits the live walk (rule 11)
  record "$1" "$2" "$3" NOT_RUN "$4"
}
# X3: the end-user screenshot story for slice 4a, wired exactly as t-live4a verified it
# (live4a results.md §"X3 report": scripts/gate/screenshots-grafana.mjs ran UNMODIFIED
# at ee173ac in krate-harness/playwright:1.60.0 with the gate's --resolve-to mapping
# shape; `STORY OK: 12 assertions over 5 screenshots`; every NEEDS-LIVE-VERIFICATION
# selector confirmed as written; the manifest sha256 list independently recomputed).
# Credentials come from the helper's enrolment state files ($STATE/p4/kc-{p4v,p4both}.json)
# through the environment only, never argv; all four values join the leak set.
phase4_screenshots_x3() {
  local slice="$1" viewer_json="$STATE/p4/kc-p4v.json" admin_json="$STATE/p4/kc-p4both.json"
  local outdir="$OUT/screenshots-grafana" gateway st n sha_ok f s rest pw totp
  if ! $SCREENSHOTS; then
    phase4_stub X3 "$slice" X "not run: --no-screenshots (X3 is outside the required inventory)"
    return
  fi
  if [[ ! -f "$viewer_json" || ! -f "$admin_json" ]]; then
    phase4_stub X3 "$slice" X "the helper's enrolment state files are missing (kc-p4v.json / kc-p4both.json): the slice setup did not run, so the story has no signed-in users"
    return
  fi
  if ! docker image inspect krate-harness/playwright:1.60.0 >/dev/null 2>&1; then
    printf 'FROM mcr.microsoft.com/playwright:v1.60.0-noble\nRUN npm i -g playwright@1.60.0\nENV NODE_PATH=/usr/lib/node_modules\n' | docker build -q -t krate-harness/playwright:1.60.0 - >/dev/null 2>&1 \
      || { record X3 "$slice" X FAIL "harness image krate-harness/playwright:1.60.0 could not be built (network needed once)"; return; }
  fi
  gateway="$(docker run --rm --add-host host.docker.internal:host-gateway "$PG_IMAGE" sh -c 'getent ahostsv4 host.docker.internal | awk "{print \$1; exit}"' 2>/dev/null | tr -d '[:space:]')"
  if [[ -z "$gateway" ]]; then
    record X3 "$slice" X FAIL "cannot resolve the Docker host gateway (host.docker.internal) from a container"
    return
  fi
  mkdir -p "$outdir" && chmod 755 "$outdir"
  pw="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$viewer_json" 2>/dev/null)"
  totp="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["totp"])' "$viewer_json" 2>/dev/null)"
  [[ -n "$pw" && -n "$totp" ]] || { record X3 "$slice" X FAIL "kc-p4v.json carries no password/totp"; return; }
  add_secret "$pw"; add_secret "$totp"
  export GATE_VIEWER_PASSWORD="$pw" GATE_VIEWER_TOTP="$totp"; pw=""; totp=""
  pw="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$admin_json" 2>/dev/null)"
  totp="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["totp"])' "$admin_json" 2>/dev/null)"
  [[ -n "$pw" && -n "$totp" ]] || { record X3 "$slice" X FAIL "kc-p4both.json carries no password/totp"; return; }
  add_secret "$pw"; add_secret "$totp"
  export GATE_ADMIN_PASSWORD="$pw" GATE_ADMIN_TOTP="$totp"; pw=""; totp=""
  cap docker run --rm --add-host host.docker.internal:host-gateway -v "$outdir:/out" -v "$GATE_DIR:/gate:ro" \
    -e GATE_VIEWER_PASSWORD -e GATE_VIEWER_TOTP -e GATE_ADMIN_PASSWORD -e GATE_ADMIN_TOTP -e PW_MODULES=/usr/lib/node_modules \
    krate-harness/playwright:1.60.0 node /gate/screenshots-grafana.mjs \
    --base "$BASE" --host "$BASE_HOST" --out /out --viewer-user p4v --admin-user p4both --resolve-to "$gateway"
  st=$?
  unset GATE_VIEWER_PASSWORD GATE_VIEWER_TOTP GATE_ADMIN_PASSWORD GATE_ADMIN_TOTP
  n="$(find "$outdir" -name '*.png' | wc -l | tr -d ' ')"
  sha_ok=0
  if [[ -f "$outdir/manifest.tsv" ]]; then
    sha_ok=1
    while IFS=$'\t' read -r f s rest; do
      [[ "$f" == file || -z "$f" || ! -f "$outdir/$f" ]] && continue
      printf '%s  %s\n' "$s" "$outdir/$f" | { shasum -a 256 -c - >/dev/null 2>&1 || sha256sum -c - >/dev/null 2>&1; } || sha_ok=0
    done < "$outdir/manifest.tsv"
  fi
  [[ $st -eq 0 && "$n" == 5 && "$CAP" == *"STORY OK"* && $sha_ok -eq 1 ]]; s=$?
  ok_if X3 "$slice" X "$s" "$n screenshots in ${outdir##*/}/, every manifest.tsv sha256 verified=$sha_ok, story exit=$st: $(printf '%s' "$CAP" | grep -E '^STORY' | tail -1 | cut -c1-120)"
}
phase4_leak_scan_z4a() {
  local slice="$1"
  section "Z4a: extended secret-leak scan over docker logs of every container, raw gate log, receipt, screenshot manifests, and ps dumps"
  if [[ -f "$STATE/phase4-secrets.txt" ]]; then
    local v
    while IFS= read -r v; do
      add_secret "$v"
    done < "$STATE/phase4-secrets.txt"
  fi
  local -a cnames=() places=("$JOURNAL" "$RECEIPT") unread=()
  local listing="" out cn ps_failed=0
  if command -v docker >/dev/null 2>&1; then
    # Every container of both Compose projects by label (the EPC cluster's own containers are named epc-*,
    # which no name prefix below matches), plus the label-less gate containers by name (the stand-in IdP).
    # A listing or a log that cannot be read fails the row: a scan over nothing is not a clean scan.
    out="$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' 2>/dev/null)" || ps_failed=1
    listing+="$out"$'\n'
    out="$(docker ps -a --filter "label=com.docker.compose.project=$MON_PROJECT" --format '{{.Names}}' 2>/dev/null)" || ps_failed=1
    listing+="$out"$'\n'
    out="$(docker ps -a --format '{{.Names}}' 2>/dev/null)" || ps_failed=1
    listing+="$(printf '%s\n' "$out" | grep -E "^(${PROJECT}|${MON_PROJECT}|krate)-")"$'\n'
    while IFS= read -r cn; do
      [[ -n "$cn" ]] || continue
      cnames+=("$cn")
      if docker logs "$cn" > "$STATE/docker-$cn.log" 2>&1; then
        places+=("$STATE/docker-$cn.log")
      else
        unread+=("$cn")
      fi
    done < <(printf '%s' "$listing" | sort -u)
  else
    ps_failed=1
  fi
  local mf psd
  for mf in "$OUT"/screenshots*/manifest.tsv "$OUT"/screenshots*/manifest.json; do
    [[ -f "$mf" ]] && places+=("$mf")
  done
  for psd in "$STATE"/*ps*.txt; do
    [[ -f "$psd" ]] && places+=("$psd")
  done

  local raw_without_display="$STATE/raw-without-display.log"
  awk '/Temporary password for/ {print; skip=1; next} skip {skip=0; next} {print}' "$RAW" > "$raw_without_display" 2>/dev/null || unread+=("raw log (no display)")

  local secrets_all="$STATE/secrets-all.$$.txt"
  local secrets_temp="$STATE/secrets-temp.$$.txt"
  local files_list="$STATE/scan-places.$$.txt"
  : > "$secrets_all"; chmod 600 "$secrets_all"
  : > "$secrets_temp"; chmod 600 "$secrets_temp"
  : > "$files_list"; chmod 600 "$files_list"

  local s t p
  for s in "${SECRETS[@]}"; do
    printf '%s\n' "$s" >> "$secrets_all"
  done
  for t in "${TEMP_SECRETS[@]}"; do
    printf '%s\n' "$t" >> "$secrets_temp"
  done
  for p in "${places[@]}"; do
    printf '%s\n' "$p" >> "$files_list"
  done

  local scan_err="$STATE/leak-scan.$$.err"
  local hits unreadable_n unreadable_names scan_out
  scan_out=$(python3 -I -c '
import sys, os

all_secrets = [line.strip() for line in open(sys.argv[1], encoding="utf-8", errors="replace") if len(line.strip()) >= 6]
temp_secrets = set(line.strip() for line in open(sys.argv[2], encoding="utf-8", errors="replace") if len(line.strip()) >= 6)
places = [line.strip() for line in open(sys.argv[3], encoding="utf-8", errors="replace") if line.strip()]
raw_file = sys.argv[4]
raw_no_disp = sys.argv[5]

hits = 0
unreadable = []


def mark_unreadable(name):
    unreadable.append(name)
    print(f"UNREADABLE: {name}", file=sys.stderr)


for p in places:
    try:
        content = open(p, "rb").read().decode("utf-8", "replace")
    except OSError:
        mark_unreadable(os.path.basename(p))
        continue
    for s in all_secrets:
        c = content.count(s)
        if c > 0:
            hits += c
            print(f"LEAK: secret appears in {os.path.basename(p)} x{c}", file=sys.stderr)

try:
    raw_content = open(raw_file, "rb").read().decode("utf-8", "replace")
except OSError:
    mark_unreadable("raw log")
else:
    for s in all_secrets:
        if s not in temp_secrets:
            c = raw_content.count(s)
            if c > 0:
                hits += c
                print(f"LEAK: non-temp secret appears in raw log x{c}", file=sys.stderr)

try:
    raw_nd_content = open(raw_no_disp, "rb").read().decode("utf-8", "replace")
except OSError:
    mark_unreadable("raw log (no display)")
else:
    for s in temp_secrets:
        c = raw_nd_content.count(s)
        if c > 0:
            hits += c
            print(f"LEAK: temp secret appears in raw log outside display x{c}", file=sys.stderr)

ed_auth = sys.argv[6]


def auth_label(path):
    rel = os.path.relpath(path, ed_auth) if path else "."
    return "auth/keycloak" if rel == "." else "auth/keycloak/" + rel


def walk_error(err):
    mark_unreadable(auth_label(err.filename))


for root, _dirs, files in os.walk(ed_auth, onerror=walk_error):
    for fn in files:
        fp = os.path.join(root, fn)
        try:
            content = open(fp, "rb").read().decode("utf-8", "replace")
            for s in all_secrets:
                c = content.count(s)
                if c > 0:
                    hits += c
                    print(f"LEAK: secret appears in {fp} x{c}", file=sys.stderr)
        except OSError:
            mark_unreadable(auth_label(fp))

names = sorted(set(unreadable))
print(hits, len(unreadable), ", ".join(names[:10]) + (f" (+{len(names) - 10} more)" if len(names) > 10 else ""))
' "$secrets_all" "$secrets_temp" "$files_list" "$RAW" "$raw_without_display" "$ED/auth/keycloak" 2>"$scan_err")
  if [[ -f "$scan_err" ]]; then
    cat "$scan_err" >> "$RAW"
    rm -f "$scan_err"
  fi

  rm -f "$secrets_all" "$secrets_temp" "$files_list" "$raw_without_display"
  read -r hits unreadable_n unreadable_names <<<"${scan_out:-}"
  local st gaps=""
  (( ps_failed )) && gaps+="; the container listing failed"
  (( ${#cnames[@]} )) || gaps+="; no container listed"
  (( ${#unread[@]} )) && gaps+="; logs not read: ${unread[*]}"
  [[ "${unreadable_n:-}" == "0" ]] || gaps+="; unreadable scan inputs: ${unreadable_n:-the scan did not finish}${unreadable_names:+ ($unreadable_names)}"
  (( ${#SECRETS[@]} )) || gaps+="; no secret values to search"
  [[ "${hits:-}" == "0" && -z "$gaps" ]]; st=$?
  ok_if Z4a "$slice" Z "$st" "extended leak scan over docker logs of ${#cnames[@]} containers, raw log, receipt, screenshot manifests, and ps dumps (${#SECRETS[@]} secret values searched): ${hits:-?} hits$gaps; walk: live4a 901"
}
phase4_screenshots_x4() {
  local slice="$1" viewer_json="$STATE/p4/kc-p4v.json" admin_json="$STATE/p4/kc-p4both.json"
  local disabled_json="$STATE/p4/kc-p4dis.json" nogroup_json="$STATE/p4/kc-p4nogroup.json"
  local admin_user="p4both"
  if [[ -f "$STATE/p4/kc-p4a.json" ]]; then
    admin_json="$STATE/p4/kc-p4a.json"
    admin_user="p4a"
  fi
  local outdir="$OUT/screenshots-perses" gateway st n sha_ok f s rest
  local pw_v totp_v pw_a totp_a pw_d pw_n totp_n
  if ! $SCREENSHOTS; then
    phase4_stub X4 "$slice" X "not run: --no-screenshots (X4 is outside the required inventory)"
    return
  fi
  if [[ ! -f "$viewer_json" || ! -f "$admin_json" || ! -f "$disabled_json" || ! -f "$nogroup_json" ]]; then
    phase4_stub X4 "$slice" X "the helper's enrolment state files are missing (kc-{p4v,${admin_user},p4dis,p4nogroup}.json): slice setup did not enrol required users"
    return
  fi
  if ! docker image inspect krate-harness/playwright:1.60.0 >/dev/null 2>&1; then
    printf 'FROM mcr.microsoft.com/playwright:v1.60.0-noble\nRUN npm i -g playwright@1.60.0\nENV NODE_PATH=/usr/lib/node_modules\n' | docker build -q -t krate-harness/playwright:1.60.0 - >/dev/null 2>&1 \
      || { record X4 "$slice" X FAIL "harness image krate-harness/playwright:1.60.0 could not be built"; return; }
  fi
  gateway="$(docker run --rm --add-host host.docker.internal:host-gateway "$PG_IMAGE" sh -c 'getent ahostsv4 host.docker.internal | awk "{print \$1; exit}"' 2>/dev/null | tr -d '[:space:]')"
  if [[ -z "$gateway" ]]; then
    record X4 "$slice" X FAIL "cannot resolve the Docker host gateway (host.docker.internal) from a container"
    return
  fi
  # After V24's daemon restart the guard can still be converging when the V rows
  # end: the story's first page is then a gateway 500 (auth_request to
  # perses-sync refused). Wait for the serving chain: an anonymous GET is
  # challenged (302/401), never a 500.
  local chain_t0 chain_code
  chain_t0="$(date +%s)"
  while true; do
    chain_code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${BASE_HOST}:${PERSES_GATE_PORT}:127.0.0.1" \
      "https://${BASE_HOST}:${PERSES_GATE_PORT}/" 2>/dev/null || true)"
    [[ "$chain_code" =~ ^[0-9]+$ ]] || chain_code=000
    if [[ "$chain_code" == 302 || "$chain_code" == 401 ]]; then break; fi
    if [[ $(($(date +%s) - chain_t0)) -ge 180 ]]; then
      record X4 "$slice" X FAIL "perses gateway still HTTP $chain_code after 180s (story needs the 302/401 challenge)"
      return
    fi
    sleep 5
  done
  mkdir -p "$outdir" && chmod 755 "$outdir"

  pw_v="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$viewer_json" 2>/dev/null)"
  totp_v="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["totp"])' "$viewer_json" 2>/dev/null)"
  pw_a="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$admin_json" 2>/dev/null)"
  totp_a="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["totp"])' "$admin_json" 2>/dev/null)"
  pw_d="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$disabled_json" 2>/dev/null)"
  pw_n="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$nogroup_json" 2>/dev/null)"
  totp_n="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["totp"])' "$nogroup_json" 2>/dev/null)"

  for s in "$pw_v" "$totp_v" "$pw_a" "$totp_a" "$pw_d" "$pw_n" "$totp_n"; do
    [[ -n "$s" ]] && add_secret "$s"
  done

  export GATE_VIEWER_PASSWORD="$pw_v" GATE_VIEWER_TOTP="$totp_v"
  export GATE_ADMIN_PASSWORD="$pw_a" GATE_ADMIN_TOTP="$totp_a"
  export GATE_DISABLED_PASSWORD="$pw_d"
  export GATE_NOGROUP_PASSWORD="$pw_n" GATE_NOGROUP_TOTP="$totp_n"

  cap docker run --rm --add-host host.docker.internal:host-gateway -v "$outdir:/out" -v "$GATE_DIR:/gate:ro" \
    -e GATE_VIEWER_PASSWORD -e GATE_VIEWER_TOTP -e GATE_ADMIN_PASSWORD -e GATE_ADMIN_TOTP \
    -e GATE_DISABLED_PASSWORD -e GATE_NOGROUP_PASSWORD -e GATE_NOGROUP_TOTP -e PW_MODULES=/usr/lib/node_modules \
    krate-harness/playwright:1.60.0 node /gate/screenshots-perses.mjs \
    --host "$BASE_HOST" --perses-base "https://${BASE_HOST}:${PERSES_GATE_PORT}" --out /out \
    --viewer-user p4v --admin-user "$admin_user" --disabled-user p4dis --nogroup-user p4nogroup --resolve-to "$gateway"
  st=$?

  unset GATE_VIEWER_PASSWORD GATE_VIEWER_TOTP GATE_ADMIN_PASSWORD GATE_ADMIN_TOTP
  unset GATE_DISABLED_PASSWORD GATE_NOGROUP_PASSWORD GATE_NOGROUP_TOTP

  n="$(find "$outdir" -name '*.png' | wc -l | tr -d ' ')"
  sha_ok=0
  if [[ -f "$outdir/manifest.tsv" ]]; then
    sha_ok=1
    while IFS=$'\t' read -r f s rest; do
      [[ "$f" == file || -z "$f" || ! -f "$outdir/$f" ]] && continue
      printf '%s  %s\n' "$s" "$outdir/$f" | { shasum -a 256 -c - >/dev/null 2>&1 || sha256sum -c - >/dev/null 2>&1; } || sha_ok=0
    done < "$outdir/manifest.tsv"
  fi
  [[ $st -eq 0 && "$n" == 6 && "$CAP" == *"STORY OK"* && $sha_ok -eq 1 ]]; s=$?
  ok_if X4 "$slice" X "$s" "$n screenshots in ${outdir##*/}/, every manifest.tsv sha256 verified=$sha_ok, story exit=$st: $(printf '%s' "$CAP" | grep -E '^STORY' | tail -1 | cut -c1-120)"
}
phase4_leak_scan_z4b() {
  local slice="$1"
  section "Z4b: extended secret-leak scan over docker logs of every container, raw gate log, receipt, screenshot manifests, and ps dumps"
  if [[ -f "$STATE/phase4-secrets.txt" ]]; then
    local v
    while IFS= read -r v; do
      add_secret "$v"
    done < "$STATE/phase4-secrets.txt"
  fi
  local -a cnames=() places=("$JOURNAL" "$RECEIPT") unread=()
  local listing="" out cn ps_failed=0
  if command -v docker >/dev/null 2>&1; then
    # Every container of both Compose projects by label (the EPC cluster's own containers are named epc-*,
    # which no name prefix below matches), plus the label-less gate containers by name (the stand-in IdP).
    # A listing or a log that cannot be read fails the row: a scan over nothing is not a clean scan.
    out="$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' 2>/dev/null)" || ps_failed=1
    listing+="$out"$'\n'
    out="$(docker ps -a --filter "label=com.docker.compose.project=$MON_PROJECT" --format '{{.Names}}' 2>/dev/null)" || ps_failed=1
    listing+="$out"$'\n'
    out="$(docker ps -a --format '{{.Names}}' 2>/dev/null)" || ps_failed=1
    listing+="$(printf '%s\n' "$out" | grep -E "^(${PROJECT}|${MON_PROJECT}|krate)-")"$'\n'
    while IFS= read -r cn; do
      [[ -n "$cn" ]] || continue
      cnames+=("$cn")
      if docker logs "$cn" > "$STATE/docker-$cn.log" 2>&1; then
        places+=("$STATE/docker-$cn.log")
      else
        unread+=("$cn")
      fi
    done < <(printf '%s' "$listing" | sort -u)
  else
    ps_failed=1
  fi
  local mf psd
  for mf in "$OUT"/screenshots*/manifest.tsv "$OUT"/screenshots*/manifest.json; do
    [[ -f "$mf" ]] && places+=("$mf")
  done
  for psd in "$STATE"/*ps*.txt; do
    [[ -f "$psd" ]] && places+=("$psd")
  done

  local raw_without_display="$STATE/raw-without-display.log"
  awk '/Temporary password for/ {print; skip=1; next} skip {skip=0; next} {print}' "$RAW" > "$raw_without_display" 2>/dev/null || unread+=("raw log (no display)")

  local secrets_all="$STATE/secrets-all.$$.txt"
  local secrets_temp="$STATE/secrets-temp.$$.txt"
  local files_list="$STATE/scan-places.$$.txt"
  : > "$secrets_all"; chmod 600 "$secrets_all"
  : > "$secrets_temp"; chmod 600 "$secrets_temp"
  : > "$files_list"; chmod 600 "$files_list"

  local s t p
  for s in "${SECRETS[@]}"; do
    printf '%s\n' "$s" >> "$secrets_all"
  done
  for t in "${TEMP_SECRETS[@]}"; do
    printf '%s\n' "$t" >> "$secrets_temp"
  done
  for p in "${places[@]}"; do
    printf '%s\n' "$p" >> "$files_list"
  done

  local scan_err="$STATE/leak-scan-z4b.$$.err"
  local hits unreadable_n unreadable_names scan_out
  scan_out=$(python3 -I -c '
import sys, os

all_secrets = [line.strip() for line in open(sys.argv[1], encoding="utf-8", errors="replace") if len(line.strip()) >= 6]
temp_secrets = set(line.strip() for line in open(sys.argv[2], encoding="utf-8", errors="replace") if len(line.strip()) >= 6)
places = [line.strip() for line in open(sys.argv[3], encoding="utf-8", errors="replace") if line.strip()]
raw_file = sys.argv[4]
raw_no_disp = sys.argv[5]

banned_patterns = [
    "id_token_hint=", "jwtPayload=", "jwtSignature=", "jwtRefreshToken=",
    "_oauth2_proxy=", "/oauth2/callback?code="
]

hits = 0
unreadable = []


def mark_unreadable(name):
    unreadable.append(name)
    print(f"UNREADABLE: {name}", file=sys.stderr)


for p in places:
    try:
        content = open(p, "rb").read().decode("utf-8", "replace")
    except OSError:
        mark_unreadable(os.path.basename(p))
        continue
    for s in all_secrets:
        c = content.count(s)
        if c > 0:
            hits += c
            print(f"LEAK: secret appears in {os.path.basename(p)} x{c}", file=sys.stderr)
    if "docker-" in os.path.basename(p) or p.endswith(".log"):
        for bp in banned_patterns:
            c = content.count(bp)
            if c > 0:
                hits += c
                print(f"LEAK: banned pattern {bp} appears in {os.path.basename(p)} x{c}", file=sys.stderr)

try:
    raw_content = open(raw_file, "rb").read().decode("utf-8", "replace")
except OSError:
    mark_unreadable("raw log")
else:
    for s in all_secrets:
        if s not in temp_secrets:
            c = raw_content.count(s)
            if c > 0:
                hits += c
                print(f"LEAK: non-temp secret appears in raw log x{c}", file=sys.stderr)

try:
    raw_nd_content = open(raw_no_disp, "rb").read().decode("utf-8", "replace")
except OSError:
    mark_unreadable("raw log (no display)")
else:
    for s in temp_secrets:
        c = raw_nd_content.count(s)
        if c > 0:
            hits += c
            print(f"LEAK: temp secret appears in raw log outside display x{c}", file=sys.stderr)

ed_auth = sys.argv[6]


def auth_label(path):
    rel = os.path.relpath(path, ed_auth) if path else "."
    return "auth/keycloak" if rel == "." else "auth/keycloak/" + rel


def walk_error(err):
    mark_unreadable(auth_label(err.filename))


for root, _dirs, files in os.walk(ed_auth, onerror=walk_error):
    for fn in files:
        fp = os.path.join(root, fn)
        try:
            content = open(fp, "rb").read().decode("utf-8", "replace")
            for s in all_secrets:
                c = content.count(s)
                if c > 0:
                    hits += c
                    print(f"LEAK: secret appears in {fp} x{c}", file=sys.stderr)
        except OSError:
            mark_unreadable(auth_label(fp))

names = sorted(set(unreadable))
print(hits, len(unreadable), ", ".join(names[:10]) + (f" (+{len(names) - 10} more)" if len(names) > 10 else ""))
' "$secrets_all" "$secrets_temp" "$files_list" "$RAW" "$raw_without_display" "$ED/auth/keycloak" 2>"$scan_err")
  if [[ -f "$scan_err" ]]; then
    cat "$scan_err" >> "$RAW"
    rm -f "$scan_err"
  fi

  rm -f "$secrets_all" "$secrets_temp" "$files_list" "$raw_without_display"
  read -r hits unreadable_n unreadable_names <<<"${scan_out:-}"
  local st gaps=""
  (( ps_failed )) && gaps+="; the container listing failed"
  (( ${#cnames[@]} )) || gaps+="; no container listed"
  (( ${#unread[@]} )) && gaps+="; logs not read: ${unread[*]}"
  [[ "${unreadable_n:-}" == "0" ]] || gaps+="; unreadable scan inputs: ${unreadable_n:-the scan did not finish}${unreadable_names:+ ($unreadable_names)}"
  (( ${#SECRETS[@]} )) || gaps+="; no secret values to search"
  [[ "${hits:-}" == "0" && -z "$gaps" ]]; st=$?
  ok_if Z4b "$slice" Z "$st" "extended leak scan over docker logs of ${#cnames[@]} containers, raw log, receipt, screenshot manifests, and ps dumps (${#SECRETS[@]} secret values searched): ${hits:-?} hits$gaps"
}
phase4_row_w1() {
  local slice="$1"
  section "W1: published ports census (perses-gateway 0.0.0.0:PERSES_PORT; prometheus/loki 127.0.0.1; grafana per U21a; no host port for the other 14 services)"
  local pg_cid prom_cid loki_cid graf_cid
  pg_cid="$(mon_cid perses-gateway)"
  prom_cid="$(mon_cid prometheus)"
  loki_cid="$(mon_cid loki)"
  graf_cid="$(mon_cid grafana)"

  if [[ -z "$pg_cid" || -z "$prom_cid" || -z "$loki_cid" || -z "$graf_cid" ]]; then
    phase4_stub W1 "$slice" W "precondition: missing required monitoring containers for ports census"
    return
  fi

  # shellcheck disable=SC2016  # Go template, not shell expansion
  local get_ports_tpl='{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}'
  local pg_ports prom_ports loki_ports graf_ports
  pg_ports="$(docker inspect -f "$get_ports_tpl" "$pg_cid" 2>/dev/null | xargs)"
  prom_ports="$(docker inspect -f "$get_ports_tpl" "$prom_cid" 2>/dev/null | xargs)"
  loki_ports="$(docker inspect -f "$get_ports_tpl" "$loki_cid" 2>/dev/null | xargs)"
  graf_ports="$(docker inspect -f "$get_ports_tpl" "$graf_cid" 2>/dev/null | xargs)"

  local pg_ok=0
  if [[ "$pg_ports" == *"0.0.0.0:$PERSES_GATE_PORT"* || "$pg_ports" == *":::$PERSES_GATE_PORT"* || "$pg_ports" == *":$PERSES_GATE_PORT"* ]]; then
    pg_ok=1
  fi

  local prom_ok=0
  if [[ "$prom_ports" == *"127.0.0.1:$PROM_GATE_PORT"* && "$prom_ports" != *"0.0.0.0:"* ]]; then
    prom_ok=1
  fi

  local loki_ok=0
  if [[ "$loki_ports" == *"127.0.0.1:$LOKI_GATE_PORT"* && "$loki_ports" != *"0.0.0.0:"* ]]; then
    loki_ok=1
  fi

  local graf_ok=0
  if [[ "$graf_ports" == *"127.0.0.1:$GRAFANA_GATE_PORT"* && "$graf_ports" != *"0.0.0.0:"* ]]; then
    graf_ok=1
  fi

  local -a other_services=(
    alertmanager victorialogs kafka-exporter node-exporter fluent-bit
    perses oauth2-proxy perses-sync loki-gateway idp-wait monitoring-init
    perses-migrate perses-seed log-discovery
  )
  local -a bad_services=()
  local svc cid ports
  for svc in "${other_services[@]}"; do
    cid="$(mon_cid "$svc")"
    [[ -n "$cid" ]] || continue
    ports="$(docker inspect -f "$get_ports_tpl" "$cid" 2>/dev/null | xargs)"
    if [[ -n "$ports" ]]; then
      bad_services+=("$svc($ports)")
    fi
  done

  local st
  [[ $pg_ok -eq 1 && $prom_ok -eq 1 && $loki_ok -eq 1 && $graf_ok -eq 1 && ${#bad_services[@]} -eq 0 ]]; st=$?
  ok_if W1 "$slice" W "$st" "published ports: perses-gateway [$pg_ports], prometheus [$prom_ports], loki [$loki_ports], grafana [$graf_ports]; 14 unpublished services bad=[${bad_services[*]}]"
}
phase4_row_w2() {
  local slice="$1"
  section "W2: Prometheus lifecycle API off (POST/PUT /-/reload and /-/quit -> 403) + in-place reload walk"
  local prom_cid
  prom_cid="$(mon_cid prometheus)"
  if [[ -z "$prom_cid" ]]; then
    phase4_stub W2 "$slice" W "precondition: missing prometheus container"
    return
  fi

  local lg_cid
  lg_cid="$(mon_cid loki-gateway)"
  local st_reload_post st_reload_put st_quit
  if [[ -n "$lg_cid" ]]; then
    st_reload_post="$(docker exec "$lg_cid" curl -s -o /dev/null -w "%{http_code}" -X POST http://prometheus:9090/-/reload 2>/dev/null || echo 0)"
    st_reload_put="$(docker exec "$lg_cid" curl -s -o /dev/null -w "%{http_code}" -X PUT http://prometheus:9090/-/reload 2>/dev/null || echo 0)"
    st_quit="$(docker exec "$lg_cid" curl -s -o /dev/null -w "%{http_code}" -X POST http://prometheus:9090/-/quit 2>/dev/null || echo 0)"
  else
    local net="${MON_PROJECT}_monitoring"
    st_reload_post="$(docker run --rm --network "$net" "$NGINX_IMAGE" curl -s -o /dev/null -w "%{http_code}" -X POST http://prometheus:9090/-/reload 2>/dev/null || echo 0)"
    st_reload_put="$(docker run --rm --network "$net" "$NGINX_IMAGE" curl -s -o /dev/null -w "%{http_code}" -X PUT http://prometheus:9090/-/reload 2>/dev/null || echo 0)"
    st_quit="$(docker run --rm --network "$net" "$NGINX_IMAGE" curl -s -o /dev/null -w "%{http_code}" -X POST http://prometheus:9090/-/quit 2>/dev/null || echo 0)"
  fi
  local lifecycle_403=0
  [[ "$st_reload_post" == 403 && "$st_reload_put" == 403 && "$st_quit" == 403 ]] && lifecycle_403=1

  local prom_url="http://127.0.0.1:$PROM_GATE_PORT"
  local ts_before ts_after
  ts_before="$(curl -s "$prom_url/metrics" 2>/dev/null | grep -E '^prometheus_config_last_reload_success_timestamp_seconds' | awk '{print $2}' || echo 0)"
  local id_before started_before
  id_before="$(docker inspect -f '{{.Id}}' "$prom_cid" 2>/dev/null)"
  started_before="$(docker inspect -f '{{.State.StartedAt}}' "$prom_cid" 2>/dev/null)"

  local rc_valid
  "$KRATE" monitor reload >/dev/null 2>&1; rc_valid=$?
  sleep 2
  ts_after="$(curl -s "$prom_url/metrics" 2>/dev/null | grep -E '^prometheus_config_last_reload_success_timestamp_seconds' | awk '{print $2}' || echo 0)"
  local id_after started_after
  id_after="$(docker inspect -f '{{.Id}}' "$prom_cid" 2>/dev/null)"
  started_after="$(docker inspect -f '{{.State.StartedAt}}' "$prom_cid" 2>/dev/null)"

  local valid_reload_ok=0
  local ts_increased=1
  if python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[2]) > float(sys.argv[1]) else 1)' "${ts_before:-0}" "${ts_after:-0}" 2>/dev/null; then
    ts_increased=0
  fi
  if [[ $rc_valid -eq 0 && $ts_increased -eq 0 && "$id_before" == "$id_after" && "$started_before" == "$started_after" ]]; then
    valid_reload_ok=1
  fi

  local cfg_file="$MON_DIR/prometheus/prometheus.yml"
  local cfg_bak="$STATE/prometheus.yml.bak"
  local cfg_tmp="$STATE/prometheus.yml.bak.tmp"
  if ! cp "$cfg_file" "$cfg_tmp"; then
    rm -f "$cfg_tmp"
    record W2 "$slice" W FAIL "could not back up the Prometheus configuration before the invalid-reload probe"
    return
  fi
  if ! mv "$cfg_tmp" "$cfg_bak"; then
    rm -f "$cfg_tmp"
    record W2 "$slice" W FAIL "could not finalize the Prometheus configuration backup"
    return
  fi
  W2_BACKUP_OWNED=true
  if ! printf '\ninvalid_yaml: [unclosed\n' >> "$cfg_file"; then
    restore_prometheus_config || true
    record W2 "$slice" W FAIL "could not write the temporary invalid Prometheus configuration"
    return
  fi

  local rc_invalid
  "$KRATE" monitor reload >/dev/null 2>&1; rc_invalid=$?
  sleep 2
  local reload_success_metric ans_health
  reload_success_metric="$(curl -s "$prom_url/metrics" 2>/dev/null | grep -E '^prometheus_config_last_reload_successful' | awk '{print $2}' || echo 1)"
  ans_health="$(curl -sk -o /dev/null -w '%{http_code}' "$prom_url/-/healthy" 2>/dev/null || echo 0)"

  restore_prometheus_config || return
  "$KRATE" monitor reload >/dev/null 2>&1 || true

  local invalid_reload_ok=0
  if [[ $rc_invalid -ne 0 && "${reload_success_metric%.*}" == 0 && "$ans_health" == 200 ]]; then
    invalid_reload_ok=1
  fi

  local st
  [[ $lifecycle_403 -eq 1 && $valid_reload_ok -eq 1 && $invalid_reload_ok -eq 1 ]]; st=$?
  ok_if W2 "$slice" W "$st" "Prometheus lifecycle API off (POST/PUT reload $st_reload_post/$st_reload_put, quit $st_quit); valid reload rc=$rc_valid ts $ts_before->$ts_after (same container); invalid edit reload rc=$rc_invalid metric=$reload_success_metric health=$ans_health"
}
phase4_row_w3() {
  local slice="$1"
  section "W3: foreign-source probe (macOS LAN checks (a)+(b) / Linux p4probe netns (a)-(e))"
  if [[ "$(uname -s)" == Darwin ]]; then
    local lan_ip
    lan_ip="$(ipconfig getifaddr en0 2>/dev/null || true)"
    [[ -n "$lan_ip" ]] || lan_ip="$(ipconfig getifaddr en1 2>/dev/null || true)"
    [[ -n "$lan_ip" ]] || lan_ip="$(netstat -rn -f inet 2>/dev/null | awk '/default/{print $2}' | head -1)"
    if [[ -z "$lan_ip" ]]; then
      record W3 "$slice" W FAIL "cannot determine macOS LAN IP address"
      return
    fi

    local rc_a
    rc_a="$(curl -sk -o /dev/null -m 5 -w '%{http_code}' "https://$lan_ip:$PERSES_GATE_PORT/" 2>/dev/null || echo 0)"
    local pos_ok=0
    [[ "$rc_a" =~ ^(200|302|401|403|404)$ ]] && pos_ok=1

    local p rc_p refused_count=0 total_ports=0
    local -a loop_ports=("$PROM_GATE_PORT" "$LOKI_GATE_PORT" "$GRAFANA_GATE_PORT")
    for p in "${loop_ports[@]}"; do
      total_ports=$((total_ports + 1))
      curl -s -o /dev/null -m 5 "http://$lan_ip:$p/" 2>/dev/null; rc_p=$?
      if [[ $rc_p -eq 7 || $rc_p -eq 28 ]]; then
        refused_count=$((refused_count + 1))
      fi
    done

    curl -s -o /dev/null -m 5 "http://[::1]:$PROM_GATE_PORT/" 2>/dev/null || true

    local st
    [[ $pos_ok -eq 1 && $refused_count -eq $total_ports ]]; st=$?
    ok_if W3 "$slice" W "$st" "macOS LAN probe: positive control perses-gateway reachable (HTTP $rc_a); loopback ports ($refused_count/$total_ports refused with rc 7/28 via LAN $lan_ip)"
  elif [[ "$(uname -s)" == Linux ]]; then
    local w3_script="$GATE_DIR/phase4_w3.sh"
    if [[ -f "$w3_script" ]]; then
      local cap_w3 st_w3 result_w3
      cap_w3="$(W1X_POSITIVE_PORT="$PERSES_GATE_PORT" W1X_POSITIVE_SCHEME=https \
        W1X_LOOPBACK_PORTS="$PROM_GATE_PORT $LOKI_GATE_PORT $GRAFANA_GATE_PORT" \
        W3_CLUSTER_PROJECT="$PROJECT" W3_MONITOR_PROJECT="$MON_PROJECT" W3_PUBLIC_HOST="$PUBLIC_HOST" \
        bash "$w3_script" 2>&1)"; st_w3=$?
      log "$cap_w3"
      result_w3="$(printf '%s\n' "$cap_w3" | grep '^RESULT W3 ' | tail -1)"
      if [[ $st_w3 -eq 0 && "$result_w3" == 'RESULT W3 PASS '* ]]; then
        record W3 "$slice" W PASS "Linux p4probe netns: ${result_w3#RESULT W3 PASS }"
      elif [[ $st_w3 -eq 2 && "$result_w3" == 'RESULT W3 NOT_RUN '* ]]; then
        record W3 "$slice" W NOT_RUN "Linux p4probe netns: ${result_w3#RESULT W3 NOT_RUN }"
      else
        record W3 "$slice" W FAIL "Linux p4probe netns: ${result_w3:-script exit $st_w3 without a result}; see run.log"
      fi
    else
      record W3 "$slice" W FAIL "missing tracked scripts/gate/phase4_w3.sh"
    fi
  else
    record W3 "$slice" W NOT_RUN "unsupported platform: $(uname -s)"
  fi
}
agent_request() { # row timeout_s: the runner's {schema,id,row,nonce} request to the Mac agent
  # (TOPOFIX F4): the row table, the fixed arguments, the certificate and the budget are the
  # agent's; this runner only names the row. CAP carries the response JSON. The response echoes
  # the rendezvous nonce by protocol (it binds the run); the echo must NOT reach the raw log or
  # the row's response copy, so it is redacted here before either store sees it (review S4).
  # Review T01: browser_remote.py announces the request on stderr, also on success, so CAP takes ONLY its stdout (the response
  # JSON) and the diagnostics go to CAP_ERR and the raw log, never into the saved response.
  local rc err_file="$STATE/agent-request.err"
  CAP="$(python3 -I "$GATE_DIR/browser_remote.py" request --rendezvous "$RENDEZVOUS" --nonce "$REND_NONCE" --row "$1" --timeout "$2" 2>"$err_file")"; rc=$?
  CAP_ERR="$(cat "$err_file" 2>/dev/null)"; rm -f "$err_file"
  if [[ -n "$REND_NONCE" ]]; then CAP="${CAP//$REND_NONCE/<rendezvous-nonce-redacted>}"; CAP_ERR="${CAP_ERR//$REND_NONCE/<rendezvous-nonce-redacted>}"; fi
  printf -- '--- agent request %s (exit %s)\n%s\n--- agent request %s stderr\n%s\n' "$1" "$rc" "$CAP" "$1" "$CAP_ERR" >> "$RAW"
  return $rc
}
tail_chars() { # n text: the LAST n characters of text, behind `...` when it was cut (`${s: -n}` is empty when s is shorter than n)
  local n="$1" s="$2"
  if (( ${#s} > n )); then printf '...%s' "${s: -n}"; else printf '%s' "$s"; fi
}
agent_delivered_dir() { # row: the guest folder the agent copies the row's evidence into (one
  # limactl copy --backend=scp -r invocation per response; M1 observed the flag)
  printf '%s/agent-out/w%s' "$(dirname "$RENDEZVOUS")" "${1#W}"
}

w5_published_any_ports() { # prints `service=port` for every any-address published port of the running Compose projects
  # Review T02: .Label is a `docker ps` formatting helper, not a method of the object `docker inspect` renders ("Label is not a
  # method but has arguments"), so the service label is read from .Config.Labels, and a failed inspect (or no container at all)
  # is an error (rc 1 and the reason on stdout), never a silently smaller derived set.
  # shellcheck disable=SC2016  # the Go template is literal
  local tpl='{{index .Config.Labels "com.docker.compose.service"}}|{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}'
  local cid line svc bind failed="" inspected=0
  while IFS= read -r cid; do
    [[ -z "$cid" ]] && continue
    if ! line="$(docker inspect -f "$tpl" "$cid" 2>>"$RAW")"; then failed+="$cid "; continue; fi
    inspected=$((inspected+1))
    svc="${line%%|*}"
    # shellcheck disable=SC2086  # the bind list is space-separated single tokens
    for bind in ${line#*|}; do
      case "$bind" in
        0.0.0.0:* | "::":* | :*) printf '%s=%s\n' "$svc" "${bind##*:}" ;;
      esac
    done
  done < <({ docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null
             docker ps -aq --filter "label=com.docker.compose.project=$MON_PROJECT" 2>/dev/null; } | sort -u)
  if [[ -n "$failed" ]] || (( inspected == 0 )); then
    printf 'docker inspect failed for [%s] and %d container(s) were inspected (the error is in the raw log)\n' "${failed:-none}" "$inspected"
    return 1
  fi
}
phase4_row_w5() {
  local slice="$1"
  section "W5: published-port surface from the Mac over the fixture's NIC address (derived expected set, control port 111, three outcomes, TCP only)"
  # The expected set is derived at run time from the fixture's own runtime state, never from
  # README line numbers (TOPOFIX F6): the any-address published ports of the running Compose
  # projects plus sshd's 22. Three outcomes (open / refused / rejected; M3 and the M4 sweep
  # saw both refusal shapes), the control port 111, and the guest's ss tables beside it.
  local derived svc port
  local any_ports="" ports_svc=""
  if ! derived="$(w5_published_any_ports)"; then
    record W5 "$slice" W FAIL "the derived expected set cannot be built: $derived"
    return
  fi
  while IFS='=' read -r svc port; do
    [[ -n "$port" ]] || continue
    any_ports+="$port "; ports_svc+="$svc=$port "
  done <<<"$derived"
  local expected_csv docker_csv
  # shellcheck disable=SC2086  # the CSV is built from the split port words
  expected_csv="$(printf '%s\n' $any_ports 22 | LC_ALL=C sort -n -u | paste -s -d, -)"
  # TOPOFIX2 G5: the docker-published set alone, WITHOUT sshd's 22. The IPv4 open-set equality uses the set
  # with 22; the IPv6 rule fails only a docker-published port that is open over IPv6, because sshd's own 22
  # answers over IPv6 by design (M4 point 4) and is the positive control of that pass.
  # shellcheck disable=SC2086  # the CSV is built from the split port words
  docker_csv="$(printf '%s\n' $any_ports | LC_ALL=C sort -n -u | paste -s -d, -)"
  local ss_listeners ss_udp fw_state
  ss_listeners="$(ss -ltnH 2>/dev/null | awk '{print $4}' | tr '\n' ' ' | cut -c1-240)"
  ss_udp="$(ss -lunH 2>/dev/null | awk '{print $4}' | tr '\n' ' ' | cut -c1-120)"
  # shellcheck disable=SC2086
  if ! fw_state="$( { sudo -n firewall-cmd --state 2>/dev/null || firewall-cmd --state 2>/dev/null; } | grep -E '^(running|not running)$' | head -1)"; then fw_state="firewalld not answerable"; fi
  # The Mac side: one {schema,id,row,nonce} request (F4); the agent owns the sweep's fixed
  # arguments, the certificate and the budget, and delivers the result file back (one
  # limactl copy --backend=scp -r invocation per response).
  local agent_rc=0
  agent_request W5 1500 || agent_rc=$?
  if (( agent_rc != 0 )); then
    record W5 "$slice" W FAIL "the W5 agent request failed (browser_remote rc=$agent_rc: the agent holds the refusal or the timeout; the Mac agent.log names it): $(tail_chars 300 "$CAP_ERR")${CAP:+ | stdout: ${CAP:0:300}}"
    return
  fi
  if [[ "$CAP" != *'"exit"'* ]]; then
    record W5 "$slice" W FAIL "the agent response is not the expected JSON (browser_remote printed: ${CAP:0:200})"
    return
  fi
  printf '%s\n' "$CAP" > "$STATE/w5-agent-response.json" && chmod 600 "$STATE/w5-agent-response.json"
  local result_file evidence rc_eval breaches
  result_file="$(agent_delivered_dir W5)/w5-result.json"
  if [[ ! -f "$result_file" ]]; then
    record W5 "$slice" W FAIL "the W5 result file did not arrive under $(agent_delivered_dir W5) (deliveries sit beside the rendezvous, nonce-bound)"
    return
  fi
  rc_eval=0
  evidence="$(W5_EXPECTED="$expected_csv" W5_DOCKER="$docker_csv" W5_VM_G6="${VM_G6:-}" python3 -I - "$result_file" "$fw_state" "$STATE/w5-agent-response.json" <<'PYW5' 2>>"$RAW"
import hashlib, json, os, re, sys

result_file, fw_state, response_file = sys.argv[1], sys.argv[2], sys.argv[3]
bad = []
note = []
try:
    result_bytes = open(result_file, "rb").read()   # one read: the bytes that are hashed are the bytes that are evaluated
    r = json.loads(result_bytes.decode("utf-8"))
except (OSError, ValueError) as exc:
    sys.stderr.write("the W5 result file is not readable/JSON: %s\n" % exc)
    sys.exit(1)
try:
    envelope = json.load(open(response_file, "r", encoding="utf-8"))
except (OSError, ValueError) as exc:
    sys.stderr.write("the saved W5 agent response is not readable/JSON: %s\n" % exc)
    sys.exit(1)
# Review R1: the result file on the guest must be the one THIS response delivered. The agent lists every file it delivered with its
# sha256 (files[]) in the nonce-bound response; a file under the delivery folder that is not that listed one (an earlier run's result
# that scp -r left in place, a foreign file) decides nothing: the row fails closed before any value of the file is evaluated.
result_sha = hashlib.sha256(result_bytes).hexdigest()
listed = [f for f in (envelope.get("files") or []) if isinstance(f, dict) and f.get("name") == "w5-result.json"]
if len(listed) != 1 or listed[0].get("sha256") != result_sha:
    if len(listed) != 1:
        why = "the agent response lists %d w5-result.json entries in files[] (exactly one is required), so the delivered file cannot be tied to this run" % len(listed)
    else:
        why = "the delivered w5-result.json (sha256 %s) is not the file this agent response lists (sha256 %s): a stale or foreign result is not evaluated" % (result_sha[:12], str(listed[0].get("sha256"))[:12])
    print("breaches=1")
    print("BREACH %s" % why)
    sys.exit(1)
if not (r.get("swept") or {}).get("tcpOnly"):
    bad.append("the sweep is not TCP-only as the row states")
counts = r.get("counts") or {}
open_set = sorted(int(p) for p in (r.get("open") or []) if str(p).isdigit())
spot_by_port = {int(s["port"]): s for s in (r.get("spot") or []) if str(s.get("port", "")).isdigit()}
cert = r.get("cert") or {}
v6entries = (r.get("v6") or {}).get("ports") or []
v6 = r.get("v6") or {}
v6_addr = v6.get("address", "")
v6_class = v6.get("addressClass", "")
expected = sorted(int(p) for p in re.findall(r"\d+", os.environ.get("W5_EXPECTED", "")))
docker_published = sorted(int(p) for p in re.findall(r"\d+", os.environ.get("W5_DOCKER", "")))
vm_g6 = os.environ.get("W5_VM_G6", "")
if open_set != expected:
    bad.append("observed open set [%s] != derived set [%s]" % (",".join(map(str, open_set)), ",".join(map(str, expected))))
else:
    note.append("observed open set equals the derived set [%s]" % ",".join(map(str, open_set)))
fw_running = fw_state == "running"
if 111 in expected:
    note.append("111 is in the derived set (an operator published it): no firewall control this run")
else:
    o111 = spot_by_port.get(111, {}).get("outcome", "not-swept")
    if fw_running and o111 not in ("refused", "rejected"):
        bad.append("control port 111 is %s with firewalld running (its zone is not applied to lima0; expected refused/rejected)" % o111)
    elif not fw_running:
        note.append("111=%s; no firewall control available (firewalld state: %s)" % (o111, fw_state))
    else:
        note.append("control port 111 refused/rejected as the zone requires (%s)" % o111)
for port in sorted(spot_by_port):
    if port in expected or port == 111:
        continue
    outcome = spot_by_port[port].get("outcome")
    if outcome not in ("refused", "rejected", "timeout"):
        bad.append("undocumented spot port %d is %s, expected refused/rejected/timeout" % (port, outcome))
if not cert:
    note.append("no TLS pin in the result (the agent must pass --cert for the 443 positive)")
elif not cert.get("authorized"):
    bad.append("the 443 TLS pin shows authorized=false (%s)" % cert.get("server"))
else:
    note.append("443 TLS authorized against the pinned certificate (%s, %s)" % (cert.get("protocol"), cert.get("sha256")))
v6_outcome = {}
for p in v6entries:
    try:
        port = int(p.get("port"))
    except (TypeError, ValueError):
        continue
    v6_outcome[port] = p.get("outcome")
    if p.get("outcome") not in ("open", "refused", "rejected", "timeout"):
        bad.append("IPv6 probe of port %d was inconclusive (%s): an unroutable or unscoped probe proves no filtering" % (port, p.get("outcome")))
    if port in docker_published and p.get("outcome") == "open":
        bad.append("docker-published port %d is open over IPv6 (lab8 N11a and the M4 sweep observed the [::] docker-proxy path filtered by firewalld's zone)" % port)
if vm_g6:
    # sshd's 22 is the positive control: with a global address in the hello the IPv6 pass must reach the guest at all
    if v6_outcome.get(22, "not-swept") != "open":
        bad.append("IPv6 positive control: sshd's 22 did not answer over IPv6 (%s)" % v6_outcome.get(22, "not-swept"))
    else:
        note.append("22 answers over IPv6 (sshd; M4)")
# Review T16: mac_leak_scan belongs to the agent's response envelope, not to w5-result.json (probe.mjs never writes it there);
# a missing or malformed scan is a breach, a scan with hits too.
leak = envelope.get("mac_leak_scan")
if not (isinstance(leak, dict) and isinstance(leak.get("values"), int) and isinstance(leak.get("hits"), int) and isinstance(leak.get("stores"), list)):
    bad.append("the agent response carries no valid mac_leak_scan {values, hits, stores}")
    leak = {}
elif leak.get("hits"):
    bad.append("the agent's mac leak scan found %s hit(s) in %s" % (leak.get("hits"), leak.get("stores")))
print("open=[%s]" % ",".join(map(str, open_set)))
print("expected=[%s]" % ",".join(map(str, expected)))
print("counts=%s" % counts)
print("control=%s fw=%s" % (spot_by_port.get(111, {}).get("outcome", "not-swept"), fw_state))
print("cert=%s" % (json.dumps({k: cert.get(k) for k in ("authorized", "protocol", "sha256")}) if cert else "none"))
print("v6=%s" % ("%s %s open=[%s]" % (v6_class or "?", v6_addr or "?", ",".join(str(p.get("port")) for p in v6entries if p.get("outcome") == "open")) if v6entries else ("not-run (the result carries no IPv6 ports although the hello carries vm_g6)" if vm_g6 else "not-run (no guest IPv6 global address, vm_g6, in the hello)")))
print("spot_not_open=[%s]" % (",".join(str(p) for p in sorted(spot_by_port) if spot_by_port[p].get("outcome") != "open") or "-"))
print("leak=%s" % ("%s values, %s hits in %s" % (leak.get("values", "?"), leak.get("hits", "?"), ",".join(leak.get("stores", []))) if leak else "no scan in the response"))
print("notes=%s" % (" | ".join(note) if note else "-"))
print("breaches=%d" % len(bad))
for b in bad:
    print("BREACH %s" % b)
sys.exit(1 if bad else 0)
PYW5
  )" || rc_eval=$?
  breaches="$(printf '%s\n' "$evidence" | grep -c '^BREACH ' || true)"
  if (( rc_eval != 0 || breaches > 0 )); then
    record W5 "$slice" W FAIL "$evidence (eval exit=$rc_eval breaches=$breaches; TCP only; ss -ltnH: ${ss_listeners:-none})"
  else
    record W5 "$slice" W PASS "$evidence (TCP only; ss -ltnH: ${ss_listeners:-none}; ss -lunH: ${ss_udp:-none}; exposed binds: ${ports_svc:-none})"
  fi
}

w6_response_fields() { # response.json: sets W6_STATUS, W6_UA, W6_ISSUER and W6_LEAK from the saved agent response
  # Review T04: `read` consumes ONE line whatever IFS is, and the helper prints four, so every field is taken from its own line.
  local parsed
  parsed="$(python3 -I - "$1" <<'PYW6B' 2>>"$RAW"
import json, re, sys
r = json.load(open(sys.argv[1], "r", encoding="utf-8"))
tail = r.get("stdout_tail") or ""
m = re.search(r"status=([0-9]{3})", tail)
print(m.group(1) if m else "")
m = re.search(r"ua=([A-Za-z0-9._-]+)", tail)
print(m.group(1) if m else "")
m = re.search(r"issuer=(\S+)", tail)
print(m.group(1) if m else "")
leak = r.get("mac_leak_scan") or {}
print("%s values, %s hits" % (leak.get("values", "?"), leak.get("hits", "?")))
PYW6B
  )" || return 1
  local -a fields
  mapfile -t fields <<<"$parsed"
  W6_STATUS="${fields[0]:-}"; W6_UA="${fields[1]:-}"; W6_ISSUER="${fields[2]:-}"; W6_LEAK="${fields[3]:-}"
}
phase4_row_w6() {
  local slice="$1"
  section "W6: the client address the proxy logs for a Mac request (IPv4 path; TOPOFIX W6, kept)"
  # One Mac request with a forged X-Forwarded-For and a row User-Agent; the runner (in the
  # guest) reads the proxy's log line and asserts the $remote_addr equals mac_src_ip (M4's
  # observed shape), not the forged header and not a bridge gateway.
  local agent_rc=0
  agent_request W6 240 || agent_rc=$?
  if (( agent_rc != 0 )); then
    record W6 "$slice" W FAIL "the W6 agent request failed (browser_remote rc=$agent_rc: the agent holds the refusal or the timeout; the Mac agent.log names it): $(tail_chars 300 "$CAP_ERR")${CAP:+ | stdout: ${CAP:0:300}}"
    return
  fi
  printf '%s\n' "$CAP" > "$STATE/w6-agent-response.json" && chmod 600 "$STATE/w6-agent-response.json"
  local status ua issuer leak
  w6_response_fields "$STATE/w6-agent-response.json" || { record W6 "$slice" W FAIL "the W6 agent response could not be parsed (see run.log); response kept at $STATE/w6-agent-response.json"; return; }
  status="$W6_STATUS"; ua="$W6_UA"; issuer="$W6_ISSUER"; leak="$W6_LEAK"
  if [[ ! "$status" =~ ^[0-9]{3}$ || -z "$ua" ]]; then
    record W6 "$slice" W FAIL "the agent response tail names no status/ua (the RESULT W6 line is in run.log)"
    return
  fi
  local logline addr
  logline="$(docker logs "$(cid proxy)" 2>>"$RAW" | grep -F "$ua" | head -1 || true)"
  if [[ -z "$logline" ]]; then
    record W6 "$slice" W FAIL "no proxy log line for User-Agent $ua (nginx log_format krate_identity logs this path, epc/nginx.conf)"
    return
  fi
  addr="$(printf '%s\n' "$logline" | awk '{print $1}')"
  if [[ "$addr" == "$MAC_SRC_IP" && "$status" == 200 ]]; then
    record W6 "$slice" W PASS "requested the realm discovery document from the Mac with X-Forwarded-For 203.0.113.9 and User-Agent $ua: the proxy logged remote_addr=$addr == mac_src_ip ($MAC_SRC_IP) and answered HTTP $status (issuer $issuer; M4's observed shape); IPv4 path only (the IPv6 docker-proxy path is the lab8 N11a asymmetry, not asserted here); agent leak scan: $leak"
  else
    record W6 "$slice" W FAIL "the proxy logged remote_addr=$addr, expected mac_src_ip $MAC_SRC_IP (and HTTP 200, got $status); the forged 203.0.113.9 must not appear in the log (the same-host variants stay with G6/G7)"
  fi
}

w7_os_family() { # [os-release file]: rhel | debian | unknown, from ID and ID_LIKE (review T05). The file is an argument, never an environment variable: the operator's environment must not choose the OS branch W7 takes (R7)
  local file="${1:-/etc/os-release}" ids
  ids="$(sed -n -E 's/^(ID|ID_LIKE)=//p' "$file" 2>/dev/null | tr -d "\"'" | tr '[:upper:]' '[:lower:]' | tr '\n' ' ')"
  case " $ids " in
    *" rhel "* | *" fedora "* | *" centos "* | *" rocky "* | *" almalinux "*) echo rhel ;;
    *" debian "* | *" ubuntu "*) echo debian ;;
    *) echo unknown ;;
  esac
}
phase4_row_w7() {
  local slice="$1" st=0 ev=""
  section "W7: firewalld/ufw state as the fixture itself sees it (zone of lima0, no runtime-only edit, no rich rules, the doctor's line)"
  # Review T05: the branch follows the fixture's OS, not the firewall that happens to be running, so a Rocky/RHEL fixture whose
  # firewalld stopped FAILs here instead of falling into the Ubuntu/ufw shape and passing with no firewall at all.
  local os_family fw_active=false
  os_family="$(w7_os_family "${2:-/etc/os-release}")"   # the optional second argument exists for the checker; the row's one call site passes the slice only
  if command -v firewall-cmd >/dev/null 2>&1 && [[ "$(systemctl is-active firewalld 2>/dev/null || true)" == active ]]; then fw_active=true; fi
  if [[ "$os_family" == unknown ]]; then
    st=1
    ev+="unsupported fixture OS (/etc/os-release ID/ID_LIKE are neither RHEL-family nor Debian/Ubuntu): W7 supports RHEL-family hosts with a running firewalld and Debian/Ubuntu hosts with ufw"
  elif [[ "$os_family" == rhel ]] && ! $fw_active; then
    st=1
    ev+="RHEL-family fixture without a running firewalld (firewall-cmd: $(command -v firewall-cmd || echo missing); systemctl is-active firewalld: $(systemctl is-active firewalld 2>/dev/null || echo unknown)): the supported fixture requires it running with lima0 in its default zone"
  elif [[ "$os_family" == rhel ]]; then
    local fwcmd def zone_lima0 zone_bridge docker_target bridge svc_rt svc_perm ports_rt ports_perm proto_rt proto_perm
    local icmp_rt icmp_perm rich fwd policies doctor
    # Review T06/R3: every firewall command whose output W7 reads runs under LC_ALL=C (ufw's status line is gettext-translated, so a
    # guest with a translated catalogue would otherwise fail a correct fixture as "unreadable"); `env` inside sudo keeps it whatever
    # sudo's env_reset does with the caller's locale.
    fwcmd=(sudo -n env LC_ALL=C firewall-cmd)
    sudo -n true 2>/dev/null || fwcmd=(env LC_ALL=C firewall-cmd)
    def="$("${fwcmd[@]}" --get-default-zone 2>>"$RAW")"
    zone_lima0="$("${fwcmd[@]}" --get-zone-of-interface=lima0 2>>"$RAW")"
    bridge=""
    for netdev in /sys/class/net/docker* /sys/class/net/br-*; do
      if [[ -e "$netdev" ]]; then bridge="$(basename "$netdev")"; break; fi
    done
    zone_bridge="$("${fwcmd[@]}" --get-zone-of-interface="${bridge:-none}" 2>>"$RAW" || echo "no bridge interface")"
    # Review T17: the docker zone must also be ACCEPT (a docker zone changed to DROP/REJECT changes the forwarding behaviour the row
    # asserts). The query is the doctor's own (epc/krate: firewall-cmd --info-zone=docker); --get-target is a --permanent-only query
    # (firewall-cmd(1): "--permanent [--zone=zone] --get-target") and the docker zone is runtime-managed.
    docker_target="$("${fwcmd[@]}" --info-zone=docker 2>>"$RAW" | awk -F': ' '/target:/{print $2}' | tr -d '[:space:]')"
    svc_rt="$("${fwcmd[@]}" --zone="$def" --list-services 2>>"$RAW")"; svc_perm="$("${fwcmd[@]}" --permanent --zone="$def" --list-services 2>>"$RAW")"
    ports_rt="$("${fwcmd[@]}" --zone="$def" --list-ports 2>>"$RAW")"; ports_perm="$("${fwcmd[@]}" --permanent --zone="$def" --list-ports 2>>"$RAW")"
    proto_rt="$("${fwcmd[@]}" --zone="$def" --list-protocols 2>>"$RAW")"; proto_perm="$("${fwcmd[@]}" --permanent --zone="$def" --list-protocols 2>>"$RAW")"
    icmp_rt="$("${fwcmd[@]}" --zone="$def" --list-icmp-blocks 2>>"$RAW")"; icmp_perm="$("${fwcmd[@]}" --permanent --zone="$def" --list-icmp-blocks 2>>"$RAW")"
    rich="$("${fwcmd[@]}" --zone="$def" --list-rich-rules 2>>"$RAW")"; fwd="$("${fwcmd[@]}" --zone="$def" --list-forward-ports 2>>"$RAW")"
    policies="$("${fwcmd[@]}" --get-policies 2>>"$RAW" || true)"
    doctor="$("$KRATE" doctor 2>>"$RAW" | grep -i firewall | head -2 | tr '\n' ' ' || true)"
    [[ "$def" != "?" && "$zone_lima0" == "$def" ]] || st=1
    [[ "$zone_bridge" == "docker" ]] || st=1
    [[ "$docker_target" == ACCEPT ]] || st=1
    [[ "$svc_rt" == "$svc_perm" && "$ports_rt" == "$ports_perm" && "$proto_rt" == "$proto_perm" && "$icmp_rt" == "$icmp_perm" ]] || st=1
    [[ -z "${rich// /}" && -z "${fwd// /}" ]] || st=1
    ev+="default zone $def: lima0 in it (M3), bridge ${bridge:-none} in zone $zone_bridge (docker, M4), docker zone target [${docker_target:-unknown}] (ACCEPT required);"
    ev+=" runtime==permanent for services/ports/protocols/icmp-blocks (no runtime-only harness edit; docker's interface membership is runtime-managed by design),"
    ev+=" services=[$svc_rt] ports=[$ports_rt];"
    ev+=" rich rules [${rich:-none}] forward-ports [${fwd:-none}] empty;"
    if [[ "$policies" == *"docker-forwarding"* ]]; then
      ev+=" policies include docker-forwarding;"
    else
      ev+=" policies=${policies:-not supported by this firewalld} (docker-forwarding not named);"
      st=1
    fi
    ev+=" doctor: ${doctor:-none printed}"
  else
    local ufw_state ufw_first ufw_reason="" ufw_status input_head doctor
    ufw_state="$(systemctl is-active ufw 2>/dev/null || true)"   # evidence text only: ufw.service is a oneshot that reads `active` (exited) while `ufw status` says inactive (TOPOFIX2 PRE-4)
    ufw_first="$( { sudo -n env LC_ALL=C ufw status 2>/dev/null || LC_ALL=C ufw status 2>/dev/null; } | head -1 || true)"   # fixed locale: the case below matches ufw's English status line (T06)
    ufw_status="$( { sudo -n env LC_ALL=C ufw status verbose 2>/dev/null || LC_ALL=C ufw status verbose 2>/dev/null; } | head -4 | tr '\n' ' ' || true)"
    input_head="$(sudo -n env LC_ALL=C iptables -S INPUT 2>/dev/null | head -1 || true)"
    doctor="$("$KRATE" doctor 2>>"$RAW" | grep -i firewall | head -2 | tr '\n' ' ' || true)"
    case "$ufw_first" in
      "Status: inactive"*) ;;
      "Status: active"*) st=1 ;; # the gate's standard fixture keeps ufw inactive (TOPOFIX 5.5; enabling it is an operator choice)
      *) st=1; ufw_reason="ufw status unreadable (needs root or passwordless sudo)" ;;
    esac
    ev+="no active firewalld (Ubuntu shape, M6 pending on a re-created VM): ufw status first line [${ufw_first:-none}], ufw.service $ufw_state${ufw_status:+; status: }$ufw_status,"
    [[ -z "$ufw_reason" ]] || ev+=" $ufw_reason,"
    ev+=" INPUT head: ${input_head:-unavailable}; doctor: ${doctor:-none printed};"
    ev+=" no firewall-effectiveness control available for W5 on this host (ufw ${ufw_first:-unreadable})"
  fi
  if (( st == 0 )); then
    record W7 "$slice" W PASS "$ev"
  else
    record W7 "$slice" W FAIL "$ev"
  fi
}

phase4_row_w4() {
  local slice="$1"
  section "W4: 5-source reachability census equal to Table 2 of monitoring/README.md"
  local readme_file="$MON_DIR/README.md"
  local w4_script="$GATE_DIR/phase4_w4.py"
  if [[ ! -f "$readme_file" ]]; then
    phase4_stub W4 "$slice" W "precondition: missing monitoring/README.md"
    return
  fi
  if [[ ! -f "$w4_script" ]]; then
    record W4 "$slice" W FAIL "missing tracked scripts/gate/phase4_w4.py"
    return
  fi
  local cap_w4 st_w4 result_w4
  cap_w4="$(W4_NGINX_IMAGE="$(envv NGINX_IMAGE)" python3 -I "$w4_script" \
    --readme "$readme_file" --cluster-project "$PROJECT" --monitor-project "$MON_PROJECT" 2>&1)"; st_w4=$?
  log "$cap_w4"
  result_w4="$(printf '%s\n' "$cap_w4" | grep '^RESULT W4 ' | tail -1)"
  if [[ $st_w4 -eq 0 && "$result_w4" == 'RESULT W4 PASS '* ]]; then
    record W4 "$slice" W PASS "live reachability census: ${result_w4#RESULT W4 PASS }"
  elif [[ $st_w4 -eq 2 && "$result_w4" == 'RESULT W4 NOT_RUN '* ]]; then
    record W4 "$slice" W NOT_RUN "live reachability census: ${result_w4#RESULT W4 NOT_RUN }"
  else
    record W4 "$slice" W FAIL "live reachability census: ${result_w4:-script exit $st_w4 without a result}; see run.log"
  fi
}
bringup_failed() { # slice id...: every row FAILs when the fixture never came up
  local slice="$1"; shift
  local id crit ev
  ev="fixture bring-up failed: stand-in exit $SC_STUB, auth configure exit $SC_CONFIGURE, config set exit $SC_SET, start exit $SC_START, auth apply exit $SC_APPLY, monitor up exit $SC_MONITOR (output in run.log)"
  log "$ev"
  for id in "$@"; do
    crit="${id%%[0-9]*}"
    case "$id" in
      Z*) phase4_stub "$id" "$slice" Z "$ev; the leak scan did not run" ;;
      X*) phase4_stub "$id" "$slice" X "$ev; the screenshot story did not run" ;;
      *) record "$id" "$slice" "$crit" FAIL "$ev" ;;
    esac
  done
}
run_phase4() { # slice: 4a|4b|4c
  local slice="$1" id rc ev crit job helper only tsv regex
  local -a inv=() run_inv=() helper_jobs=() only_arg=()
  section "Phase $slice fixture: brokers + Kafbat + proxy + identity + monitoring, public host $BASE_HOST${SESSION_MAX_HOURS:+, session maximum ${SESSION_MAX_HOURS}h}"
  case "$slice" in
    4a) inv=("${REQUIRED_P4A[@]}") ;;
    4b) inv=("${REQUIRED_P4B[@]}") ;;
    4c) inv=("${REQUIRED_P4C[@]}") ;;
  esac
  run_inv=("${inv[@]}")
  # Which helper produces which rows (section 5): "<script> <only|- for all> <id prefix>".
  # A companion --session-max-hours run executes U27 (through the Grafana helper) for
  # both 4a and 4b, V23 (through the Perses helper) for 4b and K37 (Kafbat's absolute
  # session lifetime, through the Kafbat helper) for 4a: the Kafbat fork and its
  # runtime.yml are the same in both slices, so one measurement per host is enough;
  # U27/V23/K37 are the only rows of the companion inventory besides REQUIRED_P1.
  if [[ -n "$SESSION_MAX_HOURS" ]]; then
    run_inv=()
    while IFS= read -r id; do run_inv+=("$id"); done < <(phase4_session_ids "$slice")
    case "$slice" in
      4a) helper_jobs=("$GATE_DIR/phase4_grafana.py U27 U" "$GATE_DIR/phase4_kafbat.py K37 K") ;;
      4b) helper_jobs=("$GATE_DIR/phase4_grafana.py U27 U" "$GATE_DIR/phase4_perses.py V23 V") ;;
    esac
  else
    case "$slice" in
      4a) helper_jobs=("$GATE_DIR/phase4_grafana.py - U") ;;
      4b) helper_jobs=("$GATE_DIR/phase4_perses.py - V") ;;
      4c) helper_jobs=() ;;  # W1-W4 are the runner's rows (section 5)
    esac
  fi
  # Slice 4b brings up the stand-in IdP and configures with its site.json (the
  # broker plan of commit 0, lead decision 2026-10-13); 4a and 4c configure plain
  # (--local, accepted and ignored by the CLI).
  local -a bringup=(--local)
  [[ "$slice" == 4b ]] && bringup=(--broker)
  if ! start_cluster "${bringup[@]}"; then
    bringup_failed "$slice" "${run_inv[@]}"
    return
  fi
  # A companion prepares the shared fixture once per helper that owns a timed row, one
  # pass after the other (they must not race). The timed observers then use read-only
  # prepared preflights and start together.
  if [[ -n "$SESSION_MAX_HOURS" ]]; then
    local prep_helper prep_tsv prep_rc
    local -a prep_helpers=()
    case "$slice" in
      4a) prep_helpers=("$GATE_DIR/phase4_grafana.py" "$GATE_DIR/phase4_kafbat.py") ;;
      4b) prep_helpers=("$GATE_DIR/phase4_perses.py") ;;
    esac
    local -a prep_extra=()
    if [[ "$slice" == 4b ]]; then
      prep_extra=(--stub-dir "$STUB_DIR" --stub-port "$STUB_PORT" --stub-script "$STUB")
    fi
    for prep_helper in "${prep_helpers[@]}"; do
      prep_tsv="$STATE/phase4-preparation-$(basename "$prep_helper" .py).tsv"
      python3 -I "$prep_helper" run --edition-dir "$ED" --base-url "$BASE" \
        --monitor-project "$MON_PROJECT" --state "$STATE" --prepare-only \
        ${prep_extra[@]+"${prep_extra[@]}"} > "$prep_tsv" 2>>"$RAW" & CHILD=$!
      wait "$CHILD" && prep_rc=0 || prep_rc=$?
      CHILD=""
      phase4_ingest "$prep_tsv" "$slice" '^$'
      if [[ $prep_rc -ne 0 || "$(awk -F '\t' '$1=="setup" {print $2}' "$prep_tsv")" != PASS ]]; then
        if [[ -z "${SEEN[${slice}-setup]:-}" ]]; then
          record "${slice}-setup" "$slice" setup FAIL "shared companion preparation ($(basename "$prep_helper")) exited $prep_rc without a PASS setup row"
        fi
        for id in "${run_inv[@]}"; do
          crit="${id%%[0-9]*}"
          record "$id" "$slice" "$crit" NOT_RUN "shared companion preparation failed; see $(basename "$prep_tsv")"
        done
        return
      fi
    done
  fi
  # The normal slice helper runs once. Companion observers start together and
  # are all owned by PHASE4_CHILDREN so an interrupt can stop every worker.
  local -a timed_tsvs=() timed_regexes=() timed_names=()
  for job in ${helper_jobs[@]+"${helper_jobs[@]}"}; do
    read -r helper only regex <<<"$job"
    if [[ ! -f "$helper" ]]; then log "$helper missing"; continue; fi
    only_arg=(); [[ "$only" == - ]] || only_arg=(--only "$only")
    local -a extra_arg=()
    if [[ "$slice" == 4b && "$(basename "$helper")" == phase4_perses.py ]]; then
      extra_arg=(--stub-dir "$STUB_DIR" --stub-port "$STUB_PORT" --stub-script "$STUB")  # V19 reuses phase3_broker.Gate.brokered_login
    fi
    tsv="$STATE/$(basename "$helper" .py).tsv"
    local -a prepared_arg=()
    if [[ -n "$SESSION_MAX_HOURS" ]]; then
      prepared_arg=(--prepared --session-max-minutes "$((SESSION_MAX_HOURS * 60))")
    fi
    python3 -I "$helper" run --edition-dir "$ED" --base-url "$BASE" --monitor-project "$MON_PROJECT" \
      --state "$STATE" "${only_arg[@]}" "${prepared_arg[@]}" \
      ${extra_arg[@]+"${extra_arg[@]}"} > "$tsv" 2>>"$RAW" & CHILD=$!
    if [[ -n "$SESSION_MAX_HOURS" ]]; then
      PHASE4_CHILDREN+=("$CHILD")
      timed_tsvs+=("$tsv")
      timed_regexes+=("^${only}\$")
      timed_names+=("$(basename "$helper")")
      CHILD=""
    else
      wait "$CHILD" && rc=0 || rc=$?
      CHILD=""
      phase4_ingest "$tsv" "$slice" "^${regex}[0-9]+[ab]?\$"
      log "$(basename "$helper") exit=$rc"
    fi
  done
  if [[ -n "$SESSION_MAX_HOURS" ]]; then
    local i
    for i in "${!PHASE4_CHILDREN[@]}"; do
      wait "${PHASE4_CHILDREN[$i]}" && rc=0 || rc=$?
      phase4_ingest "${timed_tsvs[$i]}" "$slice" "${timed_regexes[$i]}"
      if [[ $rc -ne 0 ]]; then
        record "${slice}-helper-${timed_names[$i]%.py}" "$slice" helper FAIL \
          "${timed_names[$i]} exited $rc after prepared observation"
      fi
      log "${timed_names[$i]} exit=$rc"
    done
    PHASE4_CHILDREN=()
  fi
  # Runner-owned rows: the screenshot stories (scripts/gate/screenshots-{grafana,perses}.mjs
  # are scaffolds, not run: no browser here — the lead runs them against the fixture),
  # the extended leak scans and, for 4c, the W rows.
  if [[ -z "$SESSION_MAX_HOURS" ]]; then
    case "$slice" in
      4a)
        in_inv X3 "${run_inv[@]}" && phase4_screenshots_x3 "$slice"
        in_inv Z4a "${run_inv[@]}" && phase4_leak_scan_z4a "$slice"
        ;;
      4b)
        in_inv X4 "${run_inv[@]}" && phase4_screenshots_x4 "$slice"
        in_inv Z4b "${run_inv[@]}" && phase4_leak_scan_z4b "$slice"
        ;;
      4c)
        in_inv W1 "${run_inv[@]}" && phase4_row_w1 "$slice"
        in_inv W2 "${run_inv[@]}" && phase4_row_w2 "$slice"
        if in_inv W3 "${run_inv[@]}"; then
          if $W3_REQUIRED; then
            phase4_row_w3 "$slice"
          else
            record W3 "$slice" W NOT_RUN "needs root (or sudo) and iproute2 for the p4probe namespace on Linux (J7 pattern: outside the inventory on this host; decided by the VM receipt)"
          fi
        fi
        in_inv W4 "${run_inv[@]}" && phase4_row_w4 "$slice"
        # W5/W6/W7 (TOPOFIX F6/F7): the network path of a user's computer. They follow the
        # J7 pattern: inside the inventory only under the Mac agent vantage (--browser agent
        # on a vzNAT VM fixture; W5W6W7_REQUIRED), NOT_RUN elsewhere, decided by the VM receipt.
        if in_inv W5 "${run_inv[@]}"; then
          if $W5W6W7_REQUIRED; then phase4_row_w5 "$slice"; else
            record W5 "$slice" W NOT_RUN "needs the Mac vantage (--browser agent on a vzNAT VM fixture): the row tests the fixture's surface from a second host's NIC address; decided by the VM receipt"
          fi
        fi
        if in_inv W6 "${run_inv[@]}"; then
          if $W5W6W7_REQUIRED; then phase4_row_w6 "$slice"; else
            record W6 "$slice" W NOT_RUN "needs the Mac vantage (--browser agent on a vzNAT VM fixture): the row binds a Mac request to the proxy's logged client address; decided by the VM receipt"
          fi
        fi
        if in_inv W7 "${run_inv[@]}"; then
          if $W5W6W7_REQUIRED; then phase4_row_w7 "$slice"; else
            record W7 "$slice" W NOT_RUN "needs the Mac vantage (--browser agent on a vzNAT VM fixture): the row asserts the fixture's firewall state on the VM the formal receipts run on; decided by the VM receipt"
          fi
        fi
        ;;
    esac
  fi
  # The inventory fill: a row that produced no result (helper missing, incomplete,
  # or not reached) is NOT_RUN, never silently absent.
  for id in "${run_inv[@]}"; do
    [[ -n "${SEEN[$id]:-}" ]] && continue
    crit="${id%%[0-9]*}"
    phase4_stub "$id" "$slice" "$crit" "no result produced: the ${slice} row bodies await the live walk notes (harness/phase4/live${slice}/, rule 11); scaffold only"
  done
  # In a companion --session-max-hours run the rest of the slice stays out of the
  # inventory; name it for the receipt reader.
  if [[ -n "$SESSION_MAX_HOURS" ]]; then
    for id in "${inv[@]}"; do
      [[ -n "${SEEN[$id]:-}" ]] && continue
      crit="${id%%[0-9]*}"
      phase4_stub "$id" "$slice" "$crit" "companion --session-max-hours $SESSION_MAX_HOURS run: this row belongs to the slice's default receipt"
    done
  fi
  # The helper's runtime secrets (JWTs, cookies, tokens, enrolled passwords and TOTP
  # seeds) join the leak set; Z4a/Z4b (and every later scan) search for them.
  if [[ -f "$STATE/phase4-secrets.txt" ]]; then
    local v
    while IFS= read -r v; do add_secret "$v"; done < "$STATE/phase4-secrets.txt"
  fi
}

# ═══════════════════════════ air gap (AG1-AG5) ═══════════════════════════
# A receipt on a bundle host proves the offline condition it claims (owner programme: "Installation/start in the
# offline test must not fetch missing components"; plan R2b). scripts/gate/phase4_airgap.py runs the probes and
# decides every row: AG1 and AG4 before the first row, AG2, AG3 and AG5 after the last slice row and before the
# teardown (a run that ends early runs them from finish()). The Mac and a git checkout record NOT_RUN with the
# reason; a bundle host never records NOT_RUN or PASS for a probe that could not run.
airgap_host_kind() { # darwin | bundle | checkout: the host the AG rows run on
  if [[ "$(uname -s)" == Darwin ]]; then echo darwin
  elif [[ -n "$REPO_ARG" || -z "$CANDIDATE_GIT_HEAD" ]]; then echo bundle  # an installed bundle: --repo, or no tracked git beside the edition
  else echo checkout
  fi
}
airgap_fill() { # id...: a row the helper did not return is FAIL on a bundle host and NOT_RUN elsewhere, never absent
  local id kind; kind="$(airgap_host_kind)"
  for id in "$@"; do
    [[ -n "${SEEN[$id]:-}" ]] && continue
    if [[ "$kind" == bundle ]]; then
      record "$id" airgap AG FAIL "no air-gap result for $id: the helper returned no row (see the lines above in run.log)"
    else
      record "$id" airgap AG NOT_RUN "no air-gap result for $id on a host that is not a bundle host"
    fi
  done
}
airgap_step() { # before|after [exit-path]: run the helper, record the rows it returns
  local when="$1" tsv rc
  local -a extra=()
  [[ "${2:-}" == exit-path ]] && extra=(--exit-path)
  tsv="$STATE/airgap-$when.tsv"
  python3 -I "$GATE_DIR/phase4_airgap.py" "$when" --host-kind "$(airgap_host_kind)" --state "$STATE/airgap" \
    --edition-dir "$ED" --mon-dir "$MON_DIR" ${extra[@]+"${extra[@]}"} > "$tsv" 2>>"$RAW"; rc=$?
  log "phase4_airgap.py $when exit=$rc"
  phase4_ingest "$tsv" airgap '^AG[0-9]+$'
}
airgap_before_rows() {
  section "AG: the air gap before the first row (AG1, AG4)"
  airgap_step before
  airgap_fill AG1 AG4
}
airgap_after_rows() { # [exit-path]: once per run; after the last slice row, or from finish() when the run ended early
  [[ "${AIRGAP_AFTER_RAN:-false}" == true ]] && return 0
  AIRGAP_AFTER_RAN=true
  section "AG: the air gap after the last row (AG2, AG3, AG5)"
  airgap_step after "${1:-}"
  airgap_fill AG1 AG4 AG2 AG3 AG5  # AG1 and AG4 are absent only when the run ended before the before step
}

# ═══════════════════════════ leak scan, teardown, verdict ═══════════════════════════
leak_scan() {
  section "Z: secret-leak scan over every captured output, the journal, plan files, receipt files and container logs"
  local hits=0 s where t is_temp where_raw svc id label rc u st gaps="" list="" seen=$'\n'
  local -a places=("$JOURNAL" "$RECEIPT" "$OUT/screenshots/manifest.json") unread=()
  # An input that cannot be read fails the row, as in Z4a/Z4b: a scan over nothing is not a clean scan.
  # keycloak and keycloak-db exist whenever this runs (run_phase1 ends with `identity up`; `identity down` only
  # stops them), so a missing one is a log that was not read. kafka-ui and proxy are searched when they exist
  # (a run without brokers has no kafka-ui). The listing's status is checked here and not through cid: cid prints
  # nothing both for a daemon that cannot be reached and for a missing container, and its status is the pipeline's.
  for svc in keycloak keycloak-db kafka-ui proxy; do
    id="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$svc" 2>/dev/null)" \
      || { unread+=("$svc (container listing failed)"); continue; }
    id="${id%%$'\n'*}"
    if [[ -z "$id" ]]; then
      case "$svc" in keycloak|keycloak-db) unread+=("$svc (no container)") ;; esac
      continue
    fi
    docker logs "$id" > "$STATE/$svc.log" 2>&1 || unread+=("$svc (docker logs failed)")
    places+=("$STATE/$svc.log")
  done
  for svc in prometheus grafana loki; do  # captured by run_phase2 before monitor down
    [[ -f "$STATE/mon-$svc.log" ]] && places+=("$STATE/mon-$svc.log")
  done
  [[ -f "$STATE/pingstub.log" ]] && places+=("$STATE/pingstub.log")  # captured by run_phase3 before the stand-in goes down
  if [[ -s "$STATE/logs-not-captured.txt" ]]; then  # run_phase2/run_phase3 name each monitoring or stand-in log they could not copy
    while IFS= read -r u; do [[ -z "$u" ]] || unread+=("$u"); done < "$STATE/logs-not-captured.txt" || unread+=("logs-not-captured.txt")
  fi
  local raw_without_display="$STATE/raw-without-display.log"
  awk '/Temporary password for/ {print; skip=1; next} skip {skip=0; next} {print}' "$RAW" > "$raw_without_display" || unread+=("raw log (no display)")
  # Both raw-log inputs are opened whatever the secrets are (the copy serves temporary passwords only): a missing or unreadable one fails the row.
  { : < "$RAW"; } 2>/dev/null || unread+=("raw log")
  { : < "$raw_without_display"; } 2>/dev/null || unread+=("raw log (no display)")
  local one="$STATE/one-secret.txt"
  for s in "${SECRETS[@]}"; do
    is_temp=false; for t in "${TEMP_SECRETS[@]}"; do [[ "$t" == "$s" ]] && is_temp=true; done
    if $is_temp; then where_raw="$raw_without_display"; else where_raw="$RAW"; fi
    if ! printf '%s\n' "$s" > "$one"; then unread+=("secret pattern file"); continue; fi
    chmod 600 "$one"
    for where in "$where_raw" "${places[@]}"; do
      [[ -f "$where" ]] || continue
      case "$where" in "$RAW") label="raw log" ;; "$raw_without_display") label="raw log (no display)" ;; *) label="${where##*/}" ;; esac
      grep -qF -f "$one" "$where" 2>/dev/null; rc=$?  # 0 a hit, 1 none, above 1 the file could not be read
      if (( rc == 0 )); then hits=$((hits+1)); log "LEAK: a secret value appears in $label"
      elif (( rc > 1 )); then unread+=("$label"); fi
    done
    if [[ -d "$ED/auth/keycloak" ]]; then
      grep -rqF -f "$one" "$ED/auth/keycloak/" 2>/dev/null; rc=$?
      if (( rc == 0 )); then hits=$((hits+1)); log "LEAK: a secret value appears under auth/keycloak/"
      elif (( rc > 1 )); then unread+=("auth/keycloak"); fi
    fi
  done
  rm -f "$raw_without_display" "$one"
  for u in "${unread[@]}"; do  # one entry per input however many secrets or checks reported it
    [[ "$seen" == *$'\n'"$u"$'\n'* ]] && continue
    seen+="$u"$'\n'; list+="${list:+, }$u"
  done
  [[ -z "$list" ]] || { gaps+="; not read: $list"; log "NOT READ: $list"; }
  (( ${#SECRETS[@]} )) || gaps+="; no secret values to search"
  [[ $hits -eq 0 && -z "$gaps" ]]; st=$?
  ok_if "$1" "$2" Z "$st" "${#SECRETS[@]} distinct secret values (.env and monitoring/.env passwords/secrets/keys, the backup passphrase, ${#TEMP_SECRETS[@]} temporary passwords, enrolled passwords and TOTP seeds) searched in the raw log (temporary passwords: outside their one-time display line), journal, plan files, receipt rows, screenshot captions and the keycloak, keycloak-db, kafka-ui, proxy and monitoring logs: $hits hits$gaps"
}
restore_prometheus_config() {
  local backup="$STATE/prometheus.yml.bak"
  rm -f "$STATE/prometheus.yml.bak.tmp"
  $W2_BACKUP_OWNED || return 0
  if [[ ! -f "$backup" ]]; then
    record W2-restore "$PHASE" W FAIL "the gate-owned Prometheus configuration backup is missing"
    return 1
  fi
  if cp "$backup" "$MON_DIR/prometheus/prometheus.yml"; then
    rm -f "$backup"
    W2_BACKUP_OWNED=false
    log "W2 Prometheus configuration restored"
  else
    record W2-restore "$PHASE" W FAIL "could not restore the Prometheus configuration from the gate backup"
    return 1
  fi
}
teardown() {
  section "teardown"
  [[ -z "$CHILD" ]] || { kill "$CHILD" 2>/dev/null; wait "$CHILD" 2>/dev/null; CHILD=""; }
  local phase4_child
  for phase4_child in "${PHASE4_CHILDREN[@]}"; do
    kill "$phase4_child" 2>/dev/null || true
    wait "$phase4_child" 2>/dev/null || true
  done
  PHASE4_CHILDREN=()
  local h; for h in "${HOLDERS[@]}"; do kill "$h" 2>/dev/null; done
  restore_prometheus_config || true
  if ! $FIXTURE_OWNED; then log "no fixture was created; nothing to tear down"; return; fi
  if $KEEP; then log "--keep: fixture left running (project $PROJECT)"; return; fi
  "$KRATE" monitor down >/dev/null 2>&1 || true
  "$STUB" down --project "$PROJECT" >/dev/null 2>&1 || true  # before compose down: the stand-in is attached to identity-egress
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  local v; for v in $(docker volume ls -q | grep -E "^${MON_PROJECT}_"); do docker volume rm "$v" >/dev/null 2>&1; done
  docker volume rm "${MON_PROJECT}_grafana_rendered" >/dev/null 2>&1 || true  # named explicitly (section 5); the prefix loop above is the backstop
  docker network rm "${PROJECT}_identity" "${PROJECT}_identity-egress" "${PROJECT}_kafka-network" "$CLASH_NET" "${MON_PROJECT}_monitoring" "${MON_PROJECT}_perses" >/dev/null 2>&1 || true
  local n; for n in $(docker network ls --format '{{.Name}}' | grep -E "^${PROJECT}-gate2-|^${PROJECT}-gate4-"); do docker network rm "$n" >/dev/null 2>&1; done
  for n in $(docker ps -aq --filter "name=^${PROJECT}-gate2-" --filter "name=^${PROJECT}-gate3-" --filter "name=^${PROJECT}-gate4-"); do docker rm -f "$n" >/dev/null 2>&1; done
  # A helper label alone is not ownership: restrict removal to this fixture's
  # Compose project. The name-filtered removal above covers independent helpers.
  # W4 probe containers carry no project label; a probe whose start timed out is removed here too.
  for n in $(docker ps -aq --filter "label=krate.gate=w4-probe"); do docker rm -f "$n" >/dev/null 2>&1; done
  for n in $(docker ps -aq --filter "label=krate.gate=phase4" \
      --filter "label=com.docker.compose.project=$PROJECT"); do docker rm -f "$n" >/dev/null 2>&1; done
  # scripts/gate/phase4_w3.sh owns its namespace/veth and removes only resources it created.
  rm -rf "$ENVF" "$ED/auth/keycloak" "$ED/auth/ui/runtime.yml" "$JOURNAL" "$ED/auth/.identity.lock" "$ED/certs" "$MON_DIR/.env"
  cleanup_monitor_auth
  local left; left="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ') containers, $(docker volume ls -q | grep -c -E "^${PROJECT}_|^${MON_PROJECT}_" || true) volumes, $(docker network ls --format '{{.Name}}' | grep -c -E "^${PROJECT}_|^${PROJECT}-|^${MON_PROJECT}_|^${CLASH_NET}$" || true) networks"
  log "fixture resources left: $left"
}
finish() {
  airgap_after_rows exit-path  # a no-op when the run reached its normal end (it ran before the teardown)
  airgap_fill AG1 AG4 AG2 AG3 AG5  # a signal during the after step leaves rows unrecorded: a bundle host gets FAIL rows, never absent ones
  local verdict=PASS missing=() id notrun_required=0 vmip_now
  while IFS= read -r id; do
    [[ -n "${SEEN[$id]:-}" ]] || { missing+=("$id"); continue; }
    [[ "${SEEN_RESULT[$id]:-}" == NOT_RUN ]] && notrun_required=$((notrun_required+1))
  done < <(required_ids)
  # TOPOFIX F7: with the agent vantage the fixture's lima0 address must still be the hello's
  # at finish — a DHCP re-lease during the run would void the certificate and nonce binding.
  if [[ "$BROWSER_MODE" == agent && "$PHASE" == 4* ]]; then
    vmip_now="$(ip -4 -o addr show 2>/dev/null | awk '$2 == "lima0" {split($4, a, "/"); print a[1]; exit}')"
    if [[ "$vmip_now" == "$VM_IP" ]]; then
      record vmip "${PHASE}" W PASS "end-of-run (TOPOFIX F7): the fixture's lima0 address is still $VM_IP, so the certificate and rendezvous binding holds"
    else
      record vmip "${PHASE}" W FAIL "end-of-run: the fixture's lima0 address changed during the run ($VM_IP -> ${vmip_now:-gone}); the certificate and the rendezvous binding are void (F7: a DHCP re-lease)"
    fi
  fi
  (( FAILS == 0 )) || verdict=FAIL
  if (( notrun_required > 0 || ${#missing[@]} > 0 )) && [[ "$verdict" == PASS ]]; then verdict=INCOMPLETE; fi
  if ! $BOUND && [[ "$verdict" == PASS ]]; then verdict=INCOMPLETE; fi
  # A receipt is tied to a committed candidate and runner. Tracked edits made
  # during a long run also invalidate that binding, even if every row passes.
  if $CANDIDATE_DIRTY || ! $RUNNER_BOUND || [[ -n "$RUNNER_DIRTY" ]] ||
      [[ -n "$(git -C "$TOPLEVEL" status --porcelain --untracked-files=no 2>/dev/null)" ]] ||
      [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=normal -- scripts/gate-identity.sh scripts/gate 2>/dev/null)" ]] ||
      { [[ -n "$CANDIDATE_GIT_HEAD" ]] && [[ "$(git -C "$TOPLEVEL" rev-parse HEAD 2>/dev/null || true)" != "$CANDIDATE_GIT_HEAD" ]]; } ||
      { [[ "$RUNNER_COMMIT" != 'no git' ]] && [[ "$(git -C "$REPO" rev-parse HEAD 2>/dev/null || true)" != "$RUNNER_COMMIT" ]]; } ||
      [[ "$(sha256file "$RUNNER")" != "$RUNNER_SHA_START" ]] ||
      [[ "$(find "$GATE_DIR" -type f \( -name '*.py' -o -name '*.mjs' -o -name '*.sh' \) | LC_ALL=C sort | while IFS= read -r f; do cat "$f"; done | { shasum -a 256 2>/dev/null || sha256sum; } | cut -c1-16)" != "$RUNNER_GATE_SHA_START" ]]; then
    log "candidate or runner source is dirty or differs from the candidate"
    [[ "$verdict" == PASS ]] && verdict=INCOMPLETE
  fi
  if [[ -n "$REPO_ARG" ]] && ! recheck_product_binding; then
    log "the installed product changed during the run or could not be compared again: ${PRODUCT_BINDING##*at finish: }"
    [[ "$verdict" == PASS ]] && verdict=INCOMPLETE
  fi
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
  gate_digest="$(find "$GATE_DIR" -type f \( -name '*.py' -o -name '*.mjs' -o -name '*.sh' \) | LC_ALL=C sort | while IFS= read -r f; do cat "$f"; done | { shasum -a 256 2>/dev/null || sha256sum; } | cut -c1-16)"
  {
    echo "# Krate identity gate receipt"
    echo
    echo "| field | value |"; echo "|---|---|"
    echo "| verdict | **$verdict** (PASS $PASSES, FAIL $FAILS, NOT_RUN $NOTRUN, required missing ${#missing[@]}: ${missing[*]:-none}; required not run: $notrun_required; bound: $BOUND) |"
    echo "| candidate commit | $CANDIDATE |"
    echo "| dirty tracked files at run time | ${DIRTY:-none} |"
    echo "| edition file digests (sha256, 16 hex) |$EDITION_DIGESTS |"
    echo "| product byte binding | ${PRODUCT_BINDING:-not compared} |"
    echo "| edition / fixture | $EDITION in $ED, Compose project $PROJECT, $BASE, identity $SUBNET (pool $IP_RANGE, proxy $PROXY_IP) |"
    echo "| phases | $PHASE; screenshots: $SCREENSHOTS; static: $STATIC |"
    if [[ -n "$SESSION_MAX_HOURS" ]]; then
      echo "| session maximum | KEYCLOAK_SESSION_MAX_HOURS=$SESSION_MAX_HOURS (--session-max-hours, set in .env before the realm was created); this companion run executes REQUIRED_P1 plus: $(phase4_session_ids "$PHASE" | tr '\n' ' ') |"
    fi
    echo "| host | $(uname -srm); Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null); Compose $(docker compose version --short 2>/dev/null); $(python3 --version 2>&1); $(openssl version) |"
    echo "| browser vantage | $BROWSER_MODE${RENDEZVOUS:+ (agent: rendezvous $(dirname "$RENDEZVOUS"), nonce-bound, vm_ip ${VM_IP:-unknown}, mac_src_ip ${MAC_SRC_IP:-unknown}, hello age ${HELLO_AGE:-unknown} s, clock skew ${CLOCK_SKEW_MS:-unknown} ms; the token is not printed)} |"
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
airgap_before_rows
run_static
case "$PHASE" in
  1) run_phase1; run_screenshots; leak_scan Z1 1 ;;
  2) run_phase1; run_screenshots; leak_scan Z1 1; run_phase2; leak_scan Z2 2 ;;  # Phase 2 is accepted only with Phase 1
  3|all) run_phase1; run_screenshots; leak_scan Z1 1; run_phase2; leak_scan Z2 2; run_phase3; leak_scan Z3 3 ;;  # Phase 3 reuses the Phase 2 stack
  # Phase 4: the slice runs REQUIRED_P1 (with its Z1 scan) and then its own rows.
  # X1 is not part of a Phase 4 inventory (the story's resolver maps `localhost`;
  # the Phase 4 stories are X3/X4 under --public-host); the slice's own leak rows
  # are Z4a/Z4b.
  4a|4b|4c) run_phase1; leak_scan Z1 1; run_phase4 "$PHASE" ;;
esac
airgap_after_rows
FINISHED=true
trap - EXIT HUP INT TERM
teardown
finish
