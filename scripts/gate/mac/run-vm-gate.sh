#!/usr/bin/env bash
# Mac launcher for the identity gate on a vzNAT VM fixture (TOPOFIX-DESIGN 3.6 table
# `scripts/gate/mac/run-vm-gate.sh`, amendments TOPOFIX-REVIEW F7/F8).
#
# One launcher for one heavy stack: it refuses on battery, keeps the display awake
# (caffeinate), pins the story's tooling (installed Google Chrome, PW_MODULES playwright
# 1.60.0), creates a Mac worktree of the candidate (its ledger row is printed for the
# operator; rule 3), discovers the guest's lima0 address and the Mac's owning interface,
# checks SSH reach, generates the rendezvous nonce, starts the Mac agent, starts the guest
# runner detached, tails it, harvests the receipt and the agent folder, verifies the
# agent-manifest against the harvested evidence and re-reads the guest's lima0 address so a
# DHCP re-lease during the run fails the run instead of invalidating the binding later (F7).
#
#   scripts/gate/mac/run-vm-gate.sh --vm krate-p4-topo1 --phase 4c --public-host krate-oi.test \
#     [--candidate SHA] [--out DIR] [--edition-dir /opt/krate/epc] [--rows W5,W6]
#
# limactl invocations use fixed arguments; every copy is --backend=scp (F8, M1 observed the
# flag) and never an inline heredoc (limactl's argument joining drops quoted delimiters,
# provision-rocky.sh attempt-5 note). No secret value is printed.
set -euo pipefail
VM="" PHASE="" CANDIDATE="" OUT="" HOST="" EDITION_DIR="/opt/krate/epc" ROWS="W5,W6" GUEST_ROOT=""
usage() { cat >&2 <<'EOF'
usage: run-vm-gate.sh --vm NAME --phase 4a|4b|4c --public-host NAME --guest-root PATH
                       [--candidate SHA] [--out DIR] [--edition-dir /opt/krate/epc] [--rows W5,W6]

--guest-root PATH is the fixed guest tree the agent may deliver into (e.g.
/home/<guest-user>/gate); the rendezvous is $PATH/rdv. It is required, never guessed, so the
agent's isolation holds.
EOF
exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm) VM="$2"; shift 2 ;;
    --phase) PHASE="$2"; shift 2 ;;
    --candidate) CANDIDATE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --public-host) HOST="$2"; shift 2 ;;
    --edition-dir) EDITION_DIR="$2"; shift 2 ;;
    --rows) ROWS="$2"; shift 2 ;;
    --guest-root) GUEST_ROOT="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$VM" && -n "$PHASE" && -n "$HOST" && -n "$GUEST_ROOT" ]] || usage
MAC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$MAC_DIR/../../.." && pwd)"
SHA="$(git -C "$REPO" rev-parse HEAD)"
CANDIDATE="${CANDIDATE:-$SHA}"
if [[ "$CANDIDATE" != "$SHA"* ]]; then
  REQ_CANDIDATE="$CANDIDATE"
  CANDIDATE="$(git -C "$REPO" rev-parse --verify --quiet "${CANDIDATE}^{commit}" || true)"
  [[ -n "$CANDIDATE" ]] || { echo "run-vm-gate: --candidate $REQ_CANDIDATE is not a commit of $REPO" >&2; exit 2; }
fi
OUT="${OUT:-$REPO/harness/gate-receipts/topo-mac-$PHASE-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT" "$OUT/agent-tmp"
case "$(uname -s):$(uname -m)" in Darwin:arm64|Darwin:x86_64) ;; *) echo "run-vm-gate: the Mac launcher runs on a macOS host (this is $(uname -s):$(uname -m))" >&2; exit 2 ;; esac

# ── preconditions ──
PREFLIGHT_FAIL=0
if ! pmset -g batt 2>/dev/null | grep -q 'AC Power'; then
  echo "run-vm-gate: refuse: the Mac is not on AC Power (a heavy stack must not be run on battery)" >&2
  PREFLIGHT_FAIL=1
fi
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [[ ! -x "$CHROME_BIN" ]]; then
  echo "run-vm-gate: refuse: $CHROME_BIN is not the installed Chrome" >&2
  PREFLIGHT_FAIL=1
fi
check_playwright() { # PW_MODULES must carry the gate's pin 1.60.0
  if [[ -z "${PW_MODULES:-}" || ! -d "$PW_MODULES/playwright" ]]; then
    echo "run-vm-gate: refuse: PW_MODULES must name the Mac playwright node_modules (scripts/gate/mac/package.json pins 1.60.0; install once with PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci)" >&2
    return 1
  fi
  local ver
  ver="$(PW_MODULES="$PW_MODULES" python3 -I -c 'import json, os; print(json.load(open(os.environ["PW_MODULES"] + "/playwright/package.json"))["version"])' 2>/dev/null || echo)"
  if [[ "$ver" != 1.60.0 ]]; then
    echo "run-vm-gate: refuse: PW_MODULES playwright is '${ver:-unset}', not the pin 1.60.0" >&2
    return 1
  fi
}
check_playwright || PREFLIGHT_FAIL=1
if scutil --proxy 2>/dev/null | grep -E '^\s*(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)\s*=\s*1$' | grep -q .; then
  echo "run-vm-gate: refuse: the Mac runs a system proxy; --host-resolver-rules would not apply to proxy-resolved names (TOPOFIX F3)" >&2
  PREFLIGHT_FAIL=1
fi
if [[ -e "$REPO/harness/worktrees/gate-${CANDIDATE:0:7}" ]]; then
  echo "run-vm-gate: reusing worktree harness/worktrees/gate-${CANDIDATE:0:7}"
  WT="$REPO/harness/worktrees/gate-${CANDIDATE:0:7}"
else
  WT="$REPO/harness/worktrees/gate-${CANDIDATE:0:7}"
  git -C "$REPO" worktree add "$WT" "$CANDIDATE" >/dev/null 2>&1
  echo "run-vm-gate: ledger row for the operator (Serena project/keycloak-first-resources): created worktree $WT from $CANDIDATE; remove it with git worktree remove and mark the row removed when the run is harvested"
fi
[[ -f "$WT/scripts/gate/browser-launch.mjs" && -f "$WT/scripts/gate/mac/agent.mjs" && -f "$WT/scripts/gate/browser_remote.py" ]] \
  || { echo "run-vm-gate: the candidate worktree $WT lacks the gate files this launcher binds (browser-launch.mjs, mac/agent.mjs, browser_remote.py)" >&2; PREFLIGHT_FAIL=1; }
(( PREFLIGHT_FAIL == 0 )) || exit 2
caffeinate -dims &
CAFF_PID=$!
trap 'kill "$CAFF_PID" 2>/dev/null || true; [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null || true' EXIT

# ── guest address (M1/M2 call shapes) ──
VM_IP="$(limactl shell "$VM" -- ip -4 -o addr show 2>/dev/null | awk '/lima0/ {split($4, a, "/"); print a[1]; exit}')"
if [[ -z "$VM_IP" ]]; then
  echo "run-vm-gate: no IPv4 address on the guest lima0 (is $VM a vzNAT VM and up?): $(limactl shell "$VM" -- ip -4 -o addr show 2>/dev/null | head -3 | tr '\n' ' ')" >&2
  exit 2
fi
IFACE="$(route -n get "$VM_IP" 2>/dev/null | awk '/interface:/ {print $2; exit}')"
[[ -n "$IFACE" ]] || { echo "run-vm-gate: route -n get $VM_IP names no interface" >&2; exit 2; }
nc -z -G 3 "$VM_IP" 22 >/dev/null 2>&1 || { echo "run-vm-gate: no ssh to $VM_IP:22 from the Mac (Local Network prompt? launch from Terminal.app, F7)" >&2; exit 2; }
echo "run-vm-gate: vm_ip=$VM_IP via $IFACE; preflight ok"

# ── agent + guest runner ──
NONCE="$(openssl rand -hex 16)"
RDV="$GUEST_ROOT/rdv"
limactl shell "$VM" -- mkdir -p "$RDV" "$GUEST_ROOT/agent-out" 2>/dev/null   # agent-out: limactl copy -r cannot create a missing parent (PRE-3)
TMPDIR="$OUT/agent-tmp" PW_MODULES="$PW_MODULES" node "$WT/scripts/gate/mac/agent.mjs" \
  --vm "$VM" --rendezvous "$RDV" --guest-root "$GUEST_ROOT" --public-host "$HOST" \
  --rows "$ROWS" --out "$OUT" --guest-cert "$EDITION_DIR/certs/server.crt" \
  --rendezvous-nonce "$NONCE" >"$OUT/agent.log" 2>&1 &
AGENT_PID=$!
# PRE-2: the guest runner's preflight reads the hello at argument-validation time, a fraction of a
# second after it starts; wait until the agent's first hello is in the guest rendezvous (or the
# agent died) before starting the runner.
hello_seen=0
for _ in $(seq 1 45); do
  if limactl shell "$VM" -- test -s "$RDV/agent-hello.json" 2>/dev/null; then hello_seen=1; break; fi
  kill -0 "$AGENT_PID" 2>/dev/null || { echo "run-vm-gate: the agent exited before its hello reached $RDV (see $OUT/agent.log)" >&2; exit 2; }
  sleep 2
done
(( hello_seen == 1 )) || { echo "run-vm-gate: no agent-hello.json in $RDV within 90 s (see $OUT/agent.log)" >&2; exit 2; }
# S3 (review): the receipt path is passed explicitly, so the launcher harvests what the runner
# actually wrote instead of scanning for a default path it would never match; a guest death
# without a receipt must not exit rc=0.
GUEST_RECEIPT="$GUEST_ROOT/receipt-${CANDIDATE:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
GUEST_CMD="cd $GUEST_ROOT/repo && scripts/gate-identity.sh --edition-dir $EDITION_DIR --wipe --phase $PHASE --public-host $HOST --out $GUEST_RECEIPT --browser agent --rendezvous $RDV --rendezvous-nonce $NONCE --candidate $CANDIDATE --repo $GUEST_ROOT/repo"   # PRE-7: the bound, full-inventory shape of a bundle host (identity-gate.md, the bundle-host invocation)
limactl shell "$VM" -- sh -c "nohup setsid sh -c $(printf '%q' "$GUEST_CMD") > $GUEST_ROOT/run-${CANDIDATE:0:7}.log 2>&1 & echo \$! > $RDV/runner.pid"
echo "run-vm-gate: guest runner detached (pid $(limactl shell "$VM" -- cat "$RDV/runner.pid" 2>/dev/null | tr -d '[:space:]')), tail $GUEST_ROOT/run-${CANDIDATE:0:7}.log"

# ── tail until the runner exits ──
echo "run-vm-gate: tailing the guest run log (Ctrl-C stops the launcher; the agent keeps its writes until then)"
while :; do
  sleep 20
  if limactl shell "$VM" -- sh -c "kill -0 \$(cat $RDV/runner.pid 2>/dev/null) 2>/dev/null" 2>/dev/null; then
    :
  else
    echo "run-vm-gate: the guest runner exited"
    break
  fi
done

# ── end-of-run invariants (F7): the guest's lima0 address must be unchanged ──
VM_IP_END="$(limactl shell "$VM" -- ip -4 -o addr show 2>/dev/null | awk '/lima0/ {split($4, a, "/"); print a[1]; exit}')"
if [[ "$VM_IP_END" != "$VM_IP" ]]; then
  echo "run-vm-gate: FAIL: the guest lima0 address changed during the run ($VM_IP -> $VM_IP_END); the certificate/nonce binding is void (F7; a DHCP re-lease)" >&2
  RC=3
else
  echo "run-vm-gate: the guest lima0 address is unchanged at the end ($VM_IP)"
  RC=0
fi

# ── stop the agent and harvest ──
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
limactl copy --backend=scp -r "$VM:$GUEST_ROOT/agent-out" "$OUT/agent-from-guest" 2>/dev/null || echo "run-vm-gate: note: no agent-out tree was delivered (the rows may not have run)"
RECEIPT_GUEST="$(limactl shell "$VM" -- sh -c "test -d $GUEST_RECEIPT && echo $GUEST_RECEIPT" 2>/dev/null | tr -d '[:space:]')"
if [[ -n "${RECEIPT_GUEST:-}" ]]; then
  limactl copy --backend=scp -r "$VM:$RECEIPT_GUEST" "$OUT/$(basename "$RECEIPT_GUEST")"
  echo "run-vm-gate: receipt harvested: $(basename "$RECEIPT_GUEST")"
else
  # S3: a dead guest runner (missing $GUEST_ROOT/repo, a refused preflight) must fail the
  # launcher, not exit rc=0 with nothing harvested.
  echo "run-vm-gate: FAIL: the named guest receipt $GUEST_RECEIPT does not exist (the guest runner died before writing one; its log is $GUEST_ROOT/run-${CANDIDATE:0:7}.log)" >&2
  RC=$((RC | 8))
fi
# agent-manifest vs harvested evidence: every manifest row's file digest must appear in the
# delivered agent-from-guest tree (the guest's receipt copy is the runner's own evidence path).
if [[ -f "$OUT/agent-manifest.tsv" && -d "$OUT/agent-from-guest" ]]; then
  BAD=0
  while IFS=$'\t' read -r rid row rsha files _; do # the TSV: id, row, request sha, file digests, chrome version
    [[ "$rid" == request_id || -z "$files" ]] && continue
    # shellcheck disable=SC2086  # the files column holds space-separated 12-hex digests
    for d in $files; do
      if ! find "$OUT/agent-from-guest" -type f -exec shasum -a 256 {} + 2>/dev/null | grep -q "^${d}[0-9a-f]*  "; then
        echo "run-vm-gate: manifest row $row/$rid (request ${rsha:-?}) names a file whose digest ($d) is not in the harvested evidence" >&2
        BAD=1
      fi
    done
  done < "$OUT/agent-manifest.tsv"
  (( BAD == 0 )) || RC=$((RC | 4))
  echo "run-vm-gate: agent-manifest verified against the harvested evidence"
fi
echo "run-vm-gate: out=$OUT rc=$RC; the agent-manifest.tsv, agent.log and the guest receipt are in that folder"
exit "$RC"