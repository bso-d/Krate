#!/usr/bin/env bash
# Mac launcher for the identity gate on a vzNAT VM fixture (TOPOFIX-DESIGN 3.6 table
# `scripts/gate/mac/run-vm-gate.sh`, amendments TOPOFIX-REVIEW F7/F8).
#
# One launcher for one heavy stack: it refuses on a battery below 30% (the available charge decides;
# AC is never a requirement), keeps the display awake
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
# Review R1: the guest tree is cleaned with `rm -rf` below, so the launcher checks --guest-root with the shape agent.mjs's guestPath accepts
# (absolute, plain characters, already normalized) before it builds any guest command from it. LC_ALL=C keeps the character ranges ASCII.
guest_path_ok() { # path: returns 0 for a normalized absolute guest path matching ^/[A-Za-z0-9._/-]+$ (no '..', '.', '//' or trailing '/')
  local LC_ALL=C
  [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
  case "$1/" in */./* | */../* | *//*) return 1 ;; esac
  return 0
}
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
guest_path_ok "$GUEST_ROOT" || { echo "run-vm-gate: --guest-root must be a normalized absolute guest path matching ^/[A-Za-z0-9._/-]+\$ (no '..', '.', '//' or trailing '/'): $GUEST_ROOT" >&2; exit 2; }
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

# Review T14: a harvested receipt directory is not a successful run. Success needs the guest runner's own exit status (0 only for a
# PASS verdict: finish() returns `[[ $verdict == PASS ]]`) AND a harvested receipt whose verdict row says PASS and whose candidate commit is the
# launcher's candidate. A killed runner leaves no status, an unfinished receipt has no verdict row.
receipt_verdict() { # receipt.md -> PASS | FAIL | INCOMPLETE, or nothing
  sed -n -E 's/^\| verdict \| \*\*([A-Z_]+)\*\*.*/\1/p' "$1" 2>/dev/null | head -1
}
receipt_candidate_ok() { # receipt.md candidate: the receipt's candidate commit row starts with the launcher's candidate
  local row
  row="$(sed -n -E 's/^\| candidate commit \| ([0-9a-f]+).*/\1/p' "$1" 2>/dev/null | head -1)"
  [[ -n "$row" && "$row" == "$2"* ]]
}
run_outcome() { # runner_rc receipt.md candidate: prints the reason and returns 1 unless the run is a candidate-bound PASS
  local rrc="$1" receipt="$2" cand="$3" verdict
  if [[ ! "$rrc" =~ ^[0-9]+$ ]]; then echo "the guest runner left no exit status (it was killed before it finished)"; return 1; fi
  if (( rrc != 0 )); then echo "the guest runner exited $rrc"; return 1; fi
  [[ -f "$receipt" ]] || { echo "no harvested receipt.md"; return 1; }
  verdict="$(receipt_verdict "$receipt")"
  [[ "$verdict" == PASS ]] || { echo "the receipt verdict is '${verdict:-missing}', not PASS"; return 1; }
  receipt_candidate_ok "$receipt" "$cand" || { echo "the receipt's candidate commit is not the launcher's candidate $cand"; return 1; }
  return 0
}

# Review T13: the guest checkout the runner is started from (and that --repo names) must be at the candidate, checked here so a wrong
# checkout stops the launcher before the agent and the heavy run start (the runner re-checks HEAD == candidate itself).
guest_head_is_candidate() { # head candidate: the guest checkout's HEAD starts with the launcher's candidate
  [[ -n "$1" && "$1" == "$2"* ]]
}

# Review round 4: the directory name is not proof of candidate identity. Check the
# actual checkout and every gate source (tracked or untracked) before executing the agent.
candidate_worktree_ok() { # worktree candidate: fail closed on either unreadable Git query
  local head changes
  head="$(git -C "$1" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || {
    echo "run-vm-gate: cannot read the candidate worktree HEAD at $1" >&2; return 1;
  }
  [[ "$head" == "$2" ]] || {
    echo "run-vm-gate: the candidate worktree $1 is at '$head', not $2" >&2; return 1;
  }
  changes="$(git -C "$1" status --porcelain=v1 --untracked-files=all -- scripts/gate scripts/gate-identity.sh 2>/dev/null)" || {
    echo "run-vm-gate: cannot read gate-source cleanliness at $1" >&2; return 1;
  }
  [[ -z "$changes" ]] || {
    echo "run-vm-gate: the candidate worktree $1 has changed or untracked gate source" >&2; return 1;
  }
}

# ── preconditions ──
PREFLIGHT_FAIL=0
# Power rule (owner instruction 2026-10-23): the battery's available charge decides; AC is never a
# requirement. Refuse only on a battery that is present AND under 30%; a Mac with no battery (desktop)
# has no charge to lose and runs.
batt_pct="$(pmset -g batt 2>/dev/null | awk '/InternalBattery/ {pct=$3; gsub(/[^0-9]/, "", pct); print pct+0}')" || true
if [ -n "$batt_pct" ] && [ "$batt_pct" -lt 30 ]; then
  echo "run-vm-gate: refuse: the Mac's available charge is ${batt_pct}% (the rule: 30% or more)" >&2
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
if scutil --proxy 2>/dev/null | grep -E '^[[:space:]]*(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)[[:space:]]*:[[:space:]]*1[[:space:]]*$' | grep -q .; then
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
candidate_worktree_ok "$WT" "$CANDIDATE" || PREFLIGHT_FAIL=1
[[ -f "$WT/scripts/gate/browser-launch.mjs" && -f "$WT/scripts/gate/mac/agent.mjs" && -f "$WT/scripts/gate/browser_remote.py" ]] \
  || { echo "run-vm-gate: the candidate worktree $WT lacks the gate files this launcher binds (browser-launch.mjs, mac/agent.mjs, browser_remote.py)" >&2; PREFLIGHT_FAIL=1; }
(( PREFLIGHT_FAIL == 0 )) || exit 2
caffeinate -dims &
CAFF_PID=$!
trap 'kill "$CAFF_PID" 2>/dev/null || true; [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null || true' EXIT

# ── guest address (M1/M2 call shapes) ──
# Review R2: the launcher runs under `set -euo pipefail`, so a read that FAILS (limactl, route, a missing guest file) would end the script
# silently before the message written for it; every such read below ends in `|| true` and its value is judged by the code after it.
VM_IP="$(limactl shell "$VM" -- ip -4 -o addr show 2>/dev/null | awk '/lima0/ {split($4, a, "/"); print a[1]; exit}' || true)"
if [[ -z "$VM_IP" ]]; then
  echo "run-vm-gate: no IPv4 address on the guest lima0 (is $VM a vzNAT VM and up?): $(limactl shell "$VM" -- ip -4 -o addr show 2>/dev/null | head -3 | tr '\n' ' ')" >&2
  exit 2
fi
IFACE="$(route -n get "$VM_IP" 2>/dev/null | awk '/interface:/ {print $2; exit}' || true)"
[[ -n "$IFACE" ]] || { echo "run-vm-gate: route -n get $VM_IP names no interface" >&2; exit 2; }
nc -z -G 3 "$VM_IP" 22 >/dev/null 2>&1 || { echo "run-vm-gate: no ssh to $VM_IP:22 from the Mac (Local Network prompt? launch from Terminal.app, F7)" >&2; exit 2; }
echo "run-vm-gate: vm_ip=$VM_IP via $IFACE; preflight ok"

# ── one gate run on the fixture at a time ──
# An interleaved second runner kills the first run's live fixture mid-row (2026-10-23: the 04:43
# attempt was launched while the 04:39 run still had rows running; its reset's compose down
# removed the other run's keycloak between two rows and the 04:39 ledger's B-block failed with
# 'Keycloak is not running'). Refuse while any gate runner is still live on the guest.
live_runners="$(limactl shell "$VM" -- sh -c "pgrep -af 'scripts/gate-identity' | grep -v pgrep || true" 2>/dev/null || true)"
if [[ -n "$live_runners" ]]; then
  echo "run-vm-gate: refuse: a gate runner is already live on $VM (wait for its receipt or stop it first):" >&2
  echo "$live_runners" >&2
  exit 2
fi

# ── agent + guest runner ──
GUEST_HEAD="$(limactl shell "$VM" -- git -C "$GUEST_ROOT/repo" rev-parse HEAD 2>/dev/null | tr -d '[:space:]' || true)"
guest_head_is_candidate "$GUEST_HEAD" "$CANDIDATE" \
  || { echo "run-vm-gate: the guest checkout $GUEST_ROOT/repo is at '${GUEST_HEAD:-unreadable}', not the candidate $CANDIDATE" >&2; exit 2; }
NONCE="$(openssl rand -hex 16)"
RDV="$GUEST_ROOT/rdv"
# Review R1: the delivery folder starts every run EMPTY. `limactl copy --backend=scp -r DIR VM:agent-out/w5` puts DIR INSIDE an existing
# agent-out/w5 (scp -r into an existing directory nests), so an earlier run's w5-result.json would stay where the runner reads it.
limactl shell "$VM" -- rm -rf -- "$GUEST_ROOT/agent-out" 2>/dev/null || { echo "run-vm-gate: could not empty $GUEST_ROOT/agent-out in the guest; an earlier run's delivery would be read as this run's" >&2; exit 2; }
limactl shell "$VM" -- mkdir -p "$RDV" "$GUEST_ROOT/agent-out" 2>/dev/null || { echo "run-vm-gate: could not create $RDV and $GUEST_ROOT/agent-out in the guest (is $GUEST_ROOT writable?)" >&2; exit 2; }   # agent-out: limactl copy -r cannot create a missing parent (PRE-3)
limactl shell "$VM" -- rm -f "$RDV/runner.rc" "$RDV/runner.pid" 2>/dev/null || { echo "run-vm-gate: could not remove an earlier runner.rc/runner.pid from $RDV in the guest; an earlier exit status would be read as this run's" >&2; exit 2; }   # a previous run's exit status must not be read as this run's (T14)
TMPDIR="$OUT/agent-tmp" PW_MODULES="$PW_MODULES" node "$WT/scripts/gate/mac/agent.mjs" \
  --vm "$VM" --rendezvous "$RDV" --guest-root "$GUEST_ROOT" --public-host "$HOST" \
  --rows "$ROWS" --out "$OUT" --guest-cert "$EDITION_DIR/certs/server.crt" \
  --rendezvous-nonce "$NONCE" >"$OUT/agent.log" 2>&1 &
AGENT_PID=$!
# PRE-2: the guest runner's preflight reads the hello at argument-validation time, a fraction of a
# second after it starts; wait until the agent's first hello is in the guest rendezvous (or the
# agent died) before starting the runner.
hello_seen=0
hello_deadline=$((SECONDS + 90))   # review R9: a wall-clock bound; each pass costs one limactl round trip plus the sleep, so a pass count is not 90 s
while (( SECONDS < hello_deadline )); do
  if limactl shell "$VM" -- grep -q -F -- "$NONCE" "$RDV/agent-hello.json" 2>/dev/null; then hello_seen=1; break; fi   # present, non-empty and carrying THIS run's nonce
  kill -0 "$AGENT_PID" 2>/dev/null || { echo "run-vm-gate: the agent exited before its hello reached $RDV (see $OUT/agent.log)" >&2; exit 2; }
  sleep 2
done
(( hello_seen == 1 )) || { echo "run-vm-gate: no agent-hello.json in $RDV within 90 s (see $OUT/agent.log)" >&2; exit 2; }
# S3 (review): the receipt path is passed explicitly, so the launcher harvests what the runner
# actually wrote instead of scanning for a default path it would never match; a guest death
# without a receipt must not exit rc=0.
GUEST_RECEIPT="$GUEST_ROOT/receipt-${CANDIDATE:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
GUEST_CMD="cd $GUEST_ROOT/repo && scripts/gate-identity.sh --edition-dir $EDITION_DIR --wipe --phase $PHASE --public-host $HOST --out $GUEST_RECEIPT --browser agent --rendezvous $RDV --rendezvous-nonce $NONCE --candidate $CANDIDATE --repo $GUEST_ROOT/repo"   # PRE-7: the bound, full-inventory shape of a bundle host (identity-gate.md, the bundle-host invocation)
# the runner's exit status is written next to its pid when it ends (T14): `; echo $?` runs in the detached shell after the runner
limactl shell "$VM" -- sh -c "nohup setsid sh -c $(printf '%q' "$GUEST_CMD; echo \$? > $RDV/runner.rc") > $GUEST_ROOT/run-${CANDIDATE:0:7}.log 2>&1 & echo \$! > $RDV/runner.pid"
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
VM_IP_END="$(limactl shell "$VM" -- ip -4 -o addr show 2>/dev/null | awk '/lima0/ {split($4, a, "/"); print a[1]; exit}' || true)"
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
if ! limactl copy --backend=scp -r "$VM:$GUEST_ROOT/agent-out" "$OUT/agent-from-guest" 2>/dev/null; then
  echo "run-vm-gate: FAIL: could not harvest the agent-out tree; continuing to collect the guest receipt" >&2
  RC=$((RC | 4))
fi
RECEIPT_GUEST="$(limactl shell "$VM" -- sh -c "test -d $GUEST_RECEIPT && echo $GUEST_RECEIPT" 2>/dev/null | tr -d '[:space:]' || true)"
if [[ -n "${RECEIPT_GUEST:-}" ]]; then
  limactl copy --backend=scp -r "$VM:$RECEIPT_GUEST" "$OUT/$(basename "$RECEIPT_GUEST")"
  echo "run-vm-gate: receipt harvested: $(basename "$RECEIPT_GUEST")"
else
  # S3: a dead guest runner (missing $GUEST_ROOT/repo, a refused preflight) must fail the
  # launcher, not exit rc=0 with nothing harvested.
  echo "run-vm-gate: FAIL: the named guest receipt $GUEST_RECEIPT does not exist (the guest runner died before writing one; its log is $GUEST_ROOT/run-${CANDIDATE:0:7}.log)" >&2
  RC=$((RC | 8))
fi
# T14: the run succeeds only as a candidate-bound PASS: the guest runner's own exit status and the harvested receipt's verdict
RUNNER_RC="$(limactl shell "$VM" -- cat "$RDV/runner.rc" 2>/dev/null | tr -d '[:space:]' || true)"   # a runner killed before it finished leaves no runner.rc: run_outcome names that
if OUTCOME_REASON="$(run_outcome "$RUNNER_RC" "${RECEIPT_GUEST:+$OUT/$(basename "$RECEIPT_GUEST")/receipt.md}" "$CANDIDATE")"; then
  echo "run-vm-gate: the run is a candidate-bound PASS (guest runner exit 0, receipt verdict PASS, candidate $CANDIDATE)"
else
  echo "run-vm-gate: FAIL: $OUTCOME_REASON" >&2
  RC=$((RC | 16))
fi
# agent-manifest vs harvested evidence: every manifest row's file digest must appear in the
# delivered agent-from-guest tree (the guest's receipt copy is the runner's own evidence path).
if [[ "$PHASE" == 4c && ( ! -f "$OUT/agent-manifest.tsv" || ! -s "$OUT/agent-manifest.tsv" || ! -r "$OUT/agent-manifest.tsv" || ! -d "$OUT/agent-from-guest" ) ]]; then
  echo "run-vm-gate: FAIL: phase 4c requires a readable, nonempty Mac agent-manifest.tsv and harvested agent-from-guest tree" >&2
  RC=$((RC | 4))
fi
if [[ -f "$OUT/agent-manifest.tsv" && -d "$OUT/agent-from-guest" ]]; then
  BAD=0
  while IFS=$'\t' read -r rid row rsha files _; do # the TSV: id, row, request sha, file digests, chrome version
    [[ "$rid" == request_id || -z "$files" ]] && continue
    # The files column holds space-separated 12-hex digests (agent.mjs builds it with
    # join(' '); check-identity.py:1076's fixture row is a single digest). The read's
    # IFS is tab-only and temporary — it reverts after `read`, so this loop keeps the
    # column one token — thus an explicit word-split on both joins: `printf | tr` for
    # tab-joined content and the default splitting for space-joined (2026-10-23).
    # Digest lines: `sha256sum` (verified on the gate Mac: /sbin/sha256sum, GNU
    # two-space format; Rocky 9 natively; a Mac without an un-prefixed sha256sum in
    # PATH would flag every digest, which the launcher reports).
    for d in $(printf '%s' "$files" | tr '\t' ' '); do
      if ! find "$OUT/agent-from-guest" -type f -exec sha256sum {} + 2>/dev/null | grep -q "^${d}[0-9a-f]*  "; then
        echo "run-vm-gate: manifest row $row/$rid (request ${rsha:-?}) names a file whose digest ($d) is not in the harvested evidence" >&2
        BAD=1
      fi
    done
  done < "$OUT/agent-manifest.tsv"
  (( BAD == 0 )) || RC=$((RC | 4))
  (( BAD != 0 )) || echo "run-vm-gate: agent-manifest verified against the harvested evidence"
fi
echo "run-vm-gate: out=$OUT rc=$RC; the agent-manifest.tsv, agent.log and the guest receipt are in that folder"
exit "$RC"
