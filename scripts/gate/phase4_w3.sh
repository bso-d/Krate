#!/usr/bin/env bash
# Linux W3 gate row. A network namespace + veth pair stands in for a machine on
# the LAN. The probe method was observed in harness/phase4/lab8/results.md.
# Env:
#   W1X_POSITIVE_PORT  host port published on all addresses (the Perses gateway in this gate)
#   W1X_POSITIVE_SCHEME http|https (https probes use -k: only reachability is asserted)
#   W1X_LOOPBACK_PORTS host ports that must be loopback-only (Prometheus, Loki, Grafana)
#   W3_PUBLIC_HOST     fixture HTTPS hostname for the reachable control
#   W3_CLUSTER_PROJECT, W3_MONITOR_PROJECT  Compose projects whose running containers
#                      and image-declared TCP ports are probed on every container IP
# Exit 0 = PASS, 1 = FAIL, 2 = NOT_RUN. RESULT W3 carries the verdict; an
# unsuccessful cleanup emits a later overriding FAIL result.
set -uo pipefail
NS=p4probe; VH=p4v0; VN=p4v1; HA=10.99.77.1; NA=10.99.77.2; PFX=30
POS_PORT="${W1X_POSITIVE_PORT:-3000}"; POS_SCHEME="${W1X_POSITIVE_SCHEME:-http}"
LOOP_PORTS="${W1X_LOOPBACK_PORTS:-9090 3100}"
CLUSTER_PROJECT="${W3_CLUSTER_PROJECT:-}"; MONITOR_PROJECT="${W3_MONITOR_PROJECT:-}"
PUBLIC_HOST="${W3_PUBLIC_HOST:-}"
PY_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/phase4_w3.py"
as_root() { if [[ "$(id -u)" == 0 ]]; then "$@"; else sudo -n "$@"; fi; }
# Capability check mirrors the runner's J7-style W3 inventory decision.
W3_REQUIRED=false
if [[ "$(uname -s)" == Linux ]] && { [[ "$(id -u)" == 0 ]] || sudo -n true 2>/dev/null; } \
   && command -v ip >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 && as_root ip netns list >/dev/null 2>&1; then
  W3_REQUIRED=true
fi
echo "W3_REQUIRED=$W3_REQUIRED uid=$(id -u) user=$(id -un)"
if ! $W3_REQUIRED; then echo "RESULT W3 NOT_RUN needs Linux, root (or sudo -n), iproute2 netns and curl"; exit 2; fi
if [[ -z "$CLUSTER_PROJECT" || -z "$MONITOR_PROJECT" || -z "$PUBLIC_HOST" || ! -f "$PY_HELPER" ]]; then
  echo "RESULT W3 FAIL both Compose project names and public host are required"; exit 1
fi
FAILS=0; CHECKS=0
ok()  { CHECKS=$((CHECKS+1)); echo "  ok: $*"; }
bad() { CHECKS=$((CHECKS+1)); FAILS=$((FAILS+1)); echo "  FAIL: $*"; }
# preconditions: names free, probe subnet collides with nothing but the default route
if as_root ip netns list | grep -qw "$NS" || ip link show "$VH" >/dev/null 2>&1; then
  echo "RESULT W3 FAIL probe names $NS/$VH already in use (stale run?)"; exit 1; fi
if ip -4 route show match "$NA" | grep -qv '^default' || ip -4 -o addr show | grep -qF " ${HA%.*}."; then
  echo "RESULT W3 FAIL probe subnet $HA/$PFX overlaps a local route/address"; exit 1; fi
PIF=$(ip -4 route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
PADDR=$(ip -4 -o addr show dev "$PIF" scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
if [[ -z "$PIF" || -z "$PADDR" ]]; then
  echo "RESULT W3 FAIL cannot determine the host primary IPv4 interface/address"; exit 1
fi
FWZONE=""; FW_ASSIGNED=false
OWN_NS=false; OWN_VH=false
# shellcheck disable=SC2317  # invoked through trap
cleanup() {
  local left="" namespace_list
  if $FW_ASSIGNED && ! as_root firewall-cmd -q --zone="$FWZONE" --remove-interface="$VH" 2>/dev/null; then
    left+=" firewalld:$FWZONE"
  fi
  $OWN_NS && as_root ip netns del "$NS" 2>/dev/null
  $OWN_VH && as_root ip link del "$VH" 2>/dev/null
  if namespace_list=$(as_root ip netns list 2>/dev/null); then
    grep -qw "$NS" <<< "$namespace_list" && left+=" netns:$NS"
  else
    left+=" netns-list-unknown"
  fi
  ip link show "$VH" >/dev/null 2>&1 && left+=" link:$VH"
  echo "cleanup: ${left:-nothing left}"
  if [[ -n "$left" ]]; then
    trap - EXIT
    echo "RESULT W3 FAIL probe resources left:$left"
    exit 1
  fi
}
trap cleanup EXIT
if as_root ip netns add "$NS"; then OWN_NS=true; else echo "RESULT W3 FAIL could not create probe namespace"; exit 1; fi
if as_root ip link add "$VH" type veth peer name "$VN"; then OWN_VH=true; else echo "RESULT W3 FAIL could not create probe veth"; exit 1; fi
if ! { as_root ip link set "$VN" netns "$NS" \
 && as_root ip addr add "$HA/$PFX" dev "$VH" && as_root ip link set "$VH" up \
 && as_root ip -n "$NS" addr add "$NA/$PFX" dev "$VN" && as_root ip -n "$NS" link set lo up && as_root ip -n "$NS" link set "$VN" up \
 && as_root ip -n "$NS" route add default via "$HA"; }; then echo "RESULT W3 FAIL could not build the probe namespace"; exit 1; fi
# firewalld: let the probe interface be judged like the LAN interface (runtime only; removed in cleanup)
if systemctl is-active -q firewalld 2>/dev/null; then
  FWZONE=$(as_root firewall-cmd --get-zone-of-interface="$PIF" 2>/dev/null) || FWZONE=$(as_root firewall-cmd --get-default-zone)
  FW_ASSIGNED=true  # removal is attempted even if assignment only partially succeeds
  if as_root firewall-cmd -q --zone="$FWZONE" --add-interface="$VH"; then
    echo "firewalld: $VH added to zone $FWZONE (zone of $PIF), runtime only"
  else
    echo "RESULT W3 FAIL cannot mirror the primary firewalld zone on $VH"; exit 1
  fi
fi
LL=""; PEER_LL=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  host_addr=$(ip -6 -o addr show dev "$VH" scope link)
  peer_addr=$(as_root ip -n "$NS" -6 -o addr show dev "$VN" scope link)
  if [[ "$host_addr" == *" inet6 "* && "$peer_addr" == *" inet6 "* \
        && "$host_addr" != *tentative* && "$peer_addr" != *tentative* \
        && "$host_addr" != *dadfailed* && "$peer_addr" != *dadfailed* ]]; then
    LL=$(printf '%s\n' "$host_addr" | awk '{print $4}' | cut -d/ -f1 | head -1)
    PEER_LL=$(printf '%s\n' "$peer_addr" | awk '{print $4}' | cut -d/ -f1 | head -1)
    break
  fi
  sleep 0.5
done
echo "probe: netns $NS $NA/$PFX via $VH $HA; primary $PIF $PADDR; host link-local ${LL:-none}"
if [[ -z "$LL" || -z "$PEER_LL" ]]; then
  echo "RESULT W3 FAIL IPv6 link-local address on both veth ends was not ready within 5 s"
  exit 1
fi
probe() { # url [control destination IP] -> 0 answered, 1 refused/timeout, 2 other
  local out rc
  if [[ -n "${2:-}" ]]; then
    out=$(as_root ip netns exec "$NS" curl -sS -k -g --noproxy '*' -o /dev/null -m 5 -w '%{http_code}' \
      --resolve "$PUBLIC_HOST:$POS_PORT:$2" "$1" 2>&1); rc=$?
  else
    out=$(as_root ip netns exec "$NS" curl -sS -k -g --noproxy '*' -o /dev/null -m 5 -w '%{http_code}' "$1" 2>&1); rc=$?
  fi
  echo "    netns curl $1 connect=${2:-url} -> rc=$rc ${out//$'\n'/ }"
  case $rc in 0) return 0;; 7|28) return 1;; *) return 2;; esac
}
must_reach() { if probe "$1" "${3:-}"; then ok "$2 reachable (control)"; else bad "$2 NOT reachable: the probe path is invalid"; fi; }
tcp_probe() { # host port -> 0 connected, 1 refused/timeout/unreachable, 2 unknown
  local out rc
  out=$(as_root ip netns exec "$NS" python3 -I "$PY_HELPER" tcp "$1" "$2" 2>&1); rc=$?
  echo "    netns TCP $1:$2 -> rc=$rc ${out//$'\n'/ }"
  return "$rc"
}
must_not_tcp() {
  tcp_probe "$1" "$2"
  local r=$?
  if [[ $r -eq 1 ]]; then ok "$3 not reachable"; else bad "$3 reachable or inconclusive (class $r)"; fi
}
must_reach_tcp() {
  if tcp_probe "$1" "$2"; then ok "$3 reachable (IPv6 control)"; else bad "$3 NOT reachable: the IPv6 probe path is invalid"; fi
}
# Read the live inventory. An empty project, failed Docker query or missing
# ExposedPorts data must never turn the direct-container section into a vacuous PASS.
CONTAINERS=(); TARGETS=()
for project in "$CLUSTER_PROJECT" "$MONITOR_PROJECT"; do
  names=$(as_root docker ps --filter "label=com.docker.compose.project=$project" --format '{{.Names}}') || {
    echo "RESULT W3 FAIL cannot enumerate Compose project $project"; exit 1;
  }
  if [[ -z "$names" ]]; then
    echo "RESULT W3 FAIL no running containers in Compose project $project"; exit 1
  fi
  while IFS= read -r c; do
    [[ -n "$c" ]] || continue
    CONTAINERS+=("$c")
    # shellcheck disable=SC2016  # Docker Go template variables, not shell expansions
    exposed=$(as_root docker inspect -f '{{range $p,$v := .Config.ExposedPorts}}{{$p}} {{end}}' "$c") || {
      echo "RESULT W3 FAIL cannot inspect exposed ports of $c"; exit 1;
    }
    for entry in $exposed; do
      [[ "$entry" == */tcp ]] || continue
      port="${entry%/tcp}"
      [[ "$port" =~ ^[0-9]+$ ]] || { echo "RESULT W3 FAIL invalid exposed port $entry on $c"; exit 1; }
      TARGETS+=("$c:$port")
    done
  done <<< "$names"
done
if (( ${#TARGETS[@]} == 0 )); then
  echo "RESULT W3 FAIL no image-declared TCP ports in either Compose project"; exit 1
fi
echo "inventory: ${#CONTAINERS[@]} live containers, ${#TARGETS[@]} exposed TCP target pairs across $CLUSTER_PROJECT and $MONITOR_PROJECT"
echo "## a. positive control: a port published on all addresses answers through the probe path"
must_reach "$POS_SCHEME://$PUBLIC_HOST:$POS_PORT/" "veth $HA:$POS_PORT" "$HA"
echo "## b. loopback-only host ports, from a non-loopback source"
for p in $LOOP_PORTS; do
  must_not_tcp "$HA" "$p" "veth $HA:$p"
  must_not_tcp "$PADDR" "$p" "primary $PADDR:$p"
done
if [[ -n "$LL" ]]; then
  must_reach_tcp "$LL%$VN" "$POS_PORT" "IPv6 link-local $LL:$POS_PORT"
  for p in $LOOP_PORTS; do must_not_tcp "$LL%$VN" "$p" "IPv6 link-local :$p"; done
else
  bad "no IPv6 link-local address on $VH; IPv6 negative checks are inconclusive"
fi
echo "## c. backend container IPs (direct routing)"
for t in "${TARGETS[@]}"; do
  c="${t%%:*}"; cp="${t##*:}"
  ips=$(as_root docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}' "$c" 2>/dev/null) || { bad "$c: no such container"; continue; }
  if [[ -z "${ips// /}" ]]; then bad "$c:$cp has no inspectable container IP"; continue; fi
  for ip in $ips; do
    policy_out=$(python3 -I "$PY_HELPER" target-policy "$ip" 2>&1); policy_rc=$?
    if [[ $policy_rc -ne 0 ]]; then
      bad "$c $ip:$cp: $policy_out"
      continue
    fi
    must_not_tcp "$ip" "$cp" "$c $ip:$cp"
  done
done
echo "## d. same-segment packets addressed to 127.0.0.1 (pre-28.0 Docker exposed loopback-published ports to them)"
as_root ip netns exec "$NS" sysctl -q -w net.ipv4.conf."$VN".route_localnet=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf."$VN".rp_filter=0 || bad "cannot enable same-segment 127.0.0.1 route prerequisites"
pref=10
for p in "$POS_PORT" $LOOP_PORTS; do as_root ip -n "$NS" rule add pref $pref to 127.0.0.1/32 ipproto tcp dport "$p" lookup 99; pref=$((pref+1)); done
as_root ip -n "$NS" rule del pref 0 lookup local && as_root ip -n "$NS" rule add pref 100 lookup local \
 && as_root ip -n "$NS" route add 127.0.0.1/32 via "$HA" dev "$VN" src "$NA" table 99
must_reach "$POS_SCHEME://$PUBLIC_HOST:$POS_PORT/" "dst 127.0.0.1:$POS_PORT from the segment" 127.0.0.1
for p in $LOOP_PORTS; do must_not_tcp 127.0.0.1 "$p" "dst 127.0.0.1:$p from the segment"; done
echo "## e. static: Docker options that open direct routing per interface (invisible to a probe that enters on $VH)"
declare -A seen_network=()
for c in "${CONTAINERS[@]}"; do
  # shellcheck disable=SC2016  # Go template, not shell
  networks=$(as_root docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c" 2>/dev/null) || {
    bad "$c: cannot inspect networks"; continue
  }
  for n in $networks; do
    [[ -z "${seen_network[$n]:-}" ]] || continue
    seen_network["$n"]=1
    o=$(as_root docker network inspect -f '{{index .Options "com.docker.network.bridge.trusted_host_interfaces"}}|{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}|{{index .Options "com.docker.network.bridge.gateway_mode_ipv6"}}' "$n")
    o="${o//<no value>/}"
    if [[ "$o" =~ ^\|(nat)?\|(nat)?$ ]]; then
      ok "network $n: no trusted_host_interfaces, IPv4/IPv6 gateway modes default or nat"
    else
      bad "network $n: trusted_host_interfaces|gateway_mode_ipv4|gateway_mode_ipv6 = $o"
    fi
  done
done
daemon_out=$(as_root python3 -I "$PY_HELPER" daemon-config 2>&1); daemon_rc=$?
if [[ $daemon_rc -eq 0 && "$daemon_out" == CONFIG_CLOSED* ]]; then
  ok "dockerd: $daemon_out"
else
  bad "dockerd: $daemon_out (exit $daemon_rc)"
fi
if (( FAILS == 0 )); then echo "RESULT W3 PASS $CHECKS checks (${#TARGETS[@]} container TCP targets)"; exit 0; else echo "RESULT W3 FAIL $FAILS of $CHECKS checks failed"; exit 1; fi
