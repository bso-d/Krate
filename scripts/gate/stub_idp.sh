#!/usr/bin/env bash
# Stand-in enterprise IdP for the Phase 3 gate: a second Keycloak from the edition's
# pinned KEYCLOAK_IMAGE (so it also runs from an offline bundle), dev mode, throwaway.
# Realm `pingstub`, confidential client `krate-keycloak` whose redirect is the Krate
# realm's broker endpoint, a `groups` claim from group membership, the groups
# APP-KAFKA-VIEWERS / APP-KAFKA-ADMINS and the users ping-viewer, ping-admin,
# ping-both and ping-none. TLS: a certificate generated per run (SAN localhost +
# pingstub) so the browser side reaches it on 127.0.0.1:<port> and the Krate
# Keycloak reaches it as `pingstub` over the fixture's identity-egress network.
# Every secret (admin password, client secret, user password) is a 0600 file under
# the output directory and travels to kcadm through the environment, never argv.
# Used by scripts/gate-identity.sh (Phase 3); proven by hand first in
# harness/phase3/stub-up.sh (rule 11).
#
#   stub_idp.sh up   --project NAME --edition-dir DIR --base URL --out DIR [--port N] [--cluster NAME]
#   stub_idp.sh down --project NAME
#   stub_idp.sh status --project NAME [--port N]
#   stub_idp.sh add-user --project NAME --out DIR USERNAME [GROUP...]
#   stub_idp.sh remove-group --project NAME --out DIR USERNAME GROUP
#   stub_idp.sh rotate-secret --project NAME --out DIR        (new client secret; written to DIR/.client-secret)
# --container NAME names a stand-in started under another name (the Phase 3 development fixture).
set -uo pipefail
umask 077

ACTION="${1:-}"; shift || true
PROJECT=""; EDITION_DIR=""; BASE=""; OUT=""; PORT=18443; CLUSTER="cluster-1-kraft"; CONTAINER_ARG=""
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --edition-dir) EDITION_DIR="$(cd "$2" 2>/dev/null && pwd)" || { echo "stub_idp.sh: --edition-dir $2 is not a directory" >&2; exit 2; }; shift 2 ;;
    --base) BASE="${2%/}"; shift 2 ;;
    --out) mkdir -p "$2" 2>/dev/null; OUT="$(cd "$2" 2>/dev/null && pwd)" || { echo "stub_idp.sh: cannot use --out $2" >&2; exit 2; }; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --cluster) CLUSTER="$2"; shift 2 ;;
    --container) CONTAINER_ARG="$2"; shift 2 ;;
    -*) echo "stub_idp.sh: unknown option $1" >&2; exit 2 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
[[ -n "$PROJECT" ]] || { echo "stub_idp.sh: --project is required" >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "stub_idp.sh: --port must be a number" >&2; exit 2; }
CONTAINER="${CONTAINER_ARG:-${PROJECT}-gate3-pingstub}"
NETWORK="${PROJECT}_identity-egress"
ALIAS=pingstub
ADMIN_USER=stubadmin
REALM=pingstub
CLIENT=krate-keycloak
VIEWERS=APP-KAFKA-VIEWERS
ADMINS=APP-KAFKA-ADMINS
LABELS=(--label "com.docker.compose.project=$PROJECT" --label krate.gate=phase3)

say() { printf 'stub: %s\n' "$*"; }
fail() { printf 'stub: %s\n' "$*" >&2; exit 1; }

# kcadm inside the stub, logged in as its bootstrap admin; the password comes from the
# 0600 file through the exec environment. Dev mode listens on plain HTTP inside the
# container, which is what kcadm uses (its own self-signed HTTPS is not trusted by it).
KC_CFG="/tmp/kcadm-gate3.config"
kc_login() {
  [[ -f "$OUT/.admin-pw" ]] || fail "no admin password file in $OUT (run: stub_idp.sh up)"
  KC_CLI_PASSWORD="$(cat "$OUT/.admin-pw")" docker exec -e KC_CLI_PASSWORD "$CONTAINER" /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 --realm master --user "$ADMIN_USER" --config "$KC_CFG" >/dev/null 2>&1
}
kc() { docker exec "$CONTAINER" /opt/keycloak/bin/kcadm.sh "$@" --config "$KC_CFG" </dev/null; }
kc_logout() { docker exec "$CONTAINER" rm -f "$KC_CFG" >/dev/null 2>&1 || true; }
# a 36-character id from a csv listing; empty when absent
id_of() { grep -o -E '[0-9a-f-]{36}' | head -1; }
group_id() { kc get groups -r "$REALM" -q search="$1" -q exact=true --fields id,name --format csv --noquotes 2>/dev/null | grep -E ",$1\$" | cut -d, -f1 | id_of; }
user_id() { kc get users -r "$REALM" -q username="$1" -q exact=true --fields id --format csv --noquotes 2>/dev/null | id_of; }
http_code() { curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null || true; }

# Creates a stub user with the shared user password (sent inside the JSON body on
# kcadm's stdin: it never appears on a command line, host or container side), in the
# named groups.
make_user() {
  local name="$1" uid gid g body; shift
  [[ "$name" =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || fail "user name $name: lowercase letters, digits, . _ - only"
  [[ -z "$(user_id "$name")" ]] || fail "stub user $name already exists"
  body="$OUT/.user.json"
  python3 -I - "$OUT/.user-pw" "$name" > "$body" <<'PY'
import json, sys
password = open(sys.argv[1]).read().strip(); name = sys.argv[2]
print(json.dumps({"username": name, "enabled": True, "email": name + "@example.test", "emailVerified": True,
                  "firstName": name, "lastName": "Stub",
                  "credentials": [{"type": "password", "value": password, "temporary": False}]}))
PY
  chmod 600 "$body"
  docker exec -i "$CONTAINER" /opt/keycloak/bin/kcadm.sh create users -r "$REALM" -f - --config "$KC_CFG" < "$body" >/dev/null 2>&1 \
    || { rm -f "$body"; fail "could not create stub user $name"; }
  rm -f "$body"
  uid="$(user_id "$name")"; [[ -n "$uid" ]] || fail "stub user $name not found after creation"
  for g in "$@"; do
    gid="$(group_id "$g")"; [[ -n "$gid" ]] || fail "stub group $g does not exist"
    kc update "users/$uid/groups/$gid" -r "$REALM" -s "realm=$REALM" -s "userId=$uid" -s "groupId=$gid" -n >/dev/null 2>&1 \
      || fail "could not add stub user $name to $g"
  done
  say "user $name: groups [$*]"
}

port_free() { # 127.0.0.1:PORT accepts a bind → free
  python3 -I -c 'import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()' "$1"
}

case "$ACTION" in
  up)
    [[ -n "$EDITION_DIR" && -f "$EDITION_DIR/.env.template" ]] || fail "--edition-dir must name an edition directory with .env.template"
    [[ "$BASE" == https://* ]] || fail "--base must be the fixture's public https origin"
    [[ -n "$OUT" ]] || fail "--out DIR is required"
    IMAGE="$(grep -E '^KEYCLOAK_IMAGE=' "$EDITION_DIR/.env.template" | tail -1 | cut -d= -f2-)"
    [[ -n "$IMAGE" ]] || fail "no KEYCLOAK_IMAGE in $EDITION_DIR/.env.template"
    docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "image $IMAGE is not on this host (the stand-in IdP is the edition's Keycloak image; load the bundle's images first)"
    docker network inspect "$NETWORK" >/dev/null 2>&1 || fail "network $NETWORK does not exist (the fixture's identity services must be up)"
    [[ -z "$(docker ps -aq --filter "name=^${CONTAINER}$")" ]] || fail "container $CONTAINER already exists (run: stub_idp.sh down --project $PROJECT)"
    port_free "$PORT" || fail "127.0.0.1:$PORT is in use; pass a free port with --port"
    { mkdir -p "$OUT" && chmod 700 "$OUT"; } || fail "cannot create $OUT"
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 7 -subj "/CN=$ALIAS" \
      -addext "subjectAltName=DNS:localhost,DNS:$ALIAS,IP:127.0.0.1" -keyout "$OUT/stub.key" -out "$OUT/stub.crt" >/dev/null 2>&1 \
      || fail "openssl could not generate the stub certificate"
    chmod 644 "$OUT/stub.crt"; chmod 600 "$OUT/stub.key"
    for f in .admin-pw .client-secret .user-pw; do
      { python3 -I -c 'import secrets; print(secrets.token_urlsafe(24))' > "$OUT/$f" && chmod 600 "$OUT/$f"; } || fail "cannot write $OUT/$f"
    done
    # The container reads the certificate and key through bind mounts; the key file must be
    # readable by Keycloak's user (1000) inside the container, so a copy with mode 644 is
    # mounted from the 0700 output directory (unreadable to other host users).
    { cp "$OUT/stub.key" "$OUT/.stub-mount.key" && chmod 644 "$OUT/.stub-mount.key"; } || fail "cannot stage the key for the container"
    KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat "$OUT/.admin-pw")" docker run -d --pull never --name "$CONTAINER" "${LABELS[@]}" \
      --network "$NETWORK" --network-alias "$ALIAS" -p "127.0.0.1:$PORT:8443" \
      -v "$OUT/stub.crt:/opt/keycloak/conf/stub.crt:ro" -v "$OUT/.stub-mount.key:/opt/keycloak/conf/stub.key:ro" \
      -e KC_BOOTSTRAP_ADMIN_USERNAME="$ADMIN_USER" -e KC_BOOTSTRAP_ADMIN_PASSWORD \
      -e KC_HOSTNAME="https://localhost:$PORT" -e KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true \
      -e KC_HTTPS_CERTIFICATE_FILE=/opt/keycloak/conf/stub.crt -e KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/keycloak/conf/stub.key \
      -e KC_HEALTH_ENABLED=true "$IMAGE" start-dev >/dev/null || fail "docker run of the stand-in IdP failed"
    say "container $CONTAINER started from $IMAGE on 127.0.0.1:$PORT, alias $ALIAS on $NETWORK"
    waited=0
    until [[ "$(http_code "https://127.0.0.1:$PORT/realms/master")" == 200 ]]; do
      (( waited < 240 )) || { docker logs --tail 20 "$CONTAINER" >&2; fail "the stand-in IdP did not answer within 240 s"; }
      sleep 3; waited=$((waited + 3))
    done
    say "master realm answers after ${waited}s"
    tries=0
    until kc_login; do tries=$((tries + 1)); (( tries < 10 )) || fail "kcadm login into the stand-in IdP failed"; sleep 3; done
    kc create realms -s "realm=$REALM" -s enabled=true -s displayName='PingFederate stand-in' >/dev/null 2>&1 || fail "could not create realm $REALM"
    CLIENT_JSON="$OUT/.client.json"
    python3 -I - "$OUT/.client-secret" "$CLIENT" "$BASE/identity/realms/krate/broker/pingfederate/endpoint" > "$CLIENT_JSON" <<'PY'
import json, sys
secret = open(sys.argv[1]).read().strip()
print(json.dumps({"clientId": sys.argv[2], "enabled": True, "publicClient": False, "standardFlowEnabled": True,
                  "directAccessGrantsEnabled": False, "secret": secret, "redirectUris": [sys.argv[3]]}))
PY
    chmod 600 "$CLIENT_JSON"
    docker exec -i "$CONTAINER" /opt/keycloak/bin/kcadm.sh create clients -r "$REALM" -f - --config "$KC_CFG" < "$CLIENT_JSON" >/dev/null 2>&1 \
      || { rm -f "$CLIENT_JSON"; fail "could not create client $CLIENT"; }
    rm -f "$CLIENT_JSON"
    CID="$(kc get clients -r "$REALM" -q clientId="$CLIENT" --fields id --format csv --noquotes 2>/dev/null | id_of)"
    [[ -n "$CID" ]] || fail "client $CLIENT not found after creation"
    kc create "clients/$CID/protocol-mappers/models" -r "$REALM" -s name=groups -s protocol=openid-connect -s protocolMapper=oidc-group-membership-mapper \
      -s 'config={"claim.name":"groups","full.path":"false","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true"}' >/dev/null 2>&1 \
      || fail "could not create the groups claim mapper"
    for g in "$VIEWERS" "$ADMINS"; do kc create groups -r "$REALM" -s "name=$g" >/dev/null 2>&1 || fail "could not create group $g"; done
    make_user ping-viewer "$VIEWERS"
    make_user ping-admin "$ADMINS"
    make_user ping-both "$VIEWERS" "$ADMINS"
    make_user ping-none
    kc_logout
    ISSUER="https://localhost:$PORT/realms/$REALM"
    BACK="https://$ALIAS:8443/realms/$REALM/protocol/openid-connect"
    python3 -I - "$OUT/site.json" "$ISSUER" "$BASE" "$CLIENT" "$VIEWERS" "$ADMINS" "$CLUSTER" "$BACK" <<'PY'
import json, sys
out, issuer, base, client, viewers, admins, cluster, back = sys.argv[1:9]
site = {"issuer": issuer, "public_url": base, "client_id": client, "viewer_group": viewers, "admin_group": admins,
        "groups_claim": "groups", "scopes": ["openid", "profile", "email"], "clusters": [cluster],
        "authorization_url": issuer + "/protocol/openid-connect/auth", "token_url": back + "/token",
        "userinfo_url": back + "/userinfo", "jwks_url": back + "/certs"}
open(out, "w").write(json.dumps(site, indent=2) + "\n")
PY
    chmod 644 "$OUT/site.json"
    code="$(http_code "$ISSUER/.well-known/openid-configuration")"
    [[ "$code" == 200 ]] || fail "discovery document of $ISSUER answers HTTP $code"
    say "realm $REALM ready: issuer $ISSUER, client $CLIENT, groups $VIEWERS/$ADMINS, users ping-viewer ping-admin ping-both ping-none; site file $OUT/site.json; PEM $OUT/stub.crt"
    ;;
  down)
    removed=""
    for c in $(docker ps -aq --filter "name=^${PROJECT}-gate3-"); do docker rm -f "$c" >/dev/null 2>&1 && removed="$removed $c"; done
    say "removed containers:${removed:- none}"
    ;;
  status)
    state="$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo absent)"
    say "container $CONTAINER: $state; https://127.0.0.1:$PORT/realms/$REALM: HTTP $(http_code "https://127.0.0.1:$PORT/realms/$REALM")"
    [[ "$state" == running ]]
    ;;
  add-user)
    [[ -n "$OUT" && ${#POSITIONAL[@]} -ge 1 ]] || fail "usage: add-user --project NAME --out DIR USERNAME [GROUP...]"
    kc_login || fail "kcadm login into the stand-in IdP failed"
    make_user "${POSITIONAL[@]}"
    kc_logout
    ;;
  rotate-secret)
    # A new client secret for krate-keycloak, sent inside the JSON body on kcadm's stdin (merged into the
    # client's representation); the file is replaced only after the stand-in accepted it.
    [[ -n "$OUT" && -f "$OUT/.client-secret" ]] || fail "usage: rotate-secret --project NAME --out DIR (after: stub_idp.sh up)"
    kc_login || fail "kcadm login into the stand-in IdP failed"
    CID="$(kc get clients -r "$REALM" -q clientId="$CLIENT" --fields id --format csv --noquotes 2>/dev/null | id_of)"
    [[ -n "$CID" ]] || fail "client $CLIENT not found in the stand-in"
    { python3 -I -c 'import secrets; print(secrets.token_urlsafe(24))' > "$OUT/.client-secret.new" && chmod 600 "$OUT/.client-secret.new"; } || fail "cannot write the new secret"
    python3 -I - "$OUT/.client-secret.new" > "$OUT/.client.json" <<'PY'
import json, sys
print(json.dumps({"secret": open(sys.argv[1]).read().strip()}))
PY
    chmod 600 "$OUT/.client.json"
    docker exec -i "$CONTAINER" /opt/keycloak/bin/kcadm.sh update "clients/$CID" -r "$REALM" -f - --config "$KC_CFG" < "$OUT/.client.json" >/dev/null 2>&1 \
      || { rm -f "$OUT/.client.json" "$OUT/.client-secret.new"; fail "the stand-in refused the new client secret"; }
    rm -f "$OUT/.client.json"
    stored="$(kc get "clients/$CID/client-secret" -r "$REALM" --fields value --format csv --noquotes 2>/dev/null | tr -d '"\r\n')"
    kc_logout
    [[ -n "$stored" && "$stored" == "$(tr -d '\n' < "$OUT/.client-secret.new")" ]] || { rm -f "$OUT/.client-secret.new"; fail "the stand-in does not report the new client secret"; }
    mv -f "$OUT/.client-secret.new" "$OUT/.client-secret"
    say "client secret rotated"
    ;;
  remove-group)
    [[ -n "$OUT" && ${#POSITIONAL[@]} -eq 2 ]] || fail "usage: remove-group --project NAME --out DIR USERNAME GROUP"
    kc_login || fail "kcadm login into the stand-in IdP failed"
    uid="$(user_id "${POSITIONAL[0]}")"; [[ -n "$uid" ]] || fail "no stub user ${POSITIONAL[0]}"
    gid="$(group_id "${POSITIONAL[1]}")"; [[ -n "$gid" ]] || fail "no stub group ${POSITIONAL[1]}"
    kc delete "users/$uid/groups/$gid" -r "$REALM" >/dev/null 2>&1 || fail "could not remove ${POSITIONAL[0]} from ${POSITIONAL[1]}"
    left="$(kc get "users/$uid/groups" -r "$REALM" --fields name --format csv --noquotes 2>/dev/null | tr '\n' ' ')"
    kc_logout
    say "user ${POSITIONAL[0]} removed from ${POSITIONAL[1]}; groups now [${left}]"
    ;;
  *)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
