#!/usr/bin/env bash
# Shared authentication activation for the packaged Krate CLI. Sourced by
# krate, whose helpers (compose_cmd, identity_ready, env_value, die, ...) it uses.
#
# Applies the Kafbat UI authentication mode in .env: validates the rendered
# configuration, then reconciles only kafka-ui and the proxy (each is recreated
# when its inputs changed). Keycloak is managed by `krate identity`; in
# runtime.yml mode it must already be ready. In that mode the PingFederate
# plan (auth/keycloak/pingfederate-idp.json), when it exists, is applied to
# the realm, and Keycloak is recreated first when the trust material in
# auth/keycloak/truststores changed since it started (it reads PEMs at start
# only); without the plan a leftover provider is removed.
apply_auth() {
  require_compose; require_compose_file
  require_sso_compose
  require_env
  local sso_dir="$1" mode timeout=180 service image cid
  mode="$(env_value KAFKA_UI_AUTH_CONFIG)"
  [[ "$mode" == runtime.yml || "$mode" == local.yml ]] || die "KAFKA_UI_AUTH_CONFIG must be runtime.yml or local.yml"
  if [[ "$mode" == runtime.yml ]] && ! identity_ready; then
    die "Keycloak is not ready. Run: krate identity up (then: krate identity status)"
  fi
  # Render into the validator's stdin: credentials never reach terminal output.
  compose_cmd config --format json | python3 "$sso_dir/preflight.py" --directory "$SCRIPT_DIR" --mode "$mode"
  if [[ "$mode" == runtime.yml ]]; then
    # Keycloak and its realm change below: the same lock the identity commands hold.
    identity_lock
    local kc_before kc_after trust_changed=false
    kc_before="$(compose_cmd ps -q keycloak)"
    if sync_truststore_env; then
      trust_changed=true
      info "Trust material in auth/keycloak/truststores changed; recreating Keycloak..."
    fi
    compose_cmd up -d --pull never --no-build --no-deps --wait --wait-timeout "$timeout" keycloak
    kc_after="$(compose_cmd ps -q keycloak)"
    if [[ "$kc_before" == "$kc_after" && -n "$kc_before" ]]; then
      ok "Keycloak unchanged (same trust material and image)"
    elif $trust_changed; then
      ok "Keycloak recreated with the trust material in auth/keycloak/truststores"
      identity_journal apply recreated "keycloak: truststores changed"
    else
      ok "Keycloak recreated (its service definition, image or container changed)"
      identity_journal apply recreated "keycloak: service definition changed"
    fi
    identity_apply_idp apply
  fi
  # Only kafka-ui is recreated below, and it depends on healthy brokers.
  while IFS= read -r service; do
    [[ "$service" == kafka-* && "$service" != kafka-ui ]] || continue
    cid="$(compose_cmd ps -q "$service")"
    [[ -n "$cid" && "$(docker inspect --format '{{.State.Status}}' "$cid")" == running ]] || die "Start the broker cluster before applying authentication; $service is not running"
    [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid")" == healthy ]] || die "$service must be healthy before authentication activation"
  done < <(compose_cmd config --services)
  for service in kafka-ui proxy; do
    image="$(compose_cmd config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"][sys.argv[1]]["image"])' "$service")"
    docker image inspect "$image" >/dev/null 2>&1 || die "Packaged image for $service is missing; run krate load-images first"
  done
  # The digest of the applied auth file is part of kafka-ui's environment, so Compose
  # recreates the UI (ending its sessions) only when that file or the image changed.
  # Broker containers and volumes are never reconciled.
  local auth_sha before after
  auth_sha="$(python3 -c 'import hashlib, sys; h = hashlib.sha256(sys.argv[1].encode() + b"\n"); h.update(open(sys.argv[2], "rb").read()); print(h.hexdigest()[:32])' "$mode" "$SCRIPT_DIR/auth/ui/$mode")"
  [[ "$(env_value KRATE_UI_AUTH_SHA)" == "$auth_sha" ]] || set_env_file_value "$ENV_FILE" KRATE_UI_AUTH_SHA "$auth_sha"
  # The same for the proxy: KRATE_PROXY_CONF_SHA (nginx.conf and the certificate, which a
  # running proxy never rereads) and KRATE_PROXY_PUBLIC_HOST (the one Host value served in
  # runtime.yml mode, port included) are part of its environment, so it is recreated exactly when they changed.
  sync_proxy_env "$mode"
  before="$(compose_cmd ps -q kafka-ui)"
  compose_cmd up -d --pull never --no-build --no-deps --wait --wait-timeout "$timeout" kafka-ui
  compose_cmd up -d --pull never --no-build --no-deps --wait --wait-timeout "$timeout" proxy
  after="$(compose_cmd ps -q kafka-ui)"
  if [[ "$before" == "$after" && -n "$before" ]]; then
    ok "Kafbat UI unchanged (same auth file and image); user sessions kept"
  else
    ok "Kafbat UI recreated with the applied authentication"
  fi
  if [[ "$mode" == runtime.yml ]]; then
    python3 "$sso_dir/probe.py" --directory "$SCRIPT_DIR"
  fi
  ok "Authentication applied ($mode). Broker services and stored data were unchanged."
  # The login model now in force, so nobody looks for a form that is not there.
  if [[ "$mode" == runtime.yml && -f "$SCRIPT_DIR/$IDENTITY_IDP_PLAN" ]]; then
    echo "  Sign-in: Keycloak (realm krate) sends users to PingFederate; local users (krate identity users) sign in through the"
    echo "           break-glass URL with ?kc_idp_hint= (empty), see docs/dual-login.md; there is no shared form login"
  elif [[ "$mode" == runtime.yml ]]; then
    echo "  Sign-in: Keycloak (realm krate) — manage users with krate identity users; there is no shared form login"
  else
    echo "  Sign-in: shared Admin login (KAFKA_UI_USER / KAFKA_UI_PASSWORD in .env)"
  fi
}
