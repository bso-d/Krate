#!/usr/bin/env bash
# Shared authentication activation for the packaged Krate CLI. Sourced by
# krate, whose helpers (compose_cmd, identity_ready, env_value, die, ...) it uses.
#
# Applies the Kafbat UI authentication mode in .env: validates the rendered
# configuration, then recreates only kafka-ui and the proxy. Keycloak is
# managed by `krate identity`; in runtime.yml mode it must already be ready.
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
  # Only the UI is recreated. Broker containers and volumes are never reconciled.
  compose_cmd up -d --pull never --no-build --no-deps --force-recreate --wait --wait-timeout "$timeout" kafka-ui
  compose_cmd up -d --pull never --no-build --no-deps --force-recreate --wait --wait-timeout "$timeout" proxy
  if [[ "$mode" == runtime.yml ]]; then
    python3 "$sso_dir/probe.py" --directory "$SCRIPT_DIR"
  fi
  ok "Authentication applied ($mode). Broker services and stored data were unchanged."
}
