#!/usr/bin/env bash
# Shared operational boundary for the Krate CLI and Krate Studio.
# Sourced by kraft/krate and epc/krate.

OPERATION_LOCK=""

# Verify whether the current shell (or an ancestor in the same process tree)
# legitimately owns $SCRIPT_DIR/auth/.operation.lock.
# An environment variable alone NEVER bypasses locking: the lock's pid file
# must exist, match KRATE_OP_LOCK_PID, be a live process, and be an ancestor of $$.
operation_lock_is_owner() {
  local dir="$SCRIPT_DIR/auth/.operation.lock" lock_pid owner_pid cur ppid depth=0
  owner_pid="${KRATE_OP_LOCK_PID:-}"
  [[ "$owner_pid" =~ ^[0-9]+$ ]] || return 1
  [[ -d "$dir" && -f "$dir/pid" ]] || return 1
  lock_pid="$(cat "$dir/pid" 2>/dev/null || true)"
  [[ "$lock_pid" == "$owner_pid" ]] || return 1
  identity_lock_live "$lock_pid" 0 || return 1
  cur="$$"
  while [[ "$cur" =~ ^[0-9]+$ && "$cur" -gt 1 && $depth -lt 16 ]]; do
    if [[ "$cur" == "$lock_pid" ]]; then
      return 0
    fi
    ppid="$(ps -o ppid= -p "$cur" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ -n "$ppid" && "$ppid" != "$cur" ]] || break
    cur="$ppid"
    depth=$((depth + 1))
  done
  return 1
}

operation_lock() {
  local op_name="${1:-op}"
  local dir="$SCRIPT_DIR/auth/.operation.lock" tmp pid mtime now
  if operation_lock_is_owner; then
    return 0
  fi
  mkdir -p "$SCRIPT_DIR/auth"
  now="$(date +%s)"
  tmp="$dir.$$.tmp"
  rm -rf "$tmp"
  {
    mkdir "$tmp" \
      && echo "$$" > "$tmp/pid" \
      && echo "$now" > "$tmp/start_time" \
      && echo "${op_name}-$$-${now}" > "$tmp/op_id"
  } || { rm -rf "$tmp"; die "Cannot create the operation lock $dir"; }

  mtime="$(stat -c %Y "$dir" 2>/dev/null || stat -f %m "$dir" 2>/dev/null || echo 0)"
  if ! identity_lock_rename "$tmp" "$dir"; then
    pid="$(cat "$dir/pid" 2>/dev/null || true)"
    if identity_lock_live "$pid" "$mtime"; then
      die "Another krate operation is running (pid ${pid:-?}). Wait for it to finish."
    fi
    warn "Removing the stale operation lock left by process ${pid:-?}"
    rm -rf "$dir"
    {
      mkdir "$tmp" \
        && echo "$$" > "$tmp/pid" \
        && echo "$now" > "$tmp/start_time" \
        && echo "${op_name}-$$-${now}" > "$tmp/op_id"
    } || { rm -rf "$tmp"; die "Cannot create the operation lock $dir"; }
    identity_lock_rename "$tmp" "$dir" || die "Cannot create the operation lock $dir"
  fi
  OPERATION_LOCK="$dir"
  export KRATE_OP_LOCK_PID="$$"
  trap operation_cleanup EXIT
}

operation_cleanup() {
  local self_pid="${BASHPID:-$$}"
  kcadm_logout 2>/dev/null || true
  if [[ -n "${IDENTITY_TMPDIR:-}" ]]; then
    rm -rf "$IDENTITY_TMPDIR"
    IDENTITY_TMPDIR=""
  fi
  # Only the top-level shell that acquired the lock removes .identity.lock and .operation.lock
  if [[ -n "${OPERATION_LOCK:-}" ]]; then
    local op_pid
    op_pid="$(cat "$OPERATION_LOCK/pid" 2>/dev/null || true)"
    if [[ "$op_pid" != "$self_pid" ]]; then
      return 0
    fi
  fi
  if [[ -n "${IDENTITY_LOCK:-}" ]]; then
    local id_pid
    id_pid="$(cat "$IDENTITY_LOCK/pid" 2>/dev/null || true)"
    if [[ "$id_pid" == "$self_pid" ]]; then
      rm -rf "$IDENTITY_LOCK"
    fi
    IDENTITY_LOCK=""
  fi
  if [[ -n "${OPERATION_LOCK:-}" ]]; then
    local op_pid
    op_pid="$(cat "$OPERATION_LOCK/pid" 2>/dev/null || true)"
    if [[ "$op_pid" == "$self_pid" ]]; then
      rm -rf "$OPERATION_LOCK"
    fi
    OPERATION_LOCK=""
  fi
}

# Hierarchical lock coordination: when an outer operation holds operation_lock,
# nested calls to identity_lock within the same verified process tree are re-entrant
# and do not deadlock or prematurely drop the outer EXIT trap.
identity_lock() {
  local dir="$SCRIPT_DIR/auth/.identity.lock" tmp pid mtime holder_pid
  if [[ -d "$dir" && -f "$dir/pid" ]]; then
    holder_pid="$(cat "$dir/pid" 2>/dev/null || true)"
    if [[ "$holder_pid" == "$$" ]] && identity_lock_live "$holder_pid" 0; then
      IDENTITY_LOCK="$dir"
      return 0
    fi
    if operation_lock_is_owner && [[ "$holder_pid" == "${KRATE_OP_LOCK_PID:-}" ]]; then
      IDENTITY_LOCK="$dir"
      return 0
    fi
  fi
  mkdir -p "$SCRIPT_DIR/auth"
  tmp="$dir.$$.tmp"
  rm -rf "$tmp"
  holder_pid="$$"
  if operation_lock_is_owner; then
    holder_pid="$KRATE_OP_LOCK_PID"
  fi
  { mkdir "$tmp" && echo "$holder_pid" > "$tmp/pid"; } || { rm -rf "$tmp"; die "Cannot create the lock $dir"; }
  mtime="$(stat -c %Y "$dir" 2>/dev/null || stat -f %m "$dir" 2>/dev/null || echo 0)"
  if ! identity_lock_rename "$tmp" "$dir"; then
    pid="$(cat "$dir/pid" 2>/dev/null || true)"
    if identity_lock_live "$pid" "$mtime"; then
      die "Another krate identity command is running (pid ${pid:-?}). Wait for it to finish."
    fi
    warn "Removing the stale identity lock left by process ${pid:-?}"
    rm -rf "$dir"
    { mkdir "$tmp" && echo "$holder_pid" > "$tmp/pid"; } || { rm -rf "$tmp"; die "Cannot create the lock $dir"; }
    identity_lock_rename "$tmp" "$dir" || die "Cannot create the lock $dir"
  fi
  IDENTITY_LOCK="$dir"
  if [[ -n "${OPERATION_LOCK:-}" ]] || operation_lock_is_owner; then
    trap operation_cleanup EXIT
  else
    trap identity_cleanup EXIT
  fi
}

identity_tmpdir() {
  mkdir -p "$SCRIPT_DIR/auth"
  rm -rf "$SCRIPT_DIR"/auth/.identity-work.??????
  IDENTITY_TMPDIR="$(mktemp -d "$SCRIPT_DIR/auth/.identity-work.XXXXXX")" || die "Cannot create a working directory under $SCRIPT_DIR/auth"
  chmod 700 "$IDENTITY_TMPDIR"
  if [[ -n "${OPERATION_LOCK:-}" ]] || operation_lock_is_owner; then
    trap operation_cleanup EXIT
  else
    trap identity_cleanup EXIT
  fi
}

_ops_py() {
  local sso_path
  sso_path="$(sso_dir)"
  PYTHONDONTWRITEBYTECODE=1 python3 -B "$sso_path/operations.py" "$@"
}

_ops_common_args() {
  local pkg="false"
  if is_package; then
    pkg="true"
  fi
  printf '%s\n' \
    --source-dir "$SCRIPT_DIR" \
    --install-dir "$KRATE_HOME" \
    --edition "$KRATE_VARIANT" \
    --repo-dir "${REPO_DIR:-}" \
    --is-package "$pkg"
}

cmd_workspace() {
  local action="${1:-resolve}"
  shift || true
  case "$action" in
    resolve)
      local -a common_args=()
      mapfile -t common_args < <(_ops_common_args)
      _ops_py workspace-resolve "${common_args[@]}" "$@"
      ;;
    *)
      die "Usage: krate workspace resolve [--json]"
      ;;
  esac
}

_reconcile_config_service() {
  local proj="$1" svc="$2" reason="${3:-config_change}"
  local mon_proj="krate-${KRATE_VARIANT}-monitoring"
  # Only reconcile live containers if Docker Compose shows the service is currently created/running
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  if [[ "$proj" == "$mon_proj" ]]; then
    local mon_cid
    mon_cid="$(docker ps -q --filter "label=com.docker.compose.project=$proj" --filter "label=com.docker.compose.service=$svc" 2>/dev/null | head -1 || true)"
    [[ -n "$mon_cid" ]] || return 0
    if [[ "$reason" == "auth_transition" ]]; then
      cmd_monitor up >&2
    else
      monitor_compose up -d --pull never --no-build --no-deps "$svc" >&2
    fi
  else
    local cl_cid
    cl_cid="$(docker ps -q --filter "label=com.docker.compose.project=$proj" --filter "label=com.docker.compose.service=$svc" 2>/dev/null | head -1 || true)"
    [[ -n "$cl_cid" ]] || return 0
    if [[ "$svc" == "proxy" ]]; then
      sync_proxy_env "$(env_value KAFKA_UI_AUTH_CONFIG)" >&2 || true
    elif [[ "$svc" == "keycloak" ]]; then
      sync_truststore_env >&2 || true
    fi
    if [[ "$reason" == "auth_transition" && ( "$svc" == "kafka-ui" || "$svc" == "proxy" ) ]]; then
      apply_auth >&2
    elif [[ "$svc" == "keycloak" || "$svc" == "keycloak-db" ]]; then
      identity_compose up -d --pull never --no-build --no-deps "$svc" >&2
    else
      compose_cmd up -d --pull never --no-build --no-deps "$svc" >&2
    fi
  fi
}

_execute_staged_config_work() {
  local emit_json="${1:-true}"
  local -a common_args=()
  mapfile -t common_args < <(_ops_common_args)

  local work_lines kind arg1 arg2 arg3 err_msg rot_out
  work_lines="$(_ops_py config-exec-helper "${common_args[@]}" --action list-work)" || return 1

  while IFS=$'\t' read -r kind arg1 arg2 arg3; do
    [[ -n "$kind" ]] || continue
    case "$kind" in
      ROTATE)
        _ops_py config-exec-helper "${common_args[@]}" --action step --step "rotate_${arg1}" --status applying >/dev/null
        local rot_in_file rot_rc=0
        rot_in_file="$(mktemp "$SCRIPT_DIR/auth/.operation-recovery/rot.XXXXXX")"
        chmod 600 "$rot_in_file"
        if ! _ops_py config-exec-helper "${common_args[@]}" --action stage-rotation-input --key "$arg1" --out-file "$rot_in_file"; then
          rm -f "$rot_in_file"
          return 1
        fi
        if [[ "$(env_value "$arg1")" == "$(tr -d '\r\n' < "$rot_in_file")" && "$arg1" == "KEYCLOAK_DB_PASSWORD" ]]; then
          set_env_file_value "$ENV_FILE" "$arg1" "pending-recovery-placeholder-0000"
        fi
        set +e
        rot_out="$(
          set -eo pipefail
          cmd_identity_rotate "$arg1" --value < "$rot_in_file" 2>&1
        )"
        rot_rc=$?
        set -e
        rm -f "$rot_in_file"
        if [[ $rot_rc -ne 0 ]]; then
          err_msg="Failed rotating $arg1: $(printf '%s' "$rot_out" | tail -1)"
          if [[ "$emit_json" == "true" ]]; then
            _ops_py config-exec-helper "${common_args[@]}" --action step --step "rotate_${arg1}" --status failed --error "$err_msg"
          else
            _ops_py config-exec-helper "${common_args[@]}" --action step --step "rotate_${arg1}" --status failed --error "$err_msg" >/dev/null
            err "$err_msg"
          fi
          return 1
        fi
        _ops_py config-exec-helper "${common_args[@]}" --action step --step "rotate_${arg1}" --status succeeded >/dev/null
        ;;
      WRITE_FILES)
        if ! _ops_py config-exec-helper "${common_args[@]}" --action write-files; then
          err_msg="Failed writing configuration file $arg1"
          _ops_py config-exec-helper "${common_args[@]}" --action step --step "write_${arg1}" --status failed --error "$err_msg"
          return 1
        fi
        ;;
      RECONCILE)
        local step_id="reconcile_${arg1}_${arg2}"
        _ops_py config-exec-helper "${common_args[@]}" --action step --step "$step_id" --status applying >/dev/null
        if ! _reconcile_config_service "$arg1" "$arg2" "$arg3"; then
          err_msg="Failed reconciling service $arg2 in project $arg1"
          if [[ "$emit_json" == "true" ]]; then
            _ops_py config-exec-helper "${common_args[@]}" --action step --step "$step_id" --status failed --error "$err_msg"
          else
            _ops_py config-exec-helper "${common_args[@]}" --action step --step "$step_id" --status failed --error "$err_msg" >/dev/null
            err "$err_msg"
          fi
          return 1
        fi
        _ops_py config-exec-helper "${common_args[@]}" --action step --step "$step_id" --status succeeded >/dev/null
        ;;
    esac
  done <<< "$work_lines"

  local final_json
  final_json="$(_ops_py config-exec-helper "${common_args[@]}" --action finalize)" || return 1
  identity_journal "config-apply" ok "applied"
  if [[ "$emit_json" == "true" ]]; then
    printf '%s\n' "$final_json"
  else
    ok "Configuration applied and verified"
  fi
  return 0
}

cmd_config() {
  local action="${1:-show}"
  if [[ "$action" == "--json" ]]; then
    action="show"
  else
    shift || true
  fi

  local -a common_args=()
  mapfile -t common_args < <(_ops_common_args)

  case "$action" in
    show)
      local want_json=false arg
      for arg in "$@"; do
        [[ "$arg" == "--json" ]] && want_json=true
      done
      if $want_json; then
        _ops_py config-show "${common_args[@]}" --json
        return $?
      fi
      local file
      for file in "$ENV_FILE" "$MONITOR_DIR/.env"; do
        [[ -f "$file" ]] || continue
        sep
        echo -e "${BOLD}  $file${RESET}"
        sep
        cat "$file"
      done
      sep
      [[ -f "$ENV_FILE" ]] || warn ".env does not exist yet; krate setup creates it."
      ;;
    set)
      local kv="${1:-}" want_json=false
      shift || true
      [[ "${1:-}" == "--json" ]] && want_json=true
      [[ "$kv" == *=* ]] || die "Usage: krate config set KEY=VALUE"
      local key="${kv%%=*}"
      [[ "$key" =~ ^[A-Z0-9_]+_IMAGE$ ]] && die "Image pins come from .env.template; change $key there, or export it in the shell for one run."

      operation_lock "config-set"
      local state="pristine"
      case "$key" in
        KEYCLOAK_DB_PASSWORD|KEYCLOAK_ADMIN_PASSWORD|KEYCLOAK_CLI_CLIENT_SECRET|KEYCLOAK_KAFBAT_CLIENT_SECRET|KEYCLOAK_IDP_WATCH_CLIENT_SECRET|PING_KEYCLOAK_CLIENT_SECRET)
          state="$(identity_state)" || exit 1
          ;;
      esac

      local out_target err_file rc=0
      err_file="$(mktemp)"
      if $want_json; then
        if ! printf '%s\n' "$kv" | _ops_py config-set "${common_args[@]}" --identity-state "$state" --json 2>"$err_file"; then
          rc=1
        fi
      else
        if ! out_target="$(printf '%s\n' "$kv" | _ops_py config-set "${common_args[@]}" --identity-state "$state" 2>"$err_file")"; then
          rc=1
        fi
      fi
      if [[ $rc -ne 0 ]]; then
        local msg
        msg="$(sed 's/^ERROR: //' "$err_file")"
        rm -f "$err_file"
        die "$msg"
      fi
      rm -f "$err_file"
      if ! $want_json; then
        ok "Set ${key} in ${out_target}"
      fi
      ;;
    plan)
      local want_json=false arg
      for arg in "$@"; do
        [[ "$arg" == "--json" ]] && want_json=true
      done
      local state
      state="$(identity_state 2>/dev/null || echo unknown)"
      if $want_json; then
        _ops_py config-plan "${common_args[@]}" --identity-state "$state" --json
      else
        _ops_py config-plan "${common_args[@]}" --identity-state "$state"
      fi
      ;;
    draft)
      local want_json=false arg
      for arg in "$@"; do
        [[ "$arg" == "--json" ]] && want_json=true
      done
      operation_lock "config-draft"
      local state
      state="$(identity_state 2>/dev/null || echo unknown)"
      if $want_json; then
        _ops_py config-draft "${common_args[@]}" --identity-state "$state" --json
      else
        _ops_py config-draft "${common_args[@]}" --identity-state "$state"
      fi
      ;;
    apply)
      local want_json=false arg
      for arg in "$@"; do
        [[ "$arg" == "--json" ]] && want_json=true
      done
      operation_lock "config-apply"
      identity_lock
      local state stage_out stage_rc=0
      state="$(identity_state 2>/dev/null || echo unknown)"
      stage_out="$(_ops_py config-stage-apply "${common_args[@]}" --identity-state "$state" --json)" || stage_rc=$?
      if [[ $stage_rc -ne 0 ]]; then
        if $want_json; then
          printf '%s\n' "$stage_out"
        else
          local err_text
          err_text="$(printf '%s' "$stage_out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error","Apply failed"))' 2>/dev/null || echo "Apply failed")"
          err "$err_text"
        fi
        return "$stage_rc"
      fi
      local stage_state
      stage_state="$(printf '%s' "$stage_out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null || true)"
      if [[ "$stage_state" == "succeeded" ]]; then
        if $want_json; then
          printf '%s\n' "$stage_out"
        else
          ok "No configuration changes to apply"
        fi
        return 0
      fi
      _execute_staged_config_work "$want_json"
      ;;
    recover)
      local want_json=false arg
      for arg in "$@"; do
        [[ "$arg" == "--json" ]] && want_json=true
      done
      operation_lock "config-recover"
      identity_lock
      local rec_file="$SCRIPT_DIR/auth/.operation-recovery/current.json"
      if [[ ! -f "$rec_file" ]]; then
        if $want_json; then
          printf '{"schema_version": 1, "state": "succeeded", "message": "No recovery required"}\n'
        else
          ok "No unfinished operation requires recovery"
        fi
        return 0
      fi
      _execute_staged_config_work "$want_json"
      ;;
    *)
      die "Usage: krate config [show [--json] | set KEY=VALUE | plan [--stdin] [--json] | apply [--stdin] [--json] | draft [--stdin] [--json] | recover [--json]]"
      ;;
  esac
}

if declare -f cmd_auth >/dev/null 2>&1 && ! declare -f _orig_cmd_auth >/dev/null 2>&1; then
  eval "_orig_$(declare -f cmd_auth)"
fi

if declare -f cmd_monitor >/dev/null 2>&1 && ! declare -f _orig_cmd_monitor >/dev/null 2>&1; then
  eval "_orig_$(declare -f cmd_monitor)"
fi

cmd_auth_transition() {
  local want_json=false target="" mode="" arg
  while [[ $# -gt 0 ]]; do
    arg="$1"
    shift
    case "$arg" in
      --json) want_json=true ;;
      --stdin) ;;
      --target) target="${1:-}"; shift || true ;;
      --mode) mode="${1:-}"; shift || true ;;
      *) ;;
    esac
  done

  local -a common_args=()
  mapfile -t common_args < <(_ops_common_args)

  local req_json
  if [[ -n "$target" || -n "$mode" ]]; then
    req_json="$(python3 -c 'import json,sys; print(json.dumps({"target": sys.argv[1] or "both", "mode": sys.argv[2] or "realm"}))' "$target" "$mode")"
  else
    req_json="$(cat)"
    [[ -n "$req_json" ]] || req_json="{}"
  fi

  local plan_out plan_rc=0
  plan_out="$(printf '%s\n' "$req_json" | _ops_py auth-transition-helper "${common_args[@]}" --action plan)" || plan_rc=$?
  if [[ $plan_rc -ne 0 ]]; then
    if $want_json; then
      printf '%s\n' "$plan_out"
    else
      local err_msg
      err_msg="$(printf '%s' "$plan_out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error","Auth transition refused"))' 2>/dev/null || echo "Auth transition refused")"
      err "$err_msg"
    fi
    return "$plan_rc"
  fi

  operation_lock "auth-transition"
  identity_lock

  local norm_mode inc_kafbat inc_grafana inc_perses graf_needs_prep
  read -r norm_mode inc_kafbat inc_grafana inc_perses graf_needs_prep < <(
    printf '%s' "$plan_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(
    d.get("mode", "realm"),
    "true" if d.get("include_kafbat") else "false",
    "true" if d.get("include_grafana") else "false",
    "true" if d.get("include_perses") else "false",
    "true" if d.get("grafana_needs_realm_prep") else "false",
)
'
  )

  local kafbat_status="not_selected" grafana_status="not_selected" perses_status="not_selected"
  local grafana_prep_step="not_applicable"
  local failed_step="" fail_error=""
  local sso_path
  sso_path="$(sso_dir)"

  # 1. Realm prerequisite: ensure identity stack is up when transitioning to realm mode
  if [[ "$norm_mode" == "realm" ]]; then
    local id_st
    id_st="$(identity_state 2>/dev/null || echo unknown)"
    if [[ "${id_st%% *}" != "existing" ]]; then
      if ! cmd_identity up >&2; then
        failed_step="identity_up"
        fail_error="Keycloak identity stack failed to start (krate identity up)"
      fi
    fi
  fi

  # 2. Kafbat UI transition (when selected)
  if [[ -z "$failed_step" && "$inc_kafbat" == "true" ]]; then
    if [[ "$norm_mode" == "realm" && ! -f "$SCRIPT_DIR/auth/ui/runtime.yml" ]]; then
      if ! auth_configure "$sso_path" >&2; then
        kafbat_status="failed"
        failed_step="kafbat_configure"
        fail_error="Failed generating auth/ui/runtime.yml"
      fi
    fi
    if [[ -z "$failed_step" ]]; then
      _ops_py auth-transition-helper "${common_args[@]}" --action persist-target --target-app kafbat --mode "$norm_mode" >/dev/null
      if _orig_cmd_auth apply >&2; then
        kafbat_status="succeeded"
      else
        kafbat_status="failed"
        failed_step="kafbat_apply"
        fail_error="krate auth apply failed during Kafbat transition"
      fi
    fi
  fi

  # 3. Grafana first-switch realm preparation (local.ini -> realm.ini ONLY)
  if [[ -z "$failed_step" && "$inc_grafana" == "true" ]]; then
    if [[ "$norm_mode" == "realm" ]]; then
      if [[ "$graf_needs_prep" == "true" ]]; then
        grafana_prep_step="monitor_realm_executed"
        if ! _orig_cmd_monitor realm >&2; then
          grafana_status="failed"
          failed_step="grafana_realm_prep"
          fail_error="krate monitor realm preparation failed"
        fi
      else
        grafana_prep_step="skipped_already_realm"
      fi
    else
      grafana_prep_step="local_fallback"
    fi
    if [[ -z "$failed_step" ]]; then
      _ops_py auth-transition-helper "${common_args[@]}" --action persist-target --target-app grafana --mode "$norm_mode" >/dev/null
    fi
  fi

  # 4. Perses configuration persistence
  if [[ -z "$failed_step" && "$inc_perses" == "true" ]]; then
    _ops_py auth-transition-helper "${common_args[@]}" --action persist-target --target-app perses --mode "$norm_mode" >/dev/null
  fi

  # 5. Monitoring stack reconciliation (`monitor up`) when Grafana or Perses is included
  if [[ -z "$failed_step" && ( "$inc_grafana" == "true" || "$inc_perses" == "true" ) ]]; then
    if _orig_cmd_monitor up >&2; then
      [[ "$inc_grafana" == "true" ]] && grafana_status="succeeded"
      [[ "$inc_perses" == "true" ]] && perses_status="succeeded"
    else
      [[ "$inc_grafana" == "true" ]] && grafana_status="failed"
      [[ "$inc_perses" == "true" ]] && perses_status="failed"
      failed_step="monitor_up"
      fail_error="krate monitor up failed during monitoring reconciliation"
    fi
  fi

  local overall_state="succeeded"
  if [[ -n "$failed_step" ]]; then
    overall_state="recovery_required"
  fi

  local finalize_in final_out final_rc=0
  finalize_in="$(python3 -c '
import json, sys
plan = json.loads(sys.argv[1])
state, k_st, g_st, p_st, g_prep, f_step, f_err = sys.argv[2:9]
targets = plan.get("targets", {})
if "kafbat" in targets:
    targets["kafbat"]["status"] = k_st
    targets["kafbat"]["verified"] = (k_st == "succeeded")
if "grafana" in targets:
    targets["grafana"]["status"] = g_st
    targets["grafana"]["prep_action"] = g_prep
    targets["grafana"]["verified"] = (g_st == "succeeded")
if "perses" in targets:
    targets["perses"]["status"] = p_st
    targets["perses"]["verified"] = (p_st == "succeeded")
out = {
    "state": state,
    "mode": plan.get("mode"),
    "target": plan.get("target"),
    "grafana_prep_action": g_prep,
    "targets": targets,
    "recovery_required": state != "succeeded",
}
if f_step:
    out["failed_step"] = f_step
    out["error"] = f_err
print(json.dumps(out))
' "$plan_out" "$overall_state" "$kafbat_status" "$grafana_status" "$perses_status" "$grafana_prep_step" "$failed_step" "$fail_error")"

  final_out="$(printf '%s\n' "$finalize_in" | _ops_py auth-transition-helper "${common_args[@]}" --action finalize)" || final_rc=$?
  if $want_json; then
    printf '%s\n' "$final_out"
  else
    if [[ $final_rc -eq 0 ]]; then
      ok "Authentication transition (${norm_mode}) completed and verified"
    else
      err "Authentication transition failed at ${failed_step}: ${fail_error}"
    fi
  fi
  return "$final_rc"
}

cmd_auth() {
  local sub="${1:-}"
  if [[ "$sub" == "transition" ]]; then
    shift || true
    cmd_auth_transition "$@"
    return $?
  fi
  _orig_cmd_auth "$@"
  local rc=$?
  if [[ $rc -eq 0 && "$sub" == "apply" ]]; then
    local -a common_args=()
    mapfile -t common_args < <(_ops_common_args)
    _ops_py config-clear-pending "${common_args[@]}" --scope cluster >/dev/null 2>&1 || true
  fi
  return $rc
}

cmd_monitor() {
  local sub="${1:-}"
  if [[ "$sub" == "restart" ]]; then
    shift || true
    local want_json=false
    [[ "${1:-}" == "--json" ]] && want_json=true
    operation_lock "monitor-restart"
    local -a common_args=()
    mapfile -t common_args < <(_ops_common_args)
    info "Restarting observability stack (single-operation down -> up)..."
    if ! _orig_cmd_monitor down; then
      die "Monitoring stop step (monitor down) failed during restart"
    fi
    if ! _orig_cmd_monitor up; then
      printf '%s\n' '{"state":"recovery_required","failed_step":"monitor_up","error":"Monitoring stack stopped cleanly but monitor up failed during restart"}' \
        | _ops_py auth-transition-helper "${common_args[@]}" --action finalize >/dev/null 2>&1 || true
      die "Monitoring start step (monitor up) failed after monitor down; recovery required"
    fi
    _ops_py config-clear-pending "${common_args[@]}" --scope monitoring >/dev/null 2>&1 || true
    if $want_json; then
      printf '{"schema_version": 1, "state": "succeeded", "operation": "monitor_restart"}\n'
    else
      ok "Observability stack restarted and verified"
    fi
    return 0
  fi
  _orig_cmd_monitor "$@"
  local rc=$?
  if [[ $rc -eq 0 && "$sub" == "up" ]]; then
    local -a common_args=()
    mapfile -t common_args < <(_ops_common_args)
    _ops_py config-clear-pending "${common_args[@]}" --scope monitoring >/dev/null 2>&1 || true
  fi
  return $rc
}

cmd_service() {
  local action="${1:-}"
  shift || true
  case "$action" in
    start|stop|restart|logs) ;;
    *)
      die "Usage: krate service {start|stop|restart|logs} --project <project> --service <service> [--tail N] [-f] [--json]"
      ;;
  esac

  local project="" service="" tail_lines="100" follow=false want_json=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --project) project="${2:-}"; shift 2 || true ;;
      --service) service="${2:-}"; shift 2 || true ;;
      --tail) tail_lines="${2:-100}"; shift 2 || true ;;
      -f|--follow) follow=true; shift ;;
      --json) want_json=true; shift ;;
      *) shift ;;
    esac
  done

  local -a common_args=()
  mapfile -t common_args < <(_ops_common_args)

  local val_out handler_kind resolved_proj
  if ! val_out="$(_ops_py service-validate "${common_args[@]}" --project "$project" --service "$service")"; then
    exit 1
  fi
  IFS=$'\t' read -r handler_kind resolved_proj <<< "$val_out"

  require_compose
  if [[ "$action" != "logs" ]]; then
    operation_lock "service-${action}-${service}"
    if [[ "$handler_kind" == "identity" ]]; then
      identity_lock
    elif [[ "$handler_kind" == "cluster" ]]; then
      identity_lock_if_enabled
    fi
  fi

  case "$handler_kind" in
    monitoring)
      case "$action" in
        start)   monitor_compose up -d --no-deps "$service" ;;
        stop)    monitor_compose stop "$service" ;;
        restart) monitor_compose restart "$service" ;;
        logs)
          if $follow; then
            monitor_compose logs --tail "$tail_lines" -f "$service"
          else
            monitor_compose logs --tail "$tail_lines" "$service"
          fi
          ;;
      esac
      ;;
    identity)
      require_compose_file
      case "$action" in
        start)   identity_compose up -d --pull never --no-build --no-deps "$service" ;;
        stop)    identity_compose stop "$service" ;;
        restart) identity_compose restart "$service" ;;
        logs)
          if $follow; then
            identity_compose logs --tail "$tail_lines" -f "$service"
          else
            identity_compose logs --tail "$tail_lines" "$service"
          fi
          ;;
      esac
      ;;
    cluster)
      require_compose_file
      case "$action" in
        start)   compose_cmd up -d --pull never --no-build --no-deps "$service" ;;
        stop)    compose_cmd stop "$service" ;;
        restart) compose_cmd restart "$service" ;;
        logs)
          if $follow; then
            compose_cmd logs --tail "$tail_lines" -f "$service"
          else
            compose_cmd logs --tail "$tail_lines" "$service"
          fi
          ;;
      esac
      ;;
  esac

  if [[ "$action" != "logs" ]]; then
    if $want_json; then
      python3 -c 'import json,sys; print(json.dumps({"schema_version": 1, "state": "succeeded", "action": sys.argv[1], "project": sys.argv[2], "service": sys.argv[3], "handler": sys.argv[4]}))' \
        "$action" "$resolved_proj" "$service" "$handler_kind"
    else
      ok "Service ${service} (${resolved_proj}): ${action} completed"
    fi
  fi
}

cmd_observe() {
  local mon_state="down"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --monitoring-state) mon_state="${2:-down}"; shift 2 || true ;;
      --json) shift ;;
      *) shift ;;
    esac
  done
  if [[ "$mon_state" == "down" ]] && command -v docker >/dev/null 2>&1; then
    local mon_proj="krate-${KRATE_VARIANT}-monitoring"
    local prom_cid
    prom_cid="$(docker ps -q --filter "label=com.docker.compose.project=$mon_proj" --filter "label=com.docker.compose.service=prometheus" 2>/dev/null | head -1 || true)"
    [[ -n "$prom_cid" ]] && mon_state="up"
  fi
  local -a common_args=()
  mapfile -t common_args < <(_ops_common_args)
  _ops_py observe "${common_args[@]}" --monitoring-state "$mon_state" --json
}

cmd_verify() {
  local want_json=false status_only=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json) want_json=true; shift ;;
      --status|--status-only) status_only=true; shift ;;
      *) shift ;;
    esac
  done
  local -a common_args=()
  mapfile -t common_args < <(_ops_common_args)
  local -a extra_args=()
  $want_json && extra_args+=(--json)
  $status_only && extra_args+=(--status-only)
  _ops_py verify "${common_args[@]}" "${extra_args[@]}"
}
