#!/usr/bin/env bash
# Shared operational boundary for the Krate CLI and Krate Studio.
# Sourced by kraft/krate and epc/krate.

cmd_workspace() {
  local action="${1:-resolve}"
  shift || true
  case "$action" in
    resolve)
      local pkg="false" sso_path
      sso_path="$(sso_dir)"
      if is_package; then
        pkg="true"
      fi
      PYTHONDONTWRITEBYTECODE=1 python3 -B "$sso_path/operations.py" workspace-resolve \
        --source-dir "$SCRIPT_DIR" \
        --install-dir "$KRATE_HOME" \
        --edition "$KRATE_VARIANT" \
        --repo-dir "${REPO_DIR:-}" \
        --is-package "$pkg" \
        "$@"
      ;;
    *)
      die "Usage: krate workspace resolve [--json]"
      ;;
  esac
}
