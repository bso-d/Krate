#!/usr/bin/env python3
import sys; sys.dont_write_bytecode = True
"""
Authoritative Krate CLI operational boundary helper.
Pure Python 3.9+ standard library implementation.
"""

import argparse
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
import py_compile
import re
import shutil
import subprocess
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_VERSION = 1

ESTABLISHED_ROTATION_KEYS = (
    "KEYCLOAK_DB_PASSWORD",
    "KEYCLOAK_ADMIN_PASSWORD",
    "KEYCLOAK_CLI_CLIENT_SECRET",
    "KEYCLOAK_KAFBAT_CLIENT_SECRET",
    "KEYCLOAK_IDP_WATCH_CLIENT_SECRET",
    "PING_KEYCLOAK_CLIENT_SECRET",
)

DISTINCT_SETTING_KEYS = (
    "KEYCLOAK_DB_PASSWORD",
    "KEYCLOAK_ADMIN_PASSWORD",
    "KEYCLOAK_CLI_CLIENT_SECRET",
    "KEYCLOAK_KAFBAT_CLIENT_SECRET",
    "KEYCLOAK_IDP_WATCH_CLIENT_SECRET",
    "KAFKA_UI_PASSWORD",
    "PING_KEYCLOAK_CLIENT_SECRET",
)

AUTH_MODE_KEYS = (
    "KAFKA_UI_AUTH_CONFIG",
    "GRAFANA_AUTH_CONFIG",
    "PERSES_AUTH_MODE",
    "PERSES_IDP",
)

SENSITIVE_KEY_PATTERN = re.compile(
    r"(PASSWORD|SECRET|TOKEN|PASSPHRASE|KEY|ENCRYPTION)",
    re.IGNORECASE,
)
IMAGE_PIN_PATTERN = re.compile(r"^[A-Z0-9_]+_IMAGE$")
VALID_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
GENERATED_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9._-]{16,}$")
PING_VALUE_FORBIDDEN_PATTERN = re.compile(r"[^!-~]|[\\$\"'`]")
PING_FORMAT_RULE = (
    "must be at least 16 printable ASCII characters with no whitespace, quotes, backslash, backtick or $"
)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_sensitive_key(key: str) -> bool:
    if key in ESTABLISHED_ROTATION_KEYS or key in DISTINCT_SETTING_KEYS:
        return True
    if key.endswith("_USER") or key.endswith("_USERNAME") or key.endswith("_PUBLIC_KEY"):
        return False
    return bool(SENSITIVE_KEY_PATTERN.search(key))


def parse_env_file(path: Optional[str]) -> Dict[str, str]:
    """Parse a .env file as pure data without shell evaluation."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        entries, _ = parse_env_text(text, strict=False)
        return entries
    except OSError:
        return {}


def parse_env_text(text: str, strict: bool = False) -> Tuple[Dict[str, str], List[str]]:
    """
    Parse .env content as pure data without shell evaluation.
    When strict=True, returns syntax errors for malformed lines or invalid keys.
    """
    entries: Dict[str, str] = {}
    errors: List[str] = []
    for idx, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            if strict:
                errors.append(f"Line {idx}: missing '=' in configuration assignment")
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not VALID_KEY_PATTERN.match(key):
            if strict:
                errors.append(f"Line {idx}: invalid variable name {key!r}")
            continue
        if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
            val = val[1:-1]
        if "\x00" in val or "\n" in val or "\r" in val:
            if strict:
                errors.append(f"Line {idx}: invalid control character in value for {key}")
            continue
        entries[key] = val
    return entries, errors


def _atomic_write_bytes(path: str, data: bytes, mode: int = 0o600) -> None:
    """Atomically write bytes to path using O_EXCL temporary file and os.replace."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    base = os.path.basename(path)
    tmp_path = os.path.join(parent, f".{base}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _atomic_write_json(path: str, payload: Dict[str, Any], mode: int = 0o600) -> None:
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write_bytes(path, raw, mode=mode)


def _ensure_private_recovery_dir(effective_dir: str) -> str:
    """
    Ensure auth/.operation-recovery exists with strict 0700 permissions.
    Raises RuntimeError if permissions cannot be secured.
    """
    auth_dir = os.path.join(effective_dir, "auth")
    os.makedirs(auth_dir, exist_ok=True)
    rec_dir = os.path.join(auth_dir, ".operation-recovery")
    os.makedirs(rec_dir, mode=0o700, exist_ok=True)
    os.chmod(rec_dir, 0o700)
    actual_mode = os.stat(rec_dir).st_mode & 0o777
    if actual_mode != 0o700:
        raise RuntimeError(
            f"Refusing to stage recovery state: {rec_dir} permissions are {oct(actual_mode)} (expected 0o700)"
        )
    return rec_dir


def _format_env_value(val: str) -> str:
    if any(ch in val for ch in (" ", "\t", "#", '"', "'")):
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return val


def write_env_updates(
    file_path: str,
    template_path: Optional[str],
    updates: Dict[str, str],
    removed_keys: Optional[list] = None,
) -> None:
    """
    Atomically update key=value pairs in an .env file (mode 0600), preserving comments and ordering.
    """
    removed_set = set(removed_keys or [])
    lines: List[str] = []
    if os.path.isfile(file_path):
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    elif template_path and os.path.isfile(template_path):
        with open(template_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

    seen = set()
    new_lines: List[str] = []
    for raw_line in lines:
        stripped = raw_line.strip()
        if stripped and not stripped.startswith("#"):
            candidate = stripped[len("export "):].strip() if stripped.startswith("export ") else stripped
            if "=" in candidate:
                k = candidate.split("=", 1)[0].strip()
                if k in removed_set and k not in updates:
                    seen.add(k)
                    continue
                if k in updates:
                    if k not in seen:
                        new_lines.append(f"{k}={_format_env_value(updates[k])}\n")
                        seen.add(k)
                    continue
        new_lines.append(raw_line if raw_line.endswith("\n") else (raw_line + "\n"))

    for k, v in updates.items():
        if k not in seen:
            new_lines.append(f"{k}={_format_env_value(v)}\n")

    content = "".join(new_lines).encode("utf-8")
    _atomic_write_bytes(file_path, content, mode=0o600)


def detect_edition(source_dir: str, explicit_edition: Optional[str] = None) -> str:
    """Detect Krate edition (kraft or epc) from explicit arg, CLI script, or directory name."""
    if explicit_edition in ("kraft", "epc"):
        return explicit_edition
    krate_file = os.path.join(source_dir, "krate")
    if os.path.isfile(krate_file):
        try:
            with open(krate_file, "r", encoding="utf-8", errors="replace") as f:
                for _ in range(60):
                    line = f.readline()
                    if not line:
                        break
                    m = re.match(r'^KRATE_VARIANT=["\']?([a-zA-Z0-9_-]+)["\']?', line.strip())
                    if m and m.group(1) in ("kraft", "epc"):
                        return m.group(1)
        except OSError:
            pass
    base = os.path.basename(os.path.abspath(source_dir)).lower()
    if base == "epc" or "epc" in base:
        return "epc"
    return "kraft"


def detect_repo_dir(source_dir: str, edition: str, explicit_repo_dir: Optional[str] = None) -> str:
    """Detect repository root when running from a source checkout (<repo>/kraft or <repo>/epc)."""
    if explicit_repo_dir is not None:
        cleaned = explicit_repo_dir.strip()
        if cleaned and os.path.isdir(cleaned):
            return os.path.abspath(cleaned)
        return ""
    abs_src = os.path.abspath(source_dir)
    parent = os.path.dirname(abs_src)
    if (
        os.path.basename(abs_src) == edition
        and not os.path.isdir(os.path.join(abs_src, "images"))
        and os.path.isfile(os.path.join(parent, "Makefile"))
        and os.path.isfile(os.path.join(parent, "kafbat-ui", "build.py"))
    ):
        return os.path.abspath(parent)
    return ""


def _get_or_create_revision_key(effective_dir: str) -> Optional[bytes]:
    """Read or atomically create the installation-private 32-byte HMAC key (mode 0600)."""
    auth_dir = os.path.join(effective_dir, "auth")
    key_path = os.path.join(auth_dir, ".revision.key")
    try:
        if os.path.isfile(key_path):
            with open(key_path, "rb") as f:
                data = f.read()
            if len(data) >= 32:
                try:
                    if (os.stat(key_path).st_mode & 0o777) != 0o600:
                        os.chmod(key_path, 0o600)
                except OSError:
                    pass
                return data[:32]
        os.makedirs(auth_dir, exist_ok=True)
        raw_key = os.urandom(32)
        tmp_path = os.path.join(auth_dir, f".revision.key.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw_key)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, key_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return raw_key
    except OSError:
        return None


def compute_config_revision(
    effective_dir: Optional[str],
    env_path: Optional[str],
    monitoring_env_path: Optional[str],
) -> Optional[str]:
    """
    Compute keyed HMAC-SHA256 revision over canonical configuration state.
    Returns None if the installation is not yet installed or has no .env file.
    """
    if not effective_dir or not env_path or not os.path.isfile(env_path):
        return None
    key = _get_or_create_revision_key(effective_dir)
    if not key:
        return None
    env_data = parse_env_file(env_path)
    mon_data = parse_env_file(monitoring_env_path) if (monitoring_env_path and os.path.isfile(monitoring_env_path)) else {}
    canonical = json.dumps(
        {"env": env_data, "monitoring_env": mon_data},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _read_json_file(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def resolve_workspace(
    source_dir: str,
    install_dir: Optional[str] = None,
    edition: Optional[str] = None,
    repo_dir: Optional[str] = None,
    is_package_flag: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Resolve authoritative workspace and installation context without mutating KRATE_HOME
    or requiring a running Docker daemon.
    """
    abs_source = os.path.abspath(source_dir)
    resolved_edition = detect_edition(abs_source, edition)
    resolved_repo = detect_repo_dir(abs_source, resolved_edition, repo_dir)

    if install_dir and install_dir.strip():
        abs_install = os.path.abspath(install_dir.strip())
    else:
        env_home = os.environ.get("KRATE_HOME", "").strip()
        abs_install = os.path.abspath(env_home) if env_home else f"/opt/krate/{resolved_edition}"

    same_dir = os.path.realpath(abs_source) == os.path.realpath(abs_install)
    has_images = os.path.isdir(os.path.join(abs_source, "images"))

    if is_package_flag is not None:
        is_package = bool(is_package_flag) and not bool(resolved_repo)
    else:
        is_package = (not bool(resolved_repo)) and has_images and (not same_dir)

    effective_dir: Optional[str]
    if resolved_repo:
        runtime_kind = "checkout"
        is_package = False
        is_installed = True
        effective_dir = abs_source
    elif is_package:
        installed_krate = os.path.join(abs_install, "krate")
        has_installed_cli = os.path.isfile(installed_krate) and os.access(installed_krate, os.X_OK)
        if has_installed_cli:
            runtime_kind = "installed"
            is_installed = True
            effective_dir = abs_install
        else:
            runtime_kind = "package_uninstalled"
            is_installed = False
            effective_dir = None
    else:
        runtime_kind = "installed"
        is_package = False
        is_installed = True
        abs_install = abs_source
        effective_dir = abs_source

    installation_id = f"{resolved_edition}:{effective_dir or abs_source}"

    env_path: Optional[str] = None
    monitoring_env_path: Optional[str] = None
    if effective_dir:
        env_path = os.path.join(effective_dir, ".env")
        mon_dir = os.path.join(effective_dir, "monitoring")
        if not os.path.isdir(mon_dir) and resolved_repo:
            repo_mon = os.path.join(resolved_repo, "monitoring")
            if os.path.isdir(repo_mon):
                mon_dir = repo_mon
        monitoring_env_path = os.path.join(mon_dir, ".env")

    config_revision = compute_config_revision(effective_dir, env_path, monitoring_env_path)

    has_draft = False
    pending_services: List[Any] = []
    recovery_required = False
    recovery_summary: Optional[dict] = None

    if effective_dir:
        draft_data = _read_json_file(os.path.join(effective_dir, "auth", ".config-draft.json"))
        if draft_data and (draft_data.get("entries") or draft_data.get("raw") or draft_data.get("targets")):
            has_draft = True

        applied_data = _read_json_file(os.path.join(effective_dir, "auth", ".config-applied.json"))
        if applied_data and isinstance(applied_data.get("pending_services"), list):
            pending_services = list(applied_data["pending_services"])

        rec_data = _read_json_file(os.path.join(effective_dir, "auth", ".operation-recovery", "current.json"))
        if rec_data and rec_data.get("recovery_required", True):
            recovery_required = True
            recovery_summary = {
                "op_id": rec_data.get("op_id"),
                "operation": rec_data.get("operation"),
                "step": rec_data.get("step"),
                "started_at": rec_data.get("started_at"),
                "error": rec_data.get("error"),
            }

    env_entries = parse_env_file(env_path) if env_path else {}
    cluster_project = (
        os.environ.get("KRATE_PROJECT", "").strip()
        or env_entries.get("KRATE_PROJECT", "").strip()
        or f"krate-{resolved_edition}"
    )
    monitor_project = f"krate-{resolved_edition}-monitoring"

    return {
        "schema_version": SCHEMA_VERSION,
        "source_dir": abs_source,
        "install_dir": abs_install,
        "effective_dir": effective_dir,
        "installation_id": installation_id,
        "edition": resolved_edition,
        "runtime_kind": runtime_kind,
        "is_package": is_package,
        "is_installed": is_installed,
        "env_path": env_path,
        "monitoring_env_path": monitoring_env_path,
        "config_revision": config_revision,
        "has_draft": has_draft,
        "pending_services": pending_services,
        "recovery_required": recovery_required,
        "recovery_summary": recovery_summary,
        "projects": {
            "cluster": cluster_project,
            "monitoring": monitor_project,
        },
    }


def _resolve_ws_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    is_pkg: Optional[bool] = None
    if getattr(args, "is_package", None) in ("true", "1", "yes"):
        is_pkg = True
    elif getattr(args, "is_package", None) in ("false", "0", "no"):
        is_pkg = False
    return resolve_workspace(
        source_dir=args.source_dir,
        install_dir=args.install_dir,
        edition=args.edition,
        repo_dir=args.repo_dir,
        is_package_flag=is_pkg,
    )


def _cmd_workspace_resolve(args: argparse.Namespace) -> int:
    payload = _resolve_ws_from_args(args)
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(f"Edition:         {payload['edition']}\n")
        sys.stdout.write(f"Runtime kind:    {payload['runtime_kind']}\n")
        sys.stdout.write(f"Source dir:      {payload['source_dir']}\n")
        sys.stdout.write(f"Install dir:     {payload['install_dir']}\n")
        sys.stdout.write(f"Effective dir:   {payload['effective_dir'] or '(uninstalled package)'}\n")
        sys.stdout.write(f"Installation ID: {payload['installation_id']}\n")
        sys.stdout.write(f"Config revision: {payload['config_revision'] or '(none)'}\n")
    return 0


def classify_key(key: str) -> str:
    if IMAGE_PIN_PATTERN.match(key):
        return "release_pin"
    if key in ESTABLISHED_ROTATION_KEYS:
        return "established_secret"
    if key in AUTH_MODE_KEYS:
        return "auth_mode"
    return "ordinary"


def validate_value_format(key: str, value: str) -> Optional[str]:
    if key == "PING_KEYCLOAK_CLIENT_SECRET":
        if len(value) < 16 or PING_VALUE_FORBIDDEN_PATTERN.search(value):
            return f"{key} {PING_FORMAT_RULE}"
        return None
    if key in ESTABLISHED_ROTATION_KEYS:
        if not GENERATED_VALUE_PATTERN.match(value):
            return f"{key} must be at least 16 characters of letters, digits, . _ or -"
    return None


def validate_key_value(
    key: str,
    value: str,
    effective_env: Dict[str, str],
    identity_state: str = "pristine",
    is_save_only: bool = False,
) -> Optional[str]:
    if not VALID_KEY_PATTERN.match(key):
        return f"Invalid configuration key {key!r}"
    if "\x00" in value or "\n" in value or "\r" in value:
        return f"Invalid control character in value for {key}"

    classification = classify_key(key)
    if classification == "release_pin":
        return f"Image pins come from .env.template; change {key} there, or export it in the shell for one run."

    if classification == "auth_mode":
        if key == "KAFKA_UI_AUTH_CONFIG" and value not in ("local.yml", "runtime.yml"):
            return f"Unsupported {key}={value!r}; supported modes are local.yml and runtime.yml."
        if key == "GRAFANA_AUTH_CONFIG" and value not in ("local.ini", "realm.ini"):
            return f"Unsupported {key}={value!r}; supported modes are local.ini and realm.ini (master realm is unsupported)."
        if key == "PERSES_AUTH_MODE" and value not in ("local", "native"):
            return f"Unsupported {key}={value!r}; supported modes are local and native."
        if key == "PERSES_IDP" and value == "master":
            return "Master realm mode is not supported; use 'krate' realm or local mode."

    if classification == "established_secret" or key in DISTINCT_SETTING_KEYS:
        state_head = (identity_state or "pristine").split()[0]
        if key in ESTABLISHED_ROTATION_KEYS:
            if is_save_only and key != "PING_KEYCLOAK_CLIENT_SECRET":
                if state_head == "existing":
                    return (
                        f"The identity database already uses {key} (identity state: {identity_state}). "
                        f"Change it on both sides with: krate identity rotate {key}"
                    )
                if state_head != "pristine":
                    return f"Cannot set {key} while the identity state is unclear (identity state: {identity_state})"
            elif not is_save_only:
                if state_head not in ("pristine", "existing"):
                    return f"Cannot change {key} while the identity state is unclear (identity state: {identity_state})"

            fmt_err = validate_value_format(key, value)
            if fmt_err:
                return fmt_err

        if value:
            for other in DISTINCT_SETTING_KEYS:
                if other != key:
                    other_val = effective_env.get(other, "")
                    if other_val and other_val == value:
                        return f"{key} must not reuse the value of {other} (every identity and UI credential must be distinct)"

    return None


def affected_services_for_key(
    key: str,
    target: str,
    cluster_project: str,
    monitor_project: str,
    effective_env: Dict[str, str],
    effective_mon_env: Dict[str, str],
    identity_state: str = "pristine",
) -> List[Dict[str, str]]:
    state_head = (identity_state or "pristine").split()[0]
    services: List[Dict[str, str]] = []

    def add(proj: str, svc: str, svc_reason: str) -> None:
        for item in services:
            if item["project"] == proj and item["service"] == svc:
                return
        services.append({"project": proj, "service": svc, "reason": svc_reason})

    if target == "monitoring/.env" or key.startswith(("GRAFANA_", "GF_", "PROMETHEUS_", "PROM_", "ALERTMANAGER_", "ALERT_", "LOKI_", "PERSES_", "OAUTH2_PROXY_")):
        if key.startswith(("GRAFANA_", "GF_")):
            add(monitor_project, "grafana", "auth_transition" if key in AUTH_MODE_KEYS else "config_change")
        elif key.startswith(("PROMETHEUS_", "PROM_")):
            add(monitor_project, "prometheus", "config_change")
        elif key.startswith(("ALERTMANAGER_", "ALERT_")):
            add(monitor_project, "alertmanager", "config_change")
        elif key.startswith("LOKI_"):
            add(monitor_project, "loki", "config_change")
        elif key.startswith(("PERSES_", "OAUTH2_PROXY_")) or key == "KRATE_RENDER_REVISION":
            reason = "auth_transition" if key in AUTH_MODE_KEYS else "config_change"
            add(monitor_project, "perses", reason)
            if effective_mon_env.get("PERSES_AUTH_MODE") == "native" or key in ("PERSES_AUTH_MODE", "PERSES_IDP"):
                add(monitor_project, "oauth2-proxy", reason)
                add(monitor_project, "perses-sync", reason)
        else:
            add(monitor_project, "grafana", "config_change")
        return services

    if key in ESTABLISHED_ROTATION_KEYS:
        reason = "credential_rotation" if state_head == "existing" else "config_change"
        add(cluster_project, "keycloak", reason)
        if key == "KEYCLOAK_KAFBAT_CLIENT_SECRET" and effective_env.get("KAFKA_UI_AUTH_CONFIG") == "runtime.yml":
            add(cluster_project, "kafka-ui", reason)
        elif key == "KEYCLOAK_IDP_WATCH_CLIENT_SECRET" and effective_env.get("IDP_WATCH_ENABLED") == "true":
            add(cluster_project, "idp-watch", reason)
        return services

    if key == "KAFKA_UI_AUTH_CONFIG":
        add(cluster_project, "kafka-ui", "auth_transition")
        add(cluster_project, "proxy", "auth_transition")
        return services

    if key.startswith("KAFKA_UI_") or key == "KRATE_UI_AUTH_SHA":
        add(cluster_project, "kafka-ui", "config_change")
    elif key.startswith(("HTTPS_PORT", "KRATE_PROXY_")):
        add(cluster_project, "proxy", "config_change")
    elif key == "KEYCLOAK_PUBLIC_URL":
        add(cluster_project, "keycloak", "config_change")
        add(cluster_project, "proxy", "config_change")
        if effective_env.get("KAFKA_UI_AUTH_CONFIG") == "runtime.yml":
            add(cluster_project, "kafka-ui", "config_change")
    elif key.startswith("KEYCLOAK_") or key == "KRATE_TRUSTSTORE_SHA":
        add(cluster_project, "keycloak", "config_change")
    elif key.startswith("IDP_WATCH_"):
        add(cluster_project, "idp-watch", "config_change")
    else:
        for b in ("kafka-92", "kafka-93", "kafka-94", "kafka-95"):
            add(cluster_project, b, "config_change")

    return services


def _resolve_target_paths(ws: Dict[str, Any]) -> Tuple[str, str, str, str]:
    effective_dir = ws.get("effective_dir") or ws.get("source_dir")
    env_path = ws.get("env_path") or os.path.join(effective_dir, ".env")
    env_tpl = os.path.join(os.path.dirname(env_path), ".env.template")
    if not os.path.isfile(env_tpl):
        env_tpl = os.path.join(ws["source_dir"], ".env.template")

    mon_env_path = ws.get("monitoring_env_path") or os.path.join(effective_dir, "monitoring", ".env")
    mon_tpl = mon_env_path + ".template"
    return env_path, env_tpl, mon_env_path, mon_tpl


def _load_applied_state(effective_dir: str, current_env: Dict[str, str], current_mon: Dict[str, str]) -> Dict[str, Any]:
    path = os.path.join(effective_dir, "auth", ".config-applied.json")
    data = _read_json_file(path)
    if data and isinstance(data.get("applied_env"), dict) and isinstance(data.get("applied_monitoring_env"), dict):
        return {
            "schema_version": SCHEMA_VERSION,
            "applied_env": dict(data["applied_env"]),
            "applied_monitoring_env": dict(data["applied_monitoring_env"]),
            "pending_services": list(data.get("pending_services") or []),
            "updated_at": data.get("updated_at"),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "applied_env": dict(current_env),
        "applied_monitoring_env": dict(current_mon),
        "pending_services": [],
        "updated_at": None,
    }


def _save_applied_state(effective_dir: str, state: Dict[str, Any]) -> None:
    path = os.path.join(effective_dir, "auth", ".config-applied.json")
    state["schema_version"] = SCHEMA_VERSION
    state["updated_at"] = _utc_now_iso()
    _atomic_write_json(path, state, mode=0o600)


def build_config_plan(
    ws: Dict[str, Any],
    request: Dict[str, Any],
    identity_state: str = "pristine",
) -> Tuple[int, Dict[str, Any]]:
    effective_dir = ws.get("effective_dir")
    if not effective_dir:
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "uninstalled_package",
            "error": "Package is not installed yet. Run 'krate install' before modifying configuration.",
            "effective_dir": None,
        }

    if ws.get("recovery_required"):
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "recovery_required",
            "error_code": "recovery_required",
            "error": "An interrupted configuration operation requires recovery. Run 'krate config recover' first.",
            "effective_dir": effective_dir,
            "recovery_summary": ws.get("recovery_summary"),
        }

    expected_rev = request.get("expected_revision")
    current_rev = ws.get("config_revision")
    if expected_rev and current_rev and expected_rev != current_rev:
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "stale_revision",
            "error": (
                f"Configuration was modified by another operation "
                f"(expected revision {expected_rev[:12]}, current {current_rev[:12]}). Reload before applying."
            ),
            "effective_dir": effective_dir,
            "old_revision": current_rev,
        }

    target = request.get("target") or ".env"
    if target not in (".env", "monitoring/.env"):
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "invalid_target",
            "error": f"Unsupported configuration target {target!r}; must be '.env' or 'monitoring/.env'.",
            "effective_dir": effective_dir,
        }

    env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)
    cur_env = parse_env_file(env_path if os.path.isfile(env_path) else env_tpl)
    cur_mon = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)
    tpl_env = parse_env_file(env_tpl)
    tpl_mon = parse_env_file(mon_tpl)

    applied_state = _load_applied_state(effective_dir, cur_env, cur_mon)
    applied_env = applied_state["applied_env"]
    applied_mon = applied_state["applied_monitoring_env"]

    mode = request.get("mode")
    if not mode:
        mode = "raw" if request.get("raw") is not None else "entries"

    current_target_map = cur_mon if target == "monitoring/.env" else cur_env
    template_target_map = tpl_mon if target == "monitoring/.env" else tpl_env
    applied_target_map = applied_mon if target == "monitoring/.env" else applied_env

    candidate_map: Dict[str, str] = dict(current_target_map)
    removed_keys: List[str] = []

    if mode == "raw":
        raw_text = request.get("raw")
        if not isinstance(raw_text, str):
            return 1, {
                "schema_version": SCHEMA_VERSION,
                "state": "failed",
                "error_code": "invalid_payload",
                "error": "Missing or invalid 'raw' string payload.",
                "effective_dir": effective_dir,
            }
        parsed_raw, parse_errors = parse_env_text(raw_text, strict=True)
        if parse_errors:
            return 1, {
                "schema_version": SCHEMA_VERSION,
                "state": "failed",
                "error_code": "syntax_error",
                "error": "; ".join(parse_errors),
                "effective_dir": effective_dir,
            }
        candidate_map = dict(parsed_raw)
        for existing_key in list(current_target_map.keys()):
            if existing_key not in candidate_map:
                if existing_key in template_target_map:
                    candidate_map[existing_key] = template_target_map[existing_key]
                else:
                    removed_keys.append(existing_key)
    elif mode == "entries":
        raw_entries = request.get("entries")
        if not isinstance(raw_entries, dict):
            return 1, {
                "schema_version": SCHEMA_VERSION,
                "state": "failed",
                "error_code": "invalid_payload",
                "error": "Missing or invalid 'entries' dictionary payload.",
                "effective_dir": effective_dir,
            }
        for k, v in raw_entries.items():
            key_str = str(k).strip()
            if v is None:
                if key_str in template_target_map:
                    candidate_map[key_str] = template_target_map[key_str]
                else:
                    candidate_map.pop(key_str, None)
                    removed_keys.append(key_str)
            else:
                candidate_map[key_str] = str(v)
    else:
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "invalid_mode",
            "error": f"Unsupported mode {mode!r}; must be 'entries' or 'raw'.",
            "effective_dir": effective_dir,
        }

    merged_env = dict(cur_env)
    merged_mon = dict(cur_mon)
    if target == "monitoring/.env":
        merged_mon = dict(candidate_map)
    else:
        merged_env = dict(candidate_map)

    all_keys = sorted(set(current_target_map.keys()) | set(candidate_map.keys()) | set(applied_target_map.keys()))
    changes: List[Dict[str, Any]] = []
    rotation_targets: Dict[str, str] = {}
    file_updates: Dict[str, str] = {}
    affected_services: List[Dict[str, str]] = []

    cluster_project = ws["projects"]["cluster"]
    monitor_project = ws["projects"]["monitoring"]
    state_head = (identity_state or "pristine").split()[0]

    def merge_affected(items: List[Dict[str, str]]) -> None:
        for it in items:
            if not any(x["project"] == it["project"] and x["service"] == it["service"] for x in affected_services):
                affected_services.append(it)

    for key in all_keys:
        cur_val = current_target_map.get(key)
        new_val = candidate_map.get(key)
        app_val = applied_target_map.get(key, cur_val)

        classification = classify_key(key)
        file_changed = cur_val != new_val
        pending_apply = app_val != new_val
        if classification == "established_secret" and key != "PING_KEYCLOAK_CLIENT_SECRET" and state_head == "existing":
            pending_apply = False

        if not file_changed and not pending_apply:
            continue

        val_to_check = new_val if new_val is not None else ""
        err = validate_key_value(
            key=key,
            value=val_to_check,
            effective_env=merged_env,
            identity_state=identity_state,
            is_save_only=False,
        )
        if err:
            return 1, {
                "schema_version": SCHEMA_VERSION,
                "state": "failed",
                "error_code": "validation_failed",
                "error": err,
                "effective_dir": effective_dir,
                "old_revision": current_rev,
            }

        redacted = is_sensitive_key(key)

        if classification == "established_secret" and state_head == "existing":
            action = "rotate_identity_secret"
            if new_val is not None:
                rotation_targets[key] = new_val
        elif classification == "auth_mode":
            action = "auth_transition"
            if new_val is not None and file_changed:
                file_updates[key] = new_val
        else:
            action = "update_env" if file_changed else "reconcile_pending"
            if new_val is not None and file_changed:
                file_updates[key] = new_val

        change_entry: Dict[str, Any] = {
            "key": key,
            "target": target,
            "classification": classification,
            "action": action,
            "redacted": redacted,
            "file_changed": file_changed,
            "pending_reconciliation": not file_changed and pending_apply,
        }
        if not redacted:
            change_entry["old_value"] = cur_val
            change_entry["new_value"] = new_val
        changes.append(change_entry)

        svcs = affected_services_for_key(
            key=key,
            target=target,
            cluster_project=cluster_project,
            monitor_project=monitor_project,
            effective_env=merged_env,
            effective_mon_env=merged_mon,
            identity_state=identity_state,
        )
        merge_affected(svcs)

    for pend in applied_state.get("pending_services") or []:
        if isinstance(pend, dict) and pend.get("project") and pend.get("service"):
            merge_affected([{
                "project": str(pend["project"]),
                "service": str(pend["service"]),
                "reason": str(pend.get("reason") or "pending_config_set"),
            }])

    steps: List[Dict[str, str]] = []
    for key in rotation_targets:
        steps.append({"step": f"rotate_{key}", "status": "planned"})
    if rotation_targets:
        steps.append({"step": "verify_identity_admin", "status": "planned"})
    if file_updates or removed_keys:
        steps.append({"step": f"write_{target}", "status": "planned"})
    for svc in affected_services:
        if svc["reason"] != "credential_rotation":
            steps.append({"step": f"reconcile_{svc['project']}_{svc['service']}", "status": "planned"})

    plan_payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "state": "planned",
        "effective_dir": effective_dir,
        "installation_id": ws["installation_id"],
        "target": target,
        "old_revision": current_rev,
        "new_revision": current_rev,
        "changes": changes,
        "affected_services": affected_services,
        "steps": steps,
        "_internal": {
            "rotation_targets": rotation_targets,
            "file_updates": file_updates,
            "removed_keys": removed_keys,
            "candidate_map": candidate_map,
        },
    }
    return 0, plan_payload


def _strip_internal(payload: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = dict(payload)
    cleaned.pop("_internal", None)
    return cleaned


def _cmd_config_show(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)
    env_src = env_path if os.path.isfile(env_path) else env_tpl
    mon_src = mon_env_path if os.path.isfile(mon_env_path) else mon_tpl

    def read_raw(p: str) -> str:
        if not p or not os.path.isfile(p):
            return ""
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    effective_dir = ws.get("effective_dir")
    draft_data = _read_json_file(os.path.join(effective_dir, "auth", ".config-draft.json")) if effective_dir else None

    payload = {
        "schema_version": SCHEMA_VERSION,
        "effective_dir": effective_dir,
        "runtime_kind": ws["runtime_kind"],
        "installation_id": ws["installation_id"],
        "config_revision": ws["config_revision"],
        "env": parse_env_file(env_src),
        "monitoring_env": parse_env_file(mon_src),
        "raw_env": read_raw(env_src),
        "raw_monitoring_env": read_raw(mon_src),
        "has_draft": ws["has_draft"],
        "draft": draft_data,
        "pending_services": ws["pending_services"],
        "recovery_required": ws["recovery_required"],
        "recovery_summary": ws["recovery_summary"],
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


def _cmd_config_plan(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    try:
        req = json.loads(sys.stdin.read() or "{}")
    except ValueError as e:
        out = {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "invalid_json",
            "error": f"Invalid JSON input on stdin: {e}",
            "effective_dir": ws.get("effective_dir"),
        }
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 1

    rc, plan = build_config_plan(ws, req, identity_state=args.identity_state)
    public_plan = _strip_internal(plan)
    if args.json:
        sys.stdout.write(json.dumps(public_plan, indent=2) + "\n")
    else:
        if rc != 0:
            sys.stderr.write(f"ERROR: {public_plan.get('error', 'Plan failed')}\n")
        else:
            sys.stdout.write(f"Target: {public_plan.get('effective_dir')} ({public_plan.get('target')})\n")
            sys.stdout.write(f"Changes: {len(public_plan.get('changes', []))}\n")
            for ch in public_plan.get("changes", []):
                sys.stdout.write(f"  - {ch['key']}: {ch['classification']} -> {ch['action']}\n")
    return rc


def _cmd_config_stage_apply(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    try:
        req = json.loads(sys.stdin.read() or "{}")
    except ValueError as e:
        out = {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "invalid_json",
            "error": f"Invalid JSON input on stdin: {e}",
            "effective_dir": ws.get("effective_dir"),
        }
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 1

    rc, plan = build_config_plan(ws, req, identity_state=args.identity_state)
    if rc != 0:
        sys.stdout.write(json.dumps(_strip_internal(plan), indent=2) + "\n")
        return rc

    effective_dir = ws["effective_dir"]
    internal = plan.get("_internal", {})
    changes = plan.get("changes", [])
    affected_services = plan.get("affected_services", [])

    if not changes and not affected_services:
        noop_out = _strip_internal(plan)
        noop_out["state"] = "succeeded"
        sys.stdout.write(json.dumps(noop_out, indent=2) + "\n")
        return 0

    try:
        rec_dir = _ensure_private_recovery_dir(effective_dir)
        rec_file = os.path.join(rec_dir, "current.json")
        op_id = f"cfg-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        recovery_doc = {
            "schema_version": SCHEMA_VERSION,
            "op_id": op_id,
            "operation": "config_apply",
            "state": "applying",
            "recovery_required": True,
            "step": "staged",
            "started_at": _utc_now_iso(),
            "target": plan["target"],
            "effective_dir": effective_dir,
            "old_revision": plan["old_revision"],
            "changes": changes,
            "affected_services": affected_services,
            "steps": plan["steps"],
            "rotation_targets": internal.get("rotation_targets", {}),
            "file_updates": internal.get("file_updates", {}),
            "removed_keys": internal.get("removed_keys", []),
            "completed_steps": [],
            "error": None,
        }
        _atomic_write_json(rec_file, recovery_doc, mode=0o600)
        actual_file_mode = os.stat(rec_file).st_mode & 0o777
        if actual_file_mode != 0o600:
            try:
                os.unlink(rec_file)
            except OSError:
                pass
            raise RuntimeError(
                f"Refusing to proceed: recovery file permissions are {oct(actual_file_mode)} (expected 0o600)"
            )
    except Exception as exc:
        err_out = {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "recovery_staging_failed",
            "error": str(exc),
            "effective_dir": effective_dir,
        }
        sys.stdout.write(json.dumps(err_out, indent=2) + "\n")
        return 1

    staged_out = _strip_internal(plan)
    staged_out["state"] = "applying"
    staged_out["op_id"] = op_id
    sys.stdout.write(json.dumps(staged_out, indent=2) + "\n")
    return 0


def _cmd_config_exec_helper(args: argparse.Namespace) -> int:
    """
    Internal helper used by sso/operations.sh during an active locked apply or recovery:
    - action=list-work: prints tab-separated directives for bash executor without exposing values in argv
    - action=stage-rotation-input --key KEY --out-file FILE: writes the staged value for KEY to FILE (mode 0600)
    - action=write-files: writes staged ordinary/auth_mode updates to .env / monitoring/.env
    - action=step --step NAME --status STATUS [--error MSG]: updates recovery record step
    - action=finalize: updates .config-applied.json, removes recovery record, prints final JSON
    """
    ws = _resolve_ws_from_args(args)
    effective_dir = ws.get("effective_dir")
    if not effective_dir:
        sys.stderr.write("ERROR: No effective installation directory.\n")
        return 1

    rec_file = os.path.join(effective_dir, "auth", ".operation-recovery", "current.json")
    rec_data = _read_json_file(rec_file)
    if not rec_data:
        sys.stderr.write("ERROR: No active operation recovery record found.\n")
        return 1

    sub_action = args.action
    if sub_action == "list-work":
        completed = set(rec_data.get("completed_steps") or [])
        if rec_data.get("operation") == "auth_transition":
            targets_rec = rec_data.get("targets") or {}
            cl_proj = ws["projects"]["cluster"]
            mn_proj = ws["projects"]["monitoring"]
            if "kafbat" in targets_rec and targets_rec["kafbat"].get("status") != "succeeded":
                if f"reconcile_{cl_proj}_kafka-ui" not in completed:
                    sys.stdout.write(f"RECONCILE\t{cl_proj}\tkafka-ui\tauth_transition\n")
            mon_failed = (
                rec_data.get("step") == "monitor_up"
                or ("grafana" in targets_rec and targets_rec["grafana"].get("status") != "succeeded")
                or ("perses" in targets_rec and targets_rec["perses"].get("status") != "succeeded")
            )
            if mon_failed and f"reconcile_{mn_proj}_grafana" not in completed:
                sys.stdout.write(f"RECONCILE\t{mn_proj}\tgrafana\tauth_transition\n")
            return 0
        for key in rec_data.get("rotation_targets") or {}:
            if f"rotate_{key}" not in completed:
                sys.stdout.write(f"ROTATE\t{key}\n")
        if (rec_data.get("file_updates") or rec_data.get("removed_keys")) and "write_files" not in completed:
            sys.stdout.write(f"WRITE_FILES\t{rec_data.get('target', '.env')}\n")
        for svc in rec_data.get("affected_services") or []:
            proj = svc.get("project", "")
            s_name = svc.get("service", "")
            reason = svc.get("reason", "config_change")
            step_id = f"reconcile_{proj}_{s_name}"
            if reason != "credential_rotation" and step_id not in completed:
                sys.stdout.write(f"RECONCILE\t{proj}\t{s_name}\t{reason}\n")
        return 0

    if sub_action == "stage-rotation-input":
        key = args.key or ""
        out_file = args.out_file or ""
        rot_val = (rec_data.get("rotation_targets") or {}).get(key)
        if rot_val is None or not out_file:
            return 1
        _atomic_write_bytes(out_file, (str(rot_val) + "\n").encode("utf-8"), mode=0o600)
        return 0

    if sub_action == "write-files":
        target = rec_data.get("target") or ".env"
        env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)
        file_path = mon_env_path if target == "monitoring/.env" else env_path
        tpl_path = mon_tpl if target == "monitoring/.env" else env_tpl
        updates = rec_data.get("file_updates") or {}
        removed = rec_data.get("removed_keys") or []
        if updates or removed:
            write_env_updates(file_path, tpl_path, updates, removed)
        completed_list = list(rec_data.get("completed_steps") or [])
        if "write_files" not in completed_list:
            completed_list.append("write_files")
        rec_data["completed_steps"] = completed_list
        rec_data["step"] = f"wrote_{target}"
        for st in rec_data.get("steps") or []:
            if st.get("step") == f"write_{target}":
                st["status"] = "succeeded"
        _atomic_write_json(rec_file, rec_data, mode=0o600)
        return 0

    if sub_action == "step":
        step_name = args.step or ""
        status_val = args.status or "succeeded"
        rec_data["step"] = step_name
        if status_val == "succeeded":
            completed_list = list(rec_data.get("completed_steps") or [])
            if step_name not in completed_list:
                completed_list.append(step_name)
            rec_data["completed_steps"] = completed_list
            if step_name.startswith("rotate_"):
                for st in rec_data.get("steps") or []:
                    if st.get("step") == "verify_identity_admin":
                        st["status"] = "succeeded"
        for st in rec_data.get("steps") or []:
            if st.get("step") == step_name:
                st["status"] = status_val
        if args.error:
            rec_data["error"] = args.error
            rec_data["state"] = "recovery_required"
            rec_data["recovery_required"] = True
        _atomic_write_json(rec_file, rec_data, mode=0o600)
        if args.error:
            fail_out = {
                "schema_version": SCHEMA_VERSION,
                "state": "recovery_required",
                "op_id": rec_data.get("op_id"),
                "effective_dir": effective_dir,
                "old_revision": rec_data.get("old_revision"),
                "new_revision": compute_config_revision(effective_dir, ws.get("env_path"), ws.get("monitoring_env_path")),
                "step": step_name,
                "error": args.error,
                "changes": rec_data.get("changes", []),
                "affected_services": rec_data.get("affected_services", []),
                "steps": rec_data.get("steps", []),
            }
            sys.stdout.write(json.dumps(fail_out, indent=2) + "\n")
        return 0

    if sub_action == "finalize":
        env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)
        cur_env = parse_env_file(env_path if os.path.isfile(env_path) else env_tpl)
        cur_mon = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)
        applied_state = {
            "schema_version": SCHEMA_VERSION,
            "applied_env": cur_env,
            "applied_monitoring_env": cur_mon,
            "pending_services": [],
        }
        _save_applied_state(effective_dir, applied_state)

        draft_path = os.path.join(effective_dir, "auth", ".config-draft.json")
        if os.path.isfile(draft_path):
            try:
                os.unlink(draft_path)
            except OSError:
                pass

        for st in rec_data.get("steps") or []:
            st["status"] = "succeeded"

        try:
            os.unlink(rec_file)
        except OSError:
            pass

        new_rev = compute_config_revision(effective_dir, env_path, mon_env_path)
        final_out = {
            "schema_version": SCHEMA_VERSION,
            "state": "succeeded",
            "op_id": rec_data.get("op_id"),
            "effective_dir": effective_dir,
            "old_revision": rec_data.get("old_revision"),
            "new_revision": new_rev,
            "changes": rec_data.get("changes", []),
            "affected_services": rec_data.get("affected_services", []),
            "steps": rec_data.get("steps", []),
        }
        sys.stdout.write(json.dumps(final_out, indent=2) + "\n")
        return 0

    return 1


def _cmd_config_draft(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    effective_dir = ws.get("effective_dir")
    if not effective_dir:
        out = {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "uninstalled_package",
            "error": "Package is not installed yet. Run 'krate install' first.",
        }
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 1

    try:
        req = json.loads(sys.stdin.read() or "{}")
    except ValueError as e:
        out = {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "invalid_json",
            "error": f"Invalid JSON input on stdin: {e}",
        }
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 1

    draft_path = os.path.join(effective_dir, "auth", ".config-draft.json")
    action = req.get("action", "save")
    if action == "discard":
        if os.path.isfile(draft_path):
            try:
                os.unlink(draft_path)
            except OSError:
                pass
        out = {
            "schema_version": SCHEMA_VERSION,
            "state": "discarded",
            "effective_dir": effective_dir,
            "has_draft": False,
            "config_revision": ws.get("config_revision"),
        }
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 0

    target = req.get("target") or ".env"
    if target not in (".env", "monitoring/.env"):
        out = {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "invalid_target",
            "error": f"Unsupported target {target!r}",
        }
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 1

    rc, plan = build_config_plan(ws, req, identity_state=args.identity_state)
    if rc != 0:
        sys.stdout.write(json.dumps(_strip_internal(plan), indent=2) + "\n")
        return rc

    internal = plan.get("_internal", {})
    existing_draft = _read_json_file(draft_path) or {"schema_version": SCHEMA_VERSION, "targets": {}}
    targets_map = dict(existing_draft.get("targets") or {})
    targets_map[target] = {
        "target": target,
        "mode": req.get("mode") or ("raw" if req.get("raw") is not None else "entries"),
        "entries": internal.get("candidate_map", {}),
        "raw": req.get("raw"),
        "changes": plan.get("changes", []),
        "affected_services": plan.get("affected_services", []),
        "saved_at": _utc_now_iso(),
    }
    draft_doc = {
        "schema_version": SCHEMA_VERSION,
        "base_revision": ws.get("config_revision"),
        "updated_at": _utc_now_iso(),
        "target": target,
        "entries": internal.get("candidate_map", {}),
        "raw": req.get("raw"),
        "changes": plan.get("changes", []),
        "affected_services": plan.get("affected_services", []),
        "targets": targets_map,
    }
    _atomic_write_json(draft_path, draft_doc, mode=0o600)

    out = {
        "schema_version": SCHEMA_VERSION,
        "state": "draft_saved",
        "effective_dir": effective_dir,
        "target": target,
        "has_draft": True,
        "config_revision": ws.get("config_revision"),
        "changes": plan.get("changes", []),
        "affected_services": plan.get("affected_services", []),
    }
    sys.stdout.write(json.dumps(out, indent=2) + "\n")
    return 0


def _cmd_config_set(args: argparse.Namespace) -> int:
    """
    Save-only handler for `krate config set KEY=VALUE`.
    Preserves the existing CLI contract while recording affected services as pending
    in auth/.config-applied.json.
    """
    ws = _resolve_ws_from_args(args)
    effective_dir = ws.get("effective_dir")
    if not effective_dir:
        sys.stderr.write("ERROR: Not installed yet. Run: ./krate install\n")
        return 1

    if ws.get("recovery_required"):
        sys.stderr.write("ERROR: An interrupted configuration operation requires recovery. Run: krate config recover\n")
        return 1

    kv = sys.stdin.read().rstrip("\r\n")
    if "=" not in kv:
        sys.stderr.write("ERROR: Usage: krate config set KEY=VALUE\n")
        return 1

    key, val = kv.split("=", 1)
    key = key.strip()

    env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)
    cur_env = parse_env_file(env_path if os.path.isfile(env_path) else env_tpl)
    cur_mon = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)
    tpl_env = parse_env_file(env_tpl)
    tpl_mon = parse_env_file(mon_tpl)

    target = ".env"
    target_path = env_path
    target_tpl = env_tpl
    if key not in tpl_env and key in tpl_mon:
        target = "monitoring/.env"
        target_path = mon_env_path
        target_tpl = mon_tpl

    err = validate_key_value(
        key=key,
        value=val,
        effective_env=cur_env,
        identity_state=args.identity_state,
        is_save_only=True,
    )
    if err:
        sys.stderr.write(f"ERROR: {err}\n")
        return 1

    applied_state = _load_applied_state(effective_dir, cur_env, cur_mon)

    if not os.path.isfile(target_path) and os.path.isfile(target_tpl):
        with open(target_tpl, "rb") as f:
            _atomic_write_bytes(target_path, f.read(), mode=0o600)

    write_env_updates(target_path, target_tpl, {key: val})

    new_env = parse_env_file(env_path if os.path.isfile(env_path) else env_tpl)
    new_mon = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)
    svcs = affected_services_for_key(
        key=key,
        target=target,
        cluster_project=ws["projects"]["cluster"],
        monitor_project=ws["projects"]["monitoring"],
        effective_env=new_env,
        effective_mon_env=new_mon,
        identity_state=args.identity_state,
    )
    pending_list = list(applied_state.get("pending_services") or [])
    for s in svcs:
        if not any(p.get("project") == s["project"] and p.get("service") == s["service"] for p in pending_list):
            pending_list.append({
                "project": s["project"],
                "service": s["service"],
                "reason": f"config_set:{key}",
                "key": key,
            })
    applied_state["pending_services"] = pending_list
    _save_applied_state(effective_dir, applied_state)

    compute_config_revision(effective_dir, env_path, mon_env_path)
    rel_file = os.path.relpath(target_path, effective_dir)
    if args.json:
        sys.stdout.write(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "state": "saved_pending_apply",
            "key": key,
            "target": rel_file,
            "pending_services": pending_list,
        }, indent=2) + "\n")
    else:
        sys.stdout.write(f"{rel_file}\n")
    return 0


def _cmd_config_clear_pending(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    effective_dir = ws.get("effective_dir")
    if not effective_dir:
        return 0
    env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)
    cur_env = parse_env_file(env_path if os.path.isfile(env_path) else env_tpl)
    cur_mon = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)
    applied_state = _load_applied_state(effective_dir, cur_env, cur_mon)
    scope = args.scope or "all"
    if scope == "all":
        applied_state["applied_env"] = cur_env
        applied_state["applied_monitoring_env"] = cur_mon
        applied_state["pending_services"] = []
    elif scope == "cluster":
        applied_state["applied_env"] = cur_env
        applied_state["pending_services"] = [
            p for p in (applied_state.get("pending_services") or [])
            if p.get("project") != ws["projects"]["cluster"]
        ]
    elif scope == "monitoring":
        applied_state["applied_monitoring_env"] = cur_mon
        applied_state["pending_services"] = [
            p for p in (applied_state.get("pending_services") or [])
            if p.get("project") != ws["projects"]["monitoring"]
        ]
    _save_applied_state(effective_dir, applied_state)
    return 0


def parse_compose_services(compose_path: Optional[str]) -> List[str]:
    """Extract service names from the top-level `services:` block of a docker-compose.yml file."""
    if not compose_path or not os.path.isfile(compose_path):
        return []
    services: List[str] = []
    in_services = False
    try:
        with open(compose_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not line.startswith(" "):
                    m_top = re.match(r"^([a-zA-Z0-9_-]+):\s*(?:#.*)?$", line)
                    if m_top:
                        in_services = m_top.group(1) == "services"
                    continue
                if in_services:
                    m_svc = re.match(r"^  ([a-zA-Z0-9_-]+):\s*(?:#.*)?$", line)
                    if m_svc:
                        svc_name = m_svc.group(1)
                        if svc_name not in services:
                            services.append(svc_name)
    except OSError:
        return []
    return services


def get_compose_inventory(ws: Dict[str, Any]) -> Dict[str, List[str]]:
    """Return authoritative Compose service inventory per project for this workspace."""
    effective_dir = ws.get("effective_dir") or ws.get("source_dir")
    cluster_compose = os.path.join(effective_dir, "docker-compose.yml")
    if not os.path.isfile(cluster_compose):
        cluster_compose = os.path.join(ws["source_dir"], "docker-compose.yml")

    mon_env_path = ws.get("monitoring_env_path") or os.path.join(effective_dir, "monitoring", ".env")
    mon_dir = os.path.dirname(mon_env_path)
    mon_compose = os.path.join(mon_dir, "docker-compose.yml")

    cluster_svcs = parse_compose_services(cluster_compose)
    if not cluster_svcs:
        cluster_svcs = [
            "kafka-92",
            "kafka-93",
            "kafka-94",
            "kafka-95",
            "kafka-ui",
            "proxy",
            "keycloak-db",
            "keycloak",
            "idp-watch",
        ]
    mon_svcs = parse_compose_services(mon_compose)
    if not mon_svcs:
        mon_svcs = [
            "prometheus",
            "grafana",
            "loki",
            "promtail",
            "alertmanager",
            "kafka-exporter",
            "node-exporter",
            "perses",
            "oauth2-proxy",
            "perses-sync",
        ]

    return {
        ws["projects"]["cluster"]: cluster_svcs,
        ws["projects"]["monitoring"]: mon_svcs,
    }


def validate_service_operation(
    ws: Dict[str, Any],
    project: str,
    service: str,
) -> Tuple[bool, str, str]:
    """
    Validate (project, service) against the effective Compose inventory.
    Returns (ok, handler_kind, detail_or_error).
    handler_kind is one of: 'cluster', 'identity', 'monitoring'.
    """
    proj = (project or "").strip()
    svc = (service or "").strip()
    if not proj or not svc:
        return False, "", "Both --project and --service are required for service operations."

    inventory = get_compose_inventory(ws)
    cluster_proj = ws["projects"]["cluster"]
    mon_proj = ws["projects"]["monitoring"]

    if proj not in inventory:
        return (
            False,
            "",
            f"Refused service operation: project {proj!r} does not belong to installation "
            f"{ws['installation_id']} (permitted projects: {cluster_proj}, {mon_proj}).",
        )

    allowed_services = inventory[proj]
    if svc not in allowed_services:
        return (
            False,
            "",
            f"Refused service operation: service {svc!r} is not in Compose project {proj!r} inventory "
            f"({', '.join(allowed_services)}).",
        )

    if proj == mon_proj:
        return True, "monitoring", mon_proj
    if svc in ("keycloak", "keycloak-db", "idp-watch"):
        return True, "identity", cluster_proj
    return True, "cluster", cluster_proj


def _cmd_service_validate(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    if not ws.get("effective_dir"):
        sys.stderr.write("ERROR: Package is not installed yet. Run 'krate install' first.\n")
        return 1
    ok, kind, detail = validate_service_operation(ws, args.project or "", args.service or "")
    if not ok:
        if args.json:
            sys.stdout.write(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "state": "failed",
                "error_code": "invalid_service_target",
                "error": detail,
            }, indent=2) + "\n")
        else:
            sys.stderr.write(f"ERROR: {detail}\n")
        return 1
    sys.stdout.write(f"{kind}\t{detail}\n")
    return 0


def plan_auth_transition(
    ws: Dict[str, Any],
    request: Dict[str, Any],
) -> Tuple[int, Dict[str, Any]]:
    """
    Validate and build the execution plan for `krate auth transition --stdin --json`.
    Explicitly rejects `master` mode and determines whether Grafana needs first-time
    `monitor realm` preparation (local.ini -> realm.ini) vs `monitor up` refresh.
    """
    effective_dir = ws.get("effective_dir")
    if not effective_dir:
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "uninstalled_package",
            "error": "Package is not installed yet. Run 'krate install' before transitioning authentication.",
        }

    raw_mode = str(request.get("mode") or "realm").strip().lower()
    if raw_mode == "master":
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "unsupported_mode",
            "error": "Master realm mode is not supported; use 'realm' (Krate Realm) or 'local' mode.",
            "effective_dir": effective_dir,
        }
    if raw_mode in ("krate", "sso", "oidc"):
        mode = "realm"
    elif raw_mode in ("realm", "local"):
        mode = raw_mode
    else:
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "unsupported_mode",
            "error": f"Unsupported auth transition mode {raw_mode!r}; supported modes are 'realm' and 'local'.",
            "effective_dir": effective_dir,
        }

    target = str(request.get("target") or "both").strip().lower()
    if target not in ("kafbat", "grafana", "perses", "both", "all"):
        return 1, {
            "schema_version": SCHEMA_VERSION,
            "state": "failed",
            "error_code": "invalid_target",
            "error": f"Unsupported auth transition target {target!r}; must be kafbat, grafana, perses, both, or all.",
            "effective_dir": effective_dir,
        }

    include_kafbat = target in ("kafbat", "all") or bool(request.get("include_kafbat", mode == "local" and target in ("both", "all")))
    include_grafana = target in ("grafana", "both", "all")
    include_perses = target in ("perses", "both", "all")

    env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)
    cur_env = parse_env_file(env_path if os.path.isfile(env_path) else env_tpl)
    cur_mon = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)

    cur_kafbat = cur_env.get("KAFKA_UI_AUTH_CONFIG", "local.yml").strip() or "local.yml"
    cur_grafana = cur_mon.get("GRAFANA_AUTH_CONFIG", "local.ini").strip() or "local.ini"
    cur_perses_mode = cur_mon.get("PERSES_AUTH_MODE", "local").strip() or "local"
    cur_perses_idp = cur_mon.get("PERSES_IDP", "").strip()

    desired_kafbat = "runtime.yml" if mode == "realm" else "local.yml"
    desired_grafana = "realm.ini" if mode == "realm" else "local.ini"
    desired_perses_mode = "native" if mode == "realm" else "local"
    desired_perses_idp = "krate" if mode == "realm" else ""

    # State-aware Grafana preparation: `monitor realm` runs ONLY when transitioning
    # from local.ini to realm.ini. When already in realm.ini, `monitor up` refreshes it.
    grafana_needs_realm_prep = bool(include_grafana and mode == "realm" and cur_grafana != "realm.ini")

    targets_plan: Dict[str, Any] = {}
    if include_kafbat:
        targets_plan["kafbat"] = {
            "current_config": cur_kafbat,
            "desired_config": desired_kafbat,
            "already_configured": cur_kafbat == desired_kafbat,
            "status": "planned",
        }
    if include_grafana:
        targets_plan["grafana"] = {
            "current_config": cur_grafana,
            "desired_config": desired_grafana,
            "needs_realm_prep": grafana_needs_realm_prep,
            "already_configured": cur_grafana == desired_grafana,
            "status": "planned",
        }
    if include_perses:
        targets_plan["perses"] = {
            "current_mode": cur_perses_mode,
            "current_idp": cur_perses_idp,
            "desired_mode": desired_perses_mode,
            "desired_idp": desired_perses_idp,
            "already_configured": (cur_perses_mode == desired_perses_mode and cur_perses_idp == desired_perses_idp),
            "status": "planned",
        }

    return 0, {
        "schema_version": SCHEMA_VERSION,
        "state": "planned",
        "effective_dir": effective_dir,
        "installation_id": ws["installation_id"],
        "target": target,
        "mode": mode,
        "include_kafbat": include_kafbat,
        "include_grafana": include_grafana,
        "include_perses": include_perses,
        "grafana_needs_realm_prep": grafana_needs_realm_prep,
        "targets": targets_plan,
    }


def _cmd_auth_transition_helper(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    effective_dir = ws.get("effective_dir")
    env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)

    if args.action == "plan":
        try:
            req = json.loads(sys.stdin.read() or "{}")
        except ValueError as e:
            sys.stdout.write(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "state": "failed",
                "error_code": "invalid_json",
                "error": f"Invalid JSON input on stdin: {e}",
            }, indent=2) + "\n")
            return 1
        rc, plan = plan_auth_transition(ws, req)
        sys.stdout.write(json.dumps(plan, indent=2) + "\n")
        return rc

    if args.action == "persist-target":
        if not effective_dir:
            return 1
        t_name = args.target_app or ""
        t_mode = args.mode or "local"
        if t_name == "kafbat":
            val = "runtime.yml" if t_mode == "realm" else "local.yml"
            write_env_updates(env_path, env_tpl, {"KAFKA_UI_AUTH_CONFIG": val})
        elif t_name == "grafana":
            val = "realm.ini" if t_mode == "realm" else "local.ini"
            write_env_updates(mon_env_path, mon_tpl, {"GRAFANA_AUTH_CONFIG": val})
        elif t_name == "perses":
            if t_mode == "realm":
                write_env_updates(mon_env_path, mon_tpl, {"PERSES_AUTH_MODE": "native", "PERSES_IDP": "krate"})
            else:
                write_env_updates(mon_env_path, mon_tpl, {"PERSES_AUTH_MODE": "local", "PERSES_IDP": ""})
        return 0

    if args.action == "finalize":
        if not effective_dir:
            return 1
        try:
            outcome = json.loads(sys.stdin.read() or "{}")
        except ValueError:
            outcome = {}
        cur_env = parse_env_file(env_path if os.path.isfile(env_path) else env_tpl)
        cur_mon = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)
        overall_state = outcome.get("state", "succeeded")
        if overall_state == "succeeded":
            _save_applied_state(effective_dir, {
                "schema_version": SCHEMA_VERSION,
                "applied_env": cur_env,
                "applied_monitoring_env": cur_mon,
                "pending_services": [],
            })
            rec_file = os.path.join(effective_dir, "auth", ".operation-recovery", "current.json")
            if os.path.isfile(rec_file):
                try:
                    os.unlink(rec_file)
                except OSError:
                    pass
        else:
            rec_dir = _ensure_private_recovery_dir(effective_dir)
            rec_file = os.path.join(rec_dir, "current.json")
            _atomic_write_json(rec_file, {
                "schema_version": SCHEMA_VERSION,
                "op_id": f"auth-{os.getpid()}-{uuid.uuid4().hex[:8]}",
                "operation": "auth_transition",
                "state": "recovery_required",
                "recovery_required": True,
                "step": outcome.get("failed_step", "auth_transition"),
                "started_at": _utc_now_iso(),
                "error": outcome.get("error"),
                "targets": outcome.get("targets", {}),
            }, mode=0o600)

        outcome["schema_version"] = SCHEMA_VERSION
        outcome["effective_dir"] = effective_dir
        outcome["installation_id"] = ws["installation_id"]
        outcome["config_revision"] = compute_config_revision(effective_dir, env_path, mon_env_path)
        sys.stdout.write(json.dumps(outcome, indent=2) + "\n")
        return 0 if overall_state == "succeeded" else 1

    return 1


def parse_alerts_yml(alerts_path: Optional[str]) -> List[Dict[str, str]]:
    """
    Parse configured Prometheus alert rules from monitoring/prometheus/alerts.yml
    using pure Python stdlib without external YAML libraries.
    """
    if not alerts_path or not os.path.isfile(alerts_path):
        return []
    rules: List[Dict[str, str]] = []
    cur_group = "krate"
    cur_rule: Optional[dict] = None
    in_annotations = False

    try:
        with open(alerts_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m_grp = re.match(r"^\s*-\s*name:\s*([A-Za-z0-9_-]+)\s*$", line)
                if m_grp:
                    if cur_rule and cur_rule.get("name"):
                        rules.append(cur_rule)
                        cur_rule = None
                    cur_group = m_grp.group(1)
                    in_annotations = False
                    continue

                m_alert = re.match(r"^\s*-\s*alert:\s*([A-Za-z0-9_]+)\s*$", line)
                if m_alert:
                    if cur_rule and cur_rule.get("name"):
                        rules.append(cur_rule)
                    cur_rule = {
                        "name": m_alert.group(1),
                        "group": cur_group,
                        "severity": "warning",
                        "summary": "",
                        "description": "",
                    }
                    in_annotations = False
                    continue

                if cur_rule is None:
                    continue

                m_sev = re.search(r"severity:\s*([A-Za-z0-9_-]+)", stripped)
                if m_sev and stripped.startswith("labels:"):
                    cur_rule["severity"] = m_sev.group(1).lower()
                    continue

                if stripped == "annotations:":
                    in_annotations = True
                    continue

                if in_annotations:
                    if stripped.startswith("summary:"):
                        val = stripped[len("summary:"):].strip().strip('"').strip("'")
                        cur_rule["summary"] = val
                    elif stripped.startswith("description:"):
                        val = stripped[len("description:"):].strip().strip('"').strip("'")
                        cur_rule["description"] = val

        if cur_rule and cur_rule.get("name"):
            rules.append(cur_rule)
    except OSError:
        return []
    return rules


def resolve_alerts_yml_path(ws: Dict[str, Any]) -> Optional[str]:
    effective_dir = ws.get("effective_dir") or ws.get("source_dir")
    mon_env_path = ws.get("monitoring_env_path") or os.path.join(effective_dir, "monitoring", ".env")
    mon_dir = os.path.dirname(mon_env_path)
    candidates = [
        os.path.join(mon_dir, "prometheus", "alerts.yml"),
        os.path.join(ws["source_dir"], "monitoring", "prometheus", "alerts.yml"),
        os.path.join(os.path.dirname(ws["source_dir"]), "monitoring", "prometheus", "alerts.yml"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def evaluate_alerts(
    ws: Dict[str, Any],
    monitoring_state: str = "down",
    mon_env: Optional[dict] = None,
    prom_url_override: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build authoritative alert rule inventory from monitoring/prometheus/alerts.yml
    and merge live evaluation state from Prometheus `/api/v1/rules?type=alert`.
    Unavailable or unevaluated rules always report `unknown`, never `ok`.
    """
    alerts_path = resolve_alerts_yml_path(ws)
    inventory = parse_alerts_yml(alerts_path)

    rules_map: Dict[str, Dict[str, Any]] = {}
    for item in inventory:
        rname = item["name"]
        rules_map[rname] = {
            "name": rname,
            "group": item.get("group", "krate"),
            "severity": item.get("severity", "warning"),
            "summary": item.get("summary", ""),
            "description": item.get("description", ""),
            "state": "unknown",
            "label": "Unknown",
        }

    if monitoring_state != "up" and not prom_url_override:
        return {
            "evaluated": False,
            "status": "unknown",
            "summary": "Unknown (Monitoring Inactive)",
            "rules": rules_map,
            "rule_list": list(rules_map.values()),
        }

    if mon_env is None:
        _, _, mon_env_path, mon_tpl = _resolve_target_paths(ws)
        mon_env = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)

    prom_bind = (mon_env.get("PROM_BIND") or "127.0.0.1").strip()
    if prom_bind in ("0.0.0.0", ""):
        prom_bind = "127.0.0.1"
    prom_port = (mon_env.get("PROM_PORT") or "9090").strip() or "9090"
    url = prom_url_override or os.environ.get("KRATE_PROMETHEUS_RULES_URL") or f"http://{prom_bind}:{prom_port}/api/v1/rules?type=alert"

    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if payload.get("status") != "success":
            return {
                "evaluated": False,
                "status": "unknown",
                "summary": "Unknown",
                "rules": rules_map,
                "rule_list": list(rules_map.values()),
            }
        groups = payload.get("data", {}).get("groups", [])
        firing_count = 0
        pending_count = 0
        evaluated_any = False

        for grp in groups:
            grp_name = grp.get("name", "krate")
            for rule in grp.get("rules", []):
                rname = rule.get("name", "")
                if not rname:
                    continue
                rstate = (rule.get("state") or "inactive").lower()
                health = (rule.get("health") or "").lower()
                if health not in ("ok", "good") and not rule.get("lastEvaluation"):
                    continue
                evaluated_any = True
                alerts_list = rule.get("alerts") or []
                annotations = rule.get("annotations") or {}
                labels = rule.get("labels") or {}
                entry = rules_map.get(rname) or {
                    "name": rname,
                    "group": grp_name,
                    "severity": str(labels.get("severity") or "warning").lower(),
                    "summary": str(annotations.get("summary") or ""),
                    "description": str(annotations.get("description") or ""),
                }
                if rstate == "firing":
                    firing_count += 1
                    entry["state"] = "firing"
                    entry["label"] = f"Firing ({len(alerts_list)} active)" if alerts_list else "Firing"
                elif rstate == "pending":
                    pending_count += 1
                    entry["state"] = "pending"
                    entry["label"] = "Pending"
                else:
                    entry["state"] = "ok"
                    entry["label"] = "OK (Clear)"
                rules_map[rname] = entry

        if not evaluated_any:
            return {
                "evaluated": False,
                "status": "unknown",
                "summary": "Unknown (Awaiting Evaluation)",
                "rules": rules_map,
                "rule_list": list(rules_map.values()),
            }
        if firing_count > 0:
            summary = f"{firing_count} Alert(s) Firing"
            overall = "firing"
        elif pending_count > 0:
            summary = f"{pending_count} Alert(s) Pending"
            overall = "pending"
        else:
            summary = "All Alerts Clear"
            overall = "ok"
        return {
            "evaluated": True,
            "status": overall,
            "summary": summary,
            "rules": rules_map,
            "rule_list": list(rules_map.values()),
        }
    except Exception:
        return {
            "evaluated": False,
            "status": "unknown",
            "summary": "Unknown",
            "rules": rules_map,
            "rule_list": list(rules_map.values()),
        }


def map_user_role(
    user_groups: List[str],
    admin_group: str = "KRATE_ADMINS",
    viewer_group: str = "KRATE_VIEWERS",
) -> Tuple[bool, str]:
    """
    Map a user's group list strictly from the configured KEYCLOAK_ADMIN_GROUP
    and KEYCLOAK_VIEWER_GROUP without invented alias fallbacks.
    """
    clean_groups = [str(g).strip().lstrip("/") for g in (user_groups or []) if str(g).strip()]
    cfg_admin = (admin_group or "KRATE_ADMINS").strip().lstrip("/")
    cfg_viewer = (viewer_group or "KRATE_VIEWERS").strip().lstrip("/")

    if cfg_admin and cfg_admin in clean_groups:
        return True, "admin"
    if cfg_viewer and cfg_viewer in clean_groups:
        return False, "viewer"
    return False, "none"


def build_portal_urls(env: Dict[str, str], mon_env: Dict[str, str]) -> Dict[str, str]:
    kc_pub = (env.get("KEYCLOAK_PUBLIC_URL") or "").strip()
    https_port = (env.get("HTTPS_PORT") or env.get("KAFKA_UI_HTTPS_PORT") or "443").strip() or "443"
    port_suffix = "" if https_port == "443" else f":{https_port}"
    base_origin = f"https://localhost{port_suffix}"
    if kc_pub.startswith("https://") or kc_pub.startswith("http://"):
        m = re.match(r"^(https?://[^/]+)", kc_pub)
        if m:
            base_origin = m.group(1)

    graf_cfg = (mon_env.get("GRAFANA_AUTH_CONFIG") or "local.ini").strip()
    graf_port = (mon_env.get("GRAFANA_PORT") or "3000").strip() or "3000"
    if graf_cfg == "realm.ini":
        grafana_url = f"{base_origin}/grafana/"
    else:
        grafana_url = f"http://localhost:{graf_port}/"

    perses_port = (mon_env.get("PERSES_PORT") or "3443").strip() or "3443"
    perses_url = f"https://localhost:{perses_port}/"
    loki_url = f"{grafana_url.rstrip('/')}/explore"

    return {
        "kafbat_url": f"{base_origin}/",
        "grafana_url": grafana_url,
        "perses_url": perses_url,
        "loki_url": loki_url,
    }


def collect_observations(ws: Dict[str, Any], monitoring_state: str = "down") -> Dict[str, Any]:
    env_path, env_tpl, mon_env_path, mon_tpl = _resolve_target_paths(ws)
    cur_env = parse_env_file(env_path if os.path.isfile(env_path) else env_tpl)
    cur_mon = parse_env_file(mon_env_path if os.path.isfile(mon_env_path) else mon_tpl)

    admin_group = (
        cur_env.get("KEYCLOAK_ADMIN_GROUP")
        or cur_mon.get("KEYCLOAK_ADMIN_GROUP")
        or "KRATE_ADMINS"
    ).strip()
    viewer_group = (
        cur_env.get("KEYCLOAK_VIEWER_GROUP")
        or cur_mon.get("KEYCLOAK_VIEWER_GROUP")
        or "KRATE_VIEWERS"
    ).strip()

    return {
        "schema_version": SCHEMA_VERSION,
        "installation_id": ws["installation_id"],
        "effective_dir": ws["effective_dir"],
        "edition": ws["edition"],
        "runtime_kind": ws["runtime_kind"],
        "config_revision": ws["config_revision"],
        "portals": build_portal_urls(cur_env, cur_mon),
        "inventory": get_compose_inventory(ws),
        "role_mapping": {
            "admin_group": admin_group,
            "viewer_group": viewer_group,
        },
        "alerts": evaluate_alerts(ws, monitoring_state=monitoring_state, mon_env=cur_mon),
    }


def _detect_candidate_id(ws: Dict[str, Any], repo_dir: str) -> str:
    search_dir = repo_dir or ws.get("source_dir") or ""
    if search_dir and os.path.isdir(search_dir):
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=search_dir,
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    lock_path = os.path.join(ws.get("source_dir") or "", "images.lock.tsv")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "rb") as f:
                return "bundle-" + hashlib.sha256(f.read()).hexdigest()[:16]
        except OSError:
            pass
    return f"release-{ws.get('edition', 'kraft')}"


def _default_verification_checks() -> List[Dict[str, Any]]:
    return [
        {
            "id": "SYNTAX",
            "legacy_id": "GATE-1",
            "category": "engineering_static",
            "scope": "CLI & Helper Syntax",
            "tool": "bash -n & py_compile",
            "status": "not_run",
            "detail": "Not run yet",
        },
        {
            "id": "PARITY",
            "legacy_id": "GATE-1",
            "category": "engineering_static",
            "scope": "KRaft/EPC CLI Parity & ZK Frozen",
            "tool": "scripts/check-identity.py:check_parity",
            "status": "not_run",
            "detail": "Not run yet",
        },
        {
            "id": "BUNDLE_LOCK",
            "legacy_id": "GATE-2",
            "category": "package_integrity",
            "scope": "Offline Image Lock & Archive SHA256",
            "tool": "scripts/check-bundle.py",
            "status": "not_run",
            "detail": "Not run yet",
        },
        {
            "id": "COMPOSE",
            "legacy_id": "GATE-3",
            "category": "engineering_static",
            "scope": "Compose Configuration & Digest Pins",
            "tool": "docker compose config",
            "status": "not_run",
            "detail": "Not run yet",
        },
        {
            "id": "OFFLINE",
            "legacy_id": "GATE-4",
            "category": "engineering_static",
            "scope": "Air-Gapped Offline Policy",
            "tool": "scripts/check-offline.py",
            "status": "not_run",
            "detail": "Not run yet",
        },
        {
            "id": "PREFLIGHT",
            "legacy_id": "GATE-5",
            "category": "host_preflight",
            "scope": "Host Doctor Preflight",
            "tool": "krate doctor",
            "status": "not_run",
            "detail": "Not run yet",
        },
        {
            "id": "FORMAL_IDENTITY_GATE",
            "legacy_id": "GATE-FORMAL",
            "category": "formal_acceptance",
            "scope": "Formal Identity Gate Receipt",
            "tool": "scripts/gate-identity.sh",
            "status": "not_run",
            "detail": "No candidate-bound formal receipt imported",
        },
    ]


def _verify_ledger_path(ws: Dict[str, Any]) -> str:
    base = ws.get("effective_dir") or ws.get("source_dir")
    return os.path.join(base, "auth", ".verify-ledger.json")


def _build_current_binding(ws: Dict[str, Any], repo_dir: str = "") -> Dict[str, Any]:
    return {
        "installation_id": ws["installation_id"],
        "effective_dir": ws.get("effective_dir"),
        "source_dir": ws.get("source_dir"),
        "edition": ws["edition"],
        "candidate": _detect_candidate_id(ws, repo_dir),
        "config_revision": ws.get("config_revision"),
        "observed_at": _utc_now_iso(),
    }


def _bindings_match(stored: Dict[str, Any], live: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    if stored.get("installation_id") != live.get("installation_id") or stored.get("effective_dir") != live.get("effective_dir"):
        return False, "workspace_changed"
    if stored.get("edition") != live.get("edition"):
        return False, "edition_changed"
    if stored.get("candidate") != live.get("candidate"):
        return False, "candidate_changed"
    if stored.get("config_revision") != live.get("config_revision"):
        return False, "config_revision_changed"
    return True, None


def read_verification_state(ws: Dict[str, Any], repo_dir: str = "") -> Dict[str, Any]:
    """
    Read input-bound verification results for `ws`.
    Automatically demotes stale results into `history` if workspace, edition,
    candidate, or `config_revision` changed since the run was recorded.
    """
    live_binding = _build_current_binding(ws, repo_dir)
    ledger_path = _verify_ledger_path(ws)
    ledger = _read_json_file(ledger_path) or {}
    history: List[Dict[str, Any]] = list(ledger.get("history") or [])
    current = ledger.get("current")

    if isinstance(current, dict) and isinstance(current.get("binding"), dict):
        matched, reason = _bindings_match(current["binding"], live_binding)
        if matched:
            checks = current.get("checks") or _default_verification_checks()
            return _format_verify_payload(current["binding"], checks, history)
        demoted = dict(current)
        demoted["invalidated_at"] = _utc_now_iso()
        demoted["invalidated_reason"] = reason
        history.insert(0, demoted)
        history = history[:20]
        try:
            _atomic_write_json(ledger_path, {
                "schema_version": SCHEMA_VERSION,
                "current": None,
                "history": history,
            }, mode=0o600)
        except OSError:
            pass

    return _format_verify_payload(live_binding, _default_verification_checks(), history)


def _format_verify_payload(
    binding: Dict[str, Any],
    checks: List[Dict[str, Any]],
    history: List[Dict[str, Any]],
) -> Dict[str, Any]:
    passed = sum(1 for c in checks if c.get("status") == "passed")
    failed = sum(1 for c in checks if c.get("status") == "failed")
    not_run = sum(1 for c in checks if c.get("status") not in ("passed", "failed"))
    if failed > 0:
        overall = "failed"
    elif passed == len(checks) and len(checks) > 0:
        overall = "passed"
    elif passed > 0:
        overall = "partial"
    else:
        overall = "not_run"

    return {
        "schema_version": SCHEMA_VERSION,
        "status": overall,
        "passed": passed,
        "failed": failed,
        "not_run": not_run,
        "binding": binding,
        "checks": checks,
        "gates": checks,
        "history": history,
    }


def run_verification(ws: Dict[str, Any], repo_dir: str = "") -> Dict[str, Any]:
    """
    Execute real checkout and package validators bound to (installation_id, edition,
    candidate, config_revision). Missing tools or non-applicable checks return
    `not_run`, never a fabricated `passed` fallback.
    """
    state_before = read_verification_state(ws, repo_dir)
    history = list(state_before.get("history") or [])
    binding = _build_current_binding(ws, repo_dir)

    source_dir = ws["source_dir"]
    effective_dir = ws.get("effective_dir") or source_dir
    resolved_repo = detect_repo_dir(source_dir, ws["edition"], repo_dir)
    checks: List[Dict[str, Any]] = []

    # 1. SYNTAX: bash -n & py_compile
    bash_bin = shutil.which("bash")
    krate_script = os.path.join(effective_dir, "krate")
    if not os.path.isfile(krate_script):
        krate_script = os.path.join(source_dir, "krate")
    if not bash_bin or not os.path.isfile(krate_script):
        checks.append({
            "id": "SYNTAX",
            "legacy_id": "GATE-1",
            "category": "engineering_static",
            "scope": "CLI & Helper Syntax",
            "tool": "bash -n & py_compile",
            "status": "not_run",
            "detail": "bash binary or krate CLI script unavailable",
        })
    else:
        sh_targets = [krate_script]
        sso_folder = os.path.join(effective_dir, "sso")
        if not os.path.isdir(sso_folder):
            sso_folder = os.path.join(resolved_repo or source_dir, "sso")
        for sh_name in ("activate.sh", "operations.sh"):
            p = os.path.join(sso_folder, sh_name)
            if os.path.isfile(p):
                sh_targets.append(p)
        r_sh = subprocess.run([bash_bin, "-n"] + sh_targets, capture_output=True, text=True, timeout=15)
        py_err: Optional[str] = None
        for py_candidate in (
            os.path.join(sso_folder, "operations.py"),
            os.path.join(sso_folder, "identity.py"),
            os.path.join(effective_dir, "ui", "krate_ui.py"),
        ):
            if os.path.isfile(py_candidate):
                try:
                    py_compile.compile(py_candidate, doraise=True)
                except Exception as exc:
                    py_err = str(exc)
                    break
        if r_sh.returncode == 0 and not py_err:
            checks.append({
                "id": "SYNTAX",
                "legacy_id": "GATE-1",
                "category": "engineering_static",
                "scope": "CLI & Helper Syntax",
                "tool": "bash -n & py_compile",
                "status": "passed",
                "detail": f"Verified {len(sh_targets)} shell scripts and Python helpers",
            })
        else:
            checks.append({
                "id": "SYNTAX",
                "legacy_id": "GATE-1",
                "category": "engineering_static",
                "scope": "CLI & Helper Syntax",
                "tool": "bash -n & py_compile",
                "status": "failed",
                "detail": (r_sh.stderr.strip() or py_err or "Syntax check failed")[:240],
            })

    # 2. PARITY: scripts/check-identity.py static identity & parity checks (checkout only)
    check_id_script = os.path.join(resolved_repo, "scripts", "check-identity.py") if resolved_repo else ""
    if resolved_repo and os.path.isfile(check_id_script):
        try:
            spec = importlib.util.spec_from_file_location("check_identity_mod", check_id_script)
            assert spec is not None and spec.loader is not None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            chk = mod.Checks()
            for fn_name in (
                "check_templates",
                "check_names",
                "check_compose",
                "check_monitors",
                "check_logrotate",
                "check_cli",
                "check_parity",
                "check_zk_frozen",
                "check_proxy_edge",
            ):
                fn = getattr(mod, fn_name, None)
                if callable(fn):
                    fn(chk)
            if not chk.errors:
                checks.append({
                    "id": "PARITY",
                    "legacy_id": "GATE-1",
                    "category": "engineering_static",
                    "scope": "KRaft/EPC CLI Parity & Static Identity Contracts",
                    "tool": "scripts/check-identity.py",
                    "status": "passed",
                    "detail": "check_parity, check_zk_frozen, and static identity/proxy contracts passed",
                })
            else:
                checks.append({
                    "id": "PARITY",
                    "legacy_id": "GATE-1",
                    "category": "engineering_static",
                    "scope": "KRaft/EPC CLI Parity & Static Identity Contracts",
                    "tool": "scripts/check-identity.py",
                    "status": "failed",
                    "detail": "; ".join(chk.errors)[:240],
                })
        except Exception as exc:
            checks.append({
                "id": "PARITY",
                "legacy_id": "GATE-1",
                "category": "engineering_static",
                "scope": "KRaft/EPC CLI Parity & Static Identity Contracts",
                "tool": "scripts/check-identity.py",
                "status": "failed",
                "detail": str(exc)[:240],
            })
    else:
        checks.append({
            "id": "PARITY",
            "legacy_id": "GATE-1",
            "category": "engineering_static",
            "scope": "KRaft/EPC CLI Parity & Static Identity Contracts",
            "tool": "scripts/check-identity.py",
            "status": "not_run",
            "detail": "Checkout parity validator not present in standalone package",
        })

    # 3. BUNDLE_LOCK: scripts/check-bundle.py (package with images.lock.tsv)
    bundle_root = next(
        (cand_dir for cand_dir in (source_dir, effective_dir) if cand_dir and os.path.isfile(os.path.join(cand_dir, "images.lock.tsv"))),
        None,
    )
    bundle_checker = next(
        (
            cand_checker
            for cand_checker in (
                os.path.join(resolved_repo, "scripts", "check-bundle.py") if resolved_repo else "",
                os.path.join(effective_dir, "sso", "check-bundle.py"),
                os.path.join(source_dir, "sso", "check-bundle.py"),
                os.path.join(source_dir, "scripts", "check-bundle.py"),
            )
            if cand_checker and os.path.isfile(cand_checker)
        ),
        "",
    )

    if not bundle_root:
        checks.append({
            "id": "BUNDLE_LOCK",
            "legacy_id": "GATE-2",
            "category": "package_integrity",
            "scope": "Offline Image Lock & Archive SHA256",
            "tool": "scripts/check-bundle.py",
            "status": "not_run",
            "detail": "Source checkout (not an offline bundle; no images.lock.tsv)",
        })
    elif not bundle_checker:
        checks.append({
            "id": "BUNDLE_LOCK",
            "legacy_id": "GATE-2",
            "category": "package_integrity",
            "scope": "Offline Image Lock & Archive SHA256",
            "tool": "scripts/check-bundle.py",
            "status": "not_run",
            "detail": "check-bundle.py validator unavailable",
        })
    else:
        r_bun = subprocess.run(
            [sys.executable, "-B", bundle_checker, bundle_root],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if r_bun.returncode == 0:
            checks.append({
                "id": "BUNDLE_LOCK",
                "legacy_id": "GATE-2",
                "category": "package_integrity",
                "scope": "Offline Image Lock & Archive SHA256",
                "tool": "scripts/check-bundle.py",
                "status": "passed",
                "detail": (r_bun.stdout.strip() or "Offline lock, image references, and archive SHA256 verified")[:240],
            })
        else:
            checks.append({
                "id": "BUNDLE_LOCK",
                "legacy_id": "GATE-2",
                "category": "package_integrity",
                "scope": "Offline Image Lock & Archive SHA256",
                "tool": "scripts/check-bundle.py",
                "status": "failed",
                "detail": (r_bun.stderr.strip() or r_bun.stdout.strip() or "Bundle lock check failed")[:240],
            })

    # 4. COMPOSE: template digest pins + docker compose config
    env_path, env_tpl, _, mon_tpl = _resolve_target_paths(ws)
    digest_errors: List[str] = []
    if not bundle_root:
        for tpl_file in (env_tpl, mon_tpl):
            if os.path.isfile(tpl_file):
                tpl_map = parse_env_file(tpl_file)
                for k, v in tpl_map.items():
                    if IMAGE_PIN_PATTERN.match(k):
                        if not re.search(r"@sha256:[0-9a-f]{64}$", v):
                            digest_errors.append(f"{os.path.basename(tpl_file)}:{k} not @sha256-pinned")
    compose_file = os.path.join(effective_dir, "docker-compose.yml")
    if not os.path.isfile(compose_file):
        compose_file = os.path.join(source_dir, "docker-compose.yml")
    env_for_compose = env_path if (env_path and os.path.isfile(env_path)) else env_tpl
    docker_bin = shutil.which("docker")
    if digest_errors:
        checks.append({
            "id": "COMPOSE",
            "legacy_id": "GATE-3",
            "category": "engineering_static",
            "scope": "Compose Configuration & Digest Pins",
            "tool": "docker compose config",
            "status": "failed",
            "detail": "; ".join(digest_errors)[:240],
        })
    elif not docker_bin or not os.path.isfile(compose_file) or not os.path.isfile(env_for_compose):
        checks.append({
            "id": "COMPOSE",
            "legacy_id": "GATE-3",
            "category": "engineering_static",
            "scope": "Compose Configuration & Digest Pins",
            "tool": "docker compose config",
            "status": "not_run",
            "detail": "docker CLI or compose file unavailable",
        })
    else:
        r_comp = subprocess.run(
            [docker_bin, "compose", "--env-file", env_for_compose, "-f", compose_file, "--profile", "*", "config", "--quiet"],
            cwd=os.path.dirname(compose_file),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r_comp.returncode == 0:
            checks.append({
                "id": "COMPOSE",
                "legacy_id": "GATE-3",
                "category": "engineering_static",
                "scope": "Compose Configuration & Digest Pins",
                "tool": "docker compose config",
                "status": "passed",
                "detail": "docker compose config --quiet and image pin rules verified",
            })
        else:
            checks.append({
                "id": "COMPOSE",
                "legacy_id": "GATE-3",
                "category": "engineering_static",
                "scope": "Compose Configuration & Digest Pins",
                "tool": "docker compose config",
                "status": "failed",
                "detail": (r_comp.stderr.strip() or "Compose validation failed")[:240],
            })

    # 5. OFFLINE: scripts/check-offline.py (or packaged sso/check-offline.py; never fake pass if validator is missing)
    if resolved_repo and os.path.isfile(os.path.join(resolved_repo, "scripts", "check-offline.py")):
        offline_checker = os.path.join(resolved_repo, "scripts", "check-offline.py")
        offline_cwd = resolved_repo
    elif os.path.isfile(os.path.join(effective_dir, "scripts", "check-offline.py")):
        offline_checker = os.path.join(effective_dir, "scripts", "check-offline.py")
        offline_cwd = effective_dir
    elif os.path.isfile(os.path.join(effective_dir, "sso", "check-offline.py")):
        offline_checker = os.path.join(effective_dir, "sso", "check-offline.py")
        offline_cwd = effective_dir
    elif os.path.isfile(os.path.join(source_dir, "sso", "check-offline.py")):
        offline_checker = os.path.join(source_dir, "sso", "check-offline.py")
        offline_cwd = source_dir
    else:
        offline_checker = ""
        offline_cwd = ""

    if not offline_checker:
        checks.append({
            "id": "OFFLINE",
            "legacy_id": "GATE-4",
            "category": "engineering_static",
            "scope": "Air-Gapped Offline Policy",
            "tool": "scripts/check-offline.py",
            "status": "not_run",
            "detail": "check-offline.py repository validator unavailable in this directory",
        })
    else:
        r_off = subprocess.run(
            [sys.executable, "-B", offline_checker],
            cwd=offline_cwd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r_off.returncode == 0:
            checks.append({
                "id": "OFFLINE",
                "legacy_id": "GATE-4",
                "category": "engineering_static",
                "scope": "Air-Gapped Offline Policy",
                "tool": "scripts/check-offline.py",
                "status": "passed",
                "detail": (r_off.stdout.strip() or "Air-gapped offline policy verified")[:240],
            })
        else:
            checks.append({
                "id": "OFFLINE",
                "legacy_id": "GATE-4",
                "category": "engineering_static",
                "scope": "Air-Gapped Offline Policy",
                "tool": "scripts/check-offline.py",
                "status": "failed",
                "detail": (r_off.stderr.strip() or r_off.stdout.strip() or "Offline check failed")[:240],
            })

    # 6. PREFLIGHT: Host Doctor Preflight (distinct from formal identity acceptance)
    if not bash_bin or not os.path.isfile(krate_script):
        checks.append({
            "id": "PREFLIGHT",
            "legacy_id": "GATE-5",
            "category": "host_preflight",
            "scope": "Host Doctor Preflight",
            "tool": "krate doctor",
            "status": "not_run",
            "detail": "krate CLI binary unavailable",
        })
    else:
        r_doc = subprocess.run(
            [krate_script, "doctor"],
            cwd=effective_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r_doc.returncode == 0:
            checks.append({
                "id": "PREFLIGHT",
                "legacy_id": "GATE-5",
                "category": "host_preflight",
                "scope": "Host Doctor Preflight",
                "tool": "krate doctor",
                "status": "passed",
                "detail": "Host preflight doctor checks passed",
            })
        else:
            checks.append({
                "id": "PREFLIGHT",
                "legacy_id": "GATE-5",
                "category": "host_preflight",
                "scope": "Host Doctor Preflight",
                "tool": "krate doctor",
                "status": "failed",
                "detail": "Host preflight doctor reported issues (not a formal identity gate)",
            })

    # 7. FORMAL_IDENTITY_GATE: Distinct formal gate receipt check (never faked by doctor)
    receipt_file = os.path.join(effective_dir, "auth", ".formal-gate-receipt.json")
    receipt_data = _read_json_file(receipt_file)
    if (
        receipt_data
        and receipt_data.get("candidate") == binding["candidate"]
        and receipt_data.get("edition") == binding["edition"]
        and receipt_data.get("status") in ("passed", "failed")
    ):
        checks.append({
            "id": "FORMAL_IDENTITY_GATE",
            "legacy_id": "GATE-FORMAL",
            "category": "formal_acceptance",
            "scope": "Formal Identity Gate Receipt",
            "tool": "scripts/gate-identity.sh",
            "status": receipt_data["status"],
            "detail": str(receipt_data.get("detail") or f"Bound receipt for {binding['candidate'][:12]}"),
        })
    else:
        checks.append({
            "id": "FORMAL_IDENTITY_GATE",
            "legacy_id": "GATE-FORMAL",
            "category": "formal_acceptance",
            "scope": "Formal Identity Gate Receipt",
            "tool": "scripts/gate-identity.sh",
            "status": "not_run",
            "detail": "No candidate-bound formal receipt imported (run scripts/gate-identity.sh on a disposable target)",
        })

    ledger_path = _verify_ledger_path(ws)
    try:
        _atomic_write_json(ledger_path, {
            "schema_version": SCHEMA_VERSION,
            "current": {
                "binding": binding,
                "checks": checks,
            },
            "history": history[:20],
        }, mode=0o600)
    except OSError:
        pass

    return _format_verify_payload(binding, checks, history)


def _cmd_observe(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    payload = collect_observations(ws, monitoring_state=args.monitoring_state or "down")
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    ws = _resolve_ws_from_args(args)
    resolved_repo = detect_repo_dir(ws["source_dir"], ws["edition"], args.repo_dir)
    if args.status_only:
        payload = read_verification_state(ws, repo_dir=resolved_repo)
    else:
        payload = run_verification(ws, repo_dir=resolved_repo)

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(
            f"Verification ({payload['binding']['installation_id']} @ {str(payload['binding']['candidate'])[:12]}): "
            f"{payload['status']}\n"
        )
        for chk in payload.get("checks", []):
            sys.stdout.write(f"  [{chk['status'].upper():7s}] {chk['id']} ({chk['category']}): {chk['detail']}\n")
    return 0 if payload.get("failed", 0) == 0 else 1


def _add_common_ws_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--source-dir", required=True, help="Directory containing the invoked krate script")
    p.add_argument("--install-dir", default=None, help="Configured KRATE_HOME installation directory")
    p.add_argument("--edition", default=None, help="Edition name (kraft or epc)")
    p.add_argument("--repo-dir", default=None, help="Repository root if running from checkout")
    p.add_argument("--is-package", default=None, help="Whether krate detected an extracted package (true/false)")
    p.add_argument("--json", action="store_true", help="Emit JSON output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Krate CLI operational boundary helper")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_ws = sub.add_parser("workspace-resolve", help="Resolve authoritative workspace context")
    _add_common_ws_args(p_ws)

    p_show = sub.add_parser("config-show", help="Emit structured configuration and draft/recovery state")
    _add_common_ws_args(p_show)

    p_plan = sub.add_parser("config-plan", help="Validate and classify configuration changes from stdin")
    _add_common_ws_args(p_plan)
    p_plan.add_argument("--identity-state", default="pristine", help="Current identity_state value")

    p_stage = sub.add_parser("config-stage-apply", help="Validate and stage private recovery state before apply")
    _add_common_ws_args(p_stage)
    p_stage.add_argument("--identity-state", default="pristine", help="Current identity_state value")

    p_exec = sub.add_parser("config-exec-helper", help="Internal step execution helper for config apply and recover")
    _add_common_ws_args(p_exec)
    p_exec.add_argument("--action", required=True, choices=("list-work", "stage-rotation-input", "write-files", "step", "finalize"))
    p_exec.add_argument("--key", default=None)
    p_exec.add_argument("--out-file", default=None)
    p_exec.add_argument("--step", default=None)
    p_exec.add_argument("--status", default="succeeded")
    p_exec.add_argument("--error", default=None)

    p_draft = sub.add_parser("config-draft", help="Save or discard staged configuration draft")
    _add_common_ws_args(p_draft)
    p_draft.add_argument("--identity-state", default="pristine", help="Current identity_state value")

    p_set = sub.add_parser("config-set", help="Validate and save a single KEY=VALUE in save-only mode")
    _add_common_ws_args(p_set)
    p_set.add_argument("--identity-state", default="pristine", help="Current identity_state value")

    p_clear = sub.add_parser("config-clear-pending", help="Mark pending services as reconciled")
    _add_common_ws_args(p_clear)
    p_clear.add_argument("--scope", default="all", choices=("all", "cluster", "monitoring"))

    p_svc = sub.add_parser("service-validate", help="Validate (project, service) against Compose inventory")
    _add_common_ws_args(p_svc)
    p_svc.add_argument("--project", required=True)
    p_svc.add_argument("--service", required=True)

    p_auth = sub.add_parser("auth-transition-helper", help="Internal helper for krate auth transition")
    _add_common_ws_args(p_auth)
    p_auth.add_argument("--action", required=True, choices=("plan", "persist-target", "finalize"))
    p_auth.add_argument("--target-app", default=None)
    p_auth.add_argument("--mode", default=None)

    p_obs = sub.add_parser("observe", help="Emit authoritative observations (portals, inventory, roles, alerts)")
    _add_common_ws_args(p_obs)
    p_obs.add_argument("--monitoring-state", default="down", choices=("up", "down", "partial", "unknown"))

    p_ver = sub.add_parser("verify", help="Run or inspect input-bound verification checks")
    _add_common_ws_args(p_ver)
    p_ver.add_argument("--status-only", action="store_true", help="Read current bound verification state without executing checks")

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "workspace-resolve":
        return _cmd_workspace_resolve(args)
    if args.subcommand == "config-show":
        return _cmd_config_show(args)
    if args.subcommand == "config-plan":
        return _cmd_config_plan(args)
    if args.subcommand == "config-stage-apply":
        return _cmd_config_stage_apply(args)
    if args.subcommand == "config-exec-helper":
        return _cmd_config_exec_helper(args)
    if args.subcommand == "config-draft":
        return _cmd_config_draft(args)
    if args.subcommand == "config-set":
        return _cmd_config_set(args)
    if args.subcommand == "config-clear-pending":
        return _cmd_config_clear_pending(args)
    if args.subcommand == "service-validate":
        return _cmd_service_validate(args)
    if args.subcommand == "auth-transition-helper":
        return _cmd_auth_transition_helper(args)
    if args.subcommand == "observe":
        return _cmd_observe(args)
    if args.subcommand == "verify":
        return _cmd_verify(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
