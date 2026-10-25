#!/usr/bin/env python3
import sys; sys.dont_write_bytecode = True
"""
Authoritative Krate CLI operational boundary helper.
Pure Python 3.9+ standard library implementation.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
from typing import Any, Dict, List, Optional


SCHEMA_VERSION = 1


def parse_env_file(path: Optional[str]) -> Dict[str, str]:
    """Parse a .env file as pure data without shell evaluation."""
    if not path or not os.path.isfile(path):
        return {}
    entries: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].strip()
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
                    val = val[1:-1]
                if key:
                    entries[key] = val
    except OSError:
        return {}
    return entries


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
        raw_key = secrets.token_bytes(32)
        tmp_path = os.path.join(auth_dir, f".revision.key.{os.getpid()}.{secrets.token_hex(4)}.tmp")
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


def _read_json_file(path: str) -> Optional[Dict[str, Any]]:
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
    recovery_summary: Optional[Dict[str, Any]] = None

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


def _cmd_workspace_resolve(args: argparse.Namespace) -> int:
    is_pkg: Optional[bool] = None
    if args.is_package in ("true", "1", "yes"):
        is_pkg = True
    elif args.is_package in ("false", "0", "no"):
        is_pkg = False

    payload = resolve_workspace(
        source_dir=args.source_dir,
        install_dir=args.install_dir,
        edition=args.edition,
        repo_dir=args.repo_dir,
        is_package_flag=is_pkg,
    )
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Krate CLI operational boundary helper")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_ws = sub.add_parser("workspace-resolve", help="Resolve authoritative workspace context")
    p_ws.add_argument("--source-dir", required=True, help="Directory containing the invoked krate script")
    p_ws.add_argument("--install-dir", default=None, help="Configured KRATE_HOME installation directory")
    p_ws.add_argument("--edition", default=None, help="Edition name (kraft or epc)")
    p_ws.add_argument("--repo-dir", default=None, help="Repository root if running from checkout")
    p_ws.add_argument("--is-package", default=None, help="Whether krate detected an extracted package (true/false)")
    p_ws.add_argument("--json", action="store_true", help="Emit JSON output")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "workspace-resolve":
        return _cmd_workspace_resolve(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
