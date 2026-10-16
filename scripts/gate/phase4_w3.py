#!/usr/bin/env python3
"""Linux W3 TCP and Docker daemon configuration probes."""

import errno
import ipaddress
import json
import os
import pathlib
import socket
import sys


BLOCKED_ERRNOS = {
    errno.ECONNREFUSED,
    errno.ETIMEDOUT,
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.EACCES,
    errno.EPERM,
}


def tcp_probe(host: str, port: str) -> int:
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            print(f"TCP_CONNECTED {host}:{port}")
            return 0
    except OSError as exc:
        # socket.timeout is TimeoutError only from Python 3.10 on; the Rocky guests run 3.9.
        if exc.errno in BLOCKED_ERRNOS or isinstance(exc, (socket.timeout, TimeoutError)):
            print(f"TCP_BLOCKED {host}:{port} {type(exc).__name__}")
            return 1
        print(f"TCP_ERROR {host}:{port} {type(exc).__name__}: {exc}")
        return 2


def target_policy(host: str) -> int:
    """Reject IPv6 container targets until a global IPv6 probe path is proven."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        print(f"TARGET_INVALID {host}")
        return 2
    if address.version == 6:
        print(f"TARGET_IPV6_UNPROVEN {host}: namespace has no global IPv6 route/control")
        return 2
    print(f"TARGET_IPV4_READY {host}")
    return 0


def routing_state(args: list[str], cwd: pathlib.Path, default_path: pathlib.Path) -> tuple[bool, pathlib.Path]:
    """Return the configured direct-routing state; reject ambiguous inputs."""
    path = default_path
    explicit_path = False
    flag = None
    i = 1
    while i < len(args):
        arg = args[i]
        if arg == "--config-file":
            if explicit_path:
                raise ValueError("duplicate --config-file flags")
            i += 1
            if i >= len(args):
                raise ValueError("--config-file has no path")
            path = pathlib.Path(args[i])
            explicit_path = True
        elif arg.startswith("--config-file="):
            if explicit_path:
                raise ValueError("duplicate --config-file flags")
            path = pathlib.Path(arg.split("=", 1)[1])
            explicit_path = True
        elif arg == "--allow-direct-routing":
            if flag is not None:
                raise ValueError("duplicate --allow-direct-routing flags")
            flag = True
        elif arg.startswith("--allow-direct-routing="):
            if flag is not None:
                raise ValueError("duplicate --allow-direct-routing flags")
            value = arg.split("=", 1)[1].lower()
            if value not in ("true", "false"):
                raise ValueError("invalid --allow-direct-routing value")
            flag = value == "true"
        i += 1

    if not path.is_absolute():
        path = cwd / path
    if explicit_path and not path.exists():
        raise ValueError(f"explicit daemon config missing: {path}")
    config = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(config, dict):
        raise ValueError(f"daemon config is not an object: {path}")
    setting = config.get("allow-direct-routing", False)
    if not isinstance(setting, bool):
        raise ValueError(f"non-boolean allow-direct-routing in {path}")
    if flag is not None and "allow-direct-routing" in config:
        raise ValueError("direct-routing set in both daemon flag and config")
    return flag is True or setting is True, path


def daemon_config() -> int:
    pids = []
    try:
        for proc in pathlib.Path("/proc").iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                if (proc / "comm").read_text().strip() == "dockerd":
                    pids.append(proc)
            except (OSError, UnicodeError):
                continue
    except OSError as exc:
        print(f"CONFIG_UNKNOWN cannot list /proc: {exc}")
        return 2
    if len(pids) != 1:
        print(f"CONFIG_UNKNOWN expected one readable dockerd process, found {len(pids)}")
        return 2

    try:
        args = [os.fsdecode(arg) for arg in (pids[0] / "cmdline").read_bytes().split(b"\0") if arg]
        cwd = (pids[0] / "cwd").resolve(strict=True)
        enabled, path = routing_state(args, cwd, pathlib.Path("/etc/docker/daemon.json"))
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"CONFIG_UNKNOWN cannot determine effective dockerd option: {exc}")
        return 2
    if enabled:
        print(f"CONFIG_OPEN allow-direct-routing enabled (config {path})")
        return 1
    print(f"CONFIG_CLOSED allow-direct-routing disabled (config {path})")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "tcp":
        sys.exit(tcp_probe(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 3 and sys.argv[1] == "target-policy":
        sys.exit(target_policy(sys.argv[2]))
    if len(sys.argv) == 2 and sys.argv[1] == "daemon-config":
        sys.exit(daemon_config())
    print("usage: phase4_w3.py tcp HOST PORT | target-policy HOST | daemon-config", file=sys.stderr)
    sys.exit(2)
