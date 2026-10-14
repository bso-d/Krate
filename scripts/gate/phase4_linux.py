#!/usr/bin/env python3
"""Linux foreign-source Grafana host-port probe for Phase 4a U21b.

The namespace method was manually walked in harness/phase4/lab8/results.md and
again with IPv4/IPv6 positive and negative controls in
harness/phase4/formal-r1/u21b-live/ before this helper was written.
"""

import fcntl
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import time


HERE = pathlib.Path(__file__).resolve().parent
TCP_HELPER = HERE / "phase4_w3.py"
_RUN_ID = secrets.token_hex(4)
# Fresh names identify this invocation's resources even if another probe is
# running or a previous probe left its own namespace behind. Interface names
# remain below Linux's 15-character limit.
NS = "p4u21b-" + _RUN_ID
HOST_LINK = "p4u21h" + _RUN_ID
NET_LINK = "p4u21n" + _RUN_ID
HOST_IP = "10.99.78.1"
NET_IP = "10.99.78.2"


def _run(args, *, root=False, timeout=20):
    command = (["sudo", "-n"] if root and os.geteuid() != 0 else []) + list(args)
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, check=False)
        return result.returncode, (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 125, "%s: %s" % (type(exc).__name__, exc)


def _tcp(host, port, *, foreign=False):
    args = [sys.executable, "-I"]
    if foreign:
        args = ["ip", "netns", "exec", NS] + args
    rc, output = _run(args + [str(TCP_HELPER), "tcp", host, str(port)],
                      root=foreign, timeout=12)
    return rc, output.replace("\n", " ")


def _primary_ipv4():
    rc, routes = _run(["ip", "-4", "route", "show", "default"])
    if rc:
        raise RuntimeError("cannot read default IPv4 route: " + routes)
    match = re.search(r"(?:^|\s)dev\s+(\S+)", routes)
    if not match:
        raise RuntimeError("default IPv4 route has no interface")
    interface = match.group(1)
    rc, addresses = _run(["ip", "-4", "-o", "addr", "show", "dev", interface,
                          "scope", "global"])
    if rc:
        raise RuntimeError("cannot read primary IPv4 address: " + addresses)
    match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", addresses)
    if not match:
        raise RuntimeError("primary interface has no global IPv4 address")
    return interface, match.group(1)


def _host_link_exists():
    rc, links = _run(["ip", "-o", "link", "show"])
    if rc:
        raise RuntimeError("cannot inventory host links: " + links)
    for line in links.splitlines():
        match = re.match(r"\s*\d+:\s+([^:@]+)", line)
        if match and match.group(1) == HOST_LINK:
            return True
    return False


def _linklocal():
    for _ in range(20):
        addresses = []
        for side, command in (
                ("host", ["ip", "-6", "-o", "addr", "show", "dev", HOST_LINK,
                          "scope", "link"]),
                ("namespace", ["ip", "-n", NS, "-6", "-o", "addr", "show",
                               "dev", NET_LINK, "scope", "link"])):
            rc, output = _run(command, root=True)
            if rc:
                raise RuntimeError("cannot read %s veth IPv6 address: %s" % (side, output))
            ready = None
            for line in output.splitlines():
                if not any(flag in line.split() for flag in ("tentative", "dadfailed")):
                    match = re.search(r"\binet6\s+(fe80:[0-9a-f:]+)/", line)
                    if match:
                        ready = match.group(1)
                        break
            addresses.append(ready)
        if all(addresses):
            return addresses[0]
        time.sleep(0.5)
    raise RuntimeError("host or namespace veth has no ready IPv6 link-local address")


def u21b_probe(grafana_port, perses_port):
    """Serialize the fixed /30 probe subnet from precheck through cleanup."""
    if not sys.platform.startswith("linux"):
        return "NOT_RUN", "Linux netns probe requires Linux"
    lock_path = HERE.parents[1] / "harness" / "phase4" / "u21b" / "probe.lock"
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "a+", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return "FAIL", "another U21b probe owns the host subnet"
            return _u21b_probe_locked(grafana_port, perses_port)
    except OSError as exc:
        return "FAIL", "cannot lock U21b probe subnet: %s" % exc


def _u21b_probe_locked(grafana_port, perses_port):
    """Return (PASS|FAIL|NOT_RUN, evidence) after a foreign-source TCP walk.

    The positive controls on Perses' all-address host port prove both paths;
    any connection to the loopback-only Grafana port fails this row. The caller
    owns the U21a Docker bind and HTTP response checks separately.
    """
    if not shutil.which("ip"):
        return "NOT_RUN", "Linux netns probe needs iproute2"
    if not TCP_HELPER.is_file():
        return "FAIL", "missing tracked scripts/gate/phase4_w3.py"
    if os.geteuid() != 0:
        rc, _ = _run(["sudo", "-n", "true"])
        if rc:
            return "NOT_RUN", "Linux netns probe needs root or sudo -n"
    try:
        grafana_port, perses_port = int(grafana_port), int(perses_port)
        if not (1 <= grafana_port <= 65535 and 1 <= perses_port <= 65535):
            raise ValueError("port outside 1..65535")
        interface, primary_ip = _primary_ipv4()
        rc, namespaces = _run(["ip", "netns", "list"], root=True)
        if rc:
            raise RuntimeError("cannot list network namespaces: " + namespaces)
        if any(line.split()[0] == NS for line in namespaces.splitlines() if line.split()):
            raise RuntimeError("probe namespace already exists: " + NS)
        if _host_link_exists():
            raise RuntimeError("probe host link already exists: " + HOST_LINK)
        rc, routes = _run(["ip", "-4", "route", "show", "match", NET_IP])
        if rc or any(not line.startswith("default") for line in routes.splitlines()):
            raise RuntimeError("probe subnet overlaps a route or route check failed")
        rc, addresses = _run(["ip", "-4", "-o", "addr", "show"])
        if rc or " 10.99.78." in addresses:
            raise RuntimeError("probe subnet overlaps a local address or address check failed")
        rc, local = _tcp("127.0.0.1", grafana_port)
        if rc != 0:
            raise RuntimeError("Grafana loopback control not reachable: " + local)
    except (RuntimeError, ValueError) as exc:
        return "FAIL", str(exc)

    owned_ns = owned_link = zone_assigned = False
    zone = ""
    checks = []
    failure = ""
    cleanup_errors = []
    try:
        steps = (
            ["ip", "netns", "add", NS],
            ["ip", "link", "add", HOST_LINK, "type", "veth", "peer", "name", NET_LINK],
            ["ip", "link", "set", NET_LINK, "netns", NS],
            ["ip", "addr", "add", HOST_IP + "/30", "dev", HOST_LINK],
            ["ip", "link", "set", HOST_LINK, "up"],
            ["ip", "-n", NS, "addr", "add", NET_IP + "/30", "dev", NET_LINK],
            ["ip", "-n", NS, "link", "set", "lo", "up"],
            ["ip", "-n", NS, "link", "set", NET_LINK, "up"],
            ["ip", "-n", NS, "route", "add", "default", "via", HOST_IP],
        )
        for index, command in enumerate(steps):
            rc, output = _run(command, root=True)
            if rc:
                # A timed-out ip command can still have created the resource.
                # Both names were proved free above; adopt any partial creation
                # before leaving so finally can remove only this probe's state.
                if index == 0:
                    probe_rc, probe_out = _run(["ip", "netns", "list"], root=True)
                    owned_ns = (probe_rc == 0 and any(
                        line.split()[0] == NS for line in probe_out.splitlines() if line.split()))
                if index == 1:
                    owned_link = _host_link_exists()
                raise RuntimeError("namespace setup step %d failed: %s" % (index + 1, output))
            if index == 0:
                owned_ns = True
            if index == 1:
                owned_link = True

        rc, active = _run(["systemctl", "is-active", "-q", "firewalld"])
        if rc == 125:
            raise RuntimeError("cannot determine firewalld state: " + active)
        if rc == 0:
            rc, zone = _run(["firewall-cmd", "--get-zone-of-interface=" + interface], root=True)
            if rc or not zone:
                rc, zone = _run(["firewall-cmd", "--get-default-zone"], root=True)
            if rc or not zone:
                raise RuntimeError("cannot determine primary firewalld zone")
            zone_assigned = True  # Cleanup is required even after partial assignment.
            rc, output = _run(["firewall-cmd", "-q", "--zone=" + zone,
                               "--add-interface=" + HOST_LINK], root=True)
            if rc:
                raise RuntimeError("cannot mirror firewalld zone %s: %s" % (zone, output))

        linklocal = _linklocal()
        for label, host, port, expected in (
                ("ipv4_control", HOST_IP, perses_port, 0),
                ("ipv4_primary_control", primary_ip, perses_port, 0),
                ("ipv6_control", linklocal + "%" + NET_LINK, perses_port, 0),
                ("ipv4_veth", HOST_IP, grafana_port, 1),
                ("ipv4_primary", primary_ip, grafana_port, 1),
                ("ipv6_linklocal", linklocal + "%" + NET_LINK, grafana_port, 1)):
            rc, detail = _tcp(host, port, foreign=True)
            passed = (rc == expected if expected == 0 else
                      rc == 1 and "ConnectionRefusedError" in detail)
            checks.append("%s=%s(%s)" % (label, "PASS" if passed else "FAIL", detail))
        if any("=FAIL(" in check for check in checks):
            raise RuntimeError("one or more foreign-source TCP checks failed")
    except RuntimeError as exc:
        failure = str(exc)
    finally:
        # The names were free before this probe began. Recheck even when a
        # creation command failed and its immediate ownership check failed:
        # subprocess timeout/error can occur after the kernel created state.
        if not owned_ns:
            rc, output = _run(["ip", "netns", "list"], root=True)
            if rc:
                cleanup_errors.append("cannot determine namespace ownership after setup failure")
            else:
                owned_ns = any(line.split()[0] == NS for line in output.splitlines() if line.split())
        if not owned_link:
            try:
                owned_link = _host_link_exists()
            except RuntimeError as exc:
                cleanup_errors.append(str(exc))
        if zone_assigned:
            rc, output = _run(["firewall-cmd", "-q", "--zone=" + zone,
                               "--remove-interface=" + HOST_LINK], root=True)
            if rc:
                cleanup_errors.append("firewalld interface removal: " + output)
        if owned_ns:
            rc, output = _run(["ip", "netns", "del", NS], root=True)
            if rc:
                cleanup_errors.append("namespace removal: " + output)
        if owned_link:
            try:
                link_present = _host_link_exists()
            except RuntimeError as exc:
                cleanup_errors.append(str(exc))
            else:
                if link_present:
                    rc, output = _run(["ip", "link", "del", HOST_LINK], root=True)
                    if rc:
                        cleanup_errors.append("host link removal: " + output)
        rc, output = _run(["ip", "netns", "list"], root=True)
        if rc or any(line.split()[0] == NS for line in output.splitlines() if line.split()):
            cleanup_errors.append("namespace still exists or cannot be checked")
        try:
            if _host_link_exists():
                cleanup_errors.append("host link still exists")
        except RuntimeError as exc:
            cleanup_errors.append(str(exc))

    evidence = "; ".join(checks)
    if failure or cleanup_errors:
        return "FAIL", "; ".join(part for part in (evidence, failure,
                         "cleanup: " + ", ".join(cleanup_errors) if cleanup_errors else "") if part)
    return "PASS", evidence + "; cleanup: namespace and link removed"
