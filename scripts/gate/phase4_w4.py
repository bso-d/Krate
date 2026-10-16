#!/usr/bin/env python3
"""Phase 4c W4 live reachability census.

The census probes every running Compose service in the cluster and
monitoring projects, on the union of its image-declared TCP ports and the
exact listener ports named for it in Table 2 of monitoring/README.md, from
five sources: host processes as root and uid 65534 (Linux only), a probe
container on each of the monitoring, perses and kafka-network Docker
networks, and the Grafana container itself.  Container probes use
`nc -z` rather than the plan's originally assumed Grafana `wget`: live
spot checks showed wget returns failure for reachable TCP listeners
(HTTP 403/404 and non-HTTP Kafka), while nc classifies the TCP connect
itself.  Any reachable pair not allowed by Table 2, any exact Table 2
pair for a running service that is not reachable, and any inconclusive
probe fails the row.

Output is one `RESULT W4 PASS|FAIL|NOT_RUN ...` line; detail lines precede
it for the runner log.  Exit codes: 0 PASS, 1 FAIL, 2 NOT_RUN.
Python 3.9 compatible.
"""
import argparse
import fnmatch
import json
import os
import platform
import socket
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Sequence, Set, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python3 -I does not add the script directory
import phase2_kafbat as p2  # noqa: E402
from phase4_w3 import BLOCKED_ERRNOS  # noqa: E402

SOURCES = ('host', 'monitoring', 'perses', 'kafka-network', 'grafana')
PROBE_LABEL = 'krate.gate=w4-probe'
TableRow = Tuple[str, str, str]
ServicePort = Tuple[str, int]
CensusPair = Tuple[str, str, int]


def parse_table2(text: str) -> List[TableRow]:
    """Rows of Table 2 as (source, target, port) strings."""
    marker = '## Table 2'
    if marker not in text:
        return []
    part = text.split(marker, 1)[1].split('\n## ', 1)[0]
    rows = []
    for line in part.splitlines():
        stripped = line.strip()
        if not stripped.startswith('|'):
            continue
        cells = [cell.strip().strip('`') for cell in stripped.strip('|').split('|')]
        if len(cells) >= 3 and cells[0] and cells[0] != 'source' and set(cells[0]) != {'-'}:
            rows.append((cells[0], cells[1], cells[2]))
    return rows


def target_ports(service: str, exposed: Iterable[int], rows: Sequence[TableRow]) -> List[int]:
    """Image-declared TCP ports plus exact Table 2 listener ports."""
    ports = {int(port) for port in exposed or ()}
    for _source, target, port in rows or ():
        if ':' not in target and fnmatch.fnmatchcase(service, target) and str(port).isdigit():
            ports.add(int(port))
    return sorted(ports)


def is_allowed(rows: Sequence[TableRow], source: str, service: str, port: int) -> bool:
    return any(row_source == source and ':' not in target
               and fnmatch.fnmatchcase(service, target)
               and (expected == '*' or expected == str(port))
               for row_source, target, expected in rows or ())


def compare_census(rows: Sequence[TableRow], targets: Dict[str, Sequence[int]],
                   observed: Dict[str, Set[ServicePort]]) -> Tuple[bool, List[CensusPair], List[CensusPair]]:
    """Return (ok, unlisted, exact-listed-unreachable).

    Wildcard Table 2 ports are allow-list entries only: they do not claim
    that every image-declared port is listening.  Exact ports for running
    services are claims and must be reachable from the named source.
    """
    observed = observed or {}
    unlisted = []
    for source in SOURCES:
        for service, port in sorted(observed.get(source) or ()):
            if not is_allowed(rows, source, service, port):
                unlisted.append((source, service, port))
    unreachable = []
    for source, target, port in rows or ():
        if source not in SOURCES or ':' in target or not str(port).isdigit():
            continue
        for service in sorted(targets or {}):
            if fnmatch.fnmatchcase(service, target) \
                    and (service, int(port)) not in (observed.get(source) or set()):
                unreachable.append((source, service, int(port)))
    return not unlisted and not unreachable, unlisted, unreachable


KNOWN_TABLE_SOURCES = set(SOURCES) | {'grafana-admin-datasource', 'anonymous-https'}


def validate_table_rows(rows: Sequence[TableRow]) -> List[str]:
    """Malformed Table 2 rows are evidence errors, never silent skips."""
    errors = []
    for source, target, port in rows or ():
        if source not in KNOWN_TABLE_SOURCES:
            errors.append('unknown Table 2 source %r' % source)
        if not target:
            errors.append('empty Table 2 target for source %r' % source)
        if port != '*' and not str(port).isdigit():
            errors.append('invalid Table 2 port %r for %s -> %s' % (port, source, target))
    return errors


def filter_unreachable_for_platform(unreachable: List[CensusPair], system: str) -> List[CensusPair]:
    if system == 'Darwin':
        return [item for item in unreachable if item[0] != 'host']
    return list(unreachable)


def classify_nc(rc):
    if rc == 0:
        return 'reachable'
    if rc == 1:
        return 'unreachable'
    return 'unknown'


def docker_json(*args):
    rc, out, err = p2.docker(*args, timeout=60)
    if rc != 0:
        raise RuntimeError('docker %s failed rc=%s: %s' % (args[0], rc, (err or out).strip()[:200:]))
    return json.loads(out)


def inventory(cluster_project, monitor_project, rows):
    """Every running container in both Compose projects.

    Service-labelled containers key by Compose service.  A container with
    no service label keys as `@container:<name>` and is probed by container
    name, so it is a census target rather than a silent skip.
    """
    targets = {}
    labelless = []
    for project in (cluster_project, monitor_project):
        rc, out, err = p2.docker('ps', '-q', '--filter',
                                 'label=com.docker.compose.project=' + project, timeout=60)
        if rc != 0:
            raise RuntimeError('cannot enumerate Compose project %s: %s'
                               % (project, (err or out).strip()[:200:]))
        ids = out.split()
        if not ids:
            raise RuntimeError('no running containers in Compose project ' + project)
        for cid in ids:
            doc = docker_json('inspect', cid)[0]
            labels = doc.get('Config', {}).get('Labels') or {}
            service_label = labels.get('com.docker.compose.service')
            name = (doc.get('Name') or '').lstrip('/')
            service = service_label or '@container:' + (name or cid[:12])
            if not service_label:
                labelless.append(name or cid[:12])
            if service in targets:
                raise RuntimeError('duplicate running container for target ' + service)
            exposed = []
            for value in (doc.get('Config', {}).get('ExposedPorts') or {}):
                if value.endswith('/tcp'):
                    port = value[:-4]
                    if not port.isdigit():
                        raise RuntimeError('invalid exposed TCP port %s on %s' % (value, service))
                    exposed.append(int(port))
            networks = doc.get('NetworkSettings', {}).get('Networks') or {}
            ips = sorted({addr for net in networks.values()
                          for addr in (net.get('IPAddress'), net.get('GlobalIPv6Address')) if addr})
            targets[service] = {
                'container': name,
                'probe_name': service_label or name or cid,
                'ports': target_ports(service, exposed, rows),
                'ips': ips,
                'networks': sorted(networks),
            }
    if not targets:
        raise RuntimeError('no running containers in either Compose project')
    return targets, labelless


def _socket_result(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=3):
            return 'reachable', 'connected'
    except OSError as error:
        if error.errno in BLOCKED_ERRNOS or isinstance(error, TimeoutError):
            return 'unreachable', type(error).__name__
        return 'unknown', '%s: %s' % (type(error).__name__, error)


_NOBODY_CODE = (
    'import errno,socket,sys\n'
    'blocked={errno.ECONNREFUSED,errno.ETIMEDOUT,errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EACCES,errno.EPERM}\n'
    'try:\n'
    ' socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close()\n'
    ' print("connected")\n'
    'except OSError as e:\n'
    ' print(type(e).__name__)\n'
    ' sys.exit(1 if e.errno in blocked or isinstance(e, TimeoutError) else 2)\n'
)


def _classify_host_worker(rc, detail):
    detail = (detail or '').strip()
    if rc == 0:
        return 'reachable', detail
    if rc == 1 and detail and not detail.startswith('sudo:'):
        return 'unreachable', detail
    return 'unknown', 'rc=%s %s' % (rc, detail[:160:])


def _drop_to_nobody():
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


def _host_probe_as(ip, port, uid):
    """One host TCP probe as root (uid 0) or nobody (uid 65534)."""
    if uid == os.geteuid():
        return _socket_result(ip, port)
    if os.geteuid() == 0 and uid == 65534:
        proc = subprocess.run(
            [sys.executable, '-I', '-c', _NOBODY_CODE, ip, str(port)],
            text=True, capture_output=True, timeout=8,
            preexec_fn=_drop_to_nobody)
    else:
        user = 'root' if uid == 0 else 'nobody'
        proc = subprocess.run(
            ['sudo', '-n', '-u', user, sys.executable, '-I', '-c', _NOBODY_CODE, ip, str(port)],
            text=True, capture_output=True, timeout=8)
    return _classify_host_worker(proc.returncode, proc.stdout + proc.stderr)


class NotRun(RuntimeError):
    pass


def _host_capability():
    if os.geteuid() == 0:
        return
    proc = subprocess.run(['sudo', '-n', 'true'], text=True, capture_output=True, timeout=10)
    if proc.returncode != 0:
        raise NotRun('Linux host census needs root or passwordless sudo for uid 0/65534 probes')


def _host_census(targets, observed, unknowns, counter):
    by_uid = {}
    for label, uid in (('root', 0), ('nobody', 65534)):
        reached = set()
        for service in sorted(targets):
            item = targets[service]
            for port in item['ports']:
                if not item['ips']:
                    unknowns.append(('host-' + label, service, port, 'no container IP'))
                    continue
                results = []
                for ip in item['ips']:
                    counter[0] += 1
                    try:
                        results.append(_host_probe_as(ip, port, uid))
                    except (OSError, subprocess.SubprocessError) as error:
                        results.append(('unknown', '%s: %s' % (type(error).__name__, error)))
                if any(kind == 'reachable' for kind, _detail in results):
                    reached.add((service, port))
                elif any(kind == 'unknown' for kind, _detail in results):
                    unknowns.append(('host-' + label, service, port, results))
        by_uid[label] = reached
        print('host-%s reachable=%s' % (label, sorted(reached)))
        if any(item['ports'] and item['ips'] for item in targets.values()) and not reached:
            unknowns.append(('host-' + label, 'positive control', '',
                             'no known listener was reachable as uid %d' % uid))
    difference = by_uid['root'] ^ by_uid['nobody']
    if difference:
        unknowns.append(('host', 'uid-difference', '', sorted(difference)))
    observed['host'] = by_uid['root'] | by_uid['nobody']


def _sweep_stale_probes():
    rc, out, err = p2.docker('ps', '-aq', '--filter', 'label=' + PROBE_LABEL, timeout=30)
    if rc != 0:
        raise RuntimeError('cannot list stale W4 probes: %s' % (err or out).strip()[:160:])
    for cid in out.split():
        rc, _out, err = p2.docker('rm', '-f', cid, timeout=30)
        if rc != 0:
            raise RuntimeError('cannot remove stale W4 probe %s: %s' % (cid[:12], err.strip()[:120:]))


def _start_probe(source, network, image):
    rc, _out, err = p2.docker('network', 'inspect', network, timeout=30)
    if rc != 0:
        raise RuntimeError('Docker network %s is not inspectable: %s' % (network, err.strip()[:160:]))
    name = 'krate-gate-w4-%s-%s-%s' % (source.replace('-', ''), os.getpid(), int(time.time()))
    rc, out, err = p2.docker('run', '-d', '--rm', '--pull', 'never', '--name', name,
                             '--label', PROBE_LABEL, '--cap-drop', 'ALL', '--read-only',
                             '--network', network,
                             '--entrypoint', 'sleep', image, '3600', timeout=60)
    if rc != 0:
        raise RuntimeError('cannot start W4 probe on %s: %s' % (network, (err or out).strip()[:200:]))
    rc, out, _err = p2.docker('inspect', '-f', '{{.State.Running}}', name, timeout=30)
    if rc != 0 or out.strip() != 'true':
        p2.docker('rm', '-f', name, timeout=30)
        raise RuntimeError('W4 probe %s did not stay running on %s' % (name, network))
    return name


def _container_probe(container, service, port):
    rc, out, err = p2.docker('exec', container, 'nc', '-w', '3', '-z', service, str(port),
                             stdin='', timeout=8)
    return classify_nc(rc), (out + err).strip()[:160:]


def _kafka_network(targets, cluster_project):
    candidates = sorted({network for item in targets.values()
                         for network in item['networks'] if network.endswith('_kafka-network')})
    if len(candidates) > 1:
        raise RuntimeError('ambiguous kafka-network candidates: %s' % candidates)
    return candidates[0] if candidates else cluster_project + '_kafka-network'


def census(args):
    with open(args.readme, encoding='utf-8') as handle:
        rows = parse_table2(handle.read())
    if not rows:
        raise RuntimeError('Table 2 not found or empty in ' + args.readme)
    table_errors = validate_table_rows(rows)
    if table_errors:
        raise RuntimeError('invalid Table 2 rows: %s' % table_errors[:5:])
    targets, labelless = inventory(args.cluster_project, args.monitor_project, rows)
    if 'grafana' not in targets:
        raise RuntimeError('Grafana container is not running; the grafana source cannot be probed')
    total_ports = sum(len(item['ports']) for item in targets.values())
    print('targets=%d service-ports=%d label-less-targets=%s' % (len(targets), total_ports, labelless))
    for service in sorted(targets):
        item = targets[service]
        print('TARGET %s container=%s ports=%s ips=%s networks=%s'
              % (service, item['container'], item['ports'], item['ips'], item['networks']))

    observed = {source: set() for source in SOURCES}
    unknowns = []
    counter = [0]
    system = platform.system()
    host_note = 'host=root+nobody'
    if system == 'Linux':
        _host_capability()
        _host_census(targets, observed, unknowns, counter)
    elif system == 'Darwin':
        host_note = 'host=not-run-darwin-vm-only'
        print('host source not run on Darwin: the host-process residual is VM-only in the plan')
    else:
        raise NotRun('unsupported platform for W4 host census: ' + system)

    image = args.nginx_image or os.environ.get('W4_NGINX_IMAGE') or ''
    if not image:
        raise RuntimeError('W4 probe image is empty (pass --nginx-image or W4_NGINX_IMAGE)')
    rc, _out, err = p2.docker('image', 'inspect', image, timeout=30)
    if rc != 0:
        raise RuntimeError('W4 probe image is not present locally (--pull never): %s' % err.strip()[:160:])

    networks = {
        'monitoring': args.monitor_project + '_monitoring',
        'perses': args.monitor_project + '_perses',
        'kafka-network': _kafka_network(targets, args.cluster_project),
    }
    _sweep_stale_probes()
    probes = {}
    cleanup_errors = []
    try:
        for source in ('monitoring', 'perses', 'kafka-network'):
            probes[source] = _start_probe(source, networks[source], image)
        sources = list(probes.items())
        sources.append(('grafana', targets['grafana']['container']))
        for source, container in sources:
            for service in sorted(targets):
                if source == 'grafana' and service == 'grafana':
                    continue  # same container, not a peer reachability pair
                for port in targets[service]['ports']:
                    counter[0] += 1
                    kind, detail = _container_probe(container, targets[service]['probe_name'], port)
                    if kind == 'reachable':
                        observed[source].add((service, port))
                    elif kind == 'unknown':
                        unknowns.append((source, service, port, detail))
            print('%s via %s reachable=%s' % (source, container, sorted(observed[source])))
    finally:
        for name in probes.values():
            rc, _out, err = p2.docker('rm', '-f', name, timeout=30)
            if rc != 0:
                cleanup_errors.append('%s: %s' % (name, err.strip()[:120:]))
    if cleanup_errors:
        unknowns.append(('cleanup', '', '', cleanup_errors))

    compare_targets = {service: item['ports'] for service, item in targets.items()}
    exact_ok, unlisted, unreachable = compare_census(rows, compare_targets, observed)
    unreachable = filter_unreachable_for_platform(unreachable, system)
    exact_ok = not unlisted and not unreachable
    print('UNLISTED=%s' % unlisted)
    print('LISTED-EXACT-UNREACHABLE=%s' % unreachable)
    print('UNKNOWNS=%s' % unknowns)
    ok = exact_ok and not unknowns
    summary = ('targets=%d service-ports=%d probes=%d %s observed=%s '
               'unlisted=%d listed-unreachable=%d unknowns=%d label-less-targets=%d'
               % (len(targets), total_ports, counter[0], host_note,
                  {source: len(observed[source]) for source in SOURCES},
                  len(unlisted), len(unreachable), len(unknowns), len(labelless)))
    if unlisted:
        summary += ' first-unlisted=%s' % (unlisted[:3],)
    if unreachable:
        summary += ' first-listed-unreachable=%s' % (unreachable[:3],)
    if unknowns:
        summary += ' first-unknown=%s' % (unknowns[:2],)
    return (0 if ok else 1), summary


def main(argv=None):
    parser = argparse.ArgumentParser(description='Phase 4c W4 live reachability census')
    parser.add_argument('--readme', required=True)
    parser.add_argument('--cluster-project', required=True)
    parser.add_argument('--monitor-project', required=True)
    parser.add_argument('--nginx-image', default='')
    args = parser.parse_args(argv)
    try:
        rc, summary = census(args)
    except NotRun as error:
        print('RESULT W4 NOT_RUN %s' % error)
        return 2
    except Exception as error:
        print('RESULT W4 FAIL harness error %s: %s' % (type(error).__name__, str(error)[:300:]))
        return 1
    print('RESULT W4 %s %s' % ('PASS' if rc == 0 else 'FAIL', summary))
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
