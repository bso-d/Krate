#!/usr/bin/env python3
"""Offline integration test. Uses only cached images and isolated test volumes.

Requires Docker and Python 3; no Python packages. Cleans up only resources it
creates. Set KEEP_TEST_STACK=1 to preserve a failed stack for diagnosis.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=None, data=None):
    result = subprocess.run(args, cwd=cwd, input=data, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
    if result.returncode:
        raise RuntimeError(f'{args}:\n{result.stdout}\n{result.stderr}')
    return result.stdout


def eventually(label, fn, seconds=180):
    deadline = time.monotonic() + seconds
    error = None
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                print('PASS:', label, flush=True)
                return value
        except Exception as exc:
            error = exc
        time.sleep(3)
    raise AssertionError(f'{label} timed out: {error}')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class SMTP(socketserver.StreamRequestHandler):
    messages = []

    def handle(self):
        self.wfile.write(b'220 localhost test SMTP\r\n')
        while line := self.rfile.readline():
            verb = line.split()[0].upper()
            if verb == b'DATA':
                self.wfile.write(b'354 End with dot\r\n')
                lines = []
                while (line := self.rfile.readline()) and line != b'.\r\n':
                    lines.append(line)
                self.messages.append(b''.join(lines).decode(errors='replace'))
                self.wfile.write(b'250 accepted\r\n')
            elif verb == b'QUIT':
                self.wfile.write(b'221 bye\r\n')
                return
            else:
                self.wfile.write(b'250 OK\r\n')


def main():
    work = Path(tempfile.mkdtemp(prefix='krate-phase2-'))
    identity = 'test-' + work.name.rsplit('-', 1)[-1]
    cluster = work / 'kraft'
    monitoring = work / 'monitoring'
    shutil.copytree(ROOT / 'kraft', cluster, ignore=shutil.ignore_patterns('.env', 'certs', 'images'))
    shutil.copytree(ROOT / 'monitoring', monitoring, ignore=shutil.ignore_patterns('.env', '__pycache__'))
    cli = cluster / 'krate'
    cli.write_text(cli.read_text().replace('KRATE_VARIANT="kraft"', f'KRATE_VARIANT="{identity}"'))
    (cluster / '.env').write_text((cluster / '.env.template').read_text().replace(
        'KAFKA_UI_FQDN=', 'KAFKA_UI_FQDN=krate-test.local'))
    config = json.loads(run('docker', 'compose', '--env-file', str(cluster / '.env'),
                            '-f', str(cluster / 'docker-compose.yml'), 'config', '--format', 'json'))
    config['name'] = 'krate-' + identity
    for values in config.get('volumes', {}).values():
        values.pop('name', None)
    for values in config.get('networks', {}).values():
        values.pop('name', None)
    for svc, values in config['services'].items():
        values['container_name'] = 'krate-' + identity + '-' + svc
        values['pull_policy'] = 'never'
        values.pop('ports', None)
    (cluster / 'docker-compose.yml').write_text(json.dumps(config))

    ports = {key: free_port() for key in ['GRAFANA_PORT', 'PROM_PORT', 'LOKI_PORT']}
    env = (monitoring / '.env.template').read_text()
    for key, value in ports.items():
        import re
        env = re.sub(r'^' + key + r'=.*$', f'{key}={value}', env, flags=re.M)
    (monitoring / '.env').write_text(env)
    smtp = socketserver.ThreadingTCPServer(('0.0.0.0', 0), SMTP)
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
    # Resolve the template to JSON before adding test-only SMTP and pull policy.
    mon = json.loads(run('docker', 'compose', '--env-file', str(monitoring / '.env'),
                        '-f', str(monitoring / 'docker-compose.yml'), 'config', '--format', 'json'))
    # Keep discovery variables unresolved so the actual CLI supplies them.
    mon['name'] = '${MONITOR_PROJECT}'
    mon['networks']['kafka-network']['name'] = '${KAFKA_NETWORK}'
    for svc, values in mon['services'].items():
        values['container_name'] = '${MONITOR_PROJECT}-' + svc
        values['pull_policy'] = 'never'
        # Compose's resolved network/volume names must follow this test project.
    for values in mon['networks'].values():
        if not values.get('external'):
            values.pop('name', None)
    for values in mon['volumes'].values():
        values.pop('name', None)
    mon['services']['kafka-exporter']['command'] = '--web.listen-address=:9308 ${KAFKA_EXPORTER_TARGETS}'
    grafana = mon['services']['grafana']
    grafana['extra_hosts'] = ['host.docker.internal:host-gateway']
    grafana['environment'].update({'GF_SMTP_ENABLED': 'true',
        'GF_SMTP_HOST': f'host.docker.internal:{smtp.server_address[1]}',
        'GF_SMTP_STARTTLS_POLICY': 'NoStartTLS', 'GF_UNIFIED_ALERTING_MIN_INTERVAL': '10s'})
    (monitoring / 'docker-compose.yml').write_text(json.dumps(mon))
    # Force a real high-lag rule to fire quickly in this disposable fixture.
    rules = monitoring / 'prometheus/alerts.yml'
    rules.write_text(rules.read_text().replace('> 1000', '> 10').replace('for: 5m', 'for: 0s'))
    auth = base64.b64encode(b'admin:changeme').decode()

    def request(port, path, body=None, method=None):
        req = Request(f'http://127.0.0.1:{port}' + path,
                      data=None if body is None else json.dumps(body).encode(), method=method,
                      headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json',
                               'X-Disable-Provenance': 'true'})
        with urlopen(req, timeout=10) as response:
            return json.load(response)

    def prom(query):
        return request(ports['PROM_PORT'], '/api/v1/query?' + urlencode({'query': query}))['data']['result']

    def kafka(script, *args, data=None):
        return run('docker', 'exec', '-i', 'krate-' + identity + '-kafka-92',
                   '/opt/kafka/bin/' + script, '--bootstrap-server', 'kafka-92:9092', *args, data=data)

    compose = ['docker', 'compose', '--env-file', str(cluster / '.env'), '-f', str(cluster / 'docker-compose.yml')]
    try:
        print('Test workspace:', work, flush=True)
        print(run(str(cli), 'start'), flush=True)
        run(str(cli), 'health', '--timeout', '120')
        print('PASS: four-broker cluster healthy', flush=True)
        kafka('kafka-topics.sh', '--create', '--topic', 'phase2-test', '--partitions', '1', '--replication-factor', '3')
        kafka('kafka-console-producer.sh', '--topic', 'phase2-test', data=''.join(f'message-{i}\n' for i in range(100)))
        consumed = kafka('kafka-console-consumer.sh', '--topic', 'phase2-test', '--group', 'phase2-test',
                         '--from-beginning', '--max-messages', '40', '--timeout-ms', '20000',
                         '--consumer-property', 'max.poll.records=1',
                         '--consumer-property', 'auto.commit.interval.ms=100')
        assert len(consumed.splitlines()) == 40
        # Deterministic committed offset: restart monitoring against a known lag.
        kafka('kafka-consumer-groups.sh', '--group', 'phase2-test', '--topic', 'phase2-test',
              '--reset-offsets', '--to-offset', '40', '--execute')
        print('PASS: produce 100, consume 40, commit offset 40', flush=True)
        print(run(str(cli), 'monitor', 'up'), flush=True)
        eventually('broker metric = 4', lambda: any(float(x['value'][1]) == 4 for x in prom('kafka_brokers')))
        eventually('consumer lag = 60', lambda: any(float(x['value'][1]) == 60 for x in prom('kafka_consumergroup_lag{consumergroup="phase2-test"}')))
        assert all(float(x['value'][1]) == 0 for x in prom('kafka_topic_partition_under_replicated_partition'))
        eventually('all three scrape targets up', lambda: len([x for x in request(ports['PROM_PORT'], '/api/v1/targets')['data']['activeTargets'] if x['health'] == 'up']) == 3)
        dashboards = request(ports['GRAFANA_PORT'], '/api/search?type=dash-db')
        assert len(dashboards) == 3
        alert_rules = request(ports['GRAFANA_PORT'], '/api/v1/provisioning/alert-rules')
        assert len(alert_rules) == 14 and all(not r.get('provenance') for r in alert_rules)
        print('PASS: three dashboards and 14 editable notification rules', flush=True)
        eventually('Krate logs queryable in Loki', lambda: request(ports['LOKI_PORT'], '/loki/api/v1/query_range?' + urlencode({'query': '{job="containerlogs"}', 'limit': 1}))['data']['result'])
        eventually('real high-lag alert firing in Prometheus', lambda: prom('ALERTS{alertname="ConsumerGroupHighLag",alertstate="firing"}'))
        eventually('alert email received by local SMTP sink', lambda: any('ConsumerGroupHighLag' in m for m in SMTP.messages))
        # Operator changes survive a second initialization.
        target = next(r for r in alert_rules if r['title'] == 'ConsumerGroupHighLag')
        target['isPaused'] = True
        request(ports['GRAFANA_PORT'], '/api/v1/provisioning/alert-rules/' + target['uid'], target, 'PUT')
        run('python3', str(monitoring / 'seed-alerting.py'), str(monitoring / '.env'))
        assert request(ports['GRAFANA_PORT'], '/api/v1/provisioning/alert-rules/' + target['uid'])['isPaused']
        print('PASS: operator edits survive reinitialization', flush=True)
        run(*compose, 'down')
        run(str(cli), 'monitor', 'status')
        run(str(cli), 'monitor', 'down')
        print('PASS: monitoring status/down work after cluster removal', flush=True)
    finally:
        smtp.shutdown()
        smtp.server_close()
        if not os.environ.get('KEEP_TEST_STACK'):
            # Explicit project names and fixture files restrict cleanup to this test.
            subprocess.run(['docker', 'compose', '-p', f'krate-{identity}-monitoring',
                '--env-file', str(monitoring / '.env'), '-f', str(monitoring / 'docker-compose.yml'),
                'down', '-v'], env={**os.environ, 'MONITOR_PROJECT': f'krate-{identity}-monitoring',
                                   'KAFKA_NETWORK': 'krate-unused-network'}, check=False)
            subprocess.run([*compose, 'down', '-v'], check=False)
            shutil.rmtree(work)


if __name__ == '__main__':
    main()
