#!/usr/bin/env python3
"""Seed the shipped Krate dashboards into Perses without overwriting UI edits.

Grafana provisions these dashboards with allowUiUpdates, so an operator's
edits stay until the shipped file changes. Perses provisioning overwrites
on every interval, so dashboards are seeded instead: a missing dashboard is
created, and an existing one is replaced only when its shipped file changed
since the last seed. Runs as the one-shot perses-seed service.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import quote, urlencode

PROJECT = 'krate'


class Perses:
    def __init__(self, host='perses', port=8080):
        self.host, self.port, self.token = host, port, None

    def request(self, method, path, body=None, headers=None, raw=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        sent = {'Accept': 'application/json', **(headers or {})}
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            sent['Content-Type'] = 'application/json'
        if self.token:
            sent['Authorization'] = 'Bearer ' + self.token
        try:
            connection.request(method, path, body=data, headers=sent)
            response = connection.getresponse()
            payload = response.read()
            return response.status, (json.loads(payload) if payload.strip() else None)
        finally:
            connection.close()

    def login(self, mode, env):
        if mode == 'gateway':
            return
        if mode == 'local':
            status, data = self.request('POST', '/api/auth/providers/native/login',
                                        {'login': env['PERSES_ADMIN_USER'], 'password': env['PERSES_ADMIN_PASSWORD']})
        else:
            # The access guard's service identity also seeds dashboards.
            client_id = json.loads(Path('/etc/krate/site/perses.json').read_text())['service_client_id']
            secret = env['PERSES_SYNC_CLIENT_SECRET']
            basic = base64.b64encode((client_id + ':' + secret).encode()).decode()
            status, data = self.request('POST', '/api/auth/providers/oidc/krate/token',
                                        headers={'Authorization': 'Basic ' + basic,
                                                 'Content-Type': 'application/x-www-form-urlencoded'},
                                        raw=urlencode({'grant_type': 'client_credentials'}).encode())
        if status != 200 or not data or not data.get('access_token'):
            raise RuntimeError('Perses login for seeding failed with HTTP %d' % status)
        self.token = data['access_token']


def wait_ready(perses, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            status, _ = perses.request('GET', '/api/v1/health')
            if status == 200:
                return
        except OSError:
            pass
        time.sleep(2)
    raise RuntimeError('Perses did not become ready')


def seed(perses, directory, ledger_path):
    ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else {}
    deadline = time.monotonic() + 120
    while perses.request('GET', '/api/v1/projects/' + PROJECT)[0] != 200:
        if time.monotonic() > deadline:
            raise RuntimeError('project %s was not provisioned' % PROJECT)
        time.sleep(2)
    created = updated = kept = 0
    for path in sorted(Path(directory).glob('*.json')):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        dashboard = json.loads(raw)
        name = dashboard['metadata']['name']
        target = '/api/v1/projects/%s/dashboards/%s' % (PROJECT, quote(name, safe=''))
        status, current = perses.request('GET', target)
        if status == 404:
            status, _ = perses.request('POST', '/api/v1/projects/%s/dashboards' % PROJECT, dashboard)
            created += 1
        elif status == 200 and ledger.get(name) != digest:
            dashboard['metadata']['version'] = current['metadata'].get('version', 0)
            status, _ = perses.request('PUT', target, dashboard)
            updated += 1
        elif status == 200:
            kept += 1
            continue
        if status not in (200, 201):
            raise RuntimeError('seeding %s failed with HTTP %d' % (name, status))
        ledger[name] = digest
        temporary = ledger_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(ledger, sort_keys=True))
        os.replace(temporary, ledger_path)
    print('perses-seed: %d created, %d updated from changed files, %d kept with any UI edits' % (created, updated, kept))


def main():
    env = dict(os.environ)
    mode = env.get('PERSES_AUTH_MODE', 'local')
    perses = Perses()
    try:
        wait_ready(perses)
        perses.login(mode, env)
        seed(perses, '/etc/krate/perses/dashboards', Path('/var/lib/krate-perses-seed/seeded.json'))
    except (RuntimeError, KeyError, OSError, ValueError) as exc:
        print('perses-seed: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
