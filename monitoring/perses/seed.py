#!/usr/bin/env python3
"""Seed the shipped Krate dashboards into Perses without overwriting UI edits.

Grafana provisions these dashboards with allowUiUpdates, so an operator's
edits stay until the shipped file changes. Perses provisioning overwrites
on every interval, so dashboards are seeded instead: a missing dashboard is
created, and an existing one is replaced only when its shipped file changed
since the last seed. Runs as the one-shot perses-seed service.

In local mode it first removes the access an earlier SSO mode left behind
(see purge_sso).
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
# Bindings the SSO access guard manages, and the guard's own service binding.
MANAGED_BINDINGS = ('krate-admin-', 'krate-viewer-')
SERVICE_BINDING = 'krate-sync'


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


def expect(status, allowed, what):
    if status not in allowed:
        raise RuntimeError('%s failed with HTTP %d' % (what, status))


def strip_users(perses, bindings, users, base):
    """Remove users from each binding; delete a binding left without subjects."""
    changed = 0
    for binding in bindings or []:
        subjects = binding.get('spec', {}).get('subjects') or []
        remaining = [s for s in subjects if not (s.get('kind') == 'User' and s.get('name') in users)]
        if len(remaining) == len(subjects):
            continue
        target = base + quote(binding['metadata']['name'], safe='')
        if remaining:
            binding['spec']['subjects'] = remaining
            expect(perses.request('PUT', target, binding)[0], (200,), 'updating ' + target)
        else:
            expect(perses.request('DELETE', target)[0], (200, 204, 404), 'deleting ' + target)
        changed += 1
    return changed


def purge_sso(perses):
    """Local mode: remove every grant and user an SSO mode created.

    Perses signs tokens with a key derived from its encryption key, which stays
    the same across modes, so an SSO user's token is still valid after a switch
    to local mode, where no gateway check runs. Such a token carries only the
    access granted by role bindings, so the managed bindings, the guard's
    service binding and the SSO users (and their place in any other binding,
    including project owner bindings) are removed.
    """
    status, users = perses.request('GET', '/api/v1/users')
    expect(status, (200,), 'listing users')
    sso = {u['metadata']['name'] for u in users or [] if (u.get('spec') or {}).get('oauthProviders')}
    status, bindings = perses.request('GET', '/api/v1/globalrolebindings')
    expect(status, (200,), 'listing global role bindings')
    removed, kept = 0, []
    for binding in bindings or []:
        name = binding['metadata']['name']
        if name.startswith(MANAGED_BINDINGS) or name == SERVICE_BINDING:
            target = '/api/v1/globalrolebindings/' + quote(name, safe='')
            expect(perses.request('DELETE', target)[0], (200, 204, 404), 'deleting ' + target)
            removed += 1
        else:
            kept.append(binding)
    stripped = strip_users(perses, kept, sso, '/api/v1/globalrolebindings/')
    status, projects = perses.request('GET', '/api/v1/projects')
    expect(status, (200,), 'listing projects')
    for project in projects or []:
        base = '/api/v1/projects/%s/rolebindings' % quote(project['metadata']['name'], safe='')
        status, project_bindings = perses.request('GET', base)
        expect(status, (200,), 'listing ' + base)
        stripped += strip_users(perses, project_bindings, sso, base + '/')
    for user in sorted(sso):
        target = '/api/v1/users/' + quote(user, safe='')
        expect(perses.request('DELETE', target)[0], (200, 204, 404), 'deleting ' + target)
    print('perses-seed: local mode removed %d SSO bindings, %d SSO users and SSO users from %d other bindings'
          % (removed, len(sso), stripped))


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


def run(perses, mode, env, directory, ledger_path):
    wait_ready(perses)
    perses.login(mode, env)
    if mode == 'local':
        purge_sso(perses)
    seed(perses, directory, ledger_path)


def main():
    env = dict(os.environ)
    mode = env.get('PERSES_AUTH_MODE', 'local')
    try:
        run(Perses(), mode, env, '/etc/krate/perses/dashboards', Path('/var/lib/krate-perses-seed/seeded.json'))
    except (RuntimeError, KeyError, OSError, ValueError) as exc:
        print('perses-seed: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
