#!/usr/bin/env python3
"""Seed editable Grafana notification rules without replacing operator changes.

Prometheus owns thresholds and pending periods. Grafana watches its firing
ALERTS series and owns delivery. No third-party Python packages are required.
"""
import base64
import json
from http.client import HTTPException
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def env_file(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip().strip('\"\'')
    return values


def seed(path):
    env = env_file(path)
    base = os.environ.get('GRAFANA_URL', 'http://127.0.0.1:' + env.get('GRAFANA_PORT', '3000'))
    token = base64.b64encode((env.get('GRAFANA_USER', 'admin') + ':' +
                             env.get('GRAFANA_PASSWORD', 'changeme')).encode()).decode()

    def api(method, endpoint, body=None):
        request = Request(base + endpoint, method=method,
                          data=None if body is None else json.dumps(body).encode(),
                          headers={'Authorization': 'Basic ' + token,
                                   'Content-Type': 'application/json',
                                   'X-Disable-Provenance': 'true'})
        with urlopen(request, timeout=10) as response:
            raw = response.read()
            return json.loads(raw) if raw else None

    for attempt in range(60):
        try:
            api('GET', '/api/health')
            break
        except (URLError, OSError, HTTPException):
            if attempt == 59:
                raise RuntimeError('Grafana did not become ready within 120 seconds') from None
            time.sleep(2)

    contacts = api('GET', '/api/v1/provisioning/contact-points')
    if not any(c['uid'] == 'krate-email-default' for c in contacts):
        api('POST', '/api/v1/provisioning/contact-points', {
            'uid': 'krate-email-default', 'name': 'krate-email', 'type': 'email',
            'settings': {'addresses': env.get('ALERT_EMAIL_TO', 'ops@example.com'),
                         'singleEmail': False}})
    try:
        api('GET', '/api/folders/krate-alerts')
    except HTTPError as error:
        if error.code != 404:
            raise
        api('POST', '/api/folders', {'uid': 'krate-alerts', 'title': 'Krate alerts'})

    existing = {r['uid'] for r in api('GET', '/api/v1/provisioning/alert-rules')}
    names = re.findall(r'^\s+- alert: (\w+)\s*$',
                       (Path(__file__).parent / 'prometheus/alerts.yml').read_text(), re.M)
    if not names:
        raise RuntimeError('No Prometheus alert names found')
    for name in names:
        uid = 'krate-' + name.lower()
        if uid in existing:
            continue
        # ALERTS is 1 for every firing instance. No series means normal. Drop
        # its alertname label: Grafana assigns that reserved label itself.
        expr = f'sum without (alertname, alertstate) (ALERTS{{alertname="{name}",alertstate="firing"}})'
        api('POST', '/api/v1/provisioning/alert-rules', {
            'uid': uid, 'title': name, 'folderUID': 'krate-alerts',
            'ruleGroup': 'Krate notifications', 'orgId': 1,
            'condition': 'B', 'for': '0s', 'noDataState': 'OK', 'execErrState': 'Error',
            'annotations': {'summary': name + ' — Prometheus reports a firing alert',
                            'description': 'Inspect Prometheus Alerts for the threshold and measured value.'},
            'labels': {'source': 'krate'},
            'notification_settings': {'receiver': 'krate-email', 'group_wait': '10s'},
            'data': [
                {'refId': 'A', 'relativeTimeRange': {'from': 600, 'to': 0},
                 'datasourceUid': 'prometheus',
                 'model': {'refId': 'A', 'expr': expr, 'instant': True, 'range': False,
                           'datasource': {'type': 'prometheus', 'uid': 'prometheus'}}},
                {'refId': 'B', 'relativeTimeRange': {'from': 0, 'to': 0},
                 'datasourceUid': '__expr__',
                 'model': {'refId': 'B', 'type': 'threshold', 'expression': 'A',
                           'conditions': [{'evaluator': {'type': 'gt', 'params': [0]},
                                           'operator': {'type': 'and'},
                                           'reducer': {'type': 'last', 'params': []}}]}}]})
    print(f'Grafana alerting ready: {len(names)} notification rules (existing settings preserved).')


if __name__ == '__main__':
    seed(sys.argv[1])
