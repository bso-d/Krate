#!/usr/bin/env python3
"""Phase 4a acceptance gate: Grafana on the Krate realm.

Slice 4a of harness/phase4/PHASE4-INSTRUCTIONS-v3.md, section 2.1: rows U1-U29
of the Grafana slice. This file is the frame the runner drives:

    python3 -I scripts/gate/phase4_grafana.py run \
        --edition-dir ED --base-url https://H --monitor-project krate-<edition>-monitoring \
        --state DIR [--only U1,U2]

Output: one TSV line per row on stdout, `<id>\\tPASS|FAIL|NOT_RUN\\t<evidence>`,
plus a leading `setup` line for the slice preconditions of section 5; progress on
stderr. Exit codes of phase2_kafbat.py: 0 when no row FAILed, 1 otherwise, 2 on a
usage error.

Ownership: U1-U29 (including U21a/U21b and the session-max row U27) are this
helper's; X3 (screenshots-grafana.mjs) and Z4a (the extended leak scan) are the
runner's. U27 runs only in prepared `--session-max-hours N` companion runs (the
runner passes `--prepared --only U27 --session-max-minutes 60*N`); its bound is
read back from the live Keycloak realm and matched to running Grafana config.

ENCODING STATUS (owner rule 11: a row is encoded only from observations seen
working against the real stack; every encoded probe cites its walk log under
harness/phase4/live4a/, taken at candidate 379acf6 unless noted):

  * setup preconditions (section 5 / walk sections A-C): ENCODED — the nine
    realm users (logs/021-022), the local-mode seeding (logs/060), the before
    hash (logs/061), the U17 refusal walk and deletions (logs/070-072), the
    realm switch (logs/102,105,110), the after hash with the seed token
    (logs/113-115), the U26 realm read (logs/160) and the U20 refusal sub-probe
    (logs/161).
  * ENCODED rows: U1 (120,122), U2 (121), U3 (123-125), U4 (125,126), U5
    (126-128), U6 (128), U7 (129,130 + the c8c9337 re-measure 160; dd3a28d is
    log-format-only per lead 2026-10-13; the browser control from 148 runs via
    scripts/gate/phase4-browser.mjs on the seeded p4lokiui dashboard), U8 (131),
    U12 (154,164 outage sequence), U13 (154,164 extended outage and idp-wait),
    U15 (124,132 headless + the 146,147 browser `ui` probe via the same mjs),
    U16 (140), U17 (070-072), U18 (061,113-115),
    U19 (102,105,114,123,126), U20 (101-102,135-139,161), U21a (111,122; its
    table-2 probe parses the `anonymous-https` rows of commit 11a23d5), U21b
    Mac method (142), U22 (169 clean cycle at HEAD 5d17495; log 161 is fbfc872
    defect evidence), U23 (137,139,162,169 container ledger & realm.ini change),
    U24 three-command sequence (163,165-168 — the plan's
    two-command form was measured and failed, defect D3; lead decision
    2026-10-13), U25 (145), U26 (160,104), U28 (133-134), and the four timing
    rows U9 (151), U10 (152,152b), U11 (153,153b), U29 (150) — ports of the
    walk's u{9,10,11,29}_job.py + timing_common.py into TimedRows threads,
    scheduled after the short rows exactly as the walk serialized them. U27
    starts in the prepared session-max companion and joins at its row. The
    browser batch follows the walk's method and policy (results.md: container
    Chromium krate-harness/playwright:1.60.0, the gate's --resolve-to mapping
    shape; Viewer p4v on krate-overview = log 146, Admin p4both on p4lokiui =
    log 148; the p4lokiui panel JSON is rebuilt — the walk's creation call was
    not kept — and the dashboard is deleted again after the runs).
  * U14 was added after its six live refusals at candidate 54472fe (see
    harness/phase4/formal-r1/u14-live/results.md). U27's polling and same-jar
    authorize mechanics were observed in the 15-minute diagnostic at
    harness/phase4/formal-r1/u27-v23-15m/; a matched-lifetime live walk remains
    necessary before acceptance.
  * U21b on Linux delegates to the independently walked 4c netns method in
    phase4_linux.py (the Mac method was observed in live4a log 142).

The frame reuses phase2_kafbat.Gate/Kcadm/Browser, keycloak_login_flow.py
(enrol), probes.py (the row-pass rule: one `probe=PASS|FAIL|NOT_RUN` token per
probe in the row's listed order, the row takes the worst) and
phase4_common.TimedRows for the timing rows. Secrets (JWTs, cookies, tokens,
enrolled passwords and TOTP seeds) go to $STATE/phase4-secrets.txt through
add_runtime_secret(); the runner adds that file to its leak set.

Timing design (section 5), WIRED: the four timing rows run as parallel
TimedRows threads started after the short rows and joined at the end of the
plan (longest first): U10 polls at 10 s with the disable+logout at t0+30 s
(330 s bound), U11 the same shape for the group removal (300 s bound), U9 runs
its two cases (immediate + 6 min of activity), U29 the 16-min idle with the
once-a-minute control over 17.5 min. In prepared session-max runs U27 (M + 1
min) joins this frame. Secrets (JWTs, cookies, tokens,
enrolled passwords and TOTP seeds) go to $STATE/phase4-secrets.txt through
add_runtime_secret(); the runner adds that file to its leak set.
"""
import base64
import calendar
import datetime
import hashlib
import hmac
import html as htmlmod
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python3 -I does not add the script directory
import phase2_kafbat as p2  # noqa: E402
from phase4_common import (Phase4Gate, helper_main, aggregate, log,  # noqa: E402
                           Outcome, Terminated, not_run, fail)

CASES = (['U%d' % i for i in range(1, 21)] + ['U21a', 'U21b']
         + ['U%d' % i for i in range(22, 30)])
RUNNER_OWNED = ('X3', 'Z4a')

# The walk's realm users (harness/phase4/live4a/logs/021, scripts/make_users.sh).
EMAIL_DOMAIN = 'live4a.test'
CLI_USERS = (('p4v', ('--viewer',)), ('p4b', ('--admin',)), ('p4both', ('--admin',)),
             ('p4nogroup', ()), ('p4dis', ('--viewer',)), ('p4a2', ('--admin',)),
             ('p4idle', ('--viewer',)), ('p4ctrl', ('--viewer',)))
# U5's user is created by kcadm without an e-mail (identity users add requires
# --email in realm mode); U3's both-groups user gets its second group by kcadm.
NOEMAIL_USER = 'p4noemail'
BOTH_USER = 'p4both'
# The walk's local Grafana users (seed_grafana.py); the collide users carry the
# e-mails of the realm users p4v (Viewer) and p4b (Admin) — row U19.
LOCAL_USERS = (('p4-collide', 'p4v'), ('p4-collide-b', 'p4b'), ('p4-plain', None))
# U18's six data volumes (hash_state.py) and the volatile keys its stable hash strips.
DATA_VOLUMES = ('grafana_data', 'prometheus_data', 'loki_data',
                'victorialogs_data', 'alertmanager_data', 'perses_data')
VOLATILE = {'id', 'created', 'updated', 'version', 'createdBy', 'updatedBy',
            'lastSeenAt', 'lastSeenAtAge', 'accessControl', 'access'}
# Compose one-shots of the monitoring project: re-run in place by every `monitor up`
# (same container id, new StartedAt), so they are excluded from the recreation
# comparisons (plan U22/U23; walk logs/137-139).
ONE_SHOT_SERVICES = {'monitoring-init', 'init', 'idp-wait', 'perses-seed', 'perses-migrate'}
U6_WRITE_BODIES = {
    'dashboard_save': ('/grafana/api/dashboards/db',
                       {'dashboard': {'uid': 'p4-u6-deny', 'title': 'p4 u6 deny', 'panels': [],
                                      'schemaVersion': 39, 'version': 0},
                        'folderUid': '', 'message': 'u6', 'overwrite': True}),
    'folder_create': ('/grafana/api/folders', {'uid': 'p4-u6-deny', 'title': 'p4 u6 deny'}),
    'datasource_create': ('/grafana/api/datasources',
                          {'name': 'p4-u6-deny', 'type': 'prometheus', 'url': 'http://prometheus:9090',
                           'access': 'proxy', 'jsonData': {'httpMethod': 'POST'}}),
    'alert_rule_create': ('/grafana/api/v1/provisioning/alert-rules',
                          {'uid': 'p4-u6-deny', 'title': 'P4U6Deny', 'folderUID': 'p4foldera',
                           'ruleGroup': 'P4 u6', 'orgId': 1, 'condition': 'B', 'for': '0s',
                           'noDataState': 'OK', 'execErrState': 'Error',
                           'data': [{'refId': 'A', 'relativeTimeRange': {'from': 600, 'to': 0},
                                     'datasourceUid': 'prometheus',
                                     'model': {'refId': 'A', 'expr': 'sum(up)', 'instant': True,
                                               'datasource': {'type': 'prometheus', 'uid': 'prometheus'}}}]}),
}


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def strip_volatile(obj):
    if isinstance(obj, dict):
        return {k: strip_volatile(v) for k, v in obj.items() if k not in VOLATILE}
    if isinstance(obj, list):
        return [strip_volatile(v) for v in obj]
    return obj


# ─── Loki push payload (U28): protobuf WriteRequest + snappy block framing ────
# Rebuilt for the gate (the walk's inline builder was not kept); the OBSERVED
# outcome is the walk's: 204 and the line stored under {job="p4-u28-reach",
# source="u28-proto"} (logs/134). A JSON push answers 400 "snappy: corrupt
# input" — Loki-generated, which is U28's reach proof either way (logs/133).

def _varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _pb(num, wire, payload):
    tag = _varint((num << 3) | wire)
    if wire == 0:
        return tag + _varint(payload)
    return tag + _varint(len(payload)) + payload


def _snappy_literal(data):
    marker = len(data) - 1
    if marker < 60:
        return bytes([marker << 2]) + data
    extra = marker.to_bytes((marker.bit_length() + 7) // 8, 'little')
    return bytes([(59 + len(extra)) << 2]) + extra + data


def _loki_range_url(proxy_base, selector, start, end):
    """Range-query URL for a Loki selector over [start, end] (epoch seconds).
    Instant /query without a time selects nothing reliably on the guest Loki
    (rocky-4a: U7 forged + U28 stored FAIL while query_range controls pass);
    the walk's stored readback used a ranged query (log 134)."""
    return proxy_base + '/query_range?query=%s&start=%d&end=%d&limit=50' % (
        urllib.parse.quote(selector), start, end)


def _empty_result(body):
    """True when a Loki query body holds zero streams (probe-tested)."""
    try:
        return json.loads(body)['data']['result'] == []
    except (ValueError, KeyError, TypeError):
        return False


def _dict_diff(before, after):
    """Changed keys as {key: (old, new)}; a missing side reads as None."""
    keys = sorted(set(before) | set(after))
    return {k: (before.get(k), after.get(k)) for k in keys
            if before.get(k) != after.get(k)}


def loki_push_body(labels, line, ts_ns):
    """snappy(protobuf WriteRequest{streams:[{labels, values:[{time, line}]}]})."""
    seconds, nanos = ts_ns // 10 ** 9, ts_ns % 10 ** 9
    timestamp = _pb(1, 0, seconds) + (_pb(2, 0, nanos) if nanos else b'')
    entry = _pb(1, 2, timestamp) + _pb(2, 2, line.encode())
    labels_str = '{' + ','.join('%s="%s"' % (k, v) for k, v in sorted(labels.items())) + '}'
    stream = _pb(1, 2, _pb(1, 2, labels_str.encode()) + _pb(2, 2, entry))
    return _varint(len(stream)) + _snappy_literal(stream)


# ─── the headless Grafana realm-mode driver (port of the walk's p4driver.py) ──

class GrafanaDriver:
    """One user agent on the public origin: cookie jar, no automatic redirects,
    pinned TLS (gate.tls), and the Grafana session-token rotation recovery the
    walk's driver proved (401 session.token.rotate -> POST
    /grafana/api/user/auth-tokens/rotate -> retry once; p4driver.py:80-90)."""

    def __init__(self, gate, label):
        self.gate = gate
        self.label = label
        self.jar = p2.http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            p2.NoRedirect, urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=gate.tls))

    def req(self, url, data=None, method=None, headers=None, timeout=60):
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        sent = dict(headers or {})
        if isinstance(data, dict):
            sent.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        request = urllib.request.Request(url, data=body, headers=sent, method=method)
        try:
            response = self.opener.open(request, timeout=timeout)
            status, hdrs, text = response.status, response.headers, response.read().decode(errors='replace')
        except urllib.error.HTTPError as error:
            status, hdrs, text = error.code, error.headers, error.read().decode(errors='replace')
        except urllib.error.URLError as error:
            return -1, {}, 'URLError: %s' % error.reason
        if status == 401 and 'session.token.rotate' in text and not url.endswith('/auth-tokens/rotate'):
            rotated = self.raw(self.gate.base + '/grafana/api/user/auth-tokens/rotate', b'', 'POST')
            if rotated[0] == 200:
                log('%s: rotated the Grafana session token (rotate endpoint 200)' % self.label)
                return self.req(url, data=data, method=method, headers=headers, timeout=timeout)
        for cookie in self.jar:
            if cookie.name.startswith('grafana_session'):
                self.gate.add_runtime_secret(cookie.value)
        return status, hdrs, text

    def raw(self, url, body, method):
        request = urllib.request.Request(url, data=body, method=method)
        try:
            response = self.opener.open(request, timeout=60)
            return response.status, response.headers, response.read().decode(errors='replace')
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read().decode(errors='replace')

    @staticmethod
    def set_cookie_headers(headers):
        """A redirect may expose get_all() but have no Set-Cookie values."""
        return (headers.get_all('Set-Cookie') or []) if hasattr(headers, 'get_all') else []

    @staticmethod
    def form_action(page):
        match = re.search(r'<form[^>]+action="([^"]+)"', page)
        if not match:
            raise RuntimeError('no form in page: ' + page[:200])
        return htmlmod.unescape(match.group(1))

    @staticmethod
    def totp(secret_b32):
        key = base64.b32decode(secret_b32.replace(' ', '').upper())
        counter = int(time.time() // 30)
        digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
        offset = digest[-1] & 15
        return '%06d' % ((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000)


class Gate(Phase4Gate):
    SLICE = '4a'
    CASES = CASES
    RUNNER_OWNED = RUNNER_OWNED

    def __init__(self, args):
        super().__init__(args)
        self.user_state = {}    # realm user -> enrolment state file (password + TOTP)
        self.seed_state = {}    # seeded local users' passwords/ids, public dashboard, snapshot keys
        self.state_before = None
        self.state_after = None
        self.drivers = {}
        self.browser_results = None  # the once-per-run browser batch (U15 ui / U7 explore_panels)
        self.cluster_initial = {}

    # ── fixture accessors ──
    def grafana_loopback(self):
        return 'http://127.0.0.1:%s' % (self.monitor_env.get('GRAFANA_PORT') or '3000')

    def admin_basic(self):
        return (self.monitor_env.get('GRAFANA_USER') or 'admin',
                self.monitor_env.get('GRAFANA_PASSWORD') or '')

    def grafana_admin(self, *args, **kwargs):
        """The product's host-side helper (monitoring/grafana-admin.py); credentials
        travel in its environment only (GRAFANA_URL + Basic admin, or the seed token)."""
        script = os.path.join(self.mon_dir(), 'grafana-admin.py')
        if not os.path.isfile(script):
            raise RuntimeError('monitoring/grafana-admin.py is missing from the edition directory')
        env = dict(os.environ, GRAFANA_URL=self.grafana_loopback())
        token = kwargs.pop('token', None)
        if token:
            env['GRAFANA_SERVICE_ACCOUNT_TOKEN'] = token
        else:
            env['GRAFANA_ADMIN_USER'] = self.admin_basic()[0]
            env['GRAFANA_ADMIN_PASSWORD'] = self.admin_basic()[1]
        return p2.run([sys.executable, script] + list(args), env=env, timeout=180)

    def grafana_api(self, method, path, body=None, auth=None, token=None, headers=None):
        """A direct Grafana API call on the loopback port (the walk's seed/hash method:
        Basic admin before the switch, the seed SA token after it). Returns (status, parsed)."""
        sent = {'Content-Type': 'application/json'}
        if token:
            sent['Authorization'] = 'Bearer ' + token
        elif auth:
            sent['Authorization'] = 'Basic ' + base64.b64encode(('%s:%s' % auth).encode()).decode()
        sent.update(headers or {})
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.grafana_loopback() + path, method=method,
                                         data=data, headers=sent)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode()
                status, payload = response.status, raw
        except urllib.error.HTTPError as error:
            status, payload = error.code, error.read().decode(errors='replace')
        except urllib.error.URLError as error:
            raise RuntimeError('Grafana at %s did not answer %s %s: %s'
                               % (self.grafana_loopback(), method, path, error.reason))
        try:
            return status, (json.loads(payload) if payload else None)
        except ValueError:
            return status, payload

    def grafana_read(self, path, auth=None, token=None):
        status, body = self.grafana_api('GET', path, auth=auth, token=token)
        if status != 200:
            raise RuntimeError('Grafana read %s answered %s' % (path, status))
        return body

    def public_api(self, method, path, driver=None, token=None, body=None, headers=None):
        """A call on the public route https://H/grafana... — with a signed-in driver's
        cookie jar, or with the seed token as Bearer (the walk's U20/U28 method)."""
        url = self.base + path
        sent = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            sent['Content-Type'] = 'application/json'
        if token:
            sent['Authorization'] = 'Bearer ' + token
        if driver is not None:
            return driver.req(url, data=data, method=method, headers=sent)
        request = urllib.request.Request(url, data=data, headers=sent, method=method)
        opener = urllib.request.build_opener(p2.NoRedirect,
                                             urllib.request.HTTPSHandler(context=self.tls))
        try:
            response = opener.open(request, timeout=60)
            return response.status, response.headers, response.read().decode(errors='replace')
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read().decode(errors='replace')
        except urllib.error.URLError as error:
            return -1, {}, 'URLError: %s' % error.reason

    def mon_id_map(self):
        """{service: (container id, StartedAt)} of the monitoring project (the walk's
        recreation-boundary method, logs/106-111)."""
        found = {}
        rc, out, _ = p2.docker('ps', '-aq', '--filter',
                               'label=com.docker.compose.project=' + self.monitor_project)
        if rc != 0 or not out.split():
            return found
        for cid in out.split():
            rc2, info, _ = p2.docker('inspect', '--format',
                                     '{{index .Config.Labels "com.docker.compose.service"}} {{.Id}} {{.State.StartedAt}}', cid)
            if rc2 == 0 and info.split():
                parts = info.split()
                found[parts[0]] = (parts[1], ' '.join(parts[2:]))
        return found

    @staticmethod
    def long_running(id_map):
        """The id map without the one-shots (they are re-run in place by every
        `monitor up` — same id, new StartedAt — and are excluded from the
        recreation-boundary comparisons, plan U22/U23 and walk logs/137-139)."""
        return {svc: value for svc, value in id_map.items()
                if svc not in ONE_SHOT_SERVICES}

    def cluster_id_map(self):
        """{service: (container id, StartedAt)} of the cluster project (U23's ledger)."""
        found = {}
        rc, out, _ = p2.docker('ps', '-aq', '--filter',
                               'label=com.docker.compose.project=' + self.project)
        if rc != 0 or not out.split():
            return found
        for cid in out.split():
            rc2, info, _ = p2.docker('inspect', '--format',
                                     '{{index .Config.Labels "com.docker.compose.service"}} {{.Id}} {{.State.StartedAt}}', cid)
            if rc2 == 0 and info.split():
                parts = info.split()
                found[parts[0]] = (parts[1], ' '.join(parts[2:]))
        return found

    def seed_token(self):
        """The Grafana seed SA token (0600 file, host-only); added to the runtime secrets."""
        path = os.path.join(self.mon_dir(), 'auth', 'secrets', 'grafana-seed.token')
        if not os.path.isfile(path):
            raise RuntimeError('no seed token at ' + path)
        with open(path, encoding='utf-8') as handle:
            token = handle.read().strip()
        self.add_runtime_secret(token)
        return token

    def seed_meta(self):
        path = os.path.join(self.mon_dir(), 'auth', 'secrets', 'grafana-seed.meta')
        values = {}
        with open(path, encoding='utf-8') as handle:
            for line in handle:
                if '=' in line:
                    key, _, value = line.partition('=')
                    values[key.strip()] = value.strip()
        return values

    def mon_env_value(self, key):
        """A fresh read of monitoring/.env (the file changes during the setup chain)."""
        try:
            return p2.read_env(os.path.join(self.mon_dir(), '.env')).get(key, '')
        except OSError:
            return ''

    def grafana_container(self):
        cid = self.mon_container('grafana')
        if not cid:
            raise RuntimeError('no grafana container in project ' + self.monitor_project)
        return cid

    def grafana_logs(self, since=None):
        args = ['logs']
        if since:
            args += ['--since', since]
        rc, out, err = p2.docker(*(args + [self.grafana_container()]), timeout=120)
        return out + err

    # ── the sign-in driver (walk logs/123-128: p4driver.py signin) ──
    def driver(self, label):
        if label not in self.drivers:
            self.drivers[label] = GrafanaDriver(self, label)
        return self.drivers[label]

    def load_state(self, user):
        path = self.user_state.get(user)
        if not path:
            raise RuntimeError('no enrolment state for %s (setup did not run?)' % user)
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)

    def signin(self, user, label, expect='ok'):
        """Full realm sign-in to Grafana (walk method p4driver.py cmd_signin, logs/123-128):
        authstart -> Keycloak password + OTP (next 30 s step, codes are single-use) ->
        callback GET -> session cookie. Returns {'kind': OK|REFUSED|FAIL, 'error', 'driver',
        'chain', 'set_cookie', 'callback_get'}; the last three feed U15's flow/cookie probes."""
        state = self.load_state(user)
        d = self.driver(label)
        # Walk anomaly 4 (log 131): every sign-in starts from a deleted jar — a stale
        # grafana_session cookie confuses the callback. Labels are unique per row/case,
        # and the clear makes a reused label safe too.
        d.jar.clear()
        chain = []
        set_cookie = ''
        callback_get = None
        status, hdrs, page = d.req(self.base + '/grafana/login/generic_oauth')
        chain.append(('GET', '/grafana/login/generic_oauth', status))
        if status != 302 or not hdrs.get('Location'):
            return {'kind': 'FAIL', 'error': 'authstart %s' % status, 'driver': d,
                    'chain': chain, 'set_cookie': set_cookie, 'callback_get': callback_get}
        url = hdrs['Location']
        for _ in range(6):  # follow to the Keycloak form (intra-realm redirects)
            status, hdrs, page = d.req(url)
            chain.append(('GET', url.split('?')[0].replace(self.base, ''), status))
            if status in (302, 303) and hdrs.get('Location'):
                url = urllib.parse.urljoin(url, hdrs['Location'])
                continue
            break
        if not (status == 200 and 'id="kc-form-login"' in page):
            return {'kind': 'FAIL', 'error': 'no Keycloak form: %s' % status, 'driver': d,
                    'chain': chain, 'set_cookie': set_cookie, 'callback_get': callback_get}
        status, hdrs, page = d.req(GrafanaDriver.form_action(page),
                                   {'username': state['user'], 'password': state['password'],
                                    'credentialId': ''})
        chain.append(('POST', 'realm:password', status))
        if status == 200 and 'name="otp"' in page:
            time.sleep(30 - time.time() % 30 + 1)  # a TOTP code is single-use: next step
            status, hdrs, page = d.req(GrafanaDriver.form_action(page),
                                       {'otp': GrafanaDriver.totp(state['totp'])})
            chain.append(('POST', 'realm:otp', status))
        login_error = ''
        for _ in range(6):  # follow back to Grafana's callback
            if status in (302, 303) and hdrs.get('Location'):
                location = hdrs['Location']
                url = urllib.parse.urljoin(url, location)
                if 'loginError' in location:
                    login_error = urllib.parse.parse_qs(
                        urllib.parse.urlsplit(location).query).get('loginError', [''])[0]
                if '/grafana/login/generic_oauth' in url and 'code=' in url:
                    callback_get = status  # U15's flow probe: the callback is a GET (walk 132)
                status, hdrs, page = d.req(url)
                chain.append(('GET', url.split('?')[0].replace(self.base, ''), status))
                for header in GrafanaDriver.set_cookie_headers(hdrs):
                    if header.startswith('grafana_session='):
                        set_cookie = header
                continue
            break
        session = [c for c in d.jar if c.name == 'grafana_session']
        if not login_error and not session:
            # Keycloak may re-show the form with an inline error (status 200,
            # no redirect): parse it so expect='refused:...' sees a REFUSED.
            login_error = self.kc_refusal_reason(page, status)
            # Grafana 12 renders the OAuth failure in the login page's boot data, not
            # only in the redirect query (observed live 2026-10-12, walk log 125).
            match = re.search(r'"loginError"\s*:\s*"([^"]+)"', page)
            if match:
                login_error = htmlmod.unescape(match.group(1))
        kind = 'OK' if (session and not login_error) else ('REFUSED' if login_error else 'FAIL')
        result = {'kind': kind, 'error': login_error, 'driver': d, 'status': status,
                  'chain': chain, 'set_cookie': set_cookie, 'callback_get': callback_get}
        if expect == 'ok' and kind != 'OK':
            fail('%s sign-in expected OK, got %s (%s)' % (user, kind, login_error or status))
        if expect.startswith('refused'):
            want = expect.split(':', 1)[1] if ':' in expect else ''
            if kind != 'REFUSED' or (want and want not in login_error):
                fail('%s sign-in expected REFUSED %r, got %s (%s)' % (user, want, kind, login_error))
        return result

    @staticmethod
    def kc_refusal_reason(page, st):
        """Keycloak-side refusal: the login form re-shown with an inline error
        (e.g. a disabled account), or the error page. Port of the walk's
        harness/phase4/live4a/scripts/p4driver.py kc_refusal_reason, mirroring
        keycloak_login_flow.py's parser (keycloak.v2 theme). Rocky 4a at
        959fed2: U10's disabled sign-in ended here with status 200 and no
        loginError query, so signin() called it FAIL instead of REFUSED."""
        if st != 200:
            return ''
        on_form = 'id="kc-form-login"' in page
        on_error_page = 'id="kc-error-message"' in page
        if not (on_form or on_error_page):
            return ''
        match = (re.search(r'id="input-error[^"]*".*?helper-text__item-text[^>]*>\s*([^<]*?)\s*<',
                           page, re.S)
                 or re.search(r'id="kc-error-message".*?<p[^>]*>([^<]*)<', page, re.S)
                 or re.search(r'<span[^>]*kc-feedback-text[^>]*>([^<]*)<', page))
        reason = htmlmod.unescape(match.group(1).strip()) if match else '(no message parsed)'
        # a plain login form with NO error (e.g. flow restart) is not a refusal
        if not match and on_form and 'kc-feedback-text' not in page and 'input-error' not in page:
            return ''
        return reason

    def ws_upgrade(self, driver, path, subprotocol=None):
        """Raw WebSocket-upgrade probe (port of the walk's scripts/ws_probe.py, logs
        129/130/132/160): an HTTP/1.1 GET with Upgrade: websocket over the pinned TLS
        context, carrying the driver's cookies; returns the response head text."""
        cookies = '; '.join('%s=%s' % (c.name, c.value) for c in driver.jar)
        key = base64.b64encode(os.urandom(16)).decode()
        host = self.origin.hostname
        port = self.origin.port or 443
        lines = ['GET %s HTTP/1.1' % path, 'Host: %s:%s' % (host, port),
                 'Upgrade: websocket', 'Connection: Upgrade',
                 'Sec-WebSocket-Key: %s' % key, 'Sec-WebSocket-Version: 13']
        if subprotocol:
            lines.append('Sec-WebSocket-Protocol: %s' % subprotocol)
        if cookies:
            lines.append('Cookie: %s' % cookies)
        request = ('\r\n'.join(lines) + '\r\n\r\n').encode()
        try:
            with socket.create_connection((host, port), timeout=30) as raw:
                with self.tls.wrap_socket(raw, server_hostname=host) as tls:
                    tls.sendall(request)
                    data = b''
                    while b'\r\n\r\n' not in data:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
        except OSError as error:
            return 'probe error: %s' % error
        return data.split(b'\r\n\r\n')[0].decode(errors='replace')

    # ── timing-row helpers (ports of the walk's scripts/timing_common.py) ──
    def kc_session_ids(self, user):
        """The user's Keycloak session ids (walk: kc.sh get users/<uid>/sessions)."""
        kc = self.master_kcadm()
        uid = kc.user_id(user)
        if not uid:
            raise RuntimeError('no realm user ' + user)
        sessions = kc.get('users/%s/sessions' % uid) or []
        return {s.get('id') for s in sessions if isinstance(s, dict)}

    def one_request(self, driver, path='/grafana/api/user'):
        """One polled request (walk timing_common.one_request): status plus the
        401's messageId or the redirect's Location."""
        status, hdrs, body = driver.req(self.base + path)
        if status in (302, 303):
            return status, (hdrs.get('Location', '') if hasattr(hdrs, 'get') else '')
        if status == 401:
            match = re.search(r'"messageId":"([^"]+)"', body or '')
            return status, (match.group(1) if match else (body or '')[:60])
        return status, ''

    def authorize_shows_form(self):
        """After a session ended: the next authorize request (a fresh agent with no
        cookies) must show the Keycloak password form (walk authorize_shows_form)."""
        d = GrafanaDriver(self, 'authform-%s' % secrets.token_hex(3))
        status, hdrs, page = d.req(self.base + '/grafana/login/generic_oauth')
        url = hdrs.get('Location', '') if hasattr(hdrs, 'get') else ''
        for _ in range(6):
            if status in (302, 303) and url:
                url = urllib.parse.urljoin(self.base, url) if url.startswith('/') else url
                status, hdrs, page = d.req(url)
                url = hdrs.get('Location', '') if hasattr(hdrs, 'get') else ''
                continue
            break
        form = status == 200 and 'id="kc-form-login"' in page
        return form, 'status=%s form=%s' % (status, form)

    def force_logout(self, user):
        """`identity users logout <user>` — the walk's stale-SSO clear before a row
        whose Keycloak-session count must be deterministic (u29_job.py preamble).
        Timed rows run concurrently, so a logout can land while a sibling holds
        the identity lock: retry lock contention like the other timed rows
        (Rocky 4a at bfd1158: U9 saw sessions 2->1)."""
        rc, _out, _err = self.krate_locked('identity', 'users', 'logout', user, timeout=120)
        return rc == 0

    # ── the browser batch (U15 `ui`, U7 `explore_panels`): container Chromium ──
    # Port of the walk's method (logs 146/147/148, scripts/ui15.mjs -> the gate's
    # scripts/gate/phase4-browser.mjs, results.md browser policy: container
    # Chromium with the gate's --resolve-to host-gateway mapping shape).
    BROWSER_IMAGE = 'krate-harness/playwright:1.60.0'

    def host_gateway(self):
        """The Docker host gateway as a container sees it (the runner's run_screenshots
        method): Chromium inside the container reaches the published proxy ports through it."""
        pg = self.env.get('KEYCLOAK_DB_IMAGE')
        if not pg:
            return None
        rc, out, _err = p2.docker('run', '--rm', '--add-host', 'host.docker.internal:host-gateway',
                                  pg, 'sh', '-c',
                                  'getent ahostsv4 host.docker.internal | awk "{print $1; exit}"',
                                  timeout=60)
        value = out.strip().splitlines()[0].strip() if rc == 0 and out.strip() else ''
        return value or None

    def run_browser_probe(self, user, dash, gateway):
        """One phase4-browser.mjs run in the Playwright container; the user's password
        and TOTP seed travel in the child environment (-e NAME), never in argv.
        Returns (summary dict | None, steps list)."""
        state = self.load_state(user)
        outdir = os.path.join(self.state_dir, 'browser', user)
        os.makedirs(outdir, exist_ok=True)
        env = dict(os.environ, UI15_USER=user, UI15_PASSWORD=state['password'],
                   UI15_TOTP=state['totp'], UI15_DASH=dash,
                   PW_MODULES='/usr/lib/node_modules')
        rc, out, err = p2.docker(
            'run', '--rm', '--add-host', 'host.docker.internal:host-gateway',
            '-v', '%s:/out' % outdir, '-v', '%s:/gate:ro' % HERE,
            '-e', 'UI15_USER', '-e', 'UI15_PASSWORD', '-e', 'UI15_TOTP',
            '-e', 'UI15_DASH', '-e', 'PW_MODULES',
            self.BROWSER_IMAGE, 'node', '/gate/phase4-browser.mjs',
            '--base', self.base, '--host', self.origin.hostname or '',
            '--resolve-to', gateway, '--out', '/out', env=env, timeout=600)
        summary = None
        for line in (out or '').splitlines():
            if line.startswith('SUMMARY '):
                try:
                    summary = json.loads(line[len('SUMMARY '):])
                except ValueError:
                    summary = None
        steps = []
        try:
            with open(os.path.join(outdir, 'ui15-summary.json'), encoding='utf-8') as handle:
                steps = json.load(handle).get('steps') or []
        except (OSError, ValueError):
            pass
        log('browser probe %s (dash %s): docker rc=%s, summary=%s' % (user, dash, rc, bool(summary)))
        if rc != 0 and summary is None:
            log('browser probe stderr tail: %s' % (err or '')[-200:])
        return summary, steps

    def browser_batch(self):
        """Both walked browser runs (Viewer p4v on krate-overview, log 146; Admin
        p4both on the Loki-panel dashboard p4lokiui, log 148), once per helper run.
        The p4lokiui control dashboard is seeded through the public route with the
        SA token and deleted again (its creation JSON is rebuilt — the walk's was
        not kept; the anchored observation is log 148's rendered result: 2669 log
        rows, 0 panel-error icons)."""
        if self.browser_results is not None:
            return self.browser_results
        out = {}
        out['problem'] = None
        out['viewer'] = None
        out['admin'] = None
        self.browser_results = out
        rc, _o, _e = p2.docker('image', 'inspect', self.BROWSER_IMAGE)
        if rc != 0:
            out['problem'] = 'harness image %s is not on this host (the runner builds it for the screenshot stories)' % self.BROWSER_IMAGE
            return out
        gateway = self.host_gateway()
        if not gateway:
            out['problem'] = 'cannot resolve the Docker host gateway (host.docker.internal) from a container'
            return out
        token = self.seed_token()
        panel = {'uid': 'p4lokiui', 'title': 'P4 Loki UI Control', 'tags': ['p4gate'],
                 'timezone': 'browser', 'schemaVersion': 39, 'version': 0, 'refresh': '',
                 'panels': [{'type': 'logs', 'title': 'Container logs', 'datasource': {'type': 'loki', 'uid': 'loki'},
                             'gridPos': {'h': 16, 'w': 24, 'x': 0, 'y': 0},
                             'targets': [{'refId': 'A', 'expr': '{job="containerlogs"}', 'queryType': 'range',
                                          'datasource': {'type': 'loki', 'uid': 'loki'}}]}]}
        st, _h, _b = self.public_api('POST', '/grafana/api/dashboards/db', token=token,
                                     body={'dashboard': panel, 'folderUid': 'p4foldera',
                                           'message': 'u7/u15 browser control', 'overwrite': True})
        if st != 200:
            out['problem'] = 'could not seed the p4lokiui control dashboard (HTTP %s)' % st
            return out
        try:
            for role, user, dash in (('viewer', 'p4v', 'krate-overview'),
                                     ('admin', 'p4both', 'p4lokiui')):
                summary, steps = self.run_browser_probe(user, dash, gateway)
                out[role] = {'summary': summary, 'steps': steps}
        finally:
            self.public_api('DELETE', '/grafana/api/dashboards/uid/p4lokiui', token=token)
        return out

    @staticmethod
    def browser_steps(steps):
        return {s.get('name'): s for s in steps if isinstance(s, dict)}

    def browser_clean(self, summary):
        """The walk's clean-run criteria (logs 146/148 SUMMARY): 0 CSP violations,
        0 page errors, no failed requests, and the only HTTP >= 400 the UI's own
        public-dashboards 404 (public dashboards are off; benign)."""
        if not summary:
            return False
        benign = all(item.get('s') == 404 and str(item.get('url', '')).endswith('/public-dashboards')
                     for item in summary.get('http4xx5xx') or [])
        return (summary.get('cspViolations') == 0 and summary.get('pageErrors') == 0
                and not (summary.get('failedRequests') or []) and benign)

    @staticmethod
    def browser_ws(summary, contains=''):
        return [w for w in (summary or {}).get('websockets') or []
                if contains in (w.get('url') or '') and (w.get('framesIn') or 0) > 0]

    def krate_locked(self, *args, timeout=300, attempts=6, gap=10):
        """Run the CLI, retrying while another timed row holds the identity
        lock. Timed rows (U9/U10/U11/...) run concurrently, so a logout or
        disable can land while a sibling's mutating CLI command still holds
        it (Rocky 4a at 959fed2: U11 `identity users logout p4a2 rc=1`).
        Only the lock contention is retried; any other failure returns at once."""
        last = (1, '', '')
        for _ in range(attempts):
            rc, out, err = self.krate(*args, timeout=timeout)
            if rc == 0 or 'Another krate identity command is running' not in (out + err):
                return rc, out, err
            last = (rc, out, err)
            time.sleep(gap)
        return last

    def api_json(self, driver, method, path, body=None, headers=None):
        # Grafana's JSON APIs need a JSON body: the driver's default dict
        # encoding is form-urlencoded, which they answer with 400 (Rocky 4a
        # at 959fed2: U6 admin_control, U15 origin, U28 create).
        sent = dict(headers or {})
        data = body
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            sent.setdefault('Content-Type', 'application/json')
        status, _hdrs, text = driver.req(self.base + path, data=data,
                                         method=method, headers=sent)
        try:
            return status, json.loads(text)
        except ValueError:
            return status, text

    # ── README table 2 (U28/W4's approved residual list) ──
    def readme_path(self):
        candidate = os.path.join(self.mon_dir(), 'README.md')
        return candidate if os.path.isfile(candidate) else None

    def table2_text(self):
        path = self.readme_path()
        if not path:
            return ''
        try:
            with open(path, encoding='utf-8') as handle:
                text = handle.read()
        except OSError:
            return ''
        parts = text.split('## Table 2', 1)
        if len(parts) < 2:
            return ''
        # up to the next top-level heading
        return re.split(r'^## ', parts[1], flags=re.M)[0]

    def table2_rows(self):
        rows = []
        for line in self.table2_text().splitlines():
            cells = [c.strip().strip('`') for c in line.strip().strip('|').split('|')]
            if len(cells) >= 3 and cells[0] and cells[0] != 'source' and not set(cells[0]) <= {'-', ' '}:
                rows.append((cells[0], cells[1], cells[2]))
        return rows

    # ── setup: the slice preconditions of section 5 (walk sections A-C) ──
    def setup(self):
        if getattr(self.args, 'prepared', False):
            return self.setup_prepared_u27()
        if getattr(self.args, 'session_max_minutes', None):
            return 'U27 timing requires --prepared so the live maxima are checked before sign-in'
        try:
            self.cluster_initial = self.cluster_id_map()
            self.setup_realm_users()   # walk logs/021-022
            self.setup_seed()          # walk logs/060
            self.state_before = self.hash_state()  # walk logs/061 (Basic admin, local mode)
            self.setup_u17()           # walk logs/070-072 (records obs['U17'])
            self.setup_switch()        # walk logs/102,105,110 (records U19/U20 observations)
            self.setup_after()         # walk logs/113-115,160-161 (records obs['U18'] and more)
        except Outcome as outcome:
            return outcome.text
        except Exception as error:  # a setup error is reported with its step, never hidden
            return 'setup step failed: %s: %s' % (type(error).__name__, str(error)[:300])
        return None

    def setup_prepared_u27(self):
        """Read-only checks for a shared fixture prepared before the timed workers."""
        try:
            if self.args.only != ['U27'] or not self.args.session_max_minutes:
                raise RuntimeError('prepared Grafana worker requires --only U27 and --session-max-minutes')
            if self.mon_env_value('GRAFANA_AUTH_CONFIG') != 'realm.ini':
                raise RuntimeError('Grafana is not in realm mode')
            state = os.path.join(self.state_dir, 'p4', 'kc-p4v.json')
            if not os.path.isfile(state) or os.stat(state).st_mode & 0o077:
                raise RuntimeError('p4v enrolment state is missing or not private')
            self.user_state['p4v'] = state
            enrolled = self.load_state('p4v')
            if enrolled.get('user') != 'p4v' or not enrolled.get('password') or not enrolled.get('totp'):
                raise RuntimeError('p4v enrolment state is incomplete')
            self.add_state_file_secrets(state)
            kc = self.master_kcadm()
            uid = kc.user_id('p4v')
            if not uid:
                raise RuntimeError('p4v realm user is absent')
            groups = kc.get('users/%s/groups' % uid) or []
            viewer = self.env.get('KEYCLOAK_VIEWER_GROUP') or 'KRATE_VIEWERS'
            if viewer not in {group.get('name') for group in groups}:
                raise RuntimeError('p4v is not in the Viewer group')
            expected = self.args.session_max_minutes * 60
            realm = kc.get('realms/krate') or {}
            realm_max = realm.get('ssoSessionMaxLifespan')
            if realm_max != expected:
                raise RuntimeError('Keycloak max %s s differs from requested %s s'
                                   % (realm_max, expected))
            ini = os.path.join(self.mon_dir(), 'auth', 'realm.ini')
            cid = self.grafana_container()
            rc, out, err = p2.docker('inspect', cid)
            if rc != 0:
                raise RuntimeError('cannot inspect running Grafana: %s' % err.strip()[:100])
            container = json.loads(out)[0]
            if not container.get('State', {}).get('Running'):
                raise RuntimeError('Grafana container is not running')
            environ = container.get('Config', {}).get('Env') or []
            if 'GF_PATHS_CONFIG=/etc/krate/auth/realm.ini' not in environ:
                raise RuntimeError('running Grafana does not select realm.ini')
            if any(item.startswith('GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=') for item in environ):
                raise RuntimeError('Grafana lifetime has an environment override')
            mounts = container.get('Mounts') or []
            if not any(mount.get('Destination') == '/etc/krate/auth'
                       and os.path.realpath(mount.get('Source', ''))
                       == os.path.realpath(os.path.join(self.mon_dir(), 'auth'))
                       and mount.get('RW') is False for mount in mounts):
                raise RuntimeError('Grafana realm auth directory is not the expected read-only mount')
            rc, config, err = p2.docker('exec', cid, 'cat', '/etc/krate/auth/realm.ini')
            if rc != 0:
                raise RuntimeError('cannot read Grafana mounted realm.ini: %s' % err.strip()[:100])
            with open(ini, encoding='utf-8') as handle:
                if config != handle.read():
                    raise RuntimeError('running Grafana mount differs from fixture realm.ini')
            started = datetime.datetime.fromisoformat(
                container['State']['StartedAt'].replace('Z', '+00:00')).timestamp()
            modified = os.stat(ini).st_mtime
            if modified > started:
                raise RuntimeError('Grafana realm.ini changed after container start')
            match = re.search(r'^login_maximum_lifetime_duration\s*=\s*(\d+)([mh])\s*$', config, re.M)
            if not match:
                raise RuntimeError('Grafana realm.ini has no supported maximum lifetime')
            grafana_max = int(match.group(1)) * (60 if match.group(2) == 'm' else 3600)
            if grafana_max != expected:
                raise RuntimeError('Grafana max %s s differs from Keycloak/requested %s s'
                                   % (grafana_max, expected))
            health, _headers, _body = self.driver('u27-health').req(self.base + '/grafana/api/health')
            if health != 200:
                raise RuntimeError('Grafana public health answered HTTP %s' % health)
            log('setup: prepared U27 p4v Viewer and matched %ss Keycloak/Grafana maxima' % expected)
            return None
        except Exception as error:
            return 'prepared U27 precondition failed: %s: %s' % (type(error).__name__, str(error)[:200])

    def setup_realm_users(self):
        """The nine realm users of the walk (logs/021-022): eight through
        `identity users add` (e-mail included) and p4noemail through the master
        kcadm without one; every user enrols (CONFIGURE_TOTP + UPDATE_PASSWORD)
        through keycloak_login_flow.py, state files under $STATE/p4/."""
        state_dir = os.path.join(self.state_dir, 'p4')
        os.makedirs(state_dir, exist_ok=True)
        viewer_group = self.env.get('KEYCLOAK_VIEWER_GROUP') or 'KRATE_VIEWERS'
        for name, flags in CLI_USERS:
            rc, out, err = self.krate('identity', 'users', 'add', name,
                                      *(flags + ('--email', '%s@%s' % (name, EMAIL_DOMAIN))),
                                      timeout=180)
            if rc != 0:
                raise RuntimeError('identity users add %s failed (rc %s): %s'
                                   % (name, rc, (err or out).strip()[-160:]))
            temp = self.temp_password(out)
            if not temp:
                raise RuntimeError('no temporary password in the users add output for ' + name)
            self.add_runtime_secret(temp)
            state = os.path.join(state_dir, 'kc-%s.json' % name)
            self.enrol_user(name, temp, state)
            self.user_state[name] = state
            log('setup: realm user %s added and enrolled' % name)
        kc = self.master_kcadm()
        gid = kc.group_id(viewer_group)
        if not gid:
            raise RuntimeError('no realm group ' + viewer_group)
        # p4both: the second group through kcadm (identity users add takes one flag) — U3.
        uid = kc.user_id(BOTH_USER)
        if not uid:
            raise RuntimeError('realm user %s missing after users add' % BOTH_USER)
        kc.add_group(uid, gid)
        # p4noemail: kcadm-created without an e-mail, viewer group, temporary password,
        # both required actions (the walk's make_users.sh; row U5's method).
        temp = secrets.token_urlsafe(16)
        kc.call('create', 'users', '-r', p2.REALM, '-s', 'username=' + NOEMAIL_USER, '-s', 'enabled=true')
        uid = kc.user_id(NOEMAIL_USER)
        if not uid:
            raise RuntimeError('realm user %s missing after kcadm create' % NOEMAIL_USER)
        kc.add_group(uid, gid)
        kc.call('set-password', '-r', p2.REALM, '--username', NOEMAIL_USER, '--temporary', password=temp)
        kc.call('update', 'users/' + uid, '-r', p2.REALM,
                '-s', 'requiredActions=["CONFIGURE_TOTP","UPDATE_PASSWORD"]')
        self.add_runtime_secret(temp)
        state = os.path.join(state_dir, 'kc-%s.json' % NOEMAIL_USER)
        self.enrol_user(NOEMAIL_USER, temp, state)
        self.user_state[NOEMAIL_USER] = state
        log('setup: %s (both groups) and %s (no e-mail) prepared; %d users enrolled'
            % (BOTH_USER, NOEMAIL_USER, len(self.user_state)))

    def setup_seed(self):
        """Seed through the Grafana API on the loopback port with the Basic admin
        (walk logs/060, scripts/seed_grafana.py): 2 folders, 3 dashboards, 1 alert
        rule, 1 contact point, 1 datasource, the local users p4-collide /
        p4-collide-b / p4-plain (p4-collide Editor, owning its folder+dashboard),
        1 public dashboard (of p4dash1) and 1 snapshot (of p4dash3)."""
        admin = self.admin_basic()
        if not admin[1]:
            raise RuntimeError('GRAFANA_PASSWORD is empty in monitoring/.env')

        def api(method, path, body=None, auth=None, headers=None):
            status, payload = self.grafana_api(method, path, body, auth or admin, headers=headers)
            log('setup seed: %s %s -> %s' % (method, path, status))
            return status, payload

        for login, realm_name in LOCAL_USERS:
            email = ('%s@%s' % (realm_name, EMAIL_DOMAIN)) if realm_name else ('%s@%s' % (login, EMAIL_DOMAIN))
            password = secrets.token_urlsafe(14)
            self.add_runtime_secret(password)
            status, payload = api('POST', '/api/admin/users',
                                  {'login': login, 'email': email, 'name': login, 'password': password})
            if status != 200 or not isinstance(payload, dict):
                raise RuntimeError('create local user %s: %s %s' % (login, status, payload))
            self.seed_state[login] = {'password': password, 'id': payload['id'], 'email': email}
        # p4-collide becomes Editor so it can own a folder and a dashboard (U19).
        collide = self.seed_state['p4-collide']
        status, payload = api('PATCH', '/api/org/users/%s' % collide['id'],
                              {'loginOrEmail': 'p4-collide', 'role': 'Editor'})
        if status != 200:
            raise RuntimeError('p4-collide role Editor: %s %s' % (status, payload))
        collide_auth = ('p4-collide', collide['password'])

        def dash_model(uid, title):
            return {'uid': uid, 'title': title, 'tags': ['p4gate'], 'timezone': 'browser',
                    'panels': [{'type': 'text', 'title': 'seed',
                                'gridPos': {'h': 4, 'w': 24, 'x': 0, 'y': 0},
                                'options': {'mode': 'markdown', 'content': '# %s (p4 gate seed)' % title}}],
                    'schemaVersion': 39, 'version': 0, 'refresh': ''}

        def save_dashboard(uid, title, folder_uid, auth=None):
            status, payload = api('POST', '/api/dashboards/db',
                                  {'dashboard': dash_model(uid, title), 'folderUid': folder_uid or '',
                                   'message': 'p4 seed', 'overwrite': False}, auth=auth)
            if status != 200:
                raise RuntimeError('dashboard save %s: %s %s' % (uid, status, payload))

        status, _p = api('POST', '/api/folders', {'uid': 'p4collidef', 'title': 'P4 Collide Folder'},
                         auth=collide_auth)
        if status != 200:
            raise RuntimeError('collide folder: %s' % status)
        save_dashboard('p4collided', 'P4 Collide Dash', 'p4collidef', auth=collide_auth)
        status, _p = api('POST', '/api/folders', {'uid': 'p4foldera', 'title': 'P4 Folder A'})
        if status != 200:
            raise RuntimeError('folder a: %s' % status)
        save_dashboard('p4dash1', 'P4 Dash 1', 'p4foldera')
        save_dashboard('p4dash3', 'P4 Dash 3', '')
        status, _p = api('POST', '/api/datasources',
                         {'name': 'p4-seed-ds', 'type': 'prometheus', 'url': 'http://prometheus:9090',
                          'access': 'proxy', 'isDefault': False, 'jsonData': {'httpMethod': 'POST'}})
        if status != 200:
            raise RuntimeError('datasource: %s' % status)
        prov = {'X-Disable-Provenance': 'true'}
        status, _p = api('POST', '/api/v1/provisioning/contact-points',
                         {'uid': 'p4-seed-cp', 'name': 'p4-seed-cp', 'type': 'email',
                          'settings': {'addresses': 'p4@gate.test', 'singleEmail': False}}, headers=prov)
        if status not in (200, 201, 202):
            raise RuntimeError('contact point: %s' % status)
        status, _p = api('POST', '/api/v1/provisioning/alert-rules',
                         {'uid': 'p4-seed-rule', 'title': 'P4SeedRule', 'folderUID': 'p4foldera',
                          'ruleGroup': 'P4 seed', 'orgId': 1, 'condition': 'B', 'for': '0s',
                          'noDataState': 'OK', 'execErrState': 'Error',
                          'annotations': {'summary': 'p4 gate seed rule'},
                          'labels': {'source': 'p4gate'},
                          'notification_settings': {'receiver': 'krate-email', 'group_wait': '10s'},
                          'data': [
                              {'refId': 'A', 'relativeTimeRange': {'from': 600, 'to': 0},
                               'datasourceUid': 'prometheus',
                               'model': {'refId': 'A', 'expr': 'sum(up)', 'instant': True, 'range': False,
                                         'datasource': {'type': 'prometheus', 'uid': 'prometheus'}}},
                              {'refId': 'B', 'relativeTimeRange': {'from': 0, 'to': 0},
                               'datasourceUid': '__expr__',
                               'model': {'refId': 'B', 'type': 'threshold', 'expression': 'A',
                                         'conditions': [{'evaluator': {'type': 'gt', 'params': [0]},
                                                         'operator': {'type': 'and'},
                                                         'reducer': {'type': 'last', 'params': []}}]}}]},
                         headers=prov)
        if status not in (200, 201):
            raise RuntimeError('alert rule: %s' % status)
        # The public dashboard and the snapshot are U17's blocked state; their
        # tokens/keys are runtime secrets (deleted again in setup_u17).
        status, payload = api('POST', '/api/dashboards/uid/p4dash1/public-dashboards',
                              {'name': 'p4-public', 'isEnabled': True, 'timeSelectionEnabled': False,
                               'annotationsEnabled': False})
        if status != 200 or not isinstance(payload, dict):
            raise RuntimeError('public dashboard: %s' % status)
        self.seed_state['public_uid'] = payload.get('uid')
        self.add_runtime_secret(payload.get('accessToken'))
        _st, d3 = api('GET', '/api/dashboards/uid/p4dash3')
        if not isinstance(d3, dict) or not isinstance(d3.get('dashboard'), dict):
            raise RuntimeError('read p4dash3 for the snapshot failed')
        status, payload = api('POST', '/api/snapshots',
                              {'name': 'p4-snapshot', 'dashboard': d3['dashboard'], 'expires': 0})
        if status != 200 or not isinstance(payload, dict):
            raise RuntimeError('snapshot: %s' % status)
        self.seed_state['snapshot_key'] = payload.get('key')
        self.add_runtime_secret(payload.get('key'))
        self.add_runtime_secret(payload.get('deleteKey'))
        log('setup: seeding complete (2 folders, 3 dashboards, 1 rule, 1 contact point, '
            '1 datasource, 3 local users, 1 public dashboard, 1 snapshot)')

    def hash_state(self, token=None):
        """U18's state hash (walk logs/061,113, scripts/hash_state.py): the six
        categories (stable hashes), the dashboards' per-uid hashes (JSON without
        version/updated), the users' strict rows and the six volumes' names and
        creation times. Basic admin before the switch, the seed token after it."""
        auth = None if token else self.admin_basic()

        def read(path):
            body = self.grafana_read(path, auth=auth, token=token)
            if body is None:
                raise RuntimeError('Grafana read %s answered an empty body' % path)
            return body

        def read_list(path):
            body = read(path)
            if not isinstance(body, list):
                raise RuntimeError('Grafana read %s is not a list' % path)
            return body

        out = {'categories': {}, 'dashboards': {}, 'users': [], 'volumes': []}
        for name, path, key in (('folders', '/api/folders?limit=1000', lambda f: f['uid']),
                                ('alert-rules', '/api/v1/provisioning/alert-rules', lambda r: r['uid']),
                                ('contact-points', '/api/v1/provisioning/contact-points', lambda c: c['uid']),
                                ('datasources', '/api/datasources', lambda d: d['uid'])):
            items = sorted(read_list(path), key=key)
            out['categories'][name] = {'count': len(items), 'stable': sha(canon(strip_volatile(items)))}
        per_uid = {}
        for entry in sorted(read_list('/api/search?type=dash-db&limit=1000'), key=lambda e: e['uid']):
            doc = read('/api/dashboards/uid/' + entry['uid'])
            if not isinstance(doc, dict) or not isinstance(doc.get('dashboard'), dict):
                raise RuntimeError('dashboard %s read failed' % entry['uid'])
            per_uid[entry['uid']] = sha(canon({k: v for k, v in doc['dashboard'].items()
                                               if k not in ('version', 'updated')}))
        out['dashboards'] = per_uid
        for user in read_list('/api/org/users'):
            out['users'].append((user.get('userId'), user.get('login'), user.get('email'),
                                 user.get('role'), user.get('isDisabled')))
        for volume in DATA_VOLUMES:
            name = self.monitor_project + '_' + volume
            rc, info, err = p2.docker('volume', 'inspect', name)
            if rc != 0:
                raise RuntimeError('docker volume inspect %s failed: %s' % (name, err.strip()[:120]))
            data = json.loads(info)[0]
            out['volumes'].append((data['Name'], data['CreatedAt']))
        return out

    def setup_u17(self):
        """Row U17, observed inside the setup chain (walk logs/070-072): the
        local-mode reads with the Basic admin while blocked, `monitor realm`
        refusing with the counts and creating nothing, then the deletion of the
        public dashboard and the snapshot and the clean reads."""
        rc, out, _err = self.grafana_admin('reads')
        try:
            reads = json.loads(out) if rc == 0 else None
        except ValueError:
            reads = None
        blocked_ok = (rc == 0 and isinstance(reads, dict)
                      and reads.get('sso_settings_source') == 'system'
                      and reads.get('public_dashboards') == 1 and reads.get('snapshots') == 1)
        rc2, out2, err2 = self.krate('monitor', 'realm', timeout=300)
        text2 = out2 + err2
        refused_ok = (rc2 != 0 and 'Grafana carries state that realm mode hides from its API' in text2
                      and '1 public dashboard' in text2 and '1 snapshot' in text2)
        # "nothing created" (walk results.md U17 row): no realm.ini, the client secret still
        # empty, no secrets directory, no krate-grafana client in the realm.
        ini = os.path.join(self.mon_dir(), 'auth', 'realm.ini')
        secrets_dir = os.path.join(self.mon_dir(), 'auth', 'secrets')
        # krate-cli has user/group roles only; client inventory requires the
        # fixture's master admin (sso/identity.py CLI_ROLES).
        clients = self.master_kcadm().get('clients', 'clientId=krate-grafana') or []
        side_free = (not os.path.isfile(ini) and not os.path.isdir(secrets_dir)
                     and not self.mon_env_value('GRAFANA_OAUTH_CLIENT_SECRET') and not clients)
        pub = self.seed_state.get('public_uid')
        st1, _b = self.grafana_api('DELETE', '/api/dashboards/uid/p4dash1/public-dashboards/%s' % pub,
                                   auth=self.admin_basic())
        st2, _b = self.grafana_api('DELETE', '/api/snapshots/%s' % self.seed_state.get('snapshot_key'),
                                   auth=self.admin_basic())
        deletes_ok = st1 == 200 and st2 == 200
        rc3, out3, _e3 = self.grafana_admin('reads')
        try:
            clean = json.loads(out3) if rc3 == 0 else {}
        except ValueError:
            clean = {}
        clean_ok = (rc3 == 0 and clean.get('sso_settings_source') == 'system'
                    and clean.get('public_dashboards') == 0 and clean.get('snapshots') == 0)
        probes = [('reads_blocked', 'PASS' if blocked_ok else 'FAIL'),
                  ('refusal', 'PASS' if refused_ok else 'FAIL'),
                  ('no_side_effects', 'PASS' if side_free else 'FAIL'),
                  ('deletes', 'PASS' if deletes_ok else 'FAIL'),
                  ('reads_clean', 'PASS' if clean_ok else 'FAIL')]
        status, tokens = aggregate(probes)
        detail = ('reads system/1/1; monitor realm rc=%d "%s"; deleted public dashboard %s and '
                  'snapshot %s; reads system/0/0; walk: live4a logs 070-072'
                  % (rc2, ' '.join(text2.split())[:80], st1, st2))
        self.obs['U17'] = (status, '%s; %s' % (tokens, detail))
        log('setup: U17 observed (%s)' % status)
        if status != 'PASS':
            fail('U17 probes failed during setup: %s; %s' % (tokens, detail))

    @staticmethod
    def collision_pairs(output):
        """Read each CLI collision warning with its immediately following command."""
        lines = output.splitlines()
        pairs = []
        for index, line in enumerate(lines):
            match = re.search(r'Local Grafana user (\S+)(?: \([^)]*\))? holds the e-mail of realm user', line)
            if not match:
                continue
            command = lines[index + 1].strip() if index + 1 < len(lines) else ''
            expected = 'krate monitor grafana-user retire ' + match.group(1)
            pairs.append((match.group(1), command == expected))
        return pairs

    def setup_switch(self):
        """The realm switch of section 5 / walk section C (logs/102,105,110):
        monitor realm (clean), the collision list, retire p4-collide only,
        config set GRAFANA_AUTH_CONFIG=realm.ini, monitor up."""
        rc, out, err = self.krate('monitor', 'realm', timeout=300)
        text = out + err
        if rc != 0:
            raise RuntimeError('monitor realm failed (rc %d): %s' % (rc, ' '.join(text.split())[-240:]))
        # U19's observations (walk logs/102): both collide users are listed, each with
        # its retire command; U20's seed-token line (idempotent since 16e4203).
        collisions = [line.strip() for line in text.splitlines()
                      if 'holds the e-mail of realm user' in line]
        pairs = self.collision_pairs(text)
        seed_line = next((line.strip() for line in text.splitlines() if 'seed token' in line.lower()), '')
        self.obs['U19-collisions'] = collisions
        self.obs['U20-seed-line'] = seed_line
        if len(collisions) != 2 or sorted(pairs) != [('p4-collide', True), ('p4-collide-b', True)]:
            raise RuntimeError('monitor realm did not list both collide users with their retire '
                               'commands: %s; pairs=%s' % (collisions, pairs))
        rc, out, err = self.krate('monitor', 'grafana-user', 'retire', 'p4-collide', timeout=180)
        text = out + err
        if rc != 0 or 'Retired the local Grafana user p4-collide' not in text:
            raise RuntimeError('grafana-user retire p4-collide failed (rc %d): %s'
                               % (rc, text.strip()[-160:]))
        rc, out, err = self.grafana_admin('local-users')
        try:
            users = json.loads(out) if rc == 0 and out.strip() else []
        except ValueError:
            raise RuntimeError('grafana-admin.py local-users printed no JSON (rc %d)' % rc)
        by_login = {u['login']: u for u in users if isinstance(u, dict)}
        retired = by_login.get('p4-collide') or {}
        kept = by_login.get('p4-collide-b') or {}
        self.obs['U19-retire'] = (
            'PASS' if (retired.get('isDisabled') is True
                       and retired.get('email') == 'p4-collide+retired@invalid'
                       and kept.get('isDisabled') is False
                       and kept.get('email') == 'p4b@%s' % EMAIL_DOMAIN) else 'FAIL',
            'retire rc=0; p4-collide disabled with +retired@invalid, p4-collide-b untouched '
            '(walk: live4a log 105)')
        rc, out, err = self.krate('config', 'set', 'GRAFANA_AUTH_CONFIG=realm.ini')
        if rc != 0:
            raise RuntimeError('config set GRAFANA_AUTH_CONFIG=realm.ini failed (rc %d)' % rc)
        rc, out, err = self.krate('monitor', 'up', timeout=900)
        if rc != 0:
            raise RuntimeError('monitor up (realm mode) failed (rc %d): %s'
                               % (rc, (out + err).strip()[-240:]))
        log('setup: realm switch complete (monitor realm, retire, realm.ini, monitor up)')

    def setup_after(self):
        """After the switch (walk logs/113-115,160-161): the after hash with the
        seed token -> U18; the realm lifetimes -> U26's realm half; the U20 refusal
        sub-probe (meta stashed -> monitor up rc=1, nothing changed)."""
        token = self.seed_token()
        self.state_after = self.hash_state(token=token)
        self.obs['U18'] = self.compare_u18(self.state_before, self.state_after)
        realm = self.master_kcadm().call('get', 'realms/' + p2.REALM)
        try:
            data = json.loads(realm)
        except ValueError:
            raise RuntimeError('kcadm get realms/krate printed no JSON')
        max_hours = int(self.env.get('KEYCLOAK_SESSION_MAX_HOURS') or 8)
        idle_minutes = int(self.env.get('KEYCLOAK_SESSION_IDLE_MINUTES') or 15)
        realm_ok = (data.get('ssoSessionMaxLifespan') == max_hours * 3600
                    and data.get('ssoSessionIdleTimeout') == idle_minutes * 60)
        self.obs['U26-realm'] = ('PASS' if realm_ok else 'FAIL',
                                 'ssoSessionMaxLifespan=%s ssoSessionIdleTimeout=%s (walk: live4a log 160)'
                                 % (data.get('ssoSessionMaxLifespan'), data.get('ssoSessionIdleTimeout')))
        # U20's refusal sub-row (walk log 161): meta stashed -> monitor up refuses naming
        # krate monitor realm, no container changed. The renewal half runs in the U20 row.
        meta = os.path.join(self.mon_dir(), 'auth', 'secrets', 'grafana-seed.meta')
        stash = meta + '.stashed'
        before = self.mon_id_map()
        os.rename(meta, stash)
        try:
            rc, out, err = self.krate('monitor', 'up', timeout=600)
            text = out + err
        finally:
            os.rename(stash, meta)
        after = self.mon_id_map()
        refusal_ok = (rc != 0 and 'grafana-seed.meta is missing' in text
                      and 'krate monitor realm' in text and before == after)
        self.obs['U20-refusal'] = ('PASS' if refusal_ok else 'FAIL',
                                   'meta stashed: monitor up rc=%d, ids/StartedAt equal=%s '
                                   '(walk: live4a log 161)' % (rc, before == after))
        log('setup: after-switch observations recorded (U18, U26 realm half, U20 refusal)')

    @staticmethod
    def compare_u18(before, after):
        """U18's comparison (walk logs/114-115): stable hashes equal per category,
        per-uid dashboard hashes equal, volumes equal, users equal except exactly
        the retired p4-collide row (e-mail -> +retired@invalid, isDisabled -> true).

        Provenance note (lead, 2026-10-13): a `datasources` delta in a run that
        straddles commit 34d6ab6 is provenance-clean, not state drift — the Loki
        datasource's jsonData gained `manageAlerts: false` from the product's
        datasources.yml, re-applied at a later Grafana start. A single-candidate
        gate run cannot straddle it; if this probe ever fails, check that first."""
        probes = []
        for name in ('folders', 'alert-rules', 'contact-points', 'datasources'):
            same = before['categories'][name]['stable'] == after['categories'][name]['stable']
            probes.append((name, 'PASS' if same else 'FAIL'))
        probes.append(('dashboards', 'PASS' if before['dashboards'] == after['dashboards'] else 'FAIL'))
        probes.append(('volumes', 'PASS' if before['volumes'] == after['volumes'] else 'FAIL'))
        before_rows = {row[0]: row for row in before['users']}
        after_rows = {row[0]: row for row in after['users']}
        diffs = []
        users_ok = set(before_rows) == set(after_rows)
        for uid in sorted(set(before_rows) & set(after_rows)):
            b, a = before_rows[uid], after_rows[uid]
            if b == a:
                continue
            if (b[1] == 'p4-collide' and a[1] == 'p4-collide' and a[0] == b[0]
                    and a[2] == 'p4-collide+retired@invalid' and a[3] == b[3]
                    and a[4] is True and b[4] is False):
                continue  # exactly the retired row (walk log 115's verdict)
            users_ok = False
            diffs.append('%s->%s' % (b, a))
        probes.append(('users', 'PASS' if users_ok else 'FAIL'))
        status, tokens = aggregate(probes)
        detail = ('%d categories + dashboards per-uid + %d volumes stable-equal; users equal except '
                  'the retired p4-collide row%s; walk: live4a logs 061,113-115'
                  % (len(before['categories']), len(before['volumes']),
                     ('' if users_ok else '; unexpected diffs: %s' % diffs[:2])))
        return status, '%s; %s' % (tokens, detail)

    # ── encoded rows (each probe cites its walk log) ──

    def u1(self):
        # walk logs/120,122: authstart query + the login page's boot data.
        d = self.driver('u1')
        status, hdrs, _text = d.req(self.base + '/grafana/login/generic_oauth')
        location = hdrs.get('Location', '')
        auth_base = self.base + '/identity/realms/krate/protocol/openid-connect/auth'
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)

        def one(key):
            values = query.get(key) or ['']
            return values[0]

        authstart_ok = (status == 302 and location.split('?')[0] == auth_base
                        and one('client_id') == 'krate-grafana'
                        and one('redirect_uri') == self.base + '/grafana/login/generic_oauth'
                        and one('scope') == 'openid profile email'
                        and one('response_type') == 'code'
                        and one('code_challenge_method') == 'S256')
        st2, _h2, page = d.req(self.base + '/grafana/login')
        password_fields = len(re.findall(r'<input[^>]+type=["\']?password', page, re.I))
        page_ok = (st2 == 200 and password_fields == 0
                   and '"generic_oauth":{"icon":"signin","name":"Krate sign-in"}' in page
                   and 'disableLoginForm":true' in page and '"version":""' in page
                   and len(re.findall(r'Krate sign-in', page)) == 1)
        probes = [('authstart', 'PASS' if authstart_ok else 'FAIL'),
                  ('login_page', 'PASS' if page_ok else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; authorize %s client_id=%s scope=%r pkce=%s; login page: %d password ' \
                       'fields, one provider, disableLoginForm, blank version; walk: live4a 120,122' \
               % (tokens, 'ok' if authstart_ok else location[:60], one('client_id'),
                  one('scope'), one('code_challenge_method'), password_fields)

    def u2(self):
        # walk log/121: 400 / 401 / 200 with the messageId evidence.
        admin_pw = self.monitor_env.get('GRAFANA_PASSWORD') or ''
        self.add_runtime_secret(admin_pw)
        d = self.driver('u2')
        st1, _h1, body1 = d.req(self.base + '/grafana/login',
                                data=json.dumps({'user': self.admin_basic()[0], 'password': admin_pw}).encode(),
                                method='POST', headers={'Content-Type': 'application/json'})
        post_ok = st1 == 400 and 'auth.client.notConfigured' in body1
        st2, _h2, body2 = d.req(self.base + '/grafana/api/user', method='GET',
                                headers={'Authorization': 'Basic ' + base64.b64encode(
                                    ('%s:%s' % (self.admin_basic()[0], admin_pw)).encode()).decode()})
        basic_ok = st2 == 401
        token = self.seed_token()
        st3, _h3, body3 = d.req(self.base + '/grafana/api/org', method='GET',
                                headers={'Authorization': 'Bearer ' + token})
        bearer_ok = st3 == 200 and 'Main Org.' in body3
        probes = [('post_login_400', 'PASS' if post_ok else 'FAIL'),
                  ('basic_401', 'PASS' if basic_ok else 'FAIL'),
                  ('bearer_200', 'PASS' if bearer_ok else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; POST /grafana/login %s, Basic /api/user %s, seed Bearer /api/org %s; ' \
                       'walk: live4a 121' % (tokens, st1, st2, st3)

    def _user_json(self, driver):
        st, body = self.api_json(driver, 'GET', '/grafana/api/user')
        if st != 200 or not isinstance(body, dict):
            fail('/grafana/api/user answered %s' % st)
        st2, orgs = self.api_json(driver, 'GET', '/grafana/api/user/orgs')
        role = orgs[0].get('role') if st2 == 200 and isinstance(orgs, list) and orgs else None
        return body, role

    def u3(self):
        # walk logs/123-125: role mapping of real sign-ins (fresh sign-in per user).
        expect = {'p4v': 'Viewer', 'p4a2': 'Admin', BOTH_USER: 'Admin'}
        probes = []
        notes = []
        for user in ('p4v', 'p4a2', BOTH_USER):
            result = self.signin(user, 'u3-' + user, expect='ok')
            me, role = self._user_json(result['driver'])
            sub = self.master_kcadm().user_id(user)
            ok = (role == expect[user] and me.get('isGrafanaAdmin') is False
                  and me.get('login') == sub and me.get('isExternal') is True)
            probes.append((user, 'PASS' if ok else 'FAIL'))
            notes.append('%s:%s(id %s,login=sub:%s,gAdmin:%s)' % (user, role, me.get('id'),
                                                                  me.get('login') == sub,
                                                                  me.get('isGrafanaAdmin')))
        status, tokens = aggregate(probes)
        return status, '%s; %s; walk: live4a 123-125' % (tokens, ' '.join(notes))

    def u4(self):
        # walk logs/125-126: refusal message (boot data) + no user row.
        result = self.signin('p4nogroup', 'u4', expect='refused')
        refused_ok = result['kind'] == 'REFUSED' \
            and 'IdP did not return a role attribute' in (result['error'] or '')
        sub = self.master_kcadm().user_id('p4nogroup')
        users = self.grafana_read('/api/org/users', token=self.seed_token())
        rows = users if isinstance(users, list) else []
        absent = not any(u.get('login') in ('p4nogroup', sub) for u in rows if isinstance(u, dict))
        probes = [('refusal', 'PASS' if refused_ok else 'FAIL'),
                  ('no_user_row', 'PASS' if absent else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; loginError=%r; org users without p4nogroup/sub: %s; walk: live4a 125-126' \
               % (tokens, (result['error'] or '')[:60], absent)

    def u5(self):
        # walk logs/126,127,127b,128: InternalError + the /userinfo/emails 404 in the
        # Grafana log + set-email recovery (the driver waits for the next TOTP step,
        # the method of the clean retry 127b; 127's first retry collided on a step).
        result = self.signin(NOEMAIL_USER, 'u5-refused', expect='refused')
        refused_ok = result['kind'] == 'REFUSED' and result['error'] == 'InternalError'
        logs = self.grafana_logs()
        log_ok = any('Error getting email address' in line and '/openid-connect/userinfo/emails' in line
                     and '404' in line for line in logs.splitlines())
        rc, out, err = self.krate('identity', 'users', 'set-email', NOEMAIL_USER,
                                  '%s@%s' % (NOEMAIL_USER, EMAIL_DOMAIN), timeout=180)
        email_ok = rc == 0
        recovered = False
        role = None
        if email_ok:
            time.sleep(2)
            result2 = self.signin(NOEMAIL_USER, 'u5-ok', expect='ok')
            _me, role = self._user_json(result2['driver'])
            recovered = result2['kind'] == 'OK' and role == 'Viewer'
        probes = [('refused_internalerror', 'PASS' if refused_ok else 'FAIL'),
                  ('log_emails_404', 'PASS' if log_ok else 'FAIL'),
                  ('set_email', 'PASS' if email_ok else 'FAIL'),
                  ('recovery_viewer', 'PASS' if recovered else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; loginError=%r; set-email rc=%d; after: role=%s; walk: live4a 126-128' \
               % (tokens, result['error'], rc, role)

    def u6(self):
        # walk log/128: five Viewer 403s + the Admin datasource control (deleted after).
        result = self.signin('p4v', 'u6-viewer', expect='ok')
        probes = []
        statuses = []
        for name in ('dashboard_save', 'folder_create', 'datasource_create', 'alert_rule_create'):
            path, body = U6_WRITE_BODIES[name]
            st, _b = self.api_json(result['driver'], 'POST', path, body,
                                   headers={'X-Disable-Provenance': 'true'})
            probes.append((name, 'PASS' if st == 403 else 'FAIL'))
            statuses.append('%s=%s' % (name, st))
        st, _b = self.api_json(result['driver'], 'GET', '/grafana/api/users')
        probes.append(('users_read', 'PASS' if st == 403 else 'FAIL'))
        statuses.append('users_read=%s' % st)
        admin = self.signin('p4a2', 'u6-admin', expect='ok')
        st, body = self.api_json(admin['driver'], 'POST', '/grafana/api/datasources',
                                 {'name': 'p4-u6-ds', 'type': 'prometheus',
                                  'url': 'http://prometheus:9090', 'access': 'proxy',
                                  'jsonData': {'httpMethod': 'POST'}})
        control_ok = st == 200
        uid = None
        if isinstance(body, dict):
            uid = (body.get('datasource') or {}).get('uid')
        deleted = None
        if control_ok and uid:
            deleted, _b = self.api_json(admin['driver'], 'DELETE', '/grafana/api/datasources/uid/' + uid)
            control_ok = deleted == 200
        probes.append(('admin_control', 'PASS' if control_ok else 'FAIL'))
        statuses.append('admin_ds=%s(cleanup %s)' % (st, deleted))
        status, tokens = aggregate(probes)
        return status, '%s; %s; walk: live4a 128' % (tokens, ' '.join(statuses))

    def u8(self):
        # walk log/131: lifecycle off, admin API off, remote-write off, Prometheus alive.
        mon = self.mon_container('prometheus')
        if not mon:
            not_run('precondition: no prometheus container in ' + self.monitor_project)
        rc, before, _ = p2.docker('inspect', '--format', '{{.State.Status}} {{.RestartCount}} {{.State.StartedAt}}', mon)
        result = self.signin('p4v', 'u8', expect='ok')
        d = result['driver']
        res = '/grafana/api/datasources/uid/prometheus/resources'

        def count_up():
            st, _h, text = d.req(self.base + res + '/api/v1/query?query=' + urllib.parse.quote('count(up)'))
            try:
                data = json.loads(text)
                return data['data']['result'][0]['value'][1]
            except (ValueError, KeyError, IndexError):
                return None

        up_before = count_up()
        probes = [('count_before', 'PASS' if up_before is not None else 'FAIL')]
        st, _h, body = d.req(self.base + res + '/-/reload', data=b'', method='POST')
        probes.append(('reload_403', 'PASS' if st == 403 and 'Lifecycle API is not enabled.' in body else 'FAIL'))
        st, _h, body = d.req(self.base + res + '/-/quit', data=b'', method='POST')
        probes.append(('quit_403', 'PASS' if st == 403 and 'Lifecycle API is not enabled.' in body else 'FAIL'))
        st, _h, body = d.req(self.base + res + '/api/v1/admin/tsdb/delete_series?match[]=up',
                             data=b'', method='POST')
        probes.append(('delete_series_non2xx', 'PASS' if st >= 400 and 'admin APIs disabled' in body else 'FAIL'))
        st, _h, body = d.req(self.base + res + '/api/v1/write', data=b'', method='POST')
        probes.append(('write_non2xx', 'PASS' if st >= 400 and 'remote write receiver' in body else 'FAIL'))
        rc2, after, _ = p2.docker('inspect', '--format', '{{.State.Status}} {{.RestartCount}} {{.State.StartedAt}}', mon)
        same = rc2 == 0 and before.split()[0] == 'running' and before == after
        probes.append(('prometheus_unchanged', 'PASS' if same else 'FAIL'))
        up_after = count_up()
        probes.append(('count_unchanged', 'PASS' if up_before is not None and up_after == up_before else 'FAIL'))
        status, tokens = aggregate(probes)
        return status, '%s; reload/quit 403 "Lifecycle API is not enabled.", delete_series/write ' \
                       'non-2xx, prometheus %s, count(up) %s->%s; walk: live4a 131' \
               % (tokens, 'unchanged' if same else before + '/' + after, up_before, up_after)

    def u16(self):
        # walk log/140: no x509 in the log; CA-removal negative control; restore.
        # The walk used p4noemail (post-U5); the gate uses p4v so the row stays
        # independent of U5's outcome (deviation recorded in the evidence).
        cid = self.grafana_container()
        before = self.grafana_logs().count('x509: certificate signed by unknown authority')
        ini = os.path.join(self.mon_dir(), 'auth', 'realm.ini')
        with open(ini, encoding='utf-8') as handle:
            original = handle.read()
        stripped = '\n'.join(line for line in original.splitlines()
                             if not line.strip().startswith('tls_client_ca')) + '\n'
        if stripped == original:
            fail('realm.ini has no tls_client_ca line to remove')
        with open(ini, 'w', encoding='utf-8') as handle:
            handle.write(stripped)
        try:
            p2.docker('restart', cid, timeout=180)
            healthy = self._wait_grafana_healthy(cid)
            refused = self.signin('p4v', 'u16-noca', expect='refused')
            refused_ok = refused['kind'] == 'REFUSED' \
                and 'Failed to get token from provider' in (refused['error'] or '')
            logs = self.grafana_logs()
            induced = logs.count('x509: certificate signed by unknown authority')
            x509_ok = induced == before + 1 and 'failed to exchange code to token' in logs
        finally:
            with open(ini, 'w', encoding='utf-8') as handle:
                handle.write(original)
            p2.docker('restart', cid, timeout=180)
            healthy2 = self._wait_grafana_healthy(cid)
        recovered = False
        clean = False
        if healthy2:
            ok = self.signin('p4v', 'u16-restored', expect='ok')
            recovered = ok['kind'] == 'OK'
            clean = self.grafana_logs().count('x509: certificate signed by unknown authority') == before + 1
        probes = [('no_x509_before', 'PASS' if before == 0 else 'FAIL'),
                  ('restart_healthy', 'PASS' if healthy and healthy2 else 'FAIL'),
                  ('refused_without_ca', 'PASS' if refused_ok else 'FAIL'),
                  ('x509_logged_once', 'PASS' if x509_ok else 'FAIL'),
                  ('restored_signin', 'PASS' if recovered else 'FAIL'),
                  ('no_new_x509', 'PASS' if clean else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; x509 lines 0 -> 1 (induced) -> 1; sign-in p4v (walk used p4noemail); ' \
                       'walk: live4a 140' % tokens

    def _wait_grafana_healthy(self, cid, limit=180):
        waited = 0
        while waited < limit:
            rc, out, _ = p2.docker('inspect', '-f', '{{.State.Health.Status}}', cid)
            if rc == 0 and out.strip() == 'healthy':
                return True
            time.sleep(3)
            waited += 3
        return False

    def _wait_container_healthy(self, cid, limit=180):
        t0 = time.monotonic()
        while time.monotonic() - t0 < limit:
            rc, out, _ = p2.docker('inspect', '-f', '{{.State.Health.Status}}', cid)
            if rc == 0 and out.strip() == 'healthy':
                return time.monotonic() - t0
            time.sleep(2)
        return None

    def u19(self):
        # walk logs/102,105 (setup obs) + 123,126: B refused, V fresh, content kept.
        collisions = self.obs.get('U19-collisions') or []
        listed_ok = len(collisions) == 2
        retire_status, retire_text = self.obs.get('U19-retire', ('NOT_RUN', 'retire not observed'))
        b = self.signin('p4b', 'u19-b', expect='refused')
        b_ok = b['kind'] == 'REFUSED' and 'User sync failed' in (b['error'] or '')
        v = self.signin('p4v', 'u19-v', expect='ok')
        me, role = self._user_json(v['driver'])
        collide_id = (self.seed_state.get('p4-collide') or {}).get('id')
        v_ok = (me.get('id') != collide_id and role == 'Viewer'
                and me.get('email') == 'p4v@%s' % EMAIL_DOMAIN)
        kept = bool(self.state_after and self.state_before
                    and 'p4collided' in self.state_after['dashboards']
                    and self.state_after['dashboards'].get('p4collided')
                    == self.state_before['dashboards'].get('p4collided'))
        folders = self.grafana_read('/api/folders?limit=1000', token=self.seed_token())
        kept = kept and isinstance(folders, list) and any(f.get('uid') == 'p4collidef' for f in folders)
        probes = [('collisions_listed', 'PASS' if listed_ok else 'FAIL'),
                  ('retire_selective', retire_status),
                  ('b_sync_failed', 'PASS' if b_ok else 'FAIL'),
                  ('v_fresh_viewer', 'PASS' if v_ok else 'FAIL'),
                  ('content_kept', 'PASS' if kept else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; both collisions listed with retire commands; only p4-collide retired; ' \
                       'p4b "User sync failed"; p4v new id %s (was %s) Viewer; folder+dashboard kept; ' \
                       'walk: live4a 102,105,114,123,126' % (tokens, me.get('id'), collide_id)

    def u20(self):
        # walk logs/135-139 (creation/CRUD/renewal), 101-102 (files), 161 (refusal, setup obs).
        secrets_dir = os.path.join(self.mon_dir(), 'auth', 'secrets')
        token_file = os.path.join(secrets_dir, 'grafana-seed.token')
        meta_file = os.path.join(secrets_dir, 'grafana-seed.meta')
        modes_ok = (os.path.isdir(secrets_dir) and os.stat(secrets_dir).st_mode & 0o777 == 0o700
                    and os.stat(token_file).st_mode & 0o777 == 0o600
                    and os.stat(meta_file).st_mode & 0o777 == 0o600
                    and self.mon_env_value('GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE')
                    == 'auth/secrets/grafana-seed.token')
        rc, out, err = self.grafana_admin('service-account', '--name', 'krate-seed', '--role', 'Admin')
        acct_rc = rc
        acct_note = ' '.join((err or '').split())[-80:]
        account = json.loads(out) if rc == 0 else {}
        account_id = account.get('id')
        token = self.seed_token()
        rc, out, err = self.grafana_admin('token-list', '--account-id', str(account_id), token=token)
        list_rc = rc
        tokens = json.loads(out) if rc == 0 else []
        creation_ok = False
        old_id = None
        list_n = len(tokens) if isinstance(tokens, list) else -1
        name_ok = ttl_delta = None
        if isinstance(tokens, list) and len(tokens) == 1 and isinstance(tokens[0], dict):
            entry = tokens[0]
            old_id = entry.get('id')
            match = re.fullmatch(r'krate-seed-(\d{8}T\d{6})', entry.get('name') or '')
            name_ok = bool(match)
            if match and entry.get('expiration'):
                created = calendar.timegm(time.strptime(match.group(1), '%Y%m%dT%H%M%S'))
                expires = calendar.timegm(time.strptime(entry['expiration'], '%Y-%m-%dT%H:%M:%SZ'))
                ttl_delta = expires - created
                creation_ok = ttl_delta == 7776000
        meta = self.seed_meta()
        meta_match = meta.get('id') == str(old_id)
        creation_ok = creation_ok and meta_match
        # Read-only role evidence: the search DTO carries the org role, so a
        # refusal names the drift without printing any secret value.
        sa_role = '?'
        st_sa, sa_body = self.grafana_api('GET', '/grafana/api/serviceaccounts/search?query=krate-seed',
                                          auth=self.admin_basic())
        if st_sa == 200 and isinstance(sa_body, dict):
            for cand in sa_body.get('serviceAccounts') or []:
                if isinstance(cand, dict) and cand.get('name') == 'krate-seed':
                    sa_role = cand.get('role', '?')
        else:
            sa_role = 'search-%d' % st_sa
        rc, out, err = p2.run([sys.executable, os.path.join(self.mon_dir(), 'seed-alerting.py'),
                               os.path.join(self.mon_dir(), '.env')], timeout=300)
        seeding_ok = rc == 0 and 'Grafana alerting ready' in (out + err)
        # provisioning CRUD through the public route with the token (walk 136)
        st, _h, body = self.public_api('GET', '/grafana/api/v1/provisioning/alert-rules', token=token)
        rules = json.loads(body) if st == 200 else []
        crud = [st == 200 and isinstance(rules, list) and len(rules) >= 15]
        rule = {'uid': 'p4-u20-rule', 'title': 'P4U20Rule', 'folderUID': 'p4foldera',
                'ruleGroup': 'P4 u20', 'orgId': 1, 'condition': 'B', 'for': '0s',
                'noDataState': 'OK', 'execErrState': 'Error',
                'data': [{'refId': 'A', 'relativeTimeRange': {'from': 600, 'to': 0},
                          'datasourceUid': 'prometheus',
                          'model': {'refId': 'A', 'expr': 'sum(up)', 'instant': True,
                                    'datasource': {'type': 'prometheus', 'uid': 'prometheus'}}}]}
        prov = {'X-Disable-Provenance': 'true'}
        st, _h, _b = self.public_api('POST', '/grafana/api/v1/provisioning/alert-rules',
                                     token=token, body=rule, headers=prov)
        crud.append(st == 201)
        rule['title'] = 'P4U20Rule-updated'
        st, _h, _b = self.public_api('PUT', '/grafana/api/v1/provisioning/alert-rules/p4-u20-rule',
                                     token=token, body=rule, headers=prov)
        crud.append(st == 200)
        st, _h, _b = self.public_api('DELETE', '/grafana/api/v1/provisioning/alert-rules/p4-u20-rule',
                                     token=token, headers=prov)
        crud.append(st == 204)
        st, _h, _b = self.public_api('GET', '/grafana/api/v1/provisioning/alert-rules/p4-u20-rule',
                                     token=token)
        crud.append(st == 404)
        crud_ok = all(crud)
        # renewal (walk 137-139): the gate creates the 29-day successor with the current
        # token, writes token+meta the way commit 4 does, deletes the 90-day id; monitor up
        # then creates the 90-day successor and the 29-day id is gone.
        renewal_ok = successor_ok = False
        new_id = new_key = None
        rc, out, err = self.grafana_admin('token-create', '--account-id', str(account_id),
                                          '--days', '29', token=token)
        try:
            created = json.loads(out) if rc == 0 else {}
        except ValueError:
            created = {}
        if rc == 0 and created.get('key') and created.get('id'):
            new_id, new_key = created['id'], created['key']
            self.add_runtime_secret(new_key)
            fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as handle:
                handle.write(new_key + '\n')
            fd = os.open(meta_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as handle:
                handle.write('id=%s\nexpires=%s\n' % (created['id'], created['expires']))
            rc, out, err = self.grafana_admin('token-delete', '--account-id', str(account_id),
                                              '--token-id', str(old_id), token=new_key)
            deleted_ok = rc == 0 and '"deleted"' in out
            rc, out, err = self.grafana_admin('token-list', '--account-id', str(account_id), token=new_key)
            listed = json.loads(out) if rc == 0 else []
            only29 = isinstance(listed, list) and [t.get('id') for t in listed] == [new_id]
            ids_before = self.long_running(self.mon_id_map())
            rc, out, err = self.krate('monitor', 'up', timeout=900)
            text = out + err
            renewed = (rc == 0 and 'Renewing the Grafana seed token' in text
                       and ('the previous one (id %s) is deleted' % new_id) in text)
            meta2 = self.seed_meta()
            successor = self.seed_token()
            rc, out, err = self.grafana_admin('token-list', '--account-id', str(account_id),
                                              token=successor)
            listed = json.loads(out) if rc == 0 else []
            ids = [t.get('id') for t in listed] if isinstance(listed, list) else []
            st, _h, _b = self.public_api('GET', '/grafana/api/org', token=successor)
            successor_ok = (renewed and meta2.get('id') not in (None, str(new_id))
                            and new_id not in ids and len(ids) == 1 and st == 200
                            and deleted_ok and only29
                            and self.long_running(self.mon_id_map()) == ids_before)
            renewal_ok, successor_ok = renewed, successor_ok
        refusal_status, refusal_text = self.obs.get('U20-refusal', ('NOT_RUN', 'refusal not observed'))
        probes = [('files', 'PASS' if modes_ok else 'FAIL'),
                  ('creation', 'PASS' if creation_ok else 'FAIL'),
                  ('seed_alerting', 'PASS' if seeding_ok else 'FAIL'),
                  ('crud', 'PASS' if crud_ok else 'FAIL'),
                  ('renewal', 'PASS' if renewal_ok else 'FAIL'),
                  ('successor', 'PASS' if successor_ok else 'FAIL'),
                  ('refusal', refusal_status)]
        status, tokens = aggregate(probes)
        return status, '%s; creation (acct rc %d role %s err %r, list rc %d n %d, ' \
                       'name %s, ttl %s, meta %s), CRUD %s, renewal %s/successor %s; %s; walk: live4a ' \
                       '101-102,135-139,161' % (tokens, acct_rc, sa_role, acct_note, list_rc,
                                                list_n, name_ok, ttl_delta, meta_match, crud,
                                                renewal_ok, successor_ok, refusal_text[:60])

    def u21a(self):
        # walk logs/111,122: loopback-only port, the anonymous surfaces, no data.
        cid = self.grafana_container()
        rc, out, _ = p2.docker('port', cid)
        port = self.monitor_env.get('GRAFANA_PORT') or '3000'
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        port_ok = bool(lines) and all(('127.0.0.1:' + port) in line and '0.0.0.0' not in line
                                      and '[::]' not in line for line in lines)
        st, _h, body = self.public_api('GET', '/grafana/metrics')
        metrics_ok = st in (302, 401, 403) and '# HELP' not in body and 'grafana_' not in body
        st2, _h2, body2 = self.public_api('GET', '/grafana/api/health')
        health_ok = st2 == 200 and '"version"' not in body2 and 'database' in body2
        st3, _h3, body3 = self.public_api('GET', '/grafana/healthz')
        healthz_ok = st3 == 200 and body3.strip() == 'Ok'
        st4, _h4, page4 = self.public_api('GET', '/grafana/login')
        asset = re.search(r'(public/build/[A-Za-z0-9._-]+\.js)', page4)
        asset_ok = False
        st5 = '-'
        if st4 == 200 and asset:
            st5, h5, body5 = self.public_api('GET', '/grafana/' + asset.group(1))
            asset_ok = st5 == 200 and len(body5) > 1000
        digest = hashlib.md5(b'admin@localhost').hexdigest()
        st6, h6, body6 = self.public_api('GET', '/grafana/avatar/' + digest)
        avatar_ok = st6 == 200 and ('image' in (h6.get('Content-Type') or '') or body6[:2] == '\xff\xd8')
        leak = any(marker in body3 + body2 for marker in ('"login"', 'datasource', '# HELP'))
        # The three anonymous surfaces must each be listed in table 2 of
        # monitoring/README.md: the `anonymous-https` rows landed in commit 11a23d5
        # (proxy:/grafana/healthz, proxy:/grafana/public/build/,
        # proxy:/grafana/avatar/<hash>), parsed from the README of the edition.
        surfaces = {'proxy:/grafana/healthz', 'proxy:/grafana/public/build/',
                    'proxy:/grafana/avatar/<hash>'}
        listed_targets = {t for s, t, _p in self.table2_rows() if s == 'anonymous-https'}
        listed = surfaces <= listed_targets
        probes = [('port_loopback', 'PASS' if port_ok else 'FAIL'),
                  ('metrics_hidden', 'PASS' if metrics_ok else 'FAIL'),
                  ('health_no_version', 'PASS' if health_ok else 'FAIL'),
                  ('healthz', 'PASS' if healthz_ok else 'FAIL'),
                  ('build_asset', 'PASS' if asset_ok else 'FAIL'),
                  ('avatar', 'PASS' if avatar_ok else 'FAIL'),
                  ('no_data', 'PASS' if not leak else 'FAIL'),
                  ('table2', 'PASS' if listed else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; port [%s]; metrics %s, health %s (no version), healthz %s, asset %s, ' \
                       'avatar %s; table2 anonymous-https rows %s; walk: live4a 111,122; list: ' \
                       'monitoring/README.md table 2 (commit 11a23d5)' \
               % (tokens, ' '.join(lines), st, st2, st3, st5, st6,
                  'complete' if listed else 'missing %s' % sorted(surfaces - listed_targets))

    def u21b(self):
        # walk log/142 (Mac method): the loopback-bound GRAFANA_PORT refused from the
        # Mac's LAN address over IPv4 and IPv6, with both controls. On Linux the VM
        # method probes the same published-port boundary from a foreign netns.
        if sys.platform != 'darwin':
            from phase4_linux import u21b_probe
            return u21b_probe(self.monitor_env.get('GRAFANA_PORT') or '3000',
                              self.monitor_env.get('PERSES_PORT') or '3443')
        port = self.monitor_env.get('GRAFANA_PORT') or '3000'
        perses_port = self.monitor_env.get('PERSES_PORT') or '3443'
        rc, out, _ = p2.run(['ifconfig'], timeout=30)
        lan4 = iface = None
        current = None
        linklocal_by_iface = {}
        for line in out.splitlines():
            if not line.startswith(('\t', ' ')):
                current = line.split(':', 1)[0]
            elif current and current.startswith('en'):
                m4 = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                m6 = re.search(r'inet6 (fe80::[0-9a-f:]+)%(\S+)', line)
                if m4 and lan4 is None:
                    lan4, iface = m4.group(1), current
                if m6:
                    linklocal_by_iface[current] = '%s%%%s' % (m6.group(1), m6.group(2))
        lan6 = linklocal_by_iface.get(iface)
        if not lan4:
            not_run('no LAN IPv4 address found on an en* interface (walk method, live4a 142)')

        def curl_rc(url, insecure=False):
            args = ['curl', '-s', '-o', '/dev/null', '--max-time', '8', '-w', '%{http_code}']
            if insecure:
                args.append('-k')
            rc, out, _err = p2.run(args + [url], timeout=30)
            return rc, out.strip()

        rc1, code1 = curl_rc('http://127.0.0.1:%s/api/health' % port)
        control1 = rc1 == 0 and code1 == '200'
        rc2, code2 = curl_rc('https://%s:%s/' % (lan4, perses_port), insecure=True)
        control2 = rc2 == 0 and code2 == '200'
        rc3, _c3 = curl_rc('http://%s:%s/' % (lan4, port))
        rc4, _c4 = curl_rc('http://[%s]:%s/' % (lan6, port)) if lan6 else (7, '')
        rc5, _c5 = curl_rc('http://[::1]:%s/' % port)
        probes = [('control_loopback', 'PASS' if control1 else 'FAIL'),
                  ('control_lan_published', 'PASS' if control2 else 'FAIL'),
                  ('ipv4_lan', 'PASS' if rc3 in (7, 28) else 'FAIL'),
                  ('ipv6_linklocal', 'PASS' if lan6 and rc4 in (7, 28) else ('NOT_RUN' if not lan6 else 'FAIL')),
                  ('ipv6_loopback', 'PASS' if rc5 in (7, 28) else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; %s:%s via LAN %s rc=%d, via %s rc=%d, [::1] rc=%d (controls %s/%s); ' \
                       'walk: live4a 142' % (tokens, 'grafana', port, lan4, rc3, lan6 or '-', rc4,
                                             rc5, code1, code2)

    def u26(self):
        # walk logs/160 (realm) + 104 (realm.ini): the static session defaults.
        realm_status, realm_text = self.obs.get('U26-realm', ('NOT_RUN', 'realm read not observed'))
        ini = os.path.join(self.mon_dir(), 'auth', 'realm.ini')
        text = ''
        try:
            with open(ini, encoding='utf-8') as handle:
                text = handle.read()
        except OSError:
            pass
        max_hours = int(self.env.get('KEYCLOAK_SESSION_MAX_HOURS') or 8)
        idle_minutes = int(self.env.get('KEYCLOAK_SESSION_IDLE_MINUTES') or 15)
        ini_max = re.search(r'^login_maximum_lifetime_duration\s*=\s*(\S+)\s*$', text, re.M)
        ini_idle = re.search(r'^login_maximum_inactive_lifetime_duration\s*=\s*(\S+)\s*$', text, re.M)
        max_ok = bool(ini_max) and ini_max.group(1) == '%dh' % max_hours
        idle_ok = bool(ini_idle) and ini_idle.group(1) == '%dm' % idle_minutes
        probes = [('realm', realm_status),
                  ('ini_max', 'PASS' if max_ok else 'FAIL'),
                  ('ini_idle', 'PASS' if idle_ok else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; %s; realm.ini %s/%s = KEYCLOAK_SESSION_MAX_HOURS=%d / ' \
                       'KEYCLOAK_SESSION_IDLE_MINUTES=%d; walk: live4a 160,104' \
               % (tokens, realm_text[:60], ini_max.group(1) if ini_max else '-',
                  ini_idle.group(1) if ini_idle else '-', max_hours, idle_minutes)

    def u28(self):
        # walk logs/133-134: the Admin-datasource residual, measured against table 2.
        result = self.signin('p4a2', 'u28-admin', expect='ok')
        d = result['driver']
        st, body = self.api_json(d, 'POST', '/grafana/api/datasources',
                                 {'name': 'p4-reach', 'type': 'prometheus', 'url': 'http://loki:3100',
                                  'access': 'proxy', 'jsonData': {'httpMethod': 'POST'}})
        uid = (body.get('datasource') or {}).get('uid') if isinstance(body, dict) else None
        if st != 200 or not uid:
            fail('p4-reach creation answered %s (no uid): the residual probe cannot run' % st)
        create_ok = True
        res = '/grafana/api/datasources/uid/%s/resources' % uid
        # reach 1: Loki through the raw datasource (bypassing the read-only gateway).
        # The JSON push answers 400 "snappy: corrupt input" — Loki-generated (walk 133).
        st1, _h1, body1 = d.req(self.base + res + '/loki/api/v1/push',
                                data=json.dumps({'streams': []}).encode(), method='POST',
                                headers={'Content-Type': 'application/json'})
        reached_loki = st1 == 400 and 'snappy: corrupt input' in body1
        # the stored-line half: the gate's snappy+protobuf WriteRequest (walk 134: 204 +
        # the line queryable through the read-only gateway). Rebuilt payload; a failure
        # here downgrades only the `stored` probe, never the reach verdict.
        runid = secrets.token_hex(4)
        line = 'u28 reach line %s stored' % runid
        payload = loki_push_body({'job': 'p4-u28-reach', 'source': 'u28-proto-gate'},
                                 line, time.time_ns())
        st2, _h2, _b2 = d.req(self.base + res + '/loki/api/v1/push', data=payload, method='POST',
                              headers={'Content-Type': 'application/x-protobuf'})
        stored = 'NOT_RUN'
        rq_note = ''
        if st2 == 204:
            time.sleep(3)
            # Walk results.md U28: the line is STORED by the push above and a
            # gateway query returns it; U7's controls prove this proxy path
            # 200s. The uid/.../resources query route answered 403 (rocky-4a
            # at 8036910), so the readback uses the walk's gateway query.
            loki_api = (self.base + '/grafana/api/datasources/proxy/uid/loki'
                        + '/loki/api/v1')
            now_q = int(time.time())
            st3, _h3, body3 = d.req(_loki_range_url(loki_api, '{job="p4-u28-reach"}',
                                                   now_q - 300, now_q))
            if not (st3 == 200 and runid in body3):
                time.sleep(10)  # single bounded retry: index lag, not encoding
                now_q = int(time.time())
                st3, _h3, body3 = d.req(_loki_range_url(loki_api, '{job="p4-u28-reach"}',
                                                       now_q - 300, now_q))
            stored = 'PASS' if (st3 == 200 and runid in body3) else 'FAIL'
            if stored == 'FAIL':
                rq_note = ' (rq %s %s)' % (st3, body3[:100])
        # reach 2: Kafbat's unauthenticated metrics through the repointed datasource.
        st4, body4 = self.api_json(d, 'PUT', '/grafana/api/datasources/uid/' + uid,
                                   {'name': 'p4-reach', 'type': 'prometheus', 'url': 'http://kafka-ui:8080',
                                    'access': 'proxy', 'jsonData': {'httpMethod': 'POST'}})
        repointed = st4 == 200
        st5, _h5, body5 = d.req(self.base + res + '/metrics')
        reached_kafbat = st5 == 200 and ('# HELP' in body5 or 'go_' in body5)
        st6, body6 = self.api_json(d, 'DELETE', '/grafana/api/datasources/uid/' + uid)
        st7, body7 = self.api_json(d, 'GET', '/grafana/api/datasources')
        names = [ds.get('name') for ds in body7] if isinstance(body7, list) else []
        deleted = st6 == 200 and 'p4-reach' not in names
        table = [(s, t, p) for s, t, p in self.table2_rows() if s == 'grafana-admin-datasource']
        listed = {(t, p) for _s, t, p in table}
        reached = set()
        if reached_loki:
            reached.add(('loki', '3100'))
        if reached_kafbat:
            reached.add(('kafka-ui', '8080'))
        table_ok = listed == {('loki', '3100'), ('kafka-ui', '8080')} and reached == listed
        viewer = self.signin('p4v', 'u28-viewer', expect='ok')
        st8, _b8 = self.api_json(viewer['driver'], 'POST', '/grafana/api/datasources',
                                 {'name': 'p4-u28-deny', 'type': 'prometheus',
                                  'url': 'http://loki:3100'})
        probes = [('create', 'PASS' if create_ok else 'FAIL'),
                  ('reach_loki', 'PASS' if reached_loki else 'FAIL'),
                  ('stored', stored),
                  ('reach_kafka_ui', 'PASS' if repointed and reached_kafbat else 'FAIL'),
                  ('deleted', 'PASS' if deleted else 'FAIL'),
                  ('table2_match', 'PASS' if table_ok else 'FAIL'),
                  ('viewer_ds_403', 'PASS' if st8 == 403 else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; loki push %s (Loki-generated), proto push %s stored=%s%s, kafka-ui ' \
                       'metrics %s, deleted %s, table2 %s vs reached %s; viewer POST ds %s; ' \
                       'walk: live4a 133-134' % (tokens, st1, st2, stored, rq_note, st5, deleted,
                                                 sorted(listed), sorted(reached), st8)

    # ── stub rows (bodies await their walk observations; rule 11) ──

    def u7(self):
        # walk logs 129-130 (at 379acf6), RE-MEASURED at c8c9337 (log 160) after
        # 34d6ab6/ee173ac changed monitoring/loki/gateway.conf — with the explicit
        # loki-gateway recreation anomaly 5 requires (gateway.conf content is not a
        # recreate trigger). Lead decision 2026-10-13: dd3a28d's gateway.conf change
        # is log-format-only (krate_loki), so the c8c9337 measurement stands; cite
        # that, no new re-run. The browser-side control (Explore and the dashboards'
        # Loki panels load, walk log 148) awaits the gate's browser batch (the
        # X3-shaped runner increment): `explore_panels` is NOT_RUN until then, so
        # the row is NOT_RUN by the worst-token rule — honestly, not silently.
        proxy = '/grafana/api/datasources/proxy/uid/loki/loki/api/v1'
        viewer = self.signin('p4v', 'u7-viewer', expect='ok')['driver']
        admin = self.signin('p4both', 'u7-admin', expect='ok')['driver']
        write_paths = (('/push', 'POST'), ('/delete', 'POST'), ('/config', 'GET'),
                       ('/../config', 'GET'), ('/flush', 'POST'),
                       ('/ingester/shutdown', 'POST'), ('/metrics', 'GET'),
                       ('/status/buildinfo', 'GET'))

        def refusals(d):
            bad = []
            for suffix, method in write_paths:
                st, _h, body = d.req(self.base + proxy + suffix,
                                     data=b'{}' if method == 'POST' else None, method=method,
                                     headers={'Content-Type': 'application/json'} if method == 'POST' else None)
                if not (st == 403 and 'nginx' in body.lower()):
                    bad.append('%s=%s' % (suffix, st))
            return bad

        v_bad = refusals(viewer)
        a_bad = refusals(admin)
        # the 34d6ab6 read location (re-measure 160: detected_field/<name>/values 200)
        st_det, _h, det_b = admin.req(self.base + proxy + '/detected_field/job/values')
        # controls (walk 130/160): labels 200, query_range 200, no forged line
        quote = urllib.parse.quote
        st_lab, _h, _b = viewer.req(self.base + proxy + '/labels')

        def query_range(start, end):
            return viewer.req(self.base + proxy + '/query_range?query=%s&start=%d&end=%d&limit=50'
                              % (quote('{job="containerlogs"}'), start, end))

        def newest(body):
            try:
                values = json.loads(body)['data']['result'][0]['values']
                return max(int(v[0]) for v in values)
            except (ValueError, KeyError, IndexError):
                return None

        now = int(time.time())
        st_q1, _h, b_q1 = query_range(now - 300, now)
        st_f, _h, b_f = viewer.req(_loki_range_url(self.base + proxy, '{job="p4-u7-forged"}',
                                                  now - 300, now))
        forged_absent = st_f == 200 and _empty_result(b_f)
        time.sleep(35)  # the walk's two samples 35 s apart: fluent-bit keeps shipping
        now2 = int(time.time())
        st_q2, _h, b_q2 = query_range(now2 - 60, now2)
        n1, n2 = newest(b_q1), newest(b_q2)
        fresh = st_q1 == 200 and st_q2 == 200 and n1 is not None and n2 is not None and n2 >= n1
        # Live tail upgrades to 101 through the gateway (walk 129/130/160, ws_probe method)
        head = self.ws_upgrade(viewer, proxy + '/tail?query=%s' % quote('{job="containerlogs"}'))
        tail_ok = ' 101 ' in head
        # The browser control (walk log 148, Admin p4both on the p4lokiui dashboard):
        # the Loki-logs dashboard renders rows with 0 panel errors, Explore loads rows,
        # Live tail streams over the /loki/api/v1/tail WebSocket — and the run is clean
        # (0 CSP violations, 0 page errors).
        batch = self.browser_batch()
        admin_run = batch.get('admin') or {}
        a_summary = admin_run.get('summary')
        a_steps = self.browser_steps(admin_run.get('steps') or [])
        dash_step = a_steps.get('dashboard loaded') or {}
        explore_step = a_steps.get('explore loki loaded') or {}
        live_step = a_steps.get('explore live tail 20 s') or {}
        explore_ok = (batch.get('problem') is None and a_summary is not None
                      and self.browser_clean(a_summary)
                      and dash_step.get('logRows', 0) > 0 and dash_step.get('panelErrorIcons', -1) == 0
                      and explore_step.get('logRows', 0) > 0 and live_step.get('liveRows', 0) > 0
                      and bool(self.browser_ws(a_summary, '/loki/api/v1/tail')))
        if batch.get('problem') is not None or a_summary is None:
            explore_status = 'NOT_RUN'
        else:
            explore_status = 'PASS' if explore_ok else 'FAIL'
        probes = [('viewer_writes_403', 'PASS' if not v_bad else 'FAIL'),
                  ('admin_writes_403', 'PASS' if not a_bad else 'FAIL'),
                  ('detected_field_read', 'PASS' if st_det == 200 else 'FAIL'),
                  ('controls', 'PASS' if st_lab == 200 and st_q1 == 200 else 'FAIL'),
                  ('forged_absent', 'PASS' if forged_absent else 'FAIL'),
                  ('fluent_bit_fresh', 'PASS' if fresh else 'FAIL'),
                  ('tail_101', 'PASS' if tail_ok else 'FAIL'),
                  ('explore_panels', explore_status)]
        status, tokens = aggregate(probes)
        det_note = '' if st_det == 200 else ' body=' + det_b[:120]
        forged_note = ' (query %s)' % st_f
        clean_note = a_summary is not None and self.browser_clean(a_summary)
        return status, '%s; detected_field read %s%s, tail %s len=%d, forged absent %s%s; ' \
                       '8 write/lifecycle paths 403-from-nginx for Viewer and Admin, ' \
                       'labels/query_range 200, fluent-bit fresh %s; browser control (p4lokiui rows %s, panel ' \
                       'errors %s, explore rows %s, live rows %s, clean=%s)%s; walk: live4a 129-130,148,160 ' \
                       '(re-measure at c8c9337; dd3a28d log-format-only per lead)' \
               % (tokens, st_det, det_note, head.split('\r\n')[0][:40], len(head),
                  forged_absent, forged_note, fresh,
                  dash_step.get('logRows', '-'), dash_step.get('panelErrorIcons', '-'),
                  explore_step.get('logRows', '-'), live_step.get('liveRows', '-'), clean_note,
                  (' — %s' % batch['problem']) if batch.get('problem') else '')

    def u9(self):
        if self.timed.started('U9'):
            return self.timed.join('U9', 1200)
        return self.stub('U9', 'WALKED PASS (log 151) — the timed body runs as a background '
                               'thread; it was not started (a precondition or --only selection '
                               'skipped the @start entry)')

    def _u9_keep_active(self, d, minutes):
        """Keep-alive requests on each minute boundary of a minutes-long activity
        window (walk log 151: 200 each). All six boundaries of the six-minute
        window are observed: the loop runs the real interval plus a short grace
        so the +360 s boundary is not skipped by the 5 s sleep cadence (Rocky 4a
        at bfd1158: only 5/6 keeps fit in `while < start+360`). The required
        count is unchanged. Returns the number of 200 answers."""
        start = time.monotonic()
        end = start + minutes * 60
        nxt = start + 60
        keeps = 0
        while time.monotonic() < end + 15 and keeps < minutes:
            if time.monotonic() >= nxt and nxt <= end:
                st, _msg = self.one_request(d)
                if st == 200:
                    keeps += 1
                nxt += 60
            time.sleep(5)
        return keeps

    def u9_body(self):
        """U9 (walk log 151, scripts/u9_job.py): case (a) immediate and case (b) after
        6 min of activity — the UI logout ends the Keycloak session (1 -> 0 after the
        walk's stale-session clear), the hop chain shows no confirmation page, the next
        authorize request shows the password form, and the old cookie answers 401."""
        cases = []
        for tag, minutes in (('a-immediate', 0), ('b-after-6min', 6)):
            clear_ok = self.force_logout('p4both')  # stale-SSO clear (lock-retrying)
            time.sleep(2)
            signed = self.signin('p4both', 'u9-' + tag, expect='ok')
            d = signed['driver']
            before = self.kc_session_ids('p4both')
            if len(before) != 1:
                # A stale session survived the clear (e.g. a refused logout under
                # lock contention with a concurrent timed row): retry once before
                # attributing anything to the product.
                clear_ok = self.force_logout('p4both')
                time.sleep(2)
                signed = self.signin('p4both', 'u9-' + tag + '-retry', expect='ok')
                d = signed['driver']
                before = self.kc_session_ids('p4both')
            if len(before) != 1 or not clear_ok:
                cases.append((tag, 'FAIL',
                              'stale-clear: %d Keycloak sessions before the logout test '
                              '(clear ok=%s)' % (len(before), clear_ok)))
                continue
            keeps = self._u9_keep_active(d, minutes) if minutes else 0
            if minutes:
                if keeps < minutes:
                    cases.append((tag, 'FAIL', 'only %d/%d keep-alive 200s' % (keeps, minutes)))
                    continue
            # GET /grafana/logout and follow the hop chain (walk: p4driver logout)
            url = self.base + '/grafana/logout'
            status, hdrs, page = d.req(url)
            saw_form = False
            confirmation = False
            for _ in range(8):
                location = hdrs.get('Location', '') if hasattr(hdrs, 'get') else ''
                if status in (302, 303) and location:
                    url = urllib.parse.urljoin(url, location)
                    status, hdrs, page = d.req(url)
                    continue
                if status == 200 and 'id="kc-form-login"' in page:
                    saw_form = True
                if status == 200 and 'kc-logout' in page and not saw_form:
                    confirmation = True
                break
            if not saw_form:
                # the end-session redirect can land on Grafana's own login page first
                # (walk X3 report (a)): the next authorize must then show the form.
                saw_form, _detail = self.authorize_shows_form()
            after = self.kc_session_ids('p4both')
            st_old, _msg = self.one_request(d)
            ok = (len(before) == 1 and not after and saw_form and not confirmation and st_old == 401)
            cases.append((tag, 'PASS' if ok else 'FAIL',
                          'sessions %d->%d form=%s confirmation=%s old-cookie=%s%s'
                          % (len(before), len(after), saw_form, confirmation, st_old,
                             (' keeps=%d' % keeps) if minutes else '')))
        probes = [('case_a', cases[0][1]), ('case_b', cases[1][1] if len(cases) > 1 else 'NOT_RUN')]
        status, tokens = aggregate(probes)
        return status, '%s; %s; walk: live4a 151' % (tokens, ' | '.join('%s: %s (%s)' % c for c in cases))

    def u10(self):
        if self.timed.started('U10'):
            return self.timed.join('U10', 700)
        return self.stub('U10', 'WALKED PASS (logs 152,152b) — the timed body runs as a '
                                'background thread; it was not started (it must follow U25, '
                                'which uses p4dis)')

    def u10_body(self):
        """U10 (walk logs 152,152b, scripts/u10_job.py): p4dis signed in, 10-s polling;
        at t0+30 s `identity users disable` + `identity users logout`; the first refusal
        is a 401 oauth.expired-token at token age >= 290 s (<= 330 s bound, FAIL beyond);
        a new sign-in while disabled is refused with "Account is disabled"; p4dis is
        re-enabled for later rows."""
        signed = self.signin('p4dis', 'u10', expect='ok')
        d = signed['driver']
        t0 = time.monotonic()
        revoked_at = None
        first_refusal = None
        next_poll = t0 + 10

        def _re_enable():
            # p4dis is owned state for later rows: restore it on every exit,
            # keeping the caller's primary error alongside the cleanup result.
            rc, _o, _e = self.krate_locked('identity', 'users', 'enable', 'p4dis', timeout=120)
            return rc

        while True:
            now = time.monotonic()
            if revoked_at is None and now >= t0 + 30:
                rc1, _o, _e = self.krate_locked('identity', 'users', 'disable', 'p4dis', timeout=120)
                rc2, _o, _e = self.krate_locked('identity', 'users', 'logout', 'p4dis', timeout=120)
                if rc1 != 0 or rc2 != 0:
                    rc3 = _re_enable()
                    return 'FAIL', 'disable/logout rc %s/%s; re-enable rc=%s' % (rc1, rc2, rc3)
                revoked_at = time.monotonic()
            if now >= next_poll:
                st, msg = self.one_request(d)
                log('U10 poll +%.1fs -> %s %r' % (now - t0, st, msg))
                if st != 200 and first_refusal is None:
                    first_refusal = (time.monotonic(), st, msg)
                next_poll += 10
            if first_refusal and time.monotonic() - first_refusal[0] > 30:
                break
            if now > t0 + 400:
                rc3 = _re_enable()
                return 'FAIL', 'still 200 at +400 s (the 330 s bound was exceeded); re-enable rc=%s' % rc3
            time.sleep(2)
        if revoked_at is None:
            return 'FAIL', 'refusal (%s %r) before disable+logout ran' % (first_refusal[1], first_refusal[2])
        since_revoke = first_refusal[0] - revoked_at
        try:
            self.signin('p4dis', 'u10b', expect='refused:Account is disabled')
            refused_ok = True
        except Outcome:
            refused_ok = False
        finally:
            rc3, _o, _e = self.krate_locked('identity', 'users', 'enable', 'p4dis', timeout=120)
        probes = [('first_401', 'PASS' if first_refusal[1] == 401 else 'FAIL'),
                  ('expired_token', 'PASS' if 'oauth.expired-token' in (first_refusal[2] or '') else 'FAIL'),
                  ('within_330s', 'PASS' if since_revoke <= 330 else 'FAIL'),
                  ('signin_disabled_refused', 'PASS' if refused_ok else 'FAIL'),
                  ('re_enabled', 'PASS' if rc3 == 0 else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; first refusal %.1f s after disable+logout: %s %r; sign-in while ' \
                       'disabled refused; p4dis re-enabled rc=%d; walk: live4a 152,152b' \
               % (tokens, since_revoke, first_refusal[1], first_refusal[2], rc3)

    def u11(self):
        if self.timed.started('U11'):
            return self.timed.join('U11', 700)
        return self.stub('U11', 'WALKED PASS (logs 153,153b) — the timed body runs as a '
                                'background thread; it was not started (it demotes p4a2, so it '
                                'must follow every p4a2-admin row: U3/U6/U28)')

    def u11_body(self):
        """U11 (walk logs 153,153b, scripts/u11_job.py): p4a2 live Admin session, 10-s
        polling; at t0+30 s the kcadm removal from KRATE_ADMINS + `identity users logout`;
        first refusal <= 300 s (walk: +291.6 s, 401 oauth.expired-token); KC sessions -> 0;
        the next sign-in is Viewer and a second fresh session is Viewer too. Premise from
        the walk's 153b correction: p4a2 is added to KRATE_VIEWERS FIRST (a user with no
        group at all would be refused with the U4 role-strict error instead). DEMOTES p4a2
        for the rest of the run — the plan entry runs it after U3/U6/U28."""
        kc = self.master_kcadm()
        viewer_group = self.env.get('KEYCLOAK_VIEWER_GROUP') or 'KRATE_VIEWERS'
        admin_group = self.env.get('KEYCLOAK_ADMIN_GROUP') or 'KRATE_ADMINS'
        viewer_gid = kc.group_id(viewer_group)
        admin_gid = kc.group_id(admin_group)
        uid = kc.user_id('p4a2')
        if not (viewer_gid and admin_gid and uid):
            return 'FAIL', 'precondition: group/user lookup failed (viewer %s, admin %s, uid %s)' \
                   % (viewer_gid, admin_gid, uid)
        groups = [g.get('name') for g in (kc.get('users/%s/groups' % uid) or [])]
        if viewer_group not in groups:
            kc.add_group(uid, viewer_gid)  # the row's premise (walk 153b)
        signed = self.signin('p4a2', 'u11', expect='ok')
        d = signed['driver']
        t0 = time.monotonic()
        st0, _m0 = self.one_request(d)
        if st0 != 200:
            return 'FAIL', 'the admin session did not answer 200 at t0 (%s)' % st0
        removed_at = None
        first_refusal = None
        next_poll = t0 + 10
        while True:
            now = time.monotonic()
            if removed_at is None and now >= t0 + 30:
                kc.remove_group(uid, admin_gid)
                rc, _o, _e = self.krate_locked('identity', 'users', 'logout', 'p4a2', timeout=120)
                if rc != 0:
                    return 'FAIL', 'identity users logout p4a2 rc=%d' % rc
                removed_at = time.monotonic()
            if now >= next_poll:
                st, msg = self.one_request(d)
                log('U11 poll +%.1fs -> %s %r' % (now - t0, st, msg))
                if st != 200 and first_refusal is None:
                    first_refusal = (time.monotonic(), st, msg)
                next_poll += 10
            if first_refusal and time.monotonic() - first_refusal[0] > 20:
                break
            if now > t0 + 400:
                return 'FAIL', 'still 200 at +400 s (the 300 s bound was exceeded)'
            time.sleep(2)
        if removed_at is None:
            return 'FAIL', 'refusal (%s %r) before the group removal ran' % (first_refusal[1], first_refusal[2])
        since_removal = first_refusal[0] - removed_at
        sessions_after = self.kc_session_ids('p4a2')
        next1 = self.signin('p4a2', 'u11b', expect='ok')
        st1, orgs1 = self.api_json(next1['driver'], 'GET', '/grafana/api/user/orgs')
        role1 = orgs1[0].get('role') if st1 == 200 and isinstance(orgs1, list) and orgs1 else None
        next2 = self.signin('p4a2', 'u11c', expect='ok')
        st2, orgs2 = self.api_json(next2['driver'], 'GET', '/grafana/api/user/orgs')
        role2 = orgs2[0].get('role') if st2 == 200 and isinstance(orgs2, list) and orgs2 else None
        probes = [('first_401', 'PASS' if first_refusal[1] == 401 else 'FAIL'),
                  ('within_300s', 'PASS' if since_removal <= 300 else 'FAIL'),
                  ('kc_sessions_zero', 'PASS' if not sessions_after else 'FAIL'),
                  ('next_signin_viewer', 'PASS' if role1 == 'Viewer' else 'FAIL'),
                  ('second_session_viewer', 'PASS' if role2 == 'Viewer' else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; first refusal %.1f s after removal+logout: %s %r; KC sessions %d; ' \
                       'roles %s/%s (p4a2 stays demoted for the rest of the run); walk: live4a ' \
                       '153,153b' % (tokens, since_removal, first_refusal[1], first_refusal[2],
                                      len(sessions_after), role1, role2)

    def u12(self):
        # walk logs/154,164: Keycloak stopped (502 authorize hop, live session first 401
        # within 300 s, grafana/proxy/kafka-ui RestartCount unchanged); Keycloak started
        # (healthy within 180s, signin OK within 60s without monitor up).
        kc_cid = self.cluster_container('keycloak')
        graf_cid = self.mon_container('grafana')
        proxy_cid = self.cluster_container('proxy')
        ui_cid = self.cluster_container('kafka-ui')
        if not kc_cid or not graf_cid or not proxy_cid or not ui_cid:
            not_run('precondition: missing required containers for outage test')

        # Live session before outage (p4ctrl)
        live = self.signin('p4ctrl', 'u12-live', expect='ok')
        st0, msg0 = self.one_request(live['driver'])
        if st0 != 200:
            fail('p4ctrl live session not working: %s %r' % (st0, msg0))

        def get_restarts(cid):
            rc, s, _ = p2.docker('inspect', '-f', '{{.RestartCount}}', cid)
            return int(s.strip()) if rc == 0 and s.strip().isdigit() else -1

        restarts_before = (get_restarts(graf_cid), get_restarts(proxy_cid), get_restarts(ui_cid))

        t_stop = time.monotonic()
        rc_stop, _, _ = p2.docker('stop', '-t', '5', kc_cid)
        if rc_stop != 0:
            fail('docker stop keycloak failed (rc=%d)' % rc_stop)

        time.sleep(3)
        # New sign-in during outage must fail closed (authorize hop -> 502 from cluster proxy)
        d_new = self.driver('u12-new')
        d_new.jar.clear()
        st_start, hdrs, _page = d_new.req(self.base + '/grafana/login/generic_oauth')
        loc = hdrs.get('Location', '')
        if st_start == 302 and loc:
            st_auth, _h2, _b2 = d_new.req(loc)
        else:
            st_auth = st_start

        # Live session polled every 10 s until refusal (bound 300 s)
        first_refusal = None
        t_poll = time.monotonic()
        while time.monotonic() - t_poll < 320:
            st, msg = self.one_request(live['driver'])
            if st != 200:
                first_refusal = (time.monotonic() - t_stop, st, msg)
                break
            time.sleep(10)

        restarts_after = (get_restarts(graf_cid), get_restarts(proxy_cid), get_restarts(ui_cid))
        restarts_ok = (restarts_before == restarts_after and -1 not in restarts_before)

        t_start = time.monotonic()
        rc_start, _, _ = p2.docker('start', kc_cid)
        healthy_secs = self._wait_container_healthy(kc_cid, limit=180)

        recov_ok = False
        t_recov_elapsed = -1.0
        recov_result = {'kind': 'FAIL'}
        if healthy_secs is not None:
            t_recov_start = time.monotonic()
            recov_result = self.signin('p4idle', 'u12-recov', expect='ok')
            t_recov_elapsed = time.monotonic() - t_recov_start
            recov_ok = (recov_result['kind'] == 'OK' and t_recov_elapsed <= 60.0)

        live_refused_ok = (first_refusal is not None and first_refusal[0] <= 300.0
                           and first_refusal[1] == 401)
        probes = [
            ('authorize_502', 'PASS' if st_auth == 502 else 'FAIL'),
            ('live_session_401', 'PASS' if live_refused_ok else 'FAIL'),
            ('restarts_unchanged', 'PASS' if restarts_ok else 'FAIL'),
            ('kc_healthy', 'PASS' if healthy_secs is not None else 'FAIL'),
            ('recovery_signin', 'PASS' if recov_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; Keycloak stopped: authorize %s, live session first 401 at %.1fs (%r), ' \
                       'restarts grafana/proxy/kafka-ui %s; Keycloak started: healthy +%ss, fresh signin %s ' \
                       'at +%.1fs (bound 60s); walk: live4a 154,164' \
               % (tokens, st_auth, first_refusal[0] if first_refusal else -1,
                  first_refusal[2] if first_refusal else '',
                  '%d/%d/%d' % restarts_before if restarts_ok else '%s!=%s' % (restarts_before, restarts_after),
                  '%.1f' % healthy_secs if healthy_secs is not None else 'timeout',
                  recov_result['kind'], t_recov_elapsed)

    def u13(self):
        # walk logs/154,164: Keycloak stopped >120s with grafana removed (`docker rm`):
        # `monitor up` exits rc=1 with grafana created-not-started (restarts=0), compose
        # output names `idp-wait` exit 1 and CLI warning lines from 6645087 ("Keycloak is
        # not running: the krate-grafana client is not reconciled now"); recovery `monitor up`
        # exits 0 with idp-wait exit 0 and grafana running, signin OK.
        kc_cid = self.cluster_container('keycloak')
        graf_cid = self.mon_container('grafana')
        if not kc_cid or not graf_cid:
            not_run('precondition: missing keycloak or grafana container')

        t_down = time.monotonic()
        rc_stop, _, _ = p2.docker('stop', '-t', '5', kc_cid)
        if rc_stop != 0:
            fail('docker stop keycloak failed (rc=%d)' % rc_stop)

        rc_rm, _, _ = p2.docker('rm', '-f', graf_cid)
        if rc_rm != 0:
            fail('docker rm -f grafana failed (rc=%d)' % rc_rm)

        elapsed = time.monotonic() - t_down
        if elapsed < 125:
            time.sleep(125 - elapsed)

        rc_up1, out_up1, err_up1 = self.krate('monitor', 'up', timeout=600)
        text_up1 = out_up1 + err_up1

        names_idp = ('idp-wait' in text_up1 and ('didn\'t complete successfully' in text_up1 or 'exit 1' in text_up1))
        warn_reconciled = 'Keycloak is not running: the krate-grafana client is not reconciled now' in text_up1

        graf_new = self.mon_container('grafana')
        rc_st, st_graf, _ = p2.docker('inspect', '-f', '{{.State.Status}} {{.RestartCount}}', graf_new) if graf_new else (1, '', '')
        graf_created_ok = (rc_st == 0 and st_graf.strip() == 'created 0')

        rc_start, _, _ = p2.docker('start', kc_cid)
        healthy_secs = self._wait_container_healthy(kc_cid, limit=180)
        if healthy_secs is None:
            fail('Keycloak did not recover healthy within 180 s')

        rc_up2, out_up2, err_up2 = self.krate('monitor', 'up', timeout=600)
        rc_st2, st_graf2, _ = p2.docker('inspect', '-f', '{{.State.Status}} {{.RestartCount}}', graf_new) if graf_new else (1, '', '')
        graf_running_ok = (rc_st2 == 0 and st_graf2.split()[0] == 'running')

        idp_cids = p2.docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + self.monitor_project,
                             '--filter', 'label=com.docker.compose.service=idp-wait')[1].split()
        idp_exit0 = False
        if idp_cids:
            rc_exit, code_s, _ = p2.docker('inspect', '-f', '{{.State.ExitCode}}', idp_cids[0])
            idp_exit0 = (rc_exit == 0 and code_s.strip() == '0')

        recov_result = self.signin('p4idle', 'u13-recov', expect='ok')
        signin_ok = (recov_result['kind'] == 'OK')

        probes = [
            ('outage_up_rc1', 'PASS' if rc_up1 == 1 else 'FAIL'),
            ('names_idp_wait', 'PASS' if names_idp else 'FAIL'),
            ('cli_warning', 'PASS' if warn_reconciled else 'FAIL'),
            ('grafana_created_restarts0', 'PASS' if graf_created_ok else 'FAIL'),
            ('recovery_up_rc0', 'PASS' if rc_up2 == 0 else 'FAIL'),
            ('grafana_running_idp_exit0', 'PASS' if (graf_running_ok and idp_exit0) else 'FAIL'),
            ('signin', 'PASS' if signin_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; monitor up during outage: rc=%d, idp-wait named: %s, warning: %s, ' \
                       'grafana %s; recovery monitor up: rc=%d, idp-wait exit 0: %s, grafana %s; ' \
                       'signin %s; walk: live4a 154,164' \
               % (tokens, rc_up1, names_idp, warn_reconciled, st_graf.strip(),
                  rc_up2, idp_exit0, st_graf2.strip() if graf_running_ok else 'not running',
                  recov_result['kind'])

    def u14(self):
        """Six live loopback refusals, each with a no-side-effect snapshot.

        The manual walk for this exact sequence is in
        harness/phase4/formal-r1/u14-live/results.md (candidate 54472fe).
        """
        original_url = p2.read_env(os.path.join(self.edition, '.env')).get('KEYCLOAK_PUBLIC_URL', '')
        original_mode = self.mon_env_value('GRAFANA_AUTH_CONFIG')
        if not original_url or original_mode != 'realm.ini' or not self.mon_container('grafana', all_states=False):
            not_run('precondition: public URL and running realm-mode Grafana are required')

        def snapshot():
            files = {}
            roots = (os.path.join(self.edition, 'certs'),
                     os.path.join(self.edition, 'auth'),
                     os.path.join(self.mon_dir(), 'auth'))
            paths = [os.path.join(self.edition, '.env'), os.path.join(self.mon_dir(), '.env')]
            for root in roots:
                if not os.path.isdir(root):
                    raise RuntimeError('U14 state root is missing: ' + root)
                for directory, _dirs, filenames in os.walk(root):
                    paths.extend(os.path.join(directory, filename) for filename in filenames)
            for path in paths:
                with open(path, 'rb') as handle:
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: handle.read(65536), b''):
                        digest.update(chunk)
                files[os.path.relpath(path, self.edition)] = (
                    digest.hexdigest(), os.stat(path).st_mode & 0o777)

            containers = []
            for project in (self.project, self.monitor_project):
                ps_rc, ps_out, ps_err = p2.docker('ps', '-aq', '--filter',
                                                  'label=com.docker.compose.project=' + project)
                if ps_rc != 0:
                    raise RuntimeError('U14 docker ps failed for %s: %s' % (project, ps_err[:120]))
                for cid in ps_out.split():
                    inspect_rc, detail, inspect_err = p2.docker(
                        'inspect', '--format',
                        '{{.Id}} {{.State.StartedAt}} {{index .Config.Labels "com.docker.compose.service"}}',
                        cid)
                    if inspect_rc != 0:
                        raise RuntimeError('U14 docker inspect failed: ' + inspect_err[:120])
                    containers.append((project, detail.strip()))
            if not containers:
                raise RuntimeError('U14 found no fixture containers')
            resources = []
            for kind in ('volume', 'network'):
                list_rc, list_out, list_err = p2.docker(kind, 'ls', '--format', '{{.Name}}')
                if list_rc != 0:
                    raise RuntimeError('U14 docker %s ls failed: %s' % (kind, list_err[:120]))
                resources.extend((kind, name) for name in list_out.split()
                                 if name.startswith(self.project + '_')
                                 or name.startswith(self.monitor_project + '_'))
            return files, tuple(sorted(containers)), tuple(sorted(resources))

        names = [(label + '_' + command, label, host, command, mode)
                 for label, host in (('localhost', 'localhost'),
                                     ('ipv4', '127.0.0.1'),
                                     ('ipv6', '[::1]'))
                 for command, mode in (('realm', 'local.ini'), ('up', 'realm.ini'))]
        outcomes = {name: 'NOT_RUN' for name, _label, _host, _command, _mode in names}
        observations = []
        problem = ''
        current_name = names[0][0]
        try:
            for name, _label, host, command, mode in names:
                current_name = name
                url = 'https://%s/identity' % host
                rc_set, _out, err = self.krate('config', 'set', 'KEYCLOAK_PUBLIC_URL=' + url)
                if rc_set != 0:
                    outcomes[name] = 'FAIL'
                    problem = 'setting U14 public URL failed (rc %d): %s' % (rc_set, err[-120:])
                    break
                rc_mode, _out, err = self.krate('config', 'set', 'GRAFANA_AUTH_CONFIG=' + mode)
                if rc_mode != 0:
                    outcomes[name] = 'FAIL'
                    problem = 'setting U14 Grafana mode failed (rc %d): %s' % (rc_mode, err[-120:])
                    break
                before = snapshot()
                rc, out, err = self.krate('monitor', command, timeout=120)
                after = snapshot()
                refusal = (rc != 0
                           and 'KEYCLOAK_PUBLIC_URL names the loopback or unspecified host' in out + err
                           and "host '%s'" % host in out + err)
                unchanged = before == after
                outcomes[name] = 'PASS' if refusal and unchanged else 'FAIL'
                observations.append('%s rc=%d refusal=%s unchanged=%s'
                                    % (name, rc, refusal, unchanged))
                if not unchanged:
                    problem = '%s changed fixture state' % name
                    break
        except Exception as error:
            outcomes[current_name] = 'FAIL'
            problem = 'U14 observation error %s: %s' % (type(error).__name__, str(error)[:160])
        finally:
            restore_url, err_url = -1, ''
            restore_mode, err_mode = -1, ''
            try:
                restore_url, _out, err_url = self.krate(
                    'config', 'set', 'KEYCLOAK_PUBLIC_URL=' + original_url)
            except Exception as error:
                err_url = '%s: %s' % (type(error).__name__, str(error)[:80])
            try:
                restore_mode, _out, err_mode = self.krate(
                    'config', 'set', 'GRAFANA_AUTH_CONFIG=' + original_mode)
            except Exception as error:
                err_mode = '%s: %s' % (type(error).__name__, str(error)[:80])
        try:
            restored = (restore_url == 0 and restore_mode == 0
                        and p2.read_env(os.path.join(self.edition, '.env')).get('KEYCLOAK_PUBLIC_URL')
                        == original_url
                        and self.mon_env_value('GRAFANA_AUTH_CONFIG') == original_mode)
        except OSError:
            restored = False
        outcomes['restored'] = 'PASS' if restored else 'FAIL'
        if not restored:
            problem += ' restore failed: url rc=%d %s; mode rc=%d %s' % (
                restore_url, err_url[-80:], restore_mode, err_mode[-80:])
        probes = [(name, outcomes[name]) for name, _label, _host, _command, _mode in names]
        probes.append(('restored', outcomes['restored']))
        status, tokens = aggregate(probes)
        details = [tokens]
        if problem:
            details.append(problem)
        details.extend(observations)
        details.append('live walk: u14-live/results.md')
        detail = '; '.join(details)
        if status == 'FAIL':
            self.record('U14', status, detail)
            log('U14 failed: stopping later rows because fixture state cannot be trusted')
            raise Terminated()
        return status, detail

    def u15(self):
        # walk log 132 (headless four) + 146/148 (browser `ui` half). The four
        # headless probes are encoded; `ui` (Home/dashboards/Explore with 0 CSP
        # violations and 0 page errors, container Chromium) awaits the gate's
        # browser batch — NOT_RUN until then (worst-token rule).
        signed = self.signin('p4v', 'u15-viewer', expect='ok')
        flow_ok = signed['callback_get'] == 302
        cookie = signed['set_cookie'] or ''
        max_seconds = int(self.env.get('KEYCLOAK_SESSION_MAX_HOURS') or 8) * 3600
        cookie_ok = all(marker in cookie for marker in
                        ('Path=/grafana', 'HttpOnly', 'Secure', 'SameSite=Lax',
                         'Max-Age=%d' % max_seconds))
        admin = self.signin('p4both', 'u15-admin', expect='ok')['driver']
        folder = {'uid': 'p4-u15-origin', 'title': 'p4 u15 origin'}
        st1, _b1 = self.api_json(admin, 'POST', '/grafana/api/folders', folder,
                                 headers={'Origin': self.base})
        st2, _b2 = self.api_json(admin, 'DELETE', '/grafana/api/folders/p4-u15-origin',
                                 headers={'Origin': self.base})
        st3, _h3, b3 = admin.req(self.base + '/grafana/api/folders',
                                 data=json.dumps(folder).encode(), method='POST',
                                 headers={'Content-Type': 'application/json',
                                          'Origin': 'https://evil.live4a.test'})
        origin_ok = st1 == 200 and st2 == 200 and st3 == 403 and 'origin not allowed' in b3
        if st3 != 403:  # clean up only when the foreign-Origin create unexpectedly passed
            self.api_json(admin, 'DELETE', '/grafana/api/folders/p4-u15-origin')
        head = self.ws_upgrade(admin, '/grafana/api/live/ws', subprotocol='grafana')
        ws_ok = ' 101 ' in head
        # The `ui` probe (walk log 146, Viewer p4v on krate-overview): Home, the
        # dashboards and Explore with 0 CSP violations + 0 page errors, live/ws
        # upgrades with frames on every page; the Viewer's Explore redirect to Home
        # is stock Grafana RBAC (walk log 147: `Access denied … datasources:explore`,
        # zero requests in the gateway access log for that window), not a failure.
        batch = self.browser_batch()
        viewer_run = batch.get('viewer') or {}
        v_summary = viewer_run.get('summary')
        v_steps = self.browser_steps(viewer_run.get('steps') or [])
        ui_ok = (batch.get('problem') is None and v_summary is not None
                 and self.browser_clean(v_summary)
                 and 'home loaded' in v_steps and 'dashboard loaded' in v_steps
                 and bool(self.browser_ws(v_summary, '/grafana/api/live/ws')))
        if batch.get('problem') is not None or v_summary is None:
            ui_status = 'NOT_RUN'
        else:
            ui_status = 'PASS' if ui_ok else 'FAIL'
        probes = [('flow', 'PASS' if flow_ok else 'FAIL'),
                  ('cookie', 'PASS' if cookie_ok else 'FAIL'),
                  ('origin', 'PASS' if origin_ok else 'FAIL'),
                  ('ws', 'PASS' if ws_ok else 'FAIL'),
                  ('ui', ui_status)]
        status, tokens = aggregate(probes)
        return status, '%s; callback GET %s; cookie [%s]; folder POST UI-Origin %s/%s, foreign ' \
                       'Origin %s "origin not allowed"; live/ws %s; ui: %d CSP violations, %d page ' \
                       'errors, live/ws frames on every page%s; walk: live4a 124,132,146,147' \
               % (tokens, signed['callback_get'],
                  re.sub(r'grafana_session=[^;]+', 'grafana_session=<redacted>', cookie)[:90],
                  st1, st2, st3, head.split('\r\n')[0][:30],
                  (v_summary or {}).get('cspViolations', -1), (v_summary or {}).get('pageErrors', -1),
                  (' — %s' % batch['problem']) if batch.get('problem') else '')

    def _mon_env_subset(self, cid):
        """Non-secret compose inputs on a monitor container (U22 evidence).

        Reads container env but returns only the allowlisted revision/IdP
        keys — never passwords, secrets or keys."""
        if not cid:
            return {}
        rc, out, _ = p2.docker('inspect', '-f',
                               '{{range .Config.Env}}{{println .}}{{end}}', cid)
        if rc != 0:
            return {}
        want = ('KRATE_RENDER_REVISION', 'KRATE_IDP_HOST', 'IDP_DISCOVERY_URL')
        found = {}
        for line in out.splitlines():
            key, sep, value = line.partition('=')
            if sep and key in want:
                found[key] = value
        return found

    def u22(self):
        # walk log 169 (clean cycle at HEAD 5d17495; note log 161 is fbfc872 defect evidence only):
        # Rollback probes: `config set GRAFANA_AUTH_CONFIG=local.ini` + `monitor up`: only grafana
        # recreated; local admin login 200 on loopback; six paths probed (/grafana/ -> 302,
        # /grafana/api/health -> 302, /grafana/api/user -> 302, /grafana/metrics -> 302,
        # /grafana/login -> 302, /grafana -> 301 carrying port); U18-style hash equality at rollback;
        # forward again with realm.ini + monitor up, signin OK.
        before_mon = self.mon_id_map()
        long_before = self.long_running(before_mon)
        if 'grafana' not in long_before:
            not_run('precondition: no grafana container before rollback')
        perses_before = self._mon_env_subset((before_mon.get('perses') or (None,))[0])

        rc1, out1, err1 = self.krate('config', 'set', 'GRAFANA_AUTH_CONFIG=local.ini', timeout=180)
        if rc1 != 0:
            fail('config set GRAFANA_AUTH_CONFIG=local.ini failed: %s' % (out1 + err1))

        rc2, out2, err2 = self.krate('monitor', 'up', timeout=600)
        if rc2 != 0:
            fail('monitor up after rollback failed: %s' % (out2 + err2))

        mid_mon = self.mon_id_map()
        long_mid = self.long_running(mid_mon)
        recreated = [s for s in long_before if s in long_mid and long_before[s][0] != long_mid[s][0]]
        only_grafana = (recreated == ['grafana'])
        perses_after = self._mon_env_subset((mid_mon.get('perses') or (None,))[0])

        graf_cid = (mid_mon.get('grafana') or (None,))[0]
        healthy = self._wait_grafana_healthy(graf_cid) if graf_cid else False

        # Local admin login 200 on loopback (/api/user and /login)
        port = self.mon_env_value('GRAFANA_PORT') or '13000'
        admin_user, admin_pw = self.admin_basic()
        loopback_base = 'http://127.0.0.1:%s' % port
        auth_hdr = 'Basic ' + base64.b64encode(('%s:%s' % (admin_user, admin_pw)).encode()).decode()

        st_user = -1
        try:
            req_u = urllib.request.Request(loopback_base + '/api/user', headers={'Authorization': auth_hdr})
            with urllib.request.urlopen(req_u, timeout=15) as resp:
                st_user = resp.status
        except urllib.error.HTTPError as err:
            st_user = err.code
        except Exception:
            pass

        st_login = -1
        try:
            req_l = urllib.request.Request(loopback_base + '/login',
                                           data=json.dumps({'user': admin_user, 'password': admin_pw}).encode(),
                                           headers={'Content-Type': 'application/json', 'Authorization': auth_hdr},
                                           method='POST')
            with urllib.request.urlopen(req_l, timeout=15) as resp:
                st_login = resp.status
        except urllib.error.HTTPError as err:
            st_login = err.code
        except Exception:
            pass

        local_admin_ok = (healthy and st_user == 200 and st_login == 200)

        # Six paths probed through cluster proxy (self.base)
        opener = urllib.request.build_opener(p2.NoRedirect, urllib.request.HTTPSHandler(context=self.tls))
        probe_paths = [
            ('/grafana/', 302),
            ('/grafana/api/health', 302),
            ('/grafana/api/user', 302),
            ('/grafana/metrics', 302),
            ('/grafana/login', 302),
            ('/grafana', 301),
        ]
        six_ok = True
        for path, exp_code in probe_paths:
            req_p = urllib.request.Request(self.base + path)
            st_p = -1
            loc_p = ''
            body_p = ''
            try:
                with opener.open(req_p, timeout=15) as resp:
                    st_p = resp.status
                    loc_p = resp.headers.get('Location', '')
                    body_p = resp.read().decode('utf-8', 'replace')
            except urllib.error.HTTPError as err:
                st_p = err.code
                loc_p = err.headers.get('Location', '')
                body_p = err.read().decode('utf-8', 'replace')
            except Exception:
                six_ok = False
                continue

            if st_p != exp_code:
                six_ok = False
            elif exp_code == 302:
                target = urllib.parse.quote(path, safe='')
                expected_dest = '/login?redirectTo=' + target
                if expected_dest not in loc_p or not ('<html' in body_p.lower() or '<a href' in body_p.lower()):
                    six_ok = False
            elif exp_code == 301:
                expected_dest = self.base + '/grafana/'
                if loc_p != expected_dest:
                    six_ok = False

        # U18-style hash equality at rollback
        rollback_state = self.hash_state()
        u18_ok = True
        if self.state_before:
            for cat in ('folders', 'alert-rules', 'contact-points'):
                if rollback_state['categories'].get(cat, {}).get('stable') != self.state_before['categories'].get(cat, {}).get('stable'):
                    u18_ok = False
            # datasources: stable equal (accounts for manageAlerts if straddling 34d6ab6)
            if rollback_state['categories'].get('datasources', {}).get('stable') != self.state_before['categories'].get('datasources', {}).get('stable'):
                u18_ok = False
            # volumes equal
            if rollback_state.get('volumes') != self.state_before.get('volumes'):
                u18_ok = False
            # dashboards per-uid (excluding p4lokiui if present)
            dash_b = self.state_before.get('dashboards') or {}
            dash_r = {k: v for k, v in (rollback_state.get('dashboards') or {}).items() if k != 'p4lokiui'}
            if dash_b != dash_r:
                u18_ok = False
        else:
            u18_ok = False

        # Forward again with realm.ini + monitor up
        rc3, out3, err3 = self.krate('config', 'set', 'GRAFANA_AUTH_CONFIG=realm.ini', timeout=180)
        rc4, out4, err4 = self.krate('monitor', 'up', timeout=600)
        fwd_cid = (self.mon_id_map().get('grafana') or (None,))[0]
        healthy_fwd = self._wait_grafana_healthy(fwd_cid) if fwd_cid else False
        fwd_signin = self.signin('p4v', 'u22-fwd', expect='ok')
        signin_ok = (fwd_signin['kind'] == 'OK' and healthy_fwd)

        probes = [
            ('only_grafana_recreated', 'PASS' if only_grafana else 'FAIL'),
            ('local_admin_login', 'PASS' if local_admin_ok else 'FAIL'),
            ('six_paths_proxy', 'PASS' if six_ok else 'FAIL'),
            ('u18_hash_rollback', 'PASS' if u18_ok else 'FAIL'),
            ('forward_signin', 'PASS' if (rc3 == 0 and rc4 == 0 and signin_ok) else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; rollback: only grafana recreated (%s), perses changed %s, ' \
                       'local admin 200, 6 paths ' \
                       '(5x 302 + /grafana 301 carrying port), U18 hashes equal; forward: ' \
                       'realm.ini + monitor up rc 0/0, p4v sign-in %s; walk: live4a 169' \
               % (tokens, 'grafana only' if only_grafana else str(recreated),
                  _dict_diff(perses_before, perses_after), fwd_signin['kind'])

    def u23(self):
        # walk logs/137, 139, 162, 169: Container ledger verification:
        # broker, kafka-ui, keycloak, keycloak-db unchanged across slice;
        # cluster proxy recreated once per input change; grafana recreated
        # on auth config/realm.ini change.
        curr_cluster = self.cluster_id_map()
        initial = getattr(self, 'cluster_initial', None) or curr_cluster

        # 1. Core cluster containers unchanged
        core_unchanged = True
        diff_core = []
        for svc in ('keycloak', 'keycloak-db', 'kafka-ui'):
            if svc in initial and svc in curr_cluster:
                if initial[svc] != curr_cluster[svc]:
                    core_unchanged = False
                    same = initial[svc][0] == curr_cluster[svc][0]
                    diff_core.append('%s: %s id %s->%s started %s->%s'
                                     % (svc, 'SAME_ID' if same else 'NEW_ID',
                                        initial[svc][0][:12], curr_cluster[svc][0][:12],
                                        initial[svc][1][:19], curr_cluster[svc][1][:19]))

        # brokers unchanged
        for svc in initial:
            if 'broker' in svc and svc in curr_cluster:
                if initial[svc] != curr_cluster[svc]:
                    core_unchanged = False
                    same = initial[svc][0] == curr_cluster[svc][0]
                    diff_core.append('%s: %s id %s->%s started %s->%s'
                                     % (svc, 'SAME_ID' if same else 'NEW_ID',
                                        initial[svc][0][:12], curr_cluster[svc][0][:12],
                                        initial[svc][1][:19], curr_cluster[svc][1][:19]))

        # 2. Realm.ini-content change recreates grafana only (log 162)
        # Change KEYCLOAK_SESSION_IDLE_MINUTES 15 -> 16
        before_mon = self.mon_id_map()
        long_before = self.long_running(before_mon)
        rc1, _, _ = self.krate('config', 'set', 'KEYCLOAK_SESSION_IDLE_MINUTES=16', timeout=180)
        rc2, _, _ = self.krate('monitor', 'up', timeout=600)
        mid_mon = self.mon_id_map()
        long_mid = self.long_running(mid_mon)
        recreated_16 = [s for s in long_before if s in long_mid and long_before[s][0] != long_mid[s][0]]

        ini_path = os.path.join(self.mon_dir(), 'auth', 'realm.ini')
        ini_16 = False
        try:
            ini_16 = 'login_maximum_inactive_lifetime_duration = 16m' in open(ini_path, encoding='utf-8').read()
        except OSError:
            pass

        # Restore 15
        rc3, _, _ = self.krate('config', 'set', 'KEYCLOAK_SESSION_IDLE_MINUTES=15', timeout=180)
        rc4, _, _ = self.krate('monitor', 'up', timeout=600)
        after_mon = self.mon_id_map()
        long_after = self.long_running(after_mon)
        recreated_15 = [s for s in long_mid if s in long_after and long_mid[s][0] != long_after[s][0]]

        ini_15 = False
        try:
            ini_15 = 'login_maximum_inactive_lifetime_duration = 15m' in open(ini_path, encoding='utf-8').read()
        except OSError:
            pass

        realm_grafana_only = (rc1 == 0 and rc2 == 0 and rc3 == 0 and rc4 == 0
                              and recreated_16 == ['grafana'] and recreated_15 == ['grafana']
                              and ini_16 and ini_15)

        # 3. Cluster proxy: not recreated by monitor changes
        proxy_after = (self.cluster_id_map() or {}).get('proxy')
        proxy_untouched = (curr_cluster.get('proxy') == proxy_after)

        probes = [
            ('core_cluster_unchanged', 'PASS' if core_unchanged else 'FAIL'),
            ('realm_ini_grafana_only', 'PASS' if realm_grafana_only else 'FAIL'),
            ('proxy_untouched_by_monitor', 'PASS' if proxy_untouched else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; core cluster (brokers, kafka-ui, keycloak, keycloak-db) unchanged%s; ' \
                       'realm.ini 15m->16m->15m recreated grafana only (rc %d/%d/%d/%d, ' \
                       'mid %s, after %s, ini %s/%s); proxy untouched; ' \
                       'walk: live4a 137,139,162,169' \
               % (tokens, '' if core_unchanged else ' (diffs: %s)' % diff_core,
                  rc1, rc2, rc3, rc4, recreated_16, recreated_15, ini_16, ini_15)

    def u24(self):
        # The plan's two-command form (gen-cert → monitor up) was MEASURED AND FAILED
        # (walk logs 163,165,166, defect D3): nginx reads its certificate at start only,
        # so the running cluster proxy still presents the PREVIOUS certificate while
        # idp-wait and Grafana load the new CA/server.crt — idp-wait exited 1 with
        # CERTIFICATE_VERIFY_FAILED, Grafana was created-not-started and /grafana/
        # answered 502. Only `auth apply` recreates the proxy (KRATE_PROXY_CONF_SHA
        # digests certs/server.{crt,key}), so the row runs the corrected three-command
        # sequence gen-cert → auth apply → monitor up (lead decision 2026-10-13; walk
        # logs 167,168; sso/guides/grafana-sso.md carries the corrected order, 9347a37).
        # Pass condition unchanged: Grafana recreated (KRATE_GRAFANA_AUTH_SHA covers
        # server.crt) and sign-in works.
        before = (self.mon_id_map() or {}).get('grafana')
        proxy_before = (self.cluster_id_map() or {}).get('proxy')
        if not before:
            not_run('precondition: no grafana container before the certificate renewal')
        rc1, out1, err1 = self.krate('gen-cert', timeout=180)
        if rc1 != 0:
            fail('gen-cert rc=%d: %s' % (rc1, (out1 + err1).strip()[-140:]))
        # The new certificate replaces the pinned one: rebuild the TLS context before
        # any further HTTPS probe (gen-cert writes a fresh self-signed pair).
        self.tls = ssl.create_default_context(
            cafile=os.path.join(self.edition, 'certs', 'server.crt'))
        rc2, out2, err2 = self.krate('auth', 'apply', timeout=600)
        if rc2 != 0:
            fail('auth apply rc=%d: %s' % (rc2, (out2 + err2).strip()[-140:]))
        rc3, out3, err3 = self.krate('monitor', 'up', timeout=900)
        if rc3 != 0:
            fail('monitor up rc=%d: %s' % (rc3, (out3 + err3).strip()[-140:]))
        after = (self.mon_id_map() or {}).get('grafana')
        proxy_after = (self.cluster_id_map() or {}).get('proxy')
        recreated = bool(before and after and before[0] != after[0])
        healthy = self._wait_grafana_healthy(after[0]) if (recreated and after) else False
        result = self.signin('p4v', 'u24-signin', expect='ok')
        probes = [('grafana_recreated', 'PASS' if recreated else 'FAIL'),
                  ('healthy', 'PASS' if healthy else 'FAIL'),
                  ('signin', 'PASS' if result['kind'] == 'OK' else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; gen-cert/auth apply/monitor up rc 0/0/0; grafana %s -> %s; proxy ' \
                       'recreated=%s; sign-in %s; the plan\'s two-command form was measured ' \
                       'and failed (D3: idp-wait CERTIFICATE_VERIFY_FAILED, 502); walk: live4a ' \
                       '163,165-168' % (tokens, before[0][:12], after[0][:12] if after else '-',
                                        bool(proxy_before and proxy_after
                                             and proxy_before[0] != proxy_after[0]),
                                        result['kind'])

    def u25(self):
        # walk log 145: p4dis signed in to Kafbat headless (realm flow, SESSION cookie),
        # baseline GET / 200, `identity users logout p4dis` rc=0, first poll +1.9 s →
        # 302 /oauth2/authorization/keycloak (5 s bound). Reuses phase2_kafbat's
        # kafbat_login/keycloak_login machinery (the K21 method on the Phase 4 fixture).
        state = self.load_state('p4dis')
        user = p2.User('p4dis', ['viewer'])
        user.password = state['password']
        user.secret = state['totp']
        result = self.kafbat_login(user, 'u25-kafbat')
        if result.get('kind') != 'ok' or not result.get('session'):
            fail('p4dis Kafbat sign-in: %s %s' % (result.get('kind'),
                                                  str(result.get('detail'))[:120]))
        browser = result['browser']
        baseline = browser.request('GET', self.base + '/', headers={'Accept': 'text/html'})
        rc, out, err = self.krate('identity', 'users', 'logout', 'p4dis', timeout=120)
        issued = time.monotonic()
        ended_after = None
        location = ''
        status = None
        while time.monotonic() - issued < 10:
            response = browser.request('GET', self.base + '/', headers={'Accept': 'text/html'})
            status = response.status
            if status != 200:
                ended_after = time.monotonic() - issued
                location = response.location
                break
            time.sleep(0.5)
        ended_ok = (ended_after is not None and ended_after <= 5.0
                    and status == 302 and location.startswith('/oauth2/authorization/keycloak'))
        probes = [('kafbat_signin', 'PASS'),
                  ('baseline_200', 'PASS' if baseline.status == 200 else 'FAIL'),
                  ('logout_rc', 'PASS' if rc == 0 else 'FAIL'),
                  ('session_ended_5s', 'PASS' if ended_ok else 'FAIL')]
        row, tokens = aggregate(probes)
        return row, '%s; users logout rc=%d; session ended after %.1fs -> %s %s (bound 5s); ' \
                    'walk: live4a 145' % (tokens, rc, ended_after if ended_after else -1,
                                          status, location[:40])

    def u27(self):
        minutes = getattr(self.args, 'session_max_minutes', None)
        if not minutes:
            return self.stub('U27', 'runs only in an explicit session-max companion fixture')
        if self.timed.started('U27'):
            return self.timed.join('U27', minutes * 60 + 180)
        return self.u27_body()

    def u27_body(self):
        """Active Viewer polls through matching Keycloak and Grafana maxima.

        The 540 s manual diagnostic in harness/phase4/formal-r1/u27-v23-15m/
        proved the same-jar polling and password-form mechanics, and exposed the
        need to match Grafana's own lifetime. A matched-lifetime expiry walk is
        still required before this row can be called live-proven.
        """
        if not getattr(self.args, 'prepared', False):
            not_run('U27 requires a prepared fixture with matched live maxima')
        max_seconds = self.args.session_max_minutes * 60
        kc = self.master_kcadm()
        uid = kc.user_id('p4v')
        if not uid:
            return 'FAIL', 'p4v realm user missing'
        if not self.force_logout('p4v') or kc.get('users/%s/sessions' % uid):
            return 'FAIL', 'p4v did not have zero Keycloak sessions before timed sign-in'
        before_ms = time.time_ns() // 1_000_000
        result = self.signin('p4v', 'u27-session', expect='ok')
        after_ms = time.time_ns() // 1_000_000
        if result.get('kind') != 'OK':
            return 'FAIL', 'p4v Grafana sign-in did not complete: %s' % result.get('kind')
        sessions = kc.get('users/%s/sessions' % uid) or []
        if len(sessions) != 1 or not isinstance(sessions[0].get('start'), int):
            return 'FAIL', 'expected one new Keycloak session with a start timestamp; got %d' % len(sessions)
        start_ms = sessions[0]['start']
        if not before_ms - 2000 <= start_ms <= after_ms:
            return 'FAIL', 'Keycloak session start is outside the fresh sign-in bracket'
        driver = result['driver']
        samples = []

        def sample():
            status, detail = self.one_request(driver)
            now_ms = time.time_ns() // 1_000_000
            now_mono = time.monotonic()
            age = (now_ms - start_ms) / 1000
            samples.append((age, status, now_mono, detail))
            log('U27 p4v Keycloak-start +%.1fs /grafana/api/user -> %s' % (age, status))
            return age, status

        initial_age, initial_status = sample()
        if initial_status != 200 or initial_age > 60:
            return 'FAIL', 'initial Grafana API %s at Keycloak-start +%.1fs' \
                   % (initial_status, initial_age)
        target_ms = start_ms + (max_seconds + 15) * 1000
        deadline_ms = start_ms + (max_seconds + 60) * 1000
        first_after = None
        cadence_ok = True
        early_ok = True
        while True:
            _last_age, _last_status, last_mono, _last_detail = samples[-1]
            until_target = max(0, (target_ms - time.time_ns() // 1_000_000) / 1000)
            delay = min(max(0, last_mono + 50 - time.monotonic()), until_target)
            if delay:
                time.sleep(delay)
            age, status = sample()
            if samples[-1][2] - last_mono > 60:
                cadence_ok = False
            if age < max_seconds - 60 and status != 200:
                early_ok = False
            if age >= max_seconds + 10:
                first_after = (age, status)
                break
        if first_after is None:
            return 'FAIL', 'no request at or after M+10s before the M+60s deadline'
        age, status = first_after
        location = samples[-1][3]
        sign_in = urllib.parse.urlsplit(location).path in ('/grafana/login',
                                                          '/grafana/login/generic_oauth')
        refused = (status == 401 or (status in (302, 303) and sign_in)) \
            and samples[-1][0] * 1000 + start_ms <= deadline_ms
        form = False
        form_chain = []
        if refused:
            form_status, headers, page = driver.req(self.base + '/grafana/login/generic_oauth')
            location = headers.get('Location', '') if hasattr(headers, 'get') else ''
            form_chain.append(form_status)
            for _ in range(6):
                if form_status not in (302, 303) or not location:
                    break
                url = urllib.parse.urljoin(self.base, location)
                self.check_url(url)
                form_status, headers, page = driver.req(url)
                form_chain.append(form_status)
                location = headers.get('Location', '') if hasattr(headers, 'get') else ''
            form = (form_status == 200 and 'id="kc-form-login"' in page
                    and 'name="password"' in page)
        probes = [('cadence_60s', 'PASS' if cadence_ok else 'FAIL'),
                  ('early_200', 'PASS' if early_ok else 'FAIL'),
                  ('refused_M10_M60', 'PASS' if refused else 'FAIL'),
                  ('same_jar_password_form', 'PASS' if form else 'FAIL')]
        row, tokens = aggregate(probes)
        return row, ('%s; matched max %ss; Keycloak start %sms; sign-in bracket %s..%sms; '
                     '%d API samples, first at +%.1fs, first M+10 request +%.1fs HTTP %s; '
                     'same jar authorize chain %s form=%s') \
               % (tokens, max_seconds, start_ms, before_ms, after_ms, len(samples),
                  initial_age, age, status, form_chain, form)

    def u29(self):
        if self.timed.started('U29'):
            return self.timed.join('U29', 1500)
        return self.stub('U29', 'WALKED PASS (log 150) — the timed body runs as a background '
                                'thread; it was not started (a precondition or --only selection '
                                'skipped the @start entry)')

    def u29_body(self):
        """U29 (walk log 150, scripts/u29_job.py): p4idle makes one request then stays
        silent; at +16 min the next /grafana/api/user is refused (walk: 401 plain
        Unauthorized at +961 s — the last rotation is older than the 15-min inactive
        lifetime) and the next authorize shows the Keycloak password form. Control:
        p4ctrl requests every 60 s for 17.5 min, every one 200 (the 10-min rotation
        recovered browser-style by the driver)."""
        self.force_logout('p4idle')  # the walk's preamble: stale SSO sessions would
        self.force_logout('p4ctrl')  # make the final password-form assertion unclean
        time.sleep(2)
        idle = self.signin('p4idle', 'u29-idle', expect='ok')
        ctrl = self.signin('p4ctrl', 'u29-ctrl', expect='ok')
        t0 = time.monotonic()
        st, msg = self.one_request(idle['driver'])  # the one request, then silence
        if st != 200:
            return 'FAIL', 'p4idle first request answered %s %r' % (st, msg)
        deadline = t0 + 17 * 60 + 30
        next_ctrl = t0 + 60
        ctrl_statuses = []
        idle_refusal = None
        idle_form = None
        while True:
            now = time.monotonic()
            if now >= next_ctrl and now < deadline:
                stc, _mc = self.one_request(ctrl['driver'])
                log('U29 control p4ctrl +%.0fs -> %s' % (now - t0, stc))
                ctrl_statuses.append(stc)
                next_ctrl += 60
            if idle_refusal is None and now >= t0 + 16 * 60:
                sti, msgi = self.one_request(idle['driver'])
                log('U29 idle p4idle +%.0fs -> %s %r (expect refusal)' % (now - t0, sti, msgi))
                if sti != 200:
                    idle_refusal = (now - t0, sti, msgi)
                    idle_form, detail = self.authorize_shows_form()
                elif now >= deadline:
                    return 'FAIL', 'p4idle still 200 at +%.0fs (16 min of inactivity passed)' % (now - t0)
            if now >= deadline and idle_refusal is not None:
                stf, _mf = self.one_request(ctrl['driver'])
                ctrl_statuses.append(stf)
                break
            if now >= deadline + 60:
                return 'FAIL', 'control window ended without the idle refusal'
            time.sleep(5)
        control_ok = bool(ctrl_statuses) and all(s == 200 for s in ctrl_statuses)
        refused_ok = idle_refusal is not None and (idle_refusal[1] == 401
                                                   or idle_refusal[1] in (302, 303))
        probes = [('idle_refused', 'PASS' if refused_ok else 'FAIL'),
                  ('password_form', 'PASS' if idle_form else 'FAIL'),
                  ('control_all_200', 'PASS' if control_ok else 'FAIL')]
        status, tokens = aggregate(probes)
        return status, '%s; p4idle refused at +%.0fs (%s %r), next authorize shows the password ' \
                       'form: %s; p4ctrl %d requests every 60 s all 200; walk: live4a 150' \
               % (tokens, idle_refusal[0] if idle_refusal else -1,
                  idle_refusal[1] if idle_refusal else '-', idle_refusal[2] if idle_refusal else '',
                  idle_form, len(ctrl_statuses))

    def plan(self):
        # Execution order = the order the walk proved safe (its log sequence): the
        # short API rows first — including U16/U20/U24 with their Grafana restarts
        # and monitor-up runs — then the four timing rows as PARALLEL background
        # threads (disjoint users; no container recreation happens any more while
        # they poll), then their joins (longest first). Constraints from the walk:
        # U25 precedes U10 (both use p4dis); U11's p4a2 demotion follows every
        # p4a2-admin row (U3/U6/U28); U9's p4both sessions follow U3/U7/U15; the
        # future U12/U13 outage rows must also run before the threads start (an
        # exclusive Keycloak stop would break every polling window).
        return [
            *([('U27@start', lambda: self.start_timed('U27', self.u27_body))]
              if getattr(self.args, 'session_max_minutes', None) else []),
            ('U1', self.u1), ('U2', self.u2), ('U3', self.u3), ('U4', self.u4),
            ('U5', self.u5), ('U6', self.u6), ('U7', self.u7), ('U8', self.u8),
            ('U12', self.u12), ('U13', self.u13), ('U14', self.u14), ('U15', self.u15),
            ('U16', self.u16), ('U17', self.u17), ('U18', self.u18), ('U19', self.u19),
            ('U20', self.u20), ('U21a', self.u21a), ('U21b', self.u21b),
            ('U22', self.u22), ('U23', self.u23), ('U24', self.u24), ('U25', self.u25),
            ('U26', self.u26), ('U27', self.u27), ('U28', self.u28),
            ('U29@start', lambda: self.start_timed('U29', self.u29_body)),
            ('U9@start', lambda: self.start_timed('U9', self.u9_body)),
            ('U10@start', lambda: self.start_timed('U10', self.u10_body)),
            ('U11@start', lambda: self.start_timed('U11', self.u11_body)),
            ('U29', self.u29), ('U9', self.u9), ('U10', self.u10), ('U11', self.u11),
        ]

    def u17(self):
        if 'U17' in self.obs:
            return self.obs['U17']
        return self.stub('U17', 'the setup chain did not reach the U17 probes')

    def u18(self):
        if 'U18' in self.obs:
            return self.obs['U18']
        return self.stub('U18', 'the setup chain did not reach the after-switch hash')


def main(argv=None):
    return helper_main(Gate, 'phase4_grafana.py', argv, doc=__doc__)


if __name__ == '__main__':
    sys.exit(main())
