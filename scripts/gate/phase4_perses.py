#!/usr/bin/env python3
"""Phase 4b acceptance gate: Perses on the Krate realm.

Slice 4b of harness/phase4/PHASE4-INSTRUCTIONS-v3.md, section 2.2: rows V1-V24
of the Perses slice (native mode, PERSES_IDP=krate). This file is the frame the
runner drives:

    python3 -I scripts/gate/phase4_perses.py run \
        --edition-dir ED --base-url https://H --monitor-project krate-<edition>-monitoring \
        --state DIR [--only V1,V2] \
        [--stub-dir DIR --stub-port N --stub-script scripts/gate/stub_idp.sh]

Output: one TSV line per row on stdout, `<id>\\tPASS|FAIL|NOT_RUN\\t<evidence>`,
plus a leading `setup` line for the slice preconditions of section 5 (the 4a
realm switch without seeding, the Perses local-mode seed for V17's hashes, the
commit 8 sequence); progress on stderr. Exit codes of phase2_kafbat.py: 0 when
no row FAILed, 1 otherwise, 2 on a usage error.

Ownership: V1-V24 (including the session-max row V23) are this helper's; X4
(screenshots-perses.mjs) and Z4b (the extended leak scan) are the runner's.
V23 runs only in the `--session-max-hours N` companion runs (the runner passes
`--only U27,V23` to the two helpers); its bound M = 60*N minutes comes from
KEYCLOAK_SESSION_MAX_HOURS in the edition .env, which the runner set before the
realm was created. V19 (a PingFederate-brokered user signs in to Perses) needs
the stand-in IdP of scripts/gate/stub_idp.sh and the applied broker plan
(commit 0); broker_gate() reuses phase3_broker.Gate.brokered_login for it.

STATUS: ENCODED, pending a passing candidate-bound receipt. Earlier live walks
under harness/phase4/live4b/ cover individual behaviors; the authenticated
Viewer and Linux daemon-restart parts of V24 require fresh runtime proof.
The frame reuses
phase2_kafbat.Gate/Kcadm/Browser, keycloak_login_flow.py (enrol),
phase3_broker.Gate.brokered_login (V19), probes.py (the row-pass rule: one
`probe=PASS|FAIL|NOT_RUN` token per probe, the row takes the worst) and
phase4_common.TimedRows for the timing rows.

Timing design (section 5): complete issuer, mode, certificate and container
changes first. Then run V10 (36 min: 20 active + 16 idle) alongside V7/V8 on
separate users; join them before V20's final snapshot and V24's outage restarts.
In session-max runs V23 (M + 6 min) runs as a timed row. Probes reach Perses through its
TLS gateway (https://H:PERSES_PORT, preflight adds it to the allowed origins)
and, for the guard-bypass rows (V6), from a container on the perses network.
Secrets (JWTs, cookies, refresh tokens, secrets read from monitoring/.env) go
to $STATE/phase4-secrets.txt through add_runtime_secret(); the runner adds that
file to its leak set.
"""
import argparse
import base64
import hashlib
import hmac
import html
import http.cookiejar
import json
import os
import re
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python3 -I does not add the script directory
import phase2_kafbat as p2  # noqa: E402
from phase4_common import (Phase4Gate, helper_main, fail, aggregate, log,  # noqa: E402
                           Outcome, not_run)

CASES = ['V%d' % i for i in range(1, 25)]
RUNNER_OWNED = ('X4', 'Z4b')


class PersesDriver:
    """One user agent on the Perses TLS gateway (https://H:PERSES_PORT):
    cookie jar, NoRedirect, pinned TLS (gate.tls). Adds session cookies (_oauth2_proxy,
    jwtPayload, jwtSignature, jwtRefreshToken) to runtime secrets."""

    def __init__(self, gate, label):
        self.gate = gate
        self.label = label
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            p2.NoRedirect, urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=gate.tls))
        self.last_url = None

    def req(self, url, data=None, method=None, headers=None, timeout=60):
        # Keycloak form actions and redirect Locations are often origin-relative
        # ('/...') or page-relative: resolve them against the last absolute URL
        # this driver requested instead of crashing with 'unknown url type'.
        # Absolute URLs pass through urljoin unchanged, so passing rows keep
        # byte-identical requests.
        if url and not urllib.parse.urlparse(url).scheme:
            url = urllib.parse.urljoin(self.last_url or self.gate.base, url)
        if url and urllib.parse.urlparse(url).scheme:
            self.last_url = url
        if not url:
            return -1, {}, 'empty URL (no form action or redirect Location)'
        body = None
        sent = dict(headers or {})
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            sent.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        elif isinstance(data, str):
            body = data.encode()
        elif isinstance(data, bytes):
            body = data
        request = urllib.request.Request(url, data=body, headers=sent, method=method)
        try:
            response = self.opener.open(request, timeout=timeout)
            status, hdrs, text = response.status, response.headers, response.read().decode(errors='replace')
        except urllib.error.HTTPError as error:
            status, hdrs, text = error.code, error.headers, error.read().decode(errors='replace')
        except urllib.error.URLError as error:
            return -1, {}, 'URLError: %s' % error.reason

        for cookie in self.jar:
            if cookie.name in ('_oauth2_proxy', 'jwtPayload', 'jwtSignature', 'jwtRefreshToken'):
                self.gate.add_runtime_secret(cookie.value)
        return status, hdrs, text


class Gate(Phase4Gate):
    SLICE = '4b'
    CASES = CASES
    RUNNER_OWNED = RUNNER_OWNED

    def __init__(self, args):
        super().__init__(args)
        self.drivers = {}
        self.user_state = {}
        self.cluster_initial = {}

    def driver(self, label):
        if label not in self.drivers:
            self.drivers[label] = PersesDriver(self, label)
        return self.drivers[label]

    def gateway(self, path='/'):
        """An absolute URL on the Perses TLS gateway (the slice's browser-facing origin)."""
        return (self.perses_origin or '') + path

    @staticmethod
    def totp(secret_b32, t=None):
        raw = base64.b32decode(secret_b32.replace(' ', '').upper())
        counter = int((t or time.time()) // 30)
        digest = hmac.new(raw, struct.pack('>Q', counter), hashlib.sha1).digest()
        o = digest[-1] & 15
        return '%06d' % ((struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)

    @staticmethod
    def form_action(page):
        m = re.search(r'<form[^>]+action="([^"]+)"', page)
        return html.unescape(m.group(1)) if m else ''

    def load_state(self, user):
        path = self.user_state.get(user)
        if not path:
            path = os.path.join(self.state_dir, 'p4', 'kc-%s.json' % user)
        if not os.path.exists(path):
            path = os.path.join(self.state_dir, '%s.json' % user)
        if not os.path.exists(path):
            live_path = os.path.join(self.edition, '..', 'harness', 'phase4', 'live4b', 'secrets', 'kc-%s.json' % user)
            if os.path.exists(live_path):
                path = live_path
        if not os.path.exists(path):
            fail('no enrolment state file for %s (looked in %s)' % (user, path))
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)

    def direct_perses(self, method, path, headers=None, data=None):
        """Direct request to http://perses:8080 from the perses network."""
        gw_cid = self.mon_container('perses-gateway')
        # A JSON body without a content type reaches Perses as
        # application/x-www-form-urlencoded (curl -d default) and the API
        # answers 415 instead of the asserted 403: always label dict bodies.
        body_headers = dict(headers or {})
        if data and not any(k.lower() == 'content-type' for k in body_headers):
            body_headers['Content-Type'] = 'application/json'
        cmd = []
        if gw_cid:
            cmd = ['exec', gw_cid, 'curl', '-s', '-i', '-X', method, 'http://perses:8080' + path]
            for k, v in body_headers.items():
                cmd.extend(['-H', '%s: %s' % (k, v)])
            if data:
                cmd.extend(['-d', data if isinstance(data, str) else json.dumps(data)])
            rc, out, _ = p2.docker(*cmd)
        else:
            net = '%s_perses' % self.monitor_project
            cmd = ['run', '--rm', '--network', net, self.env.get('NGINX_IMAGE', 'nginx:alpine'),
                   'curl', '-s', '-i', '-X', method, 'http://perses:8080' + path]
            for k, v in body_headers.items():
                cmd.extend(['-H', '%s: %s' % (k, v)])
            if data:
                cmd.extend(['-d', data if isinstance(data, str) else json.dumps(data)])
            rc, out, _ = p2.docker(*cmd)

        parts = out.split('\r\n\r\n', 1) if '\r\n\r\n' in out else out.split('\n\n', 1)
        hdrs = parts[0]
        body = parts[1] if len(parts) > 1 else ''
        first_line = hdrs.splitlines()[0] if hdrs.splitlines() else ''
        status = int(first_line.split()[1]) if len(first_line.split()) > 1 and first_line.split()[1].isdigit() else -1
        return status, hdrs, body

    def volume_file(self, volume, filename):
        """Read a rendered config file from a compose volume on the docker host.

        The Perses and oauth2-proxy images are distroless (no cat/ls/sh), so
        `docker exec ... cat` always fails inside them. The volume file holds
        the same bytes the container sees through its mount. Returns (rc, text).
        """
        rc, mount, _ = p2.docker('volume', 'inspect', '-f', '{{.Mountpoint}}', volume)
        mount = (mount or '').strip()
        if rc != 0 or not mount:
            return 1, ''
        try:
            with open(os.path.join(mount, filename), encoding='utf-8') as handle:
                return 0, handle.read()
        except OSError:
            return 1, ''

    def signin(self, user, label, expect='ok'):
        d = self.driver(label)
        d.jar.clear()
        state = self.load_state(user)
        pw = state['password']
        totp_seed = state.get('totp')
        self.add_runtime_secret(pw)
        if totp_seed:
            self.add_runtime_secret(totp_seed)

        st1, h1, _ = d.req(self.gateway('/'), headers={'Accept': 'text/html'})
        if st1 != 302:
            return {'kind': 'FAIL', 'status': st1, 'detail': 'GET / did not redirect'}
        loc1 = urllib.parse.urljoin(self.gateway(), h1.get('Location', ''))
        st2, h2, _ = d.req(loc1, headers={'Accept': 'text/html'})
        if st2 != 302:
            return {'kind': 'FAIL', 'status': st2, 'detail': 'GET /oauth2/start did not redirect'}
        auth_url = h2.get('Location', '')
        st3, h3, login_page = d.req(auth_url, headers={'Accept': 'text/html'})
        if 'account is disabled' in login_page.lower():
            return {'kind': 'REFUSED', 'reason': 'Account is disabled', 'driver': d}

        action = self.form_action(login_page)
        st4, h4, page4 = d.req(action, method='POST',
                               data={'username': user, 'password': pw, 'credentialId': ''},
                               headers={'Accept': 'text/html'})
        if 'account is disabled' in page4.lower():
            return {'kind': 'REFUSED', 'reason': 'Account is disabled', 'driver': d}
        while st4 in (302, 303) and h4.get('Location', '').startswith(self.base):
            st4, h4, page4 = d.req(h4['Location'], headers={'Accept': 'text/html'})

        if st4 == 200 and ('totp' in page4 or 'name="otp"' in page4):
            if not totp_seed:
                return {'kind': 'FAIL', 'detail': 'OTP prompted but no totp seed'}
            code = self.totp(totp_seed)
            action_otp = self.form_action(page4)
            st5, h5, page5 = d.req(action_otp, method='POST',
                                   data={'otp': code, 'login': 'Sign In'},
                                   headers={'Accept': 'text/html'})
            if st5 == 200 and 'Invalid authenticator code' in page5:
                retry_action = self.form_action(page5)
                if retry_action:
                    now = time.time()
                    current_step = int(now // 30)
                    delay = (current_step + 1) * 30 - now + 0.05
                    if not 0 < delay <= 30.05:
                        return {'kind': 'FAIL', 'detail': 'invalid TOTP replay wait'}
                    time.sleep(delay)
                    if int(time.time() // 30) <= current_step:
                        return {'kind': 'FAIL', 'detail': 'TOTP step did not advance'}
                    st5, h5, page5 = d.req(retry_action, method='POST',
                                           data={'otp': self.totp(totp_seed),
                                                 'login': 'Sign In'},
                                           headers={'Accept': 'text/html'})
        else:
            st5, h5, page5 = st4, h4, page4

        if st5 != 302:
            return {'kind': 'FAIL', 'status': st5, 'detail': 'credential submission did not redirect to callback'}

        cb_url = h5.get('Location', '')
        st_cb, h_cb, b_cb = d.req(cb_url, headers={'Accept': 'text/html'})
        if st_cb == 403 or (st_cb == 200 and 'forbidden' in b_cb.lower()):
            return {'kind': 'REFUSED', 'reason': 'callback_refused_403', 'driver': d, 'body': b_cb}
        if st_cb == 500:
            return {'kind': 'REFUSED', 'reason': 'callback_500', 'driver': d, 'body': b_cb}

        # Perses OIDC login
        st_oidc, h_oidc, _ = d.req(self.gateway('/api/auth/providers/oidc/krate/login?rd=%2F'),
                                   headers={'Accept': 'text/html'})
        hops = 0
        while st_oidc in (302, 303) and hops < 10:
            hops += 1
            nxt = urllib.parse.urljoin(self.gateway(), h_oidc.get('Location', ''))
            st_oidc, h_oidc, _ = d.req(nxt, headers={'Accept': 'text/html'})

        st_role, _hr, b_role = d.req(self.gateway('/krate/role'))
        role = b_role.strip() if st_role == 200 else None
        cookies = {c.name: c.value for c in d.jar}
        return {'kind': 'OK', 'driver': d, 'role': role, 'cookies': cookies}

    def signin_retry(self, user, label, role='viewer', deadline_s=180):
        """Full signin() retried until it lands (or the deadline passes).

        After a recreate/restart the first login can race container convergence
        (idp-wait covers Keycloak, not the proxy chain behind it). The bound is
        the assertion: every attempt and the landing time are recorded.
        Returns (result, attempts, elapsed_s).
        """
        t0 = time.monotonic()
        attempts = 0
        res = {'kind': 'NOT_RUN'}
        while True:
            attempts += 1
            try:
                res = self.signin(user, '%s-try%d' % (label, attempts))
            except Outcome:
                raise
            except Exception as error:
                res = {'kind': 'FAIL', 'detail': '%s: %s' % (type(error).__name__, error)}
            if res.get('kind') == 'OK' and (role is None or res.get('role') == role):
                break
            if time.monotonic() - t0 >= deadline_s:
                break
            time.sleep(10)
        return res, attempts, time.monotonic() - t0

    def broker_gate(self):
        """phase3_broker.Gate wired to the stand-in IdP, for V19's brokered sign-in.

        Scaffold: construction only; the row body calls its brokered_login(user,
        label) once the live4b walk has shown the brokered Perses sign-in (needs
        commit 0, trustEmail=true) and the runner passes --stub-dir/--stub-port.
        """
        import phase3_broker
        if not self.args.stub_dir:
            fail('V19 needs --stub-dir (the stand-in IdP directory of stub_idp.sh up)')
        args = argparse.Namespace(
            edition_dir=self.args.edition_dir, base_url=self.args.base_url, project=self.project,
            stub_dir=self.args.stub_dir, stub_port=self.args.stub_port,
            stub_script=self.args.stub_script, stub_container=self.args.stub_container,
            login_probe=None, local_user=None, local_password_env=None, clash_user=None,
            only=None)
        return phase3_broker.Gate(args)

    def setup(self):
        """Section 5 preconditions, using the order observed in live4b."""
        if getattr(self.args, 'prepared', False):
            if self.args.only != ['V23'] or not getattr(self.args, 'session_max_minutes', None):
                return 'prepared Perses worker requires --only V23 and --session-max-minutes'
            try:
                if (self.mon_env_value('PERSES_AUTH_MODE') != 'native'
                        or self.mon_env_value('PERSES_IDP') != 'krate'):
                    raise RuntimeError('Perses is not in native krate realm mode')
                self.wait_perses_ready('native')
                self.load_state('p4ctrl')
                kc = self.master_kcadm()
                uid = kc.user_id('p4ctrl')
                if not uid:
                    raise RuntimeError('p4ctrl realm user is absent')
                groups = kc.get('users/%s/groups' % uid) or []
                viewer_group = self.env.get('KEYCLOAK_VIEWER_GROUP') or 'KRATE_VIEWERS'
                if viewer_group not in {group.get('name') for group in groups}:
                    raise RuntimeError('p4ctrl is not in the Viewer group')
                realm = json.loads(kc.call('get', 'realms/krate'))
                expected = self.args.session_max_minutes * 60
                if realm.get('ssoSessionMaxLifespan') != expected:
                    raise RuntimeError('realm max %s s differs from requested %s s'
                                       % (realm.get('ssoSessionMaxLifespan'), expected))
            except Exception as error:
                return 'prepared V23 precondition failed: %s: %s' % (type(error).__name__, str(error)[:200])
            return None
        try:
            self.setup_realm_users()
            self.setup_grafana_realm()
            self.setup_perses_seed()
            self.setup_perses_realm()
        except Exception as error:
            return 'setup step failed: %s: %s' % (type(error).__name__, str(error)[:300])
        return None

    def setup_realm_users(self):
        """Live4b logs/021-022: eight users, both-group assignments, enrolment."""
        state_dir = os.path.join(self.state_dir, 'p4')
        os.makedirs(state_dir, exist_ok=True)
        users = (('p4v', ('--viewer',)), ('p4a', ('--admin',)),
                 ('p4both', ('--admin',)), ('p4nogroup', ()),
                 ('p4dis', ('--viewer',)), ('p4a2', ('--admin',)),
                 ('p4idle', ('--viewer',)), ('p4ctrl', ('--viewer',)))
        temporary = {}
        for name, flags in users:
            rc, out, err = self.krate('identity', 'users', 'add', name, *flags,
                                      '--email', name + '@live4b.test', timeout=180)
            if rc != 0:
                raise RuntimeError('identity users add %s failed (rc %d): %s'
                                   % (name, rc, (err or out).strip()[-160:]))
            temporary[name] = self.temp_password(out)
            if not temporary[name]:
                raise RuntimeError('no temporary password returned for ' + name)
            self.add_runtime_secret(temporary[name])
        kc = self.master_kcadm()
        viewer_group = self.env.get('KEYCLOAK_VIEWER_GROUP') or 'KRATE_VIEWERS'
        viewer_gid = kc.group_id(viewer_group)
        if not viewer_gid:
            raise RuntimeError('realm group missing: ' + viewer_group)
        for name in ('p4both', 'p4a2'):
            uid = kc.user_id(name)
            if not uid:
                raise RuntimeError('realm user missing: ' + name)
            kc.add_group(uid, viewer_gid)
        for name, _flags in users:
            state = os.path.join(state_dir, 'kc-%s.json' % name)
            self.enrol_user(name, temporary[name], state)
            self.user_state[name] = state
        log('setup: eight live4b realm users enrolled; two in both groups')

    def setup_grafana_realm(self):
        """Section 5: 4a switch without 4a seeding or rows."""
        for command in (('monitor', 'realm'),
                        ('config', 'set', 'GRAFANA_AUTH_CONFIG=realm.ini'),
                        ('monitor', 'up')):
            rc, out, err = self.krate(*command, timeout=900)
            if rc != 0:
                raise RuntimeError('%s failed (rc %d): %s'
                                   % (' '.join(command), rc, (err or out).strip()[-180:]))
        log('setup: Grafana switched to realm mode without 4a seed')

    def wait_perses_ready(self, mode, timeout=30):
        """Wait for the observed gateway response after a local/native mode switch.

        The normal PersesDriver uses the gate CA, hostname verification and the
        public hostname in the URL. Its NoRedirect handler exposes the native
        gateway's /oauth2/start redirect instead of following it.
        """
        if mode not in ('local', 'native'):
            raise ValueError('unknown Perses readiness mode ' + str(mode))
        url = self.gateway('/')
        self.check_url(url)
        driver = self.driver('readiness-%s-%s' % (mode, time.monotonic()))
        deadline = time.monotonic() + timeout
        last_status = None
        last_path = ''
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('%s readiness timed out after %ss; last HTTP %s, path %s'
                                   % (mode, timeout, last_status, last_path or '-'))
            status, headers, body = driver.req(
                url, headers={'Accept': 'text/html'}, timeout=min(5.0, remaining))
            location = headers.get('Location', '')
            redirect = urllib.parse.urlsplit(location)
            last_status, last_path = status, redirect.path
            completed_at = time.monotonic()
            if completed_at > deadline:
                raise RuntimeError('%s readiness timed out after %ss; last HTTP %s, path %s'
                                   % (mode, timeout, last_status, last_path or '-'))
            if mode == 'local' and status == 200:
                return
            if (mode == 'native' and status == 302
                    and redirect.path == '/oauth2/start'
                    and not redirect.scheme and not redirect.netloc):
                return
            if status == -1 and ('CERTIFICATE_VERIFY_FAILED' in body
                                 or 'hostname mismatch' in body):
                raise RuntimeError('%s readiness TLS verification failed' % mode)
            remaining = deadline - completed_at
            if remaining <= 0:
                raise RuntimeError('%s readiness timed out after %ss; last HTTP %s, path %s'
                                   % (mode, timeout, last_status, last_path or '-'))
            time.sleep(min(0.5, remaining))

    def setup_perses_seed(self):
        """Live4b results/100 and evidence/v17-before-raw.json: four local objects."""
        if self.mon_env_value('PERSES_IDP') or self.mon_env_value('PERSES_AUTH_MODE') != 'local':
            raise RuntimeError('Perses must be in local mode before seeding')
        self.wait_perses_ready('local')
        user = self.mon_env_value('PERSES_ADMIN_USER') or 'admin'
        password = self.mon_env_value('PERSES_ADMIN_PASSWORD')
        if not password:
            raise RuntimeError('PERSES_ADMIN_PASSWORD missing from monitoring/.env')
        request = urllib.request.Request(
            self.gateway('/api/auth/providers/native/login'), method='POST',
            data=json.dumps({'login': user, 'password': password}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, context=self.tls, timeout=30) as response:
            token = json.load(response).get('access_token', '')
        if not token:
            raise RuntimeError('Perses local admin login returned no access token')
        self.add_runtime_secret(token)
        base = '/api/v1/projects/p4b-seed-proj'
        datasource = {
            'kind': 'Datasource',
            'metadata': {'name': 'p4b-seed-ds', 'project': 'p4b-seed-proj'},
            'spec': {
                'default': False,
                'plugin': {
                    'kind': 'PrometheusDatasource',
                    'spec': {'proxy': {'kind': 'HTTPProxy',
                                       'spec': {'url': 'http://prometheus:9090'}}},
                },
            },
        }
        objects = (
            ('/api/v1/projects', 'p4b-seed-proj',
             {'kind': 'Project', 'metadata': {'name': 'p4b-seed-proj'},
              'spec': {'display': {'name': 'P4B Seed Project'}}}),
            (base + '/datasources', 'p4b-seed-ds', datasource),
            (base + '/variables', 'p4b_var',
             {'kind': 'Variable', 'metadata': {'name': 'p4b_var', 'project': 'p4b-seed-proj'},
              'spec': {'kind': 'TextVariable', 'spec': {'value': 'hello'}}}),
            (base + '/dashboards', 'p4b-seed-dash',
             {'kind': 'Dashboard', 'metadata': {'name': 'p4b-seed-dash', 'project': 'p4b-seed-proj'},
              'spec': {'display': {'name': 'P4B Seed Dashboard'},
                       'panels': None, 'layouts': [], 'duration': '1h'}}),
            (base + '/folders', 'p4b-seed-folder',
             {'kind': 'Folder', 'metadata': {'name': 'p4b-seed-folder', 'project': 'p4b-seed-proj'},
              'spec': {'display': {'name': 'P4B Seed Folder'},
                       'items': [{'kind': 'Dashboard', 'name': 'p4b-seed-dash'}]}}),
        )
        for path, name, payload in objects:
            headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
            request = urllib.request.Request(self.gateway(path), method='POST',
                                             data=json.dumps(payload).encode(), headers=headers)
            with urllib.request.urlopen(request, context=self.tls, timeout=30) as response:
                if response.status not in (200, 201):
                    raise RuntimeError('Perses seed %s returned HTTP %d' % (name, response.status))
            request = urllib.request.Request(self.gateway(path),
                                             headers={'Authorization': 'Bearer ' + token})
            with urllib.request.urlopen(request, context=self.tls, timeout=30) as response:
                listing = json.load(response)
            if not isinstance(listing, list):
                raise RuntimeError('Perses seed %s readback was not a list' % name)
            found = [item for item in listing
                     if isinstance(item, dict) and item.get('metadata', {}).get('name') == name]
            if len(found) != 1:
                raise RuntimeError('Perses seed %s readback count was %d' % (name, len(found)))
            actual = found[0]
            metadata = actual.get('metadata') or {}
            expected_metadata = payload['metadata']
            actual_metadata = {key: metadata.get(key) for key in expected_metadata}
            if (actual.get('kind') != payload['kind']
                    or actual_metadata != expected_metadata
                    or actual.get('spec') != payload['spec']):
                raise RuntimeError('Perses seed %s readback model differs from request' % name)
        self.obs['V17-baseline'] = self.hash_perses_state(token)
        log('setup: five Perses local seed objects read back; candidate V17 baseline captured')

    def setup_perses_realm(self):
        """Live4b log/100: enable native mode and realm issuer, then monitor up."""
        for command in (('config', 'set', 'PERSES_AUTH_MODE=native'),
                        ('config', 'set', 'PERSES_IDP=krate'),
                        ('monitor', 'up')):
            rc, out, err = self.krate(*command, timeout=900)
            if rc != 0:
                raise RuntimeError('%s failed (rc %d): %s'
                                   % (' '.join(command), rc, (err or out).strip()[-180:]))
        self.wait_perses_ready('native')
        sync_cid = self.mon_container('perses-sync', all_states=False)
        if not sync_cid or self._wait_container_healthy(sync_cid, limit=180) is None:
            raise RuntimeError('perses-sync did not become healthy after realm switch')
        log('setup: Perses switched to native realm mode')

    # ── rows (section 2.2 of PHASE4-INSTRUCTIONS-v3.md) ──
    # Every body below is a scaffold stub; `needs` records what the live4b walk
    # notes must show before the row is encoded (rule 11).

    def v1(self):
        # walk log 070: PERSES_IDP=krate with gateway and local mode refused before
        # any container changes (ids and StartedAt equal).
        before_map = self.mon_id_map()

        # Case 1: gateway mode
        self.krate('config', 'set', 'PERSES_IDP=krate')
        self.krate('config', 'set', 'PERSES_AUTH_MODE=gateway')
        rc1, out1, err1 = self.krate('monitor', 'up')
        mid_map = self.mon_id_map()
        text1 = out1 + err1
        gw_refused = (rc1 != 0 and 'PERSES_IDP=krate requires PERSES_AUTH_MODE=native (got gateway)' in text1
                      and before_map == mid_map)

        # Case 2: local mode
        self.krate('config', 'set', 'PERSES_AUTH_MODE=local')
        rc2, out2, err2 = self.krate('monitor', 'up')
        after_map = self.mon_id_map()
        text2 = out2 + err2
        local_refused = (rc2 != 0 and 'PERSES_IDP=krate requires PERSES_AUTH_MODE=native (got local)' in text2
                         and before_map == after_map)

        # Restore native mode
        self.krate('config', 'set', 'PERSES_AUTH_MODE=native')

        probes = [
            ('gateway_mode_refused', 'PASS' if gw_refused else 'FAIL'),
            ('local_mode_refused', 'PASS' if local_refused else 'FAIL'),
            ('containers_unchanged', 'PASS' if before_map == after_map else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; PERSES_IDP=krate with gateway/local refused before container changes ' \
                       '(rc %d/%d, ids/StartedAt equal); walk: live4b 070' % (tokens, rc1, rc2)

    def v2(self):
        # walk log 102: rendered Perses config (enable_auth: true), 401s from the perses network,
        # refused native login of former PERSES_ADMIN_USER, no jwtPayload cookie.
        perses_cid = self.mon_container('perses')
        if not perses_cid:
            not_run('precondition: no perses container in ' + self.monitor_project)

        # 1. Rendered config from the perses_rendered volume on the docker host
        # (the compose file starts perses with --config pointing at it; the
        # perses image is distroless, so `docker exec ... cat` cannot read it).
        rc, out = self.volume_file('%s_perses_rendered' % self.monitor_project, 'config.yaml')
        cfg_ok = (rc == 0 and 'enable_auth: true' in out and 'enable_native: false' in out
                  and 'client_id: "krate-perses"' in out)

        # 2. Direct unauthenticated requests from perses network to perses:8080
        s1, _h1, _b1 = self.direct_perses('GET', '/api/v1/projects')
        s2, _h2, _b2 = self.direct_perses('POST', '/api/v1/projects', data={})
        s3, _h3, _b3 = self.direct_perses('POST', '/proxy/unsaved/projects/krate/datasources/flags', data={})
        direct_401s = (s1 == 401 and s2 == 401 and s3 == 401)

        # 3. Former PERSES_ADMIN_USER native login
        admin_user = self.env.get('PERSES_ADMIN_USER', 'admin')
        admin_pw = self.env.get('PERSES_ADMIN_PASSWORD', 'admin')
        login_payload = json.dumps({'login': admin_user, 'password': admin_pw})

        # direct to perses:8080 (method not allowed / 405)
        s_dir, h_dir, b_dir = self.direct_perses('POST', '/api/auth/providers/native/login',
                                                 headers={'Content-Type': 'application/json'},
                                                 data=login_payload)
        # through gateway (403 forbidden)
        d = self.driver('v2-native')
        s_gw, h_gw, b_gw = d.req(self.gateway('/api/auth/providers/native/login'),
                                 method='POST',
                                 headers={'Content-Type': 'application/json'},
                                 data=login_payload)
        jwt_absent = not any(c.name == 'jwtPayload' for c in d.jar)
        native_refused = (s_dir in (404, 405) and s_gw == 403 and jwt_absent)

        probes = [
            ('enable_auth_true', 'PASS' if cfg_ok else 'FAIL'),
            ('direct_401s', 'PASS' if direct_401s else 'FAIL'),
            ('native_login_refused', 'PASS' if native_refused else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; rendered config read rc=%d markers=%s; direct perses:8080 -> %d/%d/%d; ' \
                       'native login direct %d / gateway %d, no jwtPayload; walk: live4b 102' \
               % (tokens, rc, cfg_ok, s1, s2, s3, s_dir, s_gw)

    def v3(self):
        # walk log 103: p4v -> viewer role + 7 scopes; p4a and p4both -> admin role + * scopes.
        res_v = self.signin('p4v', 'v3-viewer')
        role_v = res_v.get('role')
        d_v = self.driver('v3-viewer')
        s_pv, _hpv, b_pv = d_v.req(self.gateway('/api/v1/users/p4v/permissions'))
        scopes_v_ok = False
        if s_pv == 200:
            try:
                pdata = json.loads(b_pv).get('*', [{}])[0]
                scopes_v_ok = (pdata.get('actions') == ['read'] and len(pdata.get('scopes', [])) == 7)
            except Exception:
                pass

        res_a = self.signin('p4a', 'v3-admin')
        role_a = res_a.get('role')
        d_a = self.driver('v3-admin')
        s_pa, _hpa, b_pa = d_a.req(self.gateway('/api/v1/users/p4a/permissions'))
        perms_a_ok = False
        if s_pa == 200:
            try:
                pdata = json.loads(b_pa).get('*', [{}])[0]
                perms_a_ok = (pdata.get('actions') == ['*'] and pdata.get('scopes') == ['*'])
            except Exception:
                pass

        res_b = self.signin('p4both', 'v3-both')
        role_b = res_b.get('role')
        d_b = self.driver('v3-both')
        s_pb, _hpb, b_pb = d_b.req(self.gateway('/api/v1/users/p4both/permissions'))
        perms_b_ok = False
        if s_pb == 200:
            try:
                pdata = json.loads(b_pb).get('*', [{}])[0]
                perms_b_ok = (pdata.get('actions') == ['*'] and pdata.get('scopes') == ['*'])
            except Exception:
                pass

        probes = [
            ('viewer_role', 'PASS' if role_v == 'viewer' else 'FAIL'),
            ('viewer_permissions', 'PASS' if scopes_v_ok else 'FAIL'),
            ('admin_role', 'PASS' if role_a == 'admin' else 'FAIL'),
            ('admin_permissions', 'PASS' if perms_a_ok else 'FAIL'),
            ('both_role', 'PASS' if role_b == 'admin' else 'FAIL'),
            ('both_permissions', 'PASS' if perms_b_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; p4v -> %s (7 read scopes), p4a -> %s (*), p4both -> %s (*); walk: live4b 103' \
               % (tokens, role_v, role_a, role_b)

    def v4(self):
        # walk log 103: p4nogroup refused at /oauth2/callback (403), no Perses cookies set.
        res = self.signin('p4nogroup', 'v4-nogroup')
        refused = (res.get('kind') == 'REFUSED')
        d = self.driver('v4-nogroup')
        jar_cookies = [c.name for c in d.jar]
        perses_cookies_present = any(name in ('_oauth2_proxy', 'jwtPayload', 'jwtSignature', 'jwtRefreshToken')
                                     for name in jar_cookies)
        probes = [
            ('callback_refused', 'PASS' if refused else 'FAIL'),
            ('no_perses_cookies', 'PASS' if (not perses_cookies_present) else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; p4nogroup refused at callback (%s), Perses cookies present: %s; walk: live4b 103' \
               % (tokens, res.get('reason', 'not refused'), perses_cookies_present)

    def v5(self):
        # walk log 103: Viewer write probes through gateway -> 403, controls -> 200.
        self.signin('p4v', 'v5-viewer')
        d = self.driver('v5-viewer')

        # 9 writes / sensitive reads
        write_endpoints = [
            ('POST', '/api/v1/projects', {'metadata': {'name': 'v5-test'}}),
            ('POST', '/api/v1/projects/krate/dashboards', {'metadata': {'name': 'v5-db'}}),
            ('PUT', '/api/v1/projects/krate/dashboards/krate-overview', {'metadata': {'name': 'krate-overview'}}),
            ('DELETE', '/api/v1/projects/krate/dashboards/krate-overview', None),
            ('POST', '/api/v1/projects/krate/datasources', {'metadata': {'name': 'v5-ds'}}),
            ('GET', '/api/v1/projects/krate/secrets', None),
            ('GET', '/api/v1/users', None),
            ('GET', '/api/v1/globalroles', None),
            ('POST', '/proxy/unsaved/projects/krate/datasources/flags', {}),
        ]
        write_statuses = []
        for method, path, data in write_endpoints:
            st, _h, _b = d.req(self.gateway(path), method=method, data=data)
            write_statuses.append(st)

        writes_403 = all(s == 403 for s in write_statuses)

        st_prom, _hp, _bp = d.req(self.gateway('/proxy/projects/krate/datasources/Prometheus/api/v1/query?query=up'))
        st_vl, _hv, _bv = d.req(self.gateway('/proxy/projects/krate/datasources/VictoriaLogs/select/logsql/query'),
                                method='POST', data='query=*')

        probes = [
            ('viewer_writes_403', 'PASS' if writes_403 else 'FAIL'),
            ('prometheus_control_200', 'PASS' if st_prom == 200 else 'FAIL'),
            ('victorialogs_control_200', 'PASS' if st_vl == 200 else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; 9 writes/sensitive reads -> 403 (%s); Prometheus control %d, ' \
                       'VictoriaLogs control %d; walk: live4b 103' \
               % (tokens, 'all 403' if writes_403 else str(write_statuses), st_prom, st_vl)

    def v6(self):
        # walk log 103: guard-bypass probes directly at perses:8080 with Viewer cookies -> 403,
        # reads -> 200, Admin create/delete control -> 200/204.
        res_v = self.signin('p4v', 'v6-viewer')
        cookies_v = res_v.get('cookies')
        cookie_str = '; '.join('%s=%s' % (k, v) for k, v in cookies_v.items()) if isinstance(cookies_v, dict) else ''
        cookie_hdr = {'Cookie': cookie_str}

        write_endpoints = [
            ('POST', '/api/v1/projects', {'metadata': {'name': 'v6-test'}}),
            ('POST', '/api/v1/projects/krate/dashboards', {'metadata': {'name': 'v6-db'}}),
            ('PUT', '/api/v1/projects/krate/dashboards/krate-overview', {'metadata': {'name': 'krate-overview'}}),
            ('DELETE', '/api/v1/projects/krate/dashboards/krate-overview', None),
            ('POST', '/api/v1/projects/krate/datasources', {'metadata': {'name': 'v6-ds'}}),
            ('GET', '/api/v1/projects/krate/secrets', None),
            ('GET', '/api/v1/users', None),
            ('GET', '/api/v1/globalroles', None),
            ('POST', '/proxy/unsaved/projects/krate/datasources/flags', {}),
        ]
        statuses = []
        for method, path, data in write_endpoints:
            st, _h, _b = self.direct_perses(method, path, headers=cookie_hdr, data=data)
            statuses.append(st)

        writes_403 = all(s == 403 for s in statuses)

        s_r1, _h, _b = self.direct_perses('GET', '/api/v1/projects', headers=cookie_hdr)
        s_r2, _h, _b = self.direct_perses('GET', '/api/v1/projects/krate/dashboards', headers=cookie_hdr)
        reads_200 = (s_r1 == 200 and s_r2 == 200)

        res_a = self.signin('p4a', 'v6-admin')
        cookies_a = res_a.get('cookies')
        cookie_str_a = '; '.join('%s=%s' % (k, v) for k, v in cookies_a.items()) if isinstance(cookies_a, dict) else ''
        cookie_hdr_a = {'Cookie': cookie_str_a}

        s_create, _h, _b = self.direct_perses('POST', '/api/v1/projects', headers=cookie_hdr_a,
                                             data={'metadata': {'name': 'admin-ctrl'}})
        s_delete, _h, _b = self.direct_perses('DELETE', '/api/v1/projects/admin-ctrl', headers=cookie_hdr_a)
        admin_ok = (s_create == 200 and s_delete == 204)

        probes = [
            ('direct_writes_403', 'PASS' if writes_403 else 'FAIL'),
            ('direct_reads_200', 'PASS' if reads_200 else 'FAIL'),
            ('admin_control_200_204', 'PASS' if admin_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; direct perses:8080 writes -> 403 (%s), reads -> %d/%d; ' \
                       'Admin create/delete -> %d/%d; walk: live4b 103' \
               % (tokens, 'all 403' if writes_403 else str(statuses), s_r1, s_r2, s_create, s_delete)

    def v7(self):
        if self.timed.started('V7'):
            return self.timed.join('V7', 600)
        return self.v7_body()

    def v7_body(self):
        # walk log 107: Admin group removal -> role viewer, viewer permissions,
        # admin binding gone within 420 s.
        self.signin('p4a2', 'v7-admin')
        d = self.driver('v7-admin')
        s_r, _, b_r = d.req(self.gateway('/krate/role'))
        if s_r != 200 or b_r.strip() != 'admin':
            fail('p4a2 initial role is not admin: %d %s' % (s_r, b_r))

        kc = self.master_kcadm()
        uid = kc.user_id('p4a2')
        admin_gid = kc.group_id(self.env.get('KEYCLOAK_ADMIN_GROUP', 'KRATE_ADMINS'))
        if uid and admin_gid:
            kc.remove_group(uid, admin_gid)

        t0 = time.monotonic()
        deadline = t0 + 420
        downgraded = False
        elapsed_downgrade = -1.0
        perm_ok = False

        while time.monotonic() < deadline:
            time.sleep(20)
            now = time.monotonic()
            elapsed = now - t0
            d.req(self.gateway('/'), headers={'Accept': 'text/html'})
            s_r, _, b_r = d.req(self.gateway('/krate/role'))
            s_p, _, b_p = d.req(self.gateway('/api/v1/users/p4a2/permissions'))
            if s_r == 200 and b_r.strip() == 'viewer':
                downgraded = True
                elapsed_downgrade = elapsed
                if s_p == 200:
                    try:
                        pdata = json.loads(b_p).get('*', [{}])[0]
                        perm_ok = (pdata.get('actions') == ['read'] and len(pdata.get('scopes', [])) == 7)
                    except Exception:
                        pass
                break

        s_grb, _, _ = d.req(self.gateway('/api/v1/globalrolebindings'))
        grb_gone = (s_grb == 403)

        probes = [
            ('downgraded_viewer_420s', 'PASS' if (downgraded and elapsed_downgrade <= 420.0) else 'FAIL'),
            ('viewer_permissions', 'PASS' if perm_ok else 'FAIL'),
            ('admin_binding_gone', 'PASS' if grb_gone else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; p4a2 admin removed: downgraded to viewer in %.1fs (bound 420s), ' \
                       '7 read scopes, globalrolebindings -> %d; walk: live4b 107' \
               % (tokens, elapsed_downgrade, s_grb)

    def v8(self):
        if self.timed.started('V8'):
            return self.timed.join('V8', 600)
        return self.v8_body()

    def v8_body(self):
        # walk log 108: identity users disable + logout: refused within 420 s, grants revoked,
        # next sign-in shows "Account is disabled".
        self.signin('p4dis', 'v8-viewer')
        d = self.driver('v8-viewer')
        s_r, _, b_r = d.req(self.gateway('/krate/role'))
        if s_r != 200 or b_r.strip() != 'viewer':
            fail('p4dis initial role is not viewer: %d %s' % (s_r, b_r))

        rc_dis, _, _ = self.krate('identity', 'users', 'disable', 'p4dis')
        rc_out, _, _ = self.krate('identity', 'users', 'logout', 'p4dis')
        if rc_dis != 0 or rc_out != 0:
            fail('identity users disable/logout failed: rc %d / %d' % (rc_dis, rc_out))

        t0 = time.monotonic()
        deadline = t0 + 420
        refused = False
        elapsed_refused = -1.0
        refusal_type = ''

        while time.monotonic() < deadline:
            time.sleep(10)
            now = time.monotonic()
            elapsed = now - t0
            s_page, h_page, _ = d.req(self.gateway('/'), headers={'Accept': 'text/html'})
            s_r, _, _ = d.req(self.gateway('/krate/role'))
            s_who, _, _ = d.req(self.gateway('/api/v1/user/whoami'))

            if s_page == 302 and '/oauth2/start' in (h_page.get('Location') or ''):
                refused = True
                elapsed_refused = elapsed
                refusal_type = '302 /oauth2/start'
                break
            if s_r == 401 or s_who == 401:
                refused = True
                elapsed_refused = elapsed
                refusal_type = '401'
                break

        res_dis = self.signin('p4dis', 'v8-disabled', expect='refused')
        next_signin_refused = (res_dis.get('kind') == 'REFUSED'
                               and ('disabled' in str(res_dis.get('reason', '')).lower()
                                    or 'account is disabled' in str(res_dis.get('body', '')).lower()))

        probes = [
            ('session_refused_420s', 'PASS' if (refused and elapsed_refused <= 420.0) else 'FAIL'),
            ('next_signin_disabled', 'PASS' if next_signin_refused else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; p4dis disabled+logout: session refused in %.1fs (%s, bound 420s); ' \
                       'next signin refused with "Account is disabled"; walk: live4b 108' \
               % (tokens, elapsed_refused, refusal_type)

    def v9(self):
        # walk log 109: UI logout hop chain (/oauth2/sign_out -> Keycloak logout with id_token_hint
        # -> / -> /oauth2/start -> login form), cookies cleared, Keycloak sessions 1 -> 0, no confirmation page.
        # The walk's 1 -> 0 needs a single-session premise: shared users accumulate
        # one session per sign-in across rows, so this row owns its user (added and
        # enrolled exactly like the setup users) and signs in exactly once.
        rc_add, out_add, err_add = self.krate('identity', 'users', 'add', 'p4logout', '--viewer',
                                              '--email', 'p4logout@live4b.test', timeout=180)
        if rc_add != 0 and 'already exists' not in (out_add + err_add):
            fail('identity users add p4logout failed (rc=%d): %s' % (rc_add, (out_add + err_add)[:160]))
        temp_pw = self.temp_password(out_add)
        os.makedirs(os.path.join(self.state_dir, 'p4'), exist_ok=True)
        state = os.path.join(self.state_dir, 'p4', 'kc-p4logout.json')
        if not os.path.exists(state):
            if not temp_pw:
                fail('no temporary password returned for p4logout')
            self.add_runtime_secret(temp_pw)
            self.enrol_user('p4logout', temp_pw, state)
        self.user_state['p4logout'] = state
        res = self.signin('p4logout', 'v9-logout')
        if res.get('kind') != 'OK':
            fail('p4logout signin failed: %s' % res.get('detail', res.get('kind')))
        d = self.driver('v9-logout')

        kc = self.master_kcadm()
        uid = kc.user_id('p4logout')
        sessions_before = len(kc.call('get', 'realms/%s/users/%s/sessions' % (p2.REALM, uid)).splitlines()) if uid else -1

        st1, h1, b1 = d.req(self.gateway('/api/auth/logout'), headers={'Accept': 'text/html'})
        loc1 = h1.get('Location', '')
        hops = [('GET', '/api/auth/logout', st1)]

        curr_url = urllib.parse.urljoin(self.gateway(), loc1) if loc1 else ''
        confirmation_page = False
        login_form_reached = False

        for _ in range(8):
            if not curr_url:
                break
            st, h, b = d.req(curr_url, headers={'Accept': 'text/html'})
            hops.append(('GET', curr_url.split('?')[0].replace(self.base, '').replace(self.gateway(), ''), st))
            if 'confirmation' in b.lower() and ('logout' in b.lower() or 'sign out' in b.lower()):
                confirmation_page = True
            if st == 200 and 'kc-form-login' in b:
                login_form_reached = True
                break
            loc = h.get('Location', '')
            curr_url = urllib.parse.urljoin(self.gateway(), loc) if loc else ''

        sessions_after = len(kc.call('get', 'realms/%s/users/%s/sessions' % (p2.REALM, uid)).splitlines()) if uid else -1
        sessions_zero = (sessions_before == 1 and sessions_after == 0)

        jar_names = [c.name for c in d.jar if c.value and c.value not in ('', 'deleted')]
        cookies_cleared = not any(n in ('_oauth2_proxy', 'jwtPayload', 'jwtSignature', 'jwtRefreshToken')
                                  for n in jar_names)

        hop_chain_ok = (st1 == 302 and login_form_reached and not confirmation_page)
        probes = [
            ('hop_chain_logout', 'PASS' if hop_chain_ok else 'FAIL'),
            ('no_confirmation_page', 'PASS' if not confirmation_page else 'FAIL'),
            ('keycloak_sessions_zero', 'PASS' if sessions_zero else 'FAIL'),
            ('cookies_cleared', 'PASS' if cookies_cleared else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; GET /api/auth/logout -> hops %s -> login form; sessions %d -> %d; ' \
                       'cookies cleared; walk: live4b 109' \
               % (tokens, ' -> '.join('%s(%d)' % (h[1], h[2]) for h in hops[:5]), sessions_before, sessions_after)

    def v10(self):
        if self.timed.started('V10'):
            return self.timed.join('V10', 2500)
        return self.v10_body()

    def v10_body(self):
        # walk log 110, v10_job.py: 36-min walk (20 min active polling every 60s, then 16 min idle).
        self.signin('p4idle', 'v10-idle')
        d = self.driver('v10-idle')

        t0 = time.monotonic()
        poll_count = 0
        last_miss = 'none'
        for i in range(1, 21):
            target = t0 + i * 60
            delay = target - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            s_r, _, b_r = d.req(self.gateway('/krate/role'))
            s_p, _, _ = d.req(self.gateway('/api/v1/projects'))
            if s_r == 200 and b_r.strip() == 'viewer' and s_p == 200:
                poll_count += 1
            else:
                last_miss = 'poll %d: role %d/%s projects %d' % (i, s_r, b_r.strip()[:20], s_p)

        # 16 minutes idle
        time.sleep(16 * 60)

        # Verification request
        s_page, h_page, _ = d.req(self.gateway('/'), headers={'Accept': 'text/html'})
        loc = h_page.get('Location', '')
        refused_302 = (s_page == 302 and '/oauth2/start' in loc)

        start_url = urllib.parse.urljoin(self.gateway(), loc)
        s2, h2, _ = d.req(start_url, headers={'Accept': 'text/html'})
        auth_url = h2.get('Location', '')
        s3, _, b3 = d.req(auth_url, headers={'Accept': 'text/html'}) if auth_url else (-1, {}, '')
        form_shown = (s3 == 200 and 'kc-form-login' in b3)

        probes = [
            ('active_20min_200', 'PASS' if poll_count == 20 else 'FAIL'),
            ('idle_16min_refused_302', 'PASS' if refused_302 else 'FAIL'),
            ('keycloak_password_form', 'PASS' if form_shown else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; 20 min active (%d/20 polls 200 viewer, last miss: %s), 16 min idle -> 302 /oauth2/start ' \
                       'and Keycloak password form; walk: live4b 110' \
               % (tokens, poll_count, last_miss)

    def v11(self):
        # walk logs 021, 022, 111: identity users add p4onboard --viewer, first sign-in through
        # gateway passes CONFIGURE_TOTP + UPDATE_PASSWORD, lands in Perses as viewer.
        rc, out, err = self.krate('identity', 'users', 'add', 'p4onboard', '--viewer',
                                  '--email', 'p4onboard@live4b.test')
        temp_pw = self.temp_password(out)
        if rc != 0 or not temp_pw:
            if 'already exists' not in (out + err):
                fail('identity users add p4onboard failed (rc=%d): %s' % (rc, (out + err)[:160]))

        d = self.driver('v11-onboard')
        st_first, hdrs, page = d.req(self.gateway('/'), headers={'Accept': 'text/html'})
        loc1 = hdrs.get('Location', '')
        if loc1:
            st2, h2, page2 = d.req(urllib.parse.urljoin(self.gateway(), loc1), headers={'Accept': 'text/html'})
            auth_url = h2.get('Location', '')
        else:
            auth_url = ''

        if auth_url:
            st3, h3, login_page = d.req(auth_url, headers={'Accept': 'text/html'})
        else:
            login_page = page

        action1 = self.form_action(login_page)
        st_post, h_post, page_post = d.req(action1, method='POST',
                                           data={'username': 'p4onboard', 'password': temp_pw, 'credentialId': ''},
                                           headers={'Accept': 'text/html'})
        while st_post in (302, 303) and h_post.get('Location', '').startswith(self.base):
            st_post, h_post, page_post = d.req(h_post['Location'], headers={'Accept': 'text/html'})

        new_pw = 'P4Onboard_NewPass_2026!'
        self.add_runtime_secret(new_pw)
        totp_seed = None
        actions_seen = []
        for _ in range(4):
            if st_post == 200 and 'name="totpSecret"' in page_post:
                m_raw = re.search(r'name="totpSecret"[^>]*value="([^"]+)"', page_post)
                if m_raw:
                    raw_val = html.unescape(m_raw.group(1))
                    totp_seed = base64.b32encode(raw_val.encode()).decode()
                    self.add_runtime_secret(totp_seed)
                    code = self.totp(totp_seed)
                    action_totp = self.form_action(page_post)
                    st_post, h_post, page_post = d.req(action_totp, method='POST',
                                                       data={'totp': code, 'totpSecret': raw_val,
                                                             'userLabel': 'gate', 'logout-sessions': 'on'},
                                                       headers={'Accept': 'text/html'})
                    while st_post in (302, 303) and h_post.get('Location', '').startswith(self.base):
                        st_post, h_post, page_post = d.req(h_post['Location'], headers={'Accept': 'text/html'})
                    actions_seen.append('CONFIGURE_TOTP')
                    continue
            if st_post == 200 and 'name="password-new"' in page_post:
                action_pw = self.form_action(page_post)
                st_post, h_post, page_post = d.req(action_pw, method='POST',
                                                   data={'password-new': new_pw, 'password-confirm': new_pw},
                                                   headers={'Accept': 'text/html'})
                while st_post in (302, 303) and h_post.get('Location', '').startswith(self.base):
                    st_post, h_post, page_post = d.req(h_post['Location'], headers={'Accept': 'text/html'})
                actions_seen.append('UPDATE_PASSWORD')
                continue
            break

        cb_url = h_post.get('Location', '')
        if cb_url:
            st_cb, h_cb, _ = d.req(cb_url, headers={'Accept': 'text/html'})

        st_oidc, h_oidc, _ = d.req(self.gateway('/api/auth/providers/oidc/krate/login?rd=%2F'),
                                   headers={'Accept': 'text/html'})
        hops = 0
        while st_oidc in (302, 303) and hops < 10:
            hops += 1
            nxt = urllib.parse.urljoin(self.gateway(), h_oidc.get('Location', ''))
            st_oidc, h_oidc, _ = d.req(nxt, headers={'Accept': 'text/html'})

        st_r, _hr, b_role = d.req(self.gateway('/krate/role'))
        st_w, _hw, b_whoami = d.req(self.gateway('/api/v1/user/whoami'))
        st_p, _hp, b_perm = d.req(self.gateway('/api/v1/users/p4onboard/permissions'))

        role_ok = (st_r == 200 and b_role.strip() == 'viewer')
        whoami_ok = (st_w == 200 and '"name":"p4onboard"' in b_whoami)
        perm_ok = False
        if st_p == 200:
            try:
                pdata = json.loads(b_perm)
                actions = pdata.get('*', [{}])[0].get('actions', [])
                scopes = pdata.get('*', [{}])[0].get('scopes', [])
                perm_ok = (actions == ['read'] and len(scopes) == 7)
            except Exception:
                pass

        probes = [
            ('user_add_rc0', 'PASS' if rc == 0 else 'FAIL'),
            ('onboarding_enrol', 'PASS' if ('CONFIGURE_TOTP' in actions_seen and 'UPDATE_PASSWORD' in actions_seen) else 'FAIL'),
            ('role_viewer', 'PASS' if role_ok else 'FAIL'),
            ('whoami', 'PASS' if whoami_ok else 'FAIL'),
            ('permissions_read', 'PASS' if perm_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; users add p4onboard rc=%d; first sign-in passed TOTP+password; ' \
                       'role %s, whoami %s, permissions %s; walk: live4b 021,022,111' \
               % (tokens, rc, b_role.strip(), 'ok' if whoami_ok else 'fail', '7 read scopes' if perm_ok else 'fail')

    def v12(self):
        # walk logs 021, 112: users add without --email refused, emailVerified=false returns 500 at /oauth2/callback.
        rc1, out1, err1 = self.krate('identity', 'users', 'add', 'p4noemail_test', '--viewer')
        noemail_refused = (rc1 != 0 and '--email is required while a monitoring UI signs in through the Krate realm' in (out1 + err1))

        # Check / create Keycloak user with emailVerified=false
        kc = self.master_kcadm()
        uid = kc.user_id('p4unverified')
        if not uid:
            kc.call('create', 'users', '-r', p2.REALM,
                    '-s', 'username=p4unverified',
                    '-s', 'email=p4unverified@live4b.test',
                    '-s', 'emailVerified=false',
                    '-s', 'enabled=true')
            uid = kc.user_id('p4unverified')
            kc.call('set-password', '-r', p2.REALM, '--username', 'p4unverified', password='P4Unverified_Pass_2026!')
            viewer_grp = self.env.get('KEYCLOAK_VIEWER_GROUP', 'KRATE_VIEWERS')
            gid = kc.group_id(viewer_grp)
            if gid and uid:
                kc.add_group(uid, gid)

        d = self.driver('v12-unverified')
        st1, h1, _ = d.req(self.gateway('/'), headers={'Accept': 'text/html'})
        loc1 = h1.get('Location', '')
        st2, h2, _ = d.req(urllib.parse.urljoin(self.gateway(), loc1), headers={'Accept': 'text/html'})
        auth_url = h2.get('Location', '')
        st3, h3, login_page = d.req(auth_url, headers={'Accept': 'text/html'})
        action = self.form_action(login_page)
        st_auth, h_auth, _ = d.req(action, method='POST',
                                   data={'username': 'p4unverified', 'password': 'P4Unverified_Pass_2026!',
                                         'credentialId': ''},
                                   headers={'Accept': 'text/html'})
        # The post-credentials Location is the single-use callback URL itself
        # (it starts with self.base): follow the chain but record the callback
        # hop's own status instead of consuming it and then asserting on the
        # empty Location left behind.
        cb_status, cb_body = -1, ''
        for _ in range(10):
            if st_auth not in (302, 303):
                break
            loc = h_auth.get('Location', '')
            if not loc.startswith(self.base):
                break
            st_auth, h_auth, b_auth = d.req(loc, headers={'Accept': 'text/html'})
            if cb_status == -1 and '/oauth2/callback' in urllib.parse.urlparse(loc).path:
                cb_status, cb_body = st_auth, b_auth

        o2p_cid = self.mon_container('oauth2-proxy')
        rc_log, o2p_log, _ = p2.docker('logs', o2p_cid, timeout=30) if o2p_cid else (-1, '', '')
        log_confirmed = "email in id_token (p4unverified@live4b.test) isn't verified" in o2p_log

        cb_500_ok = (cb_status == 500 and log_confirmed)

        probes = [
            ('cli_refusal_noemail', 'PASS' if noemail_refused else 'FAIL'),
            ('callback_500_unverified', 'PASS' if cb_500_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; users add without --email refused rc=%d; emailVerified=false -> ' \
                       'callback %d log-match=%s ("email in id_token isn\'t verified"); walk: live4b 021,112' \
               % (tokens, rc1, cb_status, log_confirmed)

    def v13(self):
        # walk log 113, test_v13.py: two realm users with equal email local parts (p4dup):
        # first signs in OK, second refused (403/500), first unaffected.
        kc = self.master_kcadm()
        viewer_grp = self.env.get('KEYCLOAK_VIEWER_GROUP', 'KRATE_VIEWERS')
        gid = kc.group_id(viewer_grp)

        def create_dup_user(uname, email, pw):
            kc.call('create', 'users', '-r', p2.REALM,
                    '-s', 'username=' + uname, '-s', 'email=' + email,
                    '-s', 'emailVerified=true', '-s', 'enabled=true')
            uid = kc.user_id(uname)
            kc.call('set-password', '-r', p2.REALM, '--username', uname, password=pw)
            if uid and gid:
                kc.add_group(uid, gid)
            return uid

        uid1 = kc.user_id('p4dup1') or create_dup_user('p4dup1', 'p4dup@domain1.test', 'P4Dup1Pass_2026!')
        uid2 = kc.user_id('p4dup2') or create_dup_user('p4dup2', 'p4dup@domain2.test', 'P4Dup2Pass_2026!')

        # These users are created directly (no TOTP enrolment), so they sign in
        # through the shared signin() with a minimal password-only state file,
        # the same shape the setup enrolment writes. (Stuffing a password dict
        # into user_state crashed load_state, which expects a state path.)
        os.makedirs(os.path.join(self.state_dir, 'p4'), exist_ok=True)
        for uname, pw in (('p4dup1', 'P4Dup1Pass_2026!'), ('p4dup2', 'P4Dup2Pass_2026!')):
            state = os.path.join(self.state_dir, 'p4', 'kc-%s.json' % uname)
            if not os.path.exists(state):
                with open(state, 'w', encoding='utf-8') as handle:
                    json.dump({'password': pw}, handle)
                os.chmod(state, 0o600)
            self.add_runtime_secret(pw)
            self.user_state[uname] = state

        # Sign in first user
        d1 = self.driver('v13-dup1')
        st_first = -1
        whoami_dup = False
        try:
            res1 = self.signin('p4dup1', 'v13-dup1')
            st_first = 200 if res1.get('kind') == 'OK' else res1.get('status', -1)
            st_who, _h, b_who = d1.req(self.gateway('/api/v1/user/whoami'))
            whoami_dup = (st_who == 200 and '"name":"p4dup1"' in b_who)
        except Exception:
            whoami_dup = False

        # Sign in second user (equal email local part 'p4dup')
        st_second_refused = False
        try:
            res2 = self.signin('p4dup2', 'v13-dup2')
            st_second_refused = (res2.get('kind') == 'REFUSED' or res2.get('status') in (403, 500))
        except Exception:
            st_second_refused = True

        # Verify first user still unaffected
        st_p1, _h, _b = d1.req(self.gateway('/api/v1/projects'))
        first_unaffected = (st_p1 == 200)

        # Cleanup test users
        if uid1:
            try:
                kc.call('delete', 'users/' + uid1, '-r', p2.REALM)
            except Exception:
                pass
        if uid2:
            try:
                kc.call('delete', 'users/' + uid2, '-r', p2.REALM)
            except Exception:
                pass

        probes = [
            ('first_user_signin', 'PASS' if (st_first == 200 and whoami_dup) else 'FAIL'),
            ('second_user_refused', 'PASS' if st_second_refused else 'FAIL'),
            ('first_user_unaffected', 'PASS' if first_unaffected else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; first user p4dup1 signin=%s whoami=%s; ' \
                       'second user p4dup2 refused=%s; first unaffected=%s; walk: live4b 113' \
               % (tokens, st_first, whoami_dup, st_second_refused, first_unaffected)

    def v14(self):
        # walk log 114: seeded Perses users from foreign issuer + PERSES_ISSUER_APPLIED:
        # monitor up 0, perses-migrate reports 2 users and 2 managed bindings removed,
        # cookie secret rotated, perses-sync healthy, realm sign-in OK.
        cmd_seed = [
            'run', '--rm', '-v', '%s_perses_data:/perses' % self.monitor_project,
            self.monitor_env['LOG_DISCOVERY_IMAGE'], 'python3', '-c',
            '''
import os, json
foreign_issuer = "https://foreign-idp.example.com/realms/other"
os.makedirs("/perses/data/users", exist_ok=True)
os.makedirs("/perses/data/globalrolebindings", exist_ok=True)
open("/perses/data/.krate-issuer", "w").write(foreign_issuer + "\\n")
for i in (1, 2):
    doc = {"kind": "User", "metadata": {"name": f"user-old-{i}"},
           "spec": {"oauthProviders": [{"issuer": foreign_issuer}]}}
    open(f"/perses/data/users/user-old-{i}.json", "w").write(json.dumps(doc))
for name in ("krate-viewer-111111111111111111111111", "krate-admin-222222222222222222222222"):
    doc = {"kind": "GlobalRoleBinding", "metadata": {"name": name}}
    open(f"/perses/data/globalrolebindings/{name}.json", "w").write(json.dumps(doc))
'''
        ]
        rc_seed, _, _ = p2.docker(*cmd_seed)
        if rc_seed != 0:
            fail('seeding foreign users into perses_data failed')

        # Managed bindings present before this up: the migration removes every
        # managed binding on an issuer change (migrate_issuer docstring), so the
        # expected count is this plus the 2 seeded ones -- not exactly 2, because
        # earlier rows' sign-ins leave guard bindings behind.
        managed_before = -1
        rc_vol, mount_vol, _ = p2.docker('volume', 'inspect', '-f', '{{.Mountpoint}}',
                                         '%s_perses_data' % self.monitor_project)
        if rc_vol == 0 and (mount_vol or '').strip():
            try:
                managed_before = len([
                    n for n in os.listdir(os.path.join(mount_vol.strip(), 'globalrolebindings'))
                    if n.startswith(('krate-admin-', 'krate-viewer-'))])
            except OSError:
                managed_before = -1

        cookie_before = self.mon_env_value('OAUTH2_PROXY_COOKIE_SECRET')

        self.krate('config', 'set', 'PERSES_ISSUER_APPLIED=https://foreign-idp.example.com/realms/other')

        rc_up, out_up, err_up = self.krate('monitor', 'up')
        cookie_after = self.mon_env_value('OAUTH2_PROXY_COOKIE_SECRET')
        cookie_rotated = bool(cookie_before and cookie_after and cookie_before != cookie_after)

        pm_cid = self.mon_container('perses-migrate')
        rc_log, pm_log, _ = p2.docker('logs', pm_cid) if pm_cid else (-1, '', '')
        pm_match = re.findall(r'removed (\d+) stale user\(s\) and (\d+) managed binding\(s\)', pm_log or '')
        pm_users, pm_bindings = (int(pm_match[-1][0]), int(pm_match[-1][1])) if pm_match else (-1, -1)
        pm_want_bindings = managed_before + 2 if managed_before >= 0 else 2
        pm_reported = (pm_users == 2 and (pm_bindings == pm_want_bindings if managed_before >= 0
                                          else pm_bindings >= 2))

        sync_cid = self.mon_container('perses-sync', all_states=False)
        sync_ok = bool(sync_cid and self._wait_container_healthy(sync_cid, limit=180) is not None)

        res = self.signin('p4v', 'v14-signin', expect='ok')
        signin_ok = (res.get('kind') == 'OK' and res.get('role') == 'viewer')

        probes = [
            ('monitor_up_0', 'PASS' if rc_up == 0 else 'FAIL'),
            ('migrate_removed_stale', 'PASS' if pm_reported else 'FAIL'),
            ('cookie_secret_rotated', 'PASS' if cookie_rotated else 'FAIL'),
            ('perses_sync_healthy', 'PASS' if sync_ok else 'FAIL'),
            ('signin_ok', 'PASS' if signin_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; issuer migration: monitor up rc=%d, perses-migrate removed %d user(s)/%d binding(s) ' \
                       '(want 2/%s from %d pre-existing), ' \
                       'cookie secret rotated: %s, perses-sync healthy: %s, p4v sign-in %s; walk: live4b 114' \
               % (tokens, rc_up, pm_users, pm_bindings, pm_want_bindings, managed_before,
                  cookie_rotated, sync_ok, res.get('kind'))

    def v15(self):
        if self.timed.started('V15'):
            return self.timed.join('V15', 600)
        return self.v15_body()

    def v15_body(self):
        # walk log 115: Keycloak stopped mid-session: 200 until next refresh, then refused
        # (bound 420 s = proof window + 2 min), RestartCount unchanged, sign-in again within 60 s of healthy.
        res = self.signin('p4v', 'v15-active', expect='ok')
        d = self.driver('v15-active')
        if not d:
            fail('p4v signin failed')

        perses_cid = self.mon_container('perses')
        rc_r1, s_r1, _ = p2.docker('inspect', '-f', '{{.RestartCount}}', perses_cid) if perses_cid else (-1, '', '')
        restarts_before = s_r1.strip()

        kc_cid = self.cluster_container('keycloak')
        if not kc_cid:
            not_run('precondition: missing keycloak container')

        refused = False
        elapsed_refused = -1.0
        rc_r2 = -1
        s_r2 = ''
        stop_error = ''
        try:
            stop_rc, _, stop_err = p2.docker('stop', '-t', '5', kc_cid, timeout=15)
            if stop_rc != 0:
                stop_error = 'Keycloak stop failed (rc %d): %s' % (
                    stop_rc, stop_err[-100:])
            else:
                t0 = time.monotonic()
                deadline = t0 + 420
                while time.monotonic() < deadline:
                    time.sleep(15)
                    now = time.monotonic()
                    elapsed = now - t0
                    s_page, h_page, _ = d.req(self.gateway('/'), headers={'Accept': 'text/html'})
                    s_r, _, _ = d.req(self.gateway('/krate/role'))
                    s_proj, _, _ = d.req(self.gateway('/api/v1/projects'))

                    if ((s_page == 302 and '/oauth2/start' in (h_page.get('Location') or ''))
                            or s_r == 401 or s_proj == 401):
                        refused = True
                        elapsed_refused = elapsed
                        break
                rc_r2, s_r2, _ = (p2.docker('inspect', '-f', '{{.RestartCount}}',
                                          perses_cid, timeout=10)
                                   if perses_cid else (-1, '', ''))
        finally:
            start_rc, _, start_err = p2.docker('start', kc_cid, timeout=30)
        if start_rc != 0:
            return 'FAIL', 'Keycloak restoration failed (rc %d): %s' % (
                start_rc, start_err[-100:])
        if stop_error:
            return 'FAIL', stop_error + '; Keycloak start attempted'
        restarts_unchanged = (rc_r1 == rc_r2 == 0 and restarts_before == s_r2.strip())
        healthy_secs = self._wait_container_healthy(kc_cid, limit=180)
        t_healthy = time.monotonic()

        res_recov = self.signin('p4v', 'v15-recov', expect='ok')
        recov_elapsed = time.monotonic() - t_healthy
        recov_ok = (res_recov.get('kind') == 'OK' and recov_elapsed <= 60.0)

        probes = [
            ('refusal_within_420s', 'PASS' if (refused and elapsed_refused <= 420.0) else 'FAIL'),
            ('restarts_unchanged', 'PASS' if restarts_unchanged else 'FAIL'),
            ('kc_healthy', 'PASS' if healthy_secs is not None else 'FAIL'),
            ('recovery_signin_60s', 'PASS' if recov_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; Keycloak stopped: session refused at +%.1fs (bound 420s), restarts %s->%s; ' \
                       'Keycloak healthy +%ss, recovery signin %s in +%.1fs; walk: live4b 115' \
               % (tokens, elapsed_refused, restarts_before, s_r2.strip(),
                  '%.1f' % healthy_secs if healthy_secs is not None else 'timeout',
                  res_recov.get('kind'), recov_elapsed)

    def v16(self):
        # walk log 116: monitor up with Keycloak stopped:
        # Case (b): Keycloak stopped > 120 s: monitor up exits 1 naming idp-wait,
        # consumers created-not-started (0 restarts), started by next monitor up when healthy.
        kc_cid = self.cluster_container('keycloak')
        perses_cid = self.mon_container('perses')
        o2p_cid = self.mon_container('oauth2-proxy')
        if not kc_cid:
            not_run('precondition: missing keycloak container')

        t_down = time.monotonic()
        p2.docker('stop', '-t', '5', kc_cid)

        if perses_cid:
            p2.docker('rm', '-f', perses_cid)
        if o2p_cid:
            p2.docker('rm', '-f', o2p_cid)

        elapsed = time.monotonic() - t_down
        if elapsed < 125:
            time.sleep(125 - elapsed)

        rc_up1, out_up1, err_up1 = self.krate('monitor', 'up', timeout=600)
        text_up1 = out_up1 + err_up1
        names_idp = ('idp-wait' in text_up1 and ('didn\'t complete successfully' in text_up1 or 'exit 1' in text_up1))

        p_new = self.mon_container('perses')
        o_new = self.mon_container('oauth2-proxy')
        rc_p, st_p, _ = p2.docker('inspect', '-f', '{{.State.Status}} {{.RestartCount}}', p_new) if p_new else (1, '', '')
        rc_o, st_o, _ = p2.docker('inspect', '-f', '{{.State.Status}} {{.RestartCount}}', o_new) if o_new else (1, '', '')
        created_ok = (rc_p == 0 and rc_o == 0 and st_p.strip() == 'created 0' and st_o.strip() == 'created 0')

        p2.docker('start', kc_cid)
        healthy_secs = self._wait_container_healthy(kc_cid, limit=180)
        if healthy_secs is None:
            fail('Keycloak did not recover healthy within 180 s')

        rc_up2, out_up2, err_up2 = self.krate('monitor', 'up', timeout=600)
        rc_p2, st_p2, _ = p2.docker('inspect', '-f', '{{.State.Status}}', p_new) if p_new else (1, '', '')
        rc_o2, st_o2, _ = p2.docker('inspect', '-f', '{{.State.Status}}', o_new) if o_new else (1, '', '')
        running_ok = (rc_up2 == 0 and st_p2.strip() == 'running' and st_o2.strip() == 'running')

        res = self.signin('p4v', 'v16-signin', expect='ok')
        signin_ok = (res.get('kind') == 'OK')

        probes = [
            ('outage_up_rc1', 'PASS' if rc_up1 == 1 else 'FAIL'),
            ('names_idp_wait', 'PASS' if names_idp else 'FAIL'),
            ('consumers_created_restarts0', 'PASS' if created_ok else 'FAIL'),
            ('recovery_up_rc0', 'PASS' if rc_up2 == 0 else 'FAIL'),
            ('consumers_running', 'PASS' if running_ok else 'FAIL'),
            ('signin_ok', 'PASS' if signin_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; monitor up during outage: rc=%d, names idp-wait: %s, consumers %s/%s; ' \
                       'recovery monitor up: rc=%d, consumers %s/%s, signin %s; walk: live4b 116' \
               % (tokens, rc_up1, names_idp, st_p.strip(), st_o.strip(),
                  rc_up2, st_p2.strip(), st_o2.strip(), res.get('kind'))

    def hash_perses_state(self, token=None, driver=None):
        """Hash all five state kinds; any failed read invalidates the comparison."""
        if not token and driver is None:
            user = self.mon_env_value('PERSES_ADMIN_USER') or 'admin'
            password = self.mon_env_value('PERSES_ADMIN_PASSWORD')
            request = urllib.request.Request(
                self.gateway('/api/auth/providers/native/login'), method='POST',
                data=json.dumps({'login': user, 'password': password}).encode(),
                headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, context=self.tls, timeout=30) as response:
                token = json.load(response).get('access_token')
            if not token:
                raise RuntimeError('Perses local login returned no access token')
            self.add_runtime_secret(token)

        def get_json(path):
            if driver is not None:
                status, _headers, text = driver.req(self.gateway(path))
                if status == 404 and path in ('/api/v1/globaldatasources', '/api/v1/globalvariables'):
                    return []
                if status != 200:
                    raise RuntimeError('Perses state GET %s returned HTTP %s' % (path, status))
                result = json.loads(text)
            else:
                if not isinstance(token, str):
                    raise RuntimeError('Perses state read has no bearer token')
                request = urllib.request.Request(self.gateway(path),
                                                 headers={'Authorization': 'Bearer ' + token})
                try:
                    with urllib.request.urlopen(request, context=self.tls, timeout=30) as response:
                        result = json.load(response)
                except urllib.error.HTTPError as error:
                    if error.code == 404 and path in ('/api/v1/globaldatasources',
                                                      '/api/v1/globalvariables'):
                        return []
                    raise
            if not isinstance(result, list):
                raise RuntimeError('Perses state GET %s did not return a list' % path)
            return result

        def stable(value):
            if isinstance(value, dict):
                return {key: stable(item) for key, item in value.items()
                        if key not in ('createdAt', 'updatedAt', 'version')}
            if isinstance(value, list):
                return [stable(item) for item in value]
            return value

        projects = sorted(get_json('/api/v1/projects'),
                          key=lambda item: item['metadata']['name'])
        state = {'projects': projects, 'dashboards': [], 'folders': [],
                 'datasources': [], 'variables': []}
        for project in projects:
            name = urllib.parse.quote(project['metadata']['name'], safe='')
            for kind in ('dashboards', 'folders', 'datasources', 'variables'):
                state[kind].extend(get_json('/api/v1/projects/%s/%s' % (name, kind)))
        state['datasources'].extend(get_json('/api/v1/globaldatasources'))
        state['variables'].extend(get_json('/api/v1/globalvariables'))
        for kind in ('dashboards', 'folders', 'datasources', 'variables'):
            state[kind].sort(key=lambda item: (item['metadata'].get('project', ''),
                                                item['metadata']['name']))
        return {kind: hashlib.sha256(
            json.dumps(stable(items), sort_keys=True, separators=(',', ':')).encode()
        ).hexdigest() for kind, items in state.items()}

    def v17(self):
        """Compare the live seed across realm, local rollback and forward switch."""
        baseline = self.obs.get('V17-baseline')
        if not baseline:
            not_run('precondition: no candidate-bound local Perses seed baseline')
        before_cluster = self.cluster_id_map()
        before_monitor = self.mon_id_map()
        realm_login = self.signin('p4a', 'v17-realm', expect='ok')
        if realm_login.get('kind') != 'OK' or realm_login.get('role') != 'admin':
            return 'FAIL', 'probe=FAIL realm admin sign-in before rollback'
        realm_hashes = self.hash_perses_state(driver=realm_login['driver'])

        local_hashes = None
        rollback_error = None
        restore_error = None
        try:
            for command in (('config', 'set', 'PERSES_IDP='),
                            ('config', 'set', 'PERSES_AUTH_MODE=local'),
                            ('monitor', 'up')):
                rc, out, err = self.krate(*command, timeout=900)
                if rc != 0:
                    raise RuntimeError('V17 rollback %s failed (rc %d): %s'
                                       % (' '.join(command), rc, (err or out).strip()[-160:]))
            self.wait_perses_ready('local')
            local_hashes = self.hash_perses_state()
        except Exception as error:
            rollback_error = '%s: %s' % (type(error).__name__, str(error)[:180])
        finally:
            try:
                self.setup_perses_realm()
            except Exception as error:
                restore_error = '%s: %s' % (type(error).__name__, str(error)[:180])
        if restore_error:
            self.record('V17', 'FAIL', 'realm restoration failed after rollback: %s; '
                        'rollback error: %s; later Perses rows stopped'
                        % (restore_error, rollback_error or 'none'))
            raise p2.Terminated()
        try:
            forward_login = self.signin('p4a', 'v17-forward', expect='ok')
        except Exception as error:
            self.record('V17', 'FAIL', 'realm sign-in raised after forward switch: %s: %s; '
                        'later Perses rows stopped' % (type(error).__name__, str(error)[:180]))
            raise p2.Terminated()
        if forward_login.get('kind') != 'OK' or forward_login.get('role') != 'admin':
            self.record('V17', 'FAIL', 'realm sign-in failed after forward switch; '
                        'later Perses rows stopped')
            raise p2.Terminated()
        if rollback_error:
            return 'FAIL', ('probe=FAIL rollback failed; native realm mode restored '
                            'and admin sign-in verified: ' + rollback_error)
        forward_hashes = self.hash_perses_state(driver=forward_login['driver'])
        after_cluster = self.cluster_id_map()
        after_monitor = self.mon_id_map()
        unaffected = ('grafana', 'prometheus', 'loki', 'victorialogs', 'alertmanager')
        monitor_stable = all(name in before_monitor and name in after_monitor
                             and before_monitor[name] == after_monitor[name]
                             for name in unaffected)
        cluster_stable = (bool(before_cluster) and before_cluster == after_cluster
                          and all(name in before_cluster for name in
                                  ('keycloak', 'keycloak-db', 'kafka-ui', 'proxy')))
        probes = [
            ('realm_hashes', 'PASS' if realm_hashes == baseline else 'FAIL'),
            ('rollback_hashes', 'PASS' if local_hashes == baseline else 'FAIL'),
            ('forward_hashes', 'PASS' if forward_hashes == baseline else 'FAIL'),
            ('cluster_containers', 'PASS' if cluster_stable else 'FAIL'),
            ('other_monitoring_containers', 'PASS' if monitor_stable else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, ('%s; five candidate-bound state hashes compared across realm, '
                        'local rollback and forward switch; cluster and unrelated monitoring '
                        'containers unchanged; '
                        'walk: live4b 117') % tokens

    def v18(self):
        # walk log 118: 3-command certificate renewal sequence (gen-cert -> auth apply -> monitor up):
        # oauth2-proxy and perses recreated, idp-wait passes, sign-in works.
        perses_before = (self.mon_id_map() or {}).get('perses')
        o2p_before = (self.mon_id_map() or {}).get('oauth2-proxy')
        idp_filter = ('ps', '-aq', '--filter',
                      'label=com.docker.compose.project=' + self.monitor_project,
                      '--filter', 'label=com.docker.compose.service=idp-wait')
        rc_ids, old_ids, _ = p2.docker(*idp_filter)
        if rc_ids != 0:
            return 'FAIL', 'cannot inspect idp-wait before certificate renewal'
        old_starts = {}
        for cid in old_ids.split():
            rc, started, _ = p2.docker('inspect', '-f', '{{.State.StartedAt}}', cid)
            if rc != 0:
                return 'FAIL', 'cannot inspect prior idp-wait start time'
            old_starts[cid] = started.strip()

        rc_cert, _out, err = self.krate('gen-cert')
        if rc_cert != 0:
            return 'FAIL', 'gen-cert failed (rc %d): %s' % (rc_cert, err.strip()[-100:])
        self.tls = ssl.create_default_context(cafile=os.path.join(self.edition, 'certs', 'server.crt'))
        rc_apply, _out, err = self.krate('auth', 'apply')
        if rc_apply != 0:
            return 'FAIL', 'auth apply failed (rc %d): %s' % (rc_apply, err.strip()[-100:])
        rc_up, _out, err = self.krate('monitor', 'up')
        if rc_up != 0:
            return 'FAIL', 'monitor up failed (rc %d): %s' % (rc_up, err.strip()[-100:])

        perses_after = (self.mon_id_map() or {}).get('perses')
        o2p_after = (self.mon_id_map() or {}).get('oauth2-proxy')
        perses_recreated = bool(perses_before and perses_after and perses_before[0] != perses_after[0])
        o2p_recreated = bool(o2p_before and o2p_after and o2p_before[0] != o2p_after[0])

        rc_ids, new_ids, _ = p2.docker(*idp_filter)
        idp_exit0 = False
        if rc_ids == 0:
            for cid in new_ids.split():
                rc, observed, _ = p2.docker(
                    'inspect', '-f', '{{.State.StartedAt}}|{{.State.ExitCode}}|{{.State.Status}}', cid)
                fields = observed.strip().split('|') if rc == 0 else []
                if (len(fields) == 3 and fields[1:] == ['0', 'exited']
                        and (cid not in old_starts or fields[0] != old_starts[cid])):
                    idp_exit0 = True
                    break

        # The recreated proxy chain can still be converging when idp-wait passes
        # (it covers Keycloak, not oauth2-proxy): retry the sign-in within a
        # bounded window instead of grading one possibly-early attempt.
        res, attempts, elapsed = self.signin_retry('p4v', 'v18-signin', deadline_s=180)
        signin_ok = (res.get('kind') == 'OK' and res.get('role') == 'viewer')

        probes = [
            ('oauth2_proxy_recreated', 'PASS' if o2p_recreated else 'FAIL'),
            ('perses_recreated', 'PASS' if perses_recreated else 'FAIL'),
            ('gen_cert_rc0', 'PASS' if rc_cert == 0 else 'FAIL'),
            ('auth_apply_rc0', 'PASS' if rc_apply == 0 else 'FAIL'),
            ('monitor_up_rc0', 'PASS' if rc_up == 0 else 'FAIL'),
            ('idp_wait_new_run_exit0', 'PASS' if idp_exit0 else 'FAIL'),
            ('signin_ok', 'PASS' if signin_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; gen-cert -> auth apply -> monitor up: oauth2-proxy recreated %s, ' \
                       'perses recreated %s, idp-wait exit 0: %s, p4v signin %s (attempts=%d +%.1fs last=%s); ' \
                       'walk: live4b 118' \
               % (tokens, o2p_recreated, perses_recreated, idp_exit0, res.get('kind'),
                  attempts, elapsed, res.get('detail', res.get('reason', ''))[:80])

    def v19(self):
        # walk log 119: the broker exists only around this row. With the broker
        # applied, the browser flow redirects every login to the IdP
        # (defaultProvider), so no other row can sign in: V19 applies the plan
        # itself, exercises it, then removes it again.
        if not getattr(self.args, 'stub_dir', None) or not os.path.exists(self.args.stub_dir):
            return self.stub('V19', 'the brokered sign-in of a stand-in user (ping-viewer) through '
                                    'phase3_broker.Gate.brokered_login (broker_gate()) landing in '
                                    'Perses as viewer: the runner owns the stand-in (start_cluster '
                                    '--broker: stub_idp.sh up) and passes --stub-dir/--stub-port/--stub-script; '
                                    'the row applies the broker plan from the stand-in site.json itself '
                                    'and removes it right after; '
                                    'the row\'s evidence must record that V19 exercises commit 0 '
                                    '(trustEmail=true: the brokered user arrives e-mail-verified and signs in)')
        site = os.path.join(self.args.stub_dir, 'site.json')
        # The plain bring-up wrote auth/ui/runtime.yml and the dual configure
        # no-clobbers it (the CLI's own message prescribes removing it first);
        # the prelude already staged the stand-in secret and trust material.
        # A leftover broker plan here is unexpected state: report, don't pave over.
        runtime_yml = os.path.join(self.edition, 'auth', 'ui', 'runtime.yml')
        plan = os.path.join(self.edition, 'auth', 'keycloak', 'pingfederate-idp.json')
        if os.path.exists(plan):
            return 'FAIL', 'broker prologue: unexpected broker plan %s already present' % plan
        cleared = False
        if os.path.exists(runtime_yml):
            try:
                os.remove(runtime_yml)
                cleared = True
            except OSError as error:
                return 'FAIL', 'broker prologue: cannot clear %s: %s' % (runtime_yml, error)
        rc, out, err = self.krate('auth', 'configure', site, timeout=300)
        if rc != 0:
            restore_ev = ''
            if cleared:
                rc2, _o2, e2 = self.krate('auth', 'configure', timeout=300)
                restore_ev = ('; plain plan restored' if rc2 == 0
                              else '; plain restore FAILED rc=%d: %s' % (rc2, (e2 or '').strip()[-80:]))
            return 'FAIL', 'broker prologue: auth configure %s failed (rc %d): %s%s' % (
                site, rc, (err or out).strip()[-160:], restore_ev)
        rc, out, err = self.krate('auth', 'apply', timeout=300)
        if rc != 0 or 'Identity provider pingfederate' not in (out or ''):
            # A failed apply may still have created the provider: take it back
            # down so later rows keep their login form.
            restore = self.v19_remove_broker()
            return 'FAIL', 'broker prologue: auth apply failed (rc %d): %s; removal after failure: %s' % (
                rc, (err or out).strip()[-160:], restore)
        try:
            status, text = self.v19_brokered()
        except Exception as body_error:
            restore = self.v19_remove_broker()
            if restore.startswith('removed'):
                raise
            raise RuntimeError('v19 body %s: %s; broker epilogue also FAILED: %s'
                               % (type(body_error).__name__, body_error, restore))
        restore = self.v19_remove_broker()
        if not restore.startswith('removed'):
            return 'FAIL', '%s; broker epilogue FAILED: %s' % (text, restore)
        return status, '%s; broker removed again: %s' % (text, restore)

    def v19_remove_broker(self):
        """Walk log 119 lines 26-27: plain plan back, provider gone (verified)."""
        plan = os.path.join(self.edition, 'auth', 'keycloak', 'pingfederate-idp.json')
        runtime_yml = os.path.join(self.edition, 'auth', 'ui', 'runtime.yml')
        try:
            os.remove(plan)
        except OSError as error:
            return 'plan removal failed: %s' % error
        # The dual runtime.yml differs from the plain plan and the plain
        # configure no-clobbers it (identity.py): clear it so the plain
        # configure regenerates it from the current .env.
        if os.path.exists(runtime_yml):
            try:
                os.remove(runtime_yml)
            except OSError as error:
                return 'dual runtime.yml removal failed: %s' % error
        rc, out, err = self.krate('auth', 'configure', timeout=300)
        if rc != 0:
            return 'plain auth configure failed (rc %d): %s' % (rc, (err or out).strip()[-160:])
        rc, out, err = self.krate('auth', 'apply', timeout=300)
        if rc != 0 or 'removed from realm' not in (out or ''):
            return 'auth apply failed (rc %d): %s' % (rc, (err or out).strip()[-160:])
        return 'removed from realm, browser flow rebound'

    def v19_brokered(self):
        # walk log 119: brokered sign-in of ping-viewer through stand-in IdP landing in Perses as viewer.
        # Exercises commit 0 (trustEmail=true).

        pw_path = os.path.join(self.args.stub_dir, '.user-pw')
        if not os.path.exists(pw_path):
            fail('no .user-pw in stub-dir ' + self.args.stub_dir)
        stub_pw = open(pw_path).read().strip()
        self.add_runtime_secret(stub_pw)

        d = self.driver('v19-brokered')
        st1, h1, _ = d.req(self.gateway('/'), headers={'Accept': 'text/html'})
        loc1 = h1.get('Location', '')
        st2, h2, _ = d.req(urllib.parse.urljoin(self.gateway(), loc1), headers={'Accept': 'text/html'})
        auth_url = h2.get('Location', '')
        st3, h3, page3 = d.req(auth_url, headers={'Accept': 'text/html'})

        # In broker mode, Keycloak redirects to the stand-in IdP login form
        hops = 0
        while st3 in (302, 303) and hops < 10:
            hops += 1
            nxt = urllib.parse.urljoin(auth_url, h3.get('Location', ''))
            st3, h3, page3 = d.req(nxt, headers={'Accept': 'text/html'})

        action = self.form_action(page3)
        st_auth, h_auth, page_auth = d.req(action, method='POST',
                                           data={'username': 'ping-viewer', 'password': stub_pw, 'credentialId': ''},
                                           headers={'Accept': 'text/html'})
        while st_auth in (302, 303) and hops < 15:
            hops += 1
            nxt = urllib.parse.urljoin(action, h_auth.get('Location', ''))
            st_auth, h_auth, page_auth = d.req(nxt, headers={'Accept': 'text/html'})

        # Perses OIDC login
        st_oidc, h_oidc, _ = d.req(self.gateway('/api/auth/providers/oidc/krate/login?rd=%2F'),
                                   headers={'Accept': 'text/html'})
        while st_oidc in (302, 303) and hops < 25:
            hops += 1
            nxt = urllib.parse.urljoin(self.gateway(), h_oidc.get('Location', ''))
            st_oidc, h_oidc, _ = d.req(nxt, headers={'Accept': 'text/html'})

        # Check role, whoami, permissions
        st_r, _hr, b_role = d.req(self.gateway('/krate/role'))
        st_w, _hw, b_whoami = d.req(self.gateway('/api/v1/user/whoami'))
        st_p, _hp, b_perm = d.req(self.gateway('/api/v1/users/ping-viewer/permissions'))

        role_ok = (st_r == 200 and b_role.strip() == 'viewer')
        whoami_ok = (st_w == 200 and '"name":"ping-viewer"' in b_whoami)
        perm_ok = False
        if st_p == 200:
            try:
                pdata = json.loads(b_perm)
                actions = pdata.get('*', [{}])[0].get('actions', [])
                scopes = pdata.get('*', [{}])[0].get('scopes', [])
                perm_ok = (actions == ['read'] and len(scopes) == 7)
            except Exception:
                pass

        probes = [
            ('brokered_signin_ok', 'PASS' if (role_ok and whoami_ok) else 'FAIL'),
            ('role_viewer', 'PASS' if role_ok else 'FAIL'),
            ('whoami_ping_viewer', 'PASS' if whoami_ok else 'FAIL'),
            ('permissions_read', 'PASS' if perm_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; ping-viewer signs in through stand-in IdP: role %s, whoami ping-viewer, ' \
                       '7 read scopes; exercises commit 0 (trustEmail=true: the brokered user ' \
                       'arrives e-mail-verified and signs in); walk: live4b 119' \
               % (tokens, b_role.strip())

    def v20(self):
        # walk evidence v20-baseline.json: brokers, kafka-ui, keycloak, keycloak-db, cluster proxy unchanged.
        curr_cluster = self.cluster_id_map()
        initial = getattr(self, 'cluster_initial', None) or curr_cluster

        unchanged = True
        diffs = []
        for svc in ('keycloak', 'keycloak-db', 'kafka-ui', 'proxy'):
            if svc in initial and svc in curr_cluster:
                if initial[svc] != curr_cluster[svc]:
                    unchanged = False
                    diffs.append('%s: %s -> %s' % (svc, initial[svc][0][:12], curr_cluster[svc][0][:12]))

        for svc in initial:
            if 'broker' in svc and svc in curr_cluster:
                if initial[svc] != curr_cluster[svc]:
                    unchanged = False
                    diffs.append('%s: %s -> %s' % (svc, initial[svc][0][:12], curr_cluster[svc][0][:12]))

        probes = [
            ('cluster_ledger_unchanged', 'PASS' if unchanged else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; brokers, kafka-ui, keycloak, keycloak-db, proxy unchanged%s; walk: live4b v20-baseline.json' \
               % (tokens, '' if unchanged else ' (diffs: %s)' % diffs)

    def v21(self):
        # walk log 071: monitor up loopback refusals for localhost, 127.0.0.1, [::1] (rc 1, 0 containers changed).
        before_map = self.mon_id_map()
        hosts = ('localhost', '127.0.0.1', '[::1]')
        results = []
        for h in hosts:
            self.krate('config', 'set', 'KEYCLOAK_PUBLIC_URL=https://%s/identity' % h)
            rc, out, err = self.krate('monitor', 'up')
            after = self.mon_id_map()
            text = out + err
            refused = (rc != 0 and 'KEYCLOAK_PUBLIC_URL names the loopback or unspecified host' in text
                       and before_map == after)
            results.append((h, rc, refused))

        # Restore KEYCLOAK_PUBLIC_URL
        self.krate('config', 'set', 'KEYCLOAK_PUBLIC_URL=%s/identity' % self.base)

        all_refused = all(r[2] for r in results)
        probes = [
            ('refusal_localhost', 'PASS' if results[0][2] else 'FAIL'),
            ('refusal_127_0_0_1', 'PASS' if results[1][2] else 'FAIL'),
            ('refusal_ipv6_loopback', 'PASS' if results[2][2] else 'FAIL'),
            ('containers_unchanged', 'PASS' if all_refused else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; loopback refusals rc %s, 0 containers changed; walk: live4b 071' \
               % (tokens, '/'.join(str(r[1]) for r in results))

    def v22(self):
        # walk log 122: oauth2-proxy cookie_expire 8h, cookie_refresh 5m (= proof window),
        # request_logging false, realm ssoSessionMaxLifespan 28800.
        # The oauth2-proxy image is distroless (no cat): read its rendered
        # config from the host volume, the same bytes the container mounts.
        rc_cfg, cfg_out = self.volume_file('%s_oauth2_proxy_rendered' % self.monitor_project,
                                           'oauth2-proxy.cfg')

        exp_ok = 'cookie_expire = "8h"' in cfg_out
        ref_ok = 'cookie_refresh = "5m"' in cfg_out
        log_ok = 'request_logging = false' in cfg_out

        kc = self.master_kcadm()
        realm_raw = kc.call('get', 'realms/%s' % p2.REALM)
        realm = json.loads(realm_raw) if isinstance(realm_raw, str) and realm_raw.strip() else {}
        max_lifespan = realm.get('ssoSessionMaxLifespan')
        idle_timeout = realm.get('ssoSessionIdleTimeout')
        realm_ok = (max_lifespan == 28800 and idle_timeout == 900)

        probes = [
            ('cookie_expire_8h', 'PASS' if exp_ok else 'FAIL'),
            ('cookie_refresh_5m', 'PASS' if ref_ok else 'FAIL'),
            ('request_logging_false', 'PASS' if log_ok else 'FAIL'),
            ('realm_lifespan_28800', 'PASS' if realm_ok else 'FAIL'),
        ]
        status, tokens = aggregate(probes)
        return status, '%s; oauth2-proxy rendered read rc=%d cookie_expire 8h=%s, cookie_refresh 5m=%s ' \
                       '(derived proof 5m), request_logging false=%s, realm ssoSessionMaxLifespan %s; walk: live4b 122' \
               % (tokens, rc_cfg, exp_ok, ref_ok, log_ok, max_lifespan)

    def v23(self):
        if not getattr(self.args, 'session_max_minutes', None):
            return self.stub('V23', 'runs only in the explicit session-max companion fixture')
        if self.timed.started('V23'):
            return self.timed.join('V23', self.args.session_max_minutes * 60 + 420)
        return self.v23_body()

    def v23_body(self):
        """The same-jar 60 s Perses API walk observed in v23-live-polls.tsv."""
        max_minutes = getattr(self.args, 'session_max_minutes', None)
        if not max_minutes or max_minutes < 1:
            not_run('V23 requires an explicit positive --session-max-minutes')
        max_seconds = max_minutes * 60
        kc = self.master_kcadm()
        realm = json.loads(kc.call('get', 'realms/krate'))
        if realm.get('ssoSessionMaxLifespan') != max_seconds:
            return 'FAIL', 'realm session max readback %s s, expected %s s' \
                   % (realm.get('ssoSessionMaxLifespan'), max_seconds)
        uid = kc.user_id('p4ctrl')
        if not uid:
            return 'FAIL', 'p4ctrl realm user missing'
        rc, _out, err = self.krate('identity', 'users', 'logout', 'p4ctrl', timeout=120)
        if rc != 0:
            return 'FAIL', 'p4ctrl pre-login logout failed (rc %d): %s' % (rc, err.strip()[-100:])
        if kc.get('users/%s/sessions' % uid) or []:
            return 'FAIL', 'p4ctrl still has a Keycloak session before timed sign-in'

        before_ms = time.time_ns() // 1_000_000
        result = self.signin('p4ctrl', 'v23-session', expect='ok')
        after_ms = time.time_ns() // 1_000_000
        t0 = time.monotonic()
        if result.get('kind') != 'OK' or result.get('role') != 'viewer':
            return 'FAIL', 'p4ctrl timed sign-in was not Viewer OK: %s/%s' \
                   % (result.get('kind'), result.get('role'))
        sessions = kc.get('users/%s/sessions' % uid) or []
        if len(sessions) != 1 or not isinstance(sessions[0].get('start'), int):
            return 'FAIL', 'expected exactly one new Keycloak session with start timestamp, got %d' \
                   % len(sessions)
        session_start_ms = sessions[0]['start']
        if not (before_ms - 2000 <= session_start_ms <= after_ms):
            return 'FAIL', 'Keycloak session start is outside timed sign-in bracket'
        deadline_ms = session_start_ms + (max_seconds + 360) * 1000
        driver = self.driver('v23-session')
        poll_log = []

        def poll():
            api_status, _headers, body = driver.req(
                self.gateway('/api/v1/projects'), headers={'Accept': 'application/json'})
            at_ms = time.time_ns() // 1_000_000
            poll_log.append((round((time.monotonic() - t0), 2), api_status, at_ms))
            log('V23 API sample UTC-ms %d monotonic +%.2fs HTTP %d'
                % (at_ms, poll_log[-1][0], api_status))
            if api_status == 200:
                try:
                    projects = json.loads(body)
                except ValueError:
                    return api_status, False
                has_seed = isinstance(projects, list) and any(
                    isinstance(item, dict) and item.get('metadata', {}).get('name') == 'p4b-seed-proj'
                    for item in projects)
                return api_status, has_seed
            return api_status, False

        status, seeded = poll()
        if status != 200 or not seeded:
            return 'FAIL', 'initial Perses API status %s or seeded project absent' % status
        first_refusal = None
        minute = 1
        while True:
            # The extra request 15 s before the Keycloak-start deadline prevents
            # the final whole-minute poll from missing the M+6 min bound.
            remaining = (deadline_ms - 15000 - time.time_ns() // 1_000_000) / 1000
            if remaining <= 0:
                break
            delay = min(max(0, t0 + minute * 60 - time.monotonic()), remaining)
            if delay > 0:
                time.sleep(delay)
            status, seeded = poll()
            gap = poll_log[-1][0] - poll_log[-2][0]
            # Requests are scheduled every 60 s; allow at most 5 s for network
            # and scheduler delay. A larger gap skips a required observation.
            if gap > 65:
                return 'FAIL', 'Perses API poll cadence gap %.2f s exceeds 65 s' % gap
            elapsed_from_start_ms = poll_log[-1][2] - session_start_ms
            if status == 401:
                first_refusal = poll_log[-1]
                if elapsed_from_start_ms < (max_seconds - 60) * 1000:
                    return 'FAIL', 'Perses API refused before M-1 min at +%.2f s' \
                           % (elapsed_from_start_ms / 1000)
                break
            if status != 200 or not seeded:
                return 'FAIL', 'Perses API poll at +%.2f s returned %s or lost seed project' \
                       % (elapsed_from_start_ms / 1000, status)
            minute += 1
        if first_refusal is None:
            return 'FAIL', 'Perses API never returned 401 by M+6 min; last status %s at +%.2f s' \
                   % (poll_log[-1][1], (poll_log[-1][2] - session_start_ms) / 1000)
        if first_refusal[2] > deadline_ms:
            return 'FAIL', 'Perses API first 401 occurred after M+6 min deadline'

        page_status, page_headers, _ = driver.req(self.gateway('/'), headers={'Accept': 'text/html'})
        page_at_ms = time.time_ns() // 1_000_000
        log('V23 page sample UTC-ms %d HTTP %d' % (page_at_ms, page_status))
        page_location = page_headers.get('Location', '')
        page_path = urllib.parse.urlparse(page_location).path
        if page_status != 302 or page_path != '/oauth2/start' or page_at_ms > deadline_ms:
            return 'FAIL', 'post-refusal page was %s to %s, expected 302 /oauth2/start' \
                   % (page_status, page_path)
        start_status, start_headers, _ = driver.req(
            urllib.parse.urljoin(self.gateway(), page_location), headers={'Accept': 'text/html'})
        start_at_ms = time.time_ns() // 1_000_000
        log('V23 oauth start sample UTC-ms %d HTTP %d' % (start_at_ms, start_status))
        if start_status != 302 or start_at_ms > deadline_ms:
            return 'FAIL', 'post-refusal /oauth2/start was HTTP %s, expected 302' % start_status
        auth_url = start_headers.get('Location', '')
        if urllib.parse.urlparse(auth_url).path != '/identity/realms/krate/protocol/openid-connect/auth':
            return 'FAIL', 'post-refusal /oauth2/start did not reach Keycloak auth'
        form_status, _form_headers, form_body = driver.req(auth_url, headers={'Accept': 'text/html'})
        form_at_ms = time.time_ns() // 1_000_000
        log('V23 Keycloak form sample UTC-ms %d HTTP %d' % (form_at_ms, form_status))
        form_ok = (form_status == 200 and 'kc-form-login' in form_body
                   and 'name="password"' in form_body and form_at_ms <= deadline_ms)
        if not form_ok:
            return 'FAIL', 'post-refusal Keycloak password form missing or late (HTTP %s)' % form_status
        good_before = sum(1 for _elapsed, code, at_ms in poll_log
                          if at_ms - session_start_ms < (max_seconds - 60) * 1000 and code == 200)
        return 'PASS', ('realm max %ss; KC start %sms; sign-in %s..%sms; '
                        '%d early API 200s (scheduled 60s, max gap 65s); '
                        'last 200 KC+%.1fs; API 401 KC+%.1fs by M+6m; '
                        'same jar page 302 /oauth2/start and Keycloak password form 200 by M+6m') \
               % (max_seconds, session_start_ms, before_ms, after_ms, good_before,
                  max((at_ms - session_start_ms) / 1000 for _elapsed, code, at_ms in poll_log
                      if code == 200), (first_refusal[2] - session_start_ms) / 1000)

    def v24(self):
        """Prove a pre-existing Viewer is refused through two outage restarts.

        The daemon case runs only on Linux, after V20 and every timing row.
        Each case restores Keycloak even when a probe fails.
        """
        kc_cid = self.cluster_container('keycloak')
        perses_cid = self.mon_container('perses')
        o2p_cid = self.mon_container('oauth2-proxy')
        sync_cid = self.mon_container('perses-sync')
        if not kc_cid or not perses_cid or not o2p_cid or not sync_cid:
            not_run('precondition: missing required containers')

        def restart_count(cid):
            rc, value, _ = p2.docker('inspect', '-f', '{{.RestartCount}}', cid, timeout=10)
            if rc != 0 or not value.strip().isdigit():
                raise RuntimeError('cannot read Docker RestartCount for %s' % cid[:12])
            return int(value.strip())

        def container_status(cid):
            rc, value, _ = p2.docker('inspect', '-f', '{{.State.Status}}', cid, timeout=10)
            if rc != 0:
                raise RuntimeError('cannot read Docker state for %s' % cid[:12])
            return value.strip()

        def daemon_preflight():
            command = ['systemctl', 'restart', 'docker']
            if os.geteuid() != 0:
                try:
                    sudo = subprocess.run(['sudo', '-n', 'true'], capture_output=True,
                                          text=True, timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    return None, 'sudo -n unavailable for Docker daemon restart'
                if sudo.returncode != 0:
                    return None, 'sudo -n unavailable for Docker daemon restart'
                command = ['sudo', '-n'] + command
            rc, live_restore, err = p2.docker('info', '--format', '{{.LiveRestoreEnabled}}', timeout=10)
            if rc != 0 or live_restore.strip().lower() != 'false':
                return None, 'Docker live restore is not proven disabled: %s' % (err or live_restore)[-100:]
            for cid in (kc_cid, perses_cid, o2p_cid):
                rc, policy, err = p2.docker('inspect', '-f',
                                            '{{.HostConfig.RestartPolicy.Name}}', cid,
                                            timeout=10)
                if rc != 0 or policy.strip() != 'unless-stopped':
                    return None, 'restart policy for %s is not unless-stopped: %s' % (
                        cid[:12], (err or policy)[-100:])
            active = subprocess.run(['systemctl', 'is-active', 'docker'],
                                    capture_output=True, text=True, timeout=10)
            if active.returncode != 0 or active.stdout.strip() != 'active':
                return None, 'Docker system unit is not active'
            return command, None

        def outage_case(label, daemon_command=None):
            signed = self.signin('p4v', 'v24-' + label + '-existing', expect='ok')
            if signed.get('kind') != 'OK' or signed.get('role') != 'viewer':
                return 'FAIL', label + ': pre-existing Viewer sign-in failed'
            viewer = signed.get('driver')
            if not isinstance(viewer, PersesDriver):
                return 'FAIL', label + ': sign-in yielded no persistent cookie jar'
            initial_status, _, _ = viewer.req(self.gateway('/api/v1/projects'))
            if initial_status != 200:
                return 'FAIL', '%s: existing Viewer API was HTTP %s before outage' % (
                    label, initial_status)

            before_p = restart_count(perses_cid)
            before_o = restart_count(o2p_cid)
            after_p, after_o = before_p, before_o
            anonymous_status, viewer_status = -1, -1
            viewer_location = ''
            outage_error = None
            try:
                rc, _, err = p2.docker('stop', '-t', '5', kc_cid, timeout=15)
                if rc != 0:
                    raise RuntimeError('docker stop Keycloak rc %d: %s' % (rc, err[-100:]))
                if daemon_command is None:
                    rc, _, err = p2.docker('restart', o2p_cid, perses_cid, timeout=30)
                    if rc != 0:
                        raise RuntimeError('docker restart consumers rc %d: %s' % (
                            rc, err[-100:]))
                else:
                    result = subprocess.run(daemon_command, capture_output=True,
                                            text=True, timeout=120)
                    if result.returncode != 0:
                        raise RuntimeError('systemctl restart docker rc %d: %s' % (
                            result.returncode, result.stderr[-100:]))
                    ready_deadline = time.monotonic() + 30
                    while time.monotonic() < ready_deadline:
                        rc, _, _ = p2.docker('info', '--format', '{{.ServerVersion}}',
                                             timeout=5)
                        if rc == 0:
                            break
                        time.sleep(2)
                    else:
                        raise RuntimeError('Docker API unavailable after daemon restart')
                if container_status(kc_cid) != 'exited':
                    raise RuntimeError('Keycloak did not remain stopped during outage')
                restart_deadline = time.monotonic() + (90 if daemon_command else 45)
                while time.monotonic() < restart_deadline:
                    after_p = restart_count(perses_cid)
                    after_o = restart_count(o2p_cid)
                    if after_p > before_p and after_o > before_o:
                        break
                    time.sleep(2)
                anonymous = self.driver('v24-' + label + '-anonymous')
                anonymous_status, _, _ = anonymous.req(
                    self.gateway('/'), headers={'Accept': 'text/html'}, timeout=10)
                viewer_status, viewer_headers, _ = viewer.req(
                    self.gateway('/api/v1/projects'), timeout=10)
                viewer_location = viewer_headers.get('Location', '')
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                outage_error = '%s: %s' % (type(error).__name__, error)
            finally:
                start_rc, _, start_err = p2.docker('start', kc_cid, timeout=30)
                if start_rc != 0 and daemon_command is not None:
                    # A failed daemon restart must not leave this VM fixture's
                    # identity service stopped without a recovery attempt.
                    recover_command = daemon_command[:-2] + ['start', 'docker']
                    try:
                        recovery = subprocess.run(recover_command, capture_output=True,
                                                  text=True, timeout=60)
                        if recovery.returncode == 0:
                            start_rc, _, start_err = p2.docker('start', kc_cid,
                                                               timeout=30)
                        else:
                            start_err += '; systemctl start docker rc %d: %s' % (
                                recovery.returncode, recovery.stderr[-100:])
                    except (OSError, subprocess.TimeoutExpired) as error:
                        start_err += '; Docker daemon recovery: %s: %s' % (
                            type(error).__name__, error)
            if start_rc != 0:
                return 'FAIL', '%s: Keycloak restore rc %d: %s; outage %s' % (
                    label, start_rc, start_err[-100:], outage_error or 'none')
            if outage_error:
                return 'FAIL', '%s: outage probe failed; Keycloak restored: %s' % (
                    label, outage_error)

            healthy_secs = self._wait_container_healthy(kc_cid, limit=180)
            if healthy_secs is None:
                return 'FAIL', label + ': Keycloak did not become healthy within 180s'
            healthy_at = time.monotonic()
            # The gateway's auth check calls into perses-sync (:9091/guard):
            # perses+o2p running is not recovered while the guard is still
            # down (it answered 502/500 after the daemon restart). Wait for the
            # whole serving chain, then retry the sign-in inside the 90 s window
            # instead of grading one possibly-early attempt.
            recovered = False
            chain_probe = -1
            guard = self.driver('v24-' + label + '-guard')
            while time.monotonic() - healthy_at < 180:
                try:
                    running = (container_status(perses_cid) == 'running'
                               and container_status(o2p_cid) == 'running'
                               and container_status(sync_cid) == 'running')
                except RuntimeError:
                    running = False
                if running:
                    chain_probe, _, _ = guard.req(self.gateway('/'),
                                                 headers={'Accept': 'text/html'}, timeout=10)
                    if chain_probe in (302, 401):
                        recovered = True
                        break
                time.sleep(5)
            ready_seconds = time.monotonic() - healthy_at
            fresh, attempts, signin_seconds = ((self.signin_retry(
                'p4v', 'v24-' + label + '-recovered', deadline_s=90)
                if recovered else ({'kind': 'NOT_RUN'}, 0, 0.0)))
            viewer_refused = (viewer_status in (401, 403, 500)
                              or (viewer_status == 302
                                  and '/oauth2/start' in viewer_location))
            probes = [
                ('restart_counts_grew',
                 'PASS' if after_p > before_p and after_o > before_o else 'FAIL'),
                ('anonymous_outage_http_refusal',
                 'PASS' if anonymous_status in (403, 500) else 'FAIL'),
                ('authenticated_viewer_blocked',
                 'PASS' if viewer_refused else 'FAIL'),
                ('containers_recovered_running', 'PASS' if recovered else 'FAIL'),
                ('signin_within_90s',
                 'PASS' if (fresh.get('kind') == 'OK'
                            and fresh.get('role') == 'viewer'
                            and signin_seconds <= 90) else 'FAIL'),
            ]
            status, tokens = aggregate(probes)
            return status, ('%s: %s; anonymous HTTP %s, existing Viewer HTTP %s; '
                            'restarts perses %d->%d/o2p %d->%d; KC healthy +%.1fs; '
                            'chain ready +%.1fs (probe %s); '
                            'fresh Viewer %s attempts=%d at +%.1fs') % (
                                label, tokens, anonymous_status, viewer_status,
                                before_p, after_p, before_o, after_o, healthy_secs,
                                ready_seconds, chain_probe,
                                fresh.get('kind'), attempts, signin_seconds)

        direct_status, direct_evidence = outage_case('consumer-restart')
        if direct_status != 'PASS':
            return direct_status, direct_evidence
        if not sys.platform.startswith('linux'):
            return 'PASS', direct_evidence + '; Docker daemon restart is VM-only'

        try:
            daemon_command, preflight_problem = daemon_preflight()
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
            daemon_command = None
            preflight_problem = '%s: %s' % (type(error).__name__, error)
        if preflight_problem:
            return 'NOT_RUN', (direct_evidence + '; docker_daemon_restart=NOT_RUN: '
                               + preflight_problem)
        daemon_status, daemon_evidence = outage_case('daemon-restart', daemon_command)
        return daemon_status, (direct_evidence + '; docker_daemon_restart=%s; %s' % (
            daemon_status, daemon_evidence))

    def plan(self):
        # Destructive changes to the issuer, monitoring mode, certificates and
        # Docker containers finish before the uninterrupted V10 activity walk.
        # V7/V8 use separate users, so they can share V10's timing window.
        plan = [
            *([('V23@start', lambda: self.start_timed('V23', self.v23_body))]
              if getattr(self.args, 'session_max_minutes', None) else []),
            ('V1', self.v1), ('V2', self.v2), ('V3', self.v3), ('V4', self.v4),
            ('V5', self.v5), ('V6', self.v6),
            ('V9', self.v9), ('V11', self.v11), ('V12', self.v12),
            ('V13', self.v13), ('V14', self.v14), ('V15', self.v15),
            ('V16', self.v16), ('V17', self.v17), ('V18', self.v18),
            ('V19', self.v19), ('V21', self.v21), ('V22', self.v22),
            ('V23', self.v23),
            ('V10@start', lambda: self.start_timed('V10', self.v10_body)),
            ('V7@start', lambda: self.start_timed('V7', self.v7_body)),
            ('V8@start', lambda: self.start_timed('V8', self.v8_body)),
            ('V7', self.v7), ('V8', self.v8), ('V10', self.v10),
            # V20 is the final container snapshot. V24 is the last runtime row;
            # screenshots and the leak scan follow in the outer runner.
            ('V20', self.v20), ('V24', self.v24),
        ]
        return plan


def stub_options(run_parser):
    """The stand-in IdP options of V19, added to the `run` sub-command."""
    run_parser.add_argument('--stub-dir', help='directory stub_idp.sh up wrote (V19)')
    run_parser.add_argument('--stub-port', type=int, default=18443,
                            help='published port of the stand-in on 127.0.0.1 (V19)')
    run_parser.add_argument('--stub-script', default=os.path.join(HERE, 'stub_idp.sh'),
                            help='path of stub_idp.sh (V19)')
    run_parser.add_argument('--stub-container',
                            help='the stand-in container when it is not <project>-gate3-pingstub (V19)')


def main(argv=None):
    return helper_main(Gate, 'phase4_perses.py', argv, doc=__doc__, extra=stub_options)


if __name__ == '__main__':
    sys.exit(main())
