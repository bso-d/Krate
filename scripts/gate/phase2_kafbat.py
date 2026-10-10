#!/usr/bin/env python3
"""Phase 2 acceptance gate: Kafbat authorization through Keycloak on a live Krate fixture.

Runs against a running edition (brokers, the customized Kafbat image, the nginx
proxy and Keycloak, all reached through the public HTTPS origin) whose Kafbat
mode is KAFKA_UI_AUTH_CONFIG=runtime.yml, and checks the authorization contract
case by case (ladder rows K2-K16 and K18-K26; K1 and K17 belong to the gate
runner and are reported as NOT_RUN).

The script owns five realm users and recreates them on every run:
viewer1 (viewer group), admin1 (admin group), nobody1 (no group), disabled1
(viewer group, disabled during the run) and both1 (both groups). They are
created with `<edition-dir>/krate identity users add` and finish their required
actions (TOTP enrolment, forced password change) through a headless browser
flow over the proxy. Realm operations the CLI does not offer (both groups,
sign-out, rename, group removal, deletion) use kcadm.sh inside the Keycloak
container with the krate-cli service account. Secrets are read only from
<edition-dir>/.env and are never printed.

Output: one line per case on stdout, `K<n>\\tPASS|FAIL|NOT_RUN\\t<evidence>`;
progress on stderr. Exit status 0 when no case FAILed, 1 otherwise, 2 on a
usage error.

K9 and K18 (forged ID tokens) cannot be produced by a real Keycloak, so they
run the deployed Kafbat image a second time with the deployed runtime.yml,
pointed at a stub token/JWKS/userinfo endpoint (an nginx container from the
pinned NGINX_IMAGE) that serves ID tokens signed by a throwaway key; a
positive control must succeed for the negative results to count. K22 waits
for the Kafbat idle timeout (server.reactive.session.timeout in runtime.yml,
15 minutes by default) unless --no-idle-wait is given.

Helper Docker resources (stub network and containers) carry the labels
com.docker.compose.project=<project> and krate.gate=phase2 and are always
removed at the end; --skip-cleanup keeps only the realm users and topics.
"""

import argparse
from typing import NoReturn, Optional
import base64
import hashlib
import hmac
import html
import http.cookiejar
import ipaddress
import json
import os
import re
import secrets
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

REALM = 'krate'
UI_CLIENT = 'krate-ui'
CLI_CLIENT = 'krate-cli'
REGISTRATION = 'keycloak'
KCADM = '/opt/keycloak/bin/kcadm.sh'
KCADM_SERVER = 'http://localhost:8080/identity'
CASES = ['K%d' % i for i in range(1, 27)] + ['K31', 'K32']
RUNNER_CASES = ('K1', 'K17')
SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS', 'TRACE')
EVIDENCE_MAX = 200
POLL_SECONDS = 30
GATE_LABEL = 'krate.gate=phase2'
EVIL = 'https://evil.example'
K5_TIMEOUT = 90
# Error messages of Kafbat v1.5.0 when a cluster has no Schema Registry / Kafka Connect configured.
FEATURE_ABSENT = re.compile(r'Schema Registry is not set|getConnectsClients\(\)')


# ─── Output hygiene ───────────────────────────────────────────────────────────

class Redactor:
    """Removes every known secret, password, cookie value and token from text before it is printed."""

    TOKEN = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    PARAM = re.compile(r'((?:id_token_hint|code|state|session_state|nonce|code_challenge|logout_token)=)[^&\s"\'<>]+')

    def __init__(self):
        self.values = set()
        self.lock = threading.Lock()

    def add(self, value):
        if value and len(value) >= 6:
            with self.lock:
                self.values.add(value)

    def __call__(self, text):
        text = str(text)
        with self.lock:
            values = sorted(self.values, key=len, reverse=True)
        for value in values:
            text = text.replace(value, '<redacted>')
        text = self.TOKEN.sub('<jwt>', text)
        return self.PARAM.sub(r'\1<redacted>', text)


REDACT = Redactor()
LOG_LOCK = threading.Lock()


def log(message):
    with LOG_LOCK:
        print(time.strftime('%H:%M:%S ') + REDACT(message), file=sys.stderr, flush=True)


def evidence(text):
    text = re.sub(r'\s+', ' ', REDACT(text)).strip()
    return text if len(text) <= EVIDENCE_MAX else text[:EVIDENCE_MAX - 3] + '...'


class Outcome(Exception):
    def __init__(self, status, text):
        super().__init__(text)
        self.status = status
        self.text = text


def not_run(reason) -> NoReturn:
    raise Outcome('NOT_RUN', reason)


def fail(reason) -> NoReturn:
    raise Outcome('FAIL', reason)


# ─── HTTP ─────────────────────────────────────────────────────────────────────

class NoRedirect(urllib.request.HTTPRedirectHandler):
    # noinspection PyMethodMayBeStatic
    def redirect_request(self, *_args, **_kwargs):  # overrides an instance method
        return None


class Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body or b''

    @property
    def location(self):
        return self.headers.get('Location', '') if self.headers else ''

    @property
    def text(self):
        return self.body.decode('utf-8', 'replace')

    def json(self):
        try:
            return json.loads(self.body.decode('utf-8'))
        except ValueError:
            return None

    def snippet(self, size=60):
        return re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', self.text)))[:size].strip()


def read_stream(response, deadline):
    """Read a Kafbat server-sent event stream until its DONE event (or the deadline): the stream may stay open."""
    data = b''
    while time.monotonic() < deadline:
        try:
            line = response.readline()
        except (TimeoutError, OSError):
            break
        if not line:
            break
        data += line
        if b'"DONE"' in line:
            break
    response.close()
    return data


def open_request(opener, method, url, body=None, headers=None, timeout=30):
    request = urllib.request.Request(url, data=body, method=method,
                                     headers=dict({'User-Agent': 'krate-gate-phase2'}, **(headers or {})))
    try:
        response = opener.open(request, timeout=timeout)
        if (headers or {}).get('Accept') == 'text/event-stream' and response.status == 200:
            return Resp(response.status, response.headers, read_stream(response, time.monotonic() + timeout))
        return Resp(response.status, response.headers, response.read())
    except urllib.error.HTTPError as error:
        return Resp(error.code, error.headers, error.read())


class Browser:
    """One user agent: its own cookie jar (Kafbat and Keycloak cookies), no automatic redirects."""

    def __init__(self, gate, label, base=None):
        self.gate = gate
        self.label = label
        self.base = base or gate.base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            NoRedirect, urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=gate.tls))

    def request(self, method, url, body=None, headers=None, timeout=30):
        self.gate.check_url(url)
        response = open_request(self.opener, method, url, body, headers, timeout)
        for cookie in self.jar:
            if cookie.name in ('SESSION', 'XSRF-TOKEN') or cookie.name.startswith('KEYCLOAK') \
                    or cookie.name.startswith('AUTH_SESSION'):
                REDACT.add(cookie.value)
        return response

    def form(self, url, fields, headers=None):
        return self.request('POST', url, urllib.parse.urlencode(fields).encode(),
                            dict({'Content-Type': 'application/x-www-form-urlencoded'}, **(headers or {})))

    def cookie(self, name):
        for cookie in self.jar:
            if cookie.name == name:
                return cookie.value
        return None

    def xsrf(self):
        token = self.cookie('XSRF-TOKEN')
        if token is None:
            self.request('GET', self.base + '/api/authorization', headers={'Accept': 'application/json'})
            token = self.cookie('XSRF-TOKEN')
        return token

    def api(self, method, path, payload=None, csrf=True, headers=None, raw=None, content_type=None,
            accept='application/json', timeout=30):
        sent = {'Accept': accept}
        body = raw
        if payload is not None:
            body = json.dumps(payload).encode()
            sent['Content-Type'] = 'application/json'
        if content_type:
            sent['Content-Type'] = content_type
        if csrf and method not in SAFE_METHODS:
            token = self.xsrf()
            if token:
                sent['X-XSRF-TOKEN'] = token
        sent.update(headers or {})
        return self.request(method, self.base + path, body, sent, timeout)


# ─── Keycloak pages and TOTP ─────────────────────────────────────────────────

def form_action(page):
    match = re.search(r'<form[^>]+action="([^"]*login-actions[^"]*)"', page) \
        or re.search(r'<form[^>]+action="([^"]+)"', page)
    return html.unescape(match.group(1)) if match else None


def page_message(page):
    visible = re.sub(r'(?is)<(script|style)\b.*?</\1>', ' ', page)
    text = re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', visible)))
    for sentence in (r'Account is [A-Za-z ,]+\.', r'Invalid [A-Za-z ]+\.', r'(?:Your account|User) [A-Za-z ,]+\.'):
        known = re.search(sentence, text)
        if known:
            return known.group(0).strip()[:90]
    for pattern in (r'id="input-error[^"]*"[^>]*>(.*?)</span>',
                    r'class="[^"]*kc-feedback-text[^"]*"[^>]*>(.*?)</',
                    r'id="kc-error-message"[^>]*>(.*?)</div>',
                    r'class="[^"]*alert-error[^"]*"[^>]*>(.*?)</div>',
                    r'class="[^"]*pf-m-danger[^"]*"[^>]*>(.*?)</div>',
                    r'<title>(.*?)</title>'):
        match = re.search(pattern, page, re.S)
        if match:
            text = re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', match.group(1)))).strip()
            if text:
                return text[:90]
    return ''


def totp(secret_b32, counter):
    key = base64.b32decode(secret_b32)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return '%06d' % ((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000)


class User:
    def __init__(self, name, groups):
        self.name = name
        self.login = name
        self.groups = groups
        self.password: Optional[str] = None
        self.secret: Optional[str] = None
        self.uid: Optional[str] = None
        self.used = set()
        self.lock = threading.Lock()

    def code(self):
        """The current step's TOTP code, once per step (Keycloak refuses a reused code).

        Only the current step is used here; the realm's look-ahead window is 1 since commit
        645ea23 (the gate's B7 proves the previous step's code is accepted). A code is not
        used in the last 3 s of its step.
        """
        with self.lock:
            while True:
                now = time.time()
                counter = int(now // 30)
                if counter not in self.used and 30 - now % 30 > 3:
                    self.used.add(counter)
                    return totp(self.secret, counter)
                time.sleep(30 - now % 30 + 0.5)


# ─── Docker and kcadm ─────────────────────────────────────────────────────────

def run(args, cwd=None, env=None, stdin=None, timeout=300):
    try:
        proc = subprocess.run(args, cwd=cwd, env=env, input=stdin, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, '', 'timeout after %ss' % timeout
    except OSError as error:
        return 127, '', str(error)


def docker(*args, **kwargs):
    return run(['docker'] + list(args), **kwargs)


def service_container(project, service):
    rc, out, _ = docker('ps', '-q', '--filter', 'label=com.docker.compose.project=' + project,
                        '--filter', 'label=com.docker.compose.service=' + service)
    ids = out.split()
    return ids[0] if rc == 0 and ids else None


class Kcadm:
    """kcadm.sh in the Keycloak container, logged in as the krate-cli service account (secret via env, not argv)."""

    def __init__(self, project, secret):
        self.cid = service_container(project, 'keycloak')
        if not self.cid:
            raise RuntimeError('no running keycloak container in project ' + project)
        self.config = '/tmp/kcadm-gate-%s.config' % secrets.token_hex(8)
        self.secret = secret
        rc, _, err = self.raw('config', 'credentials', '--server', KCADM_SERVER, '--realm', REALM,
                              '--client', CLI_CLIENT)
        if rc != 0:
            raise RuntimeError('kcadm login as krate-cli failed: ' + err.strip()[:120])

    def raw(self, *args):
        env = dict(os.environ, KC_CLI_CLIENT_SECRET=self.secret)
        return docker('exec', '-e', 'KC_CLI_CLIENT_SECRET', self.cid, KCADM, *args, '--config', self.config,
                      env=env, timeout=120)

    def call(self, *args):
        rc, out, err = self.raw(*args)
        if rc != 0:
            raise RuntimeError('kcadm %s failed (rc %s): %s' % (args[0], rc, (err or out).strip()[:160]))
        return out

    def get(self, path, *query):
        args = ['get', path, '-r', REALM]
        for item in query:
            args += ['-q', item]
        out = self.call(*args)
        return json.loads(out) if out.strip() else None

    def user_id(self, username):
        users = self.get('users', 'username=' + username, 'exact=true') or []
        return next((u['id'] for u in users if u.get('username') == username), None)

    def group_id(self, name):
        groups = self.get('groups', 'search=' + name, 'exact=true') or []
        return next((g['id'] for g in groups if g.get('name') == name), None)

    def group_names(self):
        return sorted(g['name'] for g in (self.get('groups') or []))

    def add_group(self, uid, gid):
        self.call('update', 'users/%s/groups/%s' % (uid, gid), '-r', REALM, '-s', 'realm=' + REALM,
                  '-s', 'userId=' + uid, '-s', 'groupId=' + gid, '-n')

    def remove_group(self, uid, gid):
        self.call('delete', 'users/%s/groups/%s' % (uid, gid), '-r', REALM)

    def logout(self, uid):
        self.call('create', 'users/%s/logout' % uid, '-r', REALM)

    def sessions(self, uid):
        return self.get('users/%s/sessions' % uid) or []

    def delete_user(self, uid):
        self.call('delete', 'users/' + uid, '-r', REALM)

    def close(self):
        docker('exec', self.cid, 'rm', '-f', self.config)


# ─── Gate ─────────────────────────────────────────────────────────────────────

def read_env(path):
    values = {}
    with open(path, encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            values[key.strip()] = value
    return values


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def query_of(url):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def seconds(value):
    match = re.fullmatch(r'(\d+)\s*([smh]?)', str(value).strip())
    if not match:
        return None
    return int(match.group(1)) * {'': 1, 's': 1, 'm': 60, 'h': 3600}[match.group(2)]


class Gate:
    def __init__(self, args):
        self.args = args
        self.edition = os.path.abspath(args.edition_dir)
        self.base = args.base_url.rstrip('/')
        self.origin = urllib.parse.urlsplit(self.base)
        self.project = args.project
        self.realm_url = self.base + '/identity/realms/' + REALM
        self.callback = self.base + '/login/oauth2/code/' + REGISTRATION
        self.only = set(args.only) if args.only else None
        self.results = {}
        self.users = {}
        self.sessions = {}
        self.allowed_origins = {self.base}
        self.kc: Optional[Kcadm] = None
        self.tls = None
        self.fixture_data = None
        self.idle_thread = None
        self.idle_result = None
        self.cleanup_topics = set()
        self.cleanup_groups = set()
        self.run_id = secrets.token_hex(3)
        self.env = {}
        self.runtime = {}
        self.cluster: Optional[str] = None
        self.idle_seconds = None
        self.viewer_group = self.admin_group = None
        self.group_ids = {}
        self.tls_mode = ''
        self.auth_info = {}
        self.image = {}
        self.disabled_at = None
        self.disabled_credentials_proof = 'temporary password from users add'
        self.stub_results = None

    # ── plumbing ──
    def keycloak(self) -> 'Kcadm':
        if self.kc is None:
            not_run('precondition: Keycloak admin client not initialised (preflight failed)')
        return self.kc

    def cluster_api(self) -> str:
        if not self.cluster:
            not_run('precondition: no Kafbat cluster name in runtime.yml')
        return '/api/clusters/' + self.cluster

    def wanted(self, case):
        return self.only is None or case in self.only

    def check_url(self, url):
        if not any(url == o or url.startswith(o + '/') or url.startswith(o + '?') for o in self.allowed_origins):
            raise RuntimeError('refusing a request outside the fixture: ' + urllib.parse.urlsplit(url).netloc)

    def record(self, case, status, text):
        self.results[case] = (status, evidence(text))
        log('%s %s %s' % (case, status, re.sub(r'\s+', ' ', str(text))))

    def case(self, name, func):
        if not self.wanted(name) or name in self.results:
            return
        log('── %s' % name)
        try:
            status, text = func()
        except Outcome as outcome:
            status, text = outcome.status, outcome.text
        except Exception as error:  # a harness error is reported, never hidden
            status, text = 'FAIL', 'harness error %s: %s' % (type(error).__name__, error)
        self.record(name, status, text)

    def probe(self, session, path='/api/clusters', headers=None):
        """Status of a request carrying only the given SESSION cookie (no jar)."""
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=self.tls))
        sent = {'Accept': 'application/json'}
        if session:
            sent['Cookie'] = 'SESSION=' + session
        sent.update(headers or {})
        return open_request(opener, 'GET', self.base + path, None, sent)

    def wait_dead(self, session, limit=POLL_SECONDS):
        start = time.monotonic()
        while time.monotonic() - start < limit:
            response = self.probe(session)
            if response.status != 200:
                return time.monotonic() - start, response
            time.sleep(0.25)
        return None, self.probe(session)

    # ── setup ──
    def preflight(self):
        env_path = os.path.join(self.edition, '.env')
        if not os.path.isfile(env_path) or not os.access(os.path.join(self.edition, 'krate'), os.X_OK):
            return 'edition dir lacks .env or an executable krate: ' + self.edition
        self.env = read_env(env_path)
        for key, value in self.env.items():
            if re.search(r'(_PASSWORD|_SECRET|_PASSPHRASE)$', key):
                REDACT.add(value)
        if self.env.get('KAFKA_UI_AUTH_CONFIG') != 'runtime.yml':
            return 'KAFKA_UI_AUTH_CONFIG is %r, not runtime.yml' % self.env.get('KAFKA_UI_AUTH_CONFIG')
        for key in ('KEYCLOAK_CLI_CLIENT_SECRET', 'KEYCLOAK_KAFBAT_CLIENT_SECRET'):
            if self.env.get(key, '') in ('', 'REPLACE_ME'):
                return key + ' is not set in .env'
        self.viewer_group = self.env.get('KEYCLOAK_VIEWER_GROUP') or 'KRATE_VIEWERS'
        self.admin_group = self.env.get('KEYCLOAK_ADMIN_GROUP') or 'KRATE_ADMINS'
        runtime_path = os.path.join(self.edition, 'auth', 'ui', 'runtime.yml')
        try:
            with open(runtime_path, encoding='utf-8') as handle:
                self.runtime = json.load(handle)
            self.cluster = self.runtime['rbac']['roles'][0]['clusters'][0]
            self.idle_seconds = seconds(self.runtime['server']['reactive']['session']['timeout'])
        except (OSError, ValueError, KeyError, IndexError) as error:
            return 'cannot read cluster/session timeout from auth/ui/runtime.yml: %s' % error
        # TLS: trust the fixture certificate itself; fall back to no verification for this host only.
        cert = os.path.join(self.edition, 'certs', 'server.crt')
        self.tls_mode = 'pinned fixture certificate certs/server.crt'
        try:
            self.tls = ssl.create_default_context(cafile=cert)
            open_request(urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.tls)), 'GET',
                         self.base + '/api/config/authentication', timeout=15)
        except (OSError, ssl.SSLError) as error:
            reason = getattr(error, 'reason', error)
            if isinstance(error, urllib.error.URLError) and not isinstance(reason, ssl.SSLError):
                return 'fixture not reachable at %s: %s' % (self.base, reason)
            # The certificate is missing or does not verify: skip verification, for the fixture host only
            # (check_url refuses every other origin).
            self.tls = ssl.create_default_context()
            self.tls.check_hostname = False
            self.tls.verify_mode = ssl.CERT_NONE
            self.tls_mode = 'verification disabled for %s only (%s)' % (self.origin.netloc, type(reason).__name__)
        log('TLS: ' + self.tls_mode)
        response = Browser(self, 'probe').request('GET', self.base + '/api/config/authentication',
                                                  headers={'Accept': 'application/json'})
        if response.status != 200:
            return 'GET /api/config/authentication answered %s' % response.status
        self.auth_info = response.json() or {}
        try:
            self.kc = Kcadm(self.project, self.env['KEYCLOAK_CLI_CLIENT_SECRET'])
        except RuntimeError as error:
            return str(error)
        self.image = {}
        for service in ('kafka-ui', 'keycloak', 'proxy'):
            cid = service_container(self.project, service)
            rc, out, _ = docker('inspect', '--format', '{{.Image}}', cid) if cid else (1, '', '')
            self.image[service] = out.strip()[7:19] if rc == 0 else 'missing'
        if self.image['kafka-ui'] == 'missing' or self.image['proxy'] == 'missing':
            return 'kafka-ui or proxy container not running in project ' + self.project
        log('fixture: cluster %s, idle timeout %ss, images %s' % (self.cluster, self.idle_seconds, self.image))
        return None

    def krate(self, *args, timeout=300):
        return run([os.path.join(self.edition, 'krate')] + list(args), cwd=self.edition, timeout=timeout)

    def create_users(self):
        plan = {'viewer1': ['viewer'], 'admin1': ['admin'], 'nobody1': [], 'disabled1': ['viewer'],
                'both1': ['viewer', 'admin']}
        group_ids = {'viewer': self.keycloak().group_id(self.viewer_group), 'admin': self.keycloak().group_id(self.admin_group)}
        if not all(group_ids.values()):
            raise RuntimeError('realm groups %s/%s not found' % (self.viewer_group, self.admin_group))
        self.group_ids = group_ids
        for name, groups in plan.items():
            for stale in (name, name + '-renamed'):
                uid = self.keycloak().user_id(stale)
                if uid:
                    self.keycloak().delete_user(uid)
                    log('deleted stale user %s from an earlier run' % stale)
            user = User(name, groups)
            flag = ['--' + groups[0]] if groups else []
            rc, out, err = self.krate('identity', 'users', 'add', name, *flag)
            match = re.search(r'Temporary password for %s[^\n]*\n\s*(\S+)' % re.escape(name), out)
            if rc != 0 or not match:
                raise RuntimeError('krate identity users add %s failed (rc %s): %s' % (name, rc, err.strip()[-160:]))
            user.password = match.group(1)
            REDACT.add(user.password)
            user.uid = self.keycloak().user_id(name)
            for extra in groups[1:]:
                self.keycloak().add_group(user.uid, group_ids[extra])
            self.users[name] = user
            log('created %s (groups: %s) via krate identity users add' % (name, ','.join(groups) or 'none'))

    # ── login flows ──
    def realm_follow(self, browser, response):
        for _ in range(5):
            location = urllib.parse.urljoin(self.realm_url + '/', response.location) if response.location else ''
            if response.status in (302, 303) and location.startswith(self.realm_url + '/'):
                response = browser.request('GET', location)
            else:
                break
        return response

    def keycloak_login(self, browser, user, auth_url, callback=None):
        """Drive Keycloak's login pages. Returns ('callback', url) | ('refused', message) | ('unexpected', detail)."""
        callback = callback or self.callback
        response = self.realm_follow(browser, browser.request('GET', auth_url))
        if response.status in (302, 303) and response.location.startswith(callback):
            return 'callback', response.location
        page = response.text
        if response.status != 200 or 'kc-form-login' not in page:
            return 'unexpected', 'auth page %s %s' % (response.status, page_message(page))
        response = browser.form(form_action(page), {'username': user.login, 'password': user.password,
                                                     'credentialId': ''})
        otp_attempts = 0
        for _ in range(8):
            response = self.realm_follow(browser, response)
            if response.status in (302, 303) and response.location.startswith(callback):
                return 'callback', response.location
            page = response.text
            action = form_action(page)
            if response.status == 200 and 'name="totpSecret"' in page:
                found = re.search(r'name="totpSecret"[^>]*value="([^"]+)"', page)
                if not found:
                    raise RuntimeError('TOTP page without a totpSecret value')
                raw = html.unescape(found.group(1))
                REDACT.add(raw)
                user.secret = base64.b32encode(raw.encode()).decode()  # HmacOTP keys on the raw secret's bytes
                REDACT.add(user.secret)
                response = browser.form(action, {'totp': user.code(), 'totpSecret': raw, 'userLabel': 'gate'})
            elif response.status == 200 and 'name="password-new"' in page:
                new = secrets.token_urlsafe(18)
                REDACT.add(new)
                user.password = new
                response = browser.form(action, {'password-new': new, 'password-confirm': new})
            elif response.status == 200 and 'name="otp"' in page and user.secret and otp_attempts < 3:
                # A refused code (clock step boundary) shows the OTP form again; a fresh counter is tried.
                otp_attempts += 1
                response = browser.form(action, {'otp': user.code()})
            else:
                return 'refused', page_message(page) or 'status %s' % response.status
        return 'unexpected', 'too many Keycloak steps'

    def kafbat_login(self, user, label, start='/oauth2/authorization/' + REGISTRATION, browser=None):
        browser = browser or Browser(self, label)
        result = {'browser': browser, 'user': user}
        response = browser.request('GET', self.base + start, headers={'Accept': 'text/html'})
        result['start'] = (response.status, response.location)
        for _ in range(3):
            target = urllib.parse.urljoin(self.base + '/', response.location)
            if response.status in (301, 302, 303) and target.startswith(self.base + '/') \
                    and not target.startswith(self.realm_url):
                response = browser.request('GET', target, headers={'Accept': 'text/html'})
            else:
                break
        result['pre_session'] = browser.cookie('SESSION')
        if response.status not in (302, 303) or not response.location.startswith(self.realm_url):
            result.update(kind='unexpected', detail='no redirect to Keycloak (%s %s)' % (
                response.status, REDACT(response.location)[:80]))
            return result
        kind, detail = self.keycloak_login(browser, user, response.location)
        result.update(kind=kind, detail=detail)
        if kind == 'callback':
            response = browser.request('GET', detail, headers={'Accept': 'text/html'})
            result['callback'] = (response.status, response.location)
            result['session'] = browser.cookie('SESSION')
            location = response.location
            if response.status in (302, 303) and 'error' in urllib.parse.urlsplit(location).query:
                result['kind'] = 'kafbat-refused'
            elif response.status in (302, 303):
                result['kind'] = 'ok'
            else:
                result['kind'] = 'unexpected'
                result['detail'] = 'callback answered %s' % response.status
        return result

    def session(self, name, label=None):
        """A cached signed-in Kafbat browser for a user; NOT_RUN when the login itself fails."""
        label = label or name
        if label in self.sessions:
            return self.sessions[label]
        user = self.users.get(name)
        if user is None:
            not_run('precondition: user %s was not created' % name)
        result = self.kafbat_login(user, label)
        if result['kind'] != 'ok':
            not_run('precondition: %s login %s: %s %s' % (name, result['kind'], result.get('detail', ''),
                                                          result.get('callback', '')))
        status = self.probe(result['session']).status
        if status != 200:
            not_run('precondition: %s session answered %s on /api/clusters' % (name, status))
        log('%s signed in to Kafbat (%s)' % (name, label))
        self.sessions[label] = result['browser']
        return result['browser']

    # ── Kafka fixture data ──
    def broker_exec(self, *args, timeout=60):
        cid = service_container(self.project, 'kafka-92')
        if not cid:
            return 127, '', 'no kafka-92 container'
        return docker('exec', cid, *args, timeout=timeout)

    def fixture(self):
        if self.fixture_data is not None:
            if isinstance(self.fixture_data, str):
                not_run(self.fixture_data)
            return self.fixture_data
        admin = self.session('admin1')
        topic = 'gate2-fix-' + self.run_id
        groups = ['gate2-cg-' + self.run_id, 'gate2-cgdel-' + self.run_id]
        c = self.cluster_api()
        response = admin.api('POST', c + '/topics', {'name': topic, 'partitions': 1, 'replicationFactor': 1})
        if response.status != 200:
            self.fixture_data = 'precondition: admin1 could not create the fixture topic (%s %s)' % (
                response.status, response.snippet())
            not_run(self.fixture_data)
        self.cleanup_topics.add(topic)
        for index in range(3):
            admin.api('POST', '%s/topics/%s/messages' % (c, topic),
                      {'partition': 0, 'key': 'k%d' % index, 'value': 'gate-%d' % index,
                       'keySerde': 'String', 'valueSerde': 'String'})
        for group in groups:
            rc, _, err = self.broker_exec('/opt/kafka/bin/kafka-console-consumer.sh', '--bootstrap-server',
                                          'kafka-92:9092', '--topic', topic, '--group', group,
                                          '--from-beginning', '--max-messages', '1', '--timeout-ms', '30000')
            self.cleanup_groups.add(group)
            if rc != 0:
                self.fixture_data = 'precondition: consumer group %s not created: %s' % (group, err.strip()[-100:])
                not_run(self.fixture_data)
        brokers = admin.api('GET', c + '/brokers').json() or []
        broker = brokers[0]['id'] if brokers else None
        config = None
        if broker is not None:
            for item in admin.api('GET', '%s/brokers/%s/configs' % (c, broker)).json() or []:
                if item.get('name') == 'message.max.bytes':
                    config = item.get('value')
        self.fixture_data = {'topic': topic, 'group': groups[0], 'group_del': groups[1], 'broker': broker,
                             'mmb': config}
        log('fixture: topic %s, groups %s, broker %s' % (topic, ','.join(groups), broker))
        return self.fixture_data

    # ── cases ──
    def k2_viewer_reads(self):
        viewer = self.session('viewer1')
        f = self.fixture()
        c = self.cluster_api()
        core = [('clusters', '/api/clusters'), ('stats', c + '/stats'), ('metrics', c + '/metrics'),
                ('brokers', c + '/brokers'), ('broker-configs', '%s/brokers/%s/configs' % (c, f['broker'])),
                ('logdirs', c + '/brokers/logdirs'), ('topics', c + '/topics'),
                ('topic', '%s/topics/%s' % (c, f['topic'])), ('topic-config', '%s/topics/%s/config' % (c, f['topic'])),
                ('topic-groups', '%s/topics/%s/consumer-groups' % (c, f['topic'])),
                ('groups-lag', c + '/consumer-groups/paged?page=1&perPage=25'),
                ('group', '%s/consumer-groups/%s' % (c, f['group']))]
        extra = [('broker-metrics', '%s/brokers/%s/metrics' % (c, f['broker'])), ('acls', c + '/acls'),
                 ('activeproducers', '%s/topics/%s/activeproducers' % (c, f['topic'])),
                 ('config', '/api/config')]
        bad, seen = [], []
        for label, path in core:
            status = viewer.api('GET', path).status
            seen.append('%s=%s' % (label, status))
            if status != 200:
                bad.append('%s=%s' % (label, status))
        listed = any(item.get('name') == self.cluster for item in viewer.api('GET', '/api/clusters').json() or [])
        lag = viewer.api('GET', c + '/consumer-groups/paged?page=1&perPage=25').json() or {}
        has_lag = any('consumerLag' in g for g in lag.get('consumerGroups', []))
        others = ' '.join('%s=%s' % (label, viewer.api('GET', path).status) for label, path in extra)
        text = '%d/%d core reads 200; cluster listed=%s lag field=%s; other: %s' % (
            len(core) - len(bad), len(core), listed, has_lag, others)
        if bad or not listed:
            fail('viewer reads refused: %s; %s' % (' '.join(bad), text))
        return 'PASS', text

    def viewer_mutations(self, f):
        c = self.cluster_api()
        t, g, b = f['topic'], f['group'], f['broker']
        acl = {'resourceType': 'TOPIC', 'resourceName': t, 'namePatternType': 'LITERAL', 'principal': 'User:gate',
               'host': '*', 'operation': 'READ', 'permission': 'ALLOW'}
        return [
            ('topic-create', 'POST', c + '/topics', {'name': 'gate2-viewer-' + self.run_id, 'partitions': 1,
                                                      'replicationFactor': 1}, None),
            ('topic-clone', 'POST', '%s/topics/%s/clone?newTopicName=gate2-clone-%s' % (c, t, self.run_id), None, None),
            ('topic-recreate', 'POST', '%s/topics/%s' % (c, t), None, None),
            ('topic-config', 'PATCH', '%s/topics/%s' % (c, t), {'configs': {'retention.ms': '3600000'}}, None),
            ('topic-partitions', 'PATCH', '%s/topics/%s/partitions' % (c, t), {'totalPartitionsCount': 2}, None),
            ('topic-replication', 'PATCH', '%s/topics/%s/replications' % (c, t), {'totalReplicationFactor': 1}, None),
            ('topic-analysis', 'POST', '%s/topics/%s/analysis' % (c, t), None, None),
            ('topic-analysis-cancel', 'DELETE', '%s/topics/%s/analysis' % (c, t), None, None),
            ('topic-delete', 'DELETE', '%s/topics/%s' % (c, t), None, None),
            ('produce', 'POST', '%s/topics/%s/messages' % (c, t), {'partition': 0, 'key': 'v', 'value': 'v',
                                                                  'keySerde': 'String', 'valueSerde': 'String'}, None),
            ('messages-delete', 'DELETE', '%s/topics/%s/messages?partitions=0' % (c, t), None, None),
            ('group-delete', 'DELETE', '%s/consumer-groups/%s' % (c, g), None, None),
            ('offsets-reset', 'POST', '%s/consumer-groups/%s/offsets' % (c, g),
             {'topic': t, 'resetType': 'EARLIEST', 'partitions': [0]}, None),
            ('offsets-delete', 'DELETE', '%s/consumer-groups/%s/topics/%s' % (c, g, t), None, None),
            ('acl-create', 'POST', c + '/acls', acl, None),
            ('acl-delete', 'DELETE', c + '/acls', acl, None),
            ('acl-csv', 'POST', c + '/acls/csv', None, b'Principal,ResourceType,PatternType,ResourceName,Operation,'
                                                      b'PermissionType,Host\n'),
            ('acl-consumer', 'POST', c + '/acls/consumer', {'principal': 'User:gate', 'host': '*', 'topics': [t],
                                                            'consumerGroups': [g]}, None),
            ('acl-producer', 'POST', c + '/acls/producer', {'principal': 'User:gate', 'host': '*', 'topics': [t]},
             None),
            ('quotas', 'POST', c + '/clientquotas', {'user': 'gate', 'quotas': {'producer_byte_rate': 1048576}}, None),
            ('broker-config', 'PUT', '%s/brokers/%s/configs/message.max.bytes' % (c, b),
             {'value': f['mmb'] or '1048588'}, None),
            ('broker-logdirs', 'PATCH', '%s/brokers/%s/logdirs' % (c, b), [], None),
            ('connector-create', 'POST', c + '/connects/gate/connectors', {'name': 'gate', 'config': {}}, None),
            ('connector-delete', 'DELETE', c + '/connects/gate/connectors/gate', None, None),
            ('connector-config', 'PUT', c + '/connects/gate/connectors/gate/config', {}, None),
            ('connector-restart', 'POST', c + '/connects/gate/connectors/gate/action/RESTART', None, None),
            ('ksql', 'POST', c + '/ksql/v2', {'ksql': 'SHOW STREAMS;'}, None),
            ('schema-create', 'POST', c + '/schemas', {'subject': 'gate', 'schema': '"string"',
                                                       'schemaType': 'AVRO'}, None),
            ('schema-delete', 'DELETE', c + '/schemas/gate', None, None),
            ('schema-compat', 'PUT', c + '/schemas/compatibility', {'compatibility': 'NONE'}, None),
            ('app-config', 'PUT', '/api/config', {}, None),
            ('app-config-validate', 'PUT', '/api/config/validated', {}, None),
        ]

    def k3_viewer_mutations(self):
        viewer = self.session('viewer1')
        f = self.fixture()
        probes = self.viewer_mutations(f)
        bad, absent, bodies = [], [], set()
        for label, method, path, payload, raw in probes:
            response = viewer.api(method, path, payload, raw=raw,
                                  content_type='text/plain' if raw is not None else None)
            if response.status == 403:
                bodies.add(response.snippet(40) or '(empty)')
                continue
            body = response.json() if isinstance(response.json(), dict) else {}
            log('K3 %s %s -> %s %s (stackTrace entries in body: %s)' % (
                method, label, response.status, str(body.get('message', response.snippet(100)))[:120],
                len(body.get('stackTrace') or [])))
            # Kafbat resolves the cluster's optional client (Schema Registry, Connect) while assembling the
            # reactive chain, before validateAccess runs; with the feature absent the request fails there.
            if not 200 <= response.status < 300 and FEATURE_ABSENT.search(str(body.get('message', ''))):
                absent.append('%s=%s' % (label, response.status))
            else:
                bad.append('%s=%s' % (label, response.status))
        topic = viewer.api('GET', '/api/clusters/%s/topics/gate2-viewer-%s' % (self.cluster, self.run_id)).status
        still = viewer.api('GET', '/api/clusters/%s/topics/%s' % (self.cluster, f['topic'])).status
        rbac = len(probes) - len(bad) - len(absent)
        grouped = {}
        for item in absent:
            label, status = item.split('=')
            grouped.setdefault('%s*=%s' % (label.split('-')[0], status), []).append(label)
        text = ('%d/%d RBAC-checked mutations 403 (valid CSRF token, body %s); feature absent, refused before RBAC: %s; '
                'new topic GET=%s, fixture topic %s') % (
            rbac, len(probes) - len(absent), ' | '.join(sorted(bodies))[:20],
            ' '.join('%s x%d' % (k, len(v)) for k, v in grouped.items()) or 'none', topic, still)
        if bad or topic == 200 or still != 200:
            fail('not refused: %s; %s' % (' '.join(bad) or 'side effect', text))
        return 'PASS', text

    def k4_viewer_messages(self):
        viewer = self.session('viewer1')
        f = self.fixture()
        c = self.cluster_api()
        read = viewer.api('GET', '%s/topics/%s/messages/v2?mode=EARLIEST&limit=5' % (c, f['topic']),
                          accept='text/event-stream').status
        smart = viewer.api('POST', '%s/topics/%s/smartfilters' % (c, f['topic']), {'filterCode': 'true'}).status
        topic = next(p for p in self.runtime['rbac']['roles'][0]['permissions'] if p['resource'] == 'topic')
        opted = 'messages_read' in topic['actions']
        text = 'messages/v2=%s smartfilter-register=%s; runtime.yml viewer messages_read=%s (KAFKA_UI_VIEWER_MESSAGES=%s)' % (
            read, smart, opted, self.env.get('KAFKA_UI_VIEWER_MESSAGES', 'unset'))
        if opted:
            not_run('viewer_messages is opted in on this fixture; ' + text)
        if read != 403 or smart != 403:
            fail(text)
        return 'PASS', text

    def k5_admin_mutations(self):
        admin = self.session('admin1')
        f = self.fixture()
        c = self.cluster_api()
        topic = 'gate2-adm-' + self.run_id
        self.cleanup_topics.add(topic)
        acl = {'resourceType': 'TOPIC', 'resourceName': topic, 'namePatternType': 'LITERAL',
               'principal': 'User:gate', 'host': '*', 'operation': 'READ', 'permission': 'ALLOW'}
        core = [
            ('create', 'POST', c + '/topics', {'name': topic, 'partitions': 1, 'replicationFactor': 1}),
            ('config', 'PATCH', '%s/topics/%s' % (c, topic), {'configs': {'retention.ms': '3600000'}}),
            ('partitions', 'PATCH', '%s/topics/%s/partitions' % (c, topic), {'totalPartitionsCount': 2}),
            ('produce', 'POST', '%s/topics/%s/messages' % (c, topic),
             {'partition': 0, 'key': 'a', 'value': 'admin', 'keySerde': 'String', 'valueSerde': 'String'}),
            ('read', 'GET', '%s/topics/%s/messages/v2?mode=EARLIEST&limit=5' % (c, topic), None),
            ('msg-delete', 'DELETE', '%s/topics/%s/messages?partitions=0' % (c, topic), None),
            ('offsets-reset', 'POST', '%s/consumer-groups/%s/offsets' % (c, f['group']),
             {'topic': f['topic'], 'resetType': 'EARLIEST', 'partitions': [0]}),
            ('offsets-delete', 'DELETE', '%s/consumer-groups/%s/topics/%s' % (c, f['group'], f['topic']), None),
            ('group-delete', 'DELETE', '%s/consumer-groups/%s' % (c, f['group_del']), None),
            ('broker-config', 'PUT', '%s/brokers/%s/configs/message.max.bytes' % (c, f['broker']),
             {'value': f['mmb'] or '1048588'}),
            ('delete', 'DELETE', '%s/topics/%s' % (c, topic), None),
        ]
        optional = [
            ('acl-create', 'POST', c + '/acls', acl), ('ksql', 'POST', c + '/ksql/v2', {'ksql': 'SHOW STREAMS;'}),
            ('connector', 'POST', c + '/connects/gate/connectors', {'name': 'gate', 'config': {}}),
            ('schema', 'POST', c + '/schemas', {'subject': 'gate', 'schema': '"string"', 'schemaType': 'AVRO'}),
        ]
        bad, seen, forbidden = [], [], []
        for label, method, path, payload in core:
            accept = 'text/event-stream' if label == 'read' else 'application/json'
            response = self.admin_call(admin, label, method, path, payload, accept)
            seen.append('%s=%s' % (label, response.status))
            if not 200 <= response.status < 300:
                bad.append('%s=%s %s' % (label, response.status, response.snippet(30)))
            if label == 'read' and 'admin' not in response.text:
                bad.append('read: produced message not returned')
        for label, method, path, payload in optional:
            response = self.admin_call(admin, label, method, path, payload, 'application/json')
            seen.append('%s=%s' % (label, response.status))
            if response.status == 403:
                forbidden.append(label)
        gone = None
        for _ in range(40):  # topic deletion completes asynchronously in the controller quorum
            gone = admin.api('GET', '%s/topics/%s' % (c, topic)).status
            if gone != 200:
                break
            time.sleep(0.5)
        if gone == 200:
            bad.append('topic still present after delete')
        self.cleanup_groups.discard(f['group_del'])
        core_ok = sum(1 for item in seen[:len(core)] if item.split('=')[1].startswith('2'))
        text = 'admin1 core %d/%d 2xx (%s); not 403: %s; deleted topic GET=%s' % (
            core_ok, len(core), ','.join(item.split('=')[0] for item in seen[:len(core)]),
            ' '.join(seen[len(core):]), gone)
        if bad or forbidden:
            fail('%s; %s' % (' '.join(bad + ['403:' + x for x in forbidden]), text))
        return 'PASS', text

    @staticmethod
    def admin_call(admin, label, method, path, payload, accept):
        """An admin mutation with a 90 s read timeout, retried once after a timeout (Kafka admin calls can be slow)."""
        for attempt in (1, 2):
            try:
                return admin.api(method, path, payload, accept=accept, timeout=K5_TIMEOUT)
            except (TimeoutError, OSError) as error:
                log('K5 %s attempt %d: %s' % (label, attempt, error))
                if attempt == 2:
                    return Resp(0, None, str(error).encode())
        return Resp(0, None, b'')

    def k6_nobody(self):
        result = self.kafbat_login(self.users['nobody1'], 'nobody1')
        if result['kind'] == 'unexpected' or result['kind'] == 'refused':
            fail('Keycloak step did not complete: %s %s' % (result['kind'], result.get('detail')))
        status = result['browser'].api('GET', '/api/clusters').status
        location = result.get('callback', ('', ''))[1]
        text = 'Keycloak login completed (TOTP enrolled); Kafbat callback %s Location=%s; /api/clusters with jar=%s' % (
            result.get('callback', ('?',))[0], location, status)
        if result['kind'] != 'kafbat-refused' or status == 200:
            fail(text)
        return 'PASS', text

    def k7_disabled(self):
        user = self.users['disabled1']
        if self.disabled_at is None:
            self.disable_user()
        result = self.kafbat_login(user, 'disabled1-new')
        proof = self.disabled_credentials_proof
        text = 'after krate identity users disable: new login %s at Keycloak (%s), no code issued; credentials: %s' % (
            result['kind'], result.get('detail', ''), proof)
        if result['kind'] != 'refused':
            fail(text)
        return 'PASS', text

    def disable_user(self):
        rc, out, err = self.krate('identity', 'users', 'disable', 'disabled1')
        if rc != 0:
            not_run('precondition: krate identity users disable failed: ' + (err or out).strip()[-120:])
        self.disabled_at = time.monotonic()
        log('disabled1 disabled with krate identity users disable')

    def k8_shared_login(self):
        browser = Browser(self, 'shared')
        page = browser.request('GET', self.base + '/login', headers={'Accept': 'text/html'})
        token = browser.xsrf()
        user = self.env.get('KAFKA_UI_USER') or 'admin'
        password = self.env.get('KAFKA_UI_PASSWORD') or ''
        note = ''
        if not password:
            password = secrets.token_urlsafe(16)
            note = ' (KAFKA_UI_PASSWORD blank in .env; random value sent)'
        REDACT.add(password)
        headers = {'X-XSRF-TOKEN': token} if token else {}
        posted = browser.form(self.base + '/login', {'username': user, 'password': password,
                                                     '_csrf': token or ''}, headers)
        api_auth = browser.api('POST', '/api/config/authentication', raw=urllib.parse.urlencode(
            {'username': user, 'password': password}).encode(), content_type='application/x-www-form-urlencoded')
        after = browser.api('GET', '/api/clusters')
        auth_type = self.auth_info.get('authType')
        text = 'GET /login=%s; POST /login=%s %s; POST /api/config/authentication=%s; then /api/clusters=%s; authType=%s%s' % (
            page.status, posted.status, posted.location[:40], api_auth.status, after.status, auth_type, note)
        if after.status == 200 or auth_type != 'OAUTH2':
            fail(text)
        return 'PASS', text

    # K9/K18: the deployed Kafbat image against a stub token endpoint that serves forged ID tokens.
    def stub_run(self) -> dict:
        """The stub results (a dict per variant), computed once; raises the Outcome when the stub run failed."""
        if self.stub_results is None:
            self.stub_results = self.run_stub()
        results = self.stub_results
        if isinstance(results, Outcome):
            raise results
        return results

    def run_stub(self):
        stub = StubIdp(self)
        try:
            return stub.run()
        except Outcome as outcome:
            return outcome
        except Exception as error:
            return Outcome('FAIL', 'stub harness error %s: %s' % (type(error).__name__, error))
        finally:
            stub.cleanup()

    def k9_id_token(self):
        results = self.stub_run()
        control = results['control']
        parts = ['control=%s' % control['outcome']] + ['%s=%s' % (k, results[k]['outcome'])
                                                      for k in ('wrong-iss', 'wrong-aud', 'expired', 'bad-signature')]
        text = 'deployed image %s vs stub IdP: %s; no session after each refusal=%s' % (
            self.image['kafka-ui'], ' '.join(parts), all(results[k]['session'] != 200 for k in results if k != 'control'))
        if control['outcome'] != 'accepted':
            not_run('positive control was not accepted (%s); negatives inconclusive' % control['detail'])
        if any(results[k]['outcome'] != 'refused' or results[k]['session'] == 200
               for k in ('wrong-iss', 'wrong-aud', 'expired', 'bad-signature')):
            fail(text)
        return 'PASS', text

    def k18_wrong_aud(self):
        results = self.stub_run()
        if results['control']['outcome'] != 'accepted':
            not_run('positive control was not accepted (%s)' % results['control']['detail'])
        aud, iss = results['wrong-aud'], results['wrong-iss']
        text = 'ID token aud/azp=krate-cli: callback %s, /api/clusters=%s; wrong iss: callback %s, /api/clusters=%s' % (
            aud['location'], aud['session'], iss['location'], iss['session'])
        if aud['outcome'] != 'refused' or iss['outcome'] != 'refused' or 200 in (aud['session'], iss['session']):
            fail(text)
        return 'PASS', text

    def k10_identity_sub(self):
        """Kafbat's identity is the OIDC sub: it survives a profile change of the Keycloak user.

        The realm's user profile keeps `username` read-only for administrators (kcadm answers
        error-user-attribute-read-only), so the change made here is the e-mail address and the
        first/last name, the attributes an IdP or an administrator can change.
        """
        viewer = self.session('viewer1')
        user = self.users['viewer1']
        info = viewer.api('GET', '/api/authorization').json() or {}
        name = (info.get('userInfo') or {}).get('username')
        perms = json.dumps((info.get('userInfo') or {}).get('permissions'), sort_keys=True)
        if name != user.uid:
            fail('Kafbat username %r is not the Keycloak sub %s' % (name, user.uid))
        email = 'viewer1-%s@gate.invalid' % self.run_id
        rc, out, err = self.keycloak().raw('update', 'users/' + user.uid, '-r', REALM, '-s', 'email=' + email,
                                   '-s', 'firstName=Gate', '-s', 'lastName=Changed' + self.run_id)
        stored = self.keycloak().get('users/' + user.uid) or {}
        if rc != 0 or stored.get('email') != email:
            not_run('Kafbat username == sub proven; profile change refused by Keycloak (rc %s: %s)' % (
                rc, (err or out).strip()[:90]))
        result = self.kafbat_login(user, 'viewer1-profile')
        if result['kind'] != 'ok':
            fail('login after the profile change: %s %s' % (result['kind'], result.get('detail')))
        info2 = result['browser'].api('GET', '/api/authorization').json() or {}
        name2 = (info2.get('userInfo') or {}).get('username')
        same = json.dumps((info2.get('userInfo') or {}).get('permissions'), sort_keys=True) == perms
        text = ('Kafbat username = Keycloak sub before; after e-mail/first/last name change (username read-only in '
                'the user profile): username = same sub %s, same permissions %s') % (name2 == user.uid, same)
        if name2 != user.uid or not same:
            fail(text)
        return 'PASS', text

    def k11_revocation(self):
        user = self.users['admin1']
        browser = self.session('admin1', 'admin1-k11')
        session = browser.cookie('SESSION')
        c = self.cluster_api()
        gid = self.group_ids['admin']
        self.keycloak().remove_group(user.uid, gid)
        try:
            topic = 'gate2-k11-' + self.run_id
            self.cleanup_topics.add(topic)
            kept = browser.api('POST', c + '/topics', {'name': topic, 'partitions': 1, 'replicationFactor': 1}).status
            browser.api('DELETE', '%s/topics/%s' % (c, topic))
            before = len(self.keycloak().sessions(user.uid))
            start = time.monotonic()
            self.keycloak().logout(user.uid)
            took = time.monotonic() - start
            ended, response = self.wait_dead(session)
            relogin = self.kafbat_login(user, 'admin1-relogin')
        finally:
            self.keycloak().add_group(user.uid, gid)
            self.sessions.pop('admin1', None)
            self.sessions.pop('admin1-k11', None)
        text = ('admin group removed: open session kept admin (create topic %s); kcadm logout (%d KC sessions) %.2fs, '
                'old SESSION %s after %s; re-login without group: %s %s') % (
            kept, before, took, response.status, '%.2fs' % ended if ended is not None else '>%ss' % POLL_SECONDS,
            relogin['kind'], relogin.get('callback', ('', ''))[1])
        if ended is None or relogin['kind'] != 'kafbat-refused':
            fail(text)
        return 'PASS', text

    def k12_csrf_cross_site(self):
        admin = self.session('admin1')
        c = self.cluster_api()
        topic = 'gate2-csrf-' + self.run_id
        self.cleanup_topics.add(topic)
        response = admin.api('POST', c + '/topics', {'name': topic, 'partitions': 1, 'replicationFactor': 1},
                             csrf=False, headers={'Origin': EVIL, 'Referer': EVIL + '/attack'})
        created = admin.api('GET', '%s/topics/%s' % (c, topic)).status
        logout = admin.form(self.base + '/logout', {}, {'Origin': EVIL})
        alive = self.probe(admin.cookie('SESSION')).status
        text = 'cross-site POST create-topic with SESSION, no token: %s (%s); topic GET=%s; cross-site POST /logout=%s; session still %s' % (
            response.status, response.snippet(40), created, logout.status, alive)
        if response.status != 403 or created == 200 or logout.status != 403 or alive != 200:
            fail(text)
        return 'PASS', text

    def k13_logout_get(self):
        viewer = self.session('viewer1', 'viewer1-logout')
        session = viewer.cookie('SESSION')
        got = viewer.request('GET', self.base + '/logout', headers={'Accept': 'text/html'})
        after_get = self.probe(session).status
        post = viewer.form(self.base + '/logout', {})
        after_post = self.probe(session).status
        text = 'GET /logout=%s %s, session then %s; POST /logout without token=%s, session then %s' % (
            got.status, got.location[:40], after_get, post.status, after_post)
        if after_get != 200 or post.status != 403 or after_post != 200:
            fail(text)
        return 'PASS', text

    def k14_fixation(self):
        user = self.users['both1']
        result = self.kafbat_login(user, 'both1')
        if result['kind'] != 'ok':
            not_run('precondition: both1 login %s %s' % (result['kind'], result.get('detail')))
        self.sessions['both1'] = result['browser']
        before, after = result['pre_session'], result['session']
        old = self.probe(before).status if before else None
        new = self.probe(after).status
        text = 'SESSION before login present=%s, after login changed=%s; old id -> %s, new id -> %s' % (
            bool(before), before != after, old, new)
        if not before:
            not_run('no SESSION cookie before login (nothing to fixate); ' + text)
        if before == after or old == 200 or new != 200:
            fail(text)
        return 'PASS', text

    def k15_open_redirect(self):
        notes, bad = [], []
        browser = Browser(self, 'redirect')
        response = browser.request('GET', self.base + '/oauth2/authorization/%s?redirect_uri=%s/cb' % (REGISTRATION, EVIL))
        sent = query_of(response.location).get('redirect_uri', [''])[0]
        notes.append('authz redirect_uri=%s' % ('callback' if sent == self.callback else sent))
        if sent != self.callback:
            bad.append('authorization request carried ' + sent)
        auth = browser.request('GET', self.realm_url + '/protocol/openid-connect/auth?' + urllib.parse.urlencode(
            {'client_id': UI_CLIENT, 'response_type': 'code', 'scope': 'openid', 'state': 'gate',
             'redirect_uri': EVIL + '/cb'}))
        notes.append('KC auth evil redirect_uri=%s' % auth.status)
        log('K15 Keycloak auth with evil redirect_uri: %s %s' % (auth.status, page_message(auth.text)))
        if auth.location.startswith(EVIL):
            bad.append('Keycloak redirected to evil')
        out = browser.request('GET', self.realm_url + '/protocol/openid-connect/logout?' + urllib.parse.urlencode(
            {'client_id': UI_CLIENT, 'post_logout_redirect_uri': EVIL + '/'}))
        notes.append('KC logout evil target=%s' % out.status)
        log('K15 Keycloak logout with evil post_logout_redirect_uri: %s %s' % (out.status, page_message(out.text)))
        if out.location.startswith(EVIL):
            bad.append('Keycloak logout redirected to evil')
        target = browser.request('GET', self.base + '//evil.example/', headers={'Accept': 'text/html'})
        notes.append('GET //evil.example/ %s->%s' % (target.status, target.location[:32]))
        if target.status in (301, 302, 303):
            joined = urllib.parse.urljoin(self.base + '/', target.location)
            if urllib.parse.urlsplit(joined).netloc != self.origin.netloc:
                bad.append('off-origin Location ' + target.location)
            if 'oauth2/authorization' in joined:
                result = self.kafbat_login(self.users['both1'], 'both1-redirect', start='//evil.example/')
                final = result.get('callback', ('', ''))[1]
                landing = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + '/', final)).netloc
                notes.append('post-login Location %s' % final[:40])
                if result['kind'] != 'ok':
                    notes.append('login %s' % result['kind'])
                elif landing != self.origin.netloc:
                    bad.append('post-login redirect off-origin: ' + final)
        text = '; '.join(notes)
        if bad:
            fail('; '.join(bad) + ' | ' + text)
        return 'PASS', text

    def k16_proxy_headers(self):
        """Forwarded-header spoofing. Kafbat redirects are relative (the OAuth redirect-uri is explicit), so the
        observable header is X-Forwarded-Prefix, which Spring's ForwardedHeaderTransformer turns into the
        context path of every redirect. Only a spoof through the proxy fails the case; a container on the
        Docker networks reaching kafka-ui:8080 directly is an accepted boundary (dual-login.md)."""
        spoof = {'X-Forwarded-Prefix': '/gate-spoof', 'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Proto': 'http'}
        plain = self.probe(None).location
        via_proxy = self.probe(None, headers=spoof).location
        notes = ['via proxy: Location %s (unspoofed %s)' % (via_proxy[:28], plain[:28])]
        bad = []
        if 'gate-spoof' in via_proxy or 'evil.example' in via_proxy:
            bad.append('client X-Forwarded-Prefix passes nginx, honoured')
        network = self.kafka_network()
        if not network:
            notes.append('direct peer: kafka network not found')
        else:
            args = ['run', '--rm', '--pull', 'never', '--network', network, '--label',
                    'com.docker.compose.project=' + self.project, '--label', GATE_LABEL, '--entrypoint', 'curl',
                    self.env['NGINX_IMAGE'], '-s', '-o', '/dev/null', '-D', '-', '--max-time', '15']
            for key, value in spoof.items():
                args += ['-H', '%s: %s' % (key, value)]
            rc, out, _ = docker(*args, 'http://kafka-ui:8080/api/clusters', timeout=60)
            location = next((line.split(':', 1)[1].strip() for line in out.splitlines()
                             if line.lower().startswith('location:')), '')
            status = out.split()[1] if out.startswith('HTTP/') else 'rc%s' % rc
            notes.append('non-proxy peer on %s -> kafka-ui:8080: %s %s' % (network.split('_')[-1], status, location[:28]))
            if 'gate-spoof' in location or 'evil.example' in location:
                # Accepted boundary (dual-login.md): containers on the Docker networks are trusted
                # infrastructure and can reach kafka-ui:8080 with their own forwarded headers.
                notes.append('honoured from non-proxy peer: accepted boundary per dual-login.md')
        notes.append('Keycloak side not observable (I2)')
        text = '; '.join(notes)
        if bad:
            fail('; '.join(bad) + ' | ' + text)
        return 'PASS', text

    def kafka_network(self):
        cid = service_container(self.project, 'kafka-ui')
        rc, out, _ = docker('inspect', '--format', '{{json .NetworkSettings.Networks}}', cid) if cid else (1, '', '')
        if rc != 0:
            return None
        names = list(json.loads(out).keys())
        return next((n for n in names if 'identity' not in n), None)

    def k19_bearer(self):
        user = self.users['admin1']
        browser = Browser(self, 'bearer')
        verifier = secrets.token_urlsafe(48)
        challenge = b64u(hashlib.sha256(verifier.encode()).digest())
        auth = self.realm_url + '/protocol/openid-connect/auth?' + urllib.parse.urlencode(
            {'client_id': UI_CLIENT, 'response_type': 'code', 'scope': 'openid profile email',
             'redirect_uri': self.callback, 'state': secrets.token_hex(8), 'nonce': secrets.token_hex(8),
             'code_challenge': challenge, 'code_challenge_method': 'S256'})
        kind, detail = self.keycloak_login(browser, user, auth)
        if kind != 'callback':
            not_run('precondition: admin1 Keycloak login %s %s' % (kind, detail))
        code = query_of(detail)['code'][0]
        REDACT.add(code)
        token = browser.form(self.realm_url + '/protocol/openid-connect/token', {
            'grant_type': 'authorization_code', 'code': code, 'redirect_uri': self.callback, 'client_id': UI_CLIENT,
            'client_secret': self.env['KEYCLOAK_KAFBAT_CLIENT_SECRET'], 'code_verifier': verifier})
        tokens = token.json() or {}
        access = tokens.get('access_token')
        if token.status != 200 or not access:
            not_run('precondition: krate-ui code exchange answered %s' % token.status)
        REDACT.add(access)
        REDACT.add(tokens.get('id_token'))
        REDACT.add(tokens.get('refresh_token'))
        cli = browser.form(self.realm_url + '/protocol/openid-connect/token', {
            'grant_type': 'client_credentials', 'client_id': CLI_CLIENT,
            'client_secret': self.env['KEYCLOAK_CLI_CLIENT_SECRET']}).json() or {}
        REDACT.add(cli.get('access_token'))
        notes, bad = [], []
        for label, value in (('krate-ui user token', access), ('krate-ui ID token', tokens.get('id_token')),
                             ('krate-cli token', cli.get('access_token'))):
            if not value:
                notes.append('%s: not obtained' % label)
                continue
            bare = Browser(self, 'bearer-' + label)
            clusters = bare.api('GET', '/api/clusters', headers={'Authorization': 'Bearer ' + value})
            info = bare.api('GET', '/api/authorization', headers={'Authorization': 'Bearer ' + value}).json() or {}
            notes.append('%s: /api/clusters=%s userInfo=%s' % (label, clusters.status, bool(info.get('userInfo'))))
            if clusters.status == 200 or info.get('userInfo'):
                bad.append(label)
        text = '; '.join(notes)
        if bad:
            fail('bearer accepted: %s | %s' % (','.join(bad), text))
        return 'PASS', text

    def k20_unguarded(self):
        viewer = self.session('viewer1')
        test = viewer.api('PUT', '/api/smartfilters/testexecutions',
                          {'filterCode': 'true', 'key': 'k', 'value': 'v', 'partition': 0, 'offset': 0})
        cache = viewer.api('POST', '/api/clusters/%s/cache' % self.cluster)
        text = 'viewer PUT /api/smartfilters/testexecutions=%s (%s); POST /api/clusters/%s/cache=%s; guide: reachable by every signed-in user' % (
            test.status, test.snippet(30), self.cluster, cache.status)
        if test.status != 200 or cache.status != 200:
            fail('observation differs from dual-login.md "What a viewer can do": ' + text)
        return 'PASS', text

    def k21_backchannel(self):
        viewer = self.session('viewer1')
        user = self.users['viewer1']
        session = viewer.cookie('SESSION')
        if self.probe(session).status != 200:
            not_run('precondition: viewer1 session not alive')
        count = len(self.keycloak().sessions(user.uid))
        since = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(time.time() - 2))
        start = time.monotonic()
        self.keycloak().logout(user.uid)
        took = time.monotonic() - start
        ended, response = self.wait_dead(session)
        self.sessions = {k: v for k, v in self.sessions.items() if not k.startswith('viewer1')}
        text = 'kcadm users/{id}/logout (%d KC sessions) returned in %.2fs; old SESSION -> %s %s after %s' % (
            count, took, response.status, response.location[:40],
            '%.2fs' % ended if ended is not None else '>%ss' % POLL_SECONDS)
        if ended is None:
            self.kafbat_log_hint(since)
            fail(text)
        return 'PASS', text

    def kafbat_log_hint(self, since):
        cid = service_container(self.project, 'kafka-ui')
        if cid:
            _, out, err = docker('logs', '--since', since, cid)
            lines = [line for line in (out + err).splitlines() if re.search(r'(?i)back-channel|logout|exception', line)]
            for line in lines[-8:]:
                log('kafka-ui log: ' + line[:200])

    def k22_disabled_session(self):
        if self.idle_result is None and self.idle_thread is None:
            not_run('precondition: disabled1 sessions were not prepared')
        if self.idle_thread is not None:
            log('waiting for the K22 idle-expiry measurement to finish')
            self.idle_thread.join()
        if isinstance(self.idle_result, Outcome):
            raise self.idle_result
        return self.idle_result

    def prepare_disabled(self):
        """K22: two disabled1 sessions before the user is disabled; one probed just before the idle limit, one after."""
        user = self.users['disabled1']
        first = self.kafbat_login(user, 'disabled1-a')
        second = self.kafbat_login(user, 'disabled1-b')
        if first['kind'] != 'ok' or second['kind'] != 'ok':
            self.idle_result = Outcome('NOT_RUN', 'precondition: disabled1 logins %s/%s' % (first['kind'], second['kind']))
            return
        self.disabled_credentials_proof = 'same password and TOTP signed in twice just before the disable'
        self.disable_user()
        a, b = first['session'], second['session']
        status_a, touched_a = self.probe(a).status, time.monotonic()
        status_b, touched_b = self.probe(b).status, time.monotonic()
        if self.wanted('K7'):
            self.case('K7', self.k7_disabled)
        if status_a != 200 or status_b != 200:
            self.idle_result = Outcome('FAIL', 'existing sessions after disable answered %s/%s (expected 200)' % (
                status_a, status_b))
            return
        idle = self.idle_seconds
        if self.args.no_idle_wait or not idle:
            self.idle_result = Outcome('NOT_RUN', 'existing sessions still 200 after disable; idle expiry (%ss) not '
                                                  'measured (--no-idle-wait)' % idle)
            return
        margin = min(60, max(5, idle // 10))

        def measure():
            try:
                time.sleep(max(0, touched_b + idle - margin - time.monotonic()))
                early_idle = time.monotonic() - touched_b
                early = self.probe(b).status
                time.sleep(max(0, touched_a + idle + margin - time.monotonic()))
                late_idle = time.monotonic() - touched_a
                late = self.probe(a)
                text = ('sessions survived the disable (200/200, new login refused: K7); idle limit %ss: after %.0fs idle %s, '
                        'after %.0fs idle %s %s') % (idle, early_idle, early, late_idle, late.status, late.location[:30])
                ok = early == 200 and late.status != 200
                self.idle_result = ('PASS' if ok else 'FAIL', text)
            except Exception as error:
                self.idle_result = Outcome('FAIL', 'idle measurement error %s' % error)

        self.idle_thread = threading.Thread(target=measure, daemon=True)
        self.idle_thread.start()
        log('K22: measuring idle expiry in the background (%ss + %ss margin)' % (idle, margin))

    def k23_csrf_token(self):
        admin = self.session('admin1')
        viewer = self.session('viewer1')
        c = self.cluster_api()
        topic = 'gate2-k23-' + self.run_id
        self.cleanup_topics.add(topic)
        body = {'name': topic, 'partitions': 1, 'replicationFactor': 1}
        none = admin.api('POST', c + '/topics', body, csrf=False)
        wrong = admin.api('POST', c + '/topics', body, csrf=False, headers={'X-XSRF-TOKEN': 'gate-wrong-token'})
        good = admin.api('POST', c + '/topics', body)
        admin.api('DELETE', '%s/topics/%s' % (c, topic))
        rbac = viewer.api('POST', c + '/topics', dict(body, name=topic + '-v'))
        text = 'admin no header=%s (%s); wrong token=%s; valid token=%s; viewer valid token=%s (%s)' % (
            none.status, none.snippet(30), wrong.status, good.status, rbac.status, rbac.snippet(30))
        if none.status != 403 or wrong.status != 403 or good.status != 200 or rbac.status != 403:
            fail(text)
        return 'PASS', text

    def k24_logout_post(self):
        viewer = self.session('viewer1', 'viewer1-logout')
        session = viewer.cookie('SESSION')
        token = viewer.xsrf()
        response = viewer.form(self.base + '/logout', {'_csrf': token or ''}, {'X-XSRF-TOKEN': token or ''})
        self.sessions.pop('viewer1-logout', None)
        alive = self.probe(session).status
        location = response.location
        end_session = self.realm_url + '/protocol/openid-connect/logout'
        params = query_of(location)
        rp = location.startswith(end_session)
        notes = ['POST /logout+token %s -> %s' % (response.status, 'KC end_session' if rp else (location[:50] or '(none)')),
                 'old SESSION %s' % alive]
        if rp:
            target = params.get('post_logout_redirect_uri', ['absent'])[0]
            notes.append('id_token_hint %s, post_logout_redirect_uri=%s%s' % (
                'yes' if 'id_token_hint' in params else 'no', target,
                '' if target in (self.base, self.base + '/') else ' (not the public origin)'))
            kc = viewer.request('GET', location)
            notes.append('KC end-session %s %s' % (kc.status, kc.location[:30] or page_message(kc.text)[:30]))
        again = viewer.request('GET', self.realm_url + '/protocol/openid-connect/auth?' + urllib.parse.urlencode(
            {'client_id': UI_CLIENT, 'response_type': 'code', 'scope': 'openid', 'redirect_uri': self.callback,
             'state': 'gate', 'code_challenge': b64u(hashlib.sha256(b'gate-k24').digest()),
             'code_challenge_method': 'S256'}))
        kc_ended = again.status == 200 and 'kc-form-login' in again.text
        notes.append('Keycloak SSO session ended=%s' % kc_ended)
        text = '; '.join(notes)
        if not rp:
            notes.append('no RP-initiated logout')
            text = '; '.join(notes)
        if response.status not in (302, 303) or alive == 200 or not rp or not kc_ended:
            fail(text)
        return 'PASS', text

    @staticmethod
    def follow(browser, url, hops=8):
        """GET through redirects with the browser's own jar; returns the final response."""
        response = browser.request('GET', url)
        while hops and response.status in (301, 302, 303) and response.location:
            location = urllib.parse.urljoin(url, response.location)
            response = browser.request('GET', location)
            url = location
            hops -= 1
        return response

    def k31_csrf_cookie(self):
        """XSRF-TOKEN is Secure, readable by the page, and rotates when a login completes."""
        user = self.users.get('viewer1')
        if user is None:
            not_run('precondition: user viewer1 was not created')
        browser = Browser(self, 'k31')
        first = browser.request('GET', self.base + '/api/authorization', headers={'Accept': 'application/json'})
        cookie = next((c for c in browser.jar if c.name == 'XSRF-TOKEN'), None)
        if cookie is None:
            fail('no XSRF-TOKEN cookie on an anonymous GET /api/authorization (status %s)' % first.status)
        header = first.headers.get('Set-Cookie', '') if first.headers else ''
        secure = bool(cookie.secure) or 'Secure' in header
        http_only = 'HttpOnly' in header
        before = cookie.value
        # Sign in with this very browser: the success handler expires the pre-login token.
        result = self.kafbat_login(user, 'k31', browser=browser)
        if result['kind'] != 'ok':
            not_run('precondition: viewer1 login %s %s' % (result['kind'], result.get('detail', '')))
        after_login = browser.cookie('XSRF-TOKEN')
        browser.request('GET', self.base + '/api/authorization', headers={'Accept': 'application/json'})
        after = browser.cookie('XSRF-TOKEN')
        signed_in = self.probe(browser.cookie('SESSION')).status if browser.cookie('SESSION') else None
        text = 'Secure=%s HttpOnly=%s; token before login %s, cleared at login=%s, new token after=%s; session=%s' % (
            secure, http_only, 'set', after_login is None or after_login != before, bool(after and after != before), signed_in)
        if not secure or http_only or signed_in != 200 or not after or after == before:
            fail(text)
        return 'PASS', text

    def k32_error_bodies(self):
        """Error responses carry no stack trace (http.error.excludeStackTraces)."""
        viewer = self.session('viewer1')
        admin = self.session('admin1')
        c = self.cluster_api()
        missing = viewer.api('GET', '%s/topics/gate2-missing-%s' % (c, self.run_id))
        invalid = admin.api('POST', c + '/topics', {'name': '', 'partitions': 0, 'replicationFactor': 0})
        denied = viewer.api('POST', c + '/topics', {'name': 'gate2-k32-' + self.run_id, 'partitions': 1, 'replicationFactor': 1})
        leaks = []
        for label, response in (('missing', missing), ('invalid', invalid), ('denied', denied)):
            body = response.json() or {}
            trace = body.get('stackTrace') if isinstance(body, dict) else None
            if trace or 'at io.kafbat' in response.text or 'Exception' in response.text and 'at ' in response.text:
                leaks.append('%s=%s (%d bytes)' % (label, response.status, len(response.body)))
        text = 'missing topic=%s invalid body=%s viewer denied=%s; bodies without stackTrace=%s' % (
            missing.status, invalid.status, denied.status, not leaks)
        if leaks:
            fail(text + '; leaking: ' + ' '.join(leaks))
        return 'PASS', text

    def k25_both_groups(self):
        browser = self.sessions.get('both1') or self.session('both1')
        c = self.cluster_api()
        topic = 'gate2-both-' + self.run_id
        self.cleanup_topics.add(topic)
        info = browser.api('GET', '/api/authorization').json() or {}
        perms = (info.get('userInfo') or {}).get('permissions') or []
        has_ksql = any(p.get('resource', '').lower() == 'ksql' for p in perms)
        create = browser.api('POST', c + '/topics', {'name': topic, 'partitions': 1, 'replicationFactor': 1}).status
        delete = browser.api('DELETE', '%s/topics/%s' % (c, topic)).status
        groups = sorted(g['name'] for g in self.keycloak().get('users/%s/groups' % self.users['both1'].uid) or [])
        text = 'both1 groups %s; permissions include administrator-only ksql=%s (%d entries); topic create=%s delete=%s' % (
            ','.join(groups), has_ksql, len(perms), create, delete)
        if not has_ksql or create != 200 or delete != 200:
            fail(text)
        return 'PASS', text

    def k26_group_rename(self):
        original = self.viewer_group
        renamed = 'GATE2_RENAMED_VIEWERS'
        before = self.keycloak().group_names()
        rc_set, out_set, err_set = self.krate('config', 'set', 'KEYCLOAK_VIEWER_GROUP=' + renamed)
        try:
            if rc_set != 0:
                after = self.keycloak().group_names()
                summary = 'config set refused (rc %s): %s' % (rc_set, (err_set or out_set).strip()[-80:])
                rc_up, report = None, ''
            else:
                rc_up, out_up, err_up = self.krate('identity', 'up', timeout=600)
                for line in (out_up + err_up).splitlines():
                    if line.strip():
                        log('K26 identity up: ' + line.strip()[:160])
                report = [line.strip() for line in (out_up + err_up).splitlines()
                          if re.search(r'(?i)realm|krate-ui|group', line) and re.search(r'(?i)no change|unchanged|'
                                                                                       r'present|reconcil|skip', line)]
                after = self.keycloak().group_names()
                summary = 'identity up rc %s: %s' % (rc_up, ' / '.join(report)[:80] or '(no realm line)')
        finally:
            restore = self.krate('config', 'set', 'KEYCLOAK_VIEWER_GROUP=' + (original or 'KRATE_VIEWERS'))[0]
            if rc_set == 0:
                restore_up = self.krate('identity', 'up', timeout=600)[0]
            else:
                restore_up = 'skipped'
        guide = self.guide_text()
        documented = 'does not rename the realm groups' in guide and 'Renaming groups after the realm exists' in guide
        text = '%s; realm groups before %s after %s; .env restored rc %s, identity up rc %s; guide documents admin-side rename=%s' % (
            summary, ','.join(before), ','.join(after), restore, restore_up, documented)
        if before != after or renamed in after or not documented or rc_up not in (0, None) or restore != 0:
            fail(text)
        return 'PASS', text

    def guide_text(self):
        for base in (self.edition, os.path.dirname(self.edition)):
            for rel in ('sso/guides/identity-foundation.md', 'docs/identity-foundation.md'):
                path = os.path.join(base, rel)
                if os.path.isfile(path):
                    with open(path, encoding='utf-8') as handle:
                        return handle.read()
        return ''

    # ── cleanup ──
    def cleanup(self):
        if self.args.skip_cleanup:
            log('--skip-cleanup: realm users and topics kept')
            return
        for name in list(self.users) + ['viewer1-renamed']:
            uid = self.keycloak().user_id(name) if self.kc else None
            if uid:
                try:
                    self.keycloak().delete_user(uid)
                except RuntimeError as error:
                    log('cleanup: %s' % error)
        for topic in sorted(self.cleanup_topics):
            self.broker_exec('/opt/kafka/bin/kafka-topics.sh', '--bootstrap-server', 'kafka-92:9092', '--delete',
                             '--if-exists', '--topic', topic)
        for group in sorted(self.cleanup_groups):
            self.broker_exec('/opt/kafka/bin/kafka-consumer-groups.sh', '--bootstrap-server', 'kafka-92:9092',
                             '--delete', '--group', group)
        log('cleanup: users %s, topics %s, groups %s removed' % (
            ','.join(self.users), ','.join(sorted(self.cleanup_topics)), ','.join(sorted(self.cleanup_groups))))

    # ── driver ──
    def main(self):
        for case in RUNNER_CASES:
            self.results[case] = ('NOT_RUN', 'owned by runner')
        problem = self.preflight()
        if problem is None:
            try:
                self.create_users()
            except RuntimeError as error:
                problem = 'user setup failed: %s' % error
        if problem is not None:
            log('preflight: ' + problem)
            for case in CASES:
                self.results.setdefault(case, ('NOT_RUN', evidence('precondition: ' + problem)))
            return self.finish()
        try:
            if self.wanted('K22'):
                self.prepare_disabled()
            self.case('K7', self.k7_disabled)
            plan = [('K2', self.k2_viewer_reads), ('K3', self.k3_viewer_mutations), ('K4', self.k4_viewer_messages),
                    ('K20', self.k20_unguarded), ('K5', self.k5_admin_mutations), ('K12', self.k12_csrf_cross_site),
                    ('K23', self.k23_csrf_token), ('K14', self.k14_fixation), ('K25', self.k25_both_groups),
                    ('K6', self.k6_nobody), ('K8', self.k8_shared_login), ('K15', self.k15_open_redirect),
                    ('K16', self.k16_proxy_headers), ('K19', self.k19_bearer), ('K10', self.k10_identity_sub),
                    ('K13', self.k13_logout_get), ('K24', self.k24_logout_post), ('K9', self.k9_id_token),
                    ('K18', self.k18_wrong_aud), ('K11', self.k11_revocation), ('K21', self.k21_backchannel),
                    ('K31', self.k31_csrf_cookie), ('K32', self.k32_error_bodies),
                    ('K26', self.k26_group_rename), ('K22', self.k22_disabled_session)]
            for name, func in plan:
                self.case(name, func)
        finally:
            try:
                self.cleanup()
            finally:
                if self.kc:
                    self.kc.close()
        return self.finish()

    def finish(self):
        for case in CASES:
            if case not in self.results:
                reason = 'not selected (--only)' if not self.wanted(case) else 'not reached'
                self.results[case] = ('NOT_RUN', reason)
            status, text = self.results[case]
            print('%s\t%s\t%s' % (case, status, evidence(text)), flush=True)
        return 1 if any(status == 'FAIL' for status, _ in self.results.values()) else 0


# ─── Stub identity provider for K9/K18 ───────────────────────────────────────

class StubIdp:
    """The deployed Kafbat image with the deployed runtime.yml, pointed at an nginx stub that serves forged ID tokens.

    Only the client's token/JWKS/userinfo/authorization endpoints, the client
    secret (a dummy), the callback base and the cookie's Secure flag differ
    from the fixture's runtime.yml; the issuer, client id, scopes, roles and
    require-mapped-role are the deployed ones. A positive control must be
    accepted for the negative results to count.
    """

    def __init__(self, gate):
        self.gate = gate
        tag = '%s-gate2-%s' % (gate.project, gate.run_id)
        self.network = tag + '-stubnet'
        self.idp = tag + '-stub-idp'
        self.ui = tag + '-stub-kafbat'
        self.workdir: Optional[str] = None
        self.created = []
        self.issuer = None
        self.base: Optional[str] = None
        self.jwks = None
        self.labels = ['--label', 'com.docker.compose.project=' + gate.project, '--label', GATE_LABEL]

    @staticmethod
    def subnet():
        rc, out, _ = docker('network', 'ls', '-q')
        taken = []
        if rc == 0 and out.split():
            _, info, _ = docker('network', 'inspect', *out.split())
            for net in json.loads(info or '[]'):
                for cfg in (net.get('IPAM') or {}).get('Config') or []:
                    if cfg.get('Subnet'):
                        taken.append(ipaddress.ip_network(cfg['Subnet'], strict=False))
        for third in range(200, 250):
            candidate = ipaddress.ip_network('10.254.%d.0/28' % third)
            if not any(candidate.overlaps(net) for net in taken if net.version == 4):
                return str(candidate)
        raise RuntimeError('no free 10.254.x.0/28 subnet for the stub network')

    @staticmethod
    def openssl(*args, stdin=None):
        proc = subprocess.run(['openssl'] + list(args), input=stdin, capture_output=True, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError('openssl %s failed: %s' % (args[0], proc.stderr.decode()[:120]))
        return proc.stdout

    def key(self, name):
        if not self.workdir:
            raise RuntimeError('stub IdP not started')
        path = os.path.join(self.workdir, name + '.pem')
        self.openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', path)
        return path

    def jwt(self, claims, keyfile):
        header = b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'gate-stub'}).encode())
        payload = b64u(json.dumps(claims).encode())
        signing = (header + '.' + payload).encode()
        return header + '.' + payload + '.' + b64u(self.openssl('dgst', '-sha256', '-sign', keyfile, stdin=signing))

    def nginx_conf(self, token, userinfo):
        bodies = {'token': json.dumps(token), 'certs': json.dumps(self.jwks), 'userinfo': json.dumps(userinfo)}
        for value in bodies.values():
            if any(ch in value for ch in '\'$\\'):
                raise RuntimeError('stub body contains a character nginx would interpret')
        return ('server {\n listen 80 default_server;\n default_type application/json;\n'
                + ''.join(" location = /%s { return 200 '%s'; }\n" % (k, v) for k, v in bodies.items())
                + " location / { return 404 '{}'; }\n}\n")

    def serve(self, token, userinfo, marker):
        conf = self.nginx_conf(token, userinfo)
        rc, _, err = docker('exec', '-i', self.idp, 'sh', '-c',
                            'cat > /etc/nginx/conf.d/default.conf && nginx -t -q && nginx -s reload', stdin=conf)
        if rc != 0:
            raise RuntimeError('stub reload failed: ' + err.strip()[:120])
        for _ in range(40):
            _, out, _ = docker('exec', self.idp, 'curl', '-s', 'http://127.0.0.1/token')
            if marker in out:
                return
            time.sleep(0.25)
        raise RuntimeError('stub did not serve the new token')

    def config(self):
        runtime = json.loads(json.dumps(self.gate.runtime))
        client = runtime['auth']['oauth2']['client'][REGISTRATION]
        client.update({'client-secret': 'gate-stub-dummy', 'authorization-uri': 'http://stub-idp/auth',
                       'token-uri': 'http://stub-idp/token', 'user-info-uri': 'http://stub-idp/userinfo',
                       'jwk-set-uri': 'http://stub-idp/certs',
                       'redirect-uri': '{baseUrl}/login/oauth2/code/{registrationId}'})
        runtime['server']['reactive']['session']['cookie']['secure'] = False
        runtime['kafka'] = {'clusters': [{'name': self.gate.cluster, 'bootstrapServers': 'stub-idp:9092'}]}
        self.issuer = client['issuer-uri']
        return json.dumps(runtime)

    def start(self):
        rc, _, err = docker('network', 'create', '--subnet', self.subnet(), *self.labels, self.network)
        if rc != 0:
            raise RuntimeError('stub network: ' + err.strip()[:120])
        self.created.append(('network', self.network))
        rc, _, err = docker('run', '-d', '--pull', 'never', '--name', self.idp, '--network', self.network,
                            '--network-alias', 'stub-idp', *self.labels, self.gate.env['NGINX_IMAGE'])
        if rc != 0:
            raise RuntimeError('stub idp: ' + err.strip()[:120])
        self.created.append(('container', self.idp))
        rc, _, err = docker('run', '-d', '--pull', 'never', '--name', self.ui, '--network', self.network,
                            '-p', '127.0.0.1::8080', *self.labels, '-e', 'SPRING_APPLICATION_JSON',
                            self.gate.env['KAFKA_UI_IMAGE'], env=dict(os.environ, SPRING_APPLICATION_JSON=self.config()))
        if rc != 0:
            raise RuntimeError('stub kafbat: ' + err.strip()[:160])
        self.created.append(('container', self.ui))
        _, out, _ = docker('port', self.ui, '8080/tcp')
        hostport = out.strip().splitlines()[0] if out.strip() else ''
        self.base = 'http://' + hostport
        self.gate.allowed_origins.add(self.base)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                if open_request(urllib.request.build_opener(NoRedirect), 'GET', self.base + '/actuator/health',
                                timeout=5).status == 200:
                    return
            except OSError:
                pass
            time.sleep(2)
        _, logs, errs = docker('logs', '--tail', '20', self.ui)
        raise RuntimeError('stub Kafbat not healthy within 180s: ' + (logs + errs).strip()[-200:])

    def attempt(self, label, keyfile, claims_patch):
        if not self.base:
            raise RuntimeError('stub IdP not started')
        browser = Browser(self.gate, 'stub-' + label, base=self.base)
        response = browser.request('GET', self.base + '/oauth2/authorization/' + REGISTRATION)
        params = query_of(response.location)
        if response.status != 302 or 'nonce' not in params:
            raise RuntimeError('stub authorization request: %s %s' % (response.status, response.location[:60]))
        now = int(time.time())
        subject = 'gate-stub-subject'
        claims = {'iss': self.issuer, 'sub': subject, 'aud': [UI_CLIENT], 'azp': UI_CLIENT, 'exp': now + 300,
                  'iat': now, 'auth_time': now, 'nonce': params['nonce'][0], 'jti': secrets.token_hex(8),
                  'groups': [self.gate.viewer_group], 'preferred_username': 'gate-stub'}
        claims.update(claims_patch)
        token = {'access_token': 'gate-stub-access', 'token_type': 'Bearer', 'expires_in': 300,
                 'scope': 'openid profile email', 'id_token': self.jwt(claims, keyfile), 'gate_marker': claims['jti']}
        self.serve(token, {'sub': subject, 'groups': [self.gate.viewer_group]}, claims['jti'])
        callback = browser.request('GET', '%s/login/oauth2/code/%s?code=gate-code&state=%s' % (
            self.base, REGISTRATION, urllib.parse.quote(params['state'][0])))
        location = callback.location
        session = browser.api('GET', '/api/clusters').status
        if callback.status in (302, 303) and 'error' in location:
            outcome = 'refused'
        elif callback.status in (302, 303):
            outcome = 'accepted'
        else:
            outcome = 'status %s' % callback.status
        log('stub %s: callback %s %s, /api/clusters %s' % (label, callback.status, location, session))
        return {'outcome': outcome, 'location': location or str(callback.status), 'session': session,
                'detail': '%s %s' % (callback.status, location)}

    def run(self):
        for key in ('KAFKA_UI_IMAGE', 'NGINX_IMAGE'):
            if not self.gate.env.get(key):
                not_run('precondition: %s missing from .env' % key)
        self.workdir = tempfile.mkdtemp(prefix='krate-gate2-')
        good, other = self.key('good'), self.key('other')
        modulus = self.openssl('rsa', '-in', good, '-noout', '-modulus').decode().strip().split('=', 1)[1]
        self.jwks = {'keys': [{'kty': 'RSA', 'kid': 'gate-stub', 'use': 'sig', 'alg': 'RS256',
                               'n': b64u(bytes.fromhex(modulus)), 'e': 'AQAB'}]}
        self.start()
        now = int(time.time())
        return {
            'control': self.attempt('control', good, {}),
            'wrong-iss': self.attempt('wrong-iss', good, {'iss': 'https://evil.example/identity/realms/krate'}),
            'wrong-aud': self.attempt('wrong-aud', good, {'aud': [CLI_CLIENT], 'azp': CLI_CLIENT}),
            'expired': self.attempt('expired', good, {'exp': now - 600, 'iat': now - 900, 'auth_time': now - 900}),
            'bad-signature': self.attempt('bad-signature', other, {}),
        }

    def cleanup(self):
        for kind, name in reversed(self.created):
            if kind == 'container':
                docker('rm', '-f', name)
            else:
                docker('network', 'rm', name)
        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)
        if self.created:
            log('stub resources removed: ' + ', '.join(name for _, name in self.created))


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog='phase2_kafbat.py', formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(__doc__ or '').split('\n\n')[0],
        epilog='\n\n'.join((__doc__ or '').split('\n\n')[1:]))
    parser.add_argument('--edition-dir', required=True, help='kraft or epc directory containing .env and krate')
    parser.add_argument('--base-url', required=True, help='public origin, e.g. https://localhost:8443')
    parser.add_argument('--project', required=True, help='Compose project name of the fixture')
    parser.add_argument('--only', type=lambda v: [x.strip().upper() for x in v.split(',') if x.strip()],
                        help='comma-separated case ids, e.g. K2,K3 (others print NOT_RUN)')
    parser.add_argument('--skip-cleanup', action='store_true',
                        help='keep the realm users and Kafka topics/groups created by the run')
    parser.add_argument('--no-idle-wait', action='store_true',
                        help='do not wait for the Kafbat idle timeout in K22 (K22 is then NOT_RUN)')
    args = parser.parse_args(argv)
    if not re.match(r'^https://[^/]+$', args.base_url.rstrip('/')):
        parser.error('--base-url must be an https origin without a path')
    if args.only and any(case not in CASES for case in args.only):
        parser.error('--only accepts K1..K26')
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    return Gate(args).main()


if __name__ == '__main__':
    sys.exit(main())
