#!/usr/bin/env python3
"""Krate access guard for Perses: map current IdP groups to Perses roles.

nginx asks GET /guard (auth_request) before every request and proxies
POST /api/auth/refresh to POST /refresh. OAuth2 Proxy supplies the current
IdP session and groups. In native mode the guard keeps each user's native
Perses role bindings equal to that membership and checks the user's live
permissions before letting the request through. In gateway mode Perses runs
without its own authentication and the guard alone enforces Viewer/Admin.
Every failure denies; nothing falls back to an earlier grant.
"""
import argparse
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import sys
import threading
import time
from urllib.parse import quote, unquote, urlencode, urlsplit

MANAGED = ('krate-admin-', 'krate-viewer-')
# Provisioned only in local mode; provisioning never deletes it on a mode switch.
LOCAL_ADMIN_BINDING = 'krate-local-admin'
ROLE_ADMIN = 'krate-admin'
ROLE_VIEWER = 'krate-viewer'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
SAFE_SEGMENT = re.compile(r'[A-Za-z0-9_.:-]+')
WRITE_ACTIONS = {'create', 'update', 'delete', '*'}

# Datasource query endpoints a Viewer may call through a saved datasource.
VIEWER_QUERY_SUFFIXES = re.compile(
    r'/api/v1/(query|query_range|query_exemplars|series|labels|parse_query|label/[A-Za-z0-9_.:-]+/values'
    r'|metadata|status/buildinfo)'
    r'|/select/logsql/(query|stats_query|stats_query_range|field_names|field_values|hits|streams'
    r'|stream_field_names|stream_field_values)')
# API reads a Viewer may make: the kinds of the krate-viewer role in roles.json, the
# UI's own settings, and the caller's permissions (Perses answers only for the caller).
# Gateway mode depends on this list because Perses' authorization is off there.
VIEWER_READS = re.compile(
    r'/api/config|/api/v1/(health|plugins|user/whoami|users/[^/]+/permissions)'
    r'|/api/v1/(projects|dashboards|datasources|variables|folders|globaldatasources|globalvariables)(/[^/]+)?'
    r'|/api/v1/projects/[^/]+/(dashboards|datasources|variables|folders)(/[^/]+)?')
PROXY_SAVED = re.compile(
    r'/proxy/(globaldatasources/[^/]+|projects/[^/]+/datasources/[^/]+'
    r'|projects/[^/]+/dashboards/[^/]+/datasources/[^/]+)(?P<suffix>/.*)?')


class Denied(Exception):
    """A request must be refused; status is 401 (no session) or 403."""

    def __init__(self, status, reason, cookies=()):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.cookies = list(cookies)


def clean_path(raw_uri):
    """Return the request path, or None when it could reach another route.

    nginx forwards the raw URI. Reject encodings and segments that a backend
    could normalise into a different path than the one classified here.
    """
    if not isinstance(raw_uri, str) or not raw_uri.startswith('/') or len(raw_uri) > 8192:
        return None
    path = raw_uri.split('?', 1)[0]
    lowered = path.lower()
    if any(token in lowered for token in ('%2e', '%2f', '%5c', '%00', '%25', '\\', ';')):
        return None
    if '//' in path or any(part in ('.', '..') for part in path.split('/')):
        return None
    if any(ord(char) < 0x21 or ord(char) > 0x7e for char in path):
        return None
    return unquote(path)


def classify(method, path, slug):
    """Classify a request as deny, refresh, bootstrap or api."""
    auth = '/api/auth/'
    if path.startswith(auth):
        if path == '/api/auth/refresh':
            return 'refresh'
        if path == '/api/auth/logout' and method in ('GET', 'HEAD'):
            return 'bootstrap'
        provider = '/api/auth/providers/oidc/' + slug + '/'
        if path in (provider + 'login', provider + 'callback') and method in ('GET', 'HEAD'):
            return 'bootstrap'
        # Native passwords, device code and client credentials stay private.
        return 'deny'
    if path in ('/api/config', '/api/v1/health', '/api/v1/plugins') and method in ('GET', 'HEAD'):
        return 'bootstrap'
    if path.startswith(('/api/', '/proxy/')) or path in ('/api', '/proxy'):
        return 'api'
    if method in ('GET', 'HEAD'):
        # The single-page UI, its assets and plugin modules.
        return 'bootstrap'
    return 'deny'


def viewer_allowed(method, path):
    """Return whether a Viewer may make this request."""
    if path.startswith('/proxy/'):
        match = PROXY_SAVED.fullmatch(path)
        if not match or match.group('suffix') is None:
            return False
        return method in ('GET', 'POST') and bool(VIEWER_QUERY_SUFFIXES.fullmatch(match.group('suffix')))
    if method in ('GET', 'HEAD'):
        if path == '/api' or path.startswith('/api/'):
            return bool(VIEWER_READS.fullmatch(path))
        return True
    return method == 'POST' and path == '/api/v1/view'


def role_for(groups, settings):
    if settings['admin_group'] in groups:
        return 'admin'
    if settings['viewer_group'] in groups:
        return 'viewer'
    return None


def subject_hash(issuer, subject):
    return hashlib.sha256((issuer + '\0' + subject).encode()).hexdigest()[:24]


def binding_names(issuer, subject):
    digest = subject_hash(issuer, subject)
    return {'admin': 'krate-admin-' + digest, 'viewer': 'krate-viewer-' + digest}


def cookie_token(cookie_header):
    """Rebuild the native Perses access token from its two cookies."""
    cookies = {}
    for part in (cookie_header or '').split(';'):
        name, _, value = part.strip().partition('=')
        if name:
            cookies[name] = value
    payload, signature = cookies.get('jwtPayload'), cookies.get('jwtSignature')
    if payload and signature:
        return payload + '.' + signature
    return None


def jwt_expiry(token):
    try:
        payload = token.split('.')[1]
        data = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        return float(data['exp'])
    except (IndexError, KeyError, TypeError, ValueError):
        return 0.0


class Http:
    """Minimal HTTP client for the private service network (no redirects)."""

    def __init__(self, base, timeout=5.0):
        parts = urlsplit(base)
        if parts.scheme != 'http' or not parts.hostname:
            raise ValueError('private service URL must be http://host[:port]: ' + base)
        self.host, self.port = parts.hostname, parts.port or 80
        self.prefix = parts.path.rstrip('/')
        self.timeout = timeout

    def request(self, method, path, headers=None, body=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
            sent = dict(headers or {})
            if data is not None and 'Content-Type' not in sent:
                sent['Content-Type'] = 'application/json'
            connection.request(method, self.prefix + path, body=data, headers=sent)
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read(4 * 1024 * 1024)
        finally:
            connection.close()

    def json(self, method, path, token=None, body=None, expect=(200,)):
        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        status, _, data = self.request(method, path, headers, body)
        if status not in expect:
            raise Denied(403, '%s %s returned %d' % (method, path, status))
        return status, (json.loads(data) if data.strip() else None)


class Ledger:
    """Persisted record of managed users, so expiry and restarts revoke them."""

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        try:
            self.users = json.loads(self.path.read_text())
            if not isinstance(self.users, dict):
                raise ValueError('ledger is not an object')
        except FileNotFoundError:
            self.users = {}

    def save(self):
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.users, sort_keys=True))
        os.replace(temporary, self.path)

    def touch(self, key, entry):
        with self.lock:
            self.users[key] = dict(entry, seen=time.time())
            self.save()

    def forget(self, key):
        with self.lock:
            if self.users.pop(key, None) is not None:
                self.save()

    def snapshot(self):
        with self.lock:
            return dict(self.users)


class Reconciler:
    """Keep native Perses bindings equal to current IdP membership."""

    def __init__(self, settings, perses, ledger):
        self.settings = settings
        self.perses = perses
        self.ledger = ledger
        self.service_token = None
        self.token_lock = threading.Lock()
        self.user_locks = {}
        self.locks_lock = threading.Lock()
        self.verified = {}

    def token(self):
        with self.token_lock:
            if self.service_token and jwt_expiry(self.service_token) - time.time() > 60:
                return self.service_token
            secret = Path(self.settings['service_client_secret_file']).read_text().strip()
            basic = base64.b64encode((self.settings['service_client_id'] + ':' + secret).encode()).decode()
            status, _, data = self.perses.request(
                'POST', '/api/auth/providers/oidc/%s/token' % self.settings['oidc_slug'],
                {'Authorization': 'Basic ' + basic, 'Content-Type': 'application/x-www-form-urlencoded',
                 'Accept': 'application/json'},
                urlencode({'grant_type': 'client_credentials'}).encode())
            if status != 200:
                raise Denied(403, 'service token request returned %d' % status)
            self.service_token = json.loads(data)['access_token']
            return self.service_token

    def lock_for(self, user):
        with self.locks_lock:
            return self.user_locks.setdefault(user, threading.Lock())

    def whoami(self, user_token):
        status, _, data = self.perses.request('GET', '/api/v1/user/whoami',
                                              {'Authorization': 'Bearer ' + user_token, 'Accept': 'application/json'})
        if status == 401:
            return None
        if status != 200:
            raise Denied(403, 'whoami returned %d' % status)
        return json.loads(data)

    def identity(self, user_token, proof_subject):
        """Return the canonical Perses user for the gateway's verified subject."""
        user = self.whoami(user_token)
        if user is None:
            return None
        name = (user.get('metadata') or {}).get('name')
        providers = (user.get('spec') or {}).get('oauthProviders') or []
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise Denied(403, 'unsafe Perses username')
        if (user.get('spec') or {}).get('nativeProvider'):
            raise Denied(403, 'native password users are not admitted')
        if len(providers) != 1:
            raise Denied(403, 'Perses user must have exactly one OIDC identity')
        provider = providers[0]
        if provider.get('issuer') != self.settings['issuer'] or provider.get('subject') != proof_subject:
            raise Denied(403, 'Perses identity does not match the gateway session')
        return name

    def ensure(self, name, subject, role, user_token):
        """Reconcile and confirm, at most once per verify_ttl for an unchanged role."""
        key = subject_hash(self.settings['issuer'], subject)
        cached = self.verified.get(key)
        if cached and cached[0] == role and cached[1] == name and time.time() - cached[2] < self.settings['verify_ttl']:
            self.ledger.touch(key, {'user': name, 'subject': subject, 'role': role})
            return
        with self.lock_for(key):
            self.apply(name, subject, role)
            self.confirm(name, role, user_token)
            self.verified[key] = (role, name, time.time())
            self.ledger.touch(key, {'user': name, 'subject': subject, 'role': role})

    def apply(self, name, subject, role):
        token = self.token()
        names = binding_names(self.settings['issuer'], subject)
        # Remove what must not be there before adding the wanted binding.
        for other, binding in names.items():
            if other != role:
                self.delete_global(binding, token)
        if role != 'admin':
            self.strip_user(name, token, keep=names.get(role))
        if role is not None:
            body = {'kind': 'GlobalRoleBinding', 'metadata': {'name': names[role]},
                    'spec': {'role': ROLE_ADMIN if role == 'admin' else ROLE_VIEWER,
                             'subjects': [{'kind': 'User', 'name': name}]}}
            status, current = self.perses.json('GET', '/api/v1/globalrolebindings/' + names[role], token, expect=(200, 404))
            if status == 404:
                self.perses.json('POST', '/api/v1/globalrolebindings', token, body, expect=(200, 201))
            elif current.get('spec') != body['spec']:
                self.perses.json('PUT', '/api/v1/globalrolebindings/' + names[role], token, body)
            _, readback = self.perses.json('GET', '/api/v1/globalrolebindings/' + names[role], token)
            if readback.get('spec') != body['spec']:
                raise Denied(403, 'binding read-back differs')

    def delete_global(self, binding, token):
        self.perses.json('DELETE', '/api/v1/globalrolebindings/' + binding, token, expect=(200, 204, 404))

    def strip_user(self, name, token, keep=None):
        """Remove the user from every other binding, including project owners."""
        _, globals_ = self.perses.json('GET', '/api/v1/globalrolebindings', token)
        for binding in globals_ or []:
            self.remove_subject(binding, name, token, '/api/v1/globalrolebindings/', keep)
        _, projects = self.perses.json('GET', '/api/v1/projects', token)
        for project in projects or []:
            project_name = project['metadata']['name']
            if not SAFE_SEGMENT.fullmatch(project_name):
                raise Denied(403, 'unsafe project name')
            path = '/api/v1/projects/%s/rolebindings/' % quote(project_name, safe='')
            _, bindings = self.perses.json('GET', path.rstrip('/'), token)
            for binding in bindings or []:
                self.remove_subject(binding, name, token, path, None)

    def remove_subject(self, binding, name, token, path, keep):
        binding_name = binding['metadata']['name']
        if binding_name == keep or binding_name == self.settings.get('service_binding'):
            return
        subjects = binding.get('spec', {}).get('subjects') or []
        remaining = [s for s in subjects if not (s.get('kind') == 'User' and s.get('name') == name)]
        if len(remaining) == len(subjects):
            return
        target = path + quote(binding_name, safe='')
        if remaining:
            updated = dict(binding, spec=dict(binding['spec'], subjects=remaining))
            self.perses.json('PUT', target, token, updated)
        else:
            self.perses.json('DELETE', target, token, expect=(200, 204, 404))

    def confirm(self, name, role, user_token):
        """Read the user's live native permissions and compare with the role."""
        status, permissions = self.perses.json('GET', '/api/v1/users/%s/permissions' % quote(name, safe=''), user_token)
        grants = [p for scope in (permissions or {}).values() for p in (scope or [])]
        actions = {a for p in grants for a in p.get('actions', [])}
        global_ = (permissions or {}).get('*') or []
        full = any('*' in p.get('actions', []) and '*' in p.get('scopes', []) for p in global_)
        if role == 'admin' and not full:
            raise Denied(403, 'admin permissions not active yet')
        if role == 'viewer' and ('read' not in actions or actions & WRITE_ACTIONS):
            raise Denied(403, 'viewer permissions not as expected')
        if role is None and grants:
            raise Denied(403, 'revoked user still has permissions')

    def revoke(self, key, entry):
        with self.lock_for(key):
            self.apply(entry['user'], entry['subject'], None)
            self.verified.pop(key, None)
            self.ledger.forget(key)

    def sweep(self, now=None):
        """Revoke users not seen with a current IdP proof within grant_ttl."""
        now = now or time.time()
        for key, entry in self.ledger.snapshot().items():
            if now - entry.get('seen', 0) > self.settings['grant_ttl']:
                self.revoke(key, entry)

    def startup(self):
        """Revoke everything recorded before a restart, then every managed binding."""
        for key, entry in self.ledger.snapshot().items():
            self.revoke(key, entry)
        token = self.token()
        _, bindings = self.perses.json('GET', '/api/v1/globalrolebindings', token)
        for binding in bindings or []:
            name = binding['metadata']['name']
            if name.startswith(MANAGED) or name == LOCAL_ADMIN_BINDING:
                self.delete_global(name, token)


class Guard:
    def __init__(self, settings, proxy, reconciler=None, perses=None):
        self.settings = settings
        self.proxy = proxy
        self.reconciler = reconciler
        self.perses = perses

    def proof(self, cookie):
        """Ask OAuth2 Proxy for the current session.

        Returns (subject, groups, cookies). OAuth2 Proxy refreshes the session
        with the IdP every group-proof period, which brings current groups, and
        clears it when the IdP revokes it; the cookies it sets must reach the
        browser, so they are returned for relaying.
        """
        status, headers, _ = self.proxy.request('GET', '/oauth2/auth', {'Cookie': cookie or ''})
        cookies = [v for k, v in headers if k.lower() == 'set-cookie']
        if status == 401:
            raise Denied(401, 'no current IdP session', cookies)
        if status != 202:
            raise Denied(403, 'session check returned %d' % status, cookies)
        header = {k.lower(): v for k, v in headers}
        subject = header.get('x-auth-request-user', '')
        groups = [g for g in header.get('x-auth-request-groups', '').split(',') if g]
        if not subject:
            raise Denied(403, 'session has no subject', cookies)
        return subject, set(groups), cookies

    def check(self, method, raw_uri, cookie, authorization=None):
        path = clean_path(raw_uri)
        if path is None:
            raise Denied(403, 'unsafe request path')
        kind = classify(method, path, self.settings['oidc_slug'])
        if kind in ('deny', 'refresh'):
            raise Denied(403, 'route is not public')
        try:
            subject, groups, cookies = self.proof(cookie)
        except Denied as exc:
            if exc.status == 401:
                self.revoke_token_holder(cookie_token(cookie) or bearer(authorization))
            raise
        try:
            role = role_for(groups, self.settings)
            if role is None:
                if self.reconciler and self.settings['mode'] == 'native':
                    self.revoke_known(subject)
                raise Denied(403, 'no Viewer or Admin group')
            if role == 'viewer' and kind == 'api' and not viewer_allowed(method, path):
                raise Denied(403, 'Viewer may not change resources')
            if self.settings['mode'] == 'native' and kind == 'api':
                token = cookie_token(cookie) or bearer(authorization)
                if token:
                    name = self.reconciler.identity(token, subject)
                    if name is not None:
                        self.reconciler.ensure(name, subject, role, token)
        except Denied as exc:
            exc.cookies = cookies + exc.cookies
            raise
        return role, cookies

    def role(self, cookie):
        """The caller's current role for the UI, from the same IdP proof."""
        subject, groups, cookies = self.proof(cookie)
        role = role_for(groups, self.settings)
        if role is None:
            raise Denied(403, 'no Viewer or Admin group', cookies)
        return role, cookies

    def revoke_token_holder(self, token):
        """Revoke the grants of the Perses user presenting a token without an IdP session.

        OAuth2 Proxy itself drops a session whose refreshed groups no longer
        qualify, so "no session" can mean removal. Revoking on a merely expired
        session is harmless: the next authenticated request grants again.
        """
        if not token or not self.reconciler or self.settings['mode'] != 'native':
            return
        try:
            user = self.reconciler.whoami(token)
        except Denied:
            return
        name = (user or {}).get('metadata', {}).get('name')
        for key, entry in self.reconciler.ledger.snapshot().items():
            if entry.get('user') == name:
                self.reconciler.revoke(key, entry)

    def revoke_known(self, subject):
        key = subject_hash(self.settings['issuer'], subject)
        entry = self.reconciler.ledger.snapshot().get(key)
        if entry:
            self.reconciler.revoke(key, entry)

    def refresh(self, cookie, body):
        """Proxy a native token refresh, releasing it only after reconciliation."""
        try:
            subject, groups, cookies = self.proof(cookie)
        except Denied as exc:
            if exc.status == 401:
                self.revoke_token_holder(cookie_token(cookie))
            raise
        role = role_for(groups, self.settings)
        if role is None:
            self.revoke_known(subject)
            raise Denied(403, 'no Viewer or Admin group')
        status, headers, data = self.perses.request(
            'POST', '/api/auth/refresh', {'Cookie': cookie or '', 'Content-Type': 'application/json'}, body or b'{}')
        if status != 200:
            return status, [h for h in headers if h[0].lower() != 'set-cookie'], data
        token = json.loads(data).get('access_token')
        if not token:
            raise Denied(403, 'refresh returned no access token')
        name = self.reconciler.identity(token, subject)
        if name is None:
            raise Denied(403, 'refreshed token was not accepted')
        self.reconciler.ensure(name, subject, role, token)
        return status, headers + [('Set-Cookie', c) for c in cookies], data


def bearer(header):
    if header and header.startswith('Bearer '):
        return header[7:]
    return None


RELAYED_COOKIES = 4


def relay(cookies):
    """nginx auth_request passes Set-Cookie only as numbered headers it relays."""
    if len(cookies) > RELAYED_COOKIES:
        raise ValueError('OAuth2 Proxy set more session cookies than the gateway relays')
    return [('X-Krate-Set-Cookie-%d' % i, c) for i, c in enumerate(cookies)]


def make_handler(guard):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, fmt, *args):
            sys.stderr.write('perses-sync: ' + fmt % args + '\n')

        def send(self, status, headers=(), body=b''):
            self.send_response(status)
            for name, value in headers:
                if name.lower() not in ('transfer-encoding', 'connection', 'content-length'):
                    self.send_header(name, value)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def denied(self, exc):
            self.log_message('deny %s %s: %s', self.headers.get('X-Original-Method', self.command),
                             self.headers.get('X-Original-URI', self.path).split('?', 1)[0], exc.reason)
            self.send(exc.status, relay(exc.cookies))

        def do_GET(self):
            if self.path == '/healthz':
                return self.send(200, [('Content-Type', 'text/plain')], b'ok\n')
            if self.path == '/role':
                try:
                    role, cookies = guard.role(self.headers.get('Cookie'))
                    return self.send(200, [('Content-Type', 'text/plain')] + [('Set-Cookie', c) for c in cookies],
                                     role.encode())
                except Denied as exc:
                    return self.send(exc.status, [('Set-Cookie', c) for c in exc.cookies])
                except Exception as exc:
                    self.log_message('error: %r', exc)
                    return self.send(403)
            if self.path != '/guard':
                return self.send(404)
            try:
                role, cookies = guard.check(self.headers.get('X-Original-Method', ''), self.headers.get('X-Original-URI', ''),
                                            self.headers.get('Cookie'), self.headers.get('Authorization'))
                self.send(200, [('X-Krate-Role', role)] + relay(cookies))
            except Denied as exc:
                self.denied(exc)
            except Exception as exc:  # Fail closed on any unexpected error.
                self.log_message('error: %r', exc)
                self.send(403)

        def do_POST(self):
            if self.path != '/refresh':
                return self.send(404)
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(min(length, 65536)) if length else b''
            try:
                status, headers, data = guard.refresh(self.headers.get('Cookie'), body)
                self.send(status, headers, data)
            except Denied as exc:
                # Perses' UI retries a refresh on any status except 400; 400
                # makes it clear its tokens and return to sign-in, where the
                # gateway sends the browser to the IdP.
                self.log_message('deny refresh: %s', exc.reason)
                self.send(400 if exc.status == 401 else exc.status, [('Set-Cookie', c) for c in exc.cookies])
            except Exception as exc:
                self.log_message('error: %r', exc)
                self.send(403)

    return Handler


def load_settings(path):
    settings = json.loads(Path(path).read_text())
    required = ['mode', 'issuer', 'viewer_group', 'admin_group', 'oidc_slug', 'perses_url', 'oauth2_proxy_url']
    if settings.get('mode') == 'native':
        required += ['service_client_id', 'service_client_secret_file', 'state_file']
    missing = [key for key in required if not settings.get(key)]
    if missing or settings['mode'] not in ('native', 'gateway'):
        raise ValueError('invalid settings; missing or wrong: ' + ', '.join(missing or ['mode']))
    for key in ('viewer_group', 'admin_group'):
        if ',' in settings[key]:
            raise ValueError(key + ' must not contain a comma')
    settings.setdefault('verify_ttl', 30)
    settings.setdefault('grant_ttl', 900)
    settings.setdefault('listen_port', 9091)
    return settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/krate/perses-sync/config.json')
    args = parser.parse_args()
    settings = load_settings(args.config)
    proxy = Http(settings['oauth2_proxy_url'])
    perses = Http(settings['perses_url'])
    reconciler = None
    if settings['mode'] == 'native':
        reconciler = Reconciler(settings, perses, Ledger(settings['state_file']))
        # Healthy only after earlier grants are gone; retry until Perses is up.
        while True:
            try:
                reconciler.startup()
                break
            except Exception as exc:
                sys.stderr.write('perses-sync: startup reconciliation failed, retrying: %r\n' % (exc,))
                time.sleep(3)
    guard = Guard(settings, proxy, reconciler, perses)
    server = ThreadingHTTPServer(('0.0.0.0', settings['listen_port']), make_handler(guard))
    server.daemon_threads = True
    stopping = threading.Event()

    def sweeper():
        while not stopping.wait(30):
            try:
                reconciler.sweep()
            except Exception as exc:
                sys.stderr.write('perses-sync: sweep failed: %r\n' % (exc,))

    if reconciler:
        threading.Thread(target=sweeper, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown).start())
    sys.stderr.write('perses-sync: %s mode listening on %d\n' % (settings['mode'], settings['listen_port']))
    server.serve_forever()
    stopping.set()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
