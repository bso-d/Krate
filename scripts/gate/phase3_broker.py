#!/usr/bin/env python3
"""Phase 3 acceptance gate: PingFederate brokering through the Krate realm, driven headlessly.

Runs against a running kraft fixture whose realm carries the applied identity-provider
plan (auth/keycloak/pingfederate-idp.json → provider `pingfederate`, the `krate
browser` flow, the `krate first broker login` flow) and against the stand-in IdP
started by scripts/gate/stub_idp.sh (users ping-viewer, ping-admin, ping-both,
ping-none; password in <stub-dir>/.user-pw). Every sign-in starts at Kafbat's
`/oauth2/authorization/keycloak`, follows the redirects through the realm to the
stand-in's login form, posts the credentials there and follows the way back to
Kafbat, recording each hop. Rows (CONTRACT.md, agent B):

  P5  ping-viewer → Kafbat viewer: topic create 403, topic list 200
  P6  ping-admin → topic create 200 (the topic is removed again)
  P7  ping-both → administrator (same permission set and create 200 as ping-admin)
  P8  ping-none → refused at Kafbat's login (/login?error), no role to map
  P9  revocation: ping-both loses APP-KAFKA-ADMINS in the stand-in → the next sign-in
      is a viewer (create 403); ping-admin loses it → refused at login (syncMode FORCE)
  P10 no Keycloak TOTP/profile page for SSO users: every realm hop of P5–P7 is a
      redirect, none is a required-action or review-profile page; the brokered users
      carry no required actions
  P11 break-glass: the default path answers 303 to the broker login; `kc_idp_hint=`
      (empty) shows the login form; the local user from `identity users add` is
      accepted there (next step: its required action); the hint-less path still
      goes to the IdP afterwards
  P12 an SSO identity whose username equals a local user: the first-broker-login
      flow (Create User If Unique, REQUIRED) answers an error page, the local user
      keeps no federated identity, no second user appears (D2)
  P13 Kafbat logout ends the Keycloak session (0 realm sessions); the next sign-in
      asks the IdP again (broker login hop), no cookie login
  --login-probe USER (no rows): one brokered sign-in of that stand-in user, printed
      as `LOGIN\t<kind>\t<evidence>` (status, landing path, page message, hops, the
      realm user's federated identities) for the runner's P16 (client secret rotation)

Reuses the Phase 2 helper's browser, kcadm (krate-cli service account) and
redaction (scripts/gate/phase2_kafbat.py). TLS is pinned on the fixture's
certs/server.crt and the stand-in's certificate; when either does not verify, every
row FAILs with the reason (no unverified fallback). Secrets: the stand-in passwords
come from 0600 files, the local user's password from the environment variable named
on the command line; nothing secret is printed. Output: one line per row on
stdout, `P<n>\\tPASS|FAIL|NOT_RUN\\t<evidence>`; progress on stderr. Exit 0 when no
row FAILed, 1 otherwise, 2 on a usage error.
"""
import argparse
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python3 -I does not add the script directory
import phase2_kafbat as p2  # noqa: E402

REDACT = p2.REDACT
log = p2.log
evidence = p2.evidence
Outcome = p2.Outcome
fail = p2.fail
REALM = 'krate'
REGISTRATION = 'keycloak'
CASES = ['P%d' % i for i in range(5, 14)]
STUB_USERS = ('ping-viewer', 'ping-admin', 'ping-both', 'ping-none')
VIEWERS = 'APP-KAFKA-VIEWERS'
ADMINS = 'APP-KAFKA-ADMINS'
MAX_HOPS = 14


def short(url):
    """A hop for the evidence: path only, no query (codes, states and nonces stay out)."""
    parts = urllib.parse.urlsplit(url)
    return parts.path


class Gate:
    def __init__(self, args):
        self.args = args
        self.edition = os.path.abspath(args.edition_dir)
        self.base = args.base_url.rstrip('/')
        self.origin = urllib.parse.urlsplit(self.base)
        self.project = args.project
        self.realm_url = self.base + '/identity/realms/' + REALM
        self.callback = self.base + '/login/oauth2/code/' + REGISTRATION
        self.stub_dir = os.path.abspath(args.stub_dir)
        self.stub_base = 'https://localhost:%d' % args.stub_port
        self.stub_realm = self.stub_base + '/realms/pingstub'
        self.allowed_origins = {self.base, self.stub_base}
        self.only = set(args.only) if args.only else None
        self.results = {}
        self.env = {}
        self.cluster = None
        self.tls = None
        self.tls_mode = ''
        self.kc = None
        self.stub_pw = None
        self.local_pw = None
        self.hops = {}  # user label → list of (status, path) through the realm and back
        self.permissions = {}
        self.cleanup_topics = set()

    # ── plumbing shared with the Phase 2 helper's Browser ──
    def check_url(self, url):
        if not any(url == o or url.startswith(o + '/') or url.startswith(o + '?') for o in self.allowed_origins):
            raise RuntimeError('refusing a request outside the fixture: ' + urllib.parse.urlsplit(url).netloc)

    def wanted(self, case):
        return self.only is None or case in self.only

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

    def keycloak(self):
        if self.kc is None:
            fail('precondition: the krate-cli kcadm session is not open')
        return self.kc

    def stub(self, *args):
        """stub_idp.sh <action> for the stand-in; its secrets stay in the stub directory."""
        cmd = [self.args.stub_script, args[0], '--project', self.project, '--out', self.stub_dir]
        if self.args.stub_container:
            cmd += ['--container', self.args.stub_container]
        cmd += list(args[1:])
        rc, out, err = p2.run(cmd, timeout=180)
        if rc != 0:
            raise RuntimeError('stub_idp.sh %s failed (rc %s): %s' % (args[0], rc, (err or out).strip()[-160:]))
        return out.strip()

    # ── setup ──
    def preflight(self):
        env_path = os.path.join(self.edition, '.env')
        if not os.path.isfile(env_path):
            return 'edition dir lacks .env: ' + self.edition
        self.env = p2.read_env(env_path)
        for key, value in self.env.items():
            if re.search(r'(_PASSWORD|_SECRET|_PASSPHRASE|_KEY)$', key):
                REDACT.add(value)
        if self.env.get('KAFKA_UI_AUTH_CONFIG') != 'runtime.yml':
            return 'KAFKA_UI_AUTH_CONFIG is %r, not runtime.yml' % self.env.get('KAFKA_UI_AUTH_CONFIG')
        if self.env.get('KEYCLOAK_CLI_CLIENT_SECRET', '') in ('', 'REPLACE_ME'):
            return 'KEYCLOAK_CLI_CLIENT_SECRET is not set in .env'
        plan = os.path.join(self.edition, 'auth', 'keycloak', 'pingfederate-idp.json')
        if not os.path.isfile(plan):
            return 'no identity-provider plan at ' + plan
        runtime_path = os.path.join(self.edition, 'auth', 'ui', 'runtime.yml')
        try:
            with open(runtime_path, encoding='utf-8') as handle:
                self.cluster = p2.json.load(handle)['rbac']['roles'][0]['clusters'][0]
        except (OSError, ValueError, KeyError, IndexError) as error:
            return 'cannot read the cluster name from auth/ui/runtime.yml: %s' % error
        for name in ('.user-pw', '.admin-pw', '.client-secret', 'stub.crt'):
            if not os.path.isfile(os.path.join(self.stub_dir, name)):
                return 'stub directory lacks %s (run stub_idp.sh up first)' % name
        with open(os.path.join(self.stub_dir, '.user-pw'), encoding='utf-8') as handle:
            self.stub_pw = handle.read().strip()
        for name in ('.admin-pw', '.client-secret'):
            with open(os.path.join(self.stub_dir, name), encoding='utf-8') as handle:
                REDACT.add(handle.read().strip())
        REDACT.add(self.stub_pw)
        if self.args.local_password_env:
            self.local_pw = os.environ.get(self.args.local_password_env, '')
            REDACT.add(self.local_pw)
        # TLS: the fixture's own certificate and the stand-in's are pinned; a certificate that does not
        # verify is a precondition failure of every row, never a silent fallback to no verification.
        cert = os.path.join(self.edition, 'certs', 'server.crt')
        stub_cert = os.path.join(self.stub_dir, 'stub.crt')
        self.tls_mode = 'pinned certs/server.crt and the stand-in certificate'
        url = ''
        try:
            self.tls = ssl.create_default_context(cafile=cert)
            self.tls.load_verify_locations(stub_cert)
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.tls))
            for url in (self.base + '/api/config/authentication', self.stub_realm):
                p2.open_request(opener, 'GET', url, timeout=15)
        except (OSError, ssl.SSLError) as error:
            reason = getattr(error, 'reason', error)
            return 'TLS pinned on certs/server.crt and the stand-in certificate failed for %s: %s' % (
                url, reason if isinstance(reason, ssl.SSLError) else error)
        log('TLS: ' + self.tls_mode)
        probe = p2.Browser(self, 'probe')
        response = probe.request('GET', self.base + '/api/config/authentication', headers={'Accept': 'application/json'})
        if response.status != 200:
            return 'GET /api/config/authentication answered %s' % response.status
        response = probe.request('GET', self.stub_realm)
        if response.status != 200:
            return 'the stand-in realm answered %s at %s' % (response.status, self.stub_realm)
        try:
            self.kc = p2.Kcadm(self.project, self.env['KEYCLOAK_CLI_CLIENT_SECRET'])
        except RuntimeError as error:
            return str(error)
        log('fixture: cluster %s, stand-in %s' % (self.cluster, self.stub_realm))
        return None

    # ── the brokered sign-in ──
    @staticmethod
    def follow(browser, url, trail, hops=MAX_HOPS):
        """GET through redirects, appending (status, path) per hop; returns the first non-redirect response and its URL."""
        for _ in range(hops):
            response = browser.request('GET', url, headers={'Accept': 'text/html'})
            trail.append((response.status, short(url)))
            if response.status in (301, 302, 303) and response.location:
                url = urllib.parse.urljoin(url, response.location)
                continue
            return response, url
        raise RuntimeError('more than %d redirects' % hops)

    def start_login(self, browser, trail):
        """Kafbat → realm → broker → the stand-in's login form (or wherever the chain stops)."""
        return self.follow(browser, self.base + '/oauth2/authorization/' + REGISTRATION, trail)

    def stub_form(self, response, url):
        if response.status != 200 or not url.startswith(self.stub_realm) or 'kc-form-login' not in response.text:
            fail('expected the stand-in login form, got %s at %s (%s)' % (response.status, short(url),
                                                                           p2.page_message(response.text)))
        action = p2.form_action(response.text)
        if not action:
            fail('the stand-in login form has no action URL')
        return action

    def brokered_login(self, user, label, browser=None, password=None):
        """Sign in through the stand-in; returns a dict with kind (ok|kafbat-refused|error|unexpected), hops, browser."""
        browser = browser or p2.Browser(self, label)
        trail = []
        response, url = self.start_login(browser, trail)
        action = self.stub_form(response, url)
        response = browser.form(action, {'username': user, 'password': password or self.stub_pw, 'credentialId': ''})
        if response.status != 302 or not response.location:
            return {'kind': 'unexpected', 'browser': browser, 'hops': trail,
                    'detail': 'the stand-in refused the credentials: %s %s' % (response.status, p2.page_message(response.text))}
        trail.append((response.status, 'stand-in:login-actions/authenticate'))
        response, url = self.follow(browser, urllib.parse.urljoin(action, str(response.location)), trail)
        result = {'browser': browser, 'hops': trail, 'status': response.status, 'landed': short(url),
                 'page': p2.page_message(response.text)}
        self.hops[label] = trail
        query = urllib.parse.urlsplit(url).query
        if url.startswith(self.base + '/login') and 'error' in query:
            result['kind'] = 'kafbat-refused'
        elif url.startswith(self.realm_url) and response.status != 200:
            result['kind'] = 'error'
        elif url.startswith(self.base) and response.status == 200 and browser.cookie('SESSION'):
            result['kind'] = 'ok'
        else:
            result['kind'] = 'unexpected'
            result['detail'] = 'landed %s %s' % (response.status, short(url))
        return result

    @staticmethod
    def hops_text(trail):
        return ' > '.join('%s %s' % (status, re.sub(r'^/identity/realms/krate/', 'realm:', path)
                                     .replace('/realms/pingstub/', 'stand-in:')) for status, path in trail)

    def signed_in(self, user, label):
        result = self.brokered_login(user, label)
        if result['kind'] != 'ok':
            fail('%s: %s %s; hops: %s' % (user, result['kind'], result.get('detail', result.get('page', '')),
                                           self.hops_text(result['hops'])))
        return result['browser']

    @staticmethod
    def permissions_of(browser):
        response = browser.api('GET', '/api/authorization')
        info = (response.json() or {}).get('userInfo') or {}
        perms = sorted({p['resource'] + ':' + ','.join(sorted(p.get('actions', []))) for p in info.get('permissions', [])})
        return perms

    def create_topic(self, browser, name):
        self.cleanup_topics.add(name)
        response = browser.api('POST', '/api/clusters/%s/topics' % self.cluster,
                               {'name': name, 'partitions': 1, 'replicationFactor': 1})
        if response.status == 200:
            browser.api('DELETE', '/api/clusters/%s/topics/%s' % (self.cluster, name))
        return response.status

    def list_topics(self, browser):
        return browser.api('GET', '/api/clusters/%s/topics' % self.cluster).status

    # ── rows ──
    def p5_viewer(self):
        browser = self.signed_in('ping-viewer', 'ping-viewer')
        perms = self.permissions_of(browser)
        self.permissions['ping-viewer'] = perms
        topic = [p for p in perms if p.startswith('TOPIC:')]
        create = self.create_topic(browser, 'gate3-p5')
        listed = self.list_topics(browser)
        text = 'ping-viewer signed in through the stand-in; Kafbat permissions %s; topic create %s; topic list %s; hops: %s' % (
            topic or perms, create, listed, self.hops_text(self.hops['ping-viewer']))
        if create != 403 or listed != 200 or any('CREATE' in p for p in topic):
            fail(text)
        return 'PASS', text

    def p6_admin(self):
        browser = self.signed_in('ping-admin', 'ping-admin')
        perms = self.permissions_of(browser)
        self.permissions['ping-admin'] = perms
        create = self.create_topic(browser, 'gate3-p6')
        text = 'ping-admin signed in; topic create %s (removed again); %d permission entries; hops: %s' % (
            create, len(perms), self.hops_text(self.hops['ping-admin']))
        if create != 200:
            fail(text)
        return 'PASS', text

    def p7_both(self):
        browser = self.signed_in('ping-both', 'ping-both')
        perms = self.permissions_of(browser)
        admin = self.permissions.get('ping-admin')
        create = self.create_topic(browser, 'gate3-p7')
        missing = sorted(set(admin or []) - set(perms))
        text = ('ping-both (both AD groups) signed in; topic create %s; %d permission entries (viewer and administrator '
                'roles together), administrator entries of P6 missing: %s') % (create, len(perms), missing or 'none')
        if create != 200 or admin is None or missing:
            fail(text)
        return 'PASS', text

    def p8_none(self):
        result = self.brokered_login('ping-none', 'ping-none')
        text = 'ping-none (no AD group): %s at %s; hops: %s' % (result['kind'], result.get('landed'), self.hops_text(result['hops']))
        if result['kind'] != 'kafbat-refused':
            fail(text)
        return 'PASS', text

    def p10_no_totp(self):
        notes = []
        bad = False
        for user in ('ping-viewer', 'ping-admin', 'ping-both'):
            trail = self.hops.get(user)
            if not trail:
                fail('precondition: no recorded sign-in of %s (P5–P7 did not sign in)' % user)
            pages = [(s, p) for s, p in trail if p.startswith('/identity/') and s == 200]
            actions = [p for _, p in trail if 'required-action' in p or 'update-profile' in p or 'review-profile' in p]
            uid = self.keycloak().user_id(user)
            required = (self.keycloak().get('users/' + uid) or {}).get('requiredActions', []) if uid else ['(no realm user)']
            notes.append('%s: %d hops, realm pages %s, action hops %s, requiredActions %s' % (
                user, len(trail), pages or 'none', actions or 'none', required))
            if pages or actions or required:
                bad = True
        text = 'no Keycloak page between the stand-in and Kafbat: ' + '; '.join(notes)
        if bad:
            fail(text)
        return 'PASS', text

    def p11_break_glass(self):
        if not self.args.local_user or not self.local_pw:
            fail('precondition: --local-user and a password in the environment are required')
        browser = p2.Browser(self, 'break-glass')
        # The authorization request Kafbat makes (state, nonce, PKCE are Kafbat's own).
        response = browser.request('GET', self.base + '/oauth2/authorization/' + REGISTRATION, headers={'Accept': 'text/html'})
        if response.status not in (302, 303) or not response.location.startswith(self.realm_url):
            fail('Kafbat did not redirect to the realm: %s %s' % (response.status, short(response.location)))
        auth_url = response.location
        plain = browser.request('GET', auth_url)
        hint = browser.request('GET', auth_url + '&kc_idp_hint=')
        notes = ['default path %s -> %s' % (plain.status, short(plain.location) if plain.location else 'no redirect'),
                 'kc_idp_hint= %s %s' % (hint.status, 'login form' if 'kc-form-login' in hint.text else p2.page_message(hint.text))]
        ok_default = plain.status == 303 and short(plain.location).endswith('/broker/%s/login' % 'pingfederate')
        ok_hint = hint.status == 200 and 'kc-form-login' in hint.text
        ok_local = False
        if ok_hint:
            posted = browser.form(p2.form_action(hint.text), {'username': self.args.local_user, 'password': self.local_pw,
                                                             'credentialId': ''})
            location = posted.location or ''
            step = re.search(r'execution=([A-Z_]+)', location)
            notes.append('local user %s: %s -> %s%s' % (self.args.local_user, posted.status, short(location) or p2.page_message(posted.text),
                                                       ' (%s)' % step.group(1) if step else ''))
            ok_local = posted.status in (302, 303) and 'login-actions/required-action' in location \
                and step is not None and step.group(1) in ('CONFIGURE_TOTP', 'UPDATE_PASSWORD')
        again = p2.Browser(self, 'break-glass-2')
        response = again.request('GET', self.base + '/oauth2/authorization/' + REGISTRATION, headers={'Accept': 'text/html'})
        plain2 = again.request('GET', response.location) if response.location else response
        notes.append('hint-less path afterwards %s -> %s' % (plain2.status, short(plain2.location) if plain2.location else 'no redirect'))
        ok_again = plain2.status == 303 and short(plain2.location).endswith('/broker/pingfederate/login')
        text = '; '.join(notes)
        if not (ok_default and ok_hint and ok_local and ok_again):
            fail(text)
        return 'PASS', text

    def p12_clash(self):
        name = self.args.clash_user
        if not name:
            fail('precondition: --clash-user (an existing local user) is required')
        uid = self.keycloak().user_id(name)
        if not uid:
            fail('precondition: local user %s does not exist in the realm' % name)
        before = len(self.keycloak().get('users', 'username=' + name, 'exact=true') or [])
        try:
            self.stub('add-user', name, VIEWERS)
        except RuntimeError as error:  # a rerun on a development fixture: the stand-in user is already there
            if 'already exists' not in str(error):
                raise
            log('stand-in user %s already exists; reused' % name)
        result = self.brokered_login(name, 'clash-' + name)
        linked = self.keycloak().get('users/%s/federated-identity' % uid) or []
        after = len(self.keycloak().get('users', 'username=' + name, 'exact=true') or [])
        # Seen live (2026-10-11, fixture krate-p3): HTTP 409 at realm:login-actions/first-broker-login with
        # "User with username <name> already exists. Please login to account management to link the account."
        landed = result.get('landed') or ''
        text = ('stand-in user %s (same username as the local user): %s %s at %s (%s); local user federated identities %d, '
                'realm users named %s: %d before, %d after; hops: %s') % (
            name, result['kind'], result.get('status'), landed, result.get('page') or result.get('detail', ''), len(linked), name,
            before, after, self.hops_text(result['hops']))
        if result['kind'] != 'error' or result.get('status') != 409 or not landed.endswith('/login-actions/first-broker-login') \
                or 'already exists' not in (result.get('page') or '') or linked or after != before:
            fail(text)
        return 'PASS', text

    def p13_logout(self):
        browser = self.signed_in('ping-viewer', 'ping-viewer-logout')
        uid = self.keycloak().user_id('ping-viewer')
        if not uid:
            fail('precondition: no realm user ping-viewer after the sign-in')
        # The user may hold other realm sessions from P5/P10; the one this browser made must be the one that ends.
        sessions_before = {s.get('id') for s in self.keycloak().sessions(uid)}
        token = browser.xsrf()
        response = browser.form(self.base + '/logout', {'_csrf': token or ''}, {'X-XSRF-TOKEN': token or ''})
        end_session = self.realm_url + '/protocol/openid-connect/logout'
        rp = response.status in (302, 303) and response.location.startswith(end_session)
        notes = ['POST /logout %s -> %s' % (response.status, 'KC end_session' if rp else short(response.location or ''))]
        if rp:
            kc = browser.request('GET', response.location)
            notes.append('end-session %s -> %s' % (kc.status, (short(kc.location) or '/') if kc.location else p2.page_message(kc.text)[:40]))
        sessions_after = {s.get('id') for s in self.keycloak().sessions(uid)}
        ended = sessions_before - sessions_after
        notes.append('realm sessions of ping-viewer %d -> %d (%d ended)' % (len(sessions_before), len(sessions_after), len(ended)))
        trail = []
        self.start_login(browser, trail)
        asked_idp = any(path.endswith('/broker/pingfederate/login') for _, path in trail) \
            and any(path.startswith('/realms/pingstub/') for _, path in trail)
        notes.append('next sign-in hops: %s' % self.hops_text(trail))
        text = '; '.join(notes)
        if not rp or not sessions_before or len(ended) != 1 or sessions_after - sessions_before or not asked_idp:
            fail(text)
        return 'PASS', text

    def p9_revocation(self):
        if 'ping-admin' not in self.permissions:
            fail('precondition: P6 did not record the administrator permissions')
        self.stub('remove-group', 'ping-both', ADMINS)
        self.stub('remove-group', 'ping-admin', ADMINS)
        both = self.brokered_login('ping-both', 'ping-both-revoked')
        create = self.create_topic(both['browser'], 'gate3-p9') if both['kind'] == 'ok' else None
        listed = self.list_topics(both['browser']) if both['kind'] == 'ok' else None
        groups = []
        uid = self.keycloak().user_id('ping-both')
        if uid:
            groups = sorted(g.get('name') for g in (self.keycloak().get('users/%s/groups' % uid) or []))
        admin = self.brokered_login('ping-admin', 'ping-admin-revoked')
        text = ('ping-both without %s in the stand-in: next sign-in %s, topic create %s, list %s, realm groups %s; '
                'ping-admin without it: %s at %s') % (ADMINS, both['kind'], create, listed, groups, admin['kind'], admin.get('landed'))
        viewer_group = self.env.get('KEYCLOAK_VIEWER_GROUP') or 'KRATE_VIEWERS'
        if both['kind'] != 'ok' or create != 403 or listed != 200 or groups != [viewer_group] or admin['kind'] != 'kafbat-refused':
            fail(text)
        return 'PASS', text

    # ── driver ──
    def login_probe(self, user):
        """One brokered sign-in for the runner (P16): kind, status, landing, page, federated identities, hops."""
        result = self.brokered_login(user, 'probe-' + user)
        uid = self.keycloak().user_id(user)
        linked = len(self.keycloak().get('users/%s/federated-identity' % uid) or []) if uid else 0
        text = '%s: %s %s at %s%s; federated identities %d; hops: %s' % (
            user, result['kind'], result.get('status', ''), result.get('landed'),
            ' (%s)' % (result.get('page') or result.get('detail')) if result.get('page') or result.get('detail') else '',
            linked, self.hops_text(result['hops']))
        print('LOGIN\t%s\t%s' % (result['kind'], evidence(text)), flush=True)
        return 0

    def main(self):
        problem = self.preflight()
        if problem is not None:
            log('preflight: ' + problem)
            if self.args.login_probe:
                print('LOGIN\tFAIL\t' + evidence('precondition: ' + problem), flush=True)
                return 1
            for case in CASES:
                if self.wanted(case):
                    self.results[case] = ('FAIL', evidence('precondition: ' + problem))
            return self.finish()
        if self.args.login_probe:
            try:
                return self.login_probe(self.args.login_probe)
            except Outcome as outcome:
                print('LOGIN\tFAIL\t' + evidence(outcome.text), flush=True)
                return 1
            finally:
                if self.kc:
                    self.kc.close()
        try:
            for name, func in (('P5', self.p5_viewer), ('P6', self.p6_admin), ('P7', self.p7_both), ('P8', self.p8_none),
                               ('P10', self.p10_no_totp), ('P11', self.p11_break_glass), ('P12', self.p12_clash),
                               ('P13', self.p13_logout), ('P9', self.p9_revocation)):
                self.case(name, func)
        finally:
            if self.kc:
                self.kc.close()
        return self.finish()

    def finish(self):
        for case in CASES:
            if case not in self.results:
                self.results[case] = ('NOT_RUN', 'not selected (--only)' if not self.wanted(case) else 'not reached')
            status, text = self.results[case]
            if self.tls and status != 'NOT_RUN':  # the TLS mode of the run is part of every row's evidence
                text = 'TLS pinned; %s' % text
            print('%s\t%s\t%s' % (case, status, evidence(text)), flush=True)
        return 1 if any(status == 'FAIL' for status, _ in self.results.values()) else 0


def parse_args(argv):
    parser = argparse.ArgumentParser(prog='phase3_broker.py', formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=(__doc__ or '').split('\n\n')[0],
                                     epilog='\n\n'.join((__doc__ or '').split('\n\n')[1:]))
    parser.add_argument('--edition-dir', required=True, help='kraft directory containing .env, auth/ and certs/')
    parser.add_argument('--base-url', required=True, help='public origin, e.g. https://localhost:8443')
    parser.add_argument('--project', required=True, help='Compose project name of the fixture')
    parser.add_argument('--stub-dir', required=True, help='directory stub_idp.sh up wrote (.user-pw, stub.crt, ...)')
    parser.add_argument('--stub-port', type=int, default=18443, help='published port of the stand-in on 127.0.0.1')
    parser.add_argument('--stub-script', default=os.path.join(HERE, 'stub_idp.sh'), help='path of stub_idp.sh')
    parser.add_argument('--stub-container', help='the stand-in container when it is not <project>-gate3-pingstub')
    parser.add_argument('--login-probe', metavar='USER', help='one brokered sign-in of USER, printed as a LOGIN line (no rows)')
    parser.add_argument('--local-user', help='P11: a local realm user made by krate identity users add')
    parser.add_argument('--local-password-env', help='P11: environment variable holding that user\'s temporary password')
    parser.add_argument('--clash-user', help='P12: an existing local user whose name the stand-in will reuse')
    parser.add_argument('--only', type=lambda v: [x.strip().upper() for x in v.split(',') if x.strip()],
                        help='comma-separated row ids, e.g. P5,P8 (others print NOT_RUN)')
    args = parser.parse_args(argv)
    if not re.match(r'^https://[^/]+$', args.base_url.rstrip('/')):
        parser.error('--base-url must be an https origin without a path')
    if args.only and any(case not in CASES for case in args.only):
        parser.error('--only accepts ' + ', '.join(CASES))
    if not os.access(args.stub_script, os.X_OK):
        parser.error('stub script not executable: ' + args.stub_script)
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    return Gate(args).main()


if __name__ == '__main__':
    sys.exit(main())
