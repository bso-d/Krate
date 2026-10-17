#!/usr/bin/env python3
"""Phase 4 companion row K37: Kafbat's absolute session lifetime (audit gap B7, owner decision G4 "8 h max").

Runs only in the `--session-max-hours N` companion of slice 4a. The runner passes `--prepare-only` once (it adds
and enrols the viewer p4kmax), then `--prepared --only K37 --session-max-minutes 60*N` beside the Grafana helper's
U27 worker:

    python3 -I scripts/gate/phase4_kafbat.py run --edition-dir ED --base-url https://H \\
        --monitor-project krate-<edition>-monitoring --state DIR --prepare-only
    python3 -I scripts/gate/phase4_kafbat.py run ... --only K37 --prepared --session-max-minutes 60

Output: TSV rows `<id>\\tPASS|FAIL|NOT_RUN\\t<evidence>` and a leading `setup` line, exit codes of phase2_kafbat.py.

M is the session maximum in seconds. t0 is taken before the first request of the sign-in (Kafbat creates the
WebSession there), t1 after the callback answered, so the session's creation time lies in [t0, t1]: it must still
answer before t0+M-60 s and must be refused from t1+M+10 s on. The viewer asks for /api/clusters every 30 s, so the
idle limit (15 minutes) never applies and the maximum is the only thing that can end the session.

The steps are those observed on 2026-10-16/17 on a Mac KRaft fixture with the sso.8 image
(harness/kafbat-maxlife/b7/OBSERVATIONS.md H5-H10): a busy session answered 200 up to the maximum and 302 to
/oauth2/authorization/keycloak from the first request after it (H6); Kafbat logged "Ended a session that reached
its maximum lifetime of PT5M" (H6); a whitelisted path such as /api/authorization still answers 200 after the
maximum, as anonymous (H7), so the poll uses /api/clusters, which needs a sign-in; a login started with the dead
cookie ends once in /login?error and a login in a new browser works (H10), so the second sign-in uses a new browser.

K37 probes, in order (the row takes the worst token, scripts/gate/probes.py):
  cadence_60s       the first request is within 60 s of t1 and no two requests are more than 60 s apart
  early_200         every request made before t0+M-60 s answers 200
  refused_M10_M60   the first request made at or after t1+M+10 s, no later than t1+M+60 s, is 302 to
                    /oauth2/authorization/keycloak (the K28 contract for an anonymous caller); every refusal on the
                    way, the one that ends the session included, is such a redirect (not a 403 or a 5xx); and no
                    request is answered 200 after the first refusal
  ended_logged      the kafka-ui log gained the line "Ended a session that reached its maximum lifetime of PT<N>H"
                    (the refusal is the maximum's, not a restart, a logout or the idle limit)
  stays_refused     the dead SESSION cookie, sent alone 30 s later, is refused the same way
  new_login_ok      a new sign-in of the same user in a new browser (password and TOTP) works and its first
                    /api/clusters answers 200

The sign-ins take their TOTP codes from the helper's per-user ledger (phase4_common.TotpSteps), as the Grafana and
Perses sign-ins do: a step this user already submitted (the enrolment's, the first sign-in's) is waited out, nothing
else is.
"""
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python3 -I does not add the script directory
import phase2_kafbat as p2  # noqa: E402
from phase4_common import Phase4Gate, helper_main, aggregate, log  # noqa: E402

CASES = ['K37']
PROBES = ('cadence_60s', 'early_200', 'refused_M10_M60', 'ended_logged', 'stays_refused', 'new_login_ok')   # the evidence tokens, in order
USER = 'p4kmax'
EMAIL = USER + '@k37.test'
LOGIN_PATH = '/oauth2/authorization/' + p2.REGISTRATION
POLL_PATH = '/api/clusters'    # needs a sign-in; a whitelisted path (/api/authorization) answers 200 as anonymous after the maximum
CADENCE_S = 30                 # the cadence of the live observation (H6)
CADENCE_BOUND_S = 60           # the bound of cadence_60s: U27's cadence rule
POLL_TIMEOUT_S = 15            # one retry fits inside the cadence bound
TARGET_S = 15                  # the request that must be refused is aimed at t1+M+15 s (U27's aim)
EARLY_MARGIN_S = 60            # before t0+M-60 s the session must answer (U27's margin)
REFUSE_FROM_S = 10             # from t1+M+10 s on it must not
REFUSE_UNTIL_S = 60
AFTER_WAIT_S = 30              # the dead cookie is sent again this long after the refusal
MIN_IDLE_S = 300               # the idle limit the setup requires, so that the cadence tells the maximum from inactivity
STARTED_RE = re.compile(r'Absolute session lifetime: (PT[0-9A-Z.]+)')


def location_path(base, location):
    if not location:
        return ''
    return urllib.parse.urlsplit(urllib.parse.urljoin(base + '/', location)).path


def ended_line(hours):
    """The Kafbat log line of a session ended by its maximum (observed with PT5M, H6)."""
    return 'Ended a session that reached its maximum lifetime of PT%dH' % hours


def started_lifetime(text):
    """The lifetime of the last Kafbat start in a container log (observed `Absolute session lifetime: PT5M (...)`), or None."""
    found = STARTED_RE.findall(text or '')
    return found[-1] if found else None


def cookie_expired(response):
    """True when the response expires the SESSION cookie (observed `SESSION=; Max-Age=0`, H7)."""
    headers = getattr(response, 'headers', None)
    values = headers.get_all('Set-Cookie') if headers is not None and hasattr(headers, 'get_all') else None
    return any(value.startswith('SESSION=') and 'max-age=0' in value.lower() for value in values or [])


def is_login_redirect(base, sample):
    return sample[1] == 302 and location_path(base, sample[2]) == LOGIN_PATH


def judge(samples, t0, t1, max_s, base):
    """Pure decision over the polled requests: samples = [(monotonic start of the request, status, Location, ...)].

    Returns ([(probe, 'PASS'|'FAIL')] for cadence_60s, early_200 and refused_M10_M60, the index of the first
    request at or after t1+M+10 s or None). Separate from the polling so tests can feed synthetic times.

    refused_M10_M60 needs three things: the first request at or after t1+M+10 s, made no later than t1+M+60 s, is a
    redirect to the sign-in; every refusal on the way (the one that ends the session included, which is usually an
    earlier request) is such a redirect and not a 403 or a 5xx; and no request is answered 200 after the first
    refusal (the session is gone, not paused)."""
    times = [sample[0] for sample in samples]
    cadence = bool(samples) and times[0] - t1 <= CADENCE_BOUND_S \
        and all(b - a <= CADENCE_BOUND_S for a, b in zip(times, times[1:]))
    early = all(sample[1] == 200 for sample in samples if sample[0] - t0 < max_s - EARLY_MARGIN_S)
    first = next((i for i, sample in enumerate(samples) if sample[0] - t1 >= max_s + REFUSE_FROM_S), None)
    refused = False
    if first is not None:
        refusals = [i for i, sample in enumerate(samples) if sample[1] != 200]
        refused = (bool(refusals) and is_login_redirect(base, samples[first])
                   and samples[first][0] - t1 <= max_s + REFUSE_UNTIL_S
                   and all(is_login_redirect(base, samples[i]) for i in refusals)
                   and all(samples[i][1] != 200 for i in range(refusals[0], len(samples))))
    return [('cadence_60s', 'PASS' if cadence else 'FAIL'),
            ('early_200', 'PASS' if early else 'FAIL'),
            ('refused_M10_M60', 'PASS' if refused else 'FAIL')], first


def judge_log(hours, before, after, recreated, problem):
    """(status, text) of ended_logged from the count of the ending line before the sign-in and after the refusal.

    recreated: the kafka-ui container is not the one that was running at the start (a recreation ends every
    session without that line); problem: why a log could not be read (then the probe is NOT_RUN)."""
    if recreated:
        return 'FAIL', 'kafka-ui was recreated during the walk: a refusal that is not shown to be the maximum\'s'
    if problem:
        return 'NOT_RUN', 'the kafka-ui log could not be read: %s' % problem
    if after - before >= 1:
        return 'PASS', 'log line "%s" %d -> %d' % (ended_line(hours), before, after)
    return 'FAIL', 'log line "%s" not added (%d -> %d): the refusal is not shown to be the maximum\'s' % (
        ended_line(hours), before, after)


class LedgerUser(p2.User):
    """A p2.User whose sign-in codes come from the helper's per-user TOTP ledger (phase4_common.TotpSteps).

    p2.Gate.keycloak_login asks `user.code()`; here it is Phase4Gate.next_totp, so a step the user already
    submitted is waited out through the ledger and every other step is used at once."""

    def __init__(self, gate, name, password, secret):
        super().__init__(name, [])
        self.gate = gate
        self.password = password
        self.secret = secret

    def code(self):
        return self.gate.next_totp(self.name, self.secret)[0]


class Gate(Phase4Gate):
    SLICE = '4a'
    CASES = CASES
    # --replay: the row reads the maximum the companion prepared and the lifetime proof only setup_prepared() takes.
    REPLAY_NEEDS_SETUP = {'K37': 'the companion\'s session maximum (--session-max-minutes) and the proof of '
                                 'setup_prepared() that runtime.yml, the realm and the running Kafbat agree on it'}

    def __init__(self, args):
        super().__init__(args)
        self.state_file = os.path.join(self.state_dir, 'p4', 'kc-%s.json' % USER)
        self.user_state[USER] = self.state_file

    # ── setup ──
    def setup(self):
        if getattr(self.args, 'prepare_only', False):
            return self.setup_user()
        if getattr(self.args, 'prepared', False):
            return self.setup_prepared()
        return ('K37 runs only in the 4a --session-max-hours companion '
                '(--prepare-only, then --prepared --only K37 --session-max-minutes N)')

    def setup_user(self):
        """--prepare-only: one viewer through the product's own commands, enrolled (TOTP and the password change)."""
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            rc, out, err = self.krate('identity', 'users', 'add', USER, '--viewer', '--email', EMAIL, timeout=180)
            if rc != 0:
                raise RuntimeError('identity users add %s failed (rc %s): %s' % (USER, rc, (err or out).strip()[-160:]))
            temp = self.temp_password(out)
            if not temp:
                raise RuntimeError('no temporary password in the users add output')
            self.add_runtime_secret(temp)
            self.enrol_user(USER, temp, self.state_file)
            log('setup: %s added and enrolled' % USER)
            return None
        except Exception as error:
            return 'K37 preparation failed: %s: %s' % (type(error).__name__, str(error)[:200])

    def setup_prepared(self):
        """--prepared: read-only proof that what K37 measures is what the fixture runs."""
        try:
            minutes = self.args.session_max_minutes
            if self.args.only != ['K37'] or not minutes or minutes % 60:
                raise RuntimeError('prepared K37 needs --only K37 and a whole number of hours as --session-max-minutes')
            hours = minutes // 60
            expected = minutes * 60
            if not os.path.isfile(self.state_file) or os.stat(self.state_file).st_mode & 0o077:
                raise RuntimeError('%s enrolment state is missing or not private' % USER)
            enrolled = self.load_state(USER)
            if enrolled.get('user') != USER or not enrolled.get('password') or not enrolled.get('totp'):
                raise RuntimeError('%s enrolment state is incomplete' % USER)
            self.add_state_file_secrets(self.state_file)
            self.note_enrolment_steps(USER)
            kc = self.master_kcadm()
            uid = kc.user_id(USER)
            if not uid:
                raise RuntimeError('%s realm user is absent' % USER)
            if self.viewer_group not in {group.get('name') for group in kc.get('users/%s/groups' % uid) or []}:
                raise RuntimeError('%s is not in the viewer group %s' % (USER, self.viewer_group))
            realm_max = (kc.get('realms/' + p2.REALM) or {}).get('ssoSessionMaxLifespan')
            if realm_max != expected:
                raise RuntimeError('Keycloak maximum %s s differs from the requested %s s' % (realm_max, expected))
            configured = self.runtime.get('auth', {}).get('oauth2', {}).get('max-session-lifetime')
            if p2.seconds(configured) != expected:
                raise RuntimeError('runtime.yml auth.oauth2.max-session-lifetime %r is not %d h' % (configured, hours))
            if not self.idle_seconds or self.idle_seconds < MIN_IDLE_S:
                raise RuntimeError('the idle limit (%s s) is too short to tell the maximum from inactivity' % self.idle_seconds)
            _cid, text, problem = self.kafbat_log()
            if problem:
                raise RuntimeError('the kafka-ui log could not be read: %s' % problem)
            logged = started_lifetime(text)
            if logged != 'PT%dH' % hours:
                raise RuntimeError('the running Kafbat last logged "Absolute session lifetime: %s", not PT%dH '
                                   '(an image without the lifetime filter?)' % (logged, hours))
            log('setup: prepared K37 viewer %s; the realm, runtime.yml and the Kafbat log agree on %d s' % (USER, expected))
            return None
        except Exception as error:
            return 'prepared K37 precondition failed: %s: %s' % (type(error).__name__, str(error)[:200])

    def load_state(self, user):
        path = self.user_state.get(user)
        if not path:
            raise RuntimeError('no enrolment state for %s (setup did not run?)' % user)
        with open(path, encoding='utf-8') as handle:
            state = json.load(handle)
        return state

    def enrolled_user(self):
        state = self.load_state(USER)
        return LedgerUser(self, state['user'], state['password'], state['totp'])

    def kafbat_log(self):
        """(container id, log text, problem) of the running kafka-ui container; problem is None when the log was read."""
        cid = p2.service_container(self.project, 'kafka-ui')
        if not cid:
            return None, '', 'no running kafka-ui container'
        rc, out, err = p2.docker('logs', cid, timeout=120)
        if rc != 0:
            return cid, '', 'docker logs rc %s: %s' % (rc, (err or out).strip()[:80])
        return cid, out + err, None

    # ── the row ──
    def plan(self):
        return [('K37', self.k37)]

    @staticmethod
    def once_more(call, what):
        """One retry of a slow round trip (the pattern of p2.Gate.session): a timeout is not a finding."""
        try:
            return call()
        except (TimeoutError, OSError) as error:
            log('K37 %s: %s; retrying once' % (what, type(error).__name__))
        return call()

    def k37(self):
        max_s = self.args.session_max_minutes * 60
        hours = max_s // 3600
        user = self.enrolled_user()
        cid0, text0, problem0 = self.kafbat_log()
        before = text0.count(ended_line(hours))
        t0 = time.monotonic()
        login = self.once_more(lambda: self.kafbat_login(user, 'k37-session'), 'sign-in')
        t1 = time.monotonic()
        if login.get('kind') != 'ok':
            return 'FAIL', 'sign-in of %s did not complete: %s %s' % (
                USER, login.get('kind'), p2.REDACT(str(login.get('detail', '')))[:120])
        browser = login['browser']
        last_cookie = [login.get('session')]
        self.add_runtime_secret(last_cookie[0])
        samples = []

        def sample():
            # The instrument of the live observation (H6): the signed-in browser, GET /api/clusters.
            started = time.monotonic()
            try:
                response = browser.api('GET', POLL_PATH, timeout=POLL_TIMEOUT_S)
            except (TimeoutError, OSError) as error:
                log('K37 request failed (%s); retrying once' % type(error).__name__)
                started = time.monotonic()
                response = browser.api('GET', POLL_PATH, timeout=POLL_TIMEOUT_S)
            samples.append((started, response.status, response.location, cookie_expired(response)))
            if response.status == 200:  # the cookie the dead-cookie check sends is the last one the live session held
                current = browser.cookie('SESSION')
                if current and current != last_cookie[0]:
                    last_cookie[0] = current
                    self.add_runtime_secret(current)
            log('K37 +%.0fs of t1 %s -> %s %s' % (started - t1, POLL_PATH, response.status, response.location[:48]))

        sample()
        target = t1 + max_s + TARGET_S
        while True:
            now = time.monotonic()
            delay = min(max(0.0, samples[-1][0] + CADENCE_S - now), max(0.0, target - now))
            if delay:
                time.sleep(delay)
            sample()
            if samples[-1][0] - t1 >= max_s + REFUSE_FROM_S:
                break
        probes, first = judge(samples, t0, t1, max_s, self.base)
        judged = samples[first] if first is not None else samples[-1]
        refusal = next((sample for sample in samples if sample[1] != 200), None)   # the request that ended the session
        cid1, text1, problem1 = self.kafbat_log()
        recreated = bool(cid0 and cid1 and cid0 != cid1)
        ended, ended_text = judge_log(hours, before, text1.count(ended_line(hours)), recreated, problem0 or problem1)
        time.sleep(AFTER_WAIT_S)
        again = self.once_more(lambda: self.probe(last_cookie[0]), 'dead-cookie request')
        stays = again.status == 302 and location_path(self.base, again.location) == LOGIN_PATH
        # A new browser: a login started with the dead jar ends once in /login?error (H10).
        second = self.once_more(lambda: self.kafbat_login(user, 'k37-after'), 'second sign-in')
        fresh = False
        if second.get('kind') == 'ok':
            self.add_runtime_secret(second.get('session'))
            fresh = self.once_more(lambda: second['browser'].api('GET', POLL_PATH, timeout=POLL_TIMEOUT_S),
                                   'first request of the new session').status == 200
        probes += [('ended_logged', ended), ('stays_refused', 'PASS' if stays else 'FAIL'),
                   ('new_login_ok', 'PASS' if fresh else 'FAIL')]
        row, tokens = aggregate(probes)
        ending = ('first refusal at M%+.0f s -> HTTP %s %s, SESSION cookie expired=%s' % (
            refusal[0] - t1 - max_s, refusal[1], location_path(self.base, refusal[2]) or '-', refusal[3])
            if refusal else 'no refusal')
        return row, ('%s; maximum %d s (the realm, runtime.yml and the Kafbat log agreed at setup); %d requests every %d s, '
                     'first %.1f s after sign-in; %s; judged request at M+%.0f s -> HTTP %s; %s; '
                     'dead cookie 30 s later -> HTTP %s; new sign-in %s'
                     % (tokens, max_s, len(samples), CADENCE_S, samples[0][0] - t1, ending, judged[0] - t1 - max_s,
                        judged[1], ended_text, again.status, 'ok' if fresh else (second.get('kind') or 'failed')))


def selftest():
    """The windows of judge() and the log probe on synthetic times (no fixture): M = 3600 s, a sign-in of 5 s."""
    base, t0, t1, m = 'https://h.test', 1000.0, 1005.0, 3600
    redirect = '/oauth2/authorization/keycloak'

    def run(schedule, location=redirect):
        return dict(judge([(t, s, location if s == 302 else '') for t, s in schedule], t0, t1, m, base)[0])

    # the real schedule: every 30 s from t1, the last request aimed at M+15 s (t1+3600 is the last regular slot)
    ok = [(t1 + k * 30, 200) for k in range(0, 121)] + [(t1 + 3615, 302)]
    assert all(v == 'PASS' for v in run(ok).values()), run(ok)
    assert run(ok[:-1] + [(t1 + 3615, 200)])['refused_M10_M60'] == 'FAIL'                  # outlives the maximum
    assert run(ok[:-1] + [(t1 + 3700, 302)])['refused_M10_M60'] == 'FAIL'                  # refusal seen too late
    assert run(ok[:-1] + [(t1 + 3615, 302)], '/login?error')['refused_M10_M60'] == 'FAIL'  # a refusal that is not the sign-in redirect
    assert run(ok[:-1] + [(t1 + 3615, 403)])['refused_M10_M60'] == 'FAIL'
    assert run(ok[:-1] + [(t1 + 3615, 500)])['refused_M10_M60'] == 'FAIL'
    ended = ok[:-2] + [(t1 + 3600, 302), (t1 + 3615, 302)]                                   # the session ends at the slot before the judged request
    assert run(ended)['refused_M10_M60'] == 'PASS'
    assert run(ok[:-2] + [(t1 + 3600, 403), (t1 + 3615, 302)])['refused_M10_M60'] == 'FAIL'   # the request that ended it was not a redirect
    assert run(ok[:-2] + [(t1 + 3600, 500), (t1 + 3615, 302)])['refused_M10_M60'] == 'FAIL'
    assert run(ok[:-3] + [(t1 + 3570, 302), (t1 + 3600, 200), (t1 + 3615, 302)])['refused_M10_M60'] == 'FAIL'   # paused, not gone
    assert run([(t1 + 0, 200), (t1 + 100, 200)] + ok[4:])['cadence_60s'] == 'FAIL'         # a gap above 60 s
    assert run([(t1 + 70, 200)] + ok[1:])['cadence_60s'] == 'FAIL'                         # first request later than 60 s
    early_dead = [(t, 302 if t - t0 > 3000 else 200) for t, _ in ok]
    assert run(early_dead)['early_200'] == 'FAIL'                                          # ended before M-60 s
    assert run([(t, 200 if t - t0 < 3550 else 302) for t, _ in ok])['early_200'] == 'PASS'  # ending inside the margin is fine
    assert dict(judge([], t0, t1, m, base)[0]) == {'cadence_60s': 'FAIL', 'early_200': 'PASS', 'refused_M10_M60': 'FAIL'}
    assert location_path(base, 'https://h.test/oauth2/authorization/keycloak') == LOGIN_PATH
    assert location_path(base, redirect) == LOGIN_PATH and location_path(base, '') == '' and location_path(base, None) == ''
    assert judge_log(1, 0, 1, False, None)[0] == 'PASS'
    assert judge_log(1, 2, 3, False, None)[0] == 'PASS'                                    # an earlier line does not count
    assert judge_log(1, 1, 1, False, None)[0] == 'FAIL'                                    # no new line: not the maximum's
    assert judge_log(1, 0, 1, True, None)[0] == 'FAIL'                                     # kafka-ui was recreated
    assert judge_log(1, 0, 0, False, 'docker logs rc 1')[0] == 'NOT_RUN'
    text = 'x\n%s (auth.oauth2.max-session-lifetime)\nINFO Absolute session lifetime: PT1H (auth.oauth2.max-session-lifetime)\n' % (
        'Absolute session lifetime: PT8H')
    assert started_lifetime(text) == 'PT1H' and started_lifetime('') is None            # the last start counts
    assert ended_line(1) == 'Ended a session that reached its maximum lifetime of PT1H'
    assert all(('  %s ' % probe) in (__doc__ or '') for probe in PROBES)                  # the docstring describes every probe
    assert '%(' not in (__doc__ or '')                                                     # argparse expands %(prog) in a help epilog
    print('selftest ok')


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv == ['--selftest']:
        selftest()
        return 0
    return helper_main(Gate, 'phase4_kafbat.py', argv, doc=__doc__)


if __name__ == '__main__':
    sys.exit(main())
