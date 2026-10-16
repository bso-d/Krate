#!/usr/bin/env python3
"""Shared scaffolding of the Phase 4 slice helpers (4a Grafana, 4b Perses).

One implementation of the pieces both slice helpers need, on top of the Phase 2
helper (scripts/gate/phase2_kafbat.py, reused per section 5 of
harness/phase4/PHASE4-INSTRUCTIONS-v3.md):

  * Phase4Gate   - p2.Gate extended with the monitoring project, the slice's
                   state directory, the runtime-secret file
                   ($STATE/phase4-secrets.txt, which the runner adds to its
                   leak set), the Perses gateway origin, the keycloak_login_flow
                   enrolment wrapper and the `stub()` marker used by every row
                   body that awaits the live walk notes (rule 11: only rows
                   seen working by hand are encoded).
  * TimedRows    - the section 5 timing-row design: long rows (V10 36 min,
                   U29 17 min, U10/U11 <= 330 s, V7/V8/V15 <= 420 s, and
                   U27/V23 in the --session-max-hours runs) run in background
                   threads started early and joined after the short rows.
  * build_parser - the `run --edition-dir ED --base-url https://H
                   --monitor-project krate-<edition>-monitoring --state DIR
                   [--only ...]` interface of section 5.
  * helper_main  - preflight -> setup (the slice preconditions, emitted as a
                   `setup` TSV line; a setup FAIL makes every row NOT_RUN) ->
                   the row plan -> TSV rows `<id>\\tPASS|FAIL|NOT_RUN\\t<evidence>`
                   on stdout, progress on stderr; exit codes of
                   phase2_kafbat.py (0 when no row FAILed, 1 otherwise, 2 on a
                   usage error).

Probe aggregation (a row passes only when every listed probe passes; the
evidence carries one `probe=STATUS` token per probe and the row takes the
worst) lives in scripts/gate/probes.py and is re-exported here.

Python 3.9 compatible; secrets travel through the environment and 0600 files,
never through argv.
"""
import argparse
import json
import os
import re
import secrets
import signal
import ssl
import sys
import threading
import time
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python3 -I does not add the script directory
import phase2_kafbat as p2  # noqa: E402
import probes  # noqa: E402  (re-exported: the row-pass rule of section 2)
from phase2_kafbat import log, evidence, Outcome, not_run, fail  # noqa: E402,F401

Terminated = p2.Terminated
aggregate = probes.aggregate
worst = probes.worst


def broker_services(id_map):
    """Compose service names that are Kafka brokers in a cluster id map:
    kafka-N in every shipped edition (epc/kraft compose), broker-N kept
    for older layouts. Name-based, never substring-'broker' (that loop
    never matched kafka-92.. and silently compared nothing)."""
    return sorted(svc for svc in (id_map or {})
                  if re.fullmatch(r'(kafka|broker)-\d+', svc))


# ─── background threads for the timing rows (section 5) ───────────────────────

class TimedRows:
    """Rows that need minutes of wall clock run in background threads.

    A row body calls gate.start_timed('<id>', func) where the plan says the
    clock starts (for example before the short rows), and gate.finish_timed
    ('<id>', timeout) joins it and records the result. func returns
    (status, text) or raises Outcome/any exception exactly like a synchronous
    row body. Threads are daemons: a terminating helper never hangs on them.
    """

    def __init__(self):
        self._rows = {}

    def start(self, row_id, func):
        if row_id in self._rows:
            raise RuntimeError('timed row %s started twice' % row_id)
        box = {}

        def target():
            try:
                box['result'] = func()
            except Outcome as outcome:
                box['result'] = (outcome.status, outcome.text)
            except p2.Terminated:
                raise
            except Exception as error:  # a harness error is reported, never hidden
                box['result'] = ('FAIL', 'harness error %s: %s' % (type(error).__name__, error))

        thread = threading.Thread(target=target, name='row-' + row_id, daemon=True)
        self._rows[row_id] = (thread, box)
        thread.start()
        log('timed row %s started in the background' % row_id)

    def started(self, row_id):
        return row_id in self._rows

    def join(self, row_id, timeout):
        thread, box = self._rows[row_id]
        thread.join(timeout)
        if thread.is_alive():
            return ('FAIL', 'row thread still running after %s s (timeout)' % timeout)
        return box.get('result') or ('FAIL', 'row thread produced no result')

    def alive(self):
        return sorted(name for name, (thread, _) in self._rows.items() if thread.is_alive())


# ─── master-admin kcadm (the walk's kc.sh pattern) ────────────────────────────

class MasterKcadm:
    """kcadm.sh in the Keycloak container as the fixture's MASTER admin.

    The Phase 2 Kcadm (krate-cli service account) cannot create realm users, set
    their passwords or write requiredActions, which the slice preconditions need
    (the walk used the master admin for exactly these: harness/phase4/live4a/
    scripts/kc.sh, logs/021). The password travels through the docker-exec
    environment (KC_CLI_PASSWORD), never through argv; a per-call `password=`
    override feeds `set-password --temporary` the new value the same way (the
    walk's kc.sh -E mode). The in-container config file is removed by close().
    """

    def __init__(self, project, admin_user, admin_password):
        self.cid = p2.service_container(project, 'keycloak')
        if not self.cid:
            raise RuntimeError('no running keycloak container in project ' + project)
        self.config = '/tmp/kcadm-gate4-%s.config' % secrets.token_hex(8)
        self.password = admin_password
        rc, _, err = self.raw('config', 'credentials', '--server', p2.KCADM_SERVER, '--realm', 'master',
                              '--user', admin_user)
        if rc != 0:
            raise RuntimeError('master kcadm login failed: ' + err.strip()[:120])

    def raw(self, *args, **kwargs):
        password = kwargs.pop('password', None) or self.password
        env = dict(os.environ, KC_CLI_PASSWORD=password)
        return p2.docker('exec', '-e', 'KC_CLI_PASSWORD', self.cid, p2.KCADM, *args,
                         '--config', self.config, env=env, timeout=120)

    def call(self, *args, **kwargs):
        rc, out, err = self.raw(*args, **kwargs)
        if rc != 0:
            raise RuntimeError('kcadm %s failed (rc %s): %s' % (args[0], rc, (err or out).strip()[:160]))
        return out

    def get(self, path, *query):
        args = ['get', path, '-r', p2.REALM]
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

    def add_group(self, uid, gid):
        self.call('update', 'users/%s/groups/%s' % (uid, gid), '-r', p2.REALM, '-s', 'realm=' + p2.REALM,
                  '-s', 'userId=' + uid, '-s', 'groupId=' + gid, '-n')

    def remove_group(self, uid, gid):
        self.call('delete', 'users/%s/groups/%s' % (uid, gid), '-r', p2.REALM)

    def close(self):
        p2.docker('exec', self.cid, 'rm', '-f', self.config)


# ─── the shared gate ──────────────────────────────────────────────────────────

class Phase4Gate(p2.Gate):
    """p2.Gate plus the Phase 4 fixture side. Subclasses set SLICE, CASES and plan().

    p2.Gate brings the redactor, the TSV recording (record/case/finish pattern),
    the pinned-TLS Browser, Kcadm (krate-cli service account) and check_url; this
    class adds the monitoring project, the runtime-secret file, the Perses gateway
    origin, the Grafana sub-path origin and the enrolment wrapper.
    """

    SLICE = ''            # '4a' or '4b', set by the subclass
    CASES = []            # the row ids this helper prints, in receipt order
    RUNNER_OWNED = []     # ids of the slice the runner records (X3/X4, Z4a/Z4b)

    def __init__(self, args):
        # The cluster project is KRATE_PROJECT in the edition .env unless given:
        # the section 5 helper interface names only --monitor-project.
        if not getattr(args, 'project', None):
            try:
                args.project = p2.read_env(
                    os.path.join(os.path.abspath(args.edition_dir), '.env')).get('KRATE_PROJECT', '')
            except OSError:
                args.project = ''
        super().__init__(args)
        self.monitor_project = args.monitor_project
        self.state_dir = os.path.abspath(args.state)
        self.secrets_path = os.path.join(self.state_dir, 'phase4-secrets.txt')
        self.monitor_env = {}
        self.perses_origin = None
        self.grafana_origin = self.base + '/grafana'
        self.timed = TimedRows()
        self.setup_result = None   # (status, text) of the `setup` line
        self.terminated = False
        self.obs = {}              # row id -> (status, evidence) observed during setup
        self._master = None

    # ── runtime secrets ──
    def open_runtime_secrets(self):
        """Open the append-only secret list with private permissions, even if reused."""
        fd = os.open(self.secrets_path,
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, 'a', encoding='utf-8')
        except BaseException:
            os.close(fd)
            raise

    def add_runtime_secret(self, value):
        """A runtime secret (JWT, cookie, token, enrolled password, TOTP seed).

        Written to $STATE/phase4-secrets.txt (0600; the runner reads the file and
        adds every line to its leak set, so Z4a/Z4b search for it) and added to
        the redactor, so it never reaches a printed line.
        """
        if not value or len(str(value)) < 6:
            return
        value = str(value)
        p2.REDACT.add(value)
        with self.open_runtime_secrets() as handle:
            handle.write(value + '\n')

    def add_state_file_secrets(self, path):
        """The password and TOTP seed a keycloak_login_flow enrolment wrote to its state file."""
        try:
            with open(path, encoding='utf-8') as handle:
                state = json.load(handle)
        except (OSError, ValueError):
            return
        for key in ('password', 'totp'):
            if state.get(key):
                self.add_runtime_secret(state[key])

    # ── monitoring side ──
    def mon_dir(self):
        edition = os.path.normpath(self.edition)
        bundled = os.path.join(edition, 'monitoring')
        if os.path.isdir(bundled):
            return bundled
        return os.path.join(os.path.dirname(edition), 'monitoring')

    def mon_env_value(self, key):
        return p2.read_env(os.path.join(self.mon_dir(), '.env')).get(key, '')

    def _wait_container_healthy(self, cid, limit=180):
        t0 = time.monotonic()
        while time.monotonic() - t0 < limit:
            rc, out, _ = p2.docker('inspect', '-f', '{{.State.Health.Status}}', cid)
            if rc == 0 and out.strip() == 'healthy':
                return time.monotonic() - t0
            time.sleep(2)
        return None

    def mon_container(self, service, all_states=True):
        flags = ['-aq'] if all_states else ['-q']
        rc, out, _ = p2.docker('ps', *flags, '--filter', 'label=com.docker.compose.project=' + self.monitor_project,
                               '--filter', 'label=com.docker.compose.service=' + service)
        ids = out.split()
        return ids[0] if rc == 0 and ids else None

    def cluster_container(self, service, all_states=True):
        flags = ['-aq'] if all_states else ['-q']
        rc, out, _ = p2.docker('ps', *flags, '--filter', 'label=com.docker.compose.project=' + self.project,
                               '--filter', 'label=com.docker.compose.service=' + service)
        ids = out.split()
        return ids[0] if rc == 0 and ids else None

    def mon_id_map(self):
        """{service: (container id, StartedAt)} of the monitoring project."""
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
                if len(parts) >= 3 and parts[0] != '<no':  # label-less: docker prints '<no value>'
                    found[parts[0]] = (parts[1], ' '.join(parts[2:]))
        return found

    def cluster_id_map(self):
        """{service: (container id, StartedAt)} of the cluster project."""
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
                if len(parts) >= 3 and parts[0] != '<no':  # label-less: docker prints '<no value>'
                    found[parts[0]] = (parts[1], ' '.join(parts[2:]))
        return found

    # ── realm users ──
    def master_kcadm(self):
        """The master-admin kcadm session (lazily opened; closed by main())."""
        if self._master is None:
            admin_user = self.env.get('KEYCLOAK_ADMIN_USER', 'admin')
            admin_password = self.env.get('KEYCLOAK_ADMIN_PASSWORD', '')
            if not admin_password:
                raise RuntimeError('KEYCLOAK_ADMIN_PASSWORD is not in the edition .env')
            self._master = MasterKcadm(self.project, admin_user, admin_password)
        return self._master

    @staticmethod
    def temp_password(output):
        """The one-time password from `krate identity users add` output (the line
        after the "Temporary password for" header; the runner's temp_password awk)."""
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if 'Temporary password for' in line and i + 1 < len(lines):
                return lines[i + 1].strip()
        return ''

    def enrol_user(self, user, temp_pw, state_file):
        """keycloak_login_flow.py enrol as a subprocess (TOTP + forced password change).

        The temporary password and the Kafbat client secret travel in the child's
        environment, never in argv; the enrolled password and TOTP seed land in
        the 0600 state file and are added to the runtime secrets here.

        A successful enrol ends on the NEXT TOTP step boundary: enrol's own
        second login consumes the current step's code (single-use) and its
        deliberate old-password refusal is the user's last failed login, so
        an immediate sign-in would replay the consumed step and, landing
        within Keycloak's 1s quick-login check of that refusal, trip the
        60s brute-force temporary disable (V9 attempt-4, proven live:
        LOGIN_ERRORs 78ms apart then user_temporarily_disabled). Waiting
        here makes every enrol -> sign-in row start on a fresh step.
        """
        env = dict(os.environ,
                   GATE_TEMP_PW=temp_pw,
                   KEYCLOAK_KAFBAT_CLIENT_SECRET=self.env.get('KEYCLOAK_KAFBAT_CLIENT_SECRET', ''))
        cmd = [sys.executable, '-I', os.path.join(HERE, 'keycloak_login_flow.py'),
               '--cafile', os.path.join(self.edition, 'certs', 'server.crt'),
               'enrol', '--base', self.base, '--user', user,
               '--password-env', 'GATE_TEMP_PW',
               '--client-secret-env', 'KEYCLOAK_KAFBAT_CLIENT_SECRET',
               '--state', state_file]
        rc, out, err = p2.run(cmd, env=env, timeout=900)
        self.add_state_file_secrets(state_file)
        if rc != 0:
            raise RuntimeError('enrol %s failed (rc %s): %s' % (user, rc, (err or out).strip()[-200:]))
        try:
            result = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise RuntimeError('enrol %s printed no JSON result' % user)
        time.sleep(30 - time.time() % 30 + 1)  # fresh single-use TOTP step (see docstring)
        return result

    # ── rows ──
    def stub(self, row_id, needs):
        """Scaffold marker for a row body that awaits the live walk notes (rule 11).

        Every U*/V* row starts here; a row is replaced by its real body only
        after the lead's hand-walk of the slice (harness/phase4/live4a|4b/) has
        shown the probes working against the real stack. `needs` names what the
        walk notes must provide for that row.
        """
        not_run('scaffold: row body awaits the live %s walk notes (harness/phase4/live%s/); needs: %s'
                % (self.SLICE, self.SLICE, needs))

    def wanted(self, case):
        return self.only is None or case in self.only

    def case(self, name, func):
        """Plan entries named `<row>@start` only start the row's background clock
        (section 5's timing design) and record nothing; the row itself is recorded
        by its plain `<row>` entry, which joins the thread."""
        row_id, sep, phase = name.partition('@')
        if sep and phase == 'start':
            if self.wanted(row_id) and row_id not in self.results:
                try:
                    func()
                except Exception as error:
                    self.record(row_id, 'FAIL', 'thread start failed: %s: %s'
                                % (type(error).__name__, error))
            return
        super().case(name, func)

    def start_timed(self, name, func):
        """Start a timing row's clock in the background (section 5's thread design)."""
        if self.wanted(name) and name not in self.results:
            self.timed.start(name, func)

    def finish_timed(self, name, timeout):
        """Join a background row and record it; timeout is the join bound in seconds."""
        if not self.wanted(name) or name in self.results:
            return
        if not self.timed.started(name):
            self.record(name, 'NOT_RUN', 'timed row was never started (a precondition did not run)')
            return
        status, text = self.timed.join(name, timeout)
        self.record(name, status, text)

    # ── preflight and setup ──
    def preflight(self):
        """File checks first (a missing edition directory reports without any Docker
        or network call), then the Phase 2 preflight (edition .env, runtime.yml,
        pinned TLS, kcadm, kafka-ui/proxy containers), then the monitoring side."""
        if not self.project:
            return ('no cluster project: KRATE_PROJECT is not in the edition .env and --project '
                    'was not given')
        problem = super().preflight()
        if problem is not None:
            return problem
        if (self.tls_mode != 'pinned fixture certificate certs/server.crt'
                or self.tls is None or not self.tls.check_hostname
                or self.tls.verify_mode != ssl.CERT_REQUIRED):
            return 'Phase 4 requires verified TLS with the pinned fixture certificate'
        mon_env_path = os.path.join(self.mon_dir(), '.env')
        if not os.path.isfile(mon_env_path):
            return 'monitoring/.env is missing: the fixture bring-up (krate monitor up) did not run'
        self.monitor_env = p2.read_env(mon_env_path)
        for key, value in self.monitor_env.items():
            if re.search(r'(_PASSWORD|_SECRET|_PASSPHRASE|_KEY|_TOKEN)$', key):
                p2.REDACT.add(value)
        # The Perses gateway keeps its own TLS port on the public host (slice 4b
        # probes it directly); Grafana lives under /grafana/ on the cluster proxy.
        perses_port = self.monitor_env.get('PERSES_PORT') or '3443'
        self.perses_origin = 'https://%s:%s' % (self.origin.hostname or '', perses_port)
        self.allowed_origins.add(self.perses_origin)
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            with self.open_runtime_secrets():
                pass
        except OSError as error:
            return 'cannot use the state directory %s: %s' % (self.state_dir, error)
        log('monitoring project %s; perses origin %s; state %s'
            % (self.monitor_project, self.perses_origin, self.state_dir))
        return None

    def setup(self) -> Optional[str]:
        """The slice preconditions of section 5, run after start_cluster() and before
        the rows; recorded as the `setup` TSV line. A FAIL makes every row NOT_RUN.
        Returns None when the preconditions ran, else the problem text."""
        return ('scaffold: the %s preconditions (seed, state hashes, realm switch) await the '
                'live walk notes' % self.SLICE)

    def plan(self):
        """[(row id, bound method)] in execution order; the subclass lists its rows.

        The section 5 timing design: start_timed() for the long rows first (V10,
        U29, U10/U11, V7/V8/V15; U27/V23 in the session-max runs), then the short
        rows, then finish_timed() for each started thread.
        """
        return []

    # ── driver ──
    def prepare_only(self):
        """Prepare a shared companion fixture before either timed worker starts."""
        try:
            try:
                problem = self.preflight()
                if problem is None:
                    problem = self.setup()
            except Exception as error:
                problem = 'preparation raised %s: %s' % (type(error).__name__, str(error)[:200])
            status = 'FAIL' if problem else 'PASS'
            print('setup\t%s\t%s' % (status, evidence(problem or 'shared fixture prepared')),
                  flush=True)
            return 0 if problem is None else 1
        finally:
            self.cleanup()
            if self.kc:
                self.kc.close()
            if self._master:
                self._master.close()

    def main(self):
        if self.args.prepare_only:
            return self.prepare_only()
        try:
            problem = self.preflight()
            if problem is not None:
                log('preflight: ' + problem)
                self.setup_result = ('NOT_RUN', 'preflight failed: ' + problem)
                for case in self.CASES:
                    self.results.setdefault(case, ('NOT_RUN', evidence('precondition: ' + problem)))
                return self.finish()
            setup_problem = self.setup()
            if setup_problem is not None:
                log('setup: ' + setup_problem)
                # Section 5: the setup line says FAIL and every row becomes NOT_RUN;
                # while the preconditions are still scaffold, the line says NOT_RUN.
                status = 'FAIL' if not setup_problem.startswith('scaffold') else 'NOT_RUN'
                self.setup_result = (status, setup_problem)
                for case in self.CASES:
                    self.results.setdefault(case, ('NOT_RUN', evidence('setup: ' + setup_problem)))
                return self.finish()
            self.setup_result = ('PASS', 'preconditions ran')
            try:
                for name, func in self.plan():
                    self.case(name, func)
            except Terminated:
                # SIGTERM reached the helper: the rows gathered so far are still printed.
                self.terminated = True
                log('terminated: stopping after the current row')
        finally:
            for name in self.timed.alive():
                log('timed row %s still running at exit; joined with a 5 s bound' % name)
                self.timed.join(name, 5)
            self.cleanup()
            if self.kc:
                self.kc.close()
            if self._master:
                self._master.close()
        return self.finish()

    def cleanup(self):
        """Teardown backstop for what the rows created (realm users, datasources,
        projects). Scaffold: each row body registers its own cleanup when it is
        encoded from the walk notes."""

    def finish(self):
        if self.setup_result is not None:
            print('setup\t%s\t%s' % (self.setup_result[0], evidence(self.setup_result[1])), flush=True)
        first = True
        for case in self.CASES:
            if case not in self.results:
                reason = ('not selected (--only)' if not self.wanted(case)
                          else ('not reached (terminated)' if self.terminated else 'not reached'))
                self.results[case] = ('NOT_RUN', reason)
            status, text = self.results[case]
            if first and self.tls_mode:
                # The TLS mode of the whole run is part of the evidence, not only of the log.
                text = 'TLS %s; %s' % (self.tls_mode, text)
                first = False
            print('%s\t%s\t%s' % (case, status, evidence(text)), flush=True)
        return 1 if any(status == 'FAIL' for status, _ in self.results.values()) else 0


# ─── the section 5 command-line interface ─────────────────────────────────────

def only_list(value):
    return [item.strip().upper() for item in value.split(',') if item.strip()]


def build_parser(prog, doc, extra=None):
    """The section 5 `run ...` interface; extra(run_parser) may add slice options."""
    parser = argparse.ArgumentParser(
        prog=prog, formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(doc or '').split('\n\n')[0], epilog='\n\n'.join((doc or '').split('\n\n')[1:]))
    sub = parser.add_subparsers(dest='cmd', required=True)
    run = sub.add_parser('run', help='run the slice rows against a live fixture')
    run.add_argument('--edition-dir', required=True, help='kraft or epc directory containing .env and krate')
    run.add_argument('--base-url', required=True, help='public origin, e.g. https://krate-gate.test')
    run.add_argument('--monitor-project', required=True,
                     help='monitoring Compose project (krate-<edition>-monitoring)')
    run.add_argument('--state', required=True, help="the gate's state directory (secrets, hashes, cookie jars)")
    run.add_argument('--project', default='',
                     help='cluster Compose project (default: KRATE_PROJECT from the edition .env)')
    run.add_argument('--only', type=only_list, help='comma-separated row ids, e.g. U1,U2 (others print NOT_RUN)')
    run.add_argument('--prepare-only', action='store_true',
                     help='prepare the shared companion fixture without running rows')
    run.add_argument('--prepared', action='store_true',
                     help='run selected timed rows against an already prepared fixture')
    run.add_argument('--session-max-minutes', type=int,
                     help='expected live Keycloak session maximum for prepared timed rows')
    if extra is not None:
        extra(run)
    return parser


def check_run_args(parser, args, cases):
    if not re.match(r'^https://[^/]+$', args.base_url.rstrip('/')):
        parser.error('--base-url must be an https origin without a path')
    if args.only and any(case not in cases for case in args.only):
        parser.error('--only accepts ' + ', '.join(cases))
    if args.prepare_only and (args.prepared or args.only or args.session_max_minutes is not None):
        parser.error('--prepare-only cannot be combined with --prepared, --only or --session-max-minutes')
    if args.prepared and (not args.only or args.session_max_minutes is None):
        parser.error('--prepared requires --only and --session-max-minutes')
    if args.session_max_minutes is not None and args.session_max_minutes < 1:
        parser.error('--session-max-minutes must be positive')
    return args


def helper_main(gate_cls, prog, argv=None, doc=None, extra=None):
    """argparse -> SIGTERM handler -> Gate.main(), with the phase2_kafbat exit codes."""
    doc = doc or gate_cls.__doc__ or getattr(gate_cls, 'HELP', '')
    parser = build_parser(prog, doc, extra)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    check_run_args(parser, args, gate_cls.CASES)
    signal.signal(signal.SIGTERM, p2._on_sigterm)
    started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    log('%s run %s slice %s base %s monitor project %s' % (prog, started, gate_cls.SLICE,
                                                           args.base_url, args.monitor_project))
    mapping = p2.netmap.mapped() if hasattr(p2, 'netmap') else None
    if mapping:
        log('name mapping: %s -> %s (getaddrinfo only; TLS keeps the real name)' % mapping)
    return gate_cls(args).main()
