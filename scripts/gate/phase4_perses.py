#!/usr/bin/env python3
"""Phase 4b acceptance gate: Perses on the Krate realm (scaffold; rows await the live walk).

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

STATUS: SCAFFOLD, NOT RUN. Per owner rule 11 every row body is encoded only
after the lead's live hand-walk (harness/phase4/live4b/) has shown its probes
working against the real stack; until then each row returns NOT_RUN naming what
the walk notes must provide. The frame reuses phase2_kafbat.Gate/Kcadm/Browser,
keycloak_login_flow.py (enrol), phase3_broker.Gate.brokered_login (V19),
probes.py (the row-pass rule: one `probe=PASS|FAIL|NOT_RUN` token per probe,
the row takes the worst) and phase4_common.TimedRows for the timing rows.

Timing design (section 5), to be wired by the row bodies: start V10 (36 min:
20 active + 16 idle) and V7/V8/V15 (<= 420 s each) as background threads before
the short rows; in the session-max runs start V23 (M + 6 min) as a thread; join
with finish_timed() after the short rows. Probes reach Perses both through its
TLS gateway (https://H:PERSES_PORT, preflight adds it to the allowed origins)
and, for the guard-bypass rows (V6), from a container on the perses network.
Secrets (JWTs, cookies, refresh tokens, secrets read from monitoring/.env) go
to $STATE/phase4-secrets.txt through add_runtime_secret(); the runner adds that
file to its leak set.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python3 -I does not add the script directory
from phase4_common import Phase4Gate, helper_main, fail  # noqa: E402

CASES = ['V%d' % i for i in range(1, 25)]
RUNNER_OWNED = ('X4', 'Z4b')


class Gate(Phase4Gate):
    SLICE = '4b'
    CASES = CASES
    RUNNER_OWNED = RUNNER_OWNED

    def gateway(self, path='/'):
        """An absolute URL on the Perses TLS gateway (the slice's browser-facing origin)."""
        return (self.perses_origin or '') + path

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

    # ── rows (section 2.2 of PHASE4-INSTRUCTIONS-v3.md) ──
    # Every body below is a scaffold stub; `needs` records what the live4b walk
    # notes must show before the row is encoded (rule 11).

    def v1(self):
        return self.stub('V1', 'monitor up refusals for PERSES_IDP=krate with '
                               'PERSES_AUTH_MODE=gateway and =local ("requires '
                               'PERSES_AUTH_MODE=native") before any container change '
                               '(ids and StartedAt equal)')

    def v2(self):
        return self.stub('V2', 'the rendered Perses config (enable_auth: true), the 401s from '
                               'a container on the perses network (GET/POST /api/v1/projects, '
                               'POST /proxy/unsaved/...), the refused native login of the '
                               'former PERSES_ADMIN_USER (gateway and perses:8080) and the '
                               'absent jwtPayload cookie')

    def v3(self):
        return self.stub('V3', 'sign-ins of viewer/admin/both users: /krate/role and the Perses '
                               'permission sets (read on the seven viewer kinds; admin *)')

    def v4(self):
        return self.stub('V4', 'the no-group user refused at /oauth2/callback with no Perses '
                               'cookie set (page and cookie observations)')

    def v5(self):
        return self.stub('V5', 'the Viewer write probes through the gateway (project, '
                               'dashboard create/update/delete, datasource, secrets, users, '
                               'global roles, unsaved relay -> 403) and the read controls '
                               '(saved Prometheus and VictoriaLogs queries -> 200); first '
                               'item after V6 in the live walk')

    def v6(self):
        return self.stub('V6', 'the guard-bypass probes: the Viewer\'s own Perses cookies '
                               'directly at perses:8080 from a container on the perses '
                               'network (writes 403 from Perses itself, reads 200) and the '
                               'Admin create/delete control (200/204)')

    def v7(self):
        return self.stub('V7', 'the admin-group removal walk: role viewer, viewer permissions '
                               'and the admin binding gone within 420 s; timed row (thread)')

    def v8(self):
        return self.stub('V8', 'identity users disable + logout: refused within 420 s, grants '
                               'revoked, next sign-in "Account is disabled"; timed row (thread)')

    def v9(self):
        return self.stub('V9', 'the UI logout (GET /api/auth/logout) hop chain '
                               '(/oauth2/sign_out -> Keycloak logout with id_token_hint -> / '
                               '-> /oauth2/start -> login form), Perses cookies cleared, the '
                               'oauth2-proxy session gone, Keycloak sessions 1 -> 0, no '
                               'confirmation page (lab7 log 082 selectors: account menu, '
                               'Logout anchor)')

    def v10(self):
        return self.stub('V10', 'the 36-minute walk at realm defaults with '
                                'PERSES_GROUP_PROOF_MINUTES unset (derived proof 5): one '
                                'request per minute for 20 min (200, same role, no prompt), '
                                'then 16 min silence -> 302 /oauth2/start + password form; '
                                'timed row (background thread)')

    def v11(self):
        return self.stub('V11', 'identity users add <u> --viewer --email <a> and the first '
                                'Perses sign-in through TOTP enrolment and password change '
                                '(first item of the live4b walk)')

    def v12(self):
        return self.stub('V12', 'users add without --email refused while a realm UI is on, and '
                                'the emailVerified=false user\'s HTTP 500 "isn\'t verified" at '
                                '/oauth2/callback')

    def v13(self):
        return self.stub('V13', 'two realm users with equal e-mail local parts: the second '
                                'refused (403), the first unaffected')

    def v14(self):
        return self.stub('V14', 'seeded Perses users from another issuer + '
                                'PERSES_ISSUER_APPLIED: monitor up 0, perses-migrate report '
                                '(2 users removed), the cookie-secret digest change, '
                                'perses-sync healthy, realm sign-in (needs seeded state; '
                                'recorded limit: no live PingFederate)')

    def v15(self):
        return self.stub('V15', 'Keycloak stopped mid-session: 200 until the next refresh then '
                                'refused (bound 420 s = proof window + 2 min), guard API 403 '
                                '("service token request returned 500"), RestartCount '
                                'unchanged, sign-in again within 60 s of healthy; timed row '
                                '(thread)')

    def v16(self):
        return self.stub('V16', 'monitor up with Keycloak stopped: (a) started within idp-wait\'s '
                                '120 s -> consumers up within 15 s of healthy, exit 0; (b) '
                                'longer -> non-zero exit naming idp-wait, created-not-started, '
                                '0 restarts, started by the next monitor up')

    def v17(self):
        return self.stub('V17', 'the state-hash method for projects, dashboards, folders, '
                                'datasources and variables (canonical JSON without '
                                'timestamps/version) across switch, rollback (local admin '
                                'login works) and return to realm mode, and the '
                                'Perses-only recreation list')

    def v18(self):
        return self.stub('V18', 'gen-cert + monitor up: oauth2-proxy and perses recreated, '
                                'idp-wait passes, sign-in works')

    def v19(self):
        return self.stub('V19', 'the brokered sign-in of a stand-in user (ping-viewer) through '
                                'phase3_broker.Gate.brokered_login (broker_gate()) landing in '
                                'Perses as viewer: the runner owns the stand-in (start_cluster '
                                '--broker: stub_idp.sh up, auth configure with its site.json, '
                                'auth apply) and passes --stub-dir/--stub-port/--stub-script; '
                                'the walk notes must show the brokered Perses sign-in on the '
                                'current candidate, and the row\'s evidence must record that '
                                'V19 exercises commit 0 (trustEmail=true: the brokered user '
                                'arrives e-mail-verified and signs in)')

    def v20(self):
        return self.stub('V20', 'the across-slice container id/StartedAt ledger (brokers, '
                                'kafka-ui, keycloak, keycloak-db, cluster proxy unchanged)')

    def v21(self):
        return self.stub('V21', 'monitor up refusals for KEYCLOAK_PUBLIC_URL hosts localhost, '
                                '127.0.0.1 and [::1] with PERSES_IDP=krate + native, before '
                                'any container change')

    def v22(self):
        return self.stub('V22', 'the static reads: rendered oauth2-proxy.cfg cookie_expire 8h '
                                'and cookie_refresh 5m (proof derived max(1, 15//3)), equal to '
                                'KEYCLOAK_SESSION_MAX_HOURS, and realm ssoSessionMaxLifespan '
                                '28800 (default run only)')

    def v23(self):
        return self.stub('V23', 'the session-max walk at M = 60*N min (N from '
                                'KEYCLOAK_SESSION_MAX_HOURS): 60 s polling of '
                                '/api/v1/projects, 200 before M-1 min, by M+6 min API 401 and '
                                'page / 302 to /oauth2/start with the password form behind it; '
                                'runs only with --session-max-hours; timed row (thread)')

    def v24(self):
        return self.stub('V24', 'the outage restart walk: Keycloak stopped, docker restart of '
                                'oauth2-proxy and perses (RestartCount growth recorded, '
                                'gateway 500/403, nobody let in), both up without a krate '
                                'command and a Viewer signed in within 90 s of Keycloak '
                                'healthy; VM addition: systemctl restart docker as the last '
                                'row of the slice')

    def plan(self):
        return [('V%d' % i, getattr(self, 'v%d' % i)) for i in range(1, 25)]


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
