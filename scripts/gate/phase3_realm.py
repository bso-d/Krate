#!/usr/bin/env python3
"""Phase 3 gate helper: the realm's brokering state as Keycloak holds it, compared with the plan.

Reads realm `krate` through kcadm.sh inside the fixture's Keycloak container as the
master admin (user from --admin-user, password from the KC_CLI_PASSWORD environment
variable, never argv) and prints one JSON line: browserFlow, the pingfederate
provider (config without clientSecret), its mappers, every non-built-in flow as an
execution tree (providerId or sub-flow alias, requirement, priority, authenticator
config) and the required actions. With --expect PLAN it compares that state with
auth/keycloak/pingfederate-idp.json (provider, mappers, flows, browserFlow) and exits
1 on a difference, listing each one on stderr; with --expect-absent it requires the
provider and every `krate …` flow to be gone and browserFlow to be `browser`.
--required-action ALIAS=true|false adds a defaultAction check. --shape PLAN checks only
the plan file's shape (owner decisions D2 and D3: the flows, their requirements and
priorities, the redirector config, the secret placeholder, two FORCE mappers) and
needs no Keycloak. Both compare only the keys named above: a top-level key the plan may
carry in addition (for example "truststore") is ignored. Used by scripts/gate-identity.sh
(rows P1, P3, P14, P15).
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.parse

REALM = 'krate'
KCADM = '/opt/keycloak/bin/kcadm.sh'
KCADM_SERVER = 'http://localhost:8080/identity'
PROVIDER = 'pingfederate'
PLAN_FLOW_PREFIX = 'krate '


def docker(*args, env=None, timeout=120):
    try:
        proc = subprocess.run(['docker'] + list(args), env=env, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, '', 'timeout after %ss' % timeout
    except OSError as error:
        return 127, '', str(error)


class Kcadm:
    """kcadm.sh in the Keycloak container, logged in as the master admin (password via the environment)."""

    def __init__(self, project, user, password):
        rc, out, _ = docker('ps', '-q', '--filter', 'label=com.docker.compose.project=' + project,
                            '--filter', 'label=com.docker.compose.service=keycloak')
        ids = out.split()
        if rc != 0 or not ids:
            raise RuntimeError('no running keycloak container in project ' + project)
        self.cid = ids[0]
        self.config = '/tmp/kcadm-gate3-%s.config' % os.urandom(4).hex()
        env = dict(os.environ, KC_CLI_PASSWORD=password)
        rc, _, err = docker('exec', '-e', 'KC_CLI_PASSWORD', self.cid, KCADM, 'config', 'credentials', '--server',
                            KCADM_SERVER, '--realm', 'master', '--user', user, '--config', self.config, env=env)
        if rc != 0:
            raise RuntimeError('kcadm login as the master admin failed: ' + err.strip()[-120:])

    def get(self, path, *query):
        args = ['get', path, '-r', REALM]
        for item in query:
            args += ['-q', item]
        rc, out, err = docker('exec', self.cid, KCADM, *args, '--config', self.config)
        if rc != 0:
            raise RuntimeError('kcadm get %s failed (rc %s): %s' % (path, rc, (err or out).strip()[-160:]))
        return json.loads(out) if out.strip() else None

    def close(self):
        docker('exec', self.cid, 'rm', '-f', self.config)


def flow_tree(executions):
    """kcadm's flat execution list (level/index) as nested items: level n+1 entries belong to the preceding sub-flow."""
    root = []
    stack = [root]
    for execution in executions:
        level = execution.get('level', 0)
        while len(stack) > level + 1:
            stack.pop()
        while len(stack) < level + 1:  # a gap in levels (never seen; keeps the tree well-formed)
            stack.append(stack[-1][-1]['children'] if stack[-1] else root)
        item = {'requirement': execution.get('requirement'), 'priority': execution.get('priority'),
                'children': [], 'config': execution.get('authenticationConfig')}
        if execution.get('authenticationFlow') or execution.get('flowId'):
            item['flow'] = execution.get('displayName')
        else:
            item['provider'] = execution.get('providerId')
        stack[-1].append(item)
        stack.append(item['children'])
    return root


def strip(items):
    out = []
    for item in items:
        copy = {k: v for k, v in item.items() if k != 'children' and v is not None}
        if item['children']:
            copy['children'] = strip(item['children'])
        out.append(copy)
    return out


def live_state(kc):
    state = {'browserFlow': None, 'provider': None, 'mappers': {}, 'flows': {}, 'requiredActions': {}, 'configs': {}}
    realm = kc.get('realms/' + REALM) or {}
    state['browserFlow'] = realm.get('browserFlow')
    for provider in kc.get('identity-provider/instances') or []:
        if provider.get('alias') == PROVIDER:
            config = {k: v for k, v in (provider.get('config') or {}).items() if k != 'clientSecret'}
            state['provider'] = {k: provider.get(k) for k in ('alias', 'providerId', 'enabled', 'firstBrokerLoginFlowAlias',
                                                               'trustEmail', 'storeToken')}
            state['provider']['config'] = config
            for mapper in kc.get('identity-provider/instances/%s/mappers' % PROVIDER) or []:
                state['mappers'][mapper.get('name')] = {'identityProviderMapper': mapper.get('identityProviderMapper'),
                                                        'config': mapper.get('config') or {}}
    for flow in kc.get('authentication/flows') or []:
        if flow.get('builtIn'):
            continue
        alias = flow.get('alias')
        executions = kc.get('authentication/flows/%s/executions' % urllib.parse.quote(alias, safe='')) or []
        state['flows'][alias] = strip(flow_tree(executions))
        for execution in executions:
            cid = execution.get('authenticationConfig')
            if cid and cid not in state['configs']:
                config = kc.get('authentication/config/' + cid) or {}
                state['configs'][cid] = {'alias': config.get('alias'), 'config': config.get('config') or {}}
    for action in kc.get('authentication/required-actions') or []:
        state['requiredActions'][action.get('alias')] = {'enabled': action.get('enabled'),
                                                         'defaultAction': action.get('defaultAction')}
    return state


# ─── plan comparison ─────────────────────────────────────────────────────────

def plan_executions(flow):
    """The plan flow's executions sorted by priority (file order when priorities are absent)."""
    executions = list(flow.get('authenticationExecutions') or [])
    if all('priority' in e for e in executions):
        executions.sort(key=lambda e: e['priority'])
    return executions


def compare_flow(state, plan, plan_flows, alias, live_items, diffs, path):
    flow = plan_flows.get(alias)
    if flow is None:
        diffs.append('%s: sub-flow %r is not defined in the plan' % (path, alias))
        return
    wanted = plan_executions(flow)
    if len(wanted) != len(live_items):
        diffs.append('%s: %d executions planned, %d live' % (path, len(wanted), len(live_items)))
    for position, (planned, live) in enumerate(zip(wanted, live_items)):
        where = '%s[%d]' % (path, position)
        sub = planned.get('flowAlias') if (planned.get('authenticatorFlow') or planned.get('autheticatorFlow')
                                           or planned.get('flowAlias')) else None
        if sub:
            if live.get('flow') != sub:
                diffs.append('%s: planned sub-flow %r, live %s' % (where, sub, live.get('flow') or live.get('provider')))
            else:
                compare_flow(state, plan, plan_flows, sub, live.get('children', []), diffs, where + '/' + sub)
        elif planned.get('authenticator') != live.get('provider'):
            diffs.append('%s: planned authenticator %r, live %r' % (where, planned.get('authenticator'),
                                                                    live.get('provider') or live.get('flow')))
        if planned.get('requirement') != live.get('requirement'):
            diffs.append('%s: requirement planned %s, live %s' % (where, planned.get('requirement'), live.get('requirement')))
        if 'priority' in planned and planned['priority'] != live.get('priority'):
            diffs.append('%s: priority planned %s, live %s' % (where, planned['priority'], live.get('priority')))
        if planned.get('authenticatorConfig'):
            configs = {c.get('alias'): c.get('config') or {} for c in plan.get('authenticatorConfig') or []}
            wanted_config = configs.get(planned['authenticatorConfig'])
            live_config = state['configs'].get(live.get('config') or '', {}).get('config')
            if wanted_config is None:
                diffs.append('%s: authenticator config %r is not in the plan' % (where, planned['authenticatorConfig']))
            elif live_config != wanted_config:
                diffs.append('%s: authenticator config planned %s, live %s' % (where, wanted_config, live_config))
        elif live.get('config'):
            diffs.append('%s: live execution carries an authenticator config the plan does not' % where)


def compare(state, plan):
    diffs = []
    if state['browserFlow'] != plan.get('browserFlow'):
        diffs.append('browserFlow: planned %r, live %r' % (plan.get('browserFlow'), state['browserFlow']))
    providers = [p for p in plan.get('identityProviders') or [] if p.get('alias') == PROVIDER]
    if not providers:
        diffs.append('plan has no %s provider' % PROVIDER)
    elif state['provider'] is None:
        diffs.append('provider %s is not in the realm' % PROVIDER)
    else:
        planned = providers[0]
        for key in ('providerId', 'enabled', 'firstBrokerLoginFlowAlias', 'trustEmail', 'storeToken'):
            if key in planned and planned[key] != state['provider'].get(key):
                diffs.append('provider.%s: planned %r, live %r' % (key, planned[key], state['provider'].get(key)))
        for key, value in (planned.get('config') or {}).items():
            if key == 'clientSecret':
                continue
            if str(value) != str(state['provider']['config'].get(key)):
                diffs.append('provider.config.%s: planned %r, live %r' % (key, value, state['provider']['config'].get(key)))
        planned_mappers = {m.get('name'): m for m in plan.get('identityProviderMappers') or []}
        if set(planned_mappers) != set(state['mappers']):
            diffs.append('mappers: planned %s, live %s' % (sorted(planned_mappers), sorted(state['mappers'])))
        for name, mapper in planned_mappers.items():
            live = state['mappers'].get(name)
            if not live:
                continue
            if mapper.get('identityProviderMapper') != live['identityProviderMapper']:
                diffs.append('mapper %r: type planned %r, live %r' % (name, mapper.get('identityProviderMapper'),
                                                                     live['identityProviderMapper']))
            for key, value in (mapper.get('config') or {}).items():
                got = live['config'].get(key)
                if key == 'claims':
                    try:
                        same = json.loads(value) == json.loads(got or 'null')
                    except ValueError:
                        same = False
                else:
                    same = str(value) == str(got)
                if not same:
                    diffs.append('mapper %r config.%s: planned %r, live %r' % (name, key, value, got))
    plan_flows = {f.get('alias'): f for f in plan.get('authenticationFlows') or []}
    for alias, flow in plan_flows.items():
        if not flow.get('topLevel', True):
            continue
        if alias not in state['flows']:
            diffs.append('flow %r is not in the realm' % alias)
            continue
        compare_flow(state, plan, plan_flows, alias, state['flows'][alias], diffs, alias)
    return diffs


def compare_absent(state):
    diffs = []
    if state['provider'] is not None:
        diffs.append('provider %s still exists' % PROVIDER)
    if state['browserFlow'] != 'browser':
        diffs.append('browserFlow is %r, not browser' % state['browserFlow'])
    left = sorted(alias for alias in state['flows'] if alias.startswith(PLAN_FLOW_PREFIX))
    if left:
        diffs.append('flows still present: %s' % left)
    return diffs


# ─── plan shape (D2/D3), checked without Keycloak ────────────────────────────

SHAPE = {  # flow alias → (topLevel, [(authenticator | ('flow', alias), requirement, priority, config alias)])
    'krate browser': (True, [('auth-cookie', 'ALTERNATIVE', 10, None),
                             ('identity-provider-redirector', 'ALTERNATIVE', 20, 'PingFederate redirect'),
                             (('flow', 'krate forms'), 'ALTERNATIVE', 30, None)]),
    'krate forms': (False, [('auth-username-password-form', 'REQUIRED', 10, None),
                            (('flow', 'krate otp'), 'CONDITIONAL', 20, None)]),
    'krate otp': (False, [('conditional-user-configured', 'REQUIRED', None, None),
                          ('auth-otp-form', 'REQUIRED', None, None)]),
    'krate first broker login': (True, [('idp-create-user-if-unique', 'REQUIRED', None, None)]),
}


def compare_shape(plan):
    """The plan's static shape: owner decisions D2 (first-broker-login) and D3 (browser flow), placeholder, mappers."""
    diffs = []
    providers = plan.get('identityProviders') or []
    if len(providers) != 1 or providers[0].get('alias') != PROVIDER or providers[0].get('providerId') != 'oidc':
        diffs.append('identityProviders must be exactly the oidc provider %s' % PROVIDER)
    else:
        provider = providers[0]
        if provider.get('firstBrokerLoginFlowAlias') != 'krate first broker login':
            diffs.append('provider.firstBrokerLoginFlowAlias is %r' % provider.get('firstBrokerLoginFlowAlias'))
        config = provider.get('config') or {}
        if config.get('clientSecret') != '${PING_KEYCLOAK_CLIENT_SECRET}':
            diffs.append('provider.config.clientSecret is not the ${PING_KEYCLOAK_CLIENT_SECRET} placeholder')
        if config.get('syncMode') != 'FORCE':
            diffs.append('provider.config.syncMode is %r, not FORCE' % config.get('syncMode'))
    mappers = plan.get('identityProviderMappers') or []
    if len(mappers) != 2 or any(m.get('identityProviderMapper') != 'oidc-advanced-group-idp-mapper'
                                or (m.get('config') or {}).get('syncMode') != 'FORCE' for m in mappers):
        diffs.append('two oidc-advanced-group-idp-mapper mappers with syncMode FORCE are required')
    if plan.get('browserFlow') != 'krate browser':
        diffs.append('browserFlow is %r' % plan.get('browserFlow'))
    configs = {c.get('alias'): c.get('config') or {} for c in plan.get('authenticatorConfig') or []}
    if configs.get('PingFederate redirect', {}).get('defaultProvider') != PROVIDER:
        diffs.append('authenticatorConfig "PingFederate redirect" must set defaultProvider %s' % PROVIDER)
    flows = {f.get('alias'): f for f in plan.get('authenticationFlows') or []}
    for alias, (top, wanted) in SHAPE.items():
        flow = flows.get(alias)
        if flow is None:
            diffs.append('flow %r is missing' % alias)
            continue
        if bool(flow.get('topLevel', True)) != top:
            diffs.append('flow %r topLevel should be %s' % (alias, top))
        executions = plan_executions(flow)
        if len(executions) != len(wanted):
            diffs.append('flow %r: %d executions, %d expected' % (alias, len(executions), len(wanted)))
        for position, (planned, (what, requirement, priority, config)) in enumerate(zip(executions, wanted)):
            where = '%s[%d]' % (alias, position)
            if isinstance(what, tuple):
                if not (planned.get('authenticatorFlow') or planned.get('autheticatorFlow')) or planned.get('flowAlias') != what[1]:
                    diffs.append('%s: expected sub-flow %r' % (where, what[1]))
            elif planned.get('authenticator') != what:
                diffs.append('%s: expected authenticator %r, got %r' % (where, what, planned.get('authenticator')))
            if planned.get('requirement') != requirement:
                diffs.append('%s: requirement %r, expected %s' % (where, planned.get('requirement'), requirement))
            if priority is not None and planned.get('priority') != priority:
                diffs.append('%s: priority %r, expected %s' % (where, planned.get('priority'), priority))
            if config and planned.get('authenticatorConfig') != config:
                diffs.append('%s: authenticatorConfig %r, expected %r' % (where, planned.get('authenticatorConfig'), config))
    return diffs


def main(argv=None):
    parser = argparse.ArgumentParser(prog='phase3_realm.py', description=(__doc__ or '').split('\n\n')[0])
    parser.add_argument('--project', help='Compose project name of the fixture (not needed with --shape alone)')
    parser.add_argument('--admin-user', help='master admin user name (password: KC_CLI_PASSWORD)')
    parser.add_argument('--shape', metavar='PLAN', help='check the plan file\'s D2/D3 shape only (no Keycloak access)')
    parser.add_argument('--expect', metavar='PLAN', help='auth/keycloak/pingfederate-idp.json to compare with')
    parser.add_argument('--expect-absent', action='store_true', help='require the provider and flows to be gone')
    parser.add_argument('--required-action', action='append', default=[], metavar='ALIAS=true|false',
                        help='required defaultAction of a required action')
    args = parser.parse_args(argv)
    if args.expect and args.expect_absent:
        parser.error('--expect and --expect-absent exclude each other')
    if args.shape:
        try:
            with open(args.shape, encoding='utf-8') as handle:
                plan = json.load(handle)
        except (OSError, ValueError) as error:
            print('phase3_realm: cannot read %s: %s' % (args.shape, error), file=sys.stderr)
            return 1
        diffs = compare_shape(plan)
        for diff in diffs:
            print('phase3_realm: ' + diff, file=sys.stderr)
        print(json.dumps({'shape': 'ok' if not diffs else 'differs', 'flows': sorted(f.get('alias') for f in plan.get('authenticationFlows') or [])}))
        return 1 if diffs else 0
    password = os.environ.get('KC_CLI_PASSWORD', '')
    if not password or not args.project or not args.admin_user:
        parser.error('--project, --admin-user and KC_CLI_PASSWORD in the environment are required')
    try:
        kc = Kcadm(args.project, args.admin_user, password)
    except RuntimeError as error:
        print('phase3_realm: %s' % error, file=sys.stderr)
        return 2
    try:
        state = live_state(kc)
    except (RuntimeError, ValueError) as error:
        print('phase3_realm: %s' % error, file=sys.stderr)
        kc.close()
        return 2
    kc.close()
    diffs = []
    if args.expect:
        with open(args.expect, encoding='utf-8') as handle:
            plan = json.load(handle)
        diffs += compare(state, plan)
    if args.expect_absent:
        diffs += compare_absent(state)
    for item in args.required_action:
        alias, _, wanted = item.partition('=')
        live = state['requiredActions'].get(alias)
        if live is None:
            diffs.append('required action %s is not in the realm' % alias)
        elif live.get('defaultAction') is not (wanted.lower() == 'true'):
            diffs.append('required action %s defaultAction is %s, not %s' % (alias, live.get('defaultAction'), wanted))
    print(json.dumps(state, sort_keys=True))
    for diff in diffs:
        print('phase3_realm: ' + diff, file=sys.stderr)
    return 1 if diffs else 0


if __name__ == '__main__':
    sys.exit(main())
