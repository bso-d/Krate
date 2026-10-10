#!/usr/bin/env python3
"""Static checks for the Krate identity foundation (templates, realm plan, Compose, CLI parity)."""
import contextlib
import importlib.util
from typing import Callable
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sso'))
import identity  # noqa: E402  # pyright: ignore[reportMissingImports]  # sso/ is put on sys.path above

EDITIONS = ('kraft', 'epc')
TEMPLATE_VALUES = {
    'KEYCLOAK_PUBLIC_URL': 'https://localhost/identity',
    'KEYCLOAK_ADMIN_USER': 'admin',
    'KEYCLOAK_ENABLED': 'false',
    'KEYCLOAK_VIEWER_GROUP': 'KRATE_VIEWERS',
    'KEYCLOAK_ADMIN_GROUP': 'KRATE_ADMINS',
    'KEYCLOAK_ACCESS_TOKEN_MINUTES': '5',
    'KEYCLOAK_SESSION_IDLE_MINUTES': '15',
    'KEYCLOAK_SESSION_MAX_HOURS': '8',
    'KAFKA_UI_AUTH_CONFIG': 'local.yml',
    'KRATE_IDENTITY_SUBNET': '172.29.250.0/24',
    'KRATE_IDENTITY_PROXY_IP': '172.29.250.10',
    'KRATE_IDENTITY_IP_RANGE': '172.29.250.128/25',
    'KRATE_UI_AUTH_SHA': '',
    'KRATE_PROXY_CONF_SHA': '',
    'KRATE_PROXY_PUBLIC_HOST': '',
    'KRATE_TRUSTSTORE_SHA': '',
}
# The identity network as both editions must render it from the template defaults.
IDENTITY_SUBNET = '172.29.250.0/24'
IDENTITY_PROXY_IP = '172.29.250.10'
# Monitoring services that answer without a login: bound to the loopback interface by default.
LOOPBACK_SERVICES = {'prometheus': 9090, 'loki': 3100}
LOGROTATE_FILE = 'sso/logrotate/krate-identity.conf'
LOGROTATE_DIRECTIVES = ('monthly', 'rotate 12', 'maxage 400', 'copytruncate', 'missingok', 'notifempty',
                        'compress', 'delaycompress')
TEMPLATE_SECRETS = ('KAFKA_UI_PASSWORD', 'KEYCLOAK_ADMIN_PASSWORD', 'KEYCLOAK_DB_PASSWORD',
                    'KEYCLOAK_KAFBAT_CLIENT_SECRET', 'PING_KEYCLOAK_CLIENT_SECRET', 'KEYCLOAK_CLI_CLIENT_SECRET')
# Values that must never appear in any output; chosen so a leak is unambiguous.
SYNTHETIC = {
    'KAFKA_UI_USER': 'admin',
    'KAFKA_UI_PASSWORD': 'synthetic-ui-password-0f3a9c1d7e',
    'KEYCLOAK_PUBLIC_URL': 'https://kafka.example.test/identity',
    'KEYCLOAK_ADMIN_USER': 'admin',
    'KEYCLOAK_ADMIN_PASSWORD': 'synthetic-admin-secret-6b2e8d4a1c',
    'KEYCLOAK_DB_PASSWORD': 'synthetic-db-secret-9c7d5e3f2b',
    'KEYCLOAK_KAFBAT_CLIENT_SECRET': 'synthetic-kafbat-secret-4a8b6c2d0e',
    'KEYCLOAK_CLI_CLIENT_SECRET': 'synthetic-cli-secret-1d9e7f5a3b',
    'PING_KEYCLOAK_CLIENT_SECRET': 'REPLACE_ME',
    'KEYCLOAK_ENABLED': 'false',
    'KEYCLOAK_VIEWER_GROUP': 'VIEWERS_X',
    'KEYCLOAK_ADMIN_GROUP': 'ADMINS_X',
    'KEYCLOAK_ACCESS_TOKEN_MINUTES': '7',
    'KEYCLOAK_SESSION_IDLE_MINUTES': '11',
    'KEYCLOAK_SESSION_MAX_HOURS': '3',
    'KAFKA_UI_AUTH_CONFIG': 'local.yml',
}
SYNTHETIC_SECRETS = tuple(value for key, value in SYNTHETIC.items()
                          if identity.SECRET_KEY.search(key) and value not in identity.PLACEHOLDERS)
# A runtime.yml site also needs the PingFederate secret; it must never leak either.
RUNTIME_SITE = {'KAFKA_UI_AUTH_CONFIG': 'runtime.yml', 'PING_KEYCLOAK_CLIENT_SECRET': 'synthetic-ping-secret-2e4f6a8c0b'}
ALL_SECRETS = SYNTHETIC_SECRETS + (RUNTIME_SITE['PING_KEYCLOAK_CLIENT_SECRET'],)
PUBLIC_HOST = 'kafka.example.test'
# .env values preflight must refuse in both Keycloak-backed modes (the key must be named in the refusal).
REFUSED_NAMES = (('KEYCLOAK_ADMIN_USER', 'temp-admin'), ('KEYCLOAK_ADMIN_USER', 'temp-admin-1a2b3c4d'),
                 ('KEYCLOAK_ADMIN_USER', 'Admin'), ('KEYCLOAK_VIEWER_GROUP', 'bad group'))
EXPECTED_EVENTS = {'eventsEnabled': True, 'eventsListeners': ['jboss-logging'], 'enabledEventTypes': [],
                   'eventsExpiration': 2592000, 'adminEventsEnabled': True, 'adminEventsDetailsEnabled': False}
IDP_PLAN_KEYS = {'identityProviders', 'identityProviderMappers', 'authenticatorConfig', 'authenticationFlows', 'browserFlow', 'truststore'}
UI_ATTRIBUTE_KEYS = {'pkce.code.challenge.method', 'post.logout.redirect.uris', 'backchannel.logout.url',
                     'backchannel.logout.session.required', 'backchannel.logout.revoke.offline.tokens'}
# Kafbat RBAC resources a viewer may only `view`; topics add analysis_view (and messages_read on opt-in); ksql never.
VIEW_RESOURCES = ('applicationconfig', 'clusterconfig', 'topic', 'consumer', 'schema', 'connect', 'connector', 'acl', 'audit', 'client_quotas')
# The viewer never sees applicationconfig: its view renders the running configuration, client secret included.
VIEWER_RESOURCES = tuple(resource for resource in VIEW_RESOURCES if resource != 'applicationconfig')
CLUSTERS = ['cluster-a', 'cluster-b.2']
# Site keys configure-dual.py no longer reads (they moved to .env): the example must not carry them.
MOVED_SITE_KEYS = ('viewer_messages', 'session_idle_minutes')

# kraft/epc parity: every hunk between the two CLIs must be one of the known edition differences.
FORBIDDEN_IN_HUNK = re.compile(r'identity|keycloak|kcadm', re.IGNORECASE)
ALLOWED_LINES = [re.compile(pattern) for pattern in (
    r'^KRATE_VARIANT=',
    r'^BROKER_CONTAINER=',
    r'^\s*local services=\(',
    r'^BOOTSTRAP=',
    r'^# Internal listener',
    r'^\s*# \d\. ',
    r'^\s*ensure_data_dirs$',
    r'^\s*info "Checking broker data directories',
    r'^\s*echo ""$',
    r'^\s*$',
    r'docker-install|docker-offline|docker-(debs|rpms)|INCLUDE_DOCKER|rebuild_hint|This bundle was not packaged|Then transfer the rebuilt',
    r'^\s*local rpms=',
    r'printf "  %-30s %s\\n" "(disk|auth \{configure FILE\|apply\}|docker-install)"',
    r'^\s*echo "  kafka-92 ',
    r'^\s*disk\)\s+cmd_disk ;;',
)]
ALLOWED_BLOCKS = [re.compile(pattern, re.MULTILINE) for pattern in (
    r'^(fmt_kb|cmd_disk|note_auto_create|ensure_data_dirs|docker_install_rpm|docker_install_deb)\(\) \{',
    r'# ── RHEL family',
    r'info "Package conflicts"',  # the doctor's RHEL package-conflict check (EPC only)
    r'docker_install_(rpm|deb) ',
    r'systemctl (enable|start) docker',
)]


class Checks:
    def __init__(self):
        self.errors = []

    def expect(self, condition, message):
        if not condition:
            self.errors.append(message)
        return bool(condition)


def check_templates(checks):
    for edition in EDITIONS:
        path = ROOT / edition / '.env.template'
        text = path.read_text()
        env = identity.read_env(path)
        label = f'{edition}/.env.template'
        checks.expect('changeme' not in text.lower(), f'{label}: must not mention changeme (placeholders are empty or REPLACE_ME)')
        for key, expected in TEMPLATE_VALUES.items():
            checks.expect(env.get(key) == expected, f'{label}: {key} must be {expected!r}; got {env.get(key)!r}')
        for key in TEMPLATE_SECRETS:
            checks.expect(key in env, f'{label}: missing {key}')
        for key, value in env.items():
            if identity.SECRET_KEY.search(key):
                checks.expect(value in identity.PLACEHOLDERS, f'{label}: {key} must ship as a placeholder (empty or REPLACE_ME)')


def check_realm_contract(checks):
    realm = identity.realm(identity.settings(SYNTHETIC))
    text = identity.render(realm)
    e = checks.expect
    for key, expected in (('realm', 'krate'), ('enabled', True), ('registrationAllowed', False),
                          ('resetPasswordAllowed', False), ('rememberMe', False), ('verifyEmail', False),
                          ('bruteForceProtected', True), ('failureFactor', 5), ('permanentLockout', False),
                          ('waitIncrementSeconds', 60), ('maxFailureWaitSeconds', 900),
                          ('accessTokenLifespan', 7 * 60), ('ssoSessionIdleTimeout', 11 * 60),
                          ('ssoSessionMaxLifespan', 3 * 3600), ('otpPolicyType', 'totp'),
                          ('otpPolicyAlgorithm', 'HmacSHA1'), ('otpPolicyDigits', 6), ('otpPolicyPeriod', 30),
                          ('otpPolicyLookAheadWindow', 1),
                          ('browserFlow', 'browser'), *EXPECTED_EVENTS.items()):
        e(realm.get(key) == expected, f'realm plan: {key} must be {expected!r}; got {realm.get(key)!r}')
    for key in ('offlineSessionIdleTimeout', 'identityProviders', 'identityProviderMappers',
                'authenticationFlows', 'authenticatorConfig', 'defaultRoles', 'defaultRole'):
        e(key not in realm, f'realm plan: {key} must not be set in local mode')
    actions = {action['alias']: action for action in realm.get('requiredActions', [])}
    totp = actions.get('CONFIGURE_TOTP', {})
    # Phase 3, D1: the realm has no default required action (a default would also apply to brokered
    # users); the local user gets CONFIGURE_TOTP and UPDATE_PASSWORD from `identity users add`.
    e(totp.get('enabled') is True and totp.get('defaultAction') is False,
      'realm plan: CONFIGURE_TOTP must be enabled and not a default action (D1: SSO users get no Keycloak TOTP)')
    e(actions.get('UPDATE_PASSWORD', {}).get('enabled') is True and actions['UPDATE_PASSWORD'].get('defaultAction') is False,
      'realm plan: UPDATE_PASSWORD must be enabled and not a default action')
    e(all(action.get('defaultAction') is False for action in actions.values()), 'realm plan: no required action may be a realm default')
    e(identity.USER_REQUIRED_ACTIONS == ['CONFIGURE_TOTP', 'UPDATE_PASSWORD'] and set(identity.USER_REQUIRED_ACTIONS) == set(actions),
      'identity.USER_REQUIRED_ACTIONS must be exactly the planned required actions CONFIGURE_TOTP and UPDATE_PASSWORD')
    e([group.get('name') for group in realm.get('groups', [])] == ['VIEWERS_X', 'ADMINS_X'],
      'realm plan: groups must be [KEYCLOAK_VIEWER_GROUP, KEYCLOAK_ADMIN_GROUP]')
    clients = {client['clientId']: client for client in realm.get('clients', [])}
    e(set(clients) == {'krate-cli', 'krate-ui'}, f'realm plan: clients must be krate-cli and krate-ui; got {sorted(clients)}')
    cli = clients.get('krate-cli', {})
    for key, expected in (('publicClient', False), ('serviceAccountsEnabled', True), ('standardFlowEnabled', False),
                          ('directAccessGrantsEnabled', False), ('secret', '${KEYCLOAK_CLI_CLIENT_SECRET}')):
        e(cli.get(key) == expected, f'realm plan: krate-cli {key} must be {expected!r}')
    ui = clients.get('krate-ui', {})
    origin = 'https://kafka.example.test'
    for key, expected in (('publicClient', False), ('serviceAccountsEnabled', False), ('standardFlowEnabled', True),
                          ('directAccessGrantsEnabled', False), ('secret', '${KEYCLOAK_KAFBAT_CLIENT_SECRET}'),
                          ('redirectUris', [origin + '/login/oauth2/code/keycloak']), ('webOrigins', [origin])):
        e(ui.get(key) == expected, f'realm plan: krate-ui {key} must be {expected!r}')
    attributes = ui.get('attributes', {})
    e(attributes.get('pkce.code.challenge.method') == 'S256', 'realm plan: krate-ui must require PKCE S256')
    e(attributes.get('post.logout.redirect.uris') == origin + '##' + origin + '/',
      'realm plan: krate-ui post-logout redirect must be the exact values <origin>##<origin>/ (no wildcard)')
    e(attributes.get('backchannel.logout.url') == 'http://kafka-ui:8080/logout/connect/back-channel/keycloak',
      'realm plan: krate-ui must register OIDC back-channel logout at http://kafka-ui:8080/logout/connect/back-channel/keycloak')
    e(attributes.get('backchannel.logout.session.required') == 'true', 'realm plan: krate-ui backchannel.logout.session.required must be "true"')
    e(attributes.get('backchannel.logout.revoke.offline.tokens') == 'false', 'realm plan: krate-ui backchannel.logout.revoke.offline.tokens must be "false"')
    e(set(attributes) == UI_ATTRIBUTE_KEYS, f'realm plan: krate-ui attributes must be exactly {sorted(UI_ATTRIBUTE_KEYS)}; got {sorted(attributes)}')
    e(attributes == identity.ui_client_attributes(origin), 'realm plan: krate-ui attributes must come from identity.ui_client_attributes')
    e(ui.get('frontchannelLogout') is False, 'realm plan: krate-ui must state frontchannelLogout false (back-channel only)')
    mappers = [mapper for mapper in ui.get('protocolMappers', []) if mapper.get('protocolMapper') == 'oidc-group-membership-mapper']
    config = mappers[0].get('config', {}) if mappers else {}
    e(config.get('claim.name') == 'groups' and config.get('full.path') == 'false'
      and all(config.get(flag) == 'true' for flag in ('id.token.claim', 'access.token.claim', 'userinfo.token.claim')),
      'realm plan: krate-ui needs a group membership mapper to claim "groups" (full.path false; id/access/userinfo true)')
    for name, client in clients.items():
        scopes = client.get('optionalClientScopes', ['offline_access']) + client.get('defaultClientScopes', [])
        e('offline_access' not in scopes and 'optionalClientScopes' in client,
          f'realm plan: {name} must list optionalClientScopes without offline_access')
    users = realm.get('users', [])
    account = users[0] if len(users) == 1 else {}
    e(account.get('username') == 'service-account-krate-cli' and account.get('serviceAccountClientId') == 'krate-cli'
      and account.get('enabled') is True
      and sorted(account.get('clientRoles', {}).get('realm-management', [])) == sorted(identity.CLI_ROLES),
      'realm plan: the only user must be the krate-cli service account with realm-management manage/view/query roles')
    placeholders = set(re.findall(r'\$\{[A-Z0-9_]+\}', text))
    e(placeholders == {'${KEYCLOAK_CLI_CLIENT_SECRET}', '${KEYCLOAK_KAFBAT_CLIENT_SECRET}'},
      f'realm plan: placeholders must be exactly the two client secrets; got {sorted(placeholders)}')
    e(not any(secret in text for secret in SYNTHETIC_SECRETS), 'realm plan: a configured secret value leaked into the plan')



def check_runtime_contract(checks):
    """Kafbat's runtime.yml plan: Keycloak client only, no shared form login, group-mapped roles, viewer without payloads."""
    e = lambda cond, msg: checks.expect(cond, 'runtime plan: ' + msg)  # noqa: E731
    origin = 'https://kafka.example.test'
    values = identity.runtime_settings(SYNTHETIC, CLUSTERS)
    data = identity.runtime(values)
    text = identity.render(data)
    e(values['viewer_messages'] is False, 'viewer_messages must default to False when KAFKA_UI_VIEWER_MESSAGES is absent')
    e(set(data) == {'http', 'server', 'auth', 'rbac'}, f'top-level keys must be http, server, auth, rbac; got {sorted(data)}')
    e(data['http'] == {'error': {'excludeStackTraces': True}}, 'Kafbat error bodies must not carry stack traces (http.error.excludeStackTraces)')
    oauth = data['auth']['oauth2']
    e(data['auth']['type'] == 'OAUTH2', 'auth.type must be OAUTH2')
    for key in ('allow-shared-login', 'shared-role'):
        e(key not in oauth and key not in text, f'{key} must not appear anywhere (no shared form login in Keycloak mode)')
    e(oauth.get('require-mapped-role') is True, 'require-mapped-role must be true')
    e(set(oauth['client']) == {'keycloak'}, f'exactly one client registration named keycloak; got {sorted(oauth["client"])}')
    client = oauth['client']['keycloak']
    realm_url = origin + '/identity/realms/krate'
    internal = 'http://keycloak:8080/identity/realms/krate/protocol/openid-connect/'
    for key, expected in (('provider', 'keycloak'), ('client-id', 'krate-ui'), ('client-secret', '${KEYCLOAK_KAFBAT_CLIENT_SECRET}'),
                          ('scope', ['openid', 'profile', 'email']), ('issuer-uri', realm_url),
                          ('redirect-uri', origin + '/login/oauth2/code/keycloak'), ('authorization-grant-type', 'authorization_code'),
                          ('user-name-attribute', 'sub'),
                          ('custom-params', {'type': 'oauth', 'roles-field': 'groups',
                                             'end-session-uri': realm_url + '/protocol/openid-connect/logout'}),
                          ('authorization-uri', realm_url + '/protocol/openid-connect/auth'), ('token-uri', internal + 'token'),
                          ('user-info-uri', internal + 'userinfo'), ('jwk-set-uri', internal + 'certs')):
        e(client.get(key) == expected, f'client {key} must be {expected!r}; got {client.get(key)!r}')
    session = data['server']['reactive']['session']
    e(session.get('timeout') == '11m', f'session timeout must be KEYCLOAK_SESSION_IDLE_MINUTES (11m); got {session.get("timeout")!r}')
    e(session.get('cookie') == {'name': 'SESSION', 'secure': True, 'http-only': True, 'same-site': 'lax'},
      f'session cookie must be SESSION, secure, http-only, same-site lax; got {session.get("cookie")!r}')
    e('spring' not in data and 'configtree' not in text, 'no spring.config.import (the secret comes from the container environment)')
    rbac = data['rbac']
    e('defaultRole' not in rbac and set(rbac) == {'roles'}, 'rbac must define roles only (no defaultRole)')
    roles = {role['name']: role for role in rbac['roles']}
    e(set(roles) == {'viewer', 'administrator'}, f'roles must be viewer and administrator; got {sorted(roles)}')
    for name, group in (('viewer', 'VIEWERS_X'), ('administrator', 'ADMINS_X')):
        role = roles.get(name, {})
        e(role.get('clusters') == CLUSTERS, f'{name} clusters must be the given list; got {role.get("clusters")!r}')
        e(role.get('subjects') == [{'provider': 'oauth', 'type': 'role', 'value': group, 'regex': False}],
          f'{name} must have the realm group {group} as its only subject; got {role.get("subjects")!r}')
    viewer = {p['resource']: p for p in roles.get('viewer', {}).get('permissions', [])}
    e(set(viewer) == set(VIEWER_RESOURCES), f'viewer resources must be {sorted(VIEWER_RESOURCES)} (no ksql, no applicationconfig); got {sorted(viewer)}')
    for resource, permission in viewer.items():
        expected = ['view', 'analysis_view'] if resource == 'topic' else ['view']
        e(permission.get('actions') == expected, f'viewer {resource} actions must be {expected}; got {permission.get("actions")!r}')
        e((permission.get('value') == '.*') == (resource in identity.PATTERN_RESOURCES),
          f'viewer {resource} value must be ".*" exactly for the pattern resources')
    admin = {p['resource']: p for p in roles.get('administrator', {}).get('permissions', [])}
    e(set(admin) == set(VIEW_RESOURCES) | {'ksql'}, f'administrator must get every resource plus ksql; got {sorted(admin)}')
    e(all(p.get('actions') == 'all' for p in admin.values()), 'administrator actions must be "all" on every resource')
    e(not any(secret in text for secret in SYNTHETIC_SECRETS), 'a configured secret value leaked into the plan')
    e(set(re.findall(r'\$\{[A-Z0-9_]+\}', text)) == {'${KEYCLOAK_KAFBAT_CLIENT_SECRET}'}, 'the only placeholder is the Kafbat client secret')
    # Opt-in: only the viewer's topic permission changes, and only by messages_read.
    opted = identity.runtime(identity.runtime_settings(dict(SYNTHETIC, KAFKA_UI_VIEWER_MESSAGES='true'), CLUSTERS))
    opted_viewer = {p['resource']: p for p in opted['rbac']['roles'][0]['permissions']}
    e(opted_viewer['topic']['actions'] == ['view', 'analysis_view', 'messages_read'],
      f'opted-in viewer topic actions must add messages_read only; got {opted_viewer["topic"]["actions"]!r}')
    opted_viewer['topic'] = viewer['topic']
    e(opted_viewer == viewer and opted['rbac']['roles'][1] == roles['administrator'] and opted['auth'] == data['auth'],
      'KAFKA_UI_VIEWER_MESSAGES must change nothing but the viewer topic actions')
    for value in ('yes', '1', 'TRUE ', 'on'):
        try:
            identity.runtime_settings(dict(SYNTHETIC, KAFKA_UI_VIEWER_MESSAGES=value), CLUSTERS)
            flagged = value.strip().lower() == 'true'
        except ValueError:
            flagged = False
        e(flagged == (value.strip().lower() == 'true'), f'KAFKA_UI_VIEWER_MESSAGES={value!r} must be refused unless it is true/false')
    e(identity.runtime_settings(dict(SYNTHETIC, KAFKA_UI_VIEWER_MESSAGES=''), CLUSTERS)['viewer_messages'] is False,
      'an empty KAFKA_UI_VIEWER_MESSAGES means off')
    for bad in ([], ['a', 'a'], ['*'], ['bad name'], ['a/b'], [''], ['x', 3]):
        try:
            identity.cluster_names(bad)
            e(False, f'clusters {bad!r} must be refused')
        except ValueError:
            pass
    e(identity.cluster_names(['cluster-1-kraft', 'epc_02.x']) == ['cluster-1-kraft', 'epc_02.x'], 'plain cluster names are accepted in order')
    settings_origin = identity.runtime_settings(SYNTHETIC, CLUSTERS, origin='https://other.example.test')
    e(settings_origin['public_origin'] == 'https://other.example.test', 'an explicit origin overrides KEYCLOAK_PUBLIC_URL')
    e(identity.runtime(settings_origin)['auth']['oauth2']['client']['keycloak']['issuer-uri'] == 'https://other.example.test/identity/realms/krate',
      'the issuer follows the explicit origin')
    check_runtime_writer(checks)


def check_runtime_writer(checks):
    """identity.py runtime: writes 0644, identical rerun is a no-op, a differing file needs --force."""
    e = lambda cond, msg: checks.expect(cond, 'identity.py runtime: ' + msg)  # noqa: E731
    with tempfile.TemporaryDirectory() as tmp:
        site = Path(tmp)
        write_env(site, dict(SYNTHETIC))
        output = site / 'auth/ui/runtime.yml'

        def run(*clusters, force=False):
            command = [sys.executable, '-I', str(ROOT / 'sso/identity.py'), 'runtime', '--env-file', str(site / '.env'),
                       '--clusters', *clusters, '--output', str(output)] + (['--force'] if force else [])
            return subprocess.run(command, text=True, capture_output=True)

        first = run(*CLUSTERS)
        e(first.returncode == 0 and 'written' in first.stdout, f'first run must write the plan; got exit {first.returncode}: {first.stderr.strip()}')
        e(output.is_file() and mode(output) == 0o644, 'runtime.yml must be created with mode 0644')
        e(json.loads(output.read_text()) == identity.runtime(identity.runtime_settings(SYNTHETIC, CLUSTERS)),
          'the written file must be the planner output')
        e(not any(secret in first.stdout + first.stderr for secret in SYNTHETIC_SECRETS), 'the summary must not leak a secret value')
        e('no shared form login' in first.stdout and 'KAFKA_UI_VIEWER_MESSAGES' in first.stdout,
          'the summary names the login model and the viewer opt-in key')
        second = run(*CLUSTERS)
        e(second.returncode == 0 and 'No changes' in second.stdout, 'an identical rerun must report No changes')
        before = output.read_bytes()
        third = run('other-cluster')
        e(third.returncode == 1 and '--force' in third.stderr and output.read_bytes() == before,
          f'a differing plan must be refused without --force and leave the file alone; got exit {third.returncode}: {third.stderr.strip()}')
        fourth = run('other-cluster', force=True)
        e(fourth.returncode == 0 and json.loads(output.read_text())['rbac']['roles'][0]['clusters'] == ['other-cluster'],
          '--force replaces the file with the new plan')
        e(sorted(os.listdir(output.parent)) == ['runtime.yml'], f'no temporary files may remain; got {sorted(os.listdir(output.parent))}')
        bad = run('*')
        e(bad.returncode == 1 and 'clusters' in bad.stderr, 'a wildcard cluster name must be refused')


def check_names(checks):
    """Group names are plain tokens; KEYCLOAK_ADMIN_USER is a permanent lower-case name, never bootstrap-style."""
    def accepts(function, key, value):
        try:
            function(dict(SYNTHETIC, **{key: value}))
        except ValueError as exc:
            checks.errors.append(f'identity.{function.__name__}: must accept {key}={value!r}: {exc}')

    def rejects(function, key, value):
        try:
            function(dict(SYNTHETIC, **{key: value}))
        except ValueError:
            return
        checks.errors.append(f'identity.{function.__name__}: must reject {key}={value!r}')

    for group in ('Team.ops-1_x', 'a', 'G' * 64):
        accepts(identity.settings, 'KEYCLOAK_VIEWER_GROUP', group)
    # An empty value means "use the default" (as for every optional identity key), so it is not listed here.
    for group in ('bad group', 'a/b', 'G' * 65, 'ops,admins', 'grüppe', '$GROUP', 'ADMINS_X'):
        rejects(identity.settings, 'KEYCLOAK_VIEWER_GROUP', group)
    for user in ('admin', 'ops.admin@example.test', 'a' * 63, '0ps_admin'):
        accepts(identity.admin_user, 'KEYCLOAK_ADMIN_USER', user)
    for user in ('temp-admin', 'temp-admin-1a2b3c4d', 'Admin', '-admin', '.admin', 'a' * 64, '', 'ad min', 'admin$'):
        rejects(identity.admin_user, 'KEYCLOAK_ADMIN_USER', user)


def compose_config(env_file, edition, project_dir=None):
    """Render the edition's Compose file; `project_dir` resolves bind-mount sources against a site directory."""
    command = ['docker', 'compose', '--env-file', str(env_file), '-f', str(ROOT / edition / 'docker-compose.yml')]
    if project_dir is not None:
        command += ['--project-directory', str(project_dir)]
    result = subprocess.run(command + ['--profile', 'sso', 'config', '--format', 'json'], cwd=ROOT, text=True, capture_output=True)
    return result.returncode, result.stdout


def check_compose(checks):
    for edition in EDITIONS:
        code, rendered = compose_config(ROOT / edition / '.env.template', edition)
        if not checks.expect(code == 0, f'{edition}: Compose rendering with --profile sso failed; run make compose-check'):
            continue
        services = json.loads(rendered)['services']
        e = checks.expect
        for name in ('keycloak', 'keycloak-db'):
            if not e(name in services, f'{edition}: service {name} missing from the sso profile'):
                continue
            e(not services[name].get('ports'), f'{edition}/{name}: must not publish host ports')
        kc = services.get('keycloak', {}).get('environment', {})
        e(kc.get('KC_DB_TLS_MODE') == 'verify-server', f'{edition}/keycloak: KC_DB_TLS_MODE must be verify-server; got {kc.get("KC_DB_TLS_MODE")!r}')
        e(bool(kc.get('KC_DB_TLS_TRUST_STORE_FILE')), f'{edition}/keycloak: KC_DB_TLS_TRUST_STORE_FILE must be set')
        e(kc.get('KC_HTTP_MANAGEMENT_RELATIVE_PATH') == '/', f'{edition}/keycloak: KC_HTTP_MANAGEMENT_RELATIVE_PATH must stay /')
        e('KEYCLOAK_CLI_CLIENT_SECRET' in kc, f'{edition}/keycloak: KEYCLOAK_CLI_CLIENT_SECRET must be passed for the realm placeholder')
        e(bool(services.get('keycloak', {}).get('healthcheck', {}).get('test')), f'{edition}/keycloak: healthcheck must be present')
        targets = {mount.get('target') for mount in services.get('keycloak', {}).get('volumes', [])}
        e(kc.get('KC_DB_TLS_TRUST_STORE_FILE') in targets, f'{edition}/keycloak: KC_DB_TLS_TRUST_STORE_FILE must be a mounted file')
        db_targets = {mount.get('target') for mount in services.get('keycloak-db', {}).get('volumes', [])}
        e('/run/krate-db-tls' in db_targets, f'{edition}/keycloak-db: must mount auth/keycloak/db-tls at /run/krate-db-tls')
        ui_dependencies = services.get('kafka-ui', {}).get('depends_on', {})
        e('keycloak' not in ui_dependencies and 'keycloak-db' not in ui_dependencies,
          f'{edition}/kafka-ui: must not depend_on keycloak services')
        check_networks(checks, edition, json.loads(rendered))


def networks_of(service):
    """Name -> attachment settings of a rendered service (Compose renders a mapping)."""
    networks = service.get('networks') or {}
    if isinstance(networks, list):
        return {name: {} for name in networks}
    return {name: (settings or {}) for name, settings in networks.items()}


def check_networks(checks, edition, config):
    """The identity network: internal, the template subnet, and exactly the members the design names."""
    e = checks.expect
    networks = config.get('networks', {})
    identity_net = networks.get('identity', {})
    e(identity_net.get('internal') is True, f'{edition}: network identity must be internal: true')
    subnets = [entry.get('subnet') for entry in identity_net.get('ipam', {}).get('config', [])]
    e(subnets == [IDENTITY_SUBNET], f'{edition}: network identity must have the one ipam subnet {IDENTITY_SUBNET}; got {subnets}')
    e('identity-egress' in networks and not networks['identity-egress'].get('internal'),
      f'{edition}: network identity-egress must exist and not be internal')
    services = config['services']
    expected = {'keycloak-db': {'identity'}, 'keycloak': {'identity', 'identity-egress'},
                'proxy': {'kafka-network', 'identity'}, 'kafka-ui': {'kafka-network', 'identity'}}
    for name, wanted in expected.items():
        attached = set(networks_of(services.get(name, {})))
        e(attached == wanted, f'{edition}/{name}: must be attached to {sorted(wanted)}; got {sorted(attached)}')
    for name, service in services.items():
        if re.fullmatch(r'kafka-\d+', name):
            e(set(networks_of(service)) == {'kafka-network'}, f'{edition}/{name}: brokers stay on kafka-network only')
    proxy_ip = networks_of(services.get('proxy', {})).get('identity', {}).get('ipv4_address')
    e(proxy_ip == IDENTITY_PROXY_IP, f'{edition}/proxy: ipv4_address on identity must be {IDENTITY_PROXY_IP}; got {proxy_ip!r}')
    trusted = services.get('keycloak', {}).get('environment', {}).get('KC_PROXY_TRUSTED_ADDRESSES')
    e(trusted == proxy_ip, f'{edition}/keycloak: KC_PROXY_TRUSTED_ADDRESSES must equal the proxy address; got {trusted!r}')
    e(proxy_ip is not None and ipaddress.ip_address(proxy_ip) in ipaddress.ip_network(IDENTITY_SUBNET),
      f'{edition}: the proxy address must lie inside {IDENTITY_SUBNET}')


def check_monitoring_binds(checks):
    """Prometheus and Loki publish on 127.0.0.1 from the template defaults; Grafana and Perses are unchanged."""
    template = ROOT / 'monitoring/.env.template'
    env = identity.read_env(template)
    for key in ('PROM_BIND', 'LOKI_BIND'):
        checks.expect(env.get(key) == '127.0.0.1', f'monitoring/.env.template: {key} must be 127.0.0.1; got {env.get(key)!r}')
    result = subprocess.run(['docker', 'compose', '--env-file', str(template), '-f', str(ROOT / 'monitoring/docker-compose.yml'),
                             'config', '--format', 'json'], cwd=ROOT, text=True, capture_output=True)
    if not checks.expect(result.returncode == 0, 'monitoring: Compose rendering from the template failed'):
        return
    services = json.loads(result.stdout)['services']
    for name, port in LOOPBACK_SERVICES.items():
        ports = services.get(name, {}).get('ports', [])
        checks.expect(len(ports) == 1 and ports[0].get('host_ip') == '127.0.0.1' and ports[0].get('published') == str(port)
                      and ports[0].get('target') == port,
                      f'monitoring/{name}: must publish only 127.0.0.1:{port}:{port} by default; got {ports}')
    for name, port in (('grafana', 3000), ('perses-gateway', 3443)):
        ports = services.get(name, {}).get('ports', [])
        checks.expect(len(ports) == 1 and not ports[0].get('host_ip') and ports[0].get('published') == str(port),
                      f'monitoring/{name}: must still publish {port} on every interface; got {ports}')


def check_logrotate(checks):
    """The logrotate drop-in ships with its placeholders and the decided directives, and is packaged."""
    e = checks.expect
    path = ROOT / LOGROTATE_FILE
    if not e(path.is_file(), f'{LOGROTATE_FILE} is missing'):
        return
    text = path.read_text()
    e(re.search(r'^__JOURNAL__ \{$', text, re.MULTILINE) is not None, f'{LOGROTATE_FILE}: the stanza must open with "__JOURNAL__ {{"')
    e('__NAME__' in text, f'{LOGROTATE_FILE}: must carry the __NAME__ placeholder')
    directives = [line.strip() for line in text.splitlines() if line.startswith('    ')]
    e(directives == list(LOGROTATE_DIRECTIVES), f'{LOGROTATE_FILE}: directives must be {list(LOGROTATE_DIRECTIVES)}; got {directives}')
    e(LOGROTATE_FILE in (ROOT / 'Makefile').read_text(), f'Makefile: the bundle must copy {LOGROTATE_FILE}')
    e(f"'{LOGROTATE_FILE}'" in (ROOT / 'scripts/check-bundle.py').read_text(), f'scripts/check-bundle.py: must require {LOGROTATE_FILE}')
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        for needle in ('identity_network_clash up', 'renew-db-tls)  cmd_identity_renew_db_tls', 'logrotate)     cmd_identity_logrotate',
                       '"$BROKER_CONTAINER" 2>/dev/null \\\n    | tr'):
            e(needle in cli, f'{edition}/krate: missing {needle.splitlines()[0]!r}')
        e('compose_cmd ps -q 2>/dev/null | head -1' not in cli,
          f'{edition}/krate: monitor_network must read the broker container, not the first container of the project')



def check_cli_kafbat(checks):
    """Both CLIs and activate.sh carry the Phase 2 Kafbat wiring: local auth configure, Keycloak-only sign-in lines, attribute reconciliation."""
    e = checks.expect
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        label = f'{edition}/krate'
        for needle, why in (
                ('args=(runtime --env-file "$ENV_FILE" --clusters "${clusters[@]}" --output "$SCRIPT_DIR/auth/ui/runtime.yml")',
                 'auth configure without a file must run identity.py runtime with the edition cluster list'),
                ('mapfile -t clusters < <(ui_clusters)', 'auth configure must take the cluster list from ui_clusters'),
                ('--env-file "$ENV_FILE" --output-dir "$SCRIPT_DIR/auth"', 'auth configure FILE must pass .env to configure-dual.py'),
                ('set_env_file_value "$ENV_FILE" KAFKA_UI_VIEWER_MESSAGES true', '--viewer-messages must record the opt-in in .env'),
                ('echo "  Sign-in   Keycloak (realm krate) — manage users with krate identity users"',
                 'ui/credentials in runtime.yml mode must show the Keycloak sign-in line'),
                ('"attributes": client["attributes"]}', 'identity_reconcile_ui_urls must compare the whole krate-ui attribute set'),
                ('--fields redirectUris,webOrigins,frontchannelLogout,"attributes($keys)"',
                 'identity_reconcile_ui_urls must fetch frontchannelLogout and every planned attribute'),
                ('if [[ -f "$SCRIPT_DIR/auth/keycloak/pingfederate-idp.json" ]]; then ensure_ping_secret; fi',
                 'auth apply must ask for the PingFederate secret only when its plan exists')):
            e(needle in cli, f'{label}: {why} (missing {needle[:60]!r})')
        ui_command = cli[cli.index('\ncmd_ui() {'):]
        runtime_branch = re.search(r'== "runtime\.yml" \]\]; then\n(.*?)\n  (?:elif|else)', ui_command, re.DOTALL)
        e(runtime_branch is not None and 'shared' not in runtime_branch.group(1).lower() and '$pass' not in runtime_branch.group(1),
          f'{label}: the runtime.yml branch of cmd_ui must not print a shared login or the shared password')
        e('Shared app login' not in cli, f'{label}: must not describe a shared app login beside Keycloak')
    activate = (ROOT / 'sso/activate.sh').read_text()
    e('Sign-in: Keycloak (realm krate)' in activate and 'no shared form login' in activate,
      'sso/activate.sh: auth apply must print the Keycloak login model after success')


def check_exposure(checks):
    """The public proxy hides Kafbat metrics, actuator and the back-channel endpoint; apply is idempotent; start refuses a clash; the fork ends the Keycloak session."""
    e = checks.expect
    for edition in EDITIONS:
        nginx = (ROOT / edition / 'nginx.conf').read_text()
        public = nginx.index('    location / {')
        for path in ('/metrics', '/actuator', '/logout/connect'):
            # The prefix must not end in a slash: `location ^~ /actuator/` leaves the base path /actuator
            # (Spring's unauthenticated endpoint discovery page) to the catch-all (GHAS on PR #39).
            block = nginx.find('    location ^~ ' + path + ' {\n        return 404;')
            e(0 <= block < public, f'{edition}/nginx.conf: {path} (no trailing slash, so the base path is covered) must return 404 before the catch-all location /')
            e('location ^~ ' + path + '/ {' not in nginx, f'{edition}/nginx.conf: {path}/ with a trailing slash would leave {path} itself reachable')
        e('X-Forwarded-Port $server_port' not in nginx, f'{edition}/nginx.conf: must not forward the container listening port as X-Forwarded-Port (the client port is in X-Forwarded-Host)')
        # nginx discards the server-level proxy_set_header directives in any location that sets its own
        # (AGENTS.md rule 13): every such location must restate the whole server-level set itself.
        server = nginx[nginx.index('    listen 443 ssl;'):]
        server_level = set(re.findall(r'^    proxy_set_header (\S+) (.+);$', server[:server.index('    location ')], re.M))
        e({'Host', 'X-Real-IP', 'X-Forwarded-For', 'X-Forwarded-Proto', 'X-Forwarded-Host'} <= {name for name, _ in server_level},
          f'{edition}/nginx.conf: the server level must set Host, X-Real-IP, X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Host')
        for block in re.findall(r'location [^{]+\{(.*?)\n    \}', nginx, re.S):
            own = set(re.findall(r'^        proxy_set_header (\S+) (.+);$', block, re.M))
            if not own:
                continue  # no own headers: the server-level set applies
            e(server_level <= own, f'{edition}/nginx.conf: a location that sets proxy_set_header must restate the server-level set;'
                                   f' missing {sorted(server_level - own)} in {block.strip()[:60]!r}')
        for header in ('Forwarded', 'X-Forwarded-Prefix', 'X-Forwarded-Ssl', 'X-Forwarded-Port'):
            e(nginx.count(f'proxy_set_header {header} "";') == nginx.count('proxy_set_header X-Forwarded-Host $http_host;') == 4,
              f'{edition}/nginx.conf: every proxied location must clear the client-supplied {header} header')
        cli = (ROOT / edition / 'krate').read_text()
        prepare = cli[cli.index('\nprepare() {'):cli.index('\n}', cli.index('\nprepare() {'))]
        e('identity_network_clash' in prepare and prepare.index('identity_network_clash') < prepare.index('generate_secrets'),
          f'{edition}/krate: prepare() must check the identity subnet clash before anything creates the network')
        e('pingfederate.yml' not in cli, f'{edition}/krate: no stale pingfederate.yml auth mode')
        e('--no-viewer-messages) viewer_messages=false ;;' in cli, f'{edition}/krate: auth configure must accept --no-viewer-messages')
        e('db-tls --rollback --output-dir' in cli and 'db-tls --discard-previous --output-dir' in cli,
          f'{edition}/krate: renew-db-tls must roll back on an unhealthy restart and discard .prev files on success')
        e('renewed CA and' in cli and 'identity_compose restart --no-deps keycloak\n' in cli,
          f'{edition}/krate: renew-db-tls must restart Keycloak when the CA was renewed')
        code, rendered = compose_config(ROOT / edition / '.env.template', edition)
        if e(code == 0, f'{edition}: Compose rendering failed'):
            config = json.loads(rendered)
            e('KRATE_UI_AUTH_SHA' in config['services']['kafka-ui']['environment'],
              f'{edition}/kafka-ui: KRATE_UI_AUTH_SHA must be part of the environment so a changed auth file recreates the container')
            e(config['networks']['identity']['ipam']['config'][0].get('ip_range') == '172.29.250.128/25',
              f'{edition}: identity network ip_range must default to 172.29.250.128/25')
    activate = (ROOT / 'sso/activate.sh').read_text()
    e('--force-recreate' not in activate, 'sso/activate.sh: apply must not force-recreate (sessions survive an unchanged apply)')
    e('KRATE_UI_AUTH_SHA' in activate, 'sso/activate.sh: apply must record the auth file digest in .env')
    patch = (ROOT / 'kafbat-ui/native-auth.patch').read_text()
    for needle, why in (('END_SESSION_URI = "end-session-uri"', 'the fork reads end_session_endpoint from the end-session-uri custom param'),
                        ('providerConfigurationMetadata(Map.of("end_session_endpoint", endSession))', 'the registration carries end_session_endpoint'),
                        ('handler.setPostLogoutRedirectUri("{baseUrl}");', 'RP-initiated logout returns to the application origin'),
                        ('handler.setLogoutUri("http://127.0.0.1:"', 'the back-channel handler posts to its own listener'),
                        ('csrfRepository.setCookieCustomizer(cookie -> cookie.secure(true));', 'the XSRF-TOKEN cookie is Secure'),
                        ('csrfRepository.saveToken(webFilterExchange.getExchange(), null)', 'the CSRF token rotates at login'),
                        ('oidcSessionRegistry.removeSessionInformation(session.getId())', 'a local logout forgets the OIDC session')):
        e(needle in patch, f'kafbat-ui/native-auth.patch: {why} (missing {needle[:50]!r})')
    # PR #39 review threads: lifecycle lock during bootstrap, temp-admin listing in the parent shell, group before user,
    # rotate --value reuse, passphrase minimum from the environment, restore reconciles the UI client.
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        lock = cli[cli.index('\nidentity_lock_if_enabled() {'):cli.index('\n}', cli.index('\nidentity_lock_if_enabled() {'))]
        e('identity_volume_present' in lock and '.identity.lock' in lock, f'{edition}/krate: lifecycle commands must lock while an identity command runs or the database volume exists, not only once KEYCLOAK_ENABLED is true')
        e('done <<< "$listing"' in cli and 'listing="$(kcadm -- get users -r master -q search=temp-admin' in cli, f'{edition}/krate: the temp-admin listing must be validated in the parent shell (no die inside a process substitution)')
        add = cli[cli.index('\n    add)\n      uid='):cli.index('identity_set_temp_password "$user" "$uid"', cli.index('\n    add)\n      uid='))]
        e(add.index('gid="$(kcadm_group_id') < add.index('kcadm -- create users'), f'{edition}/krate: users add must resolve the group before creating the user')
        e('must not reuse the value of $other' in cli, f'{edition}/krate: rotate --value must refuse a value equal to another identity/UI credential')
        e('KRATE_BACKUP_PASSPHRASE must be at least 8 characters' in cli, f'{edition}/krate: the environment passphrase gets the same minimum as the prompt')
        restore = cli[cli.index('\ncmd_identity_restore() {'):cli.index('\n}', cli.index('\ncmd_identity_restore() {'))]
        e('identity_reconcile_ui_urls restore' in restore and restore.index('identity_reconcile_ui_urls restore') < restore.index('identity_journal restore ok'),
          f'{edition}/krate: restore must reconcile the krate-ui client with this host before reporting success')
    build = (ROOT / 'kafbat-ui/build.py').read_text()
    e("IMAGE = 'krate/kafka-ui:1.5.0-sso.7'" in build, 'kafbat-ui/build.py must build sso.7 (the templates pin it)')


def check_gate_scripts(checks):
    """The gate helpers import and their pure helpers behave; --help works under python3 -I (a self-recursive helper once passed every static tool)."""
    import types
    e = lambda cond, msg: checks.expect(cond, 'gate scripts: ' + msg)  # noqa: E731
    for name in ('scripts/gate/phase2_kafbat.py', 'scripts/gate/keycloak_login_flow.py'):
        result = subprocess.run([sys.executable, '-I', str(ROOT / name), '--help'], text=True, capture_output=True)
        e(result.returncode == 0 and 'usage' in result.stdout.lower(), f'{name} --help must exit 0; got {result.returncode}: {result.stderr.strip()[:120]}')
    spec = importlib.util.spec_from_file_location('phase2_kafbat', ROOT / 'scripts/gate/phase2_kafbat.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    gate = types.SimpleNamespace(cluster='cluster-x', kc='client')
    e(module.Gate.cluster_api(gate) == '/api/clusters/cluster-x', 'Gate.cluster_api builds the cluster path without recursion')
    e(module.Gate.keycloak(gate) == 'client', 'Gate.keycloak returns the initialised client')
    for attr, value in (('cluster', None), ('kc', None)):
        try:
            getattr(module.Gate, 'cluster_api' if attr == 'cluster' else 'keycloak')(types.SimpleNamespace(**{attr: value, 'kc': 'c', 'cluster': 'c'} | {attr: value}))
            e(False, f'Gate helper must refuse a missing {attr}')
        except module.Outcome as outcome:
            e(outcome.status == 'NOT_RUN', f'a missing {attr} is NOT_RUN with a reason; got {outcome.status}')
    e(isinstance(module.Gate.__dict__['follow'], staticmethod), 'Gate.follow is static (no self)')
    e(set(module.CASES) == {f'K{i}' for i in range(1, 27)} | {'K31', 'K32'}, f'CASES are K1-K26, K31, K32; got {module.CASES}')


def check_parity(checks):
    result = subprocess.run(['diff', '-U0', str(ROOT / 'kraft/krate'), str(ROOT / 'epc/krate')], text=True, capture_output=True)
    hunks = re.split(r'^(?=@@ )', result.stdout, flags=re.MULTILINE)[1:]
    for hunk in hunks:
        header, _, body = hunk.partition('\n')
        changed = [line[1:] for line in body.splitlines() if line[:1] in '+-']
        text = '\n'.join(changed)
        allowed = (not FORBIDDEN_IN_HUNK.search(text)
                   and (all(any(pattern.search(line) for pattern in ALLOWED_LINES) for line in changed)
                        or any(pattern.search(text) for pattern in ALLOWED_BLOCKS)))
        first = next((line for line in changed if line.strip()), '')
        checks.expect(allowed, f'kraft/epc parity: unexplained hunk {header} ({first.strip()[:60]!r})')


def check_zk_frozen(checks):
    listed = subprocess.run(['git', 'ls-files', '-z', 'zk'], cwd=ROOT, text=True, capture_output=True)
    if listed.returncode == 0:
        files = [ROOT / name for name in listed.stdout.split('\0') if name]
    else:  # not a checkout (an extracted archive): scan the tree instead
        files = [path for path in sorted((ROOT / 'zk').rglob('*')) if path.is_file()]
    for path in files:
        if re.search(r'keycloak|identity', path.read_text(errors='replace'), re.IGNORECASE):
            checks.errors.append(f'zk frozen: {path.relative_to(ROOT)} mentions keycloak/identity')
    base = subprocess.run(['git', 'rev-parse', '--verify', '--quiet', 'origin/main'], cwd=ROOT, capture_output=True)
    if base.returncode:
        print('warning: zk frozen: origin/main is not available; skipped the git diff of zk/ (string scan done)',
              file=sys.stderr)
        return
    diff = subprocess.run(['git', 'diff', '--quiet', 'origin/main', '--', 'zk/'], cwd=ROOT)
    checks.expect(diff.returncode == 0, 'zk frozen: zk/ differs from origin/main')


def mode(path):
    return os.stat(path).st_mode & 0o7777


def check_writers(checks):
    source = (ROOT / 'sso/identity.py').read_text()
    checks.expect('os.O_EXCL' in source and 'os.replace(' in source, 'identity.py: writers must create an O_EXCL temporary and os.replace it')
    with tempfile.TemporaryDirectory() as tmp:
        tls = Path(tmp) / 'db-tls'
        checks.expect(identity.db_tls(tls) == list(identity.TLS_FILES), 'identity.db_tls: first run must write the full set')
        checks.expect(mode(tls) == 0o700, f'identity.db_tls: directory mode must be 0700; got {mode(tls):o}')
        for name, expected in identity.TLS_MODES.items():
            checks.expect(mode(tls / name) == expected, f'identity.db_tls: {name} mode must be {expected:o}; got {mode(tls / name):o}')
        checks.expect(sorted(os.listdir(tls)) == sorted(identity.TLS_FILES), 'identity.db_tls: temporary files must not remain')
        checks.expect(identity.db_tls(tls) == [], 'identity.db_tls: a complete set must be left unchanged')
        (tls / 'server.crt').unlink()
        try:
            identity.db_tls(tls)
            checks.errors.append('identity.db_tls: an incomplete set must raise instead of regenerating')
        except identity.IncompleteMaterial as exc:
            checks.expect('server.crt' in str(exc), 'identity.db_tls: the incomplete-set error must name the missing file')
        checks.expect(not (tls / 'server.crt').exists(), 'identity.db_tls: must never regenerate over an incomplete set')
        try:
            identity.renew_server(tls)
            checks.errors.append('identity.renew_server: an incomplete set must raise instead of issuing a certificate')
        except identity.IncompleteMaterial:
            pass
        check_renewal(checks, Path(tmp) / 'renew')
        plan = Path(tmp) / 'realm.json'
        checks.expect(identity.write_if_changed(plan, '{}\n', 0o644) is True and mode(plan) == 0o644,
                      'identity.write_if_changed: realm plan must be created with mode 0644')
        checks.expect(identity.write_if_changed(plan, '{}\n', 0o644) is False, 'identity.write_if_changed: identical content must be a no-op')
        checks.expect(not plan.with_name('.realm.json.tmp').exists(), 'identity.write_if_changed: temporary file must not remain')


def openssl(*args):
    return subprocess.run(['openssl', *args], stdin=subprocess.DEVNULL, capture_output=True, text=True)


def days_left(certificate):
    """Whole days until the certificate expires, from openssl's notAfter."""
    import datetime
    text = openssl('x509', '-in', str(certificate), '-noout', '-enddate').stdout.strip().partition('=')[2]
    expiry = datetime.datetime.strptime(text, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
    return (expiry - datetime.datetime.now(datetime.timezone.utc)).days


def check_renewal(checks, tls):
    """renew_server reissues key and certificate under the same CA (398 days) and leaves the CA and policy alone."""
    e = lambda cond, msg: checks.expect(cond, 'identity.renew_server: ' + msg)  # noqa: E731
    identity.db_tls(tls)
    before = {name: (tls / name).read_bytes() for name in identity.TLS_FILES}
    e(identity.SERVER_CERT_DAYS == 398 and identity.CA_CERT_DAYS == 1825, 'server certificates are issued for 398 days, the CA for 1825')
    e(396 <= days_left(tls / 'server.crt') <= 398, f'a fresh server.crt must be valid for 398 days; got {days_left(tls / "server.crt")}')
    e(1823 <= days_left(tls / 'ca.crt') <= 1825, f'a fresh ca.crt must be valid for 1825 days; got {days_left(tls / "ca.crt")}')
    expiry, renewed_ca = identity.renew_server(tls)
    e(bool(re.fullmatch(r'[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \d{4} GMT', expiry)), f'returns the new notAfter; got {expiry!r}')
    e(renewed_ca is False, 'a CA with 1825 days left is not renewed with the server certificate')
    e(all((tls / (name + '.prev')).read_bytes() == before[name] for name in ('server.key', 'server.crt')),
      'the replaced server.key and server.crt are kept as .prev until the caller discards them')
    e(not (tls / 'ca.key.prev').exists(), 'no ca .prev file when the CA was not renewed')
    e(identity.discard_previous(tls) == ['server.key', 'server.crt'], 'discard_previous removes exactly the two .prev files')
    after = {name: (tls / name).read_bytes() for name in identity.TLS_FILES}
    for name in ('ca.key', 'ca.crt', 'pg_hba.conf'):
        e(after[name] == before[name], f'{name} must not change')
    for name in ('server.key', 'server.crt'):
        e(after[name] != before[name], f'{name} must be reissued')
        e(mode(tls / name) == identity.TLS_MODES[name], f'{name} mode must stay {identity.TLS_MODES[name]:o}')
    e(sorted(os.listdir(tls)) == sorted(identity.TLS_FILES), f'no .new or temporary files may remain; got {sorted(os.listdir(tls))}')
    e(openssl('verify', '-CAfile', str(tls / 'ca.crt'), str(tls / 'server.crt')).returncode == 0, 'the new server.crt must chain to the same CA')
    cert_pub = openssl('x509', '-in', str(tls / 'server.crt'), '-pubkey', '-noout').stdout
    key_pub = openssl('pkey', '-in', str(tls / 'server.key'), '-pubout').stdout
    e(bool(cert_pub) and cert_pub == key_pub, 'the new certificate must match the new key')
    e('DNS:' + identity.DB_HOST in openssl('x509', '-in', str(tls / 'server.crt'), '-noout', '-ext', 'subjectAltName').stdout.replace(' ', ''),
      'the new certificate must keep SAN DNS:keycloak-db')
    e(396 <= days_left(tls / 'server.crt') <= 398, f'the renewed server.crt must be valid for 398 days; got {days_left(tls / "server.crt")}')
    e(identity.db_tls(tls) == [], 'db-tls without the flag must leave the renewed set unchanged')
    # The SAN check is exact: DNS:keycloak-db.example is not DNS:keycloak-db (PR #39 review).
    import tempfile as _tf
    with _tf.TemporaryDirectory() as tmp2:
        site = Path(tmp2) / 'kraft'
        site.mkdir(mode=0o700)
        write_env(site, site_env('kraft'))
        bad = site / 'auth/keycloak/db-tls'
        identity.db_tls(bad)
        (bad / 'bad.ext').write_text('subjectAltName=DNS:keycloak-db.example\nextendedKeyUsage=serverAuth\n')
        subprocess.run(['openssl', 'req', '-new', '-key', str(bad / 'server.key'), '-subj', '/CN=keycloak-db', '-out', str(bad / 'bad.csr')],
                       check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'x509', '-req', '-sha256', '-days', '2', '-in', str(bad / 'bad.csr'), '-CA', str(bad / 'ca.crt'), '-CAkey', str(bad / 'ca.key'),
                        '-CAcreateserial', '-extfile', str(bad / 'bad.ext'), '-out', str(bad / 'server.crt')],
                       check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in ('bad.ext', 'bad.csr'):
            (bad / name).unlink()
        code, rendered = compose_config(site / '.env', 'kraft')
        result = preflight(site, 'identity', rendered) if code == 0 else None
        e(result is not None and result.returncode == 1 and 'subjectAltName' in result.stderr,
          f'preflight must refuse a server.crt whose SAN is DNS:keycloak-db.example; got {None if result is None else (result.returncode, result.stderr.strip()[:160])}')
    # A CA that would expire before the new server certificate is renewed with it, and a renewal can be rolled back.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        short = Path(tmp) / 'db-tls'
        saved_days = identity.CA_CERT_DAYS
        identity.CA_CERT_DAYS = 100
        try:
            identity.db_tls(short)
        finally:
            identity.CA_CERT_DAYS = saved_days
        e(98 <= days_left(short / 'ca.crt') <= 100, 'fixture: a 100-day CA')
        first = {name: (short / name).read_bytes() for name in identity.TLS_FILES}
        expiry, renewed_ca = identity.renew_server(short)
        e(renewed_ca is True, 'a CA that expires before the new server certificate must be renewed with it')
        e(1823 <= days_left(short / 'ca.crt') <= 1825 and 396 <= days_left(short / 'server.crt') <= 398,
          'the renewed CA is valid for 1825 days and the server certificate for 398')
        e(openssl('verify', '-CAfile', str(short / 'ca.crt'), str(short / 'server.crt')).returncode == 0, 'the new server.crt chains to the new CA')
        e(all((short / (name + '.prev')).read_bytes() == first[name] for name in ('ca.key', 'ca.crt', 'server.key', 'server.crt')),
          'all four replaced files are kept as .prev')
        e(sorted(identity.rollback(short)) == sorted(['ca.key', 'ca.crt', 'server.key', 'server.crt']), 'rollback restores the four files')
        e({name: (short / name).read_bytes() for name in identity.TLS_FILES} == first, 'after rollback the files are byte-identical to before')
        e(sorted(os.listdir(short)) == sorted(identity.TLS_FILES), f'rollback leaves no .prev files; got {sorted(os.listdir(short))}')
        try:
            identity.rollback(short)
            e(False, 'a second rollback must be refused')
        except ValueError:
            pass
        (short / '.renew-stale').mkdir()
        (short / '.renew-stale' / 'ca.key').write_bytes(b'x')
        identity.renew_server(short)
        e(not (short / '.renew-stale').exists(), 'a stale work directory from a killed run is removed before renewing')
        identity.discard_previous(short)
        e(sorted(os.listdir(short)) == sorted(identity.TLS_FILES), 'after discard only the five files remain')
        # A renewal over a mixed set (.prev files beside a server.crt that no longer chains to ca.crt) is refused:
        # discarding .prev there would delete the only good copy (post-c4e0d41 review nit).
        good = {name: (short / name).read_bytes() for name in identity.TLS_FILES}
        with tempfile.TemporaryDirectory() as other_dir:
            other = Path(other_dir) / 'tls'
            identity.db_tls(other)
            for name in ('server.key', 'server.crt'):
                (short / (name + '.prev')).write_bytes(good[name])
                (short / name).write_bytes((other / name).read_bytes())
        try:
            identity.renew_server(short)
            e(False, 'a renewal over a mixed set (.prev present, server.crt not chaining to ca.crt) must be refused')
        except ValueError as error:
            e('.prev' in str(error) and 'Put the previous set back' in str(error), f'the refusal names the .prev files and how to put the previous set back; got {error}')
        e(sorted(identity.rollback(short)) == ['server.crt', 'server.key'], 'the rollback puts the previous server files back')
        e({name: (short / name).read_bytes() for name in identity.TLS_FILES} == good, 'after the rollback the set is the good one again')
        # A killed CA renewal leaves ca.*.prev behind; a later server-only renewal must discard them first,
        # or its rollback would put the old CA back beside a server certificate signed by the new one (PR #39 review S8).
        ca_now = {name: (short / name).read_bytes() for name in ('ca.key', 'ca.crt')}
        for name in ('ca.key', 'ca.crt'):
            (short / (name + '.prev')).write_bytes(b'stale ' + name.encode())
        server_now = {name: (short / name).read_bytes() for name in ('server.key', 'server.crt')}
        _, renewed_ca = identity.renew_server(short)
        e(renewed_ca is False, 'fixture: a 1825-day CA is not renewed')
        e(not (short / 'ca.key.prev').exists() and not (short / 'ca.crt.prev').exists(),
          'stale ca.*.prev files from a killed renewal are discarded before a server-only renewal writes its own .prev set')
        e(sorted(identity.rollback(short)) == ['server.crt', 'server.key'], 'the rollback after a server-only renewal restores the server files only')
        e({name: (short / name).read_bytes() for name in ('ca.key', 'ca.crt')} == ca_now
          and {name: (short / name).read_bytes() for name in ('server.key', 'server.crt')} == server_now,
          'the rollback leaves the current CA in place and restores the previous server pair')
    # N6: renew_server(days=...) reaches the server certificate also when the CA is renewed with it.
    with tempfile.TemporaryDirectory() as tmp:
        short = Path(tmp) / 'db-tls'
        saved_days = identity.CA_CERT_DAYS
        identity.CA_CERT_DAYS = 100
        try:
            identity.db_tls(short)
        finally:
            identity.CA_CERT_DAYS = saved_days
        _, renewed_ca = identity.renew_server(short, days=200)
        e(renewed_ca is True and 198 <= days_left(short / 'server.crt') <= 200,
          f'renew_server(days=200) with a renewed CA issues a 200-day server certificate; got CA renewed {renewed_ca},'
          f' {days_left(short / "server.crt")} days')


def site_env(edition, **overrides):
    """The .env mapping of a synthetic site: the edition template, synthetic values, then overrides."""
    env = identity.read_env(ROOT / edition / '.env.template')
    env.update(SYNTHETIC)
    env.update(overrides)
    return env


def write_env(site, env):
    identity.write_file(site / '.env', ''.join(f'{key}={value}\n' for key, value in env.items()), 0o600)


def synthetic_site(edition, directory, **overrides):
    """A complete site directory for `edition` built only from synthetic values."""
    site = Path(directory) / edition
    site.mkdir(mode=0o700)
    write_env(site, site_env(edition, **overrides))
    identity.db_tls(site / 'auth/keycloak/db-tls')
    return site


def self_signed(certs, host, san=None):
    """certs/server.crt + server.key for `host` (key 0600), as krate gen-cert would provide; `san` overrides DNS:<host>."""
    certs.mkdir(mode=0o700, exist_ok=True)
    previous = os.umask(0o077)
    try:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '2',
                        '-subj', '/CN=' + host, '-addext', 'subjectAltName=' + (san or 'DNS:' + host),
                        '-keyout', str(certs / 'server.key'), '-out', str(certs / 'server.crt')],
                       check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        os.umask(previous)


def run_plan(site):
    """Run identity.py plan as the CLI does; returns (CompletedProcess, realm file)."""
    realm_file = site / 'auth/keycloak/krate-realm.json'
    command = [sys.executable, '-I', str(ROOT / 'sso/identity.py'), 'plan',
               '--env-file', str(site / '.env'), '--output', str(realm_file)]
    return subprocess.run(command, text=True, capture_output=True), realm_file


def preflight(site, auth_mode, rendered):
    return subprocess.run([sys.executable, '-I', str(ROOT / 'sso/preflight.py'), '--directory', str(site), '--mode', auth_mode],
                          input=rendered, text=True, capture_output=True)


def check_name_refusals(checks, edition, site, env, auth_mode, rendered):
    """preflight must refuse bootstrap-style or malformed admin users and malformed group names."""
    for key, value in REFUSED_NAMES:
        write_env(site, dict(env, **{key: value}))
        result = preflight(site, auth_mode, rendered)
        checks.expect(result.returncode == 1 and key in result.stderr,
                      f'{edition}: preflight --mode {auth_mode} must refuse {key}={value!r}; got exit {result.returncode}: {result.stderr.strip()}')
    write_env(site, env)


def network_mutations(rendered):
    """(label, mutated rendered config) pairs that preflight must refuse in both Keycloak-backed modes."""
    def mutate(label, change: 'Callable[[dict], object]'):
        config = json.loads(rendered)
        change(config)
        return label, json.dumps(config)

    def set_networks(config, service, networks):
        config['services'][service]['networks'] = networks

    def set_proxy_ip(config, address):
        config['services']['proxy']['networks']['identity'] = {'ipv4_address': address}
        config['services']['keycloak']['environment']['KC_PROXY_TRUSTED_ADDRESSES'] = address

    return [
        mutate('identity network not internal', lambda c: c['networks']['identity'].pop('internal')),
        mutate('identity network without subnet', lambda c: c['networks']['identity'].pop('ipam')),
        mutate('keycloak-db also on kafka-network', lambda c: set_networks(c, 'keycloak-db', {'identity': None, 'kafka-network': None})),
        mutate('keycloak on kafka-network', lambda c: set_networks(c, 'keycloak', {'identity': None, 'kafka-network': None})),
        mutate('proxy without a fixed address', lambda c: set_networks(c, 'proxy', {'identity': None, 'kafka-network': None})),
        mutate('trusted address differs from the proxy address',
               lambda c: c['services']['keycloak']['environment'].__setitem__('KC_PROXY_TRUSTED_ADDRESSES', '172.29.250.11')),
        mutate('proxy address outside the subnet', lambda c: set_proxy_ip(c, '172.29.251.10')),
        mutate('proxy address is the network address', lambda c: set_proxy_ip(c, '172.29.250.0')),
        mutate('identity network without ip_range', lambda c: c['networks']['identity']['ipam']['config'][0].pop('ip_range')),
        mutate('proxy address inside the dynamic pool', lambda c: set_proxy_ip(c, '172.29.250.200')),
        mutate('proxy address is the gateway', lambda c: set_proxy_ip(c, '172.29.250.1')),
        mutate('kafka-ui not on the identity network', lambda c: set_networks(c, 'kafka-ui', {'kafka-network': None})),
        mutate('keycloak-db on identity-egress', lambda c: set_networks(c, 'keycloak-db', {'identity': None, 'identity-egress': None})),
        mutate('kafka-exporter-like service on the identity network',
               lambda c: c['services'].__setitem__('probe', {'image': 'x', 'networks': {'identity': None}})),
    ]


def check_network_refusals(checks, edition, site, auth_mode, rendered):
    """preflight must refuse a rendered configuration whose identity network deviates from the design."""
    for label, mutated in network_mutations(rendered):
        result = preflight(site, auth_mode, mutated)
        checks.expect(result.returncode == 1 and ('identity' in result.stderr or 'PROXY' in result.stderr),
                      f'{edition}: preflight --mode {auth_mode} must refuse: {label}; got exit {result.returncode}: {result.stderr.strip()}')


def check_renewal_warning(checks, edition, site, rendered):
    """preflight warns 30 days before the database certificate expires and refuses within a day."""
    tls = site / 'auth/keycloak/db-tls'
    identity.renew_server(tls, days=10)
    result = preflight(site, 'identity', rendered)
    checks.expect(result.returncode == 0 and 'warning' in result.stderr and 'renew-db-tls' in result.stderr
                  and 'expires within 30 days' in result.stderr,
                  f'{edition}: preflight must pass with a warning naming krate identity renew-db-tls for a certificate with 10 days left;'
                  f' got exit {result.returncode}: {result.stderr.strip()}')
    identity.renew_server(tls, days=0)
    result = preflight(site, 'identity', rendered)
    checks.expect(result.returncode == 1 and 'expires within a day' in result.stderr and 'renew-db-tls' in result.stderr,
                  f'{edition}: preflight must refuse a certificate expiring today; got exit {result.returncode}: {result.stderr.strip()}')
    identity.renew_server(tls)
    result = preflight(site, 'identity', rendered)
    checks.expect(result.returncode == 0 and 'warning' not in result.stderr,
                  f'{edition}: preflight must pass without a warning after renewal; got exit {result.returncode}: {result.stderr.strip()}')


def check_plan_and_preflight(checks):
    for edition in EDITIONS:
        with tempfile.TemporaryDirectory() as tmp:
            site = synthetic_site(edition, tmp)
            env = site_env(edition)
            first, realm_file = run_plan(site)
            second, _ = run_plan(site)
            output = first.stdout + first.stderr + second.stdout + second.stderr + realm_file.read_text()
            checks.expect(first.returncode == 0 and second.returncode == 0, f'{edition}: identity.py plan failed on a synthetic .env')
            checks.expect(not any(secret in output for secret in SYNTHETIC_SECRETS), f'{edition}: identity.py plan output leaked a secret value')
            checks.expect('No changes' in second.stdout, f'{edition}: a second identity.py plan must report No changes')
            code, rendered = compose_config(site / '.env', edition)
            if not checks.expect(code == 0, f'{edition}: Compose rendering of the synthetic site failed'):
                continue
            result = preflight(site, 'identity', rendered)
            checks.expect(result.returncode == 0 and not result.stderr.strip(),
                          f'{edition}: preflight --mode identity refused or warned on a complete synthetic site: {result.stderr.strip()}')
            checks.expect(not any(secret in result.stdout + result.stderr for secret in SYNTHETIC_SECRETS),
                          f'{edition}: preflight output leaked a secret value')
            check_name_refusals(checks, edition, site, env, 'identity', rendered)
            check_network_refusals(checks, edition, site, 'identity', rendered)
            check_renewal_warning(checks, edition, site, rendered)


def load_configure_dual():
    spec = importlib.util.spec_from_file_location('configure_dual', ROOT / 'sso/configure-dual.py')
    assert spec is not None and spec.loader is not None, 'sso/configure-dual.py missing'
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_configure_dual(checks):
    """auth configure FILE writes the same runtime.yml as the local planner plus the identity-provider plan; the realm file belongs to identity up."""
    e = checks.expect
    source = (ROOT / 'sso/configure-dual.py').read_text()
    e('"keycloak/krate-realm.json"' not in source, 'configure-dual.py: must not write keycloak/krate-realm.json (owned by krate identity up)')
    for key in ('allow-shared-login', 'shared-role'):
        e(key not in source, f'configure-dual.py: must not mention {key} (no shared form login in Keycloak mode)')
    example = json.loads((ROOT / 'sso/dual-example.json').read_text())
    for key in MOVED_SITE_KEYS:
        e(key not in example, f'sso/dual-example.json: {key} moved to .env and must not be in the example')
    module = load_configure_dual()
    result = module.configs(example, SYNTHETIC)
    e(set(result) == {'ui/runtime.yml', 'keycloak/pingfederate-idp.json'},
      f'configure-dual.configs: must return exactly ui/runtime.yml and keycloak/pingfederate-idp.json; got {sorted(result)}')
    expected = identity.runtime(identity.runtime_settings(SYNTHETIC, example['clusters'], origin=example['public_url']))
    e(result.get('ui/runtime.yml') == expected,
      'configure-dual: runtime.yml must be exactly identity.runtime() for .env, the site clusters and public_url (one generator)')
    idp = result.get('keycloak/pingfederate-idp.json', {})
    e(set(idp) == IDP_PLAN_KEYS, f'configure-dual: pingfederate-idp.json keys must be {sorted(IDP_PLAN_KEYS)}; got {sorted(idp)}')
    e([provider.get('alias') for provider in idp.get('identityProviders', [])] == ['pingfederate'],
      'configure-dual: the identity-provider plan must define exactly the pingfederate provider')
    e(idp.get('browserFlow') == 'krate browser', 'configure-dual: browserFlow must be the krate browser flow')
    mappers = {json.loads(m['config']['claims'])[0]['value']: m['config']['group'] for m in idp.get('identityProviderMappers', [])}
    e(mappers == {'KRATE_VIEWERS': '/VIEWERS_X', 'KRATE_ADMINS': '/ADMINS_X'},
      f'configure-dual: each mapper must put the site AD group into the realm group from .env; got {mappers}')
    placeholders = set(re.findall(r'\$\{[A-Z0-9_]+\}', json.dumps(idp)))
    e(placeholders == {'${PING_KEYCLOAK_CLIENT_SECRET}'},
      f'configure-dual: the identity-provider plan may only reference the PingFederate secret placeholder; got {sorted(placeholders)}')
    check_broker_plan_shape(checks, idp)
    for key in MOVED_SITE_KEYS:
        try:
            module.configs(dict(example, **{key: 5 if key == 'session_idle_minutes' else True}), SYNTHETIC)
            e(False, f'configure-dual: a site file with {key} must be refused (the value lives in .env)')
        except ValueError as exc:
            e('.env' in str(exc), f'configure-dual: the refusal of {key} must point at .env; got {exc}')


def check_broker_plan_shape(checks, idp):
    """The broker plan as the contract states it: D2 first-broker-login flow, D3 browser flow with its priorities, the mappers."""
    e = lambda cond, msg: checks.expect(cond, 'configure-dual plan: ' + msg)  # noqa: E731
    provider = idp['identityProviders'][0]
    e(provider.get('firstBrokerLoginFlowAlias') == 'krate first broker login',
      f'the provider must use the flow "krate first broker login" (D2); got {provider.get("firstBrokerLoginFlowAlias")!r}')
    e(provider.get('config', {}).get('syncMode') == 'FORCE', 'the provider syncs on every login (syncMode FORCE: group removal takes effect at the next sign-in)')
    e(all(m.get('config', {}).get('syncMode') == 'FORCE' and m.get('identityProviderMapper') == 'oidc-advanced-group-idp-mapper'
          for m in idp['identityProviderMappers']), 'both mappers are oidc-advanced-group-idp-mapper with syncMode FORCE')
    e(idp.get('authenticatorConfig') == [{'alias': 'PingFederate redirect', 'config': {'defaultProvider': 'pingfederate'}}],
      f'the redirector configuration must be "PingFederate redirect" with defaultProvider pingfederate; got {idp.get("authenticatorConfig")!r}')
    flows = {flow['alias']: flow for flow in idp.get('authenticationFlows', [])}
    e(list(flows) == ['krate browser', 'krate forms', 'krate otp', 'krate first broker login'],
      f'the flows must be krate browser, krate forms, krate otp, krate first broker login (parents before sub-flows); got {list(flows)}')
    e(all(flow.get('providerId') == 'basic-flow' and flow.get('builtIn') is False for flow in flows.values()), 'every flow is a basic-flow, not builtIn')
    e({alias: flow.get('topLevel') for alias, flow in flows.items()} == {'krate browser': True, 'krate forms': False, 'krate otp': False,
                                                                        'krate first broker login': True},
      'krate browser and krate first broker login are top-level; krate forms and krate otp are sub-flows')

    def shape(alias):
        return [((x['flowAlias'], 'flow') if x.get('authenticatorFlow') else (x['authenticator'], x.get('authenticatorConfig')),
                 x['requirement'], x['priority']) for x in flows.get(alias, {}).get('authenticationExecutions', [])]
    e(shape('krate browser') == [(('auth-cookie', None), 'ALTERNATIVE', 10), (('identity-provider-redirector', 'PingFederate redirect'), 'ALTERNATIVE', 20),
                                 (('krate forms', 'flow'), 'ALTERNATIVE', 30)],
      f'D3 krate browser: cookie ALT 10, redirector ALT 20 with the PingFederate config, sub-flow krate forms ALT 30; got {shape("krate browser")}')
    e(shape('krate forms') == [(('auth-username-password-form', None), 'REQUIRED', 10), (('krate otp', 'flow'), 'CONDITIONAL', 20)],
      f'D3 krate forms: username-password form REQUIRED 10, sub-flow krate otp CONDITIONAL 20; got {shape("krate forms")}')
    e(shape('krate otp') == [(('conditional-user-configured', None), 'REQUIRED', 10), (('auth-otp-form', None), 'REQUIRED', 20)],
      f'D3 krate otp: condition user configured REQUIRED 10, OTP form REQUIRED 20; got {shape("krate otp")}')
    e(shape('krate first broker login') == [(('idp-create-user-if-unique', None), 'REQUIRED', 10)],
      f'D2 krate first broker login: Create User If Unique REQUIRED 10 only; got {shape("krate first broker login")}')
    e(all(x.get('userSetupAllowed') is False for flow in flows.values() for x in flow.get('authenticationExecutions', [])),
      'no execution allows user setup')
    e(idp.get('truststore') == 'local', f'the plan declares truststore local by default (site key idp_truststore); got {idp.get("truststore")!r}')
    module = load_configure_dual()
    example = json.loads((ROOT / 'sso/dual-example.json').read_text())
    e(module.configs(dict(example, idp_truststore='system'), SYNTHETIC)['keycloak/pingfederate-idp.json'].get('truststore') == 'system',
      'idp_truststore: system is carried into the plan as truststore system')
    try:
        module.configs(dict(example, idp_truststore='none'), SYNTHETIC)
        e(False, 'configure-dual must refuse an unknown idp_truststore value')
    except ValueError as exc:
        e('idp_truststore' in str(exc), f'the idp_truststore refusal names the key; got {exc}')
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'plan.json'
        path.write_text(json.dumps(idp))
        try:
            plan = identity.broker_plan(path)
            e(plan == idp, 'identity.broker_plan accepts the planned file unchanged')
        except ValueError as exc:
            e(False, f'identity.broker_plan must accept the planned file; got {exc}')
        for label, mutate, needle in (
                ('an http token endpoint', lambda p: p['identityProviders'][0]['config'].__setitem__('tokenUrl', 'http://ping.example.internal/t'), 'https'),
                ('a literal secret', lambda p: p['identityProviders'][0]['config'].__setitem__('clientSecret', 'literal'), 'placeholder'),
                ('the built-in first broker login', lambda p: p['identityProviders'][0].__setitem__('firstBrokerLoginFlowAlias', 'first broker login'),
                 'firstBrokerLoginFlowAlias'),
                ('a third mapper', lambda p: p['identityProviderMappers'].append(dict(p['identityProviderMappers'][0], name='x')), 'two'),
                ('a missing flow', lambda p: p['authenticationFlows'].pop(), 'authenticationFlows'),
                ('an unknown sub-flow', lambda p: p['authenticationFlows'][0]['authenticationExecutions'][2].__setitem__('flowAlias', 'other'), 'not planned'),
                ('a non-integer priority', lambda p: p['authenticationFlows'][0]['authenticationExecutions'][0].__setitem__('priority', '10'), 'priority'),
                ('another browser flow', lambda p: p.__setitem__('browserFlow', 'browser'), 'browserFlow'),
                ('an unknown truststore mode', lambda p: p.__setitem__('truststore', 'none'), 'truststore')):
            mutated = json.loads(json.dumps(idp))
            mutate(mutated)
            path.write_text(json.dumps(mutated))
            try:
                identity.broker_plan(path)
                e(False, f'identity.broker_plan must refuse {label}')
            except ValueError as exc:
                e(needle in str(exc), f'identity.broker_plan refusing {label} must name {needle!r}; got {exc}')
        for accepted in ({'truststore': 'system'}, {}):
            mutated = dict(idp, **accepted)
            mutated.pop('truststore', None) if not accepted else None
            path.write_text(json.dumps(mutated))
            try:
                identity.broker_plan(path)
            except ValueError as exc:
                e(False, f'identity.broker_plan must accept truststore {accepted or "absent (defaults to local)"}; got {exc}')
    # The provider for kcadm: the secret only from the environment, never from the plan or an argument.
    env_backup = os.environ.pop('PING_KEYCLOAK_CLIENT_SECRET', None)
    try:
        try:
            identity.broker_provider(idp, with_secret=True)
            e(False, 'broker_provider --with-secret must refuse an unset PING_KEYCLOAK_CLIENT_SECRET')
        except ValueError as exc:
            e('PING_KEYCLOAK_CLIENT_SECRET' in str(exc), f'broker_provider names the missing key; got {exc}')
        os.environ['PING_KEYCLOAK_CLIENT_SECRET'] = RUNTIME_SITE['PING_KEYCLOAK_CLIENT_SECRET']
        with_secret = identity.broker_provider(idp, with_secret=True)
        e(with_secret['config']['clientSecret'] == RUNTIME_SITE['PING_KEYCLOAK_CLIENT_SECRET'], 'broker_provider --with-secret substitutes the environment value')
        e('clientSecret' not in identity.broker_provider(idp)['config'], 'broker_provider without the secret carries no clientSecret key')
        e(idp['identityProviders'][0]['config']['clientSecret'] == '${PING_KEYCLOAK_CLIENT_SECRET}', 'the plan keeps its placeholder')
    finally:
        os.environ.pop('PING_KEYCLOAK_CLIENT_SECRET', None)
        if env_backup is not None:
            os.environ['PING_KEYCLOAK_CLIENT_SECRET'] = env_backup
    current = {'alias': 'pingfederate', 'internalId': 'x', 'providerId': 'oidc', 'enabled': True, 'trustEmail': False, 'storeToken': False,
               'displayName': 'Company sign-in', 'firstBrokerLoginFlowAlias': 'krate first broker login', 'types': ['USER_AUTHENTICATION'],
               'config': dict(idp['identityProviders'][0]['config'], clientSecret='**********', extra='ignored')}
    e(identity.differs(identity.broker_provider(idp), current) is False, 'differs(): Keycloak extras (internalId, types, masked secret, extra config) are not a difference')
    e(identity.differs(identity.broker_provider(idp), dict(current, firstBrokerLoginFlowAlias='first broker login')) is True,
      'differs(): a changed first-broker-login alias is a difference')
    e(identity.differs(identity.broker_provider(idp), dict(current, config=dict(current['config'], tokenUrl='https://x'))) is True,
      'differs(): a changed endpoint is a difference')


def truststore_pem(site, name='enterprise-ca.pem', mode=0o644):
    """A placeholder PEM in auth/keycloak/truststores (755), as the operator places the enterprise CA."""
    trust = site / 'auth/keycloak/truststores'
    trust.mkdir(parents=True, exist_ok=True)
    trust.chmod(0o755)
    # Every directory on the way gets 755 explicitly: the gate runner runs under umask 077.
    for parent in reversed((trust / name).relative_to(trust).parents):
        if str(parent) != '.':
            (trust / parent).mkdir(exist_ok=True)
            (trust / parent).chmod(0o755)
    identity.write_file(trust / name, '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', mode)
    return trust / name


def check_runtime_preflight(checks):
    """preflight --mode runtime.yml accepts the planned site (local planner and configure-dual alike) and refuses what widens access."""
    settings = json.loads((ROOT / 'sso/dual-example.json').read_text())
    settings['public_url'] = 'https://' + PUBLIC_HOST
    for edition, ping in zip(EDITIONS, (False, True)):
        with tempfile.TemporaryDirectory() as tmp:
            overrides = dict(RUNTIME_SITE) if ping else {'KAFKA_UI_AUTH_CONFIG': 'runtime.yml'}
            site = synthetic_site(edition, tmp, **overrides)
            env = site_env(edition, **overrides)
            self_signed(site / 'certs', PUBLIC_HOST)
            if ping:  # the PingFederate flow: configure-dual writes runtime.yml and the identity-provider plan; the operator adds the CA
                for name, data in load_configure_dual().configs(settings, env).items():
                    identity.write_file(site / 'auth' / name, json.dumps(data, indent=2) + '\n', 0o644)
                truststore_pem(site)
            else:  # the local flow: identity.py runtime, as krate auth configure runs it
                with contextlib.redirect_stdout(io.StringIO()):
                    identity.runtime_plan(site / '.env', CLUSTERS, site / 'auth/ui/runtime.yml')
            planned, _ = run_plan(site)
            if not checks.expect(planned.returncode == 0, f'{edition}: identity.py plan failed on a runtime.yml site'):
                continue
            code, rendered = compose_config(site / '.env', edition, project_dir=site)
            if not checks.expect(code == 0, f'{edition}: Compose rendering of the runtime.yml site failed'):
                continue
            result = preflight(site, 'runtime.yml', rendered)
            checks.expect(result.returncode == 0,
                          f'{edition}: preflight --mode runtime.yml refused the planned site ({"PingFederate" if ping else "local"} flow,'
                          f' PING secret {"set" if ping else "placeholder"}): {result.stderr.strip()}')
            checks.expect(not any(secret in result.stdout + result.stderr for secret in ALL_SECRETS),
                          f'{edition}: preflight --mode runtime.yml output leaked a secret value')
            check_name_refusals(checks, edition, site, env, 'runtime.yml', rendered)
            check_network_refusals(checks, edition, site, 'runtime.yml', rendered)
            check_runtime_refusals(checks, edition, site, env, rendered)
            if ping:
                check_broker_refusals(checks, edition, site, env, rendered)
            else:
                check_local_mode_unchanged(checks, edition, site, env, rendered)


def check_local_mode_unchanged(checks, edition, site, env, rendered):
    """Without the plan file preflight ignores the PingFederate inputs: no secret, no truststore PEM, a stray 600 PEM."""
    e = checks.expect
    env_file = site / '.env'
    write_env(site, dict(env, PING_KEYCLOAK_CLIENT_SECRET='REPLACE_ME'))
    result = preflight(site, 'runtime.yml', rendered)
    e(result.returncode == 0, f'{edition}: local mode must pass with PING_KEYCLOAK_CLIENT_SECRET at REPLACE_ME and no truststore; got {result.stderr.strip()}')
    pem = truststore_pem(site, mode=0o600)
    result = preflight(site, 'runtime.yml', rendered)
    e(result.returncode == 0, f'{edition}: local mode must not inspect truststore PEM modes; got {result.stderr.strip()}')
    pem.unlink()
    write_env(site, env)
    realm_file = site / 'auth/keycloak/krate-realm.json'
    realm_original = realm_file.read_text()
    realm = json.loads(realm_original)
    realm['identityProviders'] = [{'alias': 'pingfederate', 'providerId': 'oidc', 'config': {}}]
    identity.write_file(realm_file, json.dumps(realm) + '\n', 0o644)
    result = preflight(site, 'runtime.yml', rendered)
    e(result.returncode == 1 and 'identityProviders' in result.stderr,
      f'{edition}: identityProviders in the realm file are refused in local mode; got exit {result.returncode}: {result.stderr.strip()}')
    identity.write_file(realm_file, realm_original, 0o644)
    assert env_file.is_file()


def check_broker_refusals(checks, edition, site, env, rendered):
    """Ping mode (the plan exists): the secret, https endpoints, group mappers, trust material and the hint are checked by name."""
    plan_file = site / 'auth/keycloak/pingfederate-idp.json'
    runtime_file = site / 'auth/ui/runtime.yml'
    realm_file = site / 'auth/keycloak/krate-realm.json'
    plan_original = plan_file.read_text()
    runtime_original = runtime_file.read_text()
    realm_original = realm_file.read_text()
    trust = site / 'auth/keycloak/truststores'

    def expect_refusal(case, wanted):
        outcome = preflight(site, 'runtime.yml', rendered)
        checks.expect(outcome.returncode == 1 and wanted in outcome.stderr,
                      f'{edition}: ping-mode preflight must refuse: {case} (naming {wanted!r}); got exit {outcome.returncode}: {outcome.stderr.strip()}')
        checks.expect(not any(secret in outcome.stdout + outcome.stderr for secret in ALL_SECRETS), f'{edition}: ping-mode refusal leaked a secret ({case})')

    def expect_pass(case):
        outcome = preflight(site, 'runtime.yml', rendered)
        checks.expect(outcome.returncode == 0, f'{edition}: ping-mode preflight must accept: {case}; got exit {outcome.returncode}: {outcome.stderr.strip()}')

    def mutated_plan(mutation):
        data = json.loads(plan_original)
        mutation(data)
        identity.write_file(plan_file, json.dumps(data, indent=2) + '\n', 0o644)

    write_env(site, dict(env, PING_KEYCLOAK_CLIENT_SECRET='REPLACE_ME'))
    expect_refusal('PING_KEYCLOAK_CLIENT_SECRET not set', 'PING_KEYCLOAK_CLIENT_SECRET')
    write_env(site, dict(env, PING_KEYCLOAK_CLIENT_SECRET=env['KEYCLOAK_CLI_CLIENT_SECRET']))
    expect_refusal('PING_KEYCLOAK_CLIENT_SECRET equal to another identity secret', 'different')
    write_env(site, env)
    for label, mutation, needle in (
            ('an http token endpoint', lambda p: p['identityProviders'][0]['config'].__setitem__('tokenUrl', 'http://ping.example.internal/as/token.oauth2'), 'https'),
            ('a literal client secret', lambda p: p['identityProviders'][0]['config'].__setitem__('clientSecret', 'literal-value-0123456789'), 'placeholder'),
            ('the plan carrying the configured secret value', lambda p: p['identityProviders'][0].__setitem__('displayName', env['PING_KEYCLOAK_CLIENT_SECRET']), 'secret'),
            ('a mapper targeting another realm group', lambda p: p['identityProviderMappers'][0]['config'].__setitem__('group', '/OTHER'), 'realm groups'),
            ('a mapper without syncMode FORCE', lambda p: p['identityProviderMappers'][1]['config'].__setitem__('syncMode', 'IMPORT'), 'FORCE'),
            ('the built-in first broker login flow', lambda p: p['identityProviders'][0].__setitem__('firstBrokerLoginFlowAlias', 'first broker login'), 'krate first broker login'),
            ('browserFlow bound to browser', lambda p: p.__setitem__('browserFlow', 'browser'), 'browserFlow')):
        mutated_plan(mutation)
        expect_refusal(label, needle)
    identity.write_file(plan_file, plan_original, 0o644)
    expect_pass('the planned ping site')
    pem = trust / 'enterprise-ca.pem'
    pem.chmod(0o600)
    expect_refusal('a 600 PEM in the truststores', 'chmod 644')
    pem.chmod(0o644)
    pem.unlink()
    expect_refusal('no PEM while the identity provider is on another host', 'holds no truststore file')
    truststore_pem(site, name='enterprise-ca.crt')
    expect_pass('a .crt PEM instead of .pem')
    trust.chmod(0o700)
    expect_refusal('a 700 truststores directory', '755')
    trust.chmod(0o755)
    (trust / 'enterprise-ca.crt').unlink()
    # Keycloak scans the directory recursively and loads PEM and PKCS12 files; anything else is refused by name.
    truststore_pem(site, name='enterprise-ca.p12')
    expect_pass('a PKCS12 file as the only truststore file')
    (trust / 'enterprise-ca.p12').chmod(0o600)
    expect_refusal('a 600 PKCS12 file', 'enterprise-ca.p12 must be world-readable')
    (trust / 'enterprise-ca.p12').unlink()
    truststore_pem(site, name='ca/root.pem')  # creates ca/ with 755 (the gate runner runs under umask 077)
    expect_pass('a PEM in a sub-directory')
    (trust / 'ca/root.pem').chmod(0o600)
    expect_refusal('a 600 PEM in a sub-directory', 'ca/root.pem must be world-readable')
    (trust / 'ca/root.pem').chmod(0o644)
    (trust / 'ca').chmod(0o700)
    expect_refusal('a 700 sub-directory', 'truststores/ca must have mode 755')
    (trust / 'ca').chmod(0o755)
    identity.write_file(trust / 'notes.txt', 'not a certificate\n', 0o644)  # refused by name, whatever its mode
    expect_refusal('a stray non-truststore file', 'notes.txt is not a truststore file')
    (trust / 'notes.txt').unlink()
    (trust / 'ca/root.pem').unlink()
    (trust / 'ca').rmdir()
    # The identity provider on the public host:port itself needs no extra trust material; another port does (N5).
    public = 'https://' + PUBLIC_HOST
    def endpoints_on(base):
        return lambda p: p['identityProviders'][0]['config'].update(
            {'issuer': base + '/as', 'authorizationUrl': base + '/as/authorization.oauth2', 'tokenUrl': base + '/as/token.oauth2',
             'userInfoUrl': base + '/idp/userinfo.openid', 'jwksUrl': base + '/pf/JWKS'})
    mutated_plan(endpoints_on(public))
    expect_pass('the identity provider on the public host without a truststore PEM')
    mutated_plan(endpoints_on(public + ':8443'))
    expect_refusal('the identity provider on the public host but another port, without a PEM', 'holds no truststore file')
    mutated_plan(endpoints_on(public))
    truststore_pem(site, mode=0o600)
    expect_refusal('a 600 PEM even when the provider is on the public host', 'chmod 644')
    (trust / 'enterprise-ca.pem').unlink()
    # truststore system (site key idp_truststore): no CA file required, the note names the JVM truststore; the mode rules stay.
    mutated_plan(lambda p: p.__setitem__('truststore', 'system'))
    outcome = preflight(site, 'runtime.yml', rendered)
    checks.expect(outcome.returncode == 0 and 'JVM default truststore' in outcome.stderr,
                  f'{edition}: truststore system without a PEM must pass with a note naming the JVM default truststore; got exit {outcome.returncode}: {outcome.stderr.strip()}')
    truststore_pem(site, mode=0o600)
    expect_refusal('a 600 PEM under truststore system', 'chmod 644')
    (trust / 'enterprise-ca.pem').unlink()
    trust.chmod(0o700)
    expect_refusal('a 700 truststores directory under truststore system', '755')
    trust.chmod(0o755)
    identity.write_file(plan_file, plan_original, 0o644)
    truststore_pem(site)
    # N1: a hint in runtime.yml is refused by the plan-equality check (the document differs from the Krate plan).
    runtime = json.loads(runtime_original)
    runtime['auth']['oauth2']['client']['keycloak']['custom-params']['kc_idp_hint'] = ''
    identity.write_file(runtime_file, json.dumps(runtime, indent=2) + '\n', 0o644)
    expect_refusal('a kc_idp_hint in runtime.yml', 'differs from the Krate plan')
    identity.write_file(runtime_file, runtime_original, 0o644)
    realm = json.loads(realm_original)
    realm['identityProviders'] = [{'alias': 'pingfederate', 'providerId': 'oidc', 'config': {}}]
    identity.write_file(realm_file, json.dumps(realm) + '\n', 0o644)
    expect_refusal('identityProviders in the realm file (ping mode)', 'identityProviders')
    identity.write_file(realm_file, realm_original, 0o644)
    plan_file.write_text('{not json')
    expect_refusal('an unreadable plan file', 'not valid JSON')
    identity.write_file(plan_file, plan_original, 0o644)
    expect_pass('the ping site restored')


def check_runtime_refusals(checks, edition, site, env, rendered):
    """A runtime.yml, realm file or rendering that widens Kafbat access must be refused by name."""
    runtime_file = site / 'auth/ui/runtime.yml'
    realm_file = site / 'auth/keycloak/krate-realm.json'
    original = runtime_file.read_text()
    realm_original = realm_file.read_text()

    def expect_refusal(case, wanted, auth_mode='runtime.yml', rendered_config=rendered):
        outcome = preflight(site, auth_mode, rendered_config)
        checks.expect(outcome.returncode == 1 and wanted in outcome.stderr,
                      f'{edition}: preflight --mode runtime.yml must refuse: {case} (naming {wanted!r});'
                      f' got exit {outcome.returncode}: {outcome.stderr.strip()}')

    def viewer_topic(d):
        return next(p for p in d['rbac']['roles'][0]['permissions'] if p['resource'] == 'topic')

    def mutated_runtime(mutation):
        data = json.loads(original)
        mutation(data)
        identity.write_file(runtime_file, json.dumps(data, indent=2) + '\n', 0o644)

    cases = (
        ('allow-shared-login present', 'allow-shared-login', lambda d: d['auth']['oauth2'].__setitem__('allow-shared-login', True)),
        ('shared-role present', 'shared-role', lambda d: d['auth']['oauth2'].__setitem__('shared-role', 'administrator')),
        ('require-mapped-role off', 'require-mapped-role', lambda d: d['auth']['oauth2'].__setitem__('require-mapped-role', False)),
        ('session cookie renamed', 'SESSION', lambda d: d['server']['reactive']['session']['cookie'].__setitem__('name', 'JSESSIONID')),
        ('viewer reads messages without the opt-in', 'KAFKA_UI_VIEWER_MESSAGES',
         lambda d: viewer_topic(d)['actions'].append('messages_read')),
        ('defaultRole present', 'defaultRole', lambda d: d['rbac'].__setitem__('defaultRole', {'permissions': []})),
        ('viewer granted ksql', 'ksql', lambda d: d['rbac']['roles'][0]['permissions'].append({'resource': 'ksql', 'actions': 'all'})),
        ('viewer subject is not the realm group', 'only subject',
         lambda d: d['rbac']['roles'][0]['subjects'].append({'provider': 'oauth', 'type': 'user', 'value': 'alice', 'regex': False})),
        ('viewer mutates topics', 'differs from the Krate plan', lambda d: viewer_topic(d)['actions'].append('edit')),
        ('viewer granted applicationconfig view', 'differs from the Krate plan',
         lambda d: d['rbac']['roles'][0]['permissions'].append({'resource': 'applicationconfig', 'actions': ['view']})),
        ('end-session-uri removed (logout would not end the Keycloak session)', 'differs from the Krate plan',
         lambda d: d['auth']['oauth2']['client']['keycloak']['custom-params'].pop('end-session-uri')),
        ('actuator exposed to signed-in users', 'unexpected top-level keys',
         lambda d: d.__setitem__('management', {'endpoints': {'web': {'exposure': {'include': '*'}}}})),
        ('dynamic config enabled', 'unexpected top-level keys', lambda d: d.__setitem__('dynamic', {'config': {'enabled': True}})),
        ('second client registration', 'differs from the Krate plan',
         lambda d: d['auth']['oauth2']['client'].__setitem__('other', dict(d['auth']['oauth2']['client']['keycloak']))),
        ('third role added', 'exactly the roles', lambda d: d['rbac']['roles'].append(dict(d['rbac']['roles'][1], name='ops'))),
        ('issuer points elsewhere', 'issuer/callback',
         lambda d: d['auth']['oauth2']['client']['keycloak'].__setitem__('issuer-uri', 'https://evil.example.test/identity/realms/krate')),
        ('session timeout differs from KEYCLOAK_SESSION_IDLE_MINUTES', 'differs from the Krate plan',
         lambda d: d['server']['reactive']['session'].__setitem__('timeout', '240m')),
        ('user name attribute is not sub', 'user-name-attribute',
         lambda d: d['auth']['oauth2']['client']['keycloak'].__setitem__('user-name-attribute', 'preferred_username')),
    )
    for label, needle, change in cases:
        mutated_runtime(change)
        expect_refusal(label, needle)
    identity.write_file(runtime_file, original, 0o644)
    # EPC's kafbat.yml shares the Spring configuration: anything beyond the kafka: section is refused.
    kafbat = site / 'kafbat.yml'
    kafbat.write_text('kafka:\n  clusters:\n    - name: x\nrbac:\n  defaultRole:\n    permissions: []\n')
    expect_refusal('kafbat.yml with an rbac section', 'kafbat.yml')
    for label, text in (
            ('a quoted top-level key', 'kafka:\n  clusters: []\n"management": {endpoints: {web: {exposure: {include: "*"}}}}\n'),
            ('a single-quoted top-level key', "kafka:\n  clusters: []\n'rbac':\n  roles: []\n"),
            ('a complex mapping key', 'kafka:\n  clusters: []\n? management\n: {}\n'),
            ('a flow mapping at column 0', 'kafka:\n  clusters: []\n{auth: {type: DISABLED}}\n'),
            ('a second document', 'kafka:\n  clusters: []\n---\nauth:\n  type: DISABLED\n'),
            ('a second document with an indented root', 'kafka:\n  clusters: []\n---\n management:\n   endpoints: x\n'),
            ('an indented root before kafka:', ' management:\n   endpoints: x\nkafka:\n  clusters: []\n'),
            ('a document end marker', 'kafka:\n  clusters: []\n...\nauth: {}\n'),
            ('an indented document marker', 'kafka:\n  clusters: []\n  ---\n  auth: {}\n'),
            ('kafka: glued to a comment', 'kafka:#x\n  clusters: []\n'),
            ('a second document after a final marker', 'kafka:\n  clusters: []\n...\n---\nauth: {}\n'),
            ('no kafka: section', '# clusters elsewhere\n')):
        kafbat.write_text(text)
        expect_refusal(f'kafbat.yml with {label}', 'kafbat.yml')
    for label, text in (('comments, a document marker and nested lists', '# Kafbat clusters\n---\nkafka:   # the only section\n  clusters:\n    - name: x\n\n    # - name: y\n'),
                        ('a BOM, a %YAML directive and a final document end marker', '\ufeff%YAML 1.2\n---\nkafka:\n  clusters:\n    - name: x\n...\n'),
                        ('CRLF line ends', 'kafka:\r\n  clusters:\r\n    - name: x\r\n')):
        kafbat.write_text(text)
        result = preflight(site, 'runtime.yml', rendered)
        checks.expect(result.returncode == 0, f'{edition}: preflight must accept a kafbat.yml with {label}; got exit {result.returncode}: {result.stderr.strip()}')
    kafbat.unlink()
    # The opt-in makes the same messages_read grant acceptable, and only then.
    write_env(site, dict(env, KAFKA_UI_VIEWER_MESSAGES='true'))
    with contextlib.redirect_stdout(io.StringIO()):
        identity.runtime_plan(site / '.env', json.loads(original)['rbac']['roles'][0]['clusters'], runtime_file, force=True)
    result = preflight(site, 'runtime.yml', rendered)
    checks.expect(result.returncode == 0 and 'messages_read' in runtime_file.read_text(),
                  f'{edition}: preflight must accept the viewer messages_read grant once KAFKA_UI_VIEWER_MESSAGES=true; got exit {result.returncode}: {result.stderr.strip()}')
    write_env(site, env)
    expect_refusal('opted-in file but the opt-in was withdrawn from .env', 'KAFKA_UI_VIEWER_MESSAGES')
    identity.write_file(runtime_file, original, 0o644)
    # The realm must carry the back-channel logout attributes; an older plan (wildcard post-logout, no back-channel) is refused.
    realm = json.loads(realm_original)
    ui = next(client for client in realm['clients'] if client['clientId'] == 'krate-ui')
    ui['attributes'] = {'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': 'https://' + PUBLIC_HOST + '/*'}
    identity.write_file(realm_file, json.dumps(realm, indent=2) + '\n', 0o644)
    expect_refusal('realm krate-ui without back-channel logout attributes', 'back-channel')
    expect_refusal('realm krate-ui without back-channel logout attributes (identity mode)', 'back-channel', auth_mode='identity')
    identity.write_file(realm_file, realm_original, 0o644)
    # kafka-ui must bind-mount this site's auth/ui read-only; runtime.yml must exist.
    config = json.loads(rendered)
    config['services']['kafka-ui']['volumes'] = [m for m in config['services']['kafka-ui']['volumes'] if m.get('target') != '/etc/krate/auth']
    expect_refusal('kafka-ui without the auth/ui mount', '/etc/krate/auth', rendered_config=json.dumps(config))
    config = json.loads(rendered)
    for mount in config['services']['kafka-ui']['volumes']:
        if mount.get('target') == '/etc/krate/auth':
            mount['source'] = str(ROOT / 'kraft/auth/ui')
    expect_refusal('kafka-ui mounting another directory at /etc/krate/auth', '/etc/krate/auth', rendered_config=json.dumps(config))
    runtime_file.unlink()
    expect_refusal('runtime.yml missing', 'auth/ui/runtime.yml')
    identity.write_file(runtime_file, original, 0o644)
    result = preflight(site, 'runtime.yml', rendered)
    checks.expect(result.returncode == 0, f'{edition}: preflight must pass again once the site is restored: {result.stderr.strip()}')


def check_backup_seal(checks):
    """The backup envelope must detect any modification before decryption and reject a wrong passphrase."""
    import os
    e = lambda cond, msg: checks.expect(cond, 'backup seal: ' + msg)  # noqa: E731
    ciphertext = b'Salted__' + os.urandom(8) + os.urandom(96)
    sealed = identity.backup_seal(ciphertext, b'correct horse')
    e(sealed.startswith(identity.BACKUP_MAGIC), 'sealed file starts with the format marker')
    e(identity.backup_open(sealed, b'correct horse') == ciphertext, 'round trip returns the ciphertext')
    for offset in (len(identity.BACKUP_MAGIC) + 20, len(sealed) - 1):
        flipped = bytearray(sealed)
        flipped[offset] ^= 0x01
        try:
            identity.backup_open(bytes(flipped), b'correct horse')
            e(False, f'a flipped bit at offset {offset} must be refused')
        except ValueError as exc:
            e('integrity check failed' in str(exc), f'flipped bit at {offset} reports an integrity failure; got {exc}')
    try:
        identity.backup_open(sealed, b'wrong passphrase')
        e(False, 'a wrong passphrase must be refused before decryption')
    except ValueError as exc:
        e('integrity check failed' in str(exc), f'wrong passphrase reports an integrity failure; got {exc}')
    for bad in (ciphertext, b'', b'x' * 100):
        try:
            identity.backup_open(bad, b'correct horse')
            e(False, 'a file without the marker must be refused')
        except ValueError:
            pass
    try:
        identity.backup_seal(b'not an openssl output', b'correct horse')
        e(False, 'sealing requires an openssl Salted__ ciphertext')
    except ValueError:
        pass
    key_a = identity.backup_mac_key(b'p', b'12345678')
    key_b = identity.backup_mac_key(b'p', b'12345679')
    e(key_a != key_b, 'the MAC key depends on the per-file salt')
    # The CLI path streams: a 3 MiB archive round-trips through the real subcommands, a flipped
    # byte or a wrong passphrase is refused and leaves no output file (PR #39 review, memory growth).
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        big = b'Salted__' + os.urandom(8) + os.urandom(3 * 1024 * 1024 + 7)
        (tmp / 'payload.enc').write_bytes(big)
        env = dict(os.environ, KRATE_BACKUP_PASSPHRASE='correct horse battery')
        def cli(*args, passphrase=None):
            return subprocess.run([sys.executable, '-I', str(ROOT / 'sso/identity.py'), *args], text=True, capture_output=True,
                                  env=dict(env, KRATE_BACKUP_PASSPHRASE=passphrase) if passphrase else env)
        r = cli('backup-seal', '--input', str(tmp / 'payload.enc'), '--output', str(tmp / 'sealed'))
        e(r.returncode == 0 and mode(tmp / 'sealed') == 0o600, f'backup-seal streams to a 0600 file; got {r.returncode} {r.stderr.strip()}')
        e(identity.backup_open((tmp / 'sealed').read_bytes(), b'correct horse battery') == big, 'the streamed seal matches the in-memory format')
        r = cli('backup-open', '--input', str(tmp / 'sealed'), '--output', str(tmp / 'opened'))
        e(r.returncode == 0 and (tmp / 'opened').read_bytes() == big and mode(tmp / 'opened') == 0o600, f'backup-open streams the ciphertext back; got {r.returncode} {r.stderr.strip()}')
        flipped = bytearray((tmp / 'sealed').read_bytes()); flipped[len(flipped) // 2] ^= 0x01
        (tmp / 'tampered').write_bytes(bytes(flipped))
        r = cli('backup-open', '--input', str(tmp / 'tampered'), '--output', str(tmp / 'opened2'))
        e(r.returncode == 1 and 'integrity check failed' in r.stderr and not (tmp / 'opened2').exists(),
          f'a tampered archive is refused with no output left behind; got {r.returncode} {r.stderr.strip()} exists={(tmp / "opened2").exists()}')
        r = cli('backup-open', '--input', str(tmp / 'sealed'), '--output', str(tmp / 'opened3'), passphrase='wrong passphrase!')
        e(r.returncode == 1 and 'integrity check failed' in r.stderr and not (tmp / 'opened3').exists(), 'a wrong passphrase is refused with no output')
        e(sorted(f.name for f in tmp.iterdir()) == ['opened', 'payload.enc', 'sealed', 'tampered'], f'no temporary files remain; got {sorted(f.name for f in tmp.iterdir())}')


# ─── Post-review product fixes (review-post-c4e0d41: S1-S10, N1-N7) ─────────────
# Several of these run the CLI's own Bash functions, cut out of kraft/krate or epc/krate, against
# a temporary tree with stub commands on PATH: no container, no sudo, no network.

BASH_STUBS = r'''set -euo pipefail
RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; DIM=''; RESET=''
info()  { echo "==> $*"; }
ok()    { echo "  ok $*"; }
warn()  { echo "  ! $*"; }
err()   { echo "  x $*" >&2; }
die()   { err "$*"; exit 1; }
sep()   { :; }
step()  { :; }
'''


def bash_binary():
    """A bash of at least 4.4 (mapfile, empty arrays under set -u), as on the target VMs."""
    found = shutil.which('bash')
    if not found:
        return None
    version = subprocess.run([found, '-c', 'echo "${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"'], text=True, capture_output=True).stdout.split()
    return found if len(version) == 2 and (int(version[0]), int(version[1])) >= (4, 4) else None


def bash_functions(path, *names):
    """The source of the named top-level functions of a Bash script, in the given order."""
    text = Path(path).read_text()
    parts = []
    for name in names:
        match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}\n', text, re.M | re.S)
        if match is None:
            raise ValueError(f'{path}: function {name} not found')
        parts.append(match.group(0))
    return '\n'.join(parts)


def function_body(text, name):
    start = text.index('\n' + name + '() {')
    return text[start:text.index('\n}\n', start) + 3]


def run_bash(script, *args, env=None, path_dir=None, cwd=None, stdin=None):
    bash = bash_binary()
    assert bash is not None, 'bash 4.4 or newer is required on PATH'
    environment = dict(os.environ if env is None else env)
    if path_dir is not None:
        environment['PATH'] = f'{path_dir}{os.pathsep}{environment.get("PATH", "")}'
    return subprocess.run([bash, '-c', script, 'bash', *map(str, args)], text=True, capture_output=True,
                          env=environment, cwd=cwd, input=stdin, timeout=120)


def write_tool(directory, name, body):
    path = Path(directory) / name
    path.write_text('#!/usr/bin/env bash\n' + body)
    path.chmod(0o755)


def check_bash_available(checks):
    checks.expect(bash_binary() is not None, 'the Bash function tests need bash 4.4 or newer on PATH (brew install bash on macOS)')


def check_proxy_env(checks):
    """S1/N1: the proxy's environment carries the config digest and public host; prepare and auth apply keep them current."""
    e = checks.expect
    for edition in EDITIONS:
        code, rendered = compose_config(ROOT / edition / '.env.template', edition)
        if e(code == 0, f'{edition}: Compose rendering failed'):
            proxy = json.loads(rendered)['services']['proxy']
            env = proxy.get('environment') or {}
            for key in ('KRATE_PROXY_CONF_SHA', 'KRATE_PROXY_PUBLIC_HOST'):
                e(key in env, f'{edition}/proxy: {key} must be part of the environment so a change recreates the proxy')
            e(env.get('NGINX_ENVSUBST_FILTER') == '^KRATE_PROXY_',
              f'{edition}/proxy: NGINX_ENVSUBST_FILTER must limit template substitution to KRATE_PROXY_*; got {env.get("NGINX_ENVSUBST_FILTER")!r}')
            mounts = {mount.get('target'): mount for mount in proxy.get('volumes') or []}
            template = mounts.get('/etc/nginx/templates/default.conf.template', {})
            e(template.get('read_only') is True and Path(template.get('source', '')).name == 'nginx.conf',
              f'{edition}/proxy: nginx.conf must be mounted read-only as /etc/nginx/templates/default.conf.template')
            e('/etc/nginx/conf.d/default.conf' not in mounts, f'{edition}/proxy: nginx.conf must not bypass the template step')
        nginx = (ROOT / edition / 'nginx.conf').read_text()
        placeholders = set(re.findall(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', nginx))
        e(placeholders == {'KRATE_PROXY_PUBLIC_HOST'}, f'{edition}/nginx.conf: the only template variable is KRATE_PROXY_PUBLIC_HOST; got {sorted(placeholders)}')
        cli = (ROOT / edition / 'krate').read_text()
        prepare = function_body(cli, 'prepare')
        e('sync_proxy_env' in prepare and prepare.index('ensure_cert') < prepare.index('sync_proxy_env'),
          f'{edition}/krate: prepare() must write the proxy digest after the certificate exists')
    activate = (ROOT / 'sso/activate.sh').read_text()
    e('sync_proxy_env "$mode"' in activate and activate.index('sync_proxy_env "$mode"')
      < activate.index('--wait-timeout "$timeout" proxy'), 'sso/activate.sh: apply must sync the proxy environment before reconciling the proxy')
    if bash_binary() is None:
        return
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'env_value', 'replace_env_file', 'set_env_file_value',
                                         'public_url_host', 'public_url_authority', 'sync_proxy_env') + r'''
SCRIPT_DIR="$1"; ENV_FILE="$1/.env"; CERT_CRT="$1/certs/server.crt"; CERT_KEY="$1/certs/server.key"
sync_proxy_env "${2:-}"
grep -E '^KRATE_PROXY_' "$ENV_FILE"
'''
    with tempfile.TemporaryDirectory() as tmp:
        site = Path(tmp)
        (site / 'certs').mkdir()
        (site / 'nginx.conf').write_text((ROOT / 'kraft/nginx.conf').read_text())
        (site / 'certs/server.crt').write_text('certificate one\n')
        (site / 'certs/server.key').write_text('key one\n')

        def env_file(public_url):
            write_env(site, {'KAFKA_UI_AUTH_CONFIG': 'local.yml', 'KEYCLOAK_PUBLIC_URL': public_url,
                             'KRATE_PROXY_CONF_SHA': '', 'KRATE_PROXY_PUBLIC_HOST': ''})

        def sync(auth_mode=''):
            outcome = run_bash(script, site, auth_mode)
            values = identity.read_env(site / '.env')
            return outcome, values.get('KRATE_PROXY_CONF_SHA', ''), values.get('KRATE_PROXY_PUBLIC_HOST')

        env_file('https://Kafka.Example.TEST:8443/identity')
        result, sha, host = sync()
        e(result.returncode == 0 and re.fullmatch(r'[0-9a-f]{32}', sha) and host == '',
          f'sync_proxy_env (local.yml): a 32-hex digest and no public host; got {result.returncode} {sha!r} {host!r} {result.stderr.strip()[:120]}')
        before = (site / '.env').read_bytes()
        sync()
        e((site / '.env').read_bytes() == before, 'sync_proxy_env: unchanged inputs leave .env byte-identical (no recreate)')
        e(sorted(path.name for path in site.iterdir()) == ['.env', 'certs', 'nginx.conf'], 'sync_proxy_env: no temporary file remains')
        digests = {sha}
        for path, text in (('nginx.conf', (ROOT / 'kraft/nginx.conf').read_text() + '# changed\n'),
                           ('certs/server.crt', 'certificate two\n'), ('certs/server.key', 'key two\n')):
            (site / path).write_text(text)
            _, changed, _ = sync()
            e(changed not in digests, f'sync_proxy_env: a changed {path} must change KRATE_PROXY_CONF_SHA')
            digests.add(changed)
        _, _, host = sync('runtime.yml')
        e(host == 'kafka.example.test:8443', f'sync_proxy_env (runtime.yml): the public authority in lower case, port included; got {host!r}')
        for url, expected in (('https://[FD00::5]:8443/identity', '[fd00::5]:8443'), ('https://[fd00::5]/identity', '[fd00::5]'),
                              ('https://kafka.example.test/identity', 'kafka.example.test'), ('https://kafka.example.test:443/identity', 'kafka.example.test')):
            env_file(url)
            _, _, host = sync('runtime.yml')
            e(host == expected, f'sync_proxy_env (runtime.yml): {url} gives the Host value a browser sends ({expected}: brackets kept, :443 omitted); got {host!r}')
        _, _, host = sync('local.yml')
        e(host == '', f'sync_proxy_env (local.yml): the public host is cleared again; got {host!r}')


def nginx_map(nginx, variable):
    """(entries, default) of an nginx map block: entries are (regex, case-insensitive, value)."""
    block = re.search(r'^map (\S+|"[^"]*") \$' + re.escape(variable) + r' \{\n(.*?)^\}', nginx, re.M | re.S)
    assert block is not None, f'map ${variable} missing'
    entries, default = [], None
    for line in block.group(2).splitlines():
        match = re.fullmatch(r'\s*"(~\*?)(.*)" (\S+);', line)
        if match:
            entries.append((match.group(2), match.group(1) == '~*', match.group(3)))
        elif line.strip().startswith('default '):
            default = line.strip()[len('default '):-1]
    return block.group(1).strip('"'), entries, default


def map_value(entries, default, value):
    for pattern, insensitive, result in entries:
        if re.search(pattern, value, re.I if insensitive else 0):
            return result
    return default


def check_nginx_edge(checks):
    """N1: only the public host is served in runtime.yml mode; N7: a path parameter is refused on every route."""
    e = checks.expect
    for edition in EDITIONS:
        nginx = (ROOT / edition / 'nginx.conf').read_text()
        label = f'{edition}/nginx.conf'
        source, entries, default = nginx_map(nginx, 'krate_foreign_host')
        e(source == '$http_host ${KRATE_PROXY_PUBLIC_HOST}',
          f'{label}: $krate_foreign_host must compare the raw Host header ($http_host, port included; $host is taken from an absolute request-URI) with KRATE_PROXY_PUBLIC_HOST; got {source!r}')
        for host, public, refused in (('kafka.example.test', 'kafka.example.test', '0'), ('KAFKA.example.test', 'kafka.example.test', '0'),
                                      ('evil.example', 'kafka.example.test', '1'), ('kafka.example.test.evil', 'kafka.example.test', '1'),
                                      ('kafka', 'kafka.example.test', '1'), ('_', 'localhost', '1'), ('[fd00::5]', '[fd00::5]', '0'),
                                      ('kafka.example.test:8443', 'kafka.example.test:8443', '0'), ('kafka.example.test', 'kafka.example.test:8443', '1'),
                                      ('kafka.example.test:9999', 'kafka.example.test', '1'), ('kafka.example.test:8443', 'kafka.example.test', '1'),
                                      ('[fd00::5]:8443', '[fd00::5]:8443', '0'), ('', 'kafka.example.test', '1'),
                                      ('any.name', '', '0'), ('10.1.2.3', '', '0'), ('any.name:9999', '', '0')):
            got = map_value(entries, default, f'{host} {public}')
            e(got == refused, f'{label}: host {host!r} with public host {public!r} must map to {refused}; got {got}')
        _, entries, default = nginx_map(nginx, 'krate_path_parameter')
        for uri, refused in (('/actuator;x/prometheus', '1'), ('/actuator%3Bx/prometheus', '1'), ('/metrics;a', '1'),
                             ('/api/clusters/c/topics/a..b', '0'), ('/api/clusters/c/schemas/a%2Fb/versions', '0'),
                             ('/ui/clusters?q=a;b', '0'), ('/', '0')):
            got = map_value(entries, default, uri)
            e(got == refused, f'{label}: $krate_path_parameter for {uri!r} must be {refused}; got {got}')
        servers = re.split(r'^server \{', nginx, flags=re.M)[1:]
        e(len(servers) == 2, f'{label}: expected the port-80 and port-443 servers')
        plain = servers[0]
        e('return 301 https://$krate_redirect_authority$request_uri;' in plain and 'krate_foreign_host' not in plain and 'location' not in plain,
          f'{label}: the port-80 server only redirects to the public authority (a plain-HTTP Host never carries the HTTPS port)')
        e('map "${KRATE_PROXY_PUBLIC_HOST}" $krate_redirect_authority {\n    "" $host;\n    default "${KRATE_PROXY_PUBLIC_HOST}";\n}' in nginx,
          f'{label}: $krate_redirect_authority is the public authority when set, else $host')
        tls = servers[-1]
        head = tls[:tls.index('    location ')]
        e('    if ($krate_foreign_host) { return 444; }' in head, f'{label}: the HTTPS server must close a foreign-host request (444) before any location')
        e('    if ($krate_path_parameter) { return 400; }' in head, f'{label}: the HTTPS server must refuse a path parameter before any location')
        e(head.index('return 444') < head.index('return 400'), f'{label}: the host check comes first')


RENDER_IMAGE_NOTE: list = []


def check_nginx_render(checks):
    """nginx.conf is a template: render it the way the proxy image does (envsubst with the filter) and run nginx -t, for both modes."""
    e = checks.expect
    template = (ROOT / 'kraft/.env.template').read_text()
    found = re.search(r'^NGINX_IMAGE=(\S+)', template, re.M)
    if found is None:
        e(False, 'kraft/.env.template: NGINX_IMAGE missing')
        return
    image = found.group(1)
    # An air-gapped host cannot resolve the pinned registry reference (docker load keeps no registry
    # digest): KRATE_CHECK_NGINX_IMAGE names the loaded image to render with; the final line says so.
    override = os.environ.get('KRATE_CHECK_NGINX_IMAGE')
    if override:
        known = subprocess.run(['docker', 'image', 'inspect', override], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if not e(known.returncode == 0, f'KRATE_CHECK_NGINX_IMAGE={override!r} is not a local image: {known.stderr.strip()[:120]}'):
            return
        image = override
        RENDER_IMAGE_NOTE.append(f'nginx render image: {override} (KRATE_CHECK_NGINX_IMAGE, in place of the pinned {found.group(1)[:30]}...)')
    with tempfile.TemporaryDirectory() as tmp:
        certs = Path(tmp) / 'certs'
        certs.mkdir()
        made = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=check',
                               '-keyout', str(certs / 'server.key'), '-out', str(certs / 'server.crt')],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if not e(made.returncode == 0, f'openssl could not make a throwaway certificate: {made.stderr.strip()[:120]}'):
            return
        for path in certs.iterdir():
            path.chmod(0o644)
        for edition in EDITIONS:
            for public_host in ('', 'kafka.example.test:8443'):
                result = subprocess.run(['docker', 'run', '--rm', '-v', f'{ROOT / edition / "nginx.conf"}:/etc/nginx/templates/default.conf.template:ro',
                                         '-v', f'{certs}:/etc/nginx/certs:ro', '-e', 'NGINX_ENVSUBST_FILTER=^KRATE_PROXY_',
                                         '-e', f'KRATE_PROXY_PUBLIC_HOST={public_host}', '-e', 'KRATE_PROXY_CONF_SHA=check', image, 'nginx', '-T'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)  # a cold image pull is included
                label = f'{edition}/nginx.conf rendered with KRATE_PROXY_PUBLIC_HOST={public_host!r}'
                if e(result.returncode == 0 and 'syntax is ok' in result.stderr and 'test is successful' in result.stderr,
                     f'{label}: nginx -t must pass; exit {result.returncode}: {result.stderr.strip()[-300:]}'):
                    e(f'map "$http_host {public_host}" $krate_foreign_host' in result.stdout and f'map "{public_host}" $krate_redirect_authority' in result.stdout,
                      f'{label}: the rendered maps must carry the public host literally')
                    e('${KRATE_PROXY_' not in result.stdout, f'{label}: no template variable may survive the render')


def check_identity_dirs(checks):
    """identity up / auth configure create the bind-mounted directories with explicit modes, whatever the umask
    (EPC VM run at 5b803c6: truststores 700 under umask 077 → Keycloak's bootstrap died listing KC_TRUSTSTORE_PATHS)."""
    e = checks.expect
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        e('mkdir -p "$SCRIPT_DIR/auth/keycloak/truststores"' not in cli, f'{edition}/krate: no bare mkdir of the truststores directory (umask-dependent)')
        e('ensure_identity_dirs' in function_body(cli, 'prepare_identity_files'), f'{edition}/krate: prepare_identity_files must call ensure_identity_dirs')
        e(cli.count('  ensure_identity_dirs\n') >= 2, f'{edition}/krate: both the identity and the auth configure paths call ensure_identity_dirs')
    if bash_binary() is None:
        return
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'ensure_identity_dirs') + r'''
SCRIPT_DIR="$1"; umask 077; ensure_identity_dirs
'''
    with tempfile.TemporaryDirectory() as tmp:
        site = Path(tmp)
        result = run_bash(script, site)
        e(result.returncode == 0, f'ensure_identity_dirs failed: {result.stderr.strip()[:160]}')
        for name in ('auth', 'auth/ui', 'auth/keycloak', 'auth/keycloak/truststores'):
            e((site / name).is_dir() and mode(site / name) == 0o755, f'{name} must be 755 under umask 077; got {mode(site / name) if (site / name).exists() else "missing":o}' if (site / name).exists() else f'{name} missing')
        (site / 'auth/keycloak/truststores').chmod(0o700)
        run_bash(script, site)
        e(mode(site / 'auth/keycloak/truststores') == 0o755, 'an existing 700 truststores directory is widened to 755 on the next run')


def check_deploy_release(checks):
    """S2: deploy_release widens only the paths the release archive held; secrets and leftovers keep 0600."""
    e = lambda cond, msg: checks.expect(cond, 'deploy_release: ' + msg)  # noqa: E731
    for edition in EDITIONS:
        body = function_body((ROOT / edition / 'krate').read_text(), 'deploy_release')
        e('find . ' not in body and 'release.list' in body and 'xargs -0 chmod go+rX' in body,
          f'{edition}/krate: read permissions come from the release archive listing (allow-list), not a find over KRATE_HOME')
    if bash_binary() is None:
        return
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'ensure_home_dir', 'import_site_files', 'deploy_release') + r'''
SCRIPT_DIR="$1"; KRATE_HOME="$2"; BROKER_CONTAINER=none
docker() { echo "docker must not be called" >&2; return 1; }
umask 077
deploy_release ""
'''
    with tempfile.TemporaryDirectory() as tmp:
        package, home = Path(tmp) / 'krate-kraft-v9', Path(tmp) / 'home'
        files = {'krate': 0o700, 'docker-compose.yml': 0o600, '.env.template': 0o600, 'nginx.conf': 0o600,
                 'auth/ui/local.yml': 0o600, 'monitoring/docker-compose.yml': 0o600, 'monitoring/.env.template': 0o600,
                 'sso/identity.py': 0o600,
                 # operator leftovers in the package directory: never part of the release
                 '.env.Pk12Lm': 0o600, 'monitoring/.env.Rt34Uv': 0o600, '.identity-backup.Xy12Ab': 0o600,
                 '.env.bak': 0o600, 'monitoring/.env.orig': 0o600}
        for name, file_mode in files.items():
            (package / name).parent.mkdir(parents=True, exist_ok=True)
            (package / name).write_text(name + '\n')
            (package / name).chmod(file_mode)
        for directory in (package, package / 'auth', package / 'auth/ui', package / 'monitoring', package / 'sso'):
            directory.chmod(0o700)
        site = {'.env': 'KAFKA_UI_PASSWORD=synthetic\n', '.env.Ab12Cd': 'KAFKA_UI_PASSWORD=synthetic\n',
                'monitoring/.env': 'GF=1\n', 'monitoring/.env.Qw56Er': 'GF=1\n', '.identity-backup.Zz99Yy': 'sealed\n',
                'site-backup.enc': 'sealed\n', 'certs/server.key': 'key\n', 'auth/keycloak/db-tls/ca.key': 'key\n'}
        for name, text in site.items():
            (home / name).parent.mkdir(parents=True, exist_ok=True)
            (home / name).write_text(text)
            (home / name).chmod(0o600)
        result = run_bash(script, package, home)
        e(result.returncode == 0, f'the extraction must succeed; got {result.returncode}: {result.stderr.strip()[:200]}')
        for name in ('krate', 'docker-compose.yml', '.env.template', 'nginx.conf', 'monitoring/docker-compose.yml', 'monitoring/.env.template', 'sso/identity.py'):
            e((home / name).is_file() and mode(home / name) & 0o044 == 0o044, f'release file {name} must be group/world-readable after a umask-077 install')
        for name in ('auth', 'auth/ui', 'auth/keycloak', 'auth/keycloak/truststores'):
            e((home / name).is_dir() and mode(home / name) & 0o055 == 0o055, f'{name} must be traversable by the container users after a umask-077 install; got {mode(home / name):o}')
        e(mode(home / 'krate') & 0o011 == 0o011, 'krate must stay executable for group/others (X)')
        for name in ('monitoring', 'sso'):
            e(mode(home / name) & 0o055 == 0o055, f'release directory {name} must be group/world-traversable')
        for name in site:
            e(mode(home / name) == 0o600, f'{name} must keep mode 600 (not a release file); got {mode(home / name):o}')
        for name in ('.env.Pk12Lm', 'monitoring/.env.Rt34Uv', '.identity-backup.Xy12Ab', '.env.bak', 'monitoring/.env.orig'):
            e(not (home / name).exists(), f'the package-directory leftover {name} must not be copied into KRATE_HOME')
        e((home / '.env.template').is_file() and mode(home / '.env.template') == 0o644, '.env.template is copied on its own with mode 644')
        e((home / 'auth/ui/local.yml').is_file() and mode(home / 'auth/ui/local.yml') == 0o644, 'auth/ui/local.yml is installed with mode 644')


def rpm_fixture(directory):
    """Stub sudo, dnf, rpm, systemctl, usermod and docker, and a bundle: four Docker RPMs plus optional/."""
    bin_dir, bundle = Path(directory) / 'bin', Path(directory) / 'bundle'
    (bundle / 'optional').mkdir(parents=True)
    bin_dir.mkdir()
    for name in ('containerd.io-1.7.28-1.el9.x86_64.rpm', 'docker-ce-29.0.0-1.el9.x86_64.rpm',
                 'docker-ce-cli-29.0.0-1.el9.x86_64.rpm', 'docker-ce-rootless-extras-29.0.0-1.el9.x86_64.rpm'):
        (bundle / name).write_text('rpm\n')
    for name in ('container-selinux-2.229.0-1.el9.noarch.rpm', 'nftables-1.0.9-3.el9.x86_64.rpm', 'libnftnl-1.2.6-4.el9.x86_64.rpm',
                 'jansson-2.14-1.el9.x86_64.rpm', 'libmnl-1.0.4-16.el9.x86_64.rpm', 'unrelated-tool-1.0-1.el9.x86_64.rpm'):
        (bundle / 'optional' / name).write_text('rpm\n')
    write_tool(bin_dir, 'sudo', 'exec "$@"\n')
    write_tool(bin_dir, 'systemctl', 'exit 0\n')
    write_tool(bin_dir, 'usermod', 'exit 0\n')
    write_tool(bin_dir, 'docker', 'echo "Docker version 29.0.0"\n')
    # dnf fails like dnf 4 on RHEL 9 until every requirement is in the transaction, writing its problem
    # lines only after a pause: the caller must read a complete file, not a file still being written.
    write_tool(bin_dir, 'dnf', r'''echo "dnf $*" >> "$FAKE_LOG"
names=" ${FAKE_HOST_HAS:-} "
for a in "$@"; do case "$a" in *.rpm) b="${a##*/}"; names+="${b%%-[0-9]*} " ;; esac; done
has() { [[ "$names" == *" $1 "* ]]; }
problems=()
has nftables || problems+=("nothing provides nftables >= 1:1.0.5 needed by docker-ce-3:29.0.0-1.el9.x86_64 from @commandline"
                            "nothing provides /usr/sbin/nft needed by docker-ce-rootless-extras-29.0.0-1.el9.x86_64 from @commandline")
if has nftables; then
  has libnftnl || problems+=("nothing provides libnftnl.so.11()(64bit) needed by nftables-1:1.0.9-3.el9.x86_64 from @commandline")
  has jansson || problems+=("nothing provides libjansson.so.4()(64bit) needed by nftables-1:1.0.9-3.el9.x86_64 from @commandline")
fi
if has libnftnl; then has libmnl || problems+=("nothing provides libmnl.so.0()(64bit) needed by libnftnl-1.2.6-4.el9.x86_64 from @commandline"); fi
[[ -z "${FAKE_EXTRA:-}" ]] || problems+=("nothing provides $FAKE_EXTRA needed by docker-ce-3:29.0.0-1.el9.x86_64 from @commandline")
if (( ${#problems[@]} )); then
  echo "Error: " >&2
  sleep 0.3
  for p in "${problems[@]}"; do echo " Problem: conflicting requests" >&2; echo "  - $p" >&2; done
  exit 1
fi
echo "Complete!"
''')
    write_tool(bin_dir, 'rpm', r'''case "$1" in
  -q) exit 1 ;;
  -qp) b="${3##*/}"; n="${b%%-[0-9]*}"
       case "$n" in
         nftables) printf 'nftables = 1:1.0.9-3.el9\nnftables(x86-64) = 1:1.0.9-3.el9\n' ;;
         libnftnl) printf 'libnftnl.so.11()(64bit)\nlibnftnl.so.11(LIBNFTNL_11)(64bit)\nlibnftnl = 1.2.6-4.el9\n' ;;
         jansson) printf 'libjansson.so.4()(64bit)\njansson = 2.14-1.el9\n' ;;
         libmnl) printf 'libmnl.so.0()(64bit)\nlibmnl = 1.0.4-16.el9\n' ;;
         container-selinux) printf 'container-selinux = 2:2.229.0-1.el9\ndocker-selinux = 2:2.229.0-1.el9\n' ;;
         *) echo "$n = 1.0-1.el9" ;;
       esac ;;
  -qpl) case "${2##*/}" in nftables-*) printf '/etc/nftables\n/usr/sbin/nft\n' ;; esac ;;
esac
''')
    return bin_dir, bundle


def makefile_rpm_installer():
    """The standalone install-docker.sh `make docker-rpms` writes, as Make renders it (every $ is $$ in the recipe)."""
    text = (ROOT / 'Makefile').read_text()
    start = text.index('''>cat > "$$output_dir/install-docker.sh" <<'INSTALL_RPM'\n''')
    end = text.index('>INSTALL_RPM\n', start)
    lines = text[start:end].splitlines()[1:]
    raw = '\n'.join(line[1:] if line.startswith('>') else line for line in lines) + '\n'
    return raw, raw.replace('$$', '$')


def check_rpm_install(checks):
    """S3-S6: dnf's errors are read after dnf exits, capabilities map to bundled RPMs over several rounds, both installers agree, the builder is pinned."""
    e = checks.expect
    epc = (ROOT / 'epc/krate').read_text()
    install = function_body(epc, 'docker_install_rpm')
    e('>(' not in install and '2>"$attempt_log"' in install, 'epc/krate: docker_install_rpm must write dnf stderr to the file synchronously (no process substitution)')
    makefile = (ROOT / 'Makefile').read_text()
    optional = re.search(r'^DOCKER_RPM_OPTIONAL := (.*)$', makefile, re.M)
    e(optional is not None and {'container-selinux', 'nftables', 'libnftnl', 'jansson', 'libmnl'} <= set(optional.group(1).split()),
      'Makefile: DOCKER_RPM_OPTIONAL must bundle container-selinux, nftables, libnftnl, jansson and libmnl')
    e(re.search(r'^RHEL_BUILDER_IMAGE \?= rockylinux/rockylinux:9@sha256:[0-9a-f]{64}$', makefile, re.M) is not None,
      "Makefile: RHEL_BUILDER_IMAGE must default to Rocky's maintained image rockylinux/rockylinux:9, pinned by digest")
    e('AlmaLinux' not in makefile, 'Makefile: no stale AlmaLinux builder wording')
    raw, standalone = makefile_rpm_installer()
    e(re.search(r'(?<!\$)\$(?!\$)', raw) is None, 'Makefile: every $ in the install-docker.sh heredoc must be escaped as $$')
    for name in ('rpm_missing_capabilities', 'rpm_providers_of'):
        source = bash_functions(ROOT / 'epc/krate', name)
        e(source in standalone, f'Makefile install-docker.sh: {name} must be identical to its epc/krate copy')
    e('>(' not in standalone and '2>"$attempt_log"' in standalone, 'Makefile install-docker.sh: dnf stderr must be written to the file synchronously')
    if bash_binary() is None:
        return
    krate_script = BASH_STUBS + bash_functions(ROOT / 'epc/krate', 'rpm_missing_capabilities', 'rpm_providers_of', 'docker_install_rpm') + '\ndocker_install_rpm "$1"\n'
    wanted = ['nftables-1.0.9-3.el9.x86_64.rpm', 'libnftnl-1.2.6-4.el9.x86_64.rpm', 'jansson-2.14-1.el9.x86_64.rpm', 'libmnl-1.0.4-16.el9.x86_64.rpm']
    for label, run in (('epc/krate docker-install', lambda where, variables, tools: run_bash(krate_script, where, env=variables, path_dir=tools)),
                       ('Makefile install-docker.sh', None)):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir, bundle = rpm_fixture(tmp)
            if run is None:
                (bundle / 'install-docker.sh').write_text(standalone)
                (bundle / 'install-docker.sh').chmod(0o755)
                run = lambda where, variables, tools: run_bash('exec bash "$1/install-docker.sh" --yes', where, env=variables, path_dir=tools)  # noqa: E731
            log = Path(tmp) / 'dnf.log'
            env = dict(os.environ, FAKE_LOG=str(log))
            result = run(bundle, env, bin_dir)
            calls = log.read_text().splitlines() if log.exists() else []
            e(result.returncode == 0, f'{label}: must resolve nftables -> libnftnl, jansson -> libmnl over three rounds; got {result.returncode}: {result.stderr.strip()[-300:]}')
            e(len(calls) == 4, f'{label}: one install plus three resolution rounds; got {len(calls)} dnf calls')
            last = calls[-1] if calls else ''
            e(all(name in last for name in wanted), f'{label}: the final transaction must add {wanted}; got {last[-300:]!r}')
            e('container-selinux' not in last and 'unrelated-tool' not in last,
              f'{label}: a bundled package no capability named (container-selinux on a host that has it) is never added')
            e(len(calls) > 1 and calls[1].count('nftables-1.0.9') == 1,
              f'{label}: nftables, named both as a capability and as /usr/sbin/nft, is added once')
            log.unlink(missing_ok=True)
            result = run(bundle, dict(env, FAKE_EXTRA='libfoo.so.1()(64bit)'), bin_dir)
            e(result.returncode == 1 and 'libfoo.so.1()(64bit)' in result.stderr,
              f'{label}: a capability no bundled package provides is named in the failure; got {result.returncode}: {result.stderr.strip()[-200:]}')
            log.unlink(missing_ok=True)
            result = run(bundle, dict(env, FAKE_EXTRA='libfoo.so.1()(64bit)', FAKE_HOST_HAS='nftables libnftnl jansson libmnl'), bin_dir)
            calls = log.read_text().splitlines() if log.exists() else []
            e(result.returncode == 1 and 'lacks libfoo.so.1()(64bit)' in result.stderr and len(calls) == 1,
              f'{label}: with nothing bundled to add, it stops after the first attempt naming the missing capability; got {result.returncode}, {len(calls)} calls: {result.stderr.strip()[-200:]}')


def check_gen_cert_ip(checks):
    """S7: gen-cert gives an IP-literal public host an iPAddress SAN; the preflight checks an IP host with -checkip."""
    e = checks.expect
    if bash_binary() is not None:
        script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'env_value', 'get_fqdn', 'public_url_host', 'san_entry', 'cmd_gen_cert') + r'''
ENV_FILE="$1/.env"; CERTS_DIR="$1/certs"; CERT_CRT="$CERTS_DIR/server.crt"; CERT_KEY="$CERTS_DIR/server.key"
hostname() { return 1; }
cmd_gen_cert >/dev/null
openssl x509 -in "$CERT_CRT" -noout -ext subjectAltName
'''
        for url, expected_ip, expected_dns in (('https://10.1.2.3/identity', '10.1.2.3', None),
                                               ('https://[fd00::5]:8443/identity', 'fd00::5', None),
                                               ('https://kafka.example.test/identity', None, 'kafka.example.test')):
            with tempfile.TemporaryDirectory() as tmp:
                write_env(Path(tmp), {'KAFKA_UI_FQDN': 'broker.example.test', 'KEYCLOAK_PUBLIC_URL': url})
                result = run_bash(script, tmp)
                entries = {entry.strip() for line in result.stdout.splitlines()[1:] for entry in line.split(',') if entry.strip()}
                ips = {ipaddress.ip_address(entry.partition(':')[2].strip()) for entry in entries if entry.startswith('IP Address:')}
                dns = {entry[len('DNS:'):] for entry in entries if entry.startswith('DNS:')}
                e(result.returncode == 0, f'gen-cert for {url} failed: {result.stderr.strip()[:200]}')
                if expected_ip:
                    e(ipaddress.ip_address(expected_ip) in ips and expected_ip not in dns and f'[{expected_ip}]' not in dns,
                      f'gen-cert for {url}: the public host must be an IP SAN, not DNS; got {sorted(entries)}')
                else:
                    e(expected_dns in dns, f'gen-cert for {url}: the public host must be a DNS SAN; got {sorted(entries)}')
                e({'broker.example.test', 'localhost'} <= dns, f'gen-cert for {url}: the FQDN and localhost stay covered; got {sorted(entries)}')
    preflight_source = (ROOT / 'sso/preflight.py').read_text()
    e("'-checkip'" in preflight_source, 'sso/preflight.py: an IP-literal public host must be checked with openssl -checkip')
    for public, san, accepted in (('10.1.2.3', 'IP:10.1.2.3', True), ('10.1.2.3', 'DNS:10.1.2.3', False),
                                  ('[fd00::5]', 'IP:fd00::5', True), ('[fd00::5]', 'DNS:fd00::5', False)):
        with tempfile.TemporaryDirectory() as tmp:
            overrides = {'KAFKA_UI_AUTH_CONFIG': 'runtime.yml', 'KEYCLOAK_PUBLIC_URL': f'https://{public}/identity'}
            site = synthetic_site('kraft', tmp, **overrides)
            self_signed(site / 'certs', 'krate', san=san)
            with contextlib.redirect_stdout(io.StringIO()):
                identity.runtime_plan(site / '.env', CLUSTERS, site / 'auth/ui/runtime.yml')
            planned, _ = run_plan(site)
            code, rendered = compose_config(site / '.env', 'kraft', project_dir=site)
            if not e(planned.returncode == 0 and code == 0, f'IP public host {public}: plan or Compose rendering failed'):
                continue
            result = preflight(site, 'runtime.yml', rendered)
            if accepted:
                e(result.returncode == 0, f'preflight must accept a certificate with {san} for public host {public}; got {result.returncode}: {result.stderr.strip()}')
            else:
                e(result.returncode == 1 and 'does not cover the public hostname' in result.stderr,
                  f'preflight must refuse a certificate with only {san} for the IP host {public}; got {result.returncode}: {result.stderr.strip()}')


def check_renew_db_tls_order(checks):
    """S8: with a renewed CA, .prev is discarded only after Keycloak is healthy and accepts the admin login; a failure rolls both back."""
    e = checks.expect
    if bash_binary() is None:
        return
    for edition in EDITIONS:
        script = BASH_STUBS + bash_functions(ROOT / edition / 'krate', 'identity_tls_rollback', 'cmd_identity_renew_db_tls') + r'''
SCRIPT_DIR=/site; IDENTITY_TIMEOUT=1
log() { echo "$*" >> "$CALLS"; }
prepare_identity_env() { :; }; require_env() { :; }; identity_lock() { :; }
identity_state() { echo existing; }
identity_container() { echo "cid-$1"; }
container_status() { echo running; }
sso_dir() { echo /sso; }
env_value() { echo admin; }
identity_ready() { return 0; }
python3() { log "python3 $*"; if [[ "$*" == *--renew-server* ]]; then if [[ -n "${SAME_CA:-}" ]]; then echo "renewed server certificate, valid until Jan 1 00:00:00 2030 GMT"; else echo "renewed CA and server certificate, valid until Jan 1 00:00:00 2030 GMT"; fi; fi; }
identity_compose() { log "compose $*"; }
identity_health_wait() { log "wait $1"; [[ " ${FAIL_WAIT:-} " != *" $1 "* ]]; }
identity_wait_healthy() { log "wait-or-die $1"; }
kcadm_login() { log "login $1 $3"; return "${LOGIN_RC:-0}"; }
kcadm_logout() { :; }
identity_verify_admin() { log "verify-admin"; }
identity_journal() { log "journal $*"; }
cmd_identity_renew_db_tls
'''
        for case, overrides, succeeds in (('success', {}, True), ('keycloak unhealthy', {'FAIL_WAIT': 'keycloak'}, False),
                                          ('admin login refused', {'LOGIN_RC': '1'}, False),
                                          ('database unhealthy', {'FAIL_WAIT': 'keycloak-db'}, False),
                                          ('same CA', {'SAME_CA': '1'}, True)):
            with tempfile.TemporaryDirectory() as tmp:
                calls_file = Path(tmp) / 'calls'
                result = run_bash(script, env=dict(os.environ, CALLS=str(calls_file), **overrides))
                calls = calls_file.read_text().splitlines() if calls_file.exists() else []
                discard = next((i for i, line in enumerate(calls) if '--discard-previous' in line), None)
                rollback = next((i for i, line in enumerate(calls) if '--rollback' in line), None)
                label = f'{edition}/krate renew-db-tls with a renewed CA ({case})'
                if case == 'same CA':
                    # Keycloak's trust is unchanged: the database's health settles it, .prev goes before the
                    # readiness poll, and Keycloak is neither restarted nor logged into.
                    e(result.returncode == 0 and discard is not None and rollback is None
                      and 'compose restart --no-deps keycloak-db' in calls and 'wait keycloak-db' in calls
                      and calls.index('wait keycloak-db') < discard
                      and not any(line.startswith('login ') or line == 'compose restart --no-deps keycloak' for line in calls),
                      f'{edition}/krate renew-db-tls with the same CA: restart keycloak-db, wait, discard .prev, no Keycloak restart or login; got {calls}')
                    continue
                if succeeds:
                    steps = ('compose restart --no-deps keycloak-db', 'wait keycloak-db', 'compose restart --no-deps keycloak',
                             'wait keycloak', 'login master admin')
                    order = [calls.index(step) for step in steps if step in calls]
                    e(result.returncode == 0 and len(order) == len(steps) and order == sorted(order) and discard is not None
                      and discard > order[-1] and rollback is None,
                      f'{label}: restart keycloak-db, then Keycloak, health, admin login, and only then discard .prev; got {calls}')
                    continue
                e(result.returncode == 1 and discard is None and rollback is not None and any('journal renew-db-tls rolled back' in line for line in calls),
                  f'{label}: must roll back, keep no discard and journal the rollback; got rc {result.returncode} {calls}')
                after = calls[rollback + 1:] if rollback is not None else []
                expected = ['compose restart --no-deps keycloak-db', 'wait keycloak-db']
                if case != 'database unhealthy':
                    expected += ['compose restart --no-deps keycloak', 'wait keycloak']
                e(after[:len(expected)] == expected, f'{label}: after the rollback the services restart on the previous files in order {expected}; got {after}')


def check_summaries(checks):
    """S9: the realm summary receives a copy without credential keys; the Kafbat summary is built from the
    plan's inputs and never touches the rendered plan (CodeQL alert 4: the plan holds the client-secret placeholder)."""
    e = checks.expect
    import inspect
    body = inspect.getsource(identity.summary)
    first = [line.strip() for line in body.splitlines()[1:] if line.strip() and not line.strip().startswith(('"""', "'''"))]
    e(bool(first) and first[0] == 'data = without_credentials(data)',
      'sso/identity.py: summary() must start with data = without_credentials(data) (CodeQL clear-text logging)')
    runtime_body = inspect.getsource(identity.runtime_summary)
    e(runtime_body.startswith('def runtime_summary(values, path, outcome):') and 'data' not in runtime_body
      and 'UI_SECRET' not in runtime_body and "'client-secret'" not in runtime_body,
      'sso/identity.py: runtime_summary() takes the runtime_settings() values, never the rendered plan')
    plan_body = inspect.getsource(identity.runtime_plan)
    e('print(runtime_summary(values, path,' in plan_body, 'sso/identity.py: runtime_plan prints runtime_summary(values, ...), not the plan data')

    def keys(value):
        if isinstance(value, dict):
            return set(value) | {key for item in value.values() for key in keys(item)}
        if isinstance(value, list):
            return {key for item in value for key in keys(item)}
        return set()

    seen = []
    original = identity.without_credentials

    def spy(data):
        result = original(data)
        if isinstance(data, dict):  # the top-level call: what the summary works on from here
            seen.append((sorted(data)[:3], result))
        return result

    identity.without_credentials = spy
    try:
        with tempfile.TemporaryDirectory() as tmp:
            site = synthetic_site('kraft', tmp)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                identity.plan(site / '.env', site / 'realm.json')
                identity.runtime_plan(site / '.env', CLUSTERS, site / 'runtime.yml')
    finally:
        identity.without_credentials = original
    realm_copies = [result for _, result in seen if isinstance(result, dict) and 'clients' in result]
    e(bool(realm_copies), 'identity.plan must pass its data through without_credentials before summarising')
    printed = out.getvalue()
    e('Kafbat plan:' in printed and 'client-secret' not in printed and '${' not in printed
      and not any(secret in printed for secret in SYNTHETIC_SECRETS),
      'the printed Kafbat summary carries neither a secret value nor the client-secret placeholder')
    for result in realm_copies:
        leaked = {key for key in keys(result) if 'secret' in key.lower() or 'password' in key.lower()}
        e(not leaked, f'a summary received credential keys {sorted(leaked)}')


def check_realm_reconcile(checks):
    """S10: identity up and restore reconcile otpPolicyLookAheadWindow on the realm and frontchannelLogout on krate-ui."""
    e = checks.expect
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        up = function_body(cli, 'cmd_identity_up')
        restore = function_body(cli, 'cmd_identity_restore')
        e('identity_reconcile_ui_urls\n    identity_reconcile_realm_policy up' in up,
          f'{edition}/krate: identity up must reconcile the realm policy on an existing realm')
        e('identity_reconcile_realm_policy restore' in restore
          and restore.index('identity_reconcile_realm_policy restore') < restore.index('identity_journal restore ok'),
          f'{edition}/krate: restore must reconcile the realm policy before reporting success')
    plan = identity.realm(identity.settings(site_env('kraft')))
    e(plan.get('otpPolicyLookAheadWindow') == 1 and next(c for c in plan['clients'] if c['clientId'] == identity.UI_CLIENT).get('frontchannelLogout') is False,
      'the realm plan states otpPolicyLookAheadWindow 1 and krate-ui frontchannelLogout false')
    if bash_binary() is None:
        return
    ui = next(c for c in plan['clients'] if c['clientId'] == identity.UI_CLIENT)
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'identity_reconcile_ui_urls', 'identity_reconcile_realm_policy') + r'''
SCRIPT_DIR="$1"; IDENTITY_REALM=krate; IDENTITY_CHANGED=false
log() { echo "$*" >> "$CALLS"; }
env_value() { echo admin; }
kcadm_login() { :; }; kcadm_logout() { :; }
kcadm_client_id() { echo id-1; }
identity_journal() { log "journal $*"; }
kcadm() {
  shift
  case "$1 $2" in
    "get realms/krate") echo "$CUR_WINDOW" ;;
    "update realms/krate") log "update realm ${*:3}" ;;
    "get clients/id-1") echo "$CUR_CLIENT" ;;
    "update clients/id-1") log "update client $(cat)" ;;
    "get authentication/required-actions/CONFIGURE_TOTP") echo "$CUR_TOTP" ;;
    "get authentication/required-actions/UPDATE_PASSWORD") echo '{"alias":"UPDATE_PASSWORD","name":"Update Password","providerId":"UPDATE_PASSWORD","enabled":true,"defaultAction":false,"priority":30,"config":{}}' ;;
    "update authentication/required-actions/CONFIGURE_TOTP") log "update totp ${*:3} $(cat)" ;;
    *) log "unexpected kcadm $*"; return 1 ;;
  esac
}
identity_reconcile_ui_urls "$2"
identity_reconcile_realm_policy "$2"
'''
    with tempfile.TemporaryDirectory() as tmp:
        site = Path(tmp)
        (site / 'auth/keycloak').mkdir(parents=True)
        (site / 'auth/keycloak/krate-realm.json').write_text(identity.render(plan))
        for window, frontchannel, totp_default, command in (('0', True, True, 'up'), ('1', False, False, 'restore'), ('0', False, True, 'restore')):
            calls_file = site / 'calls'
            calls_file.unlink(missing_ok=True)
            client = {'redirectUris': ui['redirectUris'], 'webOrigins': ui['webOrigins'], 'frontchannelLogout': frontchannel,
                      'attributes': ui['attributes']}
            # A Phase 1 realm: CONFIGURE_TOTP is a default action; the full representation is what Keycloak returns.
            totp = {'alias': 'CONFIGURE_TOTP', 'name': 'Configure OTP', 'providerId': 'CONFIGURE_TOTP', 'enabled': True,
                    'defaultAction': totp_default, 'priority': 10, 'config': {}}
            result = run_bash(script, site, command, env=dict(os.environ, CALLS=str(calls_file), CUR_WINDOW=window, CUR_CLIENT=json.dumps(client),
                                                              CUR_TOTP=json.dumps(totp)))
            calls = calls_file.read_text().splitlines() if calls_file.exists() else []
            label = f'{command} with look-ahead {window}, frontchannelLogout {frontchannel}, CONFIGURE_TOTP default {totp_default}'
            e(result.returncode == 0 and not any(line.startswith('unexpected') for line in calls), f'{label}: failed: {result.stderr.strip()[:200]} {calls}')
            realm_update = [line for line in calls if line.startswith('update realm')]
            e(realm_update == (['update realm -s otpPolicyLookAheadWindow=1'] if window == '0' else []),
              f'{label}: the realm look-ahead window must be set to 1 exactly when it differs; got {realm_update}')
            e((f'journal {command} reconciled realm policy' in calls) == (window == '0'),
              f'{label}: the journal records "{command} reconciled realm policy" exactly when the policy changed; got {calls}')
            client_update = [line for line in calls if line.startswith('update client')]
            e(bool(client_update) == frontchannel and all('"frontchannelLogout": false' in line for line in client_update),
              f'{label}: krate-ui is updated with frontchannelLogout false exactly when Keycloak has it on; got {client_update}')
            totp_update = [line for line in calls if line.startswith('update totp')]
            e(bool(totp_update) == totp_default, f'{label}: CONFIGURE_TOTP is updated exactly when it is still a default action; got {totp_update}')
            for line in totp_update:
                body = json.loads(line[line.index('{'):])
                e(line.split('{')[0].split() == ['update', 'totp', '-r', 'krate', '-f', '-'], f'{label}: the required action is PUT from a file without -n; got {line[:60]!r}')
                e(body == dict(totp, defaultAction=False),
                  f'{label}: the PUT carries the FULL representation (alias, name, providerId, priority kept) with defaultAction false; got {body}')
            e((f'journal {command} reconciled required action CONFIGURE_TOTP' in calls) == totp_default,
              f'{label}: the journal records the required-action reconcile exactly when it changed; got {calls}')


FAKE_KCADM = r'''
import json, os, sys, uuid
# A stand-in for kcadm.sh over a JSON state file: the endpoints identity_apply_idp uses, with Keycloak's observed
# shapes (fixture krate-p3, 26.8.0): GET flows lists top-level flows; a new execution is DISABLED/priority 0;
# executions are listed recursively with level; the provider's clientSecret reads back masked.
state_file, calls_file = os.environ['KC_STATE'], os.environ['KC_CALLS']
state = json.load(open(state_file))
args = sys.argv[1:]
with open(calls_file, 'a') as log:
    log.write(json.dumps(args) + '\n')
command, path = args[0], args[1]
opts = args[2:]
# Failure injection for the tests: KC_FAIL_GET (prefix) makes a GET exit 1 with an error line; KC_EMPTY_GET makes it print nothing.
if command == 'get' and os.environ.get('KC_FAIL_GET') and path.startswith(os.environ['KC_FAIL_GET']):
    print('HTTP error - 503 Service Unavailable', file=sys.stderr)
    sys.exit(1)
if command == 'get' and os.environ.get('KC_EMPTY_GET') and path.startswith(os.environ['KC_EMPTY_GET']):
    sys.exit(0)
def setting(key):
    for index, item in enumerate(opts):
        if item == '-s' and opts[index + 1].startswith(key + '='):
            value = opts[index + 1][len(key) + 1:]
            try:
                return json.loads(value)
            except ValueError:
                return value
    return None
def body():
    return json.load(sys.stdin) if '-f' in opts else None
def fields(items):
    if '--fields' not in opts:
        return items
    names = opts[opts.index('--fields') + 1].split(',')
    if '--format' in opts:
        return '\n'.join(','.join(str(item.get(name, '')) for name in names) for item in items)
    return [{name: item.get(name) for name in names} for item in items]
def out(value):
    if isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value))
def save():
    json.dump(state, open(state_file, 'w'))
def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)
def flow_by_alias(alias):
    return next((f for f in state['flows'] if f['alias'] == alias), None)
def listing(flow, level=0, result=None):
    result = [] if result is None else result
    for index, e in enumerate(sorted(flow['executions'], key=lambda e: (e['priority'], e['index']))):
        item = {'id': e['id'], 'requirement': e['requirement'], 'level': level, 'index': index, 'priority': e['priority']}
        if e.get('flowAlias'):
            item.update({'authenticationFlow': True, 'displayName': e['flowAlias'], 'flowId': flow_by_alias(e['flowAlias'])['id']})
            result.append(item)
            listing(flow_by_alias(e['flowAlias']), level + 1, result)
        else:
            item['providerId'] = e['providerId']
            if e.get('config'):
                item['authenticationConfig'] = e['config']
            result.append(item)
    return result
def remove_flow(flow):
    for e in flow['executions']:
        if e.get('flowAlias'):
            remove_flow(flow_by_alias(e['flowAlias']))
    state['flows'].remove(flow)
parts = path.split('/')
if path == 'identity-provider/instances/pingfederate' and command == 'get':
    p = state.get('provider')
    if not p:
        fail('Resource not found for url: .../identity-provider/instances/pingfederate')
    out(dict(p, internalId='internal-1', types=['USER_AUTHENTICATION'], config=dict(p['config'], clientSecret='**********')))
elif path == 'identity-provider/instances' and command == 'create':
    p = body()
    if state.get('provider'):
        fail('Identity Provider pingfederate already exists')
    if flow_by_alias(p['firstBrokerLoginFlowAlias']) is None:
        fail('No available authentication flow with alias: ' + p['firstBrokerLoginFlowAlias'])
    state['provider'] = p; state['mappers'] = []; save()
elif path == 'identity-provider/instances/pingfederate' and command == 'update':
    p = body(); state['provider'].update(p); save()
elif path == 'identity-provider/instances/pingfederate' and command == 'delete':
    state['provider'] = None; state['mappers'] = []; save()
elif path == 'identity-provider/instances/pingfederate/mappers' and command == 'get':
    out(fields(state['mappers']))
elif path == 'identity-provider/instances/pingfederate/mappers' and command == 'create':
    m = body(); m['id'] = str(uuid.uuid4()); state['mappers'].append(m); save()
elif path.startswith('identity-provider/instances/pingfederate/mappers/') and command == 'update':
    m = body(); current = next(x for x in state['mappers'] if x['id'] == parts[-1]); current.update(m); save()
elif path.startswith('identity-provider/instances/pingfederate/mappers/') and command == 'delete':
    state['mappers'] = [x for x in state['mappers'] if x['id'] != parts[-1]]; save()
elif path == 'authentication/flows' and command == 'get':
    out(fields([f for f in state['flows'] if f['topLevel']]))
elif path == 'authentication/flows' and command == 'create':
    f = body(); state['flows'].append({'id': str(uuid.uuid4()), 'alias': f['alias'], 'description': f.get('description', ''),
                                      'providerId': f.get('providerId', 'basic-flow'), 'topLevel': True, 'executions': []}); save()
elif path.startswith('authentication/flows/') and parts[-1] == 'executions' and command == 'get':
    import urllib.parse
    flow = flow_by_alias(urllib.parse.unquote(parts[2]))
    if flow is None:
        fail('Resource not found')
    out(fields(listing(flow)))
elif path.startswith('authentication/flows/') and parts[-1] == 'executions' and command == 'update':
    assert '-n' in opts, 'executions update needs -n'
    for flow in state['flows']:
        for e in flow['executions']:
            if e['id'] == setting('id'):
                e['requirement'] = setting('requirement'); e['priority'] = int(setting('priority')); save(); sys.exit(0)
    fail('Illegal execution')
elif path.startswith('authentication/flows/') and parts[-1] in ('execution', 'flow') and command == 'create':
    import urllib.parse
    parent = flow_by_alias(urllib.parse.unquote(parts[2]))
    execution = {'id': str(uuid.uuid4()), 'requirement': 'DISABLED', 'priority': 0, 'index': len(parent['executions'])}
    if parts[-1] == 'flow':
        assert setting('type') == 'basic-flow' and setting('provider') == 'basic-flow', 'sub-flow create needs type and provider basic-flow'
        state['flows'].append({'id': str(uuid.uuid4()), 'alias': setting('alias'), 'description': setting('description') or '',
                               'providerId': 'basic-flow', 'topLevel': False, 'executions': []})
        execution['flowAlias'] = setting('alias')
    else:
        execution['providerId'] = setting('provider')
    parent['executions'].append(execution); save()
    print("Created new execution with id '%s'" % execution['id'], file=sys.stderr)
elif path.startswith('authentication/flows/') and command == 'delete':
    remove_flow(next(f for f in state['flows'] if f['id'] == parts[-1])); save()
elif path.startswith('authentication/executions/') and parts[-1] == 'config' and command == 'create':
    c = body(); c['id'] = str(uuid.uuid4()); state['configs'][c['id']] = c
    for flow in state['flows']:
        for e in flow['executions']:
            if e['id'] == parts[2]:
                e['config'] = c['id']
    save()
elif path.startswith('authentication/executions/') and command == 'delete':
    for flow in state['flows']:
        flow['executions'] = [e for e in flow['executions'] if e['id'] != parts[-1]]
    save()
elif path.startswith('authentication/config/') and command == 'get':
    out(state['configs'][parts[-1]])
elif path.startswith('authentication/config/') and command == 'update':
    c = body(); state['configs'][parts[-1]].update(c); save()
elif path == 'realms/krate' and command == 'get':
    out(fields([{'browserFlow': state['browserFlow']}]))
elif path == 'realms/krate' and command == 'update':
    if flow_by_alias(setting('browserFlow')) is None:
        fail('Illegal browserFlow')
    state['browserFlow'] = setting('browserFlow'); save()
else:
    fail('unexpected kcadm call: ' + ' '.join(args))
'''

APPLY_FUNCTIONS = ('env_value', 'url_path_encode', 'json_field', 'identity_apply_idp', 'identity_apply_idp_plan', 'identity_apply_flow',
                   'identity_put_idp_provider', 'identity_find_execution', 'identity_remove_idp')


def flow_shape(state, alias):
    """(name, requirement, priority, config alias) of the level-0 executions of a flow in the fake realm, in priority order."""
    flow = next((f for f in state['flows'] if f['alias'] == alias), None)
    if flow is None:
        return None
    return [(e.get('flowAlias') or e.get('providerId'), e['requirement'], e['priority'],
             state['configs'].get(e.get('config', ''), {}).get('alias')) for e in sorted(flow['executions'], key=lambda e: e['priority'])]


def check_broker_apply(checks):
    """identity_apply_idp against a stand-in kcadm: creates the planned realm pieces, is idempotent, repairs drift, removes without the plan."""
    e = checks.expect
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        e('identity_apply_idp apply' in (ROOT / 'sso/activate.sh').read_text(), 'sso/activate.sh: apply must call identity_apply_idp apply')
        up = function_body(cli, 'cmd_identity_up')
        e('identity_verify_cli up\n' in up and up.index('identity_apply_idp up') > up.index('identity_verify_cli up'),
          f'{edition}/krate: identity up must apply the broker plan after the realm is verified')
        declared = re.search(r"IDENTITY_USER_ACTIONS='(\[.*?\])'", cli)
        e(declared is not None and json.loads(declared.group(1)) == identity.USER_REQUIRED_ACTIONS
          and 'kcadm -- update "users/$uid" -r "$IDENTITY_REALM" -s "requiredActions=$IDENTITY_USER_ACTIONS"' in function_body(cli, 'identity_set_temp_password'),
          f'{edition}/krate: users add/reset-password must assign exactly identity.USER_REQUIRED_ACTIONS to the user')
        add = cli[cli.index('\n    add)\n      uid='):cli.index('identity_journal "users add"')]
        e('identity_set_temp_password "$user" "$uid"' in add, f'{edition}/krate: users add sets the temporary password and required actions on the created user')
        # -n (no-merge PUT) only where Keycloak's CLI guide uses it: the executions path and the user-group membership path.
        for line in cli.splitlines():
            if 'kcadm' in line and re.search(r'\s-n(\s|$)', line):
                e('executions' in line or 'users/$uid/groups/$gid' in line, f'{edition}/krate: -n is used outside the executions/group paths: {line.strip()[:90]}')
        e('required-actions' not in ''.join(l for l in cli.splitlines() if re.search(r'\s-n(\s|$)', l)),
          f'{edition}/krate: required-actions must never be updated with -n (it replaces the representation)')
        # kcadm inside `while read` loops: the helper's default branch gives docker exec /dev/null (an -i exec eats the loop's stdin).
        kcadm_helper = function_body(cli, 'kcadm')
        e('/opt/keycloak/bin/kcadm.sh "$@" --config "$KCADM_CONFIG" </dev/null' in kcadm_helper and kcadm_helper.count('docker exec -i') == 1
          and kcadm_helper.index('docker exec -i') < kcadm_helper.index('</dev/null'),
          f'{edition}/krate: kcadm must read stdin only with KCADM_STDIN=1 and otherwise exec with </dev/null')
        for name in ('identity_apply_idp', 'identity_apply_idp_plan', 'identity_apply_flow', 'identity_remove_idp', 'identity_put_idp_provider', 'identity_rotate_ping_secret'):
            e('docker ' not in function_body(cli, name), f'{edition}/krate: {name} must go through the kcadm helper, never docker exec directly')
        e('--with-secret \\\n      | KCADM_STDIN=1 kcadm -- create identity-provider/instances' in cli
          and '--with-secret \\\n      | KCADM_STDIN=1 kcadm -- update "identity-provider/instances/$IDENTITY_IDP_ALIAS"' in cli,
          f'{edition}/krate: the provider with its secret reaches kcadm through stdin (-f -), never an argument')
        # B2: every comparison verdict is captured with || die and consumed by a case that refuses anything but same/differs.
        for verdict in ('provider-differs', 'mapper-differs', 'config-differs'):
            e(re.search(r'verdict="\$\((?:[^\n]*\\\n)*[^\n]*' + verdict + r'[^\n]*\)"( \\\n\s*)?\s*\|\| die', cli) is not None,
              f'{edition}/krate: the {verdict} verdict must be captured with || die')
            e(f'identity.py" broker --plan "$plan" {verdict}' in cli and f'== differs' not in cli.split(verdict)[1].split('\n')[0],
              f'{edition}/krate: {verdict} must not be compared inside [[ ]]')
        e(cli.count('*) die "Unexpected comparison result') == 3, f'{edition}/krate: each verdict case must refuse an unexpected result; got {cli.count("*) die \"Unexpected comparison result")}')
        e('PING_KEYCLOAK_CLIENT_SECRET="$(env_value PING_KEYCLOAK_CLIENT_SECRET)" python3' in cli,
          f'{edition}/krate: the secret enters identity.py broker through the environment of that process only')
    if bash_binary() is None:
        return
    plan = load_configure_dual().configs(json.loads((ROOT / 'sso/dual-example.json').read_text()), SYNTHETIC)['keycloak/pingfederate-idp.json']
    secret = RUNTIME_SITE['PING_KEYCLOAK_CLIENT_SECRET']
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', *APPLY_FUNCTIONS) + r'''
SCRIPT_DIR="$1"; ENV_FILE="$1/.env"; IDENTITY_REALM=krate; IDENTITY_CHANGED=false
IDENTITY_IDP_PLAN=auth/keycloak/pingfederate-idp.json; IDENTITY_IDP_ALIAS=pingfederate; IDENTITY_IDP_CHANGES=()
sso_dir() { echo "$SSO_DIR"; }
kcadm_login() { echo "login $*" >> "$KC_CALLS"; }
kcadm_logout() { :; }
identity_journal() { printf '%s %s %s\n' "$1" "$2" "$3" >> "$JOURNAL"; }
kcadm() {
  local -a names=()
  while [[ $# -gt 0 && "$1" != -- ]]; do export "$1"; names+=("${1%%=*}"); shift; done
  shift
  if [[ "${KCADM_STDIN:-}" == 1 ]]; then python3 -I "$FAKE" "$@"; else python3 -I "$FAKE" "$@" </dev/null; fi
}
identity_apply_idp "$2"
echo "changed=$IDENTITY_CHANGED"
'''
    with tempfile.TemporaryDirectory() as tmp:
        site = Path(tmp)
        (site / 'auth/keycloak').mkdir(parents=True)
        plan_file = site / 'auth/keycloak/pingfederate-idp.json'
        plan_file.write_text(json.dumps(plan, indent=2) + '\n')
        fake = site / 'fake_kcadm.py'
        fake.write_text(FAKE_KCADM)
        state_file, calls_file, journal = site / 'state.json', site / 'calls.log', site / 'journal.log'
        realm = {'provider': None, 'mappers': [], 'flows': [{'id': 'browser-id', 'alias': 'browser', 'topLevel': True, 'executions': []},
                                                             {'id': 'fbl-id', 'alias': 'first broker login', 'topLevel': True, 'executions': []}],
                 'configs': {}, 'browserFlow': 'browser'}
        state_file.write_text(json.dumps(realm))

        def run(command='apply', env_secret=secret, **extra):
            calls_file.write_text('')
            write_env(site, dict(SYNTHETIC, PING_KEYCLOAK_CLIENT_SECRET=env_secret))
            environment = dict(os.environ, KC_STATE=str(state_file), KC_CALLS=str(calls_file), JOURNAL=str(journal), FAKE=str(fake), SSO_DIR=str(ROOT / 'sso'), **extra)
            environment.pop('PING_KEYCLOAK_CLIENT_SECRET', None)
            outcome = run_bash(script, site, command, env=environment)
            calls = [json.loads(line) for line in calls_file.read_text().splitlines() if line.startswith('[')]
            return outcome, calls, json.loads(state_file.read_text())

        def mutating(calls):
            return [c for c in calls if c[0] in ('create', 'update', 'delete')]

        result, calls, state = run()
        label = 'apply on an empty realm'
        e(result.returncode == 0, f'{label}: failed: {result.stderr.strip()[:300]} {result.stdout.strip()[-300:]}')
        e(flow_shape(state, 'krate browser') == [('auth-cookie', 'ALTERNATIVE', 10, None), ('identity-provider-redirector', 'ALTERNATIVE', 20, 'PingFederate redirect'),
                                                 ('krate forms', 'ALTERNATIVE', 30, None)],
          f'{label}: krate browser must be cookie ALT 10, redirector ALT 20 (configured), krate forms ALT 30; got {flow_shape(state, "krate browser")}')
        e(flow_shape(state, 'krate forms') == [('auth-username-password-form', 'REQUIRED', 10, None), ('krate otp', 'CONDITIONAL', 20, None)],
          f'{label}: krate forms must be the password form REQUIRED 10 and krate otp CONDITIONAL 20; got {flow_shape(state, "krate forms")}')
        e(flow_shape(state, 'krate otp') == [('conditional-user-configured', 'REQUIRED', 10, None), ('auth-otp-form', 'REQUIRED', 20, None)],
          f'{label}: krate otp must be condition REQUIRED 10 and OTP form REQUIRED 20; got {flow_shape(state, "krate otp")}')
        e(flow_shape(state, 'krate first broker login') == [('idp-create-user-if-unique', 'REQUIRED', 10, None)],
          f'{label}: krate first broker login must be Create User If Unique REQUIRED 10; got {flow_shape(state, "krate first broker login")}')
        e({f['alias']: f['topLevel'] for f in state['flows'] if f['alias'].startswith('krate')} == {'krate browser': True, 'krate forms': False, 'krate otp': False,
                                                                                                   'krate first broker login': True},
          f'{label}: sub-flows are created through their parent (not top-level); got {[(f["alias"], f["topLevel"]) for f in state["flows"]]}')
        e([c['config'] for c in state['configs'].values()] == [{'defaultProvider': 'pingfederate'}], f'{label}: one redirector configuration; got {state["configs"]}')
        provider = state['provider'] or {}
        e(provider.get('firstBrokerLoginFlowAlias') == 'krate first broker login' and provider.get('config', {}).get('clientSecret') == secret,
          f'{label}: the provider is created with the first-broker-login flow and the secret from .env')
        e(provider.get('config', {}).get('tokenUrl') == plan['identityProviders'][0]['config']['tokenUrl'], f'{label}: the provider carries the planned endpoints')
        e(sorted(m['name'] for m in state['mappers']) == sorted(m['name'] for m in plan['identityProviderMappers']), f'{label}: both mappers are created')
        e(state['browserFlow'] == 'krate browser', f'{label}: the realm browser flow is bound to krate browser')
        e(not any(secret in arg for call in calls for arg in call), f'{label}: the secret must never be a kcadm argument')
        e(secret not in result.stdout + result.stderr, f'{label}: the secret must never be printed')
        e('reconciled identity provider pingfederate' in journal.read_text() and 'changed=true' in result.stdout,
          f'{label}: the journal records the reconcile and IDENTITY_CHANGED is set; got {journal.read_text()!r}')
        flow_creates = [c for c in calls if c[0] == 'create' and c[1] == 'authentication/flows']
        provider_create = next((i for i, c in enumerate(calls) if c[0] == 'create' and c[1] == 'identity-provider/instances'), -1)
        e(flow_creates and provider_create > max(i for i, c in enumerate(calls) if c in flow_creates),
          f'{label}: the flows are created before the provider that names one of them')
        result, calls, state_after = run()
        label = 'second apply'
        e(result.returncode == 0 and 'No changes' in result.stdout and mutating(calls) == [] and state_after == state and 'changed=false' in result.stdout,
          f'{label}: must report No changes, make no create/update/delete call and leave the realm as it was; got exit {result.returncode}'
          f' {result.stdout.strip()[-200:]} {mutating(calls)}')
        # Drift as the hand-applied fixture had it: zeroed priorities, the built-in first-broker-login flow, a stale redirector config,
        # an extra mapper and a third execution in krate otp.
        drift = json.loads(state_file.read_text())
        browser = next(f for f in drift['flows'] if f['alias'] == 'krate browser')
        for execution in browser['executions']:
            if execution.get('providerId') in ('auth-cookie', 'identity-provider-redirector'):
                execution['priority'] = 0
        drift['provider']['firstBrokerLoginFlowAlias'] = 'first broker login'
        next(iter(drift['configs'].values()))['config']['defaultProvider'] = 'other'
        drift['mappers'].append({'id': 'extra', 'name': 'extra mapper', 'identityProviderAlias': 'pingfederate', 'config': {}})
        drift['mappers'][0]['config']['group'] = '/WRONG'
        otp = next(f for f in drift['flows'] if f['alias'] == 'krate otp')
        otp['executions'].append({'id': 'stray', 'requirement': 'REQUIRED', 'priority': 30, 'index': 2, 'providerId': 'auth-x509'})
        drift['browserFlow'] = 'browser'
        state_file.write_text(json.dumps(drift))
        result, calls, state_fixed = run('up')
        label = 'apply after drift'
        e(result.returncode == 0, f'{label}: failed: {result.stderr.strip()[:300]}')
        e(state_fixed == state, f'{label}: the realm must be back to the planned state; differences: {_dict_diff(state, state_fixed)}')
        kinds = sorted(set((c[0], c[1].split('/')[0] + ('/' + c[1].split('/')[1] if c[1].startswith('authentication/') else '')) for c in mutating(calls)))
        e(('create', 'authentication/flows') not in kinds and ('create', 'identity-provider') not in kinds, f'{label}: nothing is recreated; got {kinds}')
        e('up reconciled identity provider pingfederate' in journal.read_text().splitlines()[-1], f'{label}: the journal line names the command (up)')
        # B2: a failing or empty helper answer must stop the apply, never read as "same" and print No changes.
        for label, extra, needle in (('config GET fails', {'KC_FAIL_GET': 'authentication/config/'}, 'configuration'),
                                     ('config GET answers nothing', {'KC_EMPTY_GET': 'authentication/config/'}, 'configuration'),
                                     ('mappers GET fails', {'KC_FAIL_GET': 'identity-provider/instances/pingfederate/mappers'}, 'mappers'),
                                     ('provider GET answers nothing', {'KC_EMPTY_GET': 'identity-provider/instances/pingfederate'}, 'identity provider')):
            result, calls, state_kept = run(**extra)
            e(result.returncode != 0 and 'No changes' not in result.stdout and needle in result.stderr and state_kept == state,
              f'apply with {label}: must die naming the step (not report No changes); got exit {result.returncode} stdout {result.stdout.strip()[-120:]!r}'
              f' stderr {result.stderr.strip()[-160:]!r}')
        # Secret still a placeholder: identity up warns and touches nothing.
        result, calls, state_same = run('up', env_secret='REPLACE_ME')
        e(result.returncode == 0 and calls == [] and state_same == state and 'PING_KEYCLOAK_CLIENT_SECRET' in result.stdout + result.stderr,
          f'{label}: with the secret unset the plan is skipped with a warning and no kcadm call; got {result.stdout.strip()[-200:]} {calls}')
        # Removal: plan file gone, provider present.
        plan_file.unlink()
        result, calls, state_removed = run()
        label = 'apply without the plan file'
        e(result.returncode == 0, f'{label}: failed: {result.stderr.strip()[:300]}')
        e(state_removed['provider'] is None and state_removed['mappers'] == [] and state_removed['browserFlow'] == 'browser'
          and sorted(f['alias'] for f in state_removed['flows']) == ['browser', 'first broker login'],
          f'{label}: the provider, mappers and the four flows are removed and the browser flow rebound; got {state_removed}')
        rebind = next((i for i, c in enumerate(calls) if c[0] == 'update' and c[1] == 'realms/krate'), None)
        provider_delete = next((i for i, c in enumerate(calls) if c[0] == 'delete' and c[1] == 'identity-provider/instances/pingfederate'), None)
        flow_deletes = [i for i, c in enumerate(calls) if c[0] == 'delete' and c[1].startswith('authentication/flows/')]
        e(rebind is not None and provider_delete is not None and flow_deletes and rebind < provider_delete < min(flow_deletes),
          f'{label}: order must be rebind, delete provider, delete flows; got rebind {rebind}, provider {provider_delete}, flows {flow_deletes}')
        e('removed identity provider pingfederate' in journal.read_text().splitlines()[-1], f'{label}: the journal records the removal')
        result, calls, state_again = run()
        e(result.returncode == 0 and mutating(calls) == [] and state_again == state_removed, f'{label} (second run): nothing left to do; got {mutating(calls)}')
        # B3/Q9: identity rotate PING_KEYCLOAK_CLIENT_SECRET re-PUTs the provider with the new .env value, never removes it.
        rotate_script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'env_value', 'identity_put_idp_provider', 'identity_rotate_ping_secret') + r'''
SCRIPT_DIR="$1"; ENV_FILE="$1/.env"; IDENTITY_REALM=krate
IDENTITY_IDP_PLAN=auth/keycloak/pingfederate-idp.json; IDENTITY_IDP_ALIAS=pingfederate
sso_dir() { echo "$SSO_DIR"; }
kcadm_login() { :; }
kcadm_logout() { :; }
identity_journal() { printf '%s %s %s\n' "$1" "$2" "$3" >> "$JOURNAL"; }
kcadm() {
  while [[ $# -gt 0 && "$1" != -- ]]; do shift; done
  shift
  if [[ "${KCADM_STDIN:-}" == 1 ]]; then python3 -I "$FAKE" "$@"; else python3 -I "$FAKE" "$@" </dev/null; fi
}
identity_rotate_ping_secret
'''
        rotated = 'synthetic-rotated-ping-secret-7a1b2c3d4e'

        def rotate(env_secret=rotated):
            calls_file.write_text('')
            write_env(site, dict(SYNTHETIC, PING_KEYCLOAK_CLIENT_SECRET=env_secret))
            environment = dict(os.environ, KC_STATE=str(state_file), KC_CALLS=str(calls_file), JOURNAL=str(journal), FAKE=str(fake), SSO_DIR=str(ROOT / 'sso'))
            environment.pop('PING_KEYCLOAK_CLIENT_SECRET', None)
            outcome = run_bash(rotate_script, site, env=environment)
            calls = [json.loads(line) for line in calls_file.read_text().splitlines() if line.startswith('[')]
            return outcome, calls, json.loads(state_file.read_text())

        result, calls, state_norotate = rotate()
        e(result.returncode == 0 and 'Identity provider pingfederate: not applied yet (krate auth apply)' in result.stdout and mutating(calls) == []
          and state_norotate == state_removed, f'rotate without a provider: .env only, prints not applied yet; got {result.stdout.strip()[-120:]!r} {mutating(calls)}')
        plan_file.write_text(json.dumps(plan, indent=2) + '\n')
        result, calls, state_back = run()
        e(result.returncode == 0 and state_back['provider']['config']['clientSecret'] == secret, 'provider recreated for the rotation test')
        result, calls, state_rotated = rotate()
        e(result.returncode == 0 and 'Identity provider pingfederate: secret updated' in result.stdout,
          f'rotate with the provider present: prints exactly "Identity provider pingfederate: secret updated"; got exit {result.returncode} {result.stdout.strip()[-160:]!r} {result.stderr.strip()[-160:]!r}')
        e(state_rotated['provider']['config']['clientSecret'] == rotated and dict(state_rotated['provider'], config=None) == dict(state_back['provider'], config=None)
          and state_rotated['mappers'] == state_back['mappers'] and state_rotated['flows'] == state_back['flows'],
          'rotate replaces only the provider secret: mappers, flows and the other provider fields are untouched')
        e([c[0:2] for c in mutating(calls)] == [['update', 'identity-provider/instances/pingfederate']], f'rotate makes exactly one PUT of the provider, no delete/create; got {mutating(calls)}')
        e(not any(rotated in arg for call in calls for arg in call) and rotated not in result.stdout + result.stderr, 'the rotated secret is never an argument or printed')
        e(journal.read_text().splitlines()[-1] == 'rotate PING_KEYCLOAK_CLIENT_SECRET applied to identity provider pingfederate',
          f'the journal line is exactly "rotate PING_KEYCLOAK_CLIENT_SECRET applied to identity provider pingfederate"; got {journal.read_text().splitlines()[-1]!r}')
        plan_file.unlink()
        result, calls, state_kept = rotate()
        e(result.returncode != 0 and 'pingfederate-idp.json is missing' in result.stderr and mutating(calls) == [] and state_kept == state_rotated,
          f'rotate with the provider present but no plan file must stop; got exit {result.returncode} {result.stderr.strip()[-160:]!r}')
        for edition in EDITIONS:
            cli = (ROOT / edition / 'krate').read_text()
            rotate_body = function_body(cli, 'cmd_identity_rotate')
            e('PING_KEYCLOAK_CLIENT_SECRET)\n      # Issued by PingFederate' in rotate_body and '[[ "${2:-}" == --value ]] || die "PING_KEYCLOAK_CLIENT_SECRET is issued by PingFederate' in rotate_body,
              f'{edition}/krate: identity rotate accepts PING_KEYCLOAK_CLIENT_SECRET only with --value (stdin), never generated')
            e('    PING_KEYCLOAK_CLIENT_SECRET)\n      set_env_file_value "$ENV_FILE" "$key" "$value"\n      identity_rotate_ping_secret\n' in rotate_body
              and rotate_body.index('identity_rotate_ping_secret\n') < rotate_body.index('identity_up_service keycloak'),
              f'{edition}/krate: identity rotate writes .env, re-PUTs the provider through identity_rotate_ping_secret, then reconciles keycloak (its environment carries the key)')
            e('krate identity rotate PING_KEYCLOAK_CLIENT_SECRET --value' in function_body(cli, 'ensure_ping_secret'),
              f'{edition}/krate: ensure_ping_secret names identity rotate --value as the non-terminal path')
            # Review NEW1: a PingFederate-issued secret is accepted as issued (base64 and punctuation included);
            # only whitespace and the characters .env quoting, Compose interpolation and the shell alter are refused.
            ping_rule = 'if [[ "$key" == PING_KEYCLOAK_CLIENT_SECRET ]]; then\n      if [[ ${#value} -lt 16 ]] || printf \'%s\' "$value" | LC_ALL=C grep -q -E \'[^!-~]|[\\\\$"\'"\'"\'`]\'; then'
            e(ping_rule in rotate_body and rotate_body.index(ping_rule) < rotate_body.index('[[ "$value" =~ ^[A-Za-z0-9._-]{16,}$ ]]'),
              f'{edition}/krate: identity rotate takes a PingFederate secret as issued (printable ASCII, 16+, no whitespace/quotes/backslash/backtick/$) and keeps the generated-value rule for the other keys')


def _dict_diff(a, b):
    return [key for key in set(a) | set(b) if a.get(key) != b.get(key)]


def check_truststore_env(checks):
    """Item 4: the truststore digest in keycloak's environment; identity up and auth apply keep it current and recreate Keycloak."""
    e = checks.expect
    for edition in EDITIONS:
        code, rendered = compose_config(ROOT / edition / '.env.template', edition)
        if e(code == 0, f'{edition}: Compose rendering failed'):
            keycloak = json.loads(rendered)['services']['keycloak']
            e('KRATE_TRUSTSTORE_SHA' in (keycloak.get('environment') or {}),
              f'{edition}/keycloak: KRATE_TRUSTSTORE_SHA must be part of the environment so a changed truststore recreates Keycloak')
            mounts = {mount.get('target'): mount for mount in keycloak.get('volumes') or []}
            e('/opt/keycloak/conf/truststores' in mounts and keycloak['environment'].get('KC_TRUSTSTORE_PATHS') == '/opt/keycloak/conf/truststores',
              f'{edition}/keycloak: auth/keycloak/truststores is mounted at KC_TRUSTSTORE_PATHS')
        cli = (ROOT / edition / 'krate').read_text()
        up = function_body(cli, 'cmd_identity_up')
        e('if sync_truststore_env; then' in up and up.index('sync_truststore_env') < up.index('--mode identity')
          and up.index('sync_truststore_env') < up.index('identity_up_service keycloak'),
          f'{edition}/krate: identity up must record the truststore digest before rendering and starting Keycloak')
        e('KRATE_TRUSTSTORE_SHA=' in (ROOT / edition / '.env.template').read_text(), f'{edition}/.env.template: KRATE_TRUSTSTORE_SHA must be listed')
    activate = (ROOT / 'sso/activate.sh').read_text()
    e('if sync_truststore_env; then' in activate and activate.index('sync_truststore_env') < activate.index('--wait-timeout "$timeout" keycloak')
      < activate.index('identity_apply_idp apply') < activate.index('--wait-timeout "$timeout" kafka-ui'),
      'sso/activate.sh: apply must sync the digest, recreate Keycloak when it changed, apply the plan, then reconcile Kafbat')
    e('--pull never --no-build --no-deps --wait --wait-timeout "$timeout" keycloak' in activate, 'sso/activate.sh: Keycloak is reconciled with --pull never, no deps')
    e('identity_lock\n' in activate, 'sso/activate.sh: apply takes the identity lock before changing Keycloak and the realm')
    with tempfile.TemporaryDirectory() as tmp:
        trust = Path(tmp) / 'truststores'
        e(identity.truststore_digest(trust) == '', 'truststore_digest: a missing directory digests to the empty string (what an absent .env key renders)')
        trust.mkdir()
        e(identity.truststore_digest(trust) == '', 'truststore_digest: an empty directory digests to the empty string')
        (trust / 'a.pem').write_text('one\n')
        first = identity.truststore_digest(trust)
        e(re.fullmatch(r'[0-9a-f]{32}', first) is not None, f'truststore_digest: 32 hex characters; got {first!r}')
        (trust / 'notes.txt').write_text('stray\n')
        with_stray = identity.truststore_digest(trust)
        e(with_stray != first, 'truststore_digest: every regular file counts (a stray file changes the digest; the preflight refuses it)')
        (trust / 'notes.txt').unlink()
        (trust / 'sub').mkdir()
        (trust / 'sub/root.p12').write_bytes(b'pkcs12')
        nested = identity.truststore_digest(trust)
        e(nested not in (first, with_stray), 'truststore_digest: a nested PKCS12 file counts (Keycloak scans recursively)')
        e([str(p.relative_to(trust)) for p in identity.truststore_files(trust)] == ['a.pem', 'sub/root.p12'], 'truststore_files lists files recursively by relative path')
        (trust / 'sub/root.p12').unlink()
        (trust / 'sub').rmdir()
        e(identity.truststore_digest(trust) == first, 'truststore_digest: back to the first digest once the extra files are gone')
        (trust / 'a.pem').write_text('two\n')
        second = identity.truststore_digest(trust)
        e(second != first, 'truststore_digest: changed content changes the digest')
        (trust / 'a.pem').write_text('one\n')
        (trust / 'b.crt').write_text('one\n')
        third = identity.truststore_digest(trust)
        e(third not in (first, second), 'truststore_digest: an added .crt changes the digest')
        (trust / 'b.crt').rename(trust / 'c.crt')
        e(identity.truststore_digest(trust) != third, 'truststore_digest: a renamed file changes the digest (names are part of it)')
    if bash_binary() is None:
        return
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'env_value', 'replace_env_file', 'set_env_file_value', 'sync_truststore_env') + r'''
SCRIPT_DIR="$1"; ENV_FILE="$1/.env"; SSO="$2"
sso_dir() { echo "$SSO"; }
if sync_truststore_env; then echo changed; else echo same; fi
grep -E '^KRATE_TRUSTSTORE_SHA=' "$ENV_FILE"
'''
    with tempfile.TemporaryDirectory() as tmp:
        site = Path(tmp)
        (site / 'auth/keycloak/truststores').mkdir(parents=True)
        # A Phase 1/2 .env has no KRATE_TRUSTSTORE_SHA line: with an empty directory nothing is written and nothing is recreated (S3).
        write_env(site, {'KEYCLOAK_ENABLED': 'true'})
        before = (site / '.env').read_bytes()
        result = run_bash(script, site, ROOT / 'sso')
        e(result.returncode == 1 and result.stdout.split() == ['same'] and (site / '.env').read_bytes() == before,
          f'sync_truststore_env: an empty set on a .env without the key is unchanged (no first-upgrade recreation); got {result.returncode} {result.stdout.split()} {result.stderr.strip()[:120]}')
        write_env(site, {'KRATE_TRUSTSTORE_SHA': ''})
        before = (site / '.env').read_bytes()
        result = run_bash(script, site, ROOT / 'sso')
        e(result.stdout.split()[0] == 'same' and (site / '.env').read_bytes() == before, 'sync_truststore_env: unchanged set leaves .env byte-identical and returns 1')
        (site / 'auth/keycloak/truststores/ca.pem').write_text('cert\n')
        result = run_bash(script, site, ROOT / 'sso')
        sha = result.stdout.split()[1].partition('=')[2]
        e(result.stdout.split()[0] == 'changed' and re.fullmatch(r'[0-9a-f]{32}', sha) is not None, f'sync_truststore_env: an added PEM records a new digest; got {result.stdout.split()}')
        result = run_bash(script, site, ROOT / 'sso')
        e(result.stdout.split()[0] == 'same', 'sync_truststore_env: the same PEM set is reported unchanged')
        (site / 'auth/keycloak/truststores/ca.pem').unlink()
        result = run_bash(script, site, ROOT / 'sso')
        e(result.stdout.split() == ['changed', 'KRATE_TRUSTSTORE_SHA='], f'sync_truststore_env: removing the last file records the empty digest; got {result.stdout.split()}')
        e(sorted(path.name for path in site.iterdir()) == ['.env', 'auth'], 'sync_truststore_env: no temporary file remains')
    activate = (ROOT / 'sso/activate.sh').read_text()
    e('identity_journal apply recreated "keycloak: truststores changed"' in activate and 'identity_journal apply recreated "keycloak: service definition changed"' in activate
      and activate.index('trust_changed=true') < activate.index('elif $trust_changed; then'),
      'sso/activate.sh: the journal says truststores changed only when the digest changed, otherwise service definition changed (N3)')


def check_broker_docs(checks):
    """Item 6: the guides and README describe what apply does, the break-glass URL, the decisions and the trust restart."""
    e = checks.expect
    dual = (ROOT / 'sso/guides/dual-login.md').read_text()
    for forbidden in ('account/?kc_idp_hint', 'creates the Keycloak session'):
        e(forbidden not in dual and forbidden not in (ROOT / 'README.md').read_text() and forbidden not in (ROOT / 'sso/guides/pingfederate-sso.md').read_text(),
          f'docs must not describe the unverified account-console break-glass URL ({forbidden!r}); only the proven authorization-URL procedure (B1)')
    for needle, why in (('&kc_idp_hint=', 'the proven break-glass procedure: the empty hint appended to the realm authorization URL'),
                        ('Log in with Keycloak', 'the break-glass procedure starts from Kafbat\'s button'),
                        ('identity rotate PING_KEYCLOAK_CLIENT_SECRET --value', 'secret rotation through identity rotate (B3/Q9)'),
                        ('federated-identity link', 'removing the plan deletes every federated-identity link'),
                        ('idp_truststore', 'the site key for a publicly trusted identity provider (S1)'),
                        ('.p12', 'the PKCS12 truststore files Keycloak also loads (S2)'),
                        ('service definition changed', 'the journal line for a recreation that is not a truststore change (N3)'),
                        ('admin console', 'console-created users and the TOTP demand (N7)'),
                        ('krate first broker login', 'the first-broker-login flow (D2)'),
                        ('krate browser', 'the browser flow (D3)'), ('krate forms', 'the forms sub-flow'), ('krate otp', 'the OTP sub-flow'),
                        ('owner to confirm', 'the decisions are marked owner to confirm'),
                        ('syncMode', 'revocation through syncMode FORCE at the next sign-in'),
                        ('KRATE_TRUSTSTORE_SHA', 'the truststore digest and Keycloak recreation'),
                        ('idp-create-user-if-unique', 'the no-linking authenticator'), ('No changes', 'the idempotent second apply'),
                        ('identity provider pingfederate', 'the journal line'), ('auth configure --local', 'the way back to local sign-in')):
        e(needle in dual, f'sso/guides/dual-login.md must describe {why} (missing {needle!r})')
    for decision in ('D1', 'D2', 'D3', 'D4'):
        e(re.search(r'\b' + decision + r'\b', dual) is not None, f'sso/guides/dual-login.md must state decision {decision}')
    foundation = (ROOT / 'sso/guides/identity-foundation.md').read_text()
    e('not a realm default' in foundation or 'no longer a realm default' in foundation,
      'sso/guides/identity-foundation.md must say CONFIGURE_TOTP is not a realm default action')
    e('requiredActions' in foundation and 'users add' in foundation, 'sso/guides/identity-foundation.md must say users add assigns the required actions')
    e('required action CONFIGURE_TOTP' in foundation, 'sso/guides/identity-foundation.md must describe the required-action reconcile of identity up')
    readme = (ROOT / 'README.md').read_text()
    e('kc_idp_hint=' in readme and 'auth/keycloak/pingfederate-idp.json' in readme, 'README.md must describe the PingFederate apply and the break-glass hint')
    sso = (ROOT / 'sso/guides/pingfederate-sso.md').read_text()
    e('kc_idp_hint=' in sso and 'krate browser' in sso, 'sso/guides/pingfederate-sso.md must describe the realm flow and the break-glass hint')
    e('PING_KEYCLOAK_CLIENT_SECRET' in foundation and 'identity rotate' in foundation, 'sso/guides/identity-foundation.md must list PING_KEYCLOAK_CLIENT_SECRET under identity rotate')


def check_health(checks):
    """N4: health names the Compose service of a crash-looping container (RestartCount, Restarting) and survives a vanished one."""
    e = checks.expect
    if bash_binary() is None:
        return
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'health_pending_count', 'cmd_health') + r'''
require_compose() { :; }; require_compose_file() { :; }
compose_cmd() { printf 'c1\nc2\nc3\nc4\nc5\n'; }
docker() {
  local cid="${*: -1}" format="$3"
  case "$cid" in
    c1) row="/krate-broker-92|running|healthy|false|2|kafka-92" ;;
    c2) row="/krate-kafka-ui|running|starting|false|3|kafka-ui" ;;
    c3) echo "Error: No such object: c3" >&2; return 1 ;;
    c4) row="/krate-proxy|restarting|unhealthy|true|5|proxy" ;;
    c5) row="/krate-exporter|running|none|false|0|kafka-exporter" ;;
  esac
  if [[ "$format" == *'|'* ]]; then echo "$row"; else IFS='|' read -r _ _ health _ <<< "$row"; echo "$health"; fi
}
cmd_health --no-wait
'''
    result = run_bash(script)
    out = result.stdout + result.stderr
    e(result.returncode == 1, f'health: a crash-looping cluster must report failure (exit 1); got {result.returncode}: {out.strip()[-300:]}')
    e('Not healthy: kafka-ui proxy keeps restarting' in out and 'krate logs kafka-ui proxy' in out,
      f'health: a container restarted by its policy (sampled while starting) and a restarting one are named by Compose service; got {out.strip()[-300:]}')
    e('gone' in out and 'kafka-92' not in out.split('Not healthy:')[-1],
      f'health: a container that vanished is reported as gone without stopping the report, and a healthy one is not blamed; got {out.strip()[-300:]}')


def check_install_lock(checks):
    """N5: install takes the identity lock in the installation, after the package branch exec'd into it."""
    for edition in EDITIONS:
        body = function_body((ROOT / edition / 'krate').read_text(), 'cmd_install')
        lock = body.find('identity_lock_if_enabled')
        checks.expect(body.count('identity_lock_if_enabled') == 1 and lock > body.index('exec "$KRATE_HOME/krate" install'),
                      f'{edition}/krate: cmd_install must take the identity lock once, after the package branch')



def main():
    checks = Checks()
    for check in (check_templates, check_realm_contract, check_runtime_contract, check_names, check_compose, check_monitoring_binds,
                  check_logrotate, check_cli_kafbat, check_exposure, check_gate_scripts, check_parity, check_zk_frozen, check_writers, check_backup_seal,
                  check_plan_and_preflight, check_configure_dual, check_runtime_preflight,
                  check_bash_available, check_proxy_env, check_nginx_edge, check_nginx_render, check_identity_dirs, check_deploy_release, check_rpm_install, check_gen_cert_ip,
                  check_renew_db_tls_order, check_summaries, check_realm_reconcile, check_health, check_install_lock,
                  check_broker_apply, check_truststore_env, check_broker_docs):
        try:
            check(checks)
        except Exception as exc:  # one failing check must not hide the others
            checks.errors.append(f'{check.__name__}: {type(exc).__name__}: {exc}')
    if checks.errors:
        print('Identity check failed:\n' + '\n'.join(checks.errors), file=sys.stderr)
        return 1
    print('Identity foundation verified: templates, realm plan, Kafbat runtime plan, names, Compose services and identity network, '
          'monitoring binds, logrotate drop-in, CLI Kafbat wiring and parity, zk frozen, writers and renewal, preflight (identity and '
          'runtime.yml incl. refusals), configure-dual, proxy environment and edge rules, release permissions, RPM dependency '
          'resolution, IP certificates, renew-db-tls order, credential-free summaries, realm policy reconcile, health, install lock, '
          'PingFederate broker plan/apply/removal, truststore digest, Phase 3 docs.')
    if RENDER_IMAGE_NOTE:  # its own last line: the gate records the last line as the S4 evidence
        print('[' + '; '.join(RENDER_IMAGE_NOTE) + ']')
    return 0


if __name__ == '__main__':
    sys.exit(main())
