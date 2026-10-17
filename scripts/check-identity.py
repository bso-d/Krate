#!/usr/bin/env python3
"""Static checks for the Krate identity foundation (templates, realm plan, Compose, CLI parity)."""
import configparser
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
# The viewer never sees applicationconfig: with dynamic configuration on, its view returns the running configuration, client secret included.
VIEWER_RESOURCES = tuple(resource for resource in VIEW_RESOURCES if resource != 'applicationconfig')
CLUSTERS = ['cluster-a', 'cluster-b.2']
# Site keys configure-dual.py no longer reads (they moved to .env): the example must not carry them.
MOVED_SITE_KEYS = ('viewer_messages', 'session_idle_minutes', 'session_max_hours')

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
    e(oauth.get('max-session-lifetime') == '3h',
      f'auth.oauth2.max-session-lifetime must be KEYCLOAK_SESSION_MAX_HOURS (3h); got {oauth.get("max-session-lifetime")!r}')
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
        # Grafana's default keeps main's behaviour (every interface, gate row M1); realm mode
        # sets GRAFANA_BIND=127.0.0.1, which check_grafana_realm_compose renders separately.
        checks.expect(len(ports) == 1 and ports[0].get('host_ip') in (None, '0.0.0.0') and ports[0].get('published') == str(port),
                      f'monitoring/{name}: must still publish {port} on every interface by default; got {ports}')


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
        # Derived, not hard-coded: the server level plus every location that restates the header set
        # must also clear the client-supplied ones. A location that proxies without restating
        # (/login, /oauth2/, /login/oauth2/) inherits the server-level set and is not counted.
        restating = 1 + len([body for body in re.findall(r'location [^{]+\{(.*?)\n    \}', nginx, re.S)
                             if 'proxy_set_header X-Forwarded-Host' in body])
        e(restating == 6, f'{edition}/nginx.conf: expected the server level and five restating locations (identity realms, identity resources, /, /grafana/login, /grafana/); got {restating}')
        for header in ('Forwarded', 'X-Forwarded-Prefix', 'X-Forwarded-Ssl', 'X-Forwarded-Port'):
            e(nginx.count(f'proxy_set_header {header} "";') == nginx.count('proxy_set_header X-Forwarded-Host $http_host;') == restating,
              f'{edition}/nginx.conf: every proxied location must clear the client-supplied {header} header ({restating} of them)')
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
                        ('oidcSessionRegistry.removeSessionInformation(session.getId())', 'a local logout forgets the OIDC session'),
                        ('MAX_SESSION_LIFETIME = "auth.oauth2.max-session-lifetime"', 'the fork reads the absolute session lifetime from auth.oauth2.max-session-lifetime'),
                        ('Duration.between(session.getCreationTime(), Instant.now()).compareTo(maximum) >= 0', 'a session older than the maximum ends however recently it was used'),
                        ('return session.invalidate().then(Mono.defer(() -> {', 'the session that reached the maximum is invalidated and its request restarts'),
                        ('            ? restartRequest(exchange, session, maximum)', 'after the invalidation the exchange is answered with the restart, so no session write lands in the invalidated-session reference'),
                        ('builder.addFilterBefore(sessionLifetimeLimit(maxSessionLifetime), SecurityWebFiltersOrder.REACTOR_CONTEXT);', 'the lifetime filter runs before the SecurityContext is read'),
                        ('response.setStatusCode(HttpStatus.FOUND);', 'the restart answers 302 at the same request URI (the expired SESSION cookie is written at the response commit)'),
                        ('String location = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());', 'the bounce location is the request path and query, relative so the browser resolves scheme and host itself'),
                        ('ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/logout")', 'a POST /logout is left to the logout filter, whose success handler needs the authentication'),
                        ('DEFAULT_MAX_SESSION_LIFETIME = Duration.ofHours(8);', 'the built-in maximum is 8 hours (owner decision G4) when the property is absent'),
                        ('DurationStyle.detectAndParse(configured.strip(), ChronoUnit.SECONDS)', 'a bare number is seconds, like server.reactive.session.timeout'),
                        ('if (lifetime.isPositive()) {', 'zero and negative values refuse to start'),
                        ('.flatMap(isLogout -> isLogout\n+            ? chain.filter(exchange)\n+            : continueOrRestart(exchange, maximum, chain)', 'only a POST /logout skips the check, every other request is checked')):
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
    e("IMAGE = 'krate/kafka-ui:1.5.0-sso.9'" in build, 'kafbat-ui/build.py must build sso.9 (the templates pin it)')
    e("VITE_TAG='v1.5.0-sso.9'" in build, 'kafbat-ui/build.py must stamp the frontend with the same sso.9 tag')
    for edition in EDITIONS:
        pin = identity.read_env(ROOT / edition / '.env.template').get('KAFKA_UI_IMAGE', '')
        e(re.fullmatch(r'krate/kafka-ui:1\.5\.0-sso\.9@sha256:[a-f0-9]{64}', pin) is not None,
          f'{edition}/.env.template: KAFKA_UI_IMAGE must pin the sso.9 image that build.py builds; got {pin[:60]!r}')


def check_gate_scripts(checks):
    """The gate helpers import and their pure helpers behave; --help works under python3 -I (a self-recursive helper once passed every static tool)."""
    import types
    e = lambda cond, msg: checks.expect(cond, 'gate scripts: ' + msg)  # noqa: E731
    for name in ('scripts/gate/phase2_kafbat.py', 'scripts/gate/keycloak_login_flow.py', 'scripts/gate/phase4_kafbat.py'):
        result = subprocess.run([sys.executable, '-I', str(ROOT / name), '--help'], text=True, capture_output=True)
        e(result.returncode == 0 and 'usage' in result.stdout.lower(), f'{name} --help must exit 0; got {result.returncode}: {result.stderr.strip()[:120]}')
    k37 = subprocess.run([sys.executable, '-I', str(ROOT / 'scripts/gate/phase4_kafbat.py'), '--selftest'], text=True, capture_output=True)
    e(k37.returncode == 0 and 'selftest ok' in k37.stdout, f'phase4_kafbat.py --selftest (the K37 windows) must pass; got {k37.returncode}: {k37.stderr.strip()[:120]}')
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

    # phase3_broker.Gate.create_topic must check the cleanup DELETE's status, not just fire it (PR41 review 3,
    # scripts/gate/phase3_broker.py:288): a 200 create with a failed DELETE has to FAIL naming the status, a
    # successful DELETE must pass, and a refused (non-200) create must not attempt a DELETE at all.
    p3_spec = importlib.util.spec_from_file_location('phase3_broker', ROOT / 'scripts/gate/phase3_broker.py')
    assert p3_spec is not None and p3_spec.loader is not None
    p3_module = importlib.util.module_from_spec(p3_spec)
    sys.modules.setdefault('phase2_kafbat', module)
    p3_spec.loader.exec_module(p3_module)

    class _FakeTopicResponse:
        def __init__(self, status):
            self.status = status

    class _FakeTopicBrowser:
        def __init__(self, post_status, delete_status):
            self.post_status = post_status
            self.delete_status = delete_status
            self.calls = []

        def api(self, method, _path, _payload=None):  # the real browser.api signature; path and body are not inspected here
            self.calls.append(method)
            return _FakeTopicResponse(self.post_status if method == 'POST' else self.delete_status)

    def _create_topic_case(post_status, delete_status):
        fake_gate = types.SimpleNamespace(cluster='cluster-x', cleanup_topics=set())
        browser = _FakeTopicBrowser(post_status, delete_status)
        try:
            return 'return', p3_module.Gate.create_topic(fake_gate, browser, 'gate3-check'), browser.calls
        except p3_module.Outcome as blocked:
            return 'fail', (blocked.status, blocked.text), browser.calls

    kind, got, calls = _create_topic_case(200, 500)
    e(kind == 'fail' and got[0] == 'FAIL' and '500' in got[1],
      f'create_topic must FAIL naming the DELETE status when cleanup fails (200/500); got {kind} {got}')
    kind, got, calls = _create_topic_case(200, 200)
    e(kind == 'return' and got == (200, 200), f'create_topic must pass through (create, delete) on a clean removal; got {kind} {got}')
    kind, got, calls = _create_topic_case(403, 500)
    e(kind == 'return' and got == (403, None) and calls == ['POST'],
      f'create_topic must not attempt a DELETE when the create itself was refused; got {kind} {got} calls={calls}')
    # Gate.cleanup (teardown backstop): every recorded topic is deleted in the broker with --if-exists; no container → no call.
    docker_calls = []
    saved = module.service_container, module.docker
    try:
        # setattr, not direct assignment: Pyright rejects module-attribute assignment
        # (reportAttributeAccessIssue — ModuleType declares no such attributes).
        setattr(module, 'service_container',
                lambda project, service: 'cid-1' if (project, service) == ('p-x', 'kafka-92') else None)
        setattr(module, 'docker', lambda *args, **kwargs: (docker_calls.append(args), (0, '', ''))[1])
        p3_module.Gate.cleanup(types.SimpleNamespace(project='p-x', cleanup_topics={'gate3-p6', 'gate3-p5'}))
        e(len(docker_calls) == 2 and all(a[0] == 'exec' and a[1] == 'cid-1' and '--delete' in a and '--if-exists' in a for a in docker_calls)
          and [a[-1] for a in docker_calls] == ['gate3-p5', 'gate3-p6'],
          f'Gate.cleanup must delete every recorded topic in the broker with --if-exists; got {docker_calls}')
        docker_calls.clear()
        p3_module.Gate.cleanup(types.SimpleNamespace(project='other', cleanup_topics={'gate3-p6'}))
        e(docker_calls == [], f'Gate.cleanup must make no docker call without a kafka-92 container; got {docker_calls}')
    finally:
        setattr(module, 'service_container', saved[0])
        setattr(module, 'docker', saved[1])
    e('self.cleanup()' in (ROOT / 'scripts/gate/phase3_broker.py').read_text().split('def main(self):', 1)[1].split('def finish', 1)[0],
      'phase3_broker.Gate.main must call self.cleanup() in its finally block')

    # Screenshot manifests are published evidence: a verbatim page.url() would
    # persist OAuth code/state/nonce query values (PR #42 review, 2026-10-14).
    for name in ('screenshots.mjs', 'screenshots-grafana.mjs', 'screenshots-perses.mjs'):
        story = (ROOT / 'scripts/gate' / name).read_text()
        e('url: page.url()' not in story and 'url: publicUrl(page.url())' in story,
          f'{name} must record only the public origin+path of each shot in its manifest')
    browser = (ROOT / 'scripts/gate/phase4-browser.mjs').read_text()
    e(browser.count("page.url().replace(BASE, '')") ==
      browser.count("page.url().replace(BASE, '').split(/[?#]/)[0]"),
      'phase4-browser.mjs must strip query and fragment from every recorded page URL')
    # Every recorded .url() in every gate story — manifest fields, asserted
    # strings and step records alike — must be stripped of query and fragment
    # before it can reach a manifest or summary file.
    # Same rule for the Mac agent's helpers under scripts/gate/mac.
    for story_folder in ((ROOT / 'scripts/gate', ROOT / 'scripts/gate/mac')):
        for story_path in sorted(story_folder.glob('*.mjs')):
            story = story_path.read_text()
            for match in re.finditer(r'\.url\(\)', story):
                tail = story[match.end():match.end() + 80]
                head = story[max(0, match.start() - 40):match.start()]
                ok = (re.search(r'publicUrl\(\w+$', head) is not None or tail.startswith('.split(/[?#]/)')
                      or tail.startswith('.includes(') or tail.startswith('.startsWith(')
                      or (tail.startswith('.replace(') and '.split(/[?#]/)' in tail[:70])
                      or re.search(r'new URL\(\w+$', head) is not None)
                e(ok, f'{story_path.name} records a verbatim .url() near: ...{story[max(0, match.start() - 40):match.end() + 40]!r}')

    # TOPOFIX: the amended browser vantage and the Mac agent (harness/phase4-completion/w2,
    # design sections 1b/3.4/3.6, review F1-F12). Every hard wiring claim is asserted here;
    # a mutant that removes one must fail the whole check.
    launch_mod = (ROOT / 'scripts/gate/browser-launch.mjs').read_text()
    # a code-only view: a comment may CITE a claim ("we once mapped * ~NOTFOUND") without the
    # code carrying it, so the claim assertions below that a comment could satisfy scan this
    # instead of the raw text
    launch_mod_code = '\n'.join(l for l in launch_mod.splitlines() if not l.strip().startswith('//'))
    for story_path in sorted((ROOT / 'scripts/gate').rglob('*.mjs')):
        if story_path.name == 'browser-launch.mjs':
            continue
        e('--host-resolver-rules' not in '\n'.join(l for l in story_path.read_text().splitlines() if not l.strip().startswith('//')),
          f'{story_path.name} must not build --host-resolver-rules itself (launchGateBrowser is the only builder; comments may name the switch)')
    e('MAP * ~NOTFOUND, EXCLUDE' in launch_mod_code,
      'browser-launch.mjs builds the F3 resolver value "MAP <host> <ip>, MAP * ~NOTFOUND, EXCLUDE <ip>" '
      '(M0 point 5: example.com resolves net::ERR_NAME_NOT_RESOLVED under it); the claim must be in code, not only in a comment')
    mac_branch = launch_mod.split('export async function launchGateBrowserMac', 1)[1].split('export async function launchGateBrowserContainer', 1)[0]
    e("channel: 'chrome'" in mac_branch, "browser-launch.mjs launches the installed Chrome (channel 'chrome') in the Mac vantage (M0/M5)")
    e('launchPersistentContext' in mac_branch, 'the Mac vantage uses a fresh per-story profile (launchPersistentContext)')
    e('ignoreHTTPSErrors' not in mac_branch,
      "the Mac vantage must NOT ignore certificate errors (Chrome's own verifier runs; the interstitial is the story's evidence; TOPOFIX 1c)")
    for story_path in sorted((ROOT / 'scripts/gate').rglob('*.mjs')):
        text_code = '\n'.join(l for l in story_path.read_text().splitlines() if not l.strip().startswith('//'))
        e('ignore-certificate-errors' not in text_code, f'{story_path.name} must not carry an --ignore-certificate-errors switch (TOPOFIX F2)')
        # the call shapes of a CDP Network.getCertificate request (a CDP session send or a
        # direct method call); naming the method in a comment or label is fine, calling it is not (M0 point 6)
        e('getCertificate(' not in text_code and "'Network.getCertificate'" not in text_code and '"Network.getCertificate"' not in text_code,
          f'{story_path.name} must not call CDP Network.getCertificate (M0 point 6: it returned no certificate in Chrome 155; the digest source is the Node pin + Response.securityDetails)')
    e('requireCertFile' in launch_mod_code and 'GATE_CERT_FILE' in launch_mod_code,
      'the Mac vantage pins the fixture certificate from GATE_CERT_FILE (fail-closed without it)')
    e('assertCertValidity' in launch_mod and 'validToDate' in launch_mod,
      "browser-launch.mjs checks the pinned certificate's Mac-side validity window (TOPOFIX F2)")
    e('assertServedFrom' in launch_mod and 'assertServedCertificate' in launch_mod,
      'browser-launch.mjs binds the served address (never 127.0.0.1/::1) and the served certificate (Response.serverAddr/securityDetails, M0 point 4)')
    e('externalAttemptsTracker' in launch_mod_code
      and launch_mod_code.count("scheme !== 'chrome'") == 1 and launch_mod_code.count("scheme !== 'devtools'") == 1,
      'external_attempts must exempt only chrome:// and devtools:// targets (TOPOFIX F3)')
    e('refuseSystemProxy' in launch_mod_code and 'ProxyAutoDiscoveryEnable' in launch_mod_code,
      'the launcher refuses a system proxy, whose names --host-resolver-rules does not cover (TOPOFIX F3; M0 observed none)')
    e('HeadlessChrome' in launch_mod_code,
      'browser evidence refuses a HeadlessChrome build in the Mac vantage (the formal receipt is the installed headed Chrome)')
    for name in ('screenshots.mjs', 'screenshots-grafana.mjs', 'screenshots-perses.mjs', 'phase4-browser.mjs'):
        story = (ROOT / 'scripts/gate' / name).read_text()
        e("from './browser-launch.mjs'" in story, f'{name} must import the shared browser launch')
        e('macMode()' in story, f"{name} must gate its new behaviour on macMode() (GATE_BROWSER_MAC; the container runner keeps today's walked shape)")
    agent = (ROOT / 'scripts/gate/mac/agent.mjs').read_text()
    e("'id,nonce,row,schema'" in agent, 'the agent accepts exactly {schema,id,row,nonce} guest requests (TOPOFIX F4)')
    e('claimRequest' in agent and 'ALLOWED_SCRIPTS' in agent, 'the agent holds claim validation and an allow-list of the scripts it may run (F4)')
    allow_list = re.search(r'const ALLOWED_SCRIPTS = \[(.*?)\];', agent, re.S)
    e(allow_list is not None, 'the agent\'s ALLOWED_SCRIPTS array must exist')
    if allow_list is not None:
        for allowed in ('probe.mjs', 'screenshots.mjs', 'screenshots-grafana.mjs', 'screenshots-perses.mjs', 'phase4-browser.mjs'):
            e(allowed in allow_list.group(1), f'the agent ALLOWED_SCRIPTS array must not silently drop {allowed}')
    e('realpath -e' in agent, 'the agent reads guest files through one realpath-confined command (F4)')
    e('65536' in agent, 'the agent caps each guest file read at 64 KiB (F4)')
    e('agent-manifest.tsv' in agent, 'the agent keeps its own manifest on the Mac (F4)')
    e('--backend=scp' in '\n'.join(l for l in agent.splitlines() if not l.strip().startswith('//')),
      'the agent delivers with limactl copy --backend=scp -r (F8; M1 observed the flag; the delivery call must be in code, not only a comment)')
    e('mac_src_ip' in agent and 'mac_iface' in agent and 'vm_g6' in agent and 'clock_skew_ms' in agent,
      'the agent hello carries the guest address, the Mac source address, the guest\'s lima0 GLOBAL address (vm_g6, review S6: the field is named for the class it carries) and the clock facts the runner preflights')
    probe = (ROOT / 'scripts/gate/mac/probe.mjs').read_text()
    e("case 'ECONNREFUSED': return 'refused';" in probe and "return 'rejected';" in probe and "return 'timeout';" in probe,
      'probe.mjs classifies every connect outcome, not only open/closed (TOPOFIX F6: three outcomes; the mapping must be the shipped one)')
    guide_fingerprint = (ROOT / 'sso/guides/identity-gate.md').read_text()
    e('net::ERR_NAME_NOT_RESOLVED' in guide_fingerprint,
      'the guide names the external-attempt fingerprint of the MAP * ~NOTFOUND rule (M5)')
    remote = (ROOT / 'scripts/gate/browser_remote.py').read_text()
    e('req = {"schema": 1, "id": int(req_id), "row": row, "nonce": nonce}' in remote,
      'browser_remote.py sends exactly {schema,id,row,nonce} — no paths, secrets or arguments (TOPOFIX F4)')
    runner_text = (ROOT / 'scripts/gate-identity.sh').read_text()
    e('REQUIRED_P4C=(W1 W2 W3 W4 W5 W6 W7)' in runner_text, 'W5/W6/W7 are inside REQUIRED_P4C (TOPOFIX F6)')
    e('--browser agent is refused with --phase $PHASE' in runner_text,
      'the runner refuses the agent vantage for phases 1-3 (X1 stays a Mac-fixture row; TOPOFIX F9)')
    u15 = (ROOT / 'scripts/gate/phase4-browser.mjs').read_text()
    e(re.search(r"^\s*const accepted = await acceptGateCertificate\(", u15, re.M) is not None
      and re.search(r"^\s*if \(accepted\.decision !== 'proceed'\) \{\s*$", u15, re.M) is not None,
      "U15 (phase4-browser.mjs) stops when acceptGateCertificate returns no 'proceed' decision: its hooks run only in the interstitial branch "
      "(TR2 G1; TOPOFIX2 G6: a multiline match on a non-comment line, so the check disabled behind a comment fails)")
    e(re.search(r'^\s*v6_addr = v6\.get\("address", ""\)\s*$', runner_text, re.M) is not None
      and re.search(r'^\s*v6_class = v6\.get\("addressClass", ""\)\s*$', runner_text, re.M) is not None
      and '.get("ll"' not in runner_text,
      'the W5 evidence reads the probe report\'s v6 address and addressClass, not the removed link-local "ll" key '
      '(TR2 G4; TOPOFIX2 G6: the exact assignments, so swapped keys fail)')
    e('is_private' not in runner_text and 'rfc1918 = [ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]' in runner_text
      and 'not any(addr in net for net in rfc1918)' in runner_text,
      'the agent preflight requires mac_src_ip inside 10/8, 172.16/12 or 192.168/16 by network membership, not ipaddress.is_private (TOPOFIX F7; TOPOFIX2 F7)')
    e("the fixture's lima0 address is still" in runner_text,
      'the runner records the end-of-run vmip row (TOPOFIX F7)')
    s3_line = next((ln for ln in runner_text.splitlines() if 'koalaman/shellcheck:v0.9.0' in ln and 'kraft/krate' in ln), '')
    e('mac/run-vm-gate.sh' in s3_line, "scripts/gate/mac/run-vm-gate.sh is in S3's shellcheck 0.9.0 list")
    e('browser_remote.py' in runner_text, 'the runner asks the agent through scripts/gate/browser_remote.py')
    e('| browser vantage |' in runner_text, 'the receipt header names the browser vantage (TOPOFIX design 3.5)')
    e('--rendezvous-nonce' in runner_text and 'the token is not printed' in runner_text,
      'the rendezvous nonce binds the run and is never printed')
    guide = (ROOT / 'sso/guides/identity-gate.md').read_text()
    for row in ('| W5 | runner (Mac vantage only; J7 pattern) | the published-port surface',
                '| W6 | runner (Mac vantage only; J7 pattern) | the client address',
                '| W7 | runner (Mac vantage only; J7 pattern) | the firewall state'):
        e(row in guide, f'the guide carries the W-row ({row[2:20]}...); its text must match the code')
    e('docker-forwarding` policy' in guide and '--add-port=443/tcp' in guide,
      "the guide carries the F10 firewall sentences (Docker's rules, the IPv6 zone clause, DOCKER-USER/bind address)")
    # ── review round (TOPOFIX-IMPL-REVIEW §4): the four defects the 48 mutants could not reach ──
    # B1: the preflight must skip the agent's own directory BEFORE the digest read; pin the choice
    # by text order (the `continue` sits above the hashlib read in agent_preflight's python).
    preflight = runner_text[runner_text.index('agent_preflight() {'):runner_text.index('case "$BROWSER_MODE" in', runner_text.index('agent_preflight() {'))]
    skip_at = preflight.find("startswith(\"mac/\")")
    hash_at = preflight.find('hashlib.sha256(open(local')
    e(0 <= skip_at < hash_at,
      'the agent preflight skips scripts/gate/mac/* BEFORE computing the digest (review B1: the agent\'s own files are not in the guest, so reading before the skip - or no skip at all - refuses every agent run)')
    # S1: the external-attempt guard compares host NAMES (the stories build the tracker with the
    # bare host; X4's Perses origin is https://<host>:3443 and user:port comparisons would
    # classify its own SPA churn as an external attempt).
    e('u.hostname !== host' in launch_mod_code and 'host: u.hostname' in launch_mod_code,
      'the external-attempts guard compares u.hostname against the bare host and records the hostname (review S1)')
    # S4: the response echoes the rendezvous nonce by protocol; the runner redacts it before the
    # raw log and the row's response copy see it.
    e('${CAP//$REND_NONCE/<rendezvous-nonce-redacted>}' in runner_text,
      'the runner redacts the rendezvous nonce from the agent response before the raw log and the row copy (review S4; the response echo is protocol, the receipt must not carry the token)')
    # S2: X1 asserts its own exact count in both vantages, the way X3/X4 do.
    x1_story = (ROOT / 'scripts/gate/screenshots.mjs').read_text()
    e('const SHOTS_EXPECTED = MAC ? 12 : 11;' in x1_story,
      'X1 asserts the exact PNG count in both vantages (11 container, 12 Mac with the interstitial shot; review S2)')

    # U9 evidence must render (tag, result, detail) 3-tuples: the rocky-4a run
    # at 959fed2 failed the gate with `TypeError: not all arguments converted`
    # (harness/gate-receipts/rocky-4a-959fed2/raw.log:85) because u9_body
    # joined its cases with `'%s: %s' % c`. The format string is read from the
    # real u9_body source so this test runs the shipped expression, not a copy.
    u9_body = (ROOT / 'scripts/gate/phase4_grafana.py').read_text().split(
        'def u9_body', 1)[1].split('\n    def ', 1)[0]
    u9_fmt = re.search(r"'([^']*%s[^']*)' % c for c in cases", u9_body)
    e(u9_fmt is not None, 'u9_body must join per-case evidence from its cases')
    if u9_fmt is not None:
        u9_cases = [('a-immediate', 'PASS', 'sessions 1->0 form=True confirmation=False old-cookie=401'),
                    ('b-after-6min', 'FAIL', 'only 5/6 keep-alive 200s')]
        try:
            u9_rendered = ' | '.join(u9_fmt.group(1) % c for c in u9_cases)
        except TypeError as exc:
            e(False, 'u9 evidence formatting must accept (tag, result, detail) cases; got TypeError: ' + str(exc))
        else:
            e(all(tag in u9_rendered and result in u9_rendered and detail in u9_rendered
                  for tag, result, detail in u9_cases),
              'u9 evidence must keep per-case tag, result and detail; got ' + repr(u9_rendered))

    # U28 loki_push_body must encode Stream.labels as one LogQL selector
    # string: rocky-4a at bfd1158 answered the gate's proto push 400 with the
    # labels built as nested LabelAdapter messages (receipt U28
    # stored=NOT_RUN). Runs the shipped builder, not a copy.
    if str(ROOT / 'scripts/gate') not in sys.path:
        sys.path.insert(0, str(ROOT / 'scripts/gate'))
    g4 = __import__('phase4_grafana')
    u28_payload = g4.loki_push_body(
        {'job': 'p4-u28-reach', 'source': 'u28-proto-gate'},
        'u28 reach line check', 1791839245241486072)

    def _u28_varint(buf, pos):
        res, shift = 0, 0
        while True:
            byte = buf[pos]
            pos += 1
            res |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                return res, pos

    u28_pos = 0
    _, u28_pos = _u28_varint(u28_payload, u28_pos)
    u28_tag = u28_payload[u28_pos]
    u28_pos += 1
    e((u28_tag & 0x03) == 0, 'u28 payload must be a snappy literal')
    u28_len = u28_tag >> 2
    if u28_len < 60:
        u28_len += 1
    elif u28_len == 60:
        u28_len = u28_payload[u28_pos] + 1
        u28_pos += 1
    elif u28_len == 61:
        u28_len = int.from_bytes(u28_payload[u28_pos:u28_pos + 2], 'little') + 1
        u28_pos += 2
    elif u28_len == 62:
        u28_len = int.from_bytes(u28_payload[u28_pos:u28_pos + 3], 'little') + 1
        u28_pos += 3
    else:
        u28_len = int.from_bytes(u28_payload[u28_pos:u28_pos + 4], 'little') + 1
        u28_pos += 4
    u28_stream = u28_payload[u28_pos:u28_pos + u28_len]
    e(len(u28_stream) == u28_len, 'u28 snappy preamble must match the literal length')
    u28_labels = None
    u28_at, u28_end = 0, len(u28_stream)
    while u28_at < u28_end:
        u28_tagno, u28_at = _u28_varint(u28_stream, u28_at)
        u28_field, u28_wire = u28_tagno >> 3, u28_tagno & 0x07
        if u28_wire != 2:
            _, u28_at = _u28_varint(u28_stream, u28_at)
            continue
        u28_size, u28_at = _u28_varint(u28_stream, u28_at)
        u28_val = u28_stream[u28_at:u28_at + u28_size]
        u28_at += u28_size
        if u28_field != 1 or len(u28_val) >= len(u28_stream):
            continue
        u28_in, u28_in_end = 0, len(u28_val)
        while u28_in < u28_in_end:
            u28_stag, u28_in = _u28_varint(u28_val, u28_in)
            u28_sfield, u28_swire = u28_stag >> 3, u28_stag & 0x07
            if u28_swire != 2:
                _, u28_in = _u28_varint(u28_val, u28_in)
                continue
            u28_ssize, u28_in = _u28_varint(u28_val, u28_in)
            u28_sval = u28_val[u28_in:u28_in + u28_ssize]
            u28_in += u28_ssize
            if u28_sfield == 1:
                try:
                    u28_text = u28_sval.decode()
                except ValueError:
                    continue
                if 'job=' in u28_text:
                    u28_labels = u28_text
    e(u28_labels is not None and 'job="p4-u28-reach"' in u28_labels
      and 'source="u28-proto-gate"' in u28_labels,
      'u28 push labels must be one selector string; got ' + repr(u28_labels))

    # U9 keep-alive must observe all six minute boundaries: rocky-4a at
    # bfd1158 got only 5/6 keeps because the loop ran while < start+360.
    # Runs the shipped scheduler with a fake clock, not a copy.
    import time as _u9_time
    u9_gate = g4
    u9_real_mono, u9_real_sleep = _u9_time.monotonic, _u9_time.sleep
    u9_now = [1000.0]
    u9_hits = []
    _u9_time.monotonic = lambda: u9_now[0]  # noqa: E731
    _u9_time.sleep = lambda s: u9_now.__setitem__(0, u9_now[0] + s)  # noqa: E731
    try:
        u9_probe = types.SimpleNamespace(
            one_request=lambda driver: (u9_hits.append(1), (200, ''))[1])
        u9_keeps = u9_gate.Gate._u9_keep_active.__get__(u9_probe, u9_gate.Gate)(None, 6)
    finally:
        _u9_time.monotonic, _u9_time.sleep = u9_real_mono, u9_real_sleep
    e(u9_keeps == 6 and len(u9_hits) == 6 and u9_now[0] - 1000.0 >= 360,
      'u9 keep-alive must make all 6 boundary requests over the real 6-minute '
      'interval; got %s keeps in %.0f s' % (u9_keeps, u9_now[0] - 1000.0))


def js_lines(text):
    """The code lines of a JS source, stripped, with comment-only lines and trailing `// ...` comments removed.
    Every pin built on these lines is a whole-line match: a claim kept in a comment cannot satisfy it (TR2 G6)."""
    out = []
    for raw in text.splitlines():
        line = re.sub(r'\s//(?:\s.*)?$', '', raw).strip()
        if line and not line.startswith('//'):
            out.append(line)
    return out


def sh_lines(text):
    """The code lines of a shell script: stripped, comment-only lines and trailing `# ...` comments removed (see js_lines)."""
    out = []
    for raw in text.splitlines():
        line = re.sub(r'\s+#(?:\s.*)?$', '', raw).strip()
        if line and not line.startswith('#'):
            out.append(line)
    return out


def check_topofix2(checks):
    """TOPOFIX2 fix round (harness/phase4-completion/w2/TOPOFIX2-BRIEF.md): behaviour pins for the defects the first read of the
    Mac agent vantage found (PRE-0..PRE-7, F1-F8, G5-G7). Pins are whole-line matches on the code lines (js_lines) or
    multiline regexes anchored at the line start, each with a mutant in harness/phase4-completion/raw/TOPOFIX2/mutants.log."""
    e = lambda cond, msg: checks.expect(cond, 'topofix2: ' + msg)  # noqa: E731
    agent_text = (ROOT / 'scripts/gate/mac/agent.mjs').read_text()
    agent_lines = js_lines(agent_text)
    agent_code = '\n'.join(agent_lines)
    remote_text = (ROOT / 'scripts/gate/browser_remote.py').read_text()
    topo_runner_text = (ROOT / 'scripts/gate-identity.sh').read_text()
    topo_runner_lines = sh_lines(topo_runner_text)

    # PRE-0: the rendezvous lives in the GUEST (the VM is --mount-none). Every operation on it is a guest operation
    # through limactl; nothing in the agent touches a Mac file named after RDV, a claim or a guest temp.
    for line in (
        'const GUEST_PATH_RE = /^\\/[A-Za-z0-9._/-]+$/;',
        "if (typeof p !== 'string' || !GUEST_PATH_RE.test(p) || posix.normalize(p) !== p) {",
        "function q(p) { return `'${guestPath('guest command path', p)}'`; }",
        "if (!RDV.startsWith(GUEST_ROOT + '/')) die('--rendezvous must sit under --guest-root');",
        "return sh('limactl', ['shell', VM, '--', 'sh', '-c', script], { timeout: opts.timeout || 30000, allowFail: opts.allowFail });",
        "return guestSh(`ls -1A -- ${q(RDV)}`).out.split('\\n').filter((x) => /^req-[0-9]{4}\\.json$/.test(x)).sort();",
        'const src = `${RDV}/${file}`;',
        'const claimed = `${src}.claimed-${process.pid}`;',
        'if (guestSh(`mv -- ${q(src)} ${q(claimed)}`, { allowFail: true }).status !== 0) return null;',
        'try { parsed = guestReadJson(claimed, RDV); } catch (e) {',
        "return JSON.parse(guestReadFile(fixedPath, mustBeUnder).toString('utf8'));",
        "guestPut('agent-hello.json', JSON.stringify(hello, null, 2) + '\\n');",
        'const guestTmp = `${RDV}/.${name}.${process.pid}.tmp`;',
        'writeFileSync(local, text, { mode: 0o600 });',
        'chmodSync(local, 0o600);',
        "sh('limactl', ['copy', '--backend=scp', local, `${VM}:${guestTmp}`], { timeout: 60000 });",
        'guestSh(`mv -f -- ${q(guestTmp)} ${q(`${RDV}/${name}`)}`);',
        'rmSync(local, { force: true });',
        'dropClaimed(claimedPath);',
        "if (!Number.isInteger(parsed.id) || parsed.id < 1 || parsed.id > 9999) {",
    ):
        e(line in agent_lines, f'agent.mjs must carry the code line {line!r} (PRE-0: the rendezvous is a guest directory reached only through limactl; a mutant that keeps it in a comment fails)')
    e(re.search(r"^const RDV = guestPath\('--rendezvous', ", agent_code, re.M) is not None
      and re.search(r"^const GUEST_ROOT = guestPath\('--guest-root', ", agent_code, re.M) is not None
      and re.search(r"^const GUEST_CERT_PATH = guestPath\('--guest-cert', ", agent_code, re.M) is not None,
      'agent.mjs validates --rendezvous, --guest-root and --guest-cert as guest paths (no resolve(): they are not Mac paths)')
    e(re.search(r"^try \{ guestSh\(`rm -f -- \$\{q\(claimedPath\)\}`\); \} catch \(e\)", agent_code, re.M) is not None,
      'agent.mjs removes a claimed request with one guest `rm -f --` (after its response or its refusal)')
    e(re.search(r"^const poll = setInterval\(\(\) => \{\n(?:.*\n)*?\}, POLL_INTERVAL_MS\);", agent_code, re.M) is not None
      and 'guestListRequests()' in agent_code,
      'agent.mjs polls the guest rendezvous through guestListRequests() on POLL_INTERVAL_MS')
    e(re.search(r"\b(?:writeFileSync|renameSync|readFileSync|readdirSync|rmSync|existsSync|statSync|mkdirSync|copyFileSync|unlinkSync|openSync|chmodSync)\([^;\n]*\b(?:RDV|claimed|claimedPath|guestTmp|src)\b", agent_code) is None,
      'agent.mjs must not apply a Mac file-system call to the rendezvous (RDV, a claim, a guest temp): PRE-0, the VM is --mount-none')
    e('renameSync' not in agent_code and 'readdirSync(RDV' not in agent_code and 'resolve(args.rendezvous' not in agent_code
      and "resolve(args['guest-root']" not in agent_code and 'addSecret' not in agent_code and 'GUEST_STATE_DIR' not in agent_code,
      'agent.mjs carries no Mac rename, no Mac rendezvous listing, no resolve() of a guest path, no addSecret and no GUEST_STATE_DIR (PRE-0)')

    # PRE-1: the requester sends the int id, waits for resp-<4 digits>.json and compares the int.
    e(re.search(r"^guestPut\(`resp-\$\{String\(req\.id\)\.padStart\(4, '0'\)\}\.json`, ", agent_code, re.M) is not None,
      'agent.mjs writes the response as resp-<4 digit id>.json, the name browser_remote.py waits for (PRE-1)')
    remote_lines = [ln.strip() for ln in remote_text.splitlines()]
    e('if resp.get("nonce") != nonce or resp.get("id") != int(req_id):' in remote_lines and 'resp.get("id") != req_id' not in remote_text,
      'browser_remote.py compares the response id with int(req_id): the request carries the int and the file name the padded string (PRE-1)')

    # PRE-2 / PRE-3 / PRE-7: the launcher creates agent-out with the rendezvous, waits for the first hello IN THE GUEST
    # before it starts the runner, and the guest command is the bound, full-inventory shape of a bundle host.
    launcher_lines = sh_lines((ROOT / 'scripts/gate/mac/run-vm-gate.sh').read_text())
    wait_lines = (
        'for _ in $(seq 1 45); do',
        'if limactl shell "$VM" -- test -s "$RDV/agent-hello.json" 2>/dev/null; then hello_seen=1; break; fi',
        'kill -0 "$AGENT_PID" 2>/dev/null || { echo "run-vm-gate: the agent exited before its hello reached $RDV (see $OUT/agent.log)" >&2; exit 2; }',
        'sleep 2',
        '(( hello_seen == 1 )) || { echo "run-vm-gate: no agent-hello.json in $RDV within 90 s (see $OUT/agent.log)" >&2; exit 2; }',
    )
    for line in ('limactl shell "$VM" -- mkdir -p "$RDV" "$GUEST_ROOT/agent-out" 2>/dev/null',) + wait_lines:
        e(line in launcher_lines, f'run-vm-gate.sh must carry the code line {line!r} (PRE-2: wait up to 90 s for the hello in the guest, exit 2 when the agent died or nothing came; PRE-3: agent-out is created with the rendezvous)')
    guest_cmd = next((ln for ln in launcher_lines if ln.startswith('GUEST_CMD="')), '')
    if all(line in launcher_lines for line in wait_lines):
        at = {name: launcher_lines.index(name) for name in ('AGENT_PID=$!', wait_lines[0])}
        e(at['AGENT_PID=$!'] < at[wait_lines[0]] < launcher_lines.index(guest_cmd) if guest_cmd else False,
          'run-vm-gate.sh waits for the hello after the agent starts and before the guest runner command is built (PRE-2)')
    e(re.search(r' --browser agent --rendezvous \$RDV --rendezvous-nonce \$NONCE --candidate \$CANDIDATE --repo \$GUEST_ROOT/repo"$', guest_cmd) is not None,
      'the launcher\'s guest command carries --candidate $CANDIDATE --repo $GUEST_ROOT/repo, the bound full-inventory shape the guide documents for a bundle host (PRE-7 / F1)')
    guide_text = (ROOT / 'sso/guides/identity-gate.md').read_text()
    e(re.search(r"^scripts/gate-identity\.sh --edition-dir /opt/krate/epc --wipe --phase 4c --public-host krate-oi\.test \\\n"
                r"  --browser agent --rendezvous /home/<guest-user>/gate/rdv --rendezvous-nonce <the launcher's token> \\\n"
                r"  --candidate <sha> --repo /home/<guest-user>/gate/repo ", guide_text, re.M) is not None,
      "the guide's launcher example states that the guest command carries --candidate and --repo (PRE-7 / F1)")

    # PRE-5: browser.json is read from the LIVE page: browserEvidence runs before browser.close() in the three stories (their
    # finally block) and in U15 (its closing block). After the close page.evaluate throws, userAgent is '' and the
    # HeadlessChrome refusal can never fire.
    for story_name in ('screenshots.mjs', 'screenshots-grafana.mjs', 'screenshots-perses.mjs'):
        story_lines = js_lines((ROOT / 'scripts/gate' / story_name).read_text())
        finally_at = max((i for i, ln in enumerate(story_lines) if ln == '} finally {'), default=-1)
        tail = story_lines[finally_at:] if finally_at >= 0 else []
        ev_at = next((i for i, ln in enumerate(tail) if ln.startswith('const ev = await browserEvidence(')), -1)
        close_at = [i for i, ln in enumerate(tail) if ln == 'await browser.close();']
        e(ev_at >= 0 and len(close_at) == 1 and ev_at < close_at[0],
          f'{story_name} reads browserEvidence from the live page BEFORE browser.close() in its finally block (PRE-5)')
    u15_lines = js_lines((ROOT / 'scripts/gate/phase4-browser.mjs').read_text())
    ev_lines = [i for i, ln in enumerate(u15_lines) if ln.startswith('const ev = await browserEvidence(')]
    close_lines = [i for i, ln in enumerate(u15_lines) if ln == 'await browser.close();']
    e(len(ev_lines) == 1 and len(close_lines) == 1 and ev_lines[0] < close_lines[0],
      'phase4-browser.mjs (U15) reads browserEvidence before its closing browser.close() (PRE-5; already so before TOPOFIX2, pinned now)')

    # G7: the no-interstitial step is persisted before the non-zero exit; the dead throw in onAssert is gone.
    e("result.steps.push({ t: new Date().toISOString(), name: 'no-interstitial', error: accepted.error });" in u15_lines,
      'phase4-browser.mjs pushes the no-interstitial step when acceptGateCertificate returns no proceed decision (G7)')
    e(not any(ln.startswith('if (!d.seen) throw') for ln in u15_lines),
      'phase4-browser.mjs carries no `if (!d.seen) throw` in onAssert: the hook runs only when the interstitial was seen (G7: dead code)')
    summary_at = [i for i, ln in enumerate(u15_lines) if ln.startswith('try { writeFileSync(`${OUT}/ui15-summary.json`, JSON.stringify({ steps: result.steps, storyFailed:')]
    exit_at = [i for i, ln in enumerate(u15_lines) if ln == 'process.exit(2);']
    e(len(summary_at) == 1 and bool(exit_at) and summary_at[0] < exit_at[0],
      'phase4-browser.mjs writes ui15-summary.json (steps, no-interstitial included) BEFORE the non-zero exit of the story-failed path (G7)')

    # PRE-6 + G5: W5's IPv6 leg. The agent passes the guest's GLOBAL address without a zone (a zone only on fe80::/10) and
    # probe.mjs accepts that shape; the runner derives the docker-published set WITHOUT sshd's 22, the IPv6 rule fails only
    # an open docker-published port, and 22 over IPv6 is the positive control. The runner's real extracted Python decides
    # the four shapes (M4: 22 open, the rest refused; 22 refused; 443 open; no vm_g6) exactly as the TR2 G4 battery ran it.
    for line in (
        "function v6Target(addr, iface) { return /^fe[89ab][0-9a-f]:/i.test(addr) && iface ? `${addr}%${iface}` : addr; }",
        "if (STATE.g6) argv.push('--v6', v6Target(STATE.g6, STATE.iface));",
    ):
        e(line in agent_lines, f'agent.mjs must carry the code line {line!r} (PRE-6: the global IPv6 address goes to the probe without a %iface zone)')
    probe_lines = js_lines((ROOT / 'scripts/gate/mac/probe.mjs').read_text())
    e(any(ln.startswith('if (!net.isIPv6(ll) || (linkLocal && !iface) || (!linkLocal && iface)) die(') for ln in probe_lines)
      and 'const target = iface ? `${ll}%${iface}` : ll;' in probe_lines
      and 'const r = await connectOnce(target, p, 6, Math.max(timeoutMs, 3000));' in probe_lines,
      'probe.mjs accepts a global --v6 address without a zone and an fe80::/10 address only with its zone, and connects to that target (PRE-6)')
    e('docker_csv="$(printf \'%s\\n\' $any_ports | LC_ALL=C sort -n -u | paste -s -d, -)"' in topo_runner_lines
      and any(ln.startswith('evidence="$(W5_EXPECTED="$expected_csv" W5_DOCKER="$docker_csv" W5_VM_G6="${VM_G6:-}" python3 -I - ') for ln in topo_runner_lines),
      'the W5 row derives the docker-published set from $any_ports WITHOUT 22 and passes it, with vm_g6, to its Python as W5_DOCKER / W5_VM_G6 (G5)')
    pyw5 = re.search(r"<<'PYW5' 2>>\"\$RAW\"\n(.*?)\nPYW5\n", topo_runner_text, re.S)
    e(pyw5 is not None, 'the W5 row keeps its evaluation in the PYW5 heredoc (the pinned cases below run its real text)')
    if pyw5 is not None:
        w5_python = pyw5.group(1)
        w5_docker = '80,443,3443,9092,9093'

        def w5_case(v6_ports, vm_g6, with_v6=True):
            report = {'swept': {'tcpOnly': True}, 'counts': {'open': 6}, 'open': [22, 80, 443, 3443, 9092, 9093],
                      'spot': [{'port': 111, 'outcome': 'refused'}],
                      'cert': {'authorized': True, 'protocol': 'TLSv1.3', 'sha256': 'ab12'},
                      'mac_leak_scan': {'values': 0, 'hits': 0, 'stores': ['agent.log']}}
            if with_v6:
                report['v6'] = {'address': 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96', 'addressClass': 'global',
                                'ports': [{'port': port, 'outcome': outcome} for port, outcome in v6_ports]}
            with tempfile.TemporaryDirectory() as w5_tmp:
                result_path = Path(w5_tmp) / 'w5-result.json'
                result_path.write_text(json.dumps(report))
                env = dict(os.environ, W5_EXPECTED='22,' + w5_docker, W5_DOCKER=w5_docker, W5_VM_G6=vm_g6)
                run = subprocess.run([sys.executable, '-I', '-', str(result_path), 'running'], input=w5_python, env=env, text=True, capture_output=True)
            return run.returncode, run.stdout + run.stderr

        m4_shape = [(22, 'open'), (80, 'refused'), (443, 'refused'), (111, 'refused'), (3443, 'refused'), (9092, 'refused'), (9093, 'refused')]
        rc_m4, out_m4 = w5_case(m4_shape, 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96')
        e(rc_m4 == 0 and 'breaches=0' in out_m4 and 'BREACH' not in out_m4 and '22 answers over IPv6 (sshd; M4)' in out_m4,
          f'W5 on the M4 IPv6 shape (22 open, the docker-published ports refused) has no breach and records the 22 control; got rc {rc_m4}: {out_m4[-200:]!r} (G5)')
        rc_c, out_c = w5_case([(22, 'refused')] + m4_shape[1:], 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96')
        e(rc_c == 1 and "IPv6 positive control: sshd's 22 did not answer over IPv6 (refused)" in out_c,
          f"W5 FAILs when the hello carries a global address and sshd's 22 is refused over IPv6; got rc {rc_c}: {out_c[-200:]!r} (G5/PRE-6)")
        rc_b, out_b = w5_case([(22, 'open'), (443, 'open')] + m4_shape[1:2] + m4_shape[3:], 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96')
        e(rc_b == 1 and 'BREACH docker-published port 443 is open over IPv6' in out_b and 'BREACH docker-published port 22' not in out_b,
          f'W5 breaches on an open docker-published port (443) over IPv6 and never on sshd\'s 22; got rc {rc_b}: {out_b[-200:]!r} (G5)')
        rc_n, out_n = w5_case([], '', with_v6=False)
        e(rc_n == 0 and 'v6=not-run (no guest IPv6 global address, vm_g6, in the hello)' in out_n and 'BREACH' not in out_n and 'positive control' not in out_n,
          f'W5 without a global address in the hello keeps the not-run text and does not decide; got rc {rc_n}: {out_n[-200:]!r} (G5)')
        rc_s, out_s = w5_case([], 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96', with_v6=False)
        e(rc_s == 1 and "IPv6 positive control: sshd's 22 did not answer over IPv6 (not-swept)" in out_s,
          f'W5 FAILs when the hello carries a global address but the result has no IPv6 pass; got rc {rc_s}: {out_s[-200:]!r} (G5)')

    # PRE-4: the W7 Ubuntu branch decides on the first line of `ufw status`, never on the ufw.service state (a oneshot that reads
    # `active (exited)` while ufw is inactive). The runner's own lines run against fake sudo/ufw commands.
    ufw_first_line = next((ln for ln in topo_runner_lines if ln.startswith('ufw_first="$(')), '')
    case_match = re.search(r'^ {4}case "\$ufw_first" in\n(?: {6}.*\n)+? {4}esac$', topo_runner_text, re.M)
    e(ufw_first_line == 'ufw_first="$( { sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null; } | head -1 || true)"'
      and case_match is not None and 'ufw_state' not in (case_match.group(0) if case_match else 'ufw_state')
      and '[[ "$ufw_state" == active ]]' not in topo_runner_text,
      'W7 (Ubuntu) reads the first line of `ufw status` (sudo -n, then plain) and decides on it in a case block that never looks at the ufw.service state (PRE-4)')
    if case_match is not None and ufw_first_line:
        def w7_ubuntu(sudo_body, ufw_body):
            with tempfile.TemporaryDirectory() as w7_tmp:
                fake_bin = Path(w7_tmp)
                for name, body in (('sudo', sudo_body), ('ufw', ufw_body)):
                    (fake_bin / name).write_text('#!/bin/sh\n' + body + '\n')
                    (fake_bin / name).chmod(0o755)
                script = 'st=0; ufw_reason=""\n' + ufw_first_line + '\n' + case_match.group(0) + '\nprintf "%s|%s|%s\\n" "$st" "$ufw_first" "$ufw_reason"\n'
                run = subprocess.run(['bash', '-c', script], env=dict(os.environ, PATH=f'{fake_bin}:{os.environ["PATH"]}'), text=True, capture_output=True)
            return run.stdout.strip()
        pass_sudo = 'exec "$@"'
        e(w7_ubuntu(pass_sudo, 'echo "Status: inactive"') == '0|Status: inactive|',
          'W7 (Ubuntu) passes on `Status: inactive` (PRE-4)')
        e(w7_ubuntu(pass_sudo, 'echo "Status: active"; echo "To  Action  From"') == '1|Status: active|',
          'W7 (Ubuntu) fails on `Status: active` (as before; PRE-4)')
        e(w7_ubuntu('exit 1', 'echo "ERROR: You need to be root to run this script" >&2; exit 1') == '1||ufw status unreadable (needs root or passwordless sudo)',
          'W7 (Ubuntu) fails with the unreadable reason when ufw status cannot be read without root (PRE-4)')
        e(w7_ubuntu(pass_sudo, 'echo "Status: unknown"') == '1|Status: unknown|ufw status unreadable (needs root or passwordless sudo)',
          'W7 (Ubuntu) fails on any first line that is neither Status: active nor Status: inactive (PRE-4)')

    # F2: --browser knows container and agent only (`local` selected nothing and was only recorded in the receipt row), and the
    # guide says what the code does: a 4c agent run needs neither image; the 4a/4b stories keep the guest's container vantage.
    topo_runner_flat = '\n'.join(topo_runner_lines)
    e('case "$BROWSER_MODE" in container|agent) ;; *) echo "--browser must be container or agent: $BROWSER_MODE" >&2; exit 2 ;; esac' in topo_runner_lines
      and 'container)' in topo_runner_lines
      and 'container|local' not in topo_runner_flat and 'local|container' not in topo_runner_flat and 'container, local' not in topo_runner_flat
      and 'local (the fixture' not in topo_runner_text,
      'the runner accepts --browser container or agent only: no `local` in the parser case, the second case, the usage text or the default comment (F2)')
    # The behaviour is checked on the runner's own refusal line alone, never by running the runner: a runner that wrongly accepted
    # the mode would go on to start a gate run (a mutant did, and recursed through this check).
    bash_for_f2 = bash_binary()
    browser_case = next((ln for ln in topo_runner_lines if ln.startswith('case "$BROWSER_MODE" in ') and ' exit 2 ;; esac' in ln), '')
    if bash_for_f2 is not None and browser_case:
        def browser_refusal(mode):
            run = subprocess.run([bash_for_f2, '-c', 'BROWSER_MODE="$1"\n' + browser_case + '\necho reached', 'bash', mode], text=True, capture_output=True)
            return run.returncode, run.stdout.strip(), run.stderr.strip()
        e(browser_refusal('local') == (2, '', '--browser must be container or agent: local'),
          f'`--browser local` is refused with exit 2 and the message (the runner\'s own refusal line); got {browser_refusal("local")!r} (F2)')
        e(browser_refusal('container') == (0, 'reached', '') and browser_refusal('agent') == (0, 'reached', ''),
          'the runner\'s refusal line lets container and agent through (F2)')
    guide_flat = ' '.join(guide_text.split())
    e('A `--phase 4c --browser agent` run on a vzNAT VM fixture needs neither image' in guide_flat
      and "The 4a/4b stories (U15, X3, X4) still run in the guest's container vantage and need the archive" in guide_flat
      and 'their Mac vantage is the story started on the Mac with `GATE_BROWSER_MAC=1`, as the X1 row describes' in guide_flat
      and 'that archive is no longer loaded into the guest at all' not in guide_flat
      and 'Only the rows W5 and W6 of slice 4c go through the agent' in guide_flat,
      'the guide says what the code does: a 4c agent run needs neither image, the 4a/4b stories keep the guest container vantage and need the archive, only W5/W6 go through the agent (F2)')

    # F7: mac_src_ip must lie inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16 (network membership). The runner's own preflight
    # Python runs on synthetic hellos; ipaddress.is_private would have accepted 198.18.0.1, 192.0.2.5 and 203.0.113.9.
    preflight_py = re.search(r"<<'PYPREFLIGHT'\n(.*?)\nPYPREFLIGHT\n", topo_runner_text, re.S)
    e(preflight_py is not None, 'the agent preflight keeps its Python in the PYPREFLIGHT heredoc (the F7 cases below run its real text)')
    if preflight_py is not None:
        def preflight_case(src):
            with tempfile.TemporaryDirectory() as pf_tmp:
                hello_path = Path(pf_tmp) / 'agent-hello.json'
                hello_path.write_text(json.dumps({'schema': 1, 'nonce': 'n0nce', 'clock_skew_ms': 5, 'mac_src_ip': src, 'vm_ip': '192.168.64.2',
                                                  'gate_files': {}, 'plan': ['W5', 'W6'], 'vm_g6': '', 'mac_iface': 'bridge100'}))
                run = subprocess.run([sys.executable, '-I', '-', str(hello_path), 'n0nce', pf_tmp], input=preflight_py.group(1), text=True, capture_output=True)
            return run.returncode, run.stdout, run.stderr
        for ok_src in ('192.168.64.1', '10.0.0.1', '10.255.255.254', '172.16.0.1', '172.31.255.254', '192.168.255.254'):
            rc_f7, out_f7, err_f7 = preflight_case(ok_src)
            e(rc_f7 == 0 and f'MAC_SRC_IP={ok_src}' in out_f7, f'the preflight accepts mac_src_ip {ok_src} (inside 10/8, 172.16/12 or 192.168/16); got rc {rc_f7}: {err_f7.strip()[:120]!r} (F7)')
        for bad_src in ('198.18.0.1', '192.0.2.5', '203.0.113.9', '169.254.10.1', '172.15.255.255', '172.32.0.1', '100.64.0.1', '127.0.0.1', 'fd00::1', 'not-an-address'):
            rc_f7, out_f7, err_f7 = preflight_case(bad_src)
            e(rc_f7 == 2 and 'mac_src_ip' in err_f7 and 'MAC_SRC_IP=' not in out_f7, f'the preflight refuses mac_src_ip {bad_src} (outside the three RFC1918 networks); got rc {rc_f7}: {err_f7.strip()[:120]!r} (F7)')

    # F3: finish() records the vmip row BEFORE it computes the verdict from FAILS (a vmip FAIL must turn the verdict into FAIL).
    finish_body = re.search(r'^finish\(\) \{\n(.*?)^\}\n', topo_runner_text, re.M | re.S)
    if finish_body is None:
        e(False, 'scripts/gate-identity.sh must define finish() (F3)')
    else:
        finish_text = finish_body.group(1)
        vmip_records = [m.start() for m in re.finditer(r'^\s*record vmip "\$\{PHASE\}" W (?:PASS|FAIL) ', finish_text, re.M)]
        verdict_lines = [m.start() for m in re.finditer(r'^\s*\(\( FAILS == 0 \)\) \|\| verdict=FAIL\s*$', finish_text, re.M)]
        e(len(vmip_records) == 2 and len(verdict_lines) == 1 and max(vmip_records) < verdict_lines[0],
          'finish() records both vmip rows (PASS and FAIL branch) before `(( FAILS == 0 )) || verdict=FAIL`, so a vmip FAIL turns the verdict into FAIL (F3)')

    # F5: the Mac package.json carries no line anchor into the runner (the old one, gate-identity.sh:889, points at a kcadm line).
    mac_package = json.loads((ROOT / 'scripts/gate/mac/package.json').read_text())
    e(re.search(r'gate-identity\.sh:\d+', mac_package.get('description', '')) is None and mac_package.get('dependencies') == {'playwright': '1.60.0'},
      'scripts/gate/mac/package.json carries no gate-identity.sh:<line> anchor and still pins playwright 1.60.0 (F5)')

    # F6: the browser vantage receipt row is written in every receipt (same indentation as the host and images rows, outside any
    # agent condition); only vmip is agent-only. The guide says so.
    row_indent = {name: re.search(r'^( *)echo "\| ' + name + r' \|', topo_runner_text, re.M) for name in ('host', 'browser vantage', 'images')}
    e(all(m is not None for m in row_indent.values()) and len({len(m.group(1)) for m in row_indent.values() if m}) == 1,
      'the receipt header writes the browser vantage row unconditionally, beside the host and images rows (F6)')
    e('Only an agent run adds a `vmip` row at the end' in guide_flat and 'the `browser vantage` receipt row is written in every receipt' in guide_flat
      and '| browser vantage | the `--browser` mode of the run' in guide_text and 'The row is written in every receipt, agent run or not' in guide_flat
      and 'adds a `vmip` row at the end (the fixture\'s NIC address must still be the hello\'s — a change voids the binding) and a receipt `browser vantage` row' not in guide_flat,
      'the guide says the browser vantage row is in every receipt and only vmip is agent-only, and its field table lists the row (F6)')

    # N: two lint findings of the first read. __doc__ is None under python -OO, so main() prints (__doc__ or "").strip(); the
    # container launch never used the viewport it destructured (the stories size their own context).
    e('print((__doc__ or "").strip())' in remote_lines and 'print(__doc__.strip())' not in remote_lines,
      'browser_remote.py prints (__doc__ or "").strip() in its usage path (N: Pyright reportOptionalMemberAccess)')
    launch_lines = js_lines((ROOT / 'scripts/gate/browser-launch.mjs').read_text())
    e('export async function launchGateBrowserContainer(chromium, { host, resolveTo }) {' in launch_lines
      and 'export async function launchGateBrowserMac(chromium, { host, resolveTo, outDir, viewport = { width: 1440, height: 900 } }) {' in launch_lines,
      'browser-launch.mjs: the container launch destructures only host and resolveTo (its viewport was unused); the Mac launch keeps its viewport (N)')

    # PRE-0 (guide): the Mac vantage paragraph says where the rendezvous lives and how the agent reaches it.
    e('the rendezvous directory itself lives in the guest (the VM has no mount)' in guide_flat
      and 'puts its hello and every response with a `limactl copy --backend=scp` into a dot-temp plus one guest `mv -f`' in guide_flat
      and 'request ids from 1 to 9999' in guide_flat,
      'the guide says the rendezvous lives in the guest and how the agent lists, claims, reads, removes and puts (PRE-0)')

    # T08 (review, P1): Response.serverAddr() and Response.securityDetails() return Promises in Playwright 1.60.0
    # (playwright-core/types/types.d.ts), so the helpers that read them, the tracker's record() and every caller are async.
    for line in ('export async function assertServedFrom(resp, expected, what) {',
                 'export async function assertServedCertificate(resp, pinned, what) {',
                 'asserted.push(await assertServedFrom(state.last, expectedIp, what));',
                 'if (pinned) asserted.push(await assertServedCertificate(state.last, pinned, what));'):
        e(line in launch_lines, f'browser-launch.mjs must carry the code line {line!r} (T08: the Response helpers are asynchronous)')
    e(any(ln.startswith('try { addr = await resp.serverAddr(); }') for ln in launch_lines)
      and any(ln.startswith('try { details = await resp.securityDetails(); }') for ln in launch_lines)
      and any(ln.startswith('async record(expectedIp, pinned, what, asserted) {') for ln in launch_lines),
      'browser-launch.mjs awaits Response.serverAddr() and Response.securityDetails() and its serve tracker record() is async (T08)')
    for story_name in ('screenshots.mjs', 'screenshots-grafana.mjs', 'screenshots-perses.mjs'):
        e('if (MAC && serve) await serve.record(' in '\n'.join(js_lines((ROOT / 'scripts/gate' / story_name).read_text())),
          f'{story_name} awaits serve.record() (T08)')
    e(any(ln.startswith("served_from = (await assertServedFrom(mr, resolveTo, 'main document')) + '; ' + (await assertServedCertificate(mr, PIN, 'main document'));") for ln in u15_lines),
      'phase4-browser.mjs awaits both served-response assertions of its summary (T08)')
    unawaited = []
    for gate_js in sorted((ROOT / 'scripts/gate').rglob('*.mjs')):
        for gate_line in js_lines(gate_js.read_text()):
            for call in re.finditer(r'(\bawait\s+)?\b(?!Response\b)[a-z]\w*(?:\.\w+)*\.(?:serverAddr|securityDetails)\(\)', gate_line):
                if not call.group(1):
                    unawaited.append(f'{gate_js.name}: {gate_line[:80]}')
    e(not unawaited, f'no gate script reads Response.serverAddr()/securityDetails() without await (T08); found {unawaited}')
    node_binary = shutil.which('node')
    if node_binary:
        probe_src = (
            "const lib = await import(process.argv[1]);\n"
            "const good = { serverAddr: async () => ({ ipAddress: '192.168.64.2', port: 443 }),\n"
            "  securityDetails: async () => ({ subjectName: 'krate-oi.test', issuer: 'Krate Test CA', protocol: 'TLSv1.3', validFrom: 1, validTo: 2 }) };\n"
            "const out = { from: await lib.assertServedFrom(good, '192.168.64.2', 'x'),\n"
            "  cert: await lib.assertServedCertificate(good, { subject: 'CN=krate-oi.test', issuer: 'CN=Krate Test CA' }, 'x') };\n"
            "const refuse = async (fn) => { try { await fn(); return false; } catch { return true; } };\n"
            "out.loopbackRefused = await refuse(() => lib.assertServedFrom({ serverAddr: async () => ({ ipAddress: '127.0.0.1', port: 443 }) }, '192.168.64.2', 'x'));\n"
            "out.emptyRefused = await refuse(() => lib.assertServedFrom({ serverAddr: async () => null }, '192.168.64.2', 'x'));\n"
            "out.certMismatchRefused = await refuse(() => lib.assertServedCertificate(good, { subject: 'CN=other.test', issuer: 'CN=Krate Test CA' }, 'x'));\n"
            "console.log(JSON.stringify(out));\n"
        )
        run_node = subprocess.run([node_binary, '--input-type=module', '-e', probe_src, str(ROOT / 'scripts/gate/browser-launch.mjs')], text=True, capture_output=True)
        try:
            node_out = json.loads(run_node.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            node_out = {}
        e(run_node.returncode == 0 and 'served from 192.168.64.2:443' in node_out.get('from', '') and node_out.get('cert', '').startswith('TLS TLSv1.3')
          and node_out.get('loopbackRefused') is True and node_out.get('emptyRefused') is True and node_out.get('certMismatchRefused') is True,
          f'the served-address and served-certificate assertions accept a valid asynchronous Response and refuse loopback, empty and mismatching ones; got rc {run_node.returncode}: {run_node.stderr.strip()[:200]!r} {node_out!r} (T08)')


def check_k37_wiring(checks):
    """Gate row K37 (Kafbat's absolute session lifetime): the helper, the 4a companion wiring of the runner and the guide rows agree."""
    e = lambda cond, msg: checks.expect(cond, 'gate row K37: ' + msg)  # noqa: E731
    if str(ROOT / 'scripts/gate') not in sys.path:
        sys.path.insert(0, str(ROOT / 'scripts/gate'))
    kafbat = __import__('phase4_kafbat')
    phase2 = __import__('phase2_kafbat')
    e(kafbat.CASES == ['K37'] and kafbat.Gate.CASES == ['K37'] and kafbat.Gate.SLICE == '4a',
      f'phase4_kafbat.py owns exactly K37 in slice 4a; got {kafbat.CASES} / {kafbat.Gate.SLICE}')
    e('K37' not in phase2.CASES, 'phase2_kafbat.CASES must not print K37 (it would be ingested into every Phase 2 receipt as a NOT_RUN row)')
    runner = (ROOT / 'scripts/gate-identity.sh').read_text()
    e(re.search(r'^SESSION_P4A=\(U27 K37\)$', runner, re.M) is not None, 'the 4a companion inventory SESSION_P4A must be (U27 K37)')
    e(re.search(r'^SESSION_P4B=\(U27 V23\)$', runner, re.M) is not None, 'the 4b companion inventory SESSION_P4B must stay (U27 V23): K37 runs once per host, in 4a')
    e(re.search(r'^REQUIRED_P(?:2|4[ABC])=\(.*\bK37\b', runner, re.M) is None, 'K37 belongs to no default inventory, only to the companion')
    e('4a) helper_jobs=("$GATE_DIR/phase4_grafana.py U27 U" "$GATE_DIR/phase4_kafbat.py K37 K") ;;' in runner,
      'the 4a companion must run phase4_kafbat.py --only K37 beside U27')
    e('4a) prep_helpers=("$GATE_DIR/phase4_grafana.py" "$GATE_DIR/phase4_kafbat.py") ;;' in runner,
      'the 4a companion must prepare the K37 viewer after the Grafana preparation')
    e('phase4_kafbat' not in runner[runner.index('4b) helper_jobs=("$GATE_DIR/phase4_grafana.py U27 U"'):].split('\n', 1)[0],
      'the 4b companion must not run K37')
    guide = (ROOT / 'sso/guides/identity-gate.md').read_text()
    for row in ('U27', 'V23', 'K37'):
        e(re.search(r'^\| %s \|' % row, guide, re.M) is not None, f'identity-gate.md must have a row for the companion row {row}')
    k37_row = next((line for line in guide.splitlines() if line.startswith('| K37 |')), '')
    for probe in kafbat.PROBES:
        e(f'`{probe}`' in k37_row, f'the identity-gate.md K37 row must describe the probe {probe}')
    e('Ended a session that reached its maximum lifetime of PT<N>H' in k37_row and 'Absolute session lifetime: PT<N>H' in k37_row,
      'the identity-gate.md K37 row must name the two Kafbat log lines the row reads')
    e('gate row K37' in (ROOT / 'sso/guides/dual-login.md').read_text(),
      'dual-login.md must cite gate row K37 where it states the absolute session lifetime')


def check_phase4_monitor_paths(checks):
    """The Phase IV gate must find monitoring in both source and offline bundle layouts."""
    from unittest.mock import patch
    import ssl

    e = lambda cond, msg: checks.expect(cond, 'phase4 monitoring path: ' + msg)  # noqa: E731
    sys.path.insert(0, str(ROOT / 'scripts/gate'))
    grafana = __import__('phase4_grafana')
    perses = __import__('phase4_perses')
    kafbat = __import__('phase4_kafbat')
    phase2 = __import__('phase2_kafbat')
    runner = (ROOT / 'scripts/gate-identity.sh').read_text()
    start = runner.index('MON_DIR="$ED/monitoring"')
    stop = runner.index('MON_PROJECT=', start)
    select_shell = runner[start:stop]

    def check_case(edition, expected):
        for module in (grafana, perses, kafbat):
            gate = object.__new__(module.Gate)
            gate.edition = str(edition)
            e(gate.mon_dir() == str(expected),
              f'{module.__name__} selected {gate.mon_dir()} for {edition}; expected {expected}')
        script = 'ED="$1"\n' + select_shell + '\nprintf "%s" "$MON_DIR"\n'
        selected = subprocess.run(['bash', '-euc', script, 'bash', str(edition)],
                                  text=True, capture_output=True)
        e(selected.returncode == 0 and selected.stdout == str(expected),
          f'gate-identity selected {selected.stdout!r} for {edition}; expected {expected}; {selected.stderr}')

    for edition in EDITIONS:
        check_case(ROOT / edition, ROOT / 'monitoring')

    fixture_root = ROOT / 'harness' / 'phase4' / 'path-contract'
    fixture_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=fixture_root) as tmp:
        base = Path(tmp)
        for edition in EDITIONS:
            installed = base / edition
            nested = installed / 'monitoring'
            nested.mkdir(parents=True)
            check_case(installed, nested)
        sibling = base / 'monitoring'
        sibling.mkdir()
        check_case(base / 'epc', base / 'epc' / 'monitoring')  # bundled path wins when both exist

        link_edition = base / 'linked-epc'
        link_edition.mkdir()
        os.symlink(sibling, link_edition / 'monitoring')
        check_case(link_edition, link_edition / 'monitoring')  # Bash -d follows symlinks

        missing_edition = base / 'missing-epc'
        missing_edition.mkdir()
        (missing_edition / 'monitoring').write_text('not a directory')
        expected = base / 'monitoring'
        check_case(missing_edition, expected)
        e(not (expected / '.env').is_file(), 'missing monitoring/.env fixture must have no false positive')
        for module in (grafana, perses, kafbat):
            gate = object.__new__(module.Gate)
            gate.edition = str(missing_edition)
            gate.project = 'path-contract'
            gate.tls_mode = 'pinned fixture certificate certs/server.crt'
            gate.tls = ssl.create_default_context()
            with patch.object(phase2.Gate, 'preflight', return_value=None):
                reason = gate.preflight()
            e(reason is not None and 'monitoring/.env is missing' in reason,
              f'{module.__name__} must refuse a missing monitoring/.env: {reason}')

        gate = object.__new__(grafana.Gate)
        gate.secrets_path = str(base / 'phase4-secrets.txt')
        Path(gate.secrets_path).write_text('prior\n')
        os.chmod(gate.secrets_path, 0o644)
        with gate.open_runtime_secrets():
            pass
        e(os.stat(gate.secrets_path).st_mode & 0o777 == 0o600,
          'reopening a reused runtime secret file must remove group/world access')
        gate.add_runtime_secret('fixture-secret')
        e(Path(gate.secrets_path).read_text() == 'prior\nfixture-secret\n',
          'the private runtime secret file must still accept appended secrets')
        Path(gate.secrets_path).unlink()
        os.symlink(base / 'outside-secret-file', gate.secrets_path)
        try:
            with gate.open_runtime_secrets():
                pass
        except OSError:
            pass
        else:
            e(False, 'runtime secret file must refuse a symlink')

        isolated = base / 'monitor-auth-isolation'
        auth = isolated / 'auth'
        auth.mkdir(parents=True)
        (auth / 'local.ini').write_text('keep local mode\n')
        (isolated / 'prometheus').mkdir()
        (isolated / 'prometheus' / 'prometheus.yml').write_text('global: {}\n')
        edition_fixture = base / 'edition-guard'
        (edition_fixture / 'auth' / 'ui').mkdir(parents=True)
        guard_start = runner.index('if [[ ! -d "$ED"')
        guard_end = runner.index('# ── candidate binding:', guard_start)
        guard = runner[guard_start:guard_end]

        def run_guard(ed, mon):
            return subprocess.run(['bash', '-euc', 'ED="$1"\nMON_DIR="$2"\n' + guard,
                                   'bash', str(ed), str(mon)], text=True, capture_output=True)

        accepted = run_guard(edition_fixture, isolated)
        e(accepted.returncode == 0,
          f'gate must accept real edition and monitoring directories: {accepted.stderr}')
        outside = base / 'outside-monitor-auth'
        outside.mkdir()
        linked_edition = base / 'linked-edition'
        os.symlink(edition_fixture, linked_edition)
        refused = run_guard(linked_edition, isolated)
        e(refused.returncode == 2, 'gate must refuse a symlinked edition directory')
        for part in ('auth', 'auth/ui'):
            real = edition_fixture / part
            saved = edition_fixture / (part + '.real')
            real.rename(saved)
            os.symlink(outside, real)
            refused = run_guard(edition_fixture, isolated)
            e(refused.returncode == 2, f'gate must refuse a symlinked edition {part} directory')
            real.unlink()
            saved.rename(real)
        linked_monitor = base / 'linked-monitor'
        os.symlink(isolated, linked_monitor)
        refused = run_guard(edition_fixture, linked_monitor)
        e(refused.returncode == 2, 'gate must refuse a symlinked monitoring directory')
        auth.rename(isolated / 'real-auth')
        os.symlink(outside, auth)
        refused = run_guard(edition_fixture, isolated)
        e(refused.returncode == 2, 'gate must refuse a symlinked monitoring auth parent')
        auth.unlink()
        (isolated / 'real-auth').rename(auth)
        prom = isolated / 'prometheus'
        prom.rename(isolated / 'real-prometheus')
        os.symlink(outside, prom)
        refused = run_guard(edition_fixture, isolated)
        e(refused.returncode == 2, 'gate must refuse a symlinked monitoring prometheus directory')
        prom.unlink()
        (isolated / 'real-prometheus').rename(prom)
        prom_file = prom / 'prometheus.yml'
        (outside / 'prometheus.yml').write_text('outside: {}\n')
        prom_file.rename(prom / 'prometheus.yml.real')
        os.symlink(outside / 'prometheus.yml', prom_file)
        refused = run_guard(edition_fixture, isolated)
        e(refused.returncode == 2 and str(prom_file) in refused.stderr,
          'gate must refuse a symlinked prometheus.yml before the W2 backup and reload probe')
        prom_file.unlink()
        (prom / 'prometheus.yml.real').rename(prom_file)
        prom_file.unlink()
        refused = run_guard(edition_fixture, isolated)
        e(refused.returncode == 2 and str(prom_file) in refused.stderr,
          'gate must refuse a missing prometheus.yml before the W2 backup and reload probe')
        prom_file.write_text('global: {}\n')
        for name in ('realm.ini', 'secrets', 'perses'):
            state = auth / name
            if name == 'realm.ini':
                state.write_text('preexisting site state\n')
            else:
                state.mkdir()
            refused = run_guard(edition_fixture, isolated)
            e(refused.returncode == 2 and str(state) in refused.stderr,
              f'gate must refuse preexisting monitoring auth state {name}')
            if state.is_dir():
                state.rmdir()
            else:
                state.unlink()

        cleanup_start = runner.index('cleanup_monitor_auth() {')
        cleanup_end = runner.index('\n}\n', cleanup_start) + len('\n}\n')
        for name in ('realm.ini', 'secrets', 'perses'):
            state = auth / name
            if name == 'realm.ini':
                state.write_text('gate-created state\n')
            else:
                state.mkdir()
        cleaned = subprocess.run(['bash', '-euc',
                                  runner[cleanup_start:cleanup_end] + '\nMON_DIR="$1"\ncleanup_monitor_auth\n',
                                  'bash', str(isolated)], text=True, capture_output=True)
        e(cleaned.returncode == 0 and all(not (auth / name).exists()
                                          for name in ('realm.ini', 'secrets', 'perses')),
          'gate teardown must remove only its generated monitoring auth state')
        e((auth / 'local.ini').read_text() == 'keep local mode\n',
          'gate teardown must preserve packaged local.ini')


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
    check_gate_shape_helper(checks, idp)
    check_stub_idp_down(checks)
    check_check_flows_priority(checks)
    for key in MOVED_SITE_KEYS:
        try:
            module.configs(dict(example, **{key: 5 if key == 'session_idle_minutes' else True}), SYNTHETIC)
            e(False, f'configure-dual: a site file with {key} must be refused (the value lives in .env)')
        except ValueError as exc:
            e('.env' in str(exc), f'configure-dual: the refusal of {key} must point at .env; got {exc}')


# R2-S2: the gate's offline plan check (scripts/gate/phase3_realm.py --shape) must accept the configure-dual plan and refuse a
# changed priority, naming the flow and execution.  (label, mutation, text stderr must name)
GATE_SHAPE_MUTATIONS = (
    ('krate otp auth-otp-form priority 30', lambda p: _execution_of(p, 'krate otp', 1).__setitem__('priority', 30), 'krate otp[1] (auth-otp-form)'),
    ('krate otp conditional-user-configured priority 15', lambda p: _execution_of(p, 'krate otp', 0).__setitem__('priority', 15),
     'krate otp[0] (conditional-user-configured)'),
    ('krate first broker login idp-create-user-if-unique priority 20', lambda p: _execution_of(p, 'krate first broker login', 0).__setitem__('priority', 20),
     'krate first broker login[0] (idp-create-user-if-unique)'),
)


def check_gate_shape_helper(checks, idp):
    """phase3_realm.py --shape needs no Keycloak: exit 0 on the generated plan, exit 1 naming the execution on a changed priority."""
    e = checks.expect
    helper = ROOT / 'scripts/gate/phase3_realm.py'
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'plan.json'

        def run(plan):
            path.write_text(json.dumps(plan))
            return subprocess.run([sys.executable, '-I', str(helper), '--shape', str(path)], text=True, capture_output=True, timeout=60)
        result = run(idp)
        e(result.returncode == 0, f'phase3_realm.py --shape must accept the configure-dual plan; got exit {result.returncode}: {result.stderr.strip()}')
        for label, mutate, needle in GATE_SHAPE_MUTATIONS:
            mutated = json.loads(json.dumps(idp))
            mutate(mutated)
            result = run(mutated)
            e(result.returncode == 1 and needle in result.stderr,
              f'phase3_realm.py --shape must refuse {label} (exit 1) naming {needle!r}; got exit {result.returncode}: {result.stderr.strip()}')


# R2-B1: scripts/gate/stub_idp.sh `down` has no automated regression test (review round 2, "Should fix" item 1).
# STUB_IDP_SH is a module-level override point: a mutation driver can set ci.STUB_IDP_SH to a copy of the
# script before calling check_stub_idp_down, without changing this file's call signature.
STUB_IDP_SH = ROOT / 'scripts/gate/stub_idp.sh'

_FAKE_DOCKER_SH = r'''#!/usr/bin/env bash
set -u
LOG="${DOCKER_LOG:?DOCKER_LOG not set}"
printf '%s\n' "$*" >> "$LOG"
REMOVED="$LOG.removed"
touch "$REMOVED"
case "${1:-}" in
  ps)
    shift
    filters=()
    while [[ $# -gt 0 ]]; do
      case "${1:-}" in
        --filter) filters+=("$2"); shift 2 ;;
        *) shift ;;
      esac
    done
    while IFS=$'\t' read -r name label; do
      [[ -z "$name" ]] && continue
      grep -qxF "id-$name" "$REMOVED" 2>/dev/null && continue
      ok=1
      for f in "${filters[@]}"; do
        key="${f%%=*}"; val="${f#*=}"
        case "$key" in
          label) [[ "$label" == "$val" ]] || ok=0 ;;
          name)
            if [[ "$val" == *'$' ]]; then
              exact="${val#^}"; exact="${exact%\$}"
              [[ "$name" == "$exact" ]] || ok=0
            else
              prefix="${val#^}"
              [[ "$name" == "$prefix"* ]] || ok=0
            fi
            ;;
        esac
      done
      [[ "$ok" == 1 ]] && echo "id-$name"
    done <<< "${FAKE_CONTAINERS:-}"
    ;;
  rm)
    shift
    for a in "$@"; do
      case "$a" in
        -*) continue ;;
      esac
      echo "$a" >> "$REMOVED"
    done
    ;;
  inspect) echo absent ;;
esac
exit 0
'''


def _stub_idp_down(tmp, project, fake_containers, container=None):
    """Run `stub_idp.sh down` for real, with a fake docker on PATH. Returns (returncode, stdout, stderr, docker_log).

    Each call gets its own scratch subdirectory so the fake docker's removed-id bookkeeping (which lives next
    to its log file) never leaks state between independent scenarios sharing the same `tmp`.
    """
    scratch = Path(tempfile.mkdtemp(dir=tmp))
    bindir = scratch / 'bin'
    bindir.mkdir()
    docker = bindir / 'docker'
    docker.write_text(_FAKE_DOCKER_SH)
    docker.chmod(0o755)
    log = scratch / 'docker.log'
    args = ['bash', str(STUB_IDP_SH), 'down', '--project', project]
    if container is not None:
        args += ['--container', container]
    env = dict(os.environ, PATH=f'{bindir}:{os.environ.get("PATH", "")}', DOCKER_LOG=str(log),
               FAKE_CONTAINERS=fake_containers)
    result = subprocess.run(args, text=True, capture_output=True, env=env, timeout=30)
    docker_log = log.read_text() if log.exists() else ''
    return result.returncode, result.stdout, result.stderr, docker_log


def check_stub_idp_down(checks):
    """stub_idp.sh down against a fake docker (review round 2 should-fix: no automated test of `down --container`).

    Confirmed by hand first (harness/phase3/pr41-r2/T5/manual): `down` sweeps containers from two `docker ps -aq`
    queries (the resolved --container name, and the project's `${PROJECT}-gate3-` prefix). The second query had
    no label filter, so an unlabelled container under the default name (`${PROJECT}-gate3-pingstub`, which matches
    the prefix) was removed before the ownership check could refuse it. Both queries now carry the
    krate.gate=phase3 label filter; the assertions below hold the documented behaviour: only labelled containers
    are removed, an unlabelled one of the resolved name is named on stderr with exit 1, another project's
    stand-in is never touched.
    """
    e = lambda cond, msg: checks.expect(cond, 'stub_idp.sh down: ' + msg)  # noqa: E731
    with tempfile.TemporaryDirectory() as tmp:
        # 1) an unlabelled container under the default name (${PROJECT}-gate3-pingstub): protected like any other
        #    unlabelled container (both sweeps carry the label filter), named on stderr, exit 1, no rm.
        rc, out, err, log = _stub_idp_down(tmp, 'P', 'P-gate3-pingstub\t')
        e(rc == 1, f'default unlabelled container: expected exit 1, got {rc}: {out!r}')
        e('container P-gate3-pingstub exists but was not started by stub_idp.sh' in err, f'default unlabelled container: expected the ownership refusal; got {err!r}')
        e('rm -f' not in log, f'default unlabelled container: must not be removed; docker log was {log!r}')

        # 2) --container NAME carrying the label: removed, reported by its docker id.
        rc, out, err, log = _stub_idp_down(tmp, 'P', 'custom-name\tkrate.gate=phase3', container='custom-name')
        e(rc == 0, f'--container labelled: expected exit 0, got {rc}: {err.strip()}')
        e('removed containers: id-custom-name' in out, f'--container labelled: expected removal message; got {out!r}')
        e('rm -f id-custom-name' in log, f'--container labelled: expected the fake docker log to show the rm; got {log!r}')

        # 3) --container NAME without the label, NAME not matching the project's gate3- prefix: protected.
        rc, out, err, log = _stub_idp_down(tmp, 'P', 'custom-name\t', container='custom-name')
        e(rc == 1, f'--container unlabelled: expected exit 1, got {rc}: {out!r}')
        e('exists but was not started by stub_idp.sh' in err, f'--container unlabelled: expected the ownership refusal; got {err!r}')
        e('docker rm -f custom-name' in err, f'--container unlabelled: expected the manual-removal hint; got {err!r}')
        e('rm -f' not in log, f'--container unlabelled: must not be removed; docker log was {log!r}')

        # 4) nothing exists: a clean no-op.
        rc, out, err, log = _stub_idp_down(tmp, 'P', '')
        e(rc == 0, f'nothing exists: expected exit 0, got {rc}: {err.strip()}')
        e('removed containers: none' in out, f'nothing exists: expected "removed containers: none"; got {out!r}')

        # 5) the default stand-in (labelled) plus an unrelated labelled container of ANOTHER project: only the
        #    project's own container is swept; the other project's container never matches the prefix filter.
        rc, out, err, log = _stub_idp_down(tmp, 'P', 'P-gate3-pingstub\tkrate.gate=phase3\nother-gate3-x\tkrate.gate=phase3')
        e(rc == 0, f'cross-project: expected exit 0, got {rc}: {err.strip()}')
        e('id-P-gate3-pingstub' in out, f'cross-project: expected the project container removed; got {out!r}')
        other_untouched = 'other-gate3-x' not in out and 'rm -f id-other-gate3-x' not in log
        e(other_untouched, f"cross-project: the other project's container must never be touched; stdout {out!r} log {log!r}")


def check_check_flows_priority(checks):
    """R2-N3: a non-integer priority is refused by naming its execution, before any sorting."""
    e = checks.expect
    flows = json.loads(json.dumps(identity.planned_flows()))
    next(f for f in flows if f['alias'] == 'krate otp')['authenticationExecutions'][1]['priority'] = '20'
    try:
        identity._check_flows('plan.json', flows)
        e(False, 'identity._check_flows must refuse a non-integer priority')
    except ValueError as exc:
        e('krate otp' in str(exc) and 'auth-otp-form' in str(exc) and 'integer' in str(exc),
          f'identity._check_flows must name the flow and execution of a non-integer priority; got {exc}')


def _execution_of(plan, flow_alias, index):
    flow = next(f for f in plan['authenticationFlows'] if f['alias'] == flow_alias)
    return flow['authenticationExecutions'][index]


def _replace_first_broker_execution(plan):
    _execution_of(plan, 'krate first broker login', 0)['authenticator'] = 'idp-auto-link'


def _add_auto_link(plan):
    flow = next(f for f in plan['authenticationFlows'] if f['alias'] == 'krate first broker login')
    flow['authenticationExecutions'].append({'authenticator': 'idp-auto-link', 'requirement': 'ALTERNATIVE', 'priority': 20,
                                             'authenticatorFlow': False, 'userSetupAllowed': False})


def _set_config_default(plan):
    plan['authenticatorConfig'][0]['config']['defaultProvider'] = 'other'


# PR #41 review (Copilot, sso/identity.py): broker_plan must validate the exact generated execution shapes, not generic types.
# (label, mutation, text the refusal must name)
PLAN_SHAPE_MUTATIONS = (
    ('the first-broker execution replaced by idp-auto-link', _replace_first_broker_execution, 'idp-create-user-if-unique'),
    ('an idp-auto-link execution added to krate first broker login', _add_auto_link, 'krate first broker login'),
    ('the redirector requirement changed', lambda p: _execution_of(p, 'krate browser', 1).__setitem__('requirement', 'REQUIRED'), 'requirement'),
    ('a priority changed', lambda p: _execution_of(p, 'krate otp', 1).__setitem__('priority', 30), 'priority'),
    ('the redirector authenticatorConfig reference changed', lambda p: _execution_of(p, 'krate browser', 1).__setitem__('authenticatorConfig', 'other'), 'authenticatorConfig'),
    ('the redirector authenticatorConfig reference removed', lambda p: _execution_of(p, 'krate browser', 1).pop('authenticatorConfig'), 'authenticatorConfig'),
    ('the redirector defaultProvider changed', _set_config_default, 'authenticatorConfig'),
    ('the authenticatorConfig list emptied', lambda p: p.__setitem__('authenticatorConfig', []), 'authenticatorConfig'),
    ('an authenticatorFlow flag flipped', lambda p: _execution_of(p, 'krate first broker login', 0).__setitem__('authenticatorFlow', True), 'not planned'),
    ('a sub-flow reference turned into an authenticator', lambda p: _execution_of(p, 'krate browser', 2).__setitem__('authenticatorFlow', False), 'names no authenticator'),
    ('a sub-flow alias swapped', lambda p: _execution_of(p, 'krate browser', 2).__setitem__('flowAlias', 'krate otp'), 'flowAlias'),
    ('userSetupAllowed enabled', lambda p: _execution_of(p, 'krate forms', 0).__setitem__('userSetupAllowed', True), 'userSetupAllowed'),
    ('a flow made not top-level', lambda p: p['authenticationFlows'][3].__setitem__('topLevel', False), 'topLevel'),
    ('a flow providerId changed', lambda p: p['authenticationFlows'][3].__setitem__('providerId', 'client-flow'), 'providerId'),
    # R2-S1: refused only by identity._same (type strictness): 0 == False and 0 == False pass every earlier generic check.
    ('userSetupAllowed 0 instead of False on the first-broker execution', lambda p: _execution_of(p, 'krate first broker login', 0).__setitem__('userSetupAllowed', 0), 'userSetupAllowed'),
    ('authenticatorFlow 0 instead of False on an authenticator execution', lambda p: _execution_of(p, 'krate otp', 1).__setitem__('authenticatorFlow', 0), 'authenticatorFlow'),
    ('builtIn 0 instead of False on a flow', lambda p: p['authenticationFlows'][2].__setitem__('builtIn', 0), 'builtIn'),
    ('an authenticator swapped in krate forms', lambda p: _execution_of(p, 'krate forms', 0).__setitem__('authenticator', 'auth-spnego'), 'auth-username-password-form'),
)


def check_broker_plan_shape(checks, idp):
    """The broker plan as the contract states it: D2 first-broker-login flow, D3 browser flow with its priorities, the mappers."""
    e = lambda cond, msg: checks.expect(cond, 'configure-dual plan: ' + msg)  # noqa: E731
    provider = idp['identityProviders'][0]
    e(provider.get('firstBrokerLoginFlowAlias') == 'krate first broker login',
      f'the provider must use the flow "krate first broker login" (D2); got {provider.get("firstBrokerLoginFlowAlias")!r}')
    e(provider.get('config', {}).get('syncMode') == 'FORCE', 'the provider syncs on every login (syncMode FORCE: group removal takes effect at the next sign-in)')
    e(all(provider.get(key) is value for key, value in identity.BROKER_PROVIDER_FLAGS.items()),
      f'the provider carries the Krate flags {sorted(identity.BROKER_PROVIDER_FLAGS)} exactly (trustEmail true: Keycloak sets the realm user\'s e-mail '
      f'verification from the email_verified claim PingFederate asserts, which the Phase 4 UIs require); got '
      f'{{{", ".join(f"{key}={provider.get(key)!r}" for key in sorted(identity.BROKER_PROVIDER_FLAGS))}}}')
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
                ('a provider that does not trust the asserted e-mail', lambda p: p['identityProviders'][0].__setitem__('trustEmail', False), 'trustEmail'),
                ('a provider that keeps the IdP token', lambda p: p['identityProviders'][0].__setitem__('storeToken', True), 'storeToken'),
                ('a disabled provider', lambda p: p['identityProviders'][0].__setitem__('enabled', False), 'enabled'),
                ('an unknown truststore mode', lambda p: p.__setitem__('truststore', 'none'), 'truststore')) + tuple(
                (label, mutate, needle) for label, mutate, needle in PLAN_SHAPE_MUTATIONS):
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
    current = {'alias': 'pingfederate', 'internalId': 'x', 'providerId': 'oidc', 'enabled': True, 'trustEmail': True, 'storeToken': False,
               'displayName': 'Company sign-in', 'firstBrokerLoginFlowAlias': 'krate first broker login', 'types': ['USER_AUTHENTICATION'],
               'config': dict(idp['identityProviders'][0]['config'], clientSecret='**********', extra='ignored')}
    e(identity.differs(identity.broker_provider(idp), current) is False, 'differs(): Keycloak extras (internalId, types, masked secret, extra config) are not a difference')
    e(identity.differs(identity.broker_provider(idp), dict(current, firstBrokerLoginFlowAlias='first broker login')) is True,
      'differs(): a changed first-broker-login alias is a difference')
    e(identity.differs(identity.broker_provider(idp), dict(current, config=dict(current['config'], tokenUrl='https://x'))) is True,
      'differs(): a changed endpoint is a difference')
    e(identity.differs(identity.broker_provider(idp), dict(current, trustEmail=False)) is True,
      'differs(): a provider that does not trust the asserted e-mail is a difference, so auth apply converges a console-only change back')


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
    # PR #41 review: `config set` bypasses the CLI's prompt/rotate validation, so preflight checks the shape too.
    for label, value in (('a space', 'has a space 1234567890'), ('a dollar sign', 'abc$defghijklmnopq'), ('a double quote', 'abc"defghijklmnopq')):
        write_env(site, dict(env, PING_KEYCLOAK_CLIENT_SECRET=value))
        expect_refusal(f'PING_KEYCLOAK_CLIENT_SECRET with {label}', 'printable ASCII')
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
    for label, mutation, needle in PLAN_SHAPE_MUTATIONS:
        mutated_plan(mutation)
        expect_refusal(label, needle)
        outcome = preflight(site, 'identity', rendered)
        checks.expect(outcome.returncode == 1 and needle in outcome.stderr,
                      f'{edition}: identity-mode preflight must refuse: {label} (naming {needle!r}); got exit {outcome.returncode}: {outcome.stderr.strip()}')
    identity.write_file(plan_file, plan_original, 0o644)
    expect_pass('the planned ping site')
    pem = trust / 'enterprise-ca.pem'
    pem.chmod(0o600)
    expect_refusal('a 600 PEM in the truststores', 'chmod 644')
    pem.chmod(0o666)
    expect_refusal('a group/other-writable PEM (666)', 'writable by its owner only')
    pem.chmod(0o644)
    pem.unlink()
    expect_refusal('no PEM while the identity provider is on another host', 'holds no truststore file')
    truststore_pem(site, name='enterprise-ca.crt')
    expect_pass('a .crt PEM instead of .pem')
    trust.chmod(0o700)
    expect_refusal('a 700 truststores directory', '755')
    trust.chmod(0o777)
    expect_refusal('a group/other-writable truststores directory (777)', 'must not write')
    trust.chmod(0o755)
    # PR #41 review: `krate identity up` applies the plan too, so identity mode validates it (a mutated plan is
    # refused there as well) while an unset secret only skips the application.
    mutated_plan(lambda p: p['identityProviderMappers'][0]['config'].__setitem__('group', '/OTHER'))
    outcome = preflight(site, 'identity', rendered)
    checks.expect(outcome.returncode == 1 and 'realm groups' in outcome.stderr,
                  f'{edition}: identity-mode preflight must refuse a plan whose mapper targets another realm group; got exit {outcome.returncode}: {outcome.stderr.strip()}')
    identity.write_file(plan_file, plan_original, 0o644)
    write_env(site, dict(env, PING_KEYCLOAK_CLIENT_SECRET='REPLACE_ME'))
    outcome = preflight(site, 'identity', rendered)
    checks.expect(outcome.returncode == 0,
                  f'{edition}: identity-mode preflight must accept the plan while PING_KEYCLOAK_CLIENT_SECRET is unset (identity up skips the application); got exit {outcome.returncode}: {outcome.stderr.strip()}')
    write_env(site, env)
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
        ('session maximum differs from KEYCLOAK_SESSION_MAX_HOURS', 'differs from the Krate plan',
         lambda d: d['auth']['oauth2'].__setitem__('max-session-lifetime', '240h')),
        ('session maximum removed (an active Kafbat session would have no absolute bound)', 'differs from the Krate plan',
         lambda d: d['auth']['oauth2'].pop('max-session-lifetime')),
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


def bash_functions(path, *names) -> str:
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


def check_install_home_dir(checks):
    """A fresh default install stays traversable under umask 077 without widening custom site paths."""
    e = lambda cond, msg: checks.expect(cond, 'ensure_home_dir: ' + msg)  # noqa: E731
    if bash_binary() is None:
        return
    for edition in EDITIONS:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'opt').mkdir(mode=0o755)
            default_base = root / 'opt' / 'krate'
            default_home = default_base / edition
            # Substitute only the fixed system prefix so this tests the real CLI function
            # without creating /opt/krate or requiring elevated privileges on the host.
            function = bash_functions(ROOT / edition / 'krate', 'ensure_home_dir').replace('/opt/krate', str(default_base))
            script = BASH_STUBS + function + r'''
KRATE_VARIANT="$1"; KRATE_HOME="$2"; FORCE_FALLBACK="${3:-}"; SUDO_LOG="$4"; FALLBACK_MARKER="$5"
mkdir() {
  if [[ "$FORCE_FALLBACK" == yes && "$1" == -p && "$2" == "$KRATE_HOME" ]]; then
    FORCE_FALLBACK=no
    : > "$FALLBACK_MARKER"
    return 1
  fi
  command mkdir "$@"
}
sudo() { printf '%s\n' "$1" >> "$SUDO_LOG"; command "$@"; }
umask 077; ensure_home_dir
'''
            sudo_log = root / 'sudo.log'
            fallback_marker = root / 'fallback.marker'
            sudo_log.write_text('')
            result = run_bash(script, edition, default_home, 'yes', sudo_log, fallback_marker)
            e(result.returncode == 0, f'{edition}: fresh default install failed: {result.stderr.strip()[:160]}')
            e(fallback_marker.exists(), f'{edition}: the first mkdir must be forced through the fallback path')
            expected_sudo = ['mkdir', 'chown', 'chmod'] if os.getuid() != 0 else []
            e(sudo_log.read_text().splitlines() == expected_sudo,
              f'{edition}: fallback commands must use sudo only for a non-root installer')
            e(os.stat(default_home).st_uid == os.getuid() and os.access(default_home, os.W_OK),
              f'{edition}: fallback must leave the edition directory owned and writable by the installer')
            for directory in (default_base, default_home):
                e(directory.is_dir() and mode(directory) == 0o711,
                  f'{edition}: fresh {directory.name} must be 0711 under umask 077, got {mode(directory):o}')
            secret = default_home / '.env'
            secret.write_text('SYNTHETIC_SECRET=keep-private\n')
            secret.chmod(0o600)
            default_base.chmod(0o700)
            default_home.chmod(0o700)
            owners = tuple(os.stat(path).st_uid for path in (default_base, default_home))
            sudo_log.write_text('')
            result = run_bash(script, edition, default_home, 'no', sudo_log, fallback_marker)
            e(result.returncode == 0, f'{edition}: existing default install failed: {result.stderr.strip()[:160]}')
            e(sudo_log.read_text().splitlines() == (['chmod'] if os.getuid() != 0 else []),
              f'{edition}: a writable existing directory must keep its owner without privileged chown')
            e(all(mode(path) == 0o711 for path in (default_base, default_home)),
              f'{edition}: existing default directories gain traversal without listing permission')
            e(owners == tuple(os.stat(path).st_uid for path in (default_base, default_home)),
              f'{edition}: existing default directory ownership must be preserved')
            custom_home = root / 'private-site' / edition
            sudo_log.write_text('')
            result = run_bash(script, edition, custom_home, 'no', sudo_log, fallback_marker)
            e(result.returncode == 0, f'{edition}: custom install failed: {result.stderr.strip()[:160]}')
            e(not sudo_log.read_text(), f'{edition}: writable custom paths must not use sudo')
            e(mode(custom_home.parent) == 0o700 and mode(custom_home) == 0o700,
              f'{edition}: custom path must keep its umask-077 permissions')
            e(mode(secret) == 0o600, f'{edition}: install must not widen an existing secret')
            linked_target = root / 'linked-target'
            linked_target.mkdir(mode=0o700)
            default_base.rename(root / 'previous-default')
            default_base.symlink_to(linked_target, target_is_directory=True)
            sudo_log.write_text('')
            result = run_bash(script, edition, default_home, 'no', sudo_log, fallback_marker)
            e(result.returncode != 0 and mode(linked_target) == 0o700,
              f'{edition}: a symlinked default parent must be rejected without widening its target')
            e(not sudo_log.read_text(), f'{edition}: symlink rejection must happen before sudo')


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
                 'jansson-2.14-1.el9.x86_64.rpm', 'libmnl-1.0.4-16.el9.x86_64.rpm', 'unrelated-tool-1.0-1.el9.x86_64.rpm',
                 'iptables-nft-1.8.10-11.el9_5.x86_64.rpm', 'iptables-libs-1.8.10-11.el9_5.x86_64.rpm',
                 'libnetfilter_conntrack-1.0.9-1.el9.x86_64.rpm', 'libnfnetlink-1.0.1-23.el9_5.x86_64.rpm',
                 'iptables-legacy-1.8.4-1.el9.x86_64.rpm'):
        (bundle / 'optional' / name).write_text('rpm\n')
    write_tool(bin_dir, 'sudo', 'exec "$@"\n')
    write_tool(bin_dir, 'systemctl', 'exit 0\n')
    write_tool(bin_dir, 'usermod', 'exit 0\n')
    write_tool(bin_dir, 'docker', 'echo "Docker version 29.0.0"\n')
    # dnf fails like dnf 4 on RHEL 9 until every requirement is in the transaction, writing its problem
    # lines only after a pause: the caller must read a complete file, not a file still being written.
    write_tool(bin_dir, 'dnf', r'''echo "dnf $*" >> "$FAKE_LOG"
# The host has the iptables-nft closure (as on a RHEL server with firewalld) unless FAKE_NO_IPTABLES is set;
# FAKE_HOST_HAS lists further packages the host has. "has" is host or transaction, "intx" the transaction only.
if [[ -n "${FAKE_NO_IPTABLES:-}" ]]; then names=" ${FAKE_HOST_HAS:-} "; else names=" iptables-nft iptables-libs libnetfilter_conntrack libnfnetlink ${FAKE_HOST_HAS:-} "; fi
txn=" "
for a in "$@"; do case "$a" in *.rpm) b="${a##*/}"; names+="${b%%-[0-9]*} "; txn+="${b%%-[0-9]*} " ;; esac; done
has() { [[ "$names" == *" $1 "* ]]; }
intx() { [[ "$txn" == *" $1 "* ]]; }
problems=()
has nftables || problems+=("nothing provides nftables >= 1:1.0.5 needed by docker-ce-3:29.0.0-1.el9.x86_64 from @commandline"
                            "nothing provides /usr/sbin/nft needed by docker-ce-rootless-extras-29.0.0-1.el9.x86_64 from @commandline")
if has nftables; then
  has libnftnl || problems+=("nothing provides libnftnl.so.11()(64bit) needed by nftables-1:1.0.9-3.el9.x86_64 from @commandline")
  has jansson || problems+=("nothing provides libjansson.so.4()(64bit) needed by nftables-1:1.0.9-3.el9.x86_64 from @commandline")
fi
if has libnftnl; then has libmnl || problems+=("nothing provides libmnl.so.0()(64bit) needed by libnftnl-1.2.6-4.el9.x86_64 from @commandline"); fi
# docker-ce 29 requires the rich dependency (iptables-nft or iptables); iptables-nft requires iptables-libs of its own
# version, libnftnl and libmnl; iptables-libs requires libnetfilter_conntrack, which requires libnfnetlink.
has iptables-nft || problems+=("nothing provides (iptables-nft or iptables) needed by docker-ce-3:29.0.0-1.el9.x86_64 from @commandline")
if intx iptables-nft; then
  has iptables-libs || problems+=("nothing provides iptables-libs(x86-64) = 1.8.10-11.el9_5 needed by iptables-nft-1.8.10-11.el9_5.x86_64 from @commandline")
  has libnftnl || problems+=("nothing provides libnftnl.so.11()(64bit) needed by iptables-nft-1.8.10-11.el9_5.x86_64 from @commandline")
  has libmnl || problems+=("nothing provides libmnl.so.0()(64bit) needed by iptables-nft-1.8.10-11.el9_5.x86_64 from @commandline")
fi
if intx iptables-libs; then has libnetfilter_conntrack || problems+=("nothing provides libnetfilter_conntrack.so.3()(64bit) needed by iptables-libs-1.8.10-11.el9_5.x86_64 from @commandline"); fi
if intx libnetfilter_conntrack; then has libnfnetlink || problems+=("nothing provides libnfnetlink.so.0()(64bit) needed by libnetfilter_conntrack-1.0.9-1.el9.x86_64 from @commandline"); fi
# FAKE_EXTRA is a capability nothing on the host provides, needed by FAKE_EXTRA_NEEDER, until package FAKE_EXTRA_BY joins the transaction.
[[ -z "${FAKE_EXTRA:-}" ]] || intx "${FAKE_EXTRA_BY:-never}" || problems+=("nothing provides $FAKE_EXTRA needed by ${FAKE_EXTRA_NEEDER:-docker-ce-3:29.0.0-1.el9.x86_64} from @commandline")
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
         iptables-nft) printf 'arptables\narptables-helper\nebtables\niptables\niptables-nft = 1.8.10-11.el9_5\niptables-nft(x86-64) = 1.8.10-11.el9_5\n' ;;
         iptables-libs) printf 'libxtables.so.12()(64bit)\niptables-libs = 1.8.10-11.el9_5\niptables-libs(x86-64) = 1.8.10-11.el9_5\n' ;;
         libnetfilter_conntrack) printf 'libnetfilter_conntrack.so.3()(64bit)\nlibnetfilter_conntrack = 1.0.9-1.el9\n' ;;
         libnfnetlink) printf 'libnfnetlink.so.0()(64bit)\nlibnfnetlink = 1.0.1-23.el9_5\n' ;;
         iptables-legacy) printf 'iptables\niptables-legacy = 1.8.4-1.el9\n' ;;
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


def check_rpm_capability_parsing(e):
    """The installers read dnf's "nothing provides" lines: plain capabilities, sonames, file paths and rich dependencies "(A or B)"."""
    source = bash_functions(ROOT / 'epc/krate', 'rpm_missing_capabilities', 'rpm_capability_alternatives', 'rpm_providers_of', 'rpm_failure_message')
    dnf_output = """Error:
 Problem 1: conflicting requests
  - nothing provides container-selinux >= 2:2.74 needed by docker-ce-3:29.9.0-1.el9.aarch64 from @commandline
 Problem 2: package docker-ce-rootless-extras-29.9.0-1.el9.aarch64 from @commandline requires docker-ce, but none of the providers can be installed
  - conflicting requests
  - nothing provides (iptables-nft or iptables) needed by docker-ce-3:29.9.0-1.el9.aarch64 from @commandline
  - nothing provides libnftnl.so.11()(64bit) needed by nftables-1.0.9-9.el9_8.aarch64 from @commandline
  - nothing provides /usr/sbin/nft needed by docker-ce-rootless-extras-29.9.0-1.el9.aarch64 from @commandline
  - nothing provides selinux-policy-base >= 38.1.75-2.el9_8 needed by container-selinux-4:2.247.0-1.el9_8.noarch from @commandline
  - nothing provides policycoreutils needed by container-selinux-4:2.247.0-1.el9_8.noarch from @commandline
"""
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / 'dnf.log'
        log.write_text(dnf_output)
        result = run_bash(BASH_STUBS + source + '\nrpm_missing_capabilities "$1"\n', log)
        e(result.returncode == 0 and set(result.stdout.splitlines()) == {
            'container-selinux', '(iptables-nft or iptables)', 'libnftnl.so.11()(64bit)', '/usr/sbin/nft', 'selinux-policy-base', 'policycoreutils'},
          f'rpm_missing_capabilities must read plain names (version dropped), sonames, file paths and whole rich dependencies; got {result.stdout.splitlines()}')
        for dependency, alternatives in (('(iptables-nft or iptables)', ['iptables-nft', 'iptables']),
                                         ('(foo >= 1.0 or bar or baz)', ['foo', 'bar', 'baz']),
                                         ('(libfoo.so.1()(64bit) or bar)', ['libfoo.so.1()(64bit)', 'bar']),
                                         ('libnftnl.so.11()(64bit)', ['libnftnl.so.11()(64bit)']),
                                         ('/usr/sbin/nft', ['/usr/sbin/nft']),
                                         ('container-selinux', ['container-selinux']),
                                         ('(foo and bar)', ['(foo and bar)']),
                                         ('(foo if bar)', ['(foo if bar)']),
                                         ('(foo or (bar and baz))', ['(foo or (bar and baz))']),
                                         ('(foo or (bar or baz))', ['(foo or (bar or baz))'])):
            result = run_bash(BASH_STUBS + source + '\nrpm_capability_alternatives "$1"\n', dependency)
            e(result.returncode == 0 and result.stdout.splitlines() == alternatives,
              f'rpm_capability_alternatives {dependency!r}: want {alternatives}; got {result.stdout.splitlines()}')
        bin_dir, bundle = rpm_fixture(tmp)
        optional = sorted(str(f) for f in (bundle / 'optional').glob('*.rpm'))
        for need, wanted in (('(iptables-nft or iptables)', ['iptables-nft-1.8.10']), ('(libabsent or iptables-legacy)', ['iptables-legacy-1.8.4']),
                             ('(libabsent or libgone)', []), ('/usr/sbin/nft', ['nftables-1.0.9']), ('iptables-libs(x86-64)', ['iptables-libs-1.8.10']),
                             ('libnftnl.so.11()(64bit)', ['libnftnl-1.2.6'])):
            result = run_bash(BASH_STUBS + source + '\nrpm_providers_of "$@"\n', need, *optional, path_dir=bin_dir)
            found = [Path(line).name for line in result.stdout.splitlines()]
            e(result.returncode == 0 and len(found) == len(wanted) and all(f.startswith(w) for f, w in zip(found, wanted)),
              f'rpm_providers_of {need!r}: want {wanted}; got {found}')
        for added, capabilities, selinux, texts in (
                ('', ['(libfoo or libbar)'], False, ['lacks (libfoo or libbar), and the bundle has no package', 'Install (libfoo or libbar) from your RHEL media']),
                ('nftables-1.rpm libnftnl-1.rpm', ['(iptables-nft or iptables)'], False,
                 ['bundled dependencies (nftables-1.rpm libnftnl-1.rpm); the bundle cannot supply (iptables-nft or iptables)', 'Install (iptables-nft or iptables) from your RHEL media']),
                ('', ['container-selinux'], True, ['lacks container-selinux', 'dnf install container-selinux']),
                ('container-selinux-1.rpm', ['selinux-policy-base'], True, ['cannot supply selinux-policy-base', 'dnf install container-selinux']),
                ('container-selinux-1.rpm', ['policycoreutils'], False, ['cannot supply policycoreutils', 'Install policycoreutils from your RHEL media']),
                ('nftables-1.rpm', ['libfoo.so.1()(64bit)', 'selinux-policy-base'], True,
                 ['cannot supply libfoo.so.1()(64bit), selinux-policy-base', 'Install libfoo.so.1()(64bit) from your RHEL media', 'dnf install container-selinux']),
                ('nftables-1.rpm', [], False, ["dnf's output above names the cause"])):
            result = run_bash(BASH_STUBS + source + '\nrpm_failure_message "$@"\n', Path(tmp) / 'dnf.log', added, *capabilities)
            e(result.returncode == 0 and all(text in result.stdout for text in texts)
              and (('container-selinux must match' in result.stdout) == selinux)
              and (selinux or 'dnf install container-selinux' not in result.stdout),
              f'rpm_failure_message {added!r} {capabilities}: want {texts} and container-selinux advice {selinux}; got {result.stdout!r}')


def check_rpm_install(checks):
    """S3-S6: dnf's errors are read after dnf exits, capabilities map to bundled RPMs over several rounds, both installers agree, the builder is pinned."""
    e = checks.expect
    epc = (ROOT / 'epc/krate').read_text()
    install = function_body(epc, 'docker_install_rpm')
    e('>(' not in install and '2>"$attempt_log"' in install, 'epc/krate: docker_install_rpm must write dnf stderr to the file synchronously (no process substitution)')
    makefile = (ROOT / 'Makefile').read_text()
    optional = re.search(r'^DOCKER_RPM_OPTIONAL := (.*)$', makefile, re.M)
    e(optional is not None and {'container-selinux', 'nftables', 'libnftnl', 'jansson', 'libmnl',
                                'iptables-nft', 'iptables-libs', 'libnetfilter_conntrack', 'libnfnetlink'} <= set(optional.group(1).split()),
      'Makefile: DOCKER_RPM_OPTIONAL must bundle container-selinux, nftables, libnftnl, jansson, libmnl and the iptables-nft closure '
      '(iptables-nft, iptables-libs, libnetfilter_conntrack, libnfnetlink): docker-ce requires (iptables-nft or iptables)')
    builder_recipe = makefile[makefile.index('docker-rpms:\n'):makefile.index('INSTALL_RPM\n')]
    e(re.search(r'dnf install -y -q [^\n]*\b(iptables-nft|nftables)\b', builder_recipe) is None,
      'Makefile docker-rpms: the builder must not install iptables-nft or nftables as if every RHEL host had them (they are optional/ downloads)')
    flat_recipe = re.sub(r'\\\n>?', ' ', builder_recipe)
    download_lines = [line for line in flat_recipe.splitlines() if 'dnf download' in line and not line.lstrip('>').lstrip().startswith('#')]
    e(len(download_lines) == 2 and not any(flag in line for line in download_lines for flag in ('--resolve', '--alldeps')),
      'Makefile docker-rpms: the main set and optional/ are named `dnf download` lists, never --resolve/--alldeps (the main set is exactly the Docker packages)')
    e(re.search(r'^RHEL_BUILDER_IMAGE \?= rockylinux/rockylinux:9@sha256:[0-9a-f]{64}$', makefile, re.M) is not None,
      "Makefile: RHEL_BUILDER_IMAGE must default to Rocky's maintained image rockylinux/rockylinux:9, pinned by digest")
    e('AlmaLinux' not in makefile, 'Makefile: no stale AlmaLinux builder wording')
    raw, standalone = makefile_rpm_installer()
    e(re.search(r'(?<!\$)\$(?!\$)', raw) is None, 'Makefile: every $ in the install-docker.sh heredoc must be escaped as $$')
    for name in ('rpm_missing_capabilities', 'rpm_capability_alternatives', 'rpm_providers_of', 'rpm_failure_message'):
        source = bash_functions(ROOT / 'epc/krate', name)
        e(source in standalone, f'Makefile install-docker.sh: {name} must be identical to its epc/krate copy')
    e('>(' not in standalone and '2>"$attempt_log"' in standalone, 'Makefile install-docker.sh: dnf stderr must be written to the file synchronously')
    if bash_binary() is None:
        return
    krate_script = BASH_STUBS + bash_functions(ROOT / 'epc/krate', 'rpm_missing_capabilities', 'rpm_capability_alternatives', 'rpm_providers_of',
                                               'rpm_failure_message', 'docker_install_rpm') + '\ndocker_install_rpm "$1"\n'
    check_rpm_capability_parsing(e)
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

            def scenario(**variables):
                assert run is not None
                log.unlink(missing_ok=True)
                outcome = run(bundle, dict(env, **variables), bin_dir)
                return outcome, (log.read_text().splitlines() if log.exists() else [])

            cloud = 'iptables-libs libnetfilter_conntrack libnfnetlink jansson libmnl'
            nft_ready = 'nftables libnftnl jansson libmnl'
            result, calls = scenario()
            e(result.returncode == 0 and not any(n in calls[-1] for n in ('iptables-nft', 'iptables-libs', 'libnetfilter_conntrack', 'libnfnetlink', 'iptables-legacy')),
              f'{label}: a host that has iptables-nft (firewalld) never gets the bundled iptables-nft closure; got {result.returncode}: {calls[-1][-200:] if calls else ""!r}')
            # Rocky GenericCloud (observed 2026-10-16): no iptables-nft, nftables, libnftnl; iptables-libs, libnetfilter_conntrack, libnfnetlink present.
            result, calls = scenario(FAKE_NO_IPTABLES='1', FAKE_HOST_HAS=cloud)
            last = calls[-1] if calls else ''
            e(result.returncode == 0 and len(calls) == 3,
              f'{label}: dnf names the rich dependency (iptables-nft or iptables): iptables-nft is added with nftables, then libnftnl; got {result.returncode}, {len(calls)} calls: {result.stderr.strip()[-300:]}')
            e(all(n in last for n in ('nftables-1.0.9', 'iptables-nft-1.8.10', 'libnftnl-1.2.6'))
              and not any(n in last for n in ('iptables-libs', 'libnetfilter_conntrack', 'libnfnetlink', 'jansson', 'libmnl', 'iptables-legacy', 'container-selinux')),
              f'{label}: only the iptables-nft, nftables and libnftnl are added there (iptables-legacy also provides iptables but is not the first alternative); got {last[-300:]!r}')
            # A host without the whole closure: iptables-nft -> iptables-libs -> libnetfilter_conntrack -> libnfnetlink is five attempts.
            result, calls = scenario(FAKE_NO_IPTABLES='1')
            last = calls[-1] if calls else ''
            e(result.returncode == 0 and len(calls) == 5,
              f'{label}: a host lacking the whole iptables-nft closure needs five dnf attempts, not a fixed three rounds; got {result.returncode}, {len(calls)} calls: {result.stderr.strip()[-300:]}')
            e(all(n in last for n in ('iptables-nft-1.8.10', 'iptables-libs-1.8.10', 'libnetfilter_conntrack-1.0.9', 'libnfnetlink-1.0.1', 'libnftnl-1.2.6', 'libmnl-1.0.4'))
              and 'iptables-legacy' not in last,
              f'{label}: the final transaction carries the whole closure; got {last[-400:]!r}')
            result, calls = scenario(FAKE_EXTRA='(libabsent or iptables-legacy)', FAKE_EXTRA_BY='iptables-legacy', FAKE_HOST_HAS=nft_ready)
            e(result.returncode == 0 and len(calls) == 2 and 'iptables-legacy' in calls[-1],
              f'{label}: a rich dependency is satisfied by the first alternative a bundled package provides (here the second); got {result.returncode}, {len(calls)} calls: {result.stderr.strip()[-200:]}')
            result, calls = scenario(FAKE_EXTRA='(libfoo or libbar)', FAKE_HOST_HAS=nft_ready)
            e(result.returncode == 1 and 'lacks (libfoo or libbar)' in result.stderr and 'container-selinux must match' not in result.stderr,
              f'{label}: an unresolved rich dependency is named whole, without the container-selinux advice; got {result.returncode}: {result.stderr.strip()[-250:]}')
            result, calls = scenario(FAKE_EXTRA='libfoo.so.1()(64bit)', FAKE_NO_IPTABLES='1', FAKE_HOST_HAS=cloud)
            e(result.returncode == 1 and 'bundled dependencies (' in result.stderr and 'cannot supply libfoo.so.1()(64bit)' in result.stderr
              and 'Install libfoo.so.1()(64bit) from your RHEL media' in result.stderr and 'container-selinux must match' not in result.stderr,
              f'{label}: after adding bundled packages, the capability that stayed unresolved is named and the container-selinux advice is absent; got {result.returncode}: {result.stderr.strip()[-350:]}')
            result, calls = scenario(FAKE_EXTRA='container-selinux >= 2:9.9', FAKE_HOST_HAS=nft_ready)
            e(result.returncode == 1 and len(calls) == 2 and 'cannot supply container-selinux' in result.stderr and 'container-selinux must match this host' in result.stderr,
              f'{label}: a capability dnf still names after its bundled provider was added (its version constraint is not met) is unresolved, with the container-selinux advice; got {result.returncode}, {len(calls)} calls: {result.stderr.strip()[-300:]}')
            result, calls = scenario(FAKE_EXTRA='selinux-policy-base >= 38.1.75-2.el9_8', FAKE_EXTRA_NEEDER='container-selinux-4:2.247.0-1.el9_8.noarch', FAKE_HOST_HAS=nft_ready)
            e(result.returncode == 1 and 'selinux-policy-base' in result.stderr and 'container-selinux must match this host' in result.stderr,
              f'{label}: a capability needed by container-selinux (the host selinux-policy) gets the container-selinux advice; got {result.returncode}: {result.stderr.strip()[-300:]}')


def check_gen_cert_ip(checks):
    """S7: gen-cert gives an IP-literal public host an iPAddress SAN; the preflight checks an IP host with -checkip."""
    e = checks.expect
    if bash_binary() is not None:
        script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'env_value', 'get_fqdn', 'public_url_host',
                                            'san_entry', 'ensure_public_cert_readable', 'cmd_gen_cert') + r'''
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


def check_public_cert_permissions(checks):
    """A restrictive install umask must not hide the public CA from unprivileged monitoring readers."""
    if bash_binary() is None:
        return
    e = checks.expect
    for edition in EDITIONS:
        script = BASH_STUBS + bash_functions(ROOT / edition / 'krate', 'env_value', 'get_fqdn',
                                            'public_url_host', 'san_entry', 'ensure_public_cert_readable',
                                            'cmd_gen_cert', 'ensure_cert') + r'''
ENV_FILE="$1/.env"; CERTS_DIR="$1/certs"; CERT_CRT="$CERTS_DIR/server.crt"; CERT_KEY="$CERTS_DIR/server.key"
umask 077
ensure_cert >/dev/null
'''
        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp)
            write_env(site, {'KAFKA_UI_FQDN': 'krate.example.test',
                             'KEYCLOAK_PUBLIC_URL': 'https://krate.example.test/identity'})
            result = run_bash(script, site)
            if not e(result.returncode == 0, f'{edition}: ensure_cert under umask 077 failed: {result.stderr.strip()[:200]}'):
                continue
            cert = site / 'certs/server.crt'
            key = site / 'certs/server.key'
            e((site / 'certs').stat().st_mode & 0o777 == 0o700,
              f'{edition}: private certs directory should retain mode 0700')
            e(cert.stat().st_mode & 0o777 == 0o644,
              f'{edition}: generated public certificate must be mode 0644 for unprivileged monitoring readers')
            e(key.stat().st_mode & 0o777 == 0o600,
              f'{edition}: generated private key must remain mode 0600')
            cert.chmod(0o600)
            result = run_bash(script, site)
            e(result.returncode == 0 and cert.stat().st_mode & 0o777 == 0o644,
              f'{edition}: ensure_cert must restore an existing public certificate from mode 0600; '
              f'got exit {result.returncode}, mode {cert.stat().st_mode & 0o777:04o}: {result.stderr.strip()[:200]}')
            e(key.stat().st_mode & 0o777 == 0o600,
              f'{edition}: repairing a public certificate must not widen the private key')
            cert.unlink()
            linked = site / 'linked.crt'
            linked.write_bytes(b'org-issued certificate')
            linked.chmod(0o600)
            cert.symlink_to(linked)
            result = run_bash(script, site)
            e(result.returncode != 0 and linked.read_bytes() == b'org-issued certificate',
              f'{edition}: a restrictive linked certificate must be refused without editing its target')
            linked.unlink()
            result = run_bash(script, site)
            e(result.returncode != 0 and not linked.exists(),
              f'{edition}: a dangling certificate symlink must be refused without creating its target')
            cert.unlink()
            cert.write_bytes(b'org-issued certificate')
            key.unlink()
            linked_key = site / 'linked.key'
            key.symlink_to(linked_key)
            result = run_bash(script, site)
            e(result.returncode != 0 and not linked_key.exists()
              and cert.read_bytes() == b'org-issued certificate',
              f'{edition}: a dangling private-key symlink must be refused without altering either target')


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
    doomed = next(f for f in state['flows'] if f['id'] == parts[-1])
    if doomed['alias'] == state['browserFlow']:  # Keycloak refuses to delete a bound flow (B-live.md section 1)
        fail('Cannot delete a flow bound to the realm')
    remove_flow(doomed); save()
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
                   'identity_put_idp_provider', 'identity_find_execution', 'identity_remove_idp', 'identity_owned_alias', 'identity_owned_flows_present')


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
        # R2-S4: the four Krate aliases are defined once (identity_owned_alias); the detection, the rebind and the flow deletion use it.
        e(cli.count('"krate browser"|"krate first broker login"|"krate forms"|"krate otp"') == 1 and 'identity_owned_alias "$current"' in function_body(cli, 'identity_remove_idp'),
          f'{edition}/krate: the owned flow aliases must be defined once and the rebind must test the current binding against them')
        for name in ('identity_apply_idp', 'identity_apply_idp_plan', 'identity_apply_flow', 'identity_remove_idp', 'identity_owned_alias', 'identity_owned_flows_present', 'identity_put_idp_provider', 'identity_rotate_ping_secret'):
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
        # Five verdict consumers: the broker provider, its mappers, its redirector config,
        # krate-grafana client and (Phase 4) krate-perses client.
        unexpected = cli.count('*) die "Unexpected comparison result')  # hoisted: Python 3.9 (RHEL 9) rejects a backslash inside an f-string expression
        e(unexpected == 5, f'{edition}/krate: each verdict case must refuse an unexpected result; got {unexpected}')
        e('PING_KEYCLOAK_CLIENT_SECRET="$(env_value PING_KEYCLOAK_CLIENT_SECRET)" python3' in cli,
          f'{edition}/krate: the secret enters identity.py broker through the environment of that process only')
    if bash_binary() is None:
        return
    plan = load_configure_dual().configs(json.loads((ROOT / 'sso/dual-example.json').read_text()), SYNTHETIC)['keycloak/pingfederate-idp.json']
    secret = RUNTIME_SITE['PING_KEYCLOAK_CLIENT_SECRET']
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', *APPLY_FUNCTIONS) + r'''
SCRIPT_DIR="$1"; ENV_FILE="$1/.env"; IDENTITY_REALM=krate; IDENTITY_CHANGED=false; IDENTITY_BROWSER_KEPT=""
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
        duplicate_state = json.loads(json.dumps(state))
        forms = next(f for f in duplicate_state['flows'] if f['alias'] == 'krate forms')
        first_password = next(e for e in forms['executions'] if e.get('providerId') == 'auth-username-password-form')['id']
        first_otp = next(e for e in forms['executions'] if e.get('flowAlias') == 'krate otp')['id']
        forms['executions'].append({'id': 'dup-password-later', 'requirement': 'DISABLED', 'priority': 11, 'index': 2,
                                    'providerId': 'auth-username-password-form'})
        forms['executions'].append({'id': 'dup-otp-later', 'requirement': 'DISABLED', 'priority': 21, 'index': 3, 'flowAlias': 'krate otp'})
        state_file.write_text(json.dumps(duplicate_state))
        result, calls, state_cleaned = run()
        label = 'apply with duplicate planned executions'
        deleted = [c[1] for c in calls if c[0] == 'delete']
        cleaned_forms = next(f for f in state_cleaned['flows'] if f['alias'] == 'krate forms')
        remaining_ids = [e['id'] for e in cleaned_forms['executions']]
        e(result.returncode == 0 and state_cleaned == state, f'{label}: duplicates removed and planned state restored; got exit {result.returncode} diff {_dict_diff(state, state_cleaned)}')
        e(deleted == ['authentication/executions/dup-password-later', 'authentication/executions/dup-otp-later'],
          f'{label}: only the later duplicate execution ids are deleted; got {deleted}')
        e(first_password in remaining_ids and first_otp in remaining_ids and 'dup-password-later' not in remaining_ids and 'dup-otp-later' not in remaining_ids,
          f'{label}: first matching password/otp executions stay and later duplicates go; got {remaining_ids}')
        e('removed' in result.stdout and 'auth-username-password-form' in result.stdout and 'krate otp' in result.stdout,
          f'{label}: change list says the duplicates were removed; got {result.stdout.strip()[-240:]!r}')
        result, calls, state_after_duplicate = run()
        e(result.returncode == 0 and 'No changes' in result.stdout and mutating(calls) == [] and state_after_duplicate == state,
          f'{label} (second run): duplicate cleanup must be idempotent; got exit {result.returncode} {mutating(calls)} {result.stdout.strip()[-200:]!r}')
        # The duplicate sorts BEFORE the original (lower priority, drifted requirement): the first occurrence in Keycloak's order
        # is the one reconciled and kept (its requirement and priority corrected), the original — now the later one — is deleted.
        duplicate_state = json.loads(json.dumps(state))
        forms = next(f for f in duplicate_state['flows'] if f['alias'] == 'krate forms')
        forms['executions'].insert(0, {'id': 'dup-password-first', 'requirement': 'DISABLED', 'priority': 5, 'index': 0,
                                       'providerId': 'auth-username-password-form'})
        state_file.write_text(json.dumps(duplicate_state))
        result, calls, state_cleaned = run()
        label = 'apply with a duplicate planned execution sorting before the original'
        deleted = [c[1] for c in calls if c[0] == 'delete']
        cleaned_forms = next(f for f in state_cleaned['flows'] if f['alias'] == 'krate forms')
        password_steps = [x for x in cleaned_forms['executions'] if x.get('providerId') == 'auth-username-password-form']
        e(result.returncode == 0 and deleted == ['authentication/executions/' + first_password] and len(password_steps) == 1
          and password_steps[0]['id'] == 'dup-password-first' and password_steps[0]['requirement'] == 'REQUIRED' and password_steps[0]['priority'] == 10,
          f'{label}: the first occurrence is reconciled (REQUIRED 10) and kept, the later original deleted; got exit {result.returncode} deleted {deleted} steps {password_steps}')
        result, calls, state_after_duplicate = run()
        e(result.returncode == 0 and 'No changes' in result.stdout and mutating(calls) == [],
          f'{label} (second run): idempotent; got exit {result.returncode} {mutating(calls)} {result.stdout.strip()[-200:]!r}')
        state_file.write_text(json.dumps(state))  # the drift case below starts from the planned state with the original ids
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
        # PR41 r2 (Copilot, medium): the removal does not hinge on the provider. An apply that stopped before the provider was
        # created, or a provider deleted out of band, leaves the Krate flows and perhaps the browser binding behind.
        def owned_flows():
            return [{'id': 'kb-id', 'alias': 'krate browser', 'topLevel': True, 'executions': [{'id': 'x1', 'requirement': 'ALTERNATIVE', 'priority': 30,
                                                                                               'index': 0, 'flowAlias': 'krate forms'}]},
                    {'id': 'kf-id', 'alias': 'krate forms', 'topLevel': False, 'executions': [{'id': 'x2', 'requirement': 'REQUIRED', 'priority': 20,
                                                                                              'index': 0, 'flowAlias': 'krate otp'}]},
                    {'id': 'ko-id', 'alias': 'krate otp', 'topLevel': False, 'executions': []},
                    {'id': 'kfbl-id', 'alias': 'krate first broker login', 'topLevel': True, 'executions': []}]

        def seed(browser_flow, flows, provider_present=False):
            fresh = {'provider': ({'alias': 'pingfederate', 'config': {}} if provider_present else None), 'mappers': [],
                     'flows': realm['flows'][:2] + flows, 'configs': {}, 'browserFlow': browser_flow}
            state_file.write_text(json.dumps(fresh))
            return fresh

        def provider_calls(made):
            return [c for c in made if 'identity-provider' in c[1] and c[0] != 'get' or 'mappers' in c[1]]

        base_aliases = ['browser', 'first broker login']
        seed('krate browser', owned_flows())
        result, calls, st = run()
        label = 'apply without the plan file, provider already absent, krate browser still bound'
        rebind = next((i for i, c in enumerate(calls) if c[0] == 'update' and c[1] == 'realms/krate'), None)
        flow_deletes = [i for i, c in enumerate(calls) if c[0] == 'delete' and c[1].startswith('authentication/flows/')]
        e(result.returncode == 0 and st['browserFlow'] == 'browser' and sorted(f['alias'] for f in st['flows']) == sorted(base_aliases),
          f'{label}: browserFlow back to browser and the four flows gone; got exit {result.returncode} {st["browserFlow"]} {[f["alias"] for f in st["flows"]]} {result.stderr.strip()[:200]}')
        e(rebind is not None and len(flow_deletes) == 2 and rebind < min(flow_deletes), f'{label}: rebind first, then the two top-level flows; got {calls}')
        e(provider_calls(calls) == [] and not any(c[0] == 'delete' and 'identity-provider' in c[1] for c in calls)
          and not any(c[0] == 'get' and c[1].endswith('/mappers') for c in calls), f'{label}: no mapper or provider call for an absent provider; got {calls}')
        last = journal.read_text().splitlines()[-1]
        e('removed identity flows only (provider pingfederate already absent)' in last and 'rebound to browser' in last, f'{label}: the journal says flows only; got {last!r}')
        e('Identity flows removed' in result.stdout and 'changed=true' in result.stdout, f'{label}: the output says what was removed and the realm changed; got {result.stdout.strip()[-200:]!r}')
        result, calls, st2 = run()
        e(result.returncode == 0 and mutating(calls) == [] and st2 == st and 'removed' not in result.stdout, f'{label} (second run): nothing left, nothing printed; got {mutating(calls)} {result.stdout!r}')
        seed('browser', owned_flows())
        result, calls, st = run()
        label = 'apply without the plan file, provider absent, browser flow already browser, flows present'
        e(result.returncode == 0 and sorted(f['alias'] for f in st['flows']) == sorted(base_aliases) and st['browserFlow'] == 'browser'
          and not any(c[0] == 'update' for c in calls) and not any('identity-provider' in c[1] and c[0] != 'get' for c in calls),
          f'{label}: the flows are deleted without a rebind or provider call; got {calls}')
        seed('krate browser', [])
        result, calls, st = run()
        label = 'apply without the plan file, provider absent, krate browser bound but no flow left'
        e(result.returncode == 0 and st['browserFlow'] == 'browser', f'{label}: the dangling binding is released; got {st["browserFlow"]} {result.stderr.strip()[:200]}')
        # R2-S4: an operator's own browser binding is never replaced; only a Krate-owned binding is released (Keycloak refuses to delete a bound flow).
        corp = {'id': 'corp-id', 'alias': 'corp browser', 'topLevel': True, 'executions': []}
        leftover = [f for f in owned_flows() if f['alias'] == 'krate first broker login']
        seed('corp browser', [corp] + leftover)
        result, calls, st = run()
        label = 'apply without the plan file, provider absent, browserFlow bound to the operator flow "corp browser", a leftover krate flow'
        e(result.returncode == 0 and st['browserFlow'] == 'corp browser' and not any(c[0] == 'update' for c in calls)
          and [c[1] for c in calls if c[0] == 'delete'] == ['authentication/flows/kfbl-id'] and sorted(f['alias'] for f in st['flows']) == sorted(base_aliases + ['corp browser']),
          f'{label}: no rebind call, the owned flow deleted, the operator flow and binding kept; got exit {result.returncode} {mutating(calls)} {st["browserFlow"]} {result.stderr.strip()[:200]}')
        e("corp browser" in result.stdout and 'stays bound' in result.stdout and 'Keycloak\'s browser again' not in result.stdout,
          f'{label}: the output names the kept binding; got {result.stdout.strip()!r}')
        last = journal.read_text().splitlines()[-1]
        e('removed identity flows only (provider pingfederate already absent)' in last and last.endswith("browser flow bound to 'corp browser' left as it is"),
          f'{label}: the journal names the kept binding; got {last!r}')
        result, calls, st2 = run()
        e(result.returncode == 0 and mutating(calls) == [] and st2 == st, f'{label} (second run): nothing left to do; got {mutating(calls)}')
        # the same with the provider present: mappers, provider and owned flows go, the binding stays
        seed('corp browser', [corp] + owned_flows(), provider_present=True)
        with_provider = json.loads(state_file.read_text()); with_provider['mappers'] = [{'id': 'm1', 'name': 'a'}]
        state_file.write_text(json.dumps(with_provider))
        result, calls, st = run()
        label = 'apply without the plan file, provider present, browserFlow bound to the operator flow "corp browser"'
        e(result.returncode == 0 and not any(c[0] == 'update' for c in calls) and st['browserFlow'] == 'corp browser' and st['provider'] is None
          and [c[1] for c in calls if c[0] == 'delete'] == ['identity-provider/instances/pingfederate/mappers/m1', 'identity-provider/instances/pingfederate',
                                                            'authentication/flows/kb-id', 'authentication/flows/kfbl-id']
          and any(f['alias'] == 'corp browser' for f in st['flows']),
          f'{label}: no rebind, mappers, provider and owned flows deleted, operator flow kept; got exit {result.returncode} {mutating(calls)} {result.stderr.strip()[:200]}')
        last = journal.read_text().splitlines()[-1]
        e(' removed identity provider pingfederate, its mappers and flows; browser flow bound to' in last and "'corp browser' left as it is" in last
          and "stays bound to 'corp browser'" in result.stdout, f'{label}: journal and output name the kept binding; got {last!r} {result.stdout.strip()!r}')
        # bound to a Krate flow other than krate browser, with an operator flow beside: rebind first, then delete
        seed('krate first broker login', [corp] + owned_flows())
        result, calls, st = run()
        label = 'apply without the plan file, provider absent, browserFlow bound to "krate first broker login"'
        rebind = next((i for i, c in enumerate(calls) if c[0] == 'update' and c[1] == 'realms/krate'), None)
        flow_deletes = [i for i, c in enumerate(calls) if c[0] == 'delete' and c[1].startswith('authentication/flows/')]
        e(result.returncode == 0 and st['browserFlow'] == 'browser' and rebind is not None and len(flow_deletes) == 2 and rebind < min(flow_deletes)
          and sorted(f['alias'] for f in st['flows']) == sorted(base_aliases + ['corp browser']) and journal.read_text().splitlines()[-1].endswith('rebound to browser'),
          f'{label}: rebind to browser, then the owned flows; operator flow kept; got exit {result.returncode} {mutating(calls)} {result.stderr.strip()[:200]}')
        seeded = seed('browser', [])
        result, calls, st = run()
        label = 'apply without the plan file, nothing Krate-owned present'
        e(result.returncode == 0 and mutating(calls) == [] and st == seeded and result.stdout.strip() == 'changed=false',
          f'{label}: no mutating call and no output; got {mutating(calls)} {result.stdout!r}')
        seeded = seed('krate browser', owned_flows())
        result, calls, st = run(KC_FAIL_GET='identity-provider/instances/pingfederate')
        label = 'apply without the plan file, provider GET fails with a real error'
        e(result.returncode != 0 and mutating(calls) == [] and st == seeded and 'identity provider' in result.stderr,
          f'{label}: must die with no mutation; got exit {result.returncode} {mutating(calls)} {result.stderr.strip()[-160:]!r}')
        for failing in ('realms/krate', 'authentication/flows'):
            seeded = seed('browser', owned_flows())
            result, calls, st = run(KC_FAIL_GET=failing)
            e(result.returncode != 0 and mutating(calls) == [] and st == seeded,
              f'apply without the plan file, GET {failing} fails: the detection must die, not read as absence; got exit {result.returncode} {mutating(calls)}')
        for failing, needle in (('identity-provider/instances/pingfederate/mappers', 'mappers'), ('authentication/flows', 'flows')):
            seeded = seed('krate browser', owned_flows(), provider_present=True)
            seeded['mappers'] = [{'id': 'm1', 'name': 'a'}]
            state_file.write_text(json.dumps(seeded))
            result, calls, st = run(KC_FAIL_GET=failing)
            e(result.returncode != 0 and mutating(calls) == [] and st == seeded and needle in result.stderr,
              f'apply without the plan file, provider present, GET {failing} fails: removal must stop before destructive calls; got exit {result.returncode} {mutating(calls)} {result.stderr.strip()[-160:]!r}')
        # the normal case is unchanged: provider present, mappers, flows (order rebind, mappers, provider, flows; the old journal wording)
        seed('krate browser', owned_flows(), provider_present=True)
        state_with = json.loads(state_file.read_text()); state_with['mappers'] = [{'id': 'm1', 'name': 'a'}, {'id': 'm2', 'name': 'b'}]
        state_file.write_text(json.dumps(state_with))
        result, calls, st = run()
        label = 'apply without the plan file, provider present (normal removal)'
        deleted = [c[1] for c in calls if c[0] == 'delete']
        e(result.returncode == 0 and deleted == ['identity-provider/instances/pingfederate/mappers/m1', 'identity-provider/instances/pingfederate/mappers/m2',
                                                 'identity-provider/instances/pingfederate', 'authentication/flows/kb-id', 'authentication/flows/kfbl-id']
          and [c[0] for c in mutating(calls)][0] == 'update' and st['provider'] is None and st['browserFlow'] == 'browser',
          f'{label}: rebind, mappers, provider, flows; got {mutating(calls)}')
        e(journal.read_text().splitlines()[-1].endswith('removed identity provider pingfederate, its mappers and flows; browser flow rebound to browser'),
          f'{label}: the journal keeps the wording the gate row P14 greps; got {journal.read_text().splitlines()[-1]!r}')
        state_file.write_text(json.dumps(state_removed))  # the rotate cases below start from the state after the normal removal
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
            ping_rule = 'if [[ "$key" == PING_KEYCLOAK_CLIENT_SECRET ]]; then\n      ping_secret_valid "$value" || die "$key $PING_SECRET_RULE"\n    else'
            e(ping_rule in rotate_body and rotate_body.index(ping_rule) < rotate_body.index('[[ "$value" =~ ^[A-Za-z0-9._-]{16,}$ ]]'),
              f'{edition}/krate: identity rotate validates a PingFederate secret through ping_secret_valid and keeps the generated-value rule for the other keys')
            validator = function_body(cli, 'ping_secret_valid')
            e('[[ ${#1} -ge 16 ]] || return 1' in validator and "grep -q -E '[^!-~]|[\\\\$\"'\"'\"'`]'" in validator,
              f'{edition}/krate: ping_secret_valid = 16+ printable ASCII, none of whitespace, quotes, backslash, backtick or $')
            # PR #41 review: the interactive prompt stores the secret through the same validator (no short or dotenv-sensitive value reaches .env).
            e('ping_secret_valid "$secret" || die "PING_KEYCLOAK_CLIENT_SECRET $PING_SECRET_RULE"' in function_body(cli, 'ensure_ping_secret'),
              f'{edition}/krate: ensure_ping_secret validates the prompted secret with ping_secret_valid before writing .env')


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
                        ('trustEmail', 'the e-mail trust the plan states (a brokered user without it is unverified, which the Phase 4 UIs refuse)'),
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
    # PR #41 review: the README/guide overview must not claim apply never touches Keycloak (it recreates it on
    # trust-material or service changes and reconciles the plan).
    readme = (ROOT / 'README.md').read_text()
    checks.expect('reconciles only the UI' not in readme and 'It does not start Keycloak' not in readme and 'trust material in `auth/keycloak/truststores`' in readme,
                  'README.md: the auth apply overview must describe the Keycloak recreation and plan reconcile, not "reconciles only the UI"')
    dual = (ROOT / 'sso/guides/dual-login.md').read_text()
    checks.expect('In `local.yml` mode the command recreates only the UI' in dual,
                  'dual-login.md: the switch-back paragraph must scope "recreates only the UI" to local.yml mode')

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



# Phase 4: every function the programme adds to the two CLIs must have the same body in both
# (the files differ only in the known edition hunks, which check_parity enforces separately).
P4_PARITY_FUNCTIONS = ('identity_email_address', 'identity_realm_ui', 'cmd_identity_users')


def check_identity_users(checks):
    """Phase 4 commit 1: `identity users logout` and `set-email`, the e-mail a realm UI needs, CLI parity."""
    e = checks.expect
    bodies = {}
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        users = function_body(cli, 'cmd_identity_users')
        bodies[edition] = users
        e('krate identity users {enable|disable|reset-password|groups|logout} <username>' in cli
          and 'krate identity users set-email <username> <address>' in cli,
          f'{edition}/krate: the users usage must list logout and set-email')
        e('identity users {enable|disable|reset-password|groups|logout} U' in cli and 'identity users set-email U A' in cli,
          f'{edition}/krate: the help must list the new users actions')
        e('kcadm -- create "users/$uid/logout" -r "$IDENTITY_REALM"' in users,
          f'{edition}/krate: users logout must create the user\'s logout resource through the kcadm helper')
        logout_line = next((line for line in cli.splitlines() if 'users/$uid/logout' in line), '')
        e(logout_line and re.search(r'\s-n(\s|$)', logout_line) is None,
          f'{edition}/krate: users logout must not pass -n (kcadm rejects it on the logout resource, rc 2)')
        e('identity_journal "users logout" ok "$user"' in users and 'identity_journal "users set-email" ok "$user"' in users,
          f'{edition}/krate: both new actions must write a journal line')
        e('[[ "$action" == list || "$action" == groups ]] || identity_lock' in users,
          f'{edition}/krate: every mutating users action (logout and set-email included) must take the identity lock; only list and groups may skip it')
        e('kcadm -- update "users/$uid" -r "$IDENTITY_REALM" -s "email=$email" -s emailVerified=true' in users,
          f'{edition}/krate: users set-email must set the address and mark it verified')
        e('-s "email=$email" -s emailVerified=true >/dev/null' in users,
          f'{edition}/krate: users add --email must create the user with a verified address (a realm UI refuses an unverified one)')
        e('if [[ "$action" == add ]] && identity_realm_ui && [[ -z "$email" ]]' in users
          and users.index('identity_realm_ui') < users.index('require_compose'),
          f'{edition}/krate: users add must refuse a missing --email while a realm UI is on, before it touches anything')
        realm_ui = function_body(cli, 'identity_realm_ui')
        e('GRAFANA_AUTH_CONFIG local.ini)" == realm.ini' in realm_ui and 'PERSES_IDP)" == krate' in realm_ui
          and 'env_value_file "$env_file"' in realm_ui and 'MONITOR_DIR/.env' in realm_ui,
          f'{edition}/krate: identity_realm_ui must read both realm-mode keys from monitoring/.env')
    e(bodies[EDITIONS[0]] == bodies[EDITIONS[1]], 'kraft/epc parity: cmd_identity_users must have the same body in both editions')
    for name in P4_PARITY_FUNCTIONS:
        first, second = (function_body((ROOT / edition / 'krate').read_text(), name) for edition in EDITIONS)
        e(first == second, f'kraft/epc parity: {name} must have the same body in both editions')
    if bash_binary() is None:
        return
    # Behavioural proof of the two new helpers (extracted, run against a temporary monitoring/.env).
    realm_script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'env_value_file', 'identity_realm_ui') + r'''
MONITOR_DIR="$1"
if identity_realm_ui; then echo realm; else echo local; fi
'''
    mail_script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'identity_email_address') + r'''
if address="$(identity_email_address "$1")"; then echo "ok $address"; else echo refused; fi
'''
    with tempfile.TemporaryDirectory() as tmp:
        monitor = Path(tmp)
        for label, content, expected in (
                ('no monitoring/.env', None, 'local'),
                ('Grafana local', 'GRAFANA_AUTH_CONFIG=local.ini\n', 'local'),
                ('Grafana on the realm', 'GRAFANA_AUTH_CONFIG=realm.ini\n', 'realm'),
                ('Grafana realm.ini quoted', 'GRAFANA_AUTH_CONFIG="realm.ini"\n', 'realm'),
                ('Perses on the realm', 'PERSES_IDP=krate\nPERSES_AUTH_MODE=native\n', 'realm'),
                ('Perses rolled back', 'PERSES_IDP=\nPERSES_AUTH_MODE=local\n', 'local'),
                ('Perses native with a company IdP', 'PERSES_AUTH_MODE=native\nPERSES_IDP=\n', 'local'),
                ('both UIs local', 'GRAFANA_AUTH_CONFIG=local.ini\nPERSES_IDP=\n', 'local')):
            if content is None:
                (monitor / '.env').unlink(missing_ok=True)
            else:
                (monitor / '.env').write_text(content)
            result = run_bash(realm_script, monitor)
            e(result.stdout.strip() == expected,
              f'identity_realm_ui with {label} must report {expected}; got {result.stdout.strip()!r} {result.stderr.strip()[:120]}')
        for address, expected in (('jane@example.test', 'ok jane@example.test'), ('jane', 'refused'),
                                  ('a b@example.test', 'refused'), ('', 'refused'), ('a@b c', 'refused')):
            result = run_bash(mail_script, address)
            e(result.stdout.strip() == expected, f'identity_email_address {address!r} must give {expected}; got {result.stdout.strip()!r}')


def prometheus_metrics(successful, timestamp):
    """A Prometheus exposition body with the two configuration-reload metrics."""
    return ('# TYPE prometheus_config_last_reload_successful gauge\n'
            f'prometheus_config_last_reload_successful {successful}\n'
            '# TYPE prometheus_config_last_reload_success_timestamp_seconds gauge\n'
            f'prometheus_config_last_reload_success_timestamp_seconds {timestamp}\n')


def check_prometheus_reload(checks):
    """Phase 4 commit 2: the lifecycle API is off and `monitor reload` proves its result from Prometheus's own metrics."""
    e = checks.expect
    # The rendered command, not the file text: the service's comment explains why the flag is gone.
    result = subprocess.run(['docker', 'compose', '--env-file', str(ROOT / 'monitoring/.env.template'),
                             '-f', str(ROOT / 'monitoring/docker-compose.yml'), 'config', '--format', 'json'],
                            cwd=ROOT, text=True, capture_output=True)
    if e(result.returncode == 0, 'monitoring: Compose rendering from the template failed'):
        command = [str(part) for part in (json.loads(result.stdout)['services']['prometheus'].get('command') or [])]
        e(not any(flag in part for part in command for flag in ('enable-lifecycle', 'enable-admin-api', 'enable-remote-write-receiver')),
          f'monitoring/prometheus: the lifecycle API, the admin API and the remote-write receiver must stay off (a Grafana Viewer reached '
          f'reload and quit through a datasource); got {command}')
    bodies = {}
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        body = function_body(cli, 'monitor_reload_prometheus')
        bodies[edition] = body
        e('--post-data' not in cli, f'{edition}/krate: no HTTP reload may be left (the lifecycle API is off)')
        e('monitor_compose kill -s SIGHUP prometheus' in body, f'{edition}/krate: the reload must send SIGHUP to the prometheus service')
        state = function_body(cli, 'monitor_prometheus_reload_state')
        e('prometheus_config_last_reload_success_timestamp_seconds' in state and 'prometheus_config_last_reload_successful' in state
          and 'http://127.0.0.1:9090/metrics' in state,
          f'{edition}/krate: the reload must read both reload metrics from Prometheus itself')
        e('rejected the configuration and keeps running with the previous one' in body,
          f'{edition}/krate: a rejected configuration must be reported as such, not as a timeout')
        e('monitor_reload_prometheus' in function_body(cli, 'cmd_monitor'), f'{edition}/krate: cmd_monitor reload must call monitor_reload_prometheus')
    e(bodies[EDITIONS[0]] == bodies[EDITIONS[1]], 'kraft/epc parity: monitor_reload_prometheus must have the same body in both editions')
    if bash_binary() is None:
        return
    # Behavioural proof with a stubbed monitor_compose: the four outcomes an operator can hit,
    # plus the two S2 edges that start from an already-rejected previous state. The `stale`
    # file is the first poll's answer AFTER the SIGHUP: Prometheus can process the signal
    # after that poll ran, so the poll still sees the BEFORE state — the race that made the
    # pre-fix decision order report a good file as rejected.
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'monitor_prometheus_reload_state', 'monitor_reload_prometheus') + r'''
monitor_compose() {
  case "$1" in
    exec)
      if [[ -f "$STATE/killed" && -f "$STATE/stale" ]]; then
        mv "$STATE/stale" "$STATE/stale.used"; cat "$STATE/stale.used"; return 0
      fi
      [[ -f "$STATE/metrics" ]] || return 1; cat "$STATE/metrics" ;;
    kill)
      touch "$STATE/killed"
      if [[ -f "$STATE/after" ]]; then cp "$STATE/after" "$STATE/metrics"; else rm -f "$STATE/metrics"; fi ;;
  esac
}
sleep() { :; }
STATE="$1"
monitor_reload_prometheus
'''
    cases = (
        ('a valid change', prometheus_metrics(1, '1.7918145079e+09'), None, prometheus_metrics(1, '1.7918145217e+09'),
         0, 'Prometheus reloaded its configuration and alert rules.'),
        ('a rejected file', prometheus_metrics(1, '1.7918145079e+09'), None, prometheus_metrics(0, '1.7918145079e+09'),
         1, 'rejected the configuration and keeps running with the previous one'),
        ('no reload reported', prometheus_metrics(1, '1.7918145079e+09'), None, prometheus_metrics(1, '1.7918145079e+09'),
         1, 'reported no reload after 20 polls'),
        # S2: the flag was already 0 from an earlier rejection, so a lingering 0 must not be
        # reported as a new rejection — the good reload moves the timestamp and sets it to 1.
        ('a good reload after an earlier rejection', prometheus_metrics(0, '1.7918145079e+09'), None,
         prometheus_metrics(1, '1.7918145217e+09'), 0, 'Prometheus reloaded its configuration and alert rules.'),
        # The S2 race itself: the first poll after the SIGHUP still reads the stale rejected
        # state; the pre-fix order (flag before the timestamp comparison) died with
        # "rejected" here, on a good file.
        ('a good reload whose first poll still sees the stale rejected state', prometheus_metrics(0, '1.7918145079e+09'),
         prometheus_metrics(0, '1.7918145079e+09'), prometheus_metrics(1, '1.7918145217e+09'),
         0, 'Prometheus reloaded its configuration and alert rules.'),
        # A file rejected twice in a row never moves the success timestamp, so the rejected
        # verdict comes at the end of the polling budget, from the last observed flag.
        ('a file rejected again after an earlier rejection', prometheus_metrics(0, '1.7918145079e+09'), None,
         prometheus_metrics(0, '1.7918145079e+09'),
         1, 'rejected the configuration and keeps running with the previous one'),
    )
    for label, before, stale, after, code, needle in cases:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / 'metrics').write_text(before)
            (state / 'after').write_text(after)
            if stale is not None:
                (state / 'stale').write_text(stale)
            result = run_bash(script, state)
            e(result.returncode == code, f'monitor reload with {label} must exit {code}; got {result.returncode} ({result.stderr.strip()[:120]})')
            e(needle in result.stdout + result.stderr, f'monitor reload with {label} must report {needle!r}; got {(result.stdout + result.stderr).strip()[:160]!r}')
    with tempfile.TemporaryDirectory() as tmp:  # Prometheus not answering at all
        result = run_bash(script, Path(tmp))
        e(result.returncode == 1 and 'did not answer' in result.stderr,
          f'monitor reload without Prometheus must say it did not answer; got {result.returncode} {result.stderr.strip()[:120]!r}')


# The five Loki read locations the gateway may proxy, and the methods each allows (S6: pinned, so
# neither a widened selector nor a widened method list can pass gmake check).
LOKI_GATEWAY_READ_LOCATIONS = (
    '~ ^/loki/api/v1/(query|query_range|labels|series|index/stats|index/volume|index/volume_range|detected_fields|detected_labels|patterns)$',
    '~ ^/loki/api/v1/label/[^/]+/values$',
    '~ ^/loki/api/v1/detected_field/[^/]+/values$',
    '= /loki/api/v1/tail',
    '= /ready',
)
LOKI_GATEWAY_METHODS = {
    '~ ^/loki/api/v1/(query|query_range|labels|series|index/stats|index/volume|index/volume_range|detected_fields|detected_labels|patterns)$': 'GET POST',
    '~ ^/loki/api/v1/label/[^/]+/values$': 'GET',
    '~ ^/loki/api/v1/detected_field/[^/]+/values$': 'GET POST',
    '= /loki/api/v1/tail': 'GET',
    '= /ready': 'GET',
}


def go_flag_value(args, name):
    """The value Go's flag package gives `name` for the argument list `args`, or None when it is not set.

    -name=x, --name=x and (for a non-boolean flag) -name x are the same flag; Set runs once per occurrence,
    in command-line order, so the last occurrence wins; parsing ends before the first non-flag argument
    ("-" is one) and after "--" (Context7 /websites/pkg_go_dev_go1_25_3, package flag). Any other flag written
    without "=" may be boolean (-name alone) or take the next argument, which the argument list does not say, so
    the answer is None (not set) rather than a guess: the caller refuses what it cannot decide.
    """
    value = None
    args = list(args or [])
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == '-' or arg == '--' or not arg.startswith('-'):
            break
        flag = arg[2:] if arg.startswith('--') else arg[1:]
        flag_name, has_value, flag_value = flag.partition('=')
        if not flag_name or flag_name.startswith('-'):
            return None
        if flag_name != name:
            if has_value:
                continue
            return None
        if has_value:
            value = flag_value
        elif i < len(args):
            value = args[i]
            i += 1
        else:
            return None
    return value


def check_loki_gateway(checks):
    """Phase 4 commit 3: Grafana reaches Loki only through the read-only gateway; the log write path stays direct."""
    e = checks.expect
    path = ROOT / 'monitoring/loki/gateway.conf'
    if not e(path.is_file(), 'monitoring/loki/gateway.conf is missing'):
        return
    text = path.read_text()
    blocks = re.findall(r'location ([^{]+)\{(.*?)\n    \}', text, re.S)
    e(len(blocks) == 6, f'monitoring/loki/gateway.conf: expected the five read locations and the default; got {len(blocks)}')
    proxied = [(selector.strip(), body) for selector, body in blocks if 'proxy_pass' in body]
    # Pinned, not counted: a regression that widened a selector (or added one for a write path)
    # must fail here, because Loki has no authentication of its own to fall back on.
    e(sorted(selector for selector, _ in proxied) == sorted(LOKI_GATEWAY_READ_LOCATIONS),
      f'monitoring/loki/gateway.conf: the proxied locations must be exactly the read paths '
      f'{sorted(LOKI_GATEWAY_READ_LOCATIONS)}; got {sorted(selector for selector, _ in proxied)}')
    e(not any('push' in selector or 'delete' in selector or 'rules' in selector for selector, _ in proxied),
      'monitoring/loki/gateway.conf: no write or lifecycle path may be proxied')
    for selector, body in proxied:
        e(body.count('proxy_pass http://loki:3100;') == 1,
          f'monitoring/loki/gateway.conf: {selector} must proxy to Loki only')
        # limit_except lists the allowed methods and denies the rest; without deny all it would only
        # require authentication for the others (nginx limit_except semantics, Context7
        # /websites/nginx_en). The list is pinned per location: widening it (PUT, DELETE) must fail.
        methods = LOKI_GATEWAY_METHODS.get(selector)
        e(methods is not None and f'limit_except methods {{ deny all; }}'.replace('methods', methods) in body,
          f'monitoring/loki/gateway.conf: {selector} must allow exactly {methods} and deny every other method; got {body.strip()[:100]!r}')
        e(selector.startswith('~ ^/loki/api/v1/') or selector in ('= /loki/api/v1/tail', '= /ready'),
          f'monitoring/loki/gateway.conf: {selector} is not one of Loki\'s read paths')
    defaults = [body for selector, body in blocks if 'proxy_pass' not in body]
    e(len(defaults) == 1 and 'return 403;' in defaults[0],
      'monitoring/loki/gateway.conf: the default location must refuse everything else with 403')
    e('listen 3100;' in text and 'client_max_body_size' in text,
      'monitoring/loki/gateway.conf: must listen on 3100 (the datasource URL) and bound the request body')
    datasources = (ROOT / 'monitoring/grafana/provisioning/datasources/datasources.yml').read_text()
    e('url: http://loki-gateway:3100' in datasources and 'url: http://loki:3100' not in datasources,
      'Grafana\'s Loki datasource must point at loki-gateway, not at loki (a Viewer could otherwise write to Loki)')
    e(re.search(r'^\s+uid:\s*loki\s*$', datasources, re.M) is not None,
      'Grafana\'s Loki datasource keeps uid `loki`: provisioned dashboards bind to it')
    e('url: http://prometheus:9090' in datasources, 'Grafana\'s Prometheus datasource is unchanged')
    fluent = (ROOT / 'monitoring/fluent-bit/fluent-bit.conf').read_text()
    e(re.search(r'^\s+Host\s+loki$', fluent, re.M) is not None,
      'Fluent Bit must keep shipping logs to loki directly: the gateway is read-only')
    makefile = (ROOT / 'Makefile').read_text()
    e('monitoring/loki' in makefile, 'Makefile: the bundle must copy monitoring/loki (gateway.conf ships with it)')
    result = subprocess.run(['docker', 'compose', '--env-file', str(ROOT / 'monitoring/.env.template'),
                             '-f', str(ROOT / 'monitoring/docker-compose.yml'), '--profile', '*', 'config', '--format', 'json'],
                            cwd=ROOT, text=True, capture_output=True)
    if not e(result.returncode == 0, 'monitoring: Compose rendering from the template failed'):
        return
    service = json.loads(result.stdout)['services'].get('loki-gateway')
    if not e(service is not None, 'monitoring/docker-compose.yml: the loki-gateway service is missing'):
        return
    e(not service.get('ports'), f'monitoring/loki-gateway must not publish a host port; got {service.get("ports")}')
    e("any(port.get('host_ip') != '127.0.0.1' for port in ports)" in (ROOT / 'sso/preflight.py').read_text(),
      'sso/preflight.py: the realm-mode bind check must cover every published port, not only the first')
    e(list(service.get('networks') or {}) == ['monitoring'],
      f'monitoring/loki-gateway must be on the monitoring network only; got {list(service.get("networks") or {})}')
    e(list(service.get('depends_on') or {}) == ['loki'], f'monitoring/loki-gateway must depend on loki; got {service.get("depends_on")}')
    loki = json.loads(result.stdout)['services'].get('loki') or {}
    # The effective value is what Go's flag package leaves after the whole command (go_flag_value): the last
    # occurrence in any spelling decides, so a later --server.grpc-listen-address=0.0.0.0 or a later
    # two-argument form is seen, not only the single-dash =value form.
    e(go_flag_value(loki.get('command'), 'server.grpc-listen-address') == '127.0.0.1',
      'monitoring/loki must bind its gRPC listener to 127.0.0.1 (-server.grpc-listen-address=127.0.0.1): it is used '
      f'in-process only, and a peer reaching loki:9096 is a residual Table 2 does not list (W4); got {loki.get("command")}')
    volumes = [(volume.get('source', ''), volume.get('target'), volume.get('read_only')) for volume in service.get('volumes') or []]
    e(any(source.endswith('monitoring/loki/gateway.conf') and target == '/etc/nginx/conf.d/default.conf' and read_only
          for source, target, read_only in volumes),
      f'monitoring/loki-gateway must mount loki/gateway.conf read-only as its nginx config; got {volumes}')


def monitoring_services(env=None):
    """The rendered monitoring Compose services, with optional interpolation overrides."""
    environment = dict(os.environ) if env is None else dict(os.environ, **env)
    result = subprocess.run(['docker', 'compose', '--env-file', str(ROOT / 'monitoring/.env.template'),
                             '-f', str(ROOT / 'monitoring/docker-compose.yml'), '--profile', '*', 'config', '--format', 'json'],
                            cwd=ROOT, text=True, capture_output=True, env=environment)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip()[:400])
    return json.loads(result.stdout)['services']


def check_grafana_realm_compose(checks):
    """Phase 4 commit 5: Grafana's realm-mode shape, the idp-wait one-shot and monitoring-init's new inputs."""
    e = checks.expect
    try:
        services = monitoring_services()
        loopback = monitoring_services({'GRAFANA_BIND': '127.0.0.1'})
    except ValueError as exc:
        e(False, f'monitoring: Compose rendering failed: {exc}')
        return
    grafana = services['grafana']
    ports = grafana.get('ports') or []
    e(len(ports) == 1 and ports[0].get('host_ip') == '0.0.0.0' and ports[0].get('published') == '3000',
      f'monitoring/grafana: local mode keeps publishing 3000 on every interface; got {ports}')
    loop_ports = loopback['grafana'].get('ports') or []
    e(len(loop_ports) == 1 and loop_ports[0].get('host_ip') == '127.0.0.1',
      f'monitoring/grafana: GRAFANA_BIND=127.0.0.1 (realm mode) must bind the port to the loopback interface; got {loop_ports}')
    networks = grafana.get('networks') or {}
    e(sorted(networks) == ['kafka-network', 'monitoring']
      and (networks.get('kafka-network') or {}).get('aliases') == ['krate-grafana'],
      f'monitoring/grafana: must be on monitoring and kafka-network with the alias krate-grafana (the cluster proxy\'s route); got {networks}')
    depends = grafana.get('depends_on') or {}
    e((depends.get('monitoring-init') or {}).get('condition') == 'service_completed_successfully'
      and (depends.get('idp-wait') or {}).get('condition') == 'service_completed_successfully'
      and (depends.get('prometheus') or {}).get('condition') == 'service_started',
      f'monitoring/grafana: must wait for the rendered secret and for the realm; got {depends}')
    mounts = {(volume.get('target'), volume.get('read_only')): volume.get('source', '') for volume in grafana.get('volumes') or []}
    e(('/etc/krate/grafana', True) in mounts and mounts[('/etc/krate/grafana', True)] == 'grafana_rendered',
      f'monitoring/grafana: must mount the rendered secret volume read-only at /etc/krate/grafana; got {mounts}')
    e(any(target == '/etc/krate/ca/server.crt' and read_only and source.endswith('certs/server.crt')
          for (target, read_only), source in mounts.items()),
      f'monitoring/grafana: must mount the cluster CA read-only at /etc/krate/ca/server.crt; got {mounts}')
    e('KRATE_GRAFANA_AUTH_SHA' in (grafana.get('environment') or {}),
      'monitoring/grafana: KRATE_GRAFANA_AUTH_SHA must be part of its environment, so a sign-in input change recreates it')
    e((grafana.get('extra_hosts') or [''])[0].endswith(':host-gateway') or 'host-gateway' in str(grafana.get('extra_hosts')),
      f'monitoring/grafana: must resolve the realm\'s public host to the host gateway; got {grafana.get("extra_hosts")}')
    waiter = services.get('idp-wait')
    if not e(waiter is not None, 'monitoring/docker-compose.yml: the idp-wait one-shot is missing'):
        return
    e(not waiter.get('ports'), f'monitoring/idp-wait must not publish a port; got {waiter.get("ports")}')
    e(list(waiter.get('networks') or {}) == ['monitoring'], f'monitoring/idp-wait must be on the monitoring network only; got {waiter.get("networks")}')
    e(waiter.get('read_only') is True and waiter.get('user') == '65534:65534' and waiter.get('cap_drop') == ['ALL']
      and waiter.get('restart') == 'no',
      f'monitoring/idp-wait must be read-only, unprivileged and run once; got user={waiter.get("user")} read_only={waiter.get("read_only")} '
      f'cap_drop={waiter.get("cap_drop")} restart={waiter.get("restart")}')
    e(waiter.get('command') == ['python3', '/etc/krate/idp/idp_wait.py'], f'monitoring/idp-wait command; got {waiter.get("command")}')
    e('IDP_DISCOVERY_URL' in (waiter.get('environment') or {}), 'monitoring/idp-wait: IDP_DISCOVERY_URL must reach it (empty means no realm UI)')
    waiter_mounts = {volume.get('target'): volume.get('source', '') for volume in waiter.get('volumes') or []}
    e('/etc/krate/idp' in waiter_mounts and waiter_mounts['/etc/krate/idp'].endswith('monitoring/idp'),
      f'monitoring/idp-wait must mount monitoring/idp read-only; got {waiter_mounts}')
    e(any(target == '/etc/krate/ca/server.crt' for target in waiter_mounts), f'monitoring/idp-wait must mount the cluster CA; got {waiter_mounts}')
    e(waiter.get('image') == services['monitoring-init'].get('image'),
      'monitoring/idp-wait must use the same pinned Python image as monitoring-init (no new image)')
    init = services['monitoring-init']
    init_env = init.get('environment') or {}
    e('GRAFANA_AUTH_CONFIG' in init_env and 'GRAFANA_OAUTH_CLIENT_SECRET' in init_env,
      f'monitoring-init: render.py renders only what its environment lists, so both Grafana keys must be there; got {sorted(init_env)}')
    for key in ('PERSES_IDP', 'PERSES_GROUP_PROOF_MINUTES', 'KEYCLOAK_PUBLIC_URL',
                'KEYCLOAK_VIEWER_GROUP', 'KEYCLOAK_ADMIN_GROUP',
                'KEYCLOAK_SESSION_IDLE_MINUTES', 'KEYCLOAK_SESSION_MAX_HOURS'):
        e(key in init_env, f'monitoring-init: compose environment must carry {key}')
    init_mounts = [volume.get('target') for volume in init.get('volumes') or []]
    e('/rendered/grafana' in init_mounts,
      'monitoring-init must mount the grafana_rendered volume it writes the client secret into')
    e('/rendered/perses-migrate' in init_mounts,
      'monitoring-init must mount the perses_migrate_rendered volume it writes the issuer into')
    e('perses-migrate' in services, 'monitoring/docker-compose.yml must define the perses-migrate service')
    e((services.get('perses-migrate') or {}).get('image') == init.get('image'),
      'monitoring/perses-migrate must use the same pinned Python image as monitoring-init')
    migrate_mounts = [volume.get('target') for volume in (services.get('perses-migrate') or {}).get('volumes') or []]
    e('/perses' in migrate_mounts,
      'perses-migrate: must mount perses_data to /perses matching perses service (data lives in /perses/data)')
    perses_svc = services.get('perses') or {}
    perses_deps = perses_svc.get('depends_on') or {}
    e((perses_deps.get('perses-migrate') or {}).get('condition') == 'service_completed_successfully',
      'monitoring/perses: must depend on perses-migrate with service_completed_successfully')
    sync_svc = services.get('perses-sync') or {}
    sync_deps = sync_svc.get('depends_on') or {}
    e((sync_deps.get('perses-migrate') or {}).get('condition') == 'service_completed_successfully',
      'monitoring/perses-sync: must depend on perses-migrate with service_completed_successfully')
    for name, service in services.items():
        listed = list(service.get('networks') or {})
        e(not any(network.startswith('identity') for network in listed),
          f'monitoring/{name}: no monitoring service may join an identity network; got {listed}')


def check_grafana_front(checks):
    """Phase 4 commit 5: the cluster proxy serves Grafana at /grafana/, rate limiting the sign-in path only."""
    e = checks.expect
    for edition in EDITIONS:
        nginx = (ROOT / edition / 'nginx.conf').read_text()
        blocks = {selector.strip(): body for selector, body in re.findall(r'location ([^{]+)\{(.*?)\n    \}', nginx, re.S)}
        e('set $grafana http://krate-grafana:3000;' in nginx,
          f'{edition}/nginx.conf: must resolve Grafana at request time through its kafka-network alias krate-grafana')
        redirect = blocks.get('= /grafana')
        e(redirect is not None and 'return 301 https://$http_host/grafana/;' in redirect,
          f'{edition}/nginx.conf: /grafana must redirect to an absolute https://$http_host/grafana/ (a relative 301 '
          f'would be absolutized with the listen port and drop a non-443 public port)')
        login, app = blocks.get('^~ /grafana/login'), blocks.get('^~ /grafana/')
        for name, body in (('/grafana/login', login), ('/grafana/', app)):
            if body is None:  # an explicit test: checks.expect does not narrow the type
                e(False, f'{edition}/nginx.conf: the {name} location is missing')
                continue
            e('proxy_pass $grafana;' in body and 'access_log /var/log/nginx/access.log krate_identity;' in body,
              f'{edition}/nginx.conf: {name} must proxy to Grafana and log without query strings (the OAuth callback carries a one-time code)')
            csp = [line for line in body.splitlines() if 'add_header Content-Security-Policy' in line]
            e(len(csp) == 1 and "worker-src 'self' blob:" in csp[0],
              f'{edition}/nginx.conf: {name} must extend its Content-Security-Policy header with worker-src '
              f'(Grafana\'s Monaco editor starts blob: workers); asserting on the block text alone is satisfied by a comment')
            for header in ('X-Frame-Options SAMEORIGIN', 'X-Content-Type-Options nosniff', 'Referrer-Policy no-referrer',
                           'Permissions-Policy', 'Content-Security-Policy'):
                e(f'add_header {header}' in body,
                  f'{edition}/nginx.conf: {name} must restate {header} (a location with its own add_header loses the server-level set)')
        if login is None or app is None:
            continue
        e('limit_req zone=krate_login burst=20 nodelay;' in login, f'{edition}/nginx.conf: /grafana/login must be rate limited')
        e('limit_req' not in app,
          f'{edition}/nginx.conf: /grafana/ must not be rate limited (the SPA loads ~100 assets at once; a limit_req with burst=40 answered 503 to 51 of them)')
        e('proxy_read_timeout 3600s;' in app and 'proxy_set_header Upgrade $http_upgrade;' in app
          and 'proxy_set_header Connection "upgrade";' in app,
          f'{edition}/nginx.conf: /grafana/ must carry the WebSocket upgrade Grafana Live tail needs')
        e('proxy_read_timeout' not in login and 'Upgrade' not in login,
          f'{edition}/nginx.conf: the WebSocket upgrade belongs to /grafana/ only')
        e(nginx.index('    location ^~ /grafana/') < nginx.index('    location ^~ /metrics {') < nginx.index('    location / {'),
          f'{edition}/nginx.conf: the Grafana locations must precede the 404 blocks and the catch-all location /')


# render.py reads these two for its Grafana output only. They reach it through
# monitoring-init's own environment, so a change recreates monitoring-init and Grafana
# (KRATE_GRAFANA_AUTH_SHA) and must NOT recreate Perses, Alertmanager or the gateway:
# they are deliberately absent from the CLI's KRATE_RENDER_ENV_KEYS.
GRAFANA_ONLY_RENDER_KEYS = {'GRAFANA_AUTH_CONFIG', 'GRAFANA_OAUTH_CLIENT_SECRET'}
# The edition .env keys render.py may read (they come from the cluster's .env, not from
# monitoring/.env, so monitor_compose passes them and hashes them separately).
RENDER_EDITION_KEYS = {'KEYCLOAK_PUBLIC_URL', 'KEYCLOAK_VIEWER_GROUP', 'KEYCLOAK_ADMIN_GROUP',
                       'KEYCLOAK_SESSION_IDLE_MINUTES', 'KEYCLOAK_SESSION_MAX_HOURS', 'PERSES_IDP',
                       'PERSES_GROUP_PROOF_MINUTES', 'PERSES_ISSUER_APPLIED'}
RENDER_ENV_ACCESSOR = re.compile(r"(?:env\.get\(|env\[|(?:positive_int|flag|require)\(env,\s*)'([A-Z][A-Z_0-9]+)'")


def render_env_keys():
    """Every monitoring/.env key render.py reads, whatever accessor it uses, plus a closure guard.

    Keys that are not in monitoring/.env.template are edition values (the KEYCLOAK_* keys
    `monitor_compose` passes in); they are hashed separately, not through KRATE_RENDER_ENV_KEYS.
    """
    text = (ROOT / 'monitoring/render.py').read_text()
    derived = set(RENDER_ENV_ACCESSOR.findall(text))
    # A new accessor style would silently shrink the derived set: any all-caps literal that is
    # also a monitoring/.env.template key must be explained by the pattern above.
    template_keys = set(identity.read_env(ROOT / 'monitoring/.env.template'))
    literals = set(re.findall(r"'([A-Z][A-Z_0-9]{3,})'", text))
    unexplained = (literals & template_keys) - derived
    if unexplained:
        raise ValueError(f'monitoring/render.py reads {sorted(unexplained)} through an accessor RENDER_ENV_ACCESSOR does not match')
    return derived & template_keys, derived - template_keys


def check_grafana_realm_cli(checks):
    """Phase 4 commits 4-5: the CLI side of the Grafana realm switch."""
    e = checks.expect
    try:
        monitor_keys, edition_keys = render_env_keys()
    except ValueError as exc:
        e(False, str(exc))
        monitor_keys, edition_keys = set(), set()
    e(edition_keys <= RENDER_EDITION_KEYS,
      f'monitoring/render.py reads edition .env keys outside the realm set {sorted(RENDER_EDITION_KEYS)}: {sorted(edition_keys - RENDER_EDITION_KEYS)}')
    compose_text = (ROOT / 'monitoring/docker-compose.yml').read_text()
    services_text = compose_text.split('\nservices:', 1)[1]
    for svc in ('perses', 'perses-gateway'):
        start = services_text.find('\n  %s:\n' % svc)
        rest = services_text[start + 1:]
        nxt = re.search(r'\n  [a-z0-9_-]+:\n', rest)
        block = rest[:nxt.start()] if nxt else rest
        e(start >= 0 and 'KRATE_PERSES_REVISION: ${KRATE_PERSES_REVISION:-}' in block
          and 'KRATE_RENDER_REVISION' not in block,
          f'monitoring/docker-compose.yml: the {svc} service must carry KRATE_PERSES_REVISION, not the global revision '
          f'(a realm timing change with an unchanged derived site must not recreate it)')
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        e('Usage: krate monitor {up|down|status|logs|reload|ui|realm|grafana-user retire <login>}' in cli,
          f'{edition}/krate: the monitor usage must list realm and grafana-user retire')
        monitor = function_body(cli, 'cmd_monitor')
        for branch in ('\n    realm)\n', '\n    grafana-user)\n'):
            e(branch in monitor, f'{edition}/krate: cmd_monitor must have a {branch.strip()} branch')
        e('refuse_loopback_public_url' in monitor and 'grafana-seed.meta' not in monitor,
          f'{edition}/krate: cmd_monitor realm must refuse a loopback public host (the seed-meta refusal belongs to monitor_prepare)')
        prepare = function_body(cli, 'monitor_prepare')
        e('refuse_loopback_public_url' in prepare and 'auth/secrets/grafana-seed.meta' in prepare
          and prepare.index('refuse_loopback_public_url') < prepare.index('preflight.py'),
          f'{edition}/krate: monitor_prepare must refuse a loopback host and a missing seed meta in realm mode, before Compose runs')
        e('preflight.py" --directory "$SCRIPT_DIR" --mode monitoring' in prepare,
          f'{edition}/krate: monitor_prepare must run the monitoring preflight')
        compose = function_body(cli, 'monitor_compose')
        for export in ('GRAFANA_BIND="$grafana_bind"', 'KRATE_IDP_HOST="$idp_host"', 'IDP_DISCOVERY_URL="$idp_url"',
                       'KRATE_GRAFANA_AUTH_SHA="$grafana_sha"'):
            e(export in compose, f'{edition}/krate: monitor_compose must export {export}')
        for key in ('KEYCLOAK_PUBLIC_URL', 'KEYCLOAK_VIEWER_GROUP', 'KEYCLOAK_ADMIN_GROUP',
                    'KEYCLOAK_SESSION_IDLE_MINUTES', 'KEYCLOAK_SESSION_MAX_HOURS',
                    'PERSES_IDP', 'PERSES_GROUP_PROOF_MINUTES'):
            e(f'{key}=' in compose, f'{edition}/krate: monitor_compose must export {key}')
        e('find "$env_file"' not in compose,
          f'{edition}/krate: the render revision must not hash the whole monitoring/.env (an unrelated key would recreate every consumer)')
        declared = re.search(r'KRATE_RENDER_ENV_KEYS=\(\n(.*?)\n\)\n', cli, re.S)
        e(declared is not None, f'{edition}/krate: KRATE_RENDER_ENV_KEYS is missing')
        if declared is not None:  # an explicit test: checks.expect does not narrow the type
            listed = set(declared.group(1).split())
            expected_keys = (monitor_keys | edition_keys) - GRAFANA_ONLY_RENDER_KEYS
            e(listed == expected_keys,
              f'{edition}/krate: KRATE_RENDER_ENV_KEYS must equal the keys render.py reads minus the Grafana-only ones; '
              f'missing {sorted(expected_keys - listed)}, unexpected {sorted(listed - expected_keys)}')
            e(not (listed & GRAFANA_ONLY_RENDER_KEYS),
              f'{edition}/krate: no GRAFANA_* key may enter the render revision (it would recreate Perses, Alertmanager and the gateway)')
            e('KRATE_PERSES_REVISION="$perses_rev"' in compose,
              f'{edition}/krate: monitor_compose must export KRATE_PERSES_REVISION')
            declared_perses = re.search(r'KRATE_PERSES_REVISION_KEYS=\(\n(.*?)\n\)\n', cli, re.S)
            e(declared_perses is not None, f'{edition}/krate: KRATE_PERSES_REVISION_KEYS is missing')
            declared_site = re.search(r'KRATE_PERSES_SITE_KEYS=\(\n(.*?)\n\)\n', cli, re.S)
            e(declared_site is not None, f'{edition}/krate: KRATE_PERSES_SITE_KEYS is missing')
            if declared_perses is not None and declared is not None and declared_site is not None:
                listed_perses = set(declared_perses.group(1).split())
                # The session timings and the other site inputs reach the Perses
                # outputs only through the derived site digest; the sync/cookie
                # secrets and the SMTP password belong to other outputs. Anything
                # else dropped here would miss a needed Perses recreation.
                site_covered = {'KEYCLOAK_PUBLIC_URL', 'KEYCLOAK_VIEWER_GROUP', 'KEYCLOAK_ADMIN_GROUP',
                                'KEYCLOAK_SESSION_IDLE_MINUTES', 'KEYCLOAK_SESSION_MAX_HOURS',
                                'PERSES_GROUP_PROOF_MINUTES', 'PERSES_PORT'}
                other_outputs = {'PERSES_SYNC_CLIENT_SECRET', 'OAUTH2_PROXY_COOKIE_SECRET', 'GF_SMTP_PASSWORD'}
                e(listed_perses == listed - site_covered - other_outputs,
                  f'{edition}/krate: KRATE_PERSES_REVISION_KEYS must be the render keys minus the site-derived and other-output keys; '
                  f'missing {sorted(listed - site_covered - other_outputs - listed_perses)}, '
                  f'unexpected {sorted(listed_perses - (listed - site_covered - other_outputs))}')
                e(set(declared_site.group(1).split()) == site_covered,
                  f'{edition}/krate: KRATE_PERSES_SITE_KEYS must be exactly the realm_site inputs')
                e('perses_site_digest' in cli and 'local-empty-site' in cli,
                  f'{edition}/krate: the Perses revision must digest the derived site with a local-mode empty-site rule')
        e('PERSES_IDP' in prepare and 'refuse_loopback_public_url' in prepare, f'{edition}/krate: monitor_prepare must check PERSES_IDP')
        e('PERSES_ISSUER_APPLIED' in prepare, f'{edition}/krate: monitor_prepare must check PERSES_ISSUER_APPLIED')
        e('identity_reconcile_perses_clients' in cli, f'{edition}/krate: must define identity_reconcile_perses_clients')
        # No Grafana credential ever reaches a command line: the helpers pass them in the
        # environment of the call, and the CLI builds no Authorization header of its own.
        e('Authorization' not in cli and 'curl ' not in cli,
          f'{edition}/krate: the CLI must build no HTTP credential and call no curl (grafana-admin.py authenticates in-process)')
        e('GRAFANA_ADMIN_PASSWORD="$(env_value_file "$env_file" GRAFANA_PASSWORD)" \\' in cli
          and 'GRAFANA_SERVICE_ACCOUNT_TOKEN="$(cat "$token_file")" \\' in cli,
          f'{edition}/krate: the Grafana credentials must reach grafana-admin.py as environment assignments')
        realm_refresh = function_body(cli, 'monitor_realm_refresh')
        e('cmp -s "$ini" "$ini.new"' in realm_refresh,
          f'{edition}/krate: monitor_realm_refresh must write realm.ini only when it changed, so an unchanged file does not recreate Grafana')
        renew = function_body(cli, 'monitor_grafana_seed_renew')
        e('2592000' in renew and 'token-delete' in renew and renew.index('token-create') < renew.index('token-delete'),
          f'{edition}/krate: the renewal must create the successor before deleting the old token id, within 30 days of expiry')
        reconcile = function_body(cli, 'identity_reconcile_grafana_client')
        # B5: the verdict must be computed WITH the plan secret, or rotating
        # GRAFANA_OAUTH_CLIENT_SECRET leaves Keycloak on the old value while Grafana reads the
        # new one, and the CLI reports "unchanged" (review-phase4-batch-b-COMPLETE.md, B5).
        e(reconcile.count('GRAFANA_OAUTH_CLIENT_SECRET="$(env_value_file "$MONITOR_DIR/.env" GRAFANA_OAUTH_CLIENT_SECRET)"') == 3
          and reconcile.count('--with-secret') == 3,
          f'{edition}/krate: the create, the update and the verdict must all carry the client secret '
          f'(got {reconcile.count("--with-secret")} of 3 --with-secret uses)')
        e('client_verdict(grafana_client(origin, args.with_secret)' in (ROOT / 'sso/identity.py').read_text(),
          'sso/identity.py: the client-differs verdict must build the plan with the secret, or client_differs\' secret branch is dead code')
        # b2/S2: retiring needs the Basic admin, which realm mode disables.
        e('Grafana is in realm mode, where the Basic admin this command needs is disabled' in cli,
          f'{edition}/krate: grafana-user retire must refuse in realm mode and give the rollback-first sequence')
        e('Cannot renew the Grafana seed token' in renew
          and renew.index('Cannot renew the Grafana seed token') < renew.index('token-create'),
          f'{edition}/krate: a renewal that cannot reach Grafana must warn and continue, not die (Grafana may be held by idp-wait)')
        e(renew.count('Recreate it: krate monitor realm') == 2,
          f'{edition}/krate: a missing or unreadable seed-token record must warn and name the command that '
          f'recreates it, because grafana_admin_token has nothing to authenticate with')
        e('is STILL VALID until it is deleted or expires' in renew,
          f'{edition}/krate: a failed token deletion must not be followed by a line claiming the previous '
          f'token is deleted')
        # Row U13: during a Keycloak outage `monitor up` must still reach Compose, so idp-wait
        # names the failure. kcadm_login dies when the container is stopped, so the optional
        # reconcile tests reachability first and downgrades a refused login to a warning.
        e('identity_reconcile_grafana_client "$origin" optional' in function_body(cli, 'monitor_realm_refresh'),
          f'{edition}/krate: monitor_realm_refresh must reconcile optionally, so an outage still reaches Compose')
        reconcile = function_body(cli, 'identity_reconcile_grafana_client')
        e('if ! identity_keycloak_running; then' in reconcile
          and reconcile.index('if ! identity_keycloak_running; then') < reconcile.index('kcadm_login master user'),
          f'{edition}/krate: the optional reconcile must test reachability before kcadm_login, which dies when Keycloak is stopped')
        # The client representation takes the bare origin: identity.py's checked_origin refuses a
        # path, and KEYCLOAK_PUBLIC_URL always ends in /identity (live4a defect D1).
        e(cli.count('origin="$(public_url_origin)"') == 2 and 'origin="$(env_value KEYCLOAK_PUBLIC_URL)"' not in cli,
          f'{edition}/krate: both client call sites must derive the bare public origin, not pass KEYCLOAK_PUBLIC_URL')
        seed = function_body(cli, 'monitor_grafana_seed_token')
        e('grafana-seed.meta' in seed and seed.index('grafana-seed.meta') < seed.index('service-account'),
          f'{edition}/krate: a re-run of the switch must not pile up seed tokens (skip while one has 30+ days left)')
    for name in ('refuse_loopback_public_url', 'grafana_admin', 'grafana_admin_token', 'identity_reconcile_grafana_client',
                 'identity_keycloak_running', 'public_url_origin',
                 'monitor_write_seed_token', 'monitor_grafana_seed_token', 'monitor_grafana_seed_renew',
                 'monitor_realm_refresh', 'grafana_list_collisions', 'monitor_compose', 'monitor_prepare'):
        first, second = (function_body((ROOT / edition / 'krate').read_text(), name) for edition in EDITIONS)
        e(first == second, f'kraft/epc parity: {name} must have the same body in both editions')
    if bash_binary() is None:
        return
    script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'env_value', 'public_url_host', 'refuse_loopback_public_url') + r'''
ENV_FILE="$1"
refuse_loopback_public_url
echo accepted
'''
    for url, expected in (('https://localhost/identity', 1), ('https://127.0.0.1/identity', 1), ('https://[::1]/identity', 1),
                          ('http://[::1]:8080/identity', 1), ('https://krate.example.test/identity', 0)):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / '.env'
            env.write_text(f'KEYCLOAK_PUBLIC_URL={url}\n')
            result = run_bash(script, env)
            e(result.returncode == expected,
              f'refuse_loopback_public_url with {url} must exit {expected}; got {result.returncode} ({result.stderr.strip()[:100]})')
            if expected == 1:
                e('KEYCLOAK_PUBLIC_URL' in result.stderr, f'the refusal of {url} must name KEYCLOAK_PUBLIC_URL; got {result.stderr.strip()[:120]!r}')
    origin_script = BASH_STUBS + bash_functions(ROOT / 'kraft/krate', 'env_value', 'public_url_origin') + r'''
ENV_FILE="$1"
public_url_origin
'''
    for url, expected in (('https://krate.example.test/identity', 'https://krate.example.test'),
                          ('https://krate.example.test:8443/identity', 'https://krate.example.test:8443'),
                          ('https://[fd00::1]:8443/identity', 'https://[fd00::1]:8443'),
                          ('https://krate.example.test/identity/', 'https://krate.example.test')):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / '.env'
            env.write_text(f'KEYCLOAK_PUBLIC_URL={url}\n')
            result = run_bash(origin_script, env)
            e(result.stdout.strip() == expected,
              f'public_url_origin of {url} must be {expected} (identity.py checked_origin refuses a path); got {result.stdout.strip()!r}')


def check_monitor_idp_host_stable(checks):
    """Formal 4a U22 at b2f458a: KRATE_IDP_HOST must not depend on the realm flags.

    monitor_compose gated the IdP host mapping on grafana_realm||perses_realm
    while the 4a fixture runs Perses local, so a Grafana-only auth switch
    changed perses extra_hosts and Compose recreated it (walk-169: grafana
    only). The mapping is only a hosts entry, so it is always exported; the
    discovery URL stays gated so idp-wait still exits at once.
    """
    e = checks.expect
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        compose = function_body(cli, 'monitor_compose')
        gate = re.search(r'if \$grafana_realm \|\| \$perses_realm; then\n(.*?)\n  fi\n', compose, re.S)
        if not e(gate is not None, f'{edition}/krate: monitor_compose must keep the realm-gated discovery block'):
            continue
        gated = gate.group(1)
        e('idp_host=' not in gated,
          f'{edition}/krate: KRATE_IDP_HOST must be exported outside the realm gate '
          f'(a Grafana-only switch must not recreate Perses); gated block holds {gated.strip()!r}')
        e('idp_url=' in gated,
          f'{edition}/krate: IDP_DISCOVERY_URL must stay realm-gated so idp-wait exits at once with no UI on the realm')
    try:
        unset = monitoring_services({'KRATE_IDP_HOST': ''})
        real = monitoring_services({'KRATE_IDP_HOST': 'krate-gate.test'})
    except ValueError as exc:
        e(False, f'monitoring: Compose rendering failed: {exc}')
        return
    hosts_unset = (unset.get('perses') or {}).get('extra_hosts')
    hosts_real = (real.get('perses') or {}).get('extra_hosts')
    e(any('host-gateway' in str(h) for h in hosts_unset or []),
      f'monitoring/perses with an empty host must keep the default host-gateway mapping; got {hosts_unset}')
    e(hosts_real == ['krate-gate.test=host-gateway'],
      f'monitoring/perses with KRATE_IDP_HOST=krate-gate.test must map exactly that host; got {hosts_real}')
    e(hosts_unset != hosts_real,
      'monitoring/perses: extra_hosts must follow KRATE_IDP_HOST '
      '(this is the recreate-relevant input the CLI must keep stable across a Grafana-only switch)')


def check_grafana_collision_paging(checks):
    """A full realm page with absent e-mails must not hide a collision on page two."""
    e = lambda cond, msg: checks.expect(cond, 'grafana collision paging: ' + msg)  # noqa: E731
    if bash_binary() is None:
        return
    # Keycloak 26.8.0 live output: --fields email returns one JSON object per
    # user, including {} for a user without e-mail; CSV emits an empty line.
    page1 = [{'email': 'collision@example.test'}]
    mixed_page = [{'email': f'user-{number:03d}@example.test'} if number not in (0, 50, 99) else {}
                  for number in range(100)]
    script_tail = r'''
IDENTITY_REALM=krate
grafana_admin() { printf '%s\n' "$LOCAL_USERS"; }
kcadm_login() { :; }
kcadm_logout() { :; }
env_value() { printf '%s\n' synthetic-secret; }
kcadm() {
  local offset='' format=json
  [[ " $* " == *' --format csv '* ]] && format=csv
  while (($#)); do
    if [[ "$1" == --offset ]]; then offset="$2"; shift 2; else shift; fi
  done
  printf 'offset=%s\n' "$offset" >&2
  case "$offset/$format" in
    0/json) printf '%s\n' "$PAGE0_JSON" ;;
    0/csv) printf '%s' "$PAGE0_CSV" ;;
    100/json) printf '%s\n' "$PAGE1_JSON" ;;
    100/csv) printf '%s\n' "$PAGE1_CSV" ;;
    *) printf '[]\n' ;;
  esac
}
grafana_list_collisions
'''
    for edition in EDITIONS:
        script = BASH_STUBS + bash_functions(ROOT / edition / 'krate', 'grafana_list_collisions') + script_tail
        for label, page0 in (('mixed', mixed_page), ('all absent', [{} for _ in range(100)])):
            environment = dict(os.environ, LOCAL_USERS=json.dumps([
                {'login': 'local-collision', 'email': 'collision@example.test', 'isDisabled': False}]),
                PAGE0_JSON=json.dumps(page0),
                PAGE0_CSV='\n'.join(row.get('email', '') for row in page0) + '\n',
                PAGE1_JSON=json.dumps(page1), PAGE1_CSV='collision@example.test')
            result = run_bash(script, env=environment)
            e(result.returncode == 0, f'{edition}/{label}: full first page must succeed: {result.stderr.strip()[:160]}')
            e('offset=100' in result.stderr, f'{edition}/{label}: absent e-mails must not end a 100-record page')
            e('krate monitor grafana-user retire local-collision' in result.stdout,
              f'{edition}/{label}: a page-two collision must be reported with its retire command')
            environment['PAGE1_JSON'] = 'malformed-json'
            result = run_bash(script, env=environment)
            e(result.returncode != 0 and 'offset=100' in result.stderr,
              f'{edition}/{label}: a malformed second page must fail closed after reading it')


def check_grafana_realm_plan(checks):
    """Phase 4 commits 4/8: Grafana's realm.ini, the krate-grafana client and the two Perses clients."""
    e = checks.expect
    values = identity.settings(SYNTHETIC)
    origin = values['public_origin']
    ini = identity.grafana_ini(values)
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read_string(ini)
    wanted_ini = {
        ('server', 'root_url'): origin + '/grafana/',
        ('server', 'serve_from_sub_path'): 'true',
        ('security', 'cookie_secure'): 'true',
        ('security', 'cookie_samesite'): 'lax',
        ('auth', 'disable_login_form'): 'true',
        ('auth', 'disable_login'): 'true',
        ('auth', 'login_maximum_inactive_lifetime_duration'): '%dm' % values['session_idle_minutes'],
        ('auth', 'login_maximum_lifetime_duration'): '%dh' % values['session_max_hours'],
        ('auth.basic', 'enabled'): 'false',
        ('auth.generic_oauth', 'enabled'): 'true',
        ('auth.generic_oauth', 'name'): 'Krate sign-in',
        ('auth.generic_oauth', 'allow_sign_up'): 'true',
        ('auth.generic_oauth', 'client_id'): 'krate-grafana',
        ('auth.generic_oauth', 'scopes'): 'openid profile email',
        ('auth.generic_oauth', 'login_attribute_path'): 'sub',
        ('auth.generic_oauth', 'groups_attribute_path'): 'groups',
        ('auth.generic_oauth', 'role_attribute_strict'): 'true',
        ('auth.generic_oauth', 'skip_org_role_sync'): 'false',
        ('auth.generic_oauth', 'allow_assign_grafana_admin'): 'false',
        ('auth.generic_oauth', 'use_pkce'): 'true',
        ('auth.generic_oauth', 'use_refresh_token'): 'true',
        ('auth.generic_oauth', 'tls_skip_verify_insecure'): 'false',
        ('auth.generic_oauth', 'tls_client_ca'): '/etc/krate/ca/server.crt',
        ('auth.generic_oauth', 'client_secret'): '$__file{/etc/krate/grafana/client-secret}',
        ('sso_settings', 'configurable_providers'): 'none',
        ('metrics', 'enabled'): 'false',
        ('auth.anonymous', 'hide_version'): 'true',
        ('public_dashboards', 'enabled'): 'false',
        ('snapshots', 'enabled'): 'false',
        ('news', 'news_feed_enabled'): 'false',
        ('dashboards', 'default_home_dashboard_path'): '/var/lib/grafana/dashboards/kafka-overview.json',
    }
    for (section, key), expected in wanted_ini.items():
        e(parser.has_option(section, key) and parser.get(section, key) == expected,
          f'realm.ini [{section}] {key} must be {expected!r} (row U26 and the plan\'s commit 4); got '
          f'{parser.get(section, key, fallback=None)!r}')
    for name, expected in (('auth_url', 'auth'), ('token_url', 'token'), ('api_url', 'userinfo')):
        e(parser.get('auth.generic_oauth', name, fallback='') == f'{origin}/identity/realms/krate/protocol/openid-connect/{expected}',
          f'realm.ini auth.generic_oauth {name} must be the realm\'s explicit {expected} endpoint')
    signout = parser.get('auth', 'signout_redirect_url', fallback='')
    e(signout.startswith(f'{origin}/identity/realms/krate/protocol/openid-connect/logout?')
      and 'post_logout_redirect_uri=' in signout and 'client_id=krate-grafana' in signout,
      f'realm.ini signout_redirect_url must end the realm session and return to the Grafana login; got {signout[:120]!r}')
    role = parser.get('auth.generic_oauth', 'role_attribute_path', fallback='')
    for group, wanted_role in ((values['admin_group'], 'Admin'), (values['viewer_group'], 'Viewer')):
        e(group in role and wanted_role in role, f'realm.ini role_attribute_path must map {group} to {wanted_role}; got {role!r}')
    e("''" in role and role.index(values['admin_group']) < role.index(values['viewer_group']),
      f'realm.ini role_attribute_path must prefer Admin and fall back to the empty role (role_attribute_strict refuses it); got {role!r}')
    for secret in ALL_SECRETS:
        e(secret not in ini, 'realm.ini must carry no secret value (the client secret is a $__file reference)')
    e((ROOT / 'monitoring/grafana/dashboards/kafka-overview.json').is_file(),
      'monitoring/grafana/dashboards/kafka-overview.json must exist: realm.ini makes it the home dashboard')

    client = identity.grafana_client(origin)
    e(client['clientId'] == 'krate-grafana' and client['publicClient'] is False and client['standardFlowEnabled'] is True
      and client['implicitFlowEnabled'] is False and client['directAccessGrantsEnabled'] is False
      and client['serviceAccountsEnabled'] is False and client['frontchannelLogout'] is False,
      f'krate-grafana must be a confidential standard-flow client with no front-channel logout; got {client}')
    e(client['redirectUris'] == [origin + '/grafana/login/generic_oauth'] and client['webOrigins'] == [origin],
      f'krate-grafana redirectUris/webOrigins; got {client["redirectUris"]} {client["webOrigins"]}')
    e(client['attributes'].get('pkce.code.challenge.method') == 'S256'
      and client['attributes'].get('post.logout.redirect.uris') == origin + '/grafana/login',
      f'krate-grafana attributes; got {client["attributes"]}')
    e(not any('backchannel' in key for key in client['attributes']),
      'krate-grafana must register no back-channel logout URL: Grafana has no such endpoint')
    e(sorted(client['defaultClientScopes']) == ['basic', 'email', 'profile', 'roles', 'web-origins']
      and client['optionalClientScopes'] == [],
      f'krate-grafana scopes must be the krate-ui default set and nothing optional; got {client["defaultClientScopes"]} {client["optionalClientScopes"]}')
    e(client['protocolMappers'] == [identity.groups_mapper()],
      'krate-grafana must carry the same groups mapper as krate-ui (one source: identity.groups_mapper)')
    e('secret' not in client, 'krate-grafana without --with-secret must carry no secret key')
    e('GRAFANA_OAUTH_CLIENT_SECRET' in identity.GRAFANA_SECRET_KEY, 'the Grafana secret key name')
    environment = dict(os.environ, GRAFANA_OAUTH_CLIENT_SECRET='synthetic-grafana-secret-7c1d2e')
    saved = {key: os.environ.pop(key, None) for key in ('GRAFANA_OAUTH_CLIENT_SECRET',)}
    try:
        try:
            identity.grafana_client(origin, with_secret=True)
            e(False, 'grafana_client --with-secret must refuse an unset GRAFANA_OAUTH_CLIENT_SECRET')
        except ValueError as exc:
            e('GRAFANA_OAUTH_CLIENT_SECRET' in str(exc) and 'synthetic' not in str(exc),
              f'the refusal must name the key and no value; got {exc}')
        os.environ['GRAFANA_OAUTH_CLIENT_SECRET'] = environment['GRAFANA_OAUTH_CLIENT_SECRET']
        with_secret = identity.grafana_client(origin, with_secret=True)
        e(with_secret['secret'] == environment['GRAFANA_OAUTH_CLIENT_SECRET'], 'grafana_client --with-secret substitutes the environment value')
    finally:
        for key, value in saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value
    # The refusal is tested through the shipped subcommand (the CLI's entry point), not the
    # library function, plus a positive control so the refusal cannot be unconditional.
    for url, expected_rc in (('https://localhost/identity', 1), ('https://127.0.0.1/identity', 1),
                             ('https://127.0.0.2/identity', 1), ('https://0.0.0.0/identity', 1),
                             ('https://[::1]/identity', 1), (SYNTHETIC['KEYCLOAK_PUBLIC_URL'], 0)):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / '.env'
            env_file.write_text(''.join(f'{key}={value}\n' for key, value in dict(SYNTHETIC, KEYCLOAK_PUBLIC_URL=url).items()))
            result = subprocess.run([sys.executable, str(ROOT / 'sso/identity.py'), 'grafana-ini', '--env-file', str(env_file)],
                                    text=True, capture_output=True)
            e((result.returncode != 0) == (expected_rc != 0),
              f'identity.py grafana-ini with KEYCLOAK_PUBLIC_URL={url} must exit {expected_rc}; got {result.returncode} {result.stderr.strip()[:120]!r}')
            if expected_rc != 0:
                e('KEYCLOAK_PUBLIC_URL' in result.stderr,
                  f'the refusal of {url} must name KEYCLOAK_PUBLIC_URL and no value; got {result.stderr.strip()[:160]!r}')
            else:
                e('[auth.generic_oauth]' in result.stdout, 'identity.py grafana-ini prints the ini on stdout')
    same = dict(client, id='generated-id', internalId='x', secret='**********',
                redirectUris=list(reversed(client['redirectUris'])), extra='ignored')
    e(identity.client_differs(client, same) is False,
      'client_differs: Keycloak additions, a masked secret and a reordered set are not a difference')
    e(identity.client_differs(client, dict(same, redirectUris=[origin + '/other'])) is True,
      'client_differs: a changed redirect URI is a difference')
    e(identity.client_differs(client, dict(same, attributes=dict(client['attributes'], **{'pkce.code.challenge.method': ''}))) is True,
      'client_differs: a dropped PKCE method is a difference')
    # The client-mode scalars, behaviourally (PR #42 review, identity.py:162 thread): flipping any
    # one of them in Keycloak's readback must flip the verdict — a mode change made in the console
    # (public client, disabled, a dropped flow, service accounts off) may never read back "same",
    # or the reconcile never converges it. The textual CLIENT_VERDICT_FIELDS check below pins the
    # list; this pins the behaviour the list exists for.
    for field, flipped in (('enabled', False), ('protocol', 'saml'), ('publicClient', True),
                           ('frontchannelLogout', not client['frontchannelLogout']),
                           ('standardFlowEnabled', not client['standardFlowEnabled']),
                           ('implicitFlowEnabled', not client['implicitFlowEnabled']),
                           ('directAccessGrantsEnabled', not client['directAccessGrantsEnabled']),
                           ('serviceAccountsEnabled', not client['serviceAccountsEnabled'])):
        e(identity.client_differs(client, dict(same, **{field: flipped})) is True,
          f'client_differs: a changed {field} is a difference (the client-mode fields take part in the verdict)')

def check_build_certificate_hint(checks):
    """kafbat-ui/build.py and scripts/collect-sources.py turn a failed certificate verification anywhere in an
    exception chain into one line that names the cause and the remedy (a Python without a certificate store, e.g.
    the python.org installer on macOS, or a proxy CA), instead of a traceback; every other failure still raises and
    the exit codes stay. The collector, which records per-component failures as unresolved, prints the same line
    after its totals. Found by a wiki walk of `krate package` on 2026-10-17 (CERTIFICATE_VERIFY_FAILED)."""
    import ast
    import ssl
    import threading
    import types
    import urllib.error
    e = checks.expect
    verify = ssl.SSLCertVerificationError(1, 'certificate verify failed: unable to get local issuer certificate')
    verify.verify_message = 'unable to get local issuer certificate'

    def explicit():
        try:
            raise urllib.error.URLError(verify)
        except urllib.error.URLError as inner:
            raise RuntimeError('download failed') from inner

    def implicit():
        try:
            raise urllib.error.URLError(verify)
        except urllib.error.URLError:
            raise RuntimeError('download failed')  # only __context__ links the cause

    def bare():
        try:
            raise verify  # http.client and ssl raise it unwrapped, without a URLError around it
        except ssl.SSLCertVerificationError:
            raise RuntimeError('download failed')

    def cyclic():
        a, b = RuntimeError('a'), RuntimeError('b')
        a.__cause__, b.__cause__ = b, a
        raise a

    def exit_three():
        try:
            raise urllib.error.URLError(verify)
        except urllib.error.URLError:
            raise SystemExit(3)  # an exit of main() whose context happens to be a certificate failure

    for rel, prog in (('kafbat-ui/build.py', 'build.py'), ('scripts/collect-sources.py', 'collect-sources.py')):
        text = (ROOT / rel).read_text()
        tree = ast.parse(text)
        lifted = ('certificate_failure', 'certificate_summary') if prog == 'collect-sources.py' else ('certificate_failure',)
        wanted: list[ast.stmt] = [node for node in tree.body
                                  if (isinstance(node, ast.FunctionDef) and node.name in lifted)
                                  or (isinstance(node, ast.Assign)
                                      and any(getattr(t, 'id', '') == 'CERTIFICATE_HINT' for t in node.targets))]
        guard = [node for node in tree.body if isinstance(node, ast.If) and "__name__ == '__main__'" in ast.unparse(node.test)]
        if not e(len(wanted) == len(lifted) + 1 and len(guard) == 1,
                 f'{rel}: defines {", ".join(lifted)}, CERTIFICATE_HINT and one __main__ guard at top level'):
            continue
        namespace: dict = {'ssl': ssl}
        exec(compile(ast.Module(body=wanted, type_ignores=[]), rel, 'exec'), namespace)
        failure, hint = namespace['certificate_failure'], namespace['CERTIFICATE_HINT']

        def bounded(chain):
            """certificate_failure(chain) in a daemon thread: a walk that a cycle never stops fails here in
            seconds instead of hanging the whole check."""
            answer = []
            worker = threading.Thread(target=lambda: answer.append(failure(chain)), daemon=True)
            worker.start()
            worker.join(5)
            return answer[0] if answer else 'no answer within 5 s'

        for maker, expected in ((explicit, verify), (implicit, verify), (bare, verify), (cyclic, None)):
            try:
                maker()
            except RuntimeError as error:
                got = bounded(error)
            else:
                got = 'no RuntimeError raised'
            e(got is expected, f'{rel}: certificate_failure on the {maker.__name__} chain gives {got!r}')
        e(bounded(verify) is verify, f'{rel}: certificate_failure returns the verification error itself')
        e(failure(urllib.error.URLError('timed out')) is None and failure(ValueError('checksum mismatch')) is None
          and failure(None) is None, f'{rel}: certificate_failure is None for unrelated errors')
        message = hint % (prog, 'unable to get local issuer certificate')
        e(message.startswith(prog + ': ') and 'unable to get local issuer certificate' in message
          and 'Install Certificates.command' in message and '/etc/ssl/cert.pem' in message
          and '/etc/ssl/certs/ca-certificates.crt' in message, f'{rel}: the hint names the cause and the remedies; got {message!r}')

        def run_guard(stub_main: 'Callable[[], object]'):
            """The file's own `if __name__ == '__main__':` block, run against a stub main()."""
            body = ast.Module(body=guard[0].body, type_ignores=[])
            scope: dict = {'main': stub_main, 'sys': sys, 'certificate_failure': failure, 'CERTIFICATE_HINT': hint}
            try:
                exec(compile(body, rel, 'exec'), scope)
            except SystemExit as stop:
                return 'exit', stop.code
            except BaseException as raised:  # noqa: B036  # the guard must let these through unchanged
                return 'raised', type(raised).__name__
            return 'returned', None

        cert = run_guard(explicit)
        e(cert[0] == 'exit' and isinstance(cert[1], str) and cert[1].startswith(prog + ': ')
          and 'unable to get local issuer certificate' in cert[1], f'{rel}: a certificate failure exits with the hint; got {cert}')
        e(run_guard(lambda: (_ for _ in ()).throw(ValueError('x'))) == ('raised', 'ValueError'),
          f'{rel}: any other failure still raises')
        e(run_guard(lambda: (_ for _ in ()).throw(KeyboardInterrupt())) == ('raised', 'KeyboardInterrupt'),
          f'{rel}: Ctrl-C still raises')
        e(run_guard(exit_three) == ('exit', 3), f'{rel}: an exit of main() keeps its code even with a certificate failure '
                                                 f'as its context; got {run_guard(exit_three)}')
        if prog == 'collect-sources.py':
            e(run_guard(lambda: 2) == ('exit', 2) and run_guard(lambda: 0) == ('exit', 0),
              f'{rel}: the exit code of main() is kept (2 on unresolved sources)')
            summary = namespace['certificate_summary']
            failing = 'Tree API failed: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed>'
            comps = [types.SimpleNamespace(reason=reason) for reason in (failing, None, 'checksum mismatch', failing)]
            line = summary(comps)
            e(summary([types.SimpleNamespace(reason=None), types.SimpleNamespace(reason='HTTP 404')]) is None
              and isinstance(line, str) and line.startswith('collect-sources.py: ')
              and 'CERTIFICATE_VERIFY_FAILED in 2 components' in line,
              f'{rel}: certificate_summary is None without a certificate failure and counts the failed components; got {line!r}')
            start = text.find("log(f'{args.edition}: {manifest[\"totals\"]}')")
            tail = text[start:text.find('def certificate_summary')] if start >= 0 else ''
            printed, returned = tail.find('print(hint, file=sys.stderr'), tail.find('return 2')
            e('hint = certificate_summary(comps)\n    if hint:\n        print(hint, file=sys.stderr' in tail
              and 0 <= printed < returned,
              f'{rel}: the summary prints certificate_summary() on stderr when there is one, before the exit code')
        else:
            e(run_guard(lambda: None) == ('returned', None), f'{rel}: a successful build returns normally')


def check_monitor_logins(checks):
    """`krate credentials` and `monitor ui` (monitor_logins) print the Grafana and Perses addresses and sign-ins
    that work: with Krate sign-in Grafana is at https://<public authority>/grafana/ and both UIs say "Krate sign-in";
    a company site file keeps "company SSO". Before, monitor_logins printed http://<host>:3000 and "company SSO"
    in realm mode (a 2026-10-17 wiki review of the credentials output)."""
    e = checks.expect
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        e(cli.count('ok "Grafana:    $(grafana_address)"') == 1, f'{edition}/krate: monitor up must print grafana_address')
        e('echo "Grafana:  $(grafana_address)"' in function_body(cli, 'monitor_logins'),
          f'{edition}/krate: monitor_logins must print grafana_address')
    if bash_binary() is None:
        return
    for edition in EDITIONS:
        script = BASH_STUBS + bash_functions(ROOT / edition / 'krate', 'env_value', 'env_value_file', 'public_url_host',
                                             'public_url_authority', 'grafana_address', 'perses_address',
                                             'monitor_logins') + r"""
ENV_FILE="$1/.env"; MONITOR_DIR="$1/monitoring"; IDENTITY_REALM=krate
hostname() { echo build-host.local; }
monitor_logins | grep -E '^(Grafana|Perses|Sign-in):'
"""
        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp)
            (site / 'monitoring').mkdir()
            cases = (
                ({'GRAFANA_AUTH_CONFIG': 'realm.ini', 'PERSES_AUTH_MODE': 'native', 'PERSES_IDP': 'krate'},
                 'https://krate.example.com/identity',
                 ['Grafana:  https://krate.example.com/grafana/',
                  "Sign-in:  Krate sign-in (realm krate); the user below is Grafana's own login, kept for the rollback on this host",
                  'Perses:   https://krate.example.com:3443', 'Sign-in:  Krate sign-in (realm krate)']),
                ({'GRAFANA_AUTH_CONFIG': 'realm.ini', 'PERSES_AUTH_MODE': 'native', 'PERSES_IDP': 'krate'},
                 'https://krate.example.com:8443/identity',
                 ['Grafana:  https://krate.example.com:8443/grafana/',
                  "Sign-in:  Krate sign-in (realm krate); the user below is Grafana's own login, kept for the rollback on this host",
                  'Perses:   https://krate.example.com:3443', 'Sign-in:  Krate sign-in (realm krate)']),
                ({'GRAFANA_AUTH_CONFIG': 'local.ini', 'PERSES_AUTH_MODE': 'local'},
                 'https://krate.example.com/identity',
                 ['Grafana:  http://build-host.local:3000', 'Perses:   https://build-host.local:3443']),
                ({'GRAFANA_AUTH_CONFIG': 'local.ini', 'PERSES_AUTH_MODE': 'native', 'PERSES_IDP': ''},
                 'https://krate.example.com/identity',
                 ['Grafana:  http://build-host.local:3000', 'Perses:   https://build-host.local:3443',
                  'Sign-in:  company SSO (native mode)']),
                ({'GRAFANA_AUTH_CONFIG': 'realm.ini', 'PERSES_AUTH_MODE': 'native', 'PERSES_IDP': 'krate'}, '',
                 ['Grafana:  http://build-host.local:3000',
                  "Sign-in:  Krate sign-in (realm krate); the user below is Grafana's own login, kept for the rollback on this host",
                  'Perses:   https://build-host.local:3443', 'Sign-in:  Krate sign-in (realm krate)']),
            )
            for monitor_env, url, expected in cases:
                write_env(site, {'KEYCLOAK_PUBLIC_URL': url})
                write_env(site / 'monitoring', dict(monitor_env, GRAFANA_PASSWORD='not-a-secret-in-this-test',
                                                    PERSES_ADMIN_PASSWORD='not-a-secret-in-this-test'))
                out = run_bash(script, site)
                got = out.stdout.strip().splitlines()
                e(out.returncode == 0 and got == expected,
                  f'{edition}/krate monitor_logins ({monitor_env}, {url}): expected {expected}; got {out.returncode} {got} {out.stderr.strip()[:120]}')
            # The two `monitor up` summary lines themselves, run as written.
            cli = (ROOT / edition / 'krate').read_text()
            up_lines = [line.strip() for line in cli.splitlines() if line.strip().startswith(('ok "Grafana:', 'ok "Perses:'))]
            e(len(up_lines) == 2, f'{edition}/krate: monitor up prints exactly one Grafana and one Perses line; got {up_lines}')
            up_script = BASH_STUBS + bash_functions(ROOT / edition / 'krate', 'env_value', 'env_value_file', 'public_url_host',
                                                    'public_url_authority', 'grafana_address', 'perses_address') + (
                '\nENV_FILE="$1/.env"; MONITOR_DIR="$1/monitoring"\nhostname() { echo build-host.local; }\n' + '\n'.join(up_lines) + '\n')
            write_env(site, {'KEYCLOAK_PUBLIC_URL': 'https://krate.example.com/identity'})
            write_env(site / 'monitoring', {'GRAFANA_AUTH_CONFIG': 'realm.ini', 'PERSES_AUTH_MODE': 'native', 'PERSES_IDP': 'krate'})
            out = run_bash(up_script, site)
            want = ['  ok Grafana:    https://krate.example.com/grafana/', '  ok Perses:     https://krate.example.com:3443 (native sign-in)']
            e(out.returncode == 0 and out.stdout.splitlines() == want,
              f'{edition}/krate monitor up summary (realm): expected {want}; got {out.returncode} {out.stdout.splitlines()} {out.stderr.strip()[:120]}')


def check_perses_address(checks):
    """monitor up and monitor logins print the Perses address that signs in: the public name with the
    Krate realm (PERSES_IDP=krate), this machine's host name otherwise. Realm mode printed the host
    name before (a 2026-10-17 walk: `https://<mac>.local:3443`, where the realm client cannot sign in)."""
    e = checks.expect
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        e('echo "Perses:   $(perses_address)"' in function_body(cli, 'monitor_logins'),
          f'{edition}/krate: monitor_logins must print perses_address')
        e(cli.count('ok "Perses:     $(perses_address) (') == 1, f'{edition}/krate: monitor up must print perses_address')
        e(':$(env_value_file "$MONITOR_DIR/.env" PERSES_PORT 3443)' not in cli,
          f'{edition}/krate: no Perses address may be built outside perses_address')
    if bash_binary() is None:
        return
    for edition in EDITIONS:
        script = BASH_STUBS + bash_functions(ROOT / edition / 'krate', 'env_value', 'env_value_file', 'public_url_host',
                                             'perses_address') + r"""
ENV_FILE="$1/.env"; MONITOR_DIR="$1/monitoring"
hostname() { echo build-host.local; }
perses_address
"""
        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp)
            (site / 'monitoring').mkdir()
            for idp, perses_mode, url, port, expected in (
                    ('krate', 'native', 'https://Krate.Example.COM/identity', '3443', 'https://krate.example.com:3443'),
                    ('krate', 'native', 'https://[FD00::5]:8443/identity', '4443', 'https://[fd00::5]:4443'),
                    ('', 'native', 'https://krate.example.com/identity', '3443', 'https://build-host.local:3443'),
                    ('', 'local', 'https://krate.example.com/identity', '3443', 'https://build-host.local:3443'),
                    ('krate', 'native', '', '3443', 'https://build-host.local:3443')):
                write_env(site, {'KEYCLOAK_PUBLIC_URL': url})
                write_env(site / 'monitoring', {'PERSES_IDP': idp, 'PERSES_AUTH_MODE': perses_mode, 'PERSES_PORT': port})
                out = run_bash(script, site)
                e(out.returncode == 0 and out.stdout.strip() == expected,
                  f'{edition}/krate perses_address (PERSES_IDP={idp or "empty"}, {perses_mode}, {url or "no public URL"}): expected {expected}; '
                  f'got {out.returncode} {out.stdout.strip()!r} {out.stderr.strip()[:120]}')


def check_perses_clients(checks):
    """Phase 4 commit 8's generators, landed with the Grafana ones because they share groups_mapper,
    checked_origin and env_secret: the two Perses realm clients."""
    e = checks.expect
    perses = identity.perses_clients('https://krate.example.test', '3443')
    ids = sorted(item['clientId'] for item in perses)
    e(ids == ['krate-perses', 'krate-perses-sync'], f'the Perses clients; got {ids}')
    main_client = next(item for item in perses if item['clientId'] == 'krate-perses')
    e(sorted(main_client['redirectUris']) == sorted(['https://krate.example.test:3443/oauth2/callback',
                                                    'https://krate.example.test:3443/api/auth/providers/oidc/krate/callback']),
      f'krate-perses must carry both callbacks (oauth2-proxy and Perses native); got {main_client["redirectUris"]}')
    e(main_client['attributes'].get('pkce.code.challenge.method') == 'S256', 'krate-perses must require PKCE S256')
    verdict_fields = (ROOT / 'sso/identity.py').read_text().split('CLIENT_VERDICT_FIELDS = (')[1].split(')')[0]
    e(all("'" + f + "'" in verdict_fields for f in
          ('enabled', 'protocol', 'publicClient', 'standardFlowEnabled', 'implicitFlowEnabled',
           'directAccessGrantsEnabled', 'serviceAccountsEnabled')),
      'sso/identity.py: the client-differs verdict must cover the client-mode fields, or a mode change '
      'made in the Keycloak console reads back as "same" and is never converged')
    e('perses_rep(args.name, origin, port, args.with_secret)' in (ROOT / 'sso/identity.py').read_text(),
      'identity.py: the Perses client-differs verdict must build the plan with the secret, or a rotated '
      'OAUTH2_PROXY_CLIENT_SECRET/PERSES_SYNC_CLIENT_SECRET is undetectable and never converged')
    guard = next(item for item in perses if item['clientId'] == 'krate-perses-sync')
    e(guard['serviceAccountsEnabled'] is True and guard['standardFlowEnabled'] is False,
      f'krate-perses-sync must be a service-account client with no browser flow; got {guard}')
    # The sync shape in the verdict too: it declares no frontchannelLogout/attributes/protocolMappers,
    # and client_differs compares a field only when the plan declares it — so a faithful readback
    # stays "same" while flipping its service-account flag is a difference (PR #42 review, :162).
    sync_readback = dict(guard, id='generated-id', realm_client=True, secret=identity.KEYCLOAK_SECRET_MASK)
    e(identity.client_differs(guard, sync_readback) is False,
      'client_differs: the perses-sync readback with Keycloak additions and a masked secret is not a difference')
    e(identity.client_differs(guard, dict(sync_readback, serviceAccountsEnabled=False)) is True,
      'client_differs: turning off the perses-sync service account is a difference')


def load_grafana_admin():
    spec = importlib.util.spec_from_file_location('grafana_admin', ROOT / 'monitoring/grafana-admin.py')
    assert spec is not None and spec.loader is not None, 'monitoring/grafana-admin.py missing'
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_grafana_admin_contract(checks):
    """PR #42 F2/F3: retire-user's address composition and service-account's role verification."""
    e = checks.expect
    admin = load_grafana_admin()

    def run(command):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            command()
        return json.loads(buffer.getvalue())

    class RecordingApi:
        """Stands in for grafana-admin's Api: records calls, answers Grafana v12.2.0's own shapes.

        The confirmations mirror the live-provided contract (t-grafana-admin row 3):
        PUT /api/users/:id -> {"message": "User updated"} (pkg/api/user.go:276),
        POST /api/admin/users/:id/disable -> {"message": "User disabled"} (pkg/api/admin_users.go:307),
        GET /api/serviceaccounts/search -> SearchOrgServiceAccountsResult (models.go:131-139) whose
        ServiceAccountDTO entries carry `role` (models.go:87, selected at database/store.go:381).
        """

        def __init__(self, users=(), search_pages=(), create=None, user_pages=None,
                     put_message='User updated', disable_message='User disabled'):
            self.users = list(users)
            self.user_pages = user_pages
            self.search_pages = list(search_pages)
            self.create = create  # (status, payload) tuple, or an exception instance to raise
            self.put_message = put_message
            self.disable_message = disable_message
            self.calls = []

        def request(self, method, path, body=None):
            self.calls.append((method, path, body))
            match = re.fullmatch(r'/api/users\?perpage=(\d+)&page=(\d+)', path)
            if method == 'GET' and match:
                per_page, page = map(int, match.groups())
                if self.user_pages is not None:
                    return 200, self.user_pages[page - 1]
                return 200, self.users[(page - 1) * per_page:page * per_page]
            if method == 'GET' and path.startswith('/api/serviceaccounts/search'):
                assert self.search_pages, 'unexpected extra search call: ' + path
                return 200, self.search_pages.pop(0)
            if method == 'PUT' and re.fullmatch(r'/api/users/\d+', path):
                return 200, {'message': self.put_message}
            if method == 'POST' and re.fullmatch(r'/api/admin/users/\d+/disable', path):
                return 200, {'message': self.disable_message}
            if method == 'POST' and path == '/api/serviceaccounts':
                if isinstance(self.create, Exception):
                    raise self.create
                return self.create
            raise AssertionError('unexpected call %s %s' % (method, path))

    # F2 — a plain login keeps the live-walk-verified behaviour byte for byte (A12/A13).
    api = RecordingApi(users=[{'id': 5, 'login': 'p4-collide', 'name': 'P4 Collide'}])
    payload = run(lambda: admin.cmd_retire_user(api, 'p4-collide', admin.DEFAULT_EMAIL_SUFFIX))
    e(payload == {'login': 'p4-collide', 'email': 'p4-collide+retired@invalid', 'disabled': True},
      f'retire-user of a plain login must keep the <login><suffix> composition; got {payload}')
    e([(method, path) for method, path, _ in api.calls]
      == [('GET', '/api/users?perpage=1000&page=1'), ('PUT', '/api/users/5'),
          ('POST', '/api/admin/users/5/disable')],
      f'retire-user must PUT the e-mail and then disable, and call nothing else; got {api.calls}')
    e(api.calls[1][2] == {'email': 'p4-collide+retired@invalid', 'login': 'p4-collide', 'name': 'P4 Collide'},
      f'the PUT must keep login and name and move only the e-mail aside (folders/dashboards untouched); '
      f'got {api.calls[1][2]}')

    # User search must not omit a collision or retirement target on the next page.
    users = [{'id': i, 'login': f'user{i}'} for i in range(1, 1001)]
    users.append({'id': 1001, 'login': 'target', 'name': 'Target'})
    api = RecordingApi(users=users)
    payload = run(lambda: admin.cmd_retire_user(api, 'target', admin.DEFAULT_EMAIL_SUFFIX))
    e(payload['disabled'] is True and payload['login'] == 'target',
      f'retire-user must find the account on page two; got {payload}')
    e([(method, path) for method, path, _ in api.calls[:2]]
      == [('GET', '/api/users?perpage=1000&page=1'),
          ('GET', '/api/users?perpage=1000&page=2')],
      f'user pagination must cross the 1000-user boundary; got {api.calls[:2]}')
    for label, bad_page in (('malformed', {'users': []}), ('duplicate', [{'id': 1}])):
        api = RecordingApi(users=users, user_pages=[users[:1000], bad_page])
        try:
            admin.list_users(api)
            e(False, f'{label} second user page must fail closed')
        except admin.OperationError:
            pass

    # F2 — an email-shaped login tags the local part; the double-@ address must never be composed.
    api = RecordingApi(users=[{'id': 6, 'login': 'jane@example.com', 'name': ''}])
    payload = run(lambda: admin.cmd_retire_user(api, 'jane@example.com', admin.DEFAULT_EMAIL_SUFFIX))
    email = payload.get('email')
    e(email == 'jane+retired@invalid' and isinstance(email, str) and email.count('@') == 1,
      f'retire-user of jane@example.com must produce jane+retired@invalid (exactly one @); got {payload}')

    # F2 — Grafana's own confirmation strings stay enforced on both steps.
    for kwargs, wanted in (({'put_message': 'Nope'}, 'did not confirm "User updated"'),
                           ({'disable_message': 'Nope'}, 'did not confirm "User disabled"')):
        api = RecordingApi(users=[{'id': 7, 'login': 'u', 'name': ''}], **kwargs)
        try:
            run(lambda: admin.cmd_retire_user(api, 'u', admin.DEFAULT_EMAIL_SUFFIX))
            e(False, f'retire-user must fail when a step is not confirmed ({wanted})')
        except admin.OperationError as error:
            e(wanted in str(error), f'retire-user refusal for an unconfirmed step; got {error}')

    # F3 — the requested role on an existing account: idempotent reuse, no create.
    def search_hit(role):
        return {'totalCount': 1, 'page': 1, 'perPage': 1000,
                'serviceAccounts': [{'id': 11, 'name': 'krate-seed', 'role': role}]}

    empty = {'totalCount': 0, 'page': 1, 'perPage': 1000, 'serviceAccounts': []}
    api = RecordingApi(search_pages=[search_hit('Admin')])
    payload = run(lambda: admin.cmd_service_account(api, 'krate-seed', 'Admin'))
    e(payload == {'id': 11, 'created': False},
      f'service-account with the correct existing role must stay idempotent (created: false); got {payload}')
    e(not any(method == 'POST' for method, _, _ in api.calls),
      f'service-account reuse must not create anything; got {api.calls}')

    # F3 — a drifted role is refused with a clear, value-free message.
    api = RecordingApi(search_pages=[search_hit('Viewer')])
    try:
        run(lambda: admin.cmd_service_account(api, 'krate-seed', 'Admin'))
        e(False, 'service-account must refuse an existing account whose role differs from the requested one')
    except admin.OperationError as error:
        message = str(error)
        e('role' in message and 'Service accounts' in message,
          f'the role refusal must name the problem and the remediation; got {message!r}')
        e(not re.search(r'\b(Viewer|Editor|Admin|krate-seed)\b', message),
          f'the role refusal must carry no value (found role, requested role, account name); got {message!r}')

    # F3 — absent account: created with the requested role.
    api = RecordingApi(search_pages=[empty], create=(201, {'id': 12, 'name': 'krate-seed'}))
    payload = run(lambda: admin.cmd_service_account(api, 'krate-seed', 'Admin'))
    e(payload == {'id': 12, 'created': True}, f'service-account creation must report created: true; got {payload}')
    e(api.calls[-1] == ('POST', '/api/serviceaccounts', {'name': 'krate-seed', 'role': 'Admin'}),
      f'the create must carry the requested role; got {api.calls[-1]}')

    # F3 — the 400-race reuse path verifies the role too, and stays idempotent when it matches.
    raced = admin.HttpFailure(400, 'POST', '/api/serviceaccounts', detail='service account already exists')
    api = RecordingApi(search_pages=[empty, search_hit('Editor')], create=raced)
    try:
        run(lambda: admin.cmd_service_account(api, 'krate-seed', 'Admin'))
        e(False, 'the search/create race reuse must verify the role as well')
    except admin.OperationError as error:
        e('role' in str(error), f'the race-path role refusal; got {error}')
    api = RecordingApi(search_pages=[empty, search_hit('Admin')], create=raced)
    payload = run(lambda: admin.cmd_service_account(api, 'krate-seed', 'Admin'))
    e(payload.get('created') is False and 'note' in payload,
      f'the race reuse with the correct role stays idempotent with its note; got {payload}')


def check_render_writes(checks):
    """Phase 4 slice 4b (F5): render.py file modes (0o400), directory sealing (0o500), and O_EXCL|O_NOFOLLOW open flags."""
    e = checks.expect
    spec = importlib.util.spec_from_file_location('render_check_mod', str(ROOT / 'monitoring/render.py'))
    if spec is None or spec.loader is None:
        e(False, 'cannot load monitoring/render.py')
        return
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    ipv6_site = mod.realm_site({
        'KEYCLOAK_PUBLIC_URL': 'https://[2001:db8::10]/identity',
        'KEYCLOAK_VIEWER_GROUP': 'KRATE_VIEWERS',
        'KEYCLOAK_ADMIN_GROUP': 'KRATE_ADMINS',
        'KEYCLOAK_SESSION_IDLE_MINUTES': '15',
        'KEYCLOAK_SESSION_MAX_HOURS': '8',
        'PERSES_PORT': '3443',
    })
    e(ipv6_site['public_url'] == 'https://[2001:db8::10]:3443',
      f'realm Perses origin must retain IPv6 brackets; got {ipv6_site["public_url"]}')
    # Realm mode is Krate's own sign-in: the Perses button says what Grafana's says, while a
    # company site file keeps its own name or the "Company sign-in" default.
    e(ipv6_site.get('display_name') == identity.GRAFANA_SIGNIN_NAME,
      f'realm Perses provider must be named {identity.GRAFANA_SIGNIN_NAME!r}; got {ipv6_site.get("display_name")!r}')
    realm_conf = mod.perses_config('native', ipv6_site)
    e('name: "%s"' % identity.GRAFANA_SIGNIN_NAME in realm_conf,
      'the rendered realm Perses config must name its provider "%s"' % identity.GRAFANA_SIGNIN_NAME)
    site_conf = mod.perses_config('native', {k: v for k, v in ipv6_site.items() if k != 'display_name'})
    e('name: "Company sign-in"' in site_conf,
      'a Perses site without display_name must keep the "Company sign-in" default')
    named_conf = mod.perses_config('native', dict(ipv6_site, display_name='Acme sign-in'))
    e('name: "Acme sign-in"' in named_conf, 'a Perses site file keeps its own display_name')

    chmods, chowns, opens = [], [], []
    real_chmod, real_chown, real_open = os.chmod, os.chown, os.open

    def chmod_stub(path, mode, *args, **kwargs):
        chmods.append((str(path), mode))
        real_chmod(path, mode, *args, **kwargs)

    def chown_stub(path, uid, gid, *args, **kwargs):
        chowns.append((str(path), uid, gid))

    def open_stub(path, flags, *args, **kwargs):
        opens.append((flags, str(path)))
        return real_open(path, flags, *args, **kwargs)

    old_chmod, old_chown, old_open = os.chmod, os.chown, os.open
    try:
        os.chmod = chmod_stub
        os.chown = chown_stub
        os.open = open_stub
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            env = {
                'PERSES_ENCRYPTION_KEY': 'A' * 32,
                'PERSES_ADMIN_USER': 'admin',
                'PERSES_ADMIN_PASSWORD': 'admin-password-1234',
            }
            mod.render(env, out, str(out / 'perses.json'))
            file_chmods = [(p, m) for p, m in chmods if '.tmp' in Path(p).name]
            e(bool(file_chmods) and all(m == 0o400 for _, m in file_chmods),
              f'render.py: every rendered file must be chmod 0o400; got {[(p, oct(m)) for p, m in file_chmods if m != 0o400]}')
            bad_flags = [('oct=%s' % oct(f), p) for f, p in opens
                         if f & os.O_EXCL and not (hasattr(os, 'O_NOFOLLOW') and f & os.O_NOFOLLOW)]
            e(not bad_flags, f'render.py: every file write must open O_EXCL|O_NOFOLLOW; offenders: {bad_flags}')
            dir_finals = {}
            for p, m in chmods:
                if '.tmp' in Path(p).name or Path(p).name == '':
                    continue
                dir_finals[p] = m
            bad_dirs = [(p, oct(m)) for p, m in dir_finals.items() if m != 0o500]
            e(bool(dir_finals) and not bad_dirs,
              f'render.py: every rendered directory tree must be sealed 0o500; offenders: {bad_dirs}')
    finally:
        os.chmod, os.chown, os.open = old_chmod, old_chown, old_open


def check_migrate_issuer(checks):
    """Phase 4 slice 4b (F6, F8, F9): migrate_issuer.py idempotence, marker perms, and parity."""
    e = checks.expect
    text = (ROOT / 'monitoring/perses/migrate_issuer.py').read_text()
    e('applied == issuer' in text,
      'migrate_issuer.py: the marker-equality guard must exist; a second run with an unchanged issuer must be a strict no-op')
    e('temporary.chmod(0o400)' in text,
      'migrate_issuer.py: marker write must chmod 0o400 (sealing discipline)')

    # Parity check: MANAGED_BINDINGS in migrate_issuer must match perses_sync.MANAGED
    sync_text = (ROOT / 'monitoring/perses/sync/perses_sync.py').read_text()
    mig_managed = re.search(r'MANAGED_BINDINGS = (\([^)]+\))', text)
    sync_managed = re.search(r'MANAGED = (\([^)]+\))', sync_text)
    e(mig_managed is not None and sync_managed is not None and mig_managed.group(1) == sync_managed.group(1),
      'migrate_issuer.MANAGED_BINDINGS must match perses_sync.MANAGED')

    # Behavioural drive: run twice on a fixture directory
    with tempfile.TemporaryDirectory() as td:
        fixture = Path(td)
        data_dir = fixture / 'data'
        users_dir = data_dir / 'users'
        grb_dir = data_dir / 'globalrolebindings'
        users_dir.mkdir(parents=True)
        grb_dir.mkdir(parents=True)
        # Old OIDC user
        (users_dir / 'old-user.json').write_text(json.dumps({
            'spec': {'oauthProviders': [{'issuer': 'https://old.invalid/realms/krate'}]}
        }))
        # Native user
        (users_dir / 'native-user.json').write_text(json.dumps({
            'spec': {}
        }))
        # Managed binding with 24-hex hash
        (grb_dir / 'krate-admin-0123456789abcdef01234567.json').write_text('{}')
        # Unrelated / service binding
        (grb_dir / 'krate-sync.json').write_text('{}')

        issuer_file = fixture / 'issuer'
        new_issuer = 'https://new.invalid/realms/krate'
        issuer_file.write_text(new_issuer + '\n')

        script = ROOT / 'monitoring/perses/migrate_issuer.py'
        # Run 1
        res1 = subprocess.run([sys.executable, '-I', str(script), '--data-dir', str(data_dir), '--issuer-file', str(issuer_file)],
                              capture_output=True, text=True)
        e(res1.returncode == 0, f'migrate_issuer run 1 failed: {res1.stderr}')
        e('removed 1 stale user(s) and 1 managed binding(s)' in res1.stdout,
          f'migrate_issuer run 1 output unexpected: {res1.stdout}')
        marker = data_dir / '.krate-issuer'
        e(marker.exists() and (marker.stat().st_mode & 0o777) == 0o400,
          'migrate_issuer: marker must exist with mode 0o400')
        census1 = sorted(p.name for p in data_dir.rglob('*') if p.is_file())

        # Run 2
        res2 = subprocess.run([sys.executable, '-I', str(script), '--data-dir', str(data_dir), '--issuer-file', str(issuer_file)],
                              capture_output=True, text=True)
        e(res2.returncode == 0, f'migrate_issuer run 2 failed: {res2.stderr}')
        e(res2.stdout.strip() == f'perses-migrate: issuer unchanged ({new_issuer}); nothing to do',
          f'migrate_issuer run 2 output unexpected: {res2.stdout}')
        census2 = sorted(p.name for p in data_dir.rglob('*') if p.is_file())
        e(census1 == census2, f'migrate_issuer: second run must not alter any file; census changed from {census1} to {census2}')

        # An unreadable user file must fail the migration before the marker
        # advances and before any stale user is removed, so a repaired file
        # is re-inspected on the next run instead of being skipped forever.
        (users_dir / 'broken-user.json').write_text('{not json')
        (users_dir / 'stale-user.json').write_text(json.dumps({
            'spec': {'oauthProviders': [{'issuer': 'https://old.invalid/realms/krate'}]}
        }))
        marker.unlink()
        res3 = subprocess.run([sys.executable, '-I', str(script), '--data-dir', str(data_dir), '--issuer-file', str(issuer_file)],
                              capture_output=True, text=True)
        e(res3.returncode != 0 and 'migration not advanced' in res3.stderr,
          f'migrate_issuer must fail before advancing the marker on an unreadable user; got rc={res3.returncode}: {res3.stdout} {res3.stderr}')
        e(not marker.exists() and (users_dir / 'stale-user.json').exists(),
          'migrate_issuer must neither write the marker nor remove stale users when a user is unreadable')
        (users_dir / 'broken-user.json').write_text(json.dumps({'spec': {}}))
        res4 = subprocess.run([sys.executable, '-I', str(script), '--data-dir', str(data_dir), '--issuer-file', str(issuer_file)],
                              capture_output=True, text=True)
        e(res4.returncode == 0 and not (users_dir / 'stale-user.json').exists() and marker.exists(),
          f'migrate_issuer must complete once the unreadable user is repaired; got rc={res4.returncode}: {res4.stdout} {res4.stderr}')


def check_monitoring_tables(checks):
    """Commit 12: monitoring/README.md Table 1 (all 18 services) and non-loopback bind warnings."""
    e = checks.expect
    text = (ROOT / 'monitoring/README.md').read_text()
    e('## Table 1 — Service exposure and enforcement' in text,
      'monitoring/README.md: must define Table 1 — Service exposure and enforcement')
    parts = text.split('## Table 1 — Service exposure and enforcement')
    table1_text = parts[1].split('## Table 2')[0] if len(parts) > 1 else ''
    components = []
    for line in table1_text.splitlines():
        line = line.strip()
        if not line.startswith('|'):
            continue
        cells = [c.strip().strip('`') for c in line.strip('|').split('|')]
        if len(cells) >= 6 and cells[0] and cells[0] != 'component' and not set(cells[0]) <= {'-', ' '}:
            components.append(cells[0])

    services = monitoring_services()
    e(len(services) == 18, f'monitoring/docker-compose.yml must have 18 services; got {len(services)}')
    e(set(components) == set(services.keys()),
      f'monitoring/README.md Table 1 must have one row per service in monitoring/docker-compose.yml; '
      f'missing {sorted(set(services.keys()) - set(components))}, unexpected {sorted(set(components) - set(services.keys()))}')

    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        prepare = function_body(cli, 'monitor_prepare')
        e('PROM_BIND' in prepare and 'LOKI_BIND' in prepare and 'not loopback 127.0.0.1' in prepare,
          f'{edition}/krate: monitor_prepare must warn when PROM_BIND or LOKI_BIND is not 127.0.0.1')


def check_airgap_rows(checks):
    """The air-gap rows AG1-AG5 (scripts/gate/phase4_airgap.py): the pure helpers behave, a probe that cannot run is FAIL on a bundle
    host and NOT_RUN on the Mac and on a checkout (never PASS), nothing is left running, and the runner calls the steps where
    sso/guides/identity-gate.md says."""
    e = lambda cond, msg: checks.expect(cond, 'air-gap rows: ' + msg)  # noqa: E731
    helper = ROOT / 'scripts/gate/phase4_airgap.py'
    spec = importlib.util.spec_from_file_location('phase4_airgap', helper)
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    keep = sys.dont_write_bytecode
    sys.dont_write_bytecode = True  # no bytecode next to the helper from a static check
    try:
        spec.loader.exec_module(m)
    finally:
        sys.dont_write_bytecode = keep
    e([m.classify_curl(rc)[0] for rc in (0, 7, 28, 56, 127)] == ['leak', 'blocked', 'blocked', 'cannot', 'cannot'],
      'curl rc 0 is a leak, 7 and 28 are blocked, anything else (a connection may exist, or curl did not run) is not proven')
    e([m.classify_getent(rc, '')[0] for rc in (0, 2, 1, 127)] == ['leak', 'blocked', 'cannot', 'cannot'], 'getent: 0 leak, 2 blocked, else not proven')
    e([m.classify_sentinel(rc, out)[0] for rc, out in ((3, 'AGPROBE blocked errno=111'), (0, 'AGPROBE reached'), (1, 'Traceback'), (0, ''))]
      == ['blocked', 'leak', 'cannot', 'cannot'], 'a container probe is conclusive only through its AGPROBE sentinel line')
    rules = m.parse_rules('-A OUTPUT -d 192.168.5.2/32 -p udp -m udp --dport 53 -j KRATE-AIRGAP-OUT\n-A OUTPUT -j KRATE-AIRGAP-OUT\n'
                          '-A KRATE-AIRGAP-OUT -j LOG --log-prefix "krate-airgap-out: "\n-A KRATE-AIRGAP-OUT -j REJECT --reject-with icmp-port-unreachable')
    e(m.has_catchall(rules, 'OUTPUT', 'KRATE-AIRGAP-OUT') and not m.has_catchall(m.parse_rules('-A OUTPUT -p tcp -j KRATE-AIRGAP-OUT'), 'OUTPUT', 'KRATE-AIRGAP-OUT'),
      'only a rule without a match is the catch-all jump')
    e(m.covers(rules, 'OUTPUT', 'KRATE-AIRGAP-OUT', '192.168.5.2', 'udp') and not m.covers(rules, 'OUTPUT', 'KRATE-AIRGAP-OUT', '192.168.5.2', 'tcp'),
      'a resolver is covered per protocol')
    e(m.last_target(rules, 'KRATE-AIRGAP-OUT') == 'REJECT', 'a reject chain ends in REJECT')
    e([m.forward_jump_state(m.parse_rules(text)) for text in ('-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD', '-A FORWARD -j DOCKER-FORWARD',
                                                              '-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j DOCKER-USER')] == ['ok', 'missing', 'late'],
      'FORWARD must jump to DOCKER-USER, and before DOCKER-FORWARD')
    lines = ['dockerd[1]: msg="[resolver] failed to query external DNS server" question=";config.liquibase.com.\\tIN\\t A"',
             'dockerd[1]: msg="[resolver] failed to query external DNS server" question=";loki.\\tIN\\t AAAA"',
             'dockerd[1]: msg="[resolver] failed to query external DNS server" question=";loki.lima.internal.\\tIN\\t A"']
    public, single = m.split_lookups(m.lookup_names(lines), ['lima.internal'])
    e(public == {'config.liquibase.com.': 1} and single == {'loki.': 1, 'loki.lima.internal.': 1},
      'dockerd lookups: a name of two labels is public-looking, a single label (alone or with a search domain) is a service name')
    e(m.parse_counters('Chain X (1 references)\n pkts bytes target\n  12 960 REJECT all -- * *\n') == {'REJECT': 12} and m.parse_counters('') is None,
      'unreadable counters are None, never zero')
    stream = ('{"Type":"volume","Action":"create","Actor":{"ID":"v","Attributes":{}},"timeNano":5}\n{"Type":"volume","Action":"create","Actor":{"ID":"v","Attributes":{}},"timeNano":5}\n'
              '{"Type":"airgap","Action":"attach","n":2,"ring":7}\n')
    events, markers, bad = m.parse_stream(stream)
    e(len(events) == 1 and len(markers) == 1 and bad == 0, 're-attached streams are de-duplicated and the supervisor markers are kept apart')
    e(m.GETENT_SECONDS <= 6 and m.CONTAINER_PROBE_SECONDS <= 15 and m.DNS_SECONDS <= 6 and m.RING_LIMIT == 256, 'probe bounds and the ring limit')
    fixture_root = ROOT / 'harness' / 'phase4' / 'path-contract'
    fixture_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=fixture_root) as tmp:
        base = Path(tmp)
        common = ['--state', str(base / 'state'), '--edition-dir', str(base), '--mon-dir', str(base), '--record', str(base / 'none.json'),
                  '--script', str(base / 'none'), '--boot-id-file', str(base / 'none'), '--resolv-conf', str(base / 'none')]
        for kind, want in (('bundle', 'FAIL'), ('darwin', 'NOT_RUN'), ('checkout', 'NOT_RUN')):
            for step, ids in (('before', ('AG1', 'AG4')), ('after', ('AG2', 'AG3', 'AG5'))):
                proc = subprocess.run([sys.executable, '-I', '-B', str(helper), step, '--host-kind', kind] + common, text=True, capture_output=True, env={'PATH': ''})
                got = {line.split('\t')[0]: line.split('\t')[1] for line in proc.stdout.splitlines() if line.count('\t') == 2}
                e(got == {i: want for i in ids}, f'{step} on a {kind} host with no tool must give {want} rows {ids}; got {got}')
        watcher = base / 'state' / 'watcher.json'
        if watcher.is_file():  # a step that could not attach must not leave its supervisor running
            try:
                os.kill(int(json.loads(watcher.read_text()).get('pid') or 0), 0)
                e(False, 'a helper step with no tool left its watcher supervisor running')
            except (OSError, ValueError):
                pass
    runner = (ROOT / 'scripts/gate-identity.sh').read_text().splitlines()

    def at(exact):
        found = [i for i, line in enumerate(runner) if line == exact]
        e(len(found) == 1, f'the runner must hold exactly one line {exact!r}; found {len(found)}')
        return found[0] if found else -1
    e(at('trap on_exit EXIT') < at('airgap_before_rows') < at('run_static'), 'airgap_before_rows runs after the traps and before the first row')
    esac = max(i for i, line in enumerate(runner) if line == 'esac')
    e(at('airgap_after_rows') == esac + 1 and runner[esac + 2] == 'FINISHED=true', 'airgap_after_rows runs right after the last slice row, before the teardown')
    finish = at('finish() {')
    e(finish >= 0 and runner[finish + 1].strip().startswith('airgap_after_rows exit-path'), 'finish() runs airgap_after_rows exit-path first (a run that ended early)')
    e(finish >= 0 and runner[finish + 2].strip().startswith('airgap_fill AG1 AG4 AG2 AG3 AG5'), 'finish() then fills the rows an interrupted after step left unrecorded')
    guide = (ROOT / 'sso/guides/identity-gate.md').read_text()
    for row in ('AG1', 'AG2', 'AG3', 'AG4', 'AG5'):
        e(f'| {row} |' in guide, f'sso/guides/identity-gate.md must list {row} in its air-gap table')
    e('AG1 AG2 AG3 AG4 AG5' in '\n'.join(runner), 'required_ids must hold AG1-AG5 for a bundle host')


def main():
    checks = Checks()
    for check in (check_templates, check_realm_contract, check_runtime_contract, check_names, check_compose, check_monitoring_binds,
                  check_prometheus_reload, check_loki_gateway, check_grafana_realm_compose, check_grafana_front,
                  check_grafana_realm_cli, check_monitor_idp_host_stable, check_grafana_collision_paging, check_grafana_realm_plan, check_perses_clients, check_perses_address, check_monitor_logins, check_build_certificate_hint,
                  check_render_writes, check_migrate_issuer, check_monitoring_tables,
                  check_grafana_admin_contract,
                  check_logrotate, check_cli_kafbat, check_exposure, check_gate_scripts, check_topofix2, check_k37_wiring, check_phase4_monitor_paths, check_airgap_rows,
                  check_parity, check_zk_frozen, check_writers, check_backup_seal,
                  check_plan_and_preflight, check_configure_dual, check_runtime_preflight,
                  check_bash_available, check_proxy_env, check_nginx_edge, check_nginx_render, check_identity_dirs, check_identity_users,
                  check_install_home_dir, check_deploy_release, check_rpm_install, check_gen_cert_ip, check_public_cert_permissions,
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
          'runtime.yml incl. refusals), configure-dual, stub_idp.sh down, proxy environment and edge rules, release permissions, RPM dependency '
          'resolution, IP certificates, renew-db-tls order, credential-free summaries, realm policy reconcile, health, install lock, '
          'PingFederate broker plan/apply/removal, truststore digest, Phase 3 docs, identity users logout/set-email and the realm-UI e-mail rule, '
          'Prometheus lifecycle off and the SIGHUP reload result, the read-only Loki gateway, '
          'the Grafana realm switch (compose, proxy front, CLI, realm.ini and clients).')
    if RENDER_IMAGE_NOTE:  # its own last line: the gate records the last line as the S4 evidence
        print('[' + '; '.join(RENDER_IMAGE_NOTE) + ']')
    return 0


if __name__ == '__main__':
    sys.exit(main())
