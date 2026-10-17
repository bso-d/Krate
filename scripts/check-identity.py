#!/usr/bin/env python3
"""Static checks for the Krate identity foundation (templates, realm plan, Compose, CLI parity)."""
import configparser
import contextlib
import hashlib
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


def bash_function_source(path, name):
    """The source of one top-level function of a Bash script whose opening line may carry a trailing comment (bash_functions needs a bare `name() {`)."""
    match = re.search(r'^' + re.escape(name) + r'\(\) \{[^\n]*\n.*?^\}\n', Path(path).read_text(), re.M | re.S)
    if match is None:
        raise ValueError(f'{path}: function {name} not found')
    return match.group(0)


def check_mac_launcher_round4(checks):
    """Run shipped admission and harvest boundaries with Git/Lima adapters only."""
    bash = shutil.which('bash')
    if bash is None:
        checks.expect(False, 'Bash is required for the Mac launcher regression checks')
        return
    text = (ROOT / 'scripts/gate/mac/run-vm-gate.sh').read_text()
    fixture_base = ROOT / 'harness/check-identity'
    fixture_base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mac-launcher-', dir=fixture_base) as fixture_dir:
        fixture = Path(fixture_dir)
        candidate = '0123456789abcdef0123456789abcdef01234567'
        wt = fixture / 'harness/worktrees' / ('gate-' + candidate[:7])
        for rel in ('scripts/gate/mac/agent.mjs', 'scripts/gate/browser-launch.mjs', 'scripts/gate/browser_remote.py'):
            path = wt / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('// inert fixture\n')
        binding = text[text.index('if [[ -e "$REPO/harness/worktrees/gate-'):text.index('caffeinate -dims &')]
        # Any helper the live binding calls must come from its actual shipped function body.
        if 'candidate_worktree_ok() {' in text:
            start = text.index('candidate_worktree_ok() {')
            end = text.index('\n}\n', start) + 3
            binding = text[start:end] + '\n' + binding
        head_stub = r"""
        git() {
          printf '%s\n' "$*" >> "$FIXTURE/git-calls"
          case "$*" in
            *rev-parse*) [[ "$CASE" != unreadable-head ]] || return 9
              if [[ "$CASE" == wrong-head ]]; then printf '%040d\n' 1; else printf '%s\n' "$CANDIDATE"; fi ;;
            *status*) [[ "$CASE" != unreadable-status ]] || return 8
              case "$CASE" in dirty-tracked) echo ' M scripts/gate/mac/probe.mjs';; dirty-untracked) echo '?? scripts/gate/mac/injected.mjs';; esac ;;
            *) return 97 ;;
          esac
        }
        """
        for case in ('clean', 'wrong-head', 'dirty-tracked', 'dirty-untracked', 'unreadable-head', 'unreadable-status'):
            script = 'set -euo pipefail\n' + head_stub + '\n' + binding + '\necho ADMITTED\n'
            env = dict(os.environ, REPO=str(fixture), CANDIDATE=candidate, PREFLIGHT_FAIL='0', CASE=case, FIXTURE=str(fixture))
            result = subprocess.run([bash, '-c', script], env=env, text=True, capture_output=True, timeout=5)
            expected = case == 'clean'
            ok = (result.returncode == 0 and 'ADMITTED' in result.stdout) == expected
            checks.expect(ok, f'launcher candidate binding {case}: expected admitted={expected}; rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}')
        # Run the complete shipped post-agent harvest/outcome/manifest tail, stubbing only limactl.
        functions = text[text.index('receipt_verdict() {'):text.index('# Review T13:')]
        harvest_at = text.index('limactl copy --backend=scp -r "$VM:$GUEST_ROOT/agent-out"')
        harvest = text[text.rfind('\n', 0, harvest_at) + 1:]
        harvest_stub = r"""
        limactl() {
          case "$1" in
            copy)
              case "$4" in
                *:*/agent-out)
                  if [[ "$CASE" == copy-fails || "$CASE" == copy-fails-partial ]]; then
                    if [[ "$CASE" == copy-fails-partial ]]; then mkdir -p "$5"; printf proof > "$5/proof.json"; fi
                    return 7
                  fi
                  mkdir -p "$5"; printf 'proof' > "$5/proof.json" ;;
                *) mkdir -p "$5"
                  printf '| verdict | **PASS** |\n| candidate commit | %s |\n' "$CANDIDATE" > "$5/receipt.md"
                  printf 'receipt-copy\n' >> "$OUT/calls" ;;
              esac ;;
            shell)
              case "$*" in
                *runner.rc*) echo 0 ;;
                *) echo "$GUEST_RECEIPT" ;;
              esac ;;
            *) return 98 ;;
          esac
        }
        """
        digest = hashlib.sha256(b'proof').hexdigest()[:12]
        for phase, case in [('4c', 'valid'), ('4c', 'copy-fails'), ('4c', 'copy-fails-partial'),
                            ('4c', 'missing-manifest'), ('4c', 'empty-manifest'), ('4c', 'manifest-directory'), ('4c', 'missing-tree'), ('4a', 'optional-evidence'),
                            ('4b', 'copy-fails')]:
            destination = fixture / (phase + '-' + case)
            destination.mkdir(exist_ok=True)
            manifest = destination / 'agent-manifest.tsv'
            if case not in ('missing-manifest', 'manifest-directory', 'optional-evidence'):
                manifest.write_text('request_id\trow\trequest_sha\tfiles\tchrome\n1\tW5\trequest\t' + digest + '\t155\n')
            if case == 'manifest-directory':
                manifest.mkdir()
            if case == 'empty-manifest':
                manifest.write_text('')
            # Missing tree is a successful-copy/no-output boundary, not an actual SCP claim.
            stub = harvest_stub
            if case in ('missing-tree', 'optional-evidence'):
                stub = stub.replace('mkdir -p "$5"; printf \'proof\' > "$5/proof.json"', ':')
            env = dict(os.environ, VM='fake', GUEST_ROOT='/fixture', GUEST_RECEIPT='/fixture/receipt',
                       OUT=str(destination), RDV='/fixture/rdv', CANDIDATE=candidate, PHASE=phase,
                       CASE=case, RC='0')
            result = subprocess.run([bash, '-c', 'set -euo pipefail\n' + functions + stub + harvest],
                                    env=env, text=True, capture_output=True, timeout=5)
            expected = case in ('valid', 'optional-evidence')
            receipt = (destination / 'receipt/receipt.md').is_file()
            ok = (result.returncode == 0) == expected and receipt
            checks.expect(ok and result.returncode == (0 if expected else 4), f'launcher harvest {phase}/{case}: expected success={expected}, receipt required; rc={result.returncode}, receipt={receipt}, stdout={result.stdout!r}, stderr={result.stderr!r}')


def check_mac_ipv6_ports(checks):
    """Execute the entire shipped sweep with deterministic filesystem/socket adapters."""
    node = shutil.which('node')
    if node is None:
        print('Identity check NOT RUN: Mac IPv6 sweep regressions (Node unavailable on this host)', file=sys.stderr)
        return
    source = r'''import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import vm from 'node:vm';

// Execute the complete shipped entrypoint, replacing only boundary dependencies.
// No copied port-selection expression, source rewriting, real sockets or product stack.
const sourcePath = resolve(process.argv[2] || 'scripts/gate/mac/probe.mjs');
const source = readFileSync(sourcePath, 'utf8');
const cases = [
  { name: 'runtime ports with default options', ports: [22, 13443, 32000], v6: true },
  { name: 'explicit ports add, deduplicate and validate', ports: [22, 13443, 32000], v6: true,
    extra: ['--v6-ports', '4444,13443,4444,0,65536,nope'] },
  { name: 'explicit ports without IPv4 opens preserve controls', ports: [], v6: true,
    extra: ['--v6-ports', '4444'] },
  { name: 'no IPv6 address preserves IPv4-only behavior', ports: [22, 13443], v6: false },
];
let failures = 0;
for (const test of cases) {
  const files = new Map();
  const connections = [];
  const argv = ['node', sourcePath, 'sweep', '--ip', '127.0.0.1', '--host', 'fixture.test', '--out', '/owned-output'];
  if (test.v6) argv.push('--v6', '::1');
  argv.push(...(test.extra || []));
  const context = vm.createContext({
    process: { argv, stdout: { write() {} }, exit(rc) { throw new Error('unexpected exit ' + rc); } },
    console: { log() {}, error() {} },
  });
  const module = new vm.SourceTextModule(source, {
    context, identifier: pathToFileURL(sourcePath).href,
    initializeImportMeta(meta) { meta.url = pathToFileURL(sourcePath).href; },
  });
  const imported = new Map();
  await module.link(async (specifier) => {
    if (imported.has(specifier)) return imported.get(specifier);
    const namespace = { ...await import(specifier) };
    if (specifier === 'node:fs') {
      namespace.mkdirSync = () => {};
      namespace.writeFileSync = (path, data) => files.set(path, String(data));
    }
    if (specifier === 'node:net') {
      namespace.default = { ...namespace.default, connect(options) {
        const socket = new EventEmitter();
        socket.setTimeout = () => socket;
        socket.destroy = () => socket;
        if (options.family === 6) connections.push(options.port);
        queueMicrotask(() => {
          if (test.ports.includes(options.port)) socket.emit('connect');
          else socket.emit('error', Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }));
        });
        return socket;
      } };
    }
    const keys = Object.keys(namespace);
    const linked = new vm.SyntheticModule(keys, function () {
      for (const key of keys) this.setExport(key, namespace[key]);
    }, { context });
    imported.set(specifier, linked);
    return linked;
  });
  await module.evaluate({ timeout: 10000 });
  const report = JSON.parse(files.get('/owned-output/w5-result.json'));
  const problems = [];
  const check = (condition, message) => { if (!condition) problems.push(message); };
  assert.deepEqual(report.open, test.ports);
  assert.equal(Object.values(report.counts).reduce((a, b) => a + b), 65535);
  if (test.v6) {
    const ports = report.v6.ports.map(p => p.port);
    check(test.ports.every(p => ports.includes(p)), 'missing IPv4-open ports: ' + test.ports.filter(p => !ports.includes(p)));
    check(ports.includes(111), 'default firewall control 111 missing');
    check(!test.extra || ports.includes(4444), 'explicit additional port 4444 missing');
    check(ports.length === new Set(ports).size, 'duplicate IPv6 probes');
    check(ports.every(p => Number.isInteger(p) && p >= 1 && p <= 65535), 'out-of-range IPv6 probes');
    check(ports.every((p, i) => !i || ports[i - 1] < p), 'IPv6 probes not sorted');
    assert.deepEqual(connections, ports);
  } else {
    assert.equal(report.v6, undefined);
    assert.deepEqual(connections, []);
  }
  console.log(JSON.stringify({ case: test.name, verdict: problems.length ? 'FAIL' : 'PASS',
    ipv4Open: report.open, ipv6Ports: report.v6?.ports.map(p => p.port) || [], problems }));
  failures += problems.length;
}
console.log(JSON.stringify({ cases: cases.length, failedAssertions: failures }));
process.exitCode = failures ? 1 : 0;
'''
    run = subprocess.run([node, '--experimental-vm-modules', '--input-type=module', '-',
                          str(ROOT / 'scripts/gate/mac/probe.mjs')], input=source,
                         text=True, capture_output=True, timeout=30)
    checks.expect(run.returncode == 0, f'Mac sweep IPv6 runtime-port/default/additional/IPv4-only regressions: rc={run.returncode}, stdout={run.stdout!r}, stderr={run.stderr!r}')


def check_firewall_round4(checks):
    """Run full shipped W5/W7 rows against deterministic listener/firewall producers."""
    bash = shutil.which('bash')
    if bash is None:
        checks.expect(False, 'Bash is required for W5/W7 firewall regression checks')
        return
    text = (ROOT / 'scripts/gate-identity.sh').read_text()
    fixture_base = ROOT / 'harness/check-identity'
    fixture_base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='firewall-', dir=fixture_base) as fixture_dir:
        folder = Path(fixture_dir)
        def function(name):
            start = text.index(name + '() {')
            return text[start:text.index('\n}\n', start) + 3] + '\n'

        common = r'''
        set -uo pipefail
        section() { :; }
        record() { printf 'RECORD %s|%s\n' "$4" "$5"; }
        sudo() { [[ "$1" == -n ]] && shift; "$@"; }
        env() { [[ "$1" == LC_ALL=C ]] && shift; "$@"; }
        systemctl() { echo active; }
        RAW=/dev/stderr; KRATE=/usr/bin/true
        '''

        def run(condition, case, script, env, expected):
            result = subprocess.run([bash, '-c', script], env=dict(os.environ, **env),
                                    text=True, capture_output=True, timeout=5)
            verdict = next((line.split('|')[0].split()[-1] for line in result.stdout.splitlines()
                            if line.startswith('RECORD ')), 'MISSING')
            checks.expect(verdict == expected, f'{condition}/{case}: expected {expected}, got {verdict}; rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}')
            if condition == 'W5 listener precondition' and expected == 'FAIL':
                checks.expect('AGENT_CALLED' not in result.stdout, f'W5/{case}: failed control precondition must stop before requesting the Mac sweep')

        w5_stub = r'''
        firewall-cmd() { echo "$FW_STATE"; }
        w5_published_any_ports() { echo proxy=443; [[ "$PUBLISHED_CONTROL" != yes ]] || echo control=111; }
        ip() { [[ "$IP_RC" == 0 ]] || return "$IP_RC"; printf '%s\n' "$NIC_INFO"; }
        ss() {
          if [[ "$*" == *'sport = :111'* ]]; then
            [[ "$SS_RC" == 0 ]] || return "$SS_RC"; printf '%s\n' "$LISTENERS"
          fi
        }
        agent_request() { CAP="$ENVELOPE"; printf 'AGENT_CALLED\n'; }
        agent_delivered_dir() { echo "$CASE_DIR"; }
        '''
        w5_script = common + w5_stub
        if 'w5_control_listener() {' in text:
            w5_script += function('w5_control_listener')
        w5_script += function('phase4_row_w5') + 'phase4_row_w5 4c\n'
        nic = '3: lima0 inet 192.168.64.3/24 scope global lima0'
        for case, listener, ip_rc, ss_rc, fw, published, expected in (
            ('wildcard', 'LISTEN 0 4096 0.0.0.0:111 0.0.0.0:*', 0, 0, 'running', 'no', 'PASS'),
            ('nic', 'LISTEN 0 4096 192.168.64.3:111 0.0.0.0:*', 0, 0, 'running', 'no', 'PASS'),
            ('asterisk', 'LISTEN 0 4096 *:111 *:*', 0, 0, 'running', 'no', 'PASS'),
            ('absent', '', 0, 0, 'running', 'no', 'FAIL'),
            ('loopback', 'LISTEN 0 4096 127.0.0.1:111 0.0.0.0:*', 0, 0, 'running', 'no', 'FAIL'),
            ('other-nic', 'LISTEN 0 4096 192.168.5.15:111 0.0.0.0:*', 0, 0, 'running', 'no', 'FAIL'),
            ('ipv6-only', 'LISTEN 0 4096 [::]:111 [::]:*', 0, 0, 'running', 'no', 'FAIL'),
            ('ip-read-fails', '', 19, 0, 'running', 'no', 'FAIL'),
            ('ss-read-fails', '', 0, 20, 'running', 'no', 'FAIL'),
            ('no-firewall', '', 0, 0, 'not running', 'no', 'PASS'),
            ('published-control', '', 0, 0, 'running', 'yes', 'PASS'),
        ):
            directory = folder / case
            directory.mkdir(exist_ok=True)
            ports = [22, 443] if published == 'no' else [22, 111, 443]
            report = dict(open=ports, swept={'tcpOnly': True}, counts={},
                          spot=[{'port': 111, 'outcome': 'refused'}], cert={'authorized': True},
                          v6={'address': '2001:db8::1', 'addressClass': 'global',
                              'ports': [{'port': 22, 'outcome': 'open'}, {'port': 443, 'outcome': 'refused'}]})
            data = json.dumps(report).encode()
            (directory / 'w5-result.json').write_bytes(data)
            envelope = dict(files=[{'name': 'w5-result.json', 'sha256': hashlib.sha256(data).hexdigest()}],
                            exit=0, mac_leak_scan={'values': 1, 'hits': 0, 'stores': ['agent.log']})
            run('W5 listener precondition', case, w5_script,
                dict(STATE=str(directory), CASE_DIR=str(directory), ENVELOPE=json.dumps(envelope),
                     FW_STATE=fw, PUBLISHED_CONTROL=published, IP_RC=str(ip_rc), SS_RC=str(ss_rc),
                     NIC_INFO=nic, LISTENERS=listener, VM_G6='2001:db8::1'), expected)

        w7_stub = r'''
        firewall-cmd() {
          local result='' key="$*"
          case "$*" in
            *--get-default-zone*|*--get-zone-of-interface=lima0*) result=public ;;
            *--get-zone-of-interface=*) result=docker ;;
            *--info-zone=docker*) result=$'docker (active)\n target: ACCEPT' ;;
            *--list-services*) result=ssh ;;
            *--get-policies*) result=docker-forwarding ;;
          esac
          printf '%s\n' "$result"
          if [[ "$key" == "$FAIL_QUERY" || ( "$FAIL_QUERY" == bridge-zone && "$key" == --get-zone-of-interface=* && "$key" != --get-zone-of-interface=lima0 ) ]]; then echo 'manual producer refusal rc23' >&2; return 23; fi
          return 0
        }
        '''
        w7_script = common + w7_stub + function('w7_os_family') + function('phase4_row_w7')
        w7_script += "phase4_row_w7 4c <(printf 'ID=rocky\\n')\n"
        queries = ['--get-default-zone', '--get-zone-of-interface=lima0', 'bridge-zone',
                   '--info-zone=docker', '--get-policies']
        for query in ('--list-services', '--list-ports', '--list-protocols', '--list-icmp-blocks'):
            queries += ['--zone=public ' + query, '--permanent --zone=public ' + query]
        queries += ['--zone=public --list-rich-rules', '--zone=public --list-forward-ports']
        run('W7 query status', 'clean', w7_script, {'FAIL_QUERY': ''}, 'PASS')
        for query in queries:
            run('W7 query status', query + ' returns23 with valid-looking stdout', w7_script,
                {'FAIL_QUERY': query}, 'FAIL')



def check_browser_certificate_proceed(checks):
    """Exercise Proceed's shipped future-document and error-propagation contract."""
    node = shutil.which('node')
    if node is None:
        print('Identity check NOT RUN: browser certificate Proceed regressions (Node unavailable on this host)', file=sys.stderr)
        return
    source = r'''import process from 'node:process';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Controlled shipped-export contract probe: no browser, socket, timer or fixtures.
// Default click below retains Playwright's main-frame navigation signal barrier.
const modulePath = resolve(process.argv[2] || 'scripts/gate/browser-launch.mjs');
const { acceptGateCertificate } = await import(pathToFileURL(modulePath).href);
const sha256 = createHash('sha256').update(readFileSync(modulePath)).digest('hex');
const HOST = 'gate.test';
const URL_START = 'https://gate.test:3443/start';
const deferred = () => {
  let release; let fail;
  const promise = new Promise((yes, no) => { release = yes; fail = no; });
  // A signal barrier consumes navigation failure even without an explicit client wait.
  promise.catch(() => {});
  return { promise, release, fail };
};
const configs = [
  { name: 'positive-click-signal-barrier', deferred: true, control: true },
  { name: 'failed-Proceed-click', clickError: true, reject: true },
  { name: 'failed-navigation', navigationError: 'Navigation failed', reject: true },
  { name: 'navigation-timeout', navigationError: 'Timeout 20000ms exceeded', reject: true },
  { name: 'null-same-document', nullResponse: true, reject: true },
  { name: 'wrong-host-response', responseURL: 'https://outside.test/landing', reject: true },
  { name: 'non-HTTPS-response', responseURL: 'http://gate.test/landing', reject: true },
  { name: 'not-navigation-request', notNavigation: true, reject: true },
  { name: 'wrong-frame-response', wrongFrame: true, reject: true },
  { name: 'same-host-port-redirect', responseURL: 'https://gate.test:443/identity/login' },
  { name: 'no-interstitial', noInterstitial: true },
  { name: 'hooks-before-expected-code-refusal', code: 'net::ERR_CERT_DATE_INVALID', reject: true },
  { name: 'hooks-before-Proceed' },
  { name: 'prearmed-bounded-main-navigation', requirePrearmed: true },
  { name: 'failed-Advanced-click', advancedError: true, reject: true },
  { name: 'hook-refusal-propagates', hookError: true, reject: true },
];
const rows = [];
for (const config of configs) {
  const failures = [];
  const events = [];
  const navigation = deferred();
  const frame = {};
  let settled = false; let decision; let error;
  let proceedClicked = false; let waiterArmed = false; let armedAtClick = false; let waitOptions;
  const response = config.nullResponse ? null : {
    url: () => config.responseURL || URL_START,
    request: () => ({ isNavigationRequest: () => !config.notNavigation, frame: () => config.wrongFrame ? {} : frame }),
  };
  const check = (yes, assertion) => { if (!yes) failures.push(assertion); };
  const page = {
    mainFrame: () => frame,
    goto: async () => { events.push('initial-goto'); if (!config.noInterstitial) throw new Error('net::ERR_CERT_AUTHORITY_INVALID'); return response; },
    waitForSelector: async () => { events.push('warning-selector'); if (config.noInterstitial) throw new Error('warning missing'); },
    locator: selector => ({
      count: async () => selector === '#details-button' && !config.noInterstitial ? 1 : 0,
      textContent: async () => config.code || 'net::ERR_CERT_AUTHORITY_INVALID',
    }),
    // The interstitial already loaded. This must not be treated as a future-document wait.
    waitForLoadState: async () => { events.push('warning-already-load'); },
    waitForNavigation: options => { events.push('wait-navigation'); waiterArmed = true; waitOptions = options; return navigation.promise; },
    click: async selector => {
      events.push(selector === '#details-button' ? 'Advanced' : 'Proceed');
      if (selector === '#details-button') { if (config.advancedError) throw new Error('Advanced click failed'); return; }
      proceedClicked = true;
      armedAtClick = waiterArmed;
      if (config.clickError) throw new Error('Proceed click failed');
      if (!config.deferred) {
        if (config.navigationError) navigation.fail(new Error(config.navigationError));
        else navigation.release(response);
      }
      // PW v1.60 SignalBarrier waits main-frame navigation announced by the click,
      // and consumes navigation failures. It does not prove the caller's response contract.
      await navigation.promise.catch(() => {});
    },
  };
  const pending = acceptGateCertificate(page, URL_START, {
    onAssert: async d => { events.push('onAssert'); check(d.seen && d.decision === 'none', 'assert hook sees warning before decision'); if (config.hookError) throw new Error('hook refused'); },
    onShot: async d => { events.push('onShot'); check(d.seen && d.decision === 'none', 'shot hook sees warning before decision'); },
  }).then(value => { decision = value; settled = true; }, reason => { error = reason; settled = true; });
  // Only microtask observation: no clock delay, browser scheduling or early-return claim.
  if (config.deferred) {
    for (let i = 0; i < 64 && !proceedClicked && !settled; i++) await Promise.resolve();
    check(proceedClicked, 'positive control reached Proceed');
    check(!settled, 'source-faithful click barrier keeps helper pending');
    navigation.release(response);
  }
  await pending;
  // Release any unused adapter-only waiter after a failed click or earlier refusal.
  navigation.release(response);
  if (config.reject) check(Boolean(error) && !decision, 'failed contract must reject, never report proceeded');
  else if (config.noInterstitial) check(!error && decision?.decision === 'no-interstitial' && !proceedClicked, 'no-interstitial behavior retained');
  else check(!error && decision?.decision === 'proceed', 'valid Proceed accepted');
  if (!config.noInterstitial) {
    check(events.indexOf('onAssert') >= 0, 'assert hook ran');
    if (!config.hookError) check(events.indexOf('onShot') > events.indexOf('onAssert'), 'shot follows assertion');
    if (proceedClicked) check(events.indexOf('onShot') < events.indexOf('Advanced') && events.indexOf('Advanced') < events.indexOf('Proceed'), 'hooks precede Advanced and Proceed');
  }
  if (config.code || config.hookError || config.advancedError) check(!proceedClicked, 'earlier refusal never reaches Proceed');
  if (config.requirePrearmed) {
    check(armedAtClick, 'future navigation waiter armed before Proceed click');
    check(waitOptions?.waitUntil === 'load' && waitOptions?.timeout === 20000, 'wait is load-bound and finite');
  }
  rows.push({ name: config.name, passed: failures.length === 0, failures, events, result: decision?.decision || null, rejected: Boolean(error), error: error?.message || null });
}
const failedAssertions = rows.reduce((sum, row) => sum + row.failures.length, 0);
console.log(JSON.stringify({ kind: 'controlled shipped-helper contract; no native scheduling claim', modulePath, sha256, gateHostname: HOST, cases: rows.length, failedAssertions, rows }, null, 2));
if (failedAssertions) process.exitCode = 1;
'''
    result = subprocess.run([node, '--input-type=module', '-', str(ROOT / 'scripts/gate/browser-launch.mjs')],
                            input=source, text=True, capture_output=True, timeout=30)
    try:
        summary = json.loads(result.stdout)
    except ValueError:
        summary = {}
    checks.expect(result.returncode == 0 and summary.get('cases') == 16 and summary.get('failedAssertions') == 0,
                  'Browser certificate Proceed contract failed: ' + result.stdout[-2400:] + result.stderr[-600:])


def check_browser_certificate_binding(checks):
    """Run current-main-browser leaf/cleanup/tracker regressions on the shipped exports."""
    node = shutil.which('node')
    if node is None:
        print('Identity check NOT RUN: browser certificate binding regressions (Node unavailable on this host)', file=sys.stderr)
        return
    source = r'''import { EventEmitter } from 'node:events';
import process from 'node:process';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

// Actual shipped exported assertion; only Playwright/CDP boundary state is adapted.
const source = resolve(process.argv[2] || 'scripts/gate/browser-launch.mjs');
const lib = await import(pathToFileURL(source).href);
// Throwaway same-DN leaves are created under harness and removed after this check.
const a = new X509Certificate(readFileSync(process.argv[3]));
// A and B have independent keys; no fixture certificate/key is committed.
const b = new X509Certificate(readFileSync(process.argv[4]));
const pin = lib.certDigests(a.raw);
const details = { subjectName: 'gate.test', issuer: 'gate.test', protocol: 'TLS 1.3', validFrom: 1, validTo: 2 };
const cases = [
  ['same leaf', {}, true],
  ['same DN different leaf', { leaf: b.raw }, false],
  ['empty certificate chain', { chain: [] }, false],
  ['invalid DER', { chain: [Buffer.from('not a certificate').toString('base64')] }, false],
  ['neutral security state', { securityState: 'neutral' }, false],
  ['missing security state', { noState: true }, false],
  ['enable fails', { fail: 'Security.enable' }, false],
  ['CDP attach fails', { attachFails: true }, false],
  ['CDP frame snapshot fails', { fail: 'Page.getFrameTree' }, false],
  ['frame loader changes', { loaderChanges: true }, false],
  ['main navigation during sampling', { navigating: true }, false],
  ['main frame navigation during sampling', { frameNavigating: true }, false],
  ['main navigation during detach', { navigationOnDetach: true }, false],
  ['session detach fails', { detachFails: true }, false],
  ['interstitial main frame', { interstitial: true }, false],
  ['missing pinned digest', { missingPin: true }, false],
  ['different current origin', { pageUrl: 'https://other.test/' }, false],
  ['subframe response', { subframe: true }, false],
  ['not a navigation response', { notNavigation: true }, false],
  ['closed page', { closed: true }, false],
  ['same-origin SPA path', { pageUrl: 'https://gate.test/route#shot' }, true],
  ['different response subject', { wrongSubject: true }, false],
];
const results = [];
for (const [name, options, expected] of cases) {
  const calls = [];
  const page = new EventEmitter();
  const session = new EventEmitter();
  let snapshots = 0;
  let detaches = 0;
  const frame = { page: () => page, isDetached: () => false };
  const request = { frame: () => frame, isNavigationRequest: () => !options.notNavigation,
    redirectedTo: () => null };
  const url = options.pageUrl || 'https://gate.test/certificate';
  Object.assign(page, { url: () => url, isClosed: () => !!options.closed,
    mainFrame: () => options.subframe ? {} : frame,
    context: () => ({ newCDPSession: async (target) => {
      if (target !== page) throw new Error('session is not bound to response page');
      calls.push('attach');
      if (options.attachFails) throw new Error('attach refused');
      return session;
    } }) });
  session.send = async (method) => {
    calls.push(method);
    if (options.fail === method) throw new Error(method + ' refused');
    if (method === 'Page.getFrameTree') {
      snapshots++;
      return { frameTree: { frame: { id: 'main', loaderId: options.loaderChanges && snapshots > 1 ? 'later' : 'current',
        url: url.split('#')[0], securityOrigin: new URL(url).origin, unreachableUrl: options.interstitial ? url : undefined } } };
    }
    if (method === 'Security.enable') {
      if (!session.listenerCount('Security.visibleSecurityStateChanged')) throw new Error('Security listener installed too late');
      if (options.navigating) page.emit('request', request);
      if (options.frameNavigating) page.emit('framenavigated', frame);
      if (!options.noState) session.emit('Security.visibleSecurityStateChanged', { visibleSecurityState: {
        securityState: options.securityState || 'insecure-broken',
        certificateSecurityState: { certificate: options.chain || [(options.leaf || a.raw).toString('base64')] },
      } });
      return {};
    }
    throw new Error('unexpected protocol method ' + method);
  };
  session.detach = async () => {
    calls.push('detach'); detaches++;
    if (options.navigationOnDetach) page.emit('request', request);
    if (options.detachFails) throw new Error('detach refused');
  };
  const response = { securityDetails: async () => ({ ...details, subjectName: options.wrongSubject ? 'other.test' : details.subjectName }),
    request: () => request, url: () => 'https://gate.test/certificate', finished: async () => null };
  let result = null;
  let error = null;
  try { result = await lib.assertServedCertificate(response, options.missingPin ? { ...pin, sha256: '' } : pin, name); }
  catch (e) { error = String(e.message || e); }
  const accepted = error === null;
  const problems = [];
  if (accepted !== expected) problems.push('expected accepted=' + expected + ', got ' + accepted);
  if (calls.includes('attach') && !options.attachFails && detaches !== 1) problems.push('owned CDP session not detached exactly once');
  if (page.eventNames().some(event => page.listenerCount(event))) problems.push('page listeners left behind');
  if (session.eventNames().some(event => session.listenerCount(event))) problems.push('CDP listeners left behind');
  results.push({ name, expected, accepted, passed: problems.length === 0, problems, result, error, calls });
}
// Actual exported tracker: proof strings must be appended atomically only for a
// response/count that remained current across asynchronous address/certificate checks.
for (const mode of ['stable', 'different response', 'same response counted again']) {
  const page = new EventEmitter();
  const frame = {};
  page.mainFrame = () => frame;
  const request = { isNavigationRequest: () => true, frame: () => frame };
  const later = { request: () => request };
  const response = { request: () => request, serverAddr: async () => {
    if (mode !== 'stable') page.emit('response', mode === 'different response' ? later : response);
    return { ipAddress: '192.168.64.3', port: 443 };
  } };
  const tracker = lib.attachServeTracker(page);
  page.emit('response', response);
  const asserted = [];
  let error = null;
  try { await tracker.record('192.168.64.3', null, mode, asserted); }
  catch (e) { error = String(e.message || e); }
  const expected = mode === 'stable';
  const accepted = error === null;
  const problems = [];
  if (accepted !== expected) problems.push('unexpected tracker verdict');
  if (asserted.length !== (expected ? 1 : 0)) problems.push('tracker published partial/stale proof');
  results.push({ name: 'tracker ' + mode, expected, accepted, asserted, error, problems, passed: !problems.length });
}
const report = { source, sourceSha256: createHash('sha256').update(readFileSync(source)).digest('hex'),
  aLeaf: createHash('sha256').update(a.raw).digest('hex'), bLeaf: createHash('sha256').update(b.raw).digest('hex'),
  results, failures: results.filter(row => !row.passed).length };
console.log(JSON.stringify(report, null, 2));
process.exitCode = report.failures ? 1 : 0;
'''
    openssl_binary = shutil.which('openssl')
    if openssl_binary is None:
        checks.expect(False, 'OpenSSL is required to generate throwaway browser certificate fixtures')
        return
    fixture_base = ROOT / 'harness/check-identity'
    fixture_base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='browser-cert-', dir=fixture_base) as fixture_dir:
        fixture = Path(fixture_dir)
        for name in ('a', 'b'):
            made = subprocess.run([openssl_binary, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                   '-sha256', '-days', '1', '-subj', '/CN=gate.test',
                                   '-keyout', str(fixture / (name + '.key')), '-out', str(fixture / (name + '.crt'))],
                                  capture_output=True, text=True, timeout=15)
            if not checks.expect(made.returncode == 0, f'cannot generate browser leaf {name}: {made.stderr[:200]}'):
                return
        run = subprocess.run([node, '--input-type=module', '-', str(ROOT / 'scripts/gate/browser-launch.mjs'),
                              str(fixture / 'a.crt'), str(fixture / 'b.crt')],
                             input=source, text=True, capture_output=True, timeout=30)
        checks.expect(run.returncode == 0, f'Browser certificate/current-main-frame/cleanup/tracker regressions: rc={run.returncode}, stdout={run.stdout!r}, stderr={run.stderr!r}')


def check_browser_http_guard(checks):
    """HTTP redirect decisions use the shipped browser-root guard; this does not prove worker WebSockets."""
    node = shutil.which('node')
    if not node:
        print('check_browser_http_guard: NOT RUN (optional host Node is absent)', file=sys.stderr)
        return
    program = r"""import { EventEmitter } from 'node:events';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
const file = resolve(process.argv[2] || 'scripts/gate/browser-launch.mjs');
const { externalAttemptsTracker } = await import(pathToFileURL(file).href);
const pause = () => new Promise(resolve => setImmediate(resolve));
const cases = ['allowed', 'redirect', 'malformed', 'missing-owner', 'enable-failure', 'decision-failure', 'session-loss', 'late-attempt', 'close-failure', 'missing-api', 'attach-failure', 'websocket-setup-failure', 'continue-failure', 'response-pause', 'still-connected', 'close-during-enable', 'delayed-decision', 'duplicate-close', 'session-loss-during-close', 'allowed-page-websocket', 'external-page-websocket'];
let failures = 0;
for (const condition of cases) {
  const events = []; const sent = []; const errors = [];
  let connected = true; let enabled = false; let closeCalls = 0;
  let websocketPredicate; let websocketHandler; const websocketCloses = [];
  const session = new EventEmitter();
  session.send = async (method, params) => {
    sent.push({method,params}); events.push(method);
    if (method === 'Fetch.enable') { if (session.listenerCount('Fetch.requestPaused') !== 1) errors.push('enable preceded pause listener'); if (condition === 'enable-failure') throw new Error('synthetic enable failure'); if (condition === 'close-during-enable') session.emit('close'); enabled = true; }
    if (method === 'Fetch.failRequest' && condition === 'decision-failure') throw new Error('synthetic fail rejection');
    if (method === 'Fetch.continueRequest' && condition === 'continue-failure') throw new Error('synthetic continue rejection');
    if (method === 'Fetch.failRequest' && condition === 'delayed-decision') { await pause(); await pause(); events.push('decision-ack'); }
    return {};
  };
  session.detach = async () => { events.push('detach'); };
  const owner = { newBrowserCDPSession: condition === 'missing-api' ? undefined : async () => { if (condition === 'attach-failure') throw new Error('synthetic attach rejection'); return session; }, isConnected: () => connected };
  const context = new EventEmitter();
  context.browser = () => condition === 'missing-owner' ? null : owner;
  context.route = async () => {}; context.routeWebSocket = async (predicate, handler) => { websocketPredicate = predicate; websocketHandler = handler; if (condition === 'websocket-setup-failure') throw new Error('synthetic websocket setup rejection'); };
  context.close = async () => {
    closeCalls++; events.push('browser-close');
    if (condition === 'late-attempt') session.emit('Fetch.requestPaused', {requestId:'late',request:{url:'http://127.0.0.1:9/path?secret=value'}});
    if (condition === 'session-loss-during-close') { session.emit('close'); await pause(); await pause(); }
    if (condition === 'close-failure') throw new Error('synthetic close rejection');
    connected = condition === 'still-connected'; session.emit('close'); context.emit('close');
  };
  const tracker = externalAttemptsTracker('gate.test');
  let setupFailed = false;
  try { await tracker.guard(context); } catch { setupFailed = true; }
  const expectedSetupFailure = ['missing-owner','enable-failure','missing-api','attach-failure','websocket-setup-failure','close-during-enable'].includes(condition);
  const check = (yes, message) => { if (!yes) errors.push(message); };
  check(setupFailed === expectedSetupFailure, 'setup verdict');
  if (!expectedSetupFailure) {
    check(enabled && session.listenerCount('Fetch.requestPaused') === 1, 'root Fetch armed with listener');
    check(sent.some(x=>x.method==='Fetch.enable'&&JSON.stringify(x.params)===JSON.stringify({patterns:[{urlPattern:'*',requestStage:'Request'}]})), 'all requests intercepted at Request stage');
    if (['allowed','continue-failure','duplicate-close'].includes(condition)) session.emit('Fetch.requestPaused',{requestId:'a',request:{url:'https://gate.test:3443/api'}});
    if (['redirect','decision-failure','delayed-decision'].includes(condition)) {
      session.emit('Fetch.requestPaused',{requestId:'a',request:{url:'https://gate.test/start'}});
      session.emit('Fetch.requestPaused',{requestId:'b',redirectedRequestId:'a',request:{url:'http://127.0.0.1:9/outside?secret=value'}});
    }
    if (['allowed-page-websocket', 'external-page-websocket'].includes(condition)) {
      const external = condition === 'external-page-websocket';
      const url = new URL(external ? 'wss://127.0.0.1:9/outside?secret=value' : 'wss://gate.test:3443/live?secret=value');
      const intercepted = typeof websocketPredicate === 'function' && websocketPredicate(url);
      check(intercepted === external, 'page WebSocket gate-host predicate');
      if (intercepted && typeof websocketHandler === 'function') await websocketHandler({ url: () => url.href, close: async options => { websocketCloses.push(options); } });
      if (external) {
        check(websocketCloses.length === 1 && websocketCloses[0].code === 1008, 'external page WebSocket closed with policy code');
        check(websocketCloses[0]?.reason === 'blocked: not the gate host', 'external page WebSocket fixed close reason');
        check(tracker.list.some(e => e.host === '127.0.0.1' && e.scheme === 'wss' && e.how === 'websocket-blocked'), 'external page WebSocket sanitized attempt retained');
      } else check(websocketCloses.length === 0 && tracker.list.length === 0, 'allowed gate WebSocket bypasses handler');
    }
    if (condition === 'malformed') session.emit('Fetch.requestPaused',{requestId:'bad',request:{url:'%%%' }});
    if (condition === 'response-pause') session.emit('Fetch.requestPaused',{requestId:'response',responseStatusCode:200,request:{url:'https://gate.test/'}});
    if (condition === 'session-loss') session.emit('close');
    if (condition !== 'delayed-decision') { await pause(); await pause(); }
  }
  let terminalFailed = false;
  try {
    if (typeof tracker.closeOwnedBrowser !== 'function') throw new Error('missing close lifecycle');
    await tracker.closeOwnedBrowser(() => context.close());
  } catch { terminalFailed = true; }
  if (condition === 'duplicate-close') { try { await tracker.closeOwnedBrowser(() => context.close()); } catch { errors.push('duplicate-close unexpectedly failed'); } }
  const bad = !['allowed','duplicate-close','allowed-page-websocket'].includes(condition);
  check(terminalFailed === bad, 'terminal verdict');
  check(closeCalls === 1, 'owned browser close exactly once');
  const commands = sent.filter(x=>x.method==='Fetch.continueRequest'||x.method==='Fetch.failRequest');
  if (condition==='allowed') check(commands.some(x=>x.method==='Fetch.continueRequest'&&x.params.requestId==='a'&&Object.keys(x.params).length===1), 'allowed request unchanged');
  if (['redirect','decision-failure','late-attempt'].includes(condition)) check(commands.some(x=>x.method==='Fetch.failRequest'&&x.params.requestId===(condition==='late-attempt'?'late':'b')&&x.params.errorReason==='BlockedByClient'), 'external hop failed');
  if (condition==='malformed') check(commands.some(x=>x.method==='Fetch.failRequest'&&x.params.requestId==='bad'), 'malformed request refused');
  check(!events.includes('Fetch.disable') && (!events.includes('detach') || events.indexOf('detach')>events.indexOf('browser-close')), 'no guard release before browser close');
  const evidence = typeof tracker.evidence==='function' ? tracker.evidence() : null;
  check(evidence && evidence.closed === (!['close-failure','still-connected'].includes(condition)), 'terminal evidence');
  if (!['allowed','duplicate-close','allowed-page-websocket','external-page-websocket','redirect','late-attempt','delayed-decision'].includes(condition)) check(evidence?.errors?.length>0, 'integrity failure retained');
  if (['redirect','decision-failure','late-attempt'].includes(condition)) check(tracker.list.some(x=>x.host==='127.0.0.1'), 'sanitized attempt retained');
  check(!JSON.stringify({evidence,list:tracker.list}).includes('secret=value'), 'sensitive URL absent');
  if (condition === 'response-pause') check(commands.some(x=>x.method==='Fetch.failRequest'&&x.params.requestId==='response'), 'response-stage pause refused');
  if (condition === 'delayed-decision') check(events.includes('decision-ack')&&tracker.list.some(x=>x.how==='http-blocked'), 'terminal waits for decision acknowledgement');
  if (evidence?.closed) check(session.listenerCount('Fetch.requestPaused')===0, 'owned listener removed only after closure');
  failures += errors.length;
  console.log(JSON.stringify({condition,errors,events,sent,evidence,list:tracker.list,websocketCloses}));
}
console.log(JSON.stringify({cases:cases.length,failedAssertions:failures,sourceSha256:createHash('sha256').update(readFileSync(file)).digest('hex')}));
process.exitCode=failures?1:0;
"""
    result = subprocess.run([node, '--input-type=module', '-e', program, 'canonical-http-guard',
                             str(ROOT / 'scripts/gate/browser-launch.mjs')], capture_output=True, text=True, timeout=45)
    try:
        summary = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        summary = {}
    checks.expect(result.returncode == 0 and summary.get('cases') == 21 and summary.get('failedAssertions') == 0,
                  'check_browser_http_guard: shipped guard decisions failed: ' + result.stdout[-2400:] + result.stderr[-600:])


def check_browser_http_callers(checks):
    """Exercise shipped terminal fragments and full setup-failure modules, not actual UI behavior."""
    node = shutil.which('node')
    if not node:
        print('check_browser_http_callers: NOT RUN (optional host Node is absent)', file=sys.stderr)
        return
    payloads = (
        (15, r"""// Execute the shipped finalizer and following verdict unchanged, in a controlled scope.
// This checks terminal receipt propagation, not DOM/login correctness or real Chrome exit.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import { resolve } from 'node:path';

const root = resolve(process.argv[2] || '.');
let failures = 0;
for (const file of ['screenshots.mjs', 'screenshots-grafana.mjs', 'screenshots-perses.mjs']) {
  const source = readFileSync(`${root}/scripts/gate/${file}`, 'utf8');
  const finalizers = [...source.matchAll(/^\} finally \{$/gm)];
  if (finalizers.length !== 1) throw new Error(`ambiguous finalizer: ${file}`);
  const tail = source.slice(finalizers[0].index + 2);
  for (const condition of ['positive', 'evidence', 'close', 'terminal-attempt', 'browser-write']) {
    const events = [], logs = [], files = new Map();
    let closed = false;
    const process = { exitCode: undefined };
    const guard = { closed: false, errors: [] };
    const ext = {
      list: [], evidence: () => ({ ...guard, errors: [...guard.errors] }),
      async closeOwnedBrowser(close) {
        events.push('guard-close');
        await close();
        guard.closed = true;
        if (condition === 'terminal-attempt') {
          ext.list.push({ host: 'outside.invalid', scheme: 'http', how: 'http-blocked' });
          guard.errors.push({ stage: 'synthetic terminal attempt' });
          throw new Error('injected terminal-attempt');
        }
      },
    };
    const scope = vm.createContext({
      URL, process, MAC: true, OUT: '/synthetic', PIN: {}, PINPERS: {}, PINPERS_PORT: 3443,
      page: {}, certDecision: {}, SHOTS_EXPECTED: 1, storySucceeded: true,
      manifest: [{ asserted: ['controlled prerequisite'] }],
      browser: { async close() {
        events.push('browser-close');
        if (condition === 'close') throw new Error('injected close');
        closed = true;
      } },
      launch: { mode: 'mac', profileDir: '/synthetic-profile', headless: false },
      ext,
      async browserEvidence() {
        events.push('evidence');
        if (closed) throw new Error('evidence sampled after close');
        if (condition === 'evidence') throw new Error('injected evidence');
        return { observedBy: 'controlled-live-boundary' };
      },
      writeFileSync(path, data) {
        const name = path.split('/').pop(); events.push(`write:${name}`);
        if (condition === 'browser-write') throw new Error('injected browser-write');
        files.set(name, JSON.parse(data));
      },
      chmodSync() {}, cleanProfile(_path, keep) { events.push(`profile:${keep}`); return !keep; },
      console: { log: (value) => logs.push(String(value)), error: (value) => logs.push(String(value)) },
    });
    const module = new vm.SourceTextModule(`try {} ${tail}`, { context: scope });
    await module.link(() => { throw new Error('unexpected finalizer import'); });
    let escaped = null;
    try { await module.evaluate({ timeout: 2000 }); } catch (error) { escaped = String(error); }
    const errors = [], expect = (ok, message) => { if (!ok) errors.push(message); };
    expect(escaped === null, 'finalization escaped');
    expect(events.filter(e => e === 'guard-close').length === 1, 'guard close not exactly once');
    expect(events.filter(e => e === 'browser-close').length === 1, 'owned close not exactly once');
    expect(events.indexOf('evidence') < events.indexOf('browser-close'), 'evidence not sampled live');
    expect(events.indexOf('browser-close') < events.indexOf('write:browser.json'), 'receipt preceded close');
    const receipt = files.get('browser.json');
    if (condition !== 'browser-write') {
      expect(receipt?.networkGuard?.closed === (condition !== 'close'), 'terminal guard state missing');
      if (condition === 'terminal-attempt') {
        expect(receipt?.networkGuard?.errors?.length === 1, 'late guard failure absent');
        // The live receipt extra/list is a reference in production; the final guard status is decisive.
      }
    }
    expect(condition === 'positive' ? process.exitCode !== 1 : process.exitCode === 1, 'terminal failure lost exit status');
    expect(logs.some(line => line.startsWith('STORY OK:')) === (condition === 'positive'), 'premature/missing success verdict');
    expect(events.includes(`profile:${condition !== 'positive'}`), 'failed profile retention flag lost');
    if (condition === 'evidence') expect(receipt?.evidenceFailed && !receipt?.observedBy, 'missing evidence fabricated');
    failures += errors.length;
    console.log(JSON.stringify({ file, condition, errors, events, networkGuard: receipt?.networkGuard }));
  }
  console.log(JSON.stringify({ file, sourceSha256: createHash('sha256').update(source).digest('hex') }));
}
console.log(JSON.stringify({ cases: 15, failedAssertions: failures }));
process.exitCode = failures ? 1 : 0;
"""),
        (3, r"""// Run complete shipped screenshot modules with guard setup failure injected before navigation.
import { readFileSync } from 'node:fs';
import { createHmac, createHash, randomInt } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { resolve } from 'node:path';
import vm from 'node:vm';

const root = resolve(process.argv[2] || '.');
let failures = 0;
for (const file of ['screenshots.mjs', 'screenshots-grafana.mjs', 'screenshots-perses.mjs']) {
  const source = readFileSync(`${root}/scripts/gate/${file}`, 'utf8');
  const events = [], files = new Map(), logs = [];
  let closed = false;
  const page = { url: () => 'about:blank', async screenshot() {}, async goto() { events.push('navigation'); } };
  const browser = { pages: () => [page], async newPage() { return page; }, async close() { events.push('close'); closed = true; } };
  const guard = {
    list: [], async guard() { events.push('guard'); throw new Error('injected setup failure'); },
    async assertClean() { throw new Error('injected setup failure'); },
    async closeOwnedBrowser(close) { events.push('guard-close'); await close(); throw new Error('injected setup failure'); },
    evidence() { return { closed, errors: [{ stage: 'injected setup failure' }] }; },
  };
  const api = {
    macMode: () => true, requireCertFile: () => ({ pem: 'synthetic' }),
    async pinGateCertificate() { return {}; },
    async launchGateBrowser() { return { browser, mode: 'mac', profileDir: '/synthetic-profile' }; },
    cleanProfile(_path, keep) { events.push(`profile:${keep}`); return !keep; },
    attachServeTracker() { return { attachContext() {}, async record() {} }; },
    externalAttemptsTracker: () => guard,
    async acceptGateCertificate() { events.push('navigation'); throw new Error('navigation reached despite failed guard'); },
    async browserEvidence() { events.push('evidence'); return { observedBy: 'controlled-live-boundary' }; },
  };
  const child = {
    argv: ['node', file, '--base', 'https://localhost', '--host', 'localhost', '--out', '/synthetic',
      '--user', 'viewer', '--viewer-user', 'viewer', '--admin-user', 'admin', '--disabled-user', 'disabled', '--nogroup-user', 'nogroup'],
    env: Object.fromEntries(['GATE_TEMP_PASSWORD', 'GATE_DISABLED_PASSWORD', 'GATE_VIEWER_PASSWORD', 'GATE_ADMIN_PASSWORD',
      'GATE_NOGROUP_PASSWORD', 'GATE_VIEWER_TOTP', 'GATE_ADMIN_TOTP', 'GATE_NOGROUP_TOTP'].map(name => [name, 'JBSWY3DPEHPK3PXP'])),
    exitCode: undefined,
    exit(code) { this.exitCode = code; throw new Error('unexpected process.exit'); },
  };
  const context = vm.createContext({ URL, Buffer, process: child,
    console: { log: text => logs.push(String(text)), error: text => logs.push(String(text)) } });
  const imports = {
    './browser-launch.mjs': api,
    'node:module': { createRequire: () => () => ({ chromium: {} }) },
    'node:crypto': { createHmac, createHash, randomInt },
    'node:fs': { mkdirSync() {}, chmodSync() {}, readFileSync: () => Buffer.from('synthetic screenshot bytes'),
      writeFileSync(path, data) { const name = path.split('/').pop(); events.push(`write:${name}`); files.set(name, name.endsWith('.json') ? JSON.parse(data) : String(data)); } },
  };
  const module = new vm.SourceTextModule(source, { context, initializeImportMeta(meta) { meta.url = `file:///shipped/${file}`; } });
  await module.link(async specifier => {
    const bindings = imports[specifier];
    if (!bindings) throw new Error(`unexpected import ${specifier}`);
    return new vm.SyntheticModule(Object.keys(bindings), function () {
      for (const [key, value] of Object.entries(bindings)) this.setExport(key, value);
    }, { context });
  });
  let escaped = null;
  try { await module.evaluate({ timeout: 2000 }); } catch (error) { escaped = String(error); }
  const errors = [], expect = (ok, message) => { if (!ok) errors.push(message); };
  expect(escaped === null, 'guard setup escaped protected lifecycle');
  expect(!events.includes('navigation'), 'navigation reached after failed setup');
  expect(events.filter(e => e === 'guard-close').length === 1 && events.filter(e => e === 'close').length === 1, 'owned browser not closed exactly once');
  expect(events.indexOf('evidence') < events.indexOf('close'), 'evidence not sampled live');
  expect(events.indexOf('close') < events.indexOf('write:browser.json'), 'receipt published before close');
  expect(files.get('browser.json')?.networkGuard?.closed && files.get('browser.json')?.networkGuard?.errors?.length, 'setup failure absent from terminal receipt');
  expect(child.exitCode === 1 && !logs.some(line => line.startsWith('STORY OK:')), 'setup failure accepted');
  expect(events.includes('profile:true'), 'failed profile not retained');
  failures += errors.length;
  console.log(JSON.stringify({ file, errors, events, sourceSha256: createHash('sha256').update(source).digest('hex') }));
}
console.log(JSON.stringify({ cases: 3, failedAssertions: failures }));
process.exitCode = failures ? 1 : 0;
"""),
    )
    for count, program in payloads:
        result = subprocess.run([node, '--experimental-vm-modules', '--input-type=module', '-e', program,
                                 'canonical-http-callers', str(ROOT)], capture_output=True, text=True, timeout=30)
        try:
            summary = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            summary = {}
        checks.expect(result.returncode == 0 and summary.get('cases') == count and summary.get('failedAssertions') == 0,
                      f'check_browser_http_callers: {count} shipped-caller cases failed: ' + result.stdout[-2400:] + result.stderr[-600:])


def check_browser_story_ports(checks):
    """Configured HTTPS pin ports; execute complete shipped modules through API adapters."""
    node = shutil.which('node')
    if not node:
        print('check_browser_story_ports: NOT RUN (optional host Node is absent)', file=sys.stderr)
        return
    program = r"""import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Execute each complete shipped story through its actual argument and pin setup.
// The browser boundary stops before launch; no browser, network, files or credentials.
const storyDir = resolve(process.argv[1] || 'scripts/gate');
const cases = [
  { story: 'grafana', flags: ['--base', 'https://fixture.test:14443'], ports: [14443] },
  { story: 'grafana', flags: [], ports: [443] },
  { story: 'perses', flags: ['--base', 'https://fixture.test:14443', '--perses-base', 'https://fixture.test:13443'], ports: [14443, 13443] },
  { story: 'perses', flags: [], ports: [443, 3443] },
  { story: 'perses', flags: ['--perses-base', 'https://fixture.test:14443'], ports: [443, 14443] },
];
let failed = 0;
for (const test of cases) {
  const path = resolve(storyDir, `screenshots-${test.story}.mjs`);
  const pins = []; let stopped = false; let error = null;
  const context = vm.createContext({ URL, process: {
    argv: ['node', path, '--host', 'fixture.test', '--resolve-to', '192.0.2.10', '--out', '/owned-output',
      '--viewer-user', 'v', '--admin-user', 'a', '--disabled-user', 'd', '--nogroup-user', 'n', ...test.flags],
    env: Object.fromEntries(['VIEWER_PASSWORD','VIEWER_TOTP','ADMIN_PASSWORD','ADMIN_TOTP','DISABLED_PASSWORD','NOGROUP_PASSWORD','NOGROUP_TOTP'].map(x=>['GATE_'+x,'synthetic'])),
    exit() { throw new Error('unexpected preflight exit'); },
  }, console });
  const module = new vm.SourceTextModule(readFileSync(path,'utf8'), { context, identifier: pathToFileURL(path).href,
    initializeImportMeta(meta) { meta.url = pathToFileURL(path).href; } });
  await module.link(async specifier => {
    let ns;
    if (specifier === './browser-launch.mjs') ns = {
      launchGateBrowser: async()=>{stopped=true;throw new Error('STOP_AT_BROWSER_BOUNDARY');}, macMode:()=>true,
      requireCertFile:()=>({pem:'synthetic'}), pinGateCertificate:async x=>{pins.push({host:x.host,port:x.port,connectHost:x.connectHost});return {};},
      acceptGateCertificate(){},attachServeTracker(){},browserEvidence(){},cleanProfile(){},externalAttemptsTracker(){},
    };
    else if (specifier === 'node:module') ns={createRequire:()=>()=>({chromium:{}})};
    else { ns={...await import(specifier)}; if(specifier==='node:fs')ns.mkdirSync=()=>{}; }
    const keys=Object.keys(ns);
    return new vm.SyntheticModule(keys,function(){for(const k of keys)this.setExport(k,ns[k]);},{context});
  });
  try { await module.evaluate(); } catch(e) { if(e.message!=='STOP_AT_BROWSER_BOUNDARY') error=String(e); }
  const ok=stopped && !error && JSON.stringify(pins.map(x=>x.port))===JSON.stringify(test.ports)
    && pins.every(x=>x.host==='fixture.test'&&x.connectHost==='192.0.2.10');
  if(!ok)failed++;
  console.log(JSON.stringify({story:test.story,flags:test.flags,pins,expected:test.ports,ok,error}));
}
console.log(JSON.stringify({cases:cases.length,failed}));
process.exitCode=failed?1:0;
"""
    result = subprocess.run([node, '--experimental-vm-modules', '--input-type=module', '-e', program,
                             str(ROOT / 'scripts/gate')], capture_output=True, text=True, timeout=30)
    checks.expect(result.returncode == 0,
                  'check_browser_story_ports: shipped module regression failed: ' + result.stdout[-1800:] + result.stderr[-600:])




    runner = (ROOT / 'scripts/gate-identity.sh').read_text()
    scratch = ROOT / 'harness/check-identity'
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='perses-port-argv-', dir=str(scratch)) as temporary:
        directory = Path(temporary)
        (directory / 'p4').mkdir()
        for user in ('p4v', 'p4both', 'p4dis', 'p4nogroup'):
            (directory / 'p4' / ('kc-' + user + '.json')).write_text(json.dumps(
                {'password': 'synthetic', 'totp': 'synthetic'}))
        script = r"""
STATE="$1"; OUT="$1/out"; ARGS="$1/argv"; BASE="$2"
BASE_HOST=fixture.test; PERSES_GATE_PORT=13443; GATE_DIR=/synthetic-gate
PG_IMAGE=synthetic-no-container; SCREENSHOTS=true; CAP=""
docker() { if [[ "$1" == image ]]; then return 0; fi; printf '192.0.2.10\n'; }
curl() { printf '302'; }
add_secret() { :; }
cap() { printf '%s\n' "$@" > "$ARGS"; return 1; }
ok_if() { :; }
""" + function_body(runner, 'phase4_screenshots_x4') + '\nphase4_screenshots_x4 synthetic\n'
        for base in ('https://fixture.test:14443', 'https://fixture.test'):
            result = run_bash(script, directory, base)
            argv = (directory / 'argv').read_text().splitlines() if (directory / 'argv').exists() else []
            checks.expect(result.returncode == 0 and '--base' in argv
                          and argv[argv.index('--base') + 1] == base,
                          f'Perses runner must pass configured realm base {base}; argv={argv}, err={result.stderr}')

def check_browser_probe_lifecycle(checks):
    """U15 assertions preserve evidence and teardown; execute complete shipped modules through API adapters."""
    node = shutil.which('node')
    if not node:
        print('check_browser_probe_lifecycle: NOT RUN (optional host Node is absent)', file=sys.stderr)
        return
    program = r"""// Standalone payload for the canonical Python checker. Pass only the shipped file
// path as argv[2]; no ignored harness file is imported or needed at runtime.
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { Buffer } from 'node:buffer';
import vm from 'node:vm';

const source = readFileSync(process.argv[1], 'utf8');
const cases = ['positive', 'address', 'certificate', 'external', 'evidence', 'close', 'browser-write', 'summary-write', 'guard', 'terminal'];
let failed = 0;
for (const condition of cases) {
  const events = [], files = new Map(), logs = [];
  const reject = (stage) => { if (condition === stage) throw new Error(`injected ${stage}`); };
  const page = {
    url: () => 'https://gate.test/grafana/', on() {}, async goto() {},
    getByRole() { return { first() { return this; }, async click() {} }; },
    locator() { return { async count() { return 0; } }; },
    async waitForSelector() {}, async fill() {}, async click() {}, async waitForURL() {},
    async waitForLoadState() {}, async waitForTimeout() {}, async screenshot() {},
  };
  const context = { pages: () => [page], async newPage() { return page; },
    async close() { events.push('close'); reject('close'); } };
  const api = {
    macMode: () => true, requireCertFile: () => ({ pem: 'synthetic-pin' }),
    async pinGateCertificate() { return {}; },
    async launchGateBrowser() { return { browser: context, mode: 'mac', profileDir: 'synthetic-profile', headless: false }; },
    cleanProfile(_path, keep) { events.push(`profile:${keep}`); return !keep; },
    attachServeTracker() { return { attachContext() {}, last: () => ({}) }; },
    externalAttemptsTracker() { return { list: condition === 'external' ? [{host: 'outside.invalid', scheme: 'ws'}] : [],
      async guard() { reject('guard'); }, async assertClean() { reject('external'); },
      async closeOwnedBrowser(close) { await close(); reject('external'); reject('terminal'); },
      evidence() { return { closed: condition !== 'close', errors: condition === 'terminal' ? [{ stage: 'injected terminal' }] : [] }; } }; },
    async acceptGateCertificate() { return { decision: 'proceed' }; },
    async assertServedFrom() { reject('address'); return 'synthetic address proof'; },
    async assertServedCertificate() { reject('certificate'); return 'synthetic certificate proof'; },
    async browserEvidence() { events.push('evidence'); reject('evidence'); return { observedBy: 'mock-api' }; },
  };
  const child = { argv: ['node', 'phase4-browser.mjs', '--base', 'https://gate.test', '--host', 'gate.test', '--out', '/synthetic'],
    env: { UI15_PASSWORD: 'synthetic', UI15_TOTP: 'JBSWY3DPEHPK3PXP' }, exitCode: 0,
    exit(code) { this.exitCode = code; throw new Error(`unexpected early exit ${code}`); } };
  const global = vm.createContext({ URL, Buffer, process: child,
    console: { log: (text) => logs.push(String(text)), error: (text) => logs.push(String(text)) } });
  const imports = { './browser-launch.mjs': api, 'node:crypto': { createHmac },
    'node:module': { createRequire: () => () => ({ chromium: {} }) },
    'node:fs': { writeFileSync(path, data) { const file = path.split('/').pop(); events.push(`write:${file}`);
      if ((condition === 'browser-write' && file === 'browser.json') || (condition === 'summary-write' && file === 'ui15-summary.json')) throw new Error(`injected ${condition}`);
      files.set(file, JSON.parse(data)); }, chmodSync() {} } };
  const module = new vm.SourceTextModule(source, { context: global, identifier: 'file:///shipped/phase4-browser.mjs',
    initializeImportMeta(meta) { meta.url = 'file:///shipped/phase4-browser.mjs'; } });
  await module.link(async (specifier) => {
    const exports = imports[specifier];
    if (!exports) throw new Error(`unexpected import ${specifier}`);
    return new vm.SyntheticModule(Object.keys(exports), function () {
      for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
    }, { context: global });
  });
  let uncaught = null;
  try { await module.evaluate({ timeout: 2000 }); } catch (error) { uncaught = String(error.message || error); }
  const summary = files.get('ui15-summary.json'), browser = files.get('browser.json');
  const stdout = logs.find((line) => line.startsWith('SUMMARY '));
  const parsed = stdout ? JSON.parse(stdout.slice('SUMMARY '.length)) : null;
  const errors = [], expect = (ok, message) => { if (!ok) errors.push(message); };
  expect(uncaught === null, 'failure escaped lifecycle');
  expect(condition === 'positive' ? child.exitCode === 0 : child.exitCode !== 0, 'incorrect exit status');
  expect((!!summary || condition === 'summary-write') && (!!browser || condition === 'browser-write') && !!parsed, 'available summary/browser/stdout evidence missing');
  expect(events.filter((event) => event === 'close').length === 1, 'close not attempted exactly once');
  expect(events.includes('evidence') && events.indexOf('evidence') < events.indexOf('close'), 'live evidence not before close');
  expect(events.indexOf('close') < events.indexOf('write:ui15-summary.json'), 'summary finalized before cleanup');
  if (condition !== 'positive') {
    if (condition !== 'summary-write') expect(summary?.failures?.some((failure) => failure.error.includes(`injected ${condition}`)), 'failure not retained in file');
    expect(parsed?.storyFailed && parsed?.failures?.length > 0, 'failure not retained in stdout');
    if (!['browser-write', 'summary-write'].includes(condition)) expect(events.includes('profile:true'), 'known failed profile not retained');
  } else expect(!summary?.storyFailed && !(summary?.failures || []).length, 'positive control fabricated failure');
  if (condition === 'evidence') expect(!!browser?.evidenceFailed && !browser?.observedBy, 'missing evidence replaced by proof');
  if (condition === 'external') expect(summary?.externalAttempts?.[0]?.host === 'outside.invalid', 'external evidence lost');
  if (condition === 'close') expect(browser?.failures?.some((failure) => failure.stage === 'browser cleanup failed'), 'cleanup failure absent from browser receipt');
  if (condition === 'positive') expect(browser?.networkGuard?.closed && summary?.networkGuard?.closed, 'terminal guard evidence absent from both receipts');
  if (condition === 'terminal') expect(browser?.networkGuard?.errors?.length && summary?.networkGuard?.errors?.length, 'terminal guard failure absent from receipts');
  failed += errors.length;
  console.log(JSON.stringify({ condition, errors }));
}
console.log(JSON.stringify({ cases: cases.length, failedAssertions: failed }));
process.exitCode = failed ? 1 : 0;
"""
    result = subprocess.run([node, '--experimental-vm-modules', '--input-type=module', '-e', program,
                             str(ROOT / 'scripts/gate/phase4-browser.mjs')], capture_output=True, text=True, timeout=30)
    checks.expect(result.returncode == 0,
                  'check_browser_probe_lifecycle: shipped module regression failed: ' + result.stdout[-1800:] + result.stderr[-600:])


def check_browser_probe_consumer(checks):
    """A retained diagnostic summary cannot pass or be erased by a retry."""
    import ast
    import types

    tree = ast.parse((ROOT / 'scripts/gate/phase4_grafana.py').read_text())
    original = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == 'Gate')
    methods = {'_benign_404', '_network_flake', '_browser_attempt', 'run_browser_probe', 'browser_clean'}
    members: list[ast.stmt] = [item for item in original.body if (
        isinstance(item, ast.FunctionDef) and item.name in methods
        or isinstance(item, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'NET_RETRY_ERRORS'
                                               for target in item.targets))]
    # Compile the shipped method ASTs without constructing a cluster-backed Gate.
    selected = ast.ClassDef(name='ProbeConsumer', bases=[], keywords=[], body=members, decorator_list=[])
    namespace = {'os': os, 'json': json, 'HERE': str(ROOT / 'scripts/gate'), 'log': lambda _message: None}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[selected], type_ignores=[])),
                 'shipped-phase4-browser-consumer', 'exec'), namespace)
    consumer = namespace['ProbeConsumer']()
    consumer._benign_404 = lambda _item: False
    clean = {'cspViolations': 0, 'pageErrors': 0, 'failedRequests': [], 'http4xx5xx': []}
    network = dict(clean, failedRequests=[{'err': 'net::ERR_CONNECTION_RESET'}])
    e = checks.expect
    e(consumer.browser_clean(clean), 'clean browser summary must pass')
    e(consumer._network_flake(network), 'successful child with network-only dirt retains one retry')
    failure_fields = ({'storyFailed': 'certificate mismatch'},
                      {'failures': [{'stage': 'browser cleanup failed', 'error': 'closed failed'}]},
                      {'probeExitCode': 1}, {'probeExitCode': -9})
    for fields in failure_fields:
        e(not consumer.browser_clean(dict(clean, **fields)), f'browser_clean must reject {fields}')
        e(not consumer._network_flake(dict(network, **fields)), f'retry must not erase {fields}')

    consumer.base = 'https://fixture.test'
    consumer.origin = types.SimpleNamespace(hostname='fixture.test')
    consumer.totp_steps = types.SimpleNamespace(guard_external_signin=lambda _user: contextlib.nullcontext())
    consumer.BROWSER_IMAGE = 'synthetic-no-container'
    consumer.load_state = lambda _user: {'password': 'synthetic', 'totp': 'synthetic'}
    scratch = ROOT / 'harness/check-identity'
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='browser-consumer-', dir=str(scratch)) as temporary:
        consumer.scratch_dir = temporary
        for rc in (0, 1, -9):
            namespace['p2'] = types.SimpleNamespace(docker=lambda *args, **kwargs:
                (rc, 'SUMMARY ' + json.dumps(dict(clean, probeExitCode=0)), ''))
            summary, _steps = consumer._browser_attempt('viewer', 'dash', '192.0.2.10',
                                                       consumer.load_state('viewer'), temporary)
            e(summary.get('probeExitCode') == rc, f'actual child exit {rc} must overwrite summary claim')
            e(consumer.browser_clean(summary) == (rc == 0), f'child exit {rc} must reach verdict')
        for fields in failure_fields:
            first = dict(network, **fields)
            calls = []

            def attempt(*_args):
                calls.append(True)
                return (first if len(calls) == 1 else clean), []

            consumer._browser_attempt = attempt
            summary, _steps, retried = consumer.run_browser_probe('viewer', 'dash', '192.0.2.10')
            e(len(calls) == 1 and summary is first and retried is None,
              f'first failure must survive without replacement: {fields}')
        calls = []
        consumer._browser_attempt = lambda *_args: (calls.append(True) or
            ((network if len(calls) == 1 else clean), []))
        summary, _steps, retried = consumer.run_browser_probe('viewer', 'dash', '192.0.2.10')
        e(len(calls) == 2 and summary is clean and retried == network['failedRequests'],
          'network-only successful-child control must retry once and retain first dirt')

def check_mac_ipv4_outcomes(checks):
    """Inconclusive ports fail; complete shipped sweep and exact report hashes."""
    node = shutil.which('node')
    if not node:
        print('check_mac_ipv4_outcomes: NOT RUN (optional host Node is absent)', file=sys.stderr)
        return
    program = r"""import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import vm from 'node:vm';

// The whole shipped entrypoint runs unchanged; only sockets/files/process are boundary adapters.
const sourcePath = resolve(process.argv[1] || 'scripts/gate/mac/probe.mjs');
const source = readFileSync(sourcePath, 'utf8');
const manual = process.argv.includes('--manual');
const savePath = process.argv.find(a => a.startsWith('--save='))?.slice(7);
const cases = manual ? [{ name: 'manual non-spot EMFILE', code: 'EMFILE', port: 32000, fail: true }] : [
  ...['EMFILE', 'ENFILE', undefined, 'EADDRNOTAVAIL', 'ENOTSUP', 'EINVAL', 'ENXIO'].map(code =>
    ({ name: `non-spot ${code || 'missing errno'}`, code, port: 32000, fail: true })),
  { name: 'spot EMFILE', code: 'EMFILE', port: 111, fail: true },
  { name: 'all inconclusive bounded sample', code: 'EMFILE', all: true, fail: true },
  ...['ECONNREFUSED', 'EHOSTUNREACH', 'ETIMEDOUT', 'open'].map(code =>
    ({ name: `conclusive ${code}`, code, port: 32000, fail: false })),
];
let failures = 0;
for (const test of cases) {
  const files = new Map(); const stdout = []; const stderr = []; const connected = [];
  let rc = 0; let caught;
  const context = vm.createContext({ process: {
    argv: ['node', sourcePath, 'sweep', '--ip', '127.0.0.1', '--host', 'fixture.test', '--out', '/owned-output'],
    stdout: { write(s) { stdout.push(s); } }, exit(n) { rc = n; const e = new Error('process exit'); e.exit = true; throw e; },
  }, console: { log(s) { stdout.push(s); }, error(s) { stderr.push(s); } } });
  const module = new vm.SourceTextModule(source, { context, identifier: pathToFileURL(sourcePath).href,
    initializeImportMeta(meta) { meta.url = pathToFileURL(sourcePath).href; } });
  const imported = new Map();
  await module.link(async specifier => {
    if (imported.has(specifier)) return imported.get(specifier);
    const namespace = { ...await import(specifier) };
    if (specifier === 'node:fs') {
      namespace.mkdirSync = () => {};
      namespace.writeFileSync = (path, data) => files.set(path, String(data));
    }
    if (specifier === 'node:net') namespace.default = { ...namespace.default, connect(options) {
      connected.push(options.port);
      const socket = new EventEmitter(); socket.destroy = () => socket;
      socket.setTimeout = () => socket;
      queueMicrotask(() => {
        const selected = test.all || options.port === test.port;
        if (selected && test.code === 'open') socket.emit('connect');
        else socket.emit('error', { code: selected ? test.code : 'ECONNREFUSED' });
      }); return socket;
    } };
    const keys = Object.keys(namespace);
    const linked = new vm.SyntheticModule(keys, function () { for (const key of keys) this.setExport(key, namespace[key]); }, { context });
    imported.set(specifier, linked); return linked;
  });
  try { await module.evaluate({ timeout: 10000 }); } catch (e) { if (!e.exit) caught = String(e.stack || e); }
  if (savePath && ['non-spot EMFILE', 'conclusive ECONNREFUSED'].includes(test.name)) {
    const dir = `${savePath}/${test.fail ? 'inconclusive' : 'conclusive'}`;
    mkdirSync(dir, { recursive: true });
    for (const [path, bytes] of files) writeFileSync(`${dir}/${path.split('/').pop()}`, bytes);
  }
  const raw = files.get('/owned-output/w5-result.json'); const report = raw ? JSON.parse(raw) : null;
  const output = stdout.join('\n'); const errors = stderr.join('\n'); const problems = [];
  const check = (yes, message) => { if (!yes) problems.push(message); };
  if (!manual) {
    check(!caught, 'unexpected module error: ' + caught);
    check(rc === (test.fail ? 1 : 0), `exit ${rc}, expected ${test.fail ? 1 : 0}`);
    check(connected.length === 65535 && new Set(connected).size === 65535, 'complete IPv4 sweep');
    check(report && Object.values(report.counts).reduce((a,b) => a+b,0) === 65535, 'complete count report');
    check(report && files.get('/owned-output/w5-result.sha256') === `${createHash('sha256').update(raw).digest('hex')}  w5-result.json\n`, 'report hash');
    if (test.fail) {
      check(!output.includes('RESULT W5 rc=0'), 'no success result');
      check(output.includes('RESULT W5 rc=1'), 'explicit failed result');
      check(report?.inconclusive?.count === (test.all ? 65535 : 1), 'all inconclusive counted');
      check(report?.inconclusive?.sample?.length === (test.all ? 8 : 1), 'bounded sample');
      check(report?.inconclusive?.sample?.[0]?.port === (test.all ? 1 : test.port), 'diagnostic names failing port');
      check(errors.includes(String(test.all ? 65535 : 1)) && errors.length < 1500, 'bounded diagnostic total');
    } else check(output.includes('RESULT W5 rc=0'), 'conclusive sweep success');
  }
  failures += problems.length;
  console.log(JSON.stringify({ case: test.name, rc, counts: report?.counts, inconclusive: report?.inconclusive,
    result: output.split('\n').filter(s => s.startsWith('RESULT')), stderr: errors, caught, problems }));
}
console.log(JSON.stringify({ cases: cases.length, failedAssertions: failures, sourceSha256: createHash('sha256').update(source).digest('hex') }));
process.exitCode = failures ? 1 : 0;
"""
    result = subprocess.run([node, '--experimental-vm-modules', '--input-type=module', '-e', program,
                             str(ROOT / 'scripts/gate/mac/probe.mjs')], capture_output=True, text=True, timeout=30)
    checks.expect(result.returncode == 0,
                  'check_mac_ipv4_outcomes: shipped sweep regression failed: ' + result.stdout[-1800:] + result.stderr[-600:])


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
        'while (( SECONDS < hello_deadline )); do',
        'if limactl shell "$VM" -- grep -q -F -- "$NONCE" "$RDV/agent-hello.json" 2>/dev/null; then hello_seen=1; break; fi',
        'kill -0 "$AGENT_PID" 2>/dev/null || { echo "run-vm-gate: the agent exited before its hello reached $RDV (see $OUT/agent.log)" >&2; exit 2; }',
        'sleep 2',
        '(( hello_seen == 1 )) || { echo "run-vm-gate: no agent-hello.json in $RDV within 90 s (see $OUT/agent.log)" >&2; exit 2; }',
    )
    mkdir_guest_line = 'limactl shell "$VM" -- mkdir -p "$RDV" "$GUEST_ROOT/agent-out" 2>/dev/null || { echo "run-vm-gate: could not create $RDV and $GUEST_ROOT/agent-out in the guest (is $GUEST_ROOT writable?)" >&2; exit 2; }'
    rm_status_line = ('limactl shell "$VM" -- rm -f "$RDV/runner.rc" "$RDV/runner.pid" 2>/dev/null || { echo "run-vm-gate: could not remove an earlier runner.rc/runner.pid from $RDV in the guest; '
                      'an earlier exit status would be read as this run\'s" >&2; exit 2; }')
    for line in (mkdir_guest_line, rm_status_line, 'hello_deadline=$((SECONDS + 90))') + wait_lines:
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

    # PRE-5 is exercised against the shipped finalizers by check_browser_http_callers
    # and against the complete U15 module by check_browser_probe_lifecycle. Those checks
    # require live evidence before owned close and final guard receipts after close.
    u15_lines = js_lines((ROOT / 'scripts/gate/phase4-browser.mjs').read_text())

    # G7: the no-interstitial step is persisted before the non-zero exit; the dead throw in onAssert is gone.
    e("result.steps.push({ t: new Date().toISOString(), name: 'no-interstitial', error: accepted.error });" in u15_lines,
      'phase4-browser.mjs pushes the no-interstitial step when acceptGateCertificate returns no proceed decision (G7)')
    e(not any(ln.startswith('if (!d.seen) throw') for ln in u15_lines),
      'phase4-browser.mjs carries no `if (!d.seen) throw` in onAssert: the hook runs only when the interstitial was seen (G7: dead code)')
    summary_at = [i for i, ln in enumerate(u15_lines) if ln.startswith('writeFileSync(`${OUT}/ui15-summary.json`, JSON.stringify({ steps: result.steps, ...summary }')]
    launch_at = next((i for i, ln in enumerate(u15_lines) if ln.startswith('const launch = await launchGateBrowser(')), len(u15_lines))
    e(len(summary_at) == 1 and not any(ln.startswith('process.exit(') for ln in u15_lines[launch_at:])
      and "recordFailure('probe ended', e);" in u15_lines,
      'phase4-browser.mjs retains no-interstitial and assertion failures through shared evidence/cleanup finalization, with no early exit after launch (G7)')

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

        def w5_case(v6_ports, vm_g6, with_v6=True, envelope_leak='ok', result_leak=None, listing='match'):
            report = {'swept': {'tcpOnly': True}, 'counts': {'open': 6}, 'open': [22, 80, 443, 3443, 9092, 9093],
                      'spot': [{'port': 111, 'outcome': 'refused'}],
                      'cert': {'authorized': True, 'protocol': 'TLSv1.3', 'sha256': 'ab12'}}
            if result_leak is not None:
                report['mac_leak_scan'] = result_leak   # probe.mjs never writes this; the evaluator must not read it from here (T16)
            if with_v6:
                report['v6'] = {'address': 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96', 'addressClass': 'global',
                                'ports': [{'port': port, 'outcome': outcome} for port, outcome in v6_ports]}
            envelope = {'schema': 1, 'id': 1, 'row': 'W5', 'exit': 0}
            if envelope_leak == 'ok':
                envelope['mac_leak_scan'] = {'values': 0, 'hits': 0, 'stores': ['agent.log', 'agent-manifest.tsv']}
            elif envelope_leak == 'hits':
                envelope['mac_leak_scan'] = {'values': 1, 'hits': 1, 'stores': ['agent.log']}
            with tempfile.TemporaryDirectory() as w5_tmp:
                result_path = Path(w5_tmp) / 'w5-result.json'
                result_path.write_text(json.dumps(report))
                # R1: the agent's response lists what it delivered (files[]: name, sha256, bytes); the runner binds the result file to that entry
                entry = {'name': 'w5-result.json', 'sha256': hashlib.sha256(result_path.read_bytes()).hexdigest(), 'bytes': result_path.stat().st_size}
                sibling = {'name': 'w5-result.sha256', 'sha256': hashlib.sha256(b'sibling').hexdigest(), 'bytes': 79}
                if listing == 'match':
                    envelope['files'] = [sibling, entry]
                elif listing == 'stale':   # the file under the delivery folder is not the one the agent delivered (scp -r nested the fresh folder)
                    envelope['files'] = [sibling, dict(entry, sha256=hashlib.sha256(b'an earlier run').hexdigest())]
                elif listing == 'unlisted':
                    envelope['files'] = [sibling]
                elif listing == 'last-char':   # all but the last hex character of the real digest: only a prefix compare accepts it
                    envelope['files'] = [sibling, dict(entry, sha256=entry['sha256'][:-1] + ('0' if entry['sha256'][-1] != '0' else '1'))]
                elif listing == 'twice':
                    envelope['files'] = [entry, entry]
                elif listing == 'no-files-key':
                    envelope.pop('files', None)
                response_path = Path(w5_tmp) / 'w5-agent-response.json'
                response_path.write_text(json.dumps(envelope))
                env = dict(os.environ, W5_EXPECTED='22,' + w5_docker, W5_DOCKER=w5_docker, W5_VM_G6=vm_g6)
                run = subprocess.run([sys.executable, '-I', '-', str(result_path), 'running', str(response_path)], input=w5_python, env=env, text=True, capture_output=True)
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
        # T16: the leak scan is read from the agent's response envelope (probe.mjs never writes it into w5-result.json) and enforced
        rc_l, out_l = w5_case(m4_shape, 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96', envelope_leak='hits', result_leak={'values': 0, 'hits': 0, 'stores': []})
        e(rc_l == 1 and "the agent's mac leak scan found 1 hit(s) in ['agent.log']" in out_l,
          f'W5 reads mac_leak_scan from the saved agent response and fails on a hit even when w5-result.json claims none; got rc {rc_l}: {out_l[-200:]!r} (T16)')
        rc_m, out_m = w5_case(m4_shape, 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96', envelope_leak='missing', result_leak={'values': 0, 'hits': 0, 'stores': []})
        e(rc_m == 1 and 'the agent response carries no valid mac_leak_scan' in out_m,
          f'W5 fails when the saved agent response carries no valid mac_leak_scan (a scan in w5-result.json does not count); got rc {rc_m}: {out_m[-200:]!r} (T16)')
        # T03: an inconclusive IPv6 probe (no route or scope, an unknown errno) proves no filtering
        rc_i, out_i = w5_case([(22, 'open'), (80, 'refused'), (443, 'no-route-or-scope')] + m4_shape[3:], 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96')
        e(rc_i == 1 and 'IPv6 probe of port 443 was inconclusive (no-route-or-scope)' in out_i,
          f'W5 rejects an inconclusive IPv6 probe outcome; got rc {rc_i}: {out_i[-200:]!r} (T03)')
        # R1: the result file the runner reads must be the one the agent's response lists in files[] (sha256), whatever else sits in the folder
        for listing, reason in (('stale', 'is not the file this agent response lists'), ('unlisted', 'lists 0 w5-result.json entries'),
                                ('twice', 'lists 2 w5-result.json entries'), ('no-files-key', 'lists 0 w5-result.json entries')):
            rc_r1, out_r1 = w5_case(m4_shape, 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96', listing=listing)
            e(rc_r1 == 1 and 'breaches=1' in out_r1 and 'BREACH the ' in out_r1 and reason in out_r1
              and 'observed open set' not in out_r1 and 'open=[' not in out_r1,
              f'W5 fails closed, evaluating nothing, when the delivered result file is not tied to the agent response ({listing}); got rc {rc_r1}: {out_r1[-240:]!r} (R1)')
        rc_r1, out_r1 = w5_case(m4_shape, 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96', listing='match')
        e(rc_r1 == 0 and 'breaches=0' in out_r1, f'W5 passes when the result file is the one the response lists; got rc {rc_r1}: {out_r1[-200:]!r} (R1)')
        # N2 (delta review of 2d4c9df, mutant D-R1p): the comparison is on the whole sha256. A listing that agrees with the result file on
        # every hex character but the last (a prefix compare would accept it) is refused, and the two lines that decide it are pinned whole.
        rc_r1, out_r1 = w5_case(m4_shape, 'fd61:4f24:7843:765b:5055:55ff:fe33:4b96', listing='last-char')
        e(rc_r1 == 1 and 'breaches=1' in out_r1 and 'is not the file this agent response lists' in out_r1 and 'open=[' not in out_r1,
          f'W5 refuses a listed sha256 that differs from the result file only in its last hex character; got rc {rc_r1}: {out_r1[-200:]!r} (N2)')
        w5_python_lines = [ln.strip() for ln in w5_python.splitlines()]
        for pin in ('result_sha = hashlib.sha256(result_bytes).hexdigest()',
                    'if len(listed) != 1 or listed[0].get("sha256") != result_sha:'):
            e(pin in w5_python_lines, f'the W5 evaluation carries the whole line {pin!r}: the listed sha256 must equal the full digest of the bytes it read (N2)')

    # PRE-4: the W7 Ubuntu branch decides on the first line of `ufw status`, never on the ufw.service state (a oneshot that reads
    # `active (exited)` while ufw is inactive). The runner's own lines run against fake sudo/ufw commands.
    ufw_first_line = next((ln for ln in topo_runner_lines if ln.startswith('ufw_first="$(')), '')
    case_match = re.search(r'^ {4}case "\$ufw_first" in\n(?: {6}.*\n)+? {4}esac$', topo_runner_text, re.M)
    e(ufw_first_line == 'ufw_first="$( { sudo -n env LC_ALL=C ufw status 2>/dev/null || LC_ALL=C ufw status 2>/dev/null; } | head -1 || true)"'
      and case_match is not None and 'ufw_state' not in (case_match.group(0) if case_match else 'ufw_state')
      and '[[ "$ufw_state" == active ]]' not in topo_runner_text,
      'W7 (Ubuntu) reads the first line of `ufw status` (sudo -n, then plain; both under LC_ALL=C, T06) and decides on it in a case block that never looks at the ufw.service state (PRE-4)')
    if case_match is not None and ufw_first_line:
        def w7_ubuntu(sudo_body, ufw_body, caller_locale=None, first_line=None):
            with tempfile.TemporaryDirectory() as w7_tmp:
                fake_bin = Path(w7_tmp)
                for name, body in (('sudo', sudo_body), ('ufw', ufw_body)):
                    (fake_bin / name).write_text('#!/bin/sh\n' + body + '\n')
                    (fake_bin / name).chmod(0o755)
                script = 'st=0; ufw_reason=""\n' + (first_line or ufw_first_line) + '\n' + case_match.group(0) + '\nprintf "%s|%s|%s\\n" "$st" "$ufw_first" "$ufw_reason"\n'
                env = dict(os.environ, PATH=f'{fake_bin}:{os.environ["PATH"]}')
                if caller_locale:
                    env['LC_ALL'] = caller_locale
                run = subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True)
            return run.stdout.strip()
        # a sudo that takes `-n` the way the runner calls it (a fake `exec "$@"` would try to run a command named -n, fail, and send every
        # test down the plain fallback arm, leaving the sudo arm of the runner's lines unexercised)
        pass_sudo = '[ "$1" = -n ] && shift\nexec "$@"'
        e(w7_ubuntu(pass_sudo, 'echo "Status: inactive"') == '0|Status: inactive|',
          'W7 (Ubuntu) passes on `Status: inactive` (PRE-4)')
        e(w7_ubuntu(pass_sudo, 'echo "Status: active"; echo "To  Action  From"') == '1|Status: active|',
          'W7 (Ubuntu) fails on `Status: active` (as before; PRE-4)')
        e(w7_ubuntu('exit 1', 'echo "ERROR: You need to be root to run this script" >&2; exit 1') == '1||ufw status unreadable (needs root or passwordless sudo)',
          'W7 (Ubuntu) fails with the unreadable reason when ufw status cannot be read without root (PRE-4)')
        e(w7_ubuntu(pass_sudo, 'echo "Status: unknown"') == '1|Status: unknown|ufw status unreadable (needs root or passwordless sudo)',
          'W7 (Ubuntu) fails on any first line that is neither Status: active nor Status: inactive (PRE-4)')
        # T06 / R3: ufw's status line is gettext-translated, so the runner reads it under LC_ALL=C. The fake ufw answers in English only when
        # it sees LC_ALL=C; the caller's locale is German; the fake sudo either passes the environment on or resets it like sudo's env_reset.
        localized_ufw = 'if [ "$LC_ALL" = C ]; then echo "Status: inactive"; else echo "Estado: inactivo"; fi'
        resetting_sudo = '[ "$1" = -n ] && shift\nexec env -i PATH="$PATH" "$@"'
        e(w7_ubuntu(resetting_sudo, localized_ufw, caller_locale='de_DE.UTF-8') == '0|Status: inactive|',
          'W7 (Ubuntu) reads ufw status under LC_ALL=C through sudo even when sudo resets the caller environment (T06, R3)')
        e(w7_ubuntu(pass_sudo, localized_ufw, caller_locale='de_DE.UTF-8') == '0|Status: inactive|',
          'W7 (Ubuntu) reads ufw status under LC_ALL=C when the caller runs in another locale (T06, R3)')
        e(w7_ubuntu('exit 1', localized_ufw, caller_locale='de_DE.UTF-8') == '0|Status: inactive|',
          'W7 (Ubuntu) reads ufw status under LC_ALL=C on the plain (no sudo) fallback too (T06, R3)')
        unfixed_line = 'ufw_first="$( { sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null; } | head -1 || true)"'
        e(w7_ubuntu(pass_sudo, localized_ufw, caller_locale='de_DE.UTF-8', first_line=unfixed_line) == '1|Estado: inactivo|ufw status unreadable (needs root or passwordless sudo)',
          'harness control: the old line, without the fixed locale, reads the translated status and fails a correct fixture as unreadable (T06, R3)')

    # F2: --browser knows container and agent only (`local` selected nothing and was only recorded in the receipt row), and the
    # guide says what the code does: the W5-W7 rows of a 4c agent run need neither image (S4 still renders with the nginx image); the 4a/4b stories keep the guest's container vantage.
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
    e('On a `--phase 4c --browser agent` run on a vzNAT VM fixture its W5–W7 rows need neither image' in guide_flat
      and 'its S4 row still renders with the nginx image unless `--no-static` is given' in guide_flat
      and 'needs neither image' not in guide_flat
      and "The 4a/4b stories (U15, X3, X4) still run in the guest's container vantage and need the archive" in guide_flat
      and 'their Mac vantage is the story started on the Mac with `GATE_BROWSER_MAC=1`, as the X1 row describes' in guide_flat
      and 'that archive is no longer loaded into the guest at all' not in guide_flat
      and 'Only the rows W5 and W6 of slice 4c go through the agent' in guide_flat,
      'the guide says what the code does: the W5-W7 rows of a 4c agent run need neither image while S4 still renders with the nginx image, the 4a/4b stories keep the guest container vantage and need the archive, only W5/W6 go through the agent (F2, R10)')

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
                 'const response = state.last;',
                 'const count = state.count;',
                 'const proof = [await assertServedFrom(response, expectedIp, what)];',
                 'if (pinned) proof.push(await assertServedCertificate(response, pinned, what));',
                 'if (state.last !== response || state.count !== count) throw new Error(`${what}: main-document response changed during served-address/certificate assertions`);',
                 'asserted.push(...proof);'):
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
            "};\n"
            "const out = { from: await lib.assertServedFrom(good, '192.168.64.2', 'x') };\n"
            "const refuse = async (fn) => { try { await fn(); return false; } catch { return true; } };\n"
            "out.loopbackRefused = await refuse(() => lib.assertServedFrom({ serverAddr: async () => ({ ipAddress: '127.0.0.1', port: 443 }) }, '192.168.64.2', 'x'));\n"
            "out.loopbackRefusedWithoutExpectation = await refuse(() => lib.assertServedFrom({ serverAddr: async () => ({ ipAddress: '::1', port: 443 }) }, '', 'x'));\n"
            "out.emptyRefused = await refuse(() => lib.assertServedFrom({ serverAddr: async () => null }, '192.168.64.2', 'x'));\n"
            "console.log(JSON.stringify(out));\n"
        )
        run_node = subprocess.run([node_binary, '--input-type=module', '-e', probe_src, str(ROOT / 'scripts/gate/browser-launch.mjs')], text=True, capture_output=True)
        try:
            node_out = json.loads(run_node.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            node_out = {}
        e(run_node.returncode == 0 and 'served from 192.168.64.2:443' in node_out.get('from', '')
          and node_out.get('loopbackRefused') is True and node_out.get('loopbackRefusedWithoutExpectation') is True
          and node_out.get('emptyRefused') is True,
          f'the served-address assertion accepts a valid asynchronous Response and refuses loopback and empty ones; browser certificate binding has its own full CDP/DER regression check; got rc {run_node.returncode}: {run_node.stderr.strip()[:200]!r} {node_out!r} (T08)')

    # T01 / T02 / T04: the runner's own functions run in bash against stubs. agent_request takes only the requester's stdout as the
    # response (its stderr announcement goes to the raw log), w5_published_any_ports reads the service label with a template
    # `docker inspect` accepts and fails closed, w6_response_fields reads all four lines of the helper's output.
    bash_t = bash_binary()
    runner_path = ROOT / 'scripts/gate-identity.sh'
    if bash_t is not None:
        import threading
        import time as _time

        def agent_request_case():
            with tempfile.TemporaryDirectory() as t01_tmp:
                base = Path(t01_tmp)
                rdv = base / 'rdv'
                rdv.mkdir()
                (base / 'state').mkdir()
                nonce = 'topofix2-t01-nonce'

                def responder():
                    deadline = _time.time() + 45
                    while _time.time() < deadline:
                        req = rdv / 'req-0001.json'
                        if req.exists():
                            data = json.loads(req.read_text())
                            envelope = {'schema': 1, 'id': data['id'], 'row': data['row'], 'nonce': data['nonce'], 'exit': 0,
                                        'stdout_tail': 'RESULT W6 rc=0 status=200 ua=krate-gate-w6-1 issuer=https://krate-oi.test/identity/realms/krate',
                                        'files': [], 'browser_json_sha256': '', 'mac_leak_scan': {'values': 0, 'hits': 0, 'stores': ['agent.log']},
                                        'agent_manifest': 'abc', 't_start': 'a', 't_end': 'b'}
                            (rdv / '.resp.tmp').write_text(json.dumps(envelope))
                            (rdv / '.resp.tmp').replace(rdv / 'resp-0001.json')
                            return
                        _time.sleep(0.1)

                worker = threading.Thread(target=responder, daemon=True)
                worker.start()
                script = ('RAW="$1"; STATE="$2"; RENDEZVOUS="$3"; REND_NONCE="$4"; GATE_DIR="$5"\n'
                          + bash_function_source(runner_path, 'agent_request')
                          + 'agent_request W6 30; echo "rc=$?" > "$STATE/rc.txt"; printf "%s" "$CAP" > "$STATE/cap.json"\n')
                subprocess.run([bash_t, '-c', script, 'bash', str(base / 'raw.log'), str(base / 'state'), str(rdv), nonce, str(ROOT / 'scripts/gate')],
                               text=True, capture_output=True, timeout=90)
                worker.join(timeout=5)
                cap_text = (base / 'state/cap.json').read_text() if (base / 'state/cap.json').exists() else ''
                raw_text = (base / 'raw.log').read_text() if (base / 'raw.log').exists() else ''
                rc_text = (base / 'state/rc.txt').read_text().strip() if (base / 'state/rc.txt').exists() else ''
                try:
                    parsed_cap = json.loads(cap_text)
                except ValueError:
                    parsed_cap = None
            return rc_text, parsed_cap, raw_text, nonce

        def agent_request_nonce_leak_case():
            with tempfile.TemporaryDirectory() as t01b_tmp:
                base = Path(t01b_tmp)
                (base / 'gate').mkdir()
                (base / 'state').mkdir()
                (base / 'gate/browser_remote.py').write_text(
                    'import sys\nnonce = sys.argv[sys.argv.index("--nonce") + 1]\nsys.stderr.write("diagnostic naming " + nonce + "\\n")\nprint(\'{"exit": 0}\')\n')
                script = ('RAW="$1"; STATE="$2"; RENDEZVOUS="$3"; REND_NONCE="$4"; GATE_DIR="$5"\n'
                          + bash_function_source(runner_path, 'agent_request')
                          + 'agent_request W6 5; printf "%s" "$CAP_ERR" > "$STATE/cap.err"\n')
                subprocess.run([bash_t, '-c', script, 'bash', str(base / 'raw.log'), str(base / 'state'), str(base), 'topofix2-t01b-nonce', str(base / 'gate')], text=True, capture_output=True, timeout=30)
                raw_text_b = (base / 'raw.log').read_text() if (base / 'raw.log').exists() else ''
                err_text_b = (base / 'state/cap.err').read_text() if (base / 'state/cap.err').exists() else ''
            return raw_text_b, err_text_b

        t01b_raw, t01b_err = agent_request_nonce_leak_case()
        e('diagnostic naming <rendezvous-nonce-redacted>' in t01b_err and 'topofix2-t01b-nonce' not in t01b_raw and 'topofix2-t01b-nonce' not in t01b_err,
          f'a requester that names the nonce on stderr leaks it neither into CAP_ERR nor into the raw log; got {t01b_err!r} / {t01b_raw[:160]!r} (T01)')
        t01_rc, t01_cap, t01_raw, t01_nonce = agent_request_case()
        e(t01_rc == 'rc=0' and isinstance(t01_cap, dict) and t01_cap.get('row') == 'W6' and t01_cap.get('nonce') == '<rendezvous-nonce-redacted>',
          f"agent_request saves the requester's stdout alone: a JSON response (nonce redacted), not text prefixed by the stderr announcement; got {t01_rc!r} {t01_cap!r} (T01)")
        e('written (nonce-bound)' in t01_raw and t01_nonce not in t01_raw,
          'the requester announcement (stderr) lands in the raw log, with the rendezvous nonce redacted (T01)')

        def w5_ports_case(containers):
            with tempfile.TemporaryDirectory() as t02_tmp:
                fake_bin = Path(t02_tmp)
                (fake_bin / 'docker').write_text(
                    '#!/bin/sh\n'
                    'case "$1" in\n'
                    '  ps) case "$*" in *krate-gate1*) printf "%s\\n" ' + ' '.join(containers.get('gate', [])) + ' ;; *monitoring*) printf "%s\\n" ' + ' '.join(containers.get('mon', [])) + ' ;; esac ;;\n'
                    '  inspect) tpl="$3"; cid="$4"\n'
                    '    case "$tpl" in *".Label "*) echo "template parsing error: template: :1:2: executing \\"\\" at <.Label>: Label is not a method but has arguments" >&2; exit 1 ;; esac\n'
                    '    case "$cid" in\n'
                    '      c1) echo "proxy|0.0.0.0:443 0.0.0.0:80 " ;;\n'
                    '      c2) echo "kafka|0.0.0.0:9092 127.0.0.1:19090 :::9093 " ;;\n'
                    '      c3) echo "grafana|127.0.0.1:13000 " ;;\n'
                    '      *) echo "Error: No such object: $cid" >&2; exit 1 ;;\n'
                    '    esac ;;\n'
                    'esac\n')
                (fake_bin / 'docker').chmod(0o755)
                script = ('RAW=/dev/null; PROJECT=krate-gate1; MON_PROJECT=krate-epc-monitoring\n' + bash_function_source(runner_path, 'w5_published_any_ports')
                          + 'out="$(w5_published_any_ports)"; rc=$?; printf "rc=%s\\n%s\\n" "$rc" "$out"\n')
                run = subprocess.run([bash_t, '-c', script], env=dict(os.environ, PATH=f'{fake_bin}:{os.environ["PATH"]}'), text=True, capture_output=True)
            return run.stdout.strip().splitlines()

        good_ports = w5_ports_case({'gate': ['c1', 'c2'], 'mon': ['c3']})
        e(good_ports[:1] == ['rc=0'] and sorted(good_ports[1:]) == ['kafka=9092', 'kafka=9093', 'proxy=443', 'proxy=80'],
          f'w5_published_any_ports derives the any-address published ports with the service labels from a docker inspect template that works; got {good_ports!r} (T02)')
        failed_ports = w5_ports_case({'gate': ['c1', 'c9'], 'mon': ['c3']})
        e(failed_ports[:1] == ['rc=1'] and 'docker inspect failed for [c9 ]' in ' '.join(failed_ports),
          f'w5_published_any_ports fails closed when a container cannot be inspected; got {failed_ports!r} (T02)')
        none_ports = w5_ports_case({})
        e(none_ports[:1] == ['rc=1'] and '0 container(s) were inspected' in ' '.join(none_ports),
          f'w5_published_any_ports fails closed when no container is listed (a derived set of only 22 would be a silent fallback); got {none_ports!r} (T02)')

        with tempfile.TemporaryDirectory() as t04_tmp:
            response_path = Path(t04_tmp) / 'w6-agent-response.json'
            response_path.write_text(json.dumps({'stdout_tail': 'RESULT W6 rc=0 status=200 ua=krate-gate-w6-0001 issuer=https://krate-oi.test/identity/realms/krate',
                                                  'mac_leak_scan': {'values': 0, 'hits': 0, 'stores': ['agent.log']}}))
            script = ('RAW=/dev/null\n' + bash_function_source(runner_path, 'w6_response_fields')
                      + 'w6_response_fields "$1" || echo FAILED; printf "%s|%s|%s|%s\\n" "$W6_STATUS" "$W6_UA" "$W6_ISSUER" "$W6_LEAK"\n')
            w6_fields = subprocess.run([bash_t, '-c', script, 'bash', str(response_path)], text=True, capture_output=True).stdout.strip()
        e(w6_fields == '200|krate-gate-w6-0001|https://krate-oi.test/identity/realms/krate|0 values, 0 hits',
          f'w6_response_fields reads all four lines of the helper output (status, ua, issuer, leak); got {w6_fields!r} (T04)')

        # T05 / T17: the runner's own W7 row runs against fake firewall-cmd, systemctl, sudo, ufw and iptables commands. The branch
        # follows the OS, a RHEL-family host without a running firewalld FAILs, and the docker zone's target must be ACCEPT.
        os_releases = {
            'rocky': 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.8"\n',
            'alma': 'ID="almalinux"\nID_LIKE="rhel centos fedora"\n',
            'ubuntu': 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n',
            'debian': 'ID=debian\n',
            'arch': 'ID=arch\n',
        }

        def w7_case(os_name, firewalld='active', with_firewall_cmd=True, docker_target='ACCEPT', ufw_status='Status: inactive', caller_locale='', sudo_works=True):
            with tempfile.TemporaryDirectory() as t05_tmp:
                base = Path(t05_tmp)
                fake_bin = base / 'bin'
                fake_bin.mkdir()
                (base / 'os-release').write_text(os_releases[os_name])
                scripts_text = {
                    'sudo': '[ "$1" = -n ] && shift\nexec "$@"' if sudo_works else 'exit 1',
                    'systemctl': 'case "$*" in "is-active firewalld") echo "${FAKE_FIREWALLD:-inactive}" ;; "is-active ufw") echo active ;; esac',
                    'ufw': 'if [ -n "$FAKE_LOCALIZED" ] && [ "$LC_ALL" != C ]; then echo "Estado: inactivo"; else echo "$FAKE_UFW_STATUS"; fi',
                    'iptables': 'echo "-P INPUT ACCEPT"',
                }
                if with_firewall_cmd:
                    scripts_text['firewall-cmd'] = (
                        'case "$*" in\n'
                        '  *--get-default-zone*) echo public ;;\n'
                        '  *--get-zone-of-interface=lima0*) echo public ;;\n'
                        '  *--get-zone-of-interface=*) echo docker ;;\n'
                        '  *--list-services*) echo "cockpit dhcpv6-client ssh" ;;\n'
                        '  *--get-policies*) echo "allow-host-ipv6 docker-forwarding docker-to-host" ;;\n'
                        '  *--info-zone=docker*) key=target; if [ -n "$FAKE_LOCALIZED" ] && [ "$LC_ALL" != C ]; then key=objetivo; fi\n'
                        '    printf "docker (active)\\n  %s: %s\\n  icmp-block-inversion: no\\n" "$key" "$FAKE_DOCKER_TARGET" ;;\n'
                        'esac')
                for name, body in scripts_text.items():
                    (fake_bin / name).write_text('#!/bin/sh\n' + body + '\n')
                    (fake_bin / name).chmod(0o755)
                (base / 'krate').write_text('#!/bin/sh\necho "[ok] firewalld active, docker zone present (target ACCEPT)"\n')
                (base / 'krate').chmod(0o755)
                script = ('section() { :; }\nrecord() { printf "RECORD %s|%s\\n" "$4" "$5"; }\nRAW=/dev/null; KRATE="$1"\n'
                          'command() { if [[ "$1" == -v && "$2" == firewall-cmd ]]; then [[ -n "${FAKE_FWCMD_PATH:-}" ]] || return 1; echo "$FAKE_FWCMD_PATH"; return 0; fi; builtin command "$@"; }\n'
                          + bash_function_source(runner_path, 'w7_os_family') + bash_function_source(runner_path, 'phase4_row_w7')
                          + 'phase4_row_w7 4c "$2"\n')
                env = dict(os.environ, PATH=f'{fake_bin}:{os.environ["PATH"]}', FAKE_FIREWALLD=firewalld, FAKE_DOCKER_TARGET=docker_target, FAKE_UFW_STATUS=ufw_status,
                           FAKE_FWCMD_PATH=str(fake_bin / 'firewall-cmd') if with_firewall_cmd else '', FAKE_LOCALIZED='1' if caller_locale else '')
                if caller_locale:
                    env['LC_ALL'] = caller_locale
                run = subprocess.run([bash_t, '-c', script, 'bash', str(base / 'krate'), str(base / 'os-release')], env=env, text=True, capture_output=True)
            return (run.stdout + run.stderr).strip()

        family_script = bash_function_source(runner_path, 'w7_os_family') + 'w7_os_family "$1"\n'
        for id_only, wanted in (('ID=rhel', 'rhel'), ('ID="rocky"', 'rhel'), ('ID=almalinux', 'rhel'), ('ID=centos', 'rhel'), ('ID=fedora', 'rhel'), ('ID=ol\nID_LIKE="fedora"', 'rhel'),
                                ('ID=ubuntu', 'debian'), ('ID=debian', 'debian'), ('ID=linuxmint\nID_LIKE="ubuntu debian"', 'debian'), ('ID=arch', 'unknown'), ('NAME=x', 'unknown')):
            with tempfile.TemporaryDirectory() as fam_tmp:
                (Path(fam_tmp) / 'os-release').write_text(id_only + '\n')
                got_family = subprocess.run([bash_t, '-c', family_script, 'bash', str(Path(fam_tmp) / 'os-release')], text=True, capture_output=True).stdout.strip()
            e(got_family == wanted, f'w7_os_family reads {id_only!r} as {wanted}; got {got_family!r} (T05)')
        e(w7_case('rocky').startswith('RECORD PASS|') and 'docker zone target [ACCEPT]' in w7_case('rocky'),
          f'W7 on a Rocky fixture with a running firewalld and the docker zone ACCEPT passes and records the target; got {w7_case("rocky")[:300]!r} (T17)')
        e(w7_case('alma').startswith('RECORD PASS|'), 'W7 treats AlmaLinux (ID_LIKE rhel) as the firewalld branch (T05)')
        for bad_target in ('DROP', 'REJECT', ''):
            out_t = w7_case('rocky', docker_target=bad_target)
            e(out_t.startswith('RECORD FAIL|') and f'docker zone target [{bad_target or "unknown"}]' in out_t,
              f'W7 fails when the docker zone target is {bad_target or "unreadable"} instead of ACCEPT; got {out_t[:260]!r} (T17)')
        out_stopped = w7_case('rocky', firewalld='inactive')
        e(out_stopped.startswith('RECORD FAIL|') and 'RHEL-family fixture without a running firewalld' in out_stopped,
          f'W7 FAILs a Rocky fixture whose firewalld stopped instead of falling into the ufw shape; got {out_stopped[:260]!r} (T05)')
        out_missing = w7_case('rocky', firewalld='inactive', with_firewall_cmd=False)
        e(out_missing.startswith('RECORD FAIL|') and 'RHEL-family fixture without a running firewalld' in out_missing,
          f'W7 FAILs a Rocky fixture without firewall-cmd; got {out_missing[:260]!r} (T05)')
        e(w7_case('ubuntu', firewalld='inactive', with_firewall_cmd=False).startswith('RECORD PASS|'), 'W7 passes an Ubuntu fixture whose ufw is inactive, whatever the ufw.service state says (T05/PRE-4)')
        e(w7_case('debian', firewalld='inactive', with_firewall_cmd=False, ufw_status='Status: active').startswith('RECORD FAIL|'), 'W7 fails a Debian-family fixture whose ufw is active (T05)')
        out_unknown = w7_case('arch', firewalld='inactive', with_firewall_cmd=False)
        e(out_unknown.startswith('RECORD FAIL|') and 'unsupported fixture OS' in out_unknown, f'W7 FAILs an unsupported OS (T05); got {out_unknown[:200]!r}')
        # T06 / R3 on the whole row: a caller in another locale, a fake firewall-cmd and ufw that answer in a translated form unless LC_ALL=C
        out_loc_rhel = w7_case('rocky', caller_locale='de_DE.UTF-8')
        e(out_loc_rhel.startswith('RECORD PASS|') and 'docker zone target [ACCEPT]' in out_loc_rhel,
          f'W7 on a RHEL-family fixture reads the firewall-cmd output under LC_ALL=C whatever the caller locale is; got {out_loc_rhel[:240]!r} (R3)')
        out_loc_plain = w7_case('rocky', caller_locale='de_DE.UTF-8', sudo_works=False)
        e(out_loc_plain.startswith('RECORD PASS|') and 'docker zone target [ACCEPT]' in out_loc_plain,
          f'W7 on a RHEL-family fixture reads the firewall-cmd output under LC_ALL=C on the no-sudo arm too; got {out_loc_plain[:240]!r} (R3)')
        out_loc_ubuntu = w7_case('ubuntu', firewalld='inactive', with_firewall_cmd=False, caller_locale='de_DE.UTF-8')
        e(out_loc_ubuntu.startswith('RECORD PASS|') and 'ufw status first line [Status: inactive]' in out_loc_ubuntu,
          f'W7 on an Ubuntu fixture reads ufw status under LC_ALL=C whatever the caller locale is; got {out_loc_ubuntu[:240]!r} (T06, R3)')
        for locale_line in ('fwcmd=(sudo -n env LC_ALL=C firewall-cmd)', 'sudo -n true 2>/dev/null || fwcmd=(env LC_ALL=C firewall-cmd)',
                            'ufw_status="$( { sudo -n env LC_ALL=C ufw status verbose 2>/dev/null || LC_ALL=C ufw status verbose 2>/dev/null; } | head -4 | tr \'\\n\' \' \' || true)"',
                            'input_head="$(sudo -n env LC_ALL=C iptables -S INPUT 2>/dev/null | head -1 || true)"'):
            e(locale_line in topo_runner_lines, f'W7 carries the code line {locale_line!r}: every firewall command whose output it prints or parses runs under LC_ALL=C (T06, R3)')
        e('every firewall command the row reads runs under `LC_ALL=C`, so a translated ufw or firewalld catalogue cannot change what it parses' in ' '.join(guide_text.split()),
          'the guide says W7 reads its firewall commands under LC_ALL=C (T06, R3)')
    e('local os_family fw_active=false' in topo_runner_text and 'elif [[ "$os_family" == rhel ]] && ! $fw_active; then' in topo_runner_text
      and "docker_target=\"$(\"${fwcmd[@]}\" --info-zone=docker" in topo_runner_text and '[[ "$docker_target" == ACCEPT ]] || st=1' in topo_runner_text,
      'W7 selects its branch from the OS and checks the docker zone target (T05, T17)')

    # T18 / T11: the agent serves only the selected plan, each row once, and trusts no id before it is an integer 1..9999 equal to
    # the id of the request's own file name; all of that runs in claimRequest, before execute() and runRow() can use the id in a path.
    for line in (
        'for (const planned of PLAN) {',
        'if (new Set(PLAN).size !== PLAN.length) die(`--rows names a row twice: ${PLAN.join(\',\')}`);',
        'public_host: PUBLIC_HOST, ports: PORTS, plan: PLAN,',
        "if (typeof parsed.row !== 'string' || !PLAN.includes(parsed.row)) {",
        'if (servedRows.has(parsed.row)) {',
        'servedRows.add(req.row);',
        'if (parsed.id !== Number(file.slice(4, 8))) {',
    ):
        e(line in agent_lines, f'agent.mjs must carry the code line {line!r} (T18/T11)')
    e(any(ln.startswith('if (!Object.hasOwn(ROWS, planned)) die(') for ln in agent_lines) and 'ROWS[parsed.row]' not in agent_code,
      'agent.mjs refuses a --rows entry that is not an own row of the table and no longer admits a request by ROWS[parsed.row] (T18: --rows W6 must not allow W5; "__proto__" is not a row)')
    claim_start = agent_lines.index('function claimRequest(file) {') if 'function claimRequest(file) {' in agent_lines else -1
    claim_end = next((i for i, ln in enumerate(agent_lines) if ln.startswith('return { req: parsed, claimedPath: claimed };')), -1)
    claim_body = agent_lines[claim_start:claim_end] if 0 <= claim_start < claim_end else []
    marks = [next((i for i, ln in enumerate(claim_body) if ln.startswith(token)), -1) for token in (
        'if (!Number.isInteger(parsed.id) || parsed.id < 1 || parsed.id > 9999) {',
        'if (parsed.id !== Number(file.slice(4, 8))) {',
        "if (typeof parsed.row !== 'string' || !PLAN.includes(parsed.row)) {",
        'if (servedRows.has(parsed.row)) {')]
    e(all(m >= 0 for m in marks) and marks == sorted(marks),
      'claimRequest validates the id (integer 1..9999, equal to its file name) and then the row (in the plan, not yet served) before it returns a request for execute() (T11, T18)')
    id_path_uses = [ln for ln in agent_lines if re.search(r'\b(?:req|parsed)\.id\b', ln) and ('join(' in ln or '${' in ln or 'resp-' in ln) and not ln.startswith('return { bad:')]
    e(len(id_path_uses) == 2 and any(ln.startswith('const outDir = join(TMP, `${req.id}-${sub}`);') for ln in id_path_uses)
      and any(ln.startswith("guestPut(`resp-${String(req.id).padStart(4, '0')}.json`") for ln in id_path_uses),
      f'the request id reaches a path in exactly two places, runRow\'s scratch folder and the response name, both after claimRequest validated it; found {id_path_uses!r} (T11)')

    # T07 / T21 / T20: the external-request guard is context-wide and installed before the first navigation of every story (and U15,
    # whose interstitial acceptance is already a page load); no story registers a tracker late or page by page; a failed evidence
    # collection fails U15 in the Mac vantage.
    for line in ('async guard(ownedContext) {',
                 "session.on('Fetch.requestPaused', onPaused);",
                 "await command('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] });",
                 'await context.routeWebSocket((url) => url.hostname !== host, (ws) => {',
                 'attachContext(context) { for (const p of context.pages()) hook(p); context.on(\'page\', hook); return this; },'):
        e(line in launch_lines, f'browser-launch.mjs must carry the code line {line!r} (T07/T21: browser-root HTTP interception and the existing page-WebSocket layer; worker WebSockets remain unproven)')
    for guarded, guard_line, ctx_name, first_nav in (
        ('screenshots.mjs', 'if (ext) { await ext.guard(ctx); serve.attachContext(ctx); }', 'ctx', 'acceptGateCertificate('),
        ('screenshots-grafana.mjs', 'if (ext) { await ext.guard(ctx); serve.attachContext(ctx); }', 'ctx', 'const decision = await acceptGateCertificate('),
        ('screenshots-perses.mjs', 'if (ext) { await ext.guard(ctx); serve.attachContext(ctx); }', 'ctx', 'const decision = await acceptGateCertificate('),
        ('phase4-browser.mjs', 'if (MAC) { await ext.guard(context); serve.attachContext(context); }', 'context', 'const accepted = await acceptGateCertificate('),
    ):
        guarded_text = (ROOT / 'scripts/gate' / guarded).read_text()
        guarded_lines = js_lines(guarded_text)
        guard_at = guarded_lines.index(guard_line) if guard_line in guarded_lines else -1
        nav_at = next((i for i, ln in enumerate(guarded_lines) if first_nav in ln and not ln.startswith('import ')), -1)
        e(guard_at >= 0 and (nav_at < 0 or guard_at < nav_at),
          f'{guarded} installs the context-wide guard ({guard_line!r}) before its first navigation (T07, T21)')
        e('ext.onFailed' not in guarded_text and not re.search(r'serve\.attach\(', guarded_text) and not re.search(r"\.on\('requestfailed', \(r\) => ext", guarded_text),
          f'{guarded} registers no tracker page by page or after a navigation (T07, T21: the Admin and later pages are covered by the context)')
    e("recordFailure('browser evidence failed', e);" in u15_lines
      and "recordFailure('browser.json not written', e);" in u15_lines
      and 'process.exitCode = 1;' in u15_lines,
      'phase4-browser.mjs (U15) records failed live evidence and browser.json writes through its common nonzero failure path (T20; shipped lifecycle cases execute both)')
    # The standalone check_browser_http_guard executes the actual shipped export and\n    # redirect pause/terminal lifecycle cases; context.route alone cannot check a redirect hop.\n\n    # R6: the rendezvous nonce binds the run and reaches no log. The agent's stdout and stderr are the Mac receipt's agent.log. Three pins: the
    # ready line is run with a known nonce in scope and must not print it; the agent code names the nonce in exactly four enumerated lines (its
    # definition, the hello, the request check, the response), so any new mention, in a log call or elsewhere, needs a conscious pin edit; and
    # no log call (console, die, throw) dumps a whole object that holds it (the hello, the response, the request, the parsed flags, argv).
    ready_line = ("console.log(`agent: ready vm=${VM} vm_ip=${STATE.vmIp} mac_src_ip=${srcIp} iface=${iface} g6=${g6 || 'none'} "
                  "plan=${PLAN.join(',')} nonce=bound`);")
    e(ready_line in agent_lines, 'agent.mjs prints its ready line with `nonce=bound`, never the value (R6, review N6)')
    ready_actual = next((ln for ln in agent_lines if ln.startswith('console.log(`agent: ready ')), '')   # whatever the line says, it is what runs below
    e(bool(ready_actual), 'agent.mjs has a ready line to run (R6)')
    if node_binary and ready_actual:
        r6_secret = 'r6-secret-nonce-value-0123456789'
        r6_run = subprocess.run([node_binary, '-e',
                                 f"const VM='vm', STATE={{vmIp:'192.168.64.2'}}, srcIp='192.168.64.1', iface='bridge100', g6='', PLAN=['W5','W6'], NONCE='{r6_secret}';\n{ready_actual}\n"],
                                text=True, capture_output=True)
        e(r6_run.returncode == 0 and 'nonce=bound' in r6_run.stdout and r6_secret not in r6_run.stdout + r6_run.stderr,
          f'the agent ready line, run with a nonce in scope, prints nonce=bound and not the nonce; got rc {r6_run.returncode}: {r6_run.stdout.strip()[:200]!r} (R6)')
    agent_nonce_refs = [ln for ln in agent_lines if re.search(r"\bNONCE\b|args\[.rendezvous-nonce.\]|\.nonce\b", ln)]
    e(len(agent_nonce_refs) == 4 and agent_nonce_refs[0].startswith("const NONCE = args['rendezvous-nonce'] || die('--rendezvous-nonce is required ")
      and agent_nonce_refs[1:] == ['schema: 1, t: new Date().toISOString(), seq: ++helloSeq, pid: process.pid, nonce: NONCE,',
                                   'if (parsed.schema !== 1 || parsed.nonce !== NONCE) {',
                                   'schema: 1, id: req.id, row: req.row, nonce: NONCE,'],
      f'agent.mjs names the rendezvous nonce in exactly its definition, the hello, the request check and the response; found {agent_nonce_refs!r} (R6)')

    def code_without_literals(js_line):
        """A JS line with string literals removed and each template literal reduced to its ${...} expressions (what a log call can print besides fixed text)."""
        out = re.sub(r"`(?:[^`\\]|\\.)*`", lambda m: ' '.join(re.findall(r"\$\{(.*?)\}", m.group(0))), js_line)
        return re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", "''", out)

    agent_log_calls = [ln for ln in agent_lines if re.search(r"\bconsole\.(?:log|error|warn|info|debug)\(|\bdie\(|process\.std(?:out|err)\.write\(|\bthrow new Error\(", ln)]
    agent_dumps = [ln for ln in agent_log_calls
                   if re.search(r"(?<![\w.])(?:hello|resp|req|parsed|claim|args|SECRETS|argvPairs)\b(?![\w.\[])|process\.argv|process\.env\b(?!\.)", code_without_literals(ln))]
    e(len(agent_log_calls) >= 10 and not agent_dumps, f'no agent log call (console, die, throw) prints a whole hello, response, request, flags, argv or environment object; found {agent_dumps!r} (R6)')
    e(not [ln for ln in launcher_lines if not ln.startswith('limactl shell') and re.search(r"\b(?:echo|printf)\b[^;|]*\$\{?(?:NONCE|GUEST_CMD)\b", ln)],
      'run-vm-gate.sh echoes neither $NONCE nor $GUEST_CMD (the guest command carries the nonce) (R6)')

    # R4: guest-derived text (a file name, a JSON key or value, a command's stderr) reaches agent.log only through clip(): cut to a limit and
    # JSON-quoted, so a hostile guest can neither fill the log nor start a line that reads like the agent's own (`agent: W6 req=1 exit=0 ...`).
    clip_line = 'function clip(value, limit = 120) { return JSON.stringify(String(value).slice(0, limit)); }'
    e(clip_line in agent_lines, 'agent.mjs defines clip(value, limit): the only way guest text reaches its log (R4)')
    for line in ("return { bad: `refused: unreadable or unparseable request ${file}: ${clip(e.message || e, 80)}` };",
                 "return { bad: `refused: the guest request carries the keys ${clip(keys)}; the protocol is exactly {schema,id,row,nonce} (F4)` };",
                 "return { bad: `refused: row ${clip(parsed.row)} is not in this run's plan: ${PLAN.join(', ')}` };"):
        e(line in agent_lines, f'agent.mjs must carry the code line {line!r} (R4: the guest-supplied key list, row and parse message go through clip())')
    e(not [ln for ln in agent_lines if re.search(r"\be\.message\b", ln) and re.search(r"console\.|\bdie\(|\bbad:", ln) and 'clip(' not in ln],
      'no agent.mjs log line (console, die, a refusal text) prints an exception message without clip(); the one e.message that is not logged goes into the response tail (R4)')
    clip_actual = next((ln for ln in agent_lines if ln.startswith('function clip(')), '')
    if node_binary and clip_actual:
        clip_run = subprocess.run([node_binary, '-e', clip_actual + r"""
const forged = 'x\nagent: W6 req=1 exit=0 files=0 manifest=abc\n' + 'A'.repeat(70000);
const out = clip(forged);
console.log(JSON.stringify({ length: out.length, newline: out.includes('\n'), parsed: JSON.parse(out).length, small: clip('ab'), num: clip(7, 5) }));
"""], text=True, capture_output=True)
        try:
            clip_out = json.loads(clip_run.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            clip_out = {}
        e(clip_run.returncode == 0 and clip_out.get('parsed') == 120 and clip_out.get('length', 999) <= 130 and clip_out.get('newline') is False
          and clip_out.get('small') == '"ab"' and clip_out.get('num') == '"7"',
          f'clip() cuts a 70 KB guest text with newlines to 120 characters, escapes the newlines and quotes the result; got rc {clip_run.returncode}: {clip_out!r} {clip_run.stderr.strip()[:160]!r} (R4)')

    # R5: the guest read confines the RESOLVED file to the RESOLVED directory by path components (`"$d"/*`), not by a substring match. The
    # function's own text runs in node against a stub GNU `realpath -e` (macOS has none) in a temp tree: a file inside, a sibling directory
    # that merely starts with the directory's name, a directory that is itself reached through a symlink, a symlink pointing out, a missing file.
    e('grep -F -- ${q(mustBeUnder)}' not in agent_code, 'agent.mjs no longer confines a guest read with a substring match (grep -F) (R5)')

    def js_function_source(text, name):
        match = re.search(r'^function ' + re.escape(name) + r'\([^\n]*\n', text, re.M)
        if match is None:
            raise ValueError(f'agent.mjs: function {name} not found')
        if match.group(0).count('{') == match.group(0).count('}'):
            return match.group(0)
        return text[match.start():text.index('\n}\n', match.start()) + 3]

    if node_binary:
        with tempfile.TemporaryDirectory() as r5_tmp:
            base = Path(r5_tmp)
            (base / 'bin').mkdir()
            (base / 'bin/realpath').write_text('#!/bin/sh\n[ "$1" = -e ] && shift\n[ "$1" = -- ] && shift\nexec "%s" -I -c \'import os, sys\nif not os.path.exists(sys.argv[1]): sys.exit(1)\nprint(os.path.realpath(sys.argv[1]))\' "$1"\n' % sys.executable)
            (base / 'bin/realpath').chmod(0o755)
            (base / 'rdv').mkdir()
            (base / 'rdv/req-0001.json').write_text('{"a":1}')
            (base / 'rdv-other').mkdir()
            (base / 'rdv-other/req-0001.json').write_text('{"other":1}')
            (base / 'real').mkdir()
            (base / 'real/req-0001.json').write_text('{"a":1}')
            os.symlink(base / 'real', base / 'link')
            (base / 'secret.txt').write_text('SECRET')
            os.symlink(base / 'secret.txt', base / 'rdv/evil')
            (base / 'cert.pem').write_text('CERT')
            r5_script = (
                "import { spawnSync } from 'node:child_process';\nimport { posix } from 'node:path';\nconst READ_CAP_BYTES = 65536;\n"
                "function die(m) { throw new Error(m); }\n"
                "function guestSh(script, opts = {}) { const r = spawnSync('sh', ['-c', script], { encoding: 'utf8' }); if (r.status !== 0 && !opts.allowFail) throw new Error('exit ' + r.status); return { out: r.stdout || '', status: r.status }; }\n"
                + next((ln for ln in agent_lines if ln.startswith('const GUEST_PATH_RE = ')), 'const GUEST_PATH_RE = /(?!)/;') + '\n'
                + js_function_source(agent_text, 'guestPath') + js_function_source(agent_text, 'q') + js_function_source(agent_text, 'guestReadFile')
                + "const T = process.argv[1];\nconst out = {};\n"
                  "const tryRead = (p, under) => { try { return guestReadFile(p, under).toString('utf8'); } catch (e) { return 'THROWS'; } };\n"
                  "out.inside = tryRead(`${T}/rdv/req-0001.json`, `${T}/rdv`);\n"
                  "out.siblingWithSamePrefix = tryRead(`${T}/rdv-other/req-0001.json`, `${T}/rdv`);\n"
                  "out.symlinkedDirectory = tryRead(`${T}/link/req-0001.json`, `${T}/link`);\n"
                  "out.symlinkPointingOut = tryRead(`${T}/rdv/evil`, `${T}/rdv`);\n"
                  "out.missing = tryRead(`${T}/rdv/nope.json`, `${T}/rdv`);\n"
                  "out.unconfined = tryRead(`${T}/cert.pem`, null);\n"
                  "console.log(JSON.stringify(out));\n")
            r5_run = subprocess.run([node_binary, '--input-type=module', '-e', r5_script, str(base)], env=dict(os.environ, PATH=f'{base / "bin"}:{os.environ["PATH"]}'), text=True, capture_output=True, timeout=60)
            try:
                r5_out = json.loads(r5_run.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                r5_out = {}
            e(r5_out == {'inside': '{"a":1}', 'siblingWithSamePrefix': '', 'symlinkedDirectory': '{"a":1}', 'symlinkPointingOut': '', 'missing': 'THROWS', 'unconfined': 'CERT'},
              f'the guest read returns a file inside the directory (also one reached through a symlinked directory) and nothing for a sibling that shares the name prefix or a symlink that points out; got rc {r5_run.returncode}: {r5_out!r} {r5_run.stderr.strip()[:200]!r} (R5)')

    # R7: the OS branch of W7 follows an argument, never the operator's environment: the row's one call site passes no file, and an
    # OS_RELEASE_FILE in the environment changes nothing.
    e('os_family="$(w7_os_family "${2:-/etc/os-release}")"' in topo_runner_lines and 'OS_RELEASE_FILE' not in topo_runner_text,
      'W7 takes the os-release file as an argument (default /etc/os-release) and the runner reads no OS_RELEASE_FILE variable (R7)')
    if bash_t is not None:
        with tempfile.TemporaryDirectory() as r7_tmp:
            (Path(r7_tmp) / 'rhel').write_text('ID=rocky\n')
            (Path(r7_tmp) / 'deb').write_text('ID=ubuntu\n')
            r7_script = bash_function_source(runner_path, 'w7_os_family') + 'w7_os_family "$1"\n'
            r7_run = subprocess.run([bash_t, '-c', r7_script, 'bash', str(Path(r7_tmp) / 'deb')], env=dict(os.environ, OS_RELEASE_FILE=str(Path(r7_tmp) / 'rhel')), text=True, capture_output=True)
        e(r7_run.stdout.strip() == 'debian', f'w7_os_family reads the file it is given and ignores OS_RELEASE_FILE in the environment; got {r7_run.stdout.strip()!r} (R7)')

        # R8: a failed agent request keeps the TAIL of the requester's stderr (the cause, `no response in N s`, comes last, behind the line
        # it repeats every 2 s while a row runs); `${s: -n}` alone is empty for a string shorter than n, so the cut is a function.
        tail_src = bash_function_source(runner_path, 'tail_chars')

        def tail_case(count, text):
            return subprocess.run([bash_t, '-c', tail_src + 'tail_chars "$1" "$2"', 'bash', str(count), text], text=True, capture_output=True).stdout

        e(tail_case(10, 'short') == 'short' and tail_case(5, '12345') == '12345' and tail_case(5, '1234567890') == '...67890' and tail_case(5, '') == '',
          'tail_chars keeps a short text whole and the last n characters of a long one behind ... (R8)')
        repeated = 'browser_remote: the request /g/rdv/req-0001.json disappeared without a response (the agent agent log holds the refusal)\n'
        cause = 'browser_remote: no response in 1500 s (hello age 3 s; heartbeat expected every 15 s)\n'
        e('no response in 1500 s' in tail_case(300, repeated * 40 + cause) and 'no response in 1500 s' not in (repeated * 40 + cause)[:300],
          'the failure record keeps the cause at the end of a long requester stderr, which the first 300 characters never reach (R8)')
        e(topo_runner_text.count('$(tail_chars 300 "$CAP_ERR")') == 2 and '${CAP_ERR:0:' not in topo_runner_text,
          'the W5 and W6 failure records quote the tail of the requester stderr, not its first 300 characters (R8)')

    # R12: the delivery target is validated twice (it sits under --guest-root, and it is a plain normalized guest path) before it reaches limactl.
    for line in ("if (!guestDir.startsWith(GUEST_ROOT + '/')) die(`agent: refusing to deliver outside --guest-root: ${guestDir}`);",
                 "sh('limactl', ['copy', '--backend=scp', '-r', localDir, `${VM}:${guestPath('delivery target', guestDir)}`], { timeout: 180000 });"):
        e(line in agent_lines, f'agent.mjs must carry the code line {line!r} (R12: the delivery target is a validated guest path under --guest-root)')

    # T14: the launcher returns success only for a candidate-bound PASS: the guest runner's own exit status (written beside its pid when
    # it ends) and the harvested receipt's verdict row and candidate commit. Its own functions run on receipt fixtures; the launch line
    # (setsid removed, macOS has none) runs behind a fake limactl to prove the exit status is really recorded.
    launcher_path = ROOT / 'scripts/gate/mac/run-vm-gate.sh'
    candidate_sha = '0123456789abcdef0123456789abcdef01234567'
    if bash_t is not None:
        launcher_funcs = ''.join(bash_function_source(launcher_path, name) for name in ('receipt_verdict', 'receipt_candidate_ok', 'run_outcome'))

        def outcome_case(runner_rc, receipt_text, candidate=candidate_sha):
            with tempfile.TemporaryDirectory() as t14_tmp:
                receipt = Path(t14_tmp) / 'receipt.md'
                if receipt_text is not None:
                    receipt.write_text(receipt_text)
                script = launcher_funcs + 'reason="$(run_outcome "$1" "$2" "$3")"; rc=$?; printf "%s|%s\\n" "$rc" "$reason"\n'
                run = subprocess.run([bash_t, '-c', script, 'bash', runner_rc, str(receipt), candidate], text=True, capture_output=True)
            return run.stdout.strip()

        def receipt_text(verdict='PASS', commit=candidate_sha):
            return (f'| field | value |\n|---|---|\n| verdict | **{verdict}** (PASS 70, FAIL 0, NOT_RUN 0, required missing 0: none; bound: true) |\n'
                    f'| candidate commit | {commit} (stated as {commit[:7]} and resolved in --repo) |\n')

        e(outcome_case('0', receipt_text()) == '0|', f'a guest runner exit 0 with a PASS receipt of the launcher candidate is a success; got {outcome_case("0", receipt_text())!r} (T14)')
        e(outcome_case('0', receipt_text(commit=candidate_sha[:7] + 'f' * 33)) .startswith('1|the receipt') and 'candidate commit' in outcome_case('0', receipt_text(commit=candidate_sha[:7] + 'f' * 33)),
          'a PASS receipt of another candidate commit is a failure (T14)')
        e(outcome_case('garbage', receipt_text()) == '1|the guest runner left no exit status (it was killed before it finished)',
          'a runner that left no numeric exit status (killed, stale or garbage) is a failure (T14)')
        e(outcome_case('', receipt_text()) == '1|the guest runner left no exit status (it was killed before it finished)', 'an empty runner exit status is a failure (T14)')
        e(outcome_case('1', receipt_text()) == '1|the guest runner exited 1', 'a non-zero runner exit status is a failure even beside a PASS receipt (T14)')
        e(outcome_case('0', receipt_text('FAIL')) == "1|the receipt verdict is 'FAIL', not PASS", 'a FAIL receipt is a failure (T14)')
        e(outcome_case('0', receipt_text('INCOMPLETE')) == "1|the receipt verdict is 'INCOMPLETE', not PASS", 'an INCOMPLETE receipt is a failure (T14)')
        e(outcome_case('0', None) == '1|no harvested receipt.md', 'a missing receipt is a failure (T14)')
        e(outcome_case('0', '| field | value |\n|---|---|\n| candidate commit | ' + candidate_sha + ' |\n') == "1|the receipt verdict is 'missing', not PASS",
          'an unfinished receipt without a verdict row is a failure (T14)')
        launcher_raw = launcher_path.read_text()
        launch_line = next((ln for ln in launcher_raw.splitlines() if ln.startswith('limactl shell "$VM" -- sh -c "nohup setsid sh -c $(printf')), '')
        e(bool(launch_line), 'the launcher keeps its detached guest command line (T14 test anchor)')
        if launch_line:
            with tempfile.TemporaryDirectory() as t14_launch:
                base = Path(t14_launch)
                (base / 'bin').mkdir()
                (base / 'bin/limactl').write_text('#!/bin/sh\n[ "$1" = shell ] || exit 9\nshift; shift\n[ "$1" = -- ] && shift\nexec "$@"\n')
                (base / 'bin/limactl').chmod(0o755)
                (base / 'rdv').mkdir()
                results = {}
                # `(exit 7)` fails with the same status in every sh; a failed `cd` is 1 in bash's sh but 2 in dash
                # (Ubuntu's /bin/sh, as on the CI runner), so that case only has to record some non-zero status.
                for name, guest_cmd in (('pass', 'true'), ('fail', '(exit 7)'), ('cd', 'cd /nonexistent-for-the-check && true')):
                    sub_rdv = base / name
                    sub_rdv.mkdir()
                    script = ('VM=fake; GUEST_ROOT="$1"; RDV="$2"; CANDIDATE=0123456789abcdef; GUEST_CMD="$3"\n' + launch_line.replace('nohup setsid sh', 'nohup sh') + '\n'
                              'for _ in $(seq 1 50); do [ -s "$RDV/runner.rc" ] && break; sleep 0.1; done; printf "%s|%s" "$(cat "$RDV/runner.rc" 2>/dev/null)" "$(test -s "$RDV/runner.pid" && echo pid)"\n')
                    run = subprocess.run([bash_t, '-c', script, 'bash', str(base), str(sub_rdv), guest_cmd], env=dict(os.environ, PATH=f'{base / "bin"}:{os.environ["PATH"]}'), text=True, capture_output=True, timeout=30)
                    results[name] = run.stdout.strip()
            e(results.get('pass') == '0|pid' and results.get('fail') == '7|pid'
              and re.fullmatch(r'[1-9][0-9]*\|pid', results.get('cd', '')) is not None,
              f"the launcher's detached guest command records the runner's exit status beside its pid (0 for a pass, the failure status otherwise); got {results!r} (T14)")
    e('RUNNER_RC="$(limactl shell "$VM" -- cat "$RDV/runner.rc" 2>/dev/null | tr -d \'[:space:]\' || true)"' in launcher_lines, 'the launcher reads the runner exit status from the guest and survives a missing runner.rc (T14, R2)')
    # T12 (rest): the hello wait is for THIS run's nonce, not any non-empty file (a previous run's hello would pass `test -s`).
    # T13 (rest): the guest checkout must be at the candidate before the agent starts.
    e('GUEST_HEAD="$(limactl shell "$VM" -- git -C "$GUEST_ROOT/repo" rev-parse HEAD 2>/dev/null | tr -d \'[:space:]\' || true)"' in launcher_lines
      and 'guest_head_is_candidate "$GUEST_HEAD" "$CANDIDATE" \\' in [ln.strip() for ln in (ROOT / 'scripts/gate/mac/run-vm-gate.sh').read_text().splitlines()]
      and launcher_lines.index('NONCE="$(openssl rand -hex 16)"') > launcher_lines.index('GUEST_HEAD="$(limactl shell "$VM" -- git -C "$GUEST_ROOT/repo" rev-parse HEAD 2>/dev/null | tr -d \'[:space:]\' || true)"'),
      'the launcher reads the guest checkout HEAD and refuses a checkout that is not the candidate before it starts the agent (T13)')
    if bash_t is not None:
        head_funcs = bash_function_source(launcher_path, 'guest_head_is_candidate')

        def head_case(head, candidate):
            return subprocess.run([bash_t, '-c', head_funcs + 'guest_head_is_candidate "$1" "$2"; echo $?', 'bash', head, candidate], text=True, capture_output=True).stdout.strip()

        e(head_case(candidate_sha, candidate_sha) == '0' and head_case(candidate_sha, candidate_sha[:9]) == '0'
          and head_case('', candidate_sha) == '1' and head_case('f' + candidate_sha[1:], candidate_sha) == '1' and head_case(candidate_sha, 'f' + candidate_sha[1:]) == '1',
          'guest_head_is_candidate accepts the candidate (full or abbreviated) and refuses an unreadable or different HEAD (T13)')

        # R1 (launcher half): the delivery folder starts every run empty. `limactl copy -r DIR VM:agent-out/w5` nests DIR inside an
        # existing agent-out/w5, so a stale w5-result.json from an earlier run would stay where the runner reads it. The launcher's own two
        # guest lines (the rm and the mkdir) run behind a fake limactl that permits only rm and mkdir under the temp guest root and never
        # anything else; the delivery itself is stood in for by `cp -R DIR agent-out/w5`, which nests into an existing destination as scp -r
        # does (observed with scp in harness/phase4-completion/raw/TOPOFIX2-REVIEW/scp-sem). The CONTROL (mkdir line only) must show the
        # stale file surviving, or this harness would prove nothing.
        launcher_all = launcher_path.read_text().splitlines()
        rm_line = next((ln for ln in launcher_all if ln.startswith('limactl shell "$VM" -- rm -rf -- "$GUEST_ROOT/agent-out" ')), '')
        mkdir_line = next((ln for ln in launcher_all if ln.startswith('limactl shell "$VM" -- mkdir -p "$RDV" "$GUEST_ROOT/agent-out" ')), '')
        e(bool(rm_line) and bool(mkdir_line), 'the launcher keeps its guest rm -rf and mkdir lines for agent-out (R1 test anchor)')
        if rm_line and mkdir_line:
            def delivery_after(prelude_lines):
                with tempfile.TemporaryDirectory() as r1_tmp:
                    base = Path(r1_tmp)
                    guest = base / 'guest'
                    (guest / 'agent-out/w5').mkdir(parents=True)
                    (guest / 'agent-out/w5/w5-result.json').write_text('STALE')
                    (guest / 'rdv').mkdir()
                    (guest / 'rdv/agent-hello.json').write_text('hello')
                    (guest / 'keep.txt').write_text('keep')
                    (base / 'bin').mkdir()
                    (base / 'bin/limactl').write_text(
                        '#!/bin/sh\n[ "$1" = shell ] || exit 9\nshift; shift; [ "$1" = -- ] && shift\n'
                        'cmd="$1"; shift\n'
                        'case "$cmd" in rm|mkdir) ;; *) echo "fake limactl: refused $cmd" >&2; exit 9 ;; esac\n'
                        'for a in "$@"; do case "$a" in -*) ;; "$FAKE_GUEST"/*) ;; *) echo "fake limactl: refused path $a" >&2; exit 9 ;; esac; done\n'
                        'exec "$cmd" "$@"\n')
                    (base / 'bin/limactl').chmod(0o755)
                    script = 'set -euo pipefail\nVM=fake; GUEST_ROOT="$1"; RDV="$1/rdv"\n' + '\n'.join(prelude_lines) + '\n'
                    run = subprocess.run([bash_t, '-c', script, 'bash', str(guest)], env=dict(os.environ, PATH=f'{base / "bin"}:{os.environ["PATH"]}', FAKE_GUEST=str(guest)),
                                         text=True, capture_output=True, timeout=30)
                    fresh = base / 'fresh/1-sweep'
                    fresh.mkdir(parents=True)
                    (fresh / 'w5-result.json').write_text('FRESH')
                    subprocess.run(['cp', '-R', str(fresh), str(guest / 'agent-out/w5')], check=True)
                    top = guest / 'agent-out/w5/w5-result.json'
                    return {'rc': run.returncode, 'stderr': run.stderr.strip(), 'top': top.read_text() if top.exists() else None,
                            'nested': (guest / 'agent-out/w5/1-sweep').exists(), 'keep': (guest / 'keep.txt').exists(), 'hello': (guest / 'rdv/agent-hello.json').exists()}
            control = delivery_after([mkdir_line])
            e(control['rc'] == 0 and control['top'] == 'STALE' and control['nested'], f'R1 harness control: with only the mkdir line the stale w5-result.json survives and the fresh folder nests; got {control!r}')
            fixed = delivery_after([rm_line, mkdir_line])
            e(fixed == {'rc': 0, 'stderr': '', 'top': 'FRESH', 'nested': False, 'keep': True, 'hello': True},
              f'the launcher empties the guest agent-out before the run: after its rm and mkdir lines the delivered w5-result.json is the fresh one, nothing nests, and files outside agent-out stay; got {fixed!r} (R1)')
            rm_at = [i for i, ln in enumerate(launcher_lines) if ln.startswith('limactl shell "$VM" -- rm -rf -- "$GUEST_ROOT/agent-out"')]
            mkdir_at = [i for i, ln in enumerate(launcher_lines) if ln.startswith('limactl shell "$VM" -- mkdir -p "$RDV" "$GUEST_ROOT/agent-out" 2>/dev/null')]
            agent_at = [i for i, ln in enumerate(launcher_lines) if ln == 'AGENT_PID=$!']
            e(len(rm_at) == 1 and len(mkdir_at) == 1 and len(agent_at) == 1 and rm_at[0] < mkdir_at[0] < agent_at[0],
              'the launcher empties agent-out before it creates it and before the agent starts (R1)')
        e(any(ln.startswith('limactl shell "$VM" -- rm -rf -- "$GUEST_ROOT/agent-out" 2>/dev/null || { echo "run-vm-gate: could not empty ') and ln.endswith('exit 2; }') for ln in launcher_lines),
          'the launcher exits 2 with a reason when it cannot empty the guest agent-out (R1: a stale delivery must not be read as this run\'s)')
        # N1 (delta review of 2d4c9df): the guest's mkdir and the removal of the previous run's exit status fail loudly. Under `set -e` a bare
        # failing line ended the launcher silently with rc 1; each of the three guest lines runs behind a limactl whose `shell` always fails and
        # must end the script with exit 2 and exactly one message line of its own on stderr (nothing on stdout, nothing after it).
        rm_status = next((ln for ln in launcher_all if ln.startswith('limactl shell "$VM" -- rm -f "$RDV/runner.rc" "$RDV/runner.pid" ')), '')
        e(bool(rm_status), 'the launcher keeps its guest rm -f line for runner.rc and runner.pid (N1 test anchor)')
        with tempfile.TemporaryDirectory() as n1_tmp:
            (Path(n1_tmp) / 'limactl').write_text('#!/bin/sh\nexit 1\n')
            (Path(n1_tmp) / 'limactl').chmod(0o755)
            for label, guest_line, word in (('rm -rf', rm_line, 'could not empty'), ('mkdir', mkdir_line, 'could not create'), ('rm -f', rm_status, 'could not remove')):
                if not guest_line:
                    continue
                script = 'set -euo pipefail\nVM=fake; GUEST_ROOT=/g; RDV=/g/rdv\n' + guest_line + '\necho CONTINUED\n'
                run = subprocess.run([bash_t, '-c', script], env=dict(os.environ, PATH=f'{n1_tmp}:{os.environ["PATH"]}'), text=True, capture_output=True, timeout=30)
                e(run.returncode == 2 and run.stdout == '' and run.stderr.startswith(f'run-vm-gate: {word} ') and len(run.stderr.strip().splitlines()) == 1,
                  f'the launcher exits 2 with one message line when its guest {label} fails (N1); got rc {run.returncode}: stdout {run.stdout!r} stderr {run.stderr!r}')
        # the launcher checks --guest-root with the shape agent.mjs's guestPath accepts before it runs `rm -rf` on a path built from it
        guest_path_funcs = bash_function_source(launcher_path, 'guest_path_ok')

        def guest_path_case(path):
            return subprocess.run([bash_t, '-c', guest_path_funcs + 'guest_path_ok "$1"; echo $?', 'bash', path], text=True, capture_output=True).stdout.strip()

        e(all(guest_path_case(good) == '0' for good in ('/home/u/gate', '/opt/g.1/x_y-z', '/a')),
          'guest_path_ok accepts normalized absolute guest paths of plain characters (R1)')
        bad_paths = ('', '/', 'gate', 'rel/gate', '/a/../b', '/a/./b', '/a//b', '/a/b/', '/..', '/.', '/a b', "/a'b", '/a$b', '/a`b', '/a;b', '/a\\b', '/a\nb', '/a*', '/a"b', '/é')
        e(all(guest_path_case(bad) == '1' for bad in bad_paths),
          f'guest_path_ok refuses relative, empty, non-normalized and non-plain guest paths before a guest rm -rf is built from them; accepted: {[b for b in bad_paths if guest_path_case(b) != "1"]!r} (R1)')
        e(any(ln.startswith('guest_path_ok "$GUEST_ROOT" || { echo "run-vm-gate: --guest-root must be a normalized absolute guest path') and ln.endswith('exit 2; }') for ln in launcher_lines),
          'the launcher refuses a --guest-root that is not a plain normalized guest path with exit 2, before any guest command (R1)')

        # R2: the launcher runs under `set -euo pipefail`, so a guest read that FAILS used to end it silently (rc 1) before the message
        # written for that case: a runner killed before it finished leaves no runner.rc, an unreadable guest checkout fails `git -C`, a
        # missing receipt fails `test -d`. The launcher's own blocks run behind a fake limactl (shell: ip, git, cat, sh only; copy: cp -R) and
        # fake route and git commands; each failing case is paired with a control showing the same block reaching its end when it works.
        def launcher_block(start, end):
            first = next((i for i, ln in enumerate(launcher_all) if ln.startswith(start)), -1)
            last = next((i for i in range(first, len(launcher_all)) if end(launcher_all[i])), -1) if first >= 0 else -1
            return '\n'.join(launcher_all[first:last + 1]) if first >= 0 and last >= 0 else ''

        r2_blocks = {
            'addr': launcher_block('VM_IP="$(limactl shell', lambda ln: ln == 'fi'),
            'iface': launcher_block('IFACE="$(route', lambda ln: ln.startswith('[[ -n "$IFACE" ]]')),
            'head': launcher_block('GUEST_HEAD="$(limactl shell', lambda ln: ln.lstrip().startswith('|| { echo "run-vm-gate: the guest checkout')),
            'end': launcher_block('VM_IP_END="$(limactl shell', lambda ln: ln == 'fi'),
            'tail': launcher_block('if ! limactl copy --backend=scp -r "$VM:$GUEST_ROOT/agent-out"', lambda ln: ln == 'exit "$RC"'),
        }
        e(all(r2_blocks.values()), f'the launcher keeps the blocks the R2 test runs (VM address, interface, guest HEAD, end address, harvest tail); missing: {[k for k, v in r2_blocks.items() if not v]}')
        fake_lima_r2 = """#!/bin/sh
[ -z "$FAKE_FAIL" ] || exit 1
sub="$1"; shift
case "$sub" in
  shell) shift; [ "$1" = -- ] && shift; cmd="$1"; shift
    case "$cmd" in
      ip) echo "3: lima0    inet 192.168.64.2/24 brd 192.168.64.255 scope global lima0" ;;
      cat|sh) exec "$cmd" "$@" ;;
      git) if [ -n "$FAKE_HEAD" ]; then echo "$FAKE_HEAD"; else echo "fatal: cannot change to '/g/repo': No such file or directory" >&2; exit 128; fi ;;
      *) echo "fake limactl: refused $cmd" >&2; exit 9 ;;
    esac ;;
  copy) while [ $# -gt 0 ]; do case "$1" in -*) shift ;; *) break ;; esac; done
    exec cp -R "${1#*:}" "$2" ;;
  *) exit 9 ;;
esac
"""
        fake_route_r2 = '#!/bin/sh\nif [ -n "$FAKE_IFACE" ]; then echo "   interface: $FAKE_IFACE"; exit 0; fi\necho "route: writing to routing socket: not in table" >&2\nexit 1\n'

        def r2_run(prelude, block, epilogue='', runner_rc=None, receipt=False, **fake_env):
            with tempfile.TemporaryDirectory() as r2_tmp:
                base = Path(r2_tmp)
                (base / 'bin').mkdir()
                (base / 'bin/limactl').write_text(fake_lima_r2)
                (base / 'bin/route').write_text(fake_route_r2)
                for tool in ('limactl', 'route'):
                    (base / 'bin' / tool).chmod(0o755)
                guest, out = base / 'guest', base / 'out'
                (guest / 'rdv').mkdir(parents=True)
                (guest / 'agent-out').mkdir()
                out.mkdir()
                if runner_rc is not None:
                    (guest / 'rdv/runner.rc').write_text(runner_rc + '\n')
                if receipt:
                    (guest / 'receipt-x').mkdir()
                    (guest / 'receipt-x/receipt.md').write_text(receipt_text())
                script = ('set -euo pipefail\nVM=fake; GUEST_ROOT="$1"; RDV="$1/rdv"; OUT="$2"; GUEST_RECEIPT="$1/receipt-x"; CANDIDATE="$3"; RC=0; PHASE=4a\n'
                          + prelude + '\n' + block + '\n' + epilogue + '\n')
                env = dict(os.environ, PATH=f'{base / "bin"}:{os.environ["PATH"]}', FAKE_FAIL='', FAKE_HEAD='', FAKE_IFACE='')
                env.update({k.upper(): v for k, v in fake_env.items()})
                run = subprocess.run([bash_t, '-c', script, 'bash', str(guest), str(out), candidate_sha], env=env, text=True, capture_output=True, timeout=30)
            return run.returncode, run.stdout, run.stderr

        if all(r2_blocks.values()):
            rc_a, out_a, err_a = r2_run('', r2_blocks['addr'], fake_fail='1')
            e(rc_a == 2 and 'no IPv4 address on the guest lima0' in err_a, f'an unreachable guest ends the VM address read in its message (exit 2), not silently; got rc {rc_a}: {err_a[:160]!r} (R2)')
            rc_a, out_a, err_a = r2_run('', r2_blocks['addr'], 'echo "VM_IP=$VM_IP"')
            e(rc_a == 0 and 'VM_IP=192.168.64.2' in out_a, f'control: a reachable guest gives its lima0 address; got rc {rc_a}: {out_a!r} {err_a[:160]!r} (R2)')
            rc_b, out_b, err_b = r2_run('VM_IP=192.168.64.2', r2_blocks['iface'])
            e(rc_b == 2 and 'names no interface' in err_b, f'a failing `route -n get` ends in its message (exit 2), not silently; got rc {rc_b}: {err_b[:160]!r} (R2)')
            rc_b, out_b, err_b = r2_run('VM_IP=192.168.64.2', r2_blocks['iface'], 'echo "IFACE=$IFACE"', fake_iface='bridge100')
            e(rc_b == 0 and 'IFACE=bridge100' in out_b, f'control: the interface of the route is taken; got rc {rc_b}: {out_b!r} (R2)')
            rc_c, out_c, err_c = r2_run(head_funcs, r2_blocks['head'])
            e(rc_c == 2 and "is at 'unreadable'" in err_c,
              f"a guest checkout that cannot be read ends the launcher with the message `is at 'unreadable'` (exit 2); got rc {rc_c}: {err_c[:200]!r} (R2, T13)")
            rc_c, out_c, err_c = r2_run(head_funcs, r2_blocks['head'], 'echo head-ok', fake_head=candidate_sha)
            e(rc_c == 0 and 'head-ok' in out_c, f'control: a guest checkout at the candidate passes; got rc {rc_c}: {err_c[:160]!r} (R2)')
            rc_d, out_d, err_d = r2_run('VM_IP=192.168.64.2', r2_blocks['end'], 'echo "RC=$RC"', fake_fail='1')
            e(rc_d == 0 and 'RC=3' in out_d and 'the guest lima0 address changed during the run' in err_d,
              f'an unreadable address at the end of the run is reported as a changed address (RC 3), not a silent exit; got rc {rc_d}: {out_d!r} {err_d[:160]!r} (R2)')
            rc_d, out_d, err_d = r2_run('VM_IP=192.168.64.2', r2_blocks['end'], 'echo "RC=$RC"')
            e(rc_d == 0 and 'RC=0' in out_d and 'unchanged at the end' in out_d, f'control: an unchanged address leaves RC 0; got rc {rc_d}: {out_d!r} (R2)')
            tail_prelude = ''.join(bash_function_source(launcher_path, name) for name in ('receipt_verdict', 'receipt_candidate_ok', 'run_outcome'))
            rc_e, out_e, err_e = r2_run(tail_prelude, r2_blocks['tail'], receipt=True)
            e(rc_e == 16 and 'the guest runner left no exit status (it was killed before it finished)' in err_e and 'receipt harvested' in out_e,
              f'a runner that left no runner.rc is reported by its message and bit 16 (T14: "left no exit status" is reachable); got rc {rc_e}: {err_e[:200]!r} (R2)')
            rc_e, out_e, err_e = r2_run(tail_prelude, r2_blocks['tail'], runner_rc='0', receipt=True)
            e(rc_e == 0 and 'candidate-bound PASS' in out_e, f'control: runner exit 0 with a PASS receipt of the candidate is a success; got rc {rc_e}: {out_e[-200:]!r} {err_e[:160]!r} (R2)')
            rc_e, out_e, err_e = r2_run(tail_prelude, r2_blocks['tail'], runner_rc='1', receipt=True)
            e(rc_e == 16 and 'the guest runner exited 1' in err_e, f'a runner exit 1 keeps bit 16 and its reason; got rc {rc_e}: {err_e[:160]!r} (R2)')
            rc_e, out_e, err_e = r2_run(tail_prelude, r2_blocks['tail'])
            e(rc_e == 24 and 'the named guest receipt' in err_e and 'does not exist' in err_e and 'left no exit status' in err_e,
              f'a guest with neither receipt nor runner.rc reports both reasons and bits 8 and 16 (S3, T14); got rc {rc_e}: {err_e[:300]!r} (R2)')

            # R9: the hello wait is bounded by the clock (90 s), not by a number of passes: each pass costs a limactl round trip and a sleep. Both are
            # stood in for by functions that advance SECONDS (a round trip takes 5 s, a sleep its argument); the real loop runs, in no real time.
            hello_wait = launcher_block('hello_seen=0', lambda ln: ln.startswith('(( hello_seen == 1 )) || {'))
            e(bool(hello_wait), 'the launcher keeps the hello wait block the R9 test runs')

            def hello_wait_case(seen_on_call):
                script = ('set -euo pipefail\nVM=fake; RDV=/g/rdv; NONCE=n; OUT=/o; AGENT_PID=$$; calls=0; SEEN="$1"\n'
                          'limactl() { calls=$((calls + 1)); SECONDS=$((SECONDS + 5)); [[ -n "$SEEN" && $calls -ge $SEEN ]]; }\n'
                          'sleep() { SECONDS=$((SECONDS + $1)); }\n'
                          'trap \'echo "calls=$calls" >&2\' EXIT\n' + hello_wait + '\necho passed\n')
                run = subprocess.run([bash_t, '-c', script, 'bash', str(seen_on_call or '')], text=True, capture_output=True, timeout=30)
                found = re.search(r'calls=(\d+)', run.stderr)
                return run.returncode, run.stdout.strip(), run.stderr, int(found.group(1)) if found else -1

            if hello_wait:
                rc_h, out_h, err_h, calls_h = hello_wait_case(None)
                e(rc_h == 2 and 'no agent-hello.json' in err_h and 'within 90 s' in err_h and 10 <= calls_h <= 14,
                  f'with 7 s per pass the hello wait gives up after about 90 s (13 passes), not after 45 passes; got rc {rc_h}, {calls_h} passes: {err_h[:200]!r} (R9)')
                rc_h, out_h, err_h, calls_h = hello_wait_case(3)
                e(rc_h == 0 and out_h == 'passed' and calls_h == 3, f'control: a hello seen on the third pass ends the wait; got rc {rc_h}, {calls_h} passes: {out_h!r} (R9)')
    e("The launcher empties the guest's `agent-out` folder before every run" in guide_flat
      and "W5 evaluates its result file only when that file's sha256 equals the `w5-result.json` entry in the `files[]` of the agent's response" in guide_flat,
      'the guide says the launcher empties the guest agent-out and W5 binds its result file to the response files[] sha256 (R1)')
    # the guide says what the review fixes made true (T16, T03, T02, T05, T17, T14, T13)
    guide_flat = ' '.join((ROOT / 'sso/guides/identity-gate.md').read_text().split())
    for sentence in ("read from the saved agent response, where the scan lives, and required to be present and valid",
                     "built from `docker inspect` of every container of both Compose projects; a failed inspect fails the row",
                     "a probe that found no route or scope proves nothing and fails",
                     "the branch follows the fixture's OS (`/etc/os-release` `ID`/`ID_LIKE`: RHEL-family fixtures must run firewalld and fail without it",
                     "whose target is `ACCEPT` as `firewall-cmd --info-zone=docker` reports it",
                     "the launcher returns success only for a candidate-bound PASS",
                     "and the guest checkout is at that candidate before anything starts"):
        e(sentence in guide_flat, f'the guide must say: {sentence!r} (review T02/T03/T05/T13/T14/T16/T17)')
    e('RC=$((RC | 16))' in launcher_lines and any(ln.startswith('if OUTCOME_REASON="$(run_outcome "$RUNNER_RC"') for ln in launcher_lines),
      'the launcher turns a run that is not a candidate-bound PASS into a non-zero exit (T14)')
    e("agent_request" in topo_runner_text and 'CAP="$(python3 -I "$GATE_DIR/browser_remote.py" request' in topo_runner_text
      and '2>&1)"; rc=$?\n  if [[ -n "$REND_NONCE" ]]' not in topo_runner_text,
      'agent_request no longer merges the requester stderr into CAP (T01)')
    e("{{index .Config.Labels \"com.docker.compose.service\"}}" in topo_runner_text and "{{.Label \"com.docker.compose.service\"}}|{{range" not in topo_runner_text,
      'the W5 inspect template reads the service label from .Config.Labels (T02)')
    e('IFS=$\'\\n\' read -r status ua issuer leak' not in topo_runner_text and 'mapfile -t fields <<<"$parsed"' in topo_runner_text,
      'W6 takes each helper output line into its own variable (mapfile), not one `read` (T04)')


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


def example_site(**changes):
    """sso/dual-example.json with its two claim placeholders replaced by a real claim: the shipped file is refused as it is
    (the placeholders must be edited), so every case that needs a valid PingFederate site starts from this one."""
    site = json.loads((ROOT / 'sso/dual-example.json').read_text())
    site.update(mfa_claim_name='amr', mfa_claim_value='otp')
    site.update(changes)
    return site


def check_configure_dual(checks):
    """auth configure FILE writes the same runtime.yml as the local planner plus the identity-provider plan; the realm file belongs to identity up."""
    e = checks.expect
    source = (ROOT / 'sso/configure-dual.py').read_text()
    e('"keycloak/krate-realm.json"' not in source, 'configure-dual.py: must not write keycloak/krate-realm.json (owned by krate identity up)')
    for key in ('allow-shared-login', 'shared-role'):
        e(key not in source, f'configure-dual.py: must not mention {key} (no shared form login in Keycloak mode)')
    example = example_site()
    for key in MOVED_SITE_KEYS:
        e(key not in json.loads((ROOT / 'sso/dual-example.json').read_text()), f'sso/dual-example.json: {key} moved to .env and must not be in the example')
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
    example = example_site()
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
    settings = example_site()
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


def check_probe_diagnostic_privacy(checks):
    """Actual probe.main() must not log credential-bearing URLs or arbitrary server/library text.

    Manual CLI RED is harness/progress/codex-probe-codeql/MANUAL-BASELINE.json. These isolated
    cases replace file, trust, resolver, signal and HTTP boundaries; no request or real alarm runs.
    Cause categories, safe public host, file references and repair hints remain observable.
    """
    import email.message
    import http.client
    import signal
    import socket
    import ssl
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlsplit
    from unittest import mock

    spec = importlib.util.spec_from_file_location('probe_privacy', ROOT / 'sso/probe.py')
    assert spec is not None and spec.loader is not None, 'sso/probe.py missing'
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    origin = f'https://{PUBLIC_HOST}'
    issuer = origin + '/identity/realms/krate'
    user = 'privacy-user-codeql15'
    password = 'privacy-password-codeql15'
    query = 'privacy-query-codeql15'
    fragment = 'privacy-fragment-codeql15'
    path_token = 'privacy-path-codeql15'
    external_text = 'privacy-external-codeql15'
    markers = (user, password, query, fragment, path_token, external_text)
    unsafe_url = f'https://{user}:{password}@outside.example.test/{path_token}?token={query}#{fragment}'
    runtime_file = 'auth/ui/runtime.yml'
    cert_file = 'certs/server.crt'
    document = {'issuer': issuer, **{key: issuer + '/' + key for key in probe.ENDPOINT_KEYS}}
    rows = []

    def add(title, configured=issuer, error=None, reply=None, lookups=None, required=(), forbidden=(), request_expected=True):
        rows.append((title, configured, error, reply, lookups, required, forbidden, request_expected))

    invalid_hints = (runtime_file, 'KEYCLOAK_PUBLIC_URL', 'krate auth configure')
    add('malformed credential-bearing issuer', f'https://{user}:{password}@[broken', required=invalid_hints, request_expected=False)
    add('valid userinfo issuer', f'https://{user}:{password}@{PUBLIC_HOST}/identity/realms/krate',
        error=HTTPError(issuer, 502, external_text, email.message.Message(), None),
        required=invalid_hints, request_expected=False)
    for label, configured in (
            ('query', issuer + '?token=' + query), ('fragment', issuer + '#' + fragment),
            ('path', origin + '/' + path_token)):
        add('configured issuer ' + label, configured,
            error=HTTPError(configured, 502, external_text, email.message.Message(), None),
            required=invalid_hints if label != 'path' else ('HTTP 502', PUBLIC_HOST, 'Keycloak'),
            request_expected=label == 'path')
    for field in ('issuer',) + probe.ENDPOINT_KEYS:
        add('server ' + field + ' contains credentials', reply=dict(document, **{field: unsafe_url}),
            required=('KEYCLOAK_PUBLIC_URL', runtime_file, 'krate auth configure',
                      'issuer' if field == 'issuer' else field))
    add('HTTP reason contains arbitrary secret',
        error=HTTPError(issuer, 503, external_text + ' ' + unsafe_url, email.message.Message(), None),
        required=('HTTP 503', PUBLIC_HOST, 'Keycloak'))
    invalid_url_text = 'nonnumeric port: ' + unsafe_url + ' ' + external_text
    for label, error in (('raw', http.client.InvalidURL(invalid_url_text)),
                         ('wrapped', URLError(http.client.InvalidURL(invalid_url_text)))):
        add(label + ' InvalidURL contains secret', error=error,
            required=('is invalid', runtime_file, 'KEYCLOAK_PUBLIC_URL', 'redirect or proxy target'),
            forbidden=('nothing was contacted', 'the issuer URL'))
    add('OSError text contains secret', error=URLError(OSError(113, external_text + unsafe_url)),
        required=('no connection', PUBLIC_HOST, 'proxy must be running'))
    add('SSL error text contains secret', error=URLError(ssl.SSLError(1, external_text + unsafe_url)),
        required=('TLS error', PUBLIC_HOST, cert_file))
    verification = ssl.SSLCertVerificationError(1, external_text + unsafe_url)
    verification.verify_code, verification.verify_message = 62, external_text + unsafe_url
    add('SSL verify_message contains secret', error=URLError(verification),
        required=('certificate verification failed', PUBLIC_HOST, cert_file, 'must cover', '62'))
    add('redirect credential-like invalid lookup', error=URLError(socket.gaierror(-2, external_text)),
        lookups=((PUBLIC_HOST, 443), (f'{user}:{password}@outside.example.test', 8443)),
        required=('cannot resolve', 'DNS', 'redirect', PUBLIC_HOST))
    add('proxy URL-like invalid lookup', error=URLError(ConnectionRefusedError(111, external_text)),
        lookups=((PUBLIC_HOST, 443), (unsafe_url, 8443)),
        required=('no connection', 'proxy must be running', 'proxy setting', PUBLIC_HOST))
    add('generic library reason contains secret', error=URLError(external_text + unsafe_url),
        required=('request', 'failed', PUBLIC_HOST, 'proxy'))
    add('unexpected exception contains secret', error=RuntimeError(external_text + unsafe_url),
        required=('unexpected readiness error', PUBLIC_HOST), forbidden=('RuntimeError',))
    # Positive cause controls use native error objects but never contact their named endpoints.
    add('ordinary DNS cause', error=URLError(socket.gaierror(-2, 'Name or service not known')),
        required=('cannot resolve', PUBLIC_HOST, 'DNS', '/etc/hosts'), forbidden=('no connection',))
    add('ordinary refusal cause', error=URLError(ConnectionRefusedError(111, 'Connection refused')),
        required=('no connection', PUBLIC_HOST, 'proxy must be running', '111'), forbidden=('cannot resolve',))
    add('ordinary connected read stall', error=socket.timeout('The read operation timed out'),
        required=('accepted the connection but did not answer in time', PUBLIC_HOST, 'Keycloak'), forbidden=('no connection',))
    add('ordinary deadline', error=TimeoutError('Readiness deadline exceeded'),
        required=('no answer within 15 s', PUBLIC_HOST, 'Keycloak'), forbidden=('no connection',))
    add('ordinary invalid redirect after issuer lookup', error=http.client.InvalidURL('nonnumeric port: hidden'),
        required=('is invalid', runtime_file, 'redirect or proxy target'), forbidden=('nothing was contacted', 'hidden'))
    add('ordinary plain HTTP compatibility', configured=f'http://{PUBLIC_HOST}/identity/realms/krate',
        error=HTTPError(issuer, 502, 'Bad Gateway', email.message.Message(), None),
        lookups=((PUBLIC_HOST, 80),), required=('HTTP 502', f'http://{PUBLIC_HOST}', 'Keycloak'))
    add('ordinary IPv6 origin', configured='https://[2001:db8::1]:8443/identity/realms/krate',
        error=URLError(ConnectionRefusedError(111, 'Connection refused')),
        lookups=(('2001:db8::1', 8443),), required=('no connection', '[2001:db8::1]:8443', 'proxy must be running'))
    add('ordinary redirected destination', error=URLError(ConnectionRefusedError(111, 'Connection refused')),
        lookups=((PUBLIC_HOST, 443), ('outside.example.test', 8443)),
        required=('no connection to outside.example.test:8443', 'redirect', PUBLIC_HOST),
        forbidden=(f'no connection to {PUBLIC_HOST}',))
    add('configured multiple DNS root dots', configured=f'https://{PUBLIC_HOST}.../identity/realms/krate',
        required=invalid_hints, forbidden=(PUBLIC_HOST + '...',), request_expected=False)
    add('configured scoped IPv6', configured='https://[fe80::1%25privacy-password-codeql15]/identity/realms/krate',
        required=invalid_hints, forbidden=('fe80::1%',), request_expected=False)
    add('redirect multiple DNS root dots', error=URLError(socket.gaierror(-2, external_text)),
        lookups=((PUBLIC_HOST, 443), ('outside.example.test...', 8443)),
        required=('cannot resolve <invalid host>', 'redirect', PUBLIC_HOST), forbidden=('outside.example.test...',))
    add('redirect scoped IPv6', error=URLError(socket.gaierror(-2, external_text)),
        lookups=((PUBLIC_HOST, 443), ('fe80::1%privacy-password-codeql15', 8443)),
        required=('cannot resolve <invalid host>', 'redirect', PUBLIC_HOST), forbidden=('fe80::1%',))
    add('ordinary single DNS root dot', configured=f'https://{PUBLIC_HOST}./identity/realms/krate',
        error=URLError(ConnectionRefusedError(111, 'Connection refused')),
        lookups=((PUBLIC_HOST + '.', 443),), required=('no connection', PUBLIC_HOST, '111'), forbidden=('redirect',))
    add('ordinary valid discovery', reply=document)

    class Reply:
        def __init__(self, value):
            self.body = json.dumps(value).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def read(self, size):
            return self.body[:size]

    for title, configured, error, reply, lookups, required, forbidden, request_expected in rows:
        reads, alarms, requests = [], [], []
        runtime = json.dumps({'auth': {'oauth2': {'client': {'keycloak': {
            'issuer-uri': configured, 'client-secret': password}}}}})

        def read_runtime(file, *_args, **_kwargs):
            reads.append(str(file))
            assert str(file).endswith(runtime_file), 'only runtime.yml may be read'
            return runtime

        def request(*args, **kwargs):
            requests.append((args, kwargs))
            for host, port in lookups if lookups is not None else ((PUBLIC_HOST, 443),):
                socket.getaddrinfo(host, port)
            if error is not None:
                raise error
            return Reply(reply if reply is not None else document)

        def resolver(*_args, **_kwargs):
            return []

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(Path, 'read_text', read_runtime), \
                mock.patch.object(probe, 'urlopen', request), \
                mock.patch.object(ssl, 'create_default_context', return_value=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)), \
                mock.patch.object(socket, 'getaddrinfo', resolver), \
                mock.patch.object(signal, 'signal'), \
                mock.patch.object(signal, 'alarm', side_effect=lambda seconds: alarms.append(seconds) or 0), \
                mock.patch.object(sys, 'argv', ['probe.py', '--directory', '/privacy-fixture']), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = probe.main()
            restored = socket.getaddrinfo is resolver
        output = out.getvalue() + err.getvalue()
        label = 'probe diagnostic privacy (' + title + ')'
        success = title == 'ordinary valid discovery'
        checks.expect(status == (0 if success else 1), f'{label}: failure stays exit1; only valid discovery exits0; got {status}')
        checks.expect(all(marker not in output for marker in markers), f'{label}: no credentials, URL tokens or external text may be printed; got {output!r}')
        displayed_urls = re.findall(r'https?://[^\s)>,;]+', output)
        try:
            parts = [urlsplit(value.rstrip(':')) for value in displayed_urls]
            origin_only = all(value.hostname and not any((value.username, value.password, value.path, value.query, value.fragment))
                              for value in parts)
        except ValueError:
            origin_only = False
        checks.expect(origin_only,
                      f'{label}: diagnostic URLs expose only the safe origin, never userinfo/path/query/fragment; got {output!r}')
        checks.expect(success or (out.getvalue() == '' and err.getvalue().startswith('Public SSO readiness failed: ')
                                  and err.getvalue().count('\n') == 1 and err.getvalue()[:-1].isprintable()),
                      f'{label}: failure remains one printable stderr line and no stdout; got {output!r}')
        for needle in required:
            checks.expect(needle in output, f'{label}: cause/file/repair detail {needle!r} must remain; got {output!r}')
        for needle in forbidden:
            checks.expect(needle not in output, f'{label}: must not misattribute {needle!r}; got {output!r}')
        checks.expect(reads == ['/privacy-fixture/' + runtime_file] and restored and alarms == [15, 0],
                      f'{label}: read only runtime.yml, cancel the deadline and restore the resolver')
        if request_expected:
            checks.expect(len(requests) == 1 and requests[0][0] == (configured + '/.well-known/openid-configuration',),
                          f'{label}: sanitizing the displayed address must not rewrite the actual discovery request target; got {requests!r}')
        else:
            checks.expect(not requests, f'{label}: malformed/private issuer is refused before any request')
        if success:
            checks.expect(len(requests) == 1 and out.getvalue() == 'Public HTTPS identity discovery verified.\n' and not err.getvalue(),
                          f'{label}: valid discovery still reaches the real main success contract')


def check_probe_causes(checks):
    """sso/probe.py, the public sign-in check `krate auth apply` ends with, names the actual cause of a failure (its real main(),
    urlopen replaced by stubs that raise real exception objects; nothing connects): one stderr line that keeps the
    'Public SSO readiness failed: ' prefix, the safe public host/origin involved and what to check, exit status 1, no file content, no raw
    server values or library text (status-line reason, fetched issuer/endpoints, error messages), the
    host named in a lookup failure being the one looked up (a redirect target), a read stall told from a failed connection,
    an invalid issuer URL told from a dead proxy, the alarm armed for 15 s and cancelled on every path, getaddrinfo restored.
    Found on 2026-10-17 on an Ubuntu server that could not resolve its own public name: the old line listed four possible
    causes and not that one."""
    import email.message
    import http.client
    import pathlib
    import signal
    import socket
    import ssl
    import urllib.error
    spec = importlib.util.spec_from_file_location('probe', ROOT / 'sso/probe.py')
    assert spec is not None and spec.loader is not None, 'sso/probe.py missing'
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    e = checks.expect
    secret = SYNTHETIC['KEYCLOAK_KAFBAT_CLIENT_SECRET']
    prefix = 'Public SSO readiness failed: '
    old_message = 'verify application DNS, HTTPS certificate, proxy identity route and realm issuer'
    issuer = f'https://{PUBLIC_HOST}/identity/realms/krate'
    url = issuer + '/.well-known/openid-configuration'
    display = f'https://{PUBLIC_HOST}:443'  # diagnostics expose an origin; requests retain the complete URL
    other = 'https://other.example.test/identity/realms/krate'
    endpoints = ('authorization_endpoint', 'token_endpoint', 'jwks_uri')
    document = {'issuer': issuer, 'authorization_endpoint': issuer + '/protocol/openid-connect/auth',
                'token_endpoint': issuer + '/protocol/openid-connect/token', 'jwks_uri': issuer + '/protocol/openid-connect/certs'}
    verify_text = f"Hostname mismatch, certificate is not valid for '{PUBLIC_HOST}'."
    mismatch = ssl.SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:1129)')
    mismatch.verify_code, mismatch.verify_message = 62, verify_text  # set by the ssl module on a real handshake failure
    deadline = 'Readiness deadline exceeded'  # the text the SIGALRM handler raises in a TimeoutError
    hostile_reason = 'Bad\nGate\x1b[2J\x07way ' + 'A' * 5000  # a server's status-line reason phrase: 17 characters, then a flood
    hostile_value = other + '/' + 'Z' * 5000  # a fetched issuer or endpoint far beyond the limit
    hostile_library = 'Refused\x1b[2J ' + 'R' * 5000  # an OS or ssl error text: 12 characters, then a flood
    hostile_verify = ssl.SSLCertVerificationError(1, 'certificate verify failed (_ssl.c:1129)')
    hostile_verify.verify_code, hostile_verify.verify_message = 62, 'Hostile\x1b[2J ' + 'V' * 5000
    hostile_name = 'evil\x1b[2J.' + 'H' * 5000  # a redirect target's host name: 9 characters, then a flood
    as_directory = object()
    detour_lookups = ((PUBLIC_HOST, 443), ('elsewhere.example.test', 443))  # the issuer's host first, then where a redirect led
    calls, lookups, cafiles, alarms, hooks = [], [], [], [], {}
    real_context, real_alarm, real_read_text = ssl.create_default_context, signal.alarm, pathlib.Path.read_text

    class Reply:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def read(self, size=-1):
            return self.body[:size]

    def raising(error, lookup=((PUBLIC_HOST, 443),)):
        def fail(*call_args, **call_kwargs):
            calls.append((call_args, call_kwargs))
            for pair in lookup:  # what urlopen does first, including the name a redirect leads to
                socket.getaddrinfo(*pair)
            raise error
        return fail

    def answering(body, lookup=((PUBLIC_HOST, 443),)):
        def answer(*call_args, **call_kwargs):
            calls.append((call_args, call_kwargs))
            for pair in lookup:
                socket.getaddrinfo(*pair)
            return Reply(body)
        return answer

    def runtime(client):
        return json.dumps({'auth': {'oauth2': {'client': {'keycloak': client}}}})

    def with_issuer(value):
        return runtime({'issuer-uri': value, 'client-secret': secret})

    def fake_getaddrinfo(host, service, *_address_args, **_address_kwargs):
        lookups.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (host, service))]

    def bare_context(*context_args, **context_kwargs):
        """create_default_context without the partial-chain flag that Python 3.13+ sets by default: probe.py must set it itself."""
        if 'context' in hooks:
            raise hooks['context']
        cafiles.append(context_kwargs.get('cafile'))
        bare = real_context(*context_args, **context_kwargs)
        if hasattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN'):
            bare.verify_flags &= ~ssl.VERIFY_X509_PARTIAL_CHAIN
        return bare

    def counting_alarm(seconds):
        alarms.append(seconds)
        return real_alarm(seconds)

    def failing_read_text(_path, *_read_args, **_read_kwargs):
        raise hooks['read_text']

    def run(directory, urlopen_stub: 'Callable[..., object]', arguments):
        """probe.main() for `directory`: exit status, stdout, stderr, alarm still pending, getaddrinfo restored, the alarm calls
        main made, and what the SIGALRM handler it installed raises."""
        real_argv, real_urlopen, real_getaddrinfo = sys.argv, getattr(probe, 'urlopen'), socket.getaddrinfo
        real_handler = signal.getsignal(signal.SIGALRM)
        stdout, stderr = io.StringIO(), io.StringIO()
        sys.argv = ['probe.py', '--directory', str(directory), *arguments]
        setattr(probe, 'urlopen', urlopen_stub)
        socket.getaddrinfo, ssl.create_default_context, signal.alarm = fake_getaddrinfo, bare_context, counting_alarm
        if 'read_text' in hooks:
            setattr(pathlib.Path, 'read_text', failing_read_text)
        del alarms[:]
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    status = probe.main()
                except BaseException as exc:  # a mutant that raises is a finding, not a crash of the check
                    status = f'raised {type(exc).__name__}: {exc}'
            signal.alarm = real_alarm
            left = real_alarm(0)
            installed = signal.getsignal(signal.SIGALRM)
            try:
                if callable(installed):
                    installed(signal.SIGALRM, None)
                handler_text = 'raised nothing'
            except BaseException as exc:
                handler_text = f'{type(exc).__name__}: {exc}'
        finally:
            resolver_restored = socket.getaddrinfo is fake_getaddrinfo
            socket.getaddrinfo, ssl.create_default_context, signal.alarm = real_getaddrinfo, real_context, real_alarm
            setattr(pathlib.Path, 'read_text', real_read_text)
            sys.argv = real_argv
            setattr(probe, 'urlopen', real_urlopen)
            real_alarm(0)
            signal.signal(signal.SIGALRM, real_handler)
        return {'status': status, 'out': stdout.getvalue(), 'err': stderr.getvalue(), 'left': left, 'resolver': resolver_restored,
                'alarms': list(alarms), 'handler': handler_text}

    def place(path, content):
        """None removes `path`, as_directory makes a directory there, any other value is its text."""
        if path.is_dir():
            path.rmdir()
        else:
            path.unlink(missing_ok=True)
        if content is as_directory:
            path.mkdir()
        elif content is not None:
            path.write_text(content)

    def case(title, runtime_text, stub=None, extra=(), required=(), forbidden=(), cert: 'object' = True, hook=None):
        """One failure: runtime.yml text, certs/server.crt (True: a real one, None: absent, text: that), the urlopen stub (None: must not
        be reached), extra arguments, substrings the message must and must not hold, an optional ('context' | 'read_text', error)."""
        return {'title': title, 'runtime': runtime_text, 'cert': cert, 'stub': stub, 'extra': extra, 'required': required,
                'forbidden': forbidden, 'hook': hook}

    keycloak = {'issuer-uri': issuer, 'client-secret': secret}
    cases = [
        case('runtime.yml missing', None, required=('auth/ui/runtime.yml', 'is missing', 'krate auth configure')),
        case('runtime.yml not JSON', 'not json ' + secret, required=('auth/ui/runtime.yml', 'not valid JSON', 'krate auth configure')),
        case('runtime.yml unreadable (a directory)', as_directory, required=('auth/ui/runtime.yml', 'cannot be read', 'krate auth configure'),
             forbidden=('is missing',)),
        case('runtime.yml without issuer-uri', runtime({'client-secret': secret}),
             required=('auth/ui/runtime.yml', 'auth.oauth2.client.keycloak.issuer-uri', 'krate auth configure')),
        case('runtime.yml with an empty issuer-uri', runtime({'issuer-uri': '', 'client-secret': secret}),
             required=('auth.oauth2.client.keycloak.issuer-uri', 'krate auth configure')),
        case('issuer without a host name', with_issuer('https:///identity/realms/krate'),
             required=('auth/ui/runtime.yml', 'no host name', 'KEYCLOAK_PUBLIC_URL')),
        case('issuer without a host name, with line breaks', with_issuer('https:///identity/\n\nrealms\t/krate'),
             required=('no host name', 'KEYCLOAK_PUBLIC_URL')),
        case('issuer with an unbalanced IPv6 bracket', with_issuer('https://[::1/identity/realms/krate'),
             required=('auth/ui/runtime.yml', 'no host name', 'KEYCLOAK_PUBLIC_URL')),
        case('issuer with a port that is not a number', with_issuer(f'https://{PUBLIC_HOST}:notaport/identity/realms/krate'),
             required=('auth/ui/runtime.yml', 'no host name', 'KEYCLOAK_PUBLIC_URL')),
        case('certs/server.crt missing', runtime(keycloak), cert=None, required=('certs/server.crt', 'is missing', 'krate gen-cert')),
        case('certs/server.crt unusable', runtime(keycloak), cert='not a certificate\n' + secret + '\n',
             required=('certs/server.crt', 'cannot be used as the trust anchor', 'krate gen-cert'), forbidden=('is missing',)),
        case('host name does not resolve', runtime(keycloak),
             raising(urllib.error.URLError(socket.gaierror(-2, 'Name or service not known'))),
             required=(f'this server cannot resolve {PUBLIC_HOST}', 'resolver error code -2', '/etc/hosts', 'DNS'),
             forbidden=('no connection', 'certificate', 'no answer', 'redirect')),
        case('redirect target does not resolve', runtime(keycloak),
             raising(urllib.error.URLError(socket.gaierror(-2, 'Name or service not known')), detour_lookups),
             required=('this server cannot resolve elsewhere.example.test', 'add elsewhere.example.test to DNS', 'redirect', PUBLIC_HOST),
             forbidden=(f'cannot resolve {PUBLIC_HOST}', f'add {PUBLIC_HOST} to DNS')),
        case('connection refused', runtime(keycloak), raising(urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused'))),
             required=(f'no connection to {PUBLIC_HOST}:443', 'operating system error 111', 'proxy must be running', f'{PUBLIC_HOST} must point at this server'),
             forbidden=('cannot resolve', 'certificate', 'redirect', 'accepted the connection')),
        case('connection refused, host looked up in capitals', runtime(keycloak),
             raising(urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused')), ((PUBLIC_HOST.upper(), 443),)),
             required=(f'no connection to {PUBLIC_HOST}:443',), forbidden=('redirect',)),
        case('connection refused by a redirect target on another port', runtime(keycloak),
             raising(urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused')),
                     ((PUBLIC_HOST, 443), ('elsewhere.example.test', 8443))),
             required=('no connection to elsewhere.example.test:8443', 'redirect', PUBLIC_HOST), forbidden=(f'no connection to {PUBLIC_HOST}',)),
        case('connection refused by another port of the issuer host', runtime(keycloak),
             raising(urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused')), ((PUBLIC_HOST, 443), (PUBLIC_HOST, 8443))),
             required=(f'no connection to {PUBLIC_HOST}:8443', 'redirect')),
        case('redirect target with a hostile name', runtime(keycloak),
             raising(urllib.error.URLError(socket.gaierror(-2, 'Name or service not known')), ((PUBLIC_HOST, 443), (hostile_name, 443))),
             required=('cannot resolve <invalid host>', 'redirect'), forbidden=('\x1b', 'H' * 192)),
        case('connection refused, IPv6 issuer', with_issuer('https://[::1]:8443/identity/realms/krate'),
             raising(urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused')), (('::1', 8443),)),
             required=('no connection to [::1]:8443',), forbidden=('redirect',)),
        case('connection refused, with --connect-ip', runtime(keycloak),
             raising(urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused'))), extra=('--connect-ip', '127.0.0.1'),
             required=(f'no connection to {PUBLIC_HOST}:443',), forbidden=('redirect', '127.0.0.1')),
        case('connection refused, issuer over plain http', runtime({'issuer-uri': f'http://{PUBLIC_HOST}/identity/realms/krate'}),
             raising(urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused')), ()),
             required=(f'no connection to {PUBLIC_HOST}:80',), forbidden=(':443',)),
        case('library error text far beyond the limit', runtime(keycloak),
             raising(urllib.error.URLError(ConnectionRefusedError(111, hostile_library))),
             required=('operating system error 111', 'no connection'), forbidden=('\x1b', 'R' * 189)),
        case('host unreachable', runtime(keycloak), raising(urllib.error.URLError(OSError(113, 'No route to host'))),
             required=(f'no connection to {PUBLIC_HOST}:443', 'operating system error 113', 'proxy must be running'), forbidden=('cannot resolve',)),
        case('timeout while connecting', runtime(keycloak), raising(urllib.error.URLError(socket.timeout('timed out'))),
             required=(f'no connection to {PUBLIC_HOST}:443', 'timeout', 'proxy must be running'),
             forbidden=('cannot resolve', 'no answer within', 'accepted the connection')),
        case('connected, then no answer in time (read stall)', runtime(keycloak), raising(socket.timeout('The read operation timed out')),
             required=(f'{PUBLIC_HOST}:443 accepted the connection but did not answer in time', 'timeout', 'Keycloak'),
             forbidden=('no connection to', 'must point at this server', 'no answer within')),
        case('connection dropped without an answer', runtime(keycloak),
             raising(http.client.RemoteDisconnected('Remote end closed connection without response')),
             required=(f'{PUBLIC_HOST}:443', 'did not answer with valid HTTP', 'HTTP protocol error'), forbidden=('cannot resolve',)),
        case('invalid request URL before a lookup', runtime(keycloak),
             raising(http.client.InvalidURL("URL can't contain control characters. '/iden tity' (found at least ' ')"), ()),
             required=(f'a URL used while checking {display}', 'auth/ui/runtime.yml', 'is invalid', 'KEYCLOAK_PUBLIC_URL', 'redirect or proxy target'),
             forbidden=('the issuer URL', 'nothing was contacted', 'did not answer with valid HTTP', 'request had been sent on')),
        # Observed with a real loopback TLS302: the issuer answered, then the redirect's nonnumeric port raised InvalidURL
        # before a second lookup. Recording only the issuer lookup cannot establish that nothing was contacted.
        case('invalid redirect URL after the issuer answered', runtime(keycloak),
             raising(http.client.InvalidURL("nonnumeric port: 'notaport'"), ((PUBLIC_HOST, 443),)),
             required=(f'a URL used while checking {display}', 'invalid URL', 'is invalid', 'KEYCLOAK_PUBLIC_URL', 'redirect or proxy target'),
             forbidden=('the issuer URL', 'nothing was contacted', 'did not answer with valid HTTP', 'request had been sent on')),
        case('wrapped invalid request URL', runtime(keycloak),
             raising(urllib.error.URLError(http.client.InvalidURL("nonnumeric port: 'notaport'")), ()),
             required=(f'a URL used while checking {display}', 'is invalid', 'redirect or proxy target'),
             forbidden=('the issuer URL', 'nothing was contacted', 'did not answer with valid HTTP')),
        case('invalid URL with hostile library text', runtime(keycloak),
             raising(http.client.InvalidURL('Bad\x1b[2J ' + 'U' * 5000), ((PUBLIC_HOST, 443),)),
             required=('invalid URL', 'redirect or proxy target'),
             forbidden=('\x1b', 'U' * 193, 'nothing was contacted')),
        case('certificate verification failed', runtime(keycloak), raising(urllib.error.URLError(mismatch)),
             required=(f'certificate verification failed for {PUBLIC_HOST}', 'certificate verification code 62', 'certs/server.crt', f'must cover {PUBLIC_HOST}'),
             forbidden=('cannot resolve', 'no connection')),
        case('certificate verify_message far beyond the limit', runtime(keycloak), raising(urllib.error.URLError(hostile_verify)),
             required=('certificate verification code 62',), forbidden=('\x1b', 'V' * 189)),
        case('certificate verification failed, no verify_message', runtime(keycloak),
             raising(urllib.error.URLError(ssl.SSLCertVerificationError(1, 'certificate has expired'))),
             required=(f'certificate verification failed for {PUBLIC_HOST}', 'certificate verification code unavailable', 'certs/server.crt'),
             forbidden=('unexpected',)),
        case('other TLS error', runtime(keycloak),
             raising(urllib.error.URLError(ssl.SSLError(1, '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1129)'))),
             required=('TLS error', f'{PUBLIC_HOST}:443', 'TLS error code 1', 'certs/server.crt'),
             forbidden=('certificate verification failed', 'cannot resolve')),
        case('HTTP error status from the proxy', runtime(keycloak),
             raising(urllib.error.HTTPError(url, 502, 'Bad Gateway', email.message.Message(), None)),
             required=(display, 'HTTP 502', '/identity'), forbidden=('cannot resolve', 'no connection', 'redirect')),
        case('HTTP error status with a hostile reason phrase', runtime(keycloak),
             raising(urllib.error.HTTPError(url, 502, hostile_reason, email.message.Message(), None)),
             required=(display, 'HTTP 502', '/identity'), forbidden=('\x1b', 'A' * 184)),
        case('host name that urllib cannot encode', runtime(keycloak), raising(UnicodeError('label empty or too long')),
             required=(display, 'not a usable address', 'request error', 'KEYCLOAK_PUBLIC_URL'), forbidden=('unexpected',)),
        case('host name that urllib cannot encode, after a redirect', runtime(keycloak),
             raising(UnicodeError('label empty or too long'), detour_lookups),
             required=(display, 'not a usable address', 'redirect', 'elsewhere.example.test')),
        case('URLError with a text reason', runtime(keycloak), raising(urllib.error.URLError('no host given')),
             required=(f'the request to {display}', f'{PUBLIC_HOST} points at this server')),
        case('anything unanticipated', runtime(keycloak), raising(RuntimeError('boom ' + secret)),
             required=('unexpected readiness error', display), forbidden=('boom',)),
        case('answer is not JSON', runtime(keycloak), answering(b'<html>502</html>'),
             required=(display, 'not an OpenID configuration'), forbidden=('<html>', 'redirect')),
        case('answer from a redirect target is not JSON', runtime(keycloak), answering(b'<html>502</html>', detour_lookups),
             required=(display, 'not an OpenID configuration', 'redirect', 'elsewhere.example.test')),
        case('answer lacks the endpoints', runtime(keycloak), answering(json.dumps({'issuer': issuer}).encode()),
             required=(display, 'not an OpenID configuration', 'authorization_endpoint', 'token_endpoint', 'jwks_uri')),
        case('answer from a redirect target lacks the endpoints', runtime(keycloak),
             answering(json.dumps({'issuer': issuer}).encode(), detour_lookups),
             required=(display, 'not an OpenID configuration', 'redirect', 'elsewhere.example.test')),
        case('answer is not an object', runtime(keycloak), answering(b'["issuer"]'), required=(display, 'not an OpenID configuration')),
        case('issuer differs', runtime(keycloak), answering(json.dumps(dict(document, issuer=other)).encode()),
             required=('different issuer', display, 'KEYCLOAK_PUBLIC_URL'), forbidden=('redirect',)),
        case('issuer differs, from a redirect target', runtime(keycloak),
             answering(json.dumps(dict(document, issuer=other)).encode(), detour_lookups),
             required=('different issuer', display, 'KEYCLOAK_PUBLIC_URL', 'redirect', 'elsewhere.example.test')),
        case('issuer differs, hostile value', runtime(keycloak), answering(json.dumps(dict(document, issuer=hostile_value)).encode()),
             required=('different issuer', display, 'KEYCLOAK_PUBLIC_URL'), forbidden=(hostile_value[:201],)),
        case('issuer differs, control characters', runtime(keycloak), answering(json.dumps(dict(document, issuer=other + '\n\x1b[2J')).encode()),
             required=('different issuer', display, 'KEYCLOAK_PUBLIC_URL'), forbidden=('\x1b',)),
    ]
    for key in endpoints:
        outside = other + '/protocol/openid-connect/x'
        cases.append(case(f'{key} outside the issuer', runtime(keycloak), answering(json.dumps(dict(document, **{key: outside})).encode()),
                          required=('outside the configured issuer', key, 'auth/ui/runtime.yml', 'KEYCLOAK_PUBLIC_URL'), forbidden=('redirect',)))
    cases.append(case('endpoint outside the issuer, from a redirect target', runtime(keycloak),
                      answering(json.dumps(dict(document, jwks_uri=other + '/x')).encode(), detour_lookups),
                      required=('jwks_uri', 'outside the configured issuer', 'redirect', 'elsewhere.example.test')))
    cases.append(case('endpoint outside the issuer, hostile value', runtime(keycloak),
                      answering(json.dumps(dict(document, jwks_uri=hostile_value)).encode()),
                      required=('jwks_uri', 'outside the configured issuer', 'KEYCLOAK_PUBLIC_URL'), forbidden=(hostile_value[:201],)))
    cases += [
        case('deadline inside URLError', runtime(keycloak), raising(urllib.error.URLError(TimeoutError(deadline))),
             required=('no answer within 15 s', display), forbidden=('no connection', 'cannot resolve')),
        case('deadline raised directly', runtime(keycloak), raising(TimeoutError(deadline)),
             required=('no answer within 15 s', display), forbidden=('no connection', 'cannot resolve')),
        case('deadline while the trust anchor loads', runtime(keycloak), hook=('context', TimeoutError(deadline)),
             required=('no answer within 15 s', display), forbidden=('trust anchor', 'unexpected')),
        case('deadline while runtime.yml is read', runtime(keycloak), hook=('read_text', TimeoutError(deadline)),
             required=('no answer within 15 s from the identity route',), forbidden=('cannot be read', 'unexpected')),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        site = Path(tmp)
        (site / 'auth/ui').mkdir(parents=True)
        self_signed(site / 'certs', PUBLIC_HOST)
        certificate = (site / 'certs/server.crt').read_text()
        for row in cases:
            place(site / 'certs/server.crt', certificate if row['cert'] is True else row['cert'])
            place(site / 'auth/ui/runtime.yml', row['runtime'])
            hooks.clear()
            if row['hook']:
                hooks[row['hook'][0]] = row['hook'][1]
            del calls[:], lookups[:], cafiles[:]
            result = run(site, row['stub'] or raising(AssertionError('urlopen must not be reached')), row['extra'])
            err = result['err']
            what = f'probe.py ({row["title"]})'
            e(result['status'] == 1, f'{what}: the exit status stays 1; got {result["status"]!r}')
            e(result['out'] == '' and err.startswith(prefix) and err.endswith('\n') and err.count('\n') == 1,
              f'{what}: stdout stays empty and stderr is exactly one line starting {prefix!r}; got stdout {result["out"]!r}, stderr {err!r}')
            e(err[:-1].isprintable(), f'{what}: the line holds only printable characters; got {err!r}')
            e(old_message not in err, f'{what}: the four-causes catch-all must be gone; got {err.strip()!r}')
            for needle in row['required']:
                e(needle in err, f'{what}: the message must name {needle!r}; got {err.strip()!r}')
            for needle in row['forbidden']:
                e(needle not in err, f'{what}: the message must not say {needle!r}; got {err.strip()!r}')
            e(secret not in result['out'] + err, f'{what}: the output must not carry file content')
            for untrusted in (verify_text, hostile_reason[:30], hostile_value[:30], hostile_library[:30],
                              'Bad Gateway', 'no host given', 'nonnumeric port:', 'Name or service not known',
                              'Connection refused', 'No route to host', 'WRONG_VERSION_NUMBER', other):
                e(untrusted not in err, f'{what}: raw server/library/URL text must not be echoed: {untrusted!r}')
            e(result['left'] == 0 and result['resolver'], f'{what}: the alarm must be cancelled and socket.getaddrinfo restored on a failure')
            e(result['alarms'][:1] == [15] and result['alarms'][-1:] == [0],
              f'{what}: the 15 s alarm is armed first and cancelled last; main made the calls {result["alarms"]!r}')
            e(result['handler'] == f'TimeoutError: {deadline}', f'{what}: the SIGALRM handler raises TimeoutError({deadline!r}); got {result["handler"]!r}')
            e(bool(calls) == (row['stub'] is not None), f'{what}: urlopen must be reached exactly when the file checks pass; calls {len(calls)}')
        hooks.clear()
        # The unchanged success path, with and without --connect-ip (the gate's route: KRATE_PROBE_CONNECT_IP).
        place(site / 'auth/ui/runtime.yml', runtime(keycloak))
        place(site / 'certs/server.crt', certificate)
        for connect_args in ((), ('--connect-ip', '127.0.0.1')):
            del calls[:], lookups[:], cafiles[:]
            result = run(site, answering(json.dumps(document).encode(), ((PUBLIC_HOST.upper(), 443), ('elsewhere.example.test', 443))), connect_args)
            what = f'probe.py (success {" ".join(connect_args) or "without --connect-ip"})'
            e((result['status'], result['out'], result['err']) == (0, 'Public HTTPS identity discovery verified.\n', ''),
              f'{what}: exit 0, the verified line on stdout, nothing on stderr; got {(result["status"], result["out"], result["err"])!r}')
            e(result['left'] == 0 and result['resolver'], f'{what}: the alarm must be cancelled and socket.getaddrinfo restored')
            e(result['alarms'] == [15, 0], f'{what}: the 15 s alarm is armed and cancelled once; got {result["alarms"]!r}')
            urlopen_args, urlopen_kwargs = calls[0] if calls else ((None,), {})
            urlopen_context = urlopen_kwargs.get('context')
            e(urlopen_args == (url,) and urlopen_kwargs.get('timeout') == 10 and isinstance(urlopen_context, ssl.SSLContext)
              and urlopen_context.check_hostname and urlopen_context.verify_mode == ssl.CERT_REQUIRED
              and (not hasattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN') or urlopen_context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN),
              f'{what}: urlopen gets the discovery URL, a 10 s timeout and a verifying context with partial chains allowed')
            e(cafiles == [str(site / 'certs/server.crt')], f'{what}: the trust anchor is certs/server.crt; got {cafiles!r}')
            e(lookups == (['127.0.0.1'] if connect_args else [PUBLIC_HOST.upper()]) + ['elsewhere.example.test'],
              f'{what}: --connect-ip maps the issuer host (any case) to that address and no other name; resolver saw {lookups!r}')


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
    # The MFA stance (enforce-if-asserted): a plan that states neither stance is refused by name, in both preflight modes —
    # this is what makes a site's forgotten choice block `auth apply` and `identity up` instead of failing open there.
    # The example plan carries the claim pair, so "neither" removes the three provider keys.
    mutated_plan(lambda p: [p['identityProviders'][0]['config'].pop(key) for key in identity.MFA_FILTER_KEYS])
    expect_refusal('a plan without an MFA stance', 'no MFA stance')
    expect_refusal('the stance refusal names both options', 'mfa_claim_name')
    expect_refusal('the stance refusal names the opt-out', 'mfa_not_asserted')
    expect_refusal('the stance refusal names the way back', 'then run krate auth configure <site.json>')
    outcome = preflight(site, 'runtime.yml', rendered)
    checks.expect(outcome.stderr.count('regenerate') == 0 and outcome.stderr.count('remove auth/ui/runtime.yml') == 1,
                  f'{edition}: the stance refusal is complete: it must not repeat the generic regenerate hint; got {outcome.stderr.strip()}')
    outcome = preflight(site, 'identity', rendered)
    checks.expect(outcome.returncode == 1 and 'no MFA stance' in outcome.stderr,
                  f'{edition}: identity-mode preflight (identity up) must refuse a plan without an MFA stance; got exit {outcome.returncode}: {outcome.stderr.strip()}')
    # The opt-out (mfa_not_asserted, no claim keys) is the accepted alternative; so is the claim pair (restored below).
    mutated_plan(lambda p: ([p['identityProviders'][0]['config'].pop(key) for key in identity.MFA_FILTER_KEYS], p.__setitem__(identity.MFA_NOT_ASSERTED_KEY, True)))
    expect_pass('an opted-out plan (mfa_not_asserted)')
    # A claim filter that is switched off or Java-ambiguous is refused at preflight too (the plan validator is the single rule).
    identity.write_file(plan_file, plan_original, 0o644)
    mutated_plan(lambda p: p['identityProviders'][0]['config'].__setitem__('filteredByClaim', 'false'))
    expect_refusal('filteredByClaim "false" with a claim name and value', 'string "true"')
    mutated_plan(lambda p: p['identityProviders'][0]['config'].__setitem__('claimFilterValue', '(?<n>x)'))
    expect_refusal('a claim value outside the literal subset', 'literals separated by |')
    identity.write_file(plan_file, plan_original, 0o644)
    expect_pass('the claim-pair plan restored')


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
    plan = load_configure_dual().configs(example_site(), SYNTHETIC)['keycloak/pingfederate-idp.json']
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
        # F1 (MFA review): the three claim-filter keys are managed. The site switched from the claim pair to the opt-out; the live
        # provider still carries the filter, the plan does not: apply must UPDATE the provider (never print No changes), the update
        # replaces the configuration so the keys are gone, and the next apply has nothing to do.
        optout_plan = json.loads(json.dumps(plan))
        for key in identity.MFA_FILTER_KEYS:
            optout_plan['identityProviders'][0]['config'].pop(key)
        optout_plan[identity.MFA_NOT_ASSERTED_KEY] = True
        plan_file.write_text(json.dumps(optout_plan, indent=2) + '\n')
        state_file.write_text(json.dumps(state))
        result, calls, state_withdrawn = run()
        label = 'apply after the site switched from the claim pair to mfa_not_asserted'
        updates = [c for c in calls if c[0] == 'update' and c[1] == 'identity-provider/instances/pingfederate']
        kept = [key for key in identity.MFA_FILTER_KEYS if key in (state_withdrawn['provider'] or {}).get('config', {})]
        e(result.returncode == 0 and len(updates) == 1 and 'provider updated' in result.stdout and 'No changes' not in result.stdout
          and 'changed=true' in result.stdout and kept == [],
          f'{label}: must update the provider and leave none of the claim-filter keys; got exit {result.returncode} updates {len(updates)} kept {kept} {result.stdout.strip()[-220:]!r}')
        e('reconciled identity provider pingfederate: provider updated' in journal.read_text().splitlines()[-1], f'{label}: the journal records the provider update; got {journal.read_text().splitlines()[-1]!r}')
        result, calls, state_settled = run()
        e(result.returncode == 0 and 'No changes' in result.stdout and mutating(calls) == [] and state_settled == state_withdrawn,
          f'{label} (second run): nothing left to do; got {mutating(calls)} {result.stdout.strip()[-160:]!r}')
        offline = json.loads(json.dumps(state_withdrawn))
        offline['provider']['config']['filteredByClaim'] = 'false'
        state_file.write_text(json.dumps(offline))
        result, calls, state_off = run()
        e(result.returncode == 0 and 'No changes' in result.stdout and mutating(calls) == [] and state_off == offline,
          f'{label}: a live filteredByClaim "false" is a filter that is off and is left alone; got {mutating(calls)} {result.stdout.strip()[-160:]!r}')
        plan_file.write_text(json.dumps(plan, indent=2) + '\n')
        state_file.write_text(json.dumps(state))
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


def check_mfa_choice(checks):
    """The MFA stance (enforce-if-asserted): the site file states exactly one of the
    two stances, `auth configure` and the plan validator refuse neither, the claim value is a subset both Java and Python
    read the same way, and the three claim-filter keys are managed by the plan (the reconcile clears a filter the plan lost)."""
    e = checks.expect
    refuse_value = identity.MFA_VALUE_RULE

    def refuses(name, value, needle):
        try:
            identity.validate_mfa_filter(name, value)
            e(False, f'identity.validate_mfa_filter must refuse {name!r}/{value!r} naming {needle!r}')
        except ValueError as exc:
            e(needle in str(exc), f'identity.validate_mfa_filter must refuse {name!r}/{value!r} naming {needle!r}; got {exc}')

    for name in ('acr', 'amr', 'OTP', 'my_claim1'):
        try:
            identity.validate_mfa_filter(name, 'gold')
        except ValueError as exc:
            e(False, f'identity.validate_mfa_filter must accept the claim name {name!r}; got {exc}')
    for name in ('user.name', 5, '', 'a b', '1x'):
        refuses(name, 'gold', 'top-level identifier')
    e(set(identity.MFA_TYPED_CLAIMS) == {'jti', 'iss', 'aud', 'sub', 'typ', 'azp', 'exp', 'nbf', 'iat'},
      f'identity.MFA_TYPED_CLAIMS must be the nine registered JsonWebToken fields; got {identity.MFA_TYPED_CLAIMS}')
    for name in identity.MFA_TYPED_CLAIMS:
        refuses(name, 'gold', 'registered JWT field')
    # F4: the value is a literal or a |-list of literals; everything else is refused on every interpreter (Java and Python
    # disagree on the rest of the grammar), so the answer cannot depend on the Python that runs the check.
    for value in ('otp', 'OTP', 'a|b', 'pwd|otp|mfa', 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
                  'http://schemas.openid.net/pape/policies/2007/06/multi-factor', 'mfa-1_x/y.z',
                  '2', '0|1|2'):
        try:
            identity.validate_mfa_filter('acr', value)
        except ValueError as exc:
            e(False, f'identity.validate_mfa_filter must accept the literal value {value!r}; got {exc}')
    for value in ('.*', '.+', '(.*)', '.*.*', '^.*$', '(?s).*', '[\\s\\S]*', '.', '...', '..|a', 'a||b', '|a', 'a|', 'a b', 'a\tb', 'a$', 'a\n',
                  '(?P<n>x)', 'a{,3}', '{x}', '(?#c)', '(?<n>x)', '\\p{L}+', '\\h', 'a*+', '(?>x)', 'a[(', 'ａｂ',
                  'a+', 'a++', 'a?', 'a*', 'a(b)'):
        refuses('acr', value, refuse_value)
    refuses('acr', '', 'nonempty string')
    refuses('acr', 9, 'nonempty string')
    example = json.loads((ROOT / 'sso/dual-example.json').read_text())
    module = load_configure_dual()
    # F7.2: the shipped example states the claim pair with placeholders; it does not carry the weakest stance.
    e('mfa_claim_name' in example and 'mfa_claim_value' in example and identity.MFA_NOT_ASSERTED_KEY not in example,
      'sso/dual-example.json must carry the placeholder claim pair and not the opt-out (a copy must not state "enforced at Ping only" unread)')
    # N3: the placeholders are refused as they are (a forgotten edit must not apply a filter on a claim no token carries, which
    # would refuse every brokered sign-in): by the site validator, by `krate auth configure`, and by the plan reader.
    e(identity.MFA_PLACEHOLDER in example.get('mfa_claim_name', '') and identity.MFA_PLACEHOLDER in example.get('mfa_claim_value', ''),
      f'sso/dual-example.json must carry {identity.MFA_PLACEHOLDER}_... placeholders for the claim name and value')
    site = example_site()
    for label, candidate, needle in (('the shipped example as it is', example, 'mfa_claim_name still holds the example placeholder'),
                                     ('a placeholder claim name', dict(site, mfa_claim_name=example['mfa_claim_name']), 'mfa_claim_name still holds the example placeholder'),
                                     ('a placeholder claim value', dict(site, mfa_claim_value=example['mfa_claim_value']), 'mfa_claim_value still holds the example placeholder')):
        try:
            module.configs(candidate, SYNTHETIC)
            e(False, f'configure-dual must refuse {label}')
        except ValueError as exc:
            e(needle in str(exc) and 'mfa_not_asserted' in str(exc), f'configure-dual refusing {label} must name {needle!r} and the opt-out; got {exc}')
    with tempfile.TemporaryDirectory() as tmp:
        settings_file = Path(tmp) / 'site.json'
        settings_file.write_text(json.dumps(example))
        outcome = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'sso/configure-dual.py'), '--settings', str(settings_file),
                                  '--output-dir', str(Path(tmp) / 'out')], text=True, capture_output=True)
        e(outcome.returncode == 1 and 'example placeholder' in outcome.stderr and not (Path(tmp) / 'out/keycloak').exists()
          and not (Path(tmp) / 'out/ui').exists(),
          f'configure-dual.py on the unedited example must exit 1 naming the placeholder and write nothing; got exit {outcome.returncode} {outcome.stderr.strip()[:160]}')
    pair_plan = module.configs(site, SYNTHETIC)['keycloak/pingfederate-idp.json']
    config = pair_plan['identityProviders'][0]['config']
    e(all(config.get(key) == value for key, value in zip(identity.MFA_FILTER_KEYS, ('true', site['mfa_claim_name'], site['mfa_claim_value'])))
      and identity.MFA_NOT_ASSERTED_KEY not in pair_plan,
      f"configure-dual: the opted-in plan's config must carry filteredByClaim \"true\", claimFilterName and claimFilterValue from the site file ({ {k: config.get(k) for k in identity.MFA_FILTER_KEYS} })")
    optout_site = {key: value for key, value in site.items() if key not in ('mfa_claim_name', 'mfa_claim_value')}
    optout_site[identity.MFA_NOT_ASSERTED_KEY] = True
    plan = module.configs(optout_site, SYNTHETIC)['keycloak/pingfederate-idp.json']
    e(plan.get(identity.MFA_NOT_ASSERTED_KEY) is True,
      f'configure-dual: a site file with mfa_not_asserted must write the plan key {identity.MFA_NOT_ASSERTED_KEY} true')
    e(not any(key in plan['identityProviders'][0]['config'] for key in identity.MFA_FILTER_KEYS),
      'configure-dual: the opt-out stance must not put the claim-filter keys on the provider config')
    e(set(plan) == IDP_PLAN_KEYS | {identity.MFA_NOT_ASSERTED_KEY},
      f'configure-dual: the opted-out plan must carry exactly the plan keys plus {identity.MFA_NOT_ASSERTED_KEY}; got {sorted(plan)}')
    # F7: `auth configure` itself refuses a site file that states neither stance, with the complete message.
    bare_site = {key: value for key, value in site.items() if key not in ('mfa_claim_name', 'mfa_claim_value')}
    for label, stanceless_site in (('no stance key at all', bare_site), ('mfa_not_asserted false', dict(bare_site, mfa_not_asserted=False))):
        try:
            module.configs(stanceless_site, SYNTHETIC)
            e(False, f'configure-dual must refuse a site file with {label}')
        except identity.MfaStanceError as exc:
            message = str(exc)
            e('no MFA stance' in message and 'mfa_claim_name' in message and 'mfa_not_asserted' in message and 'run krate auth configure again' in message,
              f'configure-dual refusing {label} must name both options and the way back; got {message}')
        except ValueError as exc:
            e(False, f'configure-dual refusing {label} must raise MfaStanceError; got {exc}')
    with tempfile.TemporaryDirectory() as tmp:
        settings_file = Path(tmp) / 'site.json'
        settings_file.write_text(json.dumps(bare_site))
        outcome = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'sso/configure-dual.py'), '--settings', str(settings_file),
                                  '--output-dir', str(Path(tmp) / 'out')], text=True, capture_output=True)
        e(outcome.returncode == 1 and 'no MFA stance' in outcome.stderr and not (Path(tmp) / 'out/keycloak').exists()
          and not (Path(tmp) / 'out/ui').exists(),
          f'configure-dual.py with a stance-less site file must exit 1 naming the stance and write nothing; got exit {outcome.returncode} {outcome.stderr.strip()[:160]}')
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'plan.json'
        for label, planned in (('opted-out', plan), ('claim-filter', pair_plan)):
            path.write_text(json.dumps(planned))
            try:
                identity.broker_plan(path)
            except ValueError as exc:
                e(False, f'identity.broker_plan must accept the {label} planned file; got {exc}')

        def plan_refusal(label, base, mutation: 'Callable[[dict], object]', *needles):
            mutated = json.loads(json.dumps(base))
            mutation(mutated)
            path.write_text(json.dumps(mutated))
            try:
                identity.broker_plan(path)
                e(False, f'identity.broker_plan must refuse {label}')
            except ValueError as exc:
                e(all(needle in str(exc) for needle in needles),
                  f'identity.broker_plan refusing {label} must name {needles[0]!r}; got {exc}')

        def provider_config(p):
            return p['identityProviders'][0]['config']
        plan_refusal('no MFA stance at all', plan, lambda p: p.pop(identity.MFA_NOT_ASSERTED_KEY),
                     'no MFA stance', 'mfa_claim_name', 'mfa_not_asserted', 'remove auth/ui/runtime.yml', 'then run krate auth configure <site.json>')
        plan_refusal('mfa_not_asserted written as a string', plan, lambda p: p.__setitem__(identity.MFA_NOT_ASSERTED_KEY, 'true'), 'boolean true')
        plan_refusal('mfa_not_asserted false', plan, lambda p: p.__setitem__(identity.MFA_NOT_ASSERTED_KEY, False), 'boolean true')
        plan_refusal('the marker beside the filter keys', pair_plan, lambda p: p.__setitem__(identity.MFA_NOT_ASSERTED_KEY, True), 'exactly one')
        plan_refusal('filteredByClaim without the claim name', pair_plan, lambda p: provider_config(p).pop('claimFilterName'),
                     'must set all three config keys together')
        for label, value in (('the boolean true', True), ('the string "false"', 'false'), ('the string "TRUE"', 'TRUE'), ('the string "True"', 'True')):
            plan_refusal(f'filteredByClaim as {label}', pair_plan, lambda p, v=value: provider_config(p).__setitem__('filteredByClaim', v), 'string "true"')
        plan_refusal('a claimFilterValue of .*', pair_plan, lambda p: provider_config(p).__setitem__('claimFilterValue', '.*'), refuse_value)
        plan_refusal('an invalid claimFilterValue', pair_plan, lambda p: provider_config(p).__setitem__('claimFilterValue', 'a[('), refuse_value)
        plan_refusal('a claimFilterName that is not an identifier', pair_plan, lambda p: provider_config(p).__setitem__('claimFilterName', 'a b'),
                     'top-level identifier')
        plan_refusal('a claimFilterName that is a registered JWT field', pair_plan, lambda p: provider_config(p).__setitem__('claimFilterName', 'sub'),
                     'registered JWT field')
        plan_refusal('a claimFilterName that is the example placeholder', pair_plan,
                     lambda p: provider_config(p).__setitem__('claimFilterName', 'REPLACE_WITH_ASSERTED_CLAIM'), 'mfa_claim_name still holds the example placeholder')
        plan_refusal('a claimFilterValue that is the example placeholder', pair_plan,
                     lambda p: provider_config(p).__setitem__('claimFilterValue', 'REPLACE_WITH_ASSERTED_VALUE'), 'mfa_claim_value still holds the example placeholder')
    # The site validator (sso/configure.py). `broker=True` is the PingFederate broker plan, the only consumer of the keys.
    spec = importlib.util.spec_from_file_location('configure_validations', ROOT / 'sso/configure.py')
    assert spec is not None and spec.loader is not None
    module_config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module_config)
    for label, accepted in (('the example with its placeholders replaced (the claim pair)', site), ('the opt-out site', optout_site)):
        try:
            module_config.validate(accepted, 'kafbat', broker=True)
        except ValueError as exc:
            e(False, f'configure.validate must accept {label} for the broker plan; got {exc}')
    try:
        module_config.validate(example, 'kafbat', broker=True)
        e(False, 'configure.validate must refuse the shipped example as it is (its claim placeholders are not a claim)')
    except ValueError as exc:
        e('example placeholder' in str(exc), f'configure.validate refusing the shipped example must name the example placeholder; got {exc}')
    pair = {'mfa_claim_name': 'acr', 'mfa_claim_value': 'otp'}
    site_cases = (
        ('mfa_claim_name alone', dict(bare_site, mfa_claim_name='acr', mfa_not_asserted=False), 'together or neither'),
        ('mfa_claim_value alone', dict(bare_site, mfa_claim_value='otp', mfa_not_asserted=False), 'together or neither'),
        ('the opt-out beside the pair', dict(bare_site, **pair, mfa_not_asserted=True), 'excludes'),
        ('mfa_not_asserted as a string', dict(bare_site, mfa_not_asserted='true'), 'mfa_not_asserted must be boolean'),
        ('mfa_not_asserted as a string beside the pair', dict(bare_site, **pair, mfa_not_asserted='true'), 'mfa_not_asserted must be boolean'),
        ('mfa_claim_value .*', dict(bare_site, mfa_claim_name='acr', mfa_claim_value='.*'), refuse_value),
        ('a claim name that is not an identifier', dict(bare_site, mfa_claim_name='user.name', mfa_claim_value='otp'), 'top-level identifier'),
        # text() is the first guard of both values: it names the precise reason before the claim rules run.
        ('a claim value with $', dict(bare_site, mfa_claim_name='acr', mfa_claim_value='o$tp'), 'configuration interpolation characters'),
        ('a claim value with {', dict(bare_site, mfa_claim_name='acr', mfa_claim_value='o{tp'), 'configuration interpolation characters'),
        ('a claim value with a control character', dict(bare_site, mfa_claim_name='acr', mfa_claim_value='o\ntp'), 'mfa_claim_value must be a nonempty single-line string'),
        ('a blank claim value', dict(bare_site, mfa_claim_name='acr', mfa_claim_value='   '), 'mfa_claim_value must be a nonempty single-line string'),
        ('a claim name with $', dict(bare_site, mfa_claim_name='a$cr', mfa_claim_value='otp'), 'configuration interpolation characters'),
        ('a blank claim name', dict(bare_site, mfa_claim_name='  ', mfa_claim_value='otp'), 'mfa_claim_name must be a nonempty single-line string'),
    )
    for label, candidate, needle in site_cases:
        try:
            module_config.validate(candidate, 'kafbat', broker=True)
            e(False, f'configure.validate must refuse {label}')
        except ValueError as exc:
            e(needle in str(exc), f'configure.validate refusing {label} must name {needle!r}; got {exc}')
    # F9: every other generator of this program refuses the keys (rejected, not ignored), whatever the app.
    for app in ('kafbat', 'grafana', 'perses'):
        settings = {'issuer': 'https://realm.example.test', 'public_url': 'https://realm.example.test', 'client_id': 'id',
                    'viewer_group': 'VIEW', 'admin_group': 'ADMIN', 'groups_claim': 'groups', 'scopes': ['openid'], 'clusters': CLUSTERS}
        for keys in (pair, {'mfa_not_asserted': True}):
            try:
                module_config.validate(dict(settings, **keys), app)
                e(False, f'configure.validate must refuse {sorted(keys)} for {app} without the broker plan')
            except ValueError as exc:
                e('PingFederate broker plan' in str(exc) and 'remove them from this settings file' in str(exc),
                  f'configure.validate refusing {sorted(keys)} for {app} must name the PingFederate broker plan; got {exc}')
    with tempfile.TemporaryDirectory() as tmp:
        settings_file = Path(tmp) / 'site.json'
        settings_file.write_text(json.dumps(dict(json.loads((ROOT / 'sso/example.json').read_text()), **pair)))
        outcome = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'sso/configure.py'), '--app', 'kafbat', '--settings', str(settings_file),
                                  '--output', str(Path(tmp) / 'kafbat.yml')], text=True, capture_output=True)
        e(outcome.returncode == 1 and 'PingFederate broker plan' in outcome.stderr and not (Path(tmp) / 'kafbat.yml').exists(),
          f'sso/configure.py --app kafbat must refuse the mfa keys (they have no effect there) and write nothing; got exit {outcome.returncode} {outcome.stderr.strip()[:160]}')


def check_mfa_reconcile(checks):
    """F1: the three claim-filter keys are managed. A live provider that still carries a filter the plan does not is a difference,
    and the update the CLI sends (the plan's representation, no merge) leaves none of the keys."""
    e = checks.expect
    module = load_configure_dual()
    example = example_site()
    optout_site = {key: value for key, value in example.items() if key not in ('mfa_claim_name', 'mfa_claim_value')}
    optout_site[identity.MFA_NOT_ASSERTED_KEY] = True
    trio = {'filteredByClaim': 'true', 'claimFilterName': 'amr', 'claimFilterValue': 'otp'}
    with tempfile.TemporaryDirectory() as tmp:
        files = {}
        for name, site in (('pair', example), ('optout', optout_site)):
            files[name] = Path(tmp) / f'{name}.json'
            files[name].write_text(json.dumps(module.configs(site, SYNTHETIC)['keycloak/pingfederate-idp.json']))
        plans = {name: identity.broker_plan(path) for name, path in files.items()}

        def live_of(name, extra=None, drop=()):
            rep = json.loads(json.dumps(plans[name]['identityProviders'][0]))
            rep['config']['clientSecret'] = '**********'
            rep.update({'internalId': 'x', 'types': ['USER_AUTHENTICATION']})
            for key in drop:
                rep['config'].pop(key, None)
            rep['config'].update(extra or {})
            return rep
        cases = (
            ('the opt-out plan against a live provider equal to it', 'optout', live_of('optout'), False),
            ('the opt-out plan against a live provider that still carries the whole filter (the site switched from the pair)', 'optout', live_of('optout', trio), True),
            ('the opt-out plan against a live claimFilterName alone', 'optout', live_of('optout', {'claimFilterName': 'amr'}), True),
            ('the opt-out plan against a live claimFilterValue alone', 'optout', live_of('optout', {'claimFilterValue': 'otp'}), True),
            ('the opt-out plan against a live filteredByClaim "true"', 'optout', live_of('optout', {'filteredByClaim': 'true'}), True),
            ('the opt-out plan against a live filteredByClaim "TRUE"', 'optout', live_of('optout', {'filteredByClaim': 'TRUE'}), True),
            ('the opt-out plan against a live filteredByClaim "false" (a filter that is off)', 'optout', live_of('optout', {'filteredByClaim': 'false'}), False),
            ('the opt-out plan against a live filteredByClaim "FALSE" (Boolean.parseBoolean reads any casing)', 'optout', live_of('optout', {'filteredByClaim': 'FALSE'}), False),
            ('the opt-out plan against a live filteredByClaim "false" plus a live claimFilterName', 'optout', live_of('optout', {'filteredByClaim': 'false', 'claimFilterName': 'amr'}), True),
            ('the opt-out plan, live filter plus another drifted key', 'optout', live_of('optout', dict(trio, tokenUrl='https://other.example/t')), True),
            ('the pair plan against a live provider equal to it', 'pair', live_of('pair'), False),
            ('the pair plan against a live provider without the filter', 'pair', live_of('pair', drop=identity.MFA_FILTER_KEYS), True),
            ('the pair plan against a changed live claim value', 'pair', live_of('pair', {'claimFilterValue': 'other'}), True),
        )
        for label, name, live, wanted in cases:
            got = identity.provider_differs(plans[name], live)
            e(got is wanted, f'identity.provider_differs: {label} must be {"a difference" if wanted else "no difference"}; got {got}')
            outcome = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'sso/identity.py'), 'broker', '--plan', str(files[name]), 'provider-differs'],
                                     input=json.dumps(live), text=True, capture_output=True)
            e(outcome.returncode == 0 and outcome.stdout.strip() == ('differs' if wanted else 'same'),
              f'identity.py broker provider-differs (the verdict auth apply reads): {label} must answer {"differs" if wanted else "same"}; got {outcome.stdout.strip()!r} {outcome.stderr.strip()[:120]}')
        # The update body is the plan's whole representation: with no pair planned, none of the three keys is in it.
        body = identity.broker_provider(plans['optout'])
        e(not any(key in body['config'] for key in identity.MFA_FILTER_KEYS) and 'clientSecret' not in body['config'],
          f'the opt-out provider body (what kcadm update -f - sends) must carry none of the claim-filter keys; got {sorted(body["config"])}')
        outcome = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'sso/identity.py'), 'broker', '--plan', str(files['optout']), 'provider'],
                                 text=True, capture_output=True)
        sent = json.loads(outcome.stdout or '{}')
        e(outcome.returncode == 0 and not any(key in sent.get('config', {}) for key in identity.MFA_FILTER_KEYS),
          f'identity.py broker provider (the update body) for the opt-out plan must carry none of the claim-filter keys; got {outcome.stdout[:120]!r}')
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        put = function_body(cli, 'identity_put_idp_provider')
        e('kcadm -- update "identity-provider/instances/$IDENTITY_IDP_ALIAS" -r "$IDENTITY_REALM" -f -' in put and '--merge' not in put and ' -m ' not in put
          and ' -s ' not in put,
          f'{edition}/krate: the provider update must send the plan as the whole body (-f -), never merged or patched with -s (the filter keys leave only through a replace)')


P18_MODEL = r'''
# The product as the P18 block's stubs model it: the REAL identity.py (broker_plan, provider_differs, broker_provider)
# decides the preflight and the reconcile; the realm, the stand-in IdP and the browser are stubs (INJECT perturbs one effect).
import json, os, sys
sys.path.insert(0, os.environ['ROOT'] + '/sso')
import identity
S = os.environ['S']
INJ = set(filter(None, os.environ.get('INJECT', '').split(',')))
live_path = S + '/live.json'


def live():
    return json.load(open(live_path)) if os.path.exists(live_path) else None


def counter(name, bump=0):
    path = S + '/' + name
    value = int(open(path).read() or 0) if os.path.exists(path) else 0
    if bump:
        open(path, 'w').write(str(value + bump))
    return value


def write_live(plan):
    rep = json.loads(json.dumps(plan['identityProviders'][0]))
    rep['config']['clientSecret'] = '**********'
    json.dump(rep, open(live_path, 'w'))


def add_user():
    open(S + '/users', 'a').write('ping-mfa 11111111-2222-3333-4444-555555555555\n')


def verdict(plan, current):
    if 'f1_bug' in INJ:  # the pre-fix reconcile: only the planned keys are compared
        return identity.differs(identity.broker_provider(plan), current)
    return identity.provider_differs(plan, current)


cmd = sys.argv[1]
if cmd == 'seed':
    write_live(identity.broker_plan(sys.argv[2]))
elif cmd == 'validate':
    if 'preflight_accepts' in INJ:
        sys.exit(0)
    try:
        identity.broker_plan(sys.argv[2])
    except identity.MfaStanceError as exc:
        print(f'Authentication preflight failed: {exc}'); sys.exit(1)
    except ValueError as exc:
        print(f'Authentication preflight failed: {exc}; regenerate it'); sys.exit(1)
elif cmd == 'apply':
    n = counter('applies', 1) + 1
    try:
        plan = identity.broker_plan(sys.argv[2])
    except ValueError as exc:
        print(f'{exc}'); sys.exit(1)
    current = live()
    if current is None or verdict(plan, current):
        if n == 2 and 'withdraw_keys_stay' in INJ:
            pass
        else:
            write_live(plan)
        if n == 2 and 'withdraw_says_no_changes' in INJ:
            print('Identity provider pingfederate: No changes')
        else:
            print('Identity provider pingfederate applied to realm krate (1 change(s): provider updated)')
    else:
        print('Identity provider pingfederate: No changes')
elif cmd == 'expect':
    if 'realm_mismatch_once' in INJ and counter('expects', 1) == 0:
        print('phase3_realm: provider.config.filteredByClaim: planned true, live None'); sys.exit(1)
    plan, current = json.load(open(sys.argv[2])), live()
    if current is None:
        print('phase3_realm: provider pingfederate is not in the realm'); sys.exit(1)
    bad = [k for k, v in plan['identityProviders'][0]['config'].items() if k != 'clientSecret' and str(v) != str(current['config'].get(k))]
    for k in bad:
        print(f'phase3_realm: provider.config.{k} differs')
    sys.exit(1 if bad else 0)
elif cmd == 'login':
    user, current = sys.argv[2], live()
    cfg = (current or {}).get('config', {})
    if user == 'ping-viewer':
        print('error\tping-viewer: error 502 at /identity/realms/krate/broker/pingfederate/endpoint' if 'control_fails' in INJ
              else 'ok\tping-viewer: ok 200 at /; federated identities 1; hops: 302 x')
    elif cfg.get('filteredByClaim') == 'true' and not ('withdraw_keys_stay' in INJ and counter('applies') >= 2):
        counter('events', 2 if 'two_events' in INJ else 1)
        if 'created_on_refusal' in INJ:
            add_user()
        status = '500' if 'refused_not_502' in INJ else '502'
        print(f'error\tping-mfa: error {status} at /identity/realms/krate/broker/pingfederate/endpoint (Unexpected error); federated identities 0; hops: 302 x')
    elif 'relogin_fails' in INJ:
        print('unexpected\tping-mfa: unexpected landed 200 /login')
    else:
        add_user()
        print('ok\tping-mfa: ok 200 at /; federated identities 1; hops: 302 x')
elif cmd == 'users':
    if 'users_query_fails' in INJ:
        sys.exit(1)
    if 'preexisting_once' in INJ and counter('user-queries', 1) == 0:
        print('99999999-2222-3333-4444-555555555555'); sys.exit(0)
    if os.path.exists(S + '/users'):
        for line in open(S + '/users'):
            print(line.split()[1])
elif cmd == 'events':
    if 'events_query_fails' in INJ:
        sys.exit(1)
    for _ in range(counter('events') + (250 if 'events_cap' in INJ else 3)):
        print('IDENTITY_PROVIDER_LOGIN_ERROR,identity_provider_login_failure')
elif cmd == 'idp':
    if 'idp_get_fails' in INJ or live() is None:
        sys.exit(1)
    print(json.dumps(live(), indent=2))
elif cmd == 'delete-users':
    open(S + '/users', 'w').write('')
'''

P18_DRIVER = r'''set -uo pipefail
S="$1"; export S
plan="$S/pingfederate-idp.json"; RAW="$S/raw.log"; : > "$RAW"; STATE="$S/st"; PROJECT=stubproj; STUB_DIR="$S"; KRATE="$S/krate-stub"; STUB="$S/stub-stub"
mkdir -p "$STATE"; cp "$S/plan.optout.json" "$plan"; cp "$plan" "$STATE/plan.saved"
python3 -I -B "$S/model.py" seed "$plan"
cap() { local rc; CAP="$("$@" 2>&1)"; rc=$?; printf -- '--- %s (exit %s)\n%s\n' "$*" "$rc" "$CAP" >> "$RAW"; return $rc; }
sleep() { :; }
preflight_runtime() { python3 -I -B "$S/model.py" validate "$plan"; }
realm_state() { [[ "$1" == --expect ]] || return 2; python3 -I -B "$S/model.py" expect "$2"; }
realm_diffs() { printf '%s\n' "$1" | grep -E '^phase3_realm:' | sed 's/^phase3_realm: //' | head -3 | tr '\n' ';'; }
login_probe() { python3 -I -B "$S/model.py" login "$1"; }
kcadm_master() {
  case "$1 $2" in
    "get users") python3 -I -B "$S/model.py" users ;;
    "get events") python3 -I -B "$S/model.py" events ;;
    "get identity-provider/instances/pingfederate") python3 -I -B "$S/model.py" idp ;;
    "delete users/"*) python3 -I -B "$S/model.py" delete-users ;;
    *) echo "stub kcadm: unhandled: $*" >&2; return 3 ;;
  esac
}
printf '#!/usr/bin/env bash\n[[ "$1 $2" == "auth apply" ]] || exit 2\nexec python3 -I -B "$S/model.py" apply "$S/pingfederate-idp.json"\n' > "$KRATE"
printf '#!/usr/bin/env bash\n[[ "${INJECT:-}" == *adduser_fails* ]] && { echo "stub: could not create stub user"; exit 1; }\nexit 0\n' > "$STUB"
chmod +x "$KRATE" "$STUB"
ok_if() { if [[ "$4" == 0 ]]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL"; fi; echo "EVIDENCE ${5:0:600}"; }
run() {
@@LOCALS@@
  plan="$S/pingfederate-idp.json"
@@BLOCK@@
}
run
'''

# Each injection perturbs exactly one effect of the P18 block's world and must turn the row to FAIL; the term it isolates is named.
P18_INJECTIONS = (
    ('preflight_accepts', 'a: the stance-less plan must be refused by the preflight'),
    ('realm_mismatch_once', 'b: the claim-filter plan must be applied (realm matches the plan)'),
    ('control_fails', 'c: the positive control must sign in'),
    ('adduser_fails', 'd: the fresh stand-in user must be created'),
    ('preexisting_once', 'e: no realm user may exist before the refused attempt'),
    ('created_on_refusal', 'f: no realm user may exist after the refused attempt'),
    ('refused_not_502', 'g: the refused attempt must end error 502 under the realm'),
    ('two_events', 'h: exactly one more error event'),
    ('events_cap', 'h: the event read must stay below its cap'),
    ('events_query_fails', 'h: a failing event read is a failure'),
    ('users_query_fails', 'e/f: a failing user read is a failure'),
    ('withdraw_says_no_changes', 'w: the withdrawing apply must update the provider, not print No changes'),
    ('withdraw_keys_stay', 'k: the live provider must lose the three keys'),
    ('idp_get_fails', 'k: a failing provider read is a failure'),
    ('relogin_fails', 'l: the same user must sign in after the withdrawal'),
    ('f1_bug', 'w/k/l: the reconcile that compares only planned keys (the F1 defect) must fail the row'),
)


def check_p18_logic(checks):
    """P18's decision logic against stubs: the runner's own block (extracted verbatim) runs in a bash driver whose effects are stubs
    and whose product logic (preflight, reconcile) is the real identity.py. NOT a live observation: it pins that every term of the
    row's pass condition can fail alone, so dropping or weakening a term is caught, and that the F1 defect shape fails the row."""
    e = checks.expect
    if bash_binary() is None:
        return
    runner = (ROOT / 'scripts/gate-identity.sh').read_text().split('\n')
    try:
        start = next(i for i, line in enumerate(runner) if line.startswith('  # ── P18:'))
        end = next(i for i, line in enumerate(runner) if line.startswith('  ok_if P18 3 P'))
        locals_ = [line for line in runner if line.startswith('  local ') and ' refused stance ' in line or line.startswith('  local rc rc2 rc3 ev before')]
    except StopIteration:
        e(False, 'check_p18_logic: the P18 block (from its comment header to its ok_if line) was not found in scripts/gate-identity.sh')
        return
    driver = P18_DRIVER.replace('@@LOCALS@@', '\n'.join(locals_)).replace('@@BLOCK@@', '\n'.join(runner[start:end + 1]))
    example = example_site()
    optout_site = {key: value for key, value in example.items() if key not in ('mfa_claim_name', 'mfa_claim_value')}
    optout_site[identity.MFA_NOT_ASSERTED_KEY] = True
    optout_plan = load_configure_dual().configs(optout_site, SYNTHETIC)['keycloak/pingfederate-idp.json']

    def run(inject):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            (scratch / 'model.py').write_text(P18_MODEL)
            (scratch / 'plan.optout.json').write_text(json.dumps(optout_plan, indent=2) + '\n')
            (scratch / 'driver.sh').write_text(driver)
            (scratch / 'events').write_text('0')
            environment = dict(os.environ, ROOT=str(ROOT), INJECT=inject)
            outcome = subprocess.run([bash_binary() or 'bash', str(scratch / 'driver.sh'), str(scratch)], text=True, capture_output=True, env=environment, timeout=120)
        return outcome.stdout, outcome.stderr, outcome.returncode
    out, err, rc = run('')
    e('RESULT P18 PASS' in out, f'check_p18_logic: the happy path of the P18 block must PASS against the stubs; got {out.strip()[-500:]!r} {err.strip()[-300:]!r}')
    e(not any(secret in out + err for secret in ALL_SECRETS), 'check_p18_logic: the P18 stub run must not print a secret')
    for inject, why in P18_INJECTIONS:
        out, err, rc = run(inject)
        e('RESULT P18 FAIL' in out, f'check_p18_logic: with {inject} the P18 block must FAIL ({why}); got {out.strip()[-300:]!r} {err.strip()[-200:]!r}')


ROTATE_DRIVER = r"""
SCRIPT_DIR="$1"; ENV_FILE="$1/.env"; ENV_TEMPLATE="$1/.env.template"; IDENTITY_REALM=krate; IDENTITY_TIMEOUT=5
IDENTITY_IDP_PLAN=auth/keycloak/pingfederate-idp.json; IDENTITY_IDP_ALIAS=pingfederate
PING_SECRET_RULE="must be a PingFederate secret"
sso_dir() { echo "$SSO_DIR"; }
# Everything that changes state or reaches Keycloak or Docker is recorded in $EFFECTS (names and paths, never a value).
require_compose() { :; }
require_compose_file() { :; }
require_sso_compose() { :; }
# The real preparation runs chmod and this image-pin boundary. Record its write so an early
# mutation cannot hide behind a no-op prepare_identity_env stub.
sync_image_pins() { echo prepare_identity_env >> "$EFFECTS"; echo PREPARED=true >> "$1"; }
require_env() { :; }
identity_lock() { :; }
identity_state() { echo existing; }
identity_verify_admin() { :; }
identity_verify_cli() { echo "identity_verify_cli" >> "$EFFECTS"; }
identity_journal() { printf 'journal %s %s %s\n' "$1" "$2" "$3" >> "$EFFECTS"; }
kcadm_login() { echo "kcadm_login" >> "$EFFECTS"; }
kcadm_logout() { :; }
kcadm_client_id() { echo client-id-1; }
random_secret() { echo "generated0123456789abcdefghij"; }
compose_cmd() { echo "compose_cmd $*" >> "$EFFECTS"; }
identity_compose() { echo "identity_compose $*" >> "$EFFECTS"; }
identity_up_service() { echo "identity_up_service $*" >> "$EFFECTS"; }
kcadm() {
  while [[ $# -gt 0 && "$1" != -- ]]; do shift; done
  shift
  echo "kcadm $1 $2" >> "$EFFECTS"
  if [[ "${KCADM_STDIN:-}" == 1 ]]; then cat > /dev/null; fi
  if [[ "$1" == get ]]; then echo '{"alias":"pingfederate"}'; fi
  return 0
}
cmd_identity_rotate "${@:2}"
"""


def check_rotate_stance(checks):
    """N1 (MFA re-review): `identity rotate` of a secret the PingFederate plan travels with refuses a plan that states no MFA stance
    BEFORE the first change. The real cmd_identity_rotate of both editions runs against stubs that record every effect: on a
    refusal .env is byte-identical and nothing was written to Keycloak, recreated or journaled; with a valid plan the same
    harness reaches every write (so the refusal case is not vacuous)."""
    e = checks.expect
    if bash_binary() is None:
        return
    module = load_configure_dual()
    pair_plan = module.configs(example_site(), SYNTHETIC)['keycloak/pingfederate-idp.json']
    stanceless = json.loads(json.dumps(pair_plan))
    for key in identity.MFA_FILTER_KEYS:
        stanceless['identityProviders'][0]['config'].pop(key)
    e(identity.MFA_NOT_ASSERTED_KEY not in stanceless, 'the stance-less rotate fixture must carry neither the pair nor the opt-out')
    optout_site = {key: value for key, value in example_site().items() if key not in ('mfa_claim_name', 'mfa_claim_value')}
    optout_site[identity.MFA_NOT_ASSERTED_KEY] = True
    optout_plan = module.configs(optout_site, SYNTHETIC)['keycloak/pingfederate-idp.json']
    rotated = 'synthetic-rotated-ping-secret-7a1b2c3d4e'
    writes = ('prepare_identity_env', 'kcadm update', 'kcadm create', 'kcadm delete', 'compose_cmd', 'identity_compose', 'identity_up_service', 'journal', 'identity_verify_cli')
    for edition in EDITIONS:
        cli_text = (ROOT / edition / 'krate').read_text()
        has_check = re.search(r'^identity_rotate_plan_check\(\) \{$', cli_text, re.M) is not None
        e(has_check, f'{edition}/krate: identity_rotate_plan_check must exist (the plan is read before the first change of identity rotate)')
        functions = bash_functions(ROOT / edition / 'krate', 'prepare_identity_env', 'env_value', 'replace_env_file', 'set_env_file_value', 'ping_secret_valid',
                                   'identity_put_idp_provider', 'identity_rotate_ping_secret', *(['identity_rotate_plan_check'] if has_check else []), 'cmd_identity_rotate')
        script = BASH_STUBS + functions + ROTATE_DRIVER

        def rotate(plan, key, mode='runtime.yml', stdin=None):
            with tempfile.TemporaryDirectory() as tmp:
                site = Path(tmp)
                (site / 'auth/keycloak').mkdir(parents=True)
                if plan is not None:
                    (site / 'auth/keycloak/pingfederate-idp.json').write_text(json.dumps(plan, indent=2) + '\n')
                write_env(site, dict(SYNTHETIC, KAFKA_UI_AUTH_CONFIG=mode, PING_KEYCLOAK_CLIENT_SECRET=RUNTIME_SITE['PING_KEYCLOAK_CLIENT_SECRET']))
                before = (site / '.env').read_bytes()
                effects = site / 'effects.log'
                effects.write_text('')
                environment = dict(os.environ, EFFECTS=str(effects), SSO_DIR=str(ROOT / 'sso'))
                outcome = run_bash(script, site, key, *(['--value'] if stdin else []), env=environment, stdin=stdin)
                result = (outcome, before, (site / '.env').read_bytes(), effects.read_text().splitlines())
            return result

        for key, mode, stdin in (('PING_KEYCLOAK_CLIENT_SECRET', 'runtime.yml', rotated + '\n'), ('KEYCLOAK_KAFBAT_CLIENT_SECRET', 'runtime.yml', None)):
            label = f'{edition}: identity rotate {key} ({mode}) on a plan that states no MFA stance'
            outcome, env_before, env_after, effects = rotate(stanceless, key, mode, stdin)
            e(outcome.returncode != 0 and 'no MFA stance' in outcome.stderr and 'Nothing was rotated' in outcome.stderr,
              f'{label} must refuse naming the stance and that nothing was rotated; got exit {outcome.returncode} {outcome.stderr.strip()[-200:]!r}')
            e(env_after == env_before, f'{label}: .env must be byte-identical after the refusal')
            e(not any(line.startswith(prefix) for line in effects for prefix in writes) and 'kcadm_login' not in effects,
              f'{label}: nothing may be written to Keycloak, recreated, verified or journaled before the refusal; got {effects}')
            e(rotated not in outcome.stdout + outcome.stderr, f'{label}: the secret is never printed')
            # The same harness reaches every write with a valid plan (and with the opt-out, the other valid stance).
            for stance, good in (('the claim pair', pair_plan), ('the opt-out', optout_plan)):
                outcome, env_before, env_after, effects = rotate(good, key, mode, stdin)
                wanted = (['kcadm update identity-provider/instances/pingfederate', 'identity_up_service keycloak'] if key.startswith('PING')
                          else ['kcadm update clients/client-id-1', 'compose_cmd up -d --pull never --no-build --no-deps --force-recreate --wait --wait-timeout 5 kafka-ui'])
                e(outcome.returncode == 0 and env_after != env_before and 'prepare_identity_env' in effects and all(item in effects for item in wanted),
                  f'{edition}: identity rotate {key} on a plan with {stance} must reach its writes ({wanted}); got exit {outcome.returncode} {outcome.stderr.strip()[-160:]!r} {effects}')
        # The check is exactly as wide as the commands that read the plan.
        outcome, env_before, env_after, effects = rotate(stanceless, 'KEYCLOAK_KAFBAT_CLIENT_SECRET', 'local.yml', None)
        e(outcome.returncode == 0 and env_after != env_before and 'kcadm update clients/client-id-1' in effects and not any(l.startswith('compose_cmd') for l in effects),
          f'{edition}: identity rotate KEYCLOAK_KAFBAT_CLIENT_SECRET in local.yml mode recreates nothing and never reads the plan; it must not be refused; got exit {outcome.returncode} {outcome.stderr.strip()[-160:]!r} {effects}')
        outcome, env_before, env_after, effects = rotate(stanceless, 'KEYCLOAK_CLI_CLIENT_SECRET', 'runtime.yml', None)
        e(outcome.returncode == 0 and env_after != env_before and 'kcadm update clients/client-id-1' in effects,
          f'{edition}: identity rotate KEYCLOAK_CLI_CLIENT_SECRET does not read the plan; it must not be refused; got exit {outcome.returncode} {outcome.stderr.strip()[-160:]!r} {effects}')
        outcome, env_before, env_after, effects = rotate(None, 'KEYCLOAK_KAFBAT_CLIENT_SECRET', 'runtime.yml', None)
        e(outcome.returncode == 0 and env_after != env_before and 'kcadm update clients/client-id-1' in effects,
          f'{edition}: identity rotate KEYCLOAK_KAFBAT_CLIENT_SECRET with no plan file (a site without PingFederate) must not be refused; got exit {outcome.returncode} {outcome.stderr.strip()[-160:]!r} {effects}')
        for key, needle in (('NOT_A_KEY', 'Usage: krate identity rotate'), ('PING_KEYCLOAK_CLIENT_SECRET', 'is issued by PingFederate')):
            outcome, env_before, env_after, effects = rotate(stanceless, key)
            e(outcome.returncode != 0 and needle in outcome.stderr and 'no MFA stance' not in outcome.stderr and env_after == env_before and not effects,
              f'{edition}: invalid key or missing --value must retain its argument error before the plan check or preparation; got exit {outcome.returncode} {outcome.stderr.strip()[-160:]!r} {effects}')
        body = function_body((ROOT / edition / 'krate').read_text(), 'cmd_identity_rotate')
        guard = '  identity_rotate_plan_check "$key"\n'
        e(body.count(guard) == 1 and body.index(guard) < body.index('prepare_identity_env; require_env')
          and body.index(guard) < body.index('read -rsp') and body.index(guard) < body.index('set_env_file_value')
          and body.index(guard) < body.index('kcadm_login'),
          f'{edition}/krate: cmd_identity_rotate must run identity_rotate_plan_check before preparation, reading a value, writing .env or logging in to Keycloak')


def check_mfa_docs(checks):
    """The guides state what the code does and no more: the commands that refuse a stance-less plan, the withdrawal procedure,
    the measured/asserted wording of P18 and the deprovisioning figures, and the Keycloak anchor lines."""
    e = checks.expect
    dual = (ROOT / 'sso/guides/dual-login.md').read_text()
    flat = ' '.join(dual.split())

    def between(text, start, stop):
        """The text from `start` up to `stop`; empty when `start` is missing, so the assertions below fail with their own message."""
        begin = text.find(start)
        if begin < 0:
            return ''
        end = text.find(stop, begin)
        return text[begin:end if end >= 0 else len(text)]
    # F3: the upgrade paragraph lists every command that refuses a plan without a stance; each is tied to the code below.
    upgrade = between(flat, 'A PingFederate site whose plan file was written before the MFA stance existed', '## Company SSO through PingFederate')
    for command in ('./krate start', './krate install', './krate auth apply', './krate identity up',
                    './krate identity rotate KEYCLOAK_KAFBAT_CLIENT_SECRET', './krate identity rotate PING_KEYCLOAK_CLIENT_SECRET'):
        e(command in upgrade, f'dual-login.md: the upgrade paragraph must list {command} among the commands that refuse a plan without an MFA stance')
    for edition in EDITIONS:
        cli = (ROOT / edition / 'krate').read_text()
        compose = function_body(cli, 'compose_cmd')
        e('preflight.py' in compose and '--mode runtime.yml' in compose and '== up' in compose,
          f'{edition}/krate: compose_cmd must run the runtime.yml preflight on `up` (it is how start, install and the rotate recreate refuse a plan)')
        for name in ('cmd_start', 'cmd_install'):
            e('compose_cmd up' in function_body(cli, name), f'{edition}/krate: {name} must go through compose_cmd up (the preflight)')
        rotate = function_body(cli, 'cmd_identity_rotate')
        e('compose_cmd up' in rotate and 'identity_rotate_ping_secret' in rotate,
          f'{edition}/krate: cmd_identity_rotate must recreate kafka-ui through compose_cmd up and update the provider through identity_rotate_ping_secret')
        e('identity.py" broker --plan "$plan" provider --with-secret' in function_body(cli, 'identity_put_idp_provider'),
          f'{edition}/krate: the provider update must read the plan through identity.py broker (broker_plan)')
    e('python3 "$sso_dir/preflight.py" --directory "$SCRIPT_DIR" --mode "$mode"' in (ROOT / 'sso/activate.sh').read_text(),
      'sso/activate.sh: apply_auth must run the preflight (auth apply)')
    e('preflight.py" --directory "$SCRIPT_DIR" --mode identity' in (ROOT / 'kraft/krate').read_text(),
      'kraft/krate: identity up must run the identity-mode preflight')
    e("`./krate auth configure` refuses a site file that states neither" in flat and 'first refusing' not in flat,
      'dual-login.md: step 3 must say that `auth configure` refuses a site file that states neither stance')
    # F1: the operator's way to change or withdraw the filter.
    e('### Changing or withdrawing the MFA claim filter' in dual, 'dual-login.md must carry the section "Changing or withdrawing the MFA claim filter"')
    section = between(flat, '### Changing or withdrawing the MFA claim filter', '### Rotating the PingFederate client secret')
    for needle in ('"mfa_not_asserted": true', 'remove `auth/ui/runtime.yml` and `auth/keycloak/pingfederate-idp.json`', './krate auth configure /path/to/site.json',
                   './krate auth apply', 'provider updated', 'not `No changes`', 'kcadm update -f -', 'merges nothing', 'federated-identity links',
                   'removing the plan file and applying'):
        e(needle in section, f'dual-login.md: the withdrawal section must state {needle!r}')
    # F8: figures and tenses the evidence supports.
    e('measured for a local user: gone within 5 s, gate row U25' in flat, 'dual-login.md: the U25 figure is a local-user measurement and must say so')
    e('gate row P18 tests' not in flat and '(gate row P18)' not in flat, 'dual-login.md must not cite gate row P18 as proof of a behavior the row has not yet shown live')
    gate = (ROOT / 'sso/guides/identity-gate.md').read_text()
    row = next((line for line in gate.splitlines() if line.startswith('| P18 |')), '')
    e('not yet observed on a live fixture' in row and 'not yet been observed on a live fixture' in ' '.join(gate.split()),
      'identity-gate.md must state that P18 has not yet been observed on a live fixture')
    e('no Kafbat `SESSION` cookie' not in row and '(`ok`, session, realm user)' not in row,
      'the identity-gate.md P18 row must not claim a Kafbat session or a realm user it does not measure')
    for needle in ('provider updated', 'Identity provider pingfederate: No changes', 'both counts below the 200-event read cap'):
        e(needle in row, f'the identity-gate.md P18 row must state {needle!r}')
    # N1: both rotates read the plan before their first change (check_rotate_stance runs it); the guide says exactly that.
    for needle in ('read it before their first change and refuse it without touching `.env`, Keycloak or any container',
                   'after a reboot `start` brings up no container until the plan is regenerated'):
        e(needle in upgrade, f'dual-login.md: the upgrade paragraph must state {needle!r}')
    # N3: step 2 tells the operator that the example's placeholders are refused.
    e('refuses a file that still holds the `REPLACE_WITH_...` placeholders and writes nothing' in flat,
      'dual-login.md: step 2 must say that `./krate auth configure` refuses a site file that still holds the placeholders')
    # N4: no citation of an untracked design or tracker identifier in a shipped file (the tokens are split so this file does not contain them).
    untracked = ('PF-' 'AMR', 'D12-' 'D13-DESIGN', "design's " 'forge', 'design ' 'cites', 'DESIGN ' '4.5', 'design file is ' 'a historical')
    for rel in ('scripts/gate-identity.sh', 'scripts/gate/stub_idp.sh', 'scripts/check-identity.py', 'sso/identity.py', 'sso/configure.py', 'sso/configure-dual.py',
                'sso/preflight.py', 'sso/guides/dual-login.md', 'sso/guides/identity-gate.md', 'sso/guides/identity-foundation.md', 'sso/guides/pingfederate-iam-guide.md',
                'README.md'):
        text = (ROOT / rel).read_text()
        e(not any(token in text for token in untracked), f'{rel}: must not cite a design or tracker identifier that no tracked file carries')
    # N5: the merge decision is cited where the code takes it (AbstractRequestCmd), not at kcadm's help text (UpdateCmd).
    for rel in ('sso/identity.py', 'sso/guides/identity-gate.md'):
        text = ' '.join((ROOT / rel).read_text().split())
        e('AbstractRequestCmd.java' in text and ':171 and :244' in text and 'UpdateCmd' not in text,
          f'{rel}: kcadm merge mode must be cited at AbstractRequestCmd.java :171 and :244, not at UpdateCmd.java help text')
    # N6: identity-foundation.md says where identity up refuses a plan without a stance.
    foundation = ' '.join((ROOT / 'sso/guides/identity-foundation.md').read_text().split())
    e('refuses one that states no MFA stance' in foundation and 'step 4 has already refused a plan that states no MFA stance' in foundation,
      'identity-foundation.md must say that the identity preflight (step 4) refuses a plan without an MFA stance and that step 10 relies on it')
    e('Before step 1, for `KEYCLOAK_KAFBAT_CLIENT_SECRET` in `runtime.yml` mode and for `PING_KEYCLOAK_CLIENT_SECRET`' in foundation
      and 'stops it with `Nothing was rotated`' in foundation and 'stops the command with `Nothing was rotated`' in flat,
      'identity-foundation.md and dual-login.md must say that identity rotate reads the plan before its first change and stops with `Nothing was rotated`')
    # N7: the withdrawal says what not to do exactly, and the replace semantics are stated as read from source, not observed.
    e('without regenerating it' in section and 'has not yet been observed on a running Keycloak' in section,
      'dual-login.md: the withdrawal section must say "without regenerating it" and that the replace semantics are not yet observed on a running Keycloak')
    e('exercised by the row' not in row and 'not yet observed on a running Keycloak' in row,
      'identity-gate.md: the P18 row must state the provider-update semantics as read from source and not yet observed on a running Keycloak')
    # F10: the filter code is at OIDCIdentityProvider.java 490-512, not 479-512.
    for rel in ('sso/identity.py', 'scripts/gate-identity.sh', 'sso/guides/identity-gate.md', 'sso/guides/dual-login.md'):
        e('479-512' not in (ROOT / rel).read_text(), f'{rel}: the claim filter is at OIDCIdentityProvider.java 490-512 (479 is the passMaxAge block)')
    e('MFA stance' in (ROOT / 'README.md').read_text(), 'README.md must mention that the PingFederate site file states the MFA stance')
    e('mfa_not_asserted' in (ROOT / 'sso/guides/pingfederate-iam-guide.md').read_text(), 'pingfederate-iam-guide.md must ask IAM for the MFA claim or the statement that none is asserted')
    # F5: P18 must not write the journal line P14 looks for, and P14 must require a NEW line.
    runner = (ROOT / 'scripts/gate-identity.sh').read_text()
    p18_block = between(runner, '  # ── P18:', '  ok_if P18 3 P')
    p14_block = between(runner, '  # ── P14:', '  ok_if P14 3 P')
    e(p18_block != '' and 'rm -f "$plan"' not in p18_block,
      'P18 must not remove the plan file: that apply would write the journal line P14 checks and drop the brokered users\' links')
    counted = p14_block.find("jb=\"$(grep -c ' apply removed identity provider'")
    e(0 <= counted < p14_block.find('cap "$KRATE" auth apply') and '-gt "${jb:-0}"' in p14_block,
      "P14's journal term must compare the line count after its own apply with the count taken before it")

    # The row's wiring and the guide's counts (carried over from round 1; the inventory arithmetic is derived from the runner's arrays).
    e('P18' in runner and re.search(r'^REQUIRED_P3=\(.*\bP18\b.*\)$', runner, re.M) is not None, 'the runner inventory REQUIRED_P3 must carry P18')
    e(len([line for line in runner.splitlines() if line.startswith('  ok_if P18 3 P')]) == 1, 'the runner must hold exactly one ok_if P18 3 P row')
    e('IDENTITY_PROVIDER_LOGIN_ERROR' in runner and runner.count('login_probe ping-mfa') == 2,
      'the P18 row must drive the refusal through the runner login_probe twice (the refused attempt and the sign-in after the withdrawal)')
    e(row != '', 'identity-gate.md must have a row for the gate row P18')
    for needle in ('502', 'IDENTITY_PROVIDER_LOGIN_ERROR', 'mfa_not_asserted', 'no realm user', 'identity_provider_login_failure', 'keycloak_login_flow.py:132'):
        e(needle in row, f'the identity-gate.md P18 row must state {needle!r}')
    e('enforce-if-asserted' in gate and 'mfa_not_asserted' in gate and 'MFA enforced at Ping only' in gate,
      'identity-gate.md must state the enforce-if-asserted decision and the opt-out wording')
    e(re.search(r'`REQUIRED_P3` is P1–P16, P18 and Z3 \(18 ids\)', gate) is not None, 'identity-gate.md must count P18 in REQUIRED_P3 (18 ids)')

    def required(name):
        found = re.search(r'^REQUIRED_%s=\((.*)\)$' % name, runner, re.M)
        return found.group(1).split() if found else []
    sizes = {name: required(name) for name in ('P1', 'P2', 'P3', 'X')}
    total = sum(len(ids) for ids in sizes.values())
    static = len([i for i in sizes['P1'] if i.startswith('S')])
    gate_flat = ' '.join(gate.split())
    e(f'is {total} ids ({total - 1} where J7 leaves the inventory' in gate_flat
      and f'`--no-static --no-screenshots` {total - static - 1}, {total - static - 2} without J7' in gate_flat
      and f'AG1–AG5 add five ({total + 5}, {total + 4}, {total - static + 4}, {total - static + 3})' in gate_flat,
      f'identity-gate.md must state the --phase 3/all inventory as {total} ids ({total - 1} without J7; {total - static - 1}/{total - static - 2} with --no-static --no-screenshots; '
      f'{total + 5}/{total + 4}/{total - static + 4}/{total - static + 3} on a bundle host with AG1-AG5)')
    e('### Deprovisioning a PingFederate user' in dual and 'users disable' in dual and 'users logout' in dual
      and 'P20' in dual and '8 hours' in dual and '15 minutes' in dual,
      'dual-login.md must carry the decided deprovisioning contract (two-step, upstream alone ends nothing, the bounds, P20)')
    e("State the site's MFA stance explicitly, one of the two (enforce-if-asserted):" in dual
      and 'mfa_claim_name' in dual and 'mfa_claim_value' in dual and 'mfa_not_asserted' in dual,
      'dual-login.md must document the site-file MFA stance keys and the explicit choice (enforce-if-asserted)')
    e('"mfa_not_asserted": True' in (ROOT / 'scripts/gate/stub_idp.sh').read_text(),
      'stub_idp.sh must write the stand-in site file with the explicit mfa_not_asserted stance')


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


def check_perses_sync_scopes(checks):
    """The repeated `krate-perses-sync: its scopes differ from the plan` warning: Keycloak 26.1.0+
    assigns the realm scope `service_account` to every client with serviceAccountsEnabled
    (ClientManager.enableServiceAccount, tag 26.8.0), so the readback of the sync client carries a
    scope the plan did not list and the second `krate monitor up` (the first one creates the
    clients and compares nothing) and every later one reported drift nobody made. The plan states
    the scope for the service-account client; a real drift is still reported."""
    e = checks.expect
    origin, port = 'https://krate.example.test', '3443'
    scope = identity.SERVICE_ACCOUNT_SCOPE
    e(scope == 'service_account', f'identity.SERVICE_ACCOUNT_SCOPE must be Keycloak\'s realm scope name; got {scope!r}')

    def verdict(name, current):
        """The two verdict lines `identity.py perses-clients client-differs` prints, as the CLI reads them."""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            identity.client_verdict(identity.perses_rep(name, origin, port), current)
        return buffer.getvalue().split()

    def readback(plan, default, optional=()):
        """The shape Keycloak's GET clients/<id> returns: the plan, Keycloak's own additions, the
        secret masked, the scope lists in an order of Keycloak's choosing (not the plan's)."""
        return dict(plan, id='3f1c7a52-0b6d-4c1e-9d2a-5e8b4a7c6d10', surrogateAuthRequired=False, bearerOnly=False,
                    consentRequired=False, alwaysDisplayInConsole=False, fullScopeAllowed=True,
                    nodeReRegistrationTimeout=-1, access={'view': True, 'configure': True, 'manage': True},
                    secret=identity.KEYCLOAK_SECRET_MASK, defaultClientScopes=list(default),
                    optionalClientScopes=list(optional))

    sync = identity.perses_rep('krate-perses-sync', origin, port)
    main_client = identity.perses_rep('krate-perses', origin, port)
    e(sync['serviceAccountsEnabled'] is True and scope in sync['defaultClientScopes']
      and sync['defaultClientScopes'].count(scope) == 1
      and sorted(sync['defaultClientScopes']) == sorted(identity.DEFAULT_SCOPES + [scope]),
      f'the krate-perses-sync plan must list the scopes of the krate-perses client and {scope} once; got {sync["defaultClientScopes"]}')
    e(identity.DEFAULT_SCOPES == ['profile', 'email', 'roles', 'web-origins', 'basic'],
      'identity.DEFAULT_SCOPES is shared by every client plan: the service-account scope is added to the sync plan only')
    e(main_client['serviceAccountsEnabled'] is False and scope not in main_client['defaultClientScopes'],
      f'the krate-perses client has no service account, so Keycloak gives it no {scope} scope and its plan must not list it')
    e(identity.perses_rep('krate-perses-sync', origin, port, False)['defaultClientScopes']
      == identity.perses_rep('krate-perses-sync', origin, port)['defaultClientScopes'],
      'the sync plan scopes must not depend on the secret flag')
    # Every client plan the CLI compares (the verdict is reached from cmd_grafana_client and
    # cmd_perses_clients only) must state what Keycloak does for it.
    for plan in identity.perses_clients(origin, port) + [identity.grafana_client(origin)]:
        has_scope = scope in plan['defaultClientScopes']
        e(has_scope == bool(plan['serviceAccountsEnabled']),
          f'{plan["clientId"]}: its plan lists {scope} exactly when serviceAccountsEnabled is true; got '
          f'serviceAccountsEnabled={plan["serviceAccountsEnabled"]} scopes={plan["defaultClientScopes"]}')

    # Keycloak's readback of the sync client right after Krate created it: the plan's scopes plus
    # service_account, in an order of Keycloak's own.
    live_order = [scope, 'web-origins', 'roles', 'basic', 'profile', 'email']
    got = verdict('krate-perses-sync', readback(sync, live_order))
    e(got == ['same'], f'the sync client as Keycloak reads it back (the plan plus {scope}) must compare as same; got {got}')
    got = verdict('krate-perses-sync', readback(sync, reversed(live_order)))
    e(got == ['same'], f'the scope order of the readback must not matter; got {got}')
    # Real drift is still reported.
    without = [item for item in live_order if item != scope]
    got = verdict('krate-perses-sync', readback(sync, without))
    e(got == ['same', 'scopes-differ'], f'a sync client without {scope} is a real drift to report; got {got}')
    got = verdict('krate-perses-sync', readback(sync, live_order + ['offline_access']))
    e(got == ['same', 'scopes-differ'], f'a sync client with an extra default scope is a real drift to report; got {got}')
    got = verdict('krate-perses-sync', readback(sync, live_order + ['phone']))
    e(got == ['same', 'scopes-differ'], f'a sync client with an extra unrelated scope is a real drift to report; got {got}')
    got = verdict('krate-perses-sync', readback(sync, without, optional=[scope]))
    e(got == ['same', 'scopes-differ'], f'{scope} as an optional scope instead of a default one is a real drift to report; got {got}')
    got = verdict('krate-perses-sync', readback(sync, live_order, optional=['offline_access']))
    e(got == ['same', 'scopes-differ'], f'an extra optional scope on the sync client is a real drift to report; got {got}')
    # The client without a service account: Keycloak adds nothing, so the scope appearing is drift.
    got = verdict('krate-perses', readback(main_client, list(identity.DEFAULT_SCOPES)))
    e(got == ['same'], f'the krate-perses readback with the plan scopes must compare as same; got {got}')
    got = verdict('krate-perses', readback(main_client, list(identity.DEFAULT_SCOPES) + [scope]))
    e(got == ['same', 'scopes-differ'], f'{scope} on a client without a service account is a real drift to report; got {got}')


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
                  check_grafana_realm_cli, check_monitor_idp_host_stable, check_grafana_collision_paging, check_grafana_realm_plan, check_perses_clients, check_perses_sync_scopes, check_perses_address, check_monitor_logins, check_build_certificate_hint,
                  check_render_writes, check_migrate_issuer, check_monitoring_tables,
                  check_grafana_admin_contract,
                  check_logrotate, check_cli_kafbat, check_exposure, check_gate_scripts, check_topofix2, check_mac_launcher_round4, check_mac_ipv6_ports, check_firewall_round4, check_browser_certificate_proceed, check_browser_certificate_binding, check_browser_http_guard, check_browser_http_callers, check_browser_story_ports, check_browser_probe_lifecycle, check_browser_probe_consumer, check_mac_ipv4_outcomes, check_k37_wiring, check_phase4_monitor_paths, check_airgap_rows,
                  check_parity, check_zk_frozen, check_writers, check_backup_seal,
                  check_plan_and_preflight, check_configure_dual, check_runtime_preflight, check_probe_causes, check_probe_diagnostic_privacy,
                  check_bash_available, check_proxy_env, check_nginx_edge, check_nginx_render, check_identity_dirs, check_identity_users,
                  check_install_home_dir, check_deploy_release, check_rpm_install, check_gen_cert_ip, check_public_cert_permissions,
                  check_renew_db_tls_order, check_summaries, check_realm_reconcile, check_health, check_install_lock,
                  check_broker_apply, check_truststore_env, check_broker_docs, check_mfa_choice, check_mfa_reconcile, check_rotate_stance, check_mfa_docs, check_p18_logic):
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
          'PingFederate broker plan/apply/removal, the MFA stance (site keys, plan, claim-filter reconcile, P18 logic against stubs), truststore digest, Phase 3 docs, identity users logout/set-email and the realm-UI e-mail rule, '
          'Prometheus lifecycle off and the SIGHUP reload result, the read-only Loki gateway, '
          'the Grafana realm switch (compose, proxy front, CLI, realm.ini and clients).')
    if RENDER_IMAGE_NOTE:  # its own last line: the gate records the last line as the S4 evidence
        print('[' + '; '.join(RENDER_IMAGE_NOTE) + ']')
    return 0


if __name__ == '__main__':
    sys.exit(main())
