#!/usr/bin/env python3
"""Static checks for the Krate identity foundation (templates, realm plan, Compose, CLI parity)."""
import contextlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sso'))
import identity  # noqa: E402

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
IDP_PLAN_KEYS = {'identityProviders', 'identityProviderMappers', 'authenticatorConfig', 'authenticationFlows', 'browserFlow'}
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
                          ('browserFlow', 'browser'), *EXPECTED_EVENTS.items()):
        e(realm.get(key) == expected, f'realm plan: {key} must be {expected!r}; got {realm.get(key)!r}')
    for key in ('offlineSessionIdleTimeout', 'identityProviders', 'identityProviderMappers',
                'authenticationFlows', 'authenticatorConfig', 'defaultRoles', 'defaultRole'):
        e(key not in realm, f'realm plan: {key} must not be set in local mode')
    actions = {action['alias']: action for action in realm.get('requiredActions', [])}
    totp = actions.get('CONFIGURE_TOTP', {})
    e(totp.get('enabled') is True and totp.get('defaultAction') is True,
      'realm plan: CONFIGURE_TOTP must be enabled with defaultAction true')
    e(actions.get('UPDATE_PASSWORD', {}).get('enabled') is True, 'realm plan: UPDATE_PASSWORD must be enabled')
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
    e(set(data) == {'server', 'auth', 'rbac'}, f'top-level keys must be server, auth, rbac; got {sorted(data)}')
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
                ('--fields redirectUris,webOrigins,"attributes($keys)"', 'identity_reconcile_ui_urls must fetch every planned attribute'),
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
        for path in ('/metrics', '/actuator/', '/logout/connect/'):
            block = nginx.find('    location ^~ ' + path + ' {\n        return 404;')
            e(0 <= block < public, f'{edition}/nginx.conf: {path} must return 404 before the catch-all location /')
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
    build = (ROOT / 'kafbat-ui/build.py').read_text()
    e("IMAGE = 'krate/kafka-ui:1.5.0-sso.7'" in build, 'kafbat-ui/build.py must build sso.7 (the templates pin it)')


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


def self_signed(certs, host):
    """certs/server.crt + server.key for `host` (key 0600), as krate gen-cert would provide."""
    certs.mkdir(mode=0o700)
    previous = os.umask(0o077)
    try:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '2',
                        '-subj', '/CN=' + host, '-addext', 'subjectAltName=DNS:' + host,
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
    def mutate(label, change):
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
    for key in MOVED_SITE_KEYS:
        try:
            module.configs(dict(example, **{key: 5 if key == 'session_idle_minutes' else True}), SYNTHETIC)
            e(False, f'configure-dual: a site file with {key} must be refused (the value lives in .env)')
        except ValueError as exc:
            e('.env' in str(exc), f'configure-dual: the refusal of {key} must point at .env; got {exc}')


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
            if ping:  # the PingFederate flow: configure-dual writes runtime.yml and the identity-provider plan
                for name, data in load_configure_dual().configs(settings, env).items():
                    identity.write_file(site / 'auth' / name, json.dumps(data, indent=2) + '\n', 0o644)
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


def check_runtime_refusals(checks, edition, site, env, rendered):
    """A runtime.yml, realm file or rendering that widens Kafbat access must be refused by name."""
    runtime_file = site / 'auth/ui/runtime.yml'
    realm_file = site / 'auth/keycloak/krate-realm.json'
    original = runtime_file.read_text()
    realm_original = realm_file.read_text()

    def expect_refusal(label, needle, auth_mode='runtime.yml', config=rendered):
        result = preflight(site, auth_mode, config)
        checks.expect(result.returncode == 1 and needle in result.stderr,
                      f'{edition}: preflight --mode runtime.yml must refuse: {label} (naming {needle!r});'
                      f' got exit {result.returncode}: {result.stderr.strip()}')

    def viewer_topic(d):
        return next(p for p in d['rbac']['roles'][0]['permissions'] if p['resource'] == 'topic')

    def mutated_runtime(change):
        data = json.loads(original)
        change(data)
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
    kafbat.write_text('kafka:\n  clusters:\n    - name: x\n')
    result = preflight(site, 'runtime.yml', rendered)
    checks.expect(result.returncode == 0, f'{edition}: preflight must accept a kafbat.yml with only the kafka: section; got exit {result.returncode}: {result.stderr.strip()}')
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
    expect_refusal('kafka-ui without the auth/ui mount', '/etc/krate/auth', config=json.dumps(config))
    config = json.loads(rendered)
    for mount in config['services']['kafka-ui']['volumes']:
        if mount.get('target') == '/etc/krate/auth':
            mount['source'] = str(ROOT / 'kraft/auth/ui')
    expect_refusal('kafka-ui mounting another directory at /etc/krate/auth', '/etc/krate/auth', config=json.dumps(config))
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


def main():
    checks = Checks()
    for check in (check_templates, check_realm_contract, check_runtime_contract, check_names, check_compose, check_monitoring_binds,
                  check_logrotate, check_cli_kafbat, check_exposure, check_parity, check_zk_frozen, check_writers, check_backup_seal,
                  check_plan_and_preflight, check_configure_dual, check_runtime_preflight):
        try:
            check(checks)
        except Exception as exc:  # one failing check must not hide the others
            checks.errors.append(f'{check.__name__}: {type(exc).__name__}: {exc}')
    if checks.errors:
        print('Identity check failed:\n' + '\n'.join(checks.errors), file=sys.stderr)
        return 1
    print('Identity foundation verified: templates, realm plan, Kafbat runtime plan, names, Compose services and identity network, '
          'monitoring binds, logrotate drop-in, CLI Kafbat wiring and parity, zk frozen, writers and renewal, preflight (identity and '
          'runtime.yml incl. refusals), configure-dual.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
