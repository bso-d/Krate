#!/usr/bin/env python3
"""Static checks for the Krate identity foundation (templates, realm plan, Compose, CLI parity)."""
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
}
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
                          ('browserFlow', 'browser')):
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
    e(attributes.get('post.logout.redirect.uris') == origin + '/*', 'realm plan: krate-ui post-logout redirect must be <origin>/*')
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


def compose_config(env_file, edition):
    result = subprocess.run(
        ['docker', 'compose', '--env-file', str(env_file), '-f', str(ROOT / edition / 'docker-compose.yml'),
         '--profile', 'sso', 'config', '--format', 'json'],
        cwd=ROOT, text=True, capture_output=True)
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
    files = subprocess.run(['git', 'ls-files', '-z', 'zk'], cwd=ROOT, text=True, capture_output=True).stdout.split('\0')
    for name in filter(None, files):
        if re.search(r'keycloak|identity', (ROOT / name).read_text(errors='replace'), re.IGNORECASE):
            checks.errors.append(f'zk frozen: {name} mentions keycloak/identity')
    base = subprocess.run(['git', 'rev-parse', '--verify', '--quiet', 'origin/main'], cwd=ROOT, capture_output=True)
    if not checks.expect(base.returncode == 0, 'zk frozen: origin/main is not available for comparison'):
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
        plan = Path(tmp) / 'realm.json'
        checks.expect(identity.write_if_changed(plan, '{}\n', 0o644) is True and mode(plan) == 0o644,
                      'identity.write_if_changed: realm plan must be created with mode 0644')
        checks.expect(identity.write_if_changed(plan, '{}\n', 0o644) is False, 'identity.write_if_changed: identical content must be a no-op')
        checks.expect(not plan.with_name('.realm.json.tmp').exists(), 'identity.write_if_changed: temporary file must not remain')


def synthetic_site(edition, directory):
    """A complete site directory for `edition` built only from synthetic values."""
    site = Path(directory) / edition
    site.mkdir(mode=0o700)
    env = identity.read_env(ROOT / edition / '.env.template')
    env.update(SYNTHETIC)
    identity.write_file(site / '.env', ''.join(f'{key}={value}\n' for key, value in env.items()), 0o600)
    identity.db_tls(site / 'auth/keycloak/db-tls')
    return site


def check_plan_and_preflight(checks):
    for edition in EDITIONS:
        with tempfile.TemporaryDirectory() as tmp:
            site = synthetic_site(edition, tmp)
            realm_file = site / 'auth/keycloak/krate-realm.json'
            command = [sys.executable, '-I', str(ROOT / 'sso/identity.py'), 'plan',
                       '--env-file', str(site / '.env'), '--output', str(realm_file), '--print']
            first = subprocess.run(command, text=True, capture_output=True)
            second = subprocess.run(command[:-1], text=True, capture_output=True)
            output = first.stdout + first.stderr + second.stdout + second.stderr + realm_file.read_text()
            checks.expect(first.returncode == 0 and second.returncode == 0, f'{edition}: identity.py plan failed on a synthetic .env')
            checks.expect(not any(secret in output for secret in SYNTHETIC_SECRETS), f'{edition}: identity.py plan output leaked a secret value')
            checks.expect('No changes' in second.stdout, f'{edition}: a second identity.py plan must report No changes')
            code, rendered = compose_config(site / '.env', edition)
            if not checks.expect(code == 0, f'{edition}: Compose rendering of the synthetic site failed'):
                continue
            result = subprocess.run([sys.executable, '-I', str(ROOT / 'sso/preflight.py'), '--directory', str(site), '--mode', 'identity'],
                                    input=rendered, text=True, capture_output=True)
            checks.expect(result.returncode == 0, f'{edition}: preflight --mode identity refused a complete synthetic site: {result.stderr.strip()}')
            checks.expect(not any(secret in result.stdout + result.stderr for secret in SYNTHETIC_SECRETS),
                          f'{edition}: preflight output leaked a secret value')


def main():
    checks = Checks()
    for check in (check_templates, check_realm_contract, check_compose, check_parity, check_zk_frozen,
                  check_writers, check_plan_and_preflight):
        try:
            check(checks)
        except Exception as exc:  # one failing check must not hide the others
            checks.errors.append(f'{check.__name__}: {type(exc).__name__}: {exc}')
    if checks.errors:
        print('Identity check failed:\n' + '\n'.join(checks.errors), file=sys.stderr)
        return 1
    print('Identity foundation verified: templates, realm plan, Compose services, CLI parity, zk frozen, writers, preflight.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
