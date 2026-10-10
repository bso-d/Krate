#!/usr/bin/env python3
"""Plan the local Keycloak realm and generate database TLS material for Krate identity.

Secrets never enter this program's output: the realm plan carries ``${VAR}``
placeholders that Keycloak resolves from its environment at import time.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


REALM = 'krate'
UI_CLIENT = 'krate-ui'
CLI_CLIENT = 'krate-cli'
SERVICE_ACCOUNT = 'service-account-' + CLI_CLIENT
CLI_ROLES = ['manage-users', 'view-users', 'query-users', 'query-groups']
UI_SECRET = '${KEYCLOAK_KAFBAT_CLIENT_SECRET}'
CLI_SECRET = '${KEYCLOAK_CLI_CLIENT_SECRET}'
# The .env keys the plan refers to by placeholder; named here for the summary only.
PLAN_PLACEHOLDER_KEYS = ('KEYCLOAK_CLI_CLIENT_SECRET', 'KEYCLOAK_KAFBAT_CLIENT_SECRET')
GROUPS_CLAIM = 'groups'
# Default client scopes without offline_access: no client may mint offline tokens.
DEFAULT_SCOPES = ['profile', 'email', 'roles', 'web-origins', 'basic']
DEFAULTS = {
    'KEYCLOAK_VIEWER_GROUP': 'KRATE_VIEWERS',
    'KEYCLOAK_ADMIN_GROUP': 'KRATE_ADMINS',
    'KEYCLOAK_ACCESS_TOKEN_MINUTES': '5',
    'KEYCLOAK_SESSION_IDLE_MINUTES': '15',
    'KEYCLOAK_SESSION_MAX_HOURS': '8',
}
PLACEHOLDERS = ('', 'REPLACE_ME')
SECRET_KEY = re.compile(r'(_PASSWORD|_SECRET)$')
ENV_KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
# Group names travel through kcadm arguments and the groups claim; keep them to a plain token.
GROUP_NAME = re.compile(r'[A-Za-z0-9_.-]{1,64}')
# The permanent master-realm admin created by `krate identity up`; kcadm addresses it by name.
ADMIN_USER = re.compile(r'[a-z0-9][a-z0-9._@-]{0,62}')
# `kc.sh bootstrap-admin user` names start with this; those users are temporary and get deleted.
BOOTSTRAP_PREFIX = 'temp-admin'
# Keycloak event settings: user and admin events logged to the server log, kept 30 days.
EVENTS = {
    'eventsEnabled': True,
    'eventsListeners': ['jboss-logging'],
    'enabledEventTypes': [],  # empty = Keycloak's default event type set
    'eventsExpiration': 30 * 24 * 3600,
    'adminEventsEnabled': True,
    'adminEventsDetailsEnabled': False,
}

DB_HOST = 'keycloak-db'
CA_NAME = 'Krate identity CA'
# The CA lives as long as the installation's trust (Keycloak's trust store is
# ca.crt); the server certificate is short-lived and reissued under it by
# `krate identity renew-db-tls` (PostgreSQL 17: "The server reads these files at
# server start and whenever the server configuration is reloaded").
CA_CERT_DAYS = 1825
SERVER_CERT_DAYS = 398
TLS_FILES = ('ca.key', 'ca.crt', 'server.key', 'server.crt', 'pg_hba.conf')
TLS_MODES = {'ca.key': 0o600, 'server.key': 0o600, 'ca.crt': 0o644, 'server.crt': 0o644, 'pg_hba.conf': 0o644}
PG_HBA = ('local   all all                     trust\n'
          'hostssl all all 0.0.0.0/0           scram-sha-256\n'
          'hostssl all all ::/0                scram-sha-256\n'
          'host    all all all                 reject\n')
SERVER_EXTENSIONS = ('basicConstraints=CA:FALSE\n'
                     'keyUsage=critical,digitalSignature,keyEncipherment\n'
                     'extendedKeyUsage=serverAuth\n'
                     'subjectAltName=DNS:' + DB_HOST + '\n')


class IncompleteMaterial(ValueError):
    """Some, but not all, TLS files exist; regenerating would silently break trust."""


# ─── .env helpers ──────────────────────────────────────────────────────────────

def read_env(path):
    """Parse KEY=VALUE lines without shell expansion; the last assignment wins."""
    values = {}
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        if key.startswith('export '):
            key = key[len('export '):].strip()
        if not ENV_KEY.fullmatch(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        values[key] = value
    return values


def public_origin(url):
    """KEYCLOAK_PUBLIC_URL without its trailing /identity; https only."""
    parts = urlsplit(url or '')
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or parts.path.rstrip('/') != '/identity'):
        raise ValueError('KEYCLOAK_PUBLIC_URL must be an https URL whose path is /identity')
    return 'https://' + parts.netloc


def secret_values(env):
    """Configured secret values (keys ending in _PASSWORD or _SECRET) that are not placeholders."""
    return {key: value for key, value in env.items()
            if SECRET_KEY.search(key) and value not in PLACEHOLDERS}


def _positive(env, key):
    value = env.get(key) or DEFAULTS[key]
    if not value.isdigit() or int(value) < 1:
        raise ValueError(key + ' must be a whole number of at least 1')
    return int(value)


def _group(env, key):
    value = env.get(key) or DEFAULTS[key]
    if not GROUP_NAME.fullmatch(value):
        raise ValueError(key + ' must be 1-64 characters from letters, digits, . _ - (no spaces or slashes)')
    return value


def group_names(env):
    """(viewer group, admin group) from a parsed .env mapping; validated and distinct."""
    viewer, admin = _group(env, 'KEYCLOAK_VIEWER_GROUP'), _group(env, 'KEYCLOAK_ADMIN_GROUP')
    if viewer == admin:
        raise ValueError('KEYCLOAK_VIEWER_GROUP and KEYCLOAK_ADMIN_GROUP must differ')
    return viewer, admin


def admin_user(env):
    """KEYCLOAK_ADMIN_USER: the permanent master-realm admin name; never a bootstrap-admin name."""
    value = env.get('KEYCLOAK_ADMIN_USER', '')
    if not ADMIN_USER.fullmatch(value):
        raise ValueError('KEYCLOAK_ADMIN_USER must be 1-63 characters: a lower-case letter or digit,'
                         ' then lower-case letters, digits, . _ @ -')
    if value.startswith(BOOTSTRAP_PREFIX):
        raise ValueError(f'KEYCLOAK_ADMIN_USER must not start with {BOOTSTRAP_PREFIX}:'
                         ' that prefix names the temporary bootstrap admin')
    return value


def settings(env):
    """Non-secret realm inputs taken from a parsed .env mapping."""
    viewer_group, admin_group = group_names(env)
    return {
        'public_origin': public_origin(env.get('KEYCLOAK_PUBLIC_URL')),
        'viewer_group': viewer_group,
        'admin_group': admin_group,
        'access_token_minutes': _positive(env, 'KEYCLOAK_ACCESS_TOKEN_MINUTES'),
        'session_idle_minutes': _positive(env, 'KEYCLOAK_SESSION_IDLE_MINUTES'),
        'session_max_hours': _positive(env, 'KEYCLOAK_SESSION_MAX_HOURS'),
    }


# ─── Realm plan (pure) ─────────────────────────────────────────────────────────

def realm(values):
    """Local-mode realm from settings(): local users, two groups, two clients, no identity providers."""
    origin = values['public_origin']
    ui_client = {
        'clientId': UI_CLIENT, 'name': 'Kafbat UI', 'enabled': True,
        'protocol': 'openid-connect', 'publicClient': False,
        'clientAuthenticatorType': 'client-secret', 'secret': UI_SECRET,
        'standardFlowEnabled': True, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
        'redirectUris': [origin + '/login/oauth2/code/keycloak'],
        'webOrigins': [origin],
        'attributes': {'pkce.code.challenge.method': 'S256',
                       'post.logout.redirect.uris': origin + '/*'},
        'defaultClientScopes': list(DEFAULT_SCOPES),
        'optionalClientScopes': [],
        'protocolMappers': [{
            'name': 'groups', 'protocol': 'openid-connect',
            'protocolMapper': 'oidc-group-membership-mapper', 'consentRequired': False,
            'config': {'claim.name': GROUPS_CLAIM, 'full.path': 'false', 'multivalued': 'true',
                       'id.token.claim': 'true', 'access.token.claim': 'true',
                       'userinfo.token.claim': 'true'},
        }],
    }
    cli_client = {
        'clientId': CLI_CLIENT, 'name': 'Krate CLI user management', 'enabled': True,
        'protocol': 'openid-connect', 'publicClient': False,
        'clientAuthenticatorType': 'client-secret', 'secret': CLI_SECRET,
        'standardFlowEnabled': False, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': True,
        'redirectUris': [], 'webOrigins': [],
        'defaultClientScopes': list(DEFAULT_SCOPES),
        'optionalClientScopes': [],
    }
    return {
        'realm': REALM, 'enabled': True,
        'registrationAllowed': False, 'resetPasswordAllowed': False,
        'rememberMe': False, 'verifyEmail': False,
        'bruteForceProtected': True, 'failureFactor': 5, 'permanentLockout': False,
        'waitIncrementSeconds': 60, 'maxFailureWaitSeconds': 900,
        'accessTokenLifespan': values['access_token_minutes'] * 60,
        'ssoSessionIdleTimeout': values['session_idle_minutes'] * 60,
        'ssoSessionMaxLifespan': values['session_max_hours'] * 3600,
        'otpPolicyType': 'totp', 'otpPolicyAlgorithm': 'HmacSHA1',
        'otpPolicyDigits': 6, 'otpPolicyPeriod': 30,
        **EVENTS,
        'requiredActions': [
            {'alias': 'CONFIGURE_TOTP', 'name': 'Configure OTP', 'providerId': 'CONFIGURE_TOTP',
             'enabled': True, 'defaultAction': True, 'priority': 10},
            {'alias': 'UPDATE_PASSWORD', 'name': 'Update Password', 'providerId': 'UPDATE_PASSWORD',
             'enabled': True, 'defaultAction': False, 'priority': 30},
        ],
        'groups': [{'name': values['viewer_group']}, {'name': values['admin_group']}],
        'clients': [cli_client, ui_client],
        'users': [{'username': SERVICE_ACCOUNT, 'enabled': True,
                   'serviceAccountClientId': CLI_CLIENT,
                   'clientRoles': {'realm-management': list(CLI_ROLES)}}],
        'browserFlow': 'browser',
    }


def render(data):
    return json.dumps(data, indent=2) + '\n'


def summary(data, path, outcome):
    """Human-readable description of a realm plan; it never touches a credential field."""
    clients = {client['clientId']: client for client in data['clients']}
    ui = clients[UI_CLIENT]
    lines = [
        f"Realm plan: {data['realm']} (local mode, identity providers: {len(data.get('identityProviders', []))})",
        '  public origin: ' + ui['webOrigins'][0],
        '  groups: ' + ', '.join(group['name'] for group in data['groups']),
        '  clients: ' + ', '.join(f"{name} ({'service account' if client['serviceAccountsEnabled'] else 'browser login'})"
                                 for name, client in clients.items()),
        f"  access token {data['accessTokenLifespan']} s, session idle {data['ssoSessionIdleTimeout']} s,"
        f" session max {data['ssoSessionMaxLifespan']} s",
        '  placeholders for: ' + ', '.join(PLAN_PLACEHOLDER_KEYS) + ' (values stay in .env)',
        f'  {path}: {outcome}',
    ]
    return '\n'.join(lines)


# ─── Writers ───────────────────────────────────────────────────────────────────

def write_file(path, content, mode):
    """Create the file atomically: O_EXCL temporary beside the target, then rename."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # A unique name per attempt: a temporary left by an interrupted run can
    # never block a later one (O_EXCL still refuses to reuse or follow it).
    temporary = path.with_name('.%s.%s.tmp' % (path.name, secrets.token_hex(4)))
    data = content if isinstance(content, bytes) else content.encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_if_changed(path, content, mode):
    """Write only when content or mode differ; returns True when the file changed."""
    path = Path(path)
    data = content if isinstance(content, bytes) else content.encode()
    if path.is_file():
        current = os.stat(path)
        if path.read_bytes() == data and (current.st_mode & 0o7777) == mode:
            return False
    write_file(path, data, mode)
    return True


def assert_redacted(text, env):
    """Refuse output that embeds any configured secret value."""
    for key, value in secret_values(env).items():
        if value in text:
            raise ValueError('refusing to emit ' + key + ': its value would appear in the realm plan')


def plan(env_file, output, show=False):
    env = read_env(env_file)
    data = realm(settings(env))
    text = render(data)
    assert_redacted(text, env)
    changed = write_if_changed(output, text, 0o644)
    if show:
        sys.stdout.write(text)
    print(summary(data, output, 'written' if changed else 'No changes'))
    return data


# ─── Database TLS material ─────────────────────────────────────────────────────

def _openssl(args, cwd, capture=False):
    result = subprocess.run(['openssl', *args], cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        raise subprocess.SubprocessError(f'openssl {args[0]} failed (exit {result.returncode}); is OpenSSL 1.1.1 or newer installed?')
    return result.stdout.decode() if capture else ''


def issue_server(work, days=SERVER_CERT_DAYS):
    """A new server key and certificate (SAN DNS:keycloak-db) signed by the CA files in `work`."""
    work = Path(work)
    (work / 'server.ext').write_text(SERVER_EXTENSIONS)
    _openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
              '-subj', '/CN=' + DB_HOST, '-keyout', 'server.key', '-out', 'server.csr'], work)
    _openssl(['x509', '-req', '-sha256', '-days', str(days), '-in', 'server.csr',
              '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
              '-extfile', 'server.ext', '-out', 'server.crt'], work)


def generate_material(work):
    """Create a private CA and a server certificate for keycloak-db in `work`."""
    work = Path(work)
    _openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', str(CA_CERT_DAYS),
              '-subj', '/CN=' + CA_NAME, '-keyout', 'ca.key', '-out', 'ca.crt',
              '-addext', 'basicConstraints=critical,CA:TRUE',
              '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], work)
    issue_server(work)
    material = {name: (work / name).read_bytes() for name in TLS_FILES if name != 'pg_hba.conf'}
    material['pg_hba.conf'] = PG_HBA.encode()
    return material


def not_after(certificate):
    """The certificate's expiry as openssl prints it, e.g. 'Oct 10 12:00:00 2027 GMT'."""
    text = _openssl(['x509', '-in', str(certificate), '-noout', '-enddate'], None, capture=True)
    return text.strip().partition('=')[2]


def renew_server(directory, days=SERVER_CERT_DAYS):
    """Reissue server.key and server.crt under the existing CA; returns the new expiry.

    Both files are written beside the current ones as `.new` and then moved into
    place (key first, then certificate), so no reader ever sees a partial file.
    The CA, Keycloak's trust store, is untouched.
    """
    directory = Path(directory)
    missing = [name for name in TLS_FILES if not (directory / name).is_file()]
    if missing:
        raise IncompleteMaterial(f'{directory} is incomplete; missing ' + ', '.join(missing)
                                 + '. Renewal needs the existing CA; restore the directory from a backup first.')
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='.renew-', dir=directory) as work:
            work = Path(work)
            for name in ('ca.crt', 'ca.key'):
                (work / name).write_bytes((directory / name).read_bytes())
            issue_server(work, days)
            material = {name: (work / name).read_bytes() for name in ('server.key', 'server.crt')}
    finally:
        os.umask(previous)
    for name in ('server.key', 'server.crt'):
        write_file(directory / (name + '.new'), material[name], TLS_MODES[name])
    for name in ('server.key', 'server.crt'):
        os.replace(directory / (name + '.new'), directory / name)
    return not_after(directory / 'server.crt')


def db_tls(directory):
    """Generate the keycloak-db TLS set once; returns the names written."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    present = [name for name in TLS_FILES if (directory / name).is_file()]
    if len(present) == len(TLS_FILES):
        if write_if_changed(directory / 'pg_hba.conf', PG_HBA, TLS_MODES['pg_hba.conf']):
            return ['pg_hba.conf']
        return []
    if present:
        missing = [name for name in TLS_FILES if name not in present]
        raise IncompleteMaterial(
            f'{directory} is incomplete; missing ' + ', '.join(missing) + '. Restore the directory from '
            'a backup (or move it aside to issue a new CA and re-import trust) before continuing.')
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='.generate-', dir=directory) as work:
            material = generate_material(work)
    finally:
        os.umask(previous)
    for name in TLS_FILES:
        write_file(directory / name, material[name], TLS_MODES[name])
    return list(TLS_FILES)


# ─── CLI ───────────────────────────────────────────────────────────────────────

def cmd_plan(args):
    plan(args.env_file, args.output, args.show)
    return 0


def cmd_db_tls(args):
    if args.renew_server:
        print(f'renewed server certificate, valid until {renew_server(args.output_dir)}')
        return 0
    written = db_tls(args.output_dir)
    if written:
        print(f"Database TLS material: wrote {', '.join(written)} in {args.output_dir}")
    else:
        print(f'Database TLS material: No changes in {args.output_dir}')
    return 0


# ─── Backup integrity (encrypt-then-MAC) ───────────────────────────────────────
# `openssl enc` cannot produce an authenticated mode ("This command does not
# support authenticated encryption modes like CCM and GCM", openssl-enc(1)), so
# the CLI encrypts with AES-256-CBC and this module seals the ciphertext with an
# HMAC-SHA256 whose key is derived separately from the same passphrase. The tag
# is verified before any byte is decrypted, unpacked or restored.
BACKUP_MAGIC = b'krate-identity-backup/1\n'
BACKUP_MAC_SALT = b'krate-identity-backup-mac:'
BACKUP_ITERATIONS = 600000
BACKUP_PASSPHRASE_ENV = 'KRATE_BACKUP_PASSPHRASE'
OPENSSL_SALTED = b'Salted__'


def backup_mac_key(passphrase, salt):
    """Independent MAC key: PBKDF2-HMAC-SHA256 over a salt that differs from openssl's own derivation."""
    return hashlib.pbkdf2_hmac('sha256', passphrase, BACKUP_MAC_SALT + salt, BACKUP_ITERATIONS, 32)


def backup_seal(ciphertext, passphrase):
    """Return magic || ciphertext || HMAC-SHA256(ciphertext) for an openssl `Salted__` ciphertext."""
    if not ciphertext.startswith(OPENSSL_SALTED) or len(ciphertext) < 32:
        raise ValueError('ciphertext is not an openssl enc -salt output')
    tag = hmac.new(backup_mac_key(passphrase, ciphertext[8:16]), ciphertext, hashlib.sha256).digest()
    return BACKUP_MAGIC + ciphertext + tag


def backup_open(sealed, passphrase):
    """Verify the tag and return the ciphertext; any mismatch raises before decryption."""
    if not sealed.startswith(BACKUP_MAGIC) or len(sealed) < len(BACKUP_MAGIC) + 32 + 32:
        raise ValueError('not a krate identity backup')
    body = sealed[len(BACKUP_MAGIC):]
    ciphertext, tag = body[:-32], body[-32:]
    if not ciphertext.startswith(OPENSSL_SALTED):
        raise ValueError('not a krate identity backup')
    expected = hmac.new(backup_mac_key(passphrase, ciphertext[8:16]), ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError('integrity check failed: the backup was modified or the passphrase is wrong')
    return ciphertext


def backup_passphrase():
    value = os.environ.get(BACKUP_PASSPHRASE_ENV, '')
    if not value:
        raise ValueError(f'{BACKUP_PASSPHRASE_ENV} is not set')
    return value.encode()


def cmd_backup_seal(args):
    write_file(args.output, backup_seal(Path(args.input).read_bytes(), backup_passphrase()), 0o600)
    return 0


def cmd_backup_open(args):
    write_file(args.output, backup_open(Path(args.input).read_bytes(), backup_passphrase()), 0o600)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest='command', required=True)
    planner = commands.add_parser('plan', help='write the local realm plan from .env values')
    planner.add_argument('--env-file', type=Path, required=True)
    planner.add_argument('--output', type=Path, required=True)
    planner.add_argument('--print', dest='show', action='store_true', help='also print the plan JSON')
    planner.set_defaults(func=cmd_plan)
    tls = commands.add_parser('db-tls', help='generate CA, server certificate and pg_hba.conf for keycloak-db')
    tls.add_argument('--output-dir', type=Path, required=True)
    tls.add_argument('--renew-server', action='store_true',
                     help=f'reissue server.key and server.crt under the existing CA ({SERVER_CERT_DAYS} days)')
    tls.set_defaults(func=cmd_db_tls)
    seal = commands.add_parser('backup-seal', help='append an HMAC-SHA256 tag to an openssl ciphertext (passphrase from env)')
    seal.add_argument('--input', type=Path, required=True)
    seal.add_argument('--output', type=Path, required=True)
    seal.set_defaults(func=cmd_backup_seal)
    opener = commands.add_parser('backup-open', help='verify a sealed backup and write the ciphertext for decryption')
    opener.add_argument('--input', type=Path, required=True)
    opener.add_argument('--output', type=Path, required=True)
    opener.set_defaults(func=cmd_backup_open)
    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'Identity {args.command} failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
