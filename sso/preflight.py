#!/usr/bin/env python3
"""Validate authentication activation before any service mutation."""
import argparse
import json
from pathlib import Path
import stat
import subprocess
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import identity  # noqa: E402  (sibling module; explicit path keeps python -I working)

IDENTITY_SECRETS = ('KEYCLOAK_ADMIN_PASSWORD', 'KEYCLOAK_DB_PASSWORD',
                    'KEYCLOAK_KAFBAT_CLIENT_SECRET', 'KEYCLOAK_CLI_CLIENT_SECRET')
# Issued by PingFederate; unused by the local realm, so only validated when set.
OPTIONAL_SECRETS = ('PING_KEYCLOAK_CLIENT_SECRET',)
INSECURE = ('', 'REPLACE_ME', 'changeme')
TLS_DIR = 'auth/keycloak/db-tls'
REALM_FILE = 'auth/keycloak/krate-realm.json'


class Preflight(ValueError):
    """A refusal whose message is safe to print: it never carries a configured value."""


def validate(root, mode, config):
    env = root / '.env'
    if stat.S_IMODE(env.stat().st_mode) & 0o077:
        raise ValueError('Protect .env with chmod 600 before activation')
    if mode == 'identity':
        validate_identity(root, config)
        return
    services = config['services']
    ui = services['kafka-ui']['environment']
    location = ui.get('SPRING_CONFIG_ADDITIONAL_LOCATION', '')
    if 'file:/etc/krate/auth/' + mode not in location.split(','):
        raise ValueError('Rendered authentication mode differs from .env; clear conflicting shell environment variables')
    if not ui.get('SPRING_SECURITY_USER_NAME'):
        raise ValueError('Set KAFKA_UI_USER')
    password = ui.get('SPRING_SECURITY_USER_PASSWORD', '')
    if len(password) < 16 or password in ('changeme', 'REPLACE_ME'):
        raise ValueError('Set KAFKA_UI_PASSWORD to a unique password of at least 16 characters')
    for filename in ('server.crt', 'server.key'):
        if not (root / 'certs' / filename).is_file():
            raise ValueError('Provision certs/server.crt and certs/server.key first')
    if stat.S_IMODE((root / 'certs/server.key').stat().st_mode) & 0o077:
        raise ValueError('Protect TLS private key with chmod 600')
    cert = root / 'certs/server.crt'
    subprocess.run(['openssl', 'x509', '-in', str(cert), '-checkend', '86400', '-noout'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cert_pub = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'])
    key_pub = subprocess.check_output(['openssl', 'pkey', '-in', str(root / 'certs/server.key'), '-pubout', '-passin', 'pass:'],
                                     stderr=subprocess.DEVNULL)
    if cert_pub != key_pub:
        raise ValueError('TLS certificate and private key do not match')
    if mode == 'local.yml':
        if not (root / 'auth/ui/local.yml').is_file():
            raise ValueError('Missing shared-login configuration')
        return
    runtime = json.loads((root / 'auth/ui/runtime.yml').read_text())
    realm = json.loads((root / 'auth/keycloak/krate-realm.json').read_text())
    client = runtime['auth']['oauth2']['client']['keycloak']
    ui_clients = [client for client in realm['clients'] if client.get('clientId') == 'krate-ui']
    public = ui_clients[0]['webOrigins'][0].rstrip('/')
    host = urlsplit(public).hostname
    if urlsplit(public).scheme != 'https' or not host:
        raise ValueError('The public application URL must use HTTPS')
    match = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-checkhost', host, '-noout'], text=True)
    if 'does match certificate' not in match:
        raise ValueError('TLS certificate does not match the public hostname')
    expected_issuer = public + '/identity/realms/krate'
    if client['issuer-uri'] != expected_issuer or client['redirect-uri'] != public + '/login/oauth2/code/keycloak':
        raise ValueError('Kafbat issuer/callback does not match the imported realm')
    kc = services['keycloak']['environment']
    if kc.get('KC_HOSTNAME') != public + '/identity':
        raise ValueError('KEYCLOAK_PUBLIC_URL must match the generated public_url plus /identity')
    # A runtime.yml `up` renders the sso profile, so the database TLS contract applies here too.
    if kc.get('KC_DB_TLS_MODE') != 'verify-server':
        raise Preflight('keycloak must render KC_DB_TLS_MODE=verify-server')
    validate_db_tls(root)
    # The bootstrap admin is exported only by `krate identity up` on a pristine database;
    # the permanent admin password lives in .env. The realm also carries the krate-cli secret.
    site = identity.read_env(root / '.env')
    secrets = [site.get('KEYCLOAK_ADMIN_PASSWORD', '')] + [kc.get(key, '') for key in (
        'KC_DB_PASSWORD', 'KEYCLOAK_KAFBAT_CLIENT_SECRET', 'PING_KEYCLOAK_CLIENT_SECRET', 'KEYCLOAK_CLI_CLIENT_SECRET')]
    if any(len(value) < 16 or value in ('REPLACE_ME', 'changeme') for value in secrets):
        raise ValueError('Set all five identity secrets to unique values of at least 16 characters')
    if len(set(secrets + [password])) != 6:
        raise ValueError('Identity secrets and shared Admin password must be different')
    if ui.get('KEYCLOAK_KAFBAT_CLIENT_SECRET') != kc['KEYCLOAK_KAFBAT_CLIENT_SECRET']:
        raise ValueError('Kafbat and Keycloak client secrets differ')


def secure(value):
    return len(value) >= 16 and value not in INSECURE


def identity_secrets(env):
    """Secret values that identity services depend on; refuses placeholders and reuse."""
    secrets = {}
    for key in IDENTITY_SECRETS + OPTIONAL_SECRETS:
        value = env.get(key, '')
        if key in OPTIONAL_SECRETS and value in ('', 'REPLACE_ME'):
            continue
        if not secure(value):
            raise Preflight(f'Set {key} to a unique secret of at least 16 characters (changeme and REPLACE_ME are refused): '
                            f'krate identity rotate {key}, or krate config set {key}=... before the first start')
        secrets[key] = value
    if len(set(secrets.values())) != len(secrets):
        raise Preflight('Identity secrets must all be different from each other')
    if env.get('KAFKA_UI_PASSWORD', '') in secrets.values():
        raise Preflight('KAFKA_UI_PASSWORD must differ from the identity secrets')
    return secrets


def openssl(*args):
    return subprocess.run(['openssl', *args], stdin=subprocess.DEVNULL, capture_output=True, text=True)


def validate_db_tls(root):
    tls = root / TLS_DIR
    missing = [name for name in identity.TLS_FILES if not (tls / name).is_file()]
    if missing:
        raise Preflight(f'Missing database TLS files in {TLS_DIR}: ' + ', '.join(missing)
                        + '; run krate identity up on a pristine site or restore the directory from a backup')
    for name in ('ca.key', 'server.key'):
        if stat.S_IMODE((tls / name).stat().st_mode) & 0o077:
            raise Preflight(f'Protect {TLS_DIR}/{name} with chmod 600')
    if (tls / 'pg_hba.conf').read_text() != identity.PG_HBA:
        raise Preflight(f'{TLS_DIR}/pg_hba.conf differs from the generated policy; run krate identity up to restore it')
    server = str(tls / 'server.crt')
    if openssl('x509', '-in', server, '-checkend', '86400', '-noout').returncode:
        raise Preflight(f'{TLS_DIR}/server.crt is unreadable or expires within a day')
    names = openssl('x509', '-in', server, '-noout', '-ext', 'subjectAltName').stdout
    if 'DNS:' + identity.DB_HOST not in names.replace(' ', ''):
        raise Preflight(f'{TLS_DIR}/server.crt must carry subjectAltName DNS:{identity.DB_HOST}')
    if openssl('verify', '-CAfile', str(tls / 'ca.crt'), server).returncode:
        raise Preflight(f'{TLS_DIR}/server.crt is not signed by {TLS_DIR}/ca.crt')
    cert_pub = openssl('x509', '-in', server, '-pubkey', '-noout').stdout
    key_pub = openssl('pkey', '-in', str(tls / 'server.key'), '-pubout', '-passin', 'pass:').stdout
    if not cert_pub or cert_pub != key_pub:
        raise Preflight(f'{TLS_DIR}/server.crt and server.key do not match')


def validate_realm(root, origin, secrets):
    path = root / REALM_FILE
    if not path.is_file():
        raise Preflight(f'Missing {REALM_FILE}; run krate identity up to plan the realm')
    text = path.read_text()
    try:
        realm = json.loads(text)
    except ValueError:
        raise Preflight(f'{REALM_FILE} is not valid JSON') from None
    if not isinstance(realm, dict) or realm.get('realm') != identity.REALM:
        raise Preflight(f'{REALM_FILE} must describe realm {identity.REALM}')
    if realm.get('identityProviders'):
        raise Preflight(f'{REALM_FILE} must not define identityProviders in local mode')
    clients = {client.get('clientId'): client for client in realm.get('clients', []) if isinstance(client, dict)}
    for client_id, placeholder in ((identity.UI_CLIENT, identity.UI_SECRET), (identity.CLI_CLIENT, identity.CLI_SECRET)):
        if client_id not in clients:
            raise Preflight(f'{REALM_FILE} must define client {client_id}')
        if clients[client_id].get('secret') != placeholder:
            raise Preflight(f'{REALM_FILE}: client {client_id} secret must be the {placeholder} placeholder')
    if any(value in text for value in secrets.values()):
        raise Preflight(f'{REALM_FILE} embeds a secret value; regenerate it with krate identity up')
    ui = clients[identity.UI_CLIENT]
    if ui.get('webOrigins') != [origin] or ui.get('redirectUris') != [origin + '/login/oauth2/code/keycloak']:
        raise Preflight(f'{REALM_FILE}: krate-ui redirect URI and web origin must match KEYCLOAK_PUBLIC_URL; regenerate the plan')


def validate_identity(root, config):
    """Identity foundation checks: .env values, rendered services, TLS material and realm plan."""
    env = identity.read_env(root / '.env')
    try:
        origin = identity.public_origin(env.get('KEYCLOAK_PUBLIC_URL'))
    except ValueError as exc:
        raise Preflight(str(exc)) from None
    services = config['services']
    keycloak = services['keycloak']['environment']
    database = services['keycloak-db']
    if keycloak.get('KC_HOSTNAME') != env['KEYCLOAK_PUBLIC_URL']:
        raise Preflight('Rendered KC_HOSTNAME differs from KEYCLOAK_PUBLIC_URL in .env; clear conflicting shell environment variables')
    secrets = identity_secrets(env)
    rendered = {
        'KEYCLOAK_DB_PASSWORD': (keycloak.get('KC_DB_PASSWORD'), database['environment'].get('POSTGRES_PASSWORD')),
        'KEYCLOAK_KAFBAT_CLIENT_SECRET': (keycloak.get('KEYCLOAK_KAFBAT_CLIENT_SECRET'),
                                          services['kafka-ui']['environment'].get('KEYCLOAK_KAFBAT_CLIENT_SECRET')),
        'KEYCLOAK_CLI_CLIENT_SECRET': (keycloak.get('KEYCLOAK_CLI_CLIENT_SECRET'),),
    }
    for key, values in rendered.items():
        if any(value != secrets[key] for value in values):
            raise Preflight(f'Rendered {key} differs from .env; clear conflicting shell environment variables')
    if keycloak.get('KC_DB_TLS_MODE') != 'verify-server':
        raise Preflight('keycloak must render KC_DB_TLS_MODE=verify-server')
    if not keycloak.get('KC_DB_TLS_TRUST_STORE_FILE'):
        raise Preflight('keycloak must render KC_DB_TLS_TRUST_STORE_FILE')
    for name in ('keycloak', 'keycloak-db'):
        if services[name].get('ports'):
            raise Preflight(f'{name} must not publish host ports')
    validate_db_tls(root)
    validate_realm(root, origin, secrets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--mode', choices=['local.yml', 'runtime.yml', 'identity'], required=True)
    args = parser.parse_args()
    try:
        validate(args.directory, args.mode, json.load(sys.stdin))
    except Preflight as exc:
        label = 'Identity' if args.mode == 'identity' else 'Authentication'
        print(f'{label} preflight failed: {exc}', file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
        # Never print exception payloads: rendered configuration contains secrets.
        if args.mode == 'identity':
            print('Identity preflight failed: check protected .env, the rendered keycloak/keycloak-db services, '
                  'auth/keycloak/db-tls and auth/keycloak/krate-realm.json.', file=sys.stderr)
            return 1
        print('Authentication preflight failed: check protected .env, unique secrets (16+ characters), generated auth files, HTTPS URL and matching unexpired TLS certificate.', file=sys.stderr)
        return 1
    if args.mode == 'identity':
        print('Identity preflight passed; no services changed.')
        return 0
    print('Authentication preflight passed; no services changed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
