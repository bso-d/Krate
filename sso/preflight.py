#!/usr/bin/env python3
"""Validate authentication activation before any service mutation."""
import argparse
import json
from pathlib import Path
import stat
import subprocess
import sys
from urllib.parse import urlsplit


def validate(root, mode, config):
    env = root / '.env'
    if stat.S_IMODE(env.stat().st_mode) & 0o077:
        raise ValueError('Protect .env with chmod 600 before activation')
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
    public = realm['clients'][0]['webOrigins'][0].rstrip('/')
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
    secrets = [kc.get(key, '') for key in ('KC_BOOTSTRAP_ADMIN_PASSWORD', 'KC_DB_PASSWORD',
               'KEYCLOAK_KAFBAT_CLIENT_SECRET', 'PING_KEYCLOAK_CLIENT_SECRET')]
    if any(len(value) < 16 or value == 'REPLACE_ME' for value in secrets):
        raise ValueError('Set all four identity secrets to unique values of at least 16 characters')
    if len(set(secrets + [password])) != 5:
        raise ValueError('Identity secrets and shared Admin password must be different')
    if ui.get('KEYCLOAK_KAFBAT_CLIENT_SECRET') != kc['KEYCLOAK_KAFBAT_CLIENT_SECRET']:
        raise ValueError('Kafbat and Keycloak client secrets differ')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--mode', choices=['local.yml', 'runtime.yml'], required=True)
    args = parser.parse_args()
    try:
        validate(args.directory, args.mode, json.load(sys.stdin))
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
        # Never print exception payloads: rendered configuration contains secrets.
        print('Authentication preflight failed: check protected .env, unique secrets (16+ characters), generated auth files, HTTPS URL and matching unexpired TLS certificate.', file=sys.stderr)
        return 1
    print('Authentication preflight passed; no services changed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
