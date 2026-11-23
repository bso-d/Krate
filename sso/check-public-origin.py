#!/usr/bin/env python3
"""Read-only TLS and exact Keycloak issuer check from the operator network."""
import argparse
import http.client
import json
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit

import identity

MAX_DISCOVERY_BYTES = 256 * 1024


def verify(configured_url, ca_file=None):
    origin = identity.public_origin(configured_url)
    target = urlsplit(origin)
    host = target.hostname
    if not host:
        raise ValueError('KEYCLOAK_PUBLIC_URL has no hostname')
    issuer_path = '/identity/realms/' + identity.REALM
    expected_issuer = origin + issuer_path
    authority = target.netloc.rsplit(':', 1)[0] if target.port == 443 else target.netloc
    context = ssl.create_default_context(cafile=ca_file)
    san_checked_by_tls = ssl.HAS_NEVER_CHECK_COMMON_NAME
    if san_checked_by_tls:
        context.hostname_checks_common_name = False
    connection = http.client.HTTPSConnection(host, target.port or 443, context=context, timeout=10)
    try:
        if not san_checked_by_tls:
            # Older LibreSSL verifies CN by default but cannot disable that fallback.
            # Keep its normal chain/hostname checks and require a matching SAN as well.
            connection.connect()
            peer = connection.sock.getpeercert()
            ssl.match_hostname({'subjectAltName': peer.get('subjectAltName', ())}, host)
        # Explicit authority matches the installed browser-facing origin, including non-default ports.
        connection.request('GET', issuer_path + '/.well-known/openid-configuration',
                           headers={'Host': authority, 'Accept': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f'Keycloak discovery returned HTTP {response.status}; redirects are not followed')
        raw_body = response.read(MAX_DISCOVERY_BYTES + 1)
        if len(raw_body) > MAX_DISCOVERY_BYTES:
            raise ValueError('Keycloak discovery exceeded the response size limit')
        document = json.loads(raw_body)
        if not isinstance(document, dict) or document.get('issuer') != expected_issuer:
            raise ValueError('Keycloak discovery issuer does not exactly match the configured public URL and realm')
    finally:
        connection.close()
    return expected_issuer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--workspace', type=Path, default=Path.cwd(), help='Read KEYCLOAK_PUBLIC_URL from .env here')
    source.add_argument('--public-url', help='The configured KEYCLOAK_PUBLIC_URL for a workstation without .env')
    parser.add_argument('--ca-file', type=Path, help='Explicit trusted enterprise CA bundle (default: system trust)')
    args = parser.parse_args()
    try:
        url = args.public_url
        if url is None:
            url = identity.read_env(args.workspace / '.env').get('KEYCLOAK_PUBLIC_URL')
        issuer = verify(url, ca_file=args.ca_file)
    except ssl.SSLCertVerificationError as exc:
        message = getattr(exc, 'verify_message', str(exc))
        print(f'Keycloak origin check failed: TLS certificate verification: {message}', file=sys.stderr)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        print(f'Keycloak origin check failed: {exc}', file=sys.stderr)
    else:
        print(f'Hostname and certificate chain verified; exact issuer: {issuer}')
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
