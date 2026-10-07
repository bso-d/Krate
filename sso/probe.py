#!/usr/bin/env python3
"""Verify browser-facing identity discovery through the installation's HTTPS proxy."""
import argparse
import json
from pathlib import Path
import ssl
import signal
import sys
from urllib.request import urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    def deadline(_signum, _frame):
        raise TimeoutError('Readiness deadline exceeded')
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(15)
    try:
        runtime = json.loads((args.directory / 'auth/ui/runtime.yml').read_text())
        issuer = runtime['auth']['oauth2']['client']['keycloak']['issuer-uri']
        context = ssl.create_default_context(cafile=str(args.directory / 'certs/server.crt'))
        # The provisioned certificate/chain is the local trust anchor, including
        # enterprise-issued leaf certificates. Hostname and expiry remain checked.
        if hasattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN'):
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        with urlopen(issuer + '/.well-known/openid-configuration', context=context, timeout=10) as response:
            data = json.loads(response.read(1024 * 1024))
        if data['issuer'] != issuer or not all(data.get(key, '').startswith(issuer + '/')
                                              for key in ('authorization_endpoint', 'token_endpoint', 'jwks_uri')):
            raise ValueError('Unexpected public identity endpoints')
    except Exception:
        print('Public SSO readiness failed: verify application DNS, HTTPS certificate, proxy identity route and realm issuer.', file=sys.stderr)
        return 1
    signal.alarm(0)
    print('Public HTTPS identity discovery verified.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
