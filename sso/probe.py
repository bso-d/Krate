#!/usr/bin/env python3
"""Verify browser-facing identity discovery through the installation's HTTPS proxy."""
import argparse
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import signal
import sys
from urllib.request import urlopen
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--connect-ip', help='connect to this IP while verifying the issuer hostname')
    args = parser.parse_args()
    connect_ip = None
    if args.connect_ip:
        try:
            connect_ip = str(ipaddress.ip_address(args.connect_ip))
        except ValueError:
            parser.error('--connect-ip must be an IPv4 or IPv6 address')

    def deadline(_signum, _frame):
        raise TimeoutError('Readiness deadline exceeded')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(15)
    real_getaddrinfo = socket.getaddrinfo
    try:
        runtime = json.loads((args.directory / 'auth/ui/runtime.yml').read_text())
        issuer = runtime['auth']['oauth2']['client']['keycloak']['issuer-uri']
        if connect_ip:
            issuer_host = urlsplit(issuer).hostname
            if not issuer_host:
                raise ValueError('Issuer has no hostname')

            def mapped_getaddrinfo(host, port, *address_args, **kwargs):
                if isinstance(host, str) and host.lower() == issuer_host.lower():
                    host = connect_ip
                return real_getaddrinfo(host, port, *address_args, **kwargs)

            socket.getaddrinfo = mapped_getaddrinfo
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
    finally:
        socket.getaddrinfo = real_getaddrinfo
    signal.alarm(0)
    print('Public HTTPS identity discovery verified.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
