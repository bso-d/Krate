#!/usr/bin/env python3
"""Hold the monitoring consumers until the Krate realm answers.

`krate monitor up` starts Grafana, oauth2-proxy and Perses with
`depends_on: idp-wait: condition: service_completed_successfully`, so during a
Keycloak outage Compose creates them but does not start them and none of them
restart-loops; when Keycloak answers, they start on their own without a restart
(Phase 4 rows U13 and V16, observed in harness/phase4/lab7 Q4).

The container runs read-only as uid 65534 with no capabilities on the monitoring
network, and resolves the realm's public host through its `extra_hosts`
host-gateway entry: the discovery document is fetched over TLS with the cluster
CA, the same one the consumers verify their tokens against.

An empty IDP_DISCOVERY_URL means no monitoring UI is on the realm, so there is
nothing to wait for and the exit is immediate.
"""
import json
import os
import ssl
import sys
import time
import urllib.request

# Mounted read-only from the cluster certificate directory.
CA_FILE = '/etc/krate/ca/server.crt'
INTERVAL_SECONDS = 3
BUDGET_SECONDS = 120
REQUEST_TIMEOUT_SECONDS = 5
SUFFIX = '/.well-known/openid-configuration'


def expected_issuer(url):
    """The issuer the document must carry: the discovery URL without its suffix.

    Refusing anything else keeps the waiter on the one URL the CLI derives from
    KEYCLOAK_PUBLIC_URL, so a stray value cannot turn it into a general fetcher.
    """
    if not url.startswith('https://') or not url.endswith(SUFFIX):
        raise ValueError('IDP_DISCOVERY_URL must be an https URL ending in %s' % SUFFIX)
    return url[:-len(SUFFIX)]


def main():
    url = os.environ.get('IDP_DISCOVERY_URL', '').strip()
    if not url:
        print('idp-wait: no realm discovery URL is set (no monitoring UI on the realm); nothing to wait for')
        return 0
    issuer = expected_issuer(url)
    context = ssl.create_default_context(cafile=CA_FILE)
    deadline = time.monotonic() + BUDGET_SECONDS
    attempt = 0
    last = 'no attempt'
    while time.monotonic() < deadline:
        attempt += 1
        try:
            with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_SECONDS, context=context) as response:
                document = json.loads(response.read().decode('utf-8'))
            if document.get('issuer') != issuer:
                last = 'the discovery document names issuer %r instead of %r' % (document.get('issuer'), issuer)
            else:
                print('idp-wait: %s answers and names itself as the issuer (attempt %d)' % (issuer, attempt))
                return 0
        except Exception as exc:  # every failure keeps the wait going until the budget is used up
            last = '%s: %s' % (type(exc).__name__, exc)
        time.sleep(INTERVAL_SECONDS)
    print('idp-wait: %s did not answer within %d s (last: %s)' % (issuer, BUDGET_SECONDS, last), file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
