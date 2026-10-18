#!/usr/bin/env python3
"""Verify browser-facing identity discovery through the installation's HTTPS proxy."""
import argparse
import http.client
import ipaddress
import json
import errno
import re
from pathlib import Path
import socket
import ssl
import signal
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from urllib.parse import urlsplit

RUNTIME_FILE = 'auth/ui/runtime.yml'
CERT_FILE = 'certs/server.crt'
DEADLINE_SECONDS = 15
DEADLINE_TEXT = 'Readiness deadline exceeded'
ENDPOINT_KEYS = ('authorization_endpoint', 'token_endpoint', 'jwks_uri')
ISSUER_HINT = ('check KEYCLOAK_PUBLIC_URL in .env (the https address users open, ending in /identity) and rerun '
               'krate auth configure')


class Failure(Exception):
    """A failed readiness step, already worded for the administrator."""


def public_host(value):
    """A bounded DNS/IP name only; never arbitrary URL, user information or error text."""
    if not isinstance(value, str) or not value or len(value) > 253 or '%' in value:
        return '<invalid host>'
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    name = value[:-1] if value.endswith('.') else value
    labels = name.split('.')
    if all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels):
        return name.lower()
    return '<invalid host>'


def integer_code(value):
    return str(value) if type(value) is int and -(2 ** 31) <= value < 2 ** 31 else 'unavailable'


def describe(error):
    """Fixed categories and numeric codes; library messages can contain credentials."""
    if isinstance(error, ssl.SSLCertVerificationError):
        return 'certificate verification code ' + integer_code(getattr(error, 'verify_code', None))
    if isinstance(error, ssl.SSLError):
        return 'TLS error code ' + integer_code(error.errno)
    if isinstance(error, socket.gaierror):
        return 'resolver error code ' + integer_code(error.errno)
    if isinstance(error, http.client.InvalidURL):
        return 'invalid URL'
    if isinstance(error, (socket.timeout, TimeoutError)):
        return 'timeout'
    if isinstance(error, http.client.HTTPException):
        return 'HTTP protocol error'
    if isinstance(error, OSError):
        code = getattr(error, 'errno', None)
        name = errno.errorcode.get(code, 'unknown') if type(code) is int else 'unavailable'
        return 'operating system error ' + integer_code(code) + ' (' + name + ')'
    return 'request error'


def is_deadline(error):
    return isinstance(error, TimeoutError) and str(error) == DEADLINE_TEXT


def address(name, port):
    """Only a validated public host and a numeric port are safe diagnostic values."""
    host = public_host(name)
    host = f'[{host}]' if ':' in host else host
    return f'{host}:{integer_code(port)}'


class Target:
    """What is being probed: the issuer, its discovery URL, host and port, and the files a failure points at."""

    def __init__(self, issuer, host, port, runtime_file, certificate):
        self.issuer, self.host, self.port = issuer, host, port
        self.url = issuer + '/.well-known/openid-configuration'
        self.display_url = f'{urlsplit(issuer).scheme}://{address(host, port)} (identity discovery from {runtime_file})'
        self.runtime_file, self.certificate = runtime_file, certificate
        self.lookups = []  # (name, port) the resolver was asked for, in order; a redirect or proxy setting makes the last differ

    def reached(self):
        """(name, port) of the last lookup: the issuer's own unless the request was sent on elsewhere."""
        return self.lookups[-1] if self.lookups else (self.host, self.port)

    def detour(self):
        """A note for a failure that happened after the request left the issuer's own host, else ''."""
        name, port = self.reached()
        if self.lookups and (str(name).lower(), port) != (self.host.lower(), self.port):
            return f' (the request had been sent on to {address(name, port)} from {public_host(self.host)}, by a redirect or a proxy setting)'
        return ''

    def watching(self, real_getaddrinfo, connect_ip):
        """A getaddrinfo that records every name asked for and, with connect_ip, maps the issuer's host to that address."""
        def watching_getaddrinfo(host, port, *address_args, **kwargs):
            self.lookups.append((host, port))
            if connect_ip and isinstance(host, str) and host.lower() == self.host.lower():
                host = connect_ip
            return real_getaddrinfo(host, port, *address_args, **kwargs)

        return watching_getaddrinfo


def deadline_failure(target):
    return (f'no answer within {DEADLINE_SECONDS} s from {target.display_url if target else "the identity route"}: check that the proxy '
            f'and Keycloak are running and that {public_host(target.reached()[0]) if target else "the public name"} points at this server')


def runtime_issuer(runtime_file):
    """The issuer-uri of runtime.yml, or a Failure that names the file and what is wrong with it."""
    try:
        issuer = json.loads(runtime_file.read_text())['auth']['oauth2']['client']['keycloak']['issuer-uri']
    except FileNotFoundError:
        raise Failure(f'{runtime_file} is missing: run krate auth configure to write it') from None
    except OSError as error:
        if is_deadline(error):  # TimeoutError is an OSError: the alarm is not a read failure
            raise
        raise Failure(f'{runtime_file} cannot be read ({describe(error)}): fix its permissions or run krate auth configure') from None
    except ValueError:
        raise Failure(f'{runtime_file} is not valid JSON: run krate auth configure to write it again') from None
    except (KeyError, TypeError):
        issuer = None
    if not isinstance(issuer, str) or not issuer:
        raise Failure(f'{runtime_file} has no auth.oauth2.client.keycloak.issuer-uri: run krate auth configure to write it again')
    return issuer


def make_target(issuer, runtime_file, certificate):
    """Validate the request address without ever printing a malformed/private URL."""
    host = port = None
    try:
        parts = urlsplit(issuer)
        host = parts.hostname
        port = parts.port if parts.port is not None else (80 if parts.scheme == 'http' else 443)
        valid = (parts.scheme in ('http', 'https') and host and public_host(host) != '<invalid host>'
                 and 0 < port < 65536 and parts.username is None and parts.password is None
                 and not parts.query and not parts.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise Failure(f'the issuer in {runtime_file} has no host name or has a malformed/private address: {ISSUER_HINT}')
    return Target(issuer, host, port, runtime_file, certificate)


def trust_context(certificate):
    try:
        context = ssl.create_default_context(cafile=str(certificate))
    except FileNotFoundError:
        raise Failure(f'{certificate} is missing: install the CA-issued certificate and key in certs/, or run krate gen-cert') from None
    except OSError as error:  # an unreadable file or one that is not a PEM certificate (ssl.SSLError)
        if is_deadline(error):
            raise
        raise Failure(f'{certificate} cannot be used as the trust anchor ({describe(error)}): install the CA-issued certificate '
                      'and key in certs/, or run krate gen-cert') from None
    # The provisioned certificate/chain is the local trust anchor, including
    # enterprise-issued leaf certificates. Hostname and expiry remain checked.
    if hasattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN'):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def explain_request(error, target: Target):
    """Say what a failed request to the identity route means and what to check (HTTPError and URLError are OSErrors)."""
    if isinstance(error, HTTPError):
        return (f'{target.display_url} answered HTTP {integer_code(error.code)}: the proxy identity route /identity must reach a '
                'running Keycloak (check krate health and the proxy and Keycloak logs)')
    wrapped = isinstance(error, URLError)  # urllib wraps only connect-time OSErrors: a stall while reading arrives unwrapped
    cause = error.reason if wrapped else error
    name, port = target.reached()  # the name last looked up: after a redirect that is not the issuer's host
    name = public_host(name)
    where = address(name, port)
    if is_deadline(cause):
        return deadline_failure(target)
    if isinstance(cause, socket.gaierror):
        return (f'this server cannot resolve {name} ({describe(cause)}): add {name} to DNS or to /etc/hosts on this server, '
                "pointing at this server's address")
    if isinstance(cause, ssl.SSLCertVerificationError):
        why = describe(cause)  # verify_message may contain a URL or credential-bearing library text
        return (f'HTTPS certificate verification failed for {name} ({why}): the certificate in {target.certificate} must cover '
                f'{name} and be valid (krate gen-cert makes a self-signed one)')
    if isinstance(cause, ssl.SSLError):
        return (f'TLS error talking to {where} ({describe(cause)}): {where} must be the Krate proxy serving HTTPS '
                f'with the certificate in {target.certificate}')
    if isinstance(cause, http.client.InvalidURL):  # a redirect or proxy URL may fail after the issuer already answered
        return (f'a URL used while checking {target.display_url} is invalid ({describe(cause)}): '
                f'{ISSUER_HINT}; also check any redirect or proxy target')
    if isinstance(cause, http.client.HTTPException):
        return f'{where} did not answer with valid HTTP ({describe(cause)}): it must be the Krate proxy'
    if isinstance(cause, (socket.timeout, TimeoutError)) and not wrapped:  # connected, then nothing came back in time
        return (f'{where} accepted the connection but did not answer in time ({describe(cause)}): check that Keycloak behind the '
                'proxy is running and answering (krate health and the Keycloak log)')
    if isinstance(cause, OSError):  # connection refused, unreachable, reset, or a timeout while connecting
        return (f'no connection to {where} ({describe(cause)}): the Krate proxy must be running on this server '
                f'(krate health) and {name} must point at this server')
    return f'the request to {target.display_url} failed ({describe(cause)}): check that {name} points at this server and the proxy is running'


def fetch_discovery(target: Target, context):
    try:
        with urlopen(target.url, context=context, timeout=10) as response:
            body = response.read(1024 * 1024)
    except (OSError, http.client.HTTPException) as error:
        raise Failure(explain_request(error, target) + target.detour()) from None
    except ValueError as error:  # e.g. a UnicodeError for a host name with an empty label
        raise Failure(f'{target.display_url} is not a usable address ({describe(error)}): {ISSUER_HINT}' + target.detour()) from None
    try:
        return json.loads(body)
    except ValueError:
        raise Failure(f'the answer from {target.display_url} is not an OpenID configuration (not JSON): the proxy identity route /identity '
                      'must reach Keycloak' + target.detour()) from None


def verify_discovery(data, target: Target):
    issuer = target.issuer
    missing = [key for key in ('issuer',) + ENDPOINT_KEYS if not isinstance(data, dict) or not isinstance(data.get(key), str)]
    if missing:
        raise Failure(f'the answer from {target.display_url} is not an OpenID configuration (no {", ".join(missing)}): the proxy identity '
                      'route /identity must reach Keycloak' + target.detour())
    if data['issuer'] != issuer:
        raise Failure(f'Keycloak answers with a different issuer than {target.display_url}: '
                      f'{ISSUER_HINT}' + target.detour())
    for key in ENDPOINT_KEYS:
        if not data[key].startswith(issuer + '/'):
            raise Failure(f'Keycloak reports {key} outside the configured issuer in '
                          f'{target.runtime_file}: {ISSUER_HINT}' + target.detour())


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
        raise TimeoutError(DEADLINE_TEXT)

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(DEADLINE_SECONDS)
    real_getaddrinfo = socket.getaddrinfo
    runtime_file = args.directory / RUNTIME_FILE
    certificate = args.directory / CERT_FILE
    target = problem = None
    try:
        target = make_target(runtime_issuer(runtime_file), runtime_file, certificate)
        socket.getaddrinfo = target.watching(real_getaddrinfo, connect_ip)
        verify_discovery(fetch_discovery(target, trust_context(certificate)), target)
    except Failure as failure:
        problem = str(failure)
    except Exception as error:  # the alarm fired between steps, or a failure no step above anticipated
        problem = (deadline_failure(target) if is_deadline(error)
                   else f'unexpected readiness error while checking {target.display_url if target else "the public sign-in"}')
    finally:
        signal.alarm(0)  # first: the deadline must not interrupt the restore
        socket.getaddrinfo = real_getaddrinfo
    if problem:
        print('Public SSO readiness failed: ' + ' '.join(problem.split()), file=sys.stderr)
        return 1
    print('Public HTTPS identity discovery verified.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
