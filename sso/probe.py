#!/usr/bin/env python3
"""Verify browser-facing identity discovery through the installation's HTTPS proxy."""
import argparse
import http.client
import ipaddress
import json
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
SHOWN_LIMIT = 200
ENDPOINT_KEYS = ('authorization_endpoint', 'token_endpoint', 'jwks_uri')
ISSUER_HINT = ('check KEYCLOAK_PUBLIC_URL in .env (the https address users open, ending in /identity) and rerun '
               'krate auth configure')


class Failure(Exception):
    """A failed readiness step, already worded for the administrator."""


def shown(value, limit=SHOWN_LIMIT):
    """Text from outside (a server's status line or document, a library) made safe to print on one line: every character
    that is not printable becomes '?', and at most `limit` characters are kept, followed by '...'."""
    text = str(value)
    kept = ''.join(char if char.isprintable() else '?' for char in text[:limit])
    return kept + '...' if len(text) > limit else kept


def describe(error):
    """Short, bounded text for an error: its strerror, else its text, else its class."""
    return shown(getattr(error, 'strerror', None) or str(error) or type(error).__name__)


def is_deadline(error):
    return isinstance(error, TimeoutError) and str(error) == DEADLINE_TEXT


def address(name, port):
    """host:port as a person writes it, an IPv6 literal in brackets."""
    return f'[{name}]:{port}' if ':' in str(name) else f'{name}:{port}'


class Target:
    """What is being probed: the issuer, its discovery URL, host and port, and the files a failure points at."""

    def __init__(self, issuer, host, port, runtime_file, certificate):
        self.issuer, self.host, self.port = issuer, host, port
        self.url = issuer + '/.well-known/openid-configuration'
        self.runtime_file, self.certificate = runtime_file, certificate
        self.lookups = []  # (name, port) the resolver was asked for, in order; a redirect or proxy setting makes the last differ

    def reached(self):
        """(name, port) of the last lookup: the issuer's own unless the request was sent on elsewhere."""
        return self.lookups[-1] if self.lookups else (self.host, self.port)

    def detour(self):
        """A note for a failure that happened after the request left the issuer's own host, else ''."""
        name, port = self.reached()
        if self.lookups and (str(name).lower(), port) != (self.host.lower(), self.port):
            return f' (the request had been sent on to {address(shown(name), port)} from {self.host}, by a redirect or a proxy setting)'
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
    return (f'no answer within {DEADLINE_SECONDS} s from {target.url if target else "the identity route"}: check that the proxy '
            f'and Keycloak are running and that {shown(target.reached()[0]) if target else "the public name"} points at this server')


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
    """The Target of the issuer; its host name is what must resolve, certify and answer."""
    try:
        parts = urlsplit(issuer)
        host, port = parts.hostname, parts.port or (80 if parts.scheme == 'http' else 443)
    except ValueError:  # an unbalanced IPv6 bracket or a port that is not a number
        host = port = None
    if not host:
        raise Failure(f'the issuer {issuer} in {runtime_file} has no host name (or a malformed address): {ISSUER_HINT}')
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
        return (f'{target.url} answered HTTP {error.code} {shown(error.reason)}: the proxy identity route /identity must reach a '
                'running Keycloak (check krate health and the proxy and Keycloak logs)')
    wrapped = isinstance(error, URLError)  # urllib wraps only connect-time OSErrors: a stall while reading arrives unwrapped
    cause = error.reason if wrapped else error
    name, port = target.reached()  # the name last looked up: after a redirect that is not the issuer's host
    name = shown(name)
    where = address(name, port)
    if is_deadline(cause):
        return deadline_failure(target)
    if isinstance(cause, socket.gaierror):
        return (f'this server cannot resolve {name} ({describe(cause)}): add {name} to DNS or to /etc/hosts on this server, '
                "pointing at this server's address")
    if isinstance(cause, ssl.SSLCertVerificationError):
        why = shown(getattr(cause, 'verify_message', None) or describe(cause))  # the ssl module sets verify_message; a constructed error lacks it
        return (f'HTTPS certificate verification failed for {name} ({why}): the certificate in {target.certificate} must cover '
                f'{name} and be valid (krate gen-cert makes a self-signed one)')
    if isinstance(cause, ssl.SSLError):
        return (f'TLS error talking to {where} ({describe(cause)}): {where} must be the Krate proxy serving HTTPS '
                f'with the certificate in {target.certificate}')
    if isinstance(cause, http.client.InvalidURL):  # a redirect or proxy URL may fail after the issuer already answered
        return (f'a URL used while checking {target.url} (from {target.runtime_file}) is invalid ({describe(cause)}): '
                f'{ISSUER_HINT}; also check any redirect or proxy target')
    if isinstance(cause, http.client.HTTPException):
        return f'{where} did not answer with valid HTTP ({type(cause).__name__}): it must be the Krate proxy'
    if isinstance(cause, (socket.timeout, TimeoutError)) and not wrapped:  # connected, then nothing came back in time
        return (f'{where} accepted the connection but did not answer in time ({describe(cause)}): check that Keycloak behind the '
                'proxy is running and answering (krate health and the Keycloak log)')
    if isinstance(cause, OSError):  # connection refused, unreachable, reset, or a timeout while connecting
        return (f'no connection to {where} ({describe(cause)}): the Krate proxy must be running on this server '
                f'(krate health) and {name} must point at this server')
    return f'the request to {target.url} failed ({describe(cause)}): check that {name} points at this server and the proxy is running'


def fetch_discovery(target: Target, context):
    try:
        with urlopen(target.url, context=context, timeout=10) as response:
            body = response.read(1024 * 1024)
    except (OSError, http.client.HTTPException) as error:
        raise Failure(explain_request(error, target) + target.detour()) from None
    except ValueError as error:  # e.g. a UnicodeError for a host name with an empty label
        raise Failure(f'{target.url} is not a usable address ({type(error).__name__}): {ISSUER_HINT}' + target.detour()) from None
    try:
        return json.loads(body)
    except ValueError:
        raise Failure(f'the answer from {target.url} is not an OpenID configuration (not JSON): the proxy identity route /identity '
                      'must reach Keycloak' + target.detour()) from None


def verify_discovery(data, target: Target):
    issuer = target.issuer
    missing = [key for key in ('issuer',) + ENDPOINT_KEYS if not isinstance(data, dict) or not isinstance(data.get(key), str)]
    if missing:
        raise Failure(f'the answer from {target.url} is not an OpenID configuration (no {", ".join(missing)}): the proxy identity '
                      'route /identity must reach Keycloak' + target.detour())
    if data['issuer'] != issuer:
        raise Failure(f'Keycloak answers with issuer {shown(data["issuer"])} but {target.runtime_file} expects {issuer}: '
                      f'{ISSUER_HINT}' + target.detour())
    for key in ENDPOINT_KEYS:
        if not data[key].startswith(issuer + '/'):
            raise Failure(f'Keycloak reports {key} {shown(data[key])}, which is not under the issuer {issuer} in '
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
                   else f'unexpected {type(error).__name__} while checking {target.url if target else "the public sign-in"}')
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
