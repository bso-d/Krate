#!/usr/bin/env python3
"""Name mapping for the identity gate: resolve one public host name to loopback.

The Phase 4 slices run under a non-localhost public host (`--public-host NAME`),
because the realm-mode monitoring UIs refuse a loopback KEYCLOAK_PUBLIC_URL
(refuse_loopback_public_url, kraft/krate). The gate must not touch /etc/hosts,
so the name is mapped the way `curl --resolve NAME:PORT:127.0.0.1` maps it for
the runner's shell probes: this module replaces `socket.getaddrinfo` for that
one name, so every urllib/http.client connection to NAME reaches 127.0.0.1.

TLS keeps the real name: only the address resolution is substituted, the
`server_hostname`/SNI value and the certificate hostname check still see NAME
(the same split curl --resolve makes), so a certificate without NAME in its
subjectAltName fails verification instead of silently passing.

Helpers opt in with one line after importing this module:

    import netmap
    netmap.install()          # maps $GATE_PUBLIC_HOST, no-op when unset

`install()` is idempotent and a no-op when the environment variable is unset,
empty or a loopback name, so a helper keeps working unchanged on the Phase 1-3
localhost runs and when it is invoked by hand. Python 3.9 compatible.
"""
import os
import socket

DEFAULT_ENV = 'GATE_PUBLIC_HOST'
LOOPBACK_NAMES = ('localhost', '127.0.0.1', '::1', '[::1]')

_installed = None  # (name, ip) once mapped, else None


def install(host=None, ip='127.0.0.1', env=DEFAULT_ENV):
    """Map `host` (default: the value of the `env` environment variable) to `ip`.

    Returns the (name, ip) pair when a mapping was installed (or was already
    installed), None when there is nothing to map. Never maps a loopback name:
    the operating system resolves those already, and replacing their answer
    would drop the IPv6 side of `localhost`.
    """
    global _installed
    if _installed is not None:
        return _installed
    if host is None:
        host = os.environ.get(env, '')
    host = (host or '').strip()
    if not host or host.lower() in LOOPBACK_NAMES:
        return None
    real_getaddrinfo = socket.getaddrinfo
    target = host.lower()

    def mapped_getaddrinfo(mapped_host, *args, **kwargs):
        if isinstance(mapped_host, str) and mapped_host.lower() == target:
            mapped_host = ip
        return real_getaddrinfo(mapped_host, *args, **kwargs)

    socket.getaddrinfo = mapped_getaddrinfo
    _installed = (host, ip)
    return _installed


def mapped():
    """The active mapping as (name, ip), or None: diagnostics and evidence lines."""
    return _installed
