#!/usr/bin/env python3
"""Expose the certificate actually served by each Kafka external listener."""

from __future__ import annotations

import os
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def endpoints() -> tuple[tuple[str, int], ...]:
    values = os.environ.get("KAFKA_SECURITY_ENDPOINTS", "").split(",")
    parsed = []
    for value in values:
        host, separator, port = value.strip().rpartition(":")
        if not separator or not host or not port.isdecimal() or not 0 < int(port) < 65536:
            raise ValueError("KAFKA_SECURITY_ENDPOINTS must contain host:port entries")
        parsed.append((host, int(port)))
    if not 1 <= len(parsed) <= 16 or len(set(parsed)) != len(parsed):
        raise ValueError("KAFKA_SECURITY_ENDPOINTS must contain 1 to 16 distinct endpoints")
    return tuple(parsed)


def probe(endpoint: tuple[str, int], cafile: str) -> tuple[str, float | None, bool]:
    host, port = endpoint
    label = f"{host}:{port}"

    def read_expiry(legacy_ca: bool) -> float:
        context = ssl.create_default_context(cafile=cafile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if legacy_ca:
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        with socket.create_connection(endpoint, timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname=host) as stream:
                certificate = stream.getpeercert()
        if not isinstance(certificate, dict):
            raise ValueError("TLS peer did not return a certificate")
        expiry = certificate.get("notAfter")
        if not isinstance(expiry, str):
            raise ValueError("TLS peer certificate has no expiry")
        return ssl.cert_time_to_seconds(expiry) - time.time()

    try:
        return label, read_expiry(False), False
    except ssl.SSLCertVerificationError as exc:
        # Existing CAs can lack keyUsage and existing leaves can lack an
        # authorityKeyIdentifier. Keep chain and hostname verification while
        # exposing the legacy certificate for migration.
        legacy_extension_errors = (
            "CA cert does not include key usage extension",
            "Missing Authority Key Identifier",
        )
        if not any(message in str(exc) for message in legacy_extension_errors):
            return label, None, False
        try:
            return label, read_expiry(True), True
        except (OSError, ValueError, KeyError, ssl.SSLError):
            return label, None, True
    except (OSError, ValueError, KeyError, ssl.SSLError):
        return label, None, False


def render_metrics(targets: tuple[tuple[str, int], ...], cafile: str, secure: bool) -> bytes:
    lines = [
        "# HELP krate_kafka_security_mode Kafka OAuth SSL mode enabled.",
        "# TYPE krate_kafka_security_mode gauge",
        f"krate_kafka_security_mode {int(secure)}",
        "# HELP krate_kafka_listener_tls_probe_success Verified on-wire Kafka listener TLS handshake.",
        "# TYPE krate_kafka_listener_tls_probe_success gauge",
        "# HELP krate_kafka_listener_certificate_seconds_until_expiry On-wire Kafka listener certificate lifetime.",
        "# TYPE krate_kafka_listener_certificate_seconds_until_expiry gauge",
        "# HELP krate_kafka_listener_legacy_ca Kafka listener uses a pre-fix CA without key usage.",
        "# TYPE krate_kafka_listener_legacy_ca gauge",
    ]
    if secure:
        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            results = list(pool.map(lambda target: probe(target, cafile), targets))
        for label, remaining, legacy_ca in results:
            lines.append(f'krate_kafka_listener_tls_probe_success{{broker="{label}"}} {int(remaining is not None)}')
            lines.append(f'krate_kafka_listener_legacy_ca{{broker="{label}"}} {int(legacy_ca)}')
            if remaining is not None:
                lines.append(f'krate_kafka_listener_certificate_seconds_until_expiry{{broker="{label}"}} {remaining:.0f}')
    return ("\n".join(lines) + "\n").encode("ascii")


def main() -> None:
    targets = endpoints()
    secure = os.environ.get("KAFKA_SECURITY_MODE", "false") in ("true", "oauth_ssl")
    cafile = os.environ.get("KAFKA_SECURITY_CA", "/etc/krate/certs/kafka/ca.crt")
    if secure and not os.path.isfile(cafile):
        raise FileNotFoundError(cafile)

    class Handler(BaseHTTPRequestHandler):
        # BaseHTTPRequestHandler dispatches the uppercase HTTP method name.
        # noinspection PyPep8Naming
        def do_GET(self) -> None:
            if self.path == "/healthz":
                body = b"ok\n"
            elif self.path == "/metrics":
                body = render_metrics(targets, cafile, secure)
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    ThreadingHTTPServer(("0.0.0.0", 9315), Handler).serve_forever()


if __name__ == "__main__":
    main()
