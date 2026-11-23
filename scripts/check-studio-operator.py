#!/usr/bin/env python3
"""Operator safety checks with local disposable Studio and TLS listeners."""
import json
import os
import re
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
STUDIO = [sys.executable, '-B', str(ROOT / 'ui/krate_ui.py'), '--workspace', str(ROOT / 'kraft')]
PROBE = [sys.executable, '-B', str(ROOT / 'sso/check-public-origin.py')]


class StudioOperatorChecks(unittest.TestCase):
    def test_managed_studio_rotates_token_without_logging_it(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            env = dict(os.environ, RUNTIME_DIRECTORY=directory, KRATE_UI_BOOTSTRAP_TOKEN='do-not-reuse')
            command = [*STUDIO, '--managed', '--host', '127.0.0.1', '--port', '0']

            def launch():
                url_file = runtime / 'access-url'
                previous = url_file.read_text() if url_file.exists() else ''
                process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            self.fail(process.communicate()[1])
                        if url_file.exists() and url_file.read_text() != previous:
                            break
                        time.sleep(0.03)
                    else:
                        self.fail('Studio did not publish a fresh access URL')
                    self.assertEqual(stat.S_IMODE(url_file.stat().st_mode), 0o600)
                    url = url_file.read_text().strip()
                    self.assertRegex(url, r'^http://127\.0\.0\.1:[1-9][0-9]*/\?token=.{32,}$')
                    self.assertNotIn('do-not-reuse', url)
                    parsed = urlsplit(url)
                    conn = HTTPConnection('127.0.0.1', parsed.port, timeout=3)
                    try:
                        for token, status in [('do-not-reuse', 403), (parsed.query.split('=', 1)[1], 200)]:
                            conn.request('POST', '/api/v1/auth/exchange', json.dumps({'token': token}),
                                         {'Content-Type': 'application/json'})
                            response = conn.getresponse()
                            self.assertEqual(response.status, status)
                            response.read()
                    finally:
                        conn.close()
                finally:
                    if process.poll() is None:
                        process.terminate()
                    out, err = process.communicate(timeout=5)
                self.assertIn('Access URL file:', out)
                self.assertNotIn(url.split('token=', 1)[1], out + err)
                return url

            first = launch()
            second = launch()
            self.assertNotEqual(first.split('token=')[1], second.split('token=')[1])

    def test_managed_studio_refuses_insecure_runtime_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o755)
            env = dict(os.environ, RUNTIME_DIRECTORY=directory, KRATE_UI_HOST='127.0.0.1')
            result = subprocess.run([*STUDIO, '--managed'], env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('operator-owned and private', result.stderr)

    def test_managed_studio_refuses_secret_and_remote_bind(self):
        for args, expected in [
            (['--host', '0.0.0.0'], 'loopback'),
            (['--token', 'disallowed'], 'token'),
        ]:
            result = subprocess.run([*STUDIO, '--managed', *args], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr.lower())
            self.assertNotIn('disallowed', result.stderr)


class CertificatePairChecks(unittest.TestCase):
    def test_incomplete_pair_refuses_without_overwriting_surviving_material(self):
        for variant in ('kraft', 'epc'):
            source = (ROOT / variant / 'krate').read_text()
            functions = []
            for name in ('san_entry', 'ensure_public_cert_readable', 'cmd_gen_cert', 'ensure_cert'):
                match = re.search(r'^' + name + r'\(\) \{.*?^\}', source, re.MULTILINE | re.DOTALL)
                if match is None:
                    self.fail(f'{variant}: cannot extract {name}')
                functions.append(match.group())
            driver = r"""
set -euo pipefail
CERTS_DIR=$1; CERT_CRT="$1/server.crt"; CERT_KEY="$1/server.key"
get_fqdn() { echo localhost; }
public_url_host() { echo localhost; }
hostname() { echo 127.0.0.1; }
info() { :; }
ok() { :; }
warn() { :; }
die() { printf '%s\n' "$*" >&2; exit 1; }
""" + '\n'.join(functions) + '\nensure_cert\n'
            for surviving, missing in [('server.crt', 'server.key'), ('server.key', 'server.crt')]:
                with self.subTest(variant=variant, surviving=surviving), tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    file = base / surviving
                    original = b'existing operator-owned TLS material\n'
                    file.write_bytes(original)
                    file.chmod(0o600)
                    result = subprocess.run(['bash', '-s', '--', directory], input=driver, capture_output=True,
                                            text=True, timeout=12)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('incomplete', result.stderr.lower())
                    self.assertEqual(file.read_bytes(), original)
                    self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
                    self.assertFalse((base / missing).exists())


class OriginChecks(unittest.TestCase):
    def test_trusted_and_matching_issuer_required_without_following_redirects(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            cert, key = base / 'ca.pem', base / 'key.pem'
            subprocess.run(
                ['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                 '-keyout', str(key), '-out', str(cert)],
                check=True, stderr=subprocess.DEVNULL,
            )

            class DiscoveryServer(HTTPServer):
                result: int
                issuer: str

            class Fixture(BaseHTTPRequestHandler):
                def log_message(self, format, *args):
                    return

                def do_GET(self):
                    if (self.path != '/identity/realms/krate/.well-known/openid-configuration'
                            or self.headers['Host'] != f'localhost:{server.server_port}'):
                        self.send_error(404)
                        return
                    self.send_response(server.result)
                    if server.result == 302:
                        self.send_header('Location', 'https://example.invalid/')
                    self.end_headers()
                    self.wfile.write(json.dumps({'issuer': server.issuer}).encode())

            server = DiscoveryServer(('127.0.0.1', 0), Fixture)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            origin = f'https://localhost:{server.server_port}'
            server.result, server.issuer = 200, origin + '/identity/realms/krate'
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:

                def probe(host='localhost', trusted=True):
                    workspace = base / '.env'
                    workspace.write_text(f'KEYCLOAK_PUBLIC_URL=https://{host}:{server.server_port}/identity\n')
                    command = [*PROBE, '--workspace', directory]
                    if trusted:
                        command += ['--ca-file', str(cert)]
                    return subprocess.run(command, capture_output=True, text=True, timeout=10)

                good = probe()
                self.assertEqual(good.returncode, 0, good.stderr)
                self.assertIn(origin, good.stdout)
                self.assertNotEqual(probe(trusted=False).returncode, 0)
                self.assertNotEqual(probe(host='127.0.0.1').returncode, 0)
                server.issuer = 'https://localhost/identity/realms/krate'
                self.assertIn('issuer', probe().stderr.lower())
                server.result = 302
                self.assertIn('302', probe().stderr)

                # A trusted certificate with only a DNS common name is not browser-valid.
                subprocess.run(
                    ['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
                     '-days', '2', '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(cert)],
                    check=True, stderr=subprocess.DEVNULL,
                )
                context.load_cert_chain(cert, key)
                server.result, server.issuer = 200, origin + '/identity/realms/krate'
                cn_only = probe()
                self.assertNotEqual(cn_only.returncode, 0)
                self.assertIn('TLS certificate verification', cn_only.stderr)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
