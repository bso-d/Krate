#!/usr/bin/env python3
"""Operator safety checks with local disposable Studio and TLS listeners."""
import json
import os
import pwd
import re
import shutil
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
STUDIO = [sys.executable, '-B', str(ROOT / 'ui/krate_ui.py'), '--workspace', str(ROOT / 'kraft')]
PROBE = [sys.executable, '-B', str(ROOT / 'sso/check-public-origin.py')]


class StudioFixture:
    def __init__(self, runtime: Path, command: list, child_options: dict,
                 operator_uid: int, environment: dict):
        self.runtime = runtime
        self.command = command
        self.child_options = child_options
        self.operator_uid = operator_uid
        self.environment = environment


@contextmanager
def operator_fixture():
    root = os.geteuid() == 0
    with tempfile.TemporaryDirectory(dir='/tmp' if root else None) as path:
        directory = Path(path)
        runtime = directory / 'runtime'
        runtime.mkdir(mode=0o700)
        command = STUDIO
        child_options = {}
        operator_uid = os.geteuid()
        if root:
            operator = pwd.getpwnam('nobody')
            if not operator.pw_uid or not operator.pw_gid:
                raise RuntimeError('Studio fixture requires an unprivileged nobody account')
            operator_uid = operator.pw_uid
            # Root checkouts may be inaccessible to the operator. Stage only
            # the production entrypoint and workspace sentinel in this fixture.
            directory.chmod(0o755)
            workspace = directory / 'kraft'
            workspace.mkdir()
            workspace.chmod(0o755)
            (workspace / 'krate').touch()
            ui = directory / 'krate_ui.py'
            shutil.copyfile(ROOT / 'ui/krate_ui.py', ui)
            ui.chmod(0o644)
            os.chown(runtime, operator.pw_uid, operator.pw_gid)
            command = [sys.executable, '-B', str(ui), '--workspace', str(workspace)]
            child_options = dict(user=operator.pw_uid, group=operator.pw_gid, extra_groups=[], cwd=directory)
        environment = dict(os.environ, RUNTIME_DIRECTORY=str(runtime), HOME=str(runtime), KRATE_UI_HOST='127.0.0.1')
        yield StudioFixture(runtime, command, child_options, operator_uid, environment)


class StudioOperatorChecks(unittest.TestCase):
    def test_managed_studio_rotates_token_without_logging_it(self):
        with operator_fixture() as fixture:
            env = dict(fixture.environment, KRATE_UI_BOOTSTRAP_TOKEN='do-not-reuse')
            command = [*fixture.command, '--managed', '--host', '127.0.0.1', '--port', '0']

            def launch():
                url_file = fixture.runtime / 'access-url'
                previous = url_file.read_text() if url_file.exists() else ''
                process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True, **fixture.child_options)
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
                    self.assertEqual(url_file.stat().st_uid, fixture.operator_uid)
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
        with operator_fixture() as fixture:
            fixture.runtime.chmod(0o755)
            result = subprocess.run([*fixture.command, '--managed'], env=fixture.environment, capture_output=True,
                                    text=True, timeout=10, **fixture.child_options)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('operator-owned and private', result.stderr)

    @unittest.skipUnless(os.geteuid() == 0, 'requires an actual root process')
    def test_managed_studio_refuses_root(self):
        with operator_fixture() as fixture:
            result = subprocess.run([*STUDIO, '--managed', '--host', '127.0.0.1'],
                                    env=fixture.environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('must run as a non-root operator', result.stderr)
            self.assertFalse((fixture.runtime / 'access-url').exists())

    def test_managed_studio_refuses_secret_and_remote_bind(self):
        with operator_fixture() as fixture:
            for args, expected in [
                (['--host', '0.0.0.0'], 'loopback'),
                (['--token', 'disallowed'], 'token'),
            ]:
                result = subprocess.run([*fixture.command, '--managed', *args], env=fixture.environment,
                                        capture_output=True, text=True, timeout=10, **fixture.child_options)
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

                # noinspection PyPep8Naming
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
            context.minimum_version = ssl.TLSVersion.TLSv1_2
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


class ActivationTrustChecks(unittest.TestCase):
    def test_public_chain_and_self_signed_bootstrap_on_legacy_ssl(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)

            def openssl(*args):
                subprocess.run(['openssl', *args], cwd=base, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            openssl('req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                    '-subj', '/CN=Krate fixture root', '-addext', 'basicConstraints=critical,CA:TRUE',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash',
                    '-keyout', 'root.key', '-out', 'root.pem')
            for name, signer, extensions in (
                ('intermediate', 'root', 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'),
                ('leaf', 'intermediate', 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\n'),
            ):
                (base / 'ext').write_text(extensions + 'authorityKeyIdentifier=keyid:always\nsubjectKeyIdentifier=hash\n')
                openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN={name}',
                        '-keyout', f'{name}.key', '-out', f'{name}.csr')
                openssl('x509', '-req', '-days', '2', '-in', f'{name}.csr', '-CA', f'{signer}.pem',
                        '-CAkey', f'{signer}.key', '-CAcreateserial', '-extfile', 'ext', '-out', f'{name}.pem')
            bundle = base / 'bundle.pem'
            bundle.write_bytes((base / 'leaf.pem').read_bytes() + (base / 'intermediate.pem').read_bytes())
            openssl('req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                    '-keyout', 'fixture.key', '-out', 'fixture.pem')
            client = """
import runpy, socket, ssl, sys
from pathlib import Path
partial_chain = getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0)
if partial_chain:
    del ssl.VERIFY_X509_PARTIAL_CHAIN
def load_test_os_roots(context, purpose=ssl.Purpose.SERVER_AUTH):
    context.load_verify_locations(cafile=sys.argv[5])
ssl.SSLContext.load_default_certs = load_test_os_roots
probe = runpy.run_path(sys.argv[1])
context = probe['trust_context'](Path(sys.argv[2]))
context.verify_flags &= ~partial_chain
with socket.create_connection(('127.0.0.1', int(sys.argv[3])), 5) as tcp:
    with context.wrap_socket(tcp, server_hostname=sys.argv[4]) as https:
        https.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')
        while https.recv(4096):
            pass
"""
            class Ready(BaseHTTPRequestHandler):
                def log_message(self, format, *args):
                    return

                # noinspection PyPep8Naming
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()

            for pem, key in [(bundle, 'leaf.key'), (base / 'fixture.pem', 'fixture.key')]:
                with self.subTest(pem=pem.name), HTTPServer(('127.0.0.1', 0), Ready) as server:
                    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    tls.minimum_version = ssl.TLSVersion.TLSv1_2
                    tls.load_cert_chain(pem, base / key)
                    server.socket = tls.wrap_socket(server.socket, server_side=True)
                    worker = threading.Thread(target=server.serve_forever, daemon=True)
                    worker.start()
                    try:
                        command = [sys.executable, '-B', '-c', client, str(ROOT / 'sso/probe.py'),
                                   str(pem), str(server.server_port)]
                        root = str(base / 'root.pem')
                        good = subprocess.run([*command, 'localhost', root], capture_output=True,
                                              text=True, timeout=10)
                        self.assertEqual(good.returncode, 0, good.stderr)
                        wrong = subprocess.run([*command, 'wrong.invalid', root], capture_output=True,
                                               text=True, timeout=10)
                        self.assertNotEqual(wrong.returncode, 0)
                        self.assertIn('hostname mismatch', wrong.stderr.lower())
                    finally:
                        server.shutdown()
                        worker.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
