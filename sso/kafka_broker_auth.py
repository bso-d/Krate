#!/usr/bin/env python3
"""Kafka broker TLS certificates and SASL configuration for OAuth2 + mTLS.

Generates CA, leaf certificates, and server.properties for broker clusters.
Secrets (passwords) are never returned in dicts or printed; functions write them
to disk and return only metadata.
"""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def validate_jaas_secret(env, key):
    """Validate a JAAS secret: nonempty, 16-256 chars, no whitespace/control/special chars.

    Raises ValueError if the secret is invalid for JAAS property files.
    """
    secret = env.get(key, '').strip()
    if not secret:
        raise ValueError(f'{key} is empty or missing')
    if len(secret) < 16:
        raise ValueError(f'{key} is {len(secret)} chars; minimum 16 required')
    if len(secret) > 256:
        raise ValueError(f'{key} is {len(secret)} chars; maximum 256 allowed')
    # Check for forbidden chars: whitespace, control chars, quotes, backslash, semicolon, brackets, comma
    forbidden = set(' \t\n\r\x00"\'\\;[],')
    forbidden.update(chr(i) for i in range(32))
    for char in secret:
        if char in forbidden:
            raise ValueError(f'{key} contains forbidden character {repr(char)}')
    return secret


def validate_keystore_password(env, key='KAFKA_TLS_KEYSTORE_PASSWORD'):
    """Validate a PKCS12 keystore password: nonempty, 16-256 chars, no CR/LF/NUL.

    Raises ValueError if the password is invalid.
    """
    password = env.get(key, '').strip()
    if not password:
        raise ValueError(f'{key} is empty or missing')
    if len(password) < 16:
        raise ValueError(f'{key} is {len(password)} chars; minimum 16 required')
    if len(password) > 256:
        raise ValueError(f'{key} is {len(password)} chars; maximum 256 allowed')
    # Check for forbidden chars: CR, LF, NUL
    if '\r' in password or '\n' in password or '\x00' in password:
        raise ValueError(f'{key} contains forbidden line-break or NUL character')
    return password


def validate_advertised_host(raw):
    """Validate advertised host: defaults empty to 'localhost', accepts IP or RFC-1123 hostname.

    Raises ValueError if the host is invalid.
    """
    host = (raw or '').strip()
    if not host:
        return 'localhost'

    # Try parsing as an IP address (stripping brackets for IPv6)
    stripped = host.lstrip('[').rstrip(']')
    try:
        ipaddress.ip_address(stripped)
        return stripped
    except ValueError:
        pass

    # Try parsing as RFC-1123 hostname
    dns_pattern = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')
    if dns_pattern.fullmatch(host):
        return host

    raise ValueError(f'KAFKA_ADVERTISED_HOST {repr(host)} is not a valid IPv4, IPv6, or hostname')


def san_entries(edition, advertised_host):
    """Build Subject Alternative Name entries for certificate.

    Args:
        edition: 'kraft' or 'epc'
        advertised_host: the advertised host to add (or not, if already present)

    Returns:
        List of SAN entries like ['DNS:kafka-92', 'IP:127.0.0.1', ...]
    """
    if edition == 'kraft':
        base = ['DNS:kafka-92', 'DNS:kafka-93', 'DNS:kafka-94', 'DNS:kafka-95',
                'DNS:proxy', 'DNS:localhost', 'IP:127.0.0.1']
    elif edition == 'epc':
        base = ['DNS:kafka-92', 'DNS:kafka-93', 'DNS:proxy', 'DNS:localhost', 'IP:127.0.0.1']
    else:
        raise ValueError(f'edition must be kraft or epc, got {repr(edition)}')

    # Deduplicate while preserving order
    seen = set(base)
    result = base[:]

    # Add advertised_host if not already present
    try:
        ip = ipaddress.ip_address(advertised_host)
        entry = f'IP:{ip}'
    except ValueError:
        entry = f'DNS:{advertised_host}'

    if entry not in seen:
        result.append(entry)

    return result


def _write_atomic(path, data_bytes, file_mode):
    """Write data atomically to a file: create temp in parent, chmod, and replace.

    Args:
        path: target Path
        data_bytes: bytes to write
        file_mode: mode like 0o600 or 0o644
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        tmp.write(data_bytes)
        tmp.flush()
        os.chmod(tmp.name, file_mode)
        os.replace(tmp.name, path)


def _openssl(args, cwd, capture=False, env=None):
    """Run openssl command.

    Args:
        args: openssl args (not including 'openssl')
        cwd: working directory
        capture: capture stdout
        env: environment dict (merged with os.environ)

    Returns:
        stdout text if capture, else ''

    Raises:
        subprocess.SubprocessError if openssl fails
    """
    full_env = {**os.environ}
    if env:
        full_env.update(env)
    result = subprocess.run(['openssl', *args], cwd=cwd, env=full_env,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    if result.returncode:
        raise subprocess.SubprocessError(f'openssl {args[0]} failed (exit {result.returncode})')
    return result.stdout.decode() if capture else ''


def ensure_ca(ca_dir, trust_dir):
    """Ensure CA exists: if both ca.key and ca.crt present, keep them; if only one, error.

    Otherwise generate new CA key + self-signed cert.

    Args:
        ca_dir: directory for ca.key and ca.crt
        trust_dir: directory to copy ca.crt into

    Raises:
        ValueError if material is incomplete
    """
    ca_dir = Path(ca_dir).resolve()
    trust_dir = Path(trust_dir).resolve()

    ca_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    trust_dir.mkdir(parents=True, mode=0o755, exist_ok=True)

    ca_key = ca_dir / 'ca.key'
    ca_crt = ca_dir / 'ca.crt'

    key_exists = ca_key.exists()
    crt_exists = ca_crt.exists()

    if key_exists and crt_exists:
        # Both exist: keep them
        pass
    elif key_exists or crt_exists:
        # Only one exists: incomplete, error
        raise ValueError(f'Incomplete CA material: {ca_key} exists={key_exists}, {ca_crt} exists={crt_exists}')
    else:
        # Neither exists: generate
        _openssl(['genrsa', '-out', str(ca_key), '4096'], cwd=ca_dir)
        os.chmod(ca_key, 0o600)

        _openssl(['req', '-new', '-x509', '-key', str(ca_key), '-out', str(ca_crt),
                  '-days', '3650', '-subj', '/CN=Krate Kafka CA'], cwd=ca_dir)
        os.chmod(ca_crt, 0o644)

    # Copy ca.crt to trust_dir
    trust_ca = trust_dir / 'ca.crt'
    trust_ca.write_bytes(ca_crt.read_bytes())
    os.chmod(trust_ca, 0o644)


def _issue_leaf_keystore(ca_dir, certs_dir, edition, advertised_host, keystore_password):
    """Issue a leaf keystore (PKCS12) and export public cert.

    Args:
        ca_dir: directory with ca.key and ca.crt
        certs_dir: directory to write broker.p12 and broker.crt
        edition: 'kraft' or 'epc'
        advertised_host: advertised host for SANs
        keystore_password: password for PKCS12
    """
    ca_dir = Path(ca_dir).resolve()
    certs_dir = Path(certs_dir).resolve()
    certs_dir.mkdir(parents=True, mode=0o755, exist_ok=True)

    # Generate leaf key
    broker_key = certs_dir / 'broker.key'
    _openssl(['genrsa', '-out', str(broker_key), '2048'], cwd=certs_dir)
    os.chmod(broker_key, 0o600)

    # Generate CSR
    broker_csr = certs_dir / 'broker.csr'
    _openssl(['req', '-new', '-key', str(broker_key), '-out', str(broker_csr),
              '-subj', '/CN=kafka-broker'], cwd=certs_dir)

    # Create extensions file for signing
    san_list = ','.join(san_entries(edition, advertised_host))
    ext_file = certs_dir / 'broker.ext'
    ext_file.write_text(
        f'basicConstraints=critical,CA:FALSE\n'
        f'keyUsage=critical,digitalSignature,keyEncipherment\n'
        f'extendedKeyUsage=serverAuth,clientAuth\n'
        f'subjectAltName={san_list}\n'
    )

    # Sign CSR with CA
    broker_crt = certs_dir / 'broker.crt'
    ca_key = ca_dir / 'ca.key'
    ca_crt = ca_dir / 'ca.crt'

    _openssl(['x509', '-req', '-in', str(broker_csr), '-CA', str(ca_crt), '-CAkey', str(ca_key),
              '-CAcreateserial', '-out', str(broker_crt), '-days', '398', '-sha256',
              '-extfile', str(ext_file)], cwd=certs_dir)
    os.chmod(broker_crt, 0o644)

    # Export PKCS12
    broker_p12 = certs_dir / 'broker.p12'
    env = {**os.environ, 'KRATE_PKCS12_PASSWORD': keystore_password}
    _openssl(['pkcs12', '-export', '-in', str(broker_crt), '-inkey', str(broker_key),
              '-certfile', str(ca_crt), '-name', 'broker', '-out', str(broker_p12),
              '-passout', 'env:KRATE_PKCS12_PASSWORD'], cwd=certs_dir, env=env)
    os.chmod(broker_p12, 0o600)

    # Clean up temp files
    for tmp in [broker_key, broker_csr, ext_file, ca_crt.parent / 'ca.srl']:
        if tmp.exists():
            tmp.unlink()


def keystore_opens(p12_path, password):
    """True when the PKCS12 keystore opens with `password` (the password goes through the environment, never argv)."""
    try:
        _openssl(['pkcs12', '-in', str(p12_path), '-nokeys', '-passin', 'env:KRATE_PKCS12_PASSWORD'],
                 cwd=Path(p12_path).parent, env={'KRATE_PKCS12_PASSWORD': password})
    except subprocess.SubprocessError:
        return False
    return True


def inspect_cert(cert_path):
    """Inspect a certificate and return dict with serial, subject, not_after, sans.

    Args:
        cert_path: Path to X.509 certificate file

    Returns:
        Dict with keys: serial, subject, not_after, sans
    """
    cert_path = Path(cert_path)
    output = _openssl(['x509', '-in', str(cert_path), '-noout', '-serial', '-subject',
                       '-enddate', '-ext', 'subjectAltName'], cwd=cert_path.parent, capture=True)

    result = {}
    for line in output.splitlines():
        if line.startswith('serial='):
            result['serial'] = line[7:]
        elif line.startswith('subject='):
            result['subject'] = line[8:]
        elif line.startswith('notAfter='):
            result['not_after'] = line[9:]
        elif line.startswith('X509v3 Subject Alternative Name:'):
            # Next line(s) contain the SANs
            continue
        elif line.strip().startswith('DNS:') or line.strip().startswith('IP'):
            if 'sans' not in result:
                result['sans'] = []
            # Parse all SANs from this and subsequent lines
            for san in line.split(', '):
                san = san.strip()
                if san:
                    # Normalize "IP Address:" to "IP:"
                    san = san.replace('IP Address:', 'IP:')
                    result['sans'].append(san)

    return result


def render_broker_auth(env_file, edition, output_dir, ca_dir, trust_dir):
    """Render OAuth2 + SSL configuration for Kafka broker.

    Args:
        env_file: path to .env file
        edition: 'kraft' or 'epc'
        output_dir: directory to write config files
        ca_dir: directory for CA
        trust_dir: directory for public CA cert

    Returns:
        Dict with edition, expected_issuer, advertised_host, config_sha, ca_cert,
        serial, subject, not_after, sans (no secrets!)

    Raises:
        ValueError on validation errors
    """
    # Import sibling module for read_env and public_origin (works both from CLI and direct execution)
    try:
        from . import identity
    except (ImportError, ValueError):
        # Fallback for direct script execution (ValueError happens when not in package context)
        import identity

    env = identity.read_env(env_file)

    if edition not in ('kraft', 'epc'):
        raise ValueError(f'edition must be kraft or epc, got {repr(edition)}')

    # Validate and derive public values
    origin = identity.public_origin(env.get('KEYCLOAK_PUBLIC_URL'))
    expected_issuer = origin + '/identity/realms/krate'
    advertised_host = validate_advertised_host(env.get('KAFKA_ADVERTISED_HOST', ''))

    # Validate all secrets (raises ValueError if invalid)
    interbroker_pw = validate_jaas_secret(env, 'KAFKA_INTERBROKER_PASSWORD')
    admin_pw = validate_jaas_secret(env, 'KAFKA_ADMIN_PASSWORD')
    exporter_pw = validate_jaas_secret(env, 'KAFKA_EXPORTER_SCRAM_PASSWORD')
    keystore_pw = validate_keystore_password(env, 'KAFKA_TLS_KEYSTORE_PASSWORD')

    # Ensure CA
    ensure_ca(ca_dir, trust_dir)

    # Create output dirs
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, mode=0o755, exist_ok=True)
    certs_dir = output_dir / 'certs'
    certs_dir.mkdir(parents=True, mode=0o755, exist_ok=True)

    # Check if we need to issue leaf keystore
    broker_p12 = certs_dir / 'broker.p12'
    broker_crt = certs_dir / 'broker.crt'

    need_issue = False
    if not broker_p12.exists() or not broker_crt.exists():
        need_issue = True
    else:
        # A kept leaf must still match the plan: the SANs of the advertised host and edition, and the
        # keystore password of the current .env. A keystore written under an earlier .env (a wiped
        # fixture, a restored backup, a rotated KAFKA_TLS_KEYSTORE_PASSWORD) cannot be opened by the
        # broker ("keystore password was incorrect", a fatal startup error on every broker); it is
        # re-issued instead of kept.
        try:
            cert_info = inspect_cert(broker_crt)
            existing_sans = set(cert_info.get('sans', []))
            expected_sans = set(san_entries(edition, advertised_host))
            if existing_sans != expected_sans or not keystore_opens(broker_p12, keystore_pw):
                need_issue = True
        except Exception:
            need_issue = True

    if need_issue:
        _issue_leaf_keystore(ca_dir, certs_dir, edition, advertised_host, keystore_pw)

    # Write config files
    server_props = f'''# Generated by krate kafka auth enable — do not commit
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer
allow.everyone.if.no.acl.found=false
super.users=User:krate-interbroker;User:krate-admin;User:service-account-krate-ui-kafka
sasl.enabled.mechanisms=PLAIN,SCRAM-SHA-512,OAUTHBEARER
sasl.mechanism.controller.protocol=PLAIN
listener.name.controller.sasl.enabled.mechanisms=PLAIN
listener.name.controller.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="krate-interbroker" password="{interbroker_pw}" user_krate-interbroker="{interbroker_pw}";
sasl.mechanism.inter.broker.protocol=PLAIN
listener.name.internal.sasl.enabled.mechanisms=PLAIN,SCRAM-SHA-512,OAUTHBEARER
listener.name.internal.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="krate-interbroker" password="{interbroker_pw}" user_krate-interbroker="{interbroker_pw}" user_krate-admin="{admin_pw}";
listener.name.internal.scram-sha-512.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required;
listener.name.internal.oauthbearer.sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;
listener.name.internal.oauthbearer.sasl.server.callback.handler.class=org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler
listener.name.internal.sasl.oauthbearer.jwks.endpoint.url=http://keycloak:8080/identity/realms/krate/protocol/openid-connect/certs
listener.name.internal.sasl.oauthbearer.expected.audience=kafka
listener.name.internal.sasl.oauthbearer.expected.issuer={expected_issuer}
listener.name.internal.sasl.oauthbearer.sub.claim.name=kafka_principal
listener.name.external.sasl.enabled.mechanisms=OAUTHBEARER
listener.name.external.oauthbearer.sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;
listener.name.external.oauthbearer.sasl.server.callback.handler.class=org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler
listener.name.external.sasl.oauthbearer.jwks.endpoint.url=http://keycloak:8080/identity/realms/krate/protocol/openid-connect/certs
listener.name.external.sasl.oauthbearer.expected.audience=kafka
listener.name.external.sasl.oauthbearer.expected.issuer={expected_issuer}
listener.name.external.sasl.oauthbearer.sub.claim.name=kafka_principal
listener.name.external.ssl.keystore.type=PKCS12
listener.name.external.ssl.keystore.location=/mnt/shared/config/certs/broker.p12
listener.name.external.ssl.keystore.password={keystore_pw}
listener.name.external.ssl.key.password={keystore_pw}
listener.name.external.ssl.client.auth=none
ssl.allow.san.changes=true
'''

    admin_props = f'''security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="krate-admin" password="{admin_pw}";
'''

    exporter_props = f'''security.protocol=SASL_PLAINTEXT
sasl.mechanism=SCRAM-SHA-512
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="krate-exporter" password="{exporter_pw}";
'''

    exporter_scram_props = f'''SCRAM-SHA-512=password={exporter_pw}
'''

    # Write config files atomically
    _write_atomic(output_dir / 'server.properties', server_props.encode(), 0o600)
    _write_atomic(output_dir / 'admin.properties', admin_props.encode(), 0o600)
    _write_atomic(output_dir / 'exporter.properties', exporter_props.encode(), 0o600)
    _write_atomic(output_dir / 'exporter-scram.properties', exporter_scram_props.encode(), 0o600)

    # Compute config_sha over file contents (reading from disk, not memory)
    sha256 = hashlib.sha256()
    for fpath in [output_dir / 'server.properties', output_dir / 'admin.properties',
                  output_dir / 'exporter.properties', output_dir / 'exporter-scram.properties',
                  certs_dir / 'broker.crt']:
        sha256.update(fpath.read_bytes())
    config_sha = sha256.hexdigest()[:32]

    # Inspect leaf cert
    cert_info = inspect_cert(broker_crt)

    # Return secret-free metadata
    return {
        'edition': edition,
        'expected_issuer': expected_issuer,
        'advertised_host': advertised_host,
        'config_sha': config_sha,
        'ca_cert': str(Path(trust_dir) / 'ca.crt'),
        **cert_info
    }


def renew_kafka_tls(env_file, edition, output_dir, ca_dir, trust_dir):
    """Renew Kafka TLS: back up existing certs, issue new leaf under existing CA.

    Args:
        env_file: path to .env file
        edition: 'kraft' or 'epc'
        output_dir: directory with certs
        ca_dir: directory with CA
        trust_dir: directory for public CA cert

    Returns:
        Secret-free metadata dict

    Raises:
        ValueError if CA doesn't exist
    """
    # Import sibling module for read_env and public_origin
    try:
        from . import identity
    except (ImportError, ValueError):
        # Fallback for direct script execution
        import identity

    env = identity.read_env(env_file)

    ca_key = Path(ca_dir) / 'ca.key'
    ca_crt = Path(ca_dir) / 'ca.crt'

    if not ca_key.exists() or not ca_crt.exists():
        raise ValueError('CA does not exist; create it first with render_broker_auth')

    certs_dir = Path(output_dir) / 'certs'
    broker_p12 = certs_dir / 'broker.p12'
    broker_crt = certs_dir / 'broker.crt'

    # Back up existing
    if broker_p12.exists():
        broker_p12.rename(certs_dir / '.previous.broker.p12')
    if broker_crt.exists():
        broker_crt.rename(certs_dir / '.previous.broker.crt')

    # Issue new leaf
    advertised_host = validate_advertised_host(env.get('KAFKA_ADVERTISED_HOST', ''))
    keystore_pw = validate_keystore_password(env, 'KAFKA_TLS_KEYSTORE_PASSWORD')

    _issue_leaf_keystore(ca_dir, certs_dir, edition, advertised_host, keystore_pw)

    # Return metadata
    cert_info = inspect_cert(broker_crt)
    sha256 = hashlib.sha256()
    for fpath in [output_dir / 'server.properties', output_dir / 'admin.properties',
                  output_dir / 'exporter.properties', output_dir / 'exporter-scram.properties',
                  broker_crt]:
        if fpath.exists():
            sha256.update(fpath.read_bytes())
    config_sha = sha256.hexdigest()[:32]

    return {
        'config_sha': config_sha,
        **cert_info
    }


def rollback_kafka_tls(output_dir):
    """Restore .previous broker files.

    Args:
        output_dir: directory with certs
    """
    certs_dir = Path(output_dir) / 'certs'
    prev_p12 = certs_dir / '.previous.broker.p12'
    prev_crt = certs_dir / '.previous.broker.crt'

    if prev_p12.exists():
        prev_p12.rename(certs_dir / 'broker.p12')
    if prev_crt.exists():
        prev_crt.rename(certs_dir / 'broker.crt')


def discard_previous_kafka_tls(output_dir):
    """Discard .previous broker files.

    Args:
        output_dir: directory with certs
    """
    certs_dir = Path(output_dir) / 'certs'
    for fpath in [certs_dir / '.previous.broker.p12', certs_dir / '.previous.broker.crt']:
        if fpath.exists():
            fpath.unlink()


def inspect_kafka_tls(output_dir):
    """Inspect broker TLS certificate.

    Args:
        output_dir: directory with certs

    Returns:
        Secret-free metadata dict
    """
    broker_crt = Path(output_dir) / 'certs' / 'broker.crt'
    return inspect_cert(broker_crt)
