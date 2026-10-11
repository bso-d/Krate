#!/usr/bin/env python3
"""Validate authentication activation before any service mutation."""
import argparse
import ipaddress
import re
import json
from pathlib import Path
import stat
import subprocess
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import identity  # noqa: E402  (sibling module; explicit path keeps python -I working)

IDENTITY_SECRETS = ('KEYCLOAK_ADMIN_PASSWORD', 'KEYCLOAK_DB_PASSWORD',
                    'KEYCLOAK_KAFBAT_CLIENT_SECRET', 'KEYCLOAK_CLI_CLIENT_SECRET')
# Issued by PingFederate; unused by the local realm, so only validated when set.
OPTIONAL_SECRETS = ('PING_KEYCLOAK_CLIENT_SECRET',)
INSECURE = ('', 'REPLACE_ME', 'changeme')
TLS_DIR = 'auth/keycloak/db-tls'
REALM_FILE = 'auth/keycloak/krate-realm.json'
RUNTIME_FILE = 'auth/ui/runtime.yml'
UI_AUTH_DIR = '/etc/krate/auth'
IDENTITY_NETWORK = 'identity'
CLUSTER_NETWORK = 'kafka-network'
# Warn this long before the database server certificate expires (seconds); refuse within one day.
RENEW_WARNING = 30 * 86400


class Preflight(ValueError):
    """A refusal whose message is safe to print: it never carries a configured value."""


IDENTITY_MEMBERS = {'keycloak-db', 'keycloak', 'proxy', 'kafka-ui'}
EGRESS_NETWORK = 'identity-egress'


# Column-0 lines kafbat.yml may contain: blank, a comment and the kafka: key; the document
# marker only before the first content line (a later `---` opens a second document, whose root
# mapping may be indented, so it would never reach column 0).
KAFBAT_YML_BLANK = re.compile(r'\s*(#.*)?')
KAFBAT_YML_KAFKA = re.compile(r'kafka:(\s+#.*)?\s*')


def validate_kafbat_yml(root):
    """EPC's kafbat.yml is merged into the same Spring configuration; it may configure clusters only.

    A node is opened by a column-0 line, whatever its spelling (a quoted key, a flow mapping, a
    complex key), or by an indented line before any `kafka:` (an indented root mapping, which YAML
    allows). So: before `kafka:` only blank lines, comments and one leading `---` may appear; after
    it, column-0 lines must be blank or comments; `---` and `...` are refused anywhere else. Nothing
    is parsed.
    """
    path = root / 'kafbat.yml'
    if not path.is_file():
        return
    lines = path.read_text(encoding='utf-8-sig').splitlines()
    while lines and KAFBAT_YML_BLANK.fullmatch(lines[-1]):
        lines.pop()
    if lines and re.fullmatch(r'\.\.\.\s*(#.*)?', lines[-1]):
        lines.pop()  # a document end marker as the last content line is plain YAML
    offending = []
    seen_kafka = False
    seen_content = False
    for number, line in enumerate(lines, 1):
        if KAFBAT_YML_BLANK.fullmatch(line):
            continue
        if not seen_content and re.fullmatch(r'%(YAML|TAG)\s.*', line):
            continue  # directives belong before the first document marker
        if not seen_content and re.fullmatch(r'---\s*(#.*)?', line):
            seen_content = True
            continue
        seen_content = True
        if not seen_kafka:
            if KAFBAT_YML_KAFKA.fullmatch(line):
                seen_kafka = True
            else:
                offending.append(str(number))  # anything before kafka:, indented or not, opens another node
            continue
        if not line.startswith((' ', '\t')) or re.match(r'\s*(---|\.\.\.)(\s|$)', line):
            offending.append(str(number))
    if offending:
        raise Preflight('kafbat.yml may define the kafka: section only (clusters); other top-level content on line(s) '
                        + ', '.join(offending[:5]))
    if not seen_kafka:
        raise Preflight('kafbat.yml may define the kafka: section only (clusters); it has no kafka: section')


def validate(root, mode, config):
    env = root / '.env'
    if stat.S_IMODE(env.stat().st_mode) & 0o077:
        raise ValueError('Protect .env with chmod 600 before activation')
    if mode == 'identity':
        validate_identity(root, config)
        return
    services = config['services']
    ui = services['kafka-ui']['environment']
    location = ui.get('SPRING_CONFIG_ADDITIONAL_LOCATION', '')
    if 'file:/etc/krate/auth/' + mode not in location.split(','):
        raise ValueError('Rendered authentication mode differs from .env; clear conflicting shell environment variables')
    if not ui.get('SPRING_SECURITY_USER_NAME'):
        raise ValueError('Set KAFKA_UI_USER')
    password = ui.get('SPRING_SECURITY_USER_PASSWORD', '')
    if len(password) < 16 or password in ('changeme', 'REPLACE_ME'):
        raise ValueError('Set KAFKA_UI_PASSWORD to a unique password of at least 16 characters')
    for filename in ('server.crt', 'server.key'):
        if not (root / 'certs' / filename).is_file():
            raise ValueError('Provision certs/server.crt and certs/server.key first')
    if stat.S_IMODE((root / 'certs/server.key').stat().st_mode) & 0o077:
        raise ValueError('Protect TLS private key with chmod 600')
    cert = root / 'certs/server.crt'
    subprocess.run(['openssl', 'x509', '-in', str(cert), '-checkend', '86400', '-noout'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cert_pub = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'])
    key_pub = subprocess.check_output(['openssl', 'pkey', '-in', str(root / 'certs/server.key'), '-pubout', '-passin', 'pass:'],
                                     stderr=subprocess.DEVNULL)
    if cert_pub != key_pub:
        raise ValueError('TLS certificate and private key do not match')
    if mode == 'local.yml':
        if not (root / 'auth/ui/local.yml').is_file():
            raise ValueError('Missing shared-login configuration')
        return
    # runtime.yml: Kafbat signs users in through the Keycloak realm only.
    site = identity.read_env(root / '.env')
    validate_names(site)
    try:
        origin = identity.public_origin(site.get('KEYCLOAK_PUBLIC_URL'))
    except ValueError as exc:
        raise Preflight(str(exc)) from None
    secrets = identity_secrets(site)
    validate_kafbat_yml(root)
    validate_runtime(root, site, origin)
    # The realm file is the local plan written by `krate identity up`; identity providers are
    # applied to the running realm separately, so their absence here is expected.
    validate_realm(root, origin, secrets)
    # Ping mode: the broker plan exists, so the secret it needs, its endpoints, its group
    # mappers and the trust material Keycloak reads at start are checked here too.
    if (root / identity.BROKER_PLAN).is_file():
        validate_broker(root, site, origin, secrets)
    validate_ui_mount(root, services['kafka-ui'])
    host = urlsplit(origin).hostname or ''
    if not host:
        raise Preflight('KEYCLOAK_PUBLIC_URL has no hostname')
    # openssl exits 1 on a mismatch (3.x), so the status is read, not raised. Browsers accept an
    # IP-literal host only through an iPAddress SAN: -checkhost would also match DNS:<ip>.
    try:
        ipaddress.ip_address(host)
        check = '-checkip'
    except ValueError:
        check = '-checkhost'
    match = subprocess.run(['openssl', 'x509', '-in', str(cert), check, host, '-noout'],
                           text=True, capture_output=True, stdin=subprocess.DEVNULL)
    if match.returncode or 'does match certificate' not in match.stdout:
        raise Preflight(f'certs/server.crt does not cover the public hostname {host} (KEYCLOAK_PUBLIC_URL);'
                        ' run krate gen-cert (it covers that name, the host FQDN and localhost), then this command again'
                        ' (krate start or krate auth apply recreates the proxy with the new certificate)')
    kc = services['keycloak']['environment']
    if kc.get('KC_HOSTNAME') != origin + '/identity':
        raise Preflight('Rendered KC_HOSTNAME differs from KEYCLOAK_PUBLIC_URL in .env; clear conflicting shell environment variables')
    # A runtime.yml `up` renders the sso profile, so the database TLS contract applies here too.
    if kc.get('KC_DB_TLS_MODE') != 'verify-server':
        raise Preflight('keycloak must render KC_DB_TLS_MODE=verify-server')
    validate_networks(config)
    validate_db_tls(root)
    # Kafbat resolves ${KEYCLOAK_KAFBAT_CLIENT_SECRET} from its environment; both sides must carry .env's value.
    expected = secrets['KEYCLOAK_KAFBAT_CLIENT_SECRET']
    if ui.get('KEYCLOAK_KAFBAT_CLIENT_SECRET') != expected or kc.get('KEYCLOAK_KAFBAT_CLIENT_SECRET') != expected:
        raise Preflight('Rendered KEYCLOAK_KAFBAT_CLIENT_SECRET differs from .env; clear conflicting shell environment variables')


def secure(value):
    return len(value) >= 16 and value not in INSECURE


def ping_secret_shape(value):
    """The PingFederate-issued secret as the CLI stores it: 16+ printable ASCII characters, none of the
    characters .env quoting, Compose interpolation ($) or the shell would alter (same rule as `krate`)."""
    return len(value) >= 16 and all('!' <= c <= '~' for c in value) and not any(c in '\\$"\'`' for c in value)


def identity_secrets(env):
    """Secret values that identity services depend on; refuses placeholders and reuse."""
    secrets = {}
    for key in IDENTITY_SECRETS + OPTIONAL_SECRETS:
        value = env.get(key, '')
        if key in OPTIONAL_SECRETS and value in ('', 'REPLACE_ME'):
            continue
        if not secure(value):
            raise Preflight(f'Set {key} to a unique secret of at least 16 characters (changeme and REPLACE_ME are refused): '
                            f'krate identity rotate {key}, or krate config set {key}=... before the first start')
        if key == identity.BROKER_SECRET_KEY and not ping_secret_shape(value):
            raise Preflight(f'{key} must be at least 16 printable ASCII characters without spaces, quotes, backslash, backtick or $'
                            f' (as issued by PingFederate); set it with: krate identity rotate {key} --value')
        secrets[key] = value
    if len(set(secrets.values())) != len(secrets):
        raise Preflight('Identity secrets must all be different from each other')
    if env.get('KAFKA_UI_PASSWORD', '') in secrets.values():
        raise Preflight('KAFKA_UI_PASSWORD must differ from the identity secrets')
    return secrets


def validate_names(env):
    """KEYCLOAK_ADMIN_USER and the group names must be usable by kcadm and the realm plan."""
    try:
        identity.admin_user(env)
        identity.group_names(env)
    except ValueError as exc:  # identity's messages name the key, never the value
        raise Preflight(str(exc)) from None


def openssl(*args):
    return subprocess.run(['openssl', *args], stdin=subprocess.DEVNULL, capture_output=True, text=True)


def validate_db_tls(root):
    tls = root / TLS_DIR
    missing = [name for name in identity.TLS_FILES if not (tls / name).is_file()]
    if missing:
        raise Preflight(f'Missing database TLS files in {TLS_DIR}: ' + ', '.join(missing)
                        + '; run krate identity up on a pristine site or restore the directory from a backup')
    for name in ('ca.key', 'server.key'):
        if stat.S_IMODE((tls / name).stat().st_mode) & 0o077:
            raise Preflight(f'Protect {TLS_DIR}/{name} with chmod 600')
    if (tls / 'pg_hba.conf').read_text() != identity.PG_HBA:
        raise Preflight(f'{TLS_DIR}/pg_hba.conf differs from the generated policy; run krate identity up to restore it')
    ca = str(tls / 'ca.crt')
    if openssl('x509', '-in', ca, '-checkend', '86400', '-noout').returncode:
        raise Preflight(f'{TLS_DIR}/ca.crt is unreadable or expires within a day; run krate identity renew-db-tls (it renews the CA too)')
    if openssl('x509', '-in', ca, '-checkend', str(RENEW_WARNING), '-noout').returncode:
        print(f'warning: {TLS_DIR}/ca.crt expires within {RENEW_WARNING // 86400} days'
              f' ({openssl("x509", "-in", ca, "-noout", "-enddate").stdout.strip()}); run krate identity renew-db-tls', file=sys.stderr)
    server = str(tls / 'server.crt')
    if openssl('x509', '-in', server, '-checkend', '86400', '-noout').returncode:
        raise Preflight(f'{TLS_DIR}/server.crt is unreadable or expires within a day; run krate identity renew-db-tls')
    if openssl('x509', '-in', server, '-checkend', str(RENEW_WARNING), '-noout').returncode:
        print(f'warning: {TLS_DIR}/server.crt expires within {RENEW_WARNING // 86400} days'
              f' ({openssl("x509", "-in", server, "-noout", "-enddate").stdout.strip()}); run krate identity renew-db-tls',
              file=sys.stderr)
    names = openssl('x509', '-in', server, '-noout', '-ext', 'subjectAltName').stdout
    entries = {entry.strip() for line in names.splitlines() for entry in line.split(',')}
    if 'DNS:' + identity.DB_HOST not in entries:
        raise Preflight(f'{TLS_DIR}/server.crt must carry subjectAltName DNS:{identity.DB_HOST}')
    if openssl('verify', '-CAfile', str(tls / 'ca.crt'), server).returncode:
        raise Preflight(f'{TLS_DIR}/server.crt is not signed by {TLS_DIR}/ca.crt')
    cert_pub = openssl('x509', '-in', server, '-pubkey', '-noout').stdout
    key_pub = openssl('pkey', '-in', str(tls / 'server.key'), '-pubout', '-passin', 'pass:').stdout
    if not cert_pub or cert_pub != key_pub:
        raise Preflight(f'{TLS_DIR}/server.crt and server.key do not match')


def service_networks(service):
    """Name -> attachment settings of a rendered service; Compose renders a mapping, a list is tolerated."""
    networks = service.get('networks') or {}
    if isinstance(networks, list):
        return {name: {} for name in networks}
    return {name: (settings or {}) for name, settings in networks.items()}


def validate_networks(config):
    """The identity network: internal, one subnet, the database on it alone, the proxy at the trusted address."""
    networks = config.get('networks') or {}
    identity_network = networks.get(IDENTITY_NETWORK)
    if not isinstance(identity_network, dict):
        raise Preflight(f'the Compose file must define the {IDENTITY_NETWORK} network')
    if identity_network.get('internal') is not True:
        raise Preflight(f'network {IDENTITY_NETWORK} must be internal: true')
    entries = [entry for entry in (identity_network.get('ipam') or {}).get('config') or []
               if isinstance(entry, dict) and entry.get('subnet')]
    if len(entries) != 1:
        raise Preflight(f'network {IDENTITY_NETWORK} must have exactly one ipam subnet (KRATE_IDENTITY_SUBNET)')
    try:
        subnet = ipaddress.ip_network(entries[0]['subnet'], strict=True)
    except ValueError:
        raise Preflight('KRATE_IDENTITY_SUBNET is not a valid CIDR network') from None
    if not entries[0].get('ip_range'):
        raise Preflight(f'network {IDENTITY_NETWORK} must set ipam ip_range (KRATE_IDENTITY_IP_RANGE): the dynamic pool that excludes the proxy address')
    try:
        pool = ipaddress.ip_network(entries[0]['ip_range'], strict=True)
    except ValueError:
        raise Preflight('KRATE_IDENTITY_IP_RANGE is not a valid CIDR network') from None
    if pool.version != subnet.version or not pool.subnet_of(subnet):  # pyright: ignore[reportArgumentType]  # same family checked first
        raise Preflight('KRATE_IDENTITY_IP_RANGE must lie inside KRATE_IDENTITY_SUBNET')
    gateway = entries[0].get('gateway') or str(next(subnet.hosts()))
    services = config['services']
    members = {name for name, service in services.items() if IDENTITY_NETWORK in service_networks(service)}
    if members != IDENTITY_MEMBERS:
        raise Preflight(f'the {IDENTITY_NETWORK} network must carry exactly {sorted(IDENTITY_MEMBERS)}; rendered: {sorted(members)}')
    egress = {name for name, service in services.items() if EGRESS_NETWORK in service_networks(service)}
    if egress != {'keycloak'}:
        raise Preflight(f'only keycloak may be on the {EGRESS_NETWORK} network; rendered: {sorted(egress)}')
    if set(service_networks(services['keycloak-db'])) != {IDENTITY_NETWORK}:
        raise Preflight(f'keycloak-db must be attached to the {IDENTITY_NETWORK} network only')
    keycloak_networks = service_networks(services['keycloak'])
    if CLUSTER_NETWORK in keycloak_networks or IDENTITY_NETWORK not in keycloak_networks:
        raise Preflight(f'keycloak must be on the {IDENTITY_NETWORK} network and not on {CLUSTER_NETWORK}')
    proxy_networks = service_networks(services['proxy'])
    address = proxy_networks.get(IDENTITY_NETWORK, {}).get('ipv4_address')
    if not address:
        raise Preflight(f'proxy must have a fixed ipv4_address on the {IDENTITY_NETWORK} network (KRATE_IDENTITY_PROXY_IP)')
    trusted = services['keycloak']['environment'].get('KC_PROXY_TRUSTED_ADDRESSES')
    if trusted != address:
        raise Preflight('KC_PROXY_TRUSTED_ADDRESSES must equal the proxy address on the identity network;'
                        ' clear conflicting shell environment variables')
    try:
        proxy_ip = ipaddress.ip_address(address)
    except ValueError:
        raise Preflight('KRATE_IDENTITY_PROXY_IP is not a valid IP address') from None
    if proxy_ip not in subnet or proxy_ip in (subnet.network_address, subnet.broadcast_address):
        raise Preflight('KRATE_IDENTITY_PROXY_IP must be a host address inside KRATE_IDENTITY_SUBNET')
    if proxy_ip in pool:
        raise Preflight('KRATE_IDENTITY_PROXY_IP must lie outside KRATE_IDENTITY_IP_RANGE, or another container can take the trusted address')
    if str(proxy_ip) == gateway:
        raise Preflight('KRATE_IDENTITY_PROXY_IP must not be the network gateway address')



def validate_ui_mount(root, service):
    """kafka-ui must read runtime.yml from this installation's auth/ui directory."""
    if not (root / RUNTIME_FILE).is_file():
        raise Preflight(f'Missing {RUNTIME_FILE}; run krate auth configure')
    expected = (root / 'auth/ui').resolve()
    for mount in service.get('volumes') or []:
        if not isinstance(mount, dict) or mount.get('target') != UI_AUTH_DIR:
            continue
        if mount.get('type') == 'bind' and Path(mount.get('source', '')).resolve() == expected and mount.get('read_only'):
            return
    raise Preflight(f'kafka-ui must bind-mount auth/ui read-only at {UI_AUTH_DIR} (it carries runtime.yml)')


def validate_runtime(root, env, origin):
    """auth/ui/runtime.yml: the Keycloak client, the two group-mapped roles and nothing that widens access."""
    path = root / RUNTIME_FILE
    if not path.is_file():
        raise Preflight(f'Missing {RUNTIME_FILE}; run krate auth configure')
    try:
        runtime = json.loads(path.read_text())
        oauth = runtime['auth']['oauth2']
        client = oauth['client'][identity.UI_REGISTRATION]
        roles = {role['name']: role for role in runtime['rbac']['roles']}
    except (ValueError, KeyError, TypeError):
        raise Preflight(f'{RUNTIME_FILE} is not a Krate Kafbat plan; regenerate it with krate auth configure --force') from None
    regenerate = '; regenerate it with krate auth configure --force'
    for key in ('allow-shared-login', 'shared-role'):
        if key in oauth:
            raise Preflight(f'{RUNTIME_FILE} must not carry {key}: Kafbat has no shared form login in Keycloak mode' + regenerate)
    if runtime.get('auth', {}).get('type') != 'OAUTH2' or oauth.get('require-mapped-role') is not True:
        raise Preflight(f'{RUNTIME_FILE} must set auth.type OAUTH2 with require-mapped-role true' + regenerate)
    cookie = runtime.get('server', {}).get('reactive', {}).get('session', {}).get('cookie', {})
    if cookie.get('name') != identity.UI_SESSION_COOKIE:
        raise Preflight(f'{RUNTIME_FILE} must name the session cookie {identity.UI_SESSION_COOKIE} (back-channel logout matches on it)'
                        + regenerate)
    if client.get('issuer-uri') != origin + '/identity/realms/' + identity.REALM \
            or client.get('redirect-uri') != origin + '/login/oauth2/code/' + identity.UI_REGISTRATION:
        raise Preflight(f'{RUNTIME_FILE}: Kafbat issuer/callback does not match KEYCLOAK_PUBLIC_URL' + regenerate)
    if client.get('client-id') != identity.UI_CLIENT or client.get('user-name-attribute') != 'sub' \
            or 'openid' not in (client.get('scope') or []):
        raise Preflight(f'{RUNTIME_FILE}: the Keycloak client must be {identity.UI_CLIENT} with user-name-attribute sub and the openid scope'
                        + regenerate)
    if set(roles) != {'viewer', 'administrator'} or 'defaultRole' in runtime['rbac']:
        raise Preflight(f'{RUNTIME_FILE} must define exactly the roles viewer and administrator and no defaultRole' + regenerate)
    viewer_group, admin_group = identity.group_names(env)
    for name, group in (('viewer', viewer_group), ('administrator', admin_group)):
        if roles[name].get('subjects') != [{'provider': 'oauth', 'type': 'role', 'value': group, 'regex': False}]:
            raise Preflight(f'{RUNTIME_FILE}: role {name} must have the realm group from .env as its only subject' + regenerate)
    viewer = {permission.get('resource'): permission for permission in roles['viewer'].get('permissions', [])}
    if 'ksql' in viewer:
        raise Preflight(f'{RUNTIME_FILE}: the viewer role must not grant ksql' + regenerate)
    topic_actions = viewer.get('topic', {}).get('actions', [])
    if 'messages_read' in topic_actions and not identity.env_flag(env, identity.VIEWER_MESSAGES_KEY):
        raise Preflight(f'{RUNTIME_FILE}: the viewer role reads message payloads but {identity.VIEWER_MESSAGES_KEY} is not true in .env'
                        + regenerate)
    # The whole document must be what the planner produces for this .env and cluster list:
    # an extra key (management exposure, dynamic config, a third client) is a change too.
    try:
        expected = identity.runtime(identity.runtime_settings(env, roles['viewer'].get('clusters')))
    except ValueError as exc:
        raise Preflight(str(exc)) from None
    if runtime != expected:
        extra = sorted(set(runtime) - set(expected))
        raise Preflight(f'{RUNTIME_FILE} differs from the Krate plan for this .env'
                        + (f' (unexpected top-level keys: {extra})' if extra else '') + regenerate)


def validate_realm(root, origin, secrets):
    path = root / REALM_FILE
    if not path.is_file():
        raise Preflight(f'Missing {REALM_FILE}; run krate identity up to plan the realm')
    text = path.read_text()
    try:
        realm = json.loads(text)
    except ValueError:
        raise Preflight(f'{REALM_FILE} is not valid JSON') from None
    if not isinstance(realm, dict) or realm.get('realm') != identity.REALM:
        raise Preflight(f'{REALM_FILE} must describe realm {identity.REALM}')
    if realm.get('identityProviders'):
        raise Preflight(f'{REALM_FILE} must not define identityProviders: the realm plan is local-only; PingFederate is applied'
                        f' from {identity.BROKER_PLAN} by krate auth apply')
    clients = {client.get('clientId'): client for client in realm.get('clients', []) if isinstance(client, dict)}
    for client_id, placeholder in ((identity.UI_CLIENT, identity.UI_SECRET), (identity.CLI_CLIENT, identity.CLI_SECRET)):
        if client_id not in clients:
            raise Preflight(f'{REALM_FILE} must define client {client_id}')
        if clients[client_id].get('secret') != placeholder:
            raise Preflight(f'{REALM_FILE}: client {client_id} secret must be the {placeholder} placeholder')
    if any(value in text for value in secrets.values()):
        raise Preflight(f'{REALM_FILE} embeds a secret value; regenerate it with krate identity up')
    ui = clients[identity.UI_CLIENT]
    if ui.get('webOrigins') != [origin] or ui.get('redirectUris') != [origin + '/login/oauth2/code/keycloak']:
        raise Preflight(f'{REALM_FILE}: krate-ui redirect URI and web origin must match KEYCLOAK_PUBLIC_URL; regenerate the plan')
    if ui.get('attributes') != identity.ui_client_attributes(origin):
        raise Preflight(f'{REALM_FILE}: krate-ui attributes must be PKCE S256, the exact post-logout URIs and OIDC back-channel logout'
                        ' to Kafbat; regenerate the plan with krate identity up')


def authority(url):
    """host[:port] of an https URL, lower-case, the default port omitted: what a certificate must cover."""
    parts = urlsplit(url)
    host = (parts.hostname or '').lower()
    return f'{host}:{parts.port}' if parts.port and parts.port != 443 else host


def validate_truststores(root, required):
    """auth/keycloak/truststores as Keycloak loads it: directories 755 (traversable by Keycloak's user, writable by
    the owner only), every file a 644 PEM or PKCS12 (readable, writable by the owner only: another local user must
    not be able to add or change trust material); with `required`, at least one such file must exist."""
    trust = root / identity.TRUSTSTORES_DIR
    if trust.is_dir():
        for directory in [trust] + [path for path in trust.rglob('*') if path.is_dir()]:
            mode = stat.S_IMODE(directory.stat().st_mode)
            if mode & 0o055 != 0o055 or mode & 0o022:
                label = identity.TRUSTSTORES_DIR if directory == trust else f'{identity.TRUSTSTORES_DIR}/{directory.relative_to(trust)}'
                raise Preflight(f'{label} must have mode 755 (Keycloak lists it as its own user; group and others must not write to it): chmod 755')
    elif required:
        raise Preflight(f'{identity.TRUSTSTORES_DIR} must exist with mode 755 (run krate identity up, or chmod 755 it)')
    files = identity.truststore_files(trust)
    for path in files:
        name = path.relative_to(trust)
        if path.suffix not in identity.TRUSTSTORE_SUFFIXES:
            raise Preflight(f'{identity.TRUSTSTORES_DIR}/{name} is not a truststore file; Keycloak loads only PEM (.crt, .pem) and PKCS12'
                            ' (.p12, .pfx, .pkcs12) files from that directory: remove it')
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o044 != 0o044 or mode & 0o022:
            raise Preflight(f'{identity.TRUSTSTORES_DIR}/{name} must be world-readable and writable by its owner only (chmod 644):'
                            ' Keycloak reads it as its own user; group and others must not change it')
    if required and not files:
        raise Preflight(f'{identity.TRUSTSTORES_DIR} holds no truststore file (.crt, .pem, .p12, .pfx, .pkcs12): place the CA certificate'
                        " that issued the identity provider's TLS certificate there (mode 644); Keycloak loads it at start"
                        ' (a publicly trusted certificate: set "idp_truststore": "system" in the site file)')


def validate_broker(root, env, origin, secrets, require_secret=True):
    """Ping mode (the broker plan exists): the secret, https endpoints, the two group mappers and the trust material.

    `krate identity up` applies the same plan, so identity mode runs this too (require_secret=False: the
    secret may still be unset there, in which case identity up leaves the provider alone).

    runtime.yml needs no separate hint check here: validate_runtime already refuses any document
    that differs from the plan, and the plan never carries kc_idp_hint.
    """
    plan_file = root / identity.BROKER_PLAN
    try:
        plan = identity.broker_plan(plan_file)
    except ValueError as exc:  # broker_plan's messages name keys and aliases, never a value
        raise Preflight(f'{exc}; regenerate it: remove auth/ui/runtime.yml and {identity.BROKER_PLAN}, then krate auth configure <site.json>') from None
    if require_secret and identity.BROKER_SECRET_KEY not in secrets:
        raise Preflight(f'{identity.BROKER_PLAN} exists but {identity.BROKER_SECRET_KEY} is not set in .env;'
                        f' krate auth apply asks for it on a terminal, otherwise: krate identity rotate {identity.BROKER_SECRET_KEY} --value (reads it from stdin)')
    text = plan_file.read_text()
    if any(value in text for value in secrets.values()):
        raise Preflight(f'{identity.BROKER_PLAN} embeds a secret value; it must carry the {identity.BROKER_SECRET} placeholder only')
    viewer_group, admin_group = identity.group_names(env)
    groups = sorted(mapper['config'].get('group') for mapper in plan['identityProviderMappers'])
    if groups != sorted(['/' + viewer_group, '/' + admin_group]):
        raise Preflight(f'{identity.BROKER_PLAN}: the two mappers must target the realm groups /{viewer_group} and /{admin_group}'
                        ' (KEYCLOAK_VIEWER_GROUP, KEYCLOAK_ADMIN_GROUP); regenerate the plan with krate auth configure <site.json>')
    for mapper in plan['identityProviderMappers']:
        if mapper.get('identityProviderMapper') != 'oidc-advanced-group-idp-mapper' or mapper['config'].get('syncMode') != 'FORCE':
            raise Preflight(f'{identity.BROKER_PLAN}: mapper {mapper.get("name")!r} must be an oidc-advanced-group-idp-mapper with syncMode FORCE'
                            ' (group removal at the identity provider takes effect at the next sign-in)')
    # Keycloak checks the identity provider's TLS against auth/keycloak/truststores (loaded at
    # start) and the JVM default truststore. A provider on another host:port than the public one
    # needs a CA file there unless the site declared a publicly trusted chain (truststore: system).
    config = plan['identityProviders'][0]['config']
    elsewhere = {authority(config[key]) for key in identity.BROKER_ENDPOINTS} - {authority(origin)}
    mode = plan.get('truststore', 'local')
    validate_truststores(root, required=bool(elsewhere) and mode == 'local')
    if elsewhere and mode == 'system':
        print(f"note: {identity.BROKER_PLAN} declares truststore \"system\": the identity provider's TLS chain is checked against the"
              f' JVM default truststore (and any file in {identity.TRUSTSTORES_DIR}); no CA file is required', file=sys.stderr)


def validate_identity(root, config):
    """Identity foundation checks: .env values, rendered services, TLS material and realm plan."""
    env = identity.read_env(root / '.env')
    validate_names(env)
    try:
        origin = identity.public_origin(env.get('KEYCLOAK_PUBLIC_URL'))
    except ValueError as exc:
        raise Preflight(str(exc)) from None
    services = config['services']
    keycloak = services['keycloak']['environment']
    database = services['keycloak-db']
    if keycloak.get('KC_HOSTNAME') != env['KEYCLOAK_PUBLIC_URL']:
        raise Preflight('Rendered KC_HOSTNAME differs from KEYCLOAK_PUBLIC_URL in .env; clear conflicting shell environment variables')
    secrets = identity_secrets(env)
    rendered = {
        'KEYCLOAK_DB_PASSWORD': (keycloak.get('KC_DB_PASSWORD'), database['environment'].get('POSTGRES_PASSWORD')),
        'KEYCLOAK_KAFBAT_CLIENT_SECRET': (keycloak.get('KEYCLOAK_KAFBAT_CLIENT_SECRET'),
                                          services['kafka-ui']['environment'].get('KEYCLOAK_KAFBAT_CLIENT_SECRET')),
        'KEYCLOAK_CLI_CLIENT_SECRET': (keycloak.get('KEYCLOAK_CLI_CLIENT_SECRET'),),
    }
    for key, values in rendered.items():
        if any(value != secrets[key] for value in values):
            raise Preflight(f'Rendered {key} differs from .env; clear conflicting shell environment variables')
    if keycloak.get('KC_DB_TLS_MODE') != 'verify-server':
        raise Preflight('keycloak must render KC_DB_TLS_MODE=verify-server')
    if not keycloak.get('KC_DB_TLS_TRUST_STORE_FILE'):
        raise Preflight('keycloak must render KC_DB_TLS_TRUST_STORE_FILE')
    for name in ('keycloak', 'keycloak-db'):
        if services[name].get('ports'):
            raise Preflight(f'{name} must not publish host ports')
    validate_networks(config)
    validate_db_tls(root)
    validate_realm(root, origin, secrets)
    # The broker plan is applied by `krate identity up` too (when its secret is set), so its shape,
    # endpoints, mappers and trust material are checked in identity mode as well.
    if (root / identity.BROKER_PLAN).is_file():
        validate_broker(root, env, origin, secrets, require_secret=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--mode', choices=['local.yml', 'runtime.yml', 'identity'], required=True)
    args = parser.parse_args()
    try:
        validate(args.directory, args.mode, json.load(sys.stdin))
    except Preflight as exc:
        label = 'Identity' if args.mode == 'identity' else 'Authentication'
        print(f'{label} preflight failed: {exc}', file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
        # Never print exception payloads: rendered configuration contains secrets.
        if args.mode == 'identity':
            print('Identity preflight failed: check protected .env, the rendered keycloak/keycloak-db/proxy services '
                  'and identity network, auth/keycloak/db-tls and auth/keycloak/krate-realm.json.', file=sys.stderr)
            return 1
        print('Authentication preflight failed: check protected .env, unique secrets (16+ characters), generated auth files '
              '(auth/ui/runtime.yml, auth/keycloak/krate-realm.json), the rendered kafka-ui/keycloak services, HTTPS URL and '
              'matching unexpired TLS certificate.', file=sys.stderr)
        return 1
    if args.mode == 'identity':
        print('Identity preflight passed; no services changed.')
        return 0
    print('Authentication preflight passed; no services changed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
