#!/usr/bin/env python3
"""Reachability watcher for enterprise identity provider (PingFederate) fallback and recovery.

Monitors enterprise IdP health endpoints, manages Keycloak identity provider enabled status,
and handles automatic fallback to local credentials and automatic recovery.
Stdlib Python only.
"""
import datetime
import json
import os
from pathlib import Path
import signal
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_INTERVAL_SECONDS = 10
DEFAULT_TIMEOUT_SECONDS = 5
DEFAULT_FAILURES_TO_FALLBACK = 2
DEFAULT_SUCCESSES_TO_RECOVER = 2
DEFAULT_DWELL_SECONDS = 30
DEFAULT_KEYCLOAK_INTERNAL_URL = 'http://keycloak:8080/identity'
DEFAULT_REALM = 'krate'
DEFAULT_IDP_ALIAS = 'pingfederate'
WATCH_CLIENT_ID = 'krate-idp-watch'


def load_plan(plan_path):
    """Load and validate identity provider plan."""
    path = Path(plan_path)
    if not path.is_file():
        raise FileNotFoundError(f'Plan file not found: {plan_path}')
    data = json.loads(path.read_text(encoding='utf-8'))
    providers = data.get('identityProviders', [])
    if not providers:
        raise ValueError(f'No identityProviders in plan: {plan_path}')
    return data


def extract_authorities(plan):
    """Extract allowlisted host:port authorities from the plan's endpoints."""
    provider = plan['identityProviders'][0]
    config = provider.get('config', {})
    endpoints = [
        config.get('issuer'),
        config.get('authorizationUrl'),
        config.get('tokenUrl'),
        config.get('userInfoUrl'),
        config.get('jwksUrl'),
    ]
    authorities = set()
    for ep in endpoints:
        if not ep:
            continue
        parsed = urllib.parse.urlsplit(ep)
        if parsed.netloc:
            authorities.add(parsed.netloc.lower())
    return authorities


def check_target_allowed(url, allowed_authorities):
    """Verify target URL authority is in the allowlist."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.netloc:
        raise ValueError(f'Invalid target URL: {url}')
    if parsed.netloc.lower() not in allowed_authorities:
        raise PermissionError(f'Target {parsed.netloc} not in allowlisted authorities: {sorted(allowed_authorities)}')


def build_ssl_context(truststore_dir):
    """Build SSLContext loading PEM and CRT certificates from truststores directory."""
    ctx = ssl.create_default_context()
    path = Path(truststore_dir)
    certs_loaded = 0
    if path.is_dir():
        for cert_file in sorted(path.rglob('*')):
            if cert_file.is_file() and cert_file.suffix.lower() in ('.pem', '.crt'):
                try:
                    ctx.load_verify_locations(cafile=str(cert_file))
                    certs_loaded += 1
                except Exception as exc:
                    sys.stderr.write(f'Warning: could not load cert {cert_file}: {exc}\n')
    return ctx, certs_loaded


class AllowlistRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Enforce destination allowlist on every redirect hop."""
    def __init__(self, allowed_authorities):
        super().__init__()
        self.allowed_authorities = allowed_authorities

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_target_allowed(newurl, self.allowed_authorities)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def probe_http(url, ssl_context, timeout, method='GET', allowed_authorities=None, post_data=None):
    """Execute single HTTP probe with timeout and SSL context.
    
    Returns (status_code, body_bytes, error_message).
    """
    if allowed_authorities:
        check_target_allowed(url, allowed_authorities)

    req = urllib.request.Request(url, method=method)
    req.add_header('Cache-Control', 'no-cache')
    req.add_header('User-Agent', 'krate-idp-watch/1.0')
    if post_data is not None:
        if isinstance(post_data, str):
            post_data = post_data.encode('utf-8')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.data = post_data

    handlers = [urllib.request.HTTPSHandler(context=ssl_context)]
    if allowed_authorities:
        handlers.append(AllowlistRedirectHandler(allowed_authorities))
    opener = urllib.request.build_opener(*handlers)

    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, body, None
    except urllib.error.HTTPError as exc:
        body = b''
        try:
            if exc.fp:
                body = exc.read()
        except Exception:
            pass
        finally:
            try:
                exc.close()
            except Exception:
                pass
        return exc.code, body, None
    except Exception as exc:
        return 0, b'', str(exc)


def probe_idp(plan, ssl_context, timeout, allowed_authorities):
    """Run the 3 probe sequence against the enterprise IdP.
    
    Returns (ok: bool, error_reason: str or None).
    """
    start_time = time.time()

    def remaining_timeout():
        rem = timeout - (time.time() - start_time)
        if rem <= 0:
            raise TimeoutError('Overall probe deadline exceeded')
        return rem

    try:
        provider = plan['identityProviders'][0]
        config = provider.get('config', {})
        issuer = (config.get('issuer') or '').rstrip('/')
        jwks_url = config.get('jwksUrl')
        token_url = config.get('tokenUrl')
        user_info_url = config.get('userInfoUrl')

        if not issuer:
            return False, 'No issuer configured in plan'

        # Probe 1: OIDC Discovery
        # If issuer uses localhost/127.0.0.1, check backend endpoints for a reachable internal authority
        disc_url = f'{issuer}/.well-known/openid-configuration'
        issuer_parts = urllib.parse.urlsplit(issuer)
        if issuer_parts.hostname in ('localhost', '127.0.0.1'):
            # Check backend endpoints for non-loopback authority
            backend_authority = None
            for backend_url in [token_url, jwks_url, user_info_url]:
                if backend_url:
                    backend_parts = urllib.parse.urlsplit(backend_url)
                    if backend_parts.hostname and backend_parts.hostname not in ('localhost', '127.0.0.1'):
                        backend_authority = backend_parts.netloc
                        break

            if backend_authority:
                # Construct discovery URL pointing to internal authority
                disc_url = urllib.parse.urlunsplit((
                    issuer_parts.scheme,
                    backend_authority,
                    issuer_parts.path.rstrip('/') + '/.well-known/openid-configuration',
                    '',
                    ''
                ))
                # Add backend authority to allowed list so check_target_allowed permits it
                allowed_authorities = allowed_authorities.copy()
                allowed_authorities.add(backend_authority.lower())

        status, body, err = probe_http(disc_url, ssl_context, remaining_timeout(), allowed_authorities=allowed_authorities)
        if err:
            return False, f'Discovery probe failed: {err}'
        if status != 200:
            return False, f'Discovery probe returned HTTP {status}'
        try:
            disc_json = json.loads(body.decode('utf-8'))
            reported_issuer = (disc_json.get('issuer') or '').rstrip('/')
            if reported_issuer != issuer:
                return False, f'Discovery issuer mismatch: expected {issuer}, got {reported_issuer}'
        except Exception as exc:
            return False, f'Discovery JSON parse error: {exc}'

        # Probe 2: JWKS Keys
        if jwks_url:
            status, body, err = probe_http(jwks_url, ssl_context, remaining_timeout(), allowed_authorities=allowed_authorities)
            if err:
                return False, f'JWKS probe failed: {err}'
            if status != 200:
                return False, f'JWKS probe returned HTTP {status}'
            try:
                jwks_json = json.loads(body.decode('utf-8'))
                keys = jwks_json.get('keys')
                if not isinstance(keys, list) or len(keys) == 0:
                    return False, 'JWKS keys array is missing or empty'
            except Exception as exc:
                return False, f'JWKS JSON parse error: {exc}'

        # Probe 3: Token / UserInfo reachability (any HTTP status < 500 confirms application reachability)
        if token_url:
            status, _, err = probe_http(token_url, ssl_context, remaining_timeout(), method='POST',
                                        allowed_authorities=allowed_authorities, post_data='grant_type=invalid_probe')
            if err:
                return False, f'Token endpoint reachability probe failed: {err}'
            if status >= 500:
                return False, f'Token endpoint returned server error HTTP {status}'

        if user_info_url:
            status, _, err = probe_http(user_info_url, ssl_context, remaining_timeout(), method='GET',
                                        allowed_authorities=allowed_authorities)
            if err:
                return False, f'UserInfo reachability probe failed: {err}'
            if status >= 500:
                return False, f'UserInfo returned server error HTTP {status}'

        return True, None
    except TimeoutError as exc:
        return False, f'Probe deadline exceeded: {exc}'


def acquire_keycloak_token(keycloak_url, realm, client_secret, timeout=5):
    """Acquire admin access token via client_credentials grant for krate-idp-watch."""
    token_url = f"{keycloak_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_id': WATCH_CLIENT_ID,
        'client_secret': client_secret,
    }).encode('utf-8')
    req = urllib.request.Request(token_url, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req.add_header('User-Agent', 'krate-idp-watch/1.0')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode('utf-8'))
            return payload.get('access_token')
    except Exception as exc:
        raise RuntimeError(f'Failed to acquire Keycloak token: {exc}') from exc


def get_live_provider_state(keycloak_url, realm, token, alias=DEFAULT_IDP_ALIAS, timeout=5):
    """Get current enabled state of the identity provider from Keycloak Admin API."""
    url = f"{keycloak_url.rstrip('/')}/admin/realms/{realm}/identity-provider/instances/{alias}"
    req = urllib.request.Request(url, method='GET')
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('User-Agent', 'krate-idp-watch/1.0')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get('enabled')
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RuntimeError(f'Failed to get provider state: HTTP {exc.code}') from exc
    except Exception as exc:
        raise RuntimeError(f'Failed to get provider state: {exc}') from exc


def construct_provider_representation(plan, enabled, ping_client_secret):
    """Build complete provider representation with explicit enabled flag and client secret."""
    provider = json.loads(json.dumps(plan['identityProviders'][0]))
    provider['enabled'] = bool(enabled)
    if 'config' not in provider or not isinstance(provider['config'], dict):
        provider['config'] = {}
    provider['config']['clientSecret'] = ping_client_secret
    return provider


def set_live_provider_state(keycloak_url, realm, token, representation, alias=DEFAULT_IDP_ALIAS, timeout=5):
    """Update identity provider representation via Keycloak Admin API PUT."""
    url = f"{keycloak_url.rstrip('/')}/admin/realms/{realm}/identity-provider/instances/{alias}"
    data = json.dumps(representation).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='PUT')
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'krate-idp-watch/1.0')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f'Provider update returned unexpected HTTP {resp.status}')
    except Exception as exc:
        raise RuntimeError(f'Failed to update provider: {exc}') from exc


def touch_heartbeat(state_dir):
    """Touch heartbeat file to satisfy Docker container healthcheck."""
    hb_file = Path(state_dir) / 'heartbeat'
    try:
        hb_file.parent.mkdir(parents=True, exist_ok=True)
        hb_file.touch()
    except Exception as exc:
        sys.stderr.write(f'Warning: failed to touch heartbeat: {exc}\n')


def read_state_file(state_dir):
    """Read state from atomic JSON file."""
    state_file = Path(state_dir) / 'state.json'
    if not state_file.is_file():
        return None
    try:
        return json.loads(state_file.read_text(encoding='utf-8'))
    except Exception:
        return None


def write_state_file(state_dir, state_data):
    """Write state atomically via rename."""
    sdir = Path(state_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    tmp_file = sdir / 'state.json.tmp'
    dest_file = sdir / 'state.json'
    tmp_file.write_text(json.dumps(state_data, indent=2) + '\n', encoding='utf-8')
    os.replace(tmp_file, dest_file)


def log_journal_entry(state_dir, action, outcome, detail=''):
    """Record transition to journal log file and stdout."""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    line = f"{stamp} {action} {outcome} {detail}\n"
    sys.stdout.write(f"[idp-watch] {line}")
    sys.stdout.flush()

    # Append to state directory journal
    try:
        jfile = Path(state_dir) / 'journal.log'
        with open(jfile, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception as exc:
        sys.stderr.write(f"Warning: could not write to state journal: {exc}\n")

    # If host auth journal is mounted or accessible
    for alt_path in ('/var/log/krate/identity-journal.log', '/etc/krate/auth/identity-journal.log'):
        try:
            p = Path(alt_path)
            if p.parent.is_dir():
                with open(p, 'a', encoding='utf-8') as f:
                    f.write(line)
        except Exception:
            pass


class IdpWatcher:
    def __init__(self, plan_path, truststores_dir, state_dir, config):
        self.plan_path = plan_path
        self.truststores_dir = truststores_dir
        self.state_dir = Path(state_dir)
        self.config = config

        self.plan = load_plan(plan_path)
        self.authorities = extract_authorities(self.plan)
        self.ssl_context, self.certs_loaded = build_ssl_context(truststores_dir)

        # Operational parameters
        self.interval = config.get('interval', DEFAULT_INTERVAL_SECONDS)
        self.timeout = config.get('timeout', DEFAULT_TIMEOUT_SECONDS)
        self.failures_to_fallback = config.get('failures_to_fallback', DEFAULT_FAILURES_TO_FALLBACK)
        self.successes_to_recover = config.get('successes_to_recover', DEFAULT_SUCCESSES_TO_RECOVER)
        self.dwell_seconds = config.get('dwell_seconds', DEFAULT_DWELL_SECONDS)
        self.fail_open = config.get('fail_open', True)
        self.enabled = config.get('enabled', True)

        self.keycloak_url = config.get('keycloak_url', DEFAULT_KEYCLOAK_INTERNAL_URL)
        self.realm = config.get('realm', DEFAULT_REALM)
        self.watch_secret = config.get('watch_secret', '')
        self.ping_secret = config.get('ping_secret', '')

        # Internal state
        self.running = True
        self.reconciliation_pending = False
        self.load_or_init_state()

    def is_paused(self):
        """Check if pause flag exists in state volume."""
        pause_file = self.state_dir / 'paused'
        return pause_file.is_file()

    def reconcile_with_keycloak(self):
        """Query Keycloak Admin API to align local state with live provider reality.

        Returns True on success, False on failure.
        """
        if not self.watch_secret:
            return False
        try:
            token = acquire_keycloak_token(self.keycloak_url, self.realm, self.watch_secret, timeout=self.timeout)
            live_enabled = get_live_provider_state(self.keycloak_url, self.realm, token, alias=DEFAULT_IDP_ALIAS, timeout=self.timeout)
            if live_enabled is not None:
                self.provider_enabled = bool(live_enabled)
                self.current_state = 'HEALTHY' if self.provider_enabled else 'FALLBACK'
            return True
        except Exception as exc:
            sys.stderr.write(f"[idp-watch] Note: Keycloak state reconciliation skipped ({exc})\n")
            return False

    def load_or_init_state(self):
        """Restore state from disk or initialize fresh, reconciling with Keycloak ground truth."""
        existing = read_state_file(self.state_dir)
        if existing and isinstance(existing, dict):
            self.current_state = existing.get('state', 'HEALTHY')
            self.provider_enabled = existing.get('enabled', True)
            self.consecutive_failures = existing.get('consecutive_failures', 0)
            self.consecutive_successes = existing.get('consecutive_successes', 0)
            self.last_transition_ts = existing.get('last_transition_ts', 0.0)
            self.last_probe_ts = existing.get('last_probe_ts', 0.0)
            self.last_error = existing.get('last_error')
        else:
            self.current_state = 'HEALTHY'
            self.provider_enabled = True
            self.consecutive_failures = 0
            self.consecutive_successes = 0
            self.last_transition_ts = 0.0
            self.last_probe_ts = 0.0
            self.last_error = None

        self.reconcile_with_keycloak()
        self.persist_state()

    def persist_state(self):
        """Save current state to atomic JSON file."""
        state_data = {
            'state': self.current_state,
            'enabled': self.provider_enabled,
            'consecutive_failures': self.consecutive_failures,
            'consecutive_successes': self.consecutive_successes,
            'last_transition_ts': self.last_transition_ts,
            'last_probe_ts': self.last_probe_ts,
            'last_error': self.last_error,
            'paused': self.is_paused(),
        }
        write_state_file(self.state_dir, state_data)

    def execute_transition(self, target_state, target_enabled, reason):
        """Apply target enabled state to Keycloak provider representation."""
        if not self.watch_secret or not self.ping_secret:
            err = 'Cannot execute transition: KEYCLOAK_IDP_WATCH_CLIENT_SECRET or PING_KEYCLOAK_CLIENT_SECRET not set'
            sys.stderr.write(f"[idp-watch] {err}\n")
            if self.fail_open and target_enabled is False:
                sys.stderr.write("[idp-watch] FAIL_OPEN active: refusing fallback transition without secrets\n")
                return False
            raise RuntimeError(err)

        try:
            token = acquire_keycloak_token(self.keycloak_url, self.realm, self.watch_secret, timeout=self.timeout)
            rep = construct_provider_representation(self.plan, target_enabled, self.ping_secret)
            set_live_provider_state(self.keycloak_url, self.realm, token, rep, alias=DEFAULT_IDP_ALIAS, timeout=self.timeout)

            old_state = self.current_state
            self.current_state = target_state
            self.provider_enabled = target_enabled
            self.last_transition_ts = time.time()
            self.persist_state()

            # Verification readback (warn on error, do not leave internal state contrary to applied write)
            try:
                live_enabled = get_live_provider_state(self.keycloak_url, self.realm, token, alias=DEFAULT_IDP_ALIAS, timeout=self.timeout)
                if live_enabled != target_enabled:
                    sys.stderr.write(f"[idp-watch] Warning: verification readback expected enabled={target_enabled}, got {live_enabled}\n")
                    self.reconciliation_pending = True
            except Exception as e:
                sys.stderr.write(f"[idp-watch] Warning: verification readback query error: {e}\n")
                self.reconciliation_pending = True

            action_name = 'fallback' if target_enabled is False else 'recovery'
            log_journal_entry(self.state_dir, f'idp-watch {action_name}', 'ok',
                              f"{old_state}->{target_state} enabled={target_enabled} reason={reason!r}")
            return True
        except Exception as exc:
            sys.stderr.write(f"[idp-watch] Transition failed: {exc}\n")
            self.reconciliation_pending = True
            self.reconcile_with_keycloak()
            self.persist_state()
            if self.fail_open and target_enabled is False:
                sys.stderr.write("[idp-watch] FAIL_OPEN active: keeping provider enabled after Keycloak API failure\n")
            return False

    def step(self):
        """Run single probe and hysteresis evaluation cycle."""
        touch_heartbeat(self.state_dir)
        self.last_probe_ts = time.time()

        if not self.enabled:
            # Watcher disabled via configuration
            self.persist_state()
            return

        if self.is_paused():
            # Watcher paused via operator flag
            self.persist_state()
            return

        # Attempt reconciliation if pending
        if self.reconciliation_pending:
            if self.reconcile_with_keycloak():
                self.reconciliation_pending = False
            else:
                sys.stderr.write("[idp-watch] Reconciliation pending; will retry next cycle\n")

        probe_ok, error_reason = probe_idp(self.plan, self.ssl_context, self.timeout, self.authorities)
        self.last_error = error_reason

        now = time.time()
        dwell_elapsed = now - self.last_transition_ts

        if probe_ok:
            self.consecutive_failures = 0
            self.consecutive_successes += 1

            if self.current_state != 'HEALTHY':
                if self.consecutive_successes >= self.successes_to_recover and dwell_elapsed >= self.dwell_seconds:
                    self.execute_transition('HEALTHY', True, reason='probe recovery threshold and dwell satisfied')
        else:
            self.consecutive_successes = 0
            self.consecutive_failures += 1

            if self.current_state != 'FALLBACK':
                if self.consecutive_failures >= self.failures_to_fallback and dwell_elapsed >= self.dwell_seconds:
                    self.execute_transition('FALLBACK', False, reason=error_reason or 'probe failure threshold satisfied')

        self.persist_state()

    def run_forever(self):
        """Main daemon loop."""
        sys.stdout.write(f"[idp-watch] Starting daemon (interval={self.interval}s, timeout={self.timeout}s, "
                         f"dwell={self.dwell_seconds}s, certs={self.certs_loaded})\n")
        sys.stdout.flush()

        while self.running:
            cycle_start = time.time()
            try:
                self.step()
            except Exception as exc:
                sys.stderr.write(f"[idp-watch] Unexpected error in step: {exc}\n")
            
            # Sleep remainder of interval for deterministic cadence
            cycle_elapsed = time.time() - cycle_start
            sleep_remaining = max(0.0, self.interval - cycle_elapsed)
            while sleep_remaining > 0 and self.running:
                chunk = min(1.0, sleep_remaining)
                time.sleep(chunk)
                sleep_remaining -= chunk


def parse_env_config():
    """Extract configuration from environment variables."""
    def parse_bool(val, default):
        if val is None:
            return default
        return str(val).lower() in ('true', '1', 'yes')

    def parse_int(val, default):
        try:
            return int(val) if val is not None else default
        except ValueError:
            return default

    def parse_float(val, default):
        try:
            return float(val) if val is not None else default
        except ValueError:
            return default

    return {
        'enabled': parse_bool(os.environ.get('IDP_WATCH_ENABLED'), True),
        'interval': parse_int(os.environ.get('IDP_WATCH_INTERVAL_SECONDS'), DEFAULT_INTERVAL_SECONDS),
        'timeout': parse_float(os.environ.get('IDP_WATCH_TIMEOUT_SECONDS'), DEFAULT_TIMEOUT_SECONDS),
        'failures_to_fallback': parse_int(os.environ.get('IDP_WATCH_FAILURES_TO_FALLBACK'), DEFAULT_FAILURES_TO_FALLBACK),
        'successes_to_recover': parse_int(os.environ.get('IDP_WATCH_SUCCESSES_TO_RECOVER'), DEFAULT_SUCCESSES_TO_RECOVER),
        'dwell_seconds': parse_float(os.environ.get('IDP_WATCH_DWELL_SECONDS'), DEFAULT_DWELL_SECONDS),
        'fail_open': parse_bool(os.environ.get('IDP_WATCH_FAIL_OPEN'), True),
        'keycloak_url': os.environ.get('KEYCLOAK_INTERNAL_URL', DEFAULT_KEYCLOAK_INTERNAL_URL),
        'realm': os.environ.get('KEYCLOAK_REALM', DEFAULT_REALM),
        'watch_secret': os.environ.get('KEYCLOAK_IDP_WATCH_CLIENT_SECRET', ''),
        'ping_secret': os.environ.get('PING_KEYCLOAK_CLIENT_SECRET', ''),
    }


def main():
    if '--test-token' in sys.argv:
        config = parse_env_config()
        if not config['watch_secret']:
            sys.stderr.write("KEYCLOAK_IDP_WATCH_CLIENT_SECRET is not set\n")
            return 1
        try:
            token = acquire_keycloak_token(config['keycloak_url'], config['realm'], config['watch_secret'], timeout=config['timeout'])
            if not token:
                sys.stderr.write("Acquired token is empty\n")
                return 1
            sys.stdout.write("Token acquisition verified successfully\n")
            return 0
        except Exception as exc:
            sys.stderr.write(f"Token acquisition failed: {exc}\n")
            return 1

    config = parse_env_config()
    plan_path = os.environ.get('IDP_PLAN_PATH', '/etc/krate/idp.json')
    truststores_dir = os.environ.get('IDP_TRUSTSTORES_DIR', '/etc/krate/truststores')
    state_dir = os.environ.get('IDP_STATE_DIR', '/var/run/idp_watch')

    # Allow local testing if default container paths don't exist
    if not os.path.isfile(plan_path) and os.path.isfile('auth/keycloak/pingfederate-idp.json'):
        plan_path = 'auth/keycloak/pingfederate-idp.json'
    if not os.path.isdir(truststores_dir) and os.path.isdir('auth/keycloak/truststores'):
        truststores_dir = 'auth/keycloak/truststores'

    watcher = IdpWatcher(plan_path, truststores_dir, state_dir, config)

    def handle_signal(sig, frame):
        watcher.running = False
        sys.stdout.write(f"[idp-watch] Caught signal {sig}, terminating...\n")
        sys.stdout.flush()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    watcher.run_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main())
