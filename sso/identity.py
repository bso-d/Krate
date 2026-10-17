#!/usr/bin/env python3
"""Plan the local Keycloak realm, Kafbat's Keycloak login, the Grafana and Perses realm clients and the database TLS material for Krate identity.

Secrets never enter this program's output: the realm plan and Kafbat's
runtime.yml carry ``${VAR}`` placeholders that Keycloak and Kafbat resolve from
their container environment.
"""
import socket
import ipaddress
import argparse
from typing import Any
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import quote, urlsplit


REALM = 'krate'
UI_CLIENT = 'krate-ui'
CLI_CLIENT = 'krate-cli'
SERVICE_ACCOUNT = 'service-account-' + CLI_CLIENT
CLI_ROLES = ['manage-users', 'view-users', 'query-users', 'query-groups']
UI_SECRET = '${KEYCLOAK_KAFBAT_CLIENT_SECRET}'
CLI_SECRET = '${KEYCLOAK_CLI_CLIENT_SECRET}'
# The .env keys the plan refers to by placeholder; named here for the summary only.
PLAN_PLACEHOLDER_KEYS = ('KEYCLOAK_CLI_CLIENT_SECRET', 'KEYCLOAK_KAFBAT_CLIENT_SECRET')
GROUPS_CLAIM = 'groups'
# Default client scopes without offline_access: no client may mint offline tokens.
DEFAULT_SCOPES = ['profile', 'email', 'roles', 'web-origins', 'basic']
# Keycloak 26.1.0 and later assigns this realm scope as a default scope to every client with
# serviceAccountsEnabled (ClientManager.enableServiceAccount, tag 26.8.0, which Krate pins) and
# removes it when the flag is cleared; the scope carries the client_id/clientHost/clientAddress
# claims of the client_credentials grant. A client plan whose scopes are compared with Keycloak's
# readback states it for each service-account client, or Krate reports drift Keycloak itself made.
SERVICE_ACCOUNT_SCOPE = 'service_account'
# Kafbat's side of the same client (auth/ui/runtime.yml): one OAuth2 registration
# named `keycloak`, no form login, roles mapped from the realm groups only.
UI_REGISTRATION = 'keycloak'
UI_OIDC_SCOPES = ['openid', 'profile', 'email']
UI_CLIENT_NAME = 'Keycloak'
# Kafbat talks to Keycloak over the identity network; browsers use the public URL.
UI_INTERNAL_URL = 'http://keycloak:8080/identity'
# Spring Security's back-channel logout endpoint ({baseUrl}/logout/connect/back-channel/{registrationId}),
# reached by Keycloak over the identity network. The handler matches sessions on this cookie name.
UI_BACKCHANNEL_LOGOUT_URL = 'http://kafka-ui:8080/logout/connect/back-channel/' + UI_REGISTRATION
UI_SESSION_COOKIE = 'SESSION'
# The site opts viewers into message payloads with this .env key (default: off).
VIEWER_MESSAGES_KEY = 'KAFKA_UI_VIEWER_MESSAGES'
# Required actions `krate identity users add` (and reset-password) put on a local user: the
# authenticator is enrolled and the temporary password replaced at the first login. Neither is
# a realm default action (Phase 3, owner decision D1): a default action would also apply to
# users PingFederate brokers in, whose MFA is the enterprise identity provider's.
USER_REQUIRED_ACTIONS = ['CONFIGURE_TOTP', 'UPDATE_PASSWORD']
# The PingFederate broker plan `krate auth configure <site.json>` writes (sso/configure-dual.py)
# and `krate auth apply` / `krate identity up` apply to the running realm. Names shared by the
# planner, the CLI, the preflight and the checks.
BROKER_PLAN = 'auth/keycloak/pingfederate-idp.json'
BROKER_ALIAS = 'pingfederate'
BROKER_SECRET_KEY = 'PING_KEYCLOAK_CLIENT_SECRET'
BROKER_SECRET = '${' + BROKER_SECRET_KEY + '}'
BROKER_ENDPOINTS = ('issuer', 'authorizationUrl', 'tokenUrl', 'userInfoUrl', 'jwksUrl')
FIRST_BROKER_FLOW = 'krate first broker login'
BROWSER_FLOW = 'krate browser'
FORMS_FLOW = 'krate forms'
OTP_FLOW = 'krate otp'
BROKER_FLOWS = (BROWSER_FLOW, FORMS_FLOW, OTP_FLOW, FIRST_BROKER_FLOW)
REDIRECT_CONFIG = 'PingFederate redirect'
# The provider flags the Krate plan fixes: one source for the writer (sso/configure-dual.py) and for
# broker_plan() below, as planned_flows() is for the flows. `trustEmail` true makes PingFederate the
# authority for the address it asserts: Keycloak sets the realm user's e-mail verification from the
# `email_verified` claim PingFederate sends, re-reading the claim from the userinfo response whenever
# that response returns an `email`, where an absent claim parses as false
# (OIDCIdentityProvider.extractIdentity, 26.8.0:599-606,612-614) — so the provider must assert
# email_verified: true. Only when the claim reaches neither response (the ID token lacks it and the
# userinfo response returns no e-mail) does the fallback apply: it marks a new user or a changed
# address verified and leaves an existing user's flag untouched
# (OIDCIdentityProvider.setEmailVerified, 26.8.0:1114-1128, reached from
# AbstractIdentityProvider.updateEmail:202-207 for a new user or syncMode FORCE; the fallback itself
# is AbstractIdentityProvider.setEmailVerified:214-230). With the flag false every brokered user is
# unverified, which the Phase 4 UIs refuse (oauth2-proxy answers 500 "email in id_token (…) isn't
# verified"). This is not account linking: the first-broker-login flow stays Create User If Unique
# only (D2) and no linking path reads the flag: IdentityBrokerService.java,
# IdpCreateUserIfUniqueAuthenticator.java — a clash with a local user is a FEDERATED_IDENTITY_EXISTS
# error page unless runIfUserVerified consumed the single-use marker of the e-mail account-link
# confirmation — and IdpVerifyAccountLinkActionTokenHandler.java carry no reference to it at 26.8.0.
# `storeToken` stays false: the realm keeps no PingFederate token.
BROKER_PROVIDER_FLAGS = {'enabled': True, 'trustEmail': True, 'storeToken': False}
TRUSTSTORES_DIR = 'auth/keycloak/truststores'
# What Keycloak loads from a truststore-paths directory (scanned recursively): PEM files and PKCS12 files.
TRUSTSTORE_SUFFIXES = ('.crt', '.pem', '.p12', '.pfx', '.pkcs12')
# How the identity provider's TLS chain is trusted: `local` = a CA file under TRUSTSTORES_DIR is required when
# the provider is not on the public host; `system` = the JVM default truststore is relied on (public CA).
TRUSTSTORE_MODES = ('local', 'system')
# .env key carrying the truststore digest; part of keycloak's Compose environment, so a changed
# PEM set recreates Keycloak (it reads KC_TRUSTSTORE_PATHS at start only). Like KRATE_PROXY_CONF_SHA.
TRUSTSTORE_SHA_KEY = 'KRATE_TRUSTSTORE_SHA'
# ─── The MFA stance of a brokered site (enforce-if-asserted) ──────────────────
# A site decides explicitly how Keycloak treats PingFederate's MFA assertion. The one mechanism
# that can refuse a brokered sign-in without the assertion is Keycloak's IdP-side "Verify essential
# claim": `filteredByClaim` true with `claimFilterName` and `claimFilterValue` on the provider's
# config makes getFederatedIdentity throw before any user is created — the claim is read from the ID
# token only, and a missing claim and an unmatched value both fail (OIDCIdentityProvider.java
# 490-512 at 26.8.0). A site that does not opt in records `mfa_not_asserted: true` in its site file,
# which the plan carries as a top-level key that is never sent to Keycloak: "MFA for SSO users is
# enforced at PingFederate only". A plan or a site file that states neither stance is refused
# (MfaStanceError), by `krate auth configure` and by every preflight that reads the plan, so the
# choice can never stay unstated.
# The three filter keys are MANAGED: the plan is the whole truth about them. The provider update the
# CLI sends replaces the provider's configuration (kcadm `update -f -` merges nothing: merge mode is on
# only with --merge/-m or attributes and no --file, AbstractRequestCmd.java 26.8.0:171 and :244; the
# admin API builds the model from the representation, IdentityProviderResource.java updateIdpFromRep,
# and stores its config map whole, JpaIdentityProviderStorageProvider.update), so a live filter the
# plan no longer carries is reconciled away: provider_differs() reports it.
MFA_FILTER_KEYS = ('filteredByClaim', 'claimFilterName', 'claimFilterValue')
MFA_NOT_ASSERTED_KEY = 'mfa_not_asserted'
# sso/dual-example.json ships REPLACE_WITH_... for the claim pair; an unedited copy must not configure a filter.
MFA_PLACEHOLDER = 'REPLACE_WITH'
# The claim name Keycloak matches is a top-level ID-token claim (the groups-claim rule).
MFA_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
# JsonWebToken's own fields: Keycloak parses the brokered ID token as a JsonWebToken
# (OIDCIdentityProvider.validateToken) and filters on getOtherClaims(), where these names never appear,
# so a filter on one of them would refuse every sign-in.
MFA_TYPED_CLAIMS = ('jti', 'iss', 'aud', 'sub', 'typ', 'azp', 'exp', 'nbf', 'iat')
# The claim value: one literal, or several separated by `|`. Keycloak applies the value with Java's
# String.matches; Python's `re` cannot check Java's grammar (the two disagree on named groups, `a*+`,
# `\p{L}`, `{,n}`, ...), so only a subset that means the same everywhere is accepted: letters, digits
# and . _ : / - (a `.` matches any one character, as in every engine), each alternative holding at
# least one letter or digit. A claim passes when one of its values matches (`anyMatch`, same lines).
MFA_VALUE_LITERAL = re.compile(r'[A-Za-z0-9._:/-]+')
MFA_VALUE_RULE = ('mfa_claim_value must be one literal or several literals separated by | (each made of letters, digits and . _ : / -, '
                  'with at least one letter or digit); other regular-expression syntax is refused because Java and Python disagree on it')
MFA_STANCE_HINT = ('set mfa_claim_name and mfa_claim_value in the site file (Keycloak then refuses a PingFederate sign-in whose ID token '
                   f'lacks that claim) or {MFA_NOT_ASSERTED_KEY}: true (MFA for SSO users is enforced at PingFederate only)')


class MfaStanceError(ValueError):
    """A plan or site file that states no MFA stance; the message is complete (it names the options and the way back)."""


def validate_mfa_filter(name, value):
    """The essential-claim filter's claim name and value; ValueError names the broken side and the rule."""
    for label, item in (('mfa_claim_name', name), ('mfa_claim_value', value)):
        if isinstance(item, str) and MFA_PLACEHOLDER in item:
            raise ValueError(f'{label} still holds the example placeholder {item}: replace it with the claim PingFederate asserts '
                             f'and its value, or state {MFA_NOT_ASSERTED_KEY}: true instead of the pair')
    if not isinstance(name, str) or not MFA_NAME.fullmatch(name):
        raise ValueError('mfa_claim_name must be a top-level identifier, e.g. acr or amr')
    if name in MFA_TYPED_CLAIMS:
        raise ValueError(f'mfa_claim_name {name} is a registered JWT field, which Keycloak never offers to the claim filter '
                         f'(it would refuse every sign-in); name another claim, e.g. acr or amr')
    if not isinstance(value, str) or not value:
        raise ValueError('mfa_claim_value must be a nonempty string')
    for alternative in value.split('|'):
        if not MFA_VALUE_LITERAL.fullmatch(alternative) or not any(c.isalnum() for c in alternative):
            raise ValueError(MFA_VALUE_RULE)


RBAC_RESOURCES = ('applicationconfig', 'clusterconfig', 'topic', 'consumer', 'schema', 'connect',
                  'connector', 'acl', 'audit', 'client_quotas')
PATTERN_RESOURCES = ('topic', 'consumer', 'schema', 'connect', 'connector')
CLUSTER_NAME = re.compile(r'[A-Za-z0-9_.-]+')
DEFAULTS = {
    'KEYCLOAK_VIEWER_GROUP': 'KRATE_VIEWERS',
    'KEYCLOAK_ADMIN_GROUP': 'KRATE_ADMINS',
    'KEYCLOAK_ACCESS_TOKEN_MINUTES': '5',
    'KEYCLOAK_SESSION_IDLE_MINUTES': '15',
    'KEYCLOAK_SESSION_MAX_HOURS': '8',
}
PLACEHOLDERS = ('', 'REPLACE_ME')
SECRET_KEY = re.compile(r'(_PASSWORD|_SECRET)$')
ENV_KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
# Group names travel through kcadm arguments and the groups claim; keep them to a plain token.
GROUP_NAME = re.compile(r'[A-Za-z0-9_.-]{1,64}')
# The permanent master-realm admin created by `krate identity up`; kcadm addresses it by name.
ADMIN_USER = re.compile(r'[a-z0-9][a-z0-9._@-]{0,62}')
# `kc.sh bootstrap-admin user` names start with this; those users are temporary and get deleted.
BOOTSTRAP_PREFIX = 'temp-admin'
# Keycloak event settings: user and admin events logged to the server log, kept 30 days.
EVENTS = {
    'eventsEnabled': True,
    'eventsListeners': ['jboss-logging'],
    'enabledEventTypes': [],  # empty = Keycloak's default event type set
    'eventsExpiration': 30 * 24 * 3600,
    'adminEventsEnabled': True,
    'adminEventsDetailsEnabled': False,
}

# ─── Phase 4 realm-plan clients (Grafana, Perses) ─────────────────────────────
# Names shared by the generators below, the CLI's reconciles and scripts/check-identity.py.
GRAFANA_CLIENT = 'krate-grafana'
GRAFANA_CLIENT_NAME = 'Grafana'
# The generic_oauth login-button label (realm.ini `name`) and the paths the ini and the client
# representation share: the browser is served at /grafana/, signs in at /grafana/login and comes
# back on /grafana/login/generic_oauth (lab6 L5-3 walk).
GRAFANA_SIGNIN_NAME = 'Krate sign-in'
GRAFANA_ROOT_PATH = '/grafana/'
GRAFANA_LOGIN_PATH = '/grafana/login'
GRAFANA_REDIRECT_PATH = '/grafana/login/generic_oauth'
# monitoring/.env key the CLI substitutes into the client with --with-secret; Grafana itself reads
# the rendered secret file ($__file{...}), never this program's output.
GRAFANA_SECRET_KEY = 'GRAFANA_OAUTH_CLIENT_SECRET'
# Container paths of the Phase 4 compose mounts: monitoring-init renders the client secret into
# grafana_rendered (plan commit 5) and the cluster CA is mounted read-only (plan commits 5 and 7).
GRAFANA_SECRET_FILE = '/etc/krate/grafana/client-secret'
GRAFANA_TLS_CA_FILE = '/etc/krate/ca/server.crt'
# The Krate home dashboard: the provisioning provider's path (dashboards.yml `path`) + file name;
# the stock Home panel fetches grafana.com news, so the realm ini points somewhere else (lab6 L5-3).
GRAFANA_HOME_DASHBOARD = '/var/lib/grafana/dashboards/kafka-overview.json'
PERSES_CLIENT = 'krate-perses'
PERSES_CLIENT_NAME = 'Perses'
PERSES_SYNC_CLIENT = 'krate-perses-sync'
PERSES_SYNC_CLIENT_NAME = 'Perses guard'
# The OIDC provider slug render.py configures in Perses (monitoring/render.py:110,215).
PERSES_OIDC_SLUG = 'krate'
PERSES_SECRET_KEY = 'OAUTH2_PROXY_CLIENT_SECRET'
PERSES_SYNC_SECRET_KEY = 'PERSES_SYNC_CLIENT_SECRET'
PERSES_PORT_KEY = 'PERSES_PORT'
PERSES_PORT_DEFAULT = '3443'
# The client-differs verdict: the fields the CLI's reconcile converges, the ones Keycloak stores
# as sets (its readback reorders them: lab2/logs/020-realm-setup.log), the scope fields the caller
# only reports (a PUT never changes scopes), and the mask the admin API returns for a secret.
# The client-mode fields are part of the verdict too: without them a change made in the Keycloak
# console — turning the client public, disabling it, switching off service accounts or the
# standard flow — reads back as "same" and is never converged (PR #42 review). client_differs
# compares a field only when the plan declares it, so listing them cannot make the verdict
# differ spuriously; every one of them is declared by grafana_client and the Perses clients.
CLIENT_VERDICT_FIELDS = ('redirectUris', 'webOrigins', 'frontchannelLogout', 'attributes',
                         'protocolMappers', 'enabled', 'protocol', 'publicClient',
                         'standardFlowEnabled', 'implicitFlowEnabled', 'directAccessGrantsEnabled',
                         'serviceAccountsEnabled')
CLIENT_SET_FIELDS = ('redirectUris', 'webOrigins')
CLIENT_SCOPE_FIELDS = ('defaultClientScopes', 'optionalClientScopes')
KEYCLOAK_SECRET_MASK = '**********'
# Hosts grafana-ini refuses for KEYCLOAK_PUBLIC_URL; the CLI's refuse_loopback_public_url
# (monitor_prepare, plan commit 5) refuses the same hosts, so no path can write the file.
LOOPBACK_HOSTS = ('localhost', '127.0.0.1', '::1')

DB_HOST = 'keycloak-db'
CA_NAME = 'Krate identity CA'
# The CA lives as long as the installation's trust (Keycloak's trust store is
# ca.crt); the server certificate is short-lived and reissued under it by
# `krate identity renew-db-tls` (PostgreSQL 17: "The server reads these files at
# server start and whenever the server configuration is reloaded").
CA_CERT_DAYS = 1825
SERVER_CERT_DAYS = 398
TLS_FILES = ('ca.key', 'ca.crt', 'server.key', 'server.crt', 'pg_hba.conf')
TLS_MODES = {'ca.key': 0o600, 'server.key': 0o600, 'ca.crt': 0o644, 'server.crt': 0o644, 'pg_hba.conf': 0o644}
PG_HBA = ('local   all all                     trust\n'
          'hostssl all all 0.0.0.0/0           scram-sha-256\n'
          'hostssl all all ::/0                scram-sha-256\n'
          'host    all all all                 reject\n')
SERVER_EXTENSIONS = ('basicConstraints=CA:FALSE\n'
                     'keyUsage=critical,digitalSignature,keyEncipherment\n'
                     'extendedKeyUsage=serverAuth\n'
                     'subjectAltName=DNS:' + DB_HOST + '\n')


class IncompleteMaterial(ValueError):
    """Some, but not all, TLS files exist; regenerating would silently break trust."""


# ─── .env helpers ──────────────────────────────────────────────────────────────

def read_env(path):
    """Parse KEY=VALUE lines without shell expansion; the last assignment wins."""
    values = {}
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        if key.startswith('export '):
            key = key[len('export '):].strip()
        if not ENV_KEY.fullmatch(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        values[key] = value
    return values


def public_origin(url):
    """KEYCLOAK_PUBLIC_URL without its trailing /identity; https only."""
    parts = urlsplit(url or '')
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or parts.path.rstrip('/') != '/identity'):
        raise ValueError('KEYCLOAK_PUBLIC_URL must be an https URL whose path is /identity')
    return 'https://' + parts.netloc


def secret_values(env):
    """Configured secret values (keys ending in _PASSWORD or _SECRET) that are not placeholders."""
    return {key: value for key, value in env.items()
            if SECRET_KEY.search(key) and value not in PLACEHOLDERS}


def _positive(env, key):
    value = env.get(key) or DEFAULTS[key]
    if not value.isdigit() or int(value) < 1:
        raise ValueError(key + ' must be a whole number of at least 1')
    return int(value)


def _group(env, key):
    value = env.get(key) or DEFAULTS[key]
    if not GROUP_NAME.fullmatch(value):
        raise ValueError(key + ' must be 1-64 characters from letters, digits, . _ - (no spaces or slashes)')
    return value


def group_names(env):
    """(viewer group, admin group) from a parsed .env mapping; validated and distinct."""
    viewer, admin = _group(env, 'KEYCLOAK_VIEWER_GROUP'), _group(env, 'KEYCLOAK_ADMIN_GROUP')
    if viewer == admin:
        raise ValueError('KEYCLOAK_VIEWER_GROUP and KEYCLOAK_ADMIN_GROUP must differ')
    return viewer, admin


def admin_user(env):
    """KEYCLOAK_ADMIN_USER: the permanent master-realm admin name; never a bootstrap-admin name."""
    value = env.get('KEYCLOAK_ADMIN_USER', '')
    if not ADMIN_USER.fullmatch(value):
        raise ValueError('KEYCLOAK_ADMIN_USER must be 1-63 characters: a lower-case letter or digit,'
                         ' then lower-case letters, digits, . _ @ -')
    if value.startswith(BOOTSTRAP_PREFIX):
        raise ValueError(f'KEYCLOAK_ADMIN_USER must not start with {BOOTSTRAP_PREFIX}:'
                         ' that prefix names the temporary bootstrap admin')
    return value


def settings(env):
    """Non-secret realm inputs taken from a parsed .env mapping."""
    viewer_group, admin_group = group_names(env)
    return {
        'public_origin': public_origin(env.get('KEYCLOAK_PUBLIC_URL')),
        'viewer_group': viewer_group,
        'admin_group': admin_group,
        'access_token_minutes': _positive(env, 'KEYCLOAK_ACCESS_TOKEN_MINUTES'),
        'session_idle_minutes': _positive(env, 'KEYCLOAK_SESSION_IDLE_MINUTES'),
        'session_max_hours': _positive(env, 'KEYCLOAK_SESSION_MAX_HOURS'),
    }


def env_flag(env, key):
    """A true/false .env switch; empty or absent means false."""
    value = (env.get(key) or 'false').strip().lower()
    if value not in ('true', 'false'):
        raise ValueError(key + ' must be true or false')
    return value == 'true'


def cluster_names(clusters):
    """Kafbat cluster names for the RBAC roles: explicit, unique, plain tokens (no wildcards)."""
    names = list(clusters or [])
    if not names or any(not isinstance(name, str) or not CLUSTER_NAME.fullmatch(name) for name in names):
        raise ValueError('clusters must be explicit cluster names from letters, digits, . _ - (no wildcards)')
    if len(set(names)) != len(names):
        raise ValueError('clusters must be unique')
    return names


def runtime_settings(env, clusters, origin=None):
    """Inputs of the Kafbat plan from a parsed .env mapping and the edition's cluster list.

    `origin` overrides KEYCLOAK_PUBLIC_URL's origin (the site file's public_url in
    the PingFederate flow, which the CLI then writes to .env).
    """
    viewer_group, admin_group = group_names(env)
    return {
        'public_origin': origin or public_origin(env.get('KEYCLOAK_PUBLIC_URL')),
        'viewer_group': viewer_group,
        'admin_group': admin_group,
        'session_idle_minutes': _positive(env, 'KEYCLOAK_SESSION_IDLE_MINUTES'),
        'session_max_hours': _positive(env, 'KEYCLOAK_SESSION_MAX_HOURS'),
        'clusters': cluster_names(clusters),
        'viewer_messages': env_flag(env, VIEWER_MESSAGES_KEY),
    }


# ─── Realm plan (pure) ─────────────────────────────────────────────────────────

def ui_client_attributes(origin):
    """krate-ui client attributes: PKCE, the exact post-logout targets, OIDC back-channel logout to Kafbat.

    Keycloak stores multi-valued client attributes as one string joined with
    `##` (Constants.CFG_DELIMITER); the two values are the origin with and
    without a trailing slash, so no wildcard is accepted by the logout endpoint.
    """
    return {
        'pkce.code.challenge.method': 'S256',
        'post.logout.redirect.uris': origin + '##' + origin + '/',
        'backchannel.logout.url': UI_BACKCHANNEL_LOGOUT_URL,
        'backchannel.logout.session.required': 'true',
        'backchannel.logout.revoke.offline.tokens': 'false',
    }


def groups_mapper():
    """The `groups` claim mapper every Krate browser client carries: group names, never realm
    paths (full.path false), in the ID token, the access token and userinfo. One source for
    krate-ui, krate-grafana and krate-perses."""
    return {
        'name': 'groups', 'protocol': 'openid-connect',
        'protocolMapper': 'oidc-group-membership-mapper', 'consentRequired': False,
        'config': {'claim.name': GROUPS_CLAIM, 'full.path': 'false', 'multivalued': 'true',
                   'id.token.claim': 'true', 'access.token.claim': 'true',
                   'userinfo.token.claim': 'true'},
    }


def realm(values):
    """Local-mode realm from settings(): local users, two groups, two clients, no identity providers."""
    origin = values['public_origin']
    ui_client = {
        'clientId': UI_CLIENT, 'name': 'Kafbat UI', 'enabled': True,
        'protocol': 'openid-connect', 'publicClient': False,
        'clientAuthenticatorType': 'client-secret', 'secret': UI_SECRET,
        'standardFlowEnabled': True, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
        'redirectUris': [origin + '/login/oauth2/code/keycloak'],
        'webOrigins': [origin],
        # Back-channel logout only; stated so a changed Keycloak default cannot switch it on.
        'frontchannelLogout': False,
        'attributes': ui_client_attributes(origin),
        'defaultClientScopes': list(DEFAULT_SCOPES),
        'optionalClientScopes': [],
        'protocolMappers': [groups_mapper()],
    }
    cli_client = {
        'clientId': CLI_CLIENT, 'name': 'Krate CLI user management', 'enabled': True,
        'protocol': 'openid-connect', 'publicClient': False,
        'clientAuthenticatorType': 'client-secret', 'secret': CLI_SECRET,
        'standardFlowEnabled': False, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': True,
        'redirectUris': [], 'webOrigins': [],
        'defaultClientScopes': list(DEFAULT_SCOPES),
        'optionalClientScopes': [],
    }
    return {
        'realm': REALM, 'enabled': True,
        'registrationAllowed': False, 'resetPasswordAllowed': False,
        'rememberMe': False, 'verifyEmail': False,
        'bruteForceProtected': True, 'failureFactor': 5, 'permanentLockout': False,
        'waitIncrementSeconds': 60, 'maxFailureWaitSeconds': 900,
        'accessTokenLifespan': values['access_token_minutes'] * 60,
        'ssoSessionIdleTimeout': values['session_idle_minutes'] * 60,
        'ssoSessionMaxLifespan': values['session_max_hours'] * 3600,
        'otpPolicyType': 'totp', 'otpPolicyAlgorithm': 'HmacSHA1',
        'otpPolicyDigits': 6, 'otpPolicyPeriod': 30,
        # The import builds `new OTPPolicy()` whenever otpPolicyType is set and copies the
        # window only when given (DefaultExportImportManager.toPolicy, 26.8.0); the class
        # default is 0, which refuses a code typed across the 30-second boundary. Keep
        # Keycloak's documented default of one step either side.
        'otpPolicyLookAheadWindow': 1,
        **EVENTS,
        # Both enabled, neither a default action: `identity users add` assigns them to the local
        # user it creates (USER_REQUIRED_ACTIONS); a default action would also be demanded of
        # users PingFederate brokers in (Phase 3, D1). identity_reconcile_realm_policy applies
        # enabled/defaultAction to an existing realm.
        'requiredActions': [
            {'alias': 'CONFIGURE_TOTP', 'name': 'Configure OTP', 'providerId': 'CONFIGURE_TOTP',
             'enabled': True, 'defaultAction': False, 'priority': 10},
            {'alias': 'UPDATE_PASSWORD', 'name': 'Update Password', 'providerId': 'UPDATE_PASSWORD',
             'enabled': True, 'defaultAction': False, 'priority': 30},
        ],
        'groups': [{'name': values['viewer_group']}, {'name': values['admin_group']}],
        'clients': [cli_client, ui_client],
        'users': [{'username': SERVICE_ACCOUNT, 'enabled': True,
                   'serviceAccountClientId': CLI_CLIENT,
                   'clientRoles': {'realm-management': list(CLI_ROLES)}}],
        'browserFlow': 'browser',
    }


def render(data):
    return json.dumps(data, indent=2) + '\n'


def summary(data, path, outcome):
    """Human-readable description of a realm plan; it receives a copy without credential keys."""
    data = without_credentials(data)
    clients = {client['clientId']: client for client in data['clients']}
    ui = clients[UI_CLIENT]
    lines = [
        f"Realm plan: {data['realm']} (local mode, identity providers: {len(data.get('identityProviders', []))})",
        '  public origin: ' + ui['webOrigins'][0],
        '  groups: ' + ', '.join(group['name'] for group in data['groups']),
        '  clients: ' + ', '.join(f"{name} ({'service account' if client['serviceAccountsEnabled'] else 'browser login'})"
                                 for name, client in clients.items()),
        f"  access token {data['accessTokenLifespan']} s, session idle {data['ssoSessionIdleTimeout']} s,"
        f" session max {data['ssoSessionMaxLifespan']} s",
        '  placeholders for: ' + ', '.join(PLAN_PLACEHOLDER_KEYS) + ' (values stay in .env)',
        f'  {path}: {outcome}',
    ]
    return '\n'.join(lines)



# ─── Kafbat plan (pure) ────────────────────────────────────────────────────────

def kafbat_role(name, group, clusters, admin=False, viewer_messages=False):
    """One Kafbat RBAC role whose only subject is a realm group carried in the `groups` claim.

    The viewer gets `view` on every resource except `applicationconfig` (its view can
    return the running configuration, client secret included, when Kafbat's dynamic
    configuration is on) and `analysis_view`
    on topics; `messages_read` only when the site opted in. KSQL has `execute`
    only, which also permits mutations, so only the administrator gets it.
    """
    permissions = []
    for resource in RBAC_RESOURCES:
        if resource == 'applicationconfig' and not admin:
            continue
        permission = {'resource': resource, 'actions': 'all' if admin else ['view']}
        if resource in PATTERN_RESOURCES:
            permission['value'] = '.*'
        if resource == 'topic' and not admin:
            permission['actions'] = ['view', 'analysis_view'] + (['messages_read'] if viewer_messages else [])
        permissions.append(permission)
    if admin:
        permissions.append({'resource': 'ksql', 'actions': 'all'})
    return {
        'name': name, 'clusters': list(clusters),
        'subjects': [{'provider': 'oauth', 'type': 'role', 'value': group, 'regex': False}],
        'permissions': permissions,
    }


def runtime(values):
    """Kafbat's auth/ui/runtime.yml from runtime_settings(): Keycloak login only, no shared form login.

    The Keycloak client secret appears as the `${KEYCLOAK_KAFBAT_CLIENT_SECRET}`
    placeholder, which Kafbat resolves from its container environment. The
    session cookie is named so the back-channel logout handler can end sessions,
    its idle timeout is the realm's (one source: KEYCLOAK_SESSION_IDLE_MINUTES) and so is its
    absolute lifetime, which the fork's session filter enforces (auth.oauth2.max-session-lifetime,
    one source: KEYCLOAK_SESSION_MAX_HOURS).
    """
    origin = values['public_origin']
    realm_url = origin + '/identity/realms/' + REALM
    internal = UI_INTERNAL_URL + '/realms/' + REALM + '/protocol/openid-connect/'
    client = {
        'provider': UI_REGISTRATION, 'client-id': UI_CLIENT, 'client-secret': UI_SECRET,
        'client-name': UI_CLIENT_NAME, 'scope': list(UI_OIDC_SCOPES), 'issuer-uri': realm_url,
        'redirect-uri': origin + '/login/oauth2/code/' + UI_REGISTRATION,
        'authorization-grant-type': 'authorization_code', 'user-name-attribute': 'sub',
        # end-session-uri: with explicit endpoints there is no discovery, so the fork
        # reads the provider's end_session_endpoint from here (RP-initiated logout).
        'custom-params': {'type': 'oauth', 'roles-field': GROUPS_CLAIM,
                          'end-session-uri': realm_url + '/protocol/openid-connect/logout'},
        'authorization-uri': realm_url + '/protocol/openid-connect/auth',
        'token-uri': internal + 'token',
        'user-info-uri': internal + 'userinfo',
        'jwk-set-uri': internal + 'certs',
    }
    roles = [kafbat_role('viewer', values['viewer_group'], values['clusters'], False, values['viewer_messages']),
             kafbat_role('administrator', values['admin_group'], values['clusters'], True)]
    return {
        # Kafbat's error bodies carry the stack trace unless told otherwise; signed-in
        # viewers must not read it (http.error.excludeStackTraces, GlobalErrorWebExceptionHandler).
        'http': {'error': {'excludeStackTraces': True}},
        'server': {'reactive': {'session': {
            'timeout': f"{values['session_idle_minutes']}m",
            'cookie': {'name': UI_SESSION_COOKIE, 'secure': True, 'http-only': True, 'same-site': 'lax'},
        }}},
        'auth': {'type': 'OAUTH2', 'oauth2': {'require-mapped-role': True,
                                              'max-session-lifetime': f"{values['session_max_hours']}h",
                                              'client': {UI_REGISTRATION: client}}},
        'rbac': {'roles': roles},
    }


def without_credentials(data: Any) -> Any:
    """A deep copy of a plan with every *secret*/*password* key removed, for anything that prints."""
    if isinstance(data, dict):
        return {key: without_credentials(value) for key, value in data.items()
                if not any(marker in key.lower() for marker in ('secret', 'password'))}
    if isinstance(data, list):
        return [without_credentials(item) for item in data]
    return data


def runtime_summary(values, path, outcome):
    """Human-readable description of a Kafbat plan, built from the plan's inputs (runtime_settings()),
    never from the rendered plan: the plan carries the client-secret placeholder, and nothing that
    held it may reach stdout (CodeQL clear-text logging)."""
    lines = [
        'Kafbat plan: Keycloak login only (no shared form login), roles from the groups claim',
        '  issuer: ' + values['public_origin'] + '/identity/realms/' + REALM,
        '  clusters: ' + ', '.join(values['clusters']),
        f"  roles: viewer <- group {values['viewer_group']}; administrator <- group {values['admin_group']}",
        '  viewer message payloads: ' + ('on' if values['viewer_messages'] else f'off ({VIEWER_MESSAGES_KEY}=true opts in)'),
        f"  session idle: {values['session_idle_minutes']}m (cookie {UI_SESSION_COOKIE}; from KEYCLOAK_SESSION_IDLE_MINUTES)",
        f"  session maximum: {values['session_max_hours']}h (absolute, from KEYCLOAK_SESSION_MAX_HOURS)",
        '  placeholders for: KEYCLOAK_KAFBAT_CLIENT_SECRET (value stays in .env)',
        f'  {path}: {outcome}',
    ]
    return '\n'.join(lines)


# ─── Writers ───────────────────────────────────────────────────────────────────

def write_file(path, content, mode):
    """Create the file atomically: O_EXCL temporary beside the target, then rename."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # A unique name per attempt: a temporary left by an interrupted run can
    # never block a later one (O_EXCL still refuses to reuse or follow it).
    temporary = path.with_name('.%s.%s.tmp' % (path.name, secrets.token_hex(4)))
    data = content if isinstance(content, bytes) else content.encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_if_changed(path, content, mode):
    """Write only when content or mode differ; returns True when the file changed."""
    path = Path(path)
    data = content if isinstance(content, bytes) else content.encode()
    if path.is_file():
        current = os.stat(path)
        if path.read_bytes() == data and (current.st_mode & 0o7777) == mode:
            return False
    write_file(path, data, mode)
    return True


def assert_redacted(text, env, what='the realm plan'):
    """Refuse output that embeds any configured secret value; the refusal names the key only."""
    for key, value in secret_values(env).items():
        if value in text:
            raise ValueError('refusing to emit ' + key + f': its value would appear in {what}')


def plan(env_file, output, show=False):
    env = read_env(env_file)
    data = realm(settings(env))
    text = render(data)
    assert_redacted(text, env)
    changed = write_if_changed(output, text, 0o644)
    if show:
        sys.stdout.write(text)
    print(summary(data, output, 'written' if changed else 'No changes'))
    return data



def runtime_plan(env_file, clusters, output, force=False, show=False):
    """Write Kafbat's runtime.yml; an existing file that differs is kept unless `force`."""
    env = read_env(env_file)
    values = runtime_settings(env, clusters)
    data = runtime(values)
    text = render(data)
    assert_redacted(text, env)
    path = Path(output)
    if path.is_file() and path.read_bytes() != text.encode() and not force:
        raise ValueError(f'{path} exists and differs from the plan; review it, then rerun with --force to replace it')
    changed = write_if_changed(path, text, 0o644)
    if show:
        sys.stdout.write(text)
    print(runtime_summary(values, path, 'written' if changed else 'No changes'))
    return data


# ─── Database TLS material ─────────────────────────────────────────────────────

def _openssl(args, cwd, capture=False):
    result = subprocess.run(['openssl', *args], cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        raise subprocess.SubprocessError(f'openssl {args[0]} failed (exit {result.returncode}); is OpenSSL 1.1.1 or newer installed?')
    return result.stdout.decode() if capture else ''


def issue_server(work, days=SERVER_CERT_DAYS):
    """A new server key and certificate (SAN DNS:keycloak-db) signed by the CA files in `work`."""
    work = Path(work)
    (work / 'server.ext').write_text(SERVER_EXTENSIONS)
    _openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
              '-subj', '/CN=' + DB_HOST, '-keyout', 'server.key', '-out', 'server.csr'], work)
    _openssl(['x509', '-req', '-sha256', '-days', str(days), '-in', 'server.csr',
              '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
              '-extfile', 'server.ext', '-out', 'server.crt'], work)


def generate_material(work, days=SERVER_CERT_DAYS):
    """Create a private CA and a server certificate (valid `days`) for keycloak-db in `work`."""
    work = Path(work)
    _openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', str(CA_CERT_DAYS),
              '-subj', '/CN=' + CA_NAME, '-keyout', 'ca.key', '-out', 'ca.crt',
              '-addext', 'basicConstraints=critical,CA:TRUE',
              '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], work)
    issue_server(work, days)
    material = {name: (work / name).read_bytes() for name in TLS_FILES if name != 'pg_hba.conf'}
    material['pg_hba.conf'] = PG_HBA.encode()
    return material


def not_after(certificate):
    """The certificate's expiry as openssl prints it, e.g. 'Oct 10 12:00:00 2027 GMT'."""
    text = _openssl(['x509', '-in', str(certificate), '-noout', '-enddate'], None, capture=True)
    return text.strip().partition('=')[2]


def seconds_left(certificate):
    """Seconds until the certificate expires (negative when it has)."""
    text = _openssl(['x509', '-in', str(certificate), '-noout', '-enddate'], None, capture=True).strip().partition('=')[2]
    expiry = datetime.datetime.strptime(text, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
    return (expiry - datetime.datetime.now(datetime.timezone.utc)).total_seconds()


def remove_stale_work(directory):
    """Remove work directories a killed earlier run left behind (they hold key copies)."""
    for stale in Path(directory).glob('.*-*'):
        if stale.is_dir() and stale.name.split('-')[0] in ('.renew', '.generate'):
            shutil.rmtree(stale, ignore_errors=True)


def renew_server(directory, days=SERVER_CERT_DAYS):
    """Reissue server.key and server.crt; returns (new expiry, whether the CA was renewed too).

    The CA is renewed as well when it would expire before the new server
    certificate (Keycloak then needs a restart to trust it). The replaced files
    stay beside the new ones as `.prev` until rollback() or discard_previous():
    the caller restarts the database and decides. `.prev` files a killed earlier
    renewal left behind are discarded first, so a rollback restores exactly this
    renewal's set (never an older CA beside a server certificate from the new one).
    New files are written as `.new` and moved into place, so no reader ever sees
    a partial file.
    """
    directory = Path(directory)
    missing = [name for name in TLS_FILES if not (directory / name).is_file()]
    if missing:
        raise IncompleteMaterial(f'{directory} is incomplete; missing ' + ', '.join(missing)
                                 + '. Renewal needs the existing CA; restore the directory from a backup first.')
    remove_stale_work(directory)
    if any((directory / (name + '.prev')).exists() for name in TLS_FILES) and not chain_verifies(directory):
        raise IncompleteMaterial(f'{directory} holds .prev files of an interrupted renewal and server.crt does not verify '
                                 'against ca.crt: the current set is mixed. Put the previous set back first (move each '
                                 '.prev file over its current file, or restore auth/keycloak/db-tls from a backup) '
                                 'instead of renewing on top of it.')
    discard_previous(directory)
    renew_ca = seconds_left(directory / 'ca.crt') < days * 86400
    names = ('ca.key', 'ca.crt', 'server.key', 'server.crt') if renew_ca else ('server.key', 'server.crt')
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='.renew-', dir=directory) as work:
            work = Path(work)
            if renew_ca:
                generate_material(work, days)
            else:
                for name in ('ca.crt', 'ca.key'):
                    (work / name).write_bytes((directory / name).read_bytes())
                issue_server(work, days)
            material = {name: (work / name).read_bytes() for name in names}
    finally:
        os.umask(previous)
    for name in names:
        write_file(directory / (name + '.new'), material[name], TLS_MODES[name])
        write_file(directory / (name + '.prev'), (directory / name).read_bytes(), TLS_MODES[name])
    for name in names:
        os.replace(directory / (name + '.new'), directory / name)
    return not_after(directory / 'server.crt'), renew_ca


def chain_verifies(directory):
    """True when server.crt chains to ca.crt. Expiry is not the question (a renewal fixes that), so
    openssl's time errors (X509_V_ERR 9 not yet valid, 10 expired) count as a verified chain; no
    option such as -no_check_time is used because LibreSSL's verify does not know it."""
    result = subprocess.run(['openssl', 'verify', '-CAfile', 'ca.crt', 'server.crt'], cwd=directory, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode == 0:
        return True
    errors = re.findall(r'error (\d+) at \d+ depth lookup', result.stdout)
    return bool(errors) and all(code in ('9', '10') for code in errors)


def rollback(directory):
    """Put the `.prev` files of the last renewal back; returns the names restored."""
    directory = Path(directory)
    restored = [name for name in TLS_FILES if (directory / (name + '.prev')).is_file()]
    if not restored:
        raise ValueError(f'nothing to roll back in {directory}: no .prev files')
    for name in restored:
        os.replace(directory / (name + '.prev'), directory / name)
    return restored


def discard_previous(directory):
    """Remove the `.prev` files once the renewed certificate is in service."""
    directory = Path(directory)
    removed = [name for name in TLS_FILES if (directory / (name + '.prev')).is_file()]
    for name in removed:
        (directory / (name + '.prev')).unlink()
    return removed


def db_tls(directory):
    """Generate the keycloak-db TLS set once; returns the names written."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    present = [name for name in TLS_FILES if (directory / name).is_file()]
    if len(present) == len(TLS_FILES):
        if write_if_changed(directory / 'pg_hba.conf', PG_HBA, TLS_MODES['pg_hba.conf']):
            return ['pg_hba.conf']
        return []
    if present:
        missing = [name for name in TLS_FILES if name not in present]
        raise IncompleteMaterial(
            f'{directory} is incomplete; missing ' + ', '.join(missing) + '. Restore the directory from '
            'a backup (or move it aside to issue a new CA and re-import trust) before continuing.')
    remove_stale_work(directory)
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='.generate-', dir=directory) as work:
            material = generate_material(work)
    finally:
        os.umask(previous)
    for name in TLS_FILES:
        write_file(directory / name, material[name], TLS_MODES[name])
    return list(TLS_FILES)


# ─── PingFederate broker plan (read by the CLI's identity_apply_idp) ────────────
# The plan file is Keycloak's own export shape (see sso/configure-dual.py for the schema): a
# provider, its mappers, one authenticator config and flows whose executions reference a
# sub-flow by `flowAlias`. These readers hand the CLI one item at a time; the secret enters
# the provider only through the environment (BROKER_SECRET_KEY), never an argument.

# ─── The planned flows: one source for the writer and the validator ─────────────
# sso/configure-dual.py writes these into the plan; broker_plan() refuses a plan that differs
# from them in any field (PR #41 review: a generic "some authenticator" check let `idp-auto-link`
# replace the sole first-broker execution, which links a brokered identity to a local account).

def _execution(authenticator, requirement, priority, config=None):
    item = {"authenticator": authenticator, "requirement": requirement, "priority": priority,
            "authenticatorFlow": False, "userSetupAllowed": False}
    if config:
        item["authenticatorConfig"] = config
    return item


def _subflow(alias, requirement, priority):
    return {"authenticatorFlow": True, "flowAlias": alias, "requirement": requirement,
            "priority": priority, "userSetupAllowed": False}


def _flow(alias, description, executions, top_level):
    return {"alias": alias, "description": description, "providerId": "basic-flow",
            "topLevel": top_level, "builtIn": False, "authenticationExecutions": executions}


def planned_flows():
    """The realm's browser flow (D3) and first-broker-login flow (D2); parents before their sub-flows."""
    return [
        _flow(BROWSER_FLOW, "Krate: cookie, then PingFederate; local users with ?kc_idp_hint= (empty)",
             [_execution("auth-cookie", "ALTERNATIVE", 10),
              _execution("identity-provider-redirector", "ALTERNATIVE", 20, REDIRECT_CONFIG),
              _subflow(FORMS_FLOW, "ALTERNATIVE", 30)], True),
        _flow(FORMS_FLOW, "local users: password, then OTP when enrolled",
             [_execution("auth-username-password-form", "REQUIRED", 10),
              _subflow(OTP_FLOW, "CONDITIONAL", 20)], False),
        _flow(OTP_FLOW, "OTP when the user has one",
             [_execution("conditional-user-configured", "REQUIRED", 10),
              _execution("auth-otp-form", "REQUIRED", 20)], False),
        _flow(FIRST_BROKER_FLOW, "Krate: create the brokered user; never link to a local account",
             [_execution("idp-create-user-if-unique", "REQUIRED", 10)], True),
    ]


def planned_authenticator_config():
    """The redirector's configuration: SSO users go to PingFederate without a Keycloak password page."""
    return [{"alias": REDIRECT_CONFIG, "config": {"defaultProvider": BROKER_ALIAS}}]


def _same(a, b):
    """JSON equality that does not equate True with 1 or 10 with 10.0."""
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _describe(execution):
    return execution.get('flowAlias') if execution.get('authenticatorFlow') else execution.get('authenticator')


def _check_flows(path, flows):
    """Every flow must equal planned_flows() (matched by alias); an execution list is compared in priority order."""
    expected = {flow['alias']: flow for flow in planned_flows()}
    actual = {flow.get('alias'): flow for flow in flows}
    for alias, want in expected.items():
        have = actual[alias]
        for key in sorted(set(want) | set(have)):
            if key == 'authenticationExecutions':
                continue
            if not _same(have.get(key), want.get(key)):
                raise ValueError(f'{path}: flow {alias!r} field {key} differs from the Krate plan')
        for item in have['authenticationExecutions']:
            if type(item.get('priority')) is not int:
                raise ValueError(f'{path}: flow {alias!r} execution {_describe(item)!r} priority must be an integer')
        have_x = sorted(have['authenticationExecutions'], key=lambda x: x['priority'])
        want_x = want['authenticationExecutions']
        if len(have_x) != len(want_x):
            names = [_describe(x) for x in have_x]
            raise ValueError(f'{path}: flow {alias!r} must have exactly {len(want_x)} executions ({[_describe(x) for x in want_x]}); found {names}')
        for have_item, want_item in zip(have_x, want_x):
            for key in sorted(set(want_item) | set(have_item)):
                if not _same(have_item.get(key), want_item.get(key)):
                    raise ValueError(f'{path}: flow {alias!r} execution {_describe(want_item)!r} field {key} differs from the Krate plan')


def broker_plan(path):
    """The validated broker plan at `path`; a ValueError names what is wrong (never a value)."""
    try:
        plan = json.loads(Path(path).read_text())
    except ValueError:
        raise ValueError(f'{path} is not valid JSON') from None
    if not isinstance(plan, dict):
        raise ValueError(f'{path} must be a JSON object')
    providers = plan.get('identityProviders')
    if not isinstance(providers, list) or len(providers) != 1 or not isinstance(providers[0], dict):
        raise ValueError(f'{path} must define exactly one identity provider')
    provider = providers[0]
    config = provider.get('config')
    if provider.get('alias') != BROKER_ALIAS or provider.get('providerId') != 'oidc' or not isinstance(config, dict):
        raise ValueError(f'{path}: the identity provider must be the oidc provider {BROKER_ALIAS}')
    for key, value in BROKER_PROVIDER_FLAGS.items():
        if not _same(provider.get(key), value):
            raise ValueError(f'{path}: the identity provider field {key} differs from the Krate plan;'
                             ' regenerate the plan with krate auth configure <site.json>')
    if config.get('clientSecret') != BROKER_SECRET:
        raise ValueError(f'{path}: clientSecret must be the {BROKER_SECRET} placeholder')
    for key in BROKER_ENDPOINTS:
        parts = urlsplit(str(config.get(key) or ''))
        if parts.scheme != 'https' or not parts.hostname:
            raise ValueError(f'{path}: {key} must be an https URL')
    if provider.get('firstBrokerLoginFlowAlias') != FIRST_BROKER_FLOW:
        raise ValueError(f'{path}: firstBrokerLoginFlowAlias must be {FIRST_BROKER_FLOW!r}')
    mappers = plan.get('identityProviderMappers')
    if not isinstance(mappers, list) or len(mappers) != 2 or any(not isinstance(m, dict) for m in mappers):
        raise ValueError(f'{path} must define exactly two identity-provider mappers')
    names = [m.get('name') for m in mappers]
    if len(set(names)) != 2 or any(not name for name in names):
        raise ValueError(f'{path}: mapper names must be distinct')
    for mapper in mappers:
        if mapper.get('identityProviderAlias') != BROKER_ALIAS or not isinstance(mapper.get('config'), dict):
            raise ValueError(f'{path}: every mapper must belong to {BROKER_ALIAS}')
    flows = plan.get('authenticationFlows')
    if not isinstance(flows, list) or any(not isinstance(flow, dict) for flow in flows):
        raise ValueError(f'{path}: authenticationFlows must be a list of flows')
    aliases = [flow.get('alias') for flow in flows]
    if sorted(aliases) != sorted(BROKER_FLOWS):
        raise ValueError(f'{path}: authenticationFlows must be exactly {sorted(BROKER_FLOWS)}')
    for flow in flows:
        if not isinstance(flow.get('authenticationExecutions'), list):
            raise ValueError(f'{path}: flow {flow.get("alias")!r} must list authenticationExecutions')
        for execution in flow['authenticationExecutions']:
            if not isinstance(execution, dict) or execution.get('requirement') not in ('REQUIRED', 'ALTERNATIVE', 'CONDITIONAL', 'DISABLED') \
                    or not isinstance(execution.get('priority'), int):
                raise ValueError(f'{path}: every execution of {flow.get("alias")!r} needs a requirement and an integer priority')
            if execution.get('authenticatorFlow'):
                if execution.get('flowAlias') not in aliases:
                    raise ValueError(f'{path}: sub-flow {execution.get("flowAlias")!r} of {flow.get("alias")!r} is not planned')
            elif not execution.get('authenticator'):
                raise ValueError(f'{path}: an execution of {flow.get("alias")!r} names no authenticator')
    _check_flows(path, flows)
    configs = plan.get('authenticatorConfig')
    if not isinstance(configs, list) or any(not isinstance(c, dict) or not c.get('alias') or not isinstance(c.get('config'), dict) for c in configs):
        raise ValueError(f'{path}: authenticatorConfig must list named configurations')
    if not _same(configs, planned_authenticator_config()):
        raise ValueError(f'{path}: authenticatorConfig must be exactly the {REDIRECT_CONFIG!r} redirector configuration of the Krate plan')
    if plan.get('browserFlow') != BROWSER_FLOW:
        raise ValueError(f'{path}: browserFlow must be {BROWSER_FLOW!r}')
    if plan.get('truststore', 'local') not in TRUSTSTORE_MODES:
        raise ValueError(f'{path}: truststore must be one of {list(TRUSTSTORE_MODES)}')
    # The MFA stance is explicit (never fails open over an unstated one): either the three
    # essential-claim keys together on the provider's config, or the opt-out marker — never both.
    stance = plan.get(MFA_NOT_ASSERTED_KEY)
    if stance is not None and stance is not True:
        raise ValueError(f'{path}: {MFA_NOT_ASSERTED_KEY} must be the boolean true')
    filter_keys = [key for key in MFA_FILTER_KEYS if key in config]
    if filter_keys and stance is True:
        raise ValueError(f'{path}: {MFA_NOT_ASSERTED_KEY} conflicts with the essential-claim filter'
                         ' (filteredByClaim, claimFilterName, claimFilterValue);'
                         ' the plan carries exactly one of the two MFA stances')
    if filter_keys:
        missing = [key for key in MFA_FILTER_KEYS if key not in config]
        if missing:
            raise ValueError(f'{path}: the essential-claim filter must set all three config keys together'
                             f' (filteredByClaim, claimFilterName, claimFilterValue); missing {missing[0]}')
        if config.get('filteredByClaim') != 'true':
            raise ValueError(f'{path}: config.filteredByClaim must be the string "true"'
                             ' (Keycloak provider config values are strings)')
        validate_mfa_filter(config.get('claimFilterName'), config.get('claimFilterValue'))
    elif stance is not True:
        raise MfaStanceError(f'{path} states no MFA stance: {MFA_STANCE_HINT}; add one of the two to the site file, remove '
                             f'auth/ui/runtime.yml and {BROKER_PLAN}, then run krate auth configure <site.json>')
    return plan


def broker_flow(plan, alias):
    flow = next((flow for flow in plan['authenticationFlows'] if flow.get('alias') == alias), None)
    if flow is None:
        raise ValueError(f'flow {alias!r} is not in the plan')
    return flow


def broker_config(plan, alias):
    config = next((c for c in plan['authenticatorConfig'] if c.get('alias') == alias), None)
    if config is None:
        raise ValueError(f'authenticator config {alias!r} is not in the plan')
    return {'alias': config['alias'], 'config': dict(config['config'])}


def env_secret(key):
    """The environment's secret for `key`; the refusal names the key, never a value."""
    value = os.environ.get(key, '')
    if value in PLACEHOLDERS:
        raise ValueError(f'{key} is not set in the environment')
    return value


def broker_provider(plan, with_secret=False):
    """The provider representation; with `with_secret` the placeholder becomes the environment's value."""
    provider = json.loads(json.dumps(plan['identityProviders'][0]))
    if with_secret:
        provider['config']['clientSecret'] = env_secret(BROKER_SECRET_KEY)
    else:
        del provider['config']['clientSecret']
    return provider


def differs(wanted, current):
    """True when `current` (a representation Keycloak returned) lacks or differs in any key of `wanted`."""
    if isinstance(wanted, dict):
        return not isinstance(current, dict) or any(differs(value, current.get(key)) for key, value in wanted.items())
    return wanted != current


def provider_differs(plan, current):
    """True when the live provider `current` differs from the plan.

    Beyond differs() (a planned key lacks or differs), the claim-filter keys are managed: a live provider
    that still carries one the plan does not — the site switched from the claim pair to the opt-out — differs,
    so the apply sends the plan's representation, whose configuration replaces the live one. A live
    `filteredByClaim` of "false" is a filter that is off and is left alone.
    """
    wanted = broker_provider(plan)
    if differs(wanted, current):
        return True
    live = current.get('config') if isinstance(current, dict) else None
    live = live if isinstance(live, dict) else {}
    for key in MFA_FILTER_KEYS:
        if key in wanted['config'] or key not in live:
            continue
        if key == 'filteredByClaim' and str(live[key]).lower() == 'false':
            continue
        return True
    return False


def truststore_files(directory):
    """Every regular file under the truststores directory, recursively, sorted by relative path (Keycloak scans it that way)."""
    directory = Path(directory)
    if not directory.is_dir():
        return []
    return sorted((path for path in directory.rglob('*') if path.is_file()), key=lambda path: str(path.relative_to(directory)))


def truststore_digest(directory):
    """Digest of the file set Keycloak loads at start: sorted relative names, each with its content.

    An empty set digests to the empty string, the value a .env without the key renders: a
    Phase 1/2 installation (empty directory, no KRATE_TRUSTSTORE_SHA) is not recreated on its
    first upgrade, only when a file appears.
    """
    directory = Path(directory)
    files = truststore_files(directory)
    if not files:
        return ''
    digest = hashlib.sha256()
    for path in files:
        data = path.read_bytes()
        digest.update(str(path.relative_to(directory)).encode() + b'\n' + b'%d\n' % len(data) + data)
    return digest.hexdigest()[:32]


def cmd_broker(args):
    """Plan items for the CLI, one JSON document per line (flows and executions in plan order)."""
    plan = broker_plan(args.plan)
    out = sys.stdout
    if args.item == 'provider':
        # The secret travels stdin -> kcadm only; this output is piped, never logged or captured.
        out.write(json.dumps(broker_provider(plan, args.with_secret)) + '\n')
    elif args.item == 'provider-differs':
        out.write(('differs' if provider_differs(plan, json.load(sys.stdin)) else 'same') + '\n')
    elif args.item == 'mappers':
        for mapper in plan['identityProviderMappers']:
            out.write(json.dumps(mapper) + '\n')
    elif args.item == 'mapper-differs':
        wanted = next(m for m in plan['identityProviderMappers'] if m['name'] == args.name)
        out.write(('differs' if differs(wanted, json.load(sys.stdin)) else 'same') + '\n')
    elif args.item == 'flows':
        for flow in plan['authenticationFlows']:
            out.write(json.dumps({'alias': flow['alias'], 'topLevel': bool(flow.get('topLevel')),
                                  'description': flow.get('description', ''), 'providerId': flow.get('providerId', 'basic-flow')}) + '\n')
    elif args.item == 'executions':
        for execution in broker_flow(plan, args.name)['authenticationExecutions']:
            out.write(json.dumps(execution) + '\n')
    elif args.item == 'config':
        out.write(json.dumps(broker_config(plan, args.name)) + '\n')
    elif args.item == 'config-differs':
        out.write(('differs' if differs(broker_config(plan, args.name), json.load(sys.stdin)) else 'same') + '\n')
    elif args.item == 'browser-flow':
        out.write(plan['browserFlow'] + '\n')
    return 0


def cmd_truststore_digest(args):
    print(truststore_digest(args.directory))
    return 0


# ─── Phase 4 realm plans: Grafana and Perses (pure) ───────────────────────────
# The client representations and the Grafana ini that `krate monitor realm` / `krate monitor up`
# reconcile against the running realm. Every field was verified live on the lab fixtures:
# harness/phase4/lab6/logs/061-krate-grafana-client-request.json (create request) and
# 063-krate-grafana-readback.json, harness/phase4/lab2/logs/020-realm-setup.log (perses readback),
# harness/phase4/lab2/kcadmin.py:64-101 and harness/phase4/lab7/kcadmin.py:80-115 (the kcadm JSON
# that worked) and harness/phase4/lab7/results.md:30,117 (realm clients, logout chain). Client
# secrets are never part of a stored plan: --with-secret substitutes them from the environment
# exactly like broker_provider(), and the CLI pipes that output to kcadm (stdin only, never argv).

def checked_origin(origin):
    """A bare public https origin (the CLI's --origin: KEYCLOAK_PUBLIC_URL minus /identity)."""
    parts = urlsplit(origin or '')
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or parts.path not in ('', '/')):
        raise ValueError('--origin must be an https origin with no path (KEYCLOAK_PUBLIC_URL minus /identity)')
    return 'https://' + parts.netloc


def refuse_loopback_public_url(url):
    """Refuse a loopback KEYCLOAK_PUBLIC_URL host for the realm-derived Grafana configuration: its
    URLs are for browsers on other machines. The CLI's monitor_prepare refuses the same hosts
    (plan commit 5, U14); the generator repeats the refusal so no path can write the file. The
    message names the key, never the value."""
    host = urlsplit(url or '').hostname or ''
    # Parse it as an address rather than matching names: all of 127.0.0.0/8 is loopback,
    # including the inet_aton shorthand, and neither unspecified address is reachable from a
    # container. A host that is not an IP literal is checked against the name list only, so a
    # legal public hostname such as 127.example.com stays accepted (PR #42 review).
    address = None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # ipaddress rejects the shorthand forms that inet_aton — and therefore curl and every
        # browser — accept: 127.1 and 2130706433 both reach the loopback interface, so neither
        # may be a public host. A real hostname raises OSError here and stays a name.
        try:
            address = ipaddress.IPv4Address(socket.inet_aton(host))
        except (OSError, ValueError):
            address = None
    # The IPv4-mapped spelling is explicit rather than left to is_loopback: CPython only
    # reports ::ffff:127.0.0.1 as loopback from 3.13, and installations run 3.9 (PR #42 review).
    if ((address is not None and (address.is_loopback or address.is_unspecified))
            or host in LOOPBACK_HOSTS or host.startswith('::ffff:127.')):
        raise ValueError('KEYCLOAK_PUBLIC_URL must name the public host: refusing a loopback or'
                         ' unspecified address (any 127.0.0.0/8 address, ::1, 0.0.0.0, ::) and localhost')


def grafana_client(origin, with_secret=False):
    """The krate-grafana client representation (verified live: lab6/logs/061 create request,
    063 readback).

    Confidential, standard flow only, PKCE S256 (OIDCConfigAttributes.PKCE_CODE_CHALLENGE_METHOD,
    Keycloak 26.8.0 server-spi-private/src/main/java/org/keycloak/protocol/oidc/OIDCConfigAttributes.java:64),
    one exact post-logout target (POST_LOGOUT_REDIRECT_URIS, same file :93 — the logout endpoint
    accepts no wildcard) and krate-ui's groups mapper. No backchannel.logout.url: Grafana has no
    back-channel logout endpoint; its logout is the browser redirect realm.ini's
    signout_redirect_url performs. The secret is never part of the plan: `with_secret` substitutes
    GRAFANA_OAUTH_CLIENT_SECRET from the environment like broker_provider() does.
    """
    client = {
        'clientId': GRAFANA_CLIENT, 'name': GRAFANA_CLIENT_NAME, 'enabled': True,
        'protocol': 'openid-connect', 'publicClient': False,
        'clientAuthenticatorType': 'client-secret',
        'standardFlowEnabled': True, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
        # No Keycloak-initiated logout at all; stated so a changed Keycloak default cannot switch it on.
        'frontchannelLogout': False,
        'redirectUris': [origin + GRAFANA_REDIRECT_PATH],
        'webOrigins': [origin],
        'attributes': {
            'pkce.code.challenge.method': 'S256',
            'post.logout.redirect.uris': origin + GRAFANA_LOGIN_PATH,
        },
        'defaultClientScopes': list(DEFAULT_SCOPES),
        'optionalClientScopes': [],
        'protocolMappers': [groups_mapper()],
    }
    if with_secret:
        client['secret'] = env_secret(GRAFANA_SECRET_KEY)
    return client


def grafana_role_expression(values):
    """realm.ini's role_attribute_path: the JMESPath expression sso/configure.py:131-136 builds
    (back-quoted JSON literals are string literals), with the realm's group names; equal to the
    value verified live on the fixture (lab6/evidence/realm.ini:28)."""
    def contains(group):
        return f'contains({GROUPS_CLAIM}[*], `{json.dumps(group)}`)'
    return (f"{contains(values['admin_group'])} && 'Admin' || "
            f"{contains(values['viewer_group'])} && 'Viewer' || ''")


def grafana_ini(values):
    """The text of monitoring/auth/realm.ini from settings(): Grafana signs in through the Krate
    realm, served at /grafana/ by the cluster proxy. Content verified live on the lab6 fixture
    (harness/phase4/lab6/evidence/realm.ini) with the two planned deviations: the client secret is
    read from the rendered file ($__file{/etc/krate/grafana/client-secret}; monitoring-init renders
    GRAFANA_OAUTH_CLIENT_SECRET there, plan commit 5 — the value never enters this file) and the
    cluster CA is the compose-mounted /etc/krate/ca/server.crt (plan commits 5 and 7).

    Key anchors, Grafana v12.2.0 conf/defaults.ini (harness/phase4/grafana-src/grafana-v12.2.0):
    [server] root_url:60 serve_from_sub_path:63; [security] cookie_secure:384 cookie_samesite:387;
    [auth] disable_login:605 login_maximum_inactive_lifetime_duration:608
    login_maximum_lifetime_duration:611 disable_login_form:617 signout_redirect_url:623;
    [auth.basic] enabled:920; [auth.generic_oauth] 878-916 (name:879 enabled:881 allow_sign_up:882
    client_id:884 client_secret:885 scopes:886 login_attribute_path:890 role_attribute_path:892
    role_attribute_strict:893 groups_attribute_path:896 auth_url:899 token_url:900 api_url:901
    tls_skip_verify_insecure:908 tls_client_ca:911 use_pkce:912 allow_assign_grafana_admin:914
    skip_org_role_sync:915 use_refresh_token:916); [sso_settings] configurable_providers:686;
    [auth.anonymous] hide_version:700; [metrics] enabled:1729; [snapshots] enabled:457;
    [public_dashboards] enabled:2161; [news] news_feed_enabled:1708; [dashboards]
    default_home_dashboard_path:479.

    Why the non-default values: the session lifetimes are the realm's (one source:
    KEYCLOAK_SESSION_IDLE_MINUTES / KEYCLOAK_SESSION_MAX_HOURS; Grafana's own defaults are 7d/30d,
    research-grafana.md 4.1). disable_login closes every Grafana-password path even against a
    GF_* override, and [auth.basic] enabled=false because Basic does not depend on
    disable_login_form (research-grafana.md, section 4 rows). role_attribute_strict=true refuses a
    login whose groups map to no role instead of falling back to Viewer (research-grafana.md 2.2).
    use_pkce=true: generic_oauth sends no nonce, PKCE is the flow's protection
    (research-grafana.md 1.4). tls_client_ca + tls_skip_verify_insecure=false: generic_oauth in
    12.2.0 has no ID-token signature validation, so the IdP trust is the TLS-protected back
    channel to token_url/api_url (research-grafana.md 1.2). configurable_providers=none keeps a
    DB-stored SSO setting from overriding this file (research-grafana.md 1.12). metrics off and
    hide_version/public_dashboards/snapshots/news off: no unauthenticated surface, no external
    fetch, and U17 refuses the realm switch while public dashboards or snapshots hold content.
    default_home_dashboard_path: the stock Home's news panel fetches grafana.com even with
    news_feed_enabled=false (lab6 L5-3, finding 3).
    """
    origin = values['public_origin']
    endpoints = origin + '/identity/realms/' + REALM + '/protocol/openid-connect/'
    signout = (endpoints + 'logout?post_logout_redirect_uri='
               + quote(origin + GRAFANA_LOGIN_PATH, safe='') + '&client_id=' + GRAFANA_CLIENT)
    secret_ref = '$__file{' + GRAFANA_SECRET_FILE + '}'
    return f"""; Generated by Krate: Grafana signs in through the Krate realm (KEYCLOAK_PUBLIC_URL), served at /grafana/ by the cluster proxy.
[server]
root_url = {origin}{GRAFANA_ROOT_PATH}
serve_from_sub_path = true
[security]
cookie_secure = true
cookie_samesite = lax
[auth]
disable_login_form = true
disable_login = true
login_maximum_inactive_lifetime_duration = {values['session_idle_minutes']}m
login_maximum_lifetime_duration = {values['session_max_hours']}h
signout_redirect_url = {signout}
[auth.basic]
enabled = false
[auth.generic_oauth]
enabled = true
name = {GRAFANA_SIGNIN_NAME}
allow_sign_up = true
client_id = {GRAFANA_CLIENT}
client_secret = {secret_ref}
scopes = {' '.join(UI_OIDC_SCOPES)}
auth_url = {endpoints}auth
token_url = {endpoints}token
api_url = {endpoints}userinfo
login_attribute_path = sub
groups_attribute_path = {GROUPS_CLAIM}
role_attribute_path = {grafana_role_expression(values)}
role_attribute_strict = true
skip_org_role_sync = false
allow_assign_grafana_admin = false
use_pkce = true
use_refresh_token = true
tls_skip_verify_insecure = false
tls_client_ca = {GRAFANA_TLS_CA_FILE}
[sso_settings]
configurable_providers = none
[metrics]
enabled = false
[auth.anonymous]
hide_version = true
[public_dashboards]
enabled = false
[snapshots]
enabled = false
[news]
news_feed_enabled = false
[dashboards]
default_home_dashboard_path = {GRAFANA_HOME_DASHBOARD}
"""


def perses_port(env):
    """PERSES_PORT from the parsed monitoring .env: the port the Perses origin is published on.
    Same default and same validation as render.py:387-389, so the client's redirect URIs and the
    rendered gateway config can never disagree."""
    value = env.get(PERSES_PORT_KEY, PERSES_PORT_DEFAULT)
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError(PERSES_PORT_KEY + ' must be a port number from 1 to 65535')
    return int(value)


def perses_origin(origin, port):
    """The Perses public origin: the KEYCLOAK_PUBLIC_URL host on PERSES_PORT (plan commit 7:
    realm_site public_url = https://<host of KEYCLOAK_PUBLIC_URL>:<PERSES_PORT>); an IPv6 host
    keeps its brackets."""
    host = urlsplit(origin).hostname or ''
    return 'https://' + ('[' + host + ']' if ':' in host else host) + ':' + str(port)


def perses_client(origin, port, with_secret=False):
    """The krate-perses client representation: krate-ui's shape with the two callbacks of the
    Perses origin (verified live: lab2/kcadmin.py:64-87, readback lab2/logs/020-realm-setup.log,
    lab7/results.md:30).

    The redirect URIs are oauth2-proxy's callback (proxy-prefix default /oauth2, oauth2-proxy
    v7.15.5 oauthproxy.go:177 with pkg/apis/options/options.go:146) and Perses' native-OIDC
    callback /api/auth/providers/oidc/<slug>/callback (perses v0.54.0
    internal/api/impl/auth/auth.go:80 with internal/api/utils/utils.go:26,28,30; the slug is
    render.py's `krate`). post.logout.redirect.uris carries the origin with and without the
    trailing slash, joined with `##` like ui_client_attributes: the verified one-logout chain
    ends on <origin>/ (lab7/results.md:117). No backchannel.logout.url: the single logout is the
    gateway's redirect chain (plan commit 9). The secret comes from the environment only
    (OAUTH2_PROXY_CLIENT_SECRET — the same key render.py:496 renders for oauth2-proxy).
    """
    base = perses_origin(origin, port)
    client = {
        'clientId': PERSES_CLIENT, 'name': PERSES_CLIENT_NAME, 'enabled': True,
        'protocol': 'openid-connect', 'publicClient': False,
        'clientAuthenticatorType': 'client-secret',
        'standardFlowEnabled': True, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
        'frontchannelLogout': False,
        'redirectUris': [base + '/oauth2/callback',
                         base + '/api/auth/providers/oidc/' + PERSES_OIDC_SLUG + '/callback'],
        'webOrigins': [base],
        'attributes': {'pkce.code.challenge.method': 'S256',
                       'post.logout.redirect.uris': base + '##' + base + '/'},
        'defaultClientScopes': list(DEFAULT_SCOPES),
        'optionalClientScopes': [],
        'protocolMappers': [groups_mapper()],
    }
    if with_secret:
        client['secret'] = env_secret(PERSES_SECRET_KEY)
    return client


def perses_sync_client(with_secret=False):
    """The krate-perses-sync client representation: krate-cli's shape without the realm-management
    roles — the guard authenticates with its service account only and manages no users (verified
    live: lab2/kcadmin.py:90-101, lab2/results.md:34). The secret comes from the environment only
    (PERSES_SYNC_CLIENT_SECRET, the key render.py reads for the perses-sync output).

    Its default scopes state SERVICE_ACCOUNT_SCOPE: Keycloak adds that scope to a client the
    moment serviceAccountsEnabled is true, so the readback carries it, and a plan without it
    would make every later `krate monitor up` report scopes-differ for a client nobody changed.
    The scope is listed on create too: Keycloak's add is idempotent (JpaRealmProvider.addClientScopes
    skips a scope the client already has)."""
    client = {
        'clientId': PERSES_SYNC_CLIENT, 'name': PERSES_SYNC_CLIENT_NAME, 'enabled': True,
        'protocol': 'openid-connect', 'publicClient': False,
        'clientAuthenticatorType': 'client-secret',
        'standardFlowEnabled': False, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': True,
        'redirectUris': [], 'webOrigins': [],
        'defaultClientScopes': DEFAULT_SCOPES + [SERVICE_ACCOUNT_SCOPE],
        'optionalClientScopes': [],
    }
    if with_secret:
        client['secret'] = env_secret(PERSES_SYNC_SECRET_KEY)
    return client


def perses_clients(origin, port, with_secret=False):
    """Both Perses realm clients, in the order the reconcile converges them."""
    return [perses_client(origin, port, with_secret), perses_sync_client(with_secret)]


def perses_rep(name, origin, port, with_secret=False):
    """The planned representation of the one Perses client `name`."""
    if name == PERSES_CLIENT:
        return perses_client(origin, port, with_secret)
    if name == PERSES_SYNC_CLIENT:
        return perses_sync_client(with_secret)
    raise ValueError('client must be ' + PERSES_CLIENT + ' or ' + PERSES_SYNC_CLIENT)


def _mappers_differ(wanted, current):
    """Planned mappers matched by name; Keycloak's own additions (the mapper id) are ignored, and
    so is a mapper Keycloak carries beyond the plan — differs()'s subset discipline, because the
    reconcile PUTs the planned set rather than deleting foreign mappers."""
    if not isinstance(current, list):
        return True
    by_name = {mapper.get('name'): mapper for mapper in current if isinstance(mapper, dict)}
    return any(differs(mapper, by_name.get(mapper.get('name'))) for mapper in wanted)


def _set_field_differs(wanted, current):
    """Order-insensitive list equality for the fields Keycloak stores as sets: its readback
    reorders redirectUris (created /oauth2/callback first, read back second —
    lab2/logs/020-realm-setup.log:43-46), so a positional compare would never converge."""
    if not isinstance(current, list) or not all(isinstance(item, str) for item in current):
        return True
    return sorted(wanted) != sorted(current)


def client_differs(wanted, current):
    """True when Keycloak's current client representation lacks or differs in any field the
    reconcile converges (CLIENT_VERDICT_FIELDS), or in the secret when present in both: a secret
    Keycloak masked with ********** counts as equal because the admin API never returns the value.
    Keycloak's own additions (id, internalId, realm_client, its default backchannel.logout.*
    attributes) are ignored — differs()'s discipline."""
    if not isinstance(current, dict):
        return True
    for field in CLIENT_VERDICT_FIELDS:
        if field not in wanted:
            continue
        have = current.get(field)
        if field == 'protocolMappers':
            if _mappers_differ(wanted[field], have):
                return True
        elif field in CLIENT_SET_FIELDS:
            if _set_field_differs(wanted[field], have):
                return True
        elif differs(wanted[field], have):
            return True
    if 'secret' in wanted and 'secret' in current:
        if current['secret'] != KEYCLOAK_SECRET_MASK and wanted['secret'] != current['secret']:
            return True
    return False


def _scopes(rep):
    """The client's scope lists in a comparable (sorted) form; anything malformed counts as []."""
    result = []
    for field in CLIENT_SCOPE_FIELDS:
        value = rep.get(field)
        result.append(sorted(value) if isinstance(value, list)
                      and all(isinstance(item, str) for item in value) else [])
    return result


def scopes_differ(wanted, current):
    """True when the current client scopes are not the planned ones, compared order-insensitively
    (Keycloak returns them in its own order). The caller reports this instead of converging it: a
    client PUT never changes scopes."""
    if not isinstance(current, dict):
        return True
    return _scopes(wanted) != _scopes(current)


def client_verdict(wanted, current):
    """The client-differs contract: one `same`/`differs` line for the converged fields, plus a
    `scopes-differ` line when the scopes drifted (reported by the caller, never converged)."""
    sys.stdout.write(('differs' if client_differs(wanted, current) else 'same') + '\n')
    if scopes_differ(wanted, current):
        sys.stdout.write('scopes-differ\n')


# ─── CLI ───────────────────────────────────────────────────────────────────────

def cmd_plan(args):
    plan(args.env_file, args.output, args.show)
    return 0



def cmd_runtime(args):
    runtime_plan(args.env_file, args.clusters, args.output, args.force, args.show)
    return 0


def cmd_grafana_client(args):
    """The krate-grafana representation for the CLI's reconcile, or the client-differs verdict on
    Keycloak's current representation from stdin. With --with-secret the output is piped to kcadm
    only (stdin -> kcadm, never argv or a log); the verdict lines carry no value at all."""
    origin = checked_origin(args.origin)
    if args.item == 'client-differs':
        # The secret takes part in the verdict: without it a rotated
        # GRAFANA_OAUTH_CLIENT_SECRET is undetectable, so Keycloak would keep the old
        # value while the rendered file carries the new one and every sign-in failed
        # invalid_client. Keycloak returns the real secret to a master admin
        # (ClientResource.java:210-217 at 26.8.0), and a masked readback is treated as equal.
        client_verdict(grafana_client(origin, args.with_secret), json.load(sys.stdin))
    else:
        # input (KCADM_STDIN=1 kcadm … -f -), never a terminal, log or command line: it is the
        # mechanism that keeps the secret off argv, which the gate proves by sampling ps.
        # Same pattern as `broker provider --with-secret` on main.
        # codeql[py/clear-text-logging-sensitive-data]
        sys.stdout.write(render(grafana_client(origin, args.with_secret)))  # codeql[py/clear-text-logging-sensitive-data]
    return 0


def cmd_grafana_ini(args):
    """Render monitoring/auth/realm.ini from the edition .env; refuses a loopback public host."""
    env = read_env(args.env_file)
    refuse_loopback_public_url(env.get('KEYCLOAK_PUBLIC_URL'))
    text = grafana_ini(settings(env))
    assert_redacted(text, env, 'realm.ini')
    if args.output:
        write_if_changed(args.output, text, 0o644)
        print(args.output)
    else:
        # client secret is a $__file{} reference to the rendered file, and assert_redacted above
        # has already refused to emit any .env secret. The CLI redirects this into the file.
        # codeql[py/clear-text-logging-sensitive-data]
        sys.stdout.write(text)  # codeql[py/clear-text-logging-sensitive-data]
    return 0


def cmd_perses_clients(args):
    """The Perses client representations for the CLI's reconcile (one with --client, a JSON array
    of both without), or the client-differs verdict on Keycloak's current representation of one
    client from stdin. PERSES_PORT comes from monitoring/.env, the public URL from the edition
    .env; secrets travel --with-secret -> stdin -> kcadm only."""
    origin = public_origin(read_env(args.env_file).get('KEYCLOAK_PUBLIC_URL'))
    port = perses_port(read_env(args.monitor_env_file))
    if args.item == 'client-differs':
        if not args.name:
            raise ValueError('client-differs names the client: ' + PERSES_CLIENT + ' or ' + PERSES_SYNC_CLIENT)
        # With the secret, exactly as cmd_grafana_client does: without it a rotated
        # OAUTH2_PROXY_CLIENT_SECRET or PERSES_SYNC_CLIENT_SECRET is undetectable, so Keycloak
        # would keep the old value while the rendered file carries the new one.
        client_verdict(perses_rep(args.name, origin, port, args.with_secret), json.load(sys.stdin))
        return 0
    if args.client:
        # input (KCADM_STDIN=1 kcadm … -f -), never a terminal, log or command line: it is the
        # mechanism that keeps the secret off argv, which the gate proves by sampling ps.
        # Same pattern as `broker provider --with-secret` on main.
        # codeql[py/clear-text-logging-sensitive-data]
        sys.stdout.write(render(perses_rep(args.client, origin, port, args.with_secret)))  # codeql[py/clear-text-logging-sensitive-data]
    else:
        # input (KCADM_STDIN=1 kcadm … -f -), never a terminal, log or command line: it is the
        # mechanism that keeps the secret off argv, which the gate proves by sampling ps.
        # Same pattern as `broker provider --with-secret` on main.
        # codeql[py/clear-text-logging-sensitive-data]
        sys.stdout.write(render(perses_clients(origin, port, args.with_secret)))  # codeql[py/clear-text-logging-sensitive-data]
    return 0


def cmd_db_tls(args):
    if args.renew_server:
        expiry, renewed_ca = renew_server(args.output_dir)
        print(('renewed CA and server certificate' if renewed_ca else 'renewed server certificate') + f', valid until {expiry}')
        return 0
    if args.rollback:
        print('restored previous ' + ', '.join(rollback(args.output_dir)))
        return 0
    if args.discard_previous:
        print('discarded ' + (', '.join(discard_previous(args.output_dir)) or 'nothing'))
        return 0
    written = db_tls(args.output_dir)
    if written:
        print(f"Database TLS material: wrote {', '.join(written)} in {args.output_dir}")
    else:
        print(f'Database TLS material: No changes in {args.output_dir}')
    return 0


# ─── Backup integrity (encrypt-then-MAC) ───────────────────────────────────────
# `openssl enc` cannot produce an authenticated mode ("This command does not
# support authenticated encryption modes like CCM and GCM", openssl-enc(1)), so
# the CLI encrypts with AES-256-CBC and this module seals the ciphertext with an
# HMAC-SHA256 whose key is derived separately from the same passphrase. The tag
# is verified before any byte is decrypted, unpacked or restored.
BACKUP_MAGIC = b'krate-identity-backup/1\n'
BACKUP_MAC_SALT = b'krate-identity-backup-mac:'
BACKUP_ITERATIONS = 600000
BACKUP_PASSPHRASE_ENV = 'KRATE_BACKUP_PASSPHRASE'
OPENSSL_SALTED = b'Salted__'


def backup_mac_key(passphrase, salt):
    """Independent MAC key: PBKDF2-HMAC-SHA256 over a salt that differs from openssl's own derivation."""
    return hashlib.pbkdf2_hmac('sha256', passphrase, BACKUP_MAC_SALT + salt, BACKUP_ITERATIONS, 32)


def backup_seal(ciphertext, passphrase):
    """Return magic || ciphertext || HMAC-SHA256(ciphertext) for an openssl `Salted__` ciphertext."""
    if not ciphertext.startswith(OPENSSL_SALTED) or len(ciphertext) < 32:
        raise ValueError('ciphertext is not an openssl enc -salt output')
    tag = hmac.new(backup_mac_key(passphrase, ciphertext[8:16]), ciphertext, hashlib.sha256).digest()
    return BACKUP_MAGIC + ciphertext + tag


def backup_open(sealed, passphrase):
    """Verify the tag and return the ciphertext; any mismatch raises before decryption."""
    if not sealed.startswith(BACKUP_MAGIC) or len(sealed) < len(BACKUP_MAGIC) + 32 + 32:
        raise ValueError('not a krate identity backup')
    body = sealed[len(BACKUP_MAGIC):]
    ciphertext, tag = body[:-32], body[-32:]
    if not ciphertext.startswith(OPENSSL_SALTED):
        raise ValueError('not a krate identity backup')
    expected = hmac.new(backup_mac_key(passphrase, ciphertext[8:16]), ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError('integrity check failed: the backup was modified or the passphrase is wrong')
    return ciphertext


BACKUP_CHUNK = 1024 * 1024


def backup_seal_file(source, output, passphrase):
    """Stream magic || ciphertext || HMAC-SHA256(ciphertext) from `source` to `output` (one chunk in memory)."""
    source, output = Path(source), Path(output)
    size = source.stat().st_size
    with source.open('rb') as src:
        head = src.read(16)
        if not head.startswith(OPENSSL_SALTED) or size < 32:
            raise ValueError('ciphertext is not an openssl enc -salt output')
        mac = hmac.new(backup_mac_key(passphrase, head[8:16]), digestmod=hashlib.sha256)
        src.seek(0)
        fd, tmp = tempfile.mkstemp(prefix='.seal-', dir=output.parent)
        try:
            with os.fdopen(fd, 'wb') as dst:
                os.fchmod(fd, 0o600)
                dst.write(BACKUP_MAGIC)
                while True:
                    chunk = src.read(BACKUP_CHUNK)
                    if not chunk:
                        break
                    mac.update(chunk)
                    dst.write(chunk)
                dst.write(mac.digest())
            os.replace(tmp, output)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


def backup_open_file(sealed, output, passphrase):
    """Verify the trailing tag while streaming the ciphertext to `output`; a mismatch removes the output."""
    sealed, output = Path(sealed), Path(output)
    size = sealed.stat().st_size
    minimum = len(BACKUP_MAGIC) + 32 + 32
    with sealed.open('rb') as src:
        head = src.read(len(BACKUP_MAGIC) + 16)
        if size < minimum or not head.startswith(BACKUP_MAGIC) or not head[len(BACKUP_MAGIC):].startswith(OPENSSL_SALTED):
            raise ValueError('not a krate identity backup')
        salt = head[len(BACKUP_MAGIC) + 8:len(BACKUP_MAGIC) + 16]
        src.seek(size - 32)
        tag = src.read(32)
        mac = hmac.new(backup_mac_key(passphrase, salt), digestmod=hashlib.sha256)
        src.seek(len(BACKUP_MAGIC))
        remaining = size - len(BACKUP_MAGIC) - 32
        fd, tmp = tempfile.mkstemp(prefix='.open-', dir=output.parent)
        try:
            with os.fdopen(fd, 'wb') as dst:
                os.fchmod(fd, 0o600)
                while remaining > 0:
                    chunk = src.read(min(BACKUP_CHUNK, remaining))
                    if not chunk:
                        raise ValueError('not a krate identity backup')
                    remaining -= len(chunk)
                    mac.update(chunk)
                    dst.write(chunk)
            if not hmac.compare_digest(mac.digest(), tag):
                raise ValueError('integrity check failed: the backup was modified or the passphrase is wrong')
            os.replace(tmp, output)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


def backup_passphrase():
    value = os.environ.get(BACKUP_PASSPHRASE_ENV, '')
    if not value:
        raise ValueError(f'{BACKUP_PASSPHRASE_ENV} is not set')
    return value.encode()


def cmd_backup_seal(args):
    backup_seal_file(args.input, args.output, backup_passphrase())
    return 0


def cmd_backup_open(args):
    backup_open_file(args.input, args.output, backup_passphrase())
    return 0


def main():
    parser = argparse.ArgumentParser(description=(__doc__ or '').splitlines()[0])
    commands = parser.add_subparsers(dest='command', required=True)
    planner = commands.add_parser('plan', help='write the local realm plan from .env values')
    planner.add_argument('--env-file', type=Path, required=True)
    planner.add_argument('--output', type=Path, required=True)
    planner.add_argument('--print', dest='show', action='store_true', help='also print the plan JSON')
    planner.set_defaults(func=cmd_plan)
    kafbat = commands.add_parser('runtime', help="write Kafbat's auth/ui/runtime.yml (Keycloak login) from .env values")
    kafbat.add_argument('--env-file', type=Path, required=True)
    kafbat.add_argument('--clusters', nargs='+', required=True, metavar='NAME', help='Kafbat cluster names the roles apply to')
    kafbat.add_argument('--output', type=Path, required=True)
    kafbat.add_argument('--force', action='store_true', help='replace an existing runtime.yml that differs from the plan')
    kafbat.add_argument('--print', dest='show', action='store_true', help='also print the plan JSON')
    kafbat.set_defaults(func=cmd_runtime)
    tls = commands.add_parser('db-tls', help='generate CA, server certificate and pg_hba.conf for keycloak-db')
    tls.add_argument('--output-dir', type=Path, required=True)
    tls.add_argument('--renew-server', action='store_true',
                     help=f'reissue server.key and server.crt ({SERVER_CERT_DAYS} days); the CA too when it would expire first')
    tls.add_argument('--rollback', action='store_true', help='put the .prev files of the last renewal back')
    tls.add_argument('--discard-previous', action='store_true', help='remove the .prev files after a successful renewal')
    tls.set_defaults(func=cmd_db_tls)
    seal = commands.add_parser('backup-seal', help='append an HMAC-SHA256 tag to an openssl ciphertext (passphrase from env)')
    seal.add_argument('--input', type=Path, required=True)
    seal.add_argument('--output', type=Path, required=True)
    seal.set_defaults(func=cmd_backup_seal)
    opener = commands.add_parser('backup-open', help='verify a sealed backup and write the ciphertext for decryption')
    opener.add_argument('--input', type=Path, required=True)
    opener.add_argument('--output', type=Path, required=True)
    opener.set_defaults(func=cmd_backup_open)
    broker = commands.add_parser('broker', help='read one item of the PingFederate broker plan for krate auth apply')
    broker.add_argument('--plan', type=Path, required=True)
    broker.add_argument('item', choices=['provider', 'provider-differs', 'mappers', 'mapper-differs', 'flows', 'executions',
                                         'config', 'config-differs', 'browser-flow'])
    broker.add_argument('name', nargs='?', default='', help='flow alias, mapper name or config alias the item refers to')
    broker.add_argument('--with-secret', action='store_true',
                        help=f'substitute {BROKER_SECRET_KEY} from the environment into the provider (output is piped to kcadm)')
    broker.set_defaults(func=cmd_broker)
    gclient = commands.add_parser('grafana-client', help='the krate-grafana client representation for krate monitor realm')
    gclient.add_argument('--origin', required=True, help='public origin: KEYCLOAK_PUBLIC_URL without /identity')
    gclient.add_argument('item', nargs='?', choices=['client-differs'], default=None,
                         help="client-differs: same/differs verdict on Keycloak's representation from stdin")
    gclient.add_argument('--with-secret', action='store_true',
                         help=f'substitute {GRAFANA_SECRET_KEY} from the environment into the client (output is piped to kcadm)')
    gclient.set_defaults(func=cmd_grafana_client)
    gini = commands.add_parser('grafana-ini', help="render Grafana's realm.ini (Keycloak sign-in) from .env values")
    gini.add_argument('--env-file', type=Path, required=True)
    gini.add_argument('--output', type=Path, help='write the ini here (0644) and print the path instead of the text')
    gini.set_defaults(func=cmd_grafana_ini)
    pclients = commands.add_parser('perses-clients', help='the krate-perses client representations for krate monitor up')
    pclients.add_argument('--env-file', type=Path, required=True, help='edition .env (KEYCLOAK_PUBLIC_URL)')
    pclients.add_argument('--monitor-env-file', type=Path, required=True, help='monitoring/.env (PERSES_PORT)')
    pclients.add_argument('--client', choices=[PERSES_CLIENT, PERSES_SYNC_CLIENT], default=None,
                          help='print one client representation instead of a JSON array of both')
    pclients.add_argument('item', nargs='?', choices=['client-differs'], default=None,
                          help="client-differs NAME: verdict on Keycloak's representation of NAME from stdin")
    pclients.add_argument('name', nargs='?', choices=[PERSES_CLIENT, PERSES_SYNC_CLIENT], default=None,
                          help='the client name client-differs refers to')
    pclients.add_argument('--with-secret', action='store_true',
                          help=f'substitute {PERSES_SECRET_KEY} / {PERSES_SYNC_SECRET_KEY} from the environment (output is piped to kcadm)')
    pclients.set_defaults(func=cmd_perses_clients)
    digest = commands.add_parser('truststore-digest', help='digest of the PEM files Keycloak loads from a truststores directory')
    digest.add_argument('--directory', type=Path, required=True)
    digest.set_defaults(func=cmd_truststore_digest)
    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'Identity {args.command} failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
