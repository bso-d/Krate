#!/usr/bin/env python3
"""Host-side Grafana admin API helper for the krate CLI.

`krate monitor realm`, `krate monitor grafana-user retire` and `krate monitor
up` (seed-token renewal, and ending the sessions a sign-in switch leaves
behind) call this program instead of curl: no password or token may ever
appear on a command line, so every credential is read from the environment
and nothing secret is accepted as an argument.

Environment (the only credential source; no defaults, no argv, no stdin):

  GRAFANA_URL                    base URL, e.g. http://127.0.0.1:3000
  GRAFANA_SERVICE_ACCOUNT_TOKEN  Bearer token; when set it is preferred
  GRAFANA_ADMIN_USER             HTTP Basic user (local-mode admin), used
  GRAFANA_ADMIN_PASSWORD         with GRAFANA_ADMIN_USER
  GRAFANA_CA_FILE                optional CA bundle used to verify an https
                                 GRAFANA_URL (the cluster certificate is
                                 self-signed). There is deliberately no
                                 insecure mode: verification is never
                                 disabled and unknown issuers always fail.

Every invocation prints exactly one JSON document on stdout and exits 0, or
prints one line naming the operation, the HTTP status and the endpoint path on
stderr and exits 1. Error messages never carry a credential, a token value or
a response body. The only secret this program ever prints is the `key` field
of `token-create`, on stdout, for the caller's pipe.

Subcommands (the contract implemented for the krate Bash callers):

  reads
      {"sso_settings_source": str|null, "public_dashboards": int,
       "snapshots": int[, "notes": [str, ...]]}
      GET /api/v1/sso-settings/generic_oauth, GET
      /api/dashboards/public-dashboards?perpage=1 (totalCount), GET
      /api/dashboard/snapshots?limit=1000 (array length). A 403/404 on any of
      the three degrades to null/0 with a note instead of failing: the realm
      lock answers 404 on sso-settings (configurable_providers = none) and on
      public dashboards (feature off), and 403 on snapshots (snapshots off),
      and a service-account token gets 403 on sso-settings (settings:read).

  local-users
      [{"login": str, "email": str, "isDisabled": bool,
        "isGrafanaAdmin": bool, "authClass": "local"|"external"}, ...]
      Legacy command name: all human users remain visible. Corroborates list
      authLabels with profile isExternal; unknown/conflicting metadata refuses.
      GET /api/users, then GET /api/users/:id per user because the list DTO
      carries only the org-admin flag (isAdmin), not isGrafanaAdmin.

  retire-user --login LOGIN [--email-suffix SUFFIX]
      {"login": str, "email": str, "disabled": true}
      Sets the user's e-mail to <login base><suffix> (PUT /api/users/:id,
      keeping login and name) and disables it (POST
      /api/admin/users/:id/disable). The base is the login itself, or for an
      email-shaped login its local part, so the result is always a valid
      address: jane@example.com -> jane+retired@invalid, never the double-@
      jane@example.com+retired@invalid (see retired_email). The suffix
      defaults to +retired@invalid so the literal lives only here.
      Both steps are needed: a disabled-only user still collides with the
      realm e-mail and the OAuth sign-in fails with "User sync failed"
      (lab6 L5-5). Idempotent: a second run re-applies the same values.

  service-account --name NAME --role {Viewer,Editor,Admin}
      {"id": int, "created": bool}
      GET /api/serviceaccounts/search?query=NAME; creates (POST
      /api/serviceaccounts) only when no exact-name match exists. An existing
      account is reused only when it carries the requested role; a role drift
      fails with a remediation instead of letting alert seeding run into
      authorization failures later (PR #42 review).

  token-create --account-id N --days D
      {"id": int, "name": str, "expires": int|null, "key": str}
      Token named krate-seed-<UTC yyyymmddThhmmss> with secondsToLive
      D*86400 (POST /api/serviceaccounts/N/tokens). `expires` is the epoch of
      the API's own `expiration` value, read back through GET
      /api/serviceaccounts/N/tokens (RFC 3339 UTC, e.g.
      "2027-01-10T14:37:58Z"). The key goes to stdout only.

  token-list --account-id N
      [{"id": int, "name": str, "expiration": str|null}, ...]
      GET /api/serviceaccounts/N/tokens; `expiration` exactly as the API
      returns it. Callers compute the epoch themselves (see token-create for
      the observed format).

  token-delete --account-id N --token-id T
      {"deleted": int[, "note": str]}
      DELETE /api/serviceaccounts/N/tokens/T. An already-absent token is a
      success and says so in `note`. A non-existent service account is a hard
      failure: GET /api/serviceaccounts/N/tokens answers 200 [] for unknown
      accounts too, so the account is verified (GET /api/serviceaccounts/N)
      before an absence is believed.

  end-sessions --scope {all,external} [--wait-seconds N]
      {"scope": str, "users_in_scope": int, "users_ended": int,
       "sessions_ended": int}
      Ends the Grafana sessions (auth tokens) a sign-in switch leaves behind.
      Grafana keeps them in its database, which survives the recreate that
      applies a new GRAFANA_AUTH_CONFIG, so a browser that signed in before the
      switch would stay signed in after it. `krate monitor up` calls this with
      the local-mode Basic admin: scope `all` BEFORE the recreate that applies
      realm.ini (all human users, including the local admin), scope `external`
      right AFTER the recreate that returns to local.ini (users with any external
      login, including Krate sign-in users). This classifies users, not current
      realm ownership or the origin of each session. The
      user endpoints it needs are server-admin endpoints: a service-account
      token cannot call them and realm mode turns Basic off, which is why the
      caller runs it in local mode.
      GET /api/user (the caller's own id), GET /api/users (every user: Grafana's
      list excludes service accounts in SQL, grafana-v12.2.0
      pkg/services/user/userimpl/store.go:482-483, and an entry flagged
      isServiceAccount is skipped as a second guard; a service account holds no
      browser session, only API tokens, which this never touches), GET
      /api/users/:id for isExternal (scope external only; pkg/api/user.go:87),
      then per user GET /api/admin/users/:id/auth-tokens. A user with sessions
      gets POST /api/admin/users/:id/logout, which revokes all of its auth
      tokens (pkg/api/user_token.go:163); the caller's own user cannot use it
      (400 "You cannot logout yourself", pkg/api/admin_users.go:370-372, and the
      Basic admin's identity id is its numeric user id, pkg/services/authn/
      clients/grafana.go:119), so its tokens go one by one through POST
      /api/admin/users/:id/revoke-auth-token {"authTokenId": N}, which only
      refuses an active session token (user_token.go:270-271) and Basic
      authentication has none. The user's token list is read again and must be
      empty: a user that still has a session fails the command, so the caller
      can refuse to finish the switch. `sessions_ended` and `users_ended` count
      what was listed before the revocation, users with no session are not
      counted, and no login or e-mail is ever printed. --wait-seconds N first
      polls GET /api/health until Grafana answers (it may be starting, or the
      caller has just recreated it) and gives up once N seconds have passed:
      a single attempt can itself take up to the 30 s request timeout.

Python 3.9 (RHEL 9 host) compatible; standard library only.
"""

import argparse
import base64
import datetime
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROGRAM = 'grafana-admin'
TIMEOUT_SECONDS = 30
SNAPSHOT_LIST_LIMIT = 1000
USER_PAGE_SIZE = 1000
SERVICE_ACCOUNT_PAGE_SIZE = 1000
HEALTH_POLL_SECONDS = 2
SESSION_SCOPES = ('all', 'external')
TOKEN_NAME_PREFIX = 'krate-seed-'
DEFAULT_EMAIL_SUFFIX = '+retired@invalid'
ORG_ROLES = ('Viewer', 'Editor', 'Admin')


class HttpFailure(Exception):
    """A non-2xx HTTP status; the rendered message never contains a body.

    `detail` is the parsed `message` field of the error response, kept for
    internal classification only (e.g. telling a duplicate token name from
    any other 400). It is never rendered into an error line.
    """

    def __init__(self, status, method, path, detail=None):
        super().__init__('HTTP %d for %s %s' % (status, method, path))
        self.status = status
        self.method = method
        self.path = path
        self.detail = detail


class OperationError(Exception):
    """A failure whose message is safe to print (no body, no credential)."""


def fail(operation, message):
    sys.stderr.write('%s: %s: %s\n' % (PROGRAM, operation, message))
    sys.exit(1)


def resolve_config(_operation=None):
    """Read connection and credentials from the environment only."""
    url = os.environ.get('GRAFANA_URL', '').strip()
    if not url:
        raise OperationError(
            'GRAFANA_URL is not set (for example GRAFANA_URL=http://127.0.0.1:3000); '
            'this program never assumes a default')
    parsed = urllib.parse.urlsplit(url.rstrip('/'))
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise OperationError('GRAFANA_URL must be an http:// or https:// URL with a host')

    token = os.environ.get('GRAFANA_SERVICE_ACCOUNT_TOKEN', '')
    if token:
        authorization = 'Bearer ' + token
    else:
        user = os.environ.get('GRAFANA_ADMIN_USER', '')
        password = os.environ.get('GRAFANA_ADMIN_PASSWORD', '')
        if not user and not password:
            raise OperationError(
                'no credentials: set GRAFANA_SERVICE_ACCOUNT_TOKEN, or both '
                'GRAFANA_ADMIN_USER and GRAFANA_ADMIN_PASSWORD')
        if not user:
            raise OperationError('GRAFANA_ADMIN_USER is not set but GRAFANA_ADMIN_PASSWORD is; '
                                 'set both, or GRAFANA_SERVICE_ACCOUNT_TOKEN instead')
        if not password:
            raise OperationError('GRAFANA_ADMIN_PASSWORD is not set or empty (GRAFANA_ADMIN_USER is set); '
                                 'set it, or use GRAFANA_SERVICE_ACCOUNT_TOKEN instead')
        encoded = base64.b64encode(('%s:%s' % (user, password)).encode()).decode()
        authorization = 'Basic ' + encoded

    context = None
    if parsed.scheme == 'https':
        # Verification is mandatory; there is no insecure mode.
        ca_file = os.environ.get('GRAFANA_CA_FILE', '')
        if ca_file:
            if not os.path.isfile(ca_file):
                raise OperationError('GRAFANA_CA_FILE %s is not a readable file' % ca_file)
            context = ssl.create_default_context(cafile=ca_file)
        else:
            context = ssl.create_default_context()
    return url.rstrip('/'), authorization, context


def error_detail(error):
    """Best-effort `message` field of an HTTP error response, for internal
    classification only (e.g. telling a duplicate name from any other 400).
    The value is never printed: by contract a caller sees only the operation,
    the status and the path, never a response body."""
    try:
        raw = error.read(4096)
        payload = json.loads(raw.decode())
    except Exception:
        return None
    message = payload.get('message') if isinstance(payload, dict) else None
    return message if isinstance(message, str) else None


def next_utc_second(previous):
    """Bounded spin until the UTC second stamp differs from `previous`."""
    stamp = previous
    while stamp == previous:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')
    return stamp


class Api:
    def __init__(self, base_url, authorization, ssl_context):
        self.base_url = base_url
        self.authorization = authorization
        self.ssl_context = ssl_context

    def request(self, method, path, body=None):
        """One API call. Returns (status, parsed JSON or None).

        Raises HttpFailure on a non-2xx status and OperationError on a
        transport failure or an unparsable body. Neither message ever
        contains the response body or a credential.
        """
        data = None
        if body is not None:
            data = json.dumps(body).encode()
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        request.add_header('Accept', 'application/json')
        request.add_header('Authorization', self.authorization)
        if data is not None:
            request.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS,
                                        context=self.ssl_context) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raise HttpFailure(error.code, method, path, error_detail(error))
        except urllib.error.URLError as error:
            raise OperationError('cannot reach %s %s: %s' % (method, path, error.reason))
        except OSError as error:
            raise OperationError('cannot reach %s %s: %s' % (method, path, error))
        if not raw:
            return status, None
        try:
            return status, json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            raise OperationError('%s %s did not return JSON (HTTP %d)' % (method, path, status))


def parse_expiration(value):
    """Epoch seconds for the API's `expiration` string, or None.

    Observed against Grafana 12.2.0: RFC 3339 UTC with second precision and a
    literal Z ("2027-01-10T14:37:58Z", lab6 logs/070-local-prep.log); null for
    never-expiring tokens. Fractional seconds and numeric offsets are accepted
    too.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        moment = datetime.datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return int(moment.timestamp())


def print_json(payload):
    sys.stdout.write(json.dumps(payload) + '\n')


def as_int(value, what):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise OperationError('unexpected response shape: %s is not an integer' % what)


def search_service_accounts(api, name):
    """Every page of the service-account search; returns the exact-name match."""
    query = urllib.parse.quote(name)
    page = 1
    seen = 0
    while True:
        _, payload = api.request(
            'GET',
            '/api/serviceaccounts/search?query=%s&page=%d&perpage=%d'
            % (query, page, SERVICE_ACCOUNT_PAGE_SIZE))
        if not isinstance(payload, dict) or not isinstance(payload.get('serviceAccounts'), list):
            raise OperationError('unexpected response shape: GET /api/serviceaccounts/search')
        accounts = payload['serviceAccounts']
        for account in accounts:
            if isinstance(account, dict) and account.get('name') == name:
                return account
        seen += len(accounts)
        total = as_int(payload.get('totalCount', 0), 'totalCount')
        if not accounts or seen >= total:
            return None
        page += 1


def list_tokens(api, account_id):
    _, payload = api.request('GET', '/api/serviceaccounts/%d/tokens' % account_id)
    if not isinstance(payload, list):
        raise OperationError('unexpected response shape: GET /api/serviceaccounts/%d/tokens' % account_id)
    return payload


def cmd_reads(api):
    notes = []
    result = {'sso_settings_source': None, 'public_dashboards': 0, 'snapshots': 0}

    try:
        _, payload = api.request('GET', '/api/v1/sso-settings/generic_oauth')
        if isinstance(payload, dict) and 'source' in payload:
            result['sso_settings_source'] = payload['source']
        else:
            raise OperationError('unexpected response shape: GET /api/v1/sso-settings/generic_oauth')
    except HttpFailure as failure:
        if failure.status in (403, 404):
            notes.append('GET /api/v1/sso-settings/generic_oauth: HTTP %d -> sso_settings_source=null'
                         % failure.status)
        else:
            raise

    try:
        _, payload = api.request('GET', '/api/dashboards/public-dashboards?perpage=1')
        if isinstance(payload, dict) and 'totalCount' in payload:
            result['public_dashboards'] = as_int(payload['totalCount'], 'totalCount')
        else:
            raise OperationError('unexpected response shape: GET /api/dashboards/public-dashboards')
    except HttpFailure as failure:
        if failure.status in (403, 404):
            notes.append('GET /api/dashboards/public-dashboards: HTTP %d -> public_dashboards=0'
                         % failure.status)
        else:
            raise

    try:
        _, payload = api.request('GET', '/api/dashboard/snapshots?limit=%d' % SNAPSHOT_LIST_LIMIT)
        if isinstance(payload, list):
            result['snapshots'] = len(payload)
            if len(payload) >= SNAPSHOT_LIST_LIMIT:
                notes.append('GET /api/dashboard/snapshots: count reached the limit=%d, it may be capped'
                             % SNAPSHOT_LIST_LIMIT)
        else:
            raise OperationError('unexpected response shape: GET /api/dashboard/snapshots')
    except HttpFailure as failure:
        if failure.status in (403, 404):
            notes.append('GET /api/dashboard/snapshots: HTTP %d -> snapshots=0' % failure.status)
        else:
            raise

    if notes:
        result['notes'] = notes
    print_json(result)


def list_users(api):
    users = []
    seen_ids = set()
    page = 1
    while True:
        path = '/api/users?perpage=%d&page=%d' % (USER_PAGE_SIZE, page)
        _, payload = api.request('GET', path)
        if not isinstance(payload, list) or len(payload) > USER_PAGE_SIZE:
            raise OperationError('unexpected response shape: GET ' + path)
        if any(not isinstance(user, dict) or 'id' not in user for user in payload):
            raise OperationError('unexpected response shape: GET ' + path + ' list entry')
        ids = [as_int(user['id'], 'user id') for user in payload]
        if len(set(ids)) != len(ids) or seen_ids.intersection(ids):
            raise OperationError('GET ' + path + ' returned duplicate user ids')
        seen_ids.update(ids)
        users.extend(payload)
        if len(payload) < USER_PAGE_SIZE:
            return users
        page += 1


def classify_user_auth(user, profile, user_id):
    """Corroborate profile external status with independent global-list labels."""
    labels = user.get('authLabels')
    external = profile.get('isExternal')
    if (not isinstance(labels, list)
            or any(not isinstance(label, str) or not label.strip() for label in labels)
            or type(external) is not bool):
        raise OperationError('unexpected Grafana authentication metadata for user %d' % user_id)
    if bool(labels) != external:
        raise OperationError('conflicting Grafana authentication metadata for user %d' % user_id)
    return 'external' if external else 'local'


def cmd_local_users(api):
    # Legacy command name: retain every human for collision review, including external users.
    users = list_users(api)
    out = []
    for user in users:
        if not isinstance(user, dict) or 'id' not in user:
            raise OperationError('unexpected response shape: GET /api/users list entry')
        if user.get('isServiceAccount') is True:
            continue
        user_id = as_int(user['id'], 'user id')
        _, profile = api.request('GET', '/api/users/%d' % user_id)
        if not isinstance(profile, dict):
            raise OperationError('unexpected response shape: GET /api/users/%d' % user_id)
        auth_class = classify_user_auth(user, profile, user_id)
        login = profile.get('login', user.get('login'))
        email = profile.get('email', user.get('email'))
        disabled = profile.get('isDisabled', user.get('isDisabled'))
        if email is None:
            email = ''
        if (not isinstance(login, str) or not login.strip()
                or not isinstance(email, str) or type(disabled) is not bool
                or any(char in login or char in email for char in '\x00\t\r\n')):
            raise OperationError('unexpected Grafana collision metadata for user %d' % user_id)
        out.append({'login': login, 'email': email, 'isDisabled': disabled,
                    'isGrafanaAdmin': bool(profile.get('isGrafanaAdmin')),
                    'authClass': auth_class})
    print_json(out)


def retired_email(login, email_suffix):
    """The retired address for `login`, valid for plain and email-shaped logins alike.

    Concatenating the suffix onto an email-shaped login yields two unquoted '@'
    characters (jane@example.com -> jane@example.com+retired@invalid), which is
    not a valid address: with SMTP and verify_email_enabled Grafana answers 400
    "Invalid email address" (grafana-v12.2.0 pkg/api/user.go:244-257, through
    mail.ParseAddress in pkg/api/utils.go:55), and with Krate's defaults
    (verify_email_enabled = false, conf/defaults.ini:537; GF_SMTP_ENABLED=false)
    it stores the invalid string unvalidated (pkg/services/user/userimpl/store.go
    only lowercases it). So for an email-shaped login the suffix tags the local
    part instead: jane@example.com -> jane+retired@invalid. A plain login keeps
    the composition the live walk verified (t-grafana-admin A12/A13):
    p4-collide -> p4-collide+retired@invalid. The result is deterministic, so a
    re-run re-applies the same value, and it lands on the reserved .invalid
    domain, so it never collides with a realm e-mail. Two retired users collide
    only when their local parts are equal across different domains; user.email
    carries a unique index (pkg/services/sqlstore/migrations/user_mig.go:41),
    so that rare case fails the PUT loudly instead of overwriting, and re-running
    with another --email-suffix resolves it.
    """
    return login.split('@', 1)[0] + email_suffix


def cmd_retire_user(api, login, email_suffix):
    users = list_users(api)
    matches = [u for u in users if isinstance(u, dict) and u.get('login') == login]
    if not matches:
        raise OperationError('no user with login %s in GET /api/users' % login)
    if len(matches) > 1:
        raise OperationError('GET /api/users returned %d users with login %s' % (len(matches), login))
    user = matches[0]
    user_id = as_int(user['id'], 'user id')
    new_email = retired_email(login, email_suffix)

    _, payload = api.request('PUT', '/api/users/%d' % user_id,
                             {'email': new_email, 'login': login, 'name': user.get('name') or ''})
    if not (isinstance(payload, dict) and payload.get('message') == 'User updated'):
        raise OperationError('PUT /api/users/%d did not confirm "User updated"; the e-mail change was '
                             'not applied (e-mail verification may be enabled on this Grafana)' % user_id)

    _, payload = api.request('POST', '/api/admin/users/%d/disable' % user_id)
    if not (isinstance(payload, dict) and payload.get('message') == 'User disabled'):
        raise OperationError('POST /api/admin/users/%d/disable did not confirm "User disabled"' % user_id)

    print_json({'login': login, 'email': new_email, 'disabled': True})


def require_account_role(account, role):
    """Refuse an exact-name account whose role differs from the requested one.

    Reusing a drifted `krate-seed` (Viewer/Editor instead of Admin) silently
    hands alert seeding a token that gets authorization failures later (PR #42
    review). The search DTO already carries the org role, so no extra call is
    needed: grafana-v12.2.0 pkg/services/serviceaccounts/models.go:87
    (ServiceAccountDTO.role), selected by the search query itself
    (pkg/services/serviceaccounts/database/store.go:381). Refuse instead of
    converge: rewriting an existing account's role could undo a deliberate
    operator choice, and the caller gets one clear remediation now instead of
    a confusing 403 during seeding. The message carries no value — neither the
    role found nor the account name — matching this program's error policy.
    """
    if account.get('role') != role:
        raise OperationError('the existing service account does not carry the requested role; '
                             'grant it that role in Grafana (Administration > Users and access > '
                             'Service accounts) or delete the account, then re-run')


def cmd_service_account(api, name, role):
    found = search_service_accounts(api, name)
    if found is not None:
        require_account_role(found, role)
        print_json({'id': as_int(found['id'], 'id'), 'created': False})
        return
    try:
        status, payload = api.request('POST', '/api/serviceaccounts', {'name': name, 'role': role})
    except HttpFailure as failure:
        if failure.status == 400:
            # A concurrent run may have created it between the search and the
            # create; Grafana answers 400 "service account already exists".
            found = search_service_accounts(api, name)
            if found is not None:
                require_account_role(found, role)
                print_json({'id': as_int(found['id'], 'id'), 'created': False,
                            'note': 'the service account appeared between search and create; reusing it'})
                return
        raise
    if status != 201 or not isinstance(payload, dict) or 'id' not in payload:
        raise OperationError('unexpected response shape: POST /api/serviceaccounts (HTTP %d)' % status)
    print_json({'id': as_int(payload['id'], 'id'), 'created': True})


def cmd_token_create(api, account_id, days):
    seconds_to_live = days * 86400
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime('%Y%m%dT%H%M%S')
    name = TOKEN_NAME_PREFIX + stamp
    try:
        _, payload = api.request('POST', '/api/serviceaccounts/%d/tokens' % account_id,
                                 {'name': name, 'secondsToLive': seconds_to_live})
    except HttpFailure as failure:
        # Two creates inside the same UTC second collide on the fixed name
        # format: Grafana answers 400 "service account token with name ...
        # already exists in the organization". Wait for the second to tick
        # over and retry once with a fresh stamp.
        if failure.status == 400 and failure.detail and 'already exists' in failure.detail:
            stamp = next_utc_second(stamp)
            name = TOKEN_NAME_PREFIX + stamp
            _, payload = api.request('POST', '/api/serviceaccounts/%d/tokens' % account_id,
                                     {'name': name, 'secondsToLive': seconds_to_live})
        else:
            raise
    if not isinstance(payload, dict) or 'id' not in payload or 'key' not in payload:
        raise OperationError('unexpected response shape: POST /api/serviceaccounts/%d/tokens' % account_id)
    token_id = as_int(payload['id'], 'token id')
    token_name = payload.get('name', name)
    key = payload['key']  # the only secret this program prints; stdout only

    expires = None
    for token in list_tokens(api, account_id):
        if isinstance(token, dict) and as_int(token.get('id'), 'token id') == token_id:
            expires = parse_expiration(token.get('expiration'))
            break
    if expires is None:
        raise OperationError('token %d was created but GET /api/serviceaccounts/%d/tokens carries no '
                             'parsable expiration for it' % (token_id, account_id))
    print_json({'id': token_id, 'name': token_name, 'expires': expires, 'key': key})


def cmd_token_list(api, account_id):
    tokens = list_tokens(api, account_id)
    out = []
    for token in tokens:
        if not isinstance(token, dict) or 'id' not in token:
            raise OperationError('unexpected response shape: GET /api/serviceaccounts/%d/tokens entry'
                                 % account_id)
        out.append({'id': as_int(token['id'], 'token id'),
                    'name': token.get('name'),
                    'expiration': token.get('expiration')})
    print_json(out)


def cmd_token_delete(api, account_id, token_id):
    # ListTokens answers 200 with an empty list even for a non-existent
    # service account (no existence check in the handler), so an absent token
    # alone cannot tell "already deleted" from "wrong account id" — and a
    # silently skipped deletion would leave a stale seed token alive. Verify
    # the account first (404 -> hard failure), then delete idempotently.
    api.request('GET', '/api/serviceaccounts/%d' % account_id)
    tokens = list_tokens(api, account_id)
    present = any(isinstance(t, dict)
                  and as_int(t.get('id'), 'token id') == token_id for t in tokens)
    if not present:
        print_json({'deleted': token_id, 'note': 'token %d was already absent' % token_id})
        return
    try:
        api.request('DELETE', '/api/serviceaccounts/%d/tokens/%d' % (account_id, token_id))
    except HttpFailure as failure:
        if failure.status == 404:
            # Lost a race; success only when the token really is gone.
            tokens = list_tokens(api, account_id)
            still = any(isinstance(t, dict)
                        and as_int(t.get('id'), 'token id') == token_id for t in tokens)
            if still:
                raise
            print_json({'deleted': token_id, 'note': 'token %d was already absent' % token_id})
            return
        raise
    print_json({'deleted': token_id})


def wait_for_grafana(api, seconds):
    """Poll health with a `seconds` budget; an in-flight request can overrun it."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            api.request('GET', '/api/health')
            return
        except (HttpFailure, OperationError):
            if time.monotonic() >= deadline:
                raise OperationError('Grafana did not answer GET /api/health within %d seconds' % seconds)
            time.sleep(HEALTH_POLL_SECONDS)


def signed_in_user_id(api):
    """The id of the user the credentials belong to; None for a service account.

    GET /api/user answers 200 for a service account too, with id 0
    (grafana-v12.2.0 pkg/api/user.go:33-43, the non-user identity branch), and
    a 403/404 is treated the same: only the Basic admin is a user here, and it
    is the one user whose own sessions the logout endpoint refuses to end.
    """
    try:
        _, profile = api.request('GET', '/api/user')
    except HttpFailure as failure:
        if failure.status in (403, 404):
            return None
        raise
    if isinstance(profile, dict) and profile.get('id'):
        return as_int(profile['id'], 'user id')
    return None


def session_ids(api, user_id):
    path = '/api/admin/users/%d/auth-tokens' % user_id
    _, payload = api.request('GET', path)
    if not isinstance(payload, list):
        raise OperationError('unexpected response shape: GET ' + path)
    ids = []
    for token in payload:
        if not isinstance(token, dict) or 'id' not in token:
            raise OperationError('unexpected response shape: GET ' + path + ' entry')
        ids.append(as_int(token['id'], 'token id'))
    return ids


def end_user_sessions(api, user_id, own_id):
    """End every session of one user and return how many were listed.

    The user's token list is read again afterwards and must be empty, so a
    revocation that did not take effect fails instead of passing silently.
    """
    listed = session_ids(api, user_id)
    if not listed:
        return 0
    if user_id == own_id:
        # AdminLogoutUser refuses the caller's own user (grafana-v12.2.0
        # pkg/api/admin_users.go:370-372); revoke-auth-token has no such rule
        # while the caller has no session token of its own, which holds for
        # Basic authentication (pkg/api/user_token.go:270-271).
        for token_id in listed:
            try:
                api.request('POST', '/api/admin/users/%d/revoke-auth-token' % user_id,
                            {'authTokenId': token_id})
            except HttpFailure as failure:
                # 404: the token is already gone (expired or revoked meanwhile),
                # which is the state wanted; the re-read below decides.
                if failure.status != 404:
                    raise
    else:
        api.request('POST', '/api/admin/users/%d/logout' % user_id)
    if session_ids(api, user_id):
        raise OperationError('a Grafana user still has sessions after POST /api/admin/users/%d/%s'
                             % (user_id, 'revoke-auth-token' if user_id == own_id else 'logout'))
    return len(listed)


def cmd_end_sessions(api, scope, wait_seconds):
    if wait_seconds:
        wait_for_grafana(api, wait_seconds)
    own_id = signed_in_user_id(api)
    in_scope = users_ended = sessions_ended = 0
    for user in list_users(api):
        if user.get('isServiceAccount'):
            continue
        user_id = as_int(user['id'], 'user id')
        if scope == 'external':
            _, profile = api.request('GET', '/api/users/%d' % user_id)
            if not isinstance(profile, dict):
                raise OperationError('unexpected response shape: GET /api/users/%d' % user_id)
            # A failed profile auth-info lookup may default false; the shared classifier
            # corroborates it with the independent list labels and refuses UNKNOWN.
            if classify_user_auth(user, profile, user_id) == 'local':
                continue
        in_scope += 1
        ended = end_user_sessions(api, user_id, own_id)
        if ended:
            users_ended += 1
            sessions_ended += ended
    print_json({'scope': scope, 'users_in_scope': in_scope, 'users_ended': users_ended,
                'sessions_ended': sessions_ended})


def nonnegative_int(value):
    number = int(value)  # argparse surfaces a clean error for non-integers
    if number < 0:
        raise argparse.ArgumentTypeError('must be >= 0')
    return number


def positive_int(value):
    number = int(value)  # argparse surfaces a clean error for non-integers
    if number < 1:
        raise argparse.ArgumentTypeError('must be >= 1')
    return number


def build_parser():
    parser = argparse.ArgumentParser(
        prog='grafana-admin.py',
        description='Grafana admin API helper for the krate CLI. Credentials come only from the '
                    'environment (GRAFANA_URL plus GRAFANA_SERVICE_ACCOUNT_TOKEN, or '
                    'GRAFANA_ADMIN_USER and GRAFANA_ADMIN_PASSWORD; GRAFANA_CA_FILE to verify a '
                    'self-signed https URL). One JSON document on stdout; errors on stderr.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True, metavar='SUBCOMMAND')

    def add(name, help_text):
        return sub.add_parser(name, help=help_text, description=help_text)

    add('reads', 'preflight reads for krate monitor realm: sso-settings source, '
                 'public-dashboard count, snapshot count')
    add('local-users', 'list human users with login, email, isDisabled, isGrafanaAdmin, authClass')

    retire = add('retire-user', 'set a user e-mail to <login base><suffix> and disable the user')
    retire.add_argument('--login', required=True, help='exact login of the user to retire')
    retire.add_argument('--email-suffix', default=DEFAULT_EMAIL_SUFFIX,
                        help='appended to the login base (the login, or for an e-mail-shaped '
                             'login its local part) to form the new e-mail (default: %(default)s)')

    account = add('service-account', 'find-or-create a service account by exact name')
    account.add_argument('--name', required=True, help='service-account name, e.g. krate-seed')
    account.add_argument('--role', required=True, choices=ORG_ROLES, help='org role to assign')

    create = add('token-create', 'create a krate-seed-<UTC timestamp> token on a service account')
    create.add_argument('--account-id', required=True, type=int, help='service-account id')
    create.add_argument('--days', required=True, type=positive_int,
                        help='lifetime in days (secondsToLive = days * 86400)')

    tokens = add('token-list', 'list the tokens of a service account')
    tokens.add_argument('--account-id', required=True, type=int, help='service-account id')

    delete = add('token-delete', 'delete a service-account token (absent token = success with a note)')
    delete.add_argument('--account-id', required=True, type=int, help='service-account id')
    delete.add_argument('--token-id', required=True, type=int, help='token id to delete')

    ending = add('end-sessions', 'end the Grafana sessions a sign-in switch leaves behind '
                                 '(users only, never service accounts)')
    ending.add_argument('--scope', required=True, choices=SESSION_SCOPES,
                        help='all: every human user; external: users with any external login')
    ending.add_argument('--wait-seconds', type=nonnegative_int, default=0,
                        help='health-polling budget in seconds; requests may overrun it (default: %(default)s)')

    return parser


HANDLERS = {
    'reads': lambda api, args: cmd_reads(api),
    'local-users': lambda api, args: cmd_local_users(api),
    'retire-user': lambda api, args: cmd_retire_user(api, args.login, args.email_suffix),
    'service-account': lambda api, args: cmd_service_account(api, args.name, args.role),
    'token-create': lambda api, args: cmd_token_create(api, args.account_id, args.days),
    'token-list': lambda api, args: cmd_token_list(api, args.account_id),
    'token-delete': lambda api, args: cmd_token_delete(api, args.account_id, args.token_id),
    'end-sessions': lambda api, args: cmd_end_sessions(api, args.scope, args.wait_seconds),
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    operation = args.command
    try:
        url, authorization, context = resolve_config(operation)
        api = Api(url, authorization, context)
        HANDLERS[operation](api, args)
    except HttpFailure as failure:
        fail(operation, str(failure))
    except OperationError as error:
        fail(operation, str(error))
    return 0


if __name__ == '__main__':
    sys.exit(main())
