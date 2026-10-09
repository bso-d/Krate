# Perses single sign-on

Perses (the parallel dashboards on `PERSES_PORT`, default 3443) supports company
SSO in two modes, alongside Grafana's existing SSO, which is unchanged:

- **`native`** (recommended): IdP groups become native Perses Viewer/Admin
  roles, kept in step with the IdP by the `perses-sync` guard.
- **`gateway`**: Perses' own authentication is off; the guard enforces
  Viewer/Admin on every request at the gateway.

In both modes OAuth2 Proxy holds the IdP session, and every request through the
HTTPS gateway is checked against the user's current groups. A user in neither
group cannot sign in.

## What the IAM team provides

1. **One OIDC client for Perses** (confidential, authorization code with PKCE
   S256) with exactly these redirect URIs, using the public URL users open:
   - `https://<host>:<PERSES_PORT>/oauth2/callback` (OAuth2 Proxy)
   - `https://<host>:<PERSES_PORT>/api/auth/providers/oidc/krate/callback` (Perses, `native` mode)

   Using one client for both keeps the user's subject identical in both, which
   `native` mode requires (the guard matches issuer and subject exactly).
2. **A groups claim** (top-level, for example `groups`) in the ID token and
   userinfo, containing group names without commas, quotes or whitespace, plus
   `email` and `email_verified=true`.
3. **Two groups**, for example `KRATE_PERSES_VIEWERS` and `KRATE_PERSES_ADMINS`.
   A user in both is an Admin.
4. **Refresh tokens** for the Perses client, with an ID token returned on
   refresh. OAuth2 Proxy refreshes the session every `group_proof_minutes` to
   bring current groups. If the IdP rotates refresh tokens, it must tolerate a
   refresh token being used again within a few seconds: a browser makes
   parallel requests, and each can trigger a refresh with the same token. A
   strict reuse detection that revokes the session would sign users out.
   Revoking a user's IdP session or refresh token must return `invalid_grant`,
   which ends the Perses session at the next refresh.
5. **`native` mode only: a service client** for the guard (client credentials
   grant). Its client ID becomes a Perses user name, so it must start with a
   letter or digit and use only letters, digits, `.`, `_` and `-`. It needs no
   groups or user permissions at the IdP.

Secrets are delivered separately: the Perses client secret and, for `native`,
the service client secret.

## Operator steps

1. Write the site settings (no secrets), for example `sso/site-perses.json`:

   ```json
   {
     "issuer": "https://idp.example.com/realms/company",
     "public_url": "https://monitor.example.com:3443",
     "client_id": "krate-perses",
     "viewer_group": "KRATE_PERSES_VIEWERS",
     "admin_group": "KRATE_PERSES_ADMINS",
     "groups_claim": "groups",
     "scopes": ["openid", "profile", "email"],
     "service_client_id": "krate-perses-sync",
     "group_proof_minutes": 15,
     "session_hours": 8
   }
   ```

   `public_url` must be HTTPS at the root path and match the certificate in
   `certs/`. `group_proof_minutes` (1–60) bounds how long a group change can
   take to apply; `session_hours` (1–24) bounds how long a session lasts.
   Add any extra scope your IdP needs to include groups.
2. Generate `monitoring/auth/perses/perses.json`:

   ```bash
   python3 sso/configure.py --app perses --settings sso/site-perses.json \
     --output monitoring/auth/perses/perses.json
   ```

   It refuses to overwrite an existing file; remove it first to regenerate.
3. In `monitoring/.env` set `PERSES_AUTH_MODE=native` (or `gateway`),
   `OAUTH2_PROXY_CLIENT_SECRET` (the Perses client secret) and, for `native`,
   `PERSES_SYNC_CLIENT_SECRET`. Keep the file at mode 600.
4. Run `./krate monitor up`. It generates the cookie secret if needed, renders
   the configuration and starts OAuth2 Proxy and the guard.

## Checks before giving users access

- Unauthenticated browsers are sent to the IdP; API clients get 401.
- A Viewer can open every dashboard and run queries but cannot save, create or
  delete anything (403); an Admin can.
- A user in no group is refused by OAuth2 Proxy after signing in.
- Remove a test user from a group: within `group_proof_minutes` their requests
  are refused and, in `native` mode, their Perses grants are deleted.
- `https://<host>:<PERSES_PORT>/api/auth/providers/oidc/krate/token`, the
  device-code and native-login routes, and `/oauth2/auth` are refused from
  outside.

## How native mode keeps roles current

For each request the guard asks OAuth2 Proxy for the current session and
groups, then (for API requests) asks Perses who the user is and requires one
OIDC identity with the configured issuer and the session's exact subject. It
then makes the user's Krate role bindings match: Admin and Viewer bindings are
global, demotion or removal deletes the other binding and removes the user from
every other binding, including project owner grants, and the user's live
permissions are read back before the request passes. A Perses token refresh is
released only after the same checks. Any failure denies the request.

The guard's service identity can only manage role bindings, read projects,
roles and users, and seed dashboards. It signs in through Perses' private token
route, which the gateway does not expose.
