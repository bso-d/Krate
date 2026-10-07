# PingFederate setup with the IAM team

This guide applies to EPC and regular Krate. Kafbat sends an SSO user to the
Keycloak service in the same installation. Keycloak sends the user to
PingFederate. PingFederate authenticates the person and returns AD groups.
The shared Kafbat Admin account does not use these services.

## 1. Agree the registration

Register **Keycloak** as a confidential OIDC client in PingFederate. Use the
authorization code flow and a client secret. Each independent installation
needs its own client registration and secret.

| Item | Value or decision |
|---|---|
| Application URL | `https://<application-fqdn>`; use a certificate trusted by browsers |
| PingFederate redirect URI | `https://<application-fqdn>/identity/realms/krate/broker/pingfederate/endpoint` |
| PingFederate issuer and endpoints | Exact issuer, authorization, token, UserInfo and JWKS URLs from IAM |
| Client ID and secret | One confidential client for each installation |
| Scopes | `openid profile email` and any scope needed for AD groups |
| Identity | Stable `sub`; email and name as approved |
| Group claim | A top-level array, such as `groups`, in the ID token or UserInfo response |
| Required group values | Exact Viewer and Admin AD group names, including case |
| Trust | Approved enterprise CA chain for PingFederate HTTPS |

The Keycloak-to-Kafbat client is created inside the realm import. Its callback
is `https://<application-fqdn>/login/oauth2/code/keycloak`. **Do not** register
this callback in PingFederate. Do not use a wildcard redirect URI.

## 2. Decide the sign-in policy

The Kafbat SSO button starts OIDC with Keycloak. Keycloak's browser flow sends
that request to PingFederate. The text entered in Kafbat's username/email field
is an optional `login_hint`; it does not authenticate the user. PingFederate
can reuse an enterprise session. It can also require a password or MFA under
IAM policy. The user must never type AD credentials into the shared Kafbat form.

Ask IAM to provide the two application group values in the same claim for every
user. Keep the claim limited to the groups needed by this application. Keycloak
maps each matching claim value to a local group. Kafbat then applies its role
rules to the configured cluster names.

| AD group membership | Kafbat result |
|---|---|
| Viewer | See all configured clusters and read messages; no write actions |
| Admin | Full UI access to configured clusters |
| Both | Admin access |
| Neither or missing claim | SSO access denied |
| Shared Kafbat account | Admin access, independent of AD |

KSQL has no safe read-only execute right in this setup, so Viewer cannot run
KSQL. Kafbat UI roles do not secure direct Kafka producer or consumer access.
An AD group change applies at the next app sign-in. End active Kafbat sessions
for urgent revocation. Rotate the shared Admin password separately.

## 3. Approve the network path

| Source | Destination | Use |
|---|---|---|
| User browser | Application FQDN, HTTPS | Kafbat and Keycloak login |
| User browser | PingFederate authorization URL | Enterprise sign-in and MFA |
| Keycloak container | PingFederate token, UserInfo and JWKS URLs | Code exchange and identity checks |
| Kafbat container | Keycloak service on the internal Compose network, TCP 8080 | OIDC code exchange and token checks |
| Kafbat container | Configured Kafka broker listeners | Cluster data and permitted actions |

Use the ports in the IAM endpoint URLs, usually 443. Allow the approved DNS
names and keep VM time correct. Place the enterprise CA PEM chain in
`auth/keycloak/truststores/`. The user's browser must trust the application
HTTPS certificate. No public Internet is needed at runtime. The build machine
downloads images before offline delivery.

## 4. Give the operator these values

Give the non-secret values above and deliver the PingFederate client secret
through the approved secret process. The operator uses the
[setup guide](dual-login.md). The Keycloak public URL must equal the app URL
plus `/identity`.

Grafana uses its own Generic OAuth client and can connect to PingFederate
separately. Its callback is `https://<grafana-url>/login/generic_oauth`, with
any Grafana subpath included. It does not use the Kafbat callback.

## 5. Test with IAM

- A user with an existing PingFederate session reaches Kafbat. A new session
  follows IAM password and MFA policy.
- The redirect reaches the PingFederate Keycloak callback above. No Keycloak
  password form appears in the normal SSO path.
- Viewer can read a message but cannot create, edit, delete, produce, or reset
  offsets. Admin can make an approved test change.
- Users in both groups get Admin. A user in neither group is denied.
- Shared Admin login still works when PingFederate is unavailable.
- TLS validation, signing-key rollover, logout, group removal, and urgent
  revocation work under the site's policy.

Local tests use Keycloak test users. They check Kafbat login and roles, but they
cannot prove this customer's PingFederate or AD policy.
