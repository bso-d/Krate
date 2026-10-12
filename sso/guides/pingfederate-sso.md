# SSO in EPC and regular Krate

The [IAM guide](pingfederate-iam-guide.md) lists what to agree with the IAM
team. The [operator guide](dual-login.md) gives the setup steps. The
[flow diagrams](sso-flows.md) show sign-in and group enrollment.

Kafbat uses OIDC with the local Keycloak service. Keycloak brokers OIDC with
PingFederate: the realm's browser flow `krate browser` (applied from
`auth/keycloak/pingfederate-idp.json` by `./krate auth apply`) redirects every
new session to PingFederate, which supplies the authenticated identity and AD
groups. Keycloak creates the realm user on the first login without linking it
to a local account, maps the groups into the realm groups (re-synced at every
login) and includes them in the Kafbat token. Kafbat grants Viewer or Admin
access to the named clusters. Users without either group are denied. Local
Keycloak users (`./krate identity users`) sign in only through the break-glass
procedure: press Kafbat's "Log in with Keycloak" button, append `&kc_idp_hint=`
(empty) to the realm's authorization URL in the address bar, and the password
and OTP forms appear instead of the redirect. The shared Kafbat Admin
credential (`local.yml`) is a separate login mode.

Grafana has its own Generic OAuth configuration and client. It can still use
PingFederate directly; the Kafbat login page and Keycloak realm do not control
Grafana. Use `sso/configure.py --app grafana` and the separate Grafana client
secret when enabling it. Its Viewer/Admin group mapping uses the same AD group
names. Kafka producer and consumer authentication is separate from UI SSO.
