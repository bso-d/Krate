# SSO in EPC and regular Krate

The [IAM guide](pingfederate-iam-guide.md) lists what to agree with the IAM
team. The [operator guide](dual-login.md) gives the setup steps. The
[flow diagrams](sso-flows.md) show sign-in and group enrollment.

Kafbat uses OIDC with the local Keycloak service. Keycloak brokers OIDC with
PingFederate. PingFederate supplies the authenticated identity and AD groups.
Keycloak maps those groups and includes them in the Kafbat token. Kafbat grants
Viewer or Admin access to the named clusters. Users without either group are
denied. The shared Kafbat Admin credential is a separate login path.

Grafana has its own Generic OAuth configuration and client. It can still use
PingFederate directly; the Kafbat login page and Keycloak realm do not control
Grafana. Use `sso/configure.py --app grafana` and the separate Grafana client
secret when enabling it. Its Viewer/Admin group mapping uses the same AD group
names. Kafka producer and consumer authentication is separate from UI SSO.
