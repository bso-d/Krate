# Native login customization

EPC and regular Krate share `krate/kafka-ui:1.5.0-sso.5`, based on Kafbat v1.5.0
at `afc9c918e13c4422268a3a5b7933c7b448746c82`. Upstream source and license:
<https://github.com/kafbat/kafka-ui/tree/v1.5.0>.

The image runs on the digest-pinned Eclipse Temurin 25 JRE (Alpine) instead of
upstream's Azul Zulu base, because Adoptium publishes the JDK's source and Azul
does not (see [LICENSE-SOURCES.md](../LICENSE-SOURCES.md)). The runtime setup is
upstream's: `gcompat` and `tzdata`, the non-root `kafkaui` user, `/etc/kafkaui`,
port 8080 and the same Java command. The builder fetches `gcompat` and its
dependencies for the Temurin image's own Alpine release; the image build has no
network, and `apk` checks the packages' Alpine signatures. Their file hashes are
recorded in `provenance.json`.

`native-login.patch` keeps upstream React, styled-components, inputs and buttons.
It selects the native dark theme for the login page, removes the login wordmark,
and adds SSO beside the existing form. The entered username/email becomes an
encoded `login_hint`; the password is never submitted on the SSO route.

`native-auth.patch` extends native Spring Security OAuth handling with:

- An opt-in local form login using the existing app credential and an explicit
  configured RBAC role, authenticated separately from OAuth subjects.
- A resolver that preserves Spring's state/nonce/PKCE handling and forwards only
  a bounded login hint, never arbitrary request parameters.
- Rejection of an OIDC login with no mapped role when configured to require one.
- Explicit endpoint configuration without startup discovery, retaining issuer
  validation and allowing local login during an IdP outage.
- Login metadata that advertises a form plus the configured OAuth provider.

Native OIDC token validation and native Kafbat group/permission mapping remain
in use. This image is a maintained derivative; stock v1.5.0 does not provide
simultaneous LOGIN_FORM and OAUTH2 merely by setting environment variables.
The authentication changes require review when upgrading upstream.

## Build

```bash
make kafbat-ui ARCH=amd64
# Or: python3 kafbat-ui/build.py --arch arm64 --source /path/to/pinned-checkout
```

The build pins the new image ID as `KAFKA_UI_IMAGE` in `kraft/.env.template`
and `epc/.env.template`. The next `./krate` command copies that pin into an
existing `.env`.

Use a connected build host with Python 3, Git, Docker, Node and npm. Upstream
recommends Node 22. The builder pins upstream commit, pnpm and code generation
artifacts, runs TypeScript/lint/React tests, and compiles three authentication
source files against the exact deployed JAR's classes and dependencies using a
digest-pinned Java 25 compiler image and checksum-verified Lombok.

It replaces only generated static assets and those compiled authentication
classes in the upstream JAR. It verifies every other original entry is unchanged.
No dependencies or compiler images are shipped as runtime services. Upstream
license, both patches and provenance are included in the derived image at
`/usr/share/krate/kafbat-source/`. No new visible login-page branding is added.

SSO activation requires Compose 2.20.2 or newer and uses the same Compose file
as the brokers. Offline bundles include the customized UI, Keycloak and
PostgreSQL, plus activation and validation helpers. The target VM never compiles
or fetches UI assets. Activation checks locally available images and uses
`--pull never`. See [the operator guide](../sso/guides/dual-login.md).
