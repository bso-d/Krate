# Native SSO customization

EPC and regular Krate share `krate/kafka-ui:1.5.0-sso.6`, based on Kafbat v1.5.0
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

Kafbat's dependency pins at this revision: Spring Boot 3.5.13
(`gradle/libs.versions.toml`), which manages Spring Security 6.5.9
(`spring-boot-dependencies/build.gradle`, `library("Spring Security", "6.5.9")`).
The Spring behaviour cited below was read from those exact sources.

## What the patches change

`native-login.patch` keeps upstream React, styled-components, inputs and buttons.
It selects the native dark theme for the login page and removes the login
wordmark. In OAUTH2 mode upstream renders only the provider button
(`SignIn.tsx` renders `BasicSignIn` for `LOGIN_FORM`/`LDAP` and `OAuthSignIn`
for `OAUTH2`), so the page shows "Log in with <client name>" and no credential
form. The patch also:

- Adds `lib/csrf.ts`: a `pre` middleware on the generated API client copies the
  `XSRF-TOKEN` cookie into the `X-XSRF-TOKEN` header for every method other than
  GET/HEAD/OPTIONS/TRACE; the one raw `fetch` (`/api/config/relatedfiles`)
  gets the same header.
- Turns the "Log out" menu entry into a hidden POST form to `/logout` carrying
  the token as the `_csrf` field.
- In `LOGIN_FORM` mode (the untouched `local.yml`) keeps upstream's form with
  `autocomplete` hints, `required` inputs and an `aria` alert for the error.

`native-auth.patch` touches two classes, `OAuthSecurityConfig` and the new
`NativeLoginSupport`, and only applies when `auth.type: OAUTH2`:

- **No local form login in OAUTH2 mode.** The shared username/password login
  that earlier images added beside SSO is gone, as is its `LOGIN_FORM`
  advertisement in `ApplicationInfoService`. `auth.oauth2.allow-shared-login`
  and `auth.oauth2.shared-role` are no longer read; `spring.security.user.*`
  has no effect in OAUTH2 mode.
- **Required role mapping is total.** With `auth.oauth2.require-mapped-role:
  true` the application refuses to start without RBAC roles or with a resource
  server configured (a bearer-token `Jwt` principal is not an `RbacUser`, so
  `AccessControlService.validateAccess` would not restrict it). Both user
  services, OIDC and plain OAuth2, reject a login whose extracted group set is
  empty or for which no authority extractor applies, with
  `OAuth2AuthenticationException(access_denied)`; the browser lands on
  `/login?error` and no session is created.
- **ID token claims are validated.** Upstream replaces Spring's decoder
  factory with a bare `NimbusReactiveJwtDecoder` (proxy-aware `WebClient`).
  That decoder's default validator is `JwtValidators.createDefault()`, which is
  only `JwtTimestampValidator` and `X509CertificateThumbprintValidator`
  (`JwtValidators.java` 77-81), so `iss`, `aud` and `azp` were never checked.
  The patch keeps the decoder and sets
  `DelegatingOAuth2TokenValidator(JwtValidators.createDefault(),
  new OidcIdTokenValidator(clientRegistration))`
  (`NimbusReactiveJwtDecoder.setJwtValidator`, line 135;
  `OidcIdTokenValidator(ClientRegistration)`, line 62), which is what Spring's
  own `ReactiveOidcIdTokenDecoderFactory` composes ("The default composes
  `JwtTimestampValidator` and `OidcIdTokenValidator`", lines 208-209).
  `OidcIdTokenValidator` requires `iss`, `sub`, `aud`, `exp`, `iat`, compares
  `iss` with the registration's issuer, requires the client id in `aud`,
  checks `azp` and bounds `exp`/`iat` by the clock skew (lines 68-121).
  Because of that, the explicit-endpoint registration keeps `issuer-uri` on the
  `ClientRegistration` even though no discovery runs at startup.
- **CSRF protection is on.** `csrf(CsrfSpec::disable)` is replaced by
  `CookieServerCsrfTokenRepository.withHttpOnlyFalse()` with the plain
  `ServerCsrfTokenRequestAttributeHandler`, plus a `WebFilter` right after
  `SecurityWebFiltersOrder.CSRF` that subscribes to the deferred token so the
  cookie is written on GET requests. Reference: "By default, the
  `CookieServerCsrfTokenRepository` writes to a cookie named `XSRF-TOKEN` and
  read its from a header named `X-XSRF-TOKEN` or the HTTP `_csrf` parameter."
  (<https://docs.spring.io/spring-security/reference/6.5/reactive/exploits/csrf.html>).
  Why each piece: `CsrfWebFilter.continueFilterChain` only hands a
  `Mono<CsrfToken>` to the request handler (`CsrfWebFilter.java` 147-152) and
  the token is generated and saved in `generateToken` on subscription
  (178-182), so without a subscriber a SPA that never renders the token
  server-side never receives the cookie. The filter's default handler is
  `XorServerCsrfTokenRequestAttributeHandler` (line 86), which expects the
  masked value and rejects the raw token the cookie contains; the plain handler
  resolves the header or `_csrf` form field as-is, the pattern the servlet
  reference's single-page-application section describes
  (<https://docs.spring.io/spring-security/reference/6.5/servlet/exploits/csrf.html>).
  Nothing in Kafbat renders the token into a response body, so BREACH masking
  adds nothing here. `CsrfSpec.configure` also registers
  `CsrfServerLogoutHandler`, which clears the cookie on logout
  (`ServerHttpSecurity.java` 2460-2466); the next GET issues a fresh one.
- **Logout is POST-only and ends the session.** The GET `/logout` matcher of
  earlier images is gone; Spring's default applies (`LogoutSpec.logoutUrl`
  builds `pathMatchers(HttpMethod.POST, logoutUrl)`, `ServerHttpSecurity.java`
  3955-3960). Reference: "By default, Spring Security's `LogoutWebFilter` only
  processes only HTTP post requests. This ensures that logout requires a CSRF
  token and that a malicious user cannot forcibly log out your users."
  (<https://docs.spring.io/spring-security/reference/6.5/reactive/exploits/csrf.html>).
  The logout handler is `DelegatingServerLogoutHandler(
  SecurityContextServerLogoutHandler, WebSessionServerLogoutHandler)`;
  `LogoutSpec.logoutHandler` replaces the default list (3937-3941), so the
  security-context handler is re-added explicitly, as the reference does
  (<https://docs.spring.io/spring-security/reference/6.5/reactive/authentication/logout.html>).
  `WebSessionServerLogoutHandler` is `getSession().flatMap(WebSession::invalidate)`
  (line 35). Upstream's `OAuthLogoutSuccessHandler` stays, so a successful
  logout still redirects to the provider's `end_session_endpoint` with
  `id_token_hint` (RP-initiated logout).
- **OIDC back-channel logout.** `.oidcLogout(l -> l.backChannel(withDefaults()))`
  exposes `POST /logout/connect/back-channel/{registrationId}` and the patch
  publishes `ReactiveOidcSessionRegistry` and `OidcBackChannelServerLogoutHandler`
  beans. Reference: "At login time, Spring Security correlates the ID Token,
  CSRF Token, and Provider Session ID (if any) to your application's session
  id in its `ReactiveOidcSessionRegistry`" and "Spring Security validates the
  token's signature and claims. If the token contains a `sid` claim, then only
  the Client's session that correlates to that provider session is terminated."
  (<https://docs.spring.io/spring-security/reference/6.5/reactive/oauth2/login/logout.html>).
  The registry is a bean because `OAuth2LoginSpec.getOidcSessionRegistry` looks
  one up and otherwise creates a private instance (`ServerHttpSecurity.java`
  4562-4572) and the handler's only constructor takes the registry
  (`OidcBackChannelServerLogoutHandler.java` line 78); `BackChannelLogoutConfigurer`
  prefers the published handler bean (5631-5638).

  Two decisions in that handler:

  1. **`{baseUrl}` is kept; no explicit logout URI.** The handler replays each
     registered session to `logoutUri = "{baseUrl}/logout/connect/back-channel/{registrationId}"`
     (line 74) and computes `{baseUrl}` from the back-channel request itself
     (`computeLogoutEndpoint`, lines 137-166: `UriComponentsBuilder.fromUri(request.getURI())`
     with the context path). Keycloak calls Kafbat on the Docker network at
     `http://kafka-ui:8080/...` without forwarded headers, so `{baseUrl}`
     resolves to `http://kafka-ui:8080` and the self-call stays inside the
     container network, follows `server.port` and any base path, and needs no
     TLS trust. A hard-coded `http://localhost:8080/...` would work only while
     the port and base path match and would ignore how the request arrived.
     Consequence for the realm: the client's `backchannel.logout.url` must be
     the internal URL; registering the public HTTPS URL would make the handler
     call itself through nginx with Spring's plain `WebClient.create()` (line
     72), which does not trust the site certificate.
  2. **Cookie name follows the server.** `setSessionCookieName` is given
     `server.reactive.session.cookie.name` with default `SESSION`. The
     reference note says the cookie must be `JSESSIONID`, but in 6.5.9 the
     field default is `sessionCookieName = "SESSION"` (line 76), which is
     WebFlux's default (`CookieWebSessionIdResolver`), and Spring Boot applies
     `server.reactive.session.cookie.name` to that resolver
     (`WebSessionIdResolverAutoConfiguration.java` 62-65 at v3.5.13). Reading
     the property keeps the two in step when `runtime.yml` sets the name.

  The internal replay carries the session cookie and
  `_spring_security_internal_logout=true` to the same endpoint; the
  `OidcBackChannelLogoutWebFilter` is installed before CSRF
  (`http.addFilterBefore(filter, SecurityWebFiltersOrder.CSRF)`, line 5767)
  and ends the exchange itself, so no CSRF exemption is configured. The
  reference: "If `OidcBackChannelServerLogoutHandler` is not wired, then the
  URL is ... which is not recommended since it requires passing a CSRF token"
  (same logout page).
- **PKCE and `login_hint`.** `NativeLoginSupport.resolver` wraps Spring's
  resolver with `OAuth2AuthorizationRequestCustomizers.withPkce()` and copies
  only a bounded `login_hint` query parameter (at most 254 characters, no
  control characters) into the authorization request. State, nonce,
  redirect_uri and every other parameter remain Spring's.

Native OIDC token validation and native Kafbat group/permission mapping remain
in use. This image is a maintained derivative; the authentication changes
require review when upgrading upstream.

## Operator notes

- Keycloak (or any provider) must be able to reach
  `http://kafka-ui:8080/logout/connect/back-channel/keycloak` for back-channel
  logout; the realm client needs `backchannel.logout.url` set to it and
  `backchannel.logout.session.required` on.
- Keep `server.reactive.session.cookie.name` either unset or `SESSION`; any
  other value is honoured by both the session resolver and the back-channel
  handler because both read the same property.
- Browser-side scripts must be able to read the `XSRF-TOKEN` cookie; it is
  deliberately not `HttpOnly`. `SESSION` keeps its `HttpOnly` flag.
- A GET to `/logout` no longer logs anyone out; a POST without a valid token is
  refused with 403.

## Build

`./krate start` and `./krate setup` build this image when the pinned one is not
on the host, `./krate build` rebuilds it for the host, and `./krate package`
builds it for the package's processor. They run:

```bash
make kafbat-ui ARCH=amd64
# Or: python3 kafbat-ui/build.py --arch arm64 --source /path/to/pinned-checkout
```

The build pins the new image ID as `KAFKA_UI_IMAGE` in `kraft/.env.template`
and `epc/.env.template`; the next `./krate` command that runs Compose (`start`,
`status`, `health`, ...) carries that pin into `.env`. `config show`, `ui` and
`help` do not touch `.env`.

Use a connected build host with Python 3, Git, Docker, Node and npm. Upstream
recommends Node 22. The builder pins upstream commit, pnpm and code generation
artifacts, runs TypeScript, lint and the React tests for the touched components
(`AuthPage`, `NavBar/UserInfo`, `lib/csrf`), and compiles the two
authentication source files against the exact deployed JAR's classes and
dependencies using a digest-pinned Java 25 compiler image and checksum-verified
Lombok.

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
