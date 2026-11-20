# Kafka OAuth client credentials

`krate-kafka-oauth-client.jar` adds a Kafka 3.9.1 SASL/OAUTHBEARER login callback for
least-privilege application clients. The broker validates JWT signatures and ACLs. This
client checks token claims only as input sanity checks. Kafka schedules access-token
refresh; this callback reads current credentials again on each refresh.

## Build and runtime

On a connected build host with JDK 21 and Python 3, extract `libs/` from the
repository-pinned `apache/kafka:3.9.1` image, then run:

```sh
./kafka-oauth-client/build.sh /absolute/path/to/kafka/libs /absolute/build-output
```

The build verifies SHA-256 of Kafka 3.9.1 clients and three Jackson 2.16.2 jars,
compiles Java 17-compatible bytecode, and makes a deterministic jar of Krate
classes only. For the operator CLI, package the Krate jar plus
`kafka-clients-3.9.1.jar`, `jackson-databind-2.16.2.jar`,
`jackson-core-2.16.2.jar` and `jackson-annotations-2.16.2.jar`; the Kafka jar
is needed by `rotate` and `recover`. An application already using Kafka 3.9.1
needs the Krate jar and those Jackson jars on its Kafka classpath. The build
makes no network request.

## Operator workflow

From the KRaft or EPC directory, start Keycloak and enable Kafka OAuth/TLS with
`./krate identity up` and `./krate kafka auth enable`. Create the application topic
with a Kafka administrator before the first send. The application client gets
only its named topic/group permissions; it cannot create a topic. For the supplied
four-broker KRaft cluster:

```sh
docker exec krate-broker-92 /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server kafka-92:9092 \
  --command-config /mnt/shared/config/admin.properties \
  --create --topic payments --partitions 1 --replication-factor 3
install -d -m 0700 auth/payments-client
state_path="$(pwd -P)/auth/payments-client/state.json"
./krate kafka client register --state "$state_path" --client-id payments-client \
  --access read-write --topic payments --group payments-consumers
./krate kafka client status --state "$state_path"
```

`register` creates a dedicated Keycloak client, sets its service-account Kafka
principal, checks its token, stores the secret and registration access token in
mode-0600 state, and grants literal ACLs. Use `--access read`, `write`, or
`read-write`; read access needs a `--group`, while write-only access cannot have
one. The registration response contains only the eight status fields listed
below. No secret belongs in command arguments, properties, or logs.

The offline bundle includes `kafka-oauth-client/krate-kafka-oauth-client.jar` and
`kafka-oauth-client/libs/` with Kafka clients 3.9.1 and three Jackson 2.16.2
jars. In a **source checkout**, assemble the same layout from the pinned build
output and set `KAFKA_OAUTH_CLIENT_HOME` to its absolute directory before using
the CLI or Studio:

```sh
export KAFKA_OAUTH_CLIENT_HOME=/absolute/path/to/kafka-oauth-client-runtime
# This directory contains krate-kafka-oauth-client.jar and libs/{kafka-clients-3.9.1.jar,jackson-*.jar}
```

After registration, connect the application with the Kafka properties below.
Produce a message and confirm a consumer in the allowed group receives it. A
Kafka console producer can exit with code 0 after an asynchronous send failed;
check its error output and the consumed message. To inspect and operate the
credential without printing it:

```sh
./krate kafka client status --state "$state_path"
./krate kafka client rotate --state "$state_path"
./krate kafka client recover --admin --state "$state_path"
```

An early `rotate` may update only the registration token and return
`last_rotation_error=dcr-secret-not-rotated`. When the secret is due under the
Keycloak policy, rotation replaces the secret and registration token together.
`recover --admin` obtains a replacement registration token through the local
Keycloak administrator, verifies the replacement client secret, and repairs the
private state. Keep the state directory private, back up the state with the same
restrictions, and alert on `rotation_due`, `pending`, or a nonempty
`last_rotation_error`.

## Managed DCR details and direct enrollment

Create a dedicated Keycloak service client for each application with a
`kafka_principal` claim, `kafka` audience and only its required Kafka ACLs. The
Keycloak DCR profile must support secret and registration-token rotation. Keycloak
26.8.0's `clients-registrations/default` POST returns camelCase fields. Use its
`registrationAccessToken` to GET the same client through
`clients-registrations/openid-connect/{clientId}`. That OpenID GET returns the
required snake_case fields and HTTPS `registration_client_uri`; enroll that
private representation through stdin so credentials never appear in
process arguments. Use an existing private directory owned by the application
account; the state and adjacent lock files are mode `0600`, cannot be symlinks,
and must stay private. Back up the state with the same restrictions.

```sh
java -cp '/absolute/build-output/krate-kafka-oauth-client.jar:/absolute/kafka/libs/*' \
  com.krate.kafka.oauth.CredentialStateCli enroll \
  --state /absolute/private/payments-state.json \
  --token-endpoint https://keycloak.example/identity/realms/krate/protocol/openid-connect/token \
  --issuer https://keycloak.example/identity/realms/krate \
  --trust-pem /absolute/trust/keycloak-ca.pem \
  --rotation-window-seconds 172800 --overlap-seconds 172800 < private-dcr-response.json
```

The input JSON must include `client_id`, `client_secret`,
`client_secret_expires_at` (epoch seconds), `registration_access_token`, and
`registration_client_uri`. The state file stores these plus the token endpoint,
issuer, trust PEM path, rotation policy, and any pending/previous credential. A
new secret and RAT are written atomically to one state file after DCR PUT. The
file and its parent directory receive an OS sync request before success is reported. Rotation
checks that directory sync works before contacting DCR; if it is unsupported,
the callback fails and `status` reports `state-sync-unavailable` without changing
Keycloak. Concurrent callbacks in one JVM and separate processes share the same
state lock. The previous secret is retained only for the configured overlap while it still mints
a valid Kafka token. A pending new secret is verified and finalized on the next
refresh if interrupted after the state write. The current secret is re-read from
the state file for every Kafka token refresh.

The callback triggers DCR rotation when `client_secret_expires_at -
rotation_window_seconds` is reached. Rotation is synchronous during a Kafka login
refresh, so allow up to 15 seconds per DCR/token request. A failed DCR rotation
is recorded as `dcr-rotation-failed`; a still-valid current secret can continue,
but an expired secret fails the refresh. Monitor status and refresh errors.
The Keycloak token endpoint is called with HTTP Basic client authentication over
HTTPS, as advertised by the OpenID DCR `token_endpoint_auth_method`; the secret
is absent from the request form. Before Keycloak's configured remaining-rotation
window, a DCR PUT can rotate only the RAT. The client persists that new RAT and
reports `dcr-secret-not-rotated` in status. A proposed `client_secret` in an early
PUT is ignored by the observed Keycloak profile. Set the client rotation window
to the Keycloak policy's remaining-rotation period (172800 seconds in the shipped
profile) and monitor that a later due-window refresh changes the secret. The
operator can use `rotate` explicitly to trigger the same path.
Manual rotation and status use the same classpath:

```sh
java -cp '/absolute/build-output/krate-kafka-oauth-client.jar:/absolute/kafka/libs/*' \
  com.krate.kafka.oauth.CredentialStateCli rotate --state /absolute/private/payments-state.json
java -cp '/absolute/build-output/krate-kafka-oauth-client.jar:/absolute/kafka/libs/*' \
  com.krate.kafka.oauth.CredentialStateCli status --state /absolute/private/payments-state.json
```

`status`, `enroll`, `rotate`, and `recover` print only `client_id`, `secret_expires_at`,
`rotation_due_at`, `seconds_until_expiry`, `rotation_due`, `pending`,
`previous_valid_until`, and `last_rotation_error`. They never print the secret,
RAT, JWT or DCR response. A DCR GET uses the stored RAT and a PUT sends the GET
representation without `registration_access_token`; HTTP 200 and matching client
identity are required. A new token is tested before the rotation is finalized.
If Keycloak applies PUT but its response is lost, the local state cannot know the
new RAT. Obtain a replacement DCR representation through Keycloak administrative
recovery or re-registration, then pipe it to `recover`:

```sh
java -cp '/absolute/build-output/krate-kafka-oauth-client.jar:/absolute/kafka/libs/*' \
  com.krate.kafka.oauth.CredentialStateCli recover \
  --state /absolute/private/payments-state.json < private-replacement-dcr.json
```

`recover` requires the same client ID and registration URI, proves that the
replacement secret mints a Kafka token with the enrolled issuer/audience and
principal claim, then atomically replaces the secret and RAT. It preserves the
existing endpoint and rotation policy. If Keycloak cannot provide a replacement
RAT for that identity, recreate the application client and re-enroll through the
Krate operator workflow. A crash between remote PUT and the local state write
has the same recovery need; no local filesystem sync can make the remote update
and local write one transaction. A failed command prints no remote content or
credentials.

Use this Kafka client configuration (the secret and RAT are absent from JAAS):

```properties
security.protocol=SASL_SSL
sasl.mechanism=OAUTHBEARER
sasl.login.callback.handler.class=com.krate.kafka.oauth.RotatingSecretLoginCallbackHandler
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required credentialStateFile="/absolute/private/payments-state.json";
ssl.truststore.type=PEM
ssl.truststore.location=/absolute/trust/kafka-ca.pem
```

`--trust-pem` may be omitted when JVM default trust already trusts Keycloak. It
is separate from the Kafka broker CA. Alert on `rotation_due`, `pending`,
`last_rotation_error`, and Kafka login refresh failures. A user UAT must produce
and consume across a secret rotation, access-token expiry and client restart,
then confirm another client's restricted ACL is denied.

## Manual secret-file mode

For clients whose secrets are rotated by another service, the callback also
supports `clientSecretFile` with an atomically replaced mode `0600` (or `0400`)
regular file. This mode hot reloads the secret on token refresh but does not call
DCR or persist a RAT:

```properties
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required clientId="payments-consumer" clientSecretFile="/absolute/private/payments.secret" tokenEndpointUrl="https://keycloak.example/identity/realms/krate/protocol/openid-connect/token" expectedIssuer="https://keycloak.example/identity/realms/krate" scope="kafka" tokenTrustPem="/absolute/trust/keycloak-ca.pem";
```
