package com.krate.kafka.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.auth.SaslExtensionsCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;

/**
 * Kafka login callback that reads the current client secret for every token refresh.
 *
 * <p>The secret is never stored in JAAS options, a process argument, or a log message. A
 * client can atomically replace the restricted secret file while Kafka remains running;
 * Kafka's normal SASL/OAUTHBEARER login refresh then requests a token with the new value.
 * The broker, not this class, verifies the JWT signature.
 */
public final class RotatingSecretLoginCallbackHandler implements AuthenticateCallbackHandler {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_SECRET_BYTES = 4096;
    private static final int MAX_TOKEN_BYTES = 65536;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    @FunctionalInterface
    interface TokenRequester {
        String request(URI endpoint, String clientId, String secret, String scope, SSLContext trust)
                throws IOException;
    }

    private record Config(URI endpoint, String clientId, Path secretFile, String scope,
                          String expectedIssuer, SSLContext trust, Path stateFile) {}

    private final TokenRequester requester;
    private volatile Config config;

    public RotatingSecretLoginCallbackHandler() {
        this(new HttpsTokenRequester());
    }

    RotatingSecretLoginCallbackHandler(TokenRequester requester) {
        this.requester = requester;
    }

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism,
                          List<AppConfigurationEntry> jaasConfigEntries) {
        if (!"OAUTHBEARER".equals(saslMechanism)) {
            throw new ConfigException("Krate OAuth callback requires OAUTHBEARER");
        }
        if (jaasConfigEntries == null || jaasConfigEntries.size() != 1) {
            throw new ConfigException("Krate OAuth callback requires one JAAS entry");
        }
        Map<String, ?> options = jaasConfigEntries.get(0).getOptions();
        Object stateOption = options.get("credentialStateFile");
        if (stateOption instanceof String stateText && !stateText.isBlank()) {
            Path statePath = Path.of(stateText);
            if (!statePath.isAbsolute()) {
                throw new ConfigException("Credential state file path must be absolute");
            }
            config = new Config(null, null, null, null, null, null, statePath);
            return;
        }
        String clientId = required(options, "clientId");
        String secretPath = required(options, "clientSecretFile");
        String endpointText = required(options, "tokenEndpointUrl");
        String expectedIssuer = required(options, "expectedIssuer");
        String scope = required(options, "scope");
        if (!"kafka".equals(scope)) {
            throw new ConfigException("Krate OAuth callback requires scope=kafka");
        }
        URI endpoint;
        try {
            endpoint = URI.create(endpointText);
        } catch (IllegalArgumentException error) {
            throw new ConfigException("Invalid token endpoint URL");
        }
        if (!"https".equalsIgnoreCase(endpoint.getScheme()) || endpoint.getHost() == null
                || endpoint.getUserInfo() != null || endpoint.getFragment() != null) {
            throw new ConfigException("Token endpoint must be an HTTPS URL without user info or fragment");
        }
        if (!expectedIssuer.startsWith("https://")) {
            throw new ConfigException("Expected issuer must be HTTPS");
        }
        Path secretFile;
        try {
            secretFile = Path.of(secretPath);
        } catch (RuntimeException error) {
            throw new ConfigException("Invalid client secret file path");
        }
        if (!secretFile.isAbsolute()) {
            throw new ConfigException("Client secret file path must be absolute");
        }
        SSLContext trust = null;
        Object trustPath = options.get("tokenTrustPem");
        if (trustPath != null && !trustPath.toString().isBlank()) {
            trust = loadTrust(Path.of(trustPath.toString()));
        }
        config = new Config(endpoint, clientId, secretFile, scope, expectedIssuer, trust, null);
    }

    private static String required(Map<String, ?> options, String key) {
        Object value = options.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new ConfigException("Missing Kafka OAuth JAAS option " + key);
        }
        return text;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        Config current = config;
        if (current == null) {
            throw new IOException("Krate OAuth callback is not configured");
        }
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback tokenCallback) {
                if (current.stateFile() != null) {
                    CredentialState state = new DcrCredentialManager().prepare(current.stateFile());
                    String accessToken = requester.request(state.tokenEndpoint(), state.clientId(),
                            state.clientSecret(), "kafka", state.trustPem().isBlank() ? null
                                    : loadTrust(Path.of(state.trustPem())));
                    tokenCallback.token(parseToken(accessToken, state.expectedIssuer(), "kafka"));
                } else {
                    String secret = readRestrictedSecret(current.secretFile());
                    String accessToken = requester.request(current.endpoint(), current.clientId(),
                            secret, current.scope(), current.trust());
                    tokenCallback.token(parseToken(accessToken, current.expectedIssuer(), current.scope()));
                }
            } else if (callback instanceof SaslExtensionsCallback extensionsCallback) {
                extensionsCallback.extensions(SaslExtensions.empty());
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    @Override
    public void close() {
        config = null;
    }

    private static String readRestrictedSecret(Path path) throws IOException {
        try {
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Client secret file must be a regular file without a symlink");
            }
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                    path, LinkOption.NOFOLLOW_LINKS);
            if (!permissions.contains(PosixFilePermission.OWNER_READ)
                    || permissions.stream().anyMatch(p -> p != PosixFilePermission.OWNER_READ
                    && p != PosixFilePermission.OWNER_WRITE)) {
                throw new IOException("Client secret file must have owner-only read/write permissions");
            }
            ByteBuffer buffer = ByteBuffer.allocate(MAX_SECRET_BYTES + 1);
            try (SeekableByteChannel channel = Files.newByteChannel(path,
                    Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
                while (buffer.hasRemaining() && channel.read(buffer) != -1) {
                    // Read the current inode; opening with NOFOLLOW_LINKS rejects a replacement symlink.
                }
                if (buffer.position() > MAX_SECRET_BYTES || channel.read(ByteBuffer.allocate(1)) != -1) {
                    throw new IOException("Client secret file is too large");
                }
            }
            buffer.flip();
            String value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(buffer).toString();
            if (value.endsWith("\r\n")) {
                value = value.substring(0, value.length() - 2);
            } else if (value.endsWith("\n")) {
                value = value.substring(0, value.length() - 1);
            }
            if (value.isEmpty() || value.chars().anyMatch(c -> Character.isISOControl(c)
                    || Character.isWhitespace(c))) {
                throw new IOException("Client secret file has invalid content");
            }
            return value;
        } catch (CharacterCodingException error) {
            throw new IOException("Client secret file must be UTF-8");
        } catch (UnsupportedOperationException error) {
            throw new IOException("Client secret file permissions cannot be checked on this filesystem");
        }
    }

    static OAuthBearerToken parseToken(String accessToken, String expectedIssuer,
                                                String expectedScope) throws IOException {
        if (accessToken == null || accessToken.length() > MAX_TOKEN_BYTES) {
            throw new IOException("Token endpoint did not return a valid access token");
        }
        String[] parts = accessToken.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new IOException("Token endpoint returned a malformed JWT");
        }
        JsonNode claims;
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            if (payload.length > MAX_TOKEN_BYTES) {
                throw new IOException("Token endpoint returned an oversized JWT");
            }
            claims = JSON.readTree(payload);
        } catch (IllegalArgumentException | com.fasterxml.jackson.core.JsonProcessingException error) {
            throw new IOException("Token endpoint returned an unreadable JWT");
        }
        if (claims == null || !expectedIssuer.equals(claims.path("iss").asText())) {
            throw new IOException("Token issuer does not match the configured issuer");
        }
        JsonNode audience = claims.path("aud");
        boolean hasAudience = expectedScope.equals(audience.asText())
                || (audience.isArray() && elementsContain(audience, expectedScope));
        if (!hasAudience) {
            throw new IOException("Token audience does not include kafka");
        }
        String principal = claims.path("kafka_principal").asText();
        if (principal.isBlank() || principal.length() > 256 || principal.chars().anyMatch(
                c -> Character.isISOControl(c) || Character.isWhitespace(c))) {
            throw new IOException("Token lacks a valid kafka_principal claim");
        }
        JsonNode expiry = claims.path("exp");
        if (!expiry.isIntegralNumber() || expiry.asLong() <= Instant.now().plusSeconds(10).getEpochSecond()) {
            throw new IOException("Token is expired or has no usable expiry");
        }
        JsonNode issued = claims.path("iat");
        long startMs = issued.isIntegralNumber() ? issued.asLong() * 1000
                : System.currentTimeMillis();
        Set<String> scopes = new HashSet<>();
        String scopeText = claims.path("scope").asText("");
        for (String scope : scopeText.split(" ")) {
            if (!scope.isBlank()) scopes.add(scope);
        }
        scopes.add(expectedScope);
        return new JwtToken(accessToken, Set.copyOf(scopes), expiry.asLong() * 1000,
                principal, startMs);
    }

    private static boolean elementsContain(JsonNode array, String expected) {
        for (JsonNode entry : array) {
            if (expected.equals(entry.asText())) return true;
        }
        return false;
    }

    private record JwtToken(String value, Set<String> scope, long lifetimeMs,
                            String principalName, Long startTimeMs) implements OAuthBearerToken {}

    static SSLContext loadTrust(Path pemPath) {
        if (!pemPath.isAbsolute() || !Files.isRegularFile(pemPath, LinkOption.NOFOLLOW_LINKS)) {
            throw new ConfigException("Token trust PEM must be an absolute regular file");
        }
        try {
            byte[] pem = Files.readAllBytes(pemPath);
            Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(pem));
            if (certificates.isEmpty()) {
                throw new ConfigException("Token trust PEM contains no certificates");
            }
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            int index = 0;
            for (Certificate certificate : certificates) {
                store.setCertificateEntry("krate-token-ca-" + index++, certificate);
            }
            TrustManagerFactory managers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            managers.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, managers.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException | IOException error) {
            throw new ConfigException("Unable to load token TLS trust material");
        }
    }

    static final class HttpsTokenRequester implements TokenRequester {
        @Override
        public String request(URI endpoint, String clientId, String secret, String scope,
                              SSLContext trust) throws IOException {
            String form = "grant_type=client_credentials&scope=" + encode(scope);
            String authorization = "Basic " + Base64.getEncoder().encodeToString(
                    (encode(clientId) + ":" + encode(secret)).getBytes(StandardCharsets.UTF_8));
            HttpClient.Builder builder = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NEVER);
            if (trust != null) builder.sslContext(trust);
            HttpRequest request = HttpRequest.newBuilder(endpoint)
                    .timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .header("Authorization", authorization)
                    .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                    .build();
            try {
                HttpResponse<String> response;
                try {
                    response = builder.build().send(request,
                            HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                } catch (IOException error) {
                    throw new IOException("Token endpoint request failed");
                }
                if (response.statusCode() != 200) {
                    throw new IOException("Token endpoint returned HTTP " + response.statusCode());
                }
                if (response.body().length() > MAX_TOKEN_BYTES * 2) {
                    throw new IOException("Token endpoint response is too large");
                }
                JsonNode body = JSON.readTree(response.body());
                JsonNode token = body == null ? null : body.path("access_token");
                if (token == null || !token.isTextual()) {
                    throw new IOException("Token endpoint response has no access_token");
                }
                return token.asText();
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException("Token endpoint request interrupted");
            } catch (com.fasterxml.jackson.core.JsonProcessingException error) {
                throw new IOException("Token endpoint returned unreadable JSON");
            }
        }

        private static String encode(String value) {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        }
    }
}
