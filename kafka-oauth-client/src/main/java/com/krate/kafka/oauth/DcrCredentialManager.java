package com.krate.kafka.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import javax.net.ssl.SSLContext;

/** Coordinates DCR secret and registration-token rotation in one local state file. */
public final class DcrCredentialManager {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static final int MAX_DCR_BYTES = 131072;

    interface DcrTransport {
        JsonNode get(URI uri, String rat, SSLContext trust) throws IOException;
        JsonNode put(URI uri, String rat, JsonNode body, SSLContext trust) throws IOException;
    }

    @FunctionalInterface
    interface DirectorySync {
        void check(Path path) throws IOException;
    }

    private final DcrTransport dcr;
    private final RotatingSecretLoginCallbackHandler.TokenRequester tokens;
    private final DirectorySync directorySync;

    public DcrCredentialManager() {
        this(new HttpsDcrTransport(), new RotatingSecretLoginCallbackHandler.HttpsTokenRequester());
    }

    DcrCredentialManager(DcrTransport dcr,
                         RotatingSecretLoginCallbackHandler.TokenRequester tokens) {
        this(dcr, tokens, CredentialState::requireDirectorySync);
    }

    DcrCredentialManager(DcrTransport dcr,
                         RotatingSecretLoginCallbackHandler.TokenRequester tokens,
                         DirectorySync directorySync) {
        this.dcr = dcr;
        this.tokens = tokens;
        this.directorySync = directorySync;
    }

    /** An explicit operator rotation; any failure is returned to the caller. */
    public CredentialState rotate(Path path) throws IOException {
        return CredentialState.withLock(path, () -> rotateLocked(path, CredentialState.load(path)));
    }

    /** Repair after a lost DCR PUT response using a replacement representation from Keycloak. */
    public CredentialState recover(Path path, String dcrJson) throws IOException {
        return CredentialState.withLock(path, () -> {
            CredentialState current = CredentialState.load(path);
            directorySync.check(path);
            CredentialState replacement = current.recoveredFrom(dcrJson);
            if (!tokenWorks(replacement, replacement.clientSecret())) {
                throw new IOException("Recovery secret could not mint a Kafka token");
            }
            CredentialState.save(path, replacement);
            return replacement;
        });
    }

    /** Called by each Kafka login refresh; a valid current credential survives a DCR outage. */
    public CredentialState prepare(Path path) throws IOException {
        return CredentialState.withLock(path, () -> {
            CredentialState state = CredentialState.load(path);
            if (state.pending()) {
                try {
                    return finishPending(path, state);
                } catch (IOException error) {
                    if (state.previousUsable() && tokenWorks(state, state.previousSecret())) {
                        return state.usePreviousTemporarily();
                    }
                    throw new IOException("Pending DCR credential could not be verified");
                }
            }
            if (!state.rotationDue()) {
                if (state.currentExpired()) throw new IOException("Client secret expired");
                return state;
            }
            try {
                return rotateLocked(path, state);
            } catch (IOException error) {
                CredentialState current = CredentialState.load(path);
                if (current.pending()) {
                    if (current.previousUsable() && tokenWorks(current, current.previousSecret())) {
                        return current.usePreviousTemporarily();
                    }
                    throw new IOException("Pending DCR credential could not be verified");
                }
                current = current.withRotationError("dcr-rotation-failed");
                CredentialState.save(path, current);
                if (current.currentExpired()) {
                    throw new IOException("Client secret expired and DCR rotation failed");
                }
                return current;
            }
        });
    }

    private CredentialState rotateLocked(Path path, CredentialState state) throws IOException {
        if (state.pending()) return finishPending(path, state);
        // Refuse remote mutation if this host cannot sync the local state directory.
        directorySync.check(path);
        SSLContext trust = trust(state);
        JsonNode current = dcr.get(state.registrationUri(), state.registrationAccessToken(), trust);
        requireIdentity(current, state);
        if (!state.clientSecret().equals(requiredText(current, "client_secret"))) {
            throw new IOException("DCR state differs from local secret; operator recovery is required");
        }
        String activeRat = optionalText(current, "registration_access_token");
        if (activeRat.isBlank()) activeRat = state.registrationAccessToken();
        ObjectNode update = (ObjectNode) current.deepCopy();
        update.remove("registration_access_token");
        JsonNode result = dcr.put(state.registrationUri(), activeRat, update, trust);
        requireIdentity(result, state);
        String newSecret = requiredText(result, "client_secret");
        String newRat = requiredText(result, "registration_access_token");
        long newExpiry = requiredLong(result, "client_secret_expires_at");
        if (newExpiry <= Instant.now().plusSeconds(60).getEpochSecond()) {
            throw new IOException("DCR returned no usable secret expiry; operator recovery is required");
        }
        if (newSecret.equals(state.clientSecret())) {
            // Keycloak may rotate only the RAT before its configured secret rotation window.
            CredentialState ratOnly = state.withRatOnly(newRat, newExpiry);
            CredentialState.save(path, ratOnly);
            if (!tokenWorks(ratOnly, ratOnly.clientSecret())) {
                throw new IOException("DCR updated the RAT but the current secret could not mint a Kafka token");
            }
            if (ratOnly.currentExpired()) {
                throw new IOException("Client secret expired and DCR did not rotate it");
            }
            return ratOnly;
        }
        // Request file and directory sync for the pair before testing either value.
        CredentialState pending = state.withPending(newSecret, newExpiry, newRat,
                state.clientSecret(), state.secretExpiresAt());
        CredentialState.save(path, pending);
        return finishPending(path, pending);
    }

    private CredentialState finishPending(Path path, CredentialState pending) throws IOException {
        if (!tokenWorks(pending, pending.clientSecret())) {
            throw new IOException("New DCR secret could not mint a Kafka token; state remains pending");
        }
        boolean oldVerified = pending.previousUsable()
                && tokenWorks(pending, pending.previousSecret());
        CredentialState completed = pending.finalized(oldVerified);
        CredentialState.save(path, completed);
        return completed;
    }

    private boolean tokenWorks(CredentialState state, String secret) {
        try {
            String token = tokens.request(state.tokenEndpoint(), state.clientId(), secret,
                    "kafka", trust(state));
            RotatingSecretLoginCallbackHandler.parseToken(token, state.expectedIssuer(), "kafka");
            return true;
        } catch (IOException error) {
            return false;
        }
    }

    private static SSLContext trust(CredentialState state) throws IOException {
        try {
            return state.trustPem().isBlank() ? null
                    : RotatingSecretLoginCallbackHandler.loadTrust(Path.of(state.trustPem()));
        } catch (RuntimeException error) {
            throw new IOException("DCR token trust configuration is invalid");
        }
    }

    private static void requireIdentity(JsonNode response, CredentialState state) throws IOException {
        if (response == null || !response.isObject()
                || !state.clientId().equals(requiredText(response, "client_id"))
                || !state.registrationUri().toString().equals(
                requiredText(response, "registration_client_uri"))) {
            throw new IOException("DCR response does not match the enrolled client");
        }
    }

    private static String requiredText(JsonNode node, String key) throws IOException {
        JsonNode value = node.path(key);
        if (!value.isTextual() || value.asText().isBlank()) {
            throw new IOException("DCR response missing " + key);
        }
        return value.asText();
    }

    private static String optionalText(JsonNode node, String key) {
        JsonNode value = node.path(key);
        return value.isTextual() ? value.asText() : "";
    }

    private static long requiredLong(JsonNode node, String key) throws IOException {
        JsonNode value = node.path(key);
        if (!value.isIntegralNumber()) throw new IOException("DCR response missing " + key);
        return value.asLong();
    }

    private static final class HttpsDcrTransport implements DcrTransport {
        @Override
        public JsonNode get(URI uri, String rat, SSLContext trust) throws IOException {
            return send(uri, rat, null, trust);
        }

        @Override
        public JsonNode put(URI uri, String rat, JsonNode body, SSLContext trust) throws IOException {
            return send(uri, rat, body, trust);
        }

        private JsonNode send(URI uri, String rat, JsonNode body, SSLContext trust) throws IOException {
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                throw new IOException("DCR URL must use HTTPS");
            }
            HttpClient.Builder builder = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NEVER);
            if (trust != null) builder.sslContext(trust);
            HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                    .timeout(TIMEOUT)
                    .header("Authorization", "Bearer " + rat)
                    .header("Accept", "application/json");
            if (body == null) {
                request.GET();
            } else {
                request.header("Content-Type", "application/json")
                        .PUT(HttpRequest.BodyPublishers.ofString(body.toString()));
            }
            HttpResponse<String> response;
            try {
                response = builder.build().send(request.build(),
                        HttpResponse.BodyHandlers.ofString());
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException("DCR request interrupted");
            } catch (IOException error) {
                throw new IOException("DCR request failed; remote state may need operator recovery");
            }
            if (response.statusCode() != 200) {
                throw new IOException("DCR request returned HTTP " + response.statusCode());
            }
            if (response.body().length() > MAX_DCR_BYTES) {
                throw new IOException("DCR response exceeds the size limit");
            }
            JsonNode parsed;
            try {
                parsed = JSON.readTree(response.body());
            } catch (com.fasterxml.jackson.core.JsonProcessingException error) {
                throw new IOException("DCR response JSON is invalid");
            }
            if (parsed == null || !parsed.isObject()) {
                throw new IOException("DCR response is not a JSON object");
            }
            return parsed;
        }
    }
}
