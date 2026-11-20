package com.krate.kafka.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

/** One restricted file is the local authority for a managed Kafka client secret and RAT. */
public final class CredentialState {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_STATE_BYTES = 65536;
    private static final Map<Path, Object> JVM_LOCKS = Collections.synchronizedMap(new WeakHashMap<>());

    private final String clientId;
    private final String clientSecret;
    private final long secretExpiresAt;
    private final String registrationAccessToken;
    private final URI registrationUri;
    private final URI tokenEndpoint;
    private final String expectedIssuer;
    private final String trustPem;
    private final long rotationWindowSeconds;
    private final long overlapSeconds;
    private final boolean pending;
    private final String previousSecret;
    private final long previousExpiresAt;
    private final String lastRotationError;

    private CredentialState(String clientId, String clientSecret, long secretExpiresAt,
                            String registrationAccessToken, URI registrationUri,
                            URI tokenEndpoint, String expectedIssuer, String trustPem,
                            long rotationWindowSeconds, long overlapSeconds, boolean pending,
                            String previousSecret, long previousExpiresAt, String lastRotationError) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.secretExpiresAt = secretExpiresAt;
        this.registrationAccessToken = registrationAccessToken;
        this.registrationUri = registrationUri;
        this.tokenEndpoint = tokenEndpoint;
        this.expectedIssuer = expectedIssuer;
        this.trustPem = trustPem;
        this.rotationWindowSeconds = rotationWindowSeconds;
        this.overlapSeconds = overlapSeconds;
        this.pending = pending;
        this.previousSecret = previousSecret;
        this.previousExpiresAt = previousExpiresAt;
        this.lastRotationError = lastRotationError;
    }

    public String clientId() { return clientId; }
    public String clientSecret() { return clientSecret; }
    public long secretExpiresAt() { return secretExpiresAt; }
    public String registrationAccessToken() { return registrationAccessToken; }
    public URI registrationUri() { return registrationUri; }
    public URI tokenEndpoint() { return tokenEndpoint; }
    public String expectedIssuer() { return expectedIssuer; }
    public String trustPem() { return trustPem; }
    public long rotationWindowSeconds() { return rotationWindowSeconds; }
    public long overlapSeconds() { return overlapSeconds; }
    public boolean pending() { return pending; }
    public String previousSecret() { return previousSecret; }
    public long previousExpiresAt() { return previousExpiresAt; }

    public boolean rotationDue() {
        return Instant.now().getEpochSecond() >= secretExpiresAt - rotationWindowSeconds;
    }

    public boolean currentExpired() {
        return Instant.now().getEpochSecond() >= secretExpiresAt;
    }

    public boolean previousUsable() {
        return !previousSecret.isEmpty() && Instant.now().getEpochSecond() < previousExpiresAt;
    }

    public String publicStatus() {
        ObjectNode status = JSON.createObjectNode();
        long now = Instant.now().getEpochSecond();
        status.put("client_id", clientId);
        status.put("secret_expires_at", secretExpiresAt);
        status.put("rotation_due_at", secretExpiresAt - rotationWindowSeconds);
        status.put("seconds_until_expiry", Math.max(0, secretExpiresAt - now));
        status.put("rotation_due", rotationDue());
        status.put("pending", pending);
        status.put("previous_valid_until", previousUsable() ? previousExpiresAt : 0);
        status.put("last_rotation_error", lastRotationError);
        return status.toString();
    }

    public static CredentialState enroll(Path path, String dcrJson, String tokenEndpoint,
                                         String expectedIssuer, String trustPem,
                                         long rotationWindowSeconds, long overlapSeconds) throws IOException {
        if (path == null || !path.isAbsolute()) {
            throw new IllegalArgumentException("Credential state path must be absolute");
        }
        if (rotationWindowSeconds < 1 || overlapSeconds < 1) {
            throw new IllegalArgumentException("Rotation window and overlap must be positive");
        }
        requireDirectorySync(path);
        JsonNode dcr = readJson(dcrJson);
        long expiry = requiredLong(dcr, "client_secret_expires_at");
        if (expiry <= Instant.now().getEpochSecond() + 60) {
            throw new IllegalArgumentException("Client secret expiry must be more than one minute away");
        }
        CredentialState state = new CredentialState(
                requiredText(dcr, "client_id"), requiredText(dcr, "client_secret"), expiry,
                requiredText(dcr, "registration_access_token"),
                httpsUri(requiredText(dcr, "registration_client_uri")),
                httpsUri(tokenEndpoint), expectedIssuer, trustPem == null ? "" : trustPem,
                rotationWindowSeconds, overlapSeconds, false, "", 0, "");
        state.validate();
        return withLock(path, () -> {
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException("Credential state already exists");
            }
            save(path, state);
            return state;
        });
    }

    public static CredentialState load(Path path) throws IOException {
        if (path == null || !path.isAbsolute() || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Credential state must be an absolute regular file without a symlink");
        }
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
        if (!permissions.contains(PosixFilePermission.OWNER_READ)
                || permissions.stream().anyMatch(p -> p != PosixFilePermission.OWNER_READ
                && p != PosixFilePermission.OWNER_WRITE)) {
            throw new IOException("Credential state must have owner-only read/write permissions");
        }
        ByteBuffer bytes = ByteBuffer.allocate(MAX_STATE_BYTES + 1);
        try (SeekableByteChannel channel = Files.newByteChannel(path,
                Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            while (bytes.hasRemaining() && channel.read(bytes) != -1) {
                // Read one bounded snapshot of the atomically replaced state file.
            }
            if (bytes.position() > MAX_STATE_BYTES || channel.read(ByteBuffer.allocate(1)) != -1) {
                throw new IOException("Credential state exceeds the size limit");
            }
        }
        bytes.flip();
        JsonNode data = readJson(StandardCharsets.UTF_8.decode(bytes).toString());
        if (requiredLong(data, "version") != 1) {
            throw new IOException("Unsupported credential state version");
        }
        CredentialState state = new CredentialState(
                requiredText(data, "client_id"), requiredText(data, "client_secret"),
                requiredLong(data, "client_secret_expires_at"),
                requiredText(data, "registration_access_token"),
                httpsUri(requiredText(data, "registration_client_uri")),
                httpsUri(requiredText(data, "token_endpoint_url")),
                requiredText(data, "expected_issuer"), data.path("token_trust_pem").asText(""),
                requiredLong(data, "rotation_window_seconds"),
                requiredLong(data, "overlap_seconds"), data.path("pending").asBoolean(false),
                data.path("previous_client_secret").asText(""),
                data.path("previous_valid_until").asLong(0),
                data.path("last_rotation_error").asText(""));
        state.validate();
        return state;
    }

    public static void save(Path path, CredentialState state) throws IOException {
        state.validate();
        Path parent = path.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Credential state parent directory does not exist");
        }
        requireDirectorySync(path);
        Path temp = Files.createTempFile(parent, ".krate-oauth-state-", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            byte[] data = state.toJson().toString().getBytes(StandardCharsets.UTF_8);
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            requireDirectorySync(path);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    public CredentialState withPending(String newSecret, long newExpiry, String newRat,
                                       String oldSecret, long oldExpiry) {
        return new CredentialState(clientId, newSecret, newExpiry, newRat, registrationUri,
                tokenEndpoint, expectedIssuer, trustPem, rotationWindowSeconds, overlapSeconds,
                true, oldSecret, Math.min(oldExpiry,
                Instant.now().getEpochSecond() + overlapSeconds), "");
    }

    public CredentialState withRatOnly(String newRat, long newExpiry) {
        return new CredentialState(clientId, clientSecret, newExpiry, newRat,
                registrationUri, tokenEndpoint, expectedIssuer, trustPem,
                rotationWindowSeconds, overlapSeconds, false,
                previousUsable() ? previousSecret : "",
                previousUsable() ? previousExpiresAt : 0,
                "dcr-secret-not-rotated");
    }

    public CredentialState finalized(boolean oldVerified) {
        return new CredentialState(clientId, clientSecret, secretExpiresAt,
                registrationAccessToken, registrationUri, tokenEndpoint, expectedIssuer,
                trustPem, rotationWindowSeconds, overlapSeconds, false,
                oldVerified && previousUsable() ? previousSecret : "",
                oldVerified && previousUsable() ? previousExpiresAt : 0, "");
    }

    public CredentialState withRotationError(String errorCode) {
        return new CredentialState(clientId, clientSecret, secretExpiresAt,
                registrationAccessToken, registrationUri, tokenEndpoint, expectedIssuer,
                trustPem, rotationWindowSeconds, overlapSeconds, pending,
                previousSecret, previousExpiresAt, errorCode);
    }

    public CredentialState usePreviousTemporarily() {
        if (!previousUsable()) {
            throw new IllegalStateException("No verified previous secret is usable");
        }
        return new CredentialState(clientId, previousSecret, previousExpiresAt,
                registrationAccessToken, registrationUri, tokenEndpoint, expectedIssuer,
                trustPem, rotationWindowSeconds, overlapSeconds, pending,
                previousSecret, previousExpiresAt, lastRotationError);
    }

    /** Replace an enrolled pair only after the caller has proven the new secret. */
    CredentialState recoveredFrom(String dcrJson) throws IOException {
        JsonNode dcr = readJson(dcrJson);
        if (!clientId.equals(requiredText(dcr, "client_id"))
                || !registrationUri.equals(httpsUri(requiredText(dcr, "registration_client_uri")))) {
            throw new IOException("Recovery DCR identity differs from enrolled client");
        }
        long expiry = requiredLong(dcr, "client_secret_expires_at");
        if (expiry <= Instant.now().plusSeconds(60).getEpochSecond()) {
            throw new IOException("Recovery DCR secret has no usable expiry");
        }
        CredentialState replacement = new CredentialState(clientId,
                requiredText(dcr, "client_secret"), expiry,
                requiredText(dcr, "registration_access_token"), registrationUri,
                tokenEndpoint, expectedIssuer, trustPem, rotationWindowSeconds,
                overlapSeconds, false, "", 0, "");
        replacement.validate();
        return replacement;
    }

    static Path lockPath(Path path) {
        return path.resolveSibling(path.getFileName() + ".lock");
    }

    @FunctionalInterface
    interface LockedOperation<T> {
        T run() throws IOException;
    }

    /** A JVM-local monitor prevents Java's overlapping-file-lock failure; the file lock spans processes. */
    static <T> T withLock(Path path, LockedOperation<T> operation) throws IOException {
        if (path == null || !path.isAbsolute() || path.getFileName() == null) {
            throw new IOException("Credential state path must be absolute");
        }
        Path canonical = path.getParent().toRealPath().resolve(path.getFileName()).normalize();
        Object monitor;
        synchronized (JVM_LOCKS) {
            monitor = JVM_LOCKS.computeIfAbsent(canonical, ignored -> new Object());
        }
        synchronized (monitor) {
            try (FileChannel channel = FileChannel.open(lockPath(canonical),
                    Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                            LinkOption.NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                 var ignored = channel.lock()) {
                return operation.run();
            }
        }
    }

    /** Flush the directory entry as well as file data across an atomic rename. */
    static void requireDirectorySync(Path path) throws IOException {
        Path parent = path == null ? null : path.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Credential state parent directory is unavailable");
        }
        try (FileChannel directory = FileChannel.open(parent,
                Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            directory.force(true);
        } catch (IOException | RuntimeException error) {
            throw new IOException("Credential state directory sync unavailable; operator recovery may be required");
        }
    }

    private ObjectNode toJson() {
        ObjectNode data = JSON.createObjectNode();
        data.put("version", 1);
        data.put("client_id", clientId);
        data.put("client_secret", clientSecret);
        data.put("client_secret_expires_at", secretExpiresAt);
        data.put("registration_access_token", registrationAccessToken);
        data.put("registration_client_uri", registrationUri.toString());
        data.put("token_endpoint_url", tokenEndpoint.toString());
        data.put("expected_issuer", expectedIssuer);
        data.put("token_trust_pem", trustPem);
        data.put("rotation_window_seconds", rotationWindowSeconds);
        data.put("overlap_seconds", overlapSeconds);
        data.put("pending", pending);
        data.put("previous_client_secret", previousUsable() ? previousSecret : "");
        data.put("previous_valid_until", previousUsable() ? previousExpiresAt : 0);
        data.put("last_rotation_error", lastRotationError);
        return data;
    }

    private void validate() {
        if (clientId.isBlank() || clientSecret.isBlank() || registrationAccessToken.isBlank()
                || secretExpiresAt < 1 || rotationWindowSeconds < 1 || overlapSeconds < 1
                || !expectedIssuer.startsWith("https://") || registrationUri == null
                || tokenEndpoint == null || (!trustPem.isEmpty() && !Path.of(trustPem).isAbsolute())
                || (!lastRotationError.isEmpty() && !"dcr-rotation-failed".equals(lastRotationError)
                && !"state-sync-unavailable".equals(lastRotationError)
                && !"dcr-secret-not-rotated".equals(lastRotationError))) {
            throw new IllegalArgumentException("Credential state is incomplete or invalid");
        }
    }

    private static JsonNode readJson(String text) throws IOException {
        if (text == null || text.length() > MAX_STATE_BYTES) {
            throw new IOException("Credential state JSON exceeds the size limit");
        }
        JsonNode node;
        try {
            node = JSON.readTree(text);
        } catch (JsonProcessingException error) {
            throw new IOException("Credential state JSON is invalid");
        }
        if (node == null || !node.isObject()) {
            throw new IOException("Credential state must be a JSON object");
        }
        return node;
    }

    private static String requiredText(JsonNode data, String key) throws IOException {
        JsonNode node = data.path(key);
        if (!node.isTextual() || node.asText().isBlank()) {
            throw new IOException("Credential state missing " + key);
        }
        return node.asText();
    }

    private static long requiredLong(JsonNode data, String key) throws IOException {
        JsonNode node = data.path(key);
        if (!node.isIntegralNumber()) {
            throw new IOException("Credential state missing " + key);
        }
        return node.asLong();
    }

    private static URI httpsUri(String text) throws IOException {
        try {
            URI uri = URI.create(text);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getUserInfo() != null || uri.getFragment() != null) {
                throw new IOException("Credential state URL must be HTTPS");
            }
            return uri;
        } catch (IllegalArgumentException error) {
            throw new IOException("Credential state URL is invalid");
        }
    }
}
