package com.krate.kafka.oauth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** Secret-free operator entry point for managed Kafka client credentials. */
public final class CredentialStateCli {
    private CredentialStateCli() {}

    public static void main(String[] args) {
        try {
            System.out.println(run(args));
        } catch (Exception error) {
            // Do not print causes: parser and HTTP exceptions can include response content.
            System.err.println("Krate OAuth credential command failed; inspect state and Keycloak access");
            System.exit(1);
        }
    }

    static String run(String[] args) throws IOException {
        if (args.length < 1 || !Set.of("enroll", "rotate", "recover", "status").contains(args[0])) {
            throw new IllegalArgumentException("Expected enroll, rotate, recover or status");
        }
        String command = args[0];
        Map<String, String> options = parseOptions(args);
        Set<String> allowed = switch (command) {
            case "enroll" -> Set.of("--state", "--token-endpoint", "--issuer", "--trust-pem",
                    "--rotation-window-seconds", "--overlap-seconds");
            default -> Set.of("--state");
        };
        if (!allowed.containsAll(options.keySet())) {
            throw new IllegalArgumentException("Unsupported option");
        }
        Path state = Path.of(required(options, "--state"));
        if (!state.isAbsolute()) throw new IllegalArgumentException("State path must be absolute");
        return switch (command) {
            case "enroll" -> {
                String trust = options.getOrDefault("--trust-pem", "");
                CredentialState enrolled = CredentialState.enroll(state,
                        readDcrInput(),
                        required(options, "--token-endpoint"), required(options, "--issuer"),
                        trust, positiveLong(options, "--rotation-window-seconds"),
                        positiveLong(options, "--overlap-seconds"));
                yield enrolled.publicStatus();
            }
            case "rotate" -> new DcrCredentialManager().rotate(state).publicStatus();
            case "recover" -> new DcrCredentialManager().recover(state, readDcrInput()).publicStatus();
            case "status" -> {
                CredentialState loaded = CredentialState.load(state);
                try {
                    CredentialState.requireDirectorySync(state);
                } catch (IOException error) {
                    loaded = loaded.withRotationError("state-sync-unavailable");
                }
                yield loaded.publicStatus();
            }
            default -> throw new IllegalArgumentException("Unsupported command");
        };
    }

    private static Map<String, String> parseOptions(String[] args) {
        if (args.length % 2 != 1) throw new IllegalArgumentException("Options require values");
        Map<String, String> parsed = new HashMap<>();
        for (int i = 1; i < args.length; i += 2) {
            if (!args[i].startsWith("--") || args[i + 1].isBlank()
                    || parsed.putIfAbsent(args[i], args[i + 1]) != null) {
                throw new IllegalArgumentException("Invalid or duplicate option");
            }
        }
        return parsed;
    }

    private static String required(Map<String, String> options, String key) {
        String value = options.get(key);
        if (value == null) throw new IllegalArgumentException("Missing " + key);
        return value;
    }

    private static long positiveLong(Map<String, String> options, String key) {
        long value = Long.parseLong(required(options, key));
        if (value < 1) throw new IllegalArgumentException("Invalid " + key);
        return value;
    }

    private static String readDcrInput() throws IOException {
        byte[] data = System.in.readNBytes(65537);
        if (data.length == 0 || data.length > 65536) {
            throw new IOException("DCR input is missing or oversized");
        }
        return new String(data, StandardCharsets.UTF_8);
    }
}
