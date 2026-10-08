# Shared log collector

Fluent Bit 5.1.3 replaces the EOL shared Promtail collector. The built-in Loki
output keeps `job=containerlogs`, `container`, `container_id` and `stream` labels.
`metadata.lua` reads only the top-level Docker `Name` field from `config.v2.json`;
the Docker API socket is no longer needed. The metadata cache refreshes every
five seconds and retains at most 256 container identities. Only names beginning
`krate-` or `epc-` are selected; the collector excludes itself. Missing/invalid
metadata for unknown containers is rejected and reported in collector logs.
Previously identified removed containers can drain using their cached name.

The named state volume holds the SQLite tail offsets and filesystem chunks.
Tail compares filename and inode, watches rotated open files for 30 seconds,
and reads a new file from its head. Docker fragment reassembly precedes Java
stacktrace joining. Tags include the file path, so different containers have
different multiline buffers; the Java parser also groups by Docker's `stream`
field to keep interleaved stdout and stderr separate. The age filter retains the previous seven-day
ingestion cutoff, and Lua preserves nanosecond timestamps.

The output retries without a retry-count limit, with a **1 GiB** disk queue.
Once full, Fluent Bit discards the oldest queued chunks. This is a finite outage
budget, not a guarantee of lossless delivery. Set the queue and host disk budget
for the site's observed log rate and recovery window before deployment. There
is no published throughput guarantee for the 256 MiB/0.5 CPU defaults. A raw
Docker JSON line above 2 MiB stops tailing that file and produces an error rather
than silently skipping the line. Monitor collector logs and host disk capacity.

Filesystem buffering persists emitted chunks across restart. An incomplete
multiline message still being assembled is in-memory state; abrupt termination
can lose that in-flight message. Fluent Bit has a 30-second flush grace and
Compose allows 40 seconds before forced termination. Use graceful shutdown and
retain source logs through the recovery window. This pipeline does not promise
exactly-once delivery; replay/retry can produce duplicates.

No plugin download, cloud endpoint, telemetry service, update check or network
dependency is configured. All scripts and the decoder are packaged locally.
The only collector output is the monitoring network's Loki service.

## Distribution notices

- Fluent Bit 5.1.3: Apache-2.0. The upstream license is retained in
  `vendor/FLUENT-BIT-LICENSE`. Source and build recipe:
  <https://github.com/fluent/fluent-bit/tree/v5.1.3>.
- dkjson 2.11: MIT; the copyright and complete license are embedded in the
  unchanged `vendor/dkjson.lua`. Source: <https://dkolf.de/dkjson-lua/dkjson-2.11.lua>.
  SHA-256: `197cb50834c642f84b4cf99fe724932c50e6d9c92faec7ad89aa25e91df4d481`.
  LPeg is optional upstream and is not bundled or required here.
- The selected official image uses distroless Debian 13 and additional Debian
  runtime libraries. Its Apache OCI label describes the project, not every
  component. The upstream build copies libcurl, OpenSSL, systemd, gcrypt, GnuTLS,
  GMP, libc-related and other library packages; it removes `/usr/share/doc`.
  These dependencies carry mixed licenses, including LGPL/GPL-family terms.
  The amd64 and arm64 image layers were digest-verified and inspected: both
  contain the same 49 Debian package/version entries (40 source versions).
  Exact-version Debian copyright files, referenced common license texts, and
  upstream bundled-library notices are retained under `vendor/image-notices/`;
  package validation checks their presence and hashes. See that directory's
  [provenance and distribution limits](vendor/image-notices/README.md).
  Corresponding-source/relinking obligations still need fulfillment before
  redistribution; a top-level project license and notice copies are insufficient.

The index pinned in `.env.template` resolves to Linux amd64, arm64 and arm/v7.
Krate bundles target amd64/arm64. Runtime/package validation on both Linux
architectures and the target Ubuntu/RHEL filesystems remains required for a
release. The package inventory does not certify the binary's full static linkage
or replace a release compliance review.

Official configuration references: [tail and offsets](https://docs.fluentbit.io/manual/data-pipeline/inputs/tail),
[multiline filter ordering](https://docs.fluentbit.io/manual/data-pipeline/filters/multiline-stacktrace),
[filesystem buffering](https://docs.fluentbit.io/manual/data-pipeline/buffering),
[built-in Loki output](https://docs.fluentbit.io/manual/data-pipeline/outputs/loki).
