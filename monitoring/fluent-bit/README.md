# Shared log collector

Fluent Bit 5.1.3 replaces the EOL shared Promtail collector. The built-in Loki
output keeps `job=containerlogs`, `container`, `container_id` and `stream` labels.
A second Loki-protocol output sends the same records, labels and exact message
text to VictoriaLogs (`/insert/loki/api/v1/push?disable_message_parsing=1`).
Each output has its own bounded filesystem queue (1 GiB), so Loki delivery
continues while VictoriaLogs is unavailable and the backlog is sent when it
returns.
The `log-discovery` helper scans only metadata every five seconds and exposes
symlinks for names beginning `krate-` or `epc-` in the dedicated sources volume.
Fluent Bit tails that allowlist, so unrelated containers' log payloads never
enter Docker fragment decoding, Java assembly, offsets or filesystem buffering.
The helper never opens log payloads. It has no network, a read-only root filesystem
and a separate 64 MiB/0.1 CPU budget. `krate monitor up` starts the collector
only after a clean initial discovery scan. After a Docker daemon restart or host
reboot the restart policy starts both without that ordering; the collector then
tails the sources kept in the volume, which still point at the same container
IDs with their saved offsets. Recreated IDs are discovered without a collector
restart. Discovery plus tail refresh can take roughly ten seconds, so a
container that starts and is removed within that window is not collected. Both
collector and discovery containers are excluded.

Readiness is bound to a fresh startup generation on a 64 KiB tmpfs; a persisted
receipt from the previous container cannot satisfy the initial-discovery gate.
A container whose metadata cannot be read keeps its existing source rather than
being pruned, because removing a tailed link makes Fluent Bit drop that file's
offset and re-admission would replay the whole log. Only containers that were
positively renamed out of scope or removed are pruned; Fluent Bit keeps reading
a pruned file for its 30-second rotate wait and the Lua guard drops those lines.
Metadata or pruning errors make the helper unhealthy, and after twelve
consecutive erroring cycles (about a minute) it exits so its restart policy
shows the problem in `krate monitor status` instead of collecting less silently.

`metadata.lua` verifies the top-level Docker `Name` again for each admitted
container, with a five-second cache and at most 256 identities. Neither service
needs the Docker API socket. Missing/invalid
metadata for unknown containers is rejected and reported in collector logs.
Previously identified removed containers can drain using their cached name.

The named state volume holds the SQLite tail offsets and filesystem chunks.
The separate sources volume holds only symlinks and the discovery health receipt.
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
- Discovery uses the official Python 3.14.8 slim-trixie image, pinned for Linux
  amd64/arm64. Its Python license, bundled Expat notice, exact Debian inventory
  and dependency notices are retained and hash-checked under
  [vendor/discovery-notices](vendor/discovery-notices/README.md). Both architectures
  have 87 Debian packages covering the same 61 source versions; one binary
  package has an architecture-specific rebuild. GPL tools and LGPL libraries
  are included, so their redistribution obligations remain applicable.
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
