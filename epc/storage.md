# EPC dedicated storage

EPC supports a dedicated ext4 or XFS filesystem mounted read-write at the
configured `KAFKA_DATA_DIR` (default `/data`). The path must be an exact
mountpoint, not a directory under `/` or under a different mount. Subdirectory
bind mounts and an ambiguous stack of mounts are refused.

1. Identify the expected **filesystem UUID** from the storage inventory and
   verify it against the intended device. Do not choose the UUID solely by
   inspecting whatever happens to be mounted at `/data`. Make the mount
   persistent through your normal host provisioning (for example, a UUID
   entry in fstab). The host and Compose daemon must see the same mount.
2. Before opening Studio or running install, stage the expected value in
   the package's `.env`. For a new package with no `.env`:

   ```sh
   ./krate config set KAFKA_DATA_DIR=/data
   ./krate config set KAFKA_DATA_FS_UUID=<verified-lowercase-filesystem-uuid>
   ./krate doctor
   ```

   Replace the angle-bracket value with the recorded UUID. Preserve an existing
   installation's `.env`; make the change in the installed or explicitly
   selected takeover directory instead. Studio's install form does not
   discover or enroll unknown disks. Also set the expectation in the
   retained site configuration when staging an upgrade.
3. Run `./krate install` (or Studio Install) once Doctor confirms filesystem
   identity. To migrate older running brokers, arrange a maintenance window,
   stop them with the current installation, and install the guarded release
   while the expected filesystem is present. The install recreates affected
   containers. `krate restart` alone **does not** migrate pre-guard containers.

A failed or incorrect mount must not be worked around by creating broker
directories on the system disk or changing the expected UUID to the observed
incorrect disk. Restore the intended mount, then run `./krate doctor` and
`./krate start`. On a failed automatic restart, check `./krate status` and
`./krate logs` before retrying. The guarded broker validates its actual
container bind against the configured device's metadata on every start,
including a Docker daemon restart. Docker's broker data binds do not create
host directories if the configured source is missing.

This is a startup and preflight guard, not live storage failover, and cannot
protect against intentional host reconfiguration by a privileged administrator.
