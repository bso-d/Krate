# EPC dedicated storage

EPC supports a dedicated ext4 or XFS filesystem mounted read-write at the
configured `KAFKA_DATA_DIR` (default `/data`). The path must be an exact
mountpoint, not a directory under `/` or under a different mount. Subdirectory
bind mounts and an ambiguous stack of mounts are refused.

## First install from an extracted EPC package

1. Identify the expected **filesystem UUID** from the storage inventory and
   verify it against the intended device. Do not choose the UUID solely by
   inspecting whatever happens to be mounted at `/data`. Make the mount
   persistent through your normal host provisioning (for example, a UUID
   entry in fstab). The host and Compose daemon must see the same mount.
2. For a **new installation**, open a shell in the freshly extracted, verified
   EPC archive directory, not the installed workspace. Create the package's own
   private `.env` without overwriting or following an existing file or link:

   ```sh
   (
     set -euC
     if [ ! -d images ] || [ ! -f images.lock.tsv ] || [ ! -f .bundle-arch ] ||
        [ ! -f .env.template ] || [ -L .env.template ]; then
       printf '%s\n' 'Run this only from a verified, freshly extracted EPC archive.' >&2
       exit 2
     fi
     if [ -e .env ] || [ -L .env ]; then
       printf '%s\n' 'Package .env already exists. It was not changed; verify it or use a fresh extraction.' >&2
       exit 2
     fi
     umask 077
     cat .env.template > .env
   )
   ```

   Continue only after the command succeeds. Edit the existing
   `KAFKA_DATA_DIR` and `KAFKA_DATA_FS_UUID` lines in that new file using
   the chosen mount path and verified lowercase UUID. Do not modify
   `.env.template` or add duplicate keys. If Docker is absent, run
   `./krate docker-install` or use **Install Docker** in Studio first.
   Once Docker is available, run `./krate doctor` or Studio Doctor to check
   the filesystem. Then run `./krate install` or click **Install** in Studio.
   Studio does not discover or enrol unknown disks.

   Do not use `./krate config set` from the extracted package for these pins.
   It forwards to the installed CLI if present and fails before the first
   install otherwise.

## Upgrade an existing site

The installed site's `.env` takes precedence over the package's `.env`.
Verify the intended disk and its pins from the installed workspace; preserve
the site's other settings. If taking over a legacy installation, verify its
site files in the explicitly selected takeover source before installing.
Arrange a maintenance window, stop the brokers from the current installation
and install the guarded release with the expected filesystem mounted. The
install recreates affected containers. `krate restart` alone does not
migrate pre-guard containers.

## Change a storage pin

`krate restart` checks the existing broker containers against the configured
path and UUID before restarting them. If either differs, it refuses the
restart and leaves the containers unchanged. A broker that was already
running is **not** stopped by this refusal.

Schedule a maintenance window. With the old pin still in effect, run
`./krate stop` and verify both brokers are stopped. Back up and migrate both
broker trees to the intended mounted disk, preserving ownership, permissions
and each node's metadata. Do not start a blank tree or change the cluster ID
under an existing installation. Only after verifying the copy and the
intended UUID, update the two pins, run `./krate doctor`, then run
`./krate start` to let Compose recreate the containers with the new binds.
Verify broker health and read back known data before retiring the old disk.

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

Set the two storage fields as plain literal `KEY=value` lines. Do not use duplicate declarations, `export`, interpolated values, or shell overrides.

On a Docker engine with SELinux confinement enabled, `krate install` labels only the broker data trees on the verified disk as `container_file_t:s0`. This is the shared container data label; it is not a private per-container MCS `:Z` label. Other containers are not given access to these paths by Krate. It does not relabel the raw block device. Broker startup reads its numeric identity through read-only Linux mount metadata and sysfs, not by opening the disk.
