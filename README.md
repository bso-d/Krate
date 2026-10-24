<a id="readme-top"></a>

<div align="center">
  <img src="assets/krate-logo.png" alt="Krate logo: a blue and teal crate with connected nodes" width="240">

  <h1>Krate</h1>

  <p>Portable Kafka packages for Ubuntu and RHEL virtual machines.</p>

  <p>
    <a href="https://github.com/bso-d/Krate/actions/workflows/broker-ci.yml">
      <img src="https://github.com/bso-d/Krate/actions/workflows/broker-ci.yml/badge.svg?branch=main" alt="Broker images CI">
    </a>
    <a href="https://github.com/bso-d/Krate/actions/workflows/codeql.yml">
      <img src="https://github.com/bso-d/Krate/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL checks">
    </a>
    <img src="https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white" alt="Docker">
    <img src="https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white" alt="Bash">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue" alt="License: AGPL-3.0"></a>
  </p>

  <p>
    <a href="#start-on-a-connected-machine">Get started</a> ·
    <a href="#build-an-offline-package">Build a package</a> ·
    <a href="https://github.com/bso-d/Krate/releases">Downloads</a> ·
    <a href="#guides">Guides</a>
  </p>
</div>

<details>
  <summary>Contents</summary>

  - [What Krate does](#what-krate-does)
  - [Problems Krate solves](#problems-krate-solves)
  - [How it differs from similar repositories](#how-it-differs-from-similar-repositories)
  - [Choose an edition](#choose-an-edition)
  - [What you need](#what-you-need)
  - [Start on a connected machine](#start-on-a-connected-machine)
  - [Build an offline package](#build-an-offline-package)
  - [Install the package on a VM](#install-the-package-on-a-vm)
  - [Everyday commands](#everyday-commands)
  - [Identity and SSO for EPC and regular Krate](#identity-and-sso-for-epc-and-regular-krate)
  - [Monitoring](#monitoring)
  - [How the parts fit together](#how-the-parts-fit-together)
  - [Limits to understand](#limits-to-understand)
  - [Development and checks](#development-and-checks)
  - [Component credits](#component-credits)
  - [License](#license)
  - [Contributing and community conduct](#contributing-and-community-conduct)

</details>

## What Krate does

[Apache Kafka](https://kafka.apache.org/) lets applications send, store, and read streams of messages. A Kafka **broker** is a server that handles those messages. Several brokers working together form a **cluster**.

Krate supplies the files and command-line tools to run a Kafka cluster with [Docker](https://www.docker.com/), which runs software in containers. It can also collect the container images and setup files into one compressed package. Build that package on a machine with internet access, copy it to a matching virtual machine (VM), and install it there without downloading the images again.

Each edition includes [Kafbat UI](https://github.com/kafbat/kafka-ui), a browser interface for viewing brokers, topics (named message streams), and consumer groups (applications sharing the work of reading messages). The UI sits behind an nginx web proxy with HTTPS and a login.

## Problems Krate solves

| Problem | What Krate provides |
| --- | --- |
| The VM cannot download container images | A package containing the images and setup files, plus a checksum to check the transferred file |
| The VM has a different processor or operating system from the build machine | A build for the chosen processor, a processor check before installation, and matching Ubuntu or RHEL Docker packages when requested |
| Setup steps are spread across separate commands and files | A command script for installation, health checks, logs, and message backlog, with the UI already configured |
| Measurements and logs need separate setup | Included monitoring files and images, started with a separate command when needed |

You still need suitable disk space, OS dependencies, and working network settings. Krate prepares the software and runs host checks; the deployment guides cover the remaining host setup.

## How it differs from similar repositories

| Repository | Main purpose | Krate's focus |
| --- | --- | --- |
| [Apache Kafka Docker examples](https://github.com/apache/kafka/tree/trunk/docker/examples) | Show how to configure single-node and multi-node Kafka containers, including encrypted and authenticated connections | Provide selected cluster setups with an offline package builder, optional Docker installer, management commands, UI, and monitoring |
| [Confluent cp-all-in-one](https://github.com/confluentinc/cp-all-in-one) | Run examples of the broader Confluent Platform, including schema management, connectors, and stream-processing services | Package Kafka, its UI, and monitoring for VM installation; those extra Confluent services are not included |

Krate adds package builds and host management commands around Kafka and Docker, especially for a VM without internet access. Its supplied clusters share one host and need additional configuration for secure remote application access.

## Choose an edition

Ubuntu and Red Hat Enterprise Linux (RHEL) are the target operating systems.

| Edition | What it runs | Intended host | Command |
| --- | --- | --- | --- |
| **Krate (default)** | Four brokers; Kafka manages its own coordination | Ubuntu 22.04 or 24.04, x86_64 or ARM64 | `kraft/krate` |
| **EPC** | Two brokers using KRaft, with message data stored under `/data` | Tailored for RHEL 9, x86_64 or ARM64 | `epc/krate` |

These are the two active releases. Each package contains its own security features and monitoring files. The `zk/` directory is a frozen legacy package for existing users. EPC is the tailored RHEL deployment.

For a first local run, the steps below use KRaft. All brokers in these setups run on the same host.

### Ready-made downloads

The [releases page](https://github.com/bso-d/Krate/releases) holds two kinds of release. Check the tag prefix and title before downloading:

| Kind | Tag | Title starts with | What you get |
| --- | --- | --- | --- |
| **Offline install package** | `package-kraft-vN`, `package-epc-vN` | `Offline install package` | A `.tar.gz` to copy to the VM, its `.sha256` checksum and the image lock file. Install it with `./krate install`. From `package-kraft-v2` and `package-epc-v4` on, a `-sources.tar` beside each package holds the corresponding source of its copyleft components; earlier package releases have none. |
| **Broker images** | `kraft-vX.Y.Z`, `zk-vX.Y.Z` | `Broker images` | References to container images on GHCR. Nothing to install on a VM; the default setups do not use these images. |

Current offline install packages. Each includes Keycloak SSO, the Grafana and Perses monitoring paths, and the Docker packages for its target OS. Upgrade steps from the earlier packages are in each release's notes:

| Release | Edition | Packages |
| --- | --- | --- |
| [`package-kraft-v4`](https://github.com/bso-d/Krate/releases/tag/package-kraft-v4) | KRaft, Ubuntu 24.04 | `krate-kraft-v4-amd64.tar.gz` (x86_64), `krate-kraft-v4-arm64.tar.gz` (ARM64) |
| [`package-epc-v5`](https://github.com/bso-d/Krate/releases/tag/package-epc-v5) | EPC, RHEL 9 | `krate-epc-v5-amd64.tar.gz` (x86_64), `krate-epc-v5-arm64.tar.gz` (ARM64) |

Earlier packages:

| Release | Package |
| --- | --- |
| [`package-kraft-v3`](https://github.com/bso-d/Krate/releases/tag/package-kraft-v3) | KRaft with Keycloak SSO, Grafana and Perses monitoring, x86_64 and ARM64: `krate-kraft-v3-<arch>.tar.gz` |
| [`package-kraft-v2`](https://github.com/bso-d/Krate/releases/tag/package-kraft-v2) | KRaft with Keycloak SSO, Grafana and Perses monitoring, x86_64 and ARM64: `krate-kraft-v2-<arch>.tar.gz` |
| [`package-epc-v4`](https://github.com/bso-d/Krate/releases/tag/package-epc-v4) | RHEL/EPC with Keycloak SSO, Grafana and Perses monitoring, x86_64 and ARM64: `krate-epc-v4-<arch>.tar.gz` |
| [`package-kraft-v1`](https://github.com/bso-d/Krate/releases/tag/package-kraft-v1) | KRaft with Keycloak SSO, Grafana monitoring only, x86_64 and ARM64: `krate-kraft-v1-<arch>.tar.gz` |
| [`package-epc-v3`](https://github.com/bso-d/Krate/releases/tag/package-epc-v3) | RHEL/EPC with Keycloak SSO, Grafana monitoring only, x86_64: `krate-epc-v3-amd64.tar.gz` |
| [`epc-v2`](https://github.com/bso-d/Krate/releases/tag/epc-v2) | RHEL/EPC with Keycloak SSO, x86_64: `krate-epc-v2-amd64.tar.gz` |
| [`epc-v1`](https://github.com/bso-d/Krate/releases/tag/epc-v1) | RHEL/EPC, x86_64: `kafka-epc-v1-amd64.tar.gz` |
| [`v1.0.0`](https://github.com/bso-d/Krate/releases/tag/v1.0.0) | Archived ZooKeeper package, x86_64: `kafka-zk-v5-amd64.tar.gz` |

New packages are released as `package-kraft-vN` and `package-epc-vN`; see [Release an offline install package](#release-an-offline-install-package). To target Ubuntu 22.04 or another combination, build a package from source using the commands below. Earlier downloads keep their original `kafka-*` names. KRaft and EPC packages use `krate-*`; ZooKeeper keeps `kafka-zk-*`.

## What you need

- **To run a cluster:** Docker Engine 25.0.3 or newer, a working Docker service, and Docker Compose. The scripts accept the `docker compose` plugin or standalone `docker-compose` 1.29.2 or newer; the examples use the plugin.
- **To create the UI certificate:** OpenSSL, or your own certificate and key at `certs/server.crt` and `certs/server.key`.
- **To run from a checkout or build packages:** a connected machine with Docker, Bash, Git, Python 3, Node.js and npm (for the Kafbat UI image), and GNU Make 4.0 or newer, which `./krate` calls for you. On macOS, `brew install make` provides it.
- **For KRaft/EPC monitoring:** Python 3 on the host, in addition to Docker.

Choose the package for the target VM's processor: `amd64` means x86_64; `arm64` means ARM64. Leave room for the package, loaded images, and stored messages. The EPC guide explains how to budget its `/data` disk.

## Start on a connected machine

1. Clone the repository.

   ```bash
   git clone https://github.com/bso-d/Krate.git
   cd Krate/kraft
   ```

2. Optionally set the UI hostname, for example `./krate config set KAFKA_UI_FQDN=kafka.example.com`. Left blank, it is this machine's hostname.

3. Start the cluster and show its logins.

   ```bash
   ./krate start
   ./krate credentials
   ```

The first `start` does all of the setup: it creates `.env` and `monitoring/.env`, generates every password and secret, creates a self-signed UI certificate, builds the Kafbat UI image (several minutes) and downloads the other images. Nothing needs copying or editing by hand. `./krate setup` runs the same preparation without starting anything. When startup is complete, `start` reports healthy services and `credentials` prints every address and login; open the Kafbat UI address to view the four brokers.

The generated certificate is self-signed, so the browser will show a trust warning. You can trust `certs/server.crt` or supply a certificate trusted by your browser.

For ZooKeeper, use `cd Krate/zk` and `./kafka` instead of `./krate`. Use `start` when running directly from the repository. The `install` command is for an extracted package containing saved images.

## Build an offline package

Run `./krate package` on the connected machine, from `kraft/` for the KRaft package or `epc/` for the EPC package:

```bash
cd Krate/kraft
./krate package v1 amd64          # for an x86_64 VM
./krate package v1 arm64          # for an ARM64 VM
./krate package v1 amd64 none     # without Docker installation packages
```

`v1` is a package label in the form `vN`. The processor defaults to the build machine's. The last argument selects the Docker installation packages bundled for VMs without Docker: by default `noble` (Ubuntu 24.04) for KRaft and `rhel9` for EPC; `jammy` selects Ubuntu 22.04 and `none` leaves them out.

`package` builds the Kafbat UI image for the target processor, downloads the Docker packages, saves every pinned image and checks the result. For the first command above it writes:

```text
dist/release/package-kraft-v1/
├── krate-kraft-v1-amd64.tar.gz
├── krate-kraft-v1-amd64.tar.gz.sha256
├── krate-kraft-v1-amd64.tar.gz.images.lock.tsv
└── krate-kraft-v1-amd64.notes.md
```

The package includes the cluster files, its command script, saved Docker images, and monitoring files. The image record lists the exact images, their checksums, and their processor type; a copy is also inside the package. The frozen ZooKeeper package is still built with `make bundle VERSION=vN MODE=zk`.

### Offline Docker packages (Ubuntu and RHEL)

- **Ubuntu (`noble` / `jammy`):** The Ubuntu installer uses `dpkg` and may try `apt-get` to repair missing dependencies. Make sure the target has the required OS dependencies before relying on a fully offline install.
- **RHEL 9 (`rhel9`):** The RHEL installer disables network repositories; missing OS dependencies must be supplied locally.
  - **What `make docker-rpms` bundles:** Downloads the Docker CE packages plus the base-OS dependencies a minimal host may lack into `optional/` from the builder image `RHEL_BUILDER_IMAGE` (default: the Rocky Linux project's maintained `rockylinux/rockylinux:9`, pinned by digest; the Docker Official Image `rockylinux:9` is no longer updated):
    - `container-selinux`
    - `nftables` with the libraries it needs (`libnftnl`, `jansson`, `libmnl`)
    - `iptables-nft` with `iptables-libs`, `libnetfilter_conntrack`, and `libnfnetlink` (`docker-ce` requires `(iptables-nft or iptables)`: a RHEL server has `iptables-nft` because `firewalld` requires it, whereas a cloud image may have neither)
  - **How `krate docker-install` resolves dependencies:** `krate docker-install` (and the bundled `docker-offline/install-docker.sh`, which uses the same selection) adds only the bundled packages that provide a capability `dnf` names as missing on that host, round by round until no bundled package is left to add (an added package can name its own missing library; for a rich dependency such as `(iptables-nft or iptables)` the first alternative a bundled package provides is taken).
  - **Unresolved host capabilities:** When a capability stays unresolved, the installer names that capability and tells you to take it from the OS media. The advice about `container-selinux` (it must match the host's `selinux-policy` build) appears only when `container-selinux` or one of its versioned requirements (the host's `selinux-policy`) is the one that stayed unresolved.
  - **Verified environments:** Proven offline on Rocky Linux 9.8 VMs with SELinux enforcing that already had `iptables-nft` (a standard RHEL 9 server has it through `firewalld`; see [`sso/guides/identity-gate.md`](sso/guides/identity-gate.md)), and on a Rocky Linux 9.8 cloud VM with neither `firewalld` nor `iptables`, where `krate docker-install` added `iptables-nft`, `nftables`, `libnftnl`, and `container-selinux` from `optional/`.

## Install the package on a VM

Copy the package and its `.sha256` file to the VM. For the KRaft package built above:

```bash
sha256sum -c krate-kraft-v1-amd64.tar.gz.sha256
tar -xzf krate-kraft-v1-amd64.tar.gz
cd krate-kraft-v1-amd64
```

The checksum should report `OK`.

If Docker is missing and you included its packages, run `./krate docker-install` first. It needs administrator access. Then run:

```bash
./krate doctor
./krate install
```

`doctor` checks Docker, package architecture, certificates, host ports, and firewall settings. `install` runs those checks again, loads the saved images and installs the package into `/opt/krate/kraft` (`/opt/krate/epc` for EPC; set `KRATE_HOME` to choose another directory). There it does the same setup as `start` (settings, generated passwords, certificate), starts the cluster, waits for it to be healthy and prints every login. `credentials` shows them again later.

The default `/opt/krate` and edition directories must be real directories, not symlinks. Installation gives containers access through those directories while leaving passwords and other private files protected. If you choose a different `KRATE_HOME`, make sure its parent directories allow the containers to reach it; the installer does not change permissions on your custom path.

The installation directory holds everything specific to the site: `.env`, `monitoring/.env`, the certificate in `certs/` and the SSO files under `auth/`. The cluster's Docker project is always `krate-kraft` (or `krate-epc`), whatever directory a package was unpacked to, so its data volumes keep the same names.

### Update to a newer package

Unpack the new package anywhere and run its `./krate install`, with the cluster running or stopped. It replaces only the release files in the installation directory and loads the new images. Settings, passwords, certificates, SSO files and stored messages stay; new image pins and settings are added automatically.

Installations from before `/opt/krate` ran inside their package directory, and their Docker project and volumes were named after it. The first `install` of a newer package finds that installation through its containers, takes over its `.env`, `monitoring/.env`, certificate and SSO files, and keeps using its data volumes (recorded as `KRATE_PROJECT` in `.env`). If the old containers were already removed, name the old directory: `./krate install --from /path/to/krate-kraft-v1-amd64`.

For a downloaded ZooKeeper package, use `./kafka`. For EPC, set `KAFKA_ADVERTISED_HOST` for clients on other machines and review the data directory before the first start.

## Everyday commands

Run these in the installation directory (`/opt/krate/kraft` or `/opt/krate/epc`) or a checkout's `kraft/` or `epc/`. Run from an extracted package, they act on the installation:

### Cluster and configuration commands

| Command | What it does |
| --- | --- |
| `./krate credentials` | Shows every address and login: Kafbat UI, Grafana, Perses, and, with SSO, Keycloak |
| `./krate status` | Lists the services and their state |
| `./krate health` | Checks whether services are healthy |
| `./krate logs -f kafka-92` | Follows one broker's logs |
| `./krate lag [group]` | Shows how many messages consumer groups (or one named group) still need to read |
| `./krate stop` / `./krate start` | Stops or starts services, keeping stored messages |
| `./krate down` | Removes containers while keeping stored messages |
| `./krate config {get\|set\|list}` | Reads or updates settings in `.env` (for example `./krate config set KAFKA_UI_FQDN=kafka.example.com`) |
| `./krate gen-cert` | Generates or renews the cluster TLS certificate in `certs/` |
| `./krate help` | Lists the available commands |

### Identity, SSO, and monitoring commands

| Command | What it does |
| --- | --- |
| `./krate identity up` | Starts the Keycloak identity service and its database, creates its admin on first start |
| `./krate identity status` | Shows identity service health |
| `./krate identity users ...` | Manages local realm users (`list`, `add`, `enable`, `disable`, `reset-password`, `groups`, `logout`, `set-email`) |
| `./krate identity idp-watch {status\|reset\|pause\|resume}` | Shows or controls the enterprise IdP reachability watcher and automatic local login fallback |
| `./krate identity rotate ...` | Rotates identity and SSO secrets (`KEYCLOAK_DB_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`, `KEYCLOAK_CLI_CLIENT_SECRET`, `KEYCLOAK_KAFBAT_CLIENT_SECRET`, `KEYCLOAK_IDP_WATCH_CLIENT_SECRET`, `PING_KEYCLOAK_CLIENT_SECRET --value`) |
| `./krate identity {backup\|restore\|recover-admin}` | Backs up or restores the identity database; recovers a lost Keycloak admin login |
| `./krate identity renew-db-tls` / `logrotate --install` | Renews the identity database certificate; hands the identity journal to the host's logrotate |
| `./krate auth configure [--force] [--[no-]viewer-messages] [site.json]` | Plans Kafbat's Keycloak login (`auth/ui/runtime.yml`) from `.env`, and optionally PingFederate brokering from `site.json` |
| `./krate auth apply` | Validates and applies the planned authentication configuration to the UI, proxy, and realm |
| `./krate monitor {up\|down\|status\|logs\|reload\|ui}` | Starts, stops, or inspects the monitoring stack; reloads Prometheus configuration (`SIGHUP`) |
| `./krate monitor realm` / `grafana-user retire <login>` | Prepares Grafana sign-in through the Krate realm (`monitoring/auth/realm.ini`); retires a colliding local Grafana user |

Use `./kafka` for the ZooKeeper edition. EPC also has `./krate disk` to show data-disk usage against the configured budget.

### How `.env`, image pins, and `uninstall --purge` work

- **Configuration and `*_IMAGE` pins:** Settings live in `.env`. The `*_IMAGE` lines are the exception: every command that runs Docker Compose (`start`, `stop`, `status`, `health`, `logs`, `install`, `setup`, `identity ...`, `monitor up`, `auth apply`) first resets them to the pins in `.env.template`, so a rebuilt Kafbat UI image or a newer package takes effect without editing `.env`. Commands that only read or edit settings (`config`, `ui`, `credentials`, `help`) leave `.env` as it is. To use a different image, change `.env.template`.
- **Applying configuration changes:** After changing a setting used by a container, run `./krate start` to apply it. After changing the certificate hostname, also run `./krate gen-cert` and `./krate restart proxy`.
- **Purging stored messages:** In the supplied KRaft and ZooKeeper setups, `uninstall --purge` deletes stored Kafka messages by removing their Docker storage volumes. EPC stores messages in host folders under `KAFKA_DATA_DIR` (default `/data`), so those messages remain after purge; deleting EPC messages requires stopping the cluster and separately removing its broker folders. Purge is not part of the normal stop/start workflow.

## Identity and SSO for EPC and regular Krate

Each edition includes Keycloak as a local identity service with a PostgreSQL database, both in the `sso` profile of the edition's Compose file. Keycloak and PostgreSQL are included in both offline packages even when the SSO profile is inactive (EPC packages include SSO from `epc-v2`, and KRaft packages from `package-kraft-v1`). From a checkout, `./krate start` builds the customized Kafbat image when it is missing and `./krate build` rebuilds it; see the [build notes](kafbat-ui/README.md). Offline packages include that image.

### Operator workflow

```bash
# 1. Prepare or start the cluster
./krate setup            # or ./krate start

# 2. Bootstrap and start the local Keycloak realm and PostgreSQL database
./krate identity up

# 3. Plan and apply Keycloak sign-in for Kafbat UI (and optional PingFederate brokering)
./krate auth configure   # or ./krate auth configure site.json
./krate auth apply
```

Until `./krate identity up` has run, `./krate start` prints `Identity services skipped (run: krate identity up)` and starts the cluster without Keycloak. SSO requires Docker Compose 2.20.2 or newer.

### Certificates, public URL, and proxy host enforcement

- **Certificate hostnames:** The certificate `./krate gen-cert` (or the first start) writes covers the host FQDN, the host of `KEYCLOAK_PUBLIC_URL`, and `localhost`, so `./krate auth apply` passes its hostname check on a fresh install (an IP address as the host gets an IP entry, which browsers require for an IP host).
- **Changing `KEYCLOAK_PUBLIC_URL`:** Run `./krate gen-cert` and then `./krate start` or `./krate auth apply`. The proxy's Compose environment carries a digest of `nginx.conf` and the certificate (`KRATE_PROXY_CONF_SHA`) and, in Keycloak sign-in mode, the one `Host` value it serves (`KRATE_PROXY_PUBLIC_HOST`: the public host, plus `:port` unless `443`), so those commands recreate it exactly when one of them changed.
- **Strict `Host` header handling:** In Keycloak sign-in mode, an HTTPS request with any other `Host` header (name or port) is closed without a response, and the plain-HTTP port only redirects to the public origin. Open the UI at the `KEYCLOAK_PUBLIC_URL` origin (`./krate ui` prints it).

### Identity foundation and local user management (`./krate identity`)

- **Bootstrap (`./krate identity up`):** Generates the database TLS material and the realm, starts PostgreSQL and Keycloak (with Liquibase analytics disabled via `-Dliquibase.analytics.enabled=false` for air-gapped operation), creates the permanent Keycloak admin, and verifies the `krate-cli` service account.
- **Local users (`./krate identity users`):** Manages local realm users with `list`, `add`, `enable`, `disable`, `reset-password`, `groups`, `logout`, and `set-email`. Running `logout` ends every realm session of the user and triggers OIDC back-channel logout in Kafbat.
- **Secrets, backups, and maintenance:**
  - `./krate identity rotate`: Rotates `KEYCLOAK_DB_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`, `KEYCLOAK_CLI_CLIENT_SECRET`, `KEYCLOAK_KAFBAT_CLIENT_SECRET`, `KEYCLOAK_IDP_WATCH_CLIENT_SECRET`, and `PING_KEYCLOAK_CLIENT_SECRET --value`.
  - `./krate identity backup`, `restore`, and `recover-admin`: Back up or restore the identity database and recover a lost admin login.
  - `./krate identity renew-db-tls` and `logrotate --install`: Reissue the database TLS certificate and rotate the identity journal.
- **Network isolation:** Keycloak, its database, the proxy, Kafbat, and `idp-watch` share a private `identity` Docker network on which the proxy has a fixed address that Keycloak trusts for forwarded headers (`KRATE_IDENTITY_SUBNET`, `KRATE_IDENTITY_PROXY_IP` in `.env`), while `keycloak` and `idp-watch` use `identity-egress` to reach the enterprise IdP.

### Kafbat UI sign-in and PingFederate brokering (`./krate auth`)

- **Local Keycloak sign-in (`KAFKA_UI_AUTH_CONFIG=runtime.yml`):** `./krate auth configure` plans `auth/ui/runtime.yml` from `.env`. Kafbat signs users in through Keycloak only (no shared form login), and the realm groups decide Viewer and Admin access.
- **Enterprise PingFederate brokering:** With a site file, `./krate auth configure site.json` also writes the PingFederate plan `auth/keycloak/pingfederate-idp.json` (the site file must state the MFA stance: a claim PingFederate asserts, or `mfa_not_asserted`), which `./krate auth apply` applies to the realm:
  - Every login redirects to PingFederate.
  - Brokered users are created without linking to local accounts.
  - Local break-glass users sign in only by appending `&kc_idp_hint=` (empty) to the realm's authorization URL after pressing Kafbat's **"Log in with Keycloak"** button (the break-glass procedure in the [operator setup guide](sso/guides/dual-login.md)).
- **Reconciliation (`./krate auth apply`):** Validates the installation and reconciles the UI service and the proxy using locally loaded images. It never bootstraps Keycloak: when the realm is not ready, it stops and tells you to run `./krate identity up`. In `runtime.yml` mode, it recreates the running Keycloak container when the trust material in `auth/keycloak/truststores` or its Compose definition changed (ending Keycloak sessions), then applies or removes the PingFederate plan in the realm; `./krate identity rotate PING_KEYCLOAK_CLIENT_SECRET --value` recreates it once as well.

### Automatic enterprise IdP fallback and recovery (`idp-watch`)

When the PingFederate plan is active (`IDP_WATCH_ENABLED=true` by default), the `idp-watch` daemon (`sso/idp_watch.py`, using the `krate-idp-watch` service account) provides automatic break-glass fallback and recovery:

- **Endpoint health probing:** Continuously probes the allowlisted PingFederate discovery, JWKS, token, and UserInfo endpoints using PEM CA certificates in `auth/keycloak/truststores/`.
- **Automatic fallback to local login:** After `IDP_WATCH_FAILURES_TO_FALLBACK` consecutive failed probe cycles (default `2`, every `IDP_WATCH_INTERVAL_SECONDS=10` seconds) and the minimum dwell time (`IDP_WATCH_DWELL_SECONDS=30`), `idp-watch` disables the `pingfederate` provider in Keycloak:
  - Sign-in falls through automatically to the local Keycloak form (`krate forms`: username, password, and TOTP) without manual intervention.
  - The `krate` login theme (`sso/theme/krate`) renders an outage warning banner (`#kc-idp-fallback-warning`) so corporate users do not enter AD passwords into the local break-glass form.
- **State preservation and automatic recovery:** While `idp-watch` is active, `./krate auth apply` and `./krate identity up` preserve the provider's runtime `enabled` state (`--ignore-enabled`). Once PingFederate passes `IDP_WATCH_SUCCESSES_TO_RECOVER` consecutive probe cycles (default `2`) and the dwell time, `idp-watch` re-enables the provider and normal enterprise SSO redirects resume automatically.
- **Operator CLI:** Inspect or control the watcher with `./krate identity idp-watch {status|reset|pause|resume}`.

<a id="guides"></a>

### Verification gate and guides

Acceptance of the identity work — Phases 1–3 (Keycloak foundation, Kafbat OIDC, and PingFederate brokering with automatic fallback), the Phase 4 slices (4a Grafana, 4b Perses, and 4c backing-service exposure), and the bundle-host air-gap verifications (`AG1`–`AG5`) — is decided by the executable gate `scripts/gate-identity.sh`.

| Guide | What it covers |
| --- | --- |
| [Identity foundation guide](sso/guides/identity-foundation.md) | Inventory of projects, ports, volumes, and credentials, trust boundaries, operational procedures, and upgrade steps for a Keycloak database from before `krate identity` |
| [Operator setup guide](sso/guides/dual-login.md) | Configuring Keycloak sign-in, PingFederate brokering, MFA claim filters, automatic fallback (`idp-watch`), and manual break-glass login |
| [IAM configuration guide](sso/guides/pingfederate-iam-guide.md) | PingFederate OIDC client settings, group claims, and MFA stance requirements for the IAM team |
| [Grafana SSO guide](sso/guides/grafana-sso.md) | Switching Grafana to Krate realm OIDC sign-in (`GRAFANA_AUTH_CONFIG=realm.ini`) |
| [Perses SSO guide](sso/guides/perses-sso.md) | Configuring Perses with the Krate realm (`PERSES_IDP=krate`) or an external company IdP (`native` and `gateway` modes) |
| [Identity acceptance gate](sso/guides/identity-gate.md) | Gate criteria, test inventories, and execution receipts for `scripts/gate-identity.sh` |
| [Monitoring guide](monitoring/README.md) | Prometheus, Loki, VictoriaLogs, Fluent Bit, Grafana, Perses, and service exposure tables |
| [Kafbat UI build notes](kafbat-ui/README.md) | Customized Kafbat UI build, patches, and authentication profiles |

## Monitoring

Krate and EPC each include monitoring files in their package. Prometheus collects measurements and evaluates alert rules, and a host exporter supplies disk, CPU, and memory measurements. Fluent Bit collects container logs. Two dashboard and alerting paths run side by side:

- **Grafana path:** Grafana with Loki and Grafana email alerts
- **Perses path:** Perses (HTTPS) with VictoriaLogs and Alertmanager email alerts

Settings and passwords are prepared with the cluster's; `./krate credentials` shows the logins. Perses uses the cluster certificate in `certs/`. From inside an extracted package, `monitoring/` is beside `krate`; in the repository, it is at the root. With the cluster already running:

```bash
./krate monitor up
./krate monitor status
./krate monitor ui
```

### Ports, bindings, and configuration reload

| Service | Default port / bind | Notes |
| --- | --- | --- |
| **Grafana** | `3000` (`127.0.0.1:3000` in realm mode, proxied at `https://<public-host>/grafana/`) | Local login (`local.ini`) by default, or Krate realm OIDC (`realm.ini`) |
| **Perses** | `3443` (HTTPS) | Uses the cluster certificate in `certs/`; supports local or OIDC sign-in |
| **Prometheus** | `127.0.0.1:9090` (`PROM_BIND` in `monitoring/.env`) | No login; bound to loopback by default (set `0.0.0.0` to publish) |
| **Loki** | `127.0.0.1:3100` (`LOKI_BIND` in `monitoring/.env`) | No login; bound to loopback by default (set `0.0.0.0` to publish) |

- **Reloading Prometheus:** Prometheus runs with its HTTP lifecycle API disabled. After editing `monitoring/prometheus/prometheus.yml` or `alerts.yml` in place, run `./krate monitor reload` to send `SIGHUP` and verify the reload.
- **Email alerts:** Off by default; require your own mail server and recipients. When enabled, Grafana and Alertmanager both send them.
- **ZooKeeper edition:** Has its own smaller stack (Kafka measurements, Prometheus, and Grafana) started with `./kafka monitor up`. It does not include Loki or host measurements.

### Dashboard SSO with the Krate realm

Both dashboards can sign users in through the Krate Keycloak realm (`<KEYCLOAK_PUBLIC_URL>/realms/krate` on a non-loopback host, with verified user e-mail addresses set via `./krate identity users add --email` or `users set-email`):

#### Grafana (`GRAFANA_AUTH_CONFIG=realm.ini`)

1. While Grafana is still on `local.ini`, prepare realm sign-in:
   ```bash
   ./krate monitor realm
   ```
   This checks for state that realm mode hides, generates `GRAFANA_OAUTH_CLIENT_SECRET`, creates the `krate-seed` service account and 90-day token for alert seeding (auto-renewed by `monitor up` within 30 days of expiry), lists any colliding local Grafana accounts to retire with `./krate monitor grafana-user retire <login>`, registers the `krate-grafana` OIDC client, and writes `monitoring/auth/realm.ini`.
2. Switch Grafana to realm mode and apply:
   ```bash
   ./krate config set GRAFANA_AUTH_CONFIG=realm.ini
   ./krate monitor up
   ```
3. **Runtime behavior in `realm.ini` mode:**
   - Served over HTTPS at `https://<public-host>/grafana/` behind the cluster proxy; host port `3000` binds to `127.0.0.1` only.
   - Login form and Basic auth are disabled; `KEYCLOAK_VIEWER_GROUP` and `KEYCLOAK_ADMIN_GROUP` map to Viewer and Admin roles.
   - Loki datasource queries through the read-only `loki-gateway`.
   - Switching between `local.ini` and `realm.ini` with `./krate monitor up` revokes sessions from the previous sign-in mode. See the [Grafana SSO guide](sso/guides/grafana-sso.md).

#### Perses (`PERSES_IDP=krate` with `PERSES_AUTH_MODE=native`, or external company SSO)

1. Enable Krate realm sign-in in `monitoring/.env` (or via `./krate config set`) and start monitoring:
   ```bash
   ./krate config set PERSES_AUTH_MODE=native
   ./krate config set PERSES_IDP=krate
   ./krate monitor up
   ```
2. **Runtime behavior:**
   - `./krate monitor up` reconciles the `krate-perses` and `krate-perses-sync` clients in the Krate realm and enforces Viewer and Admin roles through OAuth2 Proxy, the `perses-sync` guard, and native Perses RBAC.
   - `idp-wait` holds dependent services until the realm answers, and `perses-migrate` cleans up stale foreign-issuer OIDC users on an issuer change.
   - **External IdPs:** Perses also supports `native` and `gateway` modes with an external company IdP via `sso/configure.py --app perses`; see the [Perses SSO guide](sso/guides/perses-sso.md).

## How the parts fit together

A connected machine prepares the package. The target VM runs the containers from that package:

```mermaid
flowchart LR
    Build["Connected machine"] --> Package["Package + checksum"]
    Package --> VM["Target VM"]
    VM --> Brokers["Kafka brokers"]
    Apps["Your applications"] -->|messages| Brokers
    Browser["Your browser"] -->|HTTPS| Proxy["nginx proxy"]
    Proxy --> UI["Kafbat UI"]
    UI --> Brokers
    Brokers --- Data["Stored message data"]
```

KRaft's four containers each handle messages and participate in cluster coordination. ZooKeeper handles coordination in a separate container. EPC uses two combined broker/coordination containers. KRaft and ZooKeeper store data in Docker volumes; EPC uses host directories under `/data` by default.

### Repository layout

```text
kraft/       Four-broker KRaft setup and krate command script
zk/          Frozen ZooKeeper setup and kafka command script
epc/         Two-broker RHEL setup and krate command script
monitoring/  Shared KRaft/EPC dashboards, alerts, and log collection
docker/      Broker image definitions: release and debug versions
sso/         SSO activation helpers and operator guides
kafbat-ui/   Customized Kafbat UI build: shared login without SSO, or Keycloak SSO
Makefile     Package builds and source checks
```

Separate KRaft and ZooKeeper image release workflows build regular and diagnostic images for both processors. The default setup still uses the upstream Kafka images selected in each edition's `.env.template`; the release workflow requires an edition-specific tag before publishing to GHCR, GitHub's container registry.

### Release an offline install package

The [package release workflow](.github/workflows/package-release.yml) runs `scripts/package-release.sh`. That script builds the Kafbat UI image, prepares the Docker packages, builds the package and writes the release files to `dist/release/package-<edition>-vN/`. Run the same script locally first, and start the workflow only after the local package installs:

```bash
# macOS: MAKE=gmake; Node 22 recommended
scripts/package-release.sh kraft v5 amd64        # Docker packages: noble for kraft, rhel9 for epc
scripts/package-release.sh epc v6 amd64 none     # without Docker packages
```

Then start **Release offline install packages** from `main` in GitHub Actions with the same edition, version, processor and Docker package choice. The workflow creates the `package-<edition>-vN` tag and refuses a version that already exists. For EPC, it also refuses a version already released under the earlier `epc-vN` tags. A KRaft package with the highest version becomes the repository's Latest release; EPC and broker image releases do not. Broker image releases use the separate [broker release workflow](.github/workflows/broker-release.yml) and `kraft-v*`/`zk-v*` tags.

## Limits to understand

- **One host is one point of failure.** Multiple brokers on the same VM do not protect against losing that VM. EPC also needs both of its coordination nodes available; losing either prevents its two-node group from reaching agreement.
- **Remote application connections need configuration.** KRaft and ZooKeeper advertise `localhost` on ports `19092–19095` by default. Change their Compose listener settings for clients on other machines. EPC uses `KAFKA_ADVERTISED_HOST` and host ports `9092/9093`.
- **HTTPS protects the UI only.** The Kafka listeners use plaintext, without client authentication. The monitoring web endpoints use HTTP. Restrict access or add the protection your deployment needs.
- **Disk use grows with messages and topics.** EPC limits how much data each part of a topic can keep and requires topics to be created explicitly by default.
- **Host checks still matter.** A valid package and healthy containers do not verify your network, remote clients, storage capacity, or email delivery. Follow the relevant runbook on the target VM.

## Development and checks

From the repository root:

```bash
make help
make check
```

`make check` checks Bash syntax, runs ShellCheck, validates the Compose files, the offline defaults and the identity templates and realm plan. It needs GNU Make, Bash, ShellCheck, Python 3, and the Docker Compose plugin. On macOS, run `gmake check`. `make test` and `make validate` are aliases for these same checks; they do not start a cluster.

The [broker CI workflow](.github/workflows/broker-ci.yml) separately builds the broker images and checks message delivery on GitHub Actions. Use the installation and operations guides for checks on your target host.

Keep contributions focused, work on a separate branch, and describe the checks run in the pull request. Keep local test scripts and validation output out of commits.

## Component credits

Krate uses the projects below. Credit belongs to their owners, maintainers, and contributors; each project has its own license and notices.

| Component | Credit | Used for |
| --- | --- | --- |
| [Apache Kafka](https://kafka.apache.org/) and [ZooKeeper](https://zookeeper.apache.org/) | Apache Software Foundation and project contributors | Message handling and legacy cluster coordination |
| [Confluent container images](https://github.com/confluentinc/cp-docker-images) | Confluent and contributors | Kafka and ZooKeeper images in the legacy edition |
| [Docker Engine](https://www.docker.com/), [Compose](https://github.com/docker/compose), and [Buildx](https://github.com/docker/buildx) | Docker and project contributors | Running containers and building broker images |
| [containerd](https://containerd.io/) | containerd maintainers and contributors; a CNCF project | Container runtime included with the Docker packages |
| [Kafbat UI](https://github.com/kafbat/kafka-ui) | Kafbat and contributors | Browser interface for Kafka. KRaft and EPC ship a modified v1.5.0 build with a native login page and Keycloak-only sign-in when SSO is on; the image contains the upstream license, notice, and patches. See the [build notes](kafbat-ui/README.md). |
| [Eclipse Temurin](https://adoptium.net/) | Eclipse Adoptium Working Group and OpenJDK contributors | Java runtime of the KRaft and EPC Kafbat UI image |
| [Keycloak](https://github.com/keycloak/keycloak) | Keycloak project and contributors; a CNCF project | SSO connection between Kafbat and the company identity provider |
| [PostgreSQL](https://www.postgresql.org/) | PostgreSQL Global Development Group | Keycloak data storage |
| [nginx](https://github.com/nginx/nginx) | NGINX authors, F5, and contributors | HTTPS access to the UI |
| [Kafka Exporter](https://github.com/danielqsj/kafka_exporter) | danielqsj and contributors | Kafka measurements |
| [Prometheus](https://prometheus.io/) and [Node Exporter](https://github.com/prometheus/node_exporter) | Prometheus maintainers and contributors; a CNCF project | Kafka and host measurements |
| [Grafana](https://github.com/grafana/grafana), [Loki and Promtail](https://github.com/grafana/loki) | Grafana Labs and contributors | Dashboards and alerts; Promtail remains in the frozen ZooKeeper edition |
| [Perses](https://github.com/perses/perses) and its [plugins](https://github.com/perses/plugins) | The Perses Authors | Parallel dashboards |
| [VictoriaLogs](https://github.com/VictoriaMetrics/VictoriaLogs) | VictoriaMetrics and contributors | Parallel log storage |
| [Alertmanager](https://github.com/prometheus/alertmanager) | Prometheus maintainers and contributors | Parallel alert email |
| [OAuth2 Proxy](https://github.com/oauth2-proxy/oauth2-proxy) | OAuth2 Proxy maintainers and contributors | SSO session for Perses |
| [Fluent Bit](https://github.com/fluent/fluent-bit), [dkjson](https://dkolf.de/dkjson-lua/) and [Python](https://www.python.org/) | Fluent Bit contributors, David Heiko Kolf, and the Python Software Foundation/contributors | Shared KRaft/EPC container log collection and metadata discovery; see [monitoring transition and notices](monitoring/README.md) |
| [Ubuntu](https://ubuntu.com/) | Canonical and the Ubuntu community | Ubuntu targets and Docker package preparation |
| [Red Hat Enterprise Linux](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux) | Red Hat and contributors | RHEL target for the EPC edition |
| [Rocky Linux](https://rockylinux.org/) | Rocky Enterprise Software Foundation and community | Default container used to prepare RHEL packages |
| [Alpine Linux](https://www.alpinelinux.org/) | Alpine Linux contributors | Base system used by some upstream containers |
| [Bash](https://www.gnu.org/software/bash/) and [GNU Make](https://www.gnu.org/software/make/) | GNU project, Free Software Foundation, and contributors | Command scripts and package builds |
| [Git](https://git-scm.com/) | Git maintainers and contributors | Source checkout |
| [ShellCheck](https://github.com/koalaman/shellcheck) | koalaman and contributors | Shell script checks |
| [Python](https://www.python.org/psf/) | Python Software Foundation and contributors | Monitoring alert setup |
| [OpenSSL](https://openssl-library.org/) | OpenSSL project and contributors | UI certificate creation |
| [GitHub Actions and GHCR](https://github.com/features/actions) | GitHub | Automated checks and container publishing |

The diagnostic broker images also use [BIND](https://www.isc.org/bind/) (ISC), [curl](https://curl.se/) (curl project), [iproute2](https://wiki.linuxfoundation.org/networking/iproute2) (Linux networking contributors), [jq](https://jqlang.org/) (jqlang contributors), [OpenBSD netcat](https://www.openbsd.org/) (OpenBSD project) or [Ncat](https://nmap.org/ncat/) (Nmap project), [procps-ng](https://gitlab.com/procps-ng/procps) (procps-ng contributors), and [strace](https://strace.io/) (strace contributors).

## License

Krate is licensed under the [GNU Affero General Public License v3.0](LICENSE) (`AGPL-3.0-only`). If you modify Krate and let others use it over a network, you must offer them the source of your modified version.

The third-party software Krate runs and packages, listed under [Component credits](#component-credits), keeps its own license. Offline packages include `LICENSE`, `LICENSE-SOURCES.md` and the license and notice files for those components; see `monitoring/fluent-bit/vendor/` and `monitoring/perses/vendor/notices/`.

From `package-kraft-v2` and `package-epc-v4` on, each KRaft and EPC package release also carries the complete corresponding source of the copyleft components in its container images, as a `-sources.tar` asset; see [LICENSE-SOURCES.md](LICENSE-SOURCES.md).

**Exception: the frozen ZooKeeper edition.** Its upstream Confluent and Kafbat images contain six copyleft components whose source is not publicly available (two Azul Zulu JDKs, three old RHEL 8 packages and `confluent-docker-utils`). Krate does not rebuild those images, so a ZooKeeper package ships without the source of those six components. They are listed in [LICENSE-SOURCES.md](LICENSE-SOURCES.md#unresolved-components) and in every ZooKeeper source archive.

## Contributing and community conduct

See the [contributing guidelines](CONTRIBUTING.md) for setup, validation, and pull request expectations.

Participation in Krate is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing or joining project discussions.

For security concerns or vulnerability reporting, see the [Security Policy](.github/SECURITY.md).

<p align="right"><a href="#readme-top">Back to top</a></p>
