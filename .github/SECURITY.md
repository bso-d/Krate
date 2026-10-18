# Security Policy

Krate packages containerized Apache Kafka clusters for air-gapped and enterprise
deployments on Ubuntu and Red Hat Enterprise Linux (RHEL). We take the security
and integrity of our offline bundles, container images, authentication integrations,
and management tooling seriously.

## Supported Versions

Only active editions and current releases receive security updates.

| Edition / Variant | Branch / Version | Supported | Notes |
| :--- | :--- | :---: | :--- |
| **KRaft Edition** | `main`, latest release (v2+) | :white_check_mark: | Primary active release for modern deployments |
| **EPC Edition** | `main`, latest release (v4+) | :white_check_mark: | Primary active release for RHEL 9 deployments |
| **ZooKeeper Edition** | `main` | :warning: | **Frozen legacy edition.** Severe security fixes only; users should migrate to KRaft |
| **Older releases** | Prior tags | :x: | Unsupported; please upgrade to the latest release |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**
Public disclosure creates unnecessary risk for existing deployments before a fix is ready.

### Preferred Channel: GitHub Private Vulnerability Reporting

Please submit vulnerability reports through GitHub's Private Vulnerability Reporting:

1. Navigate to the [Security Advisories](https://github.com/bso-d/Krate/security/advisories/new) page.
2. Click **Report a vulnerability**.
3. Fill in the advisory details, reproduction steps, and impact assessment.

### Alternative Channel

If Private Vulnerability Reporting is unavailable, contact the repository maintainers directly:
- Contact via the [repository maintainer profile](https://github.com/bso-d).
- Alternatively, open an issue requesting a private reporting channel **without disclosing any incident details, vulnerability descriptions, or system specifics**. Maintainers will establish a secure communication channel.

## Information to Include

To help us triage and resolve the issue quickly, include the following in your report:

- **Component & Edition**: Which variant is affected (`kraft`, `epc`, `zk`, `monitoring`, `sso`, `docker`, or CLI tooling).
- **Environment**: Target host OS and version (e.g., Ubuntu 24.04, RHEL 9.4), CPU architecture (`amd64` or `arm64`), Docker version, and Docker Compose version.
- **Vulnerability Type**: Authentication bypass, privilege escalation, credential exposure, insecure default, TLS validation failure, injection, etc.
- **Impact Assessment**: The severity and practical attack scenario.
- **Reproduction Steps**: Step-by-step commands or a minimal Proof of Concept (PoC).
- **Proposed Remediation**: Any patches or configuration suggestions, if available.

### Sanitization Warning

> **CRITICAL**: Never include real production passwords, private keys (`certs/`),
> active TLS certificates, site-specific SSO client secrets or tokens (`sso/site*.json`),
> or confidential hostnames in your report. Always substitute with sanitized placeholders
> (e.g., `<REDACTED>`, `secret-password`, `example.com`).

## Response and Remediation Process

- **Acknowledgment**: We aim to acknowledge receipt of the report within **48 hours**.
- **Triage & Validation**: Within **5 business days**, we will investigate and confirm whether the report is valid, determine affected versions, and assess severity.
- **Remediation**: Fixes will be prepared, reviewed, and validated privately in draft security advisories.
- **Coordinated Disclosure**: Once a fix and corresponding release packages are ready, we will publish a security advisory (and CVE if applicable), credit the reporter (unless anonymity is requested), and release updated packages.

## Security Guarantees & Scope in Krate

### In Scope

- **CLI Tools & Scripts**: Shell script safety, argument handling, credential handling, and permissions in `kraft/krate`, `epc/krate`, `zk/kafka`, and helper scripts.
- **Authentication & SSO**: Keycloak realm configuration, OAuth2/OIDC proxy configurations, Kafbat UI authentication patches (`kafbat-ui/native-auth.patch`, `kafbat-ui/native-login.patch`), and session handling.
- **TLS & Certificate Provisioning**: Validity and cipher configurations in `./krate gen-cert` and `nginx.conf` reverse proxy endpoints.
- **Offline / Air-gap Policy**: Enforcement that no untracked telemetry, analytics, update checks, or external phone-home requests are performed (`scripts/check-offline.py`).
- **Image Pinning & Package Integrity**: Ensuring all container images are strictly pinned by digest (`@sha256:...`) and checksums match `images.lock.tsv`.

### Out of Scope

- Vulnerabilities in third-party upstream container images (such as Apache Kafka, Keycloak, PostgreSQL, Grafana, Kafbat UI) unless Krate's configuration directly introduces or exacerbates the flaw, or Krate fails to pin available patched versions.
- Attacks requiring physical access or root/superuser compromise of the host virtual machine.
- Intentional insecure configurations introduced by the operator (e.g., setting trivial passwords in `.env`, disabling TLS, or intentionally bypassing authentication).
- Denial of service attacks caused purely by authorized Kafka message volume exceeding allocated host resources.
