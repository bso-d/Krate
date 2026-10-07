# Contributing to Krate

Read the [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Report issues and propose changes

Use [GitHub issues](https://github.com/bso-d/Krate/issues) for reproducible bugs
and feature proposals. Include the affected variant (`zk`, `kraft`, or `epc`),
CPU architecture, host OS, Docker and Compose versions, reproduction steps,
and expected versus actual behavior. Redact credentials, private hostnames,
and sensitive data from logs. Follow the Code of Conduct's reporting process
for conduct concerns.

Discuss substantial changes before implementation. Keep pull requests focused
on one problem and explain any compatibility or operational impact.

## Set up a development branch

Create a branch from the latest `main`. You need Bash, GNU Make 4.0 or newer,
ShellCheck, and Docker with the Compose plugin to run the source checks. On
macOS, use `gmake` wherever these instructions say `make`.

The main areas are:

- `kraft/`: KRaft cluster configuration and CLI.
- `epc/`: two-broker RHEL deployment and CLI.
- `zk/`: frozen ZooKeeper edition; preserve its documented compatibility.
- `monitoring/`: shared observability configuration.
- `docker/`: broker image definitions.
- `sso/`: SSO activation helpers and operator guides.
- `kafbat-ui/`: customized Kafbat UI build for shared login and SSO.

Use the [README](README.md) for local startup and bundle commands. Copy the
appropriate `.env.template` to `.env` for local configuration; never commit
credentials, private keys, or local environment files. Use disposable clusters
and data for runtime testing. Commands such as `uninstall --purge` delete data.

## Validate your changes

Run these before submitting:

```bash
make check
git diff --check
```

`make check` validates CLI shell syntax, runs ShellCheck, and validates the
Compose configurations. `make test` and `make validate` are aliases for the
same static checks; they do not prove that a cluster runs correctly.

For behavior changes, also exercise the affected workflow on a disposable
cluster. Record the commands, environment, and outcomes, including checks for
restart and data preservation when relevant.
For image changes, review the broker CI build and startup results. Describe any
validation you could not perform; do not present an untested path as verified.
Keep integration test artifacts and generated bundles local, as described in
the README.

## Open a pull request

Target `main` with a descriptive title and focused commits. Explain the problem,
what changes for users, why the change is needed, and the validation performed.
Call out breaking changes, deployment steps, and data-loss risks when applicable.
Update relevant documentation alongside behavior changes. Resolve review
feedback and check the CI results before requesting a merge.
