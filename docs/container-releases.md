# Broker container releases

KRaft and ZooKeeper have independent release tags and GHCR packages. Each
version publishes two broker images for `linux/amd64` and `linux/arm64`:

| Edition | Git release tag | GHCR images |
|---|---|---|
| KRaft | `kraft-v1.0.0` | `ghcr.io/bso-d/krate-kraft:v1.0.0-release`, `:v1.0.0-debug` |
| ZooKeeper | `zk-v5.0.0` | `ghcr.io/bso-d/krate-zk:v5.0.0-release`, `:v5.0.0-debug` |

Versions may use `vN`, `vN.N`, or `vN.N.N`. Publishing one edition does not
publish the other. There is no shared `latest` tag.

## Images

The KRaft base is `apache/kafka:3.9.1`; the ZooKeeper broker base is
`confluentinc/cp-kafka:7.6.1`. Both are pinned by their multi-platform manifest
digest. These are broker images; ZooKeeper remains a separate Compose service.
Upstream startup commands, Kafka tools and licenses remain in the images.

The `release` target adds edition metadata. The `debug` target extends it with
`curl`, DNS tools, `ip`, `jq`, `nc`, `ps`, and `strace`. Both run as upstream
`appuser`. Diagnostics do not enable remote debugging ports or change broker
configuration.

## CI and publishing

`broker-ci.yml` builds all edition/flavor/architecture combinations for PRs and
`main`. It checks image metadata and diagnostic tools, starts each broker in its
coordination mode, and verifies a produced message can be consumed. ZooKeeper
checks start a separate ZooKeeper container. Static source and Compose checks
also run.

`broker-release.yml` accepts only `kraft-v…` and `zk-v…` tags, verifies the tagged
commit is already merged into `main`, and calls CI for that edition. Only after
those checks pass does it publish release/debug images to GHCR, with SBOM and
provenance attestations, using `GITHUB_TOKEN` with `packages: write` permission.
It then creates a separate GitHub Release containing both image references,
digests, and `dependencies.txt` with the deployment dependency digest pins.
Existing GitHub Releases are rejected before building, so ordinary runs do not
replace their images or assets.

To create a new tag manually, open **Actions → Release broker images → Run
workflow**, select `main`, choose `kraft` or `zk`, and enter an unused version
such as `v1.0.0`. Manual runs validate the selected main commit, run edition CI,
create `<edition>-<version>` at that exact commit, and then publish the images
and GitHub Release. All source checkouts and image revision labels use the
validated commit SHA. Both triggers share a concurrency group for the release
tag. The tag is created using `GITHUB_TOKEN`, which does not start another
push-triggered workflow.

Write repository access is sufficient to dispatch the workflow. Tag creation
and GitHub Release creation use job-scoped `contents: write`; image publication
uses `packages: write`. Repository or organization policies must permit those
operations and GHCR package access. No personal publishing token is required.

If publishing fails after tag creation, rerun the failed jobs from that run.
A fresh manual run rejects the existing tag. Once a GitHub Release exists,
choose a new version instead of republishing it.

After merging the PR, tag the intended `main` commit and push the tag:

```bash
git fetch origin main
git tag kraft-v1.0.0 origin/main
git push origin kraft-v1.0.0
# Publish the ZooKeeper edition independently:
git tag zk-v5.0.0 origin/main
git push origin zk-v5.0.0
```

The names above are examples; choose the next version for each edition.
For anonymous pulls, set each GHCR package's visibility to public after its
first publication. Private package pulls require authentication with package
read access. See [GitHub's Container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry).

## Use with Compose

Set `KAFKA_IMAGE` in the edition's `.env` to its versioned GHCR reference, then
run that edition's normal CLI commands. For example:

```dotenv
# kraft/.env
KAFKA_IMAGE=ghcr.io/bso-d/krate-kraft:v1.0.0-release
# zk/.env
KAFKA_IMAGE=ghcr.io/bso-d/krate-zk:v5.0.0-release
```

Use the matching `-debug` tag for diagnosis. GitHub Release assets also contain
immutable digest references that can replace version tags. Existing upstream
image defaults remain usable before the first GHCR publication. Offline bundle
builders take images from the edition and monitoring `.env.template` files.
Every bundle input must include an `@sha256:` digest. The bundle selects local
tags derived from image IDs and records source references, runtime tags, image
IDs, archive checksums and platform in `images.lock.tsv`. The builder also writes
a `.tar.gz.images.lock.tsv` sidecar for release uploads.

Local builds:

```bash
docker build --target release -f docker/kraft/Dockerfile -t krate-kraft:release .
docker build --target debug -f docker/zk/Dockerfile -t krate-zk:debug .
```

## Compose compatibility

Monitoring configuration supports standalone Compose 1.29.2 and the Compose
v2 plugin. CLIs set the monitoring project using `-p`: `zk-monitoring`,
`krate-kraft-monitoring`, or `krate-epc-monitoring`. Direct Compose commands must
use the same project name for `up`, `down`, `ps`, and `logs`. For the shared
KRaft/EPC stack, also set `MONITOR_PROJECT` to that same value; the Compose file
uses it to name containers. For example, after setting `KAFKA_NETWORK` and
`KAFKA_EXPORTER_TARGETS` for each running cluster:

```bash
MONITOR_PROJECT=krate-kraft-monitoring KAFKA_EXPECTED_BROKERS=4 \
  docker compose -p krate-kraft-monitoring \
  --env-file monitoring/.env -f monitoring/docker-compose.yml up -d
MONITOR_PROJECT=krate-epc-monitoring KAFKA_EXPECTED_BROKERS=2 \
  docker compose -p krate-epc-monitoring \
  --env-file monitoring/.env -f monitoring/docker-compose.yml up -d
```

Supply the same environment/project pairing for subsequent commands. The CLIs
supply both values automatically. CI validates both monitoring files with
Compose 1.29.2 as well as the current plugin.
