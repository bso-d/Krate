# Pinned image dependency notices

The amd64 and arm64 manifests under Fluent Bit 5.1.3 index
`sha256:c5542543523c9678398dd78d927c05e8425ec15b038f226b67b3b019b1a70845`
were downloaded directly from `cr.fluentbit.io`. Manifest/layer bytes were
SHA-256 checked before inspecting their `var/lib/dpkg/status.d` files. Both
architectures contain the same 49 package/version entries, covering 40 Debian
source versions. `inventory.json` records the package/source versions,
platform digests, official Debian copyright URLs and notice hashes.

The unchanged copyright files come from Debian's official
`metadata.ftp-master.debian.org` service. The common license texts they refer to
come from `base-files_13.8+deb13u7_arm64.deb` at `deb.debian.org`. Notices describe
whole source packages and may also cover files not installed in this image.
They must not be read as a statement that every source file or license applies
to every shipped library. In particular, the GCC runtime has an exception;
consult its full copyright file rather than classifying it as plain GPL.

The upstream image build removes `/usr/share/doc`. These notice copies travel
with the offline bundle rather than depending on documents inside the image.
`upstream/` conservatively retains all 47 top-level bundled-library license and
notice files from the Fluent Bit v5.1.3 `lib/` source tree, including LuaJIT,
Onigmo, librdkafka, and WAMR. Its inventory records the original paths, URLs and
hashes. This is a source notice inventory, not a binary linkage/SBOM claim.

The selected distribution includes LGPL-family libraries and other licenses;
the project's Apache-2.0 label is not an all-permissive image certification.
These notices do not themselves satisfy every corresponding-source or
relinking obligation. Before redistributing a release, review the exact build,
make corresponding source available by a compliant method where required,
retain applicable exceptions and allow replacement/relinking as required.
The official Debian source package versions above and upstream v5.1.3 source
are the provenance anchors. No release or deployment is performed by this PR.
