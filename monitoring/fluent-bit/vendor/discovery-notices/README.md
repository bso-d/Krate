# Discovery image notices

The official Python 3.14.8 slim-trixie index is pinned at
`sha256:f85c5697265c178cc6887276c55fe16cf3d14ca35c3df6a5eab3b360534a55d2`.
Its amd64 and arm64 manifests/layers were downloaded from Docker Hub and
SHA-256 verified without importing or running the image. Each contains 87
installed Debian packages covering the same 61 source versions. The `grep`
binary package differs: amd64 `3.11-4`, arm64 `3.11-4+b1`; both use source
version `3.11-4`. `inventory.json` records actual package/source versions,
architecture digests, copyright provenance and notice hashes.

Debian source copyright files are retained unchanged from its official metadata
service. That service returned 404 for libxcrypt 4.4.38-1; the exact installed
`/usr/share/doc/libcrypt1/copyright` was instead extracted from verified layers,
and its bytes match across both architectures. The installed Python license
also matches across architectures. The source release's bundled Expat notice
is retained separately. Python's PSF license includes historical terms; this
image also includes LGPL libraries and GPL tools, so it is not an Apache-only
distribution.

Referenced common licenses come from the verified Debian base-files package
used for the collector notices. Gzip's unchanged notice calls its declared
GFDL-1.3 text `GFDL-3`; that filename is provided as an alias of the complete
GFDL-1.3 text, preserving the upstream notice and the license bytes.

These package/source notices are not a complete binary linkage SBOM and do not
alone fulfill all corresponding-source or relinking obligations. Review and
fulfill applicable redistribution terms before releasing the offline image.
No Python package installation, external request or download occurs at runtime;
the helper runs only the packaged standard-library script with no network.
