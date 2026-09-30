# syntax=docker/dockerfile:1
FROM apache/kafka:3.9.1@sha256:4ceccc577f03f51f6af8dbfda55194d0d892f4fa7913ffbded567ce3895622ed AS release
LABEL org.opencontainers.image.title="Krate KRaft broker" \
      org.opencontainers.image.source="https://github.com/bso-d/Krate" \
      io.krate.edition="kraft" \
      io.krate.flavor="release"
ENV KRATE_EDITION=kraft KRATE_IMAGE_FLAVOR=release

FROM release AS debug
USER root
RUN apk add --no-cache bind-tools curl iproute2 jq netcat-openbsd procps strace
USER appuser
LABEL io.krate.flavor="debug"
ENV KRATE_IMAGE_FLAVOR=debug
