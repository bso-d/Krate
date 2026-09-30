# syntax=docker/dockerfile:1
FROM confluentinc/cp-kafka:7.6.1@sha256:620734d9fc0bb1f9886932e5baf33806074469f40e3fe246a3fdbb59309535fa AS release
LABEL org.opencontainers.image.title="Krate ZooKeeper broker" \
      org.opencontainers.image.source="https://github.com/bso-d/Krate" \
      io.krate.edition="zk" \
      io.krate.flavor="release"
ENV KRATE_EDITION=zk KRATE_IMAGE_FLAVOR=release

FROM release AS debug
USER root
RUN yum install -y bind-utils curl iproute jq nmap-ncat procps-ng strace \
    && yum clean all \
    && rm -rf /var/cache/yum
USER appuser
LABEL io.krate.flavor="debug"
ENV KRATE_IMAGE_FLAVOR=debug
