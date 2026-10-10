# Runs the patched Kafbat v1.5.0 jar on Eclipse Temurin instead of upstream's Azul
# Zulu base, because Adoptium publishes the JDK's corresponding source (see
# LICENSE-SOURCES.md). The steps below match upstream api/Dockerfile at the pinned
# revision. build.py checks that this default matches its RUNTIME_IMAGE.
ARG KRATE_RUNTIME_IMAGE=eclipse-temurin:25-jre-alpine@sha256:3c0a9084927a221ccd1d007fcaf614465672c0af37aaa834c5184483afe56d61
FROM ${KRATE_RUNTIME_IMAGE}
LABEL org.opencontainers.image.title="Kafka UI with native SSO" \
      org.opencontainers.image.description="Kafbat v1.5.0 with native OIDC login, CSRF protection, POST and back-channel logout" \
      io.krate.kafbat-source-revision="afc9c918e13c4422268a3a5b7933c7b448746c82"

# gcompat for the glibc-linked snappy codec, as upstream. build.py fetched the
# packages for this image's Alpine release; apk checks their Alpine signatures.
# tzdata is already in the Temurin image.
RUN --mount=type=bind,source=apk,target=/tmp/krate-apk \
    apk add --no-network --no-cache /tmp/krate-apk/*.apk
RUN addgroup -S kafkaui && adduser -S kafkaui -G kafkaui

# creating folder for dynamic config usage (certificates uploads, etc)
RUN mkdir /etc/kafkaui/ && chown kafkaui /etc/kafkaui

COPY LICENSE upstream-NOTICE provenance.json native-login.patch native-auth.patch /usr/share/krate/kafbat-source/

USER kafkaui

COPY api.jar /api.jar

ENV JAVA_OPTS=

EXPOSE 8080

# see JmxSslSocketFactory docs to understand why add-opens is needed
CMD java --add-opens java.rmi/javax.rmi.ssl=ALL-UNNAMED  $JAVA_OPTS -jar api.jar
