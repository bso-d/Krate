ARG KAFBAT_BASE_IMAGE=kafbat/kafka-ui:v1.5.0@sha256:7cda86a33344160309fdb65146332e4da65db81a945614f2fe32e210803f6fd1
FROM ${KAFBAT_BASE_IMAGE}
LABEL org.opencontainers.image.title="Kafka UI with shared login and native SSO" \
      org.opencontainers.image.description="Kafbat v1.5.0 with native dual login and PingFederate OIDC" \
      io.krate.kafbat-source-revision="afc9c918e13c4422268a3a5b7933c7b448746c82"
COPY api.jar /api.jar
COPY LICENSE upstream-NOTICE provenance.json native-login.patch native-auth.patch /usr/share/krate/kafbat-source/
