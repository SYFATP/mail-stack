ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix postfix-pcre postfix-sqlite libsasl2-modules ca-certificates rsyslog && rm -rf /var/lib/apt/lists/*
COPY postfix/entrypoint.sh /entrypoint.sh
COPY postfix/config/vmailbox /etc/postfix/vmailbox
RUN chmod +x /entrypoint.sh && postmap /etc/postfix/vmailbox
EXPOSE 25
ENTRYPOINT ["/entrypoint.sh"]
