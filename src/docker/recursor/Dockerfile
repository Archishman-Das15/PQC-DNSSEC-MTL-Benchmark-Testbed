# PowerDNS Recursor (official PowerDNS Debian repository), YAML configuration.
FROM debian:bookworm-slim
ARG PDNS_REC_REPO=rec-53
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
 && install -d /etc/apt/keyrings \
 && curl -fsSL https://repo.powerdns.com/FD380FBB-pub.asc | gpg --dearmor -o /etc/apt/keyrings/pdns.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/pdns.gpg arch=amd64,arm64] http://repo.powerdns.com/debian bookworm-${PDNS_REC_REPO} main" \
      > /etc/apt/sources.list.d/pdns.list \
 && printf 'Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n' > /etc/apt/preferences.d/pdns \
 && apt-get update && apt-get install -y --no-install-recommends pdns-recursor dnsutils \
 && rm -rf /var/lib/apt/lists/* && rm -f /etc/powerdns/recursor.conf \
 && mkdir -p /var/run/pdns-recursor
COPY recursor.yml /etc/powerdns/recursor.yml
EXPOSE 53/udp 53/tcp 8082/tcp
ENTRYPOINT ["pdns_recursor", "--config-dir=/etc/powerdns", "--daemon=no", "--socket-dir=/var/run/pdns-recursor"]
