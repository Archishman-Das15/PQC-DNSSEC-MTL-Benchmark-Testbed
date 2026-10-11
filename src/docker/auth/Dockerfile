# PowerDNS Authoritative Server (official PowerDNS Debian repository), gsqlite3 backend.
FROM debian:bookworm-slim
ARG PDNS_AUTH_REPO=auth-50
# slim images drop /usr/share/doc; the sqlite schema may live there -> keep docs
RUN rm -f /etc/dpkg/dpkg.cfg.d/docker* \
 && apt-get update && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
 && install -d /etc/apt/keyrings \
 && curl -fsSL https://repo.powerdns.com/FD380FBB-pub.asc | gpg --dearmor -o /etc/apt/keyrings/pdns.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/pdns.gpg arch=amd64,arm64] http://repo.powerdns.com/debian bookworm-${PDNS_AUTH_REPO} main" \
      > /etc/apt/sources.list.d/pdns.list \
 && printf 'Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n' > /etc/apt/preferences.d/pdns \
 && apt-get update && apt-get install -y --no-install-recommends \
      pdns-server pdns-backend-sqlite3 sqlite3 dnsutils \
 && rm -rf /var/lib/apt/lists/* /etc/powerdns/pdns.d/* \
 && pdns_server --version 2>&1 | head -n2 || true
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 53/udp 53/tcp 8081/tcp
ENTRYPOINT ["/entrypoint.sh"]
