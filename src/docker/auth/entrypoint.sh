#!/bin/sh
# PowerDNS Authoritative entrypoint: (re)load a PRE-SIGNED zone into gsqlite3 and serve it.
# PowerDNS cannot sign with ML-DSA / MTL, so the zone is signed offline by pqcdns.signer and
# PowerDNS runs in "presigned" mode: it serves RRSIG/NSEC/DNSKEY exactly as provided.
set -eu
: "${ZONE_NAME:?ZONE_NAME required}"          # e.g.  .   test   aiori3.test
: "${ZONE_FILE:?ZONE_FILE required}"          # e.g.  /zones/aiori3.test.zone
CONF_DIR="${CONF_DIR:-/etc/powerdns}"
DB="${DB:-/var/lib/powerdns/pdns.sqlite3}"
LISTEN="${LISTEN:-0.0.0.0}"
WEBPORT="${WEBPORT:-8081}"

SCHEMA=$(find / -name 'schema.sqlite3.sql*' -not -path '/proc/*' 2>/dev/null | head -n1)
[ -n "$SCHEMA" ] || { echo "sqlite schema not found"; exit 1; }
mkdir -p "$(dirname "$DB")" "$CONF_DIR" "${SOCKET_DIR:-/var/run/pdns}"
rm -f "$DB"
case "$SCHEMA" in *.gz) zcat "$SCHEMA" ;; *) cat "$SCHEMA" ;; esac | sqlite3 "$DB"

cat > "$CONF_DIR/pdns.conf" <<CONF
launch=gsqlite3
gsqlite3-database=$DB
gsqlite3-dnssec=yes
local-address=$LISTEN
local-port=53
daemon=no
socket-dir=${SOCKET_DIR:-/var/run/pdns}
guardian=no
loglevel=${LOGLEVEL:-4}
# serve large PQC answers: truncate above 1232 over UDP (TC=1), full size over TCP
udp-truncation-threshold=1232
max-tcp-connections=200
webserver=yes
webserver-address=$LISTEN
webserver-port=$WEBPORT
webserver-allow-from=0.0.0.0/0
api=yes
api-key=${API_KEY:-labkey}
CONF

PDNSUTIL="pdnsutil --config-dir=$CONF_DIR"

load_one_zone() {
    _zname="$1"
    _zfile="$2"
    if [ -f "$_zfile" ]; then
        echo ">> loading $_zfile as zone '$_zname'"
        $PDNSUTIL load-zone "$_zname" "$_zfile"
        $PDNSUTIL set-presigned "$_zname"
        $PDNSUTIL rectify-zone "$_zname" >/dev/null 2>&1 || true
        echo ">> record types loaded for '$_zname':"
        $PDNSUTIL list-zone "$_zname" 2>/dev/null | awk '{print $4}' | sort | uniq -c | sed 's/^/   /'
    else
        echo ">> warning: zone file $_zfile not found for '$_zname', skipping"
    fi
}

set -- $ZONE_NAME
for zname in "$@"; do
    case "$zname" in
        .) zfile="/zones/root.zone" ;;
        test) zfile="/zones/test.zone" ;;
        lab) zfile="/zones/lab.zone" ;;
        aiori3.test) zfile="/zones/aiori3.test.zone" ;;
        *) zfile="$ZONE_FILE" ;;
    esac
    [ $# -eq 1 ] && zfile="$ZONE_FILE"
    load_one_zone "$zname" "$zfile"
done

[ "${NO_EXEC:-0}" = 1 ] && exit 0
exec pdns_server --config-dir="$CONF_DIR"
