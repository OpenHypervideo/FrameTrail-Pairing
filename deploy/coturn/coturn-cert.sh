#!/bin/sh
# /usr/local/sbin/coturn-cert.sh: hands coturn the Let's Encrypt certificate Plesk keeps for a domain, and tells coturn to load it.
#
#   coturn-cert.sh <domain>           (e.g. pair.example.org)
#
# Plesk renames its certificate files on every renewal, so their paths are read each time from the web server configuration Plesk generates for the domain: nginx's ssl_certificate (the key, the certificate and the CA chain in one file) where Plesk runs nginx, otherwise Apache's SSLCertificateFile (the key and the certificate) and SSLCACertificateFile (the chain). They are written to /etc/coturn/certs as privkey.pem and fullchain.pem (the certificate first). Nothing is replaced unless the key matches the certificate, the certificate names the domain, is valid for at least another day and verifies with its chain. Run by coturn-cert.service: daily (coturn-cert.timer) and before coturn starts.

set -eu

DOMAIN="${1:?usage: coturn-cert.sh <domain>}"
CONF_DIR="${PLESK_VHOSTS_SYSTEM:-/var/www/vhosts/system}/$DOMAIN/conf"
DEST="${COTURN_CERT_DIR:-/etc/coturn/certs}"
OWNER="${COTURN_CERT_OWNER:-root}"
GROUP="${COTURN_GROUP:-turnserver}"

fail() { echo "coturn-cert: $*" >&2; exit 1; }

# The value of the first line that starts with a directive, without quotes and a trailing semicolon.
directive() { awk -v name="$1" '$1 == name { v = $2; gsub(/^"|"?;?$/, "", v); print v; exit }' "$2"; }

if [ -r "$CONF_DIR/nginx.conf" ]; then
    SOURCES=$(directive ssl_certificate "$CONF_DIR/nginx.conf")
elif [ -r "$CONF_DIR/httpd.conf" ]; then
    SOURCES="$(directive SSLCertificateFile "$CONF_DIR/httpd.conf") $(directive SSLCACertificateFile "$CONF_DIR/httpd.conf")"
else
    fail "no Plesk web server configuration for $DOMAIN in $CONF_DIR"
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

FOUND=""
for SOURCE in $SOURCES; do
    [ -r "$SOURCE" ] || fail "cannot read $SOURCE (named in $CONF_DIR)"
    cat "$SOURCE" >> "$WORK/all.pem"
    FOUND="$FOUND $SOURCE"
done
[ -n "$FOUND" ] || fail "no certificate for $DOMAIN in $CONF_DIR (is it secured with Let's Encrypt?)"

awk '/-----BEGIN [A-Z ]*PRIVATE KEY-----/ { key = 1 } key { print } /-----END [A-Z ]*PRIVATE KEY-----/ { exit }' "$WORK/all.pem" > "$WORK/key.pem"
openssl pkey -in "$WORK/key.pem" -out "$WORK/privkey.pem" 2>/dev/null || fail "no private key in$FOUND"
awk -v dir="$WORK" '
    /-----BEGIN CERTIFICATE-----/ { n++; out = dir "/cert" n ".pem" }
    out { print > out }
    /-----END CERTIFICATE-----/ { close(out); out = "" }
' "$WORK/all.pem"
ls "$WORK"/cert*.pem >/dev/null 2>&1 || fail "no certificate in$FOUND"

# The certificate is the one whose public key is the key's; the others are its chain.
KEY=$(openssl pkey -in "$WORK/privkey.pem" -pubout | openssl sha256)
LEAF=""
for CERT in "$WORK"/cert*.pem; do
    if [ "$(openssl x509 -in "$CERT" -noout -pubkey | openssl sha256)" = "$KEY" ]; then LEAF="$CERT"; break; fi
done
[ -n "$LEAF" ] || fail "no certificate in$FOUND matches the key"
: > "$WORK/chain.pem"
for CERT in "$WORK"/cert*.pem; do
    [ "$CERT" = "$LEAF" ] || cat "$CERT" >> "$WORK/chain.pem"
done

openssl x509 -in "$LEAF" -noout -checkhost "$DOMAIN" | grep -q 'does match' || fail "the certificate in$FOUND does not name $DOMAIN"
openssl x509 -in "$LEAF" -noout -checkend 86400 >/dev/null || fail "the certificate in$FOUND expires within a day"
[ -s "$WORK/chain.pem" ] || fail "no CA chain in$FOUND"
openssl verify -untrusted "$WORK/chain.pem" "$LEAF" >/dev/null 2>&1 || fail "the certificate in$FOUND does not verify with its chain"
cat "$LEAF" "$WORK/chain.pem" > "$WORK/fullchain.pem"

if cmp -s "$WORK/fullchain.pem" "$DEST/fullchain.pem" 2>/dev/null && cmp -s "$WORK/privkey.pem" "$DEST/privkey.pem" 2>/dev/null; then
    exit 0
fi

install -d -m 0750 -o "$OWNER" -g "$GROUP" "$DEST"
install -m 0640 -o "$OWNER" -g "$GROUP" "$WORK/privkey.pem" "$DEST/privkey.pem.new"
install -m 0640 -o "$OWNER" -g "$GROUP" "$WORK/fullchain.pem" "$DEST/fullchain.pem.new"
mv -f "$DEST/privkey.pem.new" "$DEST/privkey.pem"
mv -f "$DEST/fullchain.pem.new" "$DEST/fullchain.pem"

# coturn reads its certificate again on SIGUSR2, without dropping a relay.
if command -v systemctl >/dev/null && systemctl is-active --quiet coturn.service; then
    systemctl kill --signal=SIGUSR2 coturn.service
fi
echo "coturn-cert: installed the certificate for $DOMAIN, valid until $(openssl x509 -in "$DEST/fullchain.pem" -noout -enddate | cut -d= -f2)"
