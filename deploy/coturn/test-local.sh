#!/bin/bash
# Runs deploy/coturn/turnserver.conf in a coturn container on this machine, with a broker in front, and the test suite's TURN checks against both: relays over udp, tcp and tls, wrong credentials refused, private peers refused. For changes to turnserver.conf before they go to a server.
#
#   deploy/coturn/test-local.sh [image]
#
# image: default coturn/coturn:latest; coturn/coturn:4.6.2 is about the version Ubuntu 24.04 and Debian 12 ship. Needs Docker, openssl and Node; ports 3478, 5349 and 8797 free. Leaves nothing behind.

set -euo pipefail

IMAGE="${1:-coturn/coturn:latest}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
NAME="frametrail-coturn-test-$$"
PORT=8797
BROKER=""

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    [ -n "$BROKER" ] && kill "$BROKER" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

SECRET=$(openssl rand -hex 24)

# A certificate for 127.0.0.1, which the checks trust (TURN_CA).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -keyout "$WORK/privkey.pem" -out "$WORK/fullchain.pem" 2>/dev/null
chmod 644 "$WORK/privkey.pem" "$WORK/fullchain.pem"    # coturn runs as nobody in the image

# The production configuration with this machine's values: no fixed addresses (the container's are not known), the test secret and certificate, ten relay ports.
sed -e '/^listening-ip=/d' -e '/^relay-ip=/d' \
    -e "s|^static-auth-secret=.*|static-auth-secret=$SECRET|" \
    -e 's|^realm=.*|realm=localhost|' -e 's|^server-name=.*|server-name=localhost|' \
    -e 's|^cert=.*|cert=/certs/fullchain.pem|' -e 's|^pkey=.*|pkey=/certs/privkey.pem|' \
    -e 's|^max-port=.*|max-port=50009|' \
    "$ROOT/deploy/coturn/turnserver.conf" > "$WORK/turnserver.conf"
mkdir "$WORK/certs" && mv "$WORK/privkey.pem" "$WORK/fullchain.pem" "$WORK/certs/"

echo "Starting $IMAGE …"
docker run -d --name "$NAME" -p 3478:3478/udp -p 3478:3478/tcp -p 5349:5349/tcp \
    -v "$WORK/turnserver.conf:/etc/coturn/turnserver.conf:ro" -v "$WORK/certs:/certs:ro" \
    "$IMAGE" -c /etc/coturn/turnserver.conf >/dev/null

for _ in $(seq 1 20); do
    docker logs "$NAME" 2>&1 | grep -q 'TLS/TCP listener opened' && break
    sleep 0.5
done
if [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != "true" ]; then
    docker logs "$NAME"
    echo "coturn did not start." >&2
    exit 1
fi
echo "coturn $(docker exec "$NAME" turnserver --version 2>/dev/null | head -1) is up. What it says about the configuration:"
docker logs "$NAME" 2>&1 | grep -iE 'error|warning|bad|unknown|unrecogn|cannot|deprecated' | grep -v 'cannot find config file' || echo "  (no warnings)"

TURN_SECRET="$SECRET" node "$ROOT/src/pairing-broker.mjs" --host 127.0.0.1 --port "$PORT" \
    --stun stun:127.0.0.1:3478 \
    --turn 'turn:127.0.0.1:3478?transport=udp' --turn 'turn:127.0.0.1:3478?transport=tcp' --turn 'turns:127.0.0.1:5349?transport=tcp' \
    --allowed-origin http://test.localhost --log warn &
BROKER=$!
sleep 1

BROKER_URL="http://127.0.0.1:$PORT/" BROKER_ORIGIN=http://test.localhost TURN_EXPECT_DENIED=1 TURN_CA="$WORK/certs/fullchain.pem" \
    node --test "$ROOT/test/turn.test.mjs" "$ROOT/test/contract.test.mjs"
