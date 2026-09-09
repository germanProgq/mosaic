#!/bin/sh
# Generate on the dedicated Linux relay; local generation is for disposable tests.
set -eu
umask 077
if [ "$#" -ne 3 ]; then
  echo 'usage: provision-dev.sh --dedicated-relay|--fixture DNS_NAME NEW_DIRECTORY' >&2
  exit 2
fi
case "$1" in
  --dedicated-relay) [ "$(uname -s)" = Linux ] || { echo 'BLOCKED: provision relay private key on the Linux relay' >&2; exit 2; } ;;
  --fixture) ;;
  *) echo 'BLOCKED: explicit dedicated-relay or disposable-fixture scope required' >&2; exit 2 ;;
esac
case "$2" in
  ''|*[!a-zA-Z0-9.-]*|-*|.*|*..*|*.) echo 'FAIL: invalid DNS name' >&2; exit 1 ;;
esac
command -v openssl >/dev/null
# mkdir refuses existing paths, including symlinks. Never overwrite credentials.
mkdir -m 700 -- "$3"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -keyout "$3/relay.key" -out "$3/relay.crt" -days 30 \
  -subj "/CN=$2" -addext "subjectAltName=DNS:$2" \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' -addext 'extendedKeyUsage=serverAuth' 2>/dev/null
openssl rand -hex 32 > "$3/client.token"
chmod 600 "$3/relay.key" "$3/relay.crt" "$3/client.token"
echo 'PASS: new owner-only development credentials created; transfer only relay.crt and client.token to the client'
