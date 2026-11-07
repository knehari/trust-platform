#!/bin/sh
set -eu

# Laboratory only (ADR-0013). Generates a P-256 key and a self-signed root
# certificate for a proposed CA, outside the platform: the key stays in the
# ignored .lab-keys/ directory (modes 700/600) and never reaches the API,
# the database or the browser. Only the certificate is printed, for the CA
# administrator to register with the proposal.
#
# Usage: scripts/lab/create-lab-root.sh "<proposed display name>" [days]
# The display name becomes the certificate's only subject attribute (CN) and
# must equal the proposal's display name.
#
# This software key has no custody, ceremony or hardware protection.
cd "$(dirname "$0")/../.."
name=${1:?usage: create-lab-root.sh "<proposed display name>" [days]}
days=${2:-1825}
case "$name" in
  *[!A-Za-z0-9\ .-]*|' '*|*' ') echo 'display name: letters, digits, spaces, dots and hyphens only' >&2; exit 2 ;;
esac
case "$days" in ''|*[!0-9]*) echo 'days: a positive integer' >&2; exit 2 ;; esac
umask 077
mkdir -p .lab-keys
chmod 700 .lab-keys
slug=$(printf '%s' "$name" | tr 'A-Z .' 'a-z--')
key=".lab-keys/ca-root-$slug.pem"
certificate=".lab-keys/ca-root-$slug.crt"
if [ -e "$key" ]; then
  echo "$key already exists; a root key is never overwritten" >&2
  exit 1
fi
openssl ecparam -name prime256v1 -genkey -noout -out "$key"
chmod 600 "$key"
openssl req -x509 -new -key "$key" -sha256 -days "$days" -subj "/CN=$name" -config /dev/null \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -addext 'authorityKeyIdentifier=keyid:always' \
  -out "$certificate"
cat "$certificate"
