#!/bin/sh
set -eu

# Laboratory only (ADR-0034, Proposed). The key ceremony of the lab issuing
# CA on the signer's PKCS#11 token: trust-lab-ca-ceremony generates a P-256
# key inside the SoftHSM2 token, sensitive and never extractable, and has the
# token sign the self-signed root certificate. The key never reaches the
# host, the API, the database or the browser. Only the certificate is
# written to .lab-keys/ca/ and printed, for the CA administrator to register
# with the proposal, exactly as with scripts/lab/create-lab-root.sh.
#
# Usage: scripts/lab/create-lab-root-hsm.sh "<proposed display name>" [days]
# The key label is ca-root-<slug>; the signer uses the key labelled
# TRUST_SIGNER_PKCS11_KEY_LABEL (ca-root-lab-issuing-ca in compose).
#
# The ceremony runs in the running signer container, which holds the token.
# TRUST_LAB_CEREMONY replaces that command (e.g. a local build with
# SOFTHSM2_CONF and the TRUST_SIGNER_PKCS11_* variables set).
#
# SoftHSM2 is a software token: no hardware protection, and no dual control,
# witness or quorum in this ceremony.
cd "$(dirname "$0")/../.."
name=${1:?usage: create-lab-root-hsm.sh "<proposed display name>" [days]}
days=${2:-1825}
case "$name" in
  *[!A-Za-z0-9\ .-]*|' '*|*' ') echo 'display name: letters, digits, spaces, dots and hyphens only' >&2; exit 2 ;;
esac
case "$days" in ''|*[!0-9]*) echo 'days: a positive integer' >&2; exit 2 ;; esac
umask 077
mkdir -p .lab-keys/ca
chmod 700 .lab-keys .lab-keys/ca
slug=$(printf '%s' "$name" | tr 'A-Z .' 'a-z--')
certificate=".lab-keys/ca/ca-root-$slug.crt"
export TRUST_SIGNER_PKCS11_KEY_LABEL="ca-root-$slug"
trap 'rm -f "$certificate.tmp"' EXIT
ceremony=${TRUST_LAB_CEREMONY:-docker compose --env-file .env.lab -f compose.lab.yaml exec -T signer env TRUST_SIGNER_PKCS11_KEY_LABEL=ca-root-$slug trust-lab-ca-ceremony}
# shellcheck disable=SC2086 # the command is a word list
$ceremony "$name" "$days" > "$certificate.tmp"
mv "$certificate.tmp" "$certificate"
cat "$certificate"
