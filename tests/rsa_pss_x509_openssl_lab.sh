#!/usr/bin/env bash
# X.509 RSA-PSS signature interoperability fixture, OpenSSL-only, lab-only.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$work/issuer.key" >/dev/null 2>&1
openssl req -new -x509 -sha256 -key "$work/issuer.key" \
  -subj "/CN=Trust Platform RSA-PSS Test Root" -days 1 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$work/root.pem"
openssl verify -CAfile "$work/root.pem" "$work/root.pem"
# The signature OID must be RSASSA-PSS, not sha256WithRSAEncryption.
openssl x509 -in "$work/root.pem" -noout -text > "$work/root.txt"
grep -q 'Signature Algorithm: rsassaPss' "$work/root.txt"
grep -q 'Hash Algorithm: sha256' "$work/root.txt"
grep -q 'Mask Algorithm: mgf1 with sha256' "$work/root.txt"
grep -q 'Salt Length: 0x20' "$work/root.txt"
openssl x509 -in "$work/root.pem" -pubkey -noout > "$work/root.pub"
openssl x509 -in "$work/root.pem" -outform DER -out "$work/root.der"
openssl asn1parse -inform DER -in "$work/root.der" > "$work/asn1.txt"
grep -q 'rsassaPss' "$work/asn1.txt"
echo 'RSA-PSS X.509 OpenSSL lab conformance passed'
