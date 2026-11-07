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
# Sign a leaf with the CA using explicit RSA-PSS parameters; verify the chain.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$work/leaf.key" >/dev/null 2>&1
openssl req -new -sha256 -key "$work/leaf.key" \
  -subj "/CN=api.lab.invalid" -out "$work/leaf.csr"
cat > "$work/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:api.lab.invalid
EOF
openssl x509 -req -in "$work/leaf.csr" \
  -CA "$work/root.pem" -CAkey "$work/issuer.key" \
  -set_serial 4242 -days 1 -sha256 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 \
  -extfile "$work/leaf.ext" -out "$work/leaf.pem" >/dev/null
openssl verify -CAfile "$work/root.pem" -purpose sslserver \
  -verify_hostname api.lab.invalid "$work/leaf.pem"
openssl x509 -in "$work/leaf.pem" -noout -text > "$work/leaf.txt"
grep -q 'Signature Algorithm: rsassaPss' "$work/leaf.txt"
grep -q 'Hash Algorithm: sha256' "$work/leaf.txt"
grep -q 'Mask Algorithm: mgf1 with sha256' "$work/leaf.txt"
grep -q 'Salt Length: 0x20' "$work/leaf.txt"
grep -q 'DNS:api.lab.invalid' "$work/leaf.txt"
if openssl verify -CAfile "$work/root.pem" -purpose sslserver \
  -verify_hostname other.lab.invalid "$work/leaf.pem" >/dev/null 2>&1; then
  echo "ERROR: mismatched TLS hostname accepted" >&2
  exit 1
fi
# A different trust anchor must not validate the issued certificate.
openssl req -new -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
  -subj "/CN=Unrelated Test Root" \
  -keyout "$work/other.key" -out "$work/other-root.pem" >/dev/null 2>&1
if openssl verify -CAfile "$work/other-root.pem" -purpose sslserver \
  -verify_hostname api.lab.invalid "$work/leaf.pem" >/dev/null 2>&1; then
  echo "ERROR: unrelated issuer accepted as trust anchor" >&2
  exit 1
fi
# An issued certificate must have an end-entity profile, not CA privileges.
grep -q 'CA:FALSE' "$work/leaf.txt"
grep -q 'TLS Web Server Authentication' "$work/leaf.txt"
# It must not be mistaken for an RSA-PKCS#1 v1.5 signed X.509 certificate.
if grep -q 'Signature Algorithm: sha256WithRSAEncryption' "$work/leaf.txt"; then
  echo "ERROR: leaf unexpectedly uses PKCS1 v1.5 signature" >&2
  exit 1
fi
echo 'RSA-PSS X.509 OpenSSL lab conformance passed'
