#!/usr/bin/env bash
# Laboratory RSA-PSS/SHA-256 conformance smoke test. Does not enable RSA issuance.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf 'Trust Platform RSA-PSS interop fixture\n' > "$work/message"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$work/key.pem" >/dev/null 2>&1
openssl pkey -in "$work/key.pem" -pubout -out "$work/pub.pem" >/dev/null
openssl dgst -sha256 -sign "$work/key.pem" \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 -out "$work/signature" "$work/message"
openssl dgst -sha256 -verify "$work/pub.pem" \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 -signature "$work/signature" "$work/message"
if openssl dgst -sha256 -verify "$work/pub.pem" \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 \
  -sigopt rsa_mgf1_md:sha256 -signature "$work/signature" "$work/message" >/dev/null 2>&1; then
  echo "ERROR: wrong RSA-PSS salt length accepted" >&2
  exit 1
fi
printf 'altered\n' > "$work/tampered"
if openssl dgst -sha256 -verify "$work/pub.pem" \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 -signature "$work/signature" "$work/tampered" >/dev/null 2>&1; then
  echo "ERROR: tampered RSA-PSS message accepted" >&2
  exit 1
fi
echo "RSA-PSS OpenSSL lab conformance passed"
