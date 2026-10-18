#!/usr/bin/env bash
# Builds a small, valid seed corpus with OpenSSL so the fuzzers start from
# well-formed DER instead of random bytes. Usage: fuzz/seed-corpus.sh <out-dir>
set -euo pipefail
out="${1:?usage: seed-corpus.sh <out-dir>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out/csr_p256" "$out/csr_rsa_pkcs1_lab" "$out/ca_certificate"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/p256.key" -subj "/CN=fuzz.lab.invalid" -outform DER -out "$out/csr_p256/p256.der" 2>/dev/null
openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -keyout "$work/rsa.key" -subj "/CN=fuzz.lab.invalid" -outform DER -out "$out/csr_rsa_pkcs1_lab/rsa2048.der" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$work/ca.key" -subj "/CN=Fuzz Lab Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -outform DER -out "$out/ca_certificate/root-p256.der" 2>/dev/null
