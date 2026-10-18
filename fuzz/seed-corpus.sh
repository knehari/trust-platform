#!/usr/bin/env bash
# Builds a small, valid seed corpus with OpenSSL so the fuzzers start from
# well-formed DER instead of random bytes. Usage: fuzz/seed-corpus.sh <out-dir>
set -euo pipefail
out="${1:?usage: seed-corpus.sh <out-dir>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out/csr_p256" "$out/csr_rsa_pkcs1_lab" "$out/ca_certificate" "$out/crl_verify"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/p256.key" -subj "/CN=fuzz.lab.invalid" -outform DER -out "$out/csr_p256/p256.der" 2>/dev/null
openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -keyout "$work/rsa.key" -subj "/CN=fuzz.lab.invalid" -outform DER -out "$out/csr_rsa_pkcs1_lab/rsa2048.der" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$work/ca.key" -subj "/CN=Fuzz Lab Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -outform DER -out "$out/ca_certificate/root-p256.der" 2>/dev/null

# Well-formed CRLs (empty, and with one revoked entry) from a throwaway openssl CA.
ca="$work/crlca"
mkdir -p "$ca"
: > "$ca/index.txt"
echo 01 > "$ca/serial"
echo 01 > "$ca/crlnumber"
cat > "$ca/openssl.cnf" <<CNF
[ca]
default_ca = lab
[lab]
database = $ca/index.txt
serial = $ca/serial
crlnumber = $ca/crlnumber
new_certs_dir = $ca
default_md = sha256
default_crl_days = 7
policy = pol
[pol]
commonName = supplied
CNF
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$ca/ca.key" -subj "/CN=Sovereign Trust Lab Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$ca/ca.pem" 2>/dev/null
openssl ca -config "$ca/openssl.cnf" -cert "$ca/ca.pem" -keyfile "$ca/ca.key" \
  -gencrl -out "$ca/empty.pem" 2>/dev/null
openssl crl -in "$ca/empty.pem" -outform DER -out "$out/crl_verify/empty.der"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$ca/leaf.key" -subj "/CN=leaf.lab.invalid" -out "$ca/leaf.csr" 2>/dev/null
openssl ca -batch -config "$ca/openssl.cnf" -cert "$ca/ca.pem" -keyfile "$ca/ca.key" \
  -in "$ca/leaf.csr" -out "$ca/leaf.pem" -days 1 -notext 2>/dev/null
openssl ca -config "$ca/openssl.cnf" -cert "$ca/ca.pem" -keyfile "$ca/ca.key" \
  -revoke "$ca/leaf.pem" -crl_reason keyCompromise 2>/dev/null
openssl ca -config "$ca/openssl.cnf" -cert "$ca/ca.pem" -keyfile "$ca/ca.key" \
  -gencrl -out "$ca/revoked.pem" 2>/dev/null
openssl crl -in "$ca/revoked.pem" -outform DER -out "$out/crl_verify/revoked.der"
