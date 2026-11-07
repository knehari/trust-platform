#!/usr/bin/env bash
# Builds a small, valid seed corpus with OpenSSL so the fuzzers start from
# well-formed DER instead of random bytes. Usage: fuzz/seed-corpus.sh <out-dir>
set -euo pipefail
out="${1:?usage: seed-corpus.sh <out-dir>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# OpenSSL output is kept out of the log but shown, and fatal, on failure.
quiet() {
  if ! "$@" 2>"$work/stderr"; then
    cat "$work/stderr" >&2
    echo "seed-corpus: failed: $*" >&2
    exit 1
  fi
}
mkdir -p "$out/csr_p256" "$out/csr_rsa_pkcs1_lab" "$out/ca_certificate" "$out/crl_verify" \
  "$out/webauthn_assertion" "$out/audit_checkpoint"

quiet openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/p256.key" -subj "/CN=fuzz.lab.invalid" -outform DER -out "$out/csr_p256/p256.der"
quiet openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -keyout "$work/rsa.key" -subj "/CN=fuzz.lab.invalid" -outform DER -out "$out/csr_rsa_pkcs1_lab/rsa2048.der"
quiet openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$work/ca.key" -subj "/CN=Fuzz Lab Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -outform DER -out "$out/ca_certificate/root-p256.der"

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
quiet openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$ca/ca.key" -subj "/CN=Sovereign Trust Lab Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$ca/ca.pem"
quiet openssl ca -config "$ca/openssl.cnf" -cert "$ca/ca.pem" -keyfile "$ca/ca.key" \
  -gencrl -out "$ca/empty.pem"
quiet openssl crl -in "$ca/empty.pem" -outform DER -out "$work/empty.der"
quiet openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$ca/leaf.key" -subj "/CN=leaf.lab.invalid" -out "$ca/leaf.csr"
quiet openssl ca -batch -config "$ca/openssl.cnf" -cert "$ca/ca.pem" -keyfile "$ca/ca.key" \
  -in "$ca/leaf.csr" -out "$ca/leaf.pem" -days 1 -notext
quiet openssl ca -config "$ca/openssl.cnf" -cert "$ca/ca.pem" -keyfile "$ca/ca.key" \
  -revoke "$ca/leaf.pem" -crl_reason keyCompromise
quiet openssl ca -config "$ca/openssl.cnf" -cert "$ca/ca.pem" -keyfile "$ca/ca.key" \
  -gencrl -out "$ca/revoked.pem"
quiet openssl crl -in "$ca/revoked.pem" -outform DER -out "$work/revoked.der"

# crl_verify inputs start with a mode byte (see fuzz_targets/crl_verify.rs).
# Even: foreign CRLs verified as-is (another key signed them: must be refused).
for name in empty revoked; do
  { printf '\000'; cat "$work/$name.der"; } > "$out/crl_verify/foreign-$name.der"
done
# Odd: the harness CA's own CRL, unmodified (signature success) and with one
# flipped bit in the signature area (offset 0xffff wraps modulo the length).
printf '\001' > "$out/crl_verify/own.bin"
printf '\001\377\377\001' > "$out/crl_verify/own-flip.bin"

# WebAuthn: odd selects mutations of the harness's own valid assertion; even
# with empty parts exercises the length-prefixed split.
printf '\001' > "$out/webauthn_assertion/own.bin"
printf '\001\000\041\001' > "$out/webauthn_assertion/own-flag.bin"
printf '\000\000\045' > "$out/webauthn_assertion/short.bin"
# Checkpoint lines: one canonical unsigned and one canonical signed shape.
head="$(printf 'ab%.0s' $(seq 1 32))"
printf 'audit-chain-checkpoint v1 42 %s' "$head" > "$out/audit_checkpoint/v1.txt"
printf 'audit-chain-checkpoint v2 42 %s 3006020101020101' "$head" > "$out/audit_checkpoint/v2.txt"
