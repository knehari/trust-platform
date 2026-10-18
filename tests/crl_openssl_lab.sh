#!/usr/bin/env bash
# Lab-only: OpenSSL must accept the lab CRLs and enforce revocation / released holds.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -n "${RUNNER_TEMP:-}" ]; then
  out="$RUNNER_TEMP/trust-crl-lab"
  rm -rf "$out"
  mkdir -p "$out"
else
  out="$(mktemp -d)"
fi
trap 'rm -rf "$out"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

cd "$root_dir"
cargo run --locked -q -p trust-pki-core --features lab-software --example issue_crl_lab -- "$out"

for name in root leaf1 leaf2 leaf3; do
  openssl x509 -inform DER -in "$out/$name.der" -out "$out/$name.pem"
done
for name in crl1 crl2; do
  openssl crl -inform DER -in "$out/$name.der" -out "$out/$name.pem"
done

# Leaves must chain to the root before any CRL check.
for name in leaf1 leaf2 leaf3; do
  openssl verify -CAfile "$out/root.pem" -purpose sslserver "$out/$name.pem" >/dev/null \
    || fail "$name does not verify against root without CRL"
done

# CRL signature and issuer binding.
for name in crl1 crl2; do
  res="$(openssl crl -inform DER -in "$out/$name.der" -CAfile "$out/root.pem" -noout 2>&1)" \
    || fail "$name rejected by openssl crl: $res"
  grep -qx 'verify OK' <<<"$res" || fail "$name: expected 'verify OK', got: $res"
done

text="$(openssl crl -inform DER -in "$out/crl1.der" -noout -text)"
grep -A1 'X509v3 CRL Number:' <<<"$text" | grep -qx '[[:space:]]*1' || fail "crl1 CRL Number is not 1"
grep -q 'Key Compromise' <<<"$text" || fail "crl1 lacks Key Compromise"
grep -q 'Certificate Hold' <<<"$text" || fail "crl1 lacks Certificate Hold"
text2="$(openssl crl -inform DER -in "$out/crl2.der" -noout -text)"
grep -A1 'X509v3 CRL Number:' <<<"$text2" | grep -qx '[[:space:]]*2' || fail "crl2 CRL Number is not 2"
grep -q 'Certificate Hold' <<<"$text2" && fail "crl2 still lists the released hold"

check() { # <crl> <leaf> <revoked|ok>
  local status=0 res
  res="$(openssl verify -crl_check -purpose sslserver -CAfile "$out/root.pem" \
    -CRLfile "$out/$1.pem" "$out/$2.pem" 2>&1)" || status=$?
  if [ "$3" = revoked ]; then
    [ "$status" -ne 0 ] || fail "$2 accepted with $1 (expected revoked)"
    grep -q 'certificate revoked' <<<"$res" || fail "$2/$1: expected 'certificate revoked', got: $res"
  else
    [ "$status" -eq 0 ] || fail "$2 rejected with $1: $res"
    grep -q ': OK$' <<<"$res" || fail "$2/$1: expected OK, got: $res"
  fi
}

check crl1 leaf1 revoked
check crl1 leaf2 revoked
check crl1 leaf3 ok
check crl2 leaf1 revoked
check crl2 leaf2 ok
check crl2 leaf3 ok

echo "PASS: OpenSSL accepts lab CRLs and enforces revocation and released holds"
