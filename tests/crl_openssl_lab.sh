#!/usr/bin/env bash
# Lab-only: OpenSSL must accept the lab CRLs and enforce revocation / released holds.
# Usage: crl_openssl_lab.sh            (generate with the in-memory lab example)
#        crl_openssl_lab.sh <input-dir> (check root/leaf1..3/crl1..2.der written by
#        the revocation_crl_postgres test from PostgreSQL via TRUST_CRL_EXPORT_DIR)
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }

out="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/trust-crl-lab.XXXXXX")"
trap 'rm -rf "$out"' EXIT

if [ $# -ge 1 ]; then
  source_label="PostgreSQL-stored"
  for name in root leaf1 leaf2 leaf3 crl1 crl2; do
    [ -s "$1/$name.der" ] || fail "missing $1/$name.der"
    cp "$1/$name.der" "$out/"
  done
else
  source_label="lab example"
  cd "$root_dir"
  cargo run --locked -q -p trust-pki-core --features lab-software --example issue_crl_lab -- "$out"
fi

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

# Delta CRL (RFC 5280 5.2.4), when present: crl3_delta updates base CRL 1
# with leaf3 superseded and leaf2 removeFromCRL.
delta_label=""
if [ -s "$out/crl3_delta.der" ] || { [ $# -ge 1 ] && [ -s "$1/crl3_delta.der" ] && cp "$1/crl3_delta.der" "$out/"; }; then
  openssl crl -inform DER -in "$out/crl3_delta.der" -out "$out/crl3_delta.pem"
  res="$(openssl crl -inform DER -in "$out/crl3_delta.der" -CAfile "$out/root.pem" -noout 2>&1)" \
    || fail "crl3_delta rejected by openssl crl: $res"
  grep -qx 'verify OK' <<<"$res" || fail "crl3_delta: expected 'verify OK', got: $res"
  text3="$(openssl crl -inform DER -in "$out/crl3_delta.der" -noout -text)"
  grep -A1 'X509v3 Delta CRL Indicator: critical' <<<"$text3" | grep -qx '[[:space:]]*1' \
    || fail "crl3_delta lacks a critical delta CRL indicator for base 1"
  grep -q 'Remove From CRL' <<<"$text3" || fail "crl3_delta lacks removeFromCRL"
  delta_check() { # <leaf> <revoked|ok> [no-deltas]
    local status=0 res flags=(-crl_check -use_deltas)
    [ "${3:-}" = no-deltas ] && flags=(-crl_check)
    res="$(openssl verify "${flags[@]}" -purpose sslserver -CAfile "$out/root.pem" \
      -CRLfile "$out/crl1.pem" -CRLfile "$out/crl3_delta.pem" "$out/$1.pem" 2>&1)" || status=$?
    if [ "$2" = revoked ]; then
      [ "$status" -ne 0 ] && grep -q 'certificate revoked' <<<"$res" \
        || fail "$1 with crl1+delta (${3:-deltas}): expected revoked, got: $res"
    else
      [ "$status" -eq 0 ] || fail "$1 with crl1+delta (${3:-deltas}): expected OK, got: $res"
    fi
  }
  delta_check leaf1 revoked
  delta_check leaf2 ok
  delta_check leaf3 revoked
  # Without delta processing, the base CRL alone decides.
  delta_check leaf2 revoked no-deltas
  delta_check leaf3 ok no-deltas
  delta_label=" and a delta CRL"
fi

echo "PASS: OpenSSL accepts $source_label CRLs$delta_label and enforces revocation and released holds"
