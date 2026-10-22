#!/usr/bin/env bash
# Lab-only: OpenSSL must apply a delta CRL (RFC 5280 5.2.4) to its base.
# Usage: crl_delta_openssl.sh <dir> <base> <delta>
#   <dir> holds root.der, leaf1..3.der, <base>.der and <delta>.der. The base
#   lists leaf1 (keyCompromise) and leaf2 (certificateHold) and advertises
#   delta CRLs (freshestCRL); the delta, on that base, lists leaf3
#   (superseded) and leaf2 (removeFromCRL).
# Written by the issue_crl_lab example and, from PostgreSQL, by the
# delta_crl_is_reserved_signed_and_stored_through_the_database test.
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
[ $# -eq 3 ] || fail "usage: $0 <dir> <base> <delta>"
dir="$1" base="$2" delta="$3"
out="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/trust-crl-delta.XXXXXX")"
trap 'rm -rf "$out"' EXIT
for name in root leaf1 leaf2 leaf3; do
  [ -s "$dir/$name.der" ] || fail "missing $dir/$name.der"
  openssl x509 -inform DER -in "$dir/$name.der" -out "$out/$name.pem"
done
for name in "$base" "$delta"; do
  [ -s "$dir/$name.der" ] || fail "missing $dir/$name.der"
  openssl crl -inform DER -in "$dir/$name.der" -out "$out/$name.pem"
  res="$(openssl crl -inform DER -in "$dir/$name.der" -CAfile "$out/root.pem" -noout 2>&1)" \
    || fail "$name rejected by openssl crl: $res"
  grep -qx 'verify OK' <<<"$res" || fail "$name: expected 'verify OK', got: $res"
done
base_text="$(openssl crl -inform DER -in "$dir/$base.der" -noout -text)"
base_number="$(grep -A1 'X509v3 CRL Number:' <<<"$base_text" | tail -1 | tr -d '[:space:]')"
grep -q 'X509v3 Freshest CRL:' <<<"$base_text" || fail "$base does not advertise delta CRLs"
grep -q 'Delta CRL Indicator' <<<"$base_text" && fail "$base is itself a delta CRL"
delta_text="$(openssl crl -inform DER -in "$dir/$delta.der" -noout -text)"
grep -A1 'X509v3 Delta CRL Indicator: critical' <<<"$delta_text" | tail -1 | grep -qx "[[:space:]]*$base_number" \
  || fail "$delta lacks a critical delta CRL indicator for base $base_number"
grep -q 'Remove From CRL' <<<"$delta_text" || fail "$delta lacks removeFromCRL"
grep -q 'Freshest CRL' <<<"$delta_text" && fail "$delta advertises freshestCRL (RFC 5280 5.2.6)"

# OpenSSL needs -extended_crl with -use_deltas: without it, given both
# files, it picks the newer delta as if it were the complete CRL (an entry
# revoked only in the base then verifies OK). Relying parties must enable
# both, or fetch only the complete CRL (the CDP never serves a delta).
check() { # <leaf> <revoked|ok> [no-deltas]
  local status=0 res flags=(-crl_check -extended_crl -use_deltas)
  local crls=(-CRLfile "$out/$base.pem" -CRLfile "$out/$delta.pem")
  if [ "${3:-}" = no-deltas ]; then
    flags=(-crl_check)
    crls=(-CRLfile "$out/$base.pem")
  fi
  res="$(openssl verify "${flags[@]}" -purpose sslserver -CAfile "$out/root.pem" \
    "${crls[@]}" "$out/$1.pem" 2>&1)" || status=$?
  if [ "$2" = revoked ]; then
    [ "$status" -ne 0 ] && grep -q 'certificate revoked' <<<"$res" \
      || fail "$1 with $base+$delta (${3:-deltas}): expected revoked, got: $res"
  else
    [ "$status" -eq 0 ] || fail "$1 with $base+$delta (${3:-deltas}): expected OK, got: $res"
  fi
}
check leaf1 revoked
check leaf2 ok
check leaf3 revoked
# A relying party without delta support uses the complete CRL alone.
check leaf2 revoked no-deltas
check leaf3 ok no-deltas
echo "PASS: OpenSSL applies delta CRL $delta to base $base (released hold, new revocation)"
