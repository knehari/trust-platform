#!/usr/bin/env bash
# Lab only: replays every case of the RFC 5280 path-validation suite
# (crates/pki-core/tests/rfc5280_path_validation.rs) with OpenSSL, a second
# independent validator. The Rust test checks the same cases with
# rustls-webpki and exports the platform's certificates and CRLs (public
# objects only) and a manifest; each case must give the expected outcome,
# and an invalid case must fail for the expected reason.
#   bash tests/rfc5280_path_validation.sh
set -euo pipefail
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

TRUST_PATH_VALIDATION_EXPORT_DIR="$out" cargo test -q --locked -p trust-pki-core \
  --features lab-software --test rfc5280_path_validation 2>&1 | grep -E "^test result" \
  | grep -q "1 passed" || fail "webpki suite"
[ -s "$out/manifest" ] || fail "no manifest exported"
for der in "$out"/*.der; do openssl x509 -inform DER -in "$der" -out "${der%.der}.pem"; done
for crl in "$out"/*.crl; do openssl crl -inform DER -in "$crl" -out "${crl%.crl}.crl.pem"; done

cases=0
while IFS='|' read -r name expect leaf chain anchor crls at purpose host reason; do
  args=(-CAfile "$out/$anchor.pem" -attime "$at" -purpose "$purpose")
  [ -n "$chain" ] && for c in ${chain//,/ }; do args+=(-untrusted "$out/$c.pem"); done
  if [ -n "$crls" ]; then
    args+=(-crl_check)
    for c in ${crls//,/ }; do args+=(-CRLfile "$out/$c.crl.pem"); done
  fi
  [ -n "$host" ] && args+=(-verify_hostname "$host")
  set +e
  result="$(openssl verify "${args[@]}" "$out/$leaf.pem" 2>&1)"
  status=$?
  set -e
  if [ "$expect" = valid ]; then
    [ "$status" = 0 ] || fail "$name: expected valid, OpenSSL: $result"
  else
    [ "$status" != 0 ] || fail "$name: expected invalid, OpenSSL accepted it"
    grep -qi "$reason" <<<"$result" || fail "$name: expected '$reason', OpenSSL: $result"
  fi
  cases=$((cases + 1))
done <"$out/manifest"
[ "$cases" -ge 17 ] || fail "only $cases cases"
echo "PASS: $cases RFC 5280 path-validation cases agree across webpki and OpenSSL $(openssl version | cut -d' ' -f2)"
