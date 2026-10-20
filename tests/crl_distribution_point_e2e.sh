#!/usr/bin/env bash
# Lab only: OpenSSL follows the CRL distribution point inside issued
# certificates (RFC 5280 4.2.1.13) to the crl_distribution binary and
# enforces the revocation it finds. Inputs come from the
# issued_certificates_point_relying_parties_to_the_crl test, run with
# TRUST_CDP_EXPORT_DIR=<dir> and the same TRUST_CDP_BASE_URL (default
# http://127.0.0.1:18083). Needs a superuser URL, psql, openssl, python3:
#   TRUST_CI_DATABASE_URL=postgresql://... bash tests/crl_distribution_point_e2e.sh <dir>
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
dir="${1:?usage: crl_distribution_point_e2e.sh <export-dir>}"
base="${TRUST_CDP_BASE_URL:-http://127.0.0.1:18083}"
db="$TRUST_CI_DATABASE_URL"
temp="$(mktemp -d)"
server=""
cleanup() {
  [ -n "$server" ] && kill "$server" 2>/dev/null || true
  rm -rf "$temp"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; [ -f "$temp/server.log" ] && cat "$temp/server.log" >&2; exit 1; }

for name in root revoked valid; do
  [ -s "$dir/$name.der" ] || fail "missing $dir/$name.der"
  openssl x509 -inform DER -in "$dir/$name.der" -out "$temp/$name.pem"
done
ca="$(cat "$dir/ca_id")"
expected="$base/crl/$ca.crl"
openssl x509 -in "$temp/revoked.pem" -noout -ext crlDistributionPoints \
  | grep -q "URI:$expected" || fail "certificate does not name $expected"

# A login holding only trust_crl_publisher (test-only password, lab only).
psql -X -q -v ON_ERROR_STOP=1 "$db" -c "DO \$\$BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_crl_publisher_ci') THEN
      CREATE ROLE trust_crl_publisher_ci LOGIN PASSWORD 'test-only-not-secret';
    END IF;
  END\$\$;
  GRANT trust_crl_publisher TO trust_crl_publisher_ci" >/dev/null
publisher_url="$(python3 - "$db" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname + (f":{u.port}" if u.port else "")
print(urllib.parse.urlunsplit((u.scheme, f"trust_crl_publisher_ci:test-only-not-secret@{host}",
                               u.path, u.query, u.fragment)))
PY
)"
bind="$(python3 -c 'import sys,urllib.parse;u=urllib.parse.urlsplit(sys.argv[1]);print(f"{u.hostname}:{u.port or 80}")' "$base")"

# OpenSSL 3.0 can spin when the distribution point refuses connections, so
# every verification runs under a timeout, downloads only once the server
# answers.
verify() { # <leaf> [extra openssl options]
  local leaf="$1"; shift
  timeout 30 openssl verify -CAfile "$temp/root.pem" -crl_check "$@" "$temp/$leaf.pem" 2>&1 || true
}

# Without downloading the CRL, revocation status cannot be established.
out="$(verify valid)"
echo "$out" | grep -q "unable to get certificate CRL" || fail "CRL found without the distribution point: $out"

cargo build -q --locked -p trust-management-api --bin crl_distribution
TRUST_CRL_DATABASE_URL="$publisher_url" TRUST_CRL_BIND="$bind" \
  target/debug/crl_distribution 2>"$temp/server.log" &
server=$!
for _ in $(seq 1 100); do
  curl -s -o /dev/null "$expected" && break
  sleep 0.1
done

out="$(verify revoked -crl_download)"
echo "$out" | grep -q "certificate revoked" || fail "revoked leaf not refused: $out"
out="$(verify valid -crl_download)"
echo "$out" | grep -q ": OK" || fail "valid leaf not accepted: $out"

echo "PASS: OpenSSL follows the issued CRL distribution point and enforces revocation"
