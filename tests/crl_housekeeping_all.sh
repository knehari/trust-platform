#!/usr/bin/env bash
# Disposable PostgreSQL 16 (lab only): the crl_housekeeping example with
# --all covers every CA with a registered issuer (migration 0033), under a
# login holding only trust_crl_operator, and alerts (exit 2) when one of them
# needs attention. Needs migrations 0001..0033, a superuser URL and psql:
#   TRUST_CI_DATABASE_URL=postgresql://... bash tests/crl_housekeeping_all.sh
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
db="$TRUST_CI_DATABASE_URL"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
fail() { echo "FAIL: $*" >&2; cat "$temp/out" "$temp/err" 2>/dev/null >&2; exit 1; }
sql() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" -c "$1"; }

# A CA with a registered issuer and no CRL yet: due, so the job must alert.
ca="$(sql "INSERT INTO ca(ca_id, display_name, policy_version)
           VALUES (gen_random_uuid(), 'Housekeeping All CA', 'v1') RETURNING ca_id")"
sql "SELECT register_ca_issuer('$ca', convert_to('issuer of ' || '$ca', 'UTF8'), 'bootstrap')" >/dev/null
# A login holding only trust_crl_operator (test-only password, lab only).
sql "DO \$\$BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_crl_operator_ci') THEN
         CREATE ROLE trust_crl_operator_ci LOGIN PASSWORD 'test-only-not-secret';
       END IF;
     END\$\$;
     GRANT trust_crl_operator TO trust_crl_operator_ci" >/dev/null
operator_url="$(python3 - "$db" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname + (f":{u.port}" if u.port else "")
print(urllib.parse.urlunsplit((u.scheme, f"trust_crl_operator_ci:test-only-not-secret@{host}",
                               u.path, u.query, u.fragment)))
PY
)"
cargo build -q --locked -p trust-pki-core --features postgres-store --example crl_housekeeping
bin=target/debug/examples/crl_housekeeping

set +e
TRUST_DATABASE_URL="$operator_url" "$bin" --all >"$temp/out" 2>"$temp/err"
status=$?
set -e
[ "$status" = 2 ] || fail "--all exited $status, expected 2 (a CA is due)"
grep -q "^ca=$ca .*crl_due=true" "$temp/out" || fail "the new CA was not covered"
expected="$(sql "SELECT count(*) FROM ca_issuer_certificate")"
grep -q "^cas=$expected " "$temp/out" || fail "not every issuing CA was covered"
[ "$(grep -c '^ca=' "$temp/out")" = "$expected" ] || fail "per-CA lines missing"
# A privileged login is refused (exit 1).
set +e
TRUST_DATABASE_URL="$db" "$bin" --all >"$temp/out" 2>"$temp/err"
status=$?
set -e
[ "$status" = 1 ] || fail "a superuser login was accepted"
echo "PASS: housekeeping covers every CRL-issuing CA under the operator login"
