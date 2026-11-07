#!/usr/bin/env bash
# Disposable PostgreSQL 16 (lab only): `signed_evidence_audit --all` audits
# every CA carrying signed evidence (migration 0056) under a login holding
# only trust_audit_verifier. Run it after signed_status_change_postgres on
# the same database: those tests leave several CAs with evidence, some
# deliberately altered, so the job must report them and exit 3.
#   TRUST_CI_DATABASE_URL=postgresql://... bash tests/signed_evidence_audit_all.sh
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
db="$TRUST_CI_DATABASE_URL"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
fail() { echo "FAIL: $*" >&2; cat "$temp/out" "$temp/err" >&2 2>/dev/null; exit 1; }
sql() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" -c "$1"; }

sql "DO \$\$BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_audit_verifier_ci') THEN
         CREATE ROLE trust_audit_verifier_ci LOGIN PASSWORD 'test-only-not-secret';
       END IF;
     END\$\$;
     GRANT trust_audit_verifier TO trust_audit_verifier_ci" >/dev/null
auditor_url="$(python3 - "$db" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname + (f":{u.port}" if u.port else "")
print(urllib.parse.urlunsplit((u.scheme, f"trust_audit_verifier_ci:test-only-not-secret@{host}",
                               u.path, u.query, u.fragment)))
PY
)"
expected="$(sql "SELECT count(*) FROM evidence_cas()")"
[ "$expected" -ge 2 ] || fail "expected several CAs with evidence, found $expected (run after the signed tests)"
cargo build -q --locked -p trust-management-api --bin signed_evidence_audit
set +e
TRUST_DATABASE_TLS=disable-lab TRUST_DATABASE_URL="$auditor_url" \
TRUST_WEBAUTHN_RP_ID=officer.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
  target/debug/signed_evidence_audit --all >"$temp/out" 2>"$temp/err"
status=$?
set -e
[ "$status" = 3 ] || fail "exit $status, expected 3 (altered evidence present)"
summaries="$(grep -c ' all_verified=' "$temp/out" || true)"
[ "$summaries" = "$expected" ] || fail "$summaries CA summaries, expected $expected"
grep -q ' FAILED ' "$temp/out" || fail "no failed change reported"
grep -q ' all_verified=true' "$temp/out" || fail "no CA fully verified"
echo "PASS: signed_evidence_audit --all audits every CA with signed evidence ($expected) and reports altered ones"
