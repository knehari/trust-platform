#!/usr/bin/env bash
# Lab-only: crl_restore_revocations re-applies a published CRL's revocations
# after a restore from an older backup (migration 0060). Needs the files
# written by the PostgreSQL test
# revocations_lost_in_a_restore_are_reapplied_from_the_published_crl with
# TRUST_CRL_EXPORT_DIR (<dir>/restore: crl7.der, crl7_forged.der, ids), a
# superuser URL, psql and python3:
#   TRUST_CI_DATABASE_URL=postgresql://... bash tests/crl_restore_revocations.sh <dir>
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
db="$TRUST_CI_DATABASE_URL"
dir="${1:?usage: $0 <export dir>}/restore"
fail() { echo "FAIL: $*" >&2; exit 1; }
sql() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" -c "$1"; }
read -r ca s3 lost <"$dir/ids"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
cargo build -q --locked -p trust-management-api --bin crl_restore_revocations
bin=target/debug/crl_restore_revocations
run() { TRUST_DATABASE_TLS=disable-lab TRUST_DATABASE_URL="$1" "$bin" "${@:2}" >"$temp/out" 2>"$temp/err"; }
status() { sql "SELECT certificate_status('$ca', '\\x$1')"; }
audits() { sql "SELECT count(*) FROM audit_event WHERE ca_id = '$ca' AND event_type = 'revocation.restored_from_crl'"; }

before="$(audits)"
[ "$(status "$s3")" = VALID ] || fail "s3 is not VALID before the restore"

# A service login is refused before the CRL is even sent.
sql "DO \$\$BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_crl_operator_restore_ci') THEN
         CREATE ROLE trust_crl_operator_restore_ci LOGIN PASSWORD 'test-only-not-secret';
       END IF;
     END\$\$;
     GRANT trust_crl_operator TO trust_crl_operator_restore_ci" >/dev/null
operator_url="$(python3 - "$db" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname + (f":{u.port}" if u.port else "")
print(urllib.parse.urlunsplit((u.scheme, f"trust_crl_operator_restore_ci:test-only-not-secret@{host}",
                               u.path, u.query, u.fragment)))
PY
)"
status=0; run "$operator_url" "$ca" "$dir/crl7.der" --reason drill || status=$?
[ "$status" -eq 1 ] && grep -q NotSuperuser "$temp/err" || fail "service login not refused ($status): $(cat "$temp/err")"
# Without a reason, or with a forged CRL: refused, nothing changed.
status=0; run "$db" "$ca" "$dir/crl7.der" || status=$?
[ "$status" -eq 1 ] || fail "missing --reason accepted"
status=0; run "$db" "$ca" "$dir/crl7_forged.der" --reason drill || status=$?
[ "$status" -eq 1 ] && grep -q InvalidCrl "$temp/err" || fail "forged CRL not refused ($status): $(cat "$temp/err")"
[ "$(status "$s3")" = VALID ] || fail "a refused run changed s3"
[ "$(audits)" = "$before" ] || fail "a refused run was audited as a restore"

# The real CRL: s3 restored, the unknown certificate reported, exit 2.
status=0; run "$db" "$ca" "$dir/crl7.der" --reason "restore drill" || status=$?
[ "$status" -eq 2 ] || fail "expected exit 2 (operator action), got $status: $(cat "$temp/err")"
grep -qx "serial=$s3 outcome=RESTORED" "$temp/out" || fail "s3 not restored: $(cat "$temp/out")"
grep -qx "serial=$lost outcome=UNKNOWN_CERTIFICATE" "$temp/out" || fail "unknown certificate not reported"
[ "$(grep -c 'outcome=PRESENT' "$temp/out")" -eq 2 ] || fail "s1 and s2 not reported present"
[ "$(status "$s3")" = REVOKED ] || fail "s3 is not REVOKED after the restore"
[ "$(audits)" -eq $((before + 1)) ] || fail "restore not audited"
[ "$(sql "SELECT max(floor) FROM crl_number_floor WHERE ca_id = '$ca'")" = 7 ] || fail "floor not raised to 7"
echo "PASS: crl_restore_revocations re-applies a verified CRL's revocations and refuses forged CRLs and service logins"
