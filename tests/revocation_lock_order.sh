#!/usr/bin/env bash
# Disposable PostgreSQL 16 (lab only): the status-change functions lock in one
# order (certificate, then officer grant), so a bulk grant deletion racing a
# proposal and an approval cannot deadlock. Scenario:
#   T2 holds the certificate row (open transaction), T1 proposes on it,
#   T3 deletes the CA's officer grants, then T2 approves.
# With grant-then-certificate in propose, T1 holds the maker grant while
# waiting for the certificate, T3 waits for T1, T2 waits for T3: PostgreSQL
# aborts one of them with 40P01. Needs migrations 0001..0025 and host psql:
#   TRUST_CI_DATABASE_URL=postgresql://... bash tests/revocation_lock_order.sh
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
temp="$(mktemp -d)"
cleanup() {
  exec 3>&- 2>/dev/null || true
  # An aborted run must not leave sessions holding row locks.
  psql -X -q -A -t "$TRUST_CI_DATABASE_URL" -c "SELECT pg_terminate_backend(pid)
    FROM pg_stat_activity WHERE application_name IN ('lock-t1','lock-t2','lock-t3')" \
    >/dev/null 2>&1 || true
  kill $(jobs -p) 2>/dev/null || true
  rm -rf "$temp"
}
trap cleanup EXIT

sql() {
  psql -X -q -A -t -v ON_ERROR_STOP=1 "$TRUST_CI_DATABASE_URL" -c "$1"
}
wait_for_lock_wait() { # <application_name>
  for _ in $(seq 1 200); do
    [ "$(sql "SELECT count(*) FROM pg_stat_activity
              WHERE application_name = '$1' AND wait_event_type = 'Lock'")" != 0 ] && return 0
    sql "SELECT pg_sleep(0.05)" >/dev/null
  done
  echo "FAIL: $1 never waited on a lock" >&2
  exit 1
}

iss="https://idp.lab.invalid"
ca="$(sql "SELECT gen_random_uuid()")"
sql "INSERT INTO ca(ca_id,display_name,policy_version) VALUES ('$ca','Lock Order CA','v1')" >/dev/null
sql "INSERT INTO certificate_request(request_id,ca_id,idempotency_key,csr_sha256,requester_id,policy_version,state)
     VALUES (gen_random_uuid(),'$ca','lock-1',sha256('csr'::bytea),'requester','v1','PUBLISHED')" >/dev/null
sql "INSERT INTO serial_reservation(ca_id,serial_der_content,request_id)
     SELECT '$ca','\\x01',request_id FROM certificate_request WHERE ca_id='$ca'" >/dev/null
sql "INSERT INTO certificate(ca_id,serial_der_content,request_id,fingerprint_sha256,certificate_der,signed_at)
     SELECT ca_id,serial_der_content,request_id,sha256('der'::bytea),'\\x3003020101',now()
     FROM serial_reservation WHERE ca_id='$ca'" >/dev/null
# Checker grant first, maker grant second: T3 deletes in that order.
sql "INSERT INTO revocation_officer_grant(issuer,subject,ca_id) VALUES ('$iss','checker','$ca')" >/dev/null
sql "INSERT INTO revocation_officer_grant(issuer,subject,ca_id) VALUES ('$iss','maker','$ca')" >/dev/null
# A pending REVOKE for T2 to approve; T1 races a second proposal on the same
# certificate (refused as a duplicate, but only after taking its locks).
change="$(sql "SELECT propose_certificate_status_change('$ca','\\x01','REVOKE',1::smallint,NULL,'$iss','maker')")"

# T2 is driven step by step through a FIFO: hold the certificate row now,
# approve once T1 and T3 are queued.
mkfifo "$temp/t2.in"
PGAPPNAME=lock-t2 psql -X -q -A -t "$TRUST_CI_DATABASE_URL" <"$temp/t2.in" \
  >"$temp/t2.out" 2>"$temp/t2.err" &
t2=$!
exec 3>"$temp/t2.in"
echo "BEGIN;" >&3
echo "SELECT 1 FROM certificate WHERE ca_id = '$ca' AND serial_der_content = '\\x01' FOR UPDATE;" >&3
for _ in $(seq 1 200); do
  [ "$(sql "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid)
            WHERE a.application_name = 'lock-t2' AND l.relation = 'certificate'::regclass
              AND l.granted")" != 0 ] && break
  sql "SELECT pg_sleep(0.05)" >/dev/null
done
# T1: a second proposal on the same certificate (refused later as a
# duplicate, but only after it has taken its locks).
(
  PGAPPNAME=lock-t1 psql -X -q -A -t "$TRUST_CI_DATABASE_URL" \
    -c "SELECT propose_certificate_status_change('$ca','\\x01','REVOKE',4::smallint,NULL,'$iss','maker')" \
    >"$temp/t1.out" 2>"$temp/t1.err"
) &
t1=$!
wait_for_lock_wait lock-t1
# T3: bulk deletion of the CA's grants (checker, then maker).
(
  PGAPPNAME=lock-t3 psql -X -q -A -t "$TRUST_CI_DATABASE_URL" \
    -c "DELETE FROM revocation_officer_grant WHERE ca_id = '$ca'" \
    >"$temp/t3.out" 2>"$temp/t3.err"
) &
t3=$!
# Before 0025 T3 waits for T1 (which holds the maker grant); after it, T1
# holds no grant while it waits, so T3 may simply finish.
for _ in $(seq 1 200); do
  kill -0 "$t3" 2>/dev/null || break
  [ "$(sql "SELECT count(*) FROM pg_stat_activity
            WHERE application_name = 'lock-t3' AND wait_event_type = 'Lock'")" != 0 ] && break
  sql "SELECT pg_sleep(0.05)" >/dev/null
done
echo "SELECT approve_certificate_status_change('$change', '$iss', 'checker', 'REVOKE', 1::smallint);" >&3
echo "COMMIT;" >&3
exec 3>&-
wait "$t1" || true
wait "$t2" || true
wait "$t3" || true

if grep -q "deadlock detected" "$temp"/t1.err "$temp"/t2.err "$temp"/t3.err; then
  echo "FAIL: deadlock between proposal, approval and grant deletion" >&2
  grep -h "deadlock\|ERROR" "$temp"/t*.err >&2 || true
  exit 1
fi
echo "PASS: proposal, approval and bulk grant deletion do not deadlock"
