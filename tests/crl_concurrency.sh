#!/usr/bin/env bash
# Disposable PostgreSQL 16 (lab only): 12 clients reserve a CRL number while 4
# others approve prepared revocations. Numbers must be distinct and
# consecutive, and a reservation must never observe a half-applied or
# mis-timed approval.
# Needs a database with migrations 0001..0016 applied and host psql:
#   TRUST_CI_DATABASE_URL=postgresql://user:pw@127.0.0.1:5432/db bash tests/crl_concurrency.sh
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT

sql() {
  psql -X -q -A -t -v ON_ERROR_STOP=1 "$TRUST_CI_DATABASE_URL" -c "$1"
}

iss="https://idp.lab.invalid"
ca="$(sql "SELECT gen_random_uuid()")"

# Fixture: own CA, five issued certificates, maker/checker grants, five
# PROPOSED revocations with distinct reason codes (1..5). Changes 1..4 race
# the reservations; change 5 is used by the deterministic gate check.
sql "INSERT INTO ca(ca_id,display_name,policy_version) VALUES
    ('$ca','CRL Concurrency CA','v1')" >/dev/null
sql "INSERT INTO certificate_request(request_id,ca_id,idempotency_key,csr_sha256,
        requester_id,policy_version,state)
     SELECT gen_random_uuid(),'$ca','crl-race-'||n,sha256(('csr'||n)::bytea),'requester','v1','PUBLISHED'
     FROM generate_series(1,5) n" >/dev/null
sql "INSERT INTO serial_reservation(ca_id,serial_der_content,request_id)
     SELECT '$ca',decode('0'||row_number() OVER (ORDER BY idempotency_key),'hex'),request_id
     FROM certificate_request WHERE ca_id='$ca'" >/dev/null
sql "INSERT INTO certificate(ca_id,serial_der_content,request_id,fingerprint_sha256,
        certificate_der,signed_at)
     SELECT ca_id,serial_der_content,request_id,sha256(serial_der_content),decode('3003020101','hex'),now()
     FROM serial_reservation WHERE ca_id='$ca'" >/dev/null
sql "INSERT INTO revocation_officer_grant(issuer,subject,ca_id) VALUES
    ('$iss','maker','$ca'),('$iss','checker','$ca')" >/dev/null

declare -a changes
for n in 1 2 3 4 5; do
  changes[$n]="$(sql "SELECT propose_certificate_status_change('$ca',decode('0$n','hex'),
      'REVOKE',${n}::smallint,NULL,'$iss','maker')")"
done

pids=()
for i in $(seq 1 12); do
  (
    sql "SELECT pg_sleep(random()*0.05); SELECT crl_number FROM reserve_crl(
        '$ca','crl-worker-$i','race-op-$i')" > "$temp/reserve-$i"
  ) &
  pids+=("$!")
done
for n in 1 2 3 4; do
  (
    sql "SELECT pg_sleep(random()*0.05); SELECT approve_certificate_status_change(
        '${changes[$n]}','$iss','checker','REVOKE',${n}::smallint)" > "$temp/approve-$n"
  ) &
  pids+=("$!")
done
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
if [ "$failed" != "0" ]; then
  echo "FAIL: a concurrent client exited with an error" >&2
  exit 1
fi


numbers="$(sql "SELECT count(*)||'|'||count(DISTINCT crl_number)||'|'||min(crl_number)||'|'||max(crl_number)
  FROM crl_publication WHERE ca_id='$ca'")"

# Deterministic gate: while a reservation holds the CA row, an approval waits
# for it *before* stamping decided_at. The CRL it produced therefore either
# contains the change or predates the decision; a later CRL contains it.
# Ordering comes from pg_locks, not from sleeps: the approver starts once the
# gate's snapshot insert is visible as a granted lock, and the gate commits
# only after it has seen the approver blocked behind it (10 s limit).
(
  PGAPPNAME=crl-gate sql "CREATE FUNCTION pg_temp.await_blocked() RETURNS boolean
      LANGUAGE plpgsql AS \$fn\$
      BEGIN
          FOR i IN 1..200 LOOP
              IF EXISTS (SELECT 1 FROM pg_locks l WHERE NOT l.granted
                         AND pg_backend_pid() = ANY (pg_blocking_pids(l.pid))) THEN
                  RETURN true;
              END IF;
              PERFORM pg_sleep(0.05);
          END LOOP;
          RETURN false;
      END \$fn\$;
      SELECT r.crl_number || '|' || s.t || '|' || s.blocked
      FROM reserve_crl('$ca','crl-worker-gate','race-op-gate') r,
      LATERAL (SELECT pg_temp.await_blocked()::int AS blocked, clock_timestamp() AS t
               WHERE r.crl_number > 0) s" > "$temp/gate-reserve"
) &
gate_pid=$!
gate_holds=0
for _ in $(seq 1 200); do
  gate_holds="$(sql "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid)
    WHERE a.application_name='crl-gate' AND l.granted
      AND l.relation='crl_entry_snapshot'::regclass")"
  [ "$gate_holds" != "0" ] && break
  sql "SELECT pg_sleep(0.05)" >/dev/null
done
if [ "$gate_holds" = "0" ]; then
  echo "FAIL: gate reservation never held its locks" >&2
  exit 1
fi
sql "SELECT approve_certificate_status_change('${changes[5]}','$iss','checker',
    'REVOKE',5::smallint)" >/dev/null
wait "$gate_pid"
gate_number="$(cut -d'|' -f1 "$temp/gate-reserve")"
gate_release="$(cut -d'|' -f2 "$temp/gate-reserve")"
gate_blocked="$(cut -d'|' -f3 "$temp/gate-reserve")"
gate_late="$(sql "SELECT (decided_at >= '$gate_release'::timestamptz)::int FROM certificate_status_change
  WHERE change_id='${changes[5]}'")"
gate_snapshot_has_5="$(sql "SELECT count(*) FROM crl_entry_snapshot
  WHERE ca_id='$ca' AND crl_number=$gate_number AND serial_der_content=decode('05','hex')")"
sql "SELECT crl_number FROM reserve_crl('$ca','crl-worker-after','race-op-after')" >/dev/null
gate_after="$(sql "SELECT count(*) FROM crl_entry_snapshot s JOIN crl_publication p USING (ca_id,crl_number)
  WHERE p.ca_id='$ca' AND p.operation_ref='race-op-after'
    AND s.serial_der_content=decode('05','hex') AND s.reason_code=5")"

approved="$(sql "SELECT count(*) FROM certificate_status_change WHERE ca_id='$ca' AND status='APPROVED'")"

# Every snapshot row is the revocation written by an approved change: same
# serial, reason and revoked_at = decided_at, decided no later than the
# reservation (this_update is truncated to the second, hence the 1 s bound).
wrong_rows="$(sql "SELECT count(*) FROM crl_entry_snapshot s
  JOIN crl_publication p ON p.ca_id=s.ca_id AND p.crl_number=s.crl_number
  WHERE s.ca_id='$ca' AND NOT EXISTS (
    SELECT 1 FROM certificate_status_change c
    WHERE c.ca_id=s.ca_id AND c.serial_der_content=s.serial_der_content
      AND c.status='APPROVED' AND c.action='REVOKE'
      AND c.reason_code=s.reason_code AND c.decided_at=s.revoked_at
      AND c.decided_at < p.this_update + interval '1 second')")"
# A CRL without an approved change's row must have been reserved before the
# approval was decided; otherwise the revocation would be missed while
# crl_due / overdue_status_changes treat the CRL as covering it.
missed="$(sql "SELECT count(*) FROM crl_publication p
  JOIN certificate_status_change c ON c.ca_id=p.ca_id AND c.status='APPROVED'
  WHERE p.ca_id='$ca' AND c.decided_at <= p.this_update
    AND NOT EXISTS (SELECT 1 FROM crl_entry_snapshot s
        WHERE s.ca_id=p.ca_id AND s.crl_number=p.crl_number
          AND s.serial_der_content=c.serial_der_content)")"
# Every stored digest matches its stored entries.
bad_digest="$(sql "SELECT count(*) FROM crl_publication p
  WHERE p.ca_id='$ca' AND p.entries_sha256 <> sha256(COALESCE((
    SELECT string_agg(crl_entry_encoding(s.serial_der_content,s.revoked_at,s.reason_code,s.invalidity_at),
                      '\\x'::bytea ORDER BY s.serial_der_content)
    FROM crl_entry_snapshot s WHERE s.ca_id=p.ca_id AND s.crl_number=p.crl_number),'\\x'::bytea))")"
sizes="$(sql "SELECT string_agg(n::text, ',' ORDER BY n) FROM (
  SELECT count(s.serial_der_content) AS n FROM crl_publication p
  LEFT JOIN crl_entry_snapshot s ON s.ca_id=p.ca_id AND s.crl_number=p.crl_number
  WHERE p.ca_id='$ca' GROUP BY p.crl_number) x")"

if [ "$numbers" != "12|12|1|12" ] || [ "$approved" != "5" ] || [ "$gate_late" != "1" ] \
  || [ "$gate_blocked" != "1" ] || [ "$gate_snapshot_has_5" != "0" ] \
  || [ "$gate_after" != "1" ] \
  || [ "$wrong_rows" != "0" ] || [ "$missed" != "0" ] || [ "$bad_digest" != "0" ]; then
  echo "FAIL: CRL race numbers=$numbers approved=$approved gate_late=$gate_late gate_blocked=$gate_blocked gate_after=$gate_after gate_snapshot_has_5=$gate_snapshot_has_5 wrong_rows=$wrong_rows missed=$missed bad_digest=$bad_digest sizes=$sizes" >&2
  exit 1
fi

echo "snapshot sizes: $sizes"
echo "PASS: twelve concurrent CRL reservations got distinct consecutive numbers"
