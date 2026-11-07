#!/usr/bin/env bash
# Disposable PostgreSQL 16 CI: 12 recovery workers race for one stale intent.
# Recovery must be issuer-scoped, locked, idempotent and unable to re-sign.
set -euo pipefail
container="${1:?PostgreSQL container id required}"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT

sql() {
  docker exec "$container" psql -X -A -t -v ON_ERROR_STOP=1 -U trust_ci -d trust_ci -c "$1"
}

ca="33333333-3333-4333-8333-333333333333"
sql "INSERT INTO ca(ca_id,display_name,policy_version) VALUES
    ('$ca','Recovery Concurrency CA','v1')" >/dev/null
request="$(sql "SELECT request_id::text FROM create_issuance_request(
    '$ca','recover-race',decode(repeat('da',32),'hex'),'actor','v1')")"
sql "SELECT transition_issuance_request('$ca','$request','RECEIVED','CSR_VALIDATED','actor')" >/dev/null
sql "SELECT transition_issuance_request('$ca','$request','CSR_VALIDATED','AUTHORIZED','actor')" >/dev/null
sql "SELECT reserve_issuance_serial('$ca','$request','actor')" >/dev/null
sql "SELECT intent_id FROM create_signing_intent(
    '$ca','$request','actor','nonexistent-signer',
    decode(repeat('aa',32),'hex'),'v1','recover-race-op')" >/dev/null

pids=()
for i in $(seq 1 12); do
  (
    sql "SELECT count(*) FROM quarantine_stale_signing_intents(
        '$ca',clock_timestamp(),10,'recovery-worker')" > "$temp/worker-$i"
  ) &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done

total="$(awk '{ n += $1 } END { print n+0 }' "$temp"/worker-*)"
state="$(sql "SELECT cr.state || ':' || si.outcome FROM certificate_request cr
  JOIN signing_intent si USING(ca_id,request_id) WHERE cr.request_id='$request'")"
audit="$(sql "SELECT count(*) FROM audit_event
  WHERE request_id='$request'
    AND event_type='request.transition'
    AND decision='SIGNING -> RECONCILIATION_REQUIRED'")"
cert_count="$(sql "SELECT count(*) FROM certificate WHERE request_id='$request'")"

if [ "$total" != "1" ] || [ "$audit" != "1" ] \
  || [ "$state" != "RECONCILIATION_REQUIRED:RECONCILIATION_REQUIRED" ] \
  || [ "$cert_count" != "0" ]; then
  echo "FAIL: recovery workers total=$total audit=$audit state=$state certs=$cert_count" >&2
  exit 1
fi

echo "PASS: twelve concurrent recovery workers quarantined exactly one intent"
