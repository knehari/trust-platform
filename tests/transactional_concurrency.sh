#!/usr/bin/env bash
# Integration concurrency test against DISPOSABLE PostgreSQL CI container.
# Usage: bash tests/transactional_concurrency.sh <postgres-container-id>
set -euo pipefail
container="${1:?PostgreSQL container ID required}"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

run_sql() {
  docker exec "$container" psql -X -A -t -v ON_ERROR_STOP=1 -U trust_ci -d trust_ci -c "$1"
}

ca="cccccccc-cccc-4ccc-8ccc-cccccccccccc"
run_sql "INSERT INTO ca (ca_id, display_name, policy_version) VALUES ('$ca', 'Concurrent Lab CA', 'v1');" >/dev/null

# Force multiple independent client connections to race for the SAME key.
pids=()
for i in $(seq 1 12); do
  (
    run_sql "SELECT request_id::text || ':' || replay::text FROM create_issuance_request('$ca','concurrent-key',decode(repeat('ab',32),'hex'),'concurrent-actor','v1');" >"$workdir/request-$i"
  ) &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done

request_ids="$(cat "$workdir"/request-* | cut -d: -f1 | sort -u)"
count="$(printf '%s\n' "$request_ids" | wc -l | tr -d ' ')"
if [ "$count" != 1 ]; then
  echo "FAIL: concurrent idempotency created $count request IDs" >&2
  exit 1
fi
request_id="$request_ids"
first_count="$(grep -l ':f$' "$workdir"/request-* | wc -l | tr -d ' ')"
if [ "$first_count" != 1 ]; then
  echo "FAIL: expected one initial insertion, got $first_count" >&2
  exit 1
fi

run_sql "SELECT transition_issuance_request('$ca','$request_id','RECEIVED','CSR_VALIDATED','concurrent-actor');" >/dev/null
run_sql "SELECT transition_issuance_request('$ca','$request_id','CSR_VALIDATED','AUTHORIZED','concurrent-actor');" >/dev/null

pids=()
for i in $(seq 1 12); do
  (
    run_sql "SELECT encode(reserve_issuance_serial('$ca','$request_id','concurrent-actor'),'hex');" >"$workdir/serial-$i"
  ) &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done

serial_count="$(cat "$workdir"/serial-* | sort -u | wc -l | tr -d ' ')"
if [ "$serial_count" != 1 ]; then
  echo "FAIL: concurrent serial reservation returned $serial_count values" >&2
  exit 1
fi

audit_count="$(run_sql "SELECT count(*) FROM audit_event WHERE request_id='$request_id';")"
state="$(run_sql "SELECT state FROM certificate_request WHERE request_id='$request_id';")"
reservation_count="$(run_sql "SELECT count(*) FROM serial_reservation WHERE ca_id='$ca' AND request_id='$request_id';")"
if [ "$audit_count" != 4 ] || [ "$state" != SERIAL_RESERVED ] || [ "$reservation_count" != 1 ]; then
  echo "FAIL: request state/audit/reservation mismatch: audit=$audit_count state=$state serials=$reservation_count" >&2
  exit 1
fi

echo "PASS: 12 concurrent clients, one request, one 126-bit serial, exactly four audit events"
