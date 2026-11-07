#!/usr/bin/env bash
# Concurrent regression test against a disposable PostgreSQL 16 container.
set -euo pipefail
container="${1:?Postgres container required}"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

run_sql() {
  docker exec "$container" psql -X -A -t -v ON_ERROR_STOP=1 -U trust_ci -d trust_ci -c "$1"
}

ca="cccccccc-cccc-4ccc-8ccc-cccccccccccc"
run_sql "INSERT INTO ca (ca_id, display_name, policy_version) VALUES ('$ca','Concurrent Lab CA','v1');" >/dev/null

pids=()
for i in $(seq 1 12); do
  (run_sql "SELECT request_id::text || ':' || replay::text FROM create_issuance_request('$ca','concurrent-key',decode(repeat('ab',32),'hex'),'concurrent-actor','v1');" > "$workdir/request-$i") &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done

request_ids="$(cat "$workdir"/request-* | cut -d: -f1 | sort -u)"
request_count="$(printf '%s\n' "$request_ids" | wc -l | tr -d ' ')"
if [ "$request_count" != 1 ]; then
  echo "FAIL: expected one request, received $request_count" >&2
  exit 1
fi
request_id="$request_ids"

# Booleans cast to text are 'true' and 'false' in PostgreSQL.
first_count="$(awk -F: '$2 == "false" { n++ } END { print n+0 }' "$workdir"/request-*)"
if [ "$first_count" != 1 ]; then
  echo "FAIL: expected one new insert, received $first_count" >&2
  exit 1
fi

run_sql "SELECT transition_issuance_request('$ca','$request_id','RECEIVED','CSR_VALIDATED','concurrent-actor');" >/dev/null
run_sql "SELECT transition_issuance_request('$ca','$request_id','CSR_VALIDATED','AUTHORIZED','concurrent-actor');" >/dev/null

pids=()
for i in $(seq 1 12); do
  (run_sql "SELECT encode(reserve_issuance_serial('$ca','$request_id','concurrent-actor'),'hex');" > "$workdir/serial-$i") &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done

serial_count="$(cat "$workdir"/serial-* | sort -u | wc -l | tr -d ' ')"
audit_count="$(run_sql "SELECT count(*) FROM audit_event WHERE request_id='$request_id';")"
state="$(run_sql "SELECT state FROM certificate_request WHERE request_id='$request_id';")"
reservation_count="$(run_sql "SELECT count(*) FROM serial_reservation WHERE ca_id='$ca' AND request_id='$request_id';")"
if [ "$serial_count" != 1 ] || [ "$audit_count" != 4 ] || [ "$state" != "SERIAL_RESERVED" ] || [ "$reservation_count" != 1 ]; then
  echo "FAIL: serials=$serial_count audit=$audit_count state=$state reservations=$reservation_count" >&2
  exit 1
fi
echo "PASS: 12 concurrent clients, one request, one serial, four audit events"
