#!/usr/bin/env bash
# CI only: SIGKILL a *real* Rust lab CA process AFTER a valid X.509 signature
# was obtained and verified but BEFORE the certificate can be persisted.
# A distinct recovery process must quarantine the journaled signing intent;
# the test must never start another signer.
set -euo pipefail
container="${1:?PostgreSQL disposable container id required}"
binary="target/debug/examples/crash_recovery_lab"
test -x "$binary"

workdir="$(mktemp -d)"
pid=""
cleanup() {
  if [ -n "$pid" ]; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

run_sql() {
  docker exec "$container" psql -X -A -t -v ON_ERROR_STOP=1 \
    -U trust_ci -d trust_ci -c "$1"
}

# A disposable Rust process issues a *valid, signed* lab certificate into memory.
# It deliberately pauses before PostgreSQL result persistence.
"$binary" crash > "$workdir/worker.log" 2>&1 &
pid=$!
ready=0
for i in $(seq 1 100); do
  if grep -q '^SIGNED_VERIFIED_NOT_STORED:' "$workdir/worker.log"; then
    ready=1
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: signer exited before crash point" >&2
    cat "$workdir/worker.log" >&2
    exit 1
  fi
  sleep 0.1
done
if [ "$ready" != 1 ]; then
  echo "FAIL: signer never reached signed-but-uncommitted point" >&2
  cat "$workdir/worker.log" >&2
  exit 1
fi

state_before="$(run_sql "
  SELECT cr.state || ':' || si.outcome || ':' || (
      SELECT count(*) FROM certificate c WHERE c.request_id=si.request_id
  )::text
  FROM signing_intent si
  JOIN certificate_request cr ON cr.ca_id=si.ca_id AND cr.request_id=si.request_id
  WHERE si.operation_ref='v0-8-sigkill-operation'
")"
if [ "$state_before" != "SIGNING:UNCONFIRMED:0" ]; then
  echo "FAIL: unexpected signed-but-uncommitted journal state $state_before" >&2
  exit 1
fi

# Real kernel signal: Rust never gets to update journal state or write DER.
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
pid=""
echo "Worker received SIGKILL after confirmed signature"

# Recovery executes in a wholly NEW Rust process with no access to lost key.
"$binary" recover > "$workdir/recover.log"
grep -q '^QUARANTINED_OPERATION:v0-8-sigkill-operation$' "$workdir/recover.log"
grep -q '^QUARANTINED_COUNT:1$' "$workdir/recover.log"

state_after="$(run_sql "
  SELECT cr.state || ':' || si.outcome || ':' || (
      SELECT count(*) FROM certificate c WHERE c.request_id=si.request_id
  )::text || ':' || (
      SELECT count(*) FROM audit_event e
      WHERE e.request_id=si.request_id AND e.event_type='request.transition'
        AND e.decision='SIGNING -> RECONCILIATION_REQUIRED'
  )::text
  FROM signing_intent si
  JOIN certificate_request cr ON cr.ca_id=si.ca_id AND cr.request_id=si.request_id
  WHERE si.operation_ref='v0-8-sigkill-operation'
")"
if [ "$state_after" != "RECONCILIATION_REQUIRED:RECONCILIATION_REQUIRED:0:1" ]; then
  echo "FAIL: crash reconciliation journal incomplete $state_after" >&2
  exit 1
fi

# Repeat scan must not sign or quarantine again.
"$binary" recover > "$workdir/recover-again.log"
grep -q '^QUARANTINED_COUNT:0$' "$workdir/recover-again.log"
echo "PASS: real X509 signing -> SIGKILL -> separate Rust recovery -> zero re-signs"
